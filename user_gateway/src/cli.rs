use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::crypto::{self, Keyfile, DEFAULT_DEVICE_CONFIG};
use crate::cli_print;
use crate::lockout;
use crate::ratchet;
use crate::store::{self, write_private, Device, Res, Store};

#[derive(Parser)]
#[command(name = "lotoctl", about = "Admin tool for lot-gateway (reads LOT_DATA_DIR)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage officers
    User {
        #[command(subcommand)]
        action: UserAction,
    },
    /// Inspect and manage devices
    Device {
        #[command(subcommand)]
        action: DeviceAction,
    },
    /// Lock the gateway now
    Lock,
    /// Trigger tagout investigation state
    Tagout {
        #[arg(long)]
        officer: Option<String>,
    },
    /// Generate a 2-minute restore key
    GenerateRestoreKey {
        #[arg(long)]
        out: PathBuf,
    },
    /// Restore system from LOCKED or TAGOUT using dual-officer approval
    Restore {
        #[arg(long)]
        restore_key: PathBuf,
        #[arg(long = "officer-keyfile", num_args = 1..)]
        officer_keyfile: Vec<PathBuf>,
    },
    /// Print the JSON body for POST /auth/login
    SignLogin {
        #[arg(long)]
        keyfile: PathBuf,
        #[arg(long)]
        nonce: String,
        #[arg(long, default_value = "")]
        passcode: String,
    },
    /// Print the X-Session-Id / X-Counter / X-Code headers for one protected request
    SignRequest {
        #[arg(long)]
        keyfile: PathBuf,
        #[arg(long)]
        nonce: String,
        #[arg(long)]
        session_id: String,
        #[arg(long)]
        counter: u64,
        #[arg(long)]
        curl: bool,
    },
}

#[derive(Subcommand)]
enum UserAction {
    /// Create an officer and write their device keyfile
    Add {
        officer_id: String,
        #[arg(long)]
        keyfile: PathBuf,
        #[arg(long, default_value = DEFAULT_DEVICE_CONFIG)]
        device_config: String,
        #[arg(long)]
        passcode: Option<String>,
        #[arg(long, default_value_t = 1)]
        rank_tier: u8,
    },
    /// List officers
    List,
    /// Revoke an officer and all their devices
    Revoke { officer_id: String },
}

#[derive(Subcommand)]
enum DeviceAction {
    /// List devices
    List,
    /// Reset a locked-out device
    Reset { device_id: String },
}

pub fn run() -> i32 {
    let cli = Cli::parse();
    match execute(cli) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn execute(cli: Cli) -> Res<()> {
    let config = Config::from_env();
    std::fs::create_dir_all(&config.data_dir)
        .map_err(|e| format!("cannot create data dir {:?}: {e}", config.data_dir))?;

    // First-run initialization writes NORMAL; missing lock file afterwards means LOCKED
    if !config.lock_path().exists() && !config.store_path().exists() {
        let _ = lockout::persist_lock(&config.lock_path(), &lockout::LockInfo::normal());
    }

    match &cli.command {
        Command::Lock => {
            lockout::manual_lock_file(&config)?;
            println!("lock state set to LOCKED ({:?})", config.lock_path());
            return Ok(());
        }
        Command::Tagout { officer } => {
            let initiator = officer.as_deref().unwrap_or("terminal_admin");
            lockout::manual_tagout_file(&config, initiator)?;
            println!("lock state set to TAGOUT (initiator: {initiator})");
            return Ok(());
        }
        Command::GenerateRestoreKey { out } => {
            let key_json = serde_json::json!({
                "token": crypto::random_hex(32),
                "created_at": crate::store::now_unix(),
            });
            let bytes = serde_json::to_vec_pretty(&key_json)
                .map_err(|e| format!("cannot serialize restore key: {e}"))?;
            write_private(out, &bytes, false)?;
            println!("generated restore key (valid 2 minutes): {}", out.display());
            return Ok(());
        }
        Command::Restore {
            restore_key,
            officer_keyfile,
        } => {
            let store = Store::load(&config.store_path())?;
            if officer_keyfile.len() != 2 {
                return Err(format!(
                    "restore requires exactly two officer keyfiles, got {}",
                    officer_keyfile.len()
                ));
            }
            let kf_a = load_keyfile(&officer_keyfile[0])?;
            let kf_b = load_keyfile(&officer_keyfile[1])?;
            restore_system(&config, &store, restore_key, &kf_a, &kf_b)?;
            println!("system successfully restored to NORMAL; upstream unseal called");
            return Ok(());
        }
        Command::SignLogin { keyfile, nonce, passcode } => {
            let kf = load_keyfile(keyfile)?;
            let mut body: serde_json::Value = serde_json::from_str(&crypto::sign_login_body(&kf, nonce)?)
                .map_err(|e| format!("json error: {e}"))?;
            if !passcode.is_empty() {
                body["passcode"] = serde_json::json!(passcode);
            }
            println!("{}", body);
            return Ok(());
        }
        Command::SignRequest {
            keyfile,
            nonce,
            session_id,
            counter,
            curl,
        } => {
            let kf = load_keyfile(keyfile)?;
            let headers = ratchet::request_headers(&kf, nonce, session_id, *counter)?;
            if *curl {
                let parts: Vec<String> = headers
                    .iter()
                    .map(|(k, v)| format!("-H '{k}: {v}'"))
                    .collect();
                println!("{}", parts.join(" "));
            } else {
                for (k, v) in &headers {
                    println!("{k}: {v}");
                }
            }
            return Ok(());
        }
        _ => {}
    }

    let mut store = Store::load(&config.store_path())?;

    match cli.command {
        Command::User { action } => match action {
            UserAction::Add {
                officer_id,
                keyfile,
                device_config,
                passcode,
                rank_tier,
            } => {
                let device = add_user_full(
                    &mut store,
                    &officer_id,
                    &device_config,
                    &keyfile,
                    passcode.as_deref(),
                    rank_tier,
                )?;
                println!("created officer {officer_id} (rank tier {rank_tier})");
                println!("device id: {}", device.device_id);
                println!("keyfile:   {}", keyfile.display());
            }
            UserAction::List => cli_print::list_users(&store),
            UserAction::Revoke { officer_id } => {
                store.revoke_officer(&officer_id)?;
                store.save()?;
                println!("revoked officer {officer_id} and all their devices");
            }
        },
        Command::Device { action } => match action {
            DeviceAction::List => cli_print::list_devices(&store),
            DeviceAction::Reset { device_id } => {
                store.reset_device(&device_id)?;
                store.save()?;
                println!("device {device_id} lockout cleared and failure count reset");
            }
        },
        _ => {}
    }
    Ok(())
}

pub fn load_keyfile(path: &Path) -> Res<Keyfile> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read keyfile {:?}: {e}", path))?;
    serde_json::from_str(&text).map_err(|e| format!("keyfile is not valid: {e}"))
}

pub fn add_user(
    store: &mut Store,
    officer_id: &str,
    device_config: &str,
    keyfile_path: &Path,
) -> Res<Device> {
    add_user_full(store, officer_id, device_config, keyfile_path, None, 1)
}

pub fn add_user_full(
    store: &mut Store,
    officer_id: &str,
    device_config: &str,
    keyfile_path: &Path,
    passcode: Option<&str>,
    rank_tier: u8,
) -> Res<Device> {
    let (device, keyfile) = crypto::new_device(officer_id, device_config);
    let passcode_hash = match passcode {
        Some(p) if !p.trim().is_empty() => store::hash_passcode(p.trim())?,
        _ => String::new(),
    };
    store.add_user_with_rank(device.clone(), passcode_hash, rank_tier)?;

    let json = serde_json::to_vec_pretty(&keyfile)
        .map_err(|e| format!("cannot serialize keyfile: {e}"))?;
    write_private(keyfile_path, &json, true)?;

    if let Err(e) = store.save() {
        let _ = std::fs::remove_file(keyfile_path);
        return Err(e);
    }
    Ok(device)
}

pub fn restore_system(
    config: &Config,
    store: &Store,
    restore_key_path: &Path,
    kf_a: &Keyfile,
    kf_b: &Keyfile,
) -> Res<()> {
    if kf_a.officer_id == kf_b.officer_id {
        return Err("two different officers required for restore".to_string());
    }
    let off_a = store
        .find_officer(&kf_a.officer_id)
        .ok_or_else(|| format!("officer {:?} not found", kf_a.officer_id))?;
    let off_b = store
        .find_officer(&kf_b.officer_id)
        .ok_or_else(|| format!("officer {:?} not found", kf_b.officer_id))?;

    if off_a.revoked || off_b.revoked {
        return Err("revoked officer cannot approve restore".to_string());
    }
    if off_a.rank_tier < 4 || off_b.rank_tier < 4 {
        return Err("both officers must have rank tier 4 or higher".to_string());
    }

    let key_text = std::fs::read_to_string(restore_key_path)
        .map_err(|e| format!("cannot read restore key {:?}: {e}", restore_key_path))?;
    let key_val: serde_json::Value = serde_json::from_str(&key_text)
        .map_err(|e| format!("invalid restore key JSON: {e}"))?;
    let created_at = key_val["created_at"]
        .as_u64()
        .ok_or("missing created_at in restore key")?;
    let now = crate::store::now_unix();
    if now.saturating_sub(created_at) > 120 {
        return Err("restore token has expired (older than 2 minutes)".to_string());
    }

    let info = lockout::LockInfo::normal();
    lockout::persist_lock(&config.lock_path(), &info)?;

    // Call unseal on upstream
    let url = format!("{}/internal/unseal", config.upstream.trim_end_matches('/'));
    let token = std::fs::read_to_string(config.token_path()).unwrap_or_default();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build();
    if let Ok(rt) = rt {
        rt.block_on(async {
            let client = reqwest::Client::new();
            let _ = client
                .post(&url)
                .header("x-gateway-token", token.trim())
                .send()
                .await;
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir(tag: &str) -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "lot-cli-{tag}-{}-{nanos}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn add_user_writes_keyfile_and_persists_store() {
        let dir = temp_dir("add");
        let store_path = dir.join("store.json");
        let key_path = dir.join("alice.keyfile.json");

        let mut store = Store::load(&store_path).unwrap();
        let device = add_user(&mut store, "alice", "cfg", &key_path).unwrap();

        let kf: Keyfile =
            serde_json::from_str(&std::fs::read_to_string(&key_path).unwrap()).unwrap();
        assert_eq!(kf.device_id, device.device_id);
        assert_eq!(kf.officer_id, "alice");

        let reloaded = Store::load(&store_path).unwrap();
        assert!(reloaded.find_officer("alice").is_some());
        assert_eq!(reloaded.data.devices[0].public_key_hex, device.public_key_hex);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn existing_keyfile_is_not_overwritten_and_store_not_saved() {
        let dir = temp_dir("exists");
        let store_path = dir.join("store.json");
        let key_path = dir.join("k.json");
        std::fs::write(&key_path, "precious").unwrap();

        let mut store = Store::load(&store_path).unwrap();
        assert!(add_user(&mut store, "bob", "cfg", &key_path).is_err());
        assert_eq!(std::fs::read_to_string(&key_path).unwrap(), "precious");

        let reloaded = Store::load(&store_path).unwrap();
        assert!(reloaded.find_officer("bob").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_officer_id_creates_nothing() {
        let dir = temp_dir("badid");
        let store_path = dir.join("store.json");
        let key_path = dir.join("k.json");
        let mut store = Store::load(&store_path).unwrap();
        assert!(add_user(&mut store, "bad id!", "cfg", &key_path).is_err());
        assert!(!key_path.exists());
        assert!(!store_path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restore_validation_rules() {
        let dir = temp_dir("restore");
        let store_path = dir.join("store.json");
        let lock_path = dir.join("lock-state.json");
        let key_path = dir.join("restore.key.json");

        let config = Config {
            bind: "127.0.0.1:0".to_string(),
            upstream: "http://127.0.0.1:9000".to_string(),
            data_dir: dir.clone(),
            require_face: false,
        };

        // System currently LOCKED
        let _ = lockout::persist_lock(&lock_path, &lockout::LockInfo::locked("test"));

        let mut store = Store::load(&store_path).unwrap();
        let (dev_a, kf_a) = crypto::new_device("alice", DEFAULT_DEVICE_CONFIG);
        let (dev_b, kf_b) = crypto::new_device("bob", DEFAULT_DEVICE_CONFIG);
        let (dev_c, kf_c) = crypto::new_device("charlie", DEFAULT_DEVICE_CONFIG);

        // alice: tier 4, bob: tier 4, charlie: tier 3
        store.add_user_with_rank(dev_a, String::new(), 4).unwrap();
        store.add_user_with_rank(dev_b, String::new(), 4).unwrap();
        store.add_user_with_rank(dev_c, String::new(), 3).unwrap();

        // Write a valid fresh restore key
        let fresh_key = serde_json::json!({
            "token": "tok123",
            "created_at": crate::store::now_unix(),
        });
        std::fs::write(&key_path, fresh_key.to_string()).unwrap();

        // 1. Same officer twice fails
        let res = restore_system(&config, &store, &key_path, &kf_a, &kf_a);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("two different officers required"));

        // 2. Rank tier below 4 fails
        let res = restore_system(&config, &store, &key_path, &kf_a, &kf_c);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("tier 4 or higher"));

        // 3. Expired restore key (> 2 min) fails
        let expired_key = serde_json::json!({
            "token": "tok123",
            "created_at": crate::store::now_unix() - 125,
        });
        std::fs::write(&key_path, expired_key.to_string()).unwrap();
        let res = restore_system(&config, &store, &key_path, &kf_a, &kf_b);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("expired"));

        // 4. Valid restore with two tier 4 officers succeeds and restores NORMAL
        std::fs::write(&key_path, fresh_key.to_string()).unwrap();
        let res = restore_system(&config, &store, &key_path, &kf_a, &kf_b);
        assert!(res.is_ok());
        assert_eq!(lockout::load_lock(&lock_path).state, lockout::LockState::Normal);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
