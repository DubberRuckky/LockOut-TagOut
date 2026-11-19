use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::crypto::{self, Keyfile, DEFAULT_DEVICE_CONFIG};
use crate::cli_print;
use crate::lockout;
use crate::ratchet;
use crate::store::{write_private, Device, Res, Store};

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
    /// Inspect devices
    Device {
        #[command(subcommand)]
        action: DeviceAction,
    },
    /// Lock the gateway now (saved to disk; a running gateway notices within about a second)
    Lock,
    /// Print the JSON body for POST /auth/login (signs the nonce with a device keyfile)
    SignLogin {
        #[arg(long)]
        keyfile: PathBuf,
        /// The hex nonce returned by /auth/challenge
        #[arg(long)]
        nonce: String,
    },
    /// Print the X-Session-Id / X-Counter / X-Code headers for one protected request
    SignRequest {
        #[arg(long)]
        keyfile: PathBuf,
        /// The nonce used for the login that created the session
        #[arg(long)]
        nonce: String,
        #[arg(long)]
        session_id: String,
        /// Request counter: 1 for the first request, then increasing
        #[arg(long)]
        counter: u64,
        /// Print as curl -H arguments on one line
        #[arg(long)]
        curl: bool,
    },
}

#[derive(Subcommand)]
enum UserAction {
    /// Create an officer and write their device keyfile
    Add {
        officer_id: String,
        /// Where to write the device keyfile (contains secrets; must not exist yet)
        #[arg(long)]
        keyfile: PathBuf,
        /// Expected device-config string (prototype of attestation)
        #[arg(long, default_value = DEFAULT_DEVICE_CONFIG)]
        device_config: String,
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
}

/// Entry point for the lotoctl binary. Returns the process exit code.
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
    // These only need the keyfile or the data dir, not the store.
    match &cli.command {
        Command::Lock => {
            let config = Config::from_env();
            std::fs::create_dir_all(&config.data_dir)
                .map_err(|e| format!("cannot create data dir {:?}: {e}", config.data_dir))?;
            lockout::manual_lock_file(&config)?;
            println!("lock state set to LOCKED ({:?})", config.lock_path());
            println!("A running gateway applies it within about a second; a stopped one starts LOCKED.");
            return Ok(());
        }
        Command::SignLogin { keyfile, nonce } => {
            let kf = load_keyfile(keyfile)?;
            println!("{}", crypto::sign_login_body(&kf, nonce)?);
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

    let config = Config::from_env();
    std::fs::create_dir_all(&config.data_dir)
        .map_err(|e| format!("cannot create data dir {:?}: {e}", config.data_dir))?;
    let mut store = Store::load(&config.store_path())?;

    match cli.command {
        Command::User { action } => match action {
            UserAction::Add {
                officer_id,
                keyfile,
                device_config,
            } => {
                let device = add_user(&mut store, &officer_id, &device_config, &keyfile)?;
                println!("created officer {officer_id}");
                println!("device id: {}", device.device_id);
                println!("keyfile:   {}", keyfile.display());
                println!("Keep the keyfile secret. The server does not store the private key.");
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
        },
        Command::SignLogin { .. } | Command::SignRequest { .. } | Command::Lock => {} // handled above
    }
    Ok(())
}

fn load_keyfile(path: &Path) -> Res<Keyfile> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read keyfile {:?}: {e}", path))?;
    serde_json::from_str(&text).map_err(|e| format!("keyfile is not valid: {e}"))
}

/// Create the officer + device, write the keyfile, then save the store.
/// Nothing is saved to disk unless the keyfile was written first; if saving
/// the store fails afterwards, the keyfile is removed again.
pub fn add_user(
    store: &mut Store,
    officer_id: &str,
    device_config: &str,
    keyfile_path: &Path,
) -> Res<Device> {
    let (device, keyfile) = crypto::new_device(officer_id, device_config);
    store.add_user(device.clone())?;

    let json = serde_json::to_vec_pretty(&keyfile)
        .map_err(|e| format!("cannot serialize keyfile: {e}"))?;
    write_private(keyfile_path, &json, true)?; // refuses to overwrite

    if let Err(e) = store.save() {
        let _ = std::fs::remove_file(keyfile_path);
        return Err(e);
    }
    Ok(device)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "lot-cli-{tag}-{}-{nanos}",
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
}
