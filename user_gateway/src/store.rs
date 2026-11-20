use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Simple error type: a message string.
pub type Res<T> = Result<T, String>;

fn default_rank_tier() -> u8 {
    1
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Officer {
    pub officer_id: String,
    pub revoked: bool,
    pub created_at: u64,
    #[serde(default)]
    pub passcode_hash: String,
    #[serde(default = "default_rank_tier")]
    pub rank_tier: u8,
}

/// What the SERVER keeps per device: public key + shared secret + config hash.
/// (The private signing key lives only in the device keyfile.)
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Device {
    pub device_id: String,
    pub officer_id: String,
    pub public_key_hex: String,
    pub shared_secret_hex: String,
    pub config_hash_hex: String,
    pub revoked: bool,
    pub created_at: u64,
    #[serde(default)]
    pub locked_out: bool,
    #[serde(default)]
    pub failed_attempts: u32,
}

pub fn hash_passcode(passcode: &str) -> Res<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(passcode.as_bytes(), &salt)
        .map_err(|e| format!("passcode hashing failed: {e}"))?;
    Ok(hash.to_string())
}

pub fn verify_passcode(passcode: &str, hash_str: &str) -> bool {
    if hash_str.is_empty() {
        return false;
    }
    match PasswordHash::new(hash_str) {
        Ok(parsed_hash) => Argon2::default().verify_password(passcode.as_bytes(), &parsed_hash).is_ok(),
        Err(_) => false,
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct StoreData {
    #[serde(default)]
    pub officers: Vec<Officer>,
    #[serde(default)]
    pub devices: Vec<Device>,
}

pub struct Store {
    pub path: PathBuf,
    pub data: StoreData,
}

impl Store {
    /// Load the store. Missing file = empty store. Any other problem
    /// (unreadable, corrupt JSON) is an ERROR, so we never overwrite
    /// a store we could not understand.
    pub fn load(path: &Path) -> Res<Store> {
        let data = match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str::<StoreData>(&text)
                .map_err(|e| format!("store file {:?} is corrupt: {e}", path))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => StoreData::default(),
            Err(e) => return Err(format!("cannot read store file {:?}: {e}", path)),
        };
        Ok(Store {
            path: path.to_path_buf(),
            data,
        })
    }

    /// Write to a temp file, then rename over the real file (atomic on one filesystem).
    pub fn save(&self) -> Res<()> {
        let bytes = serde_json::to_vec_pretty(&self.data)
            .map_err(|e| format!("cannot serialize store: {e}"))?;
        let tmp = self.path.with_extension("json.tmp");
        write_private(&tmp, &bytes, false)?;
        std::fs::rename(&tmp, &self.path)
            .map_err(|e| format!("cannot replace store file {:?}: {e}", self.path))
    }

    pub fn find_officer(&self, officer_id: &str) -> Option<&Officer> {
        self.data.officers.iter().find(|o| o.officer_id == officer_id)
    }

    pub fn find_device(&self, device_id: &str) -> Option<&Device> {
        self.data.devices.iter().find(|d| d.device_id == device_id)
    }

    /// Add a new officer together with their first device (in memory; call save()).
    pub fn add_user(&mut self, device: Device) -> Res<()> {
        self.add_user_with_rank(device, String::new(), 1)
    }

    pub fn add_user_with_rank(&mut self, device: Device, passcode_hash: String, rank_tier: u8) -> Res<()> {
        validate_officer_id(&device.officer_id)?;
        if self.find_officer(&device.officer_id).is_some() {
            return Err(format!("officer {:?} already exists", device.officer_id));
        }
        if self.data.devices.iter().any(|d| d.device_id == device.device_id) {
            return Err("device id collision, try again".to_string());
        }
        self.data.officers.push(Officer {
            officer_id: device.officer_id.clone(),
            revoked: false,
            created_at: now_unix(),
            passcode_hash,
            rank_tier,
        });
        self.data.devices.push(device);
        Ok(())
    }

    pub fn reset_device(&mut self, device_id: &str) -> Res<()> {
        let mut found = false;
        for d in self.data.devices.iter_mut() {
            if d.device_id == device_id {
                d.locked_out = false;
                d.failed_attempts = 0;
                found = true;
                break;
            }
        }
        if !found {
            return Err(format!("device {:?} not found", device_id));
        }
        Ok(())
    }

    pub fn increment_device_failure(&mut self, device_id: &str) -> Res<(u32, bool)> {
        for d in self.data.devices.iter_mut() {
            if d.device_id == device_id {
                d.failed_attempts = d.failed_attempts.saturating_add(1);
                if d.failed_attempts >= 3 && !d.locked_out {
                    d.locked_out = true;
                    return Ok((d.failed_attempts, true));
                }
                return Ok((d.failed_attempts, false));
            }
        }
        Err(format!("device {:?} not found", device_id))
    }

    /// Revoke an officer and all of their devices (in memory; call save()).
    pub fn revoke_officer(&mut self, officer_id: &str) -> Res<()> {
        let mut found = false;
        for o in self.data.officers.iter_mut() {
            if o.officer_id == officer_id {
                if o.revoked {
                    return Err(format!("officer {:?} is already revoked", officer_id));
                }
                o.revoked = true;
                found = true;
            }
        }
        if !found {
            return Err(format!("officer {:?} not found", officer_id));
        }
        for d in self.data.devices.iter_mut() {
            if d.officer_id == officer_id {
                d.revoked = true;
            }
        }
        Ok(())
    }
}

/// Officer ids: 1 to 64 chars, letters, digits, '-', '_' or '.'.
pub fn validate_officer_id(id: &str) -> Res<()> {
    if id.is_empty() || id.len() > 64 {
        return Err("officer id must be 1 to 64 characters".to_string());
    }
    let ok = id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
    if !ok {
        return Err("officer id may only use letters, digits, '-', '_' and '.'".to_string());
    }
    Ok(())
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(unix)]
fn set_private(opts: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    opts.mode(0o600);
}

#[cfg(not(unix))]
fn set_private(_opts: &mut OpenOptions) {}

/// Write a file readable only by the owner (on unix).
/// create_new = true refuses to overwrite an existing file.
pub fn write_private(path: &Path, bytes: &[u8], create_new: bool) -> Res<()> {
    let mut opts = OpenOptions::new();
    opts.write(true);
    if create_new {
        opts.create_new(true);
    } else {
        opts.create(true).truncate(true);
    }
    set_private(&mut opts);
    let mut file = opts
        .open(path)
        .map_err(|e| format!("cannot write {:?}: {e}", path))?;
    file.write_all(bytes)
        .map_err(|e| format!("cannot write {:?}: {e}", path))?;
    file.sync_all()
        .map_err(|e| format!("cannot sync {:?}: {e}", path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir(tag: &str) -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "lot-test-{tag}-{}-{nanos}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn officer_id_validation() {
        assert!(validate_officer_id("alice").is_ok());
        assert!(validate_officer_id("off-01_a.b").is_ok());
        assert!(validate_officer_id("").is_err());
        assert!(validate_officer_id("a b").is_err());
        assert!(validate_officer_id("a/b").is_err());
        assert!(validate_officer_id(&"x".repeat(65)).is_err());
    }

    #[test]
    fn store_survives_reload() {
        let dir = temp_dir("reload");
        let path = dir.join("store.json");
        let mut store = Store::load(&path).unwrap();
        let (device, _kf) = crypto::new_device("alice", "cfg");
        let device_id = device.device_id.clone();
        store.add_user(device).unwrap();
        store.save().unwrap();

        let again = Store::load(&path).unwrap();
        assert!(again.find_officer("alice").is_some());
        assert_eq!(again.data.devices.len(), 1);
        assert_eq!(again.data.devices[0].device_id, device_id);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn duplicate_officer_rejected() {
        let mut store = Store {
            path: PathBuf::from("unused.json"),
            data: StoreData::default(),
        };
        let (d1, _) = crypto::new_device("alice", "cfg");
        let (d2, _) = crypto::new_device("alice", "cfg");
        store.add_user(d1).unwrap();
        assert!(store.add_user(d2).is_err());
        assert_eq!(store.data.officers.len(), 1);
    }

    #[test]
    fn revoke_marks_officer_and_devices() {
        let mut store = Store {
            path: PathBuf::from("unused.json"),
            data: StoreData::default(),
        };
        let (d, _) = crypto::new_device("bob", "cfg");
        store.add_user(d).unwrap();
        store.revoke_officer("bob").unwrap();
        assert!(store.find_officer("bob").unwrap().revoked);
        assert!(store.data.devices[0].revoked);
        assert!(store.revoke_officer("bob").is_err()); // already revoked
        assert!(store.revoke_officer("nobody").is_err()); // unknown
    }

    #[test]
    fn corrupt_store_fails_closed() {
        let dir = temp_dir("corrupt");
        let path = dir.join("store.json");
        std::fs::write(&path, "{ this is not json").unwrap();
        assert!(Store::load(&path).is_err());
        // the corrupt file must be left untouched
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{ this is not json");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_private_refuses_overwrite_when_create_new() {
        let dir = temp_dir("private");
        let path = dir.join("k.json");
        write_private(&path, b"one", true).unwrap();
        assert!(write_private(&path, b"two", true).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "one");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
