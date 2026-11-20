use std::path::PathBuf;

/// Settings read from environment variables (with defaults).
#[derive(Clone, Debug)]
pub struct Config {
    pub bind: String,
    pub upstream: String,
    pub data_dir: PathBuf,
}

impl Config {
    pub fn from_env() -> Config {
        Config {
            bind: env_or("LOT_BIND", "127.0.0.1:8080"),
            upstream: env_or("LOT_UPSTREAM", "http://127.0.0.1:8000"),
            data_dir: PathBuf::from(env_or("LOT_DATA_DIR", "./lot-data")),
        }
    }

    /// The JSON file that holds the persisted lock state (NORMAL/RESTRICTED/LOCKED).
    pub fn lock_path(&self) -> PathBuf {
        self.data_dir.join("lock-state.json")
    }

    /// The JSON file that holds officers and devices.
    pub fn store_path(&self) -> PathBuf {
        self.data_dir.join("store.json")
    }

    /// The token file shared with the upstream app.
    pub fn token_path(&self) -> PathBuf {
        self.data_dir.join("gateway.token")
    }
}

/// Read an env var; empty or missing means "use the default".
pub fn env_or(name: &str, default: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => default.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_or_uses_default_when_unset() {
        assert_eq!(env_or("LOT_TEST_SURELY_NOT_SET_12345", "fallback"), "fallback");
    }

    #[test]
    fn store_path_is_inside_data_dir() {
        let c = Config {
            bind: "127.0.0.1:1".to_string(),
            upstream: "http://x".to_string(),
            data_dir: PathBuf::from("some-dir"),
        };
        assert_eq!(c.store_path(), PathBuf::from("some-dir").join("store.json"));
    }
}
