use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::store::{now_unix, Device, Res};

/// PROTOTYPE of device integrity attestation: the "expected device config"
/// is just a string whose SHA-256 the server stores and compares at login.
pub const DEFAULT_DEVICE_CONFIG: &str = "lot-prototype-device-config-v1";

/// The file handed to the officer's device. It holds the PRIVATE key and the
/// shared secret, so it must be kept secret and is never stored by the server.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Keyfile {
    pub device_id: String,
    pub officer_id: String,
    pub signing_key_hex: String,
    pub shared_secret_hex: String,
    pub device_config: String,
}

/// SHA-256 of a device-config string, as lowercase hex.
pub fn config_hash_hex(config: &str) -> String {
    let digest = Sha256::digest(config.as_bytes());
    hex::encode(digest)
}

/// Make a new device: returns (what the server stores, what the device keeps).
pub fn new_device(officer_id: &str, device_config: &str) -> (Device, Keyfile) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let public_key = signing_key.verifying_key();

    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);

    let mut id_bytes = [0u8; 8];
    OsRng.fill_bytes(&mut id_bytes);
    let device_id = format!("dev-{}", hex::encode(id_bytes));

    let device = Device {
        device_id: device_id.clone(),
        officer_id: officer_id.to_string(),
        public_key_hex: hex::encode(public_key.to_bytes()),
        shared_secret_hex: hex::encode(secret),
        config_hash_hex: config_hash_hex(device_config),
        revoked: false,
        created_at: now_unix(),
        locked_out: false,
        failed_attempts: 0,
    };

    let keyfile = Keyfile {
        device_id,
        officer_id: officer_id.to_string(),
        signing_key_hex: hex::encode(signing_key.to_bytes()),
        shared_secret_hex: hex::encode(secret),
        device_config: device_config.to_string(),
    };

    (device, keyfile)
}

/// `n` random bytes as lowercase hex.
pub fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Constant-time string equality.
pub fn ct_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}


/// Session ratchet seed = HKDF-SHA256(
///     ikm  = shared secret (32 bytes),
///     salt = nonce bytes (32 bytes, the decoded hex nonce),
///     info = "lot-gateway/session-seed/v1" followed by the device_id text,
///     length = 32 bytes).
/// Server and device both compute this, so it is documented exactly.
pub fn derive_session_seed(shared_secret: &[u8], nonce: &[u8], device_id: &str) -> Res<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(nonce), shared_secret);
    let mut info = b"lot-gateway/session-seed/v1".to_vec();
    info.extend_from_slice(device_id.as_bytes());
    let mut seed = [0u8; 32];
    hk.expand(&info, &mut seed)
        .map_err(|_| "hkdf expand failed".to_string())?;
    Ok(seed)
}

/// Build the JSON body for POST /auth/login: signs the RAW nonce bytes
/// (the hex nonce decoded) with the device's ed25519 key.
pub fn sign_login_body(keyfile: &Keyfile, nonce_hex: &str) -> Res<String> {
    let nonce = hex::decode(nonce_hex).map_err(|_| "nonce is not valid hex".to_string())?;
    let key_bytes: [u8; 32] = hex::decode(&keyfile.signing_key_hex)
        .map_err(|_| "signing key is not valid hex".to_string())?
        .try_into()
        .map_err(|_| "signing key has wrong length".to_string())?;
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let signature = signing_key.sign(&nonce);
    let body = serde_json::json!({
        "device_id": keyfile.device_id,
        "nonce": nonce_hex,
        "signature": hex::encode(signature.to_bytes()),
        "config_hash": config_hash_hex(&keyfile.device_config),
    });
    Ok(body.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, Verifier};

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            config_hash_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn new_device_server_and_keyfile_agree() {
        let (device, keyfile) = new_device("alice", "cfg-1");
        assert_eq!(device.device_id, keyfile.device_id);
        assert_eq!(device.officer_id, "alice");
        assert_eq!(device.shared_secret_hex, keyfile.shared_secret_hex);
        assert_eq!(device.config_hash_hex, config_hash_hex("cfg-1"));
        assert_eq!(keyfile.device_config, "cfg-1");
        assert!(device.device_id.starts_with("dev-"));
    }

    #[test]
    fn keyfile_key_matches_stored_public_key_and_signs() {
        let (device, keyfile) = new_device("alice", "cfg");
        let sk_bytes: [u8; 32] = hex::decode(&keyfile.signing_key_hex)
            .unwrap()
            .try_into()
            .unwrap();
        let signing_key = SigningKey::from_bytes(&sk_bytes);
        let verifying_key = signing_key.verifying_key();
        assert_eq!(hex::encode(verifying_key.to_bytes()), device.public_key_hex);

        let sig = signing_key.sign(b"nonce-bytes");
        assert!(verifying_key.verify(b"nonce-bytes", &sig).is_ok());
        assert!(verifying_key.verify(b"other", &sig).is_err());
    }

    #[test]
    fn seed_is_deterministic_and_depends_on_every_input() {
        let secret = [7u8; 32];
        let nonce = [9u8; 32];
        let a = derive_session_seed(&secret, &nonce, "dev-1").unwrap();
        assert_eq!(a, derive_session_seed(&secret, &nonce, "dev-1").unwrap());
        assert_ne!(a, derive_session_seed(&[8u8; 32], &nonce, "dev-1").unwrap());
        assert_ne!(a, derive_session_seed(&secret, &[1u8; 32], "dev-1").unwrap());
        assert_ne!(a, derive_session_seed(&secret, &nonce, "dev-2").unwrap());
    }

    #[test]
    fn session_seed_matches_independent_known_answer() {
        // Computed with a Python HKDF-SHA256 validated against RFC 5869.
        let seed = derive_session_seed(&[7u8; 32], &[9u8; 32], "dev-1").unwrap();
        assert_eq!(
            hex::encode(seed),
            "c23ecd43f3c71e0743e7cf7a8069bf6434b82014dc3f34b144088e401b94ff4a"
        );
    }

    #[test]
    fn random_hex_has_expected_length() {
        assert_eq!(random_hex(16).len(), 32);
        assert_ne!(random_hex(16), random_hex(16));
    }

    #[test]
    fn two_devices_get_different_secrets_and_ids() {
        let (a, _) = new_device("alice", "cfg");
        let (b, _) = new_device("alice", "cfg");
        assert_ne!(a.device_id, b.device_id);
        assert_ne!(a.shared_secret_hex, b.shared_secret_hex);
        assert_ne!(a.public_key_hex, b.public_key_hex);
    }
}
