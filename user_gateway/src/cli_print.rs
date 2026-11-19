use crate::store::Store;

pub fn list_users(store: &Store) {
    if store.data.officers.is_empty() {
        println!("(no officers)");
        return;
    }
    println!("{:<24} {:<8} {}", "OFFICER", "STATUS", "DEVICES");
    for o in &store.data.officers {
        let count = store
            .data
            .devices
            .iter()
            .filter(|d| d.officer_id == o.officer_id)
            .count();
        let status = if o.revoked { "revoked" } else { "active" };
        println!("{:<24} {:<8} {}", o.officer_id, status, count);
    }
}

// Never prints secrets or full keys.
pub fn list_devices(store: &Store) {
    if store.data.devices.is_empty() {
        println!("(no devices)");
        return;
    }
    println!(
        "{:<22} {:<24} {:<8} {}",
        "DEVICE", "OFFICER", "STATUS", "CONFIG-HASH"
    );
    for d in &store.data.devices {
        let status = if d.revoked { "revoked" } else { "active" };
        let short: String = d.config_hash_hex.chars().take(12).collect();
        println!("{:<22} {:<24} {:<8} {}", d.device_id, d.officer_id, status, short);
    }
}
