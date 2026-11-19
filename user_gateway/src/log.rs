// Tiny logging helper. tracing-subscriber is not an approved crate yet, so
// tracing macros alone would print nothing. We call both: tracing for later,
// eprintln! so security reasons are visible today. If a subscriber is added
// later, delete the eprintln! lines to avoid double output.

pub fn info(msg: &str) {
    tracing::info!("{}", msg);
    eprintln!("INFO  {msg}");
}

pub fn warn(msg: &str) {
    tracing::warn!("{}", msg);
    eprintln!("WARN  {msg}");
}
