//! # mimic-vt
//!
//! VirusTotal v3 API client for hash lookups.
//!
//! - **VtConfig** — API key and `hash_only` (no file upload).
//! - **VtClient** — Async client; [`lookup_hash`](client::VtClient::lookup_hash) returns report for a SHA256.
//! - **VtLookupResult** — `found`, `positives`/`total`, `detections`, permalink.
//!
//! ## WASM plugin stub
//!
//! For `target_arch = "wasm32"` this crate builds a minimal WASM plugin that exports `scan(ptr, len) -> 0`
//! (always clean). The host uses the built-in VT client when the plugin path filename is `mimic-vt.wasm`.
//! Build with: `cargo build --release --target wasm32-unknown-unknown -p mimic-vt --no-default-features`
//! Output: `target/wasm32-unknown-unknown/release/mimic_vt.wasm` (rename to `mimic-vt.wasm` if desired).

#[cfg(not(target_arch = "wasm32"))]
mod client;

#[cfg(not(target_arch = "wasm32"))]
pub use client::{VtClient, VtConfig, VtLookupResult};

/// WASM plugin ABI: always returns 0 (clean). The host enables the built-in VT client when this plugin is loaded by path.
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn scan(_ptr: i32, _len: i32) -> i32 {
    0
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
