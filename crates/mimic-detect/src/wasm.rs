//! WASM plugin ABI for mimic-detect. Only compiled for target_arch = "wasm32".
//!
//! Export: `scan(ptr: i32, len: i32) -> i32`
//! Host writes file bytes into linear memory at `ptr` (length `len`).
//! Return: 0 = clean, 1 = suspicious, 2 = infected.

use crate::{analyze, Verdict};

/// Plugin entry point: analyze the buffer at [ptr, ptr+len) in linear memory.
/// Called by the Mimic host after it has written the file content into memory.
#[no_mangle]
pub extern "C" fn scan(ptr: i32, len: i32) -> i32 {
    let len = len as usize;
    if len == 0 {
        return 0;
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr as *const u8, len) };
    let result = analyze(slice);
    match result.verdict {
        Verdict::Benign => 0,
        Verdict::Suspicious => 1,
        Verdict::Malicious => 2,
    }
}
