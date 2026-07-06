//! ZIP analyzer: Zombie ZIP (CVE-2026-0866) — method mismatch evasion.
//!
//! Detects ZIP archives that declare compression method 0 (stored) while the payload
//! is actually DEFLATE-compressed, allowing AV evasion (scanner sees "stored" and
//! scans raw bytes as content; attacker decompresses as DEFLATE to recover payload).
//!
//! References:
//! - https://github.com/bombadil-systems/zombie-zip
//! - CVE-2026-0866 | VU#976247

mod analyzer;

pub use analyzer::{analyze_zip, is_zip};
