//! RAR analyzer: CVE-2025-8088 (WinRAR path traversal via Alternate Data Streams).
//!
//! References:
//! - https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/
//! - https://cloud.google.com/blog/topics/threat-intelligence/exploiting-critical-winrar-vulnerability
//! - https://research.checkpoint.com/2026/amaranth-dragon-weaponizes-cve-2025-8088-for-targeted-espionage/

mod parser;

pub mod analyzer;

pub use analyzer::analyze_rar;
pub use parser::{collect_file_names, find_rar_signature, is_rar, RarVersion};
