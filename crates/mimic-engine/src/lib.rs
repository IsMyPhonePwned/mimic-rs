//! # mimic-engine
//!
//! Orchestrates scanning: loads ClamAV databases and optional YARA/WASM plugins,
//! runs the per-file pipeline (signatures → YARA → WASM plugins). Mimic-detect
//! (exploit detection) runs only when loaded as a WASM plugin (e.g. mimic_detect.wasm).
//!
//! - **MimicEngine** — Build from [`ScanConfig`](mimic_core::ScanConfig); use [`scan_bytes`](engine::MimicEngine::scan_bytes) or [`scan_files_parallel`](engine::MimicEngine::scan_files_parallel).
//! - **FileScanner** — Single-file scanner used by the engine; can be used with or without a signature matcher.

pub mod engine;
pub mod scanner;
pub mod yara;

pub use engine::MimicEngine;
pub use mimic_signatures::{MatcherStats, SourceStats};
pub use scanner::FileScanner;

#[cfg(test)]
mod tests;
