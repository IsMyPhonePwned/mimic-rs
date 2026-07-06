//! # mimic-core
//!
//! Shared types and configuration for the Mimic antivirus engine.
//!
//! - **Verdict** — Scan outcome: `Clean`, `Infected`, `Suspicious`, `Error`.
//! - **ScanResult** — Per-file result: path, hashes, verdict, threats, duration.
//! - **ScanVerdict** — Aggregated verdict plus lists of signature, mimic, and YARA matches.
//! - **ScanConfig** — Thread count, paths, feature flags (signatures, mimic, sandbox, etc.).
//! - **ThreatInfo** / **MimicThreat** / **YaraMatch** — Threat representations from each scanner.

pub mod config;
pub mod error;
pub mod threat;
pub mod verdict;

pub use config::ScanConfig;
pub use error::MimicError;
pub use threat::ThreatSeverity;
pub use verdict::{MimicThreat, ScanResult, ScanVerdict, ThreatInfo, Verdict, YaraMatch};

#[cfg(test)]
mod tests;
