//! # mimic-signatures
//!
//! ClamAV signature database loader and high-speed matcher. Loads `.cvd`/`.cld` containers
//! and raw `.hdb`, `.hsb`, `.ndb`, `.ldb`, `.mdb`, `.msb`, `.cdb`, `.fp`, `.sfp`, `.cbc` files
//! in parallel; builds Aho-Corasick automatons for body and logical rules; supports
//! target-type filtering and wildcard atom extraction for fast scanning.
//!
//! - **load_databases** — Load from paths; returns [`SignatureMatcher`] and per-source [`SourceStats`].
//! - **SignatureMatcher** — [`scan`](matcher::SignatureMatcher::scan) file bytes + hashes → list of [`ThreatInfo`](mimic_core::ThreatInfo).
//! - **MatcherStats** / **SourceStats** — Signature counts for summary and debugging.

pub mod body_db;
pub mod cdb_db;
pub mod cvd;
pub mod hash_db;
pub mod ldb_db;
#[cfg(feature = "native")]
pub mod loader;
pub mod matcher;

#[cfg(feature = "native")]
pub use loader::{load_databases, SourceStats};
pub use matcher::{MatcherStats, SignatureMatcher};
