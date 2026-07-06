//! # mimic-db
//!
//! SQLite persistence for Mimic scan sessions and results.
//!
//! - **MimicDb** — Open a database with [`MimicDb::open`] or [`MimicDb::open_memory`] for tests.
//! - **ScanSession** — Metadata for a scan run (path, counts, duration).
//! - **ScanRecord** — Per-file result stored in a session (path, hashes, verdict, threats JSON).
//! - **DbStats** — Aggregated statistics (total files, infected, top threats).

mod database;
mod models;

pub use database::MimicDb;
pub use models::{DbStats, ScanRecord, ScanSession};

#[cfg(test)]
mod tests;
