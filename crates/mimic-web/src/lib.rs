//! # mimic-web
//!
//! Web dashboard and REST API for Mimic: browse scan sessions and results,
//! submit files for scanning, search by hash, and optional VirusTotal lookups.
//!
//! - **AppState** — Holds engine, DB, and optional VT client; build with [`AppState::new`](state::AppState::new).
//! - **build_router** — Returns an Axum router with `/`, `/api/stats`, `/api/sessions`, `/api/scan`, etc.

mod api;
mod state;

pub use api::build_router;
pub use state::AppState;

#[cfg(test)]
mod tests;
