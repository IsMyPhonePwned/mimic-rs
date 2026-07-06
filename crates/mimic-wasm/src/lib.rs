//! # mimic-wasm
//!
//! WASM plugin system for Mimic. Load `.wasm` modules that export a
//! **`scan(ptr: i32, len: i32) -> i32`** function. The host copies file bytes
//! into the guest's linear memory; the guest returns **0** = clean,
//! **1** = suspicious, **2** = infected.
//!
//! - **WasmPluginEngine** — Load plugins from paths ([`load_file`](loader::WasmPluginEngine::load_file), [`load_dir`](loader::WasmPluginEngine::load_dir)), then [`scan`](loader::WasmPluginEngine::scan) file bytes; verdicts are merged (infected > suspicious > clean).
//! - **PluginVerdict** — Enum matching the guest convention; [`from_i32`](abi::PluginVerdict::from_i32) normalizes invalid values to clean.

mod abi;
mod loader;

pub use abi::PluginVerdict;
pub use loader::{WasmPlugin, WasmPluginEngine};

#[cfg(test)]
mod tests;
