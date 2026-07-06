//! TTF/OTF analysis for CVE-2023-41990 (Operation Triangulation – ADJUST instruction).
//! See https://github.com/msuiche/elegant-bouncer/blob/main/src/ttf.rs

mod analyzer;
mod bytecode;
mod parser;

pub use analyzer::analyze_ttf;
pub use parser::{get_table, is_ttf, table_bytes, TtfTable};
