//! PDF analysis: Adobe Acrobat JavaScript exploit heuristics (EXPMON 328131 / Haifei Li 2026).
//! CVE-2023-41990 and Operation Triangulation are primarily associated with TTF (iMessage).

mod analyzer;

pub use analyzer::{analyze_pdf, is_pdf};
