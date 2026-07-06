//! RTF (Rich Text Format) analysis for embedded OLE exploit detection.
//!
//! Targets CVE-2026-21509: Microsoft Office trust bypass via malformed OLE
//! reconstructed from RTF \object / \objdata. See [APT28: Geofencing as a Targeting Signal](https://blog.synapticsystems.de/apt28-geofencing-as-a-targeting-signal-cve-2026-21509/).

mod analyzer;
mod ole;
mod parser;

pub use analyzer::analyze_rtf;
pub use ole::{list_ole_entries, is_malformed_ole, OleDirEntry, OleEntryType, OLE_SIGNATURE};
pub use parser::{extract_embedded_objects, extract_objdata_blobs, is_rtf, EmbeddedObject, RTF_PREFIX};
