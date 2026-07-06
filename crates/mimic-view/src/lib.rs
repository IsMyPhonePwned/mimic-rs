//! # mimic-view
//!
//! File format structure parser for the Mimic hex inspector.
//! Parses RTF, PDF, and DNG/TIFF files and returns a list of annotated
//! structure nodes (offset, length, type, label, detail) as JSON.
//! Compiles to WASM for use in the browser inspector page.

pub mod rtf;
pub mod pdf;
pub mod dng;
pub mod pe;
pub mod elf;
pub mod archive;
#[cfg(test)]
mod tests;

use serde::Serialize;
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, Serialize)]
pub struct Node {
    #[serde(rename = "t")]
    pub kind: String,
    #[serde(rename = "l")]
    pub label: String,
    #[serde(rename = "d")]
    pub detail: String,
    #[serde(rename = "s")]
    pub start: usize,
    #[serde(rename = "e")]
    pub end: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct InspectResult {
    pub format: String,
    pub nodes: Vec<Node>,
}

pub fn detect_format(data: &[u8]) -> &'static str {
    if data.len() >= 5 && &data[..5] == b"{\\rtf" {
        return "rtf";
    }
    if data.len() >= 4 && &data[..4] == b"%PDF" {
        return "pdf";
    }
    if data.len() >= 4
        && ((data[0] == 0x49 && data[1] == 0x49) || (data[0] == 0x4D && data[1] == 0x4D))
    {
        let magic = if data[0] == 0x49 {
            u16::from_le_bytes([data[2], data[3]])
        } else {
            u16::from_be_bytes([data[2], data[3]])
        };
        if magic == 0x002A {
            return "dng";
        }
    }
    if data.len() >= 64 && data[0] == 0x4D && data[1] == 0x5A {
        let pe_off = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
        if pe_off + 4 <= data.len() && &data[pe_off..pe_off + 4] == b"PE\0\0" {
            return "pe";
        }
    }
    if data.len() >= 4 && data[0] == 0x7F && data[1] == b'E' && data[2] == b'L' && data[3] == b'F' {
        return "elf";
    }
    if data.len() >= 4 && data[0] == 0x50 && data[1] == 0x4B
        && (data[2] == 0x03 && data[3] == 0x04
            || data[2] == 0x01 && data[3] == 0x02
            || data[2] == 0x05 && data[3] == 0x06)
    {
        return "zip";
    }
    if data.len() >= 8 && &data[0..8] == b"Rar!\x1A\x07\x01\x00" {
        return "rar";
    }
    if data.len() >= 7 && &data[0..7] == b"Rar!\x1A\x07\x00" {
        return "rar";
    }
    "unknown"
}

pub fn inspect(data: &[u8]) -> InspectResult {
    let format = detect_format(data);
    let mut nodes = match format {
        "rtf" => rtf::parse(data),
        "pdf" => pdf::parse(data),
        "dng" => dng::parse(data),
        "pe" => pe::parse(data),
        "elf" => elf::parse(data),
        "zip" => archive::parse_zip(data),
        "rar" => archive::parse_rar(data),
        _ => Vec::new(),
    };
    nodes.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    InspectResult {
        format: format.to_string(),
        nodes,
    }
}

/// WASM entry: takes file bytes, returns JSON string with format + nodes.
#[wasm_bindgen(js_name = inspectFile)]
pub fn inspect_file(data: &[u8]) -> String {
    let result = inspect(data);
    serde_json::to_string(&result).unwrap_or_else(|_| r#"{"format":"error","nodes":[]}"#.into())
}
