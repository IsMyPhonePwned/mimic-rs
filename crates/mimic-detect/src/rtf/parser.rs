//! Minimal RTF parser to find embedded \object / \objdata and extract OLE blobs.
//! See CVE-2026-21509: malformed OLE in RTF triggers Office trust bypass.

/// RTF magic: document typically starts with "{\rtf" (optional BOM/whitespace).
pub const RTF_PREFIX: &[u8] = b"{\\rtf";
pub const RTF_PREFIX_ALT: &[u8] = b"{\r\n\\rtf";

const MAX_OBJDATA_DECODE: usize = 8 * 1024 * 1024;

/// Single embedded object: class name, kind (embed/ocx), raw payload.
#[derive(Debug, Clone, Default)]
pub struct EmbeddedObject {
    pub objclass: Option<String>,
    pub kind: String,
    pub data: Vec<u8>,
}

/// Check if data starts with RTF (after optional whitespace/BOM).
#[inline]
pub fn is_rtf(data: &[u8]) -> bool {
    let mut i = 0;
    while i < data.len() && (data[i] == b' ' || data[i] == b'\t' || data[i] == b'\r' || data[i] == b'\n') {
        i += 1;
    }
    if i + RTF_PREFIX.len() > data.len() {
        return false;
    }
    data[i..].starts_with(RTF_PREFIX) || (i + RTF_PREFIX_ALT.len() <= data.len() && data[i..].starts_with(RTF_PREFIX_ALT))
}

/// Extract embedded object data blobs from RTF.
///
/// Supports:
/// - `\\bin N <N bytes>` blocks (common in `\\objdata` groups)
/// - hex-encoded `\\objdata` payloads (pairs of hex digits, whitespace ignored)
///
/// Note: the returned blobs may contain OLE *inside* an OLE1 wrapper; callers should search
/// for `OLE_SIGNATURE` within the blob rather than assuming offset 0.
pub fn extract_objdata_blobs(data: &[u8]) -> Vec<Vec<u8>> {
    let mut blobs = Vec::new();

    // 1) Extract raw binary blocks.
    let mut i = 0;
    while i + 4 <= data.len() {
        if data[i] == b'\\' && &data[i..i + 4] == b"\\bin" {
            i += 4;
            while i < data.len() && (data[i] == b' ' || data[i] == b'\t') {
                i += 1;
            }
            let start = i;
            while i < data.len() && data[i].is_ascii_digit() {
                i += 1;
            }
            if i > start {
                let num_str = std::str::from_utf8(&data[start..i]).unwrap_or("");
                if let Ok(n) = num_str.parse::<usize>() {
                    while i < data.len() && (data[i] == b' ' || data[i] == b'\t') {
                        i += 1;
                    }
                    if n > 0 && i + n <= data.len() {
                        blobs.push(data[i..i + n].to_vec());
                    }
                    i += n;
                    continue;
                }
            }
        }
        i += 1;
    }

    // 2) Extract hex-encoded \\objdata payloads.
    i = 0;
    while i + 8 <= data.len() {
        if data[i] == b'\\' && &data[i..i + 8] == b"\\objdata" {
            i += 8;
            while i < data.len() && (data[i] == b' ' || data[i] == b'\t' || data[i] == b'\r' || data[i] == b'\n') {
                i += 1;
            }
            let mut out = Vec::new();
            while i < data.len() && out.len() < MAX_OBJDATA_DECODE {
                let c = data[i];
                if c == b'}' {
                    break;
                }
                if c == b'\\' {
                    // RTF escaped hex like \\'xx
                    if i + 4 <= data.len() && data[i + 1] == b'\'' {
                        let hi = from_hex(data[i + 2]);
                        let lo = from_hex(data[i + 3]);
                        if let (Some(hi), Some(lo)) = (hi, lo) {
                            out.push((hi << 4) | lo);
                        }
                        i += 4;
                        continue;
                    }
                    // Otherwise, it's a control word boundary; just skip it and keep scanning for hex pairs.
                    i += 1;
                    continue;
                }
                if c == b' ' || c == b'\t' || c == b'\r' || c == b'\n' {
                    i += 1;
                    continue;
                }
                if i + 1 < data.len() {
                    if let (Some(hi), Some(lo)) = (from_hex(data[i]), from_hex(data[i + 1])) {
                        out.push((hi << 4) | lo);
                        i += 2;
                        continue;
                    }
                }
                i += 1;
            }
            if !out.is_empty() {
                blobs.push(out);
            }
        } else {
            i += 1;
        }
    }

    blobs
}

/// Extract embedded objects with metadata (oleid-style): objclass, kind (embed/ocx), payload.
pub fn extract_embedded_objects(data: &[u8]) -> Vec<EmbeddedObject> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 7 <= data.len() {
        if data[i] == b'\\' && &data[i..i + 7] == b"\\object" {
            i += 7;
            let mut objclass: Option<String> = None;
            let mut kind = "embed".to_string();
            let mut depth = 0i32;
            while i < data.len() {
                if data[i] == b'{' {
                    depth += 1;
                    i += 1;
                    continue;
                }
                if data[i] == b'}' {
                    depth -= 1;
                    i += 1;
                    if depth < 0 {
                        break;
                    }
                    continue;
                }
                if data[i] == b'\\' {
                    if i + 8 <= data.len() && &data[i..i + 8] == b"\\objdata" {
                        i += 8;
                        while i < data.len() && (data[i] == b' ' || data[i] == b'\t' || data[i] == b'\r' || data[i] == b'\n') {
                            i += 1;
                        }
                        let blob = decode_objdata_payload(data, &mut i);
                        if !blob.is_empty() {
                            out.push(EmbeddedObject {
                                objclass: objclass.clone(),
                                kind: kind.clone(),
                                data: blob,
                            });
                        }
                        continue;
                    }
                    // Match \objclass or \objclass<space>; RTF uses \*\objclass Word.Document.8
                    if i + 9 <= data.len() && &data[i..i + 9] == b"\\objclass" {
                        i += 9;
                        while i < data.len() && (data[i] == b' ' || data[i] == b'\t') {
                            i += 1;
                        }
                        let start = i;
                        while i < data.len() && data[i] != b'}' && data[i] != b'\\' && data[i] != b' ' && data[i] != b'\t' && data[i] != b'\r' && data[i] != b'\n' {
                            i += 1;
                        }
                        let name = std::str::from_utf8(&data[start..i]).unwrap_or("").trim().to_string();
                        if !name.is_empty() {
                            objclass = Some(name);
                        }
                        continue;
                    }
                    if i + 7 <= data.len() && &data[i..i + 7] == b"\\objocx" && (i + 7 == data.len() || !data[i + 7].is_ascii_alphanumeric()) {
                        kind = "ocx".to_string();
                        i += 7;
                        continue;
                    }
                    if i + 6 <= data.len() && &data[i..i + 6] == b"\\objemb" && (i + 6 == data.len() || !data[i + 6].is_ascii_alphanumeric()) {
                        kind = "embed".to_string();
                        i += 6;
                        continue;
                    }
                }
                i += 1;
            }
            continue;
        }
        i += 1;
    }
    if out.is_empty() {
        let blobs = extract_objdata_blobs(data);
        for (_idx, blob) in blobs.into_iter().enumerate() {
            out.push(EmbeddedObject {
                objclass: None,
                kind: "embed".to_string(),
                data: blob,
            });
        }
    }
    out
}

fn decode_objdata_payload(data: &[u8], i: &mut usize) -> Vec<u8> {
    let mut out = Vec::new();
    if *i + 4 <= data.len() && &data[*i..*i + 4] == b"\\bin" {
        *i += 4;
        while *i < data.len() && (data[*i] == b' ' || data[*i] == b'\t') {
            *i += 1;
        }
        let start = *i;
        while *i < data.len() && data[*i].is_ascii_digit() {
            *i += 1;
        }
        if *i > start {
            let num_str = std::str::from_utf8(&data[start..*i]).unwrap_or("");
            if let Ok(n) = num_str.parse::<usize>() {
                while *i < data.len() && (data[*i] == b' ' || data[*i] == b'\t') {
                    *i += 1;
                }
                if n > 0 && *i + n <= data.len() {
                    out = data[*i..*i + n].to_vec();
                    *i += n;
                }
            }
        }
        return out;
    }
    while *i < data.len() && out.len() < MAX_OBJDATA_DECODE {
        let c = data[*i];
        if c == b'}' {
            break;
        }
        if c == b'\\' {
            if *i + 4 <= data.len() && data[*i + 1] == b'\'' {
                let hi = from_hex(data[*i + 2]);
                let lo = from_hex(data[*i + 3]);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi << 4) | lo);
                }
                *i += 4;
                continue;
            }
            *i += 1;
            continue;
        }
        if c == b' ' || c == b'\t' || c == b'\r' || c == b'\n' {
            *i += 1;
            continue;
        }
        if *i + 1 < data.len() {
            if let (Some(hi), Some(lo)) = (from_hex(data[*i]), from_hex(data[*i + 1])) {
                out.push((hi << 4) | lo);
                *i += 2;
                continue;
            }
        }
        *i += 1;
    }
    out
}

#[inline]
fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

