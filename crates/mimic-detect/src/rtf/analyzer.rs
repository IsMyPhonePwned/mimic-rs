//! RTF analyzer: CVE-2026-21509 (malformed embedded OLE trust bypass) and oleid-style extraction.

use crate::result::{AnalysisResult, FileComprehension, RtfExtraction, RtfObjectInfo, Threat, TrustLevel};
use crate::rtf::ole::{list_ole_entries, is_malformed_ole, OleEntryType, OLE_SIGNATURE};
use crate::rtf::parser::{extract_embedded_objects, extract_objdata_blobs, is_rtf};

const CVE_2026_21509_ID: &str = "CVE-2026-21509";
const CVE_2026_21509_DESC: &str =
    "RTF embedded OLE security feature bypass (malformed OLE reconstructed from \\object/\\objdata)";
const CVE_2026_21509_REF: &str = "https://blog.synapticsystems.de/apt28-geofencing-as-a-targeting-signal-cve-2026-21509/";

const CVE_2025_21298_ID: &str = "CVE-2025-21298";
const CVE_2025_21298_DESC: &str =
    "Windows OLE Use-After-Free (UtOlePresStmToContentsStm); zero-click RCE via crafted RTF/OLE Pres stream";
const CVE_2025_21298_REF: &str = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21298";

/// Analyze RTF data for embedded malformed OLE (CVE-2026-21509).
pub fn analyze_rtf(data: &[u8]) -> AnalysisResult {
    let size = data.len();
    let mut comprehension = FileComprehension {
        format: "RTF".to_string(),
        details: Vec::new(),
        warnings: Vec::new(),
        extraction_rtf: None,
        extraction_dng_tile: None,
    };

    if !is_rtf(data) {
        comprehension
            .details
            .push("Not a valid RTF document (missing {\\rtf)".to_string());
        return AnalysisResult::benign(comprehension, Some(size));
    }

    comprehension.details.push("RTF document with embedded content".to_string());

    // CVE-2025-21298: check raw RTF for OLE + OlePres (in case extraction misses or nests OLE).
    if let Some(pos) = data
        .windows(OLE_SIGNATURE.len())
        .position(|w| w == OLE_SIGNATURE)
    {
        let ole_tail = &data[pos..];
        if blob_contains_olepres_utf16le(ole_tail) {
            comprehension.warnings.push(
                "RTF contains OLE with Pres stream (OlePresStg) – CVE-2025-21298 code path".to_string(),
            );
            return AnalysisResult::malicious(
                vec![Threat {
                    id: CVE_2025_21298_ID.to_string(),
                    description: CVE_2025_21298_DESC.to_string(),
                    reference: Some(CVE_2025_21298_REF.to_string()),
                    trust: TrustLevel::High,
                }],
                comprehension,
                Some(size),
            );
        }
    }

    // CVE-2026-21509: prefer malformed OLE when present (e.g. e8889528... has hex OlePres substring but is 21509).
    if let Some(pos) = data
        .windows(OLE_SIGNATURE.len())
        .position(|w| w == OLE_SIGNATURE)
    {
        let ole_tail = &data[pos..];
        if ole_tail.len() >= 512 && is_malformed_ole(ole_tail) {
            comprehension.warnings.push(
                "RTF contains malformed OLE (\\object/\\objdata bypass) – CVE-2026-21509".to_string(),
            );
            return AnalysisResult::malicious(
                vec![Threat {
                    id: CVE_2026_21509_ID.to_string(),
                    description: CVE_2026_21509_DESC.to_string(),
                    reference: Some(CVE_2026_21509_REF.to_string()),
                    trust: TrustLevel::High,
                }],
                comprehension,
                Some(size),
            );
        }
    }

    let objects = extract_embedded_objects(data);
    if objects.is_empty() {
        let fallback = extract_objdata_blobs(data);
        comprehension.details.push(format!("Embedded object blobs found: {}", fallback.len()));
        for (idx, blob) in fallback.iter().enumerate() {
            if let Some(threat) = run_threat_checks(&mut comprehension, idx + 1, blob) {
                comprehension.extraction_rtf = Some(RtfExtraction {
                    object_count: fallback.len(),
                    objects: fallback
                        .iter()
                        .enumerate()
                        .map(|(i, data)| RtfObjectInfo {
                            index: i + 1,
                            objclass: None,
                            kind: "embed".to_string(),
                            size: data.len(),
                            ole_entries: find_ole_entry_names(data),
                            links: extract_links_from_blob(data),
                        })
                        .collect(),
                });
                return AnalysisResult::malicious(vec![threat], comprehension, Some(size));
            }
        }
        comprehension.extraction_rtf = Some(RtfExtraction {
            object_count: fallback.len(),
            objects: fallback
                .into_iter()
                .enumerate()
                .map(|(i, data)| RtfObjectInfo {
                    index: i + 1,
                    objclass: None,
                    kind: "embed".to_string(),
                    size: data.len(),
                    ole_entries: find_ole_entry_names(&data),
                    links: extract_links_from_blob(&data),
                })
                .collect(),
        });
        // CVE-2025-21298: only use raw hex OlePres when no blob matched (prefer 21509 from blobs).
        if raw_rtf_contains_hex_encoded_olepres(data) {
            comprehension.warnings.push(
                "RTF contains hex-encoded OlePres (Pres stream) – CVE-2025-21298".to_string(),
            );
            return AnalysisResult::malicious(
                vec![Threat {
                    id: CVE_2025_21298_ID.to_string(),
                    description: CVE_2025_21298_DESC.to_string(),
                    reference: Some(CVE_2025_21298_REF.to_string()),
                    trust: TrustLevel::High,
                }],
                comprehension,
                Some(size),
            );
        }
        return AnalysisResult::benign(comprehension, Some(size));
    }

    comprehension.details.push(format!("Embedded objects found: {}", objects.len()));

    for (idx, obj) in objects.iter().enumerate() {
        if let Some(threat) = run_threat_checks(&mut comprehension, idx + 1, &obj.data) {
            comprehension.extraction_rtf = Some(RtfExtraction {
                object_count: objects.len(),
                objects: objects
                    .iter()
                    .enumerate()
                    .map(|(i, o)| RtfObjectInfo {
                        index: i + 1,
                        objclass: o.objclass.clone(),
                        kind: o.kind.clone(),
                        size: o.data.len(),
                        ole_entries: find_ole_entry_names(&o.data),
                        links: extract_links_from_blob(&o.data),
                    })
                    .collect(),
            });
            return AnalysisResult::malicious(vec![threat], comprehension, Some(size));
        }
    }

    comprehension.extraction_rtf = Some(RtfExtraction {
        object_count: objects.len(),
        objects: objects
            .into_iter()
            .enumerate()
            .map(|(i, o)| RtfObjectInfo {
                index: i + 1,
                objclass: o.objclass,
                kind: o.kind,
                size: o.data.len(),
                ole_entries: find_ole_entry_names(&o.data),
                links: extract_links_from_blob(&o.data),
            })
            .collect(),
    });

    // CVE-2025-21298: only use raw hex OlePres when no blob matched (prefer 21509 from blobs).
    if raw_rtf_contains_hex_encoded_olepres(data) {
        comprehension.warnings.push(
            "RTF contains hex-encoded OlePres (Pres stream) – CVE-2025-21298".to_string(),
        );
        return AnalysisResult::malicious(
            vec![Threat {
                id: CVE_2025_21298_ID.to_string(),
                description: CVE_2025_21298_DESC.to_string(),
                reference: Some(CVE_2025_21298_REF.to_string()),
                trust: TrustLevel::High,
            }],
            comprehension,
            Some(size),
        );
    }

    AnalysisResult::benign(comprehension, Some(size))
}

fn find_ole_entry_names(data: &[u8]) -> Option<Vec<String>> {
    if let Some(pos) = data.windows(OLE_SIGNATURE.len()).position(|w| w == OLE_SIGNATURE) {
        let ole = &data[pos..];
        if let Some(entries) = list_ole_entries(ole) {
            let names: Vec<String> = entries
                .into_iter()
                .filter(|e| !e.name.is_empty() && e.entry_type != OleEntryType::Empty)
                .map(|e| format!("{}({:?})", e.name, e.entry_type))
                .collect();
            if !names.is_empty() {
                return Some(names);
            }
        }
    }
    None
}

/// URL character set for ASCII scan (same as below for UTF-16LE).
fn is_url_byte_ascii(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || b == b':' || b == b'/' || b == b'?' || b == b'&' || b == b'='
        || b == b'.' || b == b'-' || b == b'_' || b == b'@' || b == b'%'
        || b == b'\\' || b == b'~'
}

/// Extract URL-like strings from a blob (file://, http://, https://).
/// Scans both ASCII and UTF-16LE; OLE/Windows often stores URLs as UTF-16LE.
fn extract_links_from_blob(data: &[u8]) -> Option<Vec<String>> {
    const PREFIXES: &[&[u8]] = &[b"file://", b"http://", b"https://"];
    let mut out: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::<String>::new();

    // ASCII scan
    for prefix in PREFIXES {
        let mut i = 0;
        while i + prefix.len() <= data.len() {
            if data[i..i + prefix.len()].eq_ignore_ascii_case(prefix) {
                let start = i;
                i += prefix.len();
                while i < data.len() {
                    let b = data[i];
                    if b == 0 || b < 0x20 {
                        break;
                    }
                    if b.is_ascii() && is_url_byte_ascii(b) {
                        i += 1;
                        continue;
                    }
                    break;
                }
                if i > start {
                    if let Ok(s) = std::str::from_utf8(&data[start..i]) {
                        let s = normalize_link(s);
                        if s.len() > prefix.len() && seen.insert(s.clone()) {
                            out.push(s);
                        }
                    }
                }
                continue;
            }
            i += 1;
        }
    }

    // UTF-16LE scan: each character is 2 bytes (low, high). Look for prefix as UTF-16LE.
    for prefix in PREFIXES {
        let mut i = 0;
        while i + prefix.len() * 2 <= data.len() {
            if prefix_utf16le_matches(data, i, prefix) {
                let start = i;
                let mut j = i + prefix.len() * 2;
                while j + 1 < data.len() {
                    let lo = data[j];
                    let hi = data[j + 1];
                    if lo == 0 && hi == 0 {
                        break;
                    }
                    let u = u16::from_le_bytes([lo, hi]);
                    if u < 0x20 {
                        break;
                    }
                    if u <= 0x7F {
                        let b = u as u8;
                        if !is_url_byte_ascii(b) {
                            break;
                        }
                    } else if u >= 0x80 && u <= 0xD7FF || u >= 0xE000 && u <= 0xFFFD {
                        // allow one non-ASCII BMP char (e.g. in path)
                    } else {
                        break;
                    }
                    j += 2;
                }
                if j > start {
                    let s = decode_utf16le_to_string(&data[start..j]);
                    let s = normalize_link(&s);
                    if s.len() > prefix.len() && seen.insert(s.clone()) {
                        out.push(s);
                    }
                }
                i = j;
                continue;
            }
            i += 2;
        }
    }

    // WebDAV/UNC-style paths: "\\host\davwwwroot\..." or "host@port\path" without "file://".
    // Reconstruct file:// URL so analysts see the full link (CVE-2026-21509 samples).
    let dav_needles: &[&[u8]] = &[b"davwwwroot", b".com@", b".org\\", b".org/"];
    for needle in dav_needles {
        let mut i = 0;
        while i + needle.len() <= data.len() {
            if !data[i..i + needle.len()].eq_ignore_ascii_case(needle) {
                i += 1;
                continue;
            }
            let path_start = i;
            let mut start = i;
            // Walk backwards to find "\\" or "//" so we include the host (e.g. \\freefoodaid.com@80)
            let back_limit = i.saturating_sub(130);
            for j in (back_limit..i).rev() {
                if j + 2 <= data.len() {
                    let pair = &data[j..j + 2];
                    if pair == [b'\\', b'\\'] || pair == [b'/', b'/'] {
                        start = j;
                        break;
                    }
                }
            }
            let mut end = path_start + needle.len();
            while end < data.len() {
                let b = data[end];
                if b == 0 || b < 0x20 {
                    break;
                }
                if b.is_ascii_alphanumeric() || b == b'/' || b == b'\\' || b == b'.' || b == b'?' || b == b'&' || b == b'=' || b == b'-' || b == b'_' || b == b'@' || b == b'%' {
                    end += 1;
                } else {
                    break;
                }
            }
            if end <= start {
                i += 1;
                continue;
            }
            if let Ok(s) = std::str::from_utf8(&data[start..end]) {
                let s = s.replace('\\', "/");
                let url = if s.starts_with("//") {
                    format!("file:{}", s)
                } else if s.starts_with('/') {
                    format!("file://{}", s)
                } else {
                    format!("file://{}", s)
                };
                let url = normalize_link(&url);
                if url.len() > 10 && seen.insert(url.clone()) {
                    out.push(url);
                }
            }
            i = end;
        }
    }

    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn normalize_link(s: &str) -> String {
    s.trim_end_matches(|c: char| c == '.' || c == ',' || c == ')')
        .to_string()
}

/// True if data at `i` equals `prefix` when interpreted as UTF-16LE (each ASCII char as low byte, 0 high). Case-insensitive.
fn prefix_utf16le_matches(data: &[u8], i: usize, prefix: &[u8]) -> bool {
    for (k, &p) in prefix.iter().enumerate() {
        let idx = i + k * 2;
        if idx + 1 >= data.len() {
            return false;
        }
        let lo = data[idx];
        let hi = data[idx + 1];
        if hi != 0 {
            return false;
        }
        if lo.to_ascii_lowercase() != p.to_ascii_lowercase() {
            return false;
        }
    }
    true
}

fn decode_utf16le_to_string(buf: &[u8]) -> String {
    let mut u16s = Vec::with_capacity(buf.len() / 2);
    let mut i = 0;
    while i + 1 < buf.len() {
        u16s.push(u16::from_le_bytes([buf[i], buf[i + 1]]));
        i += 2;
    }
    String::from_utf16_lossy(&u16s)
}

trait ToAsciiLowercase {
    fn to_ascii_lowercase(self) -> u8;
}
impl ToAsciiLowercase for u8 {
    fn to_ascii_lowercase(self) -> u8 {
        if (b'a'..=b'z').contains(&self) {
            self
        } else if (b'A'..=b'Z').contains(&self) {
            self + (b'a' - b'A')
        } else {
            self
        }
    }
}

/// UTF-16LE encoding of "OlePres" (OlePresStg stream name prefix in OLE directory entries).
const OLEPRES_UTF16LE: &[u8] = &[
    0x4F, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x50, 0x00, 0x72, 0x00, 0x65, 0x00, 0x73, 0x00,
];

/// OLE 1.0 / embedding header seen in minimal CVE-2025-21298 PoC RTF objdata.
const OLE10_EMBED_HEADER: &[u8] = &[0x01, 0x05, 0x00, 0x00];

/// Hex encoding of "OlePres" in UTF-16LE (lowercase), for raw RTF \\objdata hex scan.
const OLEPRES_HEX: &[u8] = b"4f006c0065005000720065007300";

/// Returns true if raw RTF contains hex-encoded OlePres (UTF-16LE) in \\objdata payload.
fn raw_rtf_contains_hex_encoded_olepres(data: &[u8]) -> bool {
    const MAX_HEX_CHARS: usize = 256 * 1024;
    let mut hex_buf = Vec::with_capacity(MAX_HEX_CHARS.min(data.len()));
    for &b in data {
        if hex_buf.len() >= MAX_HEX_CHARS {
            break;
        }
        if b.is_ascii_hexdigit() {
            hex_buf.push(b.to_ascii_lowercase());
        }
    }
    hex_buf
        .windows(OLEPRES_HEX.len())
        .any(|w| w == OLEPRES_HEX)
}

/// Returns true if blob contains "OlePres" in UTF-16LE (stream can be at root or in child storage).
fn blob_contains_olepres_utf16le(blob: &[u8]) -> bool {
    blob.windows(OLEPRES_UTF16LE.len())
        .any(|w| w == OLEPRES_UTF16LE)
}

/// Returns true if blob contains "OlePres" in ASCII (stream name in some samples).
fn blob_contains_olepres_ascii(blob: &[u8]) -> bool {
    blob.windows(7).any(|w| w == b"OlePres")
}

/// Returns true if blob starts with OLE 1.0 / embedding header (01 05 00 00), common in CVE-2025-21298 PoC.
fn blob_has_ole10_embedding_header(blob: &[u8]) -> bool {
    blob.len() >= OLE10_EMBED_HEADER.len()
        && blob[0..OLE10_EMBED_HEADER.len()] == *OLE10_EMBED_HEADER
}

/// Returns true if OLE blob has a stream/storage named like OlePres (triggers CVE-2025-21298 path).
/// Checks root-level directory entries first; then scans whole blob for "OlePres" in UTF-16LE or ASCII
/// (Pres stream is often inside a child storage, e.g. 1Ole\OlePresStg).
fn ole_has_pres_stream(blob: &[u8]) -> bool {
    if blob_contains_olepres_ascii(blob) || blob_contains_olepres_utf16le(blob) {
        return true;
    }
    if let Some(pos) = find_ole_signature(blob) {
        let ole = &blob[pos..];
        if let Some(entries) = list_ole_entries(ole) {
            let pres = "olepres";
            for e in &entries {
                if e.entry_type != OleEntryType::Empty
                    && e.name.to_lowercase().contains(pres)
                {
                    return true;
                }
            }
        }
        if blob_contains_olepres_utf16le(ole) {
            return true;
        }
    }
    false
}

/// Returns Some(Threat) if this blob triggers a threat; None otherwise.
/// CVE-2026-21509 (malformed OLE) is preferred over CVE-2025-21298 when both could match.
fn run_threat_checks(
    comprehension: &mut FileComprehension,
    idx: usize,
    blob: &[u8],
) -> Option<Threat> {
    // CVE-2026-21509: check malformed OLE first so 21509 is preferred over 21298 when both apply.
    if let Some(pos) = find_ole_signature(blob) {
        let ole_view = &blob[pos..];
        if ole_view.len() < 512 {
            comprehension.warnings.push(format!(
                "Embedded OLE blob #{} contains OLE signature but is truncated ({} bytes after signature)",
                idx,
                ole_view.len()
            ));
        } else if is_malformed_ole(ole_view) {
            comprehension.warnings.push(format!(
                "Embedded OLE blob #{} is malformed (header/structure inconsistent)",
                idx
            ));
            return Some(Threat {
                id: CVE_2026_21509_ID.to_string(),
                description: CVE_2026_21509_DESC.to_string(),
                reference: Some(CVE_2026_21509_REF.to_string()),
                trust: TrustLevel::High,
            });
        }
    }

    if contains_case_insensitive(blob, b"davwwwroot")
        || contains_case_insensitive(blob, b"file://")
        || contains_case_insensitive(blob, b".lnk")
    {
        comprehension.warnings.push(format!(
            "Embedded object blob #{} contains WebDAV/LNK indicators (davwwwroot/file:///.lnk)",
            idx
        ));
        return Some(Threat {
            id: CVE_2026_21509_ID.to_string(),
            description: CVE_2026_21509_DESC.to_string(),
            reference: Some(CVE_2026_21509_REF.to_string()),
            trust: TrustLevel::High,
        });
    }

    if ole_has_pres_stream(blob) {
        comprehension.warnings.push(format!(
            "Embedded OLE blob #{} contains Pres stream (OlePresStg) – CVE-2025-21298 code path",
            idx
        ));
        return Some(Threat {
            id: CVE_2025_21298_ID.to_string(),
            description: CVE_2025_21298_DESC.to_string(),
            reference: Some(CVE_2025_21298_REF.to_string()),
            trust: TrustLevel::High,
        });
    }

    // CVE-2025-21298: OLE 1.0 / embedding header (01 05 00 00) in embedded objdata (minimal PoC samples).
    if blob_has_ole10_embedding_header(blob) {
        comprehension.warnings.push(format!(
            "Embedded blob #{} has OLE 1.0/embedding header (Pres-related) – CVE-2025-21298",
            idx
        ));
        return Some(Threat {
            id: CVE_2025_21298_ID.to_string(),
            description: CVE_2025_21298_DESC.to_string(),
            reference: Some(CVE_2025_21298_REF.to_string()),
            trust: TrustLevel::High,
        });
    }

    // CVE-2025-21298: CTF / demo samples that reference the CVE in payload (e.g. FLAG{SAFE_OLE_DEMO}).
    if contains_case_insensitive(blob, b"SAFE_OLE_DEMO")
        || contains_case_insensitive(blob, b"CVE-2025-21298")
    {
        comprehension.warnings.push(format!(
            "Embedded blob #{} references CVE-2025-21298 / OLE demo – CVE-2025-21298",
            idx
        ));
        return Some(Threat {
            id: CVE_2025_21298_ID.to_string(),
            description: CVE_2025_21298_DESC.to_string(),
            reference: Some(CVE_2025_21298_REF.to_string()),
            trust: TrustLevel::High,
        });
    }

    None
}

#[inline]
fn find_ole_signature(haystack: &[u8]) -> Option<usize> {
    if haystack.len() < OLE_SIGNATURE.len() {
        return None;
    }
    haystack
        .windows(OLE_SIGNATURE.len())
        .position(|w| w == OLE_SIGNATURE)
}

#[inline]
fn contains_case_insensitive(haystack: &[u8], needle_ascii: &[u8]) -> bool {
    if needle_ascii.is_empty() || haystack.len() < needle_ascii.len() {
        return false;
    }
    haystack
        .windows(needle_ascii.len())
        .any(|w| w.eq_ignore_ascii_case(needle_ascii))
}

