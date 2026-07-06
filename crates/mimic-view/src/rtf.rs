//! RTF structure parser for the hex inspector.

use crate::Node;

const OLE_SIG: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const OLEPRES_UTF16: [u8; 14] = [
    0x4F, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x50, 0x00, 0x72, 0x00, 0x65, 0x00, 0x73, 0x00,
];

pub fn parse(data: &[u8]) -> Vec<Node> {
    let mut nodes = Vec::new();
    let len = data.len();
    if len < 5 {
        return nodes;
    }

    // Header
    let mut header_end = 5;
    while header_end < len
        && data[header_end] != b' '
        && data[header_end] != b'\\'
        && data[header_end] != b'{'
        && data[header_end] != b'}'
    {
        header_end += 1;
    }
    nodes.push(Node {
        kind: "header".into(),
        label: "RTF Header".into(),
        detail: ascii(data, 0, header_end.min(20)),
        start: 0,
        end: header_end,
    });

    let mut i = 1usize;
    while i < len {
        if data[i] == b'\\' {
            if starts(data, i, b"\\object") {
                nodes.push(Node {
                    kind: "object".into(),
                    label: "\\object".into(),
                    detail: "Embedded object declaration".into(),
                    start: i,
                    end: (i + 8).min(len),
                });
                i += 7;
                continue;
            }
            if starts(data, i, b"\\objclass") {
                let s = i;
                i += 9;
                skip_ws(data, &mut i);
                let ns = i;
                while i < len
                    && data[i] != b'}'
                    && data[i] != b'\\'
                    && data[i] != b' '
                    && data[i] != b'\r'
                    && data[i] != b'\n'
                {
                    i += 1;
                }
                nodes.push(Node {
                    kind: "control".into(),
                    label: "\\objclass".into(),
                    detail: ascii(data, ns, i),
                    start: s,
                    end: i,
                });
                continue;
            }
            if starts(data, i, b"\\objdata") {
                let s = i;
                i += 8;
                skip_ws(data, &mut i);
                let ps = i;
                while i < len && data[i] != b'}' {
                    if i + 8 <= len && data[i..i + 8] == OLE_SIG {
                        if !nodes.iter().any(|n| n.kind == "ole" && n.start == i) {
                            nodes.push(Node {
                                kind: "ole".into(),
                                label: "OLE Signature".into(),
                                detail: "D0 CF 11 E0 A1 B1 1A E1".into(),
                                start: i,
                                end: i + 8,
                            });
                        }
                    }
                    i += 1;
                }
                nodes.push(Node {
                    kind: "data".into(),
                    label: "\\objdata".into(),
                    detail: format!("Payload: {} bytes", i - ps),
                    start: s,
                    end: i,
                });
                continue;
            }
            if starts(data, i, b"\\bin") {
                let s = i;
                i += 4;
                skip_ws(data, &mut i);
                let ns = i;
                while i < len && data[i].is_ascii_digit() {
                    i += 1;
                }
                let n: usize = ascii(data, ns, i).parse().unwrap_or(0);
                nodes.push(Node {
                    kind: "control".into(),
                    label: "\\bin".into(),
                    detail: format!("{} bytes binary", n),
                    start: s,
                    end: (i + n).min(len),
                });
                i += n;
                continue;
            }
            for (kw, desc) in [
                (&b"\\objemb"[..], "Object type: embedded"),
                (b"\\objocx", "Object type: OCX/ActiveX"),
                (b"\\fonttbl", "Font table"),
                (b"\\colortbl", "Color table"),
                (b"\\stylesheet", "Style sheet"),
                (b"\\info", "Document info"),
                (b"\\pard", "Paragraph default"),
                (b"\\header", "Header group"),
                (b"\\footer", "Footer group"),
            ] {
                if starts(data, i, kw) {
                    nodes.push(Node {
                        kind: "control".into(),
                        label: ascii(data, i, i + kw.len()),
                        detail: desc.into(),
                        start: i,
                        end: i + kw.len(),
                    });
                    i += kw.len();
                    continue;
                }
            }
            // Generic control word
            let cs = i;
            i += 1;
            if i < len && data[i] == b'*' {
                i += 1;
            }
            while i < len && data[i].is_ascii_alphabetic() {
                i += 1;
            }
            while i < len && (data[i].is_ascii_digit() || data[i] == b'-') {
                i += 1;
            }
            if i < len && data[i] == b' ' {
                i += 1;
            }
            if i - cs > 2 && i - cs < 30 {
                let word = ascii(data, cs, i).trim().to_string();
                if word.len() > 1 && word.starts_with('\\') {
                    nodes.push(Node {
                        kind: "control".into(),
                        label: word,
                        detail: String::new(),
                        start: cs,
                        end: i,
                    });
                    continue;
                }
            }
            i = cs + 1;
            continue;
        }
        if data[i] == b'{' || data[i] == b'}' {
            i += 1;
            continue;
        }
        // Text run
        let ts = i;
        while i < len && data[i] != b'\\' && data[i] != b'{' && data[i] != b'}' {
            i += 1;
        }
        if i > ts {
            let preview = ascii(data, ts, ts + (i - ts).min(80))
                .replace(|c: char| c.is_control(), "")
                .trim()
                .to_string();
            if !preview.is_empty() {
                let detail = if preview.len() > 60 {
                    format!("{}…", &preview[..60])
                } else {
                    preview
                };
                nodes.push(Node {
                    kind: "text".into(),
                    label: "Text".into(),
                    detail,
                    start: ts,
                    end: i,
                });
            }
        }
    }

    // Scan for OLE signatures not already covered
    for j in 0..len.saturating_sub(7) {
        if data[j..j + 8] == OLE_SIG && !nodes.iter().any(|n| n.kind == "ole" && n.start == j) {
            nodes.push(Node {
                kind: "ole".into(),
                label: "OLE Signature".into(),
                detail: "D0 CF 11 E0 A1 B1 1A E1".into(),
                start: j,
                end: j + 8,
            });
        }
    }

    // OlePres (CVE-2025-21298)
    for j in 0..len.saturating_sub(OLEPRES_UTF16.len() - 1) {
        if j + OLEPRES_UTF16.len() <= len && data[j..j + OLEPRES_UTF16.len()] == OLEPRES_UTF16 {
            nodes.push(Node {
                kind: "warning".into(),
                label: "OlePres stream".into(),
                detail: "CVE-2025-21298 trigger (OlePresStg)".into(),
                start: j,
                end: j + OLEPRES_UTF16.len(),
            });
        }
    }

    nodes
}

fn starts(data: &[u8], offset: usize, pattern: &[u8]) -> bool {
    offset + pattern.len() <= data.len() && data[offset..offset + pattern.len()] == *pattern
}

fn skip_ws(data: &[u8], i: &mut usize) {
    while *i < data.len() && matches!(data[*i], b' ' | b'\t' | b'\r' | b'\n') {
        *i += 1;
    }
}

fn ascii(data: &[u8], start: usize, end: usize) -> String {
    String::from_utf8_lossy(&data[start..end.min(data.len())]).into_owned()
}
