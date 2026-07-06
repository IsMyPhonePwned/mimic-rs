//! PDF structure parser for the hex inspector.

use crate::Node;

pub fn parse(data: &[u8]) -> Vec<Node> {
    let mut nodes = Vec::new();
    let len = data.len();
    if len < 8 {
        return nodes;
    }

    // Header: %PDF-X.Y
    let hdr_end = find_line_end(data, 0);
    nodes.push(Node {
        kind: "header".into(),
        label: "PDF Header".into(),
        detail: ascii(data, 0, hdr_end.min(20)),
        start: 0,
        end: hdr_end,
    });

    // Binary comment (common second line with high bytes)
    if hdr_end < len && data[hdr_end] == b'%' {
        let ce = find_line_end(data, hdr_end);
        let has_high = data[hdr_end..ce].iter().any(|&b| b > 127);
        if has_high {
            nodes.push(Node {
                kind: "header".into(),
                label: "Binary hint".into(),
                detail: format!("{} bytes", ce - hdr_end),
                start: hdr_end,
                end: ce,
            });
        }
    }

    let mut i = hdr_end;
    while i < len {
        // %%EOF
        if starts(data, i, b"%%EOF") {
            let end = find_line_end(data, i);
            nodes.push(Node {
                kind: "header".into(),
                label: "%%EOF".into(),
                detail: "End of file marker".into(),
                start: i,
                end,
            });
            i = end;
            continue;
        }

        // Objects: N G obj ... endobj
        if let Some((num, gen, obj_s)) = try_parse_obj_start(data, i) {
            if let Some(obj_e) = find_endobj(data, obj_s) {
                let label = format!("{} {} obj", num, gen);
                let body = &data[obj_s..obj_e];

                let detail = describe_obj_body(body);

                nodes.push(Node {
                    kind: "object".into(),
                    label,
                    detail: detail.clone(),
                    start: i,
                    end: obj_e,
                });

                // Streams inside object
                if let Some(stream_off) = find_stream(data, obj_s, obj_e) {
                    let stream_end = find_endstream(data, stream_off, obj_e);
                    let slen = stream_end - stream_off;
                    nodes.push(Node {
                        kind: "stream".into(),
                        label: "stream".into(),
                        detail: format!("{} bytes", slen),
                        start: stream_off,
                        end: stream_end,
                    });
                }

                // Security warnings
                check_obj_warnings(body, i, obj_e, &mut nodes);

                i = obj_e;
                continue;
            }
        }

        // xref table
        if starts(data, i, b"xref") {
            let end = find_trailer_or_end(data, i);
            nodes.push(Node {
                kind: "xref".into(),
                label: "xref".into(),
                detail: format!("{} bytes", end - i),
                start: i,
                end,
            });
            i = end;
            continue;
        }

        // trailer
        if starts(data, i, b"trailer") {
            let end = find_line_end(data, i);
            let te = find_after_trailer(data, i, len);
            nodes.push(Node {
                kind: "xref".into(),
                label: "trailer".into(),
                detail: format!("{} bytes", te - i),
                start: i,
                end: te,
            });
            i = te;
            let _ = end;
            continue;
        }

        // startxref
        if starts(data, i, b"startxref") {
            let end = find_after_startxref(data, i, len);
            nodes.push(Node {
                kind: "xref".into(),
                label: "startxref".into(),
                detail: ascii(data, i, end).trim().to_string(),
                start: i,
                end,
            });
            i = end;
            continue;
        }

        i += 1;
    }

    nodes
}

fn try_parse_obj_start(data: &[u8], pos: usize) -> Option<(u32, u32, usize)> {
    let len = data.len();
    if pos >= len || !data[pos].is_ascii_digit() {
        return None;
    }
    let mut i = pos;
    while i < len && data[i].is_ascii_digit() {
        i += 1;
    }
    let num: u32 = ascii(data, pos, i).parse().ok()?;
    skip_ws_range(data, &mut i, len);
    let gs = i;
    while i < len && data[i].is_ascii_digit() {
        i += 1;
    }
    if i == gs {
        return None;
    }
    let gen: u32 = ascii(data, gs, i).parse().ok()?;
    skip_ws_range(data, &mut i, len);
    if !starts(data, i, b"obj") {
        return None;
    }
    i += 3;
    // After "obj" there should be whitespace or <<
    if i < len && !matches!(data[i], b' ' | b'\t' | b'\r' | b'\n' | b'<') {
        return None;
    }
    Some((num, gen, i))
}

fn find_endobj(data: &[u8], from: usize) -> Option<usize> {
    let needle = b"endobj";
    for i in from..data.len().saturating_sub(needle.len() - 1) {
        if starts(data, i, needle) {
            let e = i + needle.len();
            return Some(find_line_end(data, e));
        }
    }
    None
}

fn find_stream(data: &[u8], obj_start: usize, obj_end: usize) -> Option<usize> {
    let needle = b"stream";
    for i in obj_start..obj_end.saturating_sub(needle.len() - 1) {
        if starts(data, i, needle) && (i + 6 >= obj_end || !data[i + 6].is_ascii_alphabetic()) {
            let mut s = i + 6;
            if s < obj_end && data[s] == b'\r' {
                s += 1;
            }
            if s < obj_end && data[s] == b'\n' {
                s += 1;
            }
            return Some(s);
        }
    }
    None
}

fn find_endstream(data: &[u8], stream_start: usize, obj_end: usize) -> usize {
    let needle = b"endstream";
    for i in stream_start..obj_end.saturating_sub(needle.len() - 1) {
        if starts(data, i, needle) {
            return i;
        }
    }
    obj_end
}

fn describe_obj_body(body: &[u8]) -> String {
    let upper = body.len().min(512);
    let slice = &body[..upper];
    let text = String::from_utf8_lossy(slice);
    let mut parts = Vec::new();

    if text.contains("/Type") {
        if let Some(tp) = extract_name(&text, "/Type") {
            parts.push(format!("Type={}", tp));
        }
    }
    if text.contains("/Subtype") {
        if let Some(st) = extract_name(&text, "/Subtype") {
            parts.push(format!("Subtype={}", st));
        }
    }
    if text.contains("/Filter") {
        if let Some(f) = extract_name(&text, "/Filter") {
            parts.push(format!("Filter={}", f));
        }
    }
    if text.contains("/Length") {
        if let Some(l) = extract_number(&text, "/Length") {
            parts.push(format!("Length={}", l));
        }
    }

    if parts.is_empty() {
        let preview = text.trim().chars().take(60).collect::<String>();
        format!("{}", preview.replace('\n', " ").replace('\r', ""))
    } else {
        parts.join(", ")
    }
}

fn check_obj_warnings(body: &[u8], start: usize, end: usize, nodes: &mut Vec<Node>) {
    let text = String::from_utf8_lossy(&body[..body.len().min(2048)]);
    let checks: &[(&str, &str)] = &[
        ("/JavaScript", "Contains /JavaScript action"),
        ("/JS", "Contains /JS action"),
        ("/OpenAction", "Contains /OpenAction (auto-exec)"),
        ("/AA", "Contains /AA (additional actions)"),
        ("/Launch", "Contains /Launch action"),
        ("/EmbeddedFile", "Embeds external file"),
        ("/RichMedia", "Contains /RichMedia"),
        ("/XFA", "Contains /XFA (XML Forms)"),
    ];
    for (kw, desc) in checks {
        if text.contains(kw) {
            nodes.push(Node {
                kind: "warning".into(),
                label: (*kw).to_string(),
                detail: (*desc).to_string(),
                start,
                end,
            });
        }
    }
}

fn find_trailer_or_end(data: &[u8], from: usize) -> usize {
    let needle = b"trailer";
    for i in from..data.len().saturating_sub(needle.len() - 1) {
        if starts(data, i, needle) {
            return i;
        }
    }
    data.len()
}

fn find_after_trailer(data: &[u8], from: usize, len: usize) -> usize {
    let needle = b"startxref";
    for i in from..len.saturating_sub(needle.len() - 1) {
        if starts(data, i, needle) {
            return i;
        }
    }
    // Find the end of the dict after trailer
    let mut depth = 0i32;
    let mut i = from + 7;
    while i < len {
        if starts(data, i, b"<<") {
            depth += 1;
            i += 2;
            continue;
        }
        if starts(data, i, b">>") {
            depth -= 1;
            i += 2;
            if depth <= 0 {
                return find_line_end(data, i);
            }
            continue;
        }
        i += 1;
    }
    len
}

fn find_after_startxref(data: &[u8], from: usize, len: usize) -> usize {
    let mut i = from + 9;
    while i < len && matches!(data[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    while i < len && data[i].is_ascii_digit() {
        i += 1;
    }
    find_line_end(data, i)
}

fn extract_name(text: &str, key: &str) -> Option<String> {
    let idx = text.find(key)?;
    let after = text[idx + key.len()..].trim_start();
    if !after.starts_with('/') {
        return None;
    }
    let name_end = after[1..]
        .find(|c: char| c.is_whitespace() || c == '/' || c == '>' || c == '[' || c == '(')
        .unwrap_or(after.len() - 1);
    Some(after[..name_end + 1].trim().to_string())
}

fn extract_number(text: &str, key: &str) -> Option<String> {
    let idx = text.find(key)?;
    let after = text[idx + key.len()..].trim_start();
    let end = after
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(after.len());
    if end == 0 {
        return None;
    }
    Some(after[..end].to_string())
}

fn find_line_end(data: &[u8], from: usize) -> usize {
    let mut i = from;
    let len = data.len();
    while i < len && data[i] != b'\n' && data[i] != b'\r' {
        i += 1;
    }
    if i < len && data[i] == b'\r' {
        i += 1;
    }
    if i < len && data[i] == b'\n' {
        i += 1;
    }
    i
}

fn starts(data: &[u8], offset: usize, pattern: &[u8]) -> bool {
    offset + pattern.len() <= data.len() && data[offset..offset + pattern.len()] == *pattern
}

fn skip_ws_range(data: &[u8], i: &mut usize, len: usize) {
    while *i < len && matches!(data[*i], b' ' | b'\t' | b'\r' | b'\n') {
        *i += 1;
    }
}

fn ascii(data: &[u8], start: usize, end: usize) -> String {
    String::from_utf8_lossy(&data[start..end.min(data.len())]).into_owned()
}
