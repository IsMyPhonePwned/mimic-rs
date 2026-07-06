//! ZIP and RAR archive parsers for the hex inspector.
//! ZIP: local file headers, payloads (with Zombie ZIP hint), EOCD, central directory.

use crate::Node;

const ZIP_LOCAL_SIG: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];
const ZIP_EOCD_SIG: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];
const ZIP_CFH_SIG: [u8; 4] = [0x50, 0x4B, 0x01, 0x02];
const LOCAL_HEADER_FIXED: usize = 30;
const RAR5_SIG: &[u8] = b"Rar!\x1A\x07\x01\x00";
const RAR4_SIG: &[u8] = b"Rar!\x1A\x07\x00";
const MAX_SFX_SCAN: usize = 1024 * 1024;

fn looks_like_deflate(payload: &[u8]) -> bool {
    if payload.len() < 2 {
        return false;
    }
    if payload[0] == 0x78 && (payload[1] == 0x01 || payload[1] == 0x5E || payload[1] == 0x9C || payload[1] == 0xDA) {
        return true;
    }
    if payload[0] == 0x78 {
        return true;
    }
    let b0 = payload[0];
    (b0 & 0x07) == 0x04 || (b0 & 0x07) == 0x08
}

/// Walk local file headers (PK\x03\x04) and add header + payload nodes; optional Zombie ZIP warning.
fn add_local_entries(data: &[u8], eocd_off: Option<usize>, nodes: &mut Vec<Node>) {
    let len = data.len();
    let stop = eocd_off.unwrap_or(len);
    let mut pos = 0usize;
    while pos + LOCAL_HEADER_FIXED <= stop && pos + 4 <= len {
        if data[pos..pos + 4] != ZIP_LOCAL_SIG {
            pos += 1;
            continue;
        }
        let method = u16::from_le_bytes([data[pos + 8], data[pos + 9]]);
        let compressed_size = u32::from_le_bytes([
            data[pos + 18],
            data[pos + 19],
            data[pos + 20],
            data[pos + 21],
        ]) as usize;
        let fn_len = u16::from_le_bytes([data[pos + 26], data[pos + 27]]) as usize;
        let extra_len = u16::from_le_bytes([data[pos + 28], data[pos + 29]]) as usize;
        let header_end = pos + LOCAL_HEADER_FIXED + fn_len + extra_len;
        let data_start = header_end;
        let data_end = data_start.saturating_add(compressed_size).min(len);
        if header_end > len || data_end > len {
            pos += 1;
            continue;
        }
        let method_str = match method {
            0 => "stored",
            8 => "deflate",
            _ => "other",
        };
        let name = if fn_len > 0 && header_end <= len {
            String::from_utf8_lossy(&data[pos + LOCAL_HEADER_FIXED..pos + LOCAL_HEADER_FIXED + fn_len]).into_owned()
        } else {
            String::new()
        };
        let name_display = if name.is_empty() { "(no name)" } else { name.as_str() };
        nodes.push(Node {
            kind: "header".into(),
            label: format!("Local: {}", name_display),
            detail: format!("{} (method {}), {} bytes", name_display, method_str, compressed_size),
            start: pos,
            end: header_end,
        });
        let payload = &data[data_start..data_end];
        let zombie = method == 0 && compressed_size >= 2 && looks_like_deflate(payload);
        if zombie {
            nodes.push(Node {
                kind: "warning".into(),
                label: "Zombie ZIP".into(),
                detail: "Method=0 (stored) but payload is DEFLATE (CVE-2026-0866)".into(),
                start: data_start,
                end: data_end.min(data_start + 32),
            });
        }
        nodes.push(Node {
            kind: "data".into(),
            label: "Payload".into(),
            detail: format!("{} bytes ({})", compressed_size, if zombie { "⚠ DEFLATE" } else { method_str }),
            start: data_start,
            end: data_end,
        });
        pos = data_end;
    }
}

pub fn parse_zip(data: &[u8]) -> Vec<Node> {
    let mut nodes = Vec::new();
    let len = data.len();
    if len < 4 {
        return nodes;
    }

    let eocd_off = find_eocd(data);
    add_local_entries(data, eocd_off, &mut nodes);

    let Some(eocd_off) = eocd_off else {
        return nodes;
    };
    if len < 22 {
        return nodes;
    }

    nodes.push(Node {
        kind: "header".into(),
        label: "End of central directory".into(),
        detail: format!("@ 0x{:X}", eocd_off),
        start: eocd_off,
        end: (eocd_off + 22).min(len),
    });

    if eocd_off + 22 > len {
        return nodes;
    }
    let central_offset = u32::from_le_bytes([
        data[eocd_off + 16],
        data[eocd_off + 17],
        data[eocd_off + 18],
        data[eocd_off + 19],
    ]) as usize;
    let total_entries = u16::from_le_bytes([data[eocd_off + 8], data[eocd_off + 9]]) as usize;

    let mut pos = central_offset;
    for _ in 0..total_entries {
        if pos + 46 > len {
            break;
        }
        if data[pos..pos + 4] != ZIP_CFH_SIG {
            break;
        }
        let filename_len = u16::from_le_bytes([data[pos + 28], data[pos + 29]]) as usize;
        let extra_len = u16::from_le_bytes([data[pos + 30], data[pos + 31]]) as usize;
        let comment_len = u16::from_le_bytes([data[pos + 32], data[pos + 33]]) as usize;
        let uncompressed = u32::from_le_bytes([data[pos + 24], data[pos + 25], data[pos + 26], data[pos + 27]]);
        let compressed = u32::from_le_bytes([data[pos + 20], data[pos + 21], data[pos + 22], data[pos + 23]]);
        let name_start = pos + 46;
        let name_end = name_start + filename_len;
        if name_end > len {
            break;
        }
        let name = String::from_utf8_lossy(&data[name_start..name_end]).into_owned();
        let name_display = if name.is_empty() { "(empty name)" } else { name.as_str() };
        nodes.push(Node {
            kind: "file".into(),
            label: name_display.to_string(),
            detail: format!("{} bytes (compressed {}), @ 0x{:X}", uncompressed, compressed, pos),
            start: pos,
            end: name_end + extra_len + comment_len,
        });
        pos = name_end + extra_len + comment_len;
    }

    nodes
}

fn find_eocd(data: &[u8]) -> Option<usize> {
    let len = data.len();
    let search_start = len.saturating_sub(65557).max(0);
    for i in (search_start..=len.saturating_sub(4)).rev() {
        if data[i..i + 4] == ZIP_EOCD_SIG {
            return Some(i);
        }
    }
    None
}

pub fn parse_rar(data: &[u8]) -> Vec<Node> {
    let mut nodes = Vec::new();
    let (version, first_block) = match find_rar_signature(data) {
        Some(p) => p,
        None => return nodes,
    };
    let sig_len = if matches!(version, RarVersion::Rar5) { 8 } else { 7 };
    let sig_end = first_block - sig_len;

    nodes.push(Node {
        kind: "header".into(),
        label: if matches!(version, RarVersion::Rar5) { "RAR 5.0 signature" } else { "RAR 4.x signature" }.into(),
        detail: format!("@ offset 0x{:X}", sig_end),
        start: sig_end,
        end: first_block,
    });

    let names = match version {
        RarVersion::Rar5 => collect_file_names_rar5(data, first_block),
        RarVersion::Rar4 => collect_file_names_rar4(data, first_block),
    };
    for (i, name) in names.iter().enumerate() {
        let label = if name.is_empty() { "(empty)" } else { name.as_str() };
        nodes.push(Node {
            kind: "file".into(),
            label: label.to_string(),
            detail: format!("File #{} in archive", i + 1),
            start: first_block,
            end: first_block + 1,
        });
    }

    nodes
}

fn find_rar_signature(data: &[u8]) -> Option<(RarVersion, usize)> {
    let end = data.len().min(MAX_SFX_SCAN).saturating_sub(RAR5_SIG.len());
    for off in 0..=end {
        if data.len().saturating_sub(off) >= RAR5_SIG.len()
            && data[off..off + RAR5_SIG.len()] == *RAR5_SIG
        {
            return Some((RarVersion::Rar5, off + RAR5_SIG.len()));
        }
        if data.len().saturating_sub(off) >= RAR4_SIG.len()
            && data[off..off + RAR4_SIG.len()] == *RAR4_SIG
        {
            return Some((RarVersion::Rar4, off + RAR4_SIG.len()));
        }
    }
    None
}

#[derive(Clone, Copy)]
enum RarVersion {
    Rar5,
    Rar4,
}

fn read_vint(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    let mut val: u64 = 0;
    let mut shift = 0u32;
    let mut i = offset;
    loop {
        if i >= data.len() || shift >= 70 {
            return None;
        }
        let b = data[i];
        i += 1;
        val |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            return Some((val, i - offset));
        }
        shift += 7;
    }
}

fn collect_file_names_rar5(data: &[u8], first_block_offset: usize) -> Vec<String> {
    let mut names = Vec::new();
    let mut pos = first_block_offset;
    let len = data.len();

    while pos + 4 + 1 <= len {
        pos += 4;
        let (header_size, n) = read_vint(data, pos).unwrap_or((0, 0));
        pos += n;
        let header_size = header_size as usize;
        if header_size == 0 || pos + header_size > len {
            break;
        }
        let header_end = pos + header_size;

        let (block_type, n) = read_vint(data, pos).unwrap_or((0, 0));
        pos += n;
        let (flags, n) = read_vint(data, pos).unwrap_or((0, 0));
        pos += n;
        if flags & 0x0001 != 0 {
            let (_, n) = read_vint(data, pos).unwrap_or((0, 0));
            pos += n;
        }
        let mut data_size: u64 = 0;
        if flags & 0x0002 != 0 {
            let (ds, n) = read_vint(data, pos).unwrap_or((0, 0));
            data_size = ds;
            pos += n;
        }

        if (block_type == 2 || block_type == 3) && pos < header_end {
            let (file_flags, n) = read_vint(data, pos).unwrap_or((0, 0));
            pos += n;
            let (_, n) = read_vint(data, pos).unwrap_or((0, 0));
            pos += n;
            let (_, n) = read_vint(data, pos).unwrap_or((0, 0));
            pos += n;
            if file_flags & 0x0002 != 0 && pos + 4 <= header_end {
                pos += 4;
            }
            if file_flags & 0x0004 != 0 && pos + 4 <= header_end {
                pos += 4;
            }
            let (_, n) = read_vint(data, pos).unwrap_or((0, 0));
            pos += n;
            let (_, n) = read_vint(data, pos).unwrap_or((0, 0));
            pos += n;
            let (name_len, n) = read_vint(data, pos).unwrap_or((0, 0));
            pos += n;
            let name_len = name_len as usize;
            if name_len <= 0x10000 && pos + name_len <= header_end {
                let name = String::from_utf8_lossy(&data[pos..pos + name_len]).into_owned();
                names.push(name);
            }
        }

        pos = header_end.saturating_add(data_size as usize).min(len);
        if block_type == 5 {
            break;
        }
    }
    names
}

fn collect_file_names_rar4(data: &[u8], first_block_offset: usize) -> Vec<String> {
    let mut names = Vec::new();
    let mut pos = first_block_offset;
    let len = data.len();

    while pos + 7 <= len {
        let _crc16 = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let block_type = data[pos + 2];
        let _flags = u16::from_le_bytes([data[pos + 3], data[pos + 4]]);
        let header_size = u16::from_le_bytes([data[pos + 5], data[pos + 6]]) as usize;
        pos += 7;
        if header_size < 7 || pos + header_size > len {
            break;
        }
        let block_end = pos + header_size;

        if block_type == 0x74 {
            if pos + 2 <= block_end {
                let name_len = data[pos] as usize | ((data[pos + 1] as usize) << 8);
                pos += 2;
                if name_len <= 0x10000 && pos + name_len <= block_end {
                    let name = String::from_utf8_lossy(&data[pos..pos + name_len]).into_owned();
                    names.push(name);
                }
            }
        }
        pos = block_end;
    }
    names
}
