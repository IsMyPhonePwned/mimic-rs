//! Minimal RAR 5.0 / 4.x parser to extract file names for CVE-2025-8088 detection.
//! See https://www.rarlab.com/technote.htm

/// RAR 5.0 signature: Rar!\x1A\x07\x01\x00 (8 bytes). Search in first 1 MB for SFX.
const RAR5_SIGNATURE: &[u8] = b"Rar!\x1A\x07\x01\x00";
/// RAR 4.x signature: Rar!\x1A\x07\x00 (7 bytes).
const RAR4_SIGNATURE: &[u8] = b"Rar!\x1A\x07\x00";

/// Maximum bytes to scan for RAR signature (SFX module).
const MAX_SFX_SCAN: usize = 1024 * 1024;

/// RAR version detected from signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RarVersion {
    Rar5,
    Rar4,
}

/// Find RAR 5.0 or RAR 4.x signature. Returns (version, offset of first block after signature).
pub fn find_rar_signature(data: &[u8]) -> Option<(RarVersion, usize)> {
    let end = data.len().min(MAX_SFX_SCAN).saturating_sub(RAR5_SIGNATURE.len());
    for off in 0..=end {
        if data.len().saturating_sub(off) >= RAR5_SIGNATURE.len()
            && &data[off..off + RAR5_SIGNATURE.len()] == RAR5_SIGNATURE
        {
            return Some((RarVersion::Rar5, off + RAR5_SIGNATURE.len()));
        }
        if data.len().saturating_sub(off) >= RAR4_SIGNATURE.len()
            && &data[off..off + RAR4_SIGNATURE.len()] == RAR4_SIGNATURE
        {
            return Some((RarVersion::Rar4, off + RAR4_SIGNATURE.len()));
        }
    }
    None
}

/// Detect if data looks like a RAR archive (any version).
pub fn is_rar(data: &[u8]) -> bool {
    find_rar_signature(data).is_some()
}

/// Scan header remainder for CVE-2025-8088 path (":.." or ":\").
/// Returns the path as a string if found, for ADS/traversal detection.
fn scan_header_for_traversal_path(rest: &[u8]) -> Option<String> {
    const MAX_PATH_LEN: usize = 2048;
    let colon_dotdot = b":..";
    let colon_backslash: &[u8] = b":\\";
    let i = rest
        .windows(colon_dotdot.len())
        .position(|w| w == colon_dotdot)
        .or_else(|| rest.windows(colon_backslash.len()).position(|w| w == colon_backslash))?;
    let start = i;
    let end = rest[start..]
        .iter()
        .position(|&b| b == 0)
        .map(|j| start + j)
        .unwrap_or_else(|| rest.len().min(start + MAX_PATH_LEN));
    let path_bytes = &rest[start..end];
    if path_bytes.len() >= 3 {
        Some(String::from_utf8_lossy(path_bytes).into_owned())
    } else {
        None
    }
}

/// Read a RAR 5.0 vint (variable-length integer): 7 bits per byte, high bit = continuation.
/// Returns (value, bytes consumed). Max 10 bytes for 64-bit.
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

/// Parse RAR 5.0 blocks and collect file names. Returns names (UTF-8 where possible).
pub fn collect_file_names_rar5(data: &[u8], first_block_offset: usize) -> Vec<String> {
    let mut names = Vec::new();
    let mut pos = first_block_offset;

    while pos + 4 + 1 <= data.len() {
        let _crc32 = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;

        let (header_size, n) = match read_vint(data, pos) {
            Some((s, n)) => (s as usize, n),
            None => break,
        };
        pos += n;
        if header_size == 0 || pos + header_size > data.len() {
            break;
        }
        let header_end = pos + header_size;

        let (block_type, n) = match read_vint(data, pos) {
            Some((t, n)) => (t, n),
            None => break,
        };
        pos += n;
        let (flags, n) = match read_vint(data, pos) {
            Some((f, n)) => (f, n),
            None => break,
        };
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
            let (file_flags, n) = match read_vint(data, pos) {
                Some((f, n)) => (f, n),
                None => {
                    pos = header_end;
                    pos = pos.saturating_add(data_size as usize).min(data.len());
                    continue;
                }
            };
            pos += n;
            let (_unpacked, n) = read_vint(data, pos).unwrap_or((0, 0));
            pos += n;
            let (_attrs, n) = read_vint(data, pos).unwrap_or((0, 0));
            pos += n;
            if file_flags & 0x0002 != 0 && pos + 4 <= header_end {
                pos += 4;
            }
            if file_flags & 0x0004 != 0 && pos + 4 <= header_end {
                pos += 4;
            }
            let (_comp, n) = read_vint(data, pos).unwrap_or((0, 0));
            pos += n;
            let (_host_os, n) = read_vint(data, pos).unwrap_or((0, 0));
            pos += n;
            let (name_len, n) = match read_vint(data, pos) {
                Some((l, n)) => (l as usize, n),
                None => {
                    pos = header_end;
                    pos = pos.saturating_add(data_size as usize).min(data.len());
                    continue;
                }
            };
            pos += n;
            if name_len <= 0x10000 && pos + name_len <= header_end {
                let name_bytes = &data[pos..pos + name_len];
                let name = String::from_utf8_lossy(name_bytes).into_owned();
                names.push(name);
                pos += name_len;
            }
            if pos < header_end {
                let rest = &data[pos..header_end];
                if let Some(path) = scan_header_for_traversal_path(rest) {
                    names.push(path);
                }
            }
        }

        pos = header_end.saturating_add(data_size as usize).min(data.len());

        if block_type == 5 {
            break;
        }
    }

    names
}

/// RAR 4.x file block: after 7-byte block header (CRC16, type, flags, size), file block has
/// low byte of name length at +0, high byte at +1, then name. Type 0x74 = file.
pub fn collect_file_names_rar4(data: &[u8], first_block_offset: usize) -> Vec<String> {
    let mut names = Vec::new();
    let mut pos = first_block_offset;

    while pos + 7 <= data.len() {
        let _crc16 = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let block_type = data[pos + 2];
        let _flags = u16::from_le_bytes([data[pos + 3], data[pos + 4]]);
        let header_size = u16::from_le_bytes([data[pos + 5], data[pos + 6]]) as usize;
        pos += 7;
        if header_size < 7 || pos + header_size > data.len() {
            break;
        }
        let block_end = pos + header_size;

        if block_type == 0x74 {
            if pos + 2 <= block_end {
                let name_len = data[pos] as usize | ((data[pos + 1] as usize) << 8);
                pos += 2;
                if name_len <= 0x10000 && pos + name_len <= block_end {
                    let name_bytes = &data[pos..pos + name_len];
                    let name = String::from_utf8_lossy(name_bytes).into_owned();
                    names.push(name);
                }
            }
        }

        pos = block_end;
    }

    names
}

/// Collect all file names from a RAR archive (RAR 5 or 4).
pub fn collect_file_names(data: &[u8]) -> Vec<String> {
    let Some((version, first_block)) = find_rar_signature(data) else {
        return Vec::new();
    };
    match version {
        RarVersion::Rar5 => collect_file_names_rar5(data, first_block),
        RarVersion::Rar4 => collect_file_names_rar4(data, first_block),
    }
}
