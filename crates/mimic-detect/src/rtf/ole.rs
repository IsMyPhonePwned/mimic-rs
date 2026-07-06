//! Minimal OLE/Compound File Binary (CFB) validation.
//! Malformed headers/structure indicate CVE-2026-21509 style exploits.
//! See [MS-CFB] and https://blog.synapticsystems.de/apt28-geofencing-as-a-targeting-signal-cve-2026-21509/

/// OLE/CFB signature (DOCFILE).
pub const OLE_SIGNATURE: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// Header is 512 bytes.
const HEADER_LEN: usize = 512;

/// Special sector indices (MS-CFB).
const ENDOFCHAIN: u32 = 0xFFFFFFFE;
const FREESECT: u32 = 0xFFFFFFFF;
const FATSECT: u32 = 0xFFFFFFFD;
const DIFSECT: u32 = 0xFFFFFFFC;

/// Returns true if the blob looks like OLE but fails strict validation (malformed).
/// Used to detect CVE-2026-21509: Word reconstructs embedded OLE from RTF; malformed objects
/// bypass trust checks.
pub fn is_malformed_ole(data: &[u8]) -> bool {
    if data.len() < HEADER_LEN {
        return false;
    }
    if &data[0..8] != OLE_SIGNATURE {
        return false;
    }

    let _minor = u16::from_le_bytes([data[24], data[25]]);
    let major = u16::from_le_bytes([data[26], data[27]]);
    if major != 3 && major != 4 {
        return true;
    }

    let byte_order = u16::from_le_bytes([data[28], data[29]]);
    if byte_order != 0xFFFE {
        return true;
    }

    let sector_shift = u16::from_le_bytes([data[30], data[31]]);
    let expected_shift = if major == 3 { 9u16 } else { 12u16 };
    if sector_shift != expected_shift {
        return true;
    }

    let mini_shift = u16::from_le_bytes([data[32], data[33]]);
    if mini_shift != 6 {
        return true;
    }

    let num_dir_sectors = u32::from_le_bytes([data[40], data[41], data[42], data[43]]);
    if major == 3 && num_dir_sectors != 0 {
        return true;
    }

    let num_fat_sectors = u32::from_le_bytes([data[44], data[45], data[46], data[47]]);
    let first_dir_sector = u32::from_le_bytes([data[48], data[49], data[50], data[51]]);
    let mini_cutoff = u32::from_le_bytes([data[56], data[57], data[58], data[59]]);
    if mini_cutoff != 0x1000 {
        return true;
    }

    let sector_size = 1usize << (sector_shift as usize);
    if sector_size != 512 && sector_size != 4096 {
        return true;
    }

    let _first_mini_fat = u32::from_le_bytes([data[60], data[61], data[62], data[63]]);
    let _num_mini_fat = u32::from_le_bytes([data[64], data[65], data[66], data[67]]);
    let _first_difat = u32::from_le_bytes([data[68], data[69], data[70], data[71]]);
    let num_difat = u32::from_le_bytes([data[72], data[73], data[74], data[75]]);

    let max_sector = (data.len().saturating_sub(HEADER_LEN)) / sector_size.max(1);
    let max_sector_u = max_sector as u32;

    if first_dir_sector != ENDOFCHAIN && first_dir_sector != FREESECT && first_dir_sector != FATSECT && first_dir_sector != DIFSECT {
        if first_dir_sector >= max_sector_u {
            return true;
        }
    }

    for di in 0..109u32 {
        if di >= num_difat {
            break;
        }
        let off = 76 + (di as usize) * 4;
        if off + 4 > data.len() {
            break;
        }
        let sec = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        if sec == ENDOFCHAIN || sec == FREESECT || sec == FATSECT || sec == DIFSECT {
            continue;
        }
        if sec >= max_sector_u {
            return true;
        }
    }

    // Stricter validation: build FAT from DIFAT entries and walk the directory chain.
    if num_fat_sectors == 0 {
        // Some malformed OLEs use 0 FAT sectors but still reference streams.
        return true;
    }

    let mut fat = Vec::<u32>::new();
    fat.resize(max_sector, FREESECT);

    let mut fat_sectors = Vec::<u32>::new();
    for j in 0..109usize {
        let off = 76 + j * 4;
        if off + 4 > data.len() {
            break;
        }
        let sec = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        if sec == FREESECT || sec == ENDOFCHAIN {
            continue;
        }
        if sec == FATSECT || sec == DIFSECT {
            // Unexpected special marker in DIFAT list.
            return true;
        }
        if sec >= max_sector_u {
            return true;
        }
        fat_sectors.push(sec);
        if fat_sectors.len() >= num_fat_sectors as usize {
            break;
        }
    }
    if fat_sectors.is_empty() {
        return true;
    }

    let entries_per_sector = sector_size / 4;
    let mut fat_idx = 0usize;
    for &sec in &fat_sectors {
        let start = HEADER_LEN + (sec as usize) * sector_size;
        let end = start + sector_size;
        if end > data.len() {
            return true;
        }
        for k in 0..entries_per_sector {
            if fat_idx >= fat.len() {
                break;
            }
            let o = start + k * 4;
            let v = u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
            fat[fat_idx] = v;
            fat_idx += 1;
        }
    }

    // Directory chain must be walkable and end.
    if first_dir_sector == FREESECT || first_dir_sector == FATSECT || first_dir_sector == DIFSECT {
        return true;
    }
    if first_dir_sector >= max_sector_u {
        return true;
    }

    let mut seen = std::collections::HashSet::<u32>::new();
    let mut cur = first_dir_sector;
    // hard cap to avoid loops; directory shouldn't need many sectors
    for _ in 0..(max_sector.min(4096)) {
        if cur == ENDOFCHAIN {
            return false;
        }
        if cur >= max_sector_u {
            return true;
        }
        if !seen.insert(cur) {
            return true; // loop
        }
        let next = fat.get(cur as usize).copied().unwrap_or(FREESECT);
        if next == FREESECT {
            return true;
        }
        cur = next;
    }
    true
}

/// Directory entry type (MS-CFB).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum OleEntryType {
    Empty,
    Storage,
    Stream,
    Root,
}

/// One OLE directory entry (stream or storage name) for oleid-style listing.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct OleDirEntry {
    pub name: String,
    pub entry_type: OleEntryType,
    pub size: u64,
}

const DIR_ENTRY_LEN: usize = 128;

/// List root-level OLE directory entries (stream/storage names) for analysis.
/// Returns None if data is not valid OLE or too short; otherwise list of entries.
pub fn list_ole_entries(data: &[u8]) -> Option<Vec<OleDirEntry>> {
    if data.len() < HEADER_LEN {
        return None;
    }
    if &data[0..8] != OLE_SIGNATURE {
        return None;
    }
    let major = u16::from_le_bytes([data[26], data[27]]);
    if major != 3 && major != 4 {
        return None;
    }
    let sector_shift = u16::from_le_bytes([data[30], data[31]]);
    let sector_size = 1usize << (sector_shift as usize);
    let first_dir_sector = u32::from_le_bytes([data[48], data[49], data[50], data[51]]);
    if first_dir_sector == ENDOFCHAIN || first_dir_sector == FREESECT || first_dir_sector == FATSECT || first_dir_sector == DIFSECT {
        return None;
    }
    let dir_start = HEADER_LEN + (first_dir_sector as usize) * sector_size;
    if dir_start + DIR_ENTRY_LEN > data.len() {
        return None;
    }
    let mut out = Vec::new();
    let mut offset = dir_start;
    for _ in 0..(sector_size / DIR_ENTRY_LEN) {
        if offset + DIR_ENTRY_LEN > data.len() {
            break;
        }
        let name_buf = &data[offset..offset + 64];
        let name_len = u16::from_le_bytes([data[offset + 64], data[offset + 65]]) as usize;
        let ty = data[offset + 66];
        let size = u64::from_le_bytes([
            data[offset + 120], data[offset + 121], data[offset + 122], data[offset + 123],
            data[offset + 124], data[offset + 125], data[offset + 126], data[offset + 127],
        ]);
        let entry_type = match ty {
            0 => OleEntryType::Empty,
            1 => OleEntryType::Storage,
            2 => OleEntryType::Stream,
            5 => OleEntryType::Root,
            _ => OleEntryType::Empty,
        };
        let name = decode_utf16le_name(name_buf, name_len.min(62));
        if !name.is_empty() || entry_type != OleEntryType::Empty {
            out.push(OleDirEntry {
                name,
                entry_type,
                size,
            });
        }
        offset += DIR_ENTRY_LEN;
    }
    Some(out)
}

fn decode_utf16le_name(b: &[u8], len: usize) -> String {
    let mut s = String::new();
    let mut i = 0;
    while i + 2 <= len && i + 2 <= b.len() {
        let c = u16::from_le_bytes([b[i], b[i + 1]]);
        if c == 0 {
            break;
        }
        if let Some(ch) = char::from_u32(c as u32) {
            s.push(ch);
        }
        i += 2;
    }
    s
}

