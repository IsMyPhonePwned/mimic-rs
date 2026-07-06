//! Minimal TTF/OTF SFNT parser: offset table and table directory.
//! Used for CVE-2023-41990 (ADJUST instruction) detection.
//! See https://github.com/msuiche/elegant-bouncer/blob/main/src/ttf.rs

/// TrueType/OpenType SFNT version (big-endian).
pub const TTF_VERSION_1: u32 = 0x0001_0000;
/// OpenType with CFF (optional; we still scan fpgm/prep/glyf if present).
pub const OTF_VERSION_OTTO: [u8; 4] = *b"OTTO";

/// Minimum size: offset table (12) + one table entry (16).
const OFFSET_TABLE_LEN: usize = 12;
const TABLE_ENTRY_LEN: usize = 16;

/// Check if data looks like a TTF/OTF (SFNT) file.
#[inline]
pub fn is_ttf(data: &[u8]) -> bool {
    if data.len() < OFFSET_TABLE_LEN {
        return false;
    }
    let version = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    version == TTF_VERSION_1 || data[0..4] == OTF_VERSION_OTTO
}

#[inline]
fn read_u16_be(data: &[u8], offset: usize) -> Option<u16> {
    let end = offset + 2;
    if end > data.len() {
        return None;
    }
    Some(u16::from_be_bytes([data[offset], data[offset + 1]]))
}

#[inline]
fn read_u32_be(data: &[u8], offset: usize) -> Option<u32> {
    let end = offset + 4;
    if end > data.len() {
        return None;
    }
    Some(u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

/// One table record (tag, offset, length).
#[derive(Debug, Clone, Copy)]
pub struct TtfTable {
    pub tag: [u8; 4],
    pub offset: u32,
    pub length: u32,
}

/// Parse offset table and return (num_tables, first table entry offset).
fn parse_offset_table(data: &[u8]) -> Option<(u16, usize)> {
    let num_tables = read_u16_be(data, 4)?;
    if num_tables == 0 || num_tables > 64 {
        return None;
    }
    let tables_start = OFFSET_TABLE_LEN;
    Some((num_tables, tables_start))
}

/// Find a table by tag (e.g. b"fpgm", b"prep", b"maxp", b"loca", b"glyf").
pub fn get_table(data: &[u8], tag: &[u8; 4]) -> Option<TtfTable> {
    let (num_tables, tables_start) = parse_offset_table(data)?;
    for i in 0..num_tables {
        let off = tables_start + (i as usize) * TABLE_ENTRY_LEN;
        if off + TABLE_ENTRY_LEN > data.len() {
            break;
        }
        let t_tag = [data[off], data[off + 1], data[off + 2], data[off + 3]];
        if t_tag == *tag {
            let checksum = read_u32_be(data, off + 4)?;
            let offset = read_u32_be(data, off + 8)?;
            let length = read_u32_be(data, off + 12)?;
            let _ = checksum;
            return Some(TtfTable {
                tag: t_tag,
                offset,
                length,
            });
        }
    }
    None
}

/// Return byte slice for a table, or None if out of bounds.
pub fn table_bytes<'a>(data: &'a [u8], table: &TtfTable) -> Option<&'a [u8]> {
    let start = table.offset as usize;
    let end = start.saturating_add(table.length as usize);
    if end > data.len() {
        return None;
    }
    Some(&data[start..end])
}

