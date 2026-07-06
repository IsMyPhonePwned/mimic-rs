//! Minimal TIFF/DNG structure reader for exploit detection.
//! Does not allocate for hot path; operates on slices.

/// TIFF magic number.
pub const TIFF_MAGIC: u16 = 0x002A;
#[allow(dead_code)]
/// Little-endian byte order marker.
pub const TIFF_LITTLE: u16 = 0x4949;
#[allow(dead_code)]
/// Big-endian byte order marker.
pub const TIFF_BIG: u16 = 0x4D4D;

/// SubIFD tag (DNG/TIFF‑EP).
pub const TAG_SUB_IFD: u16 = 0x014A;
/// SamplesPerPixel.
pub const TAG_SAMPLES_PER_PIXEL: u16 = 0x0115;
/// Compression: 7 = JPEG (including lossless in DNG).
pub const TAG_COMPRESSION: u16 = 0x0103;
/// StripOffsets.
pub const TAG_STRIP_OFFSETS: u16 = 0x0111;
/// JPEGInterchangeFormat (offset to JPEG stream).
pub const TAG_JPEG_INTERCHANGE_FORMAT: u16 = 0x0201;
/// ImageWidth.
pub const TAG_IMAGE_WIDTH: u16 = 0x0100;
/// ImageLength (height).
pub const TAG_IMAGE_HEIGHT: u16 = 0x0101;
/// TileWidth.
pub const TAG_TILE_WIDTH: u16 = 0x0142;
/// TileLength (tile height).
pub const TAG_TILE_HEIGHT: u16 = 0x0143;
/// TileOffsets.
pub const TAG_TILE_OFFSETS: u16 = 0x0144;
/// TileByteCounts.
pub const TAG_TILE_BYTE_COUNTS: u16 = 0x0145;
/// Opcode list tags (DNG; opcode count stored big-endian).
pub const TAG_OPCODE_LIST_1: u16 = 0xC740;
pub const TAG_OPCODE_LIST_2: u16 = 0xC741;
pub const TAG_OPCODE_LIST_3: u16 = 0xC74E;

/// Compression value: JPEG (DNG uses 7 for JPEG lossless in SubIFD).
pub const COMPRESSION_JPEG: u16 = 7;

/// TIFF field types.
#[allow(dead_code)] pub const TYPE_BYTE: u16 = 1;
#[allow(dead_code)] pub const TYPE_ASCII: u16 = 2;
pub const TYPE_SHORT: u16 = 3;
pub const TYPE_LONG: u16 = 4;
#[allow(dead_code)] pub const TYPE_RATIONAL: u16 = 5;
#[allow(dead_code)] pub const TYPE_UNDEFINED: u16 = 7;
pub const TYPE_LONG8: u16 = 16;

/// Size of TIFF header in bytes.
pub const TIFF_HEADER_LEN: usize = 8;
/// Size of one IFD entry in bytes.
pub const IFD_ENTRY_LEN: usize = 12;

#[derive(Debug, Clone, Copy)]
pub enum Endian {
    Little,
    Big,
}

/// Return the size in bytes of one value for a given TIFF field type.
#[inline]
pub fn type_unit_size(field_type: u16) -> Option<usize> {
    match field_type {
        TYPE_BYTE => Some(1),
        TYPE_ASCII => Some(1),
        TYPE_SHORT => Some(2),
        TYPE_LONG => Some(4),
        TYPE_RATIONAL => Some(8),
        TYPE_UNDEFINED => Some(1),
        TYPE_LONG8 => Some(8),
        _ => None,
    }
}

impl Endian {
    #[inline]
    pub fn read_u16(self, data: &[u8], offset: usize) -> Option<u16> {
        let end = offset + 2;
        if end > data.len() {
            return None;
        }
        let bytes = &data[offset..end];
        Some(match self {
            Endian::Little => u16::from_le_bytes([bytes[0], bytes[1]]),
            Endian::Big => u16::from_be_bytes([bytes[0], bytes[1]]),
        })
    }

    #[inline]
    pub fn read_u32(self, data: &[u8], offset: usize) -> Option<u32> {
        let end = offset + 4;
        if end > data.len() {
            return None;
        }
        let bytes = &data[offset..end];
        Some(match self {
            Endian::Little => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            Endian::Big => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        })
    }
}

/// Check TIFF header and return (Endian, IFD0 offset). Fails if not valid TIFF.
pub fn read_tiff_header(data: &[u8]) -> Option<(Endian, u32)> {
    if data.len() < TIFF_HEADER_LEN {
        return None;
    }
    let bo = if data[0] == 0x49 && data[1] == 0x49 {
        Endian::Little
    } else if data[0] == 0x4D && data[1] == 0x4D {
        Endian::Big
    } else {
        return None;
    };
    let magic = bo.read_u16(data, 2)?;
    if magic != TIFF_MAGIC {
        return None;
    }
    let ifd0 = bo.read_u32(data, 4)?;
    Some((bo, ifd0))
}

/// Single IFD entry (tag, type, count, value/offset).
#[derive(Debug, Clone, Copy)]
pub struct IfdEntry {
    pub tag: u16,
    pub field_type: u16,
    pub count: u32,
    pub value_offset: u32,
}

/// Read one IFD entry at `offset` (must have 12 bytes available).
pub fn read_ifd_entry(bo: Endian, data: &[u8], offset: usize) -> Option<IfdEntry> {
    if data.len().saturating_sub(offset) < IFD_ENTRY_LEN {
        return None;
    }
    Some(IfdEntry {
        tag: bo.read_u16(data, offset)?,
        field_type: bo.read_u16(data, offset + 2)?,
        count: bo.read_u32(data, offset + 4)?,
        value_offset: bo.read_u32(data, offset + 8)?,
    })
}

/// Validate that an IFD entry's referenced value bytes are within bounds.
///
/// Note: for values whose total size <= 4 bytes, the value is stored inline in the entry
/// and no `value_offset` bounds check is needed.
pub fn validate_entry_bounds(data_len: usize, entry: IfdEntry) -> Option<String> {
    let Some(unit) = type_unit_size(entry.field_type) else {
        return Some(format!(
            "Unknown TIFF field_type={} for tag=0x{:04x}",
            entry.field_type, entry.tag
        ));
    };
    let count = entry.count as u64;
    let total = (unit as u64).saturating_mul(count);

    // Inline value (fits in 4 bytes in classic TIFF IFD entry).
    if total <= 4 {
        return None;
    }

    let off = entry.value_offset as u64;
    let end = off.saturating_add(total);
    if end > data_len as u64 {
        return Some(format!(
            "Out-of-bounds tag=0x{:04x} type={} count={} offset=0x{:08x} needs={} bytes (file_len={})",
            entry.tag,
            entry.field_type,
            entry.count,
            entry.value_offset,
            total,
            data_len
        ));
    }
    None
}

/// Read value of a SHORT tag. When count==1, value is stored inline in the entry (value_offset bytes 0-1).
pub fn read_short_tag(
    bo: Endian,
    data: &[u8],
    entry: IfdEntry,
) -> Option<u16> {
    if entry.field_type != TYPE_SHORT || entry.count == 0 {
        return None;
    }
    if entry.count == 1 {
        return Some((entry.value_offset & 0xFFFF) as u16);
    }
    if data.len().saturating_sub(entry.value_offset as usize) < 2 {
        return None;
    }
    bo.read_u16(data, entry.value_offset as usize)
}

/// Read one LONG value. When count==1, value is stored inline in the entry.
pub fn read_long_tag(
    bo: Endian,
    data: &[u8],
    entry: IfdEntry,
) -> Option<u32> {
    if entry.field_type != TYPE_LONG && entry.field_type != TYPE_SHORT {
        return None;
    }
    if entry.count == 1 && entry.field_type == TYPE_LONG {
        return Some(entry.value_offset);
    }
    if entry.count == 1 && entry.field_type == TYPE_SHORT {
        return Some((entry.value_offset & 0xFFFF) as u32);
    }
    if data.len().saturating_sub(entry.value_offset as usize) < 4 {
        return None;
    }
    bo.read_u32(data, entry.value_offset as usize)
}

/// Read array of LONG values (e.g. TileOffsets, TileByteCounts).
pub fn read_long_array(
    bo: Endian,
    data: &[u8],
    entry: IfdEntry,
) -> Option<Vec<u32>> {
    if entry.field_type != TYPE_LONG && entry.field_type != TYPE_SHORT {
        return None;
    }
    let count = entry.count as usize;
    if count == 0 || count > 0x100_0000 {
        return None;
    }
    if count == 1 {
        let v = if entry.field_type == TYPE_LONG {
            entry.value_offset
        } else {
            (entry.value_offset & 0xFFFF) as u32
        };
        return Some(vec![v]);
    }
    let base = entry.value_offset as usize;
    let need = count * 4;
    if base + need > data.len() {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        out.push(bo.read_u32(data, base + i * 4)?);
    }
    Some(out)
}

/// Opcode list count: first 4 bytes of opcode list data are big-endian count.
/// For inline (count <= 4 bytes), value_offset holds the data as big-endian.
pub fn opcode_list_count(data: &[u8], entry: IfdEntry) -> Option<u32> {
    if entry.count <= 4 {
        return Some(entry.value_offset.to_be());
    }
    let base = entry.value_offset as usize;
    if base + 4 > data.len() {
        return None;
    }
    Some(u32::from_be_bytes([
        data[base],
        data[base + 1],
        data[base + 2],
        data[base + 3],
    ]))
}

/// Iterate over IFD at `ifd_offset`: yields (entry, next_ifd_offset).
/// Caller can recurse on SubIFD offsets. Stops on invalid offset or zero.
pub fn walk_ifd(
    bo: Endian,
    data: &[u8],
    ifd_offset: u32,
) -> Option<impl Iterator<Item = (IfdEntry, u32)> + '_> {
    let offset = ifd_offset as usize;
    if offset + 2 > data.len() {
        return None;
    }
    let num_entries = bo.read_u16(data, offset)? as usize;
    let entries_start = offset + 2;
    let entries_end = entries_start + num_entries * IFD_ENTRY_LEN;
    if entries_end > data.len() {
        return None;
    }
    let next_ifd_offset = if entries_end + 4 <= data.len() {
        bo.read_u32(data, entries_end).unwrap_or(0)
    } else {
        0
    };

    let iter = (0..num_entries).filter_map(move |i| {
        let entry_offset = entries_start + i * IFD_ENTRY_LEN;
        let entry = read_ifd_entry(bo, data, entry_offset)?;
        Some((entry, next_ifd_offset))
    });
    Some(iter)
}

/// Collect SubIFD offsets from TAG_SUB_IFD. When count==1, the offset is stored inline in the entry.
pub fn read_sub_ifd_offsets(
    bo: Endian,
    data: &[u8],
    entry: IfdEntry,
) -> Option<Vec<u32>> {
    if entry.tag != TAG_SUB_IFD || (entry.field_type != TYPE_LONG && entry.field_type != TYPE_LONG8) {
        return None;
    }
    let count = entry.count as usize;
    if count == 0 || count > 0x10000 {
        return None;
    }
    if count == 1 {
        return Some(vec![entry.value_offset]);
    }
    let base = entry.value_offset as usize;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = if entry.field_type == TYPE_LONG8 {
            if base + (i + 1) * 8 > data.len() {
                return None;
            }
            bo.read_u32(data, base + i * 8)?
        } else {
            if base + (i + 1) * 4 > data.len() {
                return None;
            }
            bo.read_u32(data, base + i * 4)?
        };
        out.push(off);
    }
    Some(out)
}

