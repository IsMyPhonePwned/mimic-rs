//! DNG / TIFF structure parser for the hex inspector.

use crate::Node;

pub fn parse(data: &[u8]) -> Vec<Node> {
    let mut nodes = Vec::new();
    let len = data.len();
    if len < 8 {
        return nodes;
    }

    let le = data[0] == 0x49; // II = little-endian, MM = big-endian
    let endian_str = if le { "Little-endian (II)" } else { "Big-endian (MM)" };

    let magic = r16(data, 2, le);
    nodes.push(Node {
        kind: "header".into(),
        label: "TIFF Header".into(),
        detail: format!("{}, magic=0x{:04X}", endian_str, magic),
        start: 0,
        end: 8,
    });

    let ifd0_off = r32(data, 4, le) as usize;
    if ifd0_off == 0 || ifd0_off >= len {
        return nodes;
    }

    parse_ifd(data, le, ifd0_off, "IFD0", &mut nodes, 0);

    // Scan for JPEG thumbnails / SOF3 markers
    scan_jpeg_markers(data, &mut nodes);

    nodes
}

fn parse_ifd(data: &[u8], le: bool, offset: usize, name: &str, nodes: &mut Vec<Node>, depth: u32) {
    if depth > 8 || offset + 2 > data.len() {
        return;
    }
    let len = data.len();
    let count = r16(data, offset, le) as usize;
    let ifd_end = offset + 2 + count * 12 + 4;
    let safe_end = ifd_end.min(len);

    nodes.push(Node {
        kind: "ifd".into(),
        label: name.to_string(),
        detail: format!("{} entries @ offset {}", count, offset),
        start: offset,
        end: safe_end,
    });

    for i in 0..count {
        let entry_off = offset + 2 + i * 12;
        if entry_off + 12 > len {
            break;
        }
        let tag = r16(data, entry_off, le);
        let typ = r16(data, entry_off + 2, le);
        let cnt = r32(data, entry_off + 4, le);
        let val = r32(data, entry_off + 8, le);

        let (tag_name, tag_detail) = describe_tag(tag, typ, cnt, val, le);

        nodes.push(Node {
            kind: "ifd".into(),
            label: tag_name.clone(),
            detail: tag_detail,
            start: entry_off,
            end: entry_off + 12,
        });

        // Recurse into SubIFDs, ExifIFD, GPSIFD
        if matches!(tag, 0x8769 | 0x8825 | 0x014A) {
            let sub_off = val as usize;
            if sub_off > 0 && sub_off < len {
                let sub_name = match tag {
                    0x8769 => "ExifIFD",
                    0x8825 => "GPSIFD",
                    0x014A => "SubIFDs",
                    _ => "SubIFD",
                };
                parse_ifd(data, le, sub_off, sub_name, nodes, depth + 1);
            }
        }

        // Highlight data regions for large tags
        let type_size = match typ {
            1 | 2 | 6 | 7 => 1,
            3 | 8 => 2,
            4 | 9 | 11 => 4,
            5 | 10 | 12 => 8,
            13 => 4,
            _ => 1,
        };
        let total_bytes = cnt as usize * type_size;
        if total_bytes > 4 {
            let data_off = val as usize;
            if data_off > 0 && data_off < len {
                let kind = match tag {
                    0x0144 | 0x0145 => "tile",
                    0x0111 | 0x0117 => "data",
                    0xC740 => "data",
                    _ => "data",
                };
                let end = (data_off + total_bytes).min(len);
                nodes.push(Node {
                    kind: kind.into(),
                    label: format!("{} data", tag_name),
                    detail: format!("{} bytes @ offset {}", total_bytes, data_off),
                    start: data_off,
                    end,
                });
            }
        }

        // Warnings
        if tag == 0x0115 {
            // SamplesPerPixel
            if cnt > 0 && val > 10 {
                nodes.push(Node {
                    kind: "warning".into(),
                    label: "SamplesPerPixel".into(),
                    detail: format!("Unusually high value: {} (potential CVE-2025-8088)", val),
                    start: entry_off,
                    end: entry_off + 12,
                });
            }
        }
        if tag == 0xC740 {
            // OpcodeList3 — potential CVE
            nodes.push(Node {
                kind: "warning".into(),
                label: "OpcodeList3".into(),
                detail: format!("OpcodeList3 present — review for CVE-2025-8088 patterns"),
                start: entry_off,
                end: entry_off + 12,
            });
        }
    }

    // Next IFD
    if ifd_end <= len {
        let next = r32(data, offset + 2 + count * 12, le) as usize;
        if next > 0 && next < len && next != offset {
            parse_ifd(data, le, next, "IFD1", nodes, depth + 1);
        }
    }
}

fn scan_jpeg_markers(data: &[u8], nodes: &mut Vec<Node>) {
    let len = data.len();
    let mut i = 0;
    while i + 1 < len {
        if data[i] == 0xFF && data[i + 1] == 0xD8 {
            nodes.push(Node {
                kind: "jpeg".into(),
                label: "JPEG SOI".into(),
                detail: "JPEG Start Of Image".into(),
                start: i,
                end: i + 2,
            });
            i += 2;
            continue;
        }
        if data[i] == 0xFF && data[i + 1] == 0xC3 {
            let marker_len = if i + 3 < len {
                r16_be(data, i + 2) as usize + 2
            } else {
                4
            };
            nodes.push(Node {
                kind: "jpeg".into(),
                label: "SOF3 (Lossless)".into(),
                detail: format!("JPEG lossless frame — {} bytes", marker_len),
                start: i,
                end: (i + marker_len).min(len),
            });
            i += marker_len;
            continue;
        }
        if data[i] == 0xFF && data[i + 1] == 0xD9 {
            nodes.push(Node {
                kind: "jpeg".into(),
                label: "JPEG EOI".into(),
                detail: "JPEG End Of Image".into(),
                start: i,
                end: i + 2,
            });
            i += 2;
            continue;
        }
        i += 1;
    }
}

fn describe_tag(tag: u16, typ: u16, cnt: u32, val: u32, _le: bool) -> (String, String) {
    let name = match tag {
        0x00FE => "NewSubfileType",
        0x0100 => "ImageWidth",
        0x0101 => "ImageLength",
        0x0102 => "BitsPerSample",
        0x0103 => "Compression",
        0x0106 => "PhotometricInterpretation",
        0x010E => "ImageDescription",
        0x010F => "Make",
        0x0110 => "Model",
        0x0111 => "StripOffsets",
        0x0112 => "Orientation",
        0x0115 => "SamplesPerPixel",
        0x0116 => "RowsPerStrip",
        0x0117 => "StripByteCounts",
        0x011A => "XResolution",
        0x011B => "YResolution",
        0x011C => "PlanarConfiguration",
        0x0128 => "ResolutionUnit",
        0x0131 => "Software",
        0x0132 => "DateTime",
        0x013B => "Artist",
        0x013D => "Predictor",
        0x0142 => "TileWidth",
        0x0143 => "TileLength",
        0x0144 => "TileOffsets",
        0x0145 => "TileByteCounts",
        0x014A => "SubIFDs",
        0x8769 => "ExifIFD",
        0x8825 => "GPSIFD",
        0xC612 => "DNGVersion",
        0xC613 => "DNGBackwardVersion",
        0xC614 => "UniqueCameraModel",
        0xC621 => "ColorMatrix1",
        0xC622 => "ColorMatrix2",
        0xC68B => "OriginalRawFileName",
        0xC740 => "OpcodeList3",
        _ => "",
    };

    let type_str = match typ {
        1 => "BYTE",
        2 => "ASCII",
        3 => "SHORT",
        4 => "LONG",
        5 => "RATIONAL",
        6 => "SBYTE",
        7 => "UNDEFINED",
        8 => "SSHORT",
        9 => "SLONG",
        10 => "SRATIONAL",
        11 => "FLOAT",
        12 => "DOUBLE",
        13 => "IFD",
        _ => "?",
    };

    let label = if name.is_empty() {
        format!("Tag 0x{:04X}", tag)
    } else {
        name.to_string()
    };

    let detail = format!("{} x{} val={}", type_str, cnt, val);
    (label, detail)
}

fn r16(data: &[u8], offset: usize, le: bool) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    if le {
        u16::from_le_bytes([data[offset], data[offset + 1]])
    } else {
        u16::from_be_bytes([data[offset], data[offset + 1]])
    }
}

fn r16_be(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    u16::from_be_bytes([data[offset], data[offset + 1]])
}

fn r32(data: &[u8], offset: usize, le: bool) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    if le {
        u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
    } else {
        u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
    }
}
