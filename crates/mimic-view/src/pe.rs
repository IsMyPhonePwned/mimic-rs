//! PE (Portable Executable) / COFF structure parser for the hex inspector.
//! Covers DOS header, PE signature, COFF header, optional header, section table.

use crate::Node;

pub fn parse(data: &[u8]) -> Vec<Node> {
    let mut nodes = Vec::new();
    let len = data.len();
    if len < 64 {
        return nodes;
    }

    // DOS header: MZ
    if data[0] != 0x4D || data[1] != 0x5A {
        return nodes;
    }

    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    nodes.push(Node {
        kind: "header".into(),
        label: "DOS Header".into(),
        detail: format!("MZ, e_lfanew=0x{:08X}", e_lfanew),
        start: 0,
        end: 64,
    });

    if e_lfanew > 64 && e_lfanew < len {
        let stub_end = e_lfanew.min(128);
        nodes.push(Node {
            kind: "data".into(),
            label: "DOS stub".into(),
            detail: format!("{} bytes", stub_end - 64),
            start: 64,
            end: stub_end,
        });
    }

    if e_lfanew + 4 > len || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return nodes;
    }

    nodes.push(Node {
        kind: "header".into(),
        label: "PE Signature".into(),
        detail: "PE\\0\\0".into(),
        start: e_lfanew,
        end: e_lfanew + 4,
    });

    let coff_off = e_lfanew + 4;
    if coff_off + 20 > len {
        return nodes;
    }

    let machine = u16::from_le_bytes([data[coff_off], data[coff_off + 1]]);
    let num_sections = u16::from_le_bytes([data[coff_off + 2], data[coff_off + 3]]) as usize;
    let opt_size = u16::from_le_bytes([data[coff_off + 16], data[coff_off + 17]]) as usize;
    let _chars = u16::from_le_bytes([data[coff_off + 18], data[coff_off + 19]]);

    let machine_str = match machine {
        0x014c => "i386",
        0x8664 => "x64",
        0x01c0 => "ARM",
        0xaa64 => "ARM64",
        _ => "?",
    };

    nodes.push(Node {
        kind: "header".into(),
        label: "COFF Header".into(),
        detail: format!("Machine={} ({:#06x}), {} sections, opt size={}", machine_str, machine, num_sections, opt_size),
        start: coff_off,
        end: coff_off + 20,
    });

    let opt_off = coff_off + 20;
    let opt_end = opt_off + opt_size;
    if opt_end <= len && opt_size >= 2 {
        let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
        let opt_type = if magic == 0x10b { "PE32" } else if magic == 0x20b { "PE32+" } else { "?" };
        let entry_rva = if opt_size >= 24 {
            let e = u32::from_le_bytes([data[opt_off + 16], data[opt_off + 17], data[opt_off + 18], data[opt_off + 19]]);
            format!("Entry RVA=0x{:08X}", e)
        } else {
            String::new()
        };
        nodes.push(Node {
            kind: "object".into(),
            label: "Optional Header".into(),
            detail: format!("{} {}", opt_type, entry_rva).trim().to_string(),
            start: opt_off,
            end: opt_end,
        });
    }

    let section_table_off = opt_end;
    for i in 0..num_sections {
        let entry_off = section_table_off + i * 40;
        if entry_off + 40 > len {
            break;
        }
        let name = ascii_trim(&data[entry_off..entry_off + 8]);
        let virt_size = u32::from_le_bytes([
            data[entry_off + 8], data[entry_off + 9], data[entry_off + 10], data[entry_off + 11],
        ]);
        let virt_addr = u32::from_le_bytes([
            data[entry_off + 12], data[entry_off + 13], data[entry_off + 14], data[entry_off + 15],
        ]);
        let raw_size = u32::from_le_bytes([
            data[entry_off + 16], data[entry_off + 17], data[entry_off + 18], data[entry_off + 19],
        ]) as usize;
        let raw_ptr = u32::from_le_bytes([
            data[entry_off + 20], data[entry_off + 21], data[entry_off + 22], data[entry_off + 23],
        ]) as usize;

        let section_name = if name.starts_with('/') {
            format!("Section {} (name in strtab)", i)
        } else if name.is_empty() {
            format!(".section{}", i)
        } else {
            name.clone()
        };

        nodes.push(Node {
            kind: "section".into(),
            label: section_name.clone(),
            detail: format!("VA=0x{:08X} Size=0x{:X} Raw@0x{:08X} {} bytes", virt_addr, virt_size, raw_ptr, raw_size),
            start: entry_off,
            end: entry_off + 40,
        });

        if raw_ptr > 0 && raw_size > 0 {
            let data_end = (raw_ptr + raw_size).min(len);
            if raw_ptr < len {
                nodes.push(Node {
                    kind: "data".into(),
                    label: format!("{} data", section_name),
                    detail: format!("{} bytes", data_end - raw_ptr),
                    start: raw_ptr,
                    end: data_end,
                });
            }
        }
    }

    nodes
}

fn ascii_trim(b: &[u8]) -> String {
    let end = b.iter().position(|&x| x == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).trim().to_string()
}
