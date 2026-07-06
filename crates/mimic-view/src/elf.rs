//! ELF (Executable and Linkable Format) structure parser for the hex inspector.
//! Covers ELF header, program headers, section headers, and section data.

use crate::Node;

pub fn parse(data: &[u8]) -> Vec<Node> {
    let mut nodes = Vec::new();
    let len = data.len();
    if len < 52 {
        return nodes;
    }

    if data[0] != 0x7F || data[1] != b'E' || data[2] != b'L' || data[3] != b'F' {
        return nodes;
    }

    let class = data[4]; // 1 = 32-bit, 2 = 64-bit
    let data_enc = data[5]; // 1 = LE, 2 = BE
    let is_64 = class == 2;
    let le = data_enc == 1;

    let class_str = if is_64 { "ELF64" } else { "ELF32" };
    let endian_str = if le { "LE" } else { "BE" };

    nodes.push(Node {
        kind: "header".into(),
        label: "ELF Header".into(),
        detail: format!("{} {}, e_ident", class_str, endian_str),
        start: 0,
        end: 16,
    });

    let (_e_type_off, e_machine_off, e_phoff_off, e_shoff_off, e_phnum_off, e_shnum_off, e_shstrndx_off, ehdr_size) = if is_64 {
        (16u32, 18u32, 32u32, 40u32, 54u32, 60u32, 62u32, 64usize)
    } else {
        (16u32, 18u32, 28u32, 32u32, 42u32, 48u32, 50u32, 52usize)
    };

    if len < ehdr_size {
        return nodes;
    }

    let e_type = r16(data, e_machine_off as usize - 2, le);
    let e_machine = r16(data, e_machine_off as usize, le);
    let e_phnum = r16(data, e_phnum_off as usize, le) as usize;
    let e_shnum = r16(data, e_shnum_off as usize, le) as usize;
    let e_shstrndx = r16(data, e_shstrndx_off as usize, le) as usize;

    let e_phoff = if is_64 { r64(data, e_phoff_off as usize, le) as usize } else { r32(data, e_phoff_off as usize, le) as usize };
    let e_shoff = if is_64 { r64(data, e_shoff_off as usize, le) as usize } else { r32(data, e_shoff_off as usize, le) as usize };

    let type_str = match e_type {
        1 => "ET_REL",
        2 => "ET_EXEC",
        3 => "ET_DYN",
        4 => "ET_CORE",
        _ => "?",
    };
    let machine_str = match e_machine {
        3 => "EM_386",
        62 => "EM_X86_64",
        183 => "EM_AARCH64",
        40 => "EM_ARM",
        _ => "?",
    };

    nodes.push(Node {
        kind: "header".into(),
        label: "ELF Header (rest)".into(),
        detail: format!("Type={} Machine={} phnum={} shnum={}", type_str, machine_str, e_phnum, e_shnum),
        start: 16,
        end: ehdr_size,
    });

    let phent_size = if is_64 { 56 } else { 32 };
    let shent_size = if is_64 { 64 } else { 40 };

    for i in 0..e_phnum {
        let off = e_phoff + i * phent_size;
        if off + phent_size > len {
            break;
        }
        let p_type = r32(data, off, le);
        let (p_offset, p_filesz) = if is_64 {
            (r64(data, off + 8, le) as usize, r64(data, off + 32, le) as usize)
        } else {
            (r32(data, off + 4, le) as usize, r32(data, off + 16, le) as usize)
        };
        let pt_str = match p_type {
            0 => "PT_NULL",
            1 => "PT_LOAD",
            2 => "PT_DYNAMIC",
            3 => "PT_INTERP",
            4 => "PT_NOTE",
            5 => "PT_SHLIB",
            6 => "PT_PHDR",
            _ => "PT_?",
        };
        nodes.push(Node {
            kind: "phdr".into(),
            label: format!("Program Header {}", i),
            detail: format!("{} file_off=0x{:X} size={}", pt_str, p_offset, p_filesz),
            start: off,
            end: off + phent_size,
        });
        if p_offset > 0 && p_filesz > 0 && p_offset < len {
            let end = (p_offset + p_filesz).min(len);
            nodes.push(Node {
                kind: "data".into(),
                label: format!("{} segment data", pt_str),
                detail: format!("{} bytes", end - p_offset),
                start: p_offset,
                end,
            });
        }
    }

    let mut sh_name_offset: Option<usize> = None;
    if e_shstrndx < e_shnum && e_shoff + e_shnum * shent_size <= len {
        let shstr_off = e_shoff + e_shstrndx * shent_size;
        let sh_offset = if is_64 { r64(data, shstr_off + 24, le) as usize } else { r32(data, shstr_off + 16, le) as usize };
        sh_name_offset = Some(sh_offset);
    }

    for i in 0..e_shnum {
        let off = e_shoff + i * shent_size;
        if off + shent_size > len {
            break;
        }
        let sh_name = r32(data, off, le) as usize;
        let sh_type = r32(data, off + 4, le);
        let (sh_offset, sh_size) = if is_64 {
            (r64(data, off + 24, le) as usize, r64(data, off + 32, le) as usize)
        } else {
            (r32(data, off + 16, le) as usize, r32(data, off + 20, le) as usize)
        };

        let section_name = resolve_sh_name(data, sh_name, sh_name_offset);
        let type_str = match sh_type {
            0 => "SHT_NULL",
            1 => "SHT_PROGBITS",
            2 => "SHT_SYMTAB",
            3 => "SHT_STRTAB",
            4 => "SHT_RELA",
            5 => "SHT_HASH",
            6 => "SHT_DYNAMIC",
            7 => "SHT_NOTE",
            8 => "SHT_NOBITS",
            9 => "SHT_REL",
            11 => "SHT_DYNSYM",
            _ => "SHT_?",
        };

        nodes.push(Node {
            kind: "section".into(),
            label: section_name.clone(),
            detail: format!("{} offset=0x{:X} size={}", type_str, sh_offset, sh_size),
            start: off,
            end: off + shent_size,
        });

        if sh_type != 8 && sh_offset > 0 && sh_size > 0 && sh_offset < len {
            let end = (sh_offset + sh_size).min(len);
            nodes.push(Node {
                kind: "data".into(),
                label: format!("{} data", section_name),
                detail: format!("{} bytes", end - sh_offset),
                start: sh_offset,
                end,
            });
        }
    }

    nodes
}

fn resolve_sh_name(data: &[u8], name_off: usize, shstr_off: Option<usize>) -> String {
    let Some(base) = shstr_off else {
        return format!("section{}", name_off);
    };
    let off = base + name_off;
    if off >= data.len() {
        return format!("section{}", name_off);
    }
    let end = data[off..].iter().position(|&b| b == 0).map(|p| off + p).unwrap_or(data.len());
    if end > off {
        String::from_utf8_lossy(&data[off..end]).into_owned()
    } else {
        format!("section{}", name_off)
    }
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

fn r64(data: &[u8], offset: usize, le: bool) -> u64 {
    if offset + 8 > data.len() {
        return 0;
    }
    if le {
        u64::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ])
    } else {
        u64::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ])
    }
}
