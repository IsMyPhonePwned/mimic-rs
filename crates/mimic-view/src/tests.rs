#[cfg(test)]
mod tests {
    use crate::{detect_format, inspect, rtf, pdf, dng, pe, elf, archive};

    #[test]
    fn detect_rtf() {
        assert_eq!(detect_format(b"{\\rtf1 hello}"), "rtf");
    }

    #[test]
    fn detect_pdf() {
        assert_eq!(detect_format(b"%PDF-1.4\n"), "pdf");
    }

    #[test]
    fn detect_dng_le() {
        let data = [0x49, 0x49, 0x2A, 0x00, 0x08, 0x00, 0x00, 0x00];
        assert_eq!(detect_format(&data), "dng");
    }

    #[test]
    fn detect_dng_be() {
        let data = [0x4D, 0x4D, 0x00, 0x2A, 0x00, 0x00, 0x00, 0x08];
        assert_eq!(detect_format(&data), "dng");
    }

    #[test]
    fn detect_pe() {
        let mut data = vec![0x4D, 0x5A]; // MZ
        data.resize(0x40, 0);
        data[0x3C] = 0x80;
        data[0x3D] = 0x00;
        data[0x3E] = 0x00;
        data[0x3F] = 0x00; // e_lfanew = 0x80
        data.resize(0x84, 0);
        data[0x80] = b'P';
        data[0x81] = b'E';
        data[0x82] = 0;
        data[0x83] = 0;
        assert_eq!(detect_format(&data), "pe");
    }

    #[test]
    fn detect_elf() {
        let data = b"\x7FELF\x01\x01\x01\x00";
        assert_eq!(detect_format(data), "elf");
    }

    #[test]
    fn detect_zip() {
        assert_eq!(detect_format(b"PK\x03\x04\x00\x00"), "zip");
        assert_eq!(detect_format(b"PK\x01\x02ab"), "zip");
        assert_eq!(detect_format(b"PK\x05\x06\x00\x00"), "zip");
    }

    #[test]
    fn detect_rar() {
        assert_eq!(detect_format(b"Rar!\x1A\x07\x01\x00"), "rar");
        assert_eq!(detect_format(b"Rar!\x1A\x07\x00"), "rar");
    }

    #[test]
    fn detect_unknown() {
        assert_eq!(detect_format(b"hello world"), "unknown");
    }

    #[test]
    fn rtf_basic_parse() {
        let rtf = b"{\\rtf1\\ansi\\fonttbl some text}";
        let nodes = rtf::parse(rtf);
        assert!(!nodes.is_empty());
        assert_eq!(nodes[0].kind, "header");
        assert!(nodes.iter().any(|n| n.label == "\\fonttbl"));
    }

    #[test]
    fn rtf_object_detection() {
        let rtf = b"{\\rtf1 {\\object\\objemb\\objdata ABCDEF}}";
        let nodes = rtf::parse(rtf);
        assert!(nodes.iter().any(|n| n.label == "\\object"));
        assert!(nodes.iter().any(|n| n.label == "\\objemb"));
        assert!(nodes.iter().any(|n| n.label == "\\objdata"));
    }

    #[test]
    fn rtf_ole_signature() {
        let mut rtf = b"{\\rtf1 data ".to_vec();
        rtf.extend_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
        rtf.extend_from_slice(b" more}");
        let nodes = rtf::parse(&rtf);
        assert!(nodes.iter().any(|n| n.kind == "ole"));
    }

    #[test]
    fn pdf_basic_parse() {
        let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n";
        let nodes = pdf::parse(pdf);
        assert!(nodes.iter().any(|n| n.kind == "header" && n.label == "PDF Header"));
        assert!(nodes.iter().any(|n| n.kind == "object"));
        assert!(nodes.iter().any(|n| n.label == "%%EOF"));
    }

    #[test]
    fn pdf_javascript_warning() {
        let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Action /JavaScript (alert) >>\nendobj\n%%EOF\n";
        let nodes = pdf::parse(pdf);
        assert!(
            nodes.iter().any(|n| n.kind == "warning"),
            "expected a warning node for /JavaScript"
        );
    }

    #[test]
    fn dng_basic_parse() {
        // Minimal TIFF LE: II, 0x002A, IFD0 at offset 8, 0 entries, next IFD = 0
        let data: Vec<u8> = vec![
            0x49, 0x49, 0x2A, 0x00, // II + magic
            0x08, 0x00, 0x00, 0x00, // IFD0 offset = 8
            0x00, 0x00, // 0 entries
            0x00, 0x00, 0x00, 0x00, // next IFD = 0
        ];
        let nodes = dng::parse(&data);
        assert!(nodes.iter().any(|n| n.kind == "header" && n.label == "TIFF Header"));
        assert!(nodes.iter().any(|n| n.kind == "ifd" && n.label == "IFD0"));
    }

    #[test]
    fn dng_ifd_entries() {
        // TIFF LE with 1 entry (ImageWidth = 100)
        let data = vec![
            0x49, 0x49, 0x2A, 0x00,
            0x08, 0x00, 0x00, 0x00, // IFD0 at 8
            0x01, 0x00,             // 1 entry
            // Tag=0x0100(ImageWidth), Type=3(SHORT), Count=1, Value=100
            0x00, 0x01, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // next IFD = 0
        ];
        let nodes = dng::parse(&data);
        assert!(nodes.iter().any(|n| n.label == "ImageWidth"));
    }

    #[test]
    fn inspect_returns_format() {
        let rtf = b"{\\rtf1 hello}";
        let result = inspect(rtf);
        assert_eq!(result.format, "rtf");
        assert!(!result.nodes.is_empty());
    }

    #[test]
    fn pe_basic_parse() {
        let mut data = vec![0x4D, 0x5A];
        data.resize(0x40, 0);
        data[0x3C] = 0x80;
        data[0x3D] = 0;
        data[0x3E] = 0;
        data[0x3F] = 0;
        data.resize(0x84, 0);
        data[0x80] = b'P';
        data[0x81] = b'E';
        data[0x82] = 0;
        data[0x83] = 0;
        // COFF: Machine=0x14c, 0 sections, 0 optional size (20 bytes total)
        data.extend_from_slice(&[
            0x4C, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let nodes = pe::parse(&data);
        assert!(nodes.iter().any(|n| n.label == "DOS Header"));
        assert!(nodes.iter().any(|n| n.label == "PE Signature"));
        assert!(nodes.iter().any(|n| n.label == "COFF Header"));
    }

    #[test]
    fn zip_list_files() {
        let mut data = vec![0x50, 0x4B, 0x03, 0x04];
        data.resize(100, 0);
        data.extend_from_slice(&[
            0x50, 0x4B, 0x05, 0x06, 0, 0, 0, 0, 1, 0, 1, 0,
            20, 0, 0, 0, 100, 0, 0, 0, 0, 0,
        ]);
        let nodes = archive::parse_zip(&data);
        assert!(nodes.iter().any(|n| n.label.contains("End of central")));
    }

    #[test]
    fn rar_list_files() {
        let mut data = b"Rar!\x1A\x07\x00".to_vec();
        data.extend_from_slice(&[0x00, 0x00, 0x74, 0x00, 0x00, 0x0A, 0x00]);
        data.extend_from_slice(&[0x08, 0x00]);
        data.extend_from_slice(b"file.txt");
        let nodes = archive::parse_rar(&data);
        assert!(nodes.iter().any(|n| n.label.contains("RAR")));
        assert!(nodes.iter().any(|n| n.kind == "file" && n.label == "file.txt"));
    }

    #[test]
    fn elf_basic_parse() {
        let mut data = vec![0x7F, b'E', b'L', b'F', 2, 1, 1, 0];
        data.resize(64, 0);
        // ELF64 header rest: e_type=2, e_machine=62, e_version=1, e_entry=0, e_phoff=0, e_shoff=64
        data[16..24].copy_from_slice(&[2, 0, 62, 0, 1, 0, 0, 0]);
        data[40..48].copy_from_slice(&[64, 0, 0, 0, 0, 0, 0, 0]); // e_shoff
        data[52..64].copy_from_slice(&[64, 0, 56, 0, 0, 0, 64, 0, 1, 0, 0, 0]); // e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
        data.resize(128, 0); // one section header at 64 (64 bytes)
        let nodes = elf::parse(&data);
        assert!(nodes.iter().any(|n| n.label == "ELF Header"));
        assert!(nodes.iter().any(|n| n.kind == "section"));
    }
}
