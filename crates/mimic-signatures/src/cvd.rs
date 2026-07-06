/// ClamAV .cvd / .cld database container parser.
///
/// Format: 512-byte ASCII header + tar.gz payload.
/// Header line: `ClamAV-VDB:build_time:version:sigs:func_level:md5:builder:stime:type\n`

use flate2::read::GzDecoder;
use std::io::{self, Read, Cursor};
use tar::Archive;
use tracing::{debug, info};

const CVD_HEADER_SIZE: usize = 512;

#[derive(Debug)]
pub struct CvdHeader {
    pub build_time: String,
    pub version: u32,
    pub num_sigs: u64,
    pub md5: String,
    pub builder: String,
}

pub fn parse_cvd_header(data: &[u8]) -> Option<CvdHeader> {
    if data.len() < CVD_HEADER_SIZE {
        return None;
    }
    let header_str = std::str::from_utf8(&data[..CVD_HEADER_SIZE]).ok()?;
    let line = header_str.lines().next()?;

    if !line.starts_with("ClamAV-VDB:") {
        return None;
    }

    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() < 8 {
        return None;
    }

    Some(CvdHeader {
        build_time: parts[1].to_string(),
        version: parts[2].parse().unwrap_or(0),
        num_sigs: parts[3].parse().unwrap_or(0),
        md5: parts[5].to_string(),
        builder: parts[6].to_string(),
    })
}

/// Extracted signature file from a .cvd/.cld container.
#[derive(Debug)]
pub struct CvdEntry {
    pub filename: String,
    pub data: Vec<u8>,
}

/// Extract all signature files from a .cvd/.cld blob.
pub fn extract_cvd(data: &[u8]) -> io::Result<Vec<CvdEntry>> {
    if data.len() <= CVD_HEADER_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "CVD too small"));
    }

    if let Some(header) = parse_cvd_header(data) {
        info!(
            version = header.version,
            num_sigs = header.num_sigs,
            build_time = %header.build_time,
            builder = %header.builder,
            "Parsed ClamAV CVD header"
        );
    }

    let payload = &data[CVD_HEADER_SIZE..];
    let gz = GzDecoder::new(Cursor::new(payload));
    let mut archive = Archive::new(gz);
    let mut entries = Vec::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry
            .path()?
            .to_string_lossy()
            .to_string();
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf)?;
        debug!(filename = %path, size = buf.len(), "extracted CVD entry");
        entries.push(CvdEntry {
            filename: path,
            data: buf,
        });
    }

    Ok(entries)
}
