//! JPEG Lossless (SOF3) parsing for DNG exploit detection.
//! Scans for SOF3 marker and reads component count without full JPEG decode.

/// JPEG SOF3 marker (Start of Frame, lossless).
pub const SOF3_MARKER: u16 = 0xFFC3;

/// Scan `data` for SOF3 (0xFFC3) and return the component count (number of components).
/// Returns None if no SOF3 found or segment too short.
/// SOF3 layout after marker: length(2), precision(1), height(2), width(2), num_components(1), ...
#[inline]
pub fn sof3_component_count(data: &[u8]) -> Option<u8> {
    let mut i = 0;
    while i + 2 <= data.len() {
        if data[i] == 0xFF && data.get(i + 1) == Some(&0xC3) {
            let segment_start = i + 2;
            if segment_start + 7 > data.len() {
                return None;
            }
            let _length = u16::from_be_bytes([data[segment_start], data[segment_start + 1]]);
            let _precision = data[segment_start + 2];
            let _height = u16::from_be_bytes([data[segment_start + 3], data[segment_start + 4]]);
            let _width = u16::from_be_bytes([data[segment_start + 5], data[segment_start + 6]]);
            let num_components = data[segment_start + 7];
            return Some(num_components);
        }
        i += 1;
    }
    None
}

/// Scan for SOF3 and return (component_count, offset_of_sof3). Uses first SOF3 if multiple.
pub fn find_sof3(data: &[u8]) -> Option<(u8, usize)> {
    let mut i = 0;
    while i + 2 <= data.len() {
        if data[i] == 0xFF && data.get(i + 1) == Some(&0xC3) {
            let segment_start = i + 2;
            if segment_start + 7 >= data.len() {
                return None;
            }
            let num_components = data[segment_start + 7];
            return Some((num_components, i));
        }
        i += 1;
    }
    None
}

