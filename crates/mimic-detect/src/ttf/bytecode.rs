//! TrueType bytecode scanner for undocumented ADJUST instruction (CVE-2023-41990).
//! See https://github.com/msuiche/elegant-bouncer/blob/main/src/ttf.rs and
//! https://securelist.com/operation-triangulation-the-last-hardware-mystery/111669/

/// Undocumented Apple-only ADJUST opcodes (Triangulation indicator).
pub const ADJUST_OPCODE_1: u8 = 0x8F;
pub const ADJUST_OPCODE_2: u8 = 0x90;

/// Maximum iterations to avoid infinite loops on malformed bytecode.
const MAX_ITERATIONS_FACTOR: usize = 2;

/// Scan bytecode for ADJUST (0x8F or 0x90). Handles variable-length instructions.
/// Returns true if ADJUST found, false if not. Stops on out-of-range.
pub fn contains_adjust_instruction(byte_data: &[u8]) -> bool {
    let max_iterations = byte_data.len().saturating_mul(MAX_ITERATIONS_FACTOR);
    let mut off = 0;
    let mut iterations = 0;

    while off < byte_data.len() {
        if iterations >= max_iterations {
            break;
        }
        iterations += 1;

        let opcode = byte_data[off];
        if opcode == ADJUST_OPCODE_1 || opcode == ADJUST_OPCODE_2 {
            return true;
        }

        match opcode {
            0x40 => {
                if off + 1 >= byte_data.len() {
                    break;
                }
                let count = byte_data[off + 1] as usize;
                off += 2;
                if off + count > byte_data.len() {
                    break;
                }
                off += count;
            }
            0x41 => {
                if off + 1 >= byte_data.len() {
                    break;
                }
                let count = byte_data[off + 1] as usize;
                off += 2;
                if off + count * 2 > byte_data.len() {
                    break;
                }
                off += count * 2;
            }
            0xB0..=0xB7 => {
                let count = (opcode - 0xB0 + 1) as usize;
                off += 1;
                if off + count > byte_data.len() {
                    break;
                }
                off += count;
            }
            0xB8..=0xBF => {
                let count = (opcode - 0xB8 + 1) as usize;
                off += 1;
                if off + count * 2 > byte_data.len() {
                    break;
                }
                off += count * 2;
            }
            _ => {
                off += 1;
            }
        }
    }
    false
}
