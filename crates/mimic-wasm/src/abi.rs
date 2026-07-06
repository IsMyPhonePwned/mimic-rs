/// Verdict returned by a WASM plugin (must match guest convention).
/// Use [`from_i32`](PluginVerdict::from_i32) to convert the guest return value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum PluginVerdict {
    Clean = 0,
    Suspicious = 1,
    Infected = 2,
}

impl PluginVerdict {
    pub fn from_i32(n: i32) -> Self {
        match n {
            1 => PluginVerdict::Suspicious,
            2 => PluginVerdict::Infected,
            _ => PluginVerdict::Clean,
        }
    }
}
