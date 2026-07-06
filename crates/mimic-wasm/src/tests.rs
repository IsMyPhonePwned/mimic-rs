//! Unit tests for mimic-wasm.

use super::*;

#[test]
fn plugin_verdict_from_i32() {
    assert_eq!(PluginVerdict::from_i32(0), PluginVerdict::Clean);
    assert_eq!(PluginVerdict::from_i32(1), PluginVerdict::Suspicious);
    assert_eq!(PluginVerdict::from_i32(2), PluginVerdict::Infected);
    assert_eq!(PluginVerdict::from_i32(-1), PluginVerdict::Clean);
    assert_eq!(PluginVerdict::from_i32(99), PluginVerdict::Clean);
}

#[test]
fn plugin_verdict_repr() {
    assert_eq!(PluginVerdict::Clean as i32, 0);
    assert_eq!(PluginVerdict::Suspicious as i32, 1);
    assert_eq!(PluginVerdict::Infected as i32, 2);
}
