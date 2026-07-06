//! Load and run WASM plugins. ABI: guest exports `scan(ptr: i32, len: i32) -> i32`.

use crate::abi::PluginVerdict;
use mimic_core::{MimicError, ScanVerdict, Verdict};
use std::path::Path;
use std::sync::Arc;
use wasmtime::{Engine, Linker, Module, Store};

/// A single loaded WASM plugin.
pub struct WasmPlugin {
    name: String,
    engine: Engine,
    module: Module,
}

impl WasmPlugin {
    /// Load a plugin from a .wasm file.
    pub fn load(path: &Path) -> Result<Self, MimicError> {
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        let bytes = std::fs::read(path)
            .map_err(|e| MimicError::Engine(format!("failed to read plugin {}: {}", path.display(), e)))?;
        Self::load_bytes(&name, &bytes)
    }

    /// Load a plugin from in-memory WASM bytes (e.g. embedded mimic_detect).
    pub fn load_bytes(name: &str, bytes: &[u8]) -> Result<Self, MimicError> {
        let engine = Engine::default();
        let module = Module::new(&engine, bytes)
            .map_err(|e| MimicError::Engine(format!("invalid WASM plugin {}: {}", name, e)))?;
        Ok(Self {
            name: name.to_string(),
            engine,
            module,
        })
    }

    /// Run the plugin's scan function on the given data. Returns (verdict, optional message).
    pub fn scan(&self, data: &[u8]) -> Result<(PluginVerdict, Option<String>), MimicError> {
        let mut store = Store::new(&self.engine, ());
        let linker = Linker::new(&self.engine);

        let instance = linker
            .instantiate(&mut store, &self.module)
            .map_err(|e| MimicError::Engine(format!("plugin {} instantiate: {}", self.name, e)))?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| MimicError::Engine(format!("plugin {} has no 'memory' export", self.name)))?;

        let scan_fn = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, "scan")
            .map_err(|e| MimicError::Engine(format!("plugin {} has no 'scan(ptr,len)->i32' export: {}", self.name, e)))?;

        let ptr = 0i32;
        let page_size = 65536usize;
        let need_pages = (data.len() + page_size - 1) / page_size;
        if need_pages > 0 {
            memory.grow(&mut store, need_pages as u64).map_err(|e| {
                MimicError::Engine(format!("plugin {} memory grow: {}", self.name, e))
            })?;
        }

        let base = ptr as u32 as usize;
        if base + data.len() <= memory.data_size(&store) {
            memory.write(&mut store, base, data).map_err(|e| {
                MimicError::Engine(format!("plugin {} memory write: {}", self.name, e))
            })?;
        } else {
            return Err(MimicError::Engine(format!(
                "plugin {}: file too large for plugin memory",
                self.name
            )));
        }

        let verdict_i32 = scan_fn.call(&mut store, (ptr, data.len() as i32)).map_err(|e| {
            MimicError::Engine(format!("plugin {} scan call: {}", self.name, e))
        })?;

        let verdict = PluginVerdict::from_i32(verdict_i32);
        Ok((verdict, None))
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Engine that holds multiple plugins and runs them in sequence.
pub struct WasmPluginEngine {
    plugins: Vec<Arc<WasmPlugin>>,
}

impl WasmPluginEngine {
    pub fn new() -> Self {
        Self { plugins: Vec::new() }
    }

    /// Load all .wasm files from a directory.
    pub fn load_dir(&mut self, dir: &Path) -> Result<(), MimicError> {
        if !dir.is_dir() {
            return Ok(());
        }
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("wasm") {
                match WasmPlugin::load(&path) {
                    Ok(p) => self.plugins.push(Arc::new(p)),
                    Err(e) => tracing::warn!(path = %path.display(), error = %e, "skipping invalid WASM plugin"),
                }
            }
        }
        Ok(())
    }

    /// Load a single .wasm file.
    pub fn load_file(&mut self, path: &Path) -> Result<(), MimicError> {
        let plugin = WasmPlugin::load(path)?;
        self.plugins.push(Arc::new(plugin));
        Ok(())
    }

    /// Load a plugin from in-memory WASM bytes (e.g. embedded mimic_detect).
    pub fn load_bytes(&mut self, name: &str, bytes: &[u8]) -> Result<(), MimicError> {
        let plugin = WasmPlugin::load_bytes(name, bytes)?;
        self.plugins.push(Arc::new(plugin));
        Ok(())
    }

    /// Run all plugins on the file data. Merges verdicts (infected wins).
    pub fn scan(&self, data: &[u8]) -> ScanVerdict {
        use tracing::debug;
        let mut verdict = ScanVerdict::clean();
        for plugin in &self.plugins {
            debug!(plugin = %plugin.name(), data_len = data.len(), "WASM plugin scan start");
            match plugin.scan(data) {
                Ok((v, _msg)) => {
                    let core_verdict = match v {
                        PluginVerdict::Clean => Verdict::Clean,
                        PluginVerdict::Suspicious => Verdict::Suspicious,
                        PluginVerdict::Infected => Verdict::Infected,
                    };
                    debug!(
                        plugin = %plugin.name(),
                        verdict = ?core_verdict,
                        "WASM plugin scan done"
                    );
                    if core_verdict != Verdict::Clean {
                        let threat = mimic_core::MimicThreat {
                            id: format!("plugin:{}", plugin.name()),
                            description: format!("WASM plugin '{}' reported {}", plugin.name(), core_verdict),
                            reference: None,
                        };
                        verdict.merge(ScanVerdict {
                            verdict: core_verdict,
                            signature_threats: Vec::new(),
                            mimic_threats: vec![threat],
                            yara_matches: Vec::new(),
                        });
                    }
                }
                Err(e) => {
                    debug!(plugin = %plugin.name(), error = %e, "WASM plugin scan failed");
                }
            }
        }
        verdict
    }

    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }

    /// Names of all loaded WASM plugins (for dashboard / API).
    pub fn plugin_names(&self) -> Vec<String> {
        self.plugins.iter().map(|p| p.name().to_string()).collect()
    }
}

impl Default for WasmPluginEngine {
    fn default() -> Self {
        Self::new()
    }
}
