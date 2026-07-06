//! MCP server handler exposing Mimic scan tools to LLMs.

use mimic_core::Verdict;
use mimic_engine::MimicEngine;
use rmcp::{
    model::{
        CallToolRequestParams, CallToolResult, Implementation, ListToolsResult,
        ServerCapabilities, ServerInfo, Tool,
        object,
    },
    service::RequestContext,
    ErrorData as McpError, RoleServer, ServerHandler,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use walkdir::WalkDir;

/// MCP server that exposes scan and engine tools for LLM use.
#[derive(Clone)]
pub struct MimicMcpServer {
    engine: Arc<MimicEngine>,
}

impl MimicMcpServer {
    pub fn new(engine: MimicEngine) -> Self {
        Self {
            engine: Arc::new(engine),
        }
    }

    fn tools() -> Vec<Tool> {
        vec![
            Tool::new(
                "scan_file",
                "Scan a file on disk for malware using Mimic (ClamAV signatures, YARA, exploit detection). Returns verdict, hashes, threats, and match reasons.",
                Arc::new(object(serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Absolute or relative path to the file to scan" }
                    },
                    "required": ["path"]
                }))),
            ),
            Tool::new(
                "scan_bytes",
                "Scan in-memory file content for malware. Provide filename and base64-encoded bytes. Returns verdict, hashes, threats, and match reasons.",
                Arc::new(object(serde_json::json!({
                    "type": "object",
                    "properties": {
                        "filename": { "type": "string", "description": "Logical filename (e.g. document.pdf)" },
                        "data_base64": { "type": "string", "description": "Base64-encoded file content" }
                    },
                    "required": ["filename", "data_base64"]
                }))),
            ),
            Tool::new(
                "scan_directory",
                "Scan all files in a directory for malware. Returns a list of ScanResult per file. Respects engine max file size.",
                Arc::new(object(serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Absolute or relative path to the directory to scan" },
                        "recursive": { "type": "boolean", "description": "If true, recurse into subdirectories. Default true.", "default": true }
                    },
                    "required": ["path"]
                }))),
            ),
            Tool::new(
                "scan_paths",
                "Scan a list of file paths for malware. Returns a list of ScanResult per path.",
                Arc::new(object(serde_json::json!({
                    "type": "object",
                    "properties": {
                        "paths": { "type": "array", "items": { "type": "string" }, "description": "List of absolute or relative file paths to scan" }
                    },
                    "required": ["paths"]
                }))),
            ),
            Tool::new(
                "get_engine_info",
                "Return information about the Mimic engine: loaded signature counts, plugin names, YARA/ClamAV/sandbox status, max file size.",
                Arc::new(object(serde_json::json!({
                    "type": "object",
                    "properties": {}
                }))),
            ),
            Tool::new(
                "signature_lookup",
                "Return a short description of a ClamAV signature by name or type. Signature names are malware IDs (e.g. Win.Trojan.Agent). Describes signature types: hash-md5, hash-sha256, body-ndb, logical-ldb, pe-section-*, container-cdb.",
                Arc::new(object(serde_json::json!({
                    "type": "object",
                    "properties": {
                        "name": { "type": "string", "description": "Signature name (ClamAV malware ID) or leave empty for type descriptions only" },
                        "type": { "type": "string", "description": "Signature type: hash-md5, hash-sha256, body-ndb, logical-ldb, pe-section-md5, pe-section-sha256, container-cdb" }
                    }
                }))),
            ),
        ]
    }

    fn collect_directory_files(path: &Path, recursive: bool, max_size: u64) -> Vec<PathBuf> {
        let mut files = Vec::new();
        let walker = if recursive {
            WalkDir::new(path).into_iter()
        } else {
            WalkDir::new(path).max_depth(1).into_iter()
        };
        for entry in walker.filter_map(|e| e.ok()) {
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            if max_size > 0 {
                if let Ok(meta) = std::fs::metadata(p) {
                    if meta.len() > max_size {
                        continue;
                    }
                }
            }
            files.push(p.to_path_buf());
        }
        files
    }
}

impl ServerHandler for MimicMcpServer {
    fn get_info(&self) -> ServerInfo {
        tracing::info!("MCP request: get_info (initialize)");
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("mimic-mcp", env!("CARGO_PKG_VERSION")))
    }

    async fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let tools = Self::tools();
        tracing::info!("MCP request: list_tools (count={})", tools.len());
        tracing::debug!("list_tools: returning {} tools", tools.len());
        Ok(ListToolsResult {
            tools,
            next_cursor: None,
            meta: None,
        })
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        Self::tools().into_iter().find(|t| t.name.as_ref() == name)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let default_args = serde_json::Map::new();
        let args = request.arguments.as_ref().unwrap_or(&default_args);
        let engine = Arc::clone(&self.engine);
        let tool_name = request.name.as_ref();

        tracing::info!("MCP request: call_tool name={}", tool_name);
        tracing::debug!("call_tool: tool={}", tool_name);

        match request.name.as_ref() {
            "scan_file" => {
                let path = args
                    .get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::invalid_params("missing argument: path", None))?;
                let path = path.to_string();
                tracing::info!("MCP scan_file path={}", path);
                tracing::debug!("scan_file: path={}", path);
                let path_clone = path.clone();
                let result = tokio::task::spawn_blocking(move || engine.scan_file(Path::new(&path)))
                    .await
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                tracing::info!("MCP scan_file path={} verdict={}", path_clone, result.scan_verdict.verdict);
                tracing::debug!("scan_file: path={} verdict={}", path_clone, result.scan_verdict.verdict);
                let json = serde_json::to_value(&result).unwrap_or_else(|_| serde_json::json!({ "error": "serialization failed" }));
                Ok(CallToolResult::structured(json))
            }
            "scan_bytes" => {
                let filename = args
                    .get("filename")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::invalid_params("missing argument: filename", None))?;
                let data_b64 = args
                    .get("data_base64")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::invalid_params("missing argument: data_base64", None))?;
                let data = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    data_b64,
                )
                    .map_err(|e| McpError::invalid_params(format!("invalid base64: {e}"), None))?;
                let filename = filename.to_string();
                let len = data.len();
                tracing::info!("MCP scan_bytes filename={} size={}", filename, len);
                tracing::debug!("scan_bytes: filename={} size={}", filename, len);
                let filename_clone = filename.clone();
                let result = tokio::task::spawn_blocking(move || engine.scan_bytes(&filename, &data))
                    .await
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                tracing::info!("MCP scan_bytes filename={} verdict={}", filename_clone, result.scan_verdict.verdict);
                tracing::debug!("scan_bytes: filename={} verdict={}", filename_clone, result.scan_verdict.verdict);
                let json = serde_json::to_value(&result).unwrap_or_else(|_| serde_json::json!({ "error": "serialization failed" }));
                Ok(CallToolResult::structured(json))
            }
            "scan_directory" => {
                let path = args
                    .get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::invalid_params("missing argument: path", None))?;
                let recursive = args
                    .get("recursive")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let path_buf = PathBuf::from(path);
                let max_size = engine.config().max_file_size;
                tracing::info!("MCP scan_directory path={} recursive={}", path, recursive);
                let files = Self::collect_directory_files(&path_buf, recursive, max_size);
                tracing::info!("MCP scan_directory collected {} files", files.len());
                let results = tokio::task::spawn_blocking(move || engine.scan_files_collect(files))
                    .await
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                let summary: (u64, u64, u64) = results.iter().fold((0, 0, 0), |(inf, sus, clean), r| {
                    match r.scan_verdict.verdict {
                        Verdict::Infected => (inf + 1, sus, clean),
                        Verdict::Suspicious => (inf, sus + 1, clean),
                        _ => (inf, sus, clean + 1),
                    }
                });
                let json = serde_json::json!({
                    "results": results,
                    "total": results.len(),
                    "infected": summary.0,
                    "suspicious": summary.1,
                    "clean": summary.2,
                });
                Ok(CallToolResult::structured(json))
            }
            "scan_paths" => {
                let paths_val = args
                    .get("paths")
                    .and_then(|v| v.as_array())
                    .ok_or_else(|| McpError::invalid_params("missing argument: paths (array of file paths)", None))?;
                let paths: Vec<PathBuf> = paths_val
                    .iter()
                    .filter_map(|v| v.as_str().map(PathBuf::from))
                    .collect();
                if paths.is_empty() {
                    return Err(McpError::invalid_params("paths array must not be empty", None));
                }
                tracing::info!("MCP scan_paths count={}", paths.len());
                let results = tokio::task::spawn_blocking(move || engine.scan_files_collect(paths))
                    .await
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                let json = serde_json::json!({ "results": results });
                Ok(CallToolResult::structured(json))
            }
            "get_engine_info" => {
                let matcher_stats = engine.matcher_stats();
                let plugin_names = engine.wasm_plugin_names();
                let signatures_loaded = engine.signatures_loaded();
                let yara_loaded = engine.yara_loaded();
                let sandbox_enabled = engine.sandbox_enabled();
                let max_file_size = engine.config().max_file_size;
                let source_stats: Vec<serde_json::Value> = engine
                    .source_stats()
                    .iter()
                    .map(|s| {
                        serde_json::json!({
                            "name": s.name,
                            "sig_count": s.sig_count,
                        })
                    })
                    .collect();
                let json = serde_json::json!({
                    "matcher_stats": matcher_stats,
                    "plugin_names": plugin_names,
                    "signatures_loaded": signatures_loaded,
                    "yara_loaded": yara_loaded,
                    "sandbox_enabled": sandbox_enabled,
                    "max_file_size_bytes": max_file_size,
                    "source_stats": source_stats,
                });
                tracing::info!("MCP get_engine_info");
                Ok(CallToolResult::structured(json))
            }
            "signature_lookup" => {
                let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let sig_type = args.get("type").and_then(|v| v.as_str()).unwrap_or("");
                let type_descriptions: std::collections::HashMap<&str, &str> = [
                    ("hash-md5", "Whole-file MD5 hash signature (.hdb). Matches when file MD5 equals a known malware hash."),
                    ("hash-sha256", "Whole-file SHA-256 hash signature (.hsb). Matches when file SHA-256 equals a known malware hash."),
                    ("body-ndb", "Byte-pattern signature (.ndb). Matches when file content contains the defined hex pattern (optionally at offset)."),
                    ("logical-ldb", "Logical signature (.ldb/.ldu). Combines subsignatures (hash, pattern, etc.) with AND/OR; target-type filtered."),
                    ("pe-section-md5", "PE section MD5 signature (.mdb). Matches when a PE section's MD5 equals a known malware section hash."),
                    ("pe-section-sha256", "PE section SHA-256 signature (.msb). Matches when a PE section's SHA-256 equals a known malware section hash."),
                    ("container-cdb", "Container metadata signature (.cdb). Matches on archive/metadata patterns."),
                ]
                .iter()
                .copied()
                .collect();
                let mut description = String::new();
                if !sig_type.is_empty() {
                    if let Some(desc) = type_descriptions.get(sig_type) {
                        description = format!("{}: {}", sig_type, desc);
                    } else {
                        description = format!("Unknown type '{}'. Known types: hash-md5, hash-sha256, body-ndb, logical-ldb, pe-section-md5, pe-section-sha256, container-cdb.", sig_type);
                    }
                }
                if !name.is_empty() {
                    if !description.is_empty() {
                        description.push(' ');
                    }
                    description.push_str(&format!(
                        "Signature name '{}' is a ClamAV malware identifier (e.g. Win.Trojan.Agent). Run a scan to see if a file matches this signature; the engine does not store per-signature metadata.",
                        name
                    ));
                }
                if description.is_empty() {
                    description = "ClamAV signature types: hash-md5, hash-sha256 (whole-file hash); body-ndb (byte pattern); logical-ldb (logical rule); pe-section-md5, pe-section-sha256 (PE section hash); container-cdb (container metadata). Pass 'type' for a specific type description, or 'name' for a malware ID.".to_string();
                }
                let json = serde_json::json!({
                    "name": name,
                    "type": sig_type,
                    "description": description,
                });
                tracing::info!("MCP signature_lookup name={} type={}", name, sig_type);
                Ok(CallToolResult::structured(json))
            }
            _ => {
                tracing::debug!("call_tool: unknown tool={}", request.name.as_ref());
                Err(McpError::invalid_params("unknown tool", None))
            }
        }
    }
}
