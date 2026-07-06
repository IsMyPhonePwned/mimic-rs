//! # mimic-mcp
//!
//! MCP (Model Context Protocol) server for Mimic. Exposes `scan_file` and `scan_bytes`
//! tools so LLMs can request malware scans and get structured results.

pub mod server;

pub use server::MimicMcpServer;
