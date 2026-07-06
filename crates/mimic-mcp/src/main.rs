//! Binary: run the Mimic MCP server on stdio or HTTP/HTTPS for use by LLM clients (Claude, Cursor, etc.).
//!
//! Use stdio by default. Build with `--features http` and pass `--listen ADDR` to expose the MCP
//! tools over the Streamable HTTP transport. Add `--features https` and `--tls-cert`/`--tls-key` for HTTPS.

use clap::Parser;
use mimic_core::ScanConfig;
use mimic_engine::MimicEngine;
use mimic_mcp::MimicMcpServer;
use rmcp::ServiceExt;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "mimic-mcp", about = "MCP server for Mimic — scan_file and scan_bytes tools for LLMs")]
struct Args {
    /// ClamAV signature database path (file or directory). Repeatable. Same as mimic -d/--db.
    #[arg(short = 'd', long = "db", value_name = "PATH")]
    databases: Vec<String>,

    /// YARA rule files or directories. Repeatable. Same as mimic -y/--yara.
    #[arg(short = 'y', long = "yara", value_name = "PATH")]
    yara: Vec<String>,

    /// WASM plugin files or directories (e.g. mimic_detect.wasm). Repeatable. Same as mimic --plugin.
    #[arg(long = "plugin", value_name = "PATH")]
    plugins: Vec<String>,

    /// Max file size in MB (0 = no limit). Same as mimic --max-size.
    #[arg(long = "max-size", default_value = "256")]
    max_size_mb: u64,

    /// VirusTotal API key for hash lookups when using mimic-vt.wasm plugin (env: MIMIC_VT_KEY). Same as mimic --vt-key.
    #[arg(long = "vt-key", value_name = "KEY", env = "MIMIC_VT_KEY")]
    vt_key: Option<String>,

    /// Verbose output (-v debug, -vv trace). Enables debug logging for engine and tool calls.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Listen on ADDR and serve MCP over HTTP (Streamable HTTP). Requires build with --features http. Same as mimic serve --listen.
    /// Example: 127.0.0.1:8010 — then use POST/GET/DELETE to http://ADDR/mcp
    #[arg(long = "listen", value_name = "ADDR")]
    #[cfg(feature = "http")]
    listen: Option<String>,

    /// TLS certificate file (PEM). Optional: if omitted with --listen, a self-signed cert is auto-generated. Requires --features https.
    #[arg(long = "tls-cert", value_name = "PATH")]
    #[cfg(feature = "https")]
    tls_cert: Option<String>,

    /// TLS private key file (PEM). Use with --tls-cert. If both --tls-cert and --tls-key are omitted, a self-signed cert is auto-generated. Requires --features https.
    #[arg(long = "tls-key", value_name = "PATH")]
    #[cfg(feature = "https")]
    tls_key: Option<String>,
}

fn init_tracing(verbose: u8) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let level = match verbose {
        0 => "mimic_mcp=info",
        1 => "mimic_mcp=debug",
        _ => "mimic_mcp=trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(level.parse()?))
        .with_writer(std::io::stderr)
        .init();
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();

    // Init tracing after parse so -v level is known (default to info).
    init_tracing(args.verbose)?;

    tracing::debug!("mimic-mcp starting; db paths: {:?}, yara: {:?}, plugins: {:?}", args.databases, args.yara, args.plugins);

    // Set env so plugins (e.g. mimic-vt) or future integration can use the same key as mimic CLI.
    if let Some(ref key) = args.vt_key {
        std::env::set_var("MIMIC_VT_KEY", key);
        tracing::debug!("MIMIC_VT_KEY set from --vt-key");
    }

    let config = ScanConfig {
        threads: 0,
        max_file_size: args.max_size_mb * 1024 * 1024,
        signature_paths: args.databases.clone(),
        enable_mimic: true,
        enable_signatures: true,
        enable_sandbox: false,
        extensions: Vec::new(),
        recursive: true,
        plugin_paths: args.plugins.clone(),
        yara_paths: args.yara.clone(),
    };

    tracing::debug!("ScanConfig: max_file_size={} bytes, signature_paths={}, plugin_paths={}", config.max_file_size, config.signature_paths.len(), config.plugin_paths.len());

    let engine = MimicEngine::new(config).map_err(|e| format!("engine init: {e}"))?;
    if let Some(stats) = engine.matcher_stats() {
        tracing::info!("{stats}");
    }
    tracing::debug!("engine initialized successfully");

    let server = MimicMcpServer::new(engine);

    #[cfg(feature = "http")]
    if let Some(addr) = args.listen {
        #[cfg(feature = "https")]
        let (tls_cert, tls_key) = (args.tls_cert, args.tls_key);
        #[cfg(not(feature = "https"))]
        let (tls_cert, tls_key): (Option<String>, Option<String>) = (None, None);

        run_http(addr, server, tls_cert, tls_key).await?;
        return Ok(());
    }

    tracing::debug!("stdio transport: reading from stdin, writing to stdout");
    let transport = (tokio::io::stdin(), tokio::io::stdout());
    let running = server.serve(transport).await?;
    running.waiting().await?;
    Ok(())
}

#[cfg(feature = "http")]
async fn run_http(
    addr: String,
    server: MimicMcpServer,
    #[allow(unused_variables)] tls_cert: Option<String>,
    #[allow(unused_variables)] tls_key: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use axum::body::Body;
    use axum::http::Request;
    use axum::middleware::{self, Next};
    use axum::Router;
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio_util::sync::CancellationToken;

    let cancellation_token = CancellationToken::new();
    let child_token = cancellation_token.child_token();

    let config = StreamableHttpServerConfig {
        sse_keep_alive: Some(Duration::from_secs(15)),
        sse_retry: Some(Duration::from_secs(3)),
        stateful_mode: true,
        json_response: false,
        cancellation_token: child_token,
    };

    let service = StreamableHttpService::new(
        move || Ok(server.clone()),
        Arc::new(LocalSessionManager::default()),
        config,
    );

    async fn log_request(request: Request<Body>, next: Next) -> axum::response::Response {
        let method = request.method().to_string();
        let path = request.uri().path().to_string();
        let content_len = request
            .headers()
            .get(axum::http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "-".to_string());
        let session = request
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "-".to_string());
        let start = Instant::now();
        tracing::info!(
            method = %method,
            path = %path,
            content_length = %content_len,
            mcp_session_id = %session,
            "request"
        );
        let response = next.run(request).await;
        let status = response.status().as_u16();
        tracing::info!(
            method = %method,
            path = %path,
            status = %status,
            duration_ms = start.elapsed().as_millis(),
            "response"
        );
        response
    }

    let router = Router::new()
        .nest_service("/mcp", service)
        .layer(middleware::from_fn(log_request));

    #[cfg(feature = "https")]
    {
        let sock_addr: std::net::SocketAddr = addr.parse()?;
        let tls_config = if let (Some(cert_path), Some(key_path)) = (tls_cert.as_deref(), tls_key.as_deref()) {
            tracing::debug!("loading TLS cert from {} and key from {}", cert_path, key_path);
            axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path).await?
        } else {
            tracing::info!("no --tls-cert/--tls-key: using auto-generated self-signed certificate (localhost, 127.0.0.1)");
            let cert = rcgen::generate_simple_self_signed([
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "::1".to_string(),
            ])
            .map_err(|e| format!("generate self-signed cert: {e}"))?;
            let cert_pem = cert.serialize_pem().map_err(|e| format!("serialize cert: {e}"))?;
            let key_pem = cert.serialize_private_key_pem();
            axum_server::tls_rustls::RustlsConfig::from_pem(
                cert_pem.into_bytes(),
                key_pem.into_bytes(),
            )
            .await?
        };
        tracing::info!("MCP HTTPS server listening on https://{addr}/mcp (Streamable HTTP)");
        let handle = axum_server::Handle::new();
        let handle_shutdown = handle.clone();
        let ct = cancellation_token.clone();
        tokio::spawn(async move {
            ct.cancelled().await;
            tracing::debug!("HTTPS server: shutdown signal received");
            handle_shutdown.graceful_shutdown(None);
        });
        axum_server::bind_rustls(sock_addr, tls_config)
            .handle(handle)
            .serve(router.into_make_service())
            .await?;
        return Ok(());
    }

    #[cfg(not(feature = "https"))]
    {
        let _ = (tls_cert, tls_key);
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        tracing::info!("MCP HTTP server listening on http://{addr}/mcp (Streamable HTTP)");
        tracing::debug!("bind ok addr={}", addr);
        let shutdown = cancellation_token.clone();
        axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                shutdown.cancelled().await;
            })
            .await?;
        Ok(())
    }
}
