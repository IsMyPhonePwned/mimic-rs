use crate::state::AppState;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Multipart, Path, Query, State};
use axum::http::{Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use mimic_core::ScanResult;
use mimic_engine::MimicEngine;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Instant;
use tower_http::cors::CorsLayer;
use tracing::{info, instrument};

/// Extracts client identifier from headers (X-Forwarded-For, X-Real-IP) or "direct".
/// Run scan on uploaded data: when sandbox is enabled, write to a temp file and use
/// sandboxed worker; otherwise scan bytes in-process. Returns a ScanResult with path set to the given filename.
/// For web uploads only one file is scanned at a time, so the engine always uses worker_slot 0.
fn run_scan_for_upload(
    engine: &MimicEngine,
    filename: &str,
    data: &[u8],
    file_index: u32,
    session_id: &str,
) -> ScanResult {
    if engine.sandbox_enabled() {
        match tempfile::NamedTempFile::new() {
            Ok(temp) => {
                if std::fs::write(temp.path(), data).is_ok() {
                    info!(
                        action = "scan_upload",
                        session_id = %session_id,
                        file = %filename,
                        file_index = file_index,
                        worker_slot = 0,
                        "scanning via sandbox (temp file)"
                    );
                    let mut result = engine.scan_file(temp.path());
                    result.path = filename.to_string();
                    return result;
                }
            }
            Err(e) => {
                info!(
                    action = "scan_upload",
                    session_id = %session_id,
                    file = %filename,
                    file_index = file_index,
                    error = %e,
                    "temp file create failed, falling back to in-process"
                );
            }
        }
        info!(
            action = "scan_upload",
            session_id = %session_id,
            file = %filename,
            file_index = file_index,
            "sandbox temp file failed, using in-process scan"
        );
    }
    engine.scan_bytes(filename, data)
}

fn client_from_headers(headers: &axum::http::HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(str::trim)
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
        })
        .unwrap_or("direct")
        .to_string()
}

async fn log_request_response(request: Request<Body>, next: Next) -> Response {
    let method = request.method().to_string();
    let uri = request.uri().to_string();
    let client = client_from_headers(request.headers());
    let start = Instant::now();
    info!(
        method = %method,
        uri = %uri,
        client = %client,
        "request"
    );
    let response = next.run(request).await;
    let status = response.status();
    let elapsed_ms = start.elapsed().as_millis();
    info!(
        method = %method,
        uri = %uri,
        client = %client,
        status = %status,
        elapsed_ms = %elapsed_ms,
        "response"
    );
    response
}

pub fn build_router(state: AppState) -> Router {
    let state = Arc::new(state);

    Router::new()
        .route("/", get(index_page))
        .route("/api/scan", post(scan_file))
        .route("/api/scan/bytes", post(scan_bytes))
        .route("/api/plugins", get(plugins_list))
        .route("/api/sessions", get(list_sessions))
        .route("/api/sessions/{id}/records", get(session_records))
        .route("/api/records/infected", get(infected_records))
        .route("/api/search", get(search_hash))
        .route("/api/stats", get(stats))
        .route("/api/vt/{sha256}", get(vt_lookup))
        .layer(middleware::from_fn(log_request_response))
        .layer(DefaultBodyLimit::max(512 * 1024 * 1024))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

#[instrument(skip_all)]
async fn index_page() -> Html<&'static str> {
    info!(action = "dashboard", "serving dashboard HTML");
    Html(include_str!("../static/index.html"))
}

#[derive(Debug, Deserialize)]
struct ScanQuery {
    session_id: Option<String>,
}

#[instrument(skip(state, multipart), fields(session_id = tracing::field::Empty, file = tracing::field::Empty, file_index = tracing::field::Empty))]
async fn scan_file(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ScanQuery>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let session_id = match query.session_id {
        Some(ref id) => id.clone(),
        None => match state.db.create_session("api-upload") {
            Ok(id) => id,
            Err(e) => {
                info!(action = "scan_upload", error = %e, "create_session failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()})));
            }
        },
    };
    tracing::Span::current().record("session_id", &tracing::field::display(&session_id));
    info!(action = "scan_upload", session_id = %session_id, "multipart scan started");

    let mut results = Vec::new();
    let mut file_count = 0u32;
    while let Ok(Some(field)) = multipart.next_field().await {
        let filename = field.file_name().unwrap_or("unknown").to_string();
        let data = match field.bytes().await {
            Ok(d) => d,
            Err(e) => {
                info!(
                    action = "scan_upload",
                    session_id = %session_id,
                    file = %filename,
                    file_index = file_count + 1,
                    error = %e,
                    "read field failed"
                );
                results.push(serde_json::json!({"error": format!("read field: {e}"), "path": filename}));
                continue;
            }
        };
        file_count += 1;
        tracing::Span::current().record("file", &tracing::field::display(&filename));
        tracing::Span::current().record("file_index", file_count);

        let result = run_scan_for_upload(
            state.engine.as_ref(),
            &filename,
            &data,
            file_count,
            &session_id,
        );
        let _ = state.db.insert_result(&session_id, &result);
        let verdict = format!("{:?}", result.scan_verdict.verdict);
        info!(
            action = "scan_upload",
            session_id = %session_id,
            file = %filename,
            file_index = file_count,
            size = data.len(),
            verdict = %verdict,
            "file scanned"
        );

        let mut result_value = serde_json::to_value(&result).unwrap_or_default();
        if let Some(vt) = &state.vt {
            info!(
                action = "scan_upload",
                session_id = %session_id,
                file = %filename,
                file_index = file_count,
                sha256 = %result.sha256,
                "VT lookup for scan result"
            );
            match vt.lookup_hash(&result.sha256).await {
                Ok(vt_res) => {
                    if let Ok(v) = serde_json::to_value(&vt_res) {
                        result_value["vt"] = v;
                    }
                    info!(
                        action = "scan_upload",
                        session_id = %session_id,
                        file = %filename,
                        file_index = file_count,
                        sha256 = %result.sha256,
                        found = vt_res.found,
                        positives = ?vt_res.positives,
                        "VT lookup done"
                    );
                }
                Err(e) => {
                    info!(
                        action = "scan_upload",
                        session_id = %session_id,
                        file = %filename,
                        file_index = file_count,
                        sha256 = %result.sha256,
                        error = %e,
                        "VT lookup failed"
                    );
                }
            }
        }
        results.push(result_value);
    }
    info!(
        action = "scan_upload",
        session_id = %session_id,
        file_count = file_count,
        result_count = results.len(),
        "upload scan completed"
    );
    (StatusCode::OK, Json(serde_json::json!({
        "session_id": session_id,
        "results": results,
    })))
}

#[derive(Deserialize)]
struct ScanBytesRequest {
    filename: String,
    data_base64: String,
}

#[instrument(skip(state, req))]
async fn scan_bytes(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ScanBytesRequest>,
) -> impl IntoResponse {
    use base64::Engine as _;
    let data = match base64::engine::general_purpose::STANDARD.decode(&req.data_base64) {
        Ok(d) => d,
        Err(e) => {
            info!(action = "scan_bytes", file = %req.filename, error = %e, "base64 decode failed");
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("base64 decode: {e}")})));
        }
    };
    let session_id = state.db.create_session("api-bytes").unwrap_or_default();
    let result = run_scan_for_upload(
        state.engine.as_ref(),
        &req.filename,
        &data,
        1,
        &session_id,
    );
    let _ = state.db.insert_result(&session_id, &result);
    let verdict = format!("{:?}", result.scan_verdict.verdict);
    info!(
        action = "scan_bytes",
        session_id = %session_id,
        file = %req.filename,
        size = data.len(),
        verdict = %verdict,
        "bytes scan completed"
    );
    let mut result_value = serde_json::to_value(&result).unwrap_or_default();
    if let Some(vt) = &state.vt {
        info!(action = "scan_bytes", sha256 = %result.sha256, "VT lookup for scan result");
        match vt.lookup_hash(&result.sha256).await {
            Ok(vt_res) => {
                if let Ok(v) = serde_json::to_value(&vt_res) {
                    result_value["vt"] = v;
                }
                info!(action = "scan_bytes", sha256 = %result.sha256, found = vt_res.found, "VT lookup done");
            }
            Err(e) => info!(action = "scan_bytes", sha256 = %result.sha256, error = %e, "VT lookup failed"),
        }
    }
    (StatusCode::OK, Json(result_value))
}

#[derive(Debug, Deserialize)]
struct PaginationParams {
    limit: Option<u32>,
    offset: Option<u32>,
}

#[instrument(skip(state))]
async fn list_sessions(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(50);
    let offset = params.offset.unwrap_or(0);
    info!(action = "list_sessions", limit = limit, offset = offset, "listing sessions");
    match state.db.get_sessions(limit) {
        Ok(sessions) => {
            info!(action = "list_sessions", count = sessions.len(), "sessions returned");
            (StatusCode::OK, Json(serde_json::to_value(&sessions).unwrap_or_default()))
        }
        Err(e) => {
            info!(action = "list_sessions", error = %e, "get_sessions failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()})))
        }
    }
}

#[instrument(skip(state))]
async fn session_records(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(100);
    let offset = params.offset.unwrap_or(0);
    info!(action = "session_records", session_id = %id, limit = limit, offset = offset, "fetching session records");
    match state.db.get_session_records(&id, limit, offset) {
        Ok(records) => {
            info!(action = "session_records", session_id = %id, count = records.len(), "records returned");
            (StatusCode::OK, Json(serde_json::to_value(&records).unwrap_or_default()))
        }
        Err(e) => {
            info!(action = "session_records", session_id = %id, error = %e, "get_session_records failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()})))
        }
    }
}

#[instrument(skip(state))]
async fn infected_records(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(100);
    info!(action = "infected_records", limit = limit, "fetching infected records");
    match state.db.get_records_by_verdict("INFECTED", limit) {
        Ok(records) => {
            info!(action = "infected_records", count = records.len(), "records returned");
            (StatusCode::OK, Json(serde_json::to_value(&records).unwrap_or_default()))
        }
        Err(e) => {
            info!(action = "infected_records", error = %e, "get_records_by_verdict failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()})))
        }
    }
}

#[derive(Debug, Deserialize)]
struct SearchQuery {
    hash: String,
}

#[instrument(skip(state))]
async fn search_hash(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SearchQuery>,
) -> impl IntoResponse {
    let hash_preview = if query.hash.len() > 16 {
        format!("{}…", &query.hash[..16])
    } else {
        query.hash.clone()
    };
    info!(action = "search_hash", hash = %hash_preview, "hash search");
    match state.db.search_by_hash(&query.hash) {
        Ok(records) => {
            info!(action = "search_hash", hash = %hash_preview, count = records.len(), "search completed");
            (StatusCode::OK, Json(serde_json::to_value(&records).unwrap_or_default()))
        }
        Err(e) => {
            info!(action = "search_hash", hash = %hash_preview, error = %e, "search failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()})))
        }
    }
}

#[instrument(skip(state))]
async fn stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    info!(action = "stats", "fetching stats");
    match state.db.get_stats() {
        Ok(stats) => {
            info!(action = "stats", "stats returned");
            (StatusCode::OK, Json(serde_json::to_value(&stats).unwrap_or_default()))
        }
        Err(e) => {
            info!(action = "stats", error = %e, "get_stats failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()})))
        }
    }
}

#[instrument(skip(state))]
async fn plugins_list(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    info!(action = "plugins_list", "listing plugins and scanner status");
    let wasm_plugins = state.engine.wasm_plugin_names();
    let yara_loaded = state.engine.yara_loaded();
    let signatures_loaded = state.engine.signatures_loaded();
    let (signature_count, signature_breakdown) = match state.engine.matcher_stats_detailed() {
        Some(s) => (
            s.total_signatures(),
            serde_json::json!({
                "md5_sigs": s.md5_sigs,
                "sha256_sigs": s.sha256_sigs,
                "mdb_sigs": s.mdb_sigs,
                "msb_sigs": s.msb_sigs,
                "fp_sigs": s.fp_sigs,
                "ndb_fixed": s.body_fixed_sigs,
                "ndb_wildcard": s.body_wildcard_sigs,
                "ldb_sigs": s.ldb_sigs,
                "cdb_sigs": s.cdb_sigs,
                "bytecode_sigs": s.bytecode_sigs,
            }),
        ),
        None => (0, serde_json::Value::Null),
    };
    let vt_configured = state.vt.is_some();
    let builtin_plugins: Vec<&str> = if vt_configured {
        vec!["mimic-vt.wasm"]
    } else {
        vec![]
    };
    info!(
        action = "plugins_list",
        wasm_count = wasm_plugins.len(),
        yara_loaded,
        signatures_loaded,
        signature_count = signature_count,
        vt_configured,
        "plugins returned"
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "wasm_plugins": wasm_plugins,
            "builtin_plugins": builtin_plugins,
            "yara_loaded": yara_loaded,
            "signatures_loaded": signatures_loaded,
            "signature_count": signature_count,
            "signature_breakdown": signature_breakdown,
            "vt_configured": vt_configured,
        })),
    )
}

#[instrument(skip(state))]
async fn vt_lookup(
    State(state): State<Arc<AppState>>,
    Path(sha256): Path<String>,
) -> impl IntoResponse {
    let hash_preview = if sha256.len() > 16 {
        format!("{}…", &sha256[..16])
    } else {
        sha256.clone()
    };
    info!(action = "vt_lookup", hash = %hash_preview, "VirusTotal lookup");
    let vt = match &state.vt {
        Some(vt) => vt,
        None => {
            info!(action = "vt_lookup", "VirusTotal not configured");
            return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": "VirusTotal not configured"})));
        }
    };

    match vt.lookup_hash(&sha256).await {
        Ok(result) => {
            info!(action = "vt_lookup", hash = %hash_preview, "VT lookup completed");
            (StatusCode::OK, Json(serde_json::to_value(&result).unwrap_or_default()))
        }
        Err(e) => {
            info!(action = "vt_lookup", hash = %hash_preview, error = %e, "VT lookup failed");
            (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"error": e.to_string()})))
        }
    }
}
