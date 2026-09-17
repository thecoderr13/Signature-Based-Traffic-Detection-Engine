//! HTTP surface. Every handler here is a thin wrapper around a
//! `pipeline::run_*` function — the handlers only deal with HTTP concerns
//! (extracting requests, shaping responses); all real logic lives in
//! `pipeline.rs`, `ingestion`, `signatures`, and `engine`.

use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::{Multipart, State};
use axum::http::{header, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::Stream;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::pipeline::{self, AppState};
use crate::report::build_report;
use crate::signatures::Source;

/// Wraps `anyhow::Error` so handlers can just use `?` and still produce a
/// sensible JSON error response instead of panicking.
pub struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let message = format!("{:#}", self.0);
        tracing::warn!("request failed: {message}");
        (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        AppError(err.into())
    }
}

pub async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

#[derive(Serialize)]
pub struct StatusResponse {
    flow_count: usize,
    signature_count: usize,
    detection_count: usize,
    pcap_file: Option<String>,
    signatures_offline: bool,
    auth_key_configured: bool,
}

pub async fn status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let store = state.store.read().await;
    Json(StatusResponse {
        flow_count: store.flows.len(),
        signature_count: store.signatures.as_ref().map(|s| s.signatures.len()).unwrap_or(0),
        detection_count: store.detections.len(),
        pcap_file: store.current_pcap.clone(),
        signatures_offline: store.signatures.as_ref().map(|s| s.offline).unwrap_or(false),
        auth_key_configured: state.config.abusech_auth_key.is_some(),
    })
}

pub async fn list_pcaps(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let names = pipeline::list_available_pcaps(&state.config).await;
    Json(json!({ "pcaps": names }))
}

pub async fn upload_pcap(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
    while let Some(field) = multipart.next_field().await.map_err(anyhow::Error::from)? {
        let filename = field.file_name().map(|s| s.to_string()).unwrap_or_else(|| "upload.pcap".to_string());
        if !filename.ends_with(".pcap") {
            return Err(AppError(anyhow::anyhow!("only .pcap files are accepted (got '{filename}')")));
        }
        let bytes = field.bytes().await.map_err(anyhow::Error::from)?;
        pipeline::save_upload(&state.config, &filename, &bytes).await?;
        state.emit(
            crate::events::Stage::Ingestion,
            crate::events::Level::Info,
            format!("Uploaded '{filename}' ({} bytes)", bytes.len()),
        );
        return Ok(Json(json!({ "filename": filename })));
    }
    Err(AppError(anyhow::anyhow!("no file field found in upload")))
}

#[derive(Deserialize)]
pub struct IngestRequest {
    filename: String,
}

pub async fn ingest(
    State(state): State<Arc<AppState>>,
    Json(req): Json<IngestRequest>,
) -> Result<impl IntoResponse, AppError> {
    let summary = pipeline::run_ingest(&state, &req.filename).await?;
    Ok(Json(summary))
}

pub async fn get_flows(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let store = state.store.read().await;
    Json(json!({ "flows": store.flows }))
}

#[derive(Deserialize)]
pub struct SignatureFetchRequest {
    #[serde(default = "default_source")]
    source: String,
    #[serde(default)]
    force: bool,
}

fn default_source() -> String {
    "all".to_string()
}

pub async fn fetch_signatures(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SignatureFetchRequest>,
) -> Result<impl IntoResponse, AppError> {
    let source = Source::parse(&req.source)
        .ok_or_else(|| anyhow::anyhow!("unknown source '{}': expected threatfox, urlhaus, all, or offline", req.source))?;
    let summary = pipeline::run_signature_fetch(&state, source, req.force).await?;
    Ok(Json(summary))
}

pub async fn get_signatures(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let store = state.store.read().await;
    match &store.signatures {
        Some(cached) => {
            let mut type_counts = std::collections::BTreeMap::new();
            for sig in &cached.signatures {
                let key = match sig.ioc_type {
                    crate::models::IocType::Ip => "IP",
                    crate::models::IocType::Domain => "Domain",
                    crate::models::IocType::Url => "URL",
                    crate::models::IocType::Sha256 => "SHA-256",
                };
                *type_counts.entry(key.to_string()).or_insert(0usize) += 1;
            }

            Json(json!({
                "loaded": true,
                "total": cached.signatures.len(),
                "source_counts": cached.source_counts,
                "type_counts": type_counts,
                "fetched_at": cached.fetched_at,
                "offline": cached.offline,
                "signatures": cached.signatures,
                "sample": cached.signatures.iter().take(25).collect::<Vec<_>>(),
            }))
        }
        None => Json(json!({ "loaded": false })),
    }
}

pub async fn detect(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, AppError> {
    let summary = pipeline::run_detection(&state).await?;
    Ok(Json(summary))
}

pub async fn get_detections(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let store = state.store.read().await;
    Json(json!({ "detections": store.detections }))
}

pub async fn get_report(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let store = state.store.read().await;
    Json(build_report(&store))
}

pub async fn export_report(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let store = state.store.read().await;
    let report = build_report(&store);
    let body = serde_json::to_vec_pretty(&report).unwrap_or_default();
    (
        [
            (header::CONTENT_TYPE, "application/json".to_string()),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"sentinel-report.json\"".to_string()),
        ],
        body,
    )
}

pub async fn sse_events(State(state): State<Arc<AppState>>) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.events.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|msg| match msg {
        Ok(evt) => Event::default().event("pipeline").json_data(&evt).ok().map(Ok),
        Err(_lagged) => None,
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}
