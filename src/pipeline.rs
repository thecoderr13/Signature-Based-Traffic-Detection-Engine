//! Ties `ingestion`, `signatures`, and `engine` together into the three
//! pipeline steps the UI (and the CLI) drive: ingest a pcap, fetch/cache
//! signatures, then run detection. Every step emits `PipelineEvent`s so the
//! dashboard can show exactly what's happening as it happens.
//!
//! This module is deliberately the *only* place that mutates `Store` — API
//! handlers in `api.rs` call into it rather than touching state directly,
//! and `main.rs`'s CLI `run` subcommand calls the exact same functions, so
//! the web UI and the command-line summary can never drift apart.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::json;
use tokio::sync::{broadcast, RwLock};

use crate::config::Config;
use crate::engine::{classify, SignatureSet};
use crate::events::{Level, PipelineEvent, Stage};
use crate::ingestion::ingest_pcap_bytes;
use crate::models::{Detection, Flow, Verdict};
use crate::signatures::{cache, load_offline_sample, threatfox, urlhaus, Source};

pub struct Store {
    pub flows: Vec<Flow>,
    pub current_pcap: Option<String>,
    pub signatures: Option<cache::CachedSignatures>,
    pub detections: Vec<Detection>,
}

impl Store {
    fn new() -> Self {
        Store { flows: Vec::new(), current_pcap: None, signatures: None, detections: Vec::new() }
    }
}

pub struct AppState {
    pub config: Config,
    pub events: broadcast::Sender<PipelineEvent>,
    pub store: RwLock<Store>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        let (tx, _rx) = broadcast::channel(512);
        AppState { config, events: tx, store: RwLock::new(Store::new()) }
    }

    pub fn emit(&self, stage: Stage, level: Level, message: impl Into<String>) {
        let evt = PipelineEvent::new(stage, level, message);
        tracing::info!(target: "sentinel::pipeline", stage = ?evt.stage, level = ?evt.level, "{}", evt.message);
        let _ = self.events.send(evt); // no subscribers yet is not an error
    }

    pub fn emit_detail(&self, stage: Stage, level: Level, message: impl Into<String>, detail: serde_json::Value) {
        let evt = PipelineEvent::new(stage, level, message).with_detail(detail);
        tracing::info!(target: "sentinel::pipeline", stage = ?evt.stage, level = ?evt.level, "{}", evt.message);
        let _ = self.events.send(evt);
    }
}

#[derive(Serialize)]
pub struct IngestSummary {
    pub filename: String,
    pub flow_count: usize,
    pub packet_count: usize,
    pub parsed_packet_count: usize,
}

/// Resolves a user-supplied filename against either the sample directory or
/// the uploads directory — never accepts an absolute or `..`-containing
/// path, so this can't be used to read arbitrary files off disk.
fn resolve_pcap_path(config: &Config, filename: &str) -> Result<PathBuf> {
    if filename.contains("..") || filename.starts_with('/') {
        bail!("invalid filename");
    }
    let sample_path = config.sample_pcap_dir.join(filename);
    if sample_path.is_file() {
        return Ok(sample_path);
    }
    let upload_path = config.upload_dir.join(filename);
    if upload_path.is_file() {
        return Ok(upload_path);
    }
    bail!("no such pcap file: {filename}");
}

pub async fn run_ingest(state: &AppState, filename: &str) -> Result<IngestSummary> {
    state.emit(Stage::Ingestion, Level::Info, format!("Reading '{filename}' from disk"));

    let path = resolve_pcap_path(&state.config, filename)
        .with_context(|| format!("resolving pcap file '{filename}'"))?;
    let bytes = tokio::fs::read(&path).await.context("reading pcap file")?;

    state.emit(Stage::Ingestion, Level::Info, format!("Read {} bytes, parsing packet-capture headers", bytes.len()));

    let result = ingest_pcap_bytes(&bytes).context("parsing pcap contents")?;

    if result.packet_count > 0 && result.parsed_packet_count == 0 {
        state.emit(
            Stage::Ingestion,
            Level::Warning,
            "No packets could be parsed — file may not be Ethernet-linked classic pcap",
        );
    }

    state.emit_detail(
        Stage::Ingestion,
        Level::Success,
        format!(
            "Assembled {} flows from {} of {} packets",
            result.flows.len(),
            result.parsed_packet_count,
            result.packet_count
        ),
        json!({
            "flows": result.flows.len(),
            "packets": result.packet_count,
            "parsed_packets": result.parsed_packet_count,
        }),
    );

    let summary = IngestSummary {
        filename: filename.to_string(),
        flow_count: result.flows.len(),
        packet_count: result.packet_count,
        parsed_packet_count: result.parsed_packet_count,
    };

    let mut store = state.store.write().await;
    store.flows = result.flows;
    store.current_pcap = Some(filename.to_string());
    store.detections.clear();

    Ok(summary)
}

#[derive(Serialize)]
pub struct SignatureSummary {
    pub total: usize,
    pub source_counts: std::collections::HashMap<String, usize>,
    pub fetched_at: chrono::DateTime<chrono::Utc>,
    pub offline: bool,
    pub from_cache: bool,
}

pub async fn run_signature_fetch(state: &AppState, source: Source, force: bool) -> Result<SignatureSummary> {
    let ttl = Duration::from_secs(state.config.cache_ttl_secs);

    if !force {
        if let Some(cached) = cache::load_cache(&state.config.cache_file) {
            if !cached.is_stale(ttl) {
                state.emit(
                    Stage::Signatures,
                    Level::Info,
                    format!("Using cached signature set from {} ({} IOCs, not yet stale)", cached.fetched_at, cached.signatures.len()),
                );
                let summary = SignatureSummary {
                    total: cached.signatures.len(),
                    source_counts: cached.source_counts.clone(),
                    fetched_at: cached.fetched_at,
                    offline: cached.offline,
                    from_cache: true,
                };
                state.store.write().await.signatures = Some(cached);
                return Ok(summary);
            }
        }
    }

    let mut all_signatures = Vec::new();
    let mut offline = false;

    let want_threatfox = matches!(source, Source::ThreatFox | Source::All);
    let want_urlhaus = matches!(source, Source::UrlHaus | Source::All);
    let want_offline = matches!(source, Source::Offline);

    if (want_threatfox || want_urlhaus) && state.config.abusech_auth_key.is_none() {
        state.emit(
            Stage::Signatures,
            Level::Warning,
            "No ABUSECH_AUTH_KEY configured — falling back to the bundled offline sample set",
        );
    }

    if want_threatfox {
        match &state.config.abusech_auth_key {
            Some(key) => {
                state.emit(Stage::Signatures, Level::Info, "Calling ThreatFox get_iocs (last 3 days)");
                match threatfox::fetch_recent(key, 3).await {
                    Ok(mut sigs) => {
                        state.emit(Stage::Signatures, Level::Success, format!("ThreatFox returned {} IOCs", sigs.len()));
                        all_signatures.append(&mut sigs);
                    }
                    Err(e) => {
                        state.emit(Stage::Signatures, Level::Error, format!("ThreatFox request failed: {e:#}"));
                    }
                }
            }
            None => {}
        }
    }

    if want_urlhaus {
        match &state.config.abusech_auth_key {
            Some(key) => {
                state.emit(Stage::Signatures, Level::Info, "Calling URLhaus recent URLs (limit 100)");
                match urlhaus::fetch_recent(key, 100).await {
                    Ok(mut sigs) => {
                        state.emit(Stage::Signatures, Level::Success, format!("URLhaus returned {} IOCs", sigs.len()));
                        all_signatures.append(&mut sigs);
                    }
                    Err(e) => {
                        state.emit(Stage::Signatures, Level::Error, format!("URLhaus request failed: {e:#}"));
                    }
                }
            }
            None => {}
        }
    }

    if want_offline || (all_signatures.is_empty() && (want_threatfox || want_urlhaus)) {
        state.emit(Stage::Signatures, Level::Info, "Loading bundled offline sample IOC set");
        let mut sigs = load_offline_sample(&state.config.offline_sample_file)?;
        all_signatures.append(&mut sigs);
        offline = true;
    }

    let cached = cache::CachedSignatures::build(all_signatures, offline);
    cache::save_cache(&state.config.cache_file, &cached).context("writing signature cache to disk")?;

    state.emit_detail(
        Stage::Signatures,
        Level::Success,
        format!("Signature set ready: {} IOCs across {} source(s)", cached.signatures.len(), cached.source_counts.len()),
        json!({ "counts": cached.source_counts, "offline": cached.offline }),
    );

    let summary = SignatureSummary {
        total: cached.signatures.len(),
        source_counts: cached.source_counts.clone(),
        fetched_at: cached.fetched_at,
        offline: cached.offline,
        from_cache: false,
    };
    state.store.write().await.signatures = Some(cached);
    Ok(summary)
}

#[derive(Serialize)]
pub struct DetectionSummary {
    pub total: usize,
    pub benign: usize,
    pub suspicious: usize,
    pub malicious: usize,
}

pub async fn run_detection(state: &AppState) -> Result<DetectionSummary> {
    let (flows, sig_set) = {
        let store = state.store.read().await;
        if store.flows.is_empty() {
            bail!("no flows to analyze — ingest a pcap file first");
        }
        let Some(cached) = store.signatures.clone() else {
            bail!("no signatures loaded — fetch signatures first");
        };
        (store.flows.clone(), SignatureSet::build(cached.signatures))
    };

    state.emit(
        Stage::Detection,
        Level::Info,
        format!("Matching {} flows against {} indicators", flows.len(), sig_set.len()),
    );

    let mut detections = Vec::with_capacity(flows.len());
    let mut benign = 0usize;
    let mut suspicious = 0usize;
    let mut malicious = 0usize;

    for flow in &flows {
        let detection = classify(flow, &sig_set);
        match detection.verdict {
            Verdict::Benign => benign += 1,
            Verdict::Suspicious => {
                suspicious += 1;
                state.emit(
                    Stage::Detection,
                    Level::Warning,
                    format!("Suspicious: {} -> {}:{} ({})", flow.src_ip, flow.dst_ip, flow.dst_port, detection.reasons.join("; ")),
                );
            }
            Verdict::Malicious => {
                malicious += 1;
                state.emit(
                    Stage::Detection,
                    Level::Error,
                    format!("Malicious: {} -> {}:{} — {}", flow.src_ip, flow.dst_ip, flow.dst_port, detection.reasons.join("; ")),
                );
                if let Some(action) = &detection.ips_action {
                    state.emit(Stage::Detection, Level::Error, format!("IPS action: {action}"));
                }
            }
        }
        detections.push(detection);
    }

    state.emit_detail(
        Stage::Detection,
        Level::Success,
        format!("Detection complete: {benign} benign, {suspicious} suspicious, {malicious} malicious"),
        json!({ "benign": benign, "suspicious": suspicious, "malicious": malicious }),
    );

    let summary = DetectionSummary { total: detections.len(), benign, suspicious, malicious };
    state.store.write().await.detections = detections;
    Ok(summary)
}

/// Lists pcap files available to ingest: bundled samples plus anything the
/// user has uploaded, so the UI never hardcodes a single filename.
pub async fn list_available_pcaps(config: &Config) -> Vec<String> {
    let mut names = Vec::new();
    for dir in [&config.sample_pcap_dir, &config.upload_dir] {
        if let Ok(mut entries) = tokio::fs::read_dir(dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if let Some(name) = entry.file_name().to_str() {
                    if name.ends_with(".pcap") {
                        names.push(name.to_string());
                    }
                }
            }
        }
    }
    names.sort();
    names.dedup();
    names
}

pub async fn save_upload(config: &Config, filename: &str, bytes: &[u8]) -> Result<()> {
    let safe_name = Path::new(filename)
        .file_name()
        .and_then(|n| n.to_str())
        .context("invalid upload filename")?;
    tokio::fs::create_dir_all(&config.upload_dir).await?;
    let path = config.upload_dir.join(safe_name);
    tokio::fs::write(path, bytes).await?;
    Ok(())
}
