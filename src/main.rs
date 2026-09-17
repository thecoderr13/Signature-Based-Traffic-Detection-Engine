mod api;
mod config;
mod engine;
mod events;
mod ingestion;
mod models;
mod pipeline;
mod report;
mod signatures;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use axum::routing::{get, post};
use axum::Router;
use clap::{Parser, Subcommand};
use tower_http::services::ServeDir;
use tracing_subscriber::EnvFilter;

fn find_dotenv_in_parents(start: &std::path::Path) -> Option<PathBuf> {
    let mut dir = start.to_path_buf();
    if dir.is_file() {
        dir = dir.parent()?.to_path_buf();
    }

    loop {
        let candidate = dir.join(".env");
        if candidate.is_file() {
            return Some(candidate);
        }

        if !dir.pop() {
            break;
        }
    }

    None
}

fn load_dotenv() {
    let mut candidates = Vec::new();

    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(find_dotenv_in_parents(&cwd));
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(find_dotenv_in_parents(dir));
        }
    }

    candidates.push(Some(PathBuf::from(".env")));

    for candidate in candidates.into_iter().flatten() {
        if candidate.is_file() {
            let _ = dotenvy::from_filename_override(&candidate);
            break;
        }
    }

    if std::env::var("ABUSECH_AUTH_KEY").is_err() {
        let _ = dotenvy::dotenv();
    }
}

use config::Config;
use pipeline::AppState;
use signatures::Source;

#[derive(Parser)]
#[command(name = "sentinel", about = "Signature-based network traffic detection engine")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Start the web dashboard (default if no subcommand is given).
    Serve {
        #[arg(long)]
        addr: Option<String>,
    },
    /// Run the full pipeline once, headless, and print a summary table.
    Run {
        /// Filename of a pcap under sample_pcaps/ or data/uploads/.
        pcap: String,
        #[arg(long, default_value = "all")]
        source: String,
        #[arg(long)]
        force_refresh: bool,
        /// Optional path to also write the full JSON report to.
        #[arg(long)]
        export: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    load_dotenv();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cli = Cli::parse();
    let config = Config::from_env();
    let state = Arc::new(AppState::new(config));

    match cli.command.unwrap_or(Command::Serve { addr: None }) {
        Command::Serve { addr } => serve(state, addr).await,
        Command::Run { pcap, source, force_refresh, export } => {
            cli_run(state, &pcap, &source, force_refresh, export.as_deref()).await
        }
    }
}

async fn serve(state: Arc<AppState>, addr_override: Option<String>) -> Result<()> {
    let addr = addr_override.unwrap_or_else(|| state.config.bind_addr.clone());
    let static_dir = state.config.static_dir.clone();

    let app = Router::new()
        .route("/api/health", get(api::health))
        .route("/api/status", get(api::status))
        .route("/api/events", get(api::sse_events))
        .route("/api/pcaps", get(api::list_pcaps))
        .route("/api/pcaps/upload", post(api::upload_pcap))
        .route("/api/ingest", post(api::ingest))
        .route("/api/flows", get(api::get_flows))
        .route("/api/signatures/fetch", post(api::fetch_signatures))
        .route("/api/signatures", get(api::get_signatures))
        .route("/api/detect", post(api::detect))
        .route("/api/detections", get(api::get_detections))
        .route("/api/report", get(api::get_report))
        .route("/api/export", get(api::export_report))
        .with_state(state)
        .fallback_service(ServeDir::new(static_dir).append_index_html_on_directories(true));

    tracing::info!("Sentinel dashboard listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn cli_run(
    state: Arc<AppState>,
    pcap: &str,
    source: &str,
    force_refresh: bool,
    export: Option<&str>,
) -> Result<()> {
    let source = Source::parse(source)
        .ok_or_else(|| anyhow::anyhow!("unknown source '{source}': expected threatfox, urlhaus, all, or offline"))?;

    println!("==> Ingesting {pcap}");
    let ingest_summary = pipeline::run_ingest(&state, pcap).await?;
    println!(
        "    {} flows from {}/{} packets parsed",
        ingest_summary.flow_count, ingest_summary.parsed_packet_count, ingest_summary.packet_count
    );

    println!("==> Fetching signatures ({source:?})");
    let sig_summary = pipeline::run_signature_fetch(&state, source, force_refresh).await?;
    println!(
        "    {} IOCs loaded ({}{})",
        sig_summary.total,
        if sig_summary.from_cache { "from cache, " } else { "" },
        if sig_summary.offline { "offline sample set" } else { "live feed(s)" }
    );

    println!("==> Running detection");
    let detect_summary = pipeline::run_detection(&state).await?;
    println!(
        "    {} benign, {} suspicious, {} malicious",
        detect_summary.benign, detect_summary.suspicious, detect_summary.malicious
    );

    let store = state.store.read().await;
    let full_report = report::build_report(&store);
    println!("{}", report::render_cli_summary(&full_report));

    if let Some(path) = export {
        let bytes = serde_json::to_vec_pretty(&full_report)?;
        tokio::fs::write(path, bytes).await?;
        println!("Full JSON report written to {path}");
    }

    Ok(())
}
