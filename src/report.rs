//! Builds the aggregate report shown on the Report page and returned by
//! `/api/export` — the CLI's end-of-run summary (see `main.rs`) is built
//! from the same `ReportSummary` type, so the web UI and terminal output
//! never disagree.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::models::{Detection, Verdict};
use crate::pipeline::Store;

#[derive(Serialize)]
pub struct ReportSummary {
    pub generated_at: DateTime<Utc>,
    pub pcap_file: Option<String>,
    pub total_flows: usize,
    pub benign: usize,
    pub suspicious: usize,
    pub malicious: usize,
    pub signature_total: usize,
    pub signature_sources: HashMap<String, usize>,
    pub signatures_fetched_at: Option<DateTime<Utc>>,
    pub signatures_offline: bool,
    pub detections: Vec<Detection>,
}

pub fn build_report(store: &Store) -> ReportSummary {
    let mut benign = 0usize;
    let mut suspicious = 0usize;
    let mut malicious = 0usize;
    for d in &store.detections {
        match d.verdict {
            Verdict::Benign => benign += 1,
            Verdict::Suspicious => suspicious += 1,
            Verdict::Malicious => malicious += 1,
        }
    }

    ReportSummary {
        generated_at: Utc::now(),
        pcap_file: store.current_pcap.clone(),
        total_flows: store.detections.len(),
        benign,
        suspicious,
        malicious,
        signature_total: store.signatures.as_ref().map(|s| s.signatures.len()).unwrap_or(0),
        signature_sources: store.signatures.as_ref().map(|s| s.source_counts.clone()).unwrap_or_default(),
        signatures_fetched_at: store.signatures.as_ref().map(|s| s.fetched_at),
        signatures_offline: store.signatures.as_ref().map(|s| s.offline).unwrap_or(false),
        detections: store.detections.clone(),
    }
}

/// Renders the same summary as a fixed-width table for the terminal, used
/// by `sentinel run` (see `main.rs`).
pub fn render_cli_summary(report: &ReportSummary) -> String {
    let mut out = String::new();
    out.push_str(&format!("\nSentinel detection report — {}\n", report.generated_at.format("%Y-%m-%d %H:%M:%S UTC")));
    if let Some(pcap) = &report.pcap_file {
        out.push_str(&format!("  pcap file:       {pcap}\n"));
    }
    out.push_str(&format!(
        "  signatures:      {} IOCs from {} source(s){}\n",
        report.signature_total,
        report.signature_sources.len(),
        if report.signatures_offline { " [offline sample]" } else { "" }
    ));
    out.push_str(&format!(
        "  flows analyzed:  {}  (benign: {}, suspicious: {}, malicious: {})\n\n",
        report.total_flows, report.benign, report.suspicious, report.malicious
    ));

    out.push_str(&format!(
        "  {:<8}  {:<21}  {:<21}  {:<10}  {}\n",
        "VERDICT", "SOURCE", "DESTINATION", "PROTO", "DETAIL"
    ));
    out.push_str(&format!("  {}\n", "-".repeat(100)));
    for d in &report.detections {
        if d.verdict == Verdict::Benign {
            continue; // keep the printed table focused on what needs attention
        }
        let src = format!("{}:{}", d.flow.src_ip, d.flow.src_port);
        let dst = format!("{}:{}", d.flow.dst_ip, d.flow.dst_port);
        let detail = d.reasons.first().cloned().unwrap_or_default();
        out.push_str(&format!(
            "  {:<8}  {:<21}  {:<21}  {:<10}  {}\n",
            d.verdict.to_string(),
            src,
            dst,
            d.flow.protocol.to_string(),
            detail
        ));
    }
    if report.benign > 0 {
        out.push_str(&format!("\n  ({} additional benign flow(s) not shown; see --export or the dashboard)\n", report.benign));
    }
    out
}
