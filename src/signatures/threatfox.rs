//! Client for abuse.ch ThreatFox (https://threatfox.abuse.ch/api/).
//!
//! Requires a free Auth-Key from https://auth.abuse.ch/. One call per
//! `fetch_recent` invocation — the caller (see `pipeline.rs`) is
//! responsible for only invoking this behind the on-disk TTL cache, never
//! per-packet or per-request.

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::models::{IocType, Signature};

const ENDPOINT: &str = "https://threatfox-api.abuse.ch/api/v1/";

#[derive(Deserialize)]
struct ThreatFoxResponse {
    query_status: String,
    #[serde(default)]
    data: Vec<ThreatFoxIoc>,
}

#[derive(Deserialize)]
struct ThreatFoxIoc {
    #[serde(default)]
    ioc: Option<String>,
    #[serde(default)]
    ioc_type: Option<String>,
    #[serde(default)]
    threat_type: Option<String>,
    #[serde(default)]
    malware_printable: Option<String>,
    #[serde(default)]
    confidence_level: Option<u8>,
    #[serde(default)]
    first_seen_utc: Option<String>,
    #[serde(default)]
    reference: Option<String>,
}

/// Fetches IOCs added to ThreatFox in the last `days` (clamped to the
/// API's supported range of 1-7).
pub async fn fetch_recent(auth_key: &str, days: u32) -> Result<Vec<Signature>> {
    let client = reqwest::Client::new();
    let body = serde_json::json!({ "query": "get_iocs", "days": days.clamp(1, 7) });

    let resp = client
        .post(ENDPOINT)
        .header("Auth-Key", auth_key)
        .json(&body)
        .send()
        .await
        .context("sending request to ThreatFox")?;

    if !resp.status().is_success() {
        bail!("ThreatFox returned HTTP {}", resp.status());
    }

    let parsed: ThreatFoxResponse = resp.json().await.context("parsing ThreatFox response body")?;
    if parsed.query_status != "ok" {
        bail!("ThreatFox query_status was '{}'", parsed.query_status);
    }

    Ok(parsed.data.into_iter().filter_map(convert).collect())
}

fn convert(ioc: ThreatFoxIoc) -> Option<Signature> {
    let raw = ioc.ioc?;
    let ioc_type_str = ioc.ioc_type.unwrap_or_default();

    let (kind, value) = if ioc_type_str.starts_with("ip:port") {
        (IocType::Ip, raw.split(':').next()?.to_string())
    } else if ioc_type_str == "domain" {
        (IocType::Domain, raw.to_lowercase())
    } else if ioc_type_str == "url" {
        (IocType::Url, raw)
    } else if ioc_type_str.contains("sha256") {
        (IocType::Sha256, raw.to_lowercase())
    } else {
        // md5 and other IOC types aren't matchable by this engine, which
        // only ever computes SHA-256 over payloads — skip rather than
        // storing an indicator that can never fire.
        return None;
    };

    Some(Signature {
        ioc_type: kind,
        value,
        source: "ThreatFox".to_string(),
        malware: ioc.malware_printable,
        threat_type: ioc.threat_type,
        confidence: ioc.confidence_level,
        reference: ioc.reference,
        first_seen: ioc.first_seen_utc,
    })
}
