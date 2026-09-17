//! Client for abuse.ch URLhaus (https://urlhaus-api.abuse.ch/).
//!
//! Uses the same shared Auth-Key as ThreatFox (both are abuse.ch community
//! APIs). Demonstrates integrating a second, independent feed as called
//! for by the assignment's "feel free to work with multiple" note.

use std::net::IpAddr;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::models::{IocType, Signature};

const ENDPOINT_BASE: &str = "https://urlhaus-api.abuse.ch/v1/urls/recent";

#[derive(Deserialize)]
struct UrlhausResponse {
    query_status: String,
    #[serde(default)]
    urls: Option<Vec<UrlhausEntry>>,
}

#[derive(Deserialize)]
struct UrlhausEntry {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    threat: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    urlhaus_reference: Option<String>,
    #[serde(default)]
    date_added: Option<String>,
}

/// Fetches the most recently added malicious URLs (capped by `limit`).
pub async fn fetch_recent(auth_key: &str, limit: u32) -> Result<Vec<Signature>> {
    let client = reqwest::Client::new();
    let url = format!("{ENDPOINT_BASE}/limit/{}/", limit.clamp(1, 1000));

    let resp = client
        .get(&url)
        .header("Auth-Key", auth_key)
        .send()
        .await
        .context("sending request to URLhaus")?;

    if !resp.status().is_success() {
        bail!("URLhaus returned HTTP {}", resp.status());
    }

    let parsed: UrlhausResponse = resp.json().await.context("parsing URLhaus response body")?;
    if parsed.query_status != "ok" {
        bail!("URLhaus query_status was '{}'", parsed.query_status);
    }

    let mut sigs = Vec::new();
    for entry in parsed.urls.unwrap_or_default() {
        let Some(url) = entry.url else { continue };
        sigs.push(Signature {
            ioc_type: IocType::Url,
            value: url,
            source: "URLhaus".to_string(),
            malware: entry.tags.and_then(|tags| tags.into_iter().next()),
            threat_type: entry.threat.clone(),
            confidence: None,
            reference: entry.urlhaus_reference.clone(),
            first_seen: entry.date_added.clone(),
        });

        if let Some(host) = entry.host {
            // `host` can be either a domain or a raw IP — file it under
            // the matching IOC type so lookups stay correct.
            if let Ok(_ip) = host.parse::<IpAddr>() {
                sigs.push(Signature {
                    ioc_type: IocType::Ip,
                    value: host,
                    source: "URLhaus".to_string(),
                    malware: None,
                    threat_type: entry.threat.clone(),
                    confidence: None,
                    reference: entry.urlhaus_reference.clone(),
                    first_seen: entry.date_added.clone(),
                });
            } else {
                sigs.push(Signature {
                    ioc_type: IocType::Domain,
                    value: host.to_lowercase(),
                    source: "URLhaus".to_string(),
                    malware: None,
                    threat_type: entry.threat.clone(),
                    confidence: None,
                    reference: entry.urlhaus_reference.clone(),
                    first_seen: entry.date_added.clone(),
                });
            }
        }
    }
    Ok(sigs)
}
