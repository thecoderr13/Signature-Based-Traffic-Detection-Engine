pub mod cache;
pub mod threatfox;
pub mod urlhaus;

use std::path::Path;

use anyhow::{Context, Result};

use crate::models::Signature;

/// Which feed(s) a fetch request should target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    ThreatFox,
    UrlHaus,
    All,
    Offline,
}

impl Source {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "threatfox" => Some(Source::ThreatFox),
            "urlhaus" => Some(Source::UrlHaus),
            "all" => Some(Source::All),
            "offline" => Some(Source::Offline),
            _ => None,
        }
    }
}

/// The bundled offline sample set is a plain JSON array of `Signature`
/// records checked into the repo (`data/sample_iocs.json`). It exists so
/// the whole pipeline — including a genuine Malicious verdict — can be
/// demonstrated with zero network access and no API key. Its `source`
/// field is always "Offline Sample Set" so the UI never confuses it with
/// live threat intel.
pub fn load_offline_sample(path: &Path) -> Result<Vec<Signature>> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading offline sample IOC file at {}", path.display()))?;
    let sigs: Vec<Signature> = serde_json::from_slice(&bytes).context("parsing offline sample IOC file")?;
    Ok(sigs)
}
