//! Signatures are fetched once and written to `data/cache/signatures.json`.
//! Every subsequent pipeline run reads from that file until it goes stale
//! (`SIGNATURE_CACHE_TTL_SECS`) or the user explicitly forces a refresh —
//! this is what keeps the engine from ever calling a threat-intel API on a
//! per-packet or per-flow basis.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::models::Signature;

#[derive(Clone, Serialize, Deserialize)]
pub struct CachedSignatures {
    pub fetched_at: DateTime<Utc>,
    pub signatures: Vec<Signature>,
    pub source_counts: HashMap<String, usize>,
    /// True when this set came from the bundled offline sample file rather
    /// than a live API call — surfaced in the UI so provenance is never
    /// hidden from the person reading the dashboard.
    pub offline: bool,
}

impl CachedSignatures {
    pub fn build(signatures: Vec<Signature>, offline: bool) -> Self {
        let mut source_counts = HashMap::new();
        for s in &signatures {
            *source_counts.entry(s.source.clone()).or_insert(0) += 1;
        }
        CachedSignatures { fetched_at: Utc::now(), signatures, source_counts, offline }
    }

    pub fn is_stale(&self, ttl: Duration) -> bool {
        let ttl = chrono::Duration::from_std(ttl).unwrap_or_else(|_| chrono::Duration::zero());
        Utc::now().signed_duration_since(self.fetched_at) > ttl
    }
}

pub fn load_cache(path: &Path) -> Option<CachedSignatures> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn save_cache(path: &Path, cache: &CachedSignatures) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(cache)?;
    std::fs::write(path, bytes)?;
    Ok(())
}
