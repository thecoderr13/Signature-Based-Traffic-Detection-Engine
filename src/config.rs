//! All environment-derived configuration lives here so nothing else in the
//! codebase reads `std::env` directly. No API keys or paths are hardcoded —
//! see `.env.example` for every variable this reads.

use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Config {
    /// Shared abuse.ch Auth-Key, used for both ThreatFox and URLhaus.
    /// `None` means "run in offline sample mode".
    pub abusech_auth_key: Option<String>,
    pub cache_ttl_secs: u64,
    pub static_dir: PathBuf,
    pub sample_pcap_dir: PathBuf,
    pub upload_dir: PathBuf,
    pub cache_file: PathBuf,
    pub offline_sample_file: PathBuf,
    pub bind_addr: String,
}

impl Config {
    pub fn from_env() -> Self {
        Config {
            abusech_auth_key: std::env::var("ABUSECH_AUTH_KEY")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            cache_ttl_secs: std::env::var("SIGNATURE_CACHE_TTL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(3600),
            static_dir: PathBuf::from("static"),
            sample_pcap_dir: PathBuf::from("sample_pcaps"),
            upload_dir: PathBuf::from("data/uploads"),
            cache_file: PathBuf::from("data/cache/signatures.json"),
            offline_sample_file: PathBuf::from("data/sample_iocs.json"),
            bind_addr: std::env::var("SENTINEL_ADDR").unwrap_or_else(|_| "127.0.0.1:8787".into()),
        }
    }
}
