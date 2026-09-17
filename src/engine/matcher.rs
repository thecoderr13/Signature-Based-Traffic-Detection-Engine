//! The detection engine's core: turning a flat list of `Signature`s into
//! fast lookup tables, then classifying a `Flow` against them.
//!
//! This module has no dependency on Axum, Tokio, or the network — it's a
//! pure function of `(Flow, SignatureSet) -> Detection`, which is what
//! makes it straightforward to unit test (see the `tests` module below).

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use crate::models::{Detection, Flow, IocType, Signature};

/// Destination ports commonly associated with backdoor / C2 tooling in the
/// wild (e.g. classic Metasploit and netcat-shell defaults). Not a
/// signature match on its own — it's one input into the Suspicious
/// heuristic, since legitimate services can also run on arbitrary ports.
const SUSPICIOUS_PORTS: [u16; 7] = [4444, 1337, 31337, 6666, 6667, 12345, 54321];

/// Minimum label length and Shannon-entropy threshold (bits/char) used by
/// the lightweight DGA heuristic. Real DGA detection needs dictionary and
/// n-gram models trained on labeled data; this is a cheap first-pass proxy
/// documented as a limitation in the README, not a claim of AV-grade DGA
/// detection.
const DGA_MIN_LABEL_LEN: usize = 10;
const DGA_ENTROPY_THRESHOLD: f64 = 3.3;

/// Signatures indexed by IOC type for O(1) average-case flow matching,
/// built once per detection run (never per-packet).
pub struct SignatureSet {
    ips: HashMap<IpAddr, Signature>,
    domains: HashMap<String, Signature>,
    urls: HashMap<String, Signature>,
    hashes: HashMap<String, Signature>,
    /// First three octets of every malicious IPv4 seen, used only for the
    /// "shares a /24 with a known-bad IP" Suspicious heuristic.
    malicious_v4_subnets: HashSet<[u8; 3]>,
}

impl SignatureSet {
    pub fn build(signatures: Vec<Signature>) -> Self {
        let mut ips = HashMap::new();
        let mut domains = HashMap::new();
        let mut urls = HashMap::new();
        let mut hashes = HashMap::new();
        let mut malicious_v4_subnets = HashSet::new();

        for sig in signatures {
            match sig.ioc_type {
                IocType::Ip => {
                    if let Ok(ip) = sig.value.parse::<IpAddr>() {
                        if let IpAddr::V4(v4) = ip {
                            let o = v4.octets();
                            malicious_v4_subnets.insert([o[0], o[1], o[2]]);
                        }
                        ips.insert(ip, sig);
                    }
                }
                IocType::Domain => {
                    domains.insert(sig.value.to_lowercase(), sig);
                }
                IocType::Url => {
                    urls.insert(normalize_url(&sig.value), sig);
                }
                IocType::Sha256 => {
                    hashes.insert(sig.value.to_lowercase(), sig);
                }
            }
        }

        SignatureSet { ips, domains, urls, hashes, malicious_v4_subnets }
    }

    pub fn is_empty(&self) -> bool {
        self.ips.is_empty() && self.domains.is_empty() && self.urls.is_empty() && self.hashes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.ips.len() + self.domains.len() + self.urls.len() + self.hashes.len()
    }
}

fn normalize_url(u: &str) -> String {
    let lower = u.trim();
    lower.strip_suffix('/').unwrap_or(lower).to_string()
}

fn shannon_entropy(s: &str) -> f64 {
    let len = s.chars().count() as f64;
    if len == 0.0 {
        return 0.0;
    }
    let mut counts: HashMap<char, u32> = HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    counts.values().fold(0.0, |acc, &c| {
        let p = c as f64 / len;
        acc - p * p.log2()
    })
}

/// Flags hostnames whose leftmost label looks algorithmically generated:
/// long, and with character-level entropy well above what typical
/// human-chosen words exhibit. See `DGA_*` constants for the thresholds.
fn looks_like_dga(hostname: &str) -> bool {
    let Some(label) = hostname.split('.').next() else {
        return false;
    };
    label.len() >= DGA_MIN_LABEL_LEN && shannon_entropy(label) >= DGA_ENTROPY_THRESHOLD
}

fn subnet24(ip: IpAddr) -> Option<[u8; 3]> {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            Some([o[0], o[1], o[2]])
        }
        IpAddr::V6(_) => None,
    }
}

/// Classifies a single flow against the given signature set. Exact IOC
/// matches (URL > domain > IP > payload hash, in that priority order)
/// always win as Malicious; failing that, a small set of heuristics can
/// still flag a flow Suspicious. Everything else is Benign.
pub fn classify(flow: &Flow, sigs: &SignatureSet) -> Detection {
    if let Some(url) = &flow.url {
        if let Some(sig) = sigs.urls.get(&normalize_url(url)) {
            let reason = format!(
                "destination URL matches a known-malicious URL indicator from {}",
                sig.source
            );
            return Detection::malicious(flow.clone(), sig.clone(), reason);
        }
    }

    if let Some(host) = &flow.hostname {
        if let Some(sig) = sigs.domains.get(&host.to_lowercase()) {
            let reason = format!(
                "hostname '{host}' matches a known-malicious domain indicator from {}",
                sig.source
            );
            return Detection::malicious(flow.clone(), sig.clone(), reason);
        }
    }

    if let Some(sig) = sigs.ips.get(&flow.dst_ip) {
        let reason = format!(
            "destination IP {} matches a known-malicious IP indicator from {}",
            flow.dst_ip, sig.source
        );
        return Detection::malicious(flow.clone(), sig.clone(), reason);
    }
    if let Some(sig) = sigs.ips.get(&flow.src_ip) {
        let reason = format!(
            "source IP {} matches a known-malicious IP indicator from {}",
            flow.src_ip, sig.source
        );
        return Detection::malicious(flow.clone(), sig.clone(), reason);
    }

    if let Some(hash) = &flow.payload_sha256 {
        if let Some(sig) = sigs.hashes.get(hash) {
            let reason = format!(
                "payload SHA-256 {hash} matches a known-malicious file hash from {}",
                sig.source
            );
            return Detection::malicious(flow.clone(), sig.clone(), reason);
        }
    }

    let mut reasons = Vec::new();

    if let Some(host) = &flow.hostname {
        if looks_like_dga(host) {
            reasons.push(format!(
                "hostname '{host}' has unusually high character entropy for its length, \
                 which is consistent with an algorithmically generated domain (possible DGA)"
            ));
        }
    }

    if SUSPICIOUS_PORTS.contains(&flow.dst_port) {
        reasons.push(format!(
            "connects on port {}, commonly associated with backdoor/C2 tooling",
            flow.dst_port
        ));
    }

    if let Some(subnet) = subnet24(flow.dst_ip) {
        if sigs.malicious_v4_subnets.contains(&subnet) {
            reasons.push(format!(
                "destination {} shares a /24 subnet with a known-malicious IP; \
                 may be related or fast-flux infrastructure",
                flow.dst_ip
            ));
        }
    }

    if reasons.is_empty() {
        Detection::benign(flow.clone())
    } else {
        Detection::suspicious(flow.clone(), reasons)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Protocol, Verdict};
    use chrono::Utc;
    use std::net::Ipv4Addr;

    fn flow(src: &str, dst: &str, dst_port: u16, protocol: Protocol) -> Flow {
        let now = Utc::now();
        Flow::new(
            src.parse().unwrap(),
            dst.parse().unwrap(),
            50000,
            dst_port,
            protocol,
            now,
        )
    }

    fn ip_signature(value: &str) -> Signature {
        Signature {
            ioc_type: IocType::Ip,
            value: value.to_string(),
            source: "TestFeed".to_string(),
            malware: Some("test.trojan".to_string()),
            threat_type: Some("botnet_cc".to_string()),
            confidence: Some(90),
            reference: None,
            first_seen: None,
        }
    }

    fn domain_signature(value: &str) -> Signature {
        Signature {
            ioc_type: IocType::Domain,
            value: value.to_string(),
            source: "TestFeed".to_string(),
            malware: Some("test.trojan".to_string()),
            threat_type: Some("payload_delivery".to_string()),
            confidence: Some(80),
            reference: None,
            first_seen: None,
        }
    }

    fn url_signature(value: &str) -> Signature {
        Signature {
            ioc_type: IocType::Url,
            value: value.to_string(),
            source: "TestFeed".to_string(),
            malware: None,
            threat_type: Some("payload_delivery".to_string()),
            confidence: None,
            reference: None,
            first_seen: None,
        }
    }

    #[test]
    fn benign_flow_with_no_matches_is_benign() {
        let sigs = SignatureSet::build(vec![ip_signature("203.0.113.99")]);
        let f = flow("10.0.0.5", "198.51.100.10", 443, Protocol::Tcp);
        let d = classify(&f, &sigs);
        assert_eq!(d.verdict, Verdict::Benign);
        assert!(d.matched_signature.is_none());
        assert!(d.ips_action.is_none());
    }

    #[test]
    fn malicious_destination_ip_is_flagged() {
        let sigs = SignatureSet::build(vec![ip_signature("203.0.113.77")]);
        let f = flow("10.0.0.5", "203.0.113.77", 443, Protocol::Tcp);
        let d = classify(&f, &sigs);
        assert_eq!(d.verdict, Verdict::Malicious);
        assert_eq!(d.matched_signature.unwrap().source, "TestFeed");
        assert!(d.ips_action.unwrap().contains("would-block"));
    }

    #[test]
    fn malicious_source_ip_is_also_flagged() {
        // A flow initiated toward us from a known-bad IP should still match,
        // even though it's the *source* rather than the destination.
        let sigs = SignatureSet::build(vec![ip_signature("203.0.113.77")]);
        let f = flow("203.0.113.77", "10.0.0.5", 443, Protocol::Tcp);
        assert_eq!(classify(&f, &sigs).verdict, Verdict::Malicious);
    }

    #[test]
    fn malicious_domain_hostname_is_flagged() {
        let sigs = SignatureSet::build(vec![domain_signature("update-cdn-sync.net")]);
        let mut f = flow("10.0.0.5", "203.0.113.77", 443, Protocol::Tcp);
        f.hostname = Some("update-cdn-sync.net".to_string());
        let d = classify(&f, &sigs);
        assert_eq!(d.verdict, Verdict::Malicious);
        assert!(d.reasons[0].contains("update-cdn-sync.net"));
    }

    #[test]
    fn domain_match_is_case_insensitive() {
        let sigs = SignatureSet::build(vec![domain_signature("evil.example")]);
        let mut f = flow("10.0.0.5", "203.0.113.5", 443, Protocol::Tcp);
        f.hostname = Some("EVIL.example".to_string());
        assert_eq!(classify(&f, &sigs).verdict, Verdict::Malicious);
    }

    #[test]
    fn url_match_takes_priority_over_domain() {
        // A malicious URL match should be reported even though the domain
        // itself is not separately listed as an IOC.
        let sigs = SignatureSet::build(vec![url_signature("http://evil.example/payload.bin")]);
        let mut f = flow("10.0.0.5", "203.0.113.5", 80, Protocol::Tcp);
        f.hostname = Some("evil.example".to_string());
        f.url = Some("http://evil.example/payload.bin".to_string());
        let d = classify(&f, &sigs);
        assert_eq!(d.verdict, Verdict::Malicious);
        assert!(d.reasons[0].contains("URL"));
    }

    #[test]
    fn url_match_ignores_trailing_slash() {
        let sigs = SignatureSet::build(vec![url_signature("http://evil.example/payload.bin/")]);
        let mut f = flow("10.0.0.5", "203.0.113.5", 80, Protocol::Tcp);
        f.url = Some("http://evil.example/payload.bin".to_string());
        assert_eq!(classify(&f, &sigs).verdict, Verdict::Malicious);
    }

    #[test]
    fn payload_hash_match_is_flagged() {
        let sig = Signature {
            ioc_type: IocType::Sha256,
            value: "deadbeef00000000000000000000000000000000000000000000000000000000".to_string(),
            source: "TestFeed".to_string(),
            malware: None,
            threat_type: None,
            confidence: None,
            reference: None,
            first_seen: None,
        };
        let sigs = SignatureSet::build(vec![sig]);
        let mut f = flow("10.0.0.5", "203.0.113.5", 443, Protocol::Tcp);
        f.payload_sha256 = Some("deadbeef00000000000000000000000000000000000000000000000000000000".to_string());
        assert_eq!(classify(&f, &sigs).verdict, Verdict::Malicious);
    }

    #[test]
    fn high_entropy_hostname_is_suspicious_not_malicious() {
        let sigs = SignatureSet::build(vec![]);
        let mut f = flow("10.0.0.5", "192.0.2.55", 443, Protocol::Tcp);
        f.hostname = Some("zx7qmvtnhpla.info".to_string());
        let d = classify(&f, &sigs);
        assert_eq!(d.verdict, Verdict::Suspicious);
        assert!(d.matched_signature.is_none());
        assert!(d.reasons.iter().any(|r| r.contains("entropy")));
    }

    #[test]
    fn short_hostname_is_not_flagged_as_dga_even_with_entropy() {
        // Below DGA_MIN_LABEL_LEN, so it should not trip the heuristic.
        let sigs = SignatureSet::build(vec![]);
        let mut f = flow("10.0.0.5", "192.0.2.55", 443, Protocol::Tcp);
        f.hostname = Some("zx7q.info".to_string());
        assert_eq!(classify(&f, &sigs).verdict, Verdict::Benign);
    }

    #[test]
    fn known_backdoor_port_is_suspicious() {
        let sigs = SignatureSet::build(vec![]);
        let f = flow("10.0.0.5", "192.0.2.90", 4444, Protocol::Tcp);
        let d = classify(&f, &sigs);
        assert_eq!(d.verdict, Verdict::Suspicious);
        assert!(d.reasons.iter().any(|r| r.contains("4444")));
    }

    #[test]
    fn neighbor_subnet_of_malicious_ip_is_suspicious() {
        let sigs = SignatureSet::build(vec![ip_signature("203.0.113.77")]);
        // Different host, same /24 as the malicious IOC.
        let f = flow("10.0.0.5", "203.0.113.5", 443, Protocol::Tcp);
        let d = classify(&f, &sigs);
        assert_eq!(d.verdict, Verdict::Suspicious);
        assert!(d.reasons.iter().any(|r| r.contains("/24")));
    }

    #[test]
    fn exact_match_always_wins_over_heuristics() {
        // Same /24 heuristic AND an exact IP match both apply; exact match
        // must win and produce Malicious, not Suspicious.
        let sigs = SignatureSet::build(vec![ip_signature("203.0.113.77")]);
        let f = flow("10.0.0.5", "203.0.113.77", 4444, Protocol::Tcp);
        assert_eq!(classify(&f, &sigs).verdict, Verdict::Malicious);
    }

    #[test]
    fn ordinary_benign_https_flow_is_benign() {
        let sigs = SignatureSet::build(vec![
            ip_signature("203.0.113.77"),
            domain_signature("update-cdn-sync.net"),
        ]);
        let mut f = flow("10.0.0.5", "198.51.100.10", 443, Protocol::Tcp);
        f.hostname = Some("www.example.com".to_string());
        assert_eq!(classify(&f, &sigs).verdict, Verdict::Benign);
    }
}
