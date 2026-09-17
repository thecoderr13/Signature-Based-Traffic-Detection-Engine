//! Core domain types shared across ingestion, signature matching, and reporting.
//!
//! Nothing in this module talks to the network, the filesystem, or Axum —
//! it is pure data, which is what keeps `engine::matcher` unit-testable in
//! isolation (see the tests at the bottom of that module).

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Transport-layer protocol of a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Icmp => write!(f, "ICMP"),
            Protocol::Other(n) => write!(f, "PROTO {n}"),
        }
    }
}

/// A bidirectional network flow assembled from one or more packets that
/// share the same (unordered) pair of endpoints and protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flow {
    pub id: Uuid,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    /// Hostname associated with this flow, taken from a DNS query/response,
    /// a TLS ClientHello SNI extension, or an HTTP Host header — in that
    /// order of discovery, first non-empty value wins.
    pub hostname: Option<String>,
    /// Full URL, only populated when plaintext HTTP was observed.
    pub url: Option<String>,
    /// SHA-256 of the first payload-bearing packet's transport payload.
    /// Used only for the bonus hash-based (AV-style) matching path.
    pub payload_sha256: Option<String>,
    pub packet_count: u32,
    pub byte_count: u64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

impl Flow {
    pub fn new(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: Protocol,
        ts: DateTime<Utc>,
    ) -> Self {
        Flow {
            id: Uuid::new_v4(),
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            hostname: None,
            url: None,
            payload_sha256: None,
            packet_count: 0,
            byte_count: 0,
            first_seen: ts,
            last_seen: ts,
        }
    }
}

/// The kind of indicator of compromise a `Signature` represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IocType {
    Ip,
    Domain,
    Url,
    Sha256,
}

/// One indicator pulled from a threat-intel feed (or the bundled offline
/// sample set), normalized into a common shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub ioc_type: IocType,
    /// Normalized value: lowercase for domains/hashes, unmodified for IPs/URLs.
    pub value: String,
    /// Which feed this came from, e.g. "ThreatFox", "URLhaus", "Offline Sample Set".
    pub source: String,
    #[serde(default)]
    pub malware: Option<String>,
    #[serde(default)]
    pub threat_type: Option<String>,
    #[serde(default)]
    pub confidence: Option<u8>,
    #[serde(default)]
    pub reference: Option<String>,
    #[serde(default)]
    pub first_seen: Option<String>,
}

/// The classification an engine run assigns to a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Benign,
    Suspicious,
    Malicious,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verdict::Benign => write!(f, "Benign"),
            Verdict::Suspicious => write!(f, "Suspicious"),
            Verdict::Malicious => write!(f, "Malicious"),
        }
    }
}

/// The outcome of matching one flow against the current signature set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub flow: Flow,
    pub verdict: Verdict,
    /// The IOC that produced a Malicious verdict, if any.
    pub matched_signature: Option<Signature>,
    /// Human-readable explanation, always populated for Suspicious/Malicious.
    pub reasons: Vec<String>,
    /// Simulated IPS decision. Only set for Malicious verdicts — this is a
    /// logged "would-block" action, no packets are actually dropped.
    pub ips_action: Option<String>,
}

impl Detection {
    pub fn benign(flow: Flow) -> Self {
        Detection {
            flow,
            verdict: Verdict::Benign,
            matched_signature: None,
            reasons: vec![],
            ips_action: None,
        }
    }

    pub fn suspicious(flow: Flow, reasons: Vec<String>) -> Self {
        Detection {
            flow,
            verdict: Verdict::Suspicious,
            matched_signature: None,
            reasons,
            ips_action: None,
        }
    }

    pub fn malicious(flow: Flow, signature: Signature, reason: String) -> Self {
        let ips_action = format!(
            "would-block: dropped connection {} -> {}:{} ({})",
            flow.src_ip, flow.dst_ip, flow.dst_port, signature.source
        );
        Detection {
            flow,
            verdict: Verdict::Malicious,
            matched_signature: Some(signature),
            reasons: vec![reason],
            ips_action: Some(ips_action),
        }
    }
}
