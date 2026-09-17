pub mod parse;
pub mod pcap;

use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::Result;
use chrono::{TimeZone, Utc};
use sha2::{Digest, Sha256};

use crate::models::{Flow, Protocol};
use parse::{extract_http, extract_sni, parse_dns_query_name, parse_dns_response, parse_ip_packet, parse_l4};
use pcap::parse_pcap;

pub struct IngestResult {
    pub flows: Vec<Flow>,
    /// Total packets present in the capture file.
    pub packet_count: usize,
    /// Packets this engine was able to parse down to a transport segment
    /// (i.e. recognized link/IP/transport layers).
    pub parsed_packet_count: usize,
}

/// An unordered endpoint pair + protocol, so both directions of one
/// connection (client->server and server->client) collapse into a single
/// `Flow` instead of appearing as two unrelated rows.
#[derive(PartialEq, Eq, Hash, Clone)]
struct FlowKey {
    a: (IpAddr, u16),
    b: (IpAddr, u16),
    protocol: Protocol,
}

impl FlowKey {
    fn new(ip1: IpAddr, port1: u16, ip2: IpAddr, port2: u16, protocol: Protocol) -> Self {
        let (a, b) = if (ip1, port1) <= (ip2, port2) {
            ((ip1, port1), (ip2, port2))
        } else {
            ((ip2, port2), (ip1, port1))
        };
        FlowKey { a, b, protocol }
    }
}

pub fn ingest_pcap_bytes(bytes: &[u8]) -> Result<IngestResult> {
    let pcap = parse_pcap(bytes)?;
    let mut flow_map: HashMap<FlowKey, Flow> = HashMap::new();
    let mut resolved: HashMap<IpAddr, String> = HashMap::new();
    let mut parsed_count = 0usize;

    for raw in &pcap.packets {
        let Some((src_ip, dst_ip, ip_proto, ip_payload)) = parse_ip_packet(&raw.data, pcap.link_type) else {
            continue;
        };
        let Some(l4) = parse_l4(ip_proto, &ip_payload) else {
            continue;
        };
        parsed_count += 1;

        let mut hostname = None;
        let mut url = None;

        if l4.protocol == Protocol::Udp && (l4.src_port == 53 || l4.dst_port == 53) {
            if l4.dst_port == 53 {
                hostname = parse_dns_query_name(&l4.payload);
            } else {
                for (name, ip) in parse_dns_response(&l4.payload) {
                    resolved.insert(ip, name);
                }
            }
        }
        if l4.protocol == Protocol::Tcp && !l4.payload.is_empty() {
            if let Some(sni) = extract_sni(&l4.payload) {
                hostname = Some(sni);
            } else if let Some((h, u)) = extract_http(&l4.payload) {
                hostname = Some(h);
                url = Some(u);
            }
        }

        let payload_hash = (!l4.payload.is_empty()).then(|| format!("{:x}", Sha256::digest(&l4.payload)));

        let ts = Utc
            .timestamp_opt(raw.timestamp_secs.floor() as i64, 0)
            .single()
            .unwrap_or_else(Utc::now);

        let key = FlowKey::new(src_ip, l4.src_port, dst_ip, l4.dst_port, l4.protocol);
        let entry = flow_map
            .entry(key)
            .or_insert_with(|| Flow::new(src_ip, dst_ip, l4.src_port, l4.dst_port, l4.protocol, ts));

        entry.packet_count += 1;
        entry.byte_count += l4.payload.len() as u64;
        entry.last_seen = ts;
        if entry.hostname.is_none() {
            entry.hostname = hostname;
        }
        if entry.url.is_none() {
            entry.url = url;
        }
        if entry.payload_sha256.is_none() {
            entry.payload_sha256 = payload_hash;
        }
    }

    let mut flows: Vec<Flow> = flow_map.into_values().collect();
    for flow in flows.iter_mut() {
        if flow.hostname.is_none() {
            if let Some(name) = resolved.get(&flow.dst_ip).or_else(|| resolved.get(&flow.src_ip)) {
                flow.hostname = Some(name.clone());
            }
        }
    }
    flows.sort_by_key(|f| f.first_seen);

    Ok(IngestResult {
        flows,
        packet_count: pcap.packets.len(),
        parsed_packet_count: parsed_count,
    })
}
