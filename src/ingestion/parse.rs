//! Byte-level protocol parsers. Each function takes a byte slice and
//! returns `None`/`vec![]` on anything malformed or unsupported rather than
//! panicking — traffic captures are untrusted input.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::models::Protocol;

/// Parsed IP-layer envelope: endpoints, the IP protocol number, and the
/// bytes after the IP header (i.e. the transport segment).
pub fn parse_ip_packet(data: &[u8], link_type: u32) -> Option<(IpAddr, IpAddr, u8, Vec<u8>)> {
    match link_type {
        1 => {
            // Ethernet II, with optional single 802.1Q VLAN tag.
            if data.len() < 14 {
                return None;
            }
            let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
            let mut offset = 14;
            if ethertype == 0x8100 {
                if data.len() < offset + 4 {
                    return None;
                }
                ethertype = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
                offset += 4;
            }
            match ethertype {
                0x0800 | 0x86DD => parse_ip_header(data.get(offset..)?),
                _ => None, // ARP or other non-IP ethertype: not a flow we track
            }
        }
        101 => parse_ip_header(data), // LINKTYPE_RAW: no link-layer header at all
        _ => None,
    }
}

fn parse_ip_header(data: &[u8]) -> Option<(IpAddr, IpAddr, u8, Vec<u8>)> {
    let first = *data.first()?;
    let version = first >> 4;
    if version == 4 {
        if data.len() < 20 {
            return None;
        }
        let ihl = ((first & 0x0f) as usize) * 4;
        if ihl < 20 || data.len() < ihl {
            return None;
        }
        let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let protocol = data[9];
        let src = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
        let dst = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));
        let end = total_len.clamp(ihl, data.len());
        Some((src, dst, protocol, data[ihl..end].to_vec()))
    } else if version == 6 {
        if data.len() < 40 {
            return None;
        }
        let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
        let next_header = data[6];
        let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).ok()?));
        let dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).ok()?));
        let end = (40 + payload_len).clamp(40, data.len());
        Some((src, dst, next_header, data[40..end].to_vec()))
    } else {
        None
    }
}

pub struct L4Info {
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub payload: Vec<u8>,
}

/// Parses the transport-layer header for the IP protocol numbers this
/// engine understands (TCP=6, UDP=17, ICMP=1); anything else is passed
/// through as an opaque `Protocol::Other` flow with no ports.
pub fn parse_l4(ip_protocol: u8, data: &[u8]) -> Option<L4Info> {
    match ip_protocol {
        6 => {
            if data.len() < 20 {
                return None;
            }
            let src_port = u16::from_be_bytes([data[0], data[1]]);
            let dst_port = u16::from_be_bytes([data[2], data[3]]);
            let data_offset = ((data[12] >> 4) as usize) * 4;
            if data_offset < 20 || data.len() < data_offset {
                return None;
            }
            Some(L4Info {
                src_port,
                dst_port,
                protocol: Protocol::Tcp,
                payload: data[data_offset..].to_vec(),
            })
        }
        17 => {
            if data.len() < 8 {
                return None;
            }
            let src_port = u16::from_be_bytes([data[0], data[1]]);
            let dst_port = u16::from_be_bytes([data[2], data[3]]);
            Some(L4Info {
                src_port,
                dst_port,
                protocol: Protocol::Udp,
                payload: data[8..].to_vec(),
            })
        }
        1 | 58 => Some(L4Info {
            src_port: 0,
            dst_port: 0,
            protocol: Protocol::Icmp,
            payload: data.to_vec(),
        }),
        other => Some(L4Info {
            src_port: 0,
            dst_port: 0,
            protocol: Protocol::Other(other),
            payload: data.to_vec(),
        }),
    }
}

/// Decodes a DNS name starting at `start`, following compression pointers.
/// Returns the dotted name and the offset just past the end of the *first*
/// (non-pointer) occurrence, so callers can keep walking the message.
fn read_dns_name(buf: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut jumped = false;
    let mut end_pos = start;
    let mut hops = 0;

    loop {
        hops += 1;
        if hops > 128 {
            return None; // guards against a pointer loop in malformed input
        }
        let len = *buf.get(pos)? as usize;
        if len == 0 {
            if !jumped {
                end_pos = pos + 1;
            }
            break;
        } else if len & 0xC0 == 0xC0 {
            let b2 = *buf.get(pos + 1)? as usize;
            let ptr = ((len & 0x3F) << 8) | b2;
            if !jumped {
                end_pos = pos + 2;
            }
            jumped = true;
            pos = ptr;
        } else {
            let label_start = pos + 1;
            let label_end = label_start + len;
            let label = buf.get(label_start..label_end)?;
            labels.push(String::from_utf8_lossy(label).to_string());
            pos = label_end;
        }
    }
    Some((labels.join("."), end_pos))
}

/// Extracts the queried domain from a DNS query message (UDP/53 towards
/// the resolver).
pub fn parse_dns_query_name(payload: &[u8]) -> Option<String> {
    if payload.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return None;
    }
    read_dns_name(payload, 12).map(|(name, _)| name)
}

/// Extracts (name, resolved IP) pairs from A/AAAA records in a DNS
/// response message (UDP/53 from the resolver). Used to enrich flows whose
/// hostname wasn't otherwise observable (e.g. plain TCP with no TLS/HTTP).
pub fn parse_dns_response(payload: &[u8]) -> Vec<(String, IpAddr)> {
    let mut out = Vec::new();
    if payload.len() < 12 {
        return out;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let ancount = u16::from_be_bytes([payload[6], payload[7]]) as usize;
    let mut pos = 12usize;

    for _ in 0..qdcount {
        let Some((_, next)) = read_dns_name(payload, pos) else {
            return out;
        };
        pos = next;
        if pos + 4 > payload.len() {
            return out;
        }
        pos += 4; // QTYPE + QCLASS
    }

    for _ in 0..ancount {
        let Some((name, next)) = read_dns_name(payload, pos) else {
            return out;
        };
        pos = next;
        if pos + 10 > payload.len() {
            return out;
        }
        let rtype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let rdlength = u16::from_be_bytes([payload[pos + 8], payload[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > payload.len() {
            return out;
        }
        let rdata = &payload[pos..pos + rdlength];
        if rtype == 1 && rdlength == 4 {
            out.push((name, IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]))));
        } else if rtype == 28 && rdlength == 16 {
            if let Ok(arr) = <[u8; 16]>::try_from(rdata) {
                out.push((name, IpAddr::V6(Ipv6Addr::from(arr))));
            }
        }
        pos += rdlength;
    }
    out
}

/// Best-effort extraction of the SNI hostname from a TLS ClientHello. Reads
/// only the record + handshake framing needed to reach the `server_name`
/// extension; returns `None` on anything that doesn't parse cleanly rather
/// than erroring, since most TCP payloads are not a ClientHello at all.
pub fn extract_sni(tcp_payload: &[u8]) -> Option<String> {
    if tcp_payload.len() < 5 || tcp_payload[0] != 0x16 {
        return None; // not a TLS handshake record
    }
    let record_len = u16::from_be_bytes([tcp_payload[3], tcp_payload[4]]) as usize;
    let record_end = (5 + record_len).min(tcp_payload.len());
    let record = tcp_payload.get(5..record_end)?;

    if record.len() < 4 || record[0] != 0x01 {
        return None; // not a ClientHello
    }
    let mut pos = 4usize; // skip handshake type(1) + length(3)
    pos = pos.checked_add(2)?; // client_version
    pos = pos.checked_add(32)?; // random
    let session_id_len = *record.get(pos)? as usize;
    pos = pos + 1 + session_id_len;

    let cipher_suites_len =
        u16::from_be_bytes([*record.get(pos)?, *record.get(pos + 1)?]) as usize;
    pos += 2 + cipher_suites_len;

    let comp_methods_len = *record.get(pos)? as usize;
    pos += 1 + comp_methods_len;

    let extensions_len = u16::from_be_bytes([*record.get(pos)?, *record.get(pos + 1)?]) as usize;
    pos += 2;
    let extensions_end = (pos + extensions_len).min(record.len());

    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([record[pos], record[pos + 1]]);
        let ext_len = u16::from_be_bytes([record[pos + 2], record[pos + 3]]) as usize;
        let ext_start = pos + 4;
        let ext_end = (ext_start + ext_len).min(extensions_end);

        if ext_type == 0x0000 {
            let ext_data = record.get(ext_start..ext_end)?;
            if ext_data.len() >= 5 {
                let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                let list_end = (2 + list_len).min(ext_data.len());
                let mut lpos = 2usize;
                while lpos + 3 <= list_end {
                    let name_type = ext_data[lpos];
                    let name_len = u16::from_be_bytes([ext_data[lpos + 1], ext_data[lpos + 2]]) as usize;
                    let name_start = lpos + 3;
                    let name_end = (name_start + name_len).min(ext_data.len());
                    if name_type == 0 {
                        return Some(String::from_utf8_lossy(&ext_data[name_start..name_end]).to_string());
                    }
                    lpos = name_end;
                }
            }
        }
        pos = ext_end;
    }
    None
}

const HTTP_METHODS: [&str; 7] = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"];

/// Best-effort extraction of `(host, url)` from a plaintext HTTP request.
pub fn extract_http(tcp_payload: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(tcp_payload).ok()?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?;
    if !HTTP_METHODS.contains(&method) {
        return None;
    }
    let path = parts.next()?;

    let host = lines
        .take_while(|l| !l.is_empty())
        .find_map(|l| l.strip_prefix("Host: ").or_else(|| l.strip_prefix("host: ")))?
        .trim()
        .to_string();

    Some((host.clone(), format!("http://{host}{path}")))
}
