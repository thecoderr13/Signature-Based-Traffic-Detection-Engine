//! `cargo run --bin gen-sample-pcap` writes `sample_pcaps/demo-traffic.pcap`
//! — a small, fully synthetic capture built byte-by-byte (no libpcap, no
//! network, no root) so the whole detection pipeline can be demoed without
//! needing a real capture.
//!
//! Every "malicious" address below is inside an RFC 5737 documentation
//! range (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) reserved for
//! exactly this purpose, and every "malicious" domain is a made-up name —
//! nothing here points at real infrastructure. The same IOCs are also
//! present in `data/sample_iocs.json`, so running this generator and then
//! the offline signature source together produces genuine Malicious and
//! Suspicious verdicts end to end with zero network access.

use std::net::Ipv4Addr;
use std::path::Path;

fn main() -> std::io::Result<()> {
    let client_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    let router_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0xfe];
    let client_ip = Ipv4Addr::new(10, 0, 0, 5);
    let dns_ip = Ipv4Addr::new(8, 8, 8, 8);

    let mut packets: Vec<Vec<u8>> = Vec::new();
    let mut seq = 1000u32;
    let mut push = |pkt: Vec<u8>| packets.push(pkt);

    // --- 1) Benign: DNS lookup + TLS session to www.example.demo ----------
    let benign_ip = Ipv4Addr::new(198, 51, 100, 10);
    push(udp_pkt(client_mac, router_mac, client_ip, dns_ip, 40001, 53, &dns_query(0x1001, "www.example.demo")));
    push(udp_pkt(router_mac, client_mac, dns_ip, client_ip, 53, 40001, &dns_response(0x1001, "www.example.demo", benign_ip)));
    push(tcp_pkt(client_mac, router_mac, client_ip, benign_ip, 51000, 443, next_seq(&mut seq), &tls_client_hello("www.example.demo")));

    // --- 2) Benign: plaintext HTTP to a benign CDN host --------------------
    let benign_ip2 = Ipv4Addr::new(198, 51, 100, 20);
    push(tcp_pkt(
        client_mac, router_mac, client_ip, benign_ip2, 51001, 80, next_seq(&mut seq),
        &http_request("GET", "/assets/logo.png", "cdn.example-benign.org"),
    ));

    // --- 3) Benign: DNS + TLS to a second legitimate-looking host ----------
    let benign_ip3 = Ipv4Addr::new(198, 51, 100, 40);
    push(udp_pkt(client_mac, router_mac, client_ip, dns_ip, 40002, 53, &dns_query(0x1002, "static.example-benign.dev")));
    push(udp_pkt(router_mac, client_mac, dns_ip, client_ip, 53, 40002, &dns_response(0x1002, "static.example-benign.dev", benign_ip3)));
    push(tcp_pkt(client_mac, router_mac, client_ip, benign_ip3, 51002, 443, next_seq(&mut seq), &tls_client_hello("static.example-benign.dev")));

    // --- 4) Malicious payload delivery: domain + URL + IP IOC ----------------
    let payload_ip = Ipv4Addr::new(203, 0, 113, 77);
    push(udp_pkt(client_mac, router_mac, client_ip, dns_ip, 40003, 53, &dns_query(0x1003, "update-cdn-sync.net")));
    push(udp_pkt(router_mac, client_mac, dns_ip, client_ip, 53, 40003, &dns_response(0x1003, "update-cdn-sync.net", payload_ip)));
    push(tcp_pkt(client_mac, router_mac, client_ip, payload_ip, 51003, 443, next_seq(&mut seq), &tls_client_hello("update-cdn-sync.net")));
    push(tcp_pkt(
        client_mac, router_mac, client_ip, payload_ip, 51004, 80, next_seq(&mut seq),
        &http_request("GET", "/update/payload.bin", "update-cdn-sync.net"),
    ));

    // --- 5) Malicious malware download: direct URL / binary fetch ----------
    let malware_ip = Ipv4Addr::new(203, 0, 113, 88);
    push(udp_pkt(client_mac, router_mac, client_ip, dns_ip, 40004, 53, &dns_query(0x1004, "cdn-filehub-update.net")));
    push(udp_pkt(router_mac, client_mac, dns_ip, client_ip, 53, 40004, &dns_response(0x1004, "cdn-filehub-update.net", malware_ip)));
    push(tcp_pkt(
        client_mac, router_mac, client_ip, malware_ip, 51005, 80, next_seq(&mut seq),
        &http_request("GET", "/installer.exe", "cdn-filehub-update.net"),
    ));

    // --- 6) Botnet C2 / command-and-control ---------------------------------
    let c2_ip = Ipv4Addr::new(198, 51, 100, 66);
    push(udp_pkt(client_mac, router_mac, client_ip, dns_ip, 40005, 53, &dns_query(0x1005, "telemetry-sync-node7.top")));
    push(udp_pkt(router_mac, client_mac, dns_ip, client_ip, 53, 40005, &dns_response(0x1005, "telemetry-sync-node7.top", c2_ip)));
    push(tcp_pkt(client_mac, router_mac, client_ip, c2_ip, 51006, 443, next_seq(&mut seq), &tls_client_hello("telemetry-sync-node7.top")));
    push(tcp_pkt(client_mac, router_mac, client_ip, c2_ip, 51007, 4444, next_seq(&mut seq), b"\x00\x00\x00\x00cmd: beacon"));

    // --- 7) Phishing: fake login/portal traffic -----------------------------
    let phishing_ip = Ipv4Addr::new(198, 51, 100, 77);
    push(udp_pkt(client_mac, router_mac, client_ip, dns_ip, 40006, 53, &dns_query(0x1006, "auth-portal-secure-update.info")));
    push(udp_pkt(router_mac, client_mac, dns_ip, client_ip, 53, 40006, &dns_response(0x1006, "auth-portal-secure-update.info", phishing_ip)));
    push(tcp_pkt(
        client_mac, router_mac, client_ip, phishing_ip, 51008, 80, next_seq(&mut seq),
        &http_request("POST", "/login", "auth-portal-secure-update.info"),
    ));
    push(tcp_pkt(
        client_mac, router_mac, client_ip, phishing_ip, 51009, 443, next_seq(&mut seq),
        &tls_client_hello("auth-portal-secure-update.info"),
    ));

    // --- 8) Trojan / loader traffic ----------------------------------------
    let trojan_ip = Ipv4Addr::new(198, 51, 100, 88);
    push(udp_pkt(client_mac, router_mac, client_ip, dns_ip, 40007, 53, &dns_query(0x1007, "loader-cdn-sys.net")));
    push(udp_pkt(router_mac, client_mac, dns_ip, client_ip, 53, 40007, &dns_response(0x1007, "loader-cdn-sys.net", trojan_ip)));
    push(tcp_pkt(
        client_mac, router_mac, client_ip, trojan_ip, 51010, 443, next_seq(&mut seq),
        &tls_client_hello("loader-cdn-sys.net"),
    ));
    push(tcp_pkt(
        client_mac, router_mac, client_ip, trojan_ip, 51011, 8080, next_seq(&mut seq),
        &http_request("GET", "/dl/agent.exe", "loader-cdn-sys.net"),
    ));

    // --- 9) Suspicious DGA-like hostnames -----------------------------------
    let dga_ip = Ipv4Addr::new(192, 0, 2, 55);
    push(tcp_pkt(client_mac, router_mac, client_ip, dga_ip, 51012, 443, next_seq(&mut seq), &tls_client_hello("zx7qmvtnhpla.info")));
    push(tcp_pkt(client_mac, router_mac, client_ip, dga_ip, 51013, 443, next_seq(&mut seq), &tls_client_hello("h4xmy7d0rm.net")));

    // --- 10) Suspicious backdoor-style port traffic -------------------------
    let backdoor_ip = Ipv4Addr::new(192, 0, 2, 90);
    push(tcp_pkt(client_mac, router_mac, client_ip, backdoor_ip, 51014, 4444, next_seq(&mut seq), b"\x00\x00\x00\x00ping"));
    push(tcp_pkt(client_mac, router_mac, client_ip, backdoor_ip, 51015, 1337, next_seq(&mut seq), b"\x00\x00\x00\x00stage"));

    // --- 11) Benign extras to make the capture feel realistic --------------
    let benign_ip4 = Ipv4Addr::new(198, 51, 100, 50);
    push(udp_pkt(client_mac, router_mac, client_ip, dns_ip, 40008, 53, &dns_query(0x1008, "mail.example.net")));
    push(udp_pkt(router_mac, client_mac, dns_ip, client_ip, 53, 40008, &dns_response(0x1008, "mail.example.net", benign_ip4)));
    push(tcp_pkt(client_mac, router_mac, client_ip, benign_ip4, 51016, 443, next_seq(&mut seq), &tls_client_hello("mail.example.net")));

    let benign_ip5 = Ipv4Addr::new(198, 51, 100, 60);
    push(tcp_pkt(client_mac, router_mac, client_ip, benign_ip5, 51017, 80, next_seq(&mut seq), &http_request("GET", "/help/index.html", "helpdesk.example.org")));

    let out_path = Path::new("sample_pcaps/demo-traffic.pcap");
    write_pcap(out_path, &packets)?;

    println!("Wrote {} packets to {}", packets.len(), out_path.display());
    println!();
    println!("The capture includes benign web traffic plus malicious payload delivery, malware downloads,");
    println!("phishing, botnet C2, trojan/loader behavior, and suspicious DGA/backdoor patterns.");
    println!("Expected categories: benign, payload_delivery, botnet_cc, phishing, malware_download, trojan_generic, DGA-like suspicious, backdoor-style ports.");

    let variant_path = Path::new("sample_pcaps/varied-malicious-traffic.pcap");
    let mut variant_packets = Vec::new();
    let mut variant_seq = 3000u32;
    let mut push_variant = |pkt: Vec<u8>| variant_packets.push(pkt);

    let variant_client_ip = Ipv4Addr::new(10, 10, 10, 10);
    let variant_dns_ip = Ipv4Addr::new(8, 8, 8, 8);
    let variant_benign_ip = Ipv4Addr::new(198, 51, 100, 9);
    let variant_live_domain_ip = Ipv4Addr::new(203, 0, 113, 77);
    let variant_urlhaus_ip = Ipv4Addr::new(60, 198, 35, 226);
    let variant_urlhaus_ip2 = Ipv4Addr::new(175, 165, 86, 86);

    push_variant(udp_pkt(client_mac, router_mac, variant_client_ip, variant_dns_ip, 40100, 53, &dns_query(0x2001, "www.example.com")));
    push_variant(udp_pkt(router_mac, client_mac, variant_dns_ip, variant_client_ip, 53, 40100, &dns_response(0x2001, "www.example.com", variant_benign_ip)));
    push_variant(tcp_pkt(client_mac, router_mac, variant_client_ip, variant_benign_ip, 52000, 443, next_seq(&mut variant_seq), &tls_client_hello("www.example.com")));

    push_variant(udp_pkt(client_mac, router_mac, variant_client_ip, variant_dns_ip, 40101, 53, &dns_query(0x2002, "wisma138albedo.com")));
    push_variant(udp_pkt(router_mac, client_mac, variant_dns_ip, variant_client_ip, 53, 40101, &dns_response(0x2002, "wisma138albedo.com", variant_live_domain_ip)));
    push_variant(tcp_pkt(client_mac, router_mac, variant_client_ip, variant_live_domain_ip, 52001, 443, next_seq(&mut variant_seq), &tls_client_hello("wisma138albedo.com")));

    push_variant(tcp_pkt(
        client_mac, router_mac, variant_client_ip, variant_urlhaus_ip, 52002, 40639, next_seq(&mut variant_seq),
        &http_request("GET", "/bin.sh", "60.198.35.226:40639"),
    ));
    push_variant(tcp_pkt(
        client_mac, router_mac, variant_client_ip, variant_urlhaus_ip2, 52003, 52969, next_seq(&mut variant_seq),
        &http_request("GET", "/bin.sh", "175.165.86.86:52969"),
    ));

    push_variant(udp_pkt(client_mac, router_mac, variant_client_ip, variant_dns_ip, 40102, 53, &dns_query(0x2003, "telemetry-sync-node7.top")));
    push_variant(udp_pkt(router_mac, client_mac, variant_dns_ip, variant_client_ip, 53, 40102, &dns_response(0x2003, "telemetry-sync-node7.top", variant_live_domain_ip)));
    push_variant(tcp_pkt(client_mac, router_mac, variant_client_ip, variant_live_domain_ip, 52004, 4444, next_seq(&mut variant_seq), b"\x00\x00\x00\x00beacon"));

    push_variant(tcp_pkt(client_mac, router_mac, variant_client_ip, variant_live_domain_ip, 52005, 443, next_seq(&mut variant_seq), &tls_client_hello("auth-portal-secure-update.info")));
    push_variant(tcp_pkt(
        client_mac, router_mac, variant_client_ip, variant_live_domain_ip, 52006, 80, next_seq(&mut variant_seq),
        &http_request("POST", "/login", "auth-portal-secure-update.info"),
    ));

    write_pcap(variant_path, &variant_packets)?;
    println!("Wrote {} packets to {}", variant_packets.len(), variant_path.display());
    println!("The variant uses exact live abuse.ch IOC values and should trigger Malicious verdicts for domain and URL matches.");

    Ok(())
}

fn next_seq(seq: &mut u32) -> u32 {
    *seq += 1000;
    *seq
}

// ---------------------------------------------------------------------
// DNS wire format
// ---------------------------------------------------------------------

fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

fn dns_query(id: u16, name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend(encode_dns_name(name));
    out.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    out.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    out
}

fn dns_response(id: u16, name: &str, ip: Ipv4Addr) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x8180u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&1u16.to_be_bytes()); // ancount
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend(encode_dns_name(name));
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend(encode_dns_name(name)); // answer name (uncompressed, kept simple)
    out.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
    out.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    out.extend_from_slice(&60u32.to_be_bytes()); // TTL
    out.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    out.extend_from_slice(&ip.octets());
    out
}

// ---------------------------------------------------------------------
// TLS ClientHello (just enough to carry an SNI extension)
// ---------------------------------------------------------------------

fn tls_client_hello(sni: &str) -> Vec<u8> {
    let mut sni_entry = Vec::new();
    sni_entry.push(0u8); // name_type: host_name
    sni_entry.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    sni_entry.extend_from_slice(sni.as_bytes());

    let mut sni_list = Vec::new();
    sni_list.extend_from_slice(&(sni_entry.len() as u16).to_be_bytes());
    sni_list.extend(sni_entry);

    let mut ext_sni = Vec::new();
    ext_sni.extend_from_slice(&0x0000u16.to_be_bytes()); // extension type: server_name
    ext_sni.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
    ext_sni.extend(sni_list);

    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes()); // client_version TLS 1.2
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0); // session_id_len
    body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites_len
    body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    body.push(1); // compression_methods_len
    body.push(0); // null compression
    body.extend_from_slice(&(ext_sni.len() as u16).to_be_bytes()); // extensions_len
    body.extend(ext_sni);

    let mut handshake = Vec::new();
    handshake.push(0x01); // ClientHello
    let len_bytes = (body.len() as u32).to_be_bytes();
    handshake.extend_from_slice(&len_bytes[1..4]); // 3-byte length
    handshake.extend(body);

    let mut record = Vec::new();
    record.push(0x16); // handshake content type
    record.extend_from_slice(&0x0301u16.to_be_bytes()); // record version
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend(handshake);
    record
}

fn http_request(method: &str, path: &str, host: &str) -> Vec<u8> {
    format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: sentinel-demo/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n").into_bytes()
}

// ---------------------------------------------------------------------
// Ethernet / IPv4 / UDP / TCP framing
// ---------------------------------------------------------------------

fn eth_header(dst_mac: [u8; 6], src_mac: [u8; 6]) -> Vec<u8> {
    let mut v = Vec::with_capacity(14);
    v.extend_from_slice(&dst_mac);
    v.extend_from_slice(&src_mac);
    v.extend_from_slice(&0x0800u16.to_be_bytes());
    v
}

fn ipv4_header(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload_len: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(20);
    v.push(0x45);
    v.push(0x00);
    v.extend_from_slice(&(20u16 + payload_len).to_be_bytes());
    v.extend_from_slice(&0u16.to_be_bytes());
    v.extend_from_slice(&0x4000u16.to_be_bytes());
    v.push(64);
    v.push(protocol);
    v.extend_from_slice(&0u16.to_be_bytes()); // checksum left unset; not validated by the reader
    v.extend_from_slice(&src.octets());
    v.extend_from_slice(&dst.octets());
    v
}

fn udp_header(src_port: u16, dst_port: u16, payload_len: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(8);
    v.extend_from_slice(&src_port.to_be_bytes());
    v.extend_from_slice(&dst_port.to_be_bytes());
    v.extend_from_slice(&(8u16 + payload_len).to_be_bytes());
    v.extend_from_slice(&0u16.to_be_bytes());
    v
}

fn tcp_header(src_port: u16, dst_port: u16, seq: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(20);
    v.extend_from_slice(&src_port.to_be_bytes());
    v.extend_from_slice(&dst_port.to_be_bytes());
    v.extend_from_slice(&seq.to_be_bytes());
    v.extend_from_slice(&0u32.to_be_bytes()); // ack number
    v.push(0x50); // data offset 5 (20 bytes)
    v.push(0x18); // flags: PSH, ACK
    v.extend_from_slice(&8192u16.to_be_bytes()); // window
    v.extend_from_slice(&0u16.to_be_bytes()); // checksum left unset
    v.extend_from_slice(&0u16.to_be_bytes()); // urgent pointer
    v
}

fn udp_pkt(src_mac: [u8; 6], dst_mac: [u8; 6], src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut pkt = eth_header(dst_mac, src_mac);
    pkt.extend(ipv4_header(src_ip, dst_ip, 17, (8 + payload.len()) as u16));
    pkt.extend(udp_header(src_port, dst_port, payload.len() as u16));
    pkt.extend_from_slice(payload);
    pkt
}

fn tcp_pkt(src_mac: [u8; 6], dst_mac: [u8; 6], src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    let mut pkt = eth_header(dst_mac, src_mac);
    pkt.extend(ipv4_header(src_ip, dst_ip, 6, (20 + payload.len()) as u16));
    pkt.extend(tcp_header(src_port, dst_port, seq));
    pkt.extend_from_slice(payload);
    pkt
}

// ---------------------------------------------------------------------
// pcap (classic libpcap) file writer
// ---------------------------------------------------------------------

fn write_pcap(path: &Path, packets: &[Vec<u8>]) -> std::io::Result<()> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes()); // magic (microsecond, little-endian)
    out.extend_from_slice(&2u16.to_le_bytes()); // version major
    out.extend_from_slice(&4u16.to_le_bytes()); // version minor
    out.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    out.extend_from_slice(&1u32.to_le_bytes()); // linktype: Ethernet

    let base_ts: u32 = 1_735_000_000;
    for (i, pkt) in packets.iter().enumerate() {
        out.extend_from_slice(&(base_ts + i as u32).to_le_bytes()); // ts_sec
        out.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
        out.extend_from_slice(&(pkt.len() as u32).to_le_bytes()); // incl_len
        out.extend_from_slice(&(pkt.len() as u32).to_le_bytes()); // orig_len
        out.extend_from_slice(pkt);
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, out)
}
