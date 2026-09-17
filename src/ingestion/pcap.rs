//! Minimal reader for the classic libpcap file format (RFC-less but very
//! stable de facto standard used by tcpdump/Wireshark/tshark).
//!
//! Deliberately hand-rolled instead of pulling in a pcap crate: the format
//! is small, fully documented, and reading it directly means this project
//! has zero dependency on a system libpcap install — a plain `.pcap` file
//! on disk is all that's needed, no root and no live capture required.
//!
//! Known limitation: this reads the *classic* pcap format only, not the
//! newer block-based pcapng format. See the README for how to convert.

use anyhow::{bail, Result};

pub struct RawPacket {
    pub timestamp_secs: f64,
    pub data: Vec<u8>,
}

pub struct PcapFile {
    /// libpcap LINKTYPE_* value. 1 = Ethernet, 101 = raw IP.
    pub link_type: u32,
    pub packets: Vec<RawPacket>,
}

const MAGIC_MICRO_LE: u32 = 0xa1b2_c3d4;
const MAGIC_NANO_LE: u32 = 0xa1b2_3c4d;
const MAGIC_MICRO_BE: u32 = 0xd4c3_b2a1;
const MAGIC_NANO_BE: u32 = 0x4d3c_b2a1;

pub fn parse_pcap(bytes: &[u8]) -> Result<PcapFile> {
    if bytes.len() < 24 {
        bail!("file is too small to contain a pcap global header");
    }

    let magic_le = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let (big_endian, nano) = match magic_le {
        MAGIC_MICRO_LE => (false, false),
        MAGIC_NANO_LE => (false, true),
        _ => {
            let magic_be = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
            match magic_be {
                MAGIC_MICRO_BE => (true, false),
                MAGIC_NANO_BE => (true, true),
                _ => bail!(
                    "unrecognized magic number ({:#x}) — this doesn't look like a classic \
                     .pcap file (pcapng is not supported; convert with \
                     `tshark -F pcap -r in.pcapng -w out.pcap`)",
                    magic_le
                ),
            }
        }
    };

    let ru32 = |b: &[u8]| -> u32 {
        if big_endian {
            u32::from_be_bytes(b.try_into().unwrap())
        } else {
            u32::from_le_bytes(b.try_into().unwrap())
        }
    };

    let link_type = ru32(&bytes[20..24]);

    let mut offset = 24usize;
    let mut packets = Vec::new();
    while offset + 16 <= bytes.len() {
        let ts_sec = ru32(&bytes[offset..offset + 4]) as f64;
        let ts_frac = ru32(&bytes[offset + 4..offset + 8]) as f64;
        let incl_len = ru32(&bytes[offset + 8..offset + 12]) as usize;
        offset += 16;

        if offset + incl_len > bytes.len() {
            // Truncated capture — stop gracefully rather than erroring out,
            // so a partially-written pcap still yields whatever was valid.
            break;
        }
        let data = bytes[offset..offset + incl_len].to_vec();
        offset += incl_len;

        let frac_scale = if nano { 1_000_000_000.0 } else { 1_000_000.0 };
        packets.push(RawPacket {
            timestamp_secs: ts_sec + ts_frac / frac_scale,
            data,
        });
    }

    Ok(PcapFile { link_type, packets })
}
