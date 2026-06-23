//! mDNS/Bonjour service discovery for Axis devices. Queries for
//! `_axis-video._tcp.local` and `_axis-nvr._tcp.local` on 224.0.0.251:5353.
//! Ported from Go `internal/mdns`.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use crate::discovery::{self, Config};
use crate::model::{self, Device};

const MULTICAST_IP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MULTICAST_PORT: u16 = 5353;
const SEND_COUNT: usize = 2;
const SEND_DELAY: Duration = Duration::from_millis(200);

const AXIS_SERVICES: &[&str] = &["_axis-video._tcp.local", "_axis-nvr._tcp.local"];

/// Sends mDNS PTR queries for Axis-specific services and collects responses
/// until the timeout expires.
pub async fn discover(timeout: Duration, verbose: bool) -> Vec<Device> {
    let payloads: Vec<Vec<u8>> = AXIS_SERVICES
        .iter()
        .filter_map(|svc| build_mdns_query(svc))
        .collect();

    let cfg = Config {
        group: SocketAddrV4::new(MULTICAST_IP, MULTICAST_PORT),
        payloads,
        send_count: SEND_COUNT,
        send_delay: SEND_DELAY,
        recv_buf: 4096,
        verbose,
        tag: "mdns",
    };

    let datagrams = discovery::run(cfg, timeout).await;

    // Merge markers across multiple packets from the same IP.
    let mut seen: BTreeMap<Ipv4Addr, Vec<String>> = BTreeMap::new();
    for dg in datagrams {
        let markers = parse_mdns_response(&dg.data);
        if markers.is_empty() {
            continue;
        }
        let entry = seen.entry(dg.src).or_default();
        for m in markers {
            if !entry.contains(&m) {
                entry.push(m);
            }
        }
    }

    let mut devices: Vec<Device> = seen
        .into_iter()
        .map(|(ip, markers)| {
            let mut d = Device::new(IpAddr::V4(ip), "mdns");
            d.hints.body_markers = markers;
            d
        })
        .collect();
    model::sort_devices(&mut devices);
    devices
}

/// Constructs a minimal DNS query packet for a PTR record of the given service.
fn build_mdns_query(service: &str) -> Option<Vec<u8>> {
    // DNS header: ID=0, flags=0 (standard query), QDCOUNT=1.
    let header: [u8; 12] = [
        0x00, 0x00, // Transaction ID
        0x00, 0x00, // Flags
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs
        0x00, 0x00, // Authority RRs
        0x00, 0x00, // Additional RRs
    ];
    let qname = encode_dns_name(service)?;
    // QTYPE=PTR (12), QCLASS=IN (1).
    let suffix: [u8; 4] = [0x00, 0x0c, 0x00, 0x01];

    let mut pkt = Vec::with_capacity(header.len() + qname.len() + suffix.len());
    pkt.extend_from_slice(&header);
    pkt.extend_from_slice(&qname);
    pkt.extend_from_slice(&suffix);
    Some(pkt)
}

/// Converts a dot-separated name to DNS wire format.
fn encode_dns_name(name: &str) -> Option<Vec<u8>> {
    let name = name.strip_suffix('.').unwrap_or(name);
    let mut buf = Vec::new();
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0x00); // Root label.
    Some(buf)
}

/// Extracts Axis-related markers from an mDNS response packet.
fn parse_mdns_response(data: &[u8]) -> Vec<String> {
    if data.len() < 12 {
        return Vec::new();
    }
    // Check QR bit (response).
    let flags = u16::from_be_bytes([data[2], data[3]]);
    if flags & 0x8000 == 0 {
        return Vec::new();
    }

    let body = String::from_utf8_lossy(data).to_lowercase();
    let mut markers = Vec::new();
    if body.contains("_axis-video") {
        markers.push("mdns:axis-video".to_string());
    }
    if body.contains("_axis-nvr") {
        markers.push("mdns:axis-nvr".to_string());
    }
    if body.contains("axis") && markers.is_empty() {
        markers.push("mdns:axis".to_string());
    }
    markers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_name_wire_format() {
        let buf = encode_dns_name("_axis-video._tcp.local").unwrap();
        // first label "_axis-video" length 11
        assert_eq!(buf[0], 11);
        assert_eq!(&buf[1..12], b"_axis-video");
        assert_eq!(*buf.last().unwrap(), 0x00);
    }

    #[test]
    fn query_packet_has_header_and_question() {
        let pkt = build_mdns_query("_axis-nvr._tcp.local").unwrap();
        assert_eq!(&pkt[0..2], &[0x00, 0x00]); // ID
        assert_eq!(&pkt[4..6], &[0x00, 0x01]); // QDCOUNT
        assert_eq!(&pkt[pkt.len() - 4..], &[0x00, 0x0c, 0x00, 0x01]); // PTR/IN
    }

    #[test]
    fn parse_response_requires_qr_bit() {
        // header with QR set (0x8000) and "_axis-video" in body
        let mut data = vec![0u8; 12];
        data[2] = 0x84; // QR=1, AA=1
        data.extend_from_slice(b"_axis-video._tcp.local");
        let m = parse_mdns_response(&data);
        assert_eq!(m, vec!["mdns:axis-video".to_string()]);
    }

    #[test]
    fn parse_response_rejects_query() {
        let mut data = vec![0u8; 12]; // flags=0 => not a response
        data.extend_from_slice(b"_axis-video");
        assert!(parse_mdns_response(&data).is_empty());
    }
}
