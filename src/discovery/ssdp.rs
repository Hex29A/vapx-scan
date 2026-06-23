//! SSDP M-SEARCH multicast discovery. Ported from Go `internal/ssdp`.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use crate::discovery::{self, Config};
use crate::model::{self, Device};

const MULTICAST_IP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const MULTICAST_PORT: u16 = 1900;
const SEND_COUNT: usize = 3;
const SEND_DELAY: Duration = Duration::from_millis(200);

/// Builds the M-SEARCH payload. `mx` is the timeout in seconds (1..=3).
fn m_search_request(mx: u32) -> Vec<u8> {
    format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: 239.255.255.250:1900\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: {}\r\n\
         ST: ssdp:all\r\n\
         \r\n",
        mx
    )
    .into_bytes()
}

/// Sends SSDP M-SEARCH on all interfaces and collects responses until the
/// timeout expires.
pub async fn discover(timeout: Duration, verbose: bool) -> Vec<Device> {
    let mx = timeout.as_secs().clamp(1, 3) as u32;

    let cfg = Config {
        group: SocketAddrV4::new(MULTICAST_IP, MULTICAST_PORT),
        payloads: vec![m_search_request(mx)],
        send_count: SEND_COUNT,
        send_delay: SEND_DELAY,
        recv_buf: 4096,
        verbose,
        tag: "ssdp",
    };

    let datagrams = discovery::run(cfg, timeout).await;

    // First response per IP wins.
    let mut seen: BTreeMap<Ipv4Addr, Device> = BTreeMap::new();
    for dg in datagrams {
        if seen.contains_key(&dg.src) {
            continue;
        }
        let (headers, server) = match parse_response(&dg.data) {
            Some(v) => v,
            None => continue,
        };
        let _ = headers;
        let mut d = Device::new(IpAddr::V4(dg.src), "ssdp");
        d.hints.ssdp_server = server;
        seen.insert(dg.src, d);
    }

    let mut devices: Vec<Device> = seen.into_values().collect();
    model::sort_devices(&mut devices);
    devices
}

/// Parses a raw SSDP response. Returns the header map and the `SERVER` value,
/// or `None` if the payload is not an HTTP-style response.
pub fn parse_response(data: &[u8]) -> Option<(Vec<(String, String)>, String)> {
    let text = String::from_utf8_lossy(data);
    let mut lines = text.split("\r\n").flat_map(|l| l.split('\n'));

    let status = lines.next()?;
    if !status.starts_with("HTTP/") {
        return None;
    }

    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    let server = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("server"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();

    Some((headers, server))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_server_header() {
        let raw = b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nSERVER: Linux/4.0 UPnP/1.0 AXIS/1.0\r\n\r\n";
        let (headers, server) = parse_response(raw).unwrap();
        assert_eq!(server, "Linux/4.0 UPnP/1.0 AXIS/1.0");
        assert!(headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("cache-control")));
    }

    #[test]
    fn rejects_non_http() {
        let raw = b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n";
        // First line does not start with HTTP/ -> rejected.
        assert!(parse_response(raw).is_none());
    }

    #[test]
    fn server_case_insensitive() {
        let raw = b"HTTP/1.1 200 OK\r\nServer: AxisThing\r\n\r\n";
        let (_, server) = parse_response(raw).unwrap();
        assert_eq!(server, "AxisThing");
    }
}
