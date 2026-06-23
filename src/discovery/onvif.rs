//! ONVIF WS-Discovery for finding cameras. Ported from Go `internal/onvif`.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use crate::discovery::{self, Config};
use crate::model::{self, Device};

const MULTICAST_IP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const MULTICAST_PORT: u16 = 3702;
const SEND_COUNT: usize = 2;
const SEND_DELAY: Duration = Duration::from_millis(200);

/// WS-Discovery Probe targeting ONVIF network video transmitters (cameras).
const PROBE_MESSAGE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
               xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"
               xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof"
               xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <soap:Header>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
    <wsa:MessageID>urn:uuid:vapx-scan-probe-00000001</wsa:MessageID>
    <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
  </soap:Header>
  <soap:Body>
    <wsd:Probe>
      <wsd:Types>dn:NetworkVideoTransmitter</wsd:Types>
    </wsd:Probe>
  </soap:Body>
</soap:Envelope>"#;

/// Sends a WS-Discovery Probe for ONVIF devices and collects responses until
/// the timeout expires.
pub async fn discover(timeout: Duration, verbose: bool) -> Vec<Device> {
    let cfg = Config {
        group: SocketAddrV4::new(MULTICAST_IP, MULTICAST_PORT),
        payloads: vec![PROBE_MESSAGE.as_bytes().to_vec()],
        send_count: SEND_COUNT,
        send_delay: SEND_DELAY,
        recv_buf: 8192,
        verbose,
        tag: "onvif",
    };

    let datagrams = discovery::run(cfg, timeout).await;

    let mut seen: BTreeMap<Ipv4Addr, Device> = BTreeMap::new();
    for dg in datagrams {
        if seen.contains_key(&dg.src) {
            continue;
        }
        let body = String::from_utf8_lossy(&dg.data);
        let mut d = Device::new(IpAddr::V4(dg.src), "onvif");
        d.hints.body_markers = extract_onvif_markers(&body);
        seen.insert(dg.src, d);
    }

    let mut devices: Vec<Device> = seen.into_values().collect();
    model::sort_devices(&mut devices);
    devices
}

/// Pulls useful Axis-related strings from WS-Discovery ProbeMatch responses.
fn extract_onvif_markers(body: &str) -> Vec<String> {
    let mut markers = Vec::new();
    if body.to_uppercase().contains("AXIS") {
        markers.push("onvif:AXIS".to_string());
    }
    if body.contains("NetworkVideoTransmitter") {
        markers.push("onvif:NetworkVideoTransmitter".to_string());
    }
    markers
}

/// Parses XAddrs from a WS-Discovery ProbeMatch response.
#[cfg_attr(not(test), allow(dead_code))]
pub fn extract_xaddrs(body: &str) -> Vec<String> {
    const OPEN: &str = "<XAddrs>";
    const CLOSE: &str = "</XAddrs>";

    let lower = body.to_lowercase();
    let start_idx = match body.find(OPEN).or_else(|| lower.find(&OPEN.to_lowercase())) {
        Some(i) => i,
        None => return Vec::new(),
    };
    let start = start_idx + OPEN.len();
    let rest = &body[start..];
    let rest_lower = &lower[start..];
    let end = match rest
        .find(CLOSE)
        .or_else(|| rest_lower.find(&CLOSE.to_lowercase()))
    {
        Some(e) => e,
        None => return Vec::new(),
    };
    rest[..end]
        .split_whitespace()
        .map(|s| s.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markers_detect_axis_and_nvt() {
        let body = "<probe>AXIS something NetworkVideoTransmitter</probe>";
        let m = extract_onvif_markers(body);
        assert!(m.contains(&"onvif:AXIS".to_string()));
        assert!(m.contains(&"onvif:NetworkVideoTransmitter".to_string()));
    }

    #[test]
    fn xaddrs_extracted() {
        let body = "<d><XAddrs>http://192.168.1.10/onvif/device http://10.0.0.1/onvif</XAddrs></d>";
        let x = extract_xaddrs(body);
        assert_eq!(
            x,
            vec!["http://192.168.1.10/onvif/device", "http://10.0.0.1/onvif"]
        );
    }

    #[test]
    fn xaddrs_absent() {
        assert!(extract_xaddrs("<d></d>").is_empty());
    }
}
