//! Core `Device` type and utilities for merging, deduplicating and sorting
//! discovered devices. Ported from Go `internal/model`.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::Serialize;

/// How likely a device is an Axis product.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    #[default]
    None,
    Low,
    Medium,
    High,
}

/// Evidence collected during discovery that feeds into Axis confidence scoring.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Hints {
    #[serde(rename = "serverHeader", skip_serializing_if = "String::is_empty")]
    pub server_header: String,
    #[serde(rename = "ssdpServer", skip_serializing_if = "String::is_empty")]
    pub ssdp_server: String,
    #[serde(rename = "mac", skip_serializing_if = "String::is_empty")]
    pub mac: String,
    #[serde(rename = "bodyMarkers", skip_serializing_if = "Vec::is_empty")]
    pub body_markers: Vec<String>,
    #[serde(rename = "axisCgi", skip_serializing_if = "is_false")]
    pub axis_cgi: bool,
    #[serde(rename = "deviceName", skip_serializing_if = "String::is_empty")]
    pub device_name: String,
    #[serde(rename = "prodNbr", skip_serializing_if = "String::is_empty")]
    pub prod_nbr: String,
    #[serde(rename = "prodType", skip_serializing_if = "String::is_empty")]
    pub prod_type: String,
    #[serde(rename = "serialNumber", skip_serializing_if = "String::is_empty")]
    pub serial_number: String,
    #[serde(rename = "firmware", skip_serializing_if = "String::is_empty")]
    pub firmware: String,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// A single discovered network device.
#[derive(Debug, Clone, Serialize)]
pub struct Device {
    pub ip: IpAddr,
    pub url: String,
    pub methods: Vec<String>,
    #[serde(rename = "openPorts", skip_serializing_if = "Vec::is_empty")]
    pub open_ports: Vec<u16>,
    pub confidence: Confidence,
    pub hints: Hints,
}

impl Device {
    pub fn new(ip: IpAddr, method: &str) -> Self {
        Device {
            ip,
            url: format!("http://{}/", ip),
            methods: vec![method.to_string()],
            open_ports: Vec::new(),
            confidence: Confidence::None,
            hints: Hints::default(),
        }
    }
}

/// Combines multiple device lists, deduplicating by IP. When two devices share
/// the same IP their methods, open ports and hints are merged together. The
/// result is sorted by IP.
pub fn merge_devices(slices: Vec<Vec<Device>>) -> Vec<Device> {
    // BTreeMap keyed by IP keeps deterministic, sorted output.
    let mut map: BTreeMap<IpAddr, Device> = BTreeMap::new();
    for s in slices {
        for d in s {
            match map.get_mut(&d.ip) {
                Some(existing) => merge_into(existing, &d),
                None => {
                    map.insert(d.ip, d);
                }
            }
        }
    }
    map.into_values().collect()
}

/// Folds `src` into `dst`, combining methods, ports and hints.
fn merge_into(dst: &mut Device, src: &Device) {
    dst.methods = unique_strings(&dst.methods, &src.methods);
    dst.open_ports = unique_ints(&dst.open_ports, &src.open_ports);

    let h = &mut dst.hints;
    let s = &src.hints;
    if h.server_header.is_empty() {
        h.server_header = s.server_header.clone();
    }
    if h.ssdp_server.is_empty() {
        h.ssdp_server = s.ssdp_server.clone();
    }
    if h.mac.is_empty() {
        h.mac = s.mac.clone();
    }
    if s.axis_cgi {
        h.axis_cgi = true;
    }
    if h.device_name.is_empty() {
        h.device_name = s.device_name.clone();
    }
    if h.prod_nbr.is_empty() {
        h.prod_nbr = s.prod_nbr.clone();
    }
    if h.prod_type.is_empty() {
        h.prod_type = s.prod_type.clone();
    }
    if h.serial_number.is_empty() {
        h.serial_number = s.serial_number.clone();
    }
    if h.firmware.is_empty() {
        h.firmware = s.firmware.clone();
    }
    h.body_markers = unique_strings(&h.body_markers, &s.body_markers);

    // Keep the higher URL preference (https > http) — only fill if empty.
    if !src.url.is_empty() && dst.url.is_empty() {
        dst.url = src.url.clone();
    }
}

/// Sorts devices by IP address.
pub fn sort_devices(devices: &mut [Device]) {
    devices.sort_by_key(|d| d.ip);
}

fn unique_strings(a: &[String], b: &[String]) -> Vec<String> {
    let mut result: Vec<String> = a.to_vec();
    for s in b {
        if !result.contains(s) {
            result.push(s.clone());
        }
    }
    result
}

fn unique_ints(a: &[u16], b: &[u16]) -> Vec<u16> {
    let mut result: Vec<u16> = a.to_vec();
    for v in b {
        if !result.contains(v) {
            result.push(*v);
        }
    }
    result.sort_unstable();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn merge_dedups_by_ip() {
        let a = Device::new(ip("192.168.1.10"), "ssdp");
        let mut b = Device::new(ip("192.168.1.10"), "onvif");
        b.open_ports = vec![80];
        let merged = merge_devices(vec![vec![a], vec![b]]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].methods, vec!["ssdp", "onvif"]);
        assert_eq!(merged[0].open_ports, vec![80]);
    }

    #[test]
    fn sorts_by_ip() {
        let mut devices = vec![
            Device::new(ip("192.168.1.20"), "x"),
            Device::new(ip("192.168.1.3"), "x"),
            Device::new(ip("10.0.0.1"), "x"),
        ];
        sort_devices(&mut devices);
        let ips: Vec<IpAddr> = devices.iter().map(|d| d.ip).collect();
        assert_eq!(
            ips,
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
            ]
        );
    }

    #[test]
    fn merge_preserves_hints() {
        let mut a = Device::new(ip("10.0.0.5"), "ssdp");
        a.hints.ssdp_server = "AXIS".into();
        let mut b = Device::new(ip("10.0.0.5"), "subnet");
        b.hints.axis_cgi = true;
        b.hints.firmware = "12.6".into();
        let merged = merge_devices(vec![vec![a], vec![b]]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].hints.ssdp_server, "AXIS");
        assert!(merged[0].hints.axis_cgi);
        assert_eq!(merged[0].hints.firmware, "12.6");
    }
}
