//! Scores devices for Axis confidence based on collected hints. Ported from
//! Go `internal/classify`.

use crate::arp::Table;
use crate::model::{Confidence, Device};

/// Known Axis Communications OUI prefixes (colon-separated, lowercase).
const AXIS_OUIS: &[&str] = &[
    "00:40:8c", "ac:cc:8e", "b8:a4:4f", "d4:81:d7", "e4:3a:6e", "00:1a:07", "5c:f9:6a",
];

/// Sets the `confidence` field on each device based on accumulated hints,
/// enriching MAC information from the ARP table where available.
pub fn classify(devices: &mut [Device], arp_table: &Table) {
    for d in devices.iter_mut() {
        // Enrich MAC from ARP table if not already set.
        if d.hints.mac.is_empty() {
            if let Some(mac) = arp_table.get(&d.ip) {
                d.hints.mac = mac.clone();
            }
        }

        let mut score = 0;

        if contains_ci(&d.hints.ssdp_server, "axis") {
            score += 1;
        }
        if contains_ci(&d.hints.server_header, "axis") {
            score += 1;
        }
        if !d.hints.body_markers.is_empty() {
            score += 1;
        }
        if !d.hints.mac.is_empty() && is_axis_oui(&d.hints.mac) {
            score += 1;
        }
        if d.hints.axis_cgi {
            score += 2; // Definitive signal — strong weight.
        }

        d.confidence = match score {
            s if s >= 3 => Confidence::High,
            2 => Confidence::Medium,
            1 => Confidence::Low,
            _ => Confidence::None,
        };
    }
}

fn contains_ci(s: &str, substr: &str) -> bool {
    s.to_lowercase().contains(&substr.to_lowercase())
}

fn is_axis_oui(mac: &str) -> bool {
    let mac = mac.to_lowercase();
    AXIS_OUIS.iter().any(|oui| mac.starts_with(oui))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arp::Table;
    use std::net::IpAddr;

    fn dev(ip: &str) -> Device {
        Device::new(ip.parse::<IpAddr>().unwrap(), "test")
    }

    #[test]
    fn axis_cgi_scores_high_alone_with_one_more() {
        let mut d = dev("10.0.0.1");
        d.hints.axis_cgi = true;
        d.hints.body_markers = vec!["AXIS".into()]; // +1, axis_cgi +2 => 3 = high
        let mut v = vec![d];
        classify(&mut v, &Table::new());
        assert_eq!(v[0].confidence, Confidence::High);
    }

    #[test]
    fn single_hint_is_low() {
        let mut d = dev("10.0.0.2");
        d.hints.ssdp_server = "AXIS/1.0".into();
        let mut v = vec![d];
        classify(&mut v, &Table::new());
        assert_eq!(v[0].confidence, Confidence::Low);
    }

    #[test]
    fn no_hints_is_none() {
        let mut v = vec![dev("10.0.0.3")];
        classify(&mut v, &Table::new());
        assert_eq!(v[0].confidence, Confidence::None);
    }

    #[test]
    fn oui_from_arp_counts() {
        let mut table = Table::new();
        table.insert("10.0.0.4".parse().unwrap(), "b8:a4:4f:00:11:22".into());
        let mut v = vec![dev("10.0.0.4")];
        classify(&mut v, &table);
        // OUI match = 1 hint => low
        assert_eq!(v[0].confidence, Confidence::Low);
        assert_eq!(v[0].hints.mac, "b8:a4:4f:00:11:22");
    }

    #[test]
    fn two_hints_medium() {
        let mut d = dev("10.0.0.5");
        d.hints.ssdp_server = "AXIS".into();
        d.hints.server_header = "Axis/2".into();
        let mut v = vec![d];
        classify(&mut v, &Table::new());
        assert_eq!(v[0].confidence, Confidence::Medium);
    }
}
