//! Local network utility functions. Ported from Go `internal/netutil`.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

/// Returns the IPv4 subnets of all up, non-loopback network interfaces. For
/// subnets larger than /24 the prefix is narrowed to the /24 around the host's
/// IP to keep scan times practical.
///
/// Note: unlike the Go version, `if-addrs` does not expose carrier (RUNNING)
/// state, so we filter loopback and link-local (169.254/16) addresses instead.
pub fn local_subnets() -> Vec<Ipv4Net> {
    let ifaces = match if_addrs::get_if_addrs() {
        Ok(i) => i,
        Err(_) => return Vec::new(),
    };

    let mut seen: BTreeSet<Ipv4Net> = BTreeSet::new();
    let mut prefixes = Vec::new();

    for iface in ifaces {
        if iface.is_loopback() {
            continue;
        }
        let v4 = match iface.addr {
            if_addrs::IfAddr::V4(v4) => v4,
            _ => continue,
        };
        let ip = v4.ip;
        // Skip link-local addresses.
        if ip.is_link_local() {
            continue;
        }

        let netmask = v4.netmask;
        let prefix_len = netmask_to_prefix(netmask);

        let net = match Ipv4Net::new(ip, prefix_len) {
            Ok(n) => n,
            Err(_) => continue,
        };
        let mut prefix = net.trunc();

        // For subnets larger than /24, narrow to the /24 around the host IP.
        if prefix_len < 24 {
            if let Ok(n) = Ipv4Net::new(ip, 24) {
                prefix = n.trunc();
            }
        }

        if seen.insert(prefix) {
            prefixes.push(prefix);
        }
    }

    prefixes
}

/// Converts a dotted IPv4 netmask to a prefix length (number of leading ones).
fn netmask_to_prefix(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netmask_conversion() {
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 255, 0, 0)), 16);
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 255, 255, 252)), 30);
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(0, 0, 0, 0)), 0);
    }

    #[test]
    fn local_subnets_does_not_panic() {
        // Smoke test: must not panic regardless of host configuration.
        let _ = local_subnets();
    }
}
