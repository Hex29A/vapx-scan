//! Parses `/proc/net/arp` to build an IP→MAC mapping. Ported from Go
//! `internal/arp`.

use std::collections::HashMap;
use std::net::IpAddr;

/// Default location of the ARP table on Linux.
pub const DEFAULT_PATH: &str = "/proc/net/arp";

/// Maps IP addresses to their MAC (hardware) address (colon-separated, lowercase).
pub type Table = HashMap<IpAddr, String>;

/// Reads and parses the ARP table from the given file path.
pub fn read(path: &str) -> std::io::Result<Table> {
    let content = std::fs::read_to_string(path)?;
    Ok(parse(&content))
}

/// Parses ARP entries from the textual contents of `/proc/net/arp`.
///
/// Format:
/// ```text
/// IP address       HW type     Flags       HW address            Mask     Device
/// 192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
/// ```
pub fn parse(content: &str) -> Table {
    let mut table = Table::new();
    // Skip the header line.
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let ip: IpAddr = match fields[0].parse() {
            Ok(ip) => ip,
            Err(_) => continue,
        };
        let mac = fields[3].to_lowercase();
        // Skip incomplete entries (all zeros).
        if mac == "00:00:00:00:00:00" {
            continue;
        }
        table.insert(ip, mac);
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_entries() {
        let data =
            "IP address       HW type     Flags       HW address            Mask     Device\n\
                    192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n\
                    192.168.1.2      0x1         0x2         B8:A4:4F:11:22:33     *        eth0\n";
        let t = parse(data);
        assert_eq!(t.len(), 2);
        assert_eq!(
            t[&"192.168.1.1".parse::<IpAddr>().unwrap()],
            "aa:bb:cc:dd:ee:ff"
        );
        // lowercased
        assert_eq!(
            t[&"192.168.1.2".parse::<IpAddr>().unwrap()],
            "b8:a4:4f:11:22:33"
        );
    }

    #[test]
    fn skips_incomplete_entries() {
        let data =
            "IP address       HW type     Flags       HW address            Mask     Device\n\
                    192.168.1.5      0x1         0x0         00:00:00:00:00:00     *        eth0\n";
        let t = parse(data);
        assert!(t.is_empty());
    }

    #[test]
    fn skips_malformed_lines() {
        let data = "header\n192.168.1.1 0x1\ngarbage\n";
        let t = parse(data);
        assert!(t.is_empty());
    }
}
