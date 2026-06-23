//! CIDR subnet scanning with a bounded worker pool. Ported from Go
//! `internal/scan`.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use ipnet::Ipv4Net;
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::model::{self, Device};
use crate::probe;

/// Per-port TCP connect timeout.
const TCP_TIMEOUT: Duration = Duration::from_millis(400);

/// Expands a CIDR prefix into all host IPs, skipping the network and broadcast
/// addresses for prefixes shorter than /31. For /31 both addresses are
/// returned; for /32 the single address. Matches Go `ExpandCIDR` semantics
/// (which is exactly `ipnet`'s `hosts()` behavior).
pub fn expand_cidr(net: Ipv4Net) -> Vec<Ipv4Addr> {
    net.hosts().collect()
}

/// Scans all IPs in the given CIDR prefix, probing the specified ports with a
/// bounded worker pool of `workers` tasks.
pub async fn subnet(
    net: Ipv4Net,
    ports: &[u16],
    workers: usize,
    prefer_https: bool,
    verbose: bool,
) -> Vec<Device> {
    let ips = expand_cidr(net);
    if ips.is_empty() {
        return Vec::new();
    }
    if verbose {
        eprintln!(
            "[scan] scanning {} IPs × {} ports ({} workers)",
            ips.len(),
            ports.len(),
            workers
        );
    }

    // Work queue.
    let (tx, rx) = mpsc::channel::<(Ipv4Addr, u16)>(workers * 2);
    let ports_vec = ports.to_vec();
    let feeder = tokio::spawn(async move {
        for ip in ips {
            for &port in &ports_vec {
                if tx.send((ip, port)).await.is_err() {
                    return;
                }
            }
        }
    });

    // Shared receiver across workers.
    let rx = std::sync::Arc::new(tokio::sync::Mutex::new(rx));
    let (res_tx, mut res_rx) = mpsc::channel::<(Ipv4Addr, u16, probe::HttpResult)>(workers * 2);

    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let rx = rx.clone();
        let res_tx = res_tx.clone();
        handles.push(tokio::spawn(async move {
            loop {
                let job = {
                    let mut guard = rx.lock().await;
                    guard.recv().await
                };
                let (ip, port) = match job {
                    Some(j) => j,
                    None => return,
                };
                let addr = SocketAddr::new(IpAddr::V4(ip), port);
                // TCP connect check.
                match timeout(TCP_TIMEOUT, tokio::net::TcpStream::connect(addr)).await {
                    Ok(Ok(stream)) => {
                        drop(stream);
                        if verbose {
                            eprintln!("[scan] {}:{} open", ip, port);
                        }
                        let pr = probe::http(&ip.to_string(), port).await;
                        let _ = res_tx.send((ip, port, pr)).await;
                    }
                    _ => continue,
                }
            }
        }));
    }
    drop(res_tx);

    // Aggregate by IP.
    let mut device_map: BTreeMap<Ipv4Addr, Device> = BTreeMap::new();
    while let Some((ip, port, pr)) = res_rx.recv().await {
        let d = device_map.entry(ip).or_insert_with(|| {
            let mut dev = Device::new(IpAddr::V4(ip), "subnet");
            dev.url = format!("http://{}/", ip);
            dev
        });
        if !d.open_ports.contains(&port) {
            d.open_ports.push(port);
        }
        if !pr.server_header.is_empty() && d.hints.server_header.is_empty() {
            d.hints.server_header = pr.server_header;
        }
        if !pr.title.is_empty() && d.hints.device_name.is_empty() {
            d.hints.device_name = pr.title;
        }
        for m in pr.body_markers {
            if !d.hints.body_markers.contains(&m) {
                d.hints.body_markers.push(m);
            }
        }
    }

    let _ = feeder.await;
    for h in handles {
        let _ = h.await;
    }

    // Apply HTTPS preference.
    if prefer_https {
        for d in device_map.values_mut() {
            if d.open_ports.contains(&443) {
                d.url = format!("https://{}/", d.ip);
            }
        }
    }

    let mut devices: Vec<Device> = device_map.into_values().collect();
    model::sort_devices(&mut devices);
    devices
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> Ipv4Net {
        s.parse().unwrap()
    }

    #[test]
    fn slash_24_skips_network_and_broadcast() {
        let ips = expand_cidr(net("192.168.1.0/24"));
        assert_eq!(ips.len(), 254);
        assert_eq!(ips[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(ips[ips.len() - 1], Ipv4Addr::new(192, 168, 1, 254));
    }

    #[test]
    fn slash_31_returns_both() {
        let ips = expand_cidr(net("10.0.0.4/31"));
        assert_eq!(
            ips,
            vec![Ipv4Addr::new(10, 0, 0, 4), Ipv4Addr::new(10, 0, 0, 5)]
        );
    }

    #[test]
    fn slash_32_returns_single() {
        let ips = expand_cidr(net("10.0.0.5/32"));
        assert_eq!(ips, vec![Ipv4Addr::new(10, 0, 0, 5)]);
    }

    #[test]
    fn slash_30_has_two_hosts() {
        let ips = expand_cidr(net("172.16.0.0/30"));
        assert_eq!(
            ips,
            vec![Ipv4Addr::new(172, 16, 0, 1), Ipv4Addr::new(172, 16, 0, 2)]
        );
    }
}
