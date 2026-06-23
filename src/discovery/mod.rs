//! Shared multicast discovery runner used by SSDP, ONVIF and mDNS.
//!
//! For each up, non-loopback IPv4 interface it opens a UDP socket bound to that
//! interface's address, sends the given payloads to the multicast group
//! (staggered for UDP reliability), and collects every datagram received until
//! the deadline. Per-protocol modules turn the raw datagrams into devices.
//!
//! Note: unlike the Go original (which bound every socket to `:0` and relied on
//! default routing), this binds per-interface and sets the multicast egress
//! interface, which is more correct on multi-homed hosts.

pub mod mdns;
pub mod onvif;
pub mod ssdp;

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::sync::Mutex;
use tokio::time::{timeout_at, Instant};

/// A datagram received during discovery: the sender's IPv4 address and payload.
pub struct Datagram {
    pub src: Ipv4Addr,
    pub data: Vec<u8>,
}

/// Configuration for a multicast discovery round.
pub struct Config {
    pub group: SocketAddrV4,
    pub payloads: Vec<Vec<u8>>,
    pub send_count: usize,
    pub send_delay: Duration,
    pub recv_buf: usize,
    pub verbose: bool,
    pub tag: &'static str,
}

/// Returns up, non-loopback interface IPv4 addresses suitable for multicast.
fn multicast_iface_ips() -> Vec<Ipv4Addr> {
    let mut ips = Vec::new();
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            if iface.is_loopback() {
                continue;
            }
            if let if_addrs::IfAddr::V4(v4) = iface.addr {
                if v4.ip.is_link_local() {
                    continue;
                }
                if !ips.contains(&v4.ip) {
                    ips.push(v4.ip);
                }
            }
        }
    }
    ips
}

fn open_socket(iface_ip: Ipv4Addr) -> std::io::Result<tokio::net::UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    let bind: SocketAddr = SocketAddr::from(SocketAddrV4::new(iface_ip, 0));
    sock.bind(&bind.into())?;
    sock.set_multicast_if_v4(&iface_ip)?;
    sock.set_multicast_ttl_v4(2)?;
    sock.set_nonblocking(true)?;
    let std_sock: std::net::UdpSocket = sock.into();
    tokio::net::UdpSocket::from_std(std_sock)
}

/// Runs a multicast discovery round and returns all datagrams received before
/// the timeout elapses.
pub async fn run(cfg: Config, timeout_dur: Duration) -> Vec<Datagram> {
    let ips = multicast_iface_ips();
    if ips.is_empty() {
        if cfg.verbose {
            eprintln!("[{}] no suitable network interfaces found", cfg.tag);
        }
        return Vec::new();
    }

    let deadline = Instant::now() + timeout_dur;
    let collected: Arc<Mutex<Vec<Datagram>>> = Arc::new(Mutex::new(Vec::new()));
    let cfg = Arc::new(cfg);
    let mut handles = Vec::new();

    for ip in ips {
        let sock = match open_socket(ip) {
            Ok(s) => s,
            Err(e) => {
                if cfg.verbose {
                    eprintln!("[{}] listen on {}: {}", cfg.tag, ip, e);
                }
                continue;
            }
        };
        let cfg = cfg.clone();
        let collected = collected.clone();
        handles.push(tokio::spawn(async move {
            // Send staggered payloads.
            for i in 0..cfg.send_count {
                if Instant::now() >= deadline {
                    break;
                }
                for p in &cfg.payloads {
                    if let Err(e) = sock.send_to(p, cfg.group).await {
                        if cfg.verbose {
                            eprintln!("[{}] send on {}: {}", cfg.tag, ip, e);
                        }
                    }
                }
                if i + 1 < cfg.send_count {
                    tokio::time::sleep(cfg.send_delay).await;
                }
            }

            // Read responses until the deadline.
            let mut buf = vec![0u8; cfg.recv_buf];
            loop {
                match timeout_at(deadline, sock.recv_from(&mut buf)).await {
                    Ok(Ok((n, src))) => {
                        if let SocketAddr::V4(v4) = src {
                            let mut guard = collected.lock().await;
                            guard.push(Datagram {
                                src: *v4.ip(),
                                data: buf[..n].to_vec(),
                            });
                        }
                    }
                    Ok(Err(_)) => break, // socket error
                    Err(_) => break,     // deadline reached
                }
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    Arc::try_unwrap(collected)
        .map(|m| m.into_inner())
        .unwrap_or_default()
}
