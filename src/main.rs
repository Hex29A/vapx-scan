//! vapx-scan discovers Axis devices on the local LAN via SSDP, ONVIF
//! WS-Discovery, mDNS, subnet scanning and `/axis-cgi/` probing.

mod arp;
mod classify;
mod discovery;
mod model;
mod netutil;
mod output;
mod probe;
mod scan;

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use ipnet::Ipv4Net;
use tokio::sync::{Mutex, Semaphore};

use model::{Confidence, Device};

/// Discover Axis devices on the local LAN.
#[derive(Parser, Debug)]
#[command(name = "vapx-scan", version, about)]
struct Args {
    /// Discovery timeout in seconds
    #[arg(long, default_value_t = 3)]
    timeout: u64,

    /// CIDR subnet to scan (e.g. 192.168.1.0/24)
    #[arg(long, default_value = "")]
    subnet: String,

    /// Comma-separated ports for subnet scan
    #[arg(long, default_value = "80,443")]
    ports: String,

    /// Prefer https:// if port 443 is open
    #[arg(long)]
    https: bool,

    /// Show all discovered devices, not just Axis
    #[arg(long)]
    all: bool,

    /// Output as JSON
    #[arg(long)]
    json: bool,

    /// Enable verbose debug logging to stderr
    #[arg(long)]
    verbose: bool,

    /// Max concurrent workers for subnet scan
    #[arg(long, default_value_t = 64)]
    workers: usize,

    /// Skip SSDP discovery
    #[arg(long = "no-ssdp")]
    no_ssdp: bool,

    /// Skip ONVIF WS-Discovery
    #[arg(long = "no-onvif")]
    no_onvif: bool,

    /// Skip mDNS/Bonjour discovery
    #[arg(long = "no-mdns")]
    no_mdns: bool,

    /// Skip /axis-cgi/ probing
    #[arg(long = "no-axis-probe")]
    no_axis_probe: bool,

    /// Skip auto-subnet scanning
    #[arg(long = "no-subnet")]
    no_subnet: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    let ports = match parse_ports(&args.ports) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: invalid --ports: {}", e);
            return ExitCode::from(2);
        }
    };

    let workers = args.workers.clamp(1, 1024);
    let timeout_dur = Duration::from_secs(args.timeout);
    let verbose = args.verbose;

    // --- Run all discovery methods concurrently ---
    let ssdp_fut = async {
        if args.no_ssdp {
            Vec::new()
        } else {
            discovery::ssdp::discover(timeout_dur, verbose).await
        }
    };
    let onvif_fut = async {
        if args.no_onvif {
            Vec::new()
        } else {
            discovery::onvif::discover(timeout_dur, verbose).await
        }
    };
    let mdns_fut = async {
        if args.no_mdns {
            Vec::new()
        } else {
            discovery::mdns::discover(timeout_dur, verbose).await
        }
    };

    // Subnet scan: explicit --subnet, or auto-detected local subnets.
    let explicit_subnet: Option<Ipv4Net> = if args.subnet.is_empty() {
        None
    } else {
        match args.subnet.parse::<Ipv4Net>() {
            Ok(n) => Some(n),
            Err(e) => {
                eprintln!("error: invalid --subnet: {}", e);
                return ExitCode::from(2);
            }
        }
    };
    let ports_for_scan = ports.clone();
    let prefer_https = args.https;
    let no_subnet = args.no_subnet;
    let subnet_fut = async {
        if let Some(net) = explicit_subnet {
            if verbose {
                eprintln!(
                    "starting subnet scan: {} ports={:?} workers={}",
                    net, ports_for_scan, workers
                );
            }
            scan::subnet(net, &ports_for_scan, workers, prefer_https, verbose).await
        } else if !no_subnet {
            let prefixes = netutil::local_subnets();
            if verbose {
                eprintln!(
                    "auto-detected {} local subnet(s) for scanning",
                    prefixes.len()
                );
            }
            let mut all = Vec::new();
            for net in prefixes {
                if verbose {
                    eprintln!(
                        "starting subnet scan: {} ports={:?} workers={}",
                        net, ports_for_scan, workers
                    );
                }
                let mut res =
                    scan::subnet(net, &ports_for_scan, workers, prefer_https, verbose).await;
                all.append(&mut res);
            }
            all
        } else {
            Vec::new()
        }
    };

    let (ssdp_devices, onvif_devices, mdns_devices, subnet_devices) =
        tokio::join!(ssdp_fut, onvif_fut, mdns_fut, subnet_fut);

    if verbose {
        eprintln!(
            "SSDP={} ONVIF={} mDNS={} subnet={}",
            ssdp_devices.len(),
            onvif_devices.len(),
            mdns_devices.len(),
            subnet_devices.len()
        );
    }

    let mut devices = model::merge_devices(vec![
        ssdp_devices,
        onvif_devices,
        mdns_devices,
        subnet_devices,
    ]);

    // Apply HTTPS preference for devices that have port 443 open.
    if args.https {
        for d in devices.iter_mut() {
            if d.open_ports.contains(&443) {
                d.url = format!("https://{}/", d.ip);
            }
        }
    }

    // --- Classify (first pass) ---
    let arp_table = arp::read(arp::DEFAULT_PATH).unwrap_or_else(|e| {
        if verbose {
            eprintln!("ARP table unavailable: {}", e);
        }
        arp::Table::new()
    });
    classify::classify(&mut devices, &arp_table);

    // --- Axis-CGI probe (enabled by default) ---
    if !args.no_axis_probe {
        if verbose {
            eprintln!(
                "probing {} device(s) with /axis-cgi/basicdeviceinfo.cgi",
                devices.len()
            );
        }
        devices = probe_axis_cgi(devices, workers, verbose).await;
        classify::classify(&mut devices, &arp_table);
    }

    // --- Filter (axis-only by default) ---
    if !args.all {
        devices.retain(|d| d.confidence != Confidence::None);
    }

    // --- Output ---
    if devices.is_empty() {
        if verbose {
            eprintln!("no devices found");
        }
        return ExitCode::from(1);
    }

    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let res = if args.json {
        output::json(&mut lock, &devices)
    } else {
        output::plain(&mut lock, &devices)
    };
    if let Err(e) = res {
        eprintln!("error: {}", e);
        return ExitCode::from(2);
    }

    ExitCode::SUCCESS
}

/// Runs `/axis-cgi/basicdeviceinfo.cgi` against all devices with a bounded
/// concurrency limit, enriching them in place.
async fn probe_axis_cgi(devices: Vec<Device>, workers: usize, verbose: bool) -> Vec<Device> {
    let devices = Arc::new(Mutex::new(devices));
    let sem = Arc::new(Semaphore::new(workers));

    // Build the job list: (device index, port).
    let jobs: Vec<(usize, u16)> = {
        let guard = devices.lock().await;
        let mut jobs = Vec::new();
        for (i, d) in guard.iter().enumerate() {
            let target_ports: Vec<u16> = if d.open_ports.is_empty() {
                vec![80]
            } else {
                d.open_ports.clone()
            };
            for p in target_ports {
                jobs.push((i, p));
            }
        }
        jobs
    };

    let mut handles = Vec::with_capacity(jobs.len());
    for (idx, port) in jobs {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let devices = devices.clone();
        let ip = {
            let guard = devices.lock().await;
            guard[idx].ip.to_string()
        };
        handles.push(tokio::spawn(async move {
            let _permit = permit;

            // 1. POST getAllUnrestrictedProperties (newer firmware).
            let info = probe::get_device_info(&ip, port).await;
            if info.is_axis {
                let mut guard = devices.lock().await;
                let d = &mut guard[idx];
                d.hints.axis_cgi = true;
                if !info.prod_full_name.is_empty() && d.hints.device_name.is_empty() {
                    d.hints.device_name = info.prod_full_name.clone();
                }
                if !info.prod_nbr.is_empty() && d.hints.prod_nbr.is_empty() {
                    d.hints.prod_nbr = info.prod_nbr;
                }
                if !info.prod_type.is_empty() && d.hints.prod_type.is_empty() {
                    d.hints.prod_type = info.prod_type;
                }
                if !info.serial_number.is_empty() && d.hints.serial_number.is_empty() {
                    d.hints.serial_number = info.serial_number;
                }
                if !info.firmware.is_empty() && d.hints.firmware.is_empty() {
                    d.hints.firmware = info.firmware.clone();
                }
                if verbose {
                    eprintln!(
                        "[axis-cgi] {}:{} POST ok: {} (fw:{} s/n:{})",
                        ip, port, info.prod_full_name, info.firmware, d.hints.serial_number
                    );
                }
                return;
            }

            // 2. GET fallback for legacy detection.
            let result = probe::axis_cgi(&ip, port).await;
            if result.is_axis {
                let mut guard = devices.lock().await;
                guard[idx].hints.axis_cgi = true;
                if verbose {
                    eprintln!(
                        "[axis-cgi] {}:{} GET confirmed Axis (status={})",
                        ip, port, result.status_code
                    );
                }
            }

            // 3. /webapp/index.shtml for the device name if still missing.
            let need_name = {
                let guard = devices.lock().await;
                guard[idx].hints.device_name.is_empty()
            };
            if need_name {
                let title = probe::webapp_title(&ip, port).await;
                if !title.is_empty() {
                    let mut guard = devices.lock().await;
                    if guard[idx].hints.device_name.is_empty() {
                        guard[idx].hints.device_name = title.clone();
                        if verbose {
                            eprintln!("[webapp] {}:{} title={:?}", ip, port, title);
                        }
                    }
                }
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    Arc::try_unwrap(devices)
        .map(|m| m.into_inner())
        .unwrap_or_default()
}

/// Parses a comma-separated port list, deduplicating and sorting. Rejects
/// out-of-range or non-numeric entries.
fn parse_ports(csv: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for part in csv.split(',') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        let n: u32 = p.parse().map_err(|_| format!("invalid port: {:?}", p))?;
        if !(1..=65535).contains(&n) {
            return Err(format!("invalid port: {:?}", p));
        }
        let n = n as u16;
        if !ports.contains(&n) {
            ports.push(n);
        }
    }
    if ports.is_empty() {
        return Err("no valid ports specified".to_string());
    }
    ports.sort_unstable();
    Ok(ports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ports_dedup_sort() {
        assert_eq!(parse_ports("80,443").unwrap(), vec![80, 443]);
        assert_eq!(parse_ports("443,80,80").unwrap(), vec![80, 443]);
        assert_eq!(parse_ports(" 8080 , 80 ").unwrap(), vec![80, 8080]);
    }

    #[test]
    fn parse_ports_rejects_invalid() {
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("70000").is_err());
        assert!(parse_ports("abc").is_err());
        assert!(parse_ports("").is_err());
    }
}
