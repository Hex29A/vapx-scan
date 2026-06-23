# vapx-scan

A fast CLI tool to discover Axis network devices on the local LAN — a Rust port
of [axiscan](https://github.com/Hex29A/axiscan).

Combines multiple discovery methods — SSDP, ONVIF WS-Discovery, mDNS, and TCP
subnet scanning — to find Axis cameras, radars, I/O controllers, and other
devices. Queries the VAPIX `basicdeviceinfo.cgi` API to extract product names,
firmware versions, and serial numbers without requiring authentication.

Ships as a single statically-linked binary with no runtime dependencies.

## Usage

```
vapx-scan [flags]
```

Running without flags discovers Axis devices on all local subnets:

```
$ vapx-scan
URL                    PRODUCT                           FIRMWARE   SERIAL
─────────────────────  ────────────────────────────────  ─────────  ────────────
http://192.168.7.10/   AXIS Q1615 Mk III Network Camera  12.6.104   B8A44F230E2A
http://192.168.7.16/   AXIS Q1647 Network Camera         11.11.181  ACCC8E98AD9B
http://192.168.7.70/   AXIS D2123-VE Radar               12.8.54    E8272513046C
http://192.168.7.155/  AXIS IO Manager                   —          ac:cc:8e:d1:36:8b
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--timeout` | `3` | Discovery timeout in seconds |
| `--subnet` | (auto) | CIDR to scan, e.g. `192.168.1.0/24` |
| `--ports` | `80,443` | Ports to probe during subnet scan |
| `--https` | off | Prefer `https://` URLs when port 443 is open |
| `--all` | off | Show all discovered devices, not just Axis |
| `--json` | off | Structured JSON output |
| `--verbose` | off | Debug logging to stderr |
| `--workers` | `64` | Max concurrent subnet scan workers |
| `--no-ssdp` | off | Skip SSDP discovery |
| `--no-onvif` | off | Skip ONVIF WS-Discovery |
| `--no-mdns` | off | Skip mDNS/Bonjour discovery |
| `--no-subnet` | off | Skip auto-subnet scanning |
| `--no-axis-probe` | off | Skip `/axis-cgi/` probing |

### Examples

Scan a specific subnet with verbose output:

```
vapx-scan --subnet 10.0.0.0/24 --verbose
```

JSON output for scripting:

```
vapx-scan --json | jq '.[].hints.deviceName'
```

Show all devices including non-Axis:

```
vapx-scan --all
```

## How it works

1. **SSDP** — sends M-SEARCH to `239.255.255.250:1900` on all interfaces
2. **ONVIF WS-Discovery** — sends SOAP Probe to `239.255.255.250:3702`
3. **mDNS** — queries `_axis-video._tcp.local` and `_axis-nvr._tcp.local`
4. **Subnet scan** — TCP connects to ports 80/443 on the local subnets, then HTTP-probes open ports
5. **VAPIX probe** — POSTs to `/axis-cgi/basicdeviceinfo.cgi` with `getAllUnrestrictedProperties` to get product name, firmware, and serial number without auth
6. **Classification** — scores each device using SSDP headers, HTTP headers, mDNS services, MAC OUI, and axis-cgi responses

All methods run in parallel. Results are deduplicated by IP and sorted.

> **Note on multicast:** unlike the Go original (which bound discovery sockets
> to `:0` and relied on default routing), vapx-scan binds a socket per
> interface and sets `IP_MULTICAST_IF`, making discovery more reliable on
> multi-homed hosts.

## Building

Requires a stable Rust toolchain.

```
make build     # debug build for the host
make release   # optimized host build
make static    # statically-linked musl binary in dist/
make test      # run tests
```

The `static` target produces a fully static `x86_64-unknown-linux-musl` binary
that runs on any Linux host without runtime dependencies.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Devices found |
| 1 | No devices found |
| 2 | Error (bad flags, etc.) |

## License

MIT
