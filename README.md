# promapper

**Production-grade cross-platform network scanner** — Linux, macOS, Windows, Android Termux.

```bash
pip install promapper
promapper scanme.nmap.org -p 22,80 --banner
```

## Features

| Category | Capabilities |
|----------|-------------|
| **Scan Techniques** | TCP Connect, SYN stealth, UDP, FIN, NULL, Xmas, ACK, Window, Maimon, Idle |
| **OS Detection** | TTL/window fingerprinting (13 signatures) |
| **Service Detection** | Banner grabbing, SSL/TLS cert inspection, SSH key extraction |
| **Web Analysis** | 22 tech patterns, 15 WAF signatures, directory brute-force, API discovery |
| **Network Intel** | GeoIP (city-level), ASN/ISP, WHOIS, Shodan, MAC vendor lookup |
| **Cloud/CDN** | AWS, Azure, GCP, Cloudflare, Akamai, Fastly, 20+ providers |
| **Security** | CVE version matching, honeypot detection, brute-force (SSH/FTP/HTTP/Telnet) |
| **Output** | Terminal (box-drawing), JSON, XML, CSV (injection-safe), grepable, HTML |
| **Monitoring** | Continuous scans, diff detection, desktop notifications |
| **Cross-platform** | Linux, macOS, Windows, Termux |

## Super Command

One command to install PROMAPPER **and all dependencies** on any device:

```bash
bash <(curl -s https://raw.githubusercontent.com/ArjunV110/ProMapper/master/install.sh)
```

Auto-detects your OS, installs system packages (Python, traceroute, whois, etc.), and all optional Python dependencies (scapy, cryptography, paramiko, dnspython). Works on Linux, macOS, Windows (Git Bash), and Android Termux.

---

## Installation

### From Source (recommended)

```bash
git clone https://github.com/ArjunV110/ProMapper.git
cd ProMapper
pip install -e .
```

### Direct (no install)

```bash
git clone https://github.com/ArjunV110/ProMapper.git
cd ProMapper
promapper scanme.nmap.org
```

### Optional Dependencies

```bash
pip install promapper[full]       # All extras
pip install promapper[scapy]      # SYN/FIN/NULL/Xmas/ACK/Window/Maimon scans
pip install promapper[crypto]     # SSL certificate fingerprints
pip install promapper[paramiko]   # SSH brute-force
pip install promapper[dnspython]  # Custom DNS resolver
```

## Usage

```
promapper <target> [options]
```

### Target Specification

| Argument | Description |
|----------|-------------|
| `target` | IP address, hostname, CIDR (e.g. `192.168.1.0/24`), or file |
| `-iL FILE` | Read targets from file |
| `-p PORTS` | Port range (e.g. `22,80,443` or `1-1024`) |
| `--exclude-ports PORTS` | Ports to exclude |

### Scan Techniques

| Flag | Scan Type | Requires |
|------|-----------|----------|
| (default) | TCP Connect | None |
| `-sU` | UDP | None |
| `-sS` | SYN stealth | scapy |
| `-sF` | FIN | scapy |
| `-sN` | NULL | scapy |
| `-sX` | Xmas | scapy |
| `-sA` | ACK | scapy |
| `-sW` | Window | scapy |
| `-sM` | Maimon | scapy |
| `--idle-scan ZOMBIE` | Idle scan | scapy |

### Detection

| Flag | Description |
|------|-------------|
| `-sV` | Service version detection |
| `-O` | OS fingerprinting |
| `--banner` | Banner grabbing |
| `--ssl-cert` | SSL/TLS certificate inspection |
| `--http-tech` | HTTP technology detection |
| `--dir-bust [WORDLIST]` | Directory brute-force |
| `--api-discovery` | API endpoint discovery |
| `--subdomain-enum [WORDLIST]` | Subdomain enumeration |
| `--detect-waf` | WAF detection |
| `--detect-cdn` | CDN detection |
| `--detect-cloud` | Cloud provider detection |
| `--detect-honeypot` | Honeypot detection |
| `--cve` | CVE checking |
| `--ssh-key` | SSH host key extraction |
| `--traceroute` | Traceroute |
| `--brute ssh,ftp,http,telnet` | Brute-force |

### Information Gathering

| Flag | Description |
|------|-------------|
| `--geo` | Geolocation lookup |
| `--asn` | ASN/ISP/ORG lookup |
| `--whois` | WHOIS lookup |
| `--shodan` | Shodan query (set `SHODAN_API_KEY`) |
| `--mac-vendor` | MAC vendor lookup |

### Output

| Flag | Format |
|------|--------|
| (default) | Terminal (colored box-drawing) |
| `-oJ FILE` | JSON |
| `-oX FILE` | XML |
| `-oN FILE` | Normal (terminal) |
| `-oC FILE` | CSV (injection-safe) |
| `-oG FILE` | Grepable |
| `--html FILE` | HTML report |
| `-v` | Verbose |

### Performance

| Flag | Description |
|------|-------------|
| `-T 0-5` | Timing template (0=paranoid, 3=normal, 5=insane) |
| `--threads N` | Max threads (default 100) |
| `--timeout SEC` | Socket timeout (default 2.0s) |
| `--rate-limit N` | Packets per second |
| `--random-delay MIN,MAX` | Random delay range |

## Architecture

```
promapper/
├── promapper.py          ← Entry point
├── pyproject.toml        ← Package config (pip install)
├── README.md
├── LICENSE               ← MIT
└── promapper/            ← Python package
    ├── __init__.py       ← Package metadata
    ├── __main__.py       ← python -m promapper
    ├── cli.py            ← CLI, argparse, main loop
    ├── config.py         ← Immutable ScanConfig, constants
    ├── datatypes.py      ← PortResult, HostResult
    ├── scanner.py        ← Core engine (ports, ping, traceroute, banner, SSL)
    ├── detection.py      ← OS, WAF, CDN, cloud, honeypot, CVE, HTTP tech
    ├── lookup.py         ← Geo, WHOIS, Shodan, MAC vendor
    ├── brute.py          ← Brute force (SSH, FTP, HTTP, Telnet)
    ├── formatters.py     ← 6 output formats
    ├── state.py          ← State persistence, diff, notifications
    └── orchestrator.py   ← scan_host pipeline (20 stages)
```

## Output Example

```
  ┌─ Host Overview ──────────────────────────────────────────────────────┐
  │ Hostname             scanme.nmap.org                                 │
  │ IP Address           45.33.32.156                                    │
  │ Reverse DNS          scanme.nmap.org                                 │
  │ Latency              234.6 ms                                        │
  └──────────────────────────────────────────────────────────────────────┘

  ┌─ Open Ports ─────────────────────────────────────────────────────────┐
  │ PORT    PROTO  STATE         SERVICE                VERSION          │
  │ ────    ─────  ──────────    ────────────────────   ──────────────   │
  │ 22      TCP    open          ssh                                     │
  │ 80      TCP    open          http                                    │
  └──────────────────────────────────────────────────────────────────────┘
    Banner (22/tcp): SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
    Banner (80/tcp): HTTP/1.1 200 OK  (Server: Apache/2.4.7)
```

## License

MIT
