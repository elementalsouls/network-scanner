# Network Scanner

[![CI](https://github.com/your-org/network-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/network-scanner/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A powerful, cross-platform network scanning tool written in Python. Supports host discovery, port scanning, service detection, OS fingerprinting, MAC vendor lookup, continuous monitoring, and a web dashboard.

---

## Features

- 🔍 **Host Discovery** – ICMP ping, TCP ping, ARP scan (via scapy)
- 🔌 **Port Scanning** – TCP connect, SYN scan, UDP scan with async engine
- 🧠 **Service Detection** – Banner grabbing and regex fingerprinting
- 💻 **OS Detection** – TTL-based and TCP fingerprinting
- 🏭 **MAC Vendor Lookup** – Embedded OUI database with 50+ entries
- 📊 **Multiple Output Formats** – Console (rich), JSON, CSV, XML, HTML report
- 🌐 **Web Dashboard** – Flask-based UI with REST API
- 📡 **Continuous Monitoring** – Background watcher with alerts on network changes
- 📂 **Scan History** – SQLite-backed persistence

---

## Quick Start

### Installation

```bash
pip install -r requirements.txt
pip install -e .
```

### Basic Usage

```bash
# Scan a single host
network-scanner scan 192.168.1.1

# Scan a subnet
network-scanner scan 192.168.1.0/24

# Scan with a profile
network-scanner scan 192.168.1.0/24 --profile service

# Scan specific ports
network-scanner scan 10.0.0.1 --ports 22,80,443,8080-8090

# Export results as HTML
network-scanner scan 192.168.1.0/24 --format html --output report.html
```

### Scan Profiles

| Profile   | Description                              |
|-----------|------------------------------------------|
| `quick`   | Top 100 ports, fast connect scan         |
| `full`    | All 65535 ports + service/OS detection   |
| `stealth` | SYN scan with rate limiting (needs root) |
| `service` | Top 1000 ports + service/OS detection    |

### Web Dashboard

```bash
network-scanner web --port 8080
# Open http://localhost:8080
```

### Continuous Monitoring

```bash
network-scanner monitor 192.168.1.0/24 --interval 300
```

### Scan History

```bash
network-scanner history
network-scanner export <scan-id> --format html --output report.html
```

---

## CLI Reference

```
Usage: network-scanner [OPTIONS] COMMAND [ARGS]...

Commands:
  scan     Scan a target for open ports and services
  monitor  Continuously monitor a target for changes
  web      Start the web dashboard
  history  Show scan history
  export   Export a scan result to file
```

---

## REST API

| Method | Endpoint                  | Description                  |
|--------|---------------------------|------------------------------|
| GET    | `/api/health`             | Health check                 |
| GET    | `/api/scans`              | List all scans               |
| GET    | `/api/scans/<id>`         | Get scan by ID               |
| DELETE | `/api/scans/<id>`         | Delete a scan                |
| POST   | `/api/scan`               | Start a new scan             |
| GET    | `/api/scan/<id>/status`   | Get scan status              |
| GET    | `/api/stats`              | Aggregate statistics         |
| GET    | `/api/profiles`           | List available profiles      |

### POST /api/scan

```json
{
  "target": "192.168.1.0/24",
  "ports": "top100",
  "scan_type": "connect",
  "timeout": 3.0,
  "max_threads": 100,
  "service_detection": false,
  "os_detection": false,
  "profile": "quick"
}
```

---

## Development

```bash
# Install dev dependencies
make install-dev

# Run tests
make test

# Lint
make lint

# Format
make format

# Docker
make docker-build
make docker-up
```

---

## Output Formats

- **console** – Rich terminal tables (default)
- **json** – Machine-readable JSON
- **csv** – Spreadsheet-compatible CSV
- **xml** – nmap-compatible XML
- **html** – Standalone HTML report with charts

---

## Architecture

```
scanner/
├── cli.py              # Click CLI entry point
├── config/             # Constants, settings, profiles
├── core/               # Scan engine, discovery, port/service/OS scanning
├── models/             # Data models (Host, Port, ScanResult, ScanProfile)
├── monitoring/         # History (SQLite), alerts, network watcher
├── output/             # JSON, CSV, XML, HTML, console formatters
└── web/                # Flask app, REST API, templates, static assets
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.