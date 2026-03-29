# Sentinel — Network Intrusion Detection System

A packet-level IDS built from raw sockets in Python. No libraries for packet capture or parsing — just the kernel, `struct.unpack()`, and custom byte-level logic.

## Features

- **Raw AF_PACKET sockets** — captures all Ethernet frames on the wire (Linux only, requires root/CAP_NET_RAW)
- **Protocol parsers** — byte-for-byte parsing of Ethernet, IPv4, TCP, UDP, ARP headers
- **Detection engines**:
  - **Port Scan Detector** — identifies SYN, FIN, NULL, and XMAS scans by unique destination port counting
  - **SYN Flood Detector** — rate-based detection of SYN packet floods
  - **ARP Spoof Detector** — ARP cache poisoning detection via MAC-change identification
- **YAML rules engine** — customizable rules for protocol-level thresholds (SSH brute force, DNS amplification, HTTP floods, etc.)
- **Structured logging** — append-mode alert log with deduplication
- **Live curses dashboard** — real-time TUI showing packet stats, top talkers, and color-coded alert feed

## Quick Start

```bash
# Install dependencies
pip install pyyaml

# Run with live dashboard
sudo python3 src/main.py -i eth0

# Run in verbose mode (hex + alerts)
sudo python3 src/main.py -i eth0 -v

# Run without dashboard (plain text output)
sudo python3 src/main.py -i eth0 --no-dashboard

# Run tests (no root required)
pip install pytest
python3 -m pytest tests/ -v
```

### Optional: local .env overrides

Use environment overrides for machine-specific values (for example local paths)
without hardcoding them in source.

```bash
cp .env.example .env
# Edit .env for your machine
```

Supported variables:
- `CODEX_PLATFORM_PATH` (default `../codex-platform`)
- `SENTINEL_CONFIG` (default `config.yaml`)
- `SENTINEL_INTERFACE` (default from config, fallback `eth0`)

## Architecture

```
Packet capture (AF_PACKET socket)
    ↓
parse_packet() dispatcher
    ├→ Ethernet parser
    ├→ IPv4 parser
    └→ TCP/UDP/ARP parsers
    ↓
Detection pipeline (parallel)
    ├→ PortScanDetector (sliding window + scan classification)
    ├→ SynFloodDetector (rate-based counting)
    ├→ ArpSpoofDetector (ARP cache tracking)
    └→ RulesMatcher (YAML-driven thresholds)
    ↓
Alert system
    ├→ AlertLogger (file append + dedup)
    └→ Dashboard (live curses UI)
```

## File Structure

| Component | Files | Purpose |
|-----------|-------|---------|
| Capture | `src/capture.py` | AF_PACKET socket setup + promiscuous mode |
| Parsers | `src/parsers/*.py` | Byte-level protocol parsing |
| Detectors | `src/detection/*.py` | Stateful intrusion detection |
| Rules | `src/rules.py` | YAML rule loader + threshold matching |
| Alerts | `src/alerts.py` | Logging + deduplication |
| Dashboard | `src/dashboard.py` | curses terminal UI |
| Entry point | `src/main.py` | CLI + pipeline orchestration |
| Tests | `tests/test_parsers.py` | 47 unit tests (hand-crafted bytes, no network) |
| Config | `config.yaml` | Runtime thresholds + paths |
| Rules | `rules/default.yaml` | 11 built-in detection rules |

## Implementation Status

✅ **Phase 1** — Project scaffold + raw socket capture  
✅ **Phase 2** — Protocol parsers (Ethernet, IPv4, TCP, UDP, ARP)  
✅ **Phase 3** — Detection engines (port scan, SYN flood, ARP spoof)  
✅ **Phase 4** — YAML rules engine + structured alerts  
✅ **Phase 5** — Live curses dashboard  
✅ **Phase 6** — Full pipeline integration  
✅ **Phase 7** — Unit tests (47/47 passing)

## Testing

All tests use hand-crafted byte sequences — no live network traffic or root required.

```bash
python3 -m pytest tests/ -v

# Expected output: 47 passed in 0.2s
```

Tests cover:
- Ethernet, IPv4, TCP, UDP, ARP header parsing
- Unified packet dispatcher
- All three detection engines
- Alert logger with deduplication
- YAML rules engine

## Configuration

Edit `config.yaml` to customize:
- Network interface
- Detection thresholds (port scan window, SYN flood rate, etc.)
- Log file path
- Dashboard refresh rate
- Alert deduplication cooldown

## Design Notes

- **No scapy** — built to learn packet internals; all parsing is explicit `struct.unpack()`
- **Linux only** — `AF_PACKET` is a Linux kernel feature
- **In-memory state** — detection state is ephemeral; no persistence across restarts
- **Stateful** — sliding windows and rate counters enable sophisticated detection patterns
- **Extensible** — add new YAML rules or write new detector classes easily

## License

Learning project. Use freely for educational purposes.