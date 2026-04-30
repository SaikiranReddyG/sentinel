# Sentinel

Sentinel is a packet-level network intrusion detection system built on raw AF_PACKET sockets. It parses Ethernet, IPv4, TCP, UDP, and ARP frames directly, applies stateful detectors and YAML rules, and emits codex-contract events for lifecycle and alert streams.

## Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .

# Run with the curses dashboard
sudo sentinel run -i eth0

# Or use the legacy entry point directly
sudo python3 src/main.py -i eth0 --no-dashboard

# Run tests
python3 -m pytest tests/ -v
```

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
    ├→ Event output (stdout, file, or HTTP POST)
    └→ Dashboard (live curses UI)
```

## Configuration

Edit `config.yaml` to control the capture interface, detector thresholds, log file path, dashboard refresh rate, and alert deduplication cooldown. `SENTINEL_CONFIG` can point to an alternate config file, and `SENTINEL_INTERFACE` overrides the interface name at runtime.

## Integration

The runtime event contract is documented in [CONTRACT.md](CONTRACT.md). That file describes the event schema, the three event types Sentinel emits in v0.1, severity levels, and the supported output destinations.

## Testing

```bash
python3 -m pytest tests/ -v
```

The tests use hand-crafted byte sequences and cover the protocol parsers, detectors, alert deduplication, rules matching, and event schema helpers.

## License

Sentinel is released under the MIT License. See [LICENSE](LICENSE).