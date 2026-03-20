"""
main.py — Entry point for Sentinel IDS.

Wires together: CLI args → config → raw socket → parsers → detectors →
rules engine → alert logger → dashboard.

Usage:
    sudo python3 src/main.py -i eth0
    sudo python3 src/main.py -c config.yaml
    sudo python3 src/main.py -i eth0 -v
"""

import argparse
import os
import sys
import time
import yaml

# codex-platform event bus
sys.path.insert(0, os.path.expanduser('~/codex-workspace/codex-platform'))
try:
    from codex_bus import CodexBus
    _HAS_BUS = True
except ImportError:
    _HAS_BUS = False

# Ensure the project root is on sys.path regardless of cwd
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.capture import create_socket, close_socket
from src.parsers.packet import parse_packet
from src.detection.port_scan import PortScanDetector
from src.detection.syn_flood import SynFloodDetector
from src.detection.arp_spoof import ArpSpoofDetector
from src.rules import load_rules, RulesMatcher
from src.alerts import Alert, AlertLogger, dict_to_alert
from src.dashboard import Dashboard


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def load_config(path: str) -> dict:
    with open(path, 'r') as fh:
        cfg = yaml.safe_load(fh)
    return cfg


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description='Sentinel — Network Intrusion Detection System',
    )
    p.add_argument('-i', '--interface', help='Network interface (e.g. eth0)')
    p.add_argument('-c', '--config', default='config.yaml',
                   help='Path to config.yaml (default: config.yaml)')
    p.add_argument('-v', '--verbose', action='store_true',
                   help='Print raw hex bytes for every packet')
    p.add_argument('--no-dashboard', action='store_true',
                   help='Disable the curses dashboard (plain text output)')
    return p.parse_args()


# ---------------------------------------------------------------------------
# Hex dump helper (used in verbose mode)
# ---------------------------------------------------------------------------

def print_hex(raw: bytes) -> None:
    for i in range(0, len(raw), 16):
        chunk = raw[i:i + 16]
        hex_part   = ' '.join(f'{b:02x}' for b in chunk).ljust(47)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f'  {i:04x}  {hex_part}  {ascii_part}')
    print()


# ---------------------------------------------------------------------------
# Shutdown summary
# ---------------------------------------------------------------------------

def _print_summary(start: float, total: int, alert_count: int) -> None:
    elapsed = time.time() - start
    pps     = total / elapsed if elapsed > 0 else 0
    print(
        f'\n--- Sentinel summary ---\n'
        f'  Duration  : {elapsed:.1f}s\n'
        f'  Packets   : {total:,}\n'
        f'  Rate      : {pps:.1f} pkt/s\n'
        f'  Alerts    : {alert_count}\n'
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args   = parse_args()
    config = load_config(args.config)

    # CLI -i overrides config file
    ifname = args.interface or config.get('interface', 'eth0')

    # --- Build the pipeline ---
    rules_file = config.get('rules_file', 'rules/default.yaml')
    log_file   = config.get('log_file',   'logs/alerts.log')
    cooldown   = float(config.get('alerts', {}).get('dedup_cooldown', 10.0))

    rules   = load_rules(rules_file)
    matcher = RulesMatcher(rules)
    logger  = AlertLogger(log_file, cooldown=cooldown)

    detectors = [
        PortScanDetector(config),
        SynFloodDetector(config),
        ArpSpoofDetector(config),
    ]

    dashboard = Dashboard(config, ifname=ifname)

    # Connect to codex-platform event bus (optional — sentinel works without it)
    bus = None
    if _HAS_BUS:
        try:
            bus = CodexBus(source='sentinel')
            bus.connect()
        except Exception as e:
            print(f'[sentinel] Bus connection failed: {e} — running without bus')
            bus = None

    print(f'[sentinel] Starting on "{ifname}" — Ctrl+C to stop')
    sock = create_socket(ifname)

    if not args.no_dashboard:
        dashboard.start()

    start_time  = time.time()
    total       = 0
    alert_count = 0

    try:
        while True:
            raw_bytes, _ = sock.recvfrom(65535)
            total += 1

            if args.verbose:
                print(f'--- packet #{total} ({len(raw_bytes)} bytes) ---')
                print_hex(raw_bytes)

            # Parse all protocol layers into one dict
            packet = parse_packet(raw_bytes)
            if packet is None:
                continue

            # Run all detectors + rules matcher
            raw_alerts = []
            for detector in detectors:
                raw_alerts.extend(detector.check(packet))
            raw_alerts.extend(matcher.match(packet))

            # Convert, log, and display each alert
            for raw in raw_alerts:
                alert = dict_to_alert(raw)
                if logger.log(alert):
                    alert_count += 1
                    dashboard.add_alert(alert)
                    if bus:
                        bus.publish(alert.to_bus_dict())
                    if args.no_dashboard or args.verbose:
                        print(alert.format_log_line())

            # Update dashboard counters
            dashboard.update(packet)

    except KeyboardInterrupt:
        print('\n[sentinel] Shutting down...')
    finally:
        if bus:
            bus.disconnect()
        dashboard.stop()
        close_socket(sock, ifname)
        _print_summary(start_time, total, alert_count)


if __name__ == '__main__':
    main()
