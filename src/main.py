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
import importlib
import os
import sys
import time
import yaml

# Ensure the project root is on sys.path regardless of cwd
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def _load_dotenv(path: str) -> None:
    """Load simple KEY=VALUE pairs from a local .env file if present."""
    if not os.path.isfile(path):
        return
    with open(path, 'r', encoding='utf-8') as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


# Load optional local environment overrides from sentinel/.env.
_ENV_FILE = os.path.join(_ROOT, '.env')
_load_dotenv(_ENV_FILE)

# codex-platform event bus import path (env override + portable default)
_DEFAULT_CODEX_PLATFORM_PATH = os.path.normpath(os.path.join(_ROOT, '..', 'codex-platform'))
_CODEX_PLATFORM_PATH = os.getenv('CODEX_PLATFORM_PATH', _DEFAULT_CODEX_PLATFORM_PATH)
if not os.path.isabs(_CODEX_PLATFORM_PATH):
    _CODEX_PLATFORM_PATH = os.path.normpath(os.path.join(_ROOT, _CODEX_PLATFORM_PATH))

_HAS_BUS = False
_BUS_DISABLED_REASON = None
CodexBus = None
if os.path.isdir(_CODEX_PLATFORM_PATH):
    if _CODEX_PLATFORM_PATH not in sys.path:
        sys.path.insert(0, _CODEX_PLATFORM_PATH)
    try:
        CodexBus = importlib.import_module('codex_bus').CodexBus
        _HAS_BUS = True
    except Exception as e:
        _BUS_DISABLED_REASON = f'codex_bus import failed: {e}'
else:
    _BUS_DISABLED_REASON = f'codex-platform path not found: {_CODEX_PLATFORM_PATH}'

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
    default_config = os.getenv('SENTINEL_CONFIG', 'config.yaml')
    p = argparse.ArgumentParser(
        description='Sentinel — Network Intrusion Detection System',
    )
    p.add_argument('-i', '--interface', help='Network interface (e.g. eth0)')
    p.add_argument('-c', '--config', default=default_config,
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
    ifname = args.interface or os.getenv('SENTINEL_INTERFACE') or config.get('interface', 'eth0')

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
    if not _HAS_BUS and _BUS_DISABLED_REASON:
        print(f'[sentinel] Bus disabled: {_BUS_DISABLED_REASON}')
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
                        bus.publish_alert(alert.to_bus_dict())
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
