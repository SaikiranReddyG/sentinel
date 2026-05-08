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
import errno
import os
import sys
import time
import yaml

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
from src.events import emit_event, set_output
from src.output import make_output

def load_config(path: str) -> dict:
    with open(path, 'r') as fh:
        cfg = yaml.safe_load(fh)
    return cfg



def print_hex(raw: bytes) -> None:
    for i in range(0, len(raw), 16):
        chunk = raw[i:i + 16]
        hex_part   = ' '.join(f'{b:02x}' for b in chunk).ljust(47)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f'  {i:04x}  {hex_part}  {ascii_part}')
    print()
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
def run_sentinel(
    interface=None,
    config_path='config.yaml',
    verbose=False,
    no_dashboard=False,
    output_spec='stdout',
    output_url=None,
    output_file=None,
) -> None:
    """
    Run the Sentinel IDS pipeline.
    
    Args:
        interface: Network interface name (e.g., 'eth0'). Overrides config file.
        config_path: Path to config.yaml file.
        verbose: Print raw hex bytes for every packet.
        no_dashboard: Disable the curses dashboard (plain text output).
    """
    set_output(make_output(output_spec, url=output_url, path=output_file))

    cfg = load_config(config_path)

    # CLI interface overrides config file
    ifname = interface or os.getenv('SENTINEL_INTERFACE') or cfg.get('interface', 'eth0')

    # --- Build the pipeline ---
    rules_file = cfg.get('rules_file', 'rules/default.yaml')
    log_file   = cfg.get('log_file',   'logs/alerts.log')
    cooldown   = float(cfg.get('alerts', {}).get('dedup_cooldown', 10.0))

    rules   = load_rules(rules_file)
    matcher = RulesMatcher(rules)
    logger  = AlertLogger(log_file, cooldown=cooldown)

    detectors = [
        PortScanDetector(cfg),
        SynFloodDetector(cfg),
        ArpSpoofDetector(cfg),
    ]

    dashboard = Dashboard(cfg, ifname=ifname)

    print(f'[sentinel] Starting on "{ifname}" — Ctrl+C to stop')
    sock = None
    lifecycle_started_emitted = False

    if not no_dashboard:
        dashboard.start()

    start_time  = time.time()
    total       = 0
    alert_count = 0

    recoverable_errnos = {
        errno.ENETDOWN,
        errno.ENODEV,
        errno.ENXIO,
        100,  # ENETUNREACH — network interface deleted/recreated (bridge teardown)
    }

    try:
        while True:
            if sock is None:
                try:
                    sock = create_socket(ifname)
                    print(f'[sentinel] Socket bound to "{ifname}"')
                    if not lifecycle_started_emitted:
                        emit_event(
                            'sentinel.lifecycle.started',
                            'info',
                            {
                                'interface': ifname,
                                'pid': os.getpid(),
                            },
                        )
                        lifecycle_started_emitted = True
                except OSError as e:
                    if e.errno in recoverable_errnos:
                        print(f'[sentinel] Interface "{ifname}" unavailable ({e}); retrying in 5s...')
                        time.sleep(5)
                        continue
                    raise

            try:
                raw_bytes, _ = sock.recvfrom(65535)
            except OSError as e:
                if e.errno in recoverable_errnos:
                    print(f'[sentinel] Interface "{ifname}" lost ({e}); reconnecting in 5s...')
                    close_socket(sock, ifname)
                    sock = None
                    time.sleep(5)
                    continue
                raise

            total += 1

            if verbose:
                print(f'--- packet #{total} ({len(raw_bytes)} bytes) ---')
                print_hex(raw_bytes)

            packet = parse_packet(raw_bytes)
            if packet is None:
                continue

            raw_alerts = []
            for detector in detectors:
                raw_alerts.extend(detector.check(packet))
            raw_alerts.extend(matcher.match(packet))

            for raw in raw_alerts:
                alert = dict_to_alert(raw)
                if logger.log(alert):
                    alert_count += 1
                    dashboard.add_alert(alert)
                    emit_event(
                        'sentinel.alert',
                        alert.severity,
                        alert.to_bus_dict(),
                    )
                    if no_dashboard or verbose:
                        print(alert.format_log_line())

            dashboard.update(packet)

    except KeyboardInterrupt:
        print('\n[sentinel] Shutting down...')
    finally:
        try:
            emit_event(
                'sentinel.lifecycle.stopped',
                'info',
                {
                    'interface': ifname,
                    'pid': os.getpid(),
                    'packets': total,
                    'alerts': alert_count,
                },
            )
        except Exception:
            pass
        try:
            dashboard.stop()
        except Exception:
            pass
        try:
            if sock is not None:
                close_socket(sock, ifname)
        except Exception:
            pass
        try:
            _print_summary(start_time, total, alert_count)
        except Exception:
            pass


if __name__ == '__main__':
    # Backward-compat argparse shim: parse CLI args and call run_sentinel()
    default_config = os.getenv('SENTINEL_CONFIG', 'config.yaml')
    parser = argparse.ArgumentParser(
        description='Sentinel — Network Intrusion Detection System',
    )
    parser.add_argument('-i', '--interface', help='Network interface (e.g. eth0)')
    parser.add_argument('-c', '--config', default=default_config,
                        help='Path to config.yaml (default: config.yaml)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Print raw hex bytes for every packet')
    parser.add_argument('--no-dashboard', action='store_true',
                        help='Disable the curses dashboard (plain text output)')
    parser.add_argument('--output', choices=['stdout', 'file', 'http_post'],
                        default='stdout', help='Where to emit codex-contract events')
    parser.add_argument('--output-url', default=None,
                        help='URL for http_post output')
    parser.add_argument('--output-file', default=None,
                        help='File path for file output')
    args = parser.parse_args()

    run_sentinel(
        interface=args.interface,
        config_path=args.config,
        verbose=args.verbose,
        no_dashboard=args.no_dashboard,
        output_spec=args.output,
        output_url=args.output_url,
        output_file=args.output_file,
    )
