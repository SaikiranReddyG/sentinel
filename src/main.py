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

# Ensure the project root is on sys.path regardless of cwd
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.capture import create_socket, close_socket


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
    return p.parse_args()


# ---------------------------------------------------------------------------
# Hex dump helper (used in verbose mode)
# ---------------------------------------------------------------------------

def print_hex(raw: bytes) -> None:
    for i in range(0, len(raw), 16):
        chunk = raw[i:i + 16]
        hex_part  = ' '.join(f'{b:02x}' for b in chunk).ljust(47)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f'  {i:04x}  {hex_part}  {ascii_part}')
    print()


# ---------------------------------------------------------------------------
# Packet stats (Phase 1 skeleton — replaced in Phase 6)
# ---------------------------------------------------------------------------

def _print_summary(stats: dict) -> None:
    elapsed = time.time() - stats['start']
    total   = stats['total']
    pps     = total / elapsed if elapsed > 0 else 0
    print(
        f'\n--- Sentinel summary ---\n'
        f'  Duration  : {elapsed:.1f}s\n'
        f'  Packets   : {total}\n'
        f'  Rate      : {pps:.1f} pkt/s\n'
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args   = parse_args()
    config = load_config(args.config)

    # CLI -i overrides config file
    ifname = args.interface or config.get('interface', 'eth0')

    print(f'[sentinel] Starting on interface "{ifname}" — Ctrl+C to stop')
    sock = create_socket(ifname)

    stats = {'total': 0, 'start': time.time()}

    try:
        while True:
            raw_bytes, _ = sock.recvfrom(65535)
            stats['total'] += 1

            if args.verbose:
                print(f'--- packet #{stats["total"]} ({len(raw_bytes)} bytes) ---')
                print_hex(raw_bytes)

    except KeyboardInterrupt:
        print('\n[sentinel] Shutting down...')
    finally:
        close_socket(sock, ifname)
        _print_summary(stats)


if __name__ == '__main__':
    main()
