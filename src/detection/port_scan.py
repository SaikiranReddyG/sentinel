"""
port_scan.py — Detect port scans by tracking unique destination ports per
source IP within a configurable sliding time window.

Scan types detected (identified by TCP flag pattern):
  SYN scan  : flags == SYN  (0x02)  — most common scanner output (nmap -sS)
  FIN scan  : flags == FIN  (0x01)  — RFC 793 closed ports reply with RST
  NULL scan : flags == 0x00         — no flags at all
  XMAS scan : flags == FIN|PSH|URG  (0x29) — "lit up like a Christmas tree"

State machine:
  connections[src_ip] = {
      'ports'     : set of dst_ports seen,
      'first_seen': timestamp of first packet,
      'last_seen' : timestamp of most recent packet,
      'scan_type' : the detected scan type string,
      'alerted'   : True once an alert has been issued (no duplicate alerts
                    until the window expires and a new scan starts),
  }
"""

import time
from typing import Optional

from src.parsers.tcp import SYN, FIN, PSH, URG


class PortScanDetector:
    """
    Stateful port scan detector.

    Parameters
    ----------
    config : dict
        Expects config['thresholds']['port_scan'] with keys:
            ports  (int) — unique port threshold before alerting
            window (int) — time window in seconds
    """

    def __init__(self, config: dict) -> None:
        cfg = config.get('thresholds', {}).get('port_scan', {})
        self._threshold = int(cfg.get('ports',  15))
        self._window    = int(cfg.get('window', 60))
        self._connections: dict = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, packet: dict) -> list:
        """
        Inspect *packet* and return a list of alert dicts (empty if nothing
        suspicious was found).
        """
        if packet.get('proto') != 'TCP':
            return []

        src_ip  = packet.get('ip_src')
        dst_port = packet.get('tcp_dst_port')
        flags    = packet.get('tcp_flags', 0)

        if not src_ip or dst_port is None:
            return []

        # Only track scan-indicative flag patterns; ignore ACK / data packets
        scan = self._classify_scan(flags)
        if scan is None:
            return []

        now = time.time()
        self._evict_stale(now)

        state = self._connections.setdefault(src_ip, {
            'ports'     : set(),
            'first_seen': now,
            'last_seen' : now,
            'scan_type' : scan,
            'alerted'   : False,
        })

        state['ports'].add(dst_port)
        state['last_seen'] = now
        # Update scan type with whatever we see (keeps the latest)
        state['scan_type'] = scan

        if not state['alerted'] and len(state['ports']) >= self._threshold:
            state['alerted'] = True
            return [self._make_alert(src_ip, state, packet)]

        return []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _classify_scan(flags: int) -> Optional[str]:
        if flags == SYN:
            return 'SYN'
        if flags == FIN:
            return 'FIN'
        if flags == 0x00:
            return 'NULL'
        if flags == (FIN | PSH | URG):
            return 'XMAS'
        return None  # not a scan-indicative pattern

    def _evict_stale(self, now: float) -> None:
        """Remove connection entries whose time window has expired."""
        expired = [
            ip for ip, st in self._connections.items()
            if now - st['first_seen'] > self._window
        ]
        for ip in expired:
            del self._connections[ip]

    @staticmethod
    def _make_alert(src_ip: str, state: dict, packet: dict) -> dict:
        return {
            'detection_type': 'PORT_SCAN',
            'severity'      : 'high',
            'src_ip'        : src_ip,
            'dst_ip'        : packet.get('ip_dst', '?'),
            'message'       : (
                f'{state["scan_type"]} scan from {src_ip} — '
                f'{len(state["ports"])} unique ports probed'
            ),
        }
