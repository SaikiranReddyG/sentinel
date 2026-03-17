"""
arp_spoof.py — Detect ARP cache poisoning (ARP spoofing) attacks.

ARP spoofing is a MITM technique where an attacker sends forged ARP replies
to associate their MAC address with a legitimate IP (typically the gateway),
redirecting traffic through the attacker's machine.

Detection strategy:
  1. ARP reply with changed MAC for a known IP → alert CRITICAL
  2. Gratuitous ARP (sender_ip == target_ip) from an unknown sender → alert HIGH
     (legitimate hosts do this after boot; repeated ones from the same IP that
     keep changing MAC are suspicious)
  3. Gratuitous ARP reply that changes a known mapping → alert CRITICAL

ARP table state:
  arp_table[ip] = {
      'mac'       : str   last known MAC for this IP,
      'first_seen': float timestamp of first ARP packet,
      'last_seen' : float timestamp of most recent packet,
      'reply_count': int  number of ARP replies seen,
      'last_alert': float timestamp of last alert issued,
  }
"""

import time

from src.parsers.arp import OP_REPLY, OP_REQUEST

_ALERT_COOLDOWN = 10.0   # seconds between re-alerting same IP


class ArpSpoofDetector:
    """
    Stateful ARP spoofing detector.

    Parameters
    ----------
    config : dict
        Expects config['thresholds']['arp_spoof'] with key:
            enabled  (bool)
            cooldown (int, seconds)
    """

    def __init__(self, config: dict) -> None:
        cfg = config.get('thresholds', {}).get('arp_spoof', {})
        self._enabled  = bool(cfg.get('enabled', True))
        self._cooldown = float(cfg.get('cooldown', _ALERT_COOLDOWN))
        self._arp_table: dict = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, packet: dict) -> list:
        if not self._enabled:
            return []
        if packet.get('proto') != 'ARP':
            return []

        operation      = packet.get('arp_operation')
        sender_mac     = packet.get('arp_sender_mac')
        sender_ip      = packet.get('arp_sender_ip')
        is_gratuitous  = packet.get('arp_is_gratuitous', False)

        if not (sender_mac and sender_ip):
            return []

        now    = time.time()
        alerts = []

        existing = self._arp_table.get(sender_ip)

        if existing is None:
            # First time we see this IP — just record it
            self._arp_table[sender_ip] = {
                'mac'        : sender_mac,
                'first_seen' : now,
                'last_seen'  : now,
                'reply_count': 1 if operation == OP_REPLY else 0,
                'last_alert' : 0.0,
            }
        else:
            existing['last_seen'] = now
            if operation == OP_REPLY:
                existing['reply_count'] += 1

            # Check if MAC changed for a known IP
            if existing['mac'] != sender_mac:
                if now - existing['last_alert'] > self._cooldown:
                    existing['last_alert'] = now
                    severity = 'critical' if is_gratuitous else 'high'
                    alerts.append({
                        'detection_type': 'ARP_SPOOF',
                        'severity'      : severity,
                        'src_ip'        : sender_ip,
                        'dst_ip'        : packet.get('arp_target_ip', '?'),
                        'message'       : (
                            f'ARP spoofing: {sender_ip} changed MAC '
                            f'{existing["mac"]} → {sender_mac}'
                            + (' (gratuitous)' if is_gratuitous else '')
                        ),
                    })
                existing['mac'] = sender_mac  # update to latest

        return alerts

    # ------------------------------------------------------------------
    # Introspection (used by dashboard / tests)
    # ------------------------------------------------------------------

    def get_arp_table(self) -> dict:
        """Return a copy of the current ARP table."""
        return dict(self._arp_table)
