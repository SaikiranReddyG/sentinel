"""
syn_flood.py — Detect SYN flood attacks by counting SYN-only packets per
source IP within a sliding time window.

A SYN flood is a Denial-of-Service technique where the attacker sends a
massive volume of TCP SYN packets (connection initiation) without completing
the three-way handshake, exhausting server connection state tables.

Detection logic:
  - Count SYN-only packets (SYN flag set, ACK flag clear) per source IP.
  - Use a fixed window: reset when now > window_start + window_size.
  - Alert if count / elapsed_seconds > rate_threshold.
  - After alerting, continue to re-alert on every subsequent packet
    during the same window so the dashboard feed shows the flood is active,
    but apply a per-source cooldown to avoid log spam.

State:
  syn_counts[src_ip] = {
      'count'       : int   SYN packets seen in current window,
      'window_start': float timestamp of window start,
      'last_alert'  : float timestamp of last alert issued,
  }
"""

import time

from src.parsers.tcp import SYN, ACK


_ALERT_COOLDOWN = 5.0   # seconds between consecutive alerts for same source


class SynFloodDetector:
    """
    Stateful SYN flood detector.

    Parameters
    ----------
    config : dict
        Expects config['thresholds']['syn_flood'] with keys:
            rate   (int) — SYN packets per second threshold
            window (int) — counting window size in seconds
    """

    def __init__(self, config: dict) -> None:
        cfg = config.get('thresholds', {}).get('syn_flood', {})
        self._rate   = int(cfg.get('rate',    100))
        self._window = int(cfg.get('window',    5))
        self._counts: dict = {}

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

        flags = packet.get('tcp_flags', 0)

        # SYN-only: SYN set, ACK clear
        if not (flags & SYN) or (flags & ACK):
            return []

        src_ip = packet.get('ip_src')
        if not src_ip:
            return []

        now = time.time()
        state = self._counts.get(src_ip)

        if state is None or now > state['window_start'] + self._window:
            # Start a fresh window
            self._counts[src_ip] = {
                'count'       : 1,
                'window_start': now,
                'last_alert'  : 0.0,
            }
            return []

        state['count'] += 1
        elapsed = now - state['window_start']

        # Need at least `rate` packets AND measurable elapsed time before
        # computing rate — avoids false positives from burst scheduling
        if state['count'] < self._rate or elapsed <= 0:
            return []

        current_rate = state['count'] / elapsed

        if (current_rate > self._rate
                and now - state['last_alert'] > _ALERT_COOLDOWN):
            state['last_alert'] = now
            return [self._make_alert(src_ip, state, packet, current_rate, elapsed)]

        return []

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    @staticmethod
    def _make_alert(src_ip, state, packet, rate, elapsed) -> dict:
        return {
            'detection_type': 'SYN_FLOOD',
            'severity'      : 'critical',
            'src_ip'        : src_ip,
            'dst_ip'        : packet.get('ip_dst', '?'),
            'message'       : (
                f'SYN flood from {src_ip} — '
                f'{state["count"]} SYNs in {elapsed:.1f}s '
                f'({rate:.0f}/s, threshold {state["count"] // max(int(elapsed), 1)}/s)'
            ),
        }
