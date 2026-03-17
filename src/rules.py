"""
rules.py — YAML-driven rules engine.

Loads rules from a YAML file, maintains per-rule rate counters (same sliding
window used by the detection engines), and matches incoming parsed packets
against rule conditions.

Rule YAML schema:
  - name: str
    protocol: tcp | udp          (required)
    src_port: int                (optional — match source port)
    dst_port: int                (optional — match destination port)
    threshold:
      count:    int              (number of matching packets before alert)
      window:   int  seconds     (sliding window duration)
      group_by: src_ip | dst_ip  (key to group counts by)
    severity: low | medium | high | critical
    message: str                 (Python str.format_map template, keys below)

Message template keys:
    {src_ip}, {dst_ip}, {src_port}, {dst_port}, {count}, {window}
"""

import time
import yaml
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Rule:
    name     : str
    protocol : str                     # 'tcp' or 'udp'
    severity : str
    message  : str
    src_port : Optional[int] = None
    dst_port : Optional[int] = None
    threshold_count  : int   = 1
    threshold_window : int   = 60
    threshold_group  : str   = 'src_ip'


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_rules(path: str) -> list:
    """Parse *path* YAML and return a list of Rule objects."""
    with open(path, 'r') as fh:
        data = yaml.safe_load(fh)

    rules = []
    for entry in data.get('rules', []):
        thresh = entry.get('threshold', {})
        rules.append(Rule(
            name             = entry['name'],
            protocol         = entry['protocol'].lower(),
            severity         = entry.get('severity', 'medium'),
            message          = entry.get('message', entry['name']),
            src_port         = entry.get('src_port'),
            dst_port         = entry.get('dst_port'),
            threshold_count  = int(thresh.get('count',    1)),
            threshold_window = int(thresh.get('window',  60)),
            threshold_group  = thresh.get('group_by', 'src_ip'),
        ))
    return rules


# ---------------------------------------------------------------------------
# Matcher
# ---------------------------------------------------------------------------

class RulesMatcher:
    """
    Matches parsed packet dicts against a list of Rule objects.

    Each rule maintains its own per-group rate counters:
        _counters[rule_name][group_key] = {'count': int, 'window_start': float}

    Parameters
    ----------
    rules : list[Rule]
    """

    def __init__(self, rules: list) -> None:
        self._rules    = rules
        self._counters: dict = {r.name: {} for r in rules}

    def match(self, packet: dict) -> list:
        """
        Check *packet* against all rules.

        Returns
        -------
        List of alert dicts for every rule whose  threshold was crossed.
        """
        alerts = []
        proto  = packet.get('proto', '').upper()  # 'TCP', 'UDP', etc.
        now    = time.time()

        for rule in self._rules:
            if rule.protocol.upper() != proto:
                continue

            if not self._port_matches(rule, packet):
                continue

            # Determine grouping key value
            group_val = packet.get(
                'ip_src' if rule.threshold_group == 'src_ip' else 'ip_dst',
                'unknown'
            )

            counter = self._counters[rule.name].get(group_val)
            if counter is None or now > counter['window_start'] + rule.threshold_window:
                self._counters[rule.name][group_val] = {
                    'count'       : 1,
                    'window_start': now,
                }
                counter = self._counters[rule.name][group_val]
            else:
                counter['count'] += 1

            if counter['count'] == rule.threshold_count:
                # Fire exactly once per window crossing
                alerts.append(self._make_alert(rule, packet, counter))

        return alerts

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _port_matches(rule: Rule, packet: dict) -> bool:
        if rule.protocol == 'tcp':
            sp = packet.get('tcp_src_port')
            dp = packet.get('tcp_dst_port')
        else:  # udp
            sp = packet.get('udp_src_port')
            dp = packet.get('udp_dst_port')

        if rule.src_port is not None and sp != rule.src_port:
            return False
        if rule.dst_port is not None and dp != rule.dst_port:
            return False
        return True

    @staticmethod
    def _make_alert(rule: Rule, packet: dict, counter: dict) -> dict:
        src_ip   = packet.get('ip_src', '?')
        dst_ip   = packet.get('ip_dst', '?')
        src_port = packet.get('tcp_src_port') or packet.get('udp_src_port', '?')
        dst_port = packet.get('tcp_dst_port') or packet.get('udp_dst_port', '?')

        try:
            msg = rule.message.format_map({
                'src_ip'  : src_ip,
                'dst_ip'  : dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'count'   : counter['count'],
                'window'  : rule.threshold_window,
            })
        except (KeyError, ValueError):
            msg = rule.name

        return {
            'detection_type': 'RULE:' + rule.name,
            'severity'      : rule.severity,
            'src_ip'        : src_ip,
            'dst_ip'        : dst_ip,
            'message'       : msg,
        }
