"""
alerts.py — Alert data model, structured log writer, and deduplication.

Alert format logged to disk:
  [2026-03-17 14:32:07] CRITICAL | SYN_FLOOD | 10.0.0.5 → 192.168.1.10 | message

Severity levels (lowest → highest):
  low  medium  high  critical

Deduplication:
  The same (src_ip, detection_type) pair is suppressed for `cooldown` seconds
  after the last alert was logged, preventing log spam during an active attack.
"""

import os
import time
from dataclasses import dataclass, field


# Map severity strings to a sortable integer for comparisons / coloring
SEVERITY_ORDER = {
    'low'     : 0,
    'medium'  : 1,
    'high'    : 2,
    'critical': 3,
}


@dataclass
class Alert:
    detection_type: str
    severity      : str
    src_ip        : str
    dst_ip        : str
    message       : str
    timestamp     : float = field(default_factory=time.time)

    def severity_level(self) -> int:
        return SEVERITY_ORDER.get(self.severity.lower(), 0)

    def format_log_line(self) -> str:
        """Return the single-line log representation."""
        ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.timestamp))
        return (
            f'[{ts}] {self.severity.upper():8s} | '
            f'{self.detection_type} | '
            f'{self.src_ip} → {self.dst_ip} | '
            f'{self.message}'
        )

    def format_display(self) -> str:
        """Short single-line form for the dashboard alert feed."""
        ts = time.strftime('%H:%M:%S', time.localtime(self.timestamp))
        return f'{ts}  {self.severity.upper():8s}  {self.detection_type}  {self.message}'

    def to_bus_dict(self) -> dict:
        """Return a dict for publishing to the codex event bus."""
        return {
            'detection_type': self.detection_type,
            'severity':       self.severity.lower(),
            'src_ip':         self.src_ip,
            'dst_ip':         self.dst_ip,
            'message':        self.message,
        }


def dict_to_alert(d: dict) -> Alert:
    """Convert a raw alert dict (as returned by detectors / rules) to an Alert."""
    return Alert(
        detection_type = d.get('detection_type', 'UNKNOWN'),
        severity       = d.get('severity',       'low'),
        src_ip         = d.get('src_ip',         '?'),
        dst_ip         = d.get('dst_ip',         '?'),
        message        = d.get('message',        ''),
    )


class AlertLogger:
    """
    Writes alerts to a log file and enforces deduplication.

    Parameters
    ----------
    log_file : str
        Path to the alert log file (will be created / appended to).
    cooldown : float
        Seconds to suppress re-logging the same (src_ip, detection_type) pair.
    """

    def __init__(self, log_file: str, cooldown: float = 10.0) -> None:
        self._log_file = log_file
        self._cooldown = cooldown
        self._seen: dict = {}   # (src_ip, detection_type) → last_logged timestamp

        # Ensure log directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

    def log(self, alert: Alert) -> bool:
        """
        Write *alert* to the log file unless suppressed by deduplication.

        Returns True if the alert was written, False if it was suppressed.
        """
        key = (alert.src_ip, alert.detection_type)
        now = time.time()

        if now - self._seen.get(key, 0.0) < self._cooldown:
            return False

        self._seen[key] = now
        line = alert.format_log_line() + '\n'

        with open(self._log_file, 'a') as fh:
            fh.write(line)

        return True
