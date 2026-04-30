"""Codex-contract event emission helpers for Sentinel."""

from __future__ import annotations

from datetime import datetime, timezone
import socket
from typing import Any

from src import __version__ as _SENTINEL_VERSION

_VALID_SEVERITIES = {'info', 'low', 'medium', 'high', 'critical'}
_OUTPUT = None


def set_output(output) -> None:
    """Set the active output sink used by emit_event()."""
    global _OUTPUT
    _OUTPUT = output


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec='milliseconds')


def _build_event(event_type: str, severity: str, payload: dict[str, Any]) -> dict[str, Any]:
    severity = severity.lower()
    if severity not in _VALID_SEVERITIES:
        raise ValueError(f'invalid severity: {severity}')

    return {
        'schema_version': '1.0',
        'timestamp': _now_iso(),
        'source': 'sentinel',
        'source_version': _SENTINEL_VERSION,
        'host': socket.gethostname(),
        'event_type': event_type,
        'severity': severity,
        'payload': payload,
    }


def emit_event(event_type: str, severity: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Build an event and emit it through the configured output sink."""
    event = _build_event(event_type, severity, payload)
    if _OUTPUT is not None:
        _OUTPUT.emit(event)
    return event