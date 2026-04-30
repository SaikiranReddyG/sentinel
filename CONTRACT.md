# Sentinel Contract

## Purpose

Sentinel is a standalone packet-level IDS. It captures traffic, parses protocol headers, applies stateful detection, and emits a small codex-contract event stream for lifecycle and alert reporting.

## Event schema

| Field | Type | Notes |
|---|---|---|
| `schema_version` | string | Event schema version. Sentinel v0.1 uses `1.0`. |
| `timestamp` | string | RFC 3339 timestamp with millisecond precision in local offset form. |
| `source` | string | Always `sentinel`. |
| `source_version` | string | Sentinel package version. |
| `host` | string | Hostname of the emitting machine. |
| `event_type` | string | One of the event types listed below. |
| `severity` | string | One of the severities listed below. |
| `payload` | object | Event-specific data. |

## Event types Sentinel emits

| Event type | When emitted | Severity |
|---|---|---|
| `sentinel.lifecycle.started` | After the socket binds and capture is ready. | `info` |
| `sentinel.alert` | When a detector or rule produces a real alert and it passes alert deduplication. | `low`, `medium`, `high`, or `critical` |
| `sentinel.lifecycle.stopped` | During shutdown, alongside the final summary. | `info` |

## Severity ladder

`info` < `low` < `medium` < `high` < `critical`

Lifecycle events use `info`. Alert severity is driven by the detector or rule that raised the alert.

## Output destinations

Sentinel supports three event sinks:

- `stdout` writes one JSON event per line to standard output.
- `file` appends JSONL events to a path on disk.
- `http_post` posts each event individually to an HTTP endpoint with retry/backoff.

## What Sentinel is not

Sentinel is not a persistent SIEM, not a packet recorder, not a general-purpose log shipper, and not an IPv6 IDS yet. It does not depend on an external message bus.