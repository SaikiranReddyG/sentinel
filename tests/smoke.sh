#!/usr/bin/env bash

set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo '[!] smoke test must be run as root' >&2
  exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
VENV_PY="$REPO_ROOT/.venv/bin/python"
VENV_SENTINEL="$REPO_ROOT/.venv/bin/sentinel"

if [[ ! -x "$VENV_PY" || ! -x "$VENV_SENTINEL" ]]; then
  echo '[!] expected venv at .venv with sentinel installed' >&2
  exit 1
fi

echo '[*] sentinel version'
"$VENV_SENTINEL" version

echo '[*] pytest'
"$VENV_PY" -m pip show pytest >/dev/null 2>&1 || "$VENV_PY" -m pip install pytest >/dev/null
"$VENV_PY" -m pytest "$REPO_ROOT/tests/" -v

echo '[*] live capture (stdout)'
(timeout 5 "$VENV_SENTINEL" run -i lo --no-dashboard --output stdout 2>&1 | head -20) || true

echo '[*] live capture (file)'
JSONL=/tmp/sentinel-smoke.jsonl
STDOUT_LOG=/tmp/sentinel-smoke.stdout.log
rm -f "$JSONL" "$STDOUT_LOG"
timeout -s INT 5 "$VENV_SENTINEL" run -i lo --no-dashboard --output file --output-file "$JSONL" >"$STDOUT_LOG" 2>&1 || true

python3 - <<'PY' "$JSONL"
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.exists():
    raise SystemExit('missing JSONL file')

events = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
required = {'schema_version', 'timestamp', 'source', 'source_version', 'host', 'event_type', 'severity', 'payload'}
types = set()

for event in events:
    missing = required - set(event)
    if missing:
        raise SystemExit(f'missing fields: {sorted(missing)}')
    types.add(event['event_type'])

if 'sentinel.lifecycle.started' not in types:
    raise SystemExit('missing sentinel.lifecycle.started')
if 'sentinel.lifecycle.stopped' not in types:
    raise SystemExit('missing sentinel.lifecycle.stopped')

print(f'{len(events)} events; types: {sorted(types)}')
PY

echo '[+] smoke test passed'