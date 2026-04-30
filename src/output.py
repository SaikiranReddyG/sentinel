"""Output adapters for Sentinel codex-contract events."""

from __future__ import annotations

import json
import time
from pathlib import Path

try:
    import requests
except Exception:  # pragma: no cover - optional dependency fallback
    requests = None

try:
    from urllib import request as urllib_request
except Exception:  # pragma: no cover - fallback should always exist
    urllib_request = None


class StdoutOutput:
    def emit(self, event: dict) -> None:
        print(json.dumps(event, sort_keys=True))


class FileOutput:
    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self._path.open('a', encoding='utf-8')

    def emit(self, event: dict) -> None:
        self._fh.write(json.dumps(event, sort_keys=True) + '\n')
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


class HttpPostOutput:
    def __init__(self, url: str, retries: int = 3, backoff: float = 0.5) -> None:
        self._url = url
        self._retries = retries
        self._backoff = backoff

    def emit(self, event: dict) -> None:
        body = json.dumps(event).encode('utf-8')
        last_error = None

        for attempt in range(self._retries + 1):
            try:
                if requests is not None:
                    response = requests.post(
                        self._url,
                        json=event,
                        timeout=5,
                    )
                    response.raise_for_status()
                    return

                if urllib_request is None:
                    raise RuntimeError('no HTTP client available')

                req = urllib_request.Request(
                    self._url,
                    data=body,
                    headers={'Content-Type': 'application/json'},
                    method='POST',
                )
                with urllib_request.urlopen(req, timeout=5):
                    return
            except Exception as exc:
                last_error = exc
                if attempt >= self._retries:
                    raise
                time.sleep(self._backoff * (2 ** attempt))

        if last_error is not None:
            raise last_error


def make_output(output_spec: str, url: str | None = None, path: str | None = None):
    if output_spec == 'stdout':
        return StdoutOutput()
    if output_spec == 'file':
        if not path:
            raise ValueError('output-file is required for file output')
        return FileOutput(path)
    if output_spec == 'http_post':
        if not url:
            raise ValueError('output-url is required for http_post output')
        return HttpPostOutput(url)
    raise ValueError(f'unknown output_spec: {output_spec}')