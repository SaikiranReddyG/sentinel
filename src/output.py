"""Output adapters for Sentinel codex-contract events."""

from __future__ import annotations

import json
import time
from pathlib import Path

import requests


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
    def __init__(self, url: str, retries: int = 3, backoff: float = 0.5, auth_header: str | None = None) -> None:
        self._url = url
        self._retries = retries
        self._backoff = backoff
        self._auth_header = auth_header

    def emit(self, event: dict) -> None:
        headers = {}
        if self._auth_header:
            headers['Authorization'] = self._auth_header.replace('Authorization: ', '', 1).strip()
        for attempt in range(self._retries + 1):
            try:
                response = requests.post(
                    self._url,
                    json=event,
                    headers=headers if headers else None,
                    timeout=5,
                )
                response.raise_for_status()
                return
            except Exception:
                if attempt >= self._retries:
                    raise
                time.sleep(self._backoff * (2 ** attempt))


def make_output(output_spec: str, url: str | None = None, path: str | None = None, auth_header: str | None = None):
    if output_spec == 'stdout':
        return StdoutOutput()
    if output_spec == 'file':
        if not path:
            raise ValueError('output-file is required for file output')
        return FileOutput(path)
    if output_spec == 'http_post':
        if not url:
            raise ValueError('output-url is required for http_post output')
        return HttpPostOutput(url, auth_header=auth_header)
    raise ValueError(f'unknown output_spec: {output_spec}')