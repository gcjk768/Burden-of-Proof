"""Disk cache of model responses, keyed by the exact request.

The request never contains the API key, so cache files are safe to keep, but they do
contain source code from the scanned repository and stay out of version control.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def request_key(request: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(request).encode("utf-8")).hexdigest()


class ResponseCache:
    def __init__(self, directory: Path, mode: str = "readwrite") -> None:
        if mode not in {"readwrite", "read", "off"}:
            raise ValueError(f"unknown cache mode {mode!r}")
        self.directory = directory
        self.mode = mode

    @property
    def readable(self) -> bool:
        return self.mode in {"readwrite", "read"}

    @property
    def writable(self) -> bool:
        return self.mode == "readwrite"

    def _path(self, key: str) -> Path:
        return self.directory / key[:2] / f"{key}.json"

    def get(self, key: str) -> dict[str, Any] | None:
        if not self.readable:
            return None
        path = self._path(key)
        if not path.is_file():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))["response"]
        except (OSError, ValueError, KeyError):
            return None

    def delete(self, key: str) -> None:
        self._path(key).unlink(missing_ok=True)

    def put(self, key: str, request: dict[str, Any], response: dict[str, Any]) -> Path | None:
        if not self.writable:
            return None
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(canonical_json({"request": request, "response": response}), encoding="utf-8")
        tmp.replace(path)
        return path
