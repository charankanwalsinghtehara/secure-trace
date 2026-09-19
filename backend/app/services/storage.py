"""Small offline JSON store used by the prototype.

Production deployments should replace this adapter with PostgreSQL while keeping
the ledger as the authoritative audit source.
"""

import json
from pathlib import Path
from threading import Lock
from typing import Any


class JsonStore:
    def __init__(self, path: str = "data/securedoc.json") -> None:
        self.path = Path(path)
        self.lock = Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._write({"users": {}, "recipients": {}, "documents": {}, "events": {}, "messages": []})

    def _read(self) -> dict[str, Any]:
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _write(self, value: dict[str, Any]) -> None:
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
        temporary.replace(self.path)

    def read(self) -> dict[str, Any]:
        with self.lock:
            value = self._read()
            value.setdefault("users", {})
            value.setdefault("recipients", {})
            value.setdefault("documents", {})
            value.setdefault("events", {})
            value.setdefault("messages", [])
            return value

    def update(self, callback: Any) -> dict[str, Any]:
        with self.lock:
            value = self._read()
            value.setdefault("users", {})
            value.setdefault("recipients", {})
            value.setdefault("documents", {})
            value.setdefault("events", {})
            value.setdefault("messages", [])
            callback(value)
            self._write(value)
            return value