"""Offline append-only, hash-chained ledger adapter."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock


class LocalLedger:
    def __init__(self, path: str = "data/ledger.jsonl", validator_count: int = 3, quorum: int = 2) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.validators = [self.path.with_name(f"{self.path.stem}-validator-{index}{self.path.suffix}") for index in range(validator_count)]
        self.quorum = quorum
        self.lock = Lock()

    def _records(self) -> list[dict[str, str]]:
        if not self.validators[0].exists():
            return []
        return [json.loads(line) for line in self.validators[0].read_text(encoding="utf-8").splitlines() if line]

    def append(self, record: dict[str, object]) -> dict[str, str]:
        with self.lock:
            records = self._records()
            previous = records[-1]["entry_hash"] if records else "GENESIS"
            canonical = json.dumps(record, separators=(",", ":"), sort_keys=True)
            entry_hash = hashlib.sha3_256(f"{previous}:{canonical}".encode("utf-8")).hexdigest()
            entry = {
                "transaction_id": hashlib.sha3_256(entry_hash.encode("ascii")).hexdigest()[:32],
                "previous_hash": previous,
                "entry_hash": entry_hash,
                "committed_at": datetime.now(timezone.utc).isoformat(),
                "record": canonical,
            }
            committed = 0
            for validator in self.validators:
                with validator.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(entry, sort_keys=True) + "\n")
                committed += 1
            if committed < self.quorum:
                raise RuntimeError("Offline validator quorum was not reached")
            return entry

    def find_by_watermark(self, watermark_id: str) -> dict[str, object] | None:
        for entry in self._records():
            record = json.loads(entry["record"])
            if record.get("watermark_id") == watermark_id:
                return {"ledger": entry, "record": record}
        return None

    def verify_chain(self) -> bool:
        validator_chains = []
        for validator in self.validators:
            if not validator.exists():
                continue
            previous = "GENESIS"
            for line in validator.read_text(encoding="utf-8").splitlines():
                entry = json.loads(line)
                if entry["previous_hash"] != previous:
                    return False
                expected = hashlib.sha3_256(f'{previous}:{entry["record"]}'.encode("utf-8")).hexdigest()
                if entry["entry_hash"] != expected:
                    return False
                previous = entry["entry_hash"]
            validator_chains.append(previous)
        return len(validator_chains) >= self.quorum and len(set(validator_chains)) == 1

    def status(self) -> dict[str, object]:
        validators = []
        for index, validator in enumerate(self.validators, start=1):
            entries = self._records_for(validator)
            validators.append({
                "validator": f"validator-{index}",
                "online": validator.exists(),
                "entries": len(entries),
                "head": entries[-1]["entry_hash"] if entries else "GENESIS",
            })
        return {
            "chain_valid": self.verify_chain(),
            "quorum": self.quorum,
            "validator_count": len(self.validators),
            "validators": validators,
        }

    @staticmethod
    def _records_for(validator: Path) -> list[dict[str, str]]:
        if not validator.exists():
            return []
        return [json.loads(line) for line in validator.read_text(encoding="utf-8").splitlines() if line]
