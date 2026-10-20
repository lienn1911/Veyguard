"""Append-only audit trail with a hash chain.

Module 4 owns the project's audit log; it was not implemented when this module
was built. This is the triage service's own append-only record so that every
investigation, tool call, and analyst confirmation is traceable today. It is
deliberately boring: JSON Lines, append mode only, sequence number plus
prev-hash so silent edits are detectable.

Nothing in this codebase rewrites or truncates the file (there is no delete API
and no truncate path). Merging this stream into Module 4's audit log later is a
concatenation, not a migration.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

GENESIS_HASH = "0" * 64


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _canonical(record: dict) -> str:
    body = {key: value for key, value in record.items() if key != "hash"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


class AuditLog:
    """Thread-safe append-only JSONL log."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ write
    def append(
        self,
        event: str,
        *,
        incident_id: str | None = None,
        actor: str = "system:triage-agent",
        payload: dict | None = None,
    ) -> dict:
        with self._lock:
            last = self._tail()
            record: dict[str, Any] = {
                "seq": (last["seq"] + 1) if last else 1,
                "event_id": f"AUD-{uuid.uuid4().hex[:12].upper()}",
                "ts": _utc_now(),
                "event": event,
                "incident_id": incident_id,
                "actor": actor,
                "payload": payload or {},
                "prev_hash": last["hash"] if last else GENESIS_HASH,
            }
            record["hash"] = hashlib.sha256(_canonical(record).encode("utf-8")).hexdigest()
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            return record

    # ------------------------------------------------------------------- read
    def entries(
        self, *, limit: int | None = None, incident_id: str | None = None
    ) -> list[dict]:
        records = self._read_all()
        if incident_id:
            records = [record for record in records if record.get("incident_id") == incident_id]
        if limit is not None:
            records = records[-limit:]
        return records

    def verify(self) -> dict:
        """Recompute the chain. Any tampering shows up as a broken link."""
        records = self._read_all()
        expected_prev = GENESIS_HASH
        for index, record in enumerate(records):
            if record.get("prev_hash") != expected_prev:
                return {
                    "ok": False,
                    "checked": index,
                    "reason": f"broken link at seq {record.get('seq')}",
                }
            recomputed = hashlib.sha256(_canonical(record).encode("utf-8")).hexdigest()
            if record.get("hash") != recomputed:
                return {
                    "ok": False,
                    "checked": index,
                    "reason": f"record hash mismatch at seq {record.get('seq')}",
                }
            expected_prev = record["hash"]
        return {"ok": True, "checked": len(records), "reason": None}

    def _read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        records: list[dict] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return records

    def _tail(self) -> dict | None:
        records = self._read_all()
        return records[-1] if records else None


def summarize(records: Iterable[dict]) -> list[dict]:
    """Trim audit records for the API (payloads are already small)."""
    return [
        {
            "seq": record.get("seq"),
            "event_id": record.get("event_id"),
            "ts": record.get("ts"),
            "event": record.get("event"),
            "incident_id": record.get("incident_id"),
            "actor": record.get("actor"),
            "payload": record.get("payload") or {},
            "hash": record.get("hash"),
            "prev_hash": record.get("prev_hash"),
        }
        for record in records
    ]
