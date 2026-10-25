"""Compatibility facade over the shared, append-only SQLite audit trail."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from . import unified_audit
from .recommendations import DB_PATH


class AuditLog:
    def __init__(self, path: Path):
        path = Path(path)
        default_jsonl = (
            Path(__file__).resolve().parents[1] / "data" / "audit" / "triage-audit.jsonl"
        )
        if path.suffix == ".db":
            self.path = path
        elif path.resolve() == default_jsonl.resolve():
            self.path = DB_PATH
        elif path.name == "triage-audit.jsonl" and path.parent.name == "audit":
            self.path = path.parent.parent / "audit.db"
        else:
            self.path = path.with_suffix(".db")
        self.legacy_jsonl = path if path.suffix != ".db" else None

    def append(
        self,
        event: str,
        *,
        incident_id: str | None = None,
        actor: str = "system:triage-agent",
        payload: dict | None = None,
    ) -> dict:
        return unified_audit.append(
            self.path,
            event,
            incident_id=incident_id,
            actor=actor,
            payload=payload,
            legacy_jsonl=self.legacy_jsonl,
        )

    def entries(self, *, limit: int | None = None, incident_id: str | None = None) -> list[dict]:
        return unified_audit.entries(
            self.path, limit=limit, incident_id=incident_id, legacy_jsonl=self.legacy_jsonl
        )

    def verify(self) -> dict:
        return unified_audit.verify(self.path, legacy_jsonl=self.legacy_jsonl)


def summarize(records: Iterable[dict]) -> list[dict]:
    return list(records)
