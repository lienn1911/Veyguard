"""Persistence for triage proposals and analyst decisions.

A *proposal* (what the agent thinks) and a *decision* (what the analyst ruled)
are stored in separate keys and never collapsed. The UI reads both, which is why
a verdict can be shown as "proposed" and still read ``pending`` in the decision
column - the frontend cannot mark something approved that the backend has not.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

MAX_RUNS_PER_INCIDENT = 5


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _empty_decision() -> dict:
    return {"status": "pending", "analyst": None, "note": None, "at": None}


class TriageStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._state: dict[str, dict] = self._load()

    # ------------------------------------------------------------------- i/o
    def _load(self) -> dict[str, dict]:
        if not self.path.exists():
            return {}
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            # A corrupt cache must not take the API down; investigations can be rerun.
            return {}
        incidents = payload.get("incidents")
        return incidents if isinstance(incidents, dict) else {}

    def _flush(self) -> None:
        payload = {"updated_at": _utc_now(), "incidents": self._state}
        directory = self.path.parent
        handle, temp_name = tempfile.mkstemp(dir=directory, prefix=".triage-", suffix=".json")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, ensure_ascii=False, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, self.path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    # --------------------------------------------------------------- queries
    def get(self, incident_id: str) -> dict | None:
        with self._lock:
            record = self._state.get(incident_id)
            return json.loads(json.dumps(record)) if record else None

    def all(self) -> dict[str, dict]:
        with self._lock:
            return json.loads(json.dumps(self._state))

    def verdict_counts(self) -> dict[str, int]:
        counts = {"Likely Attack": 0, "Likely Benign": 0, "Needs Review": 0}
        pending = 0
        untriaged = 0
        for record in self._state.values():
            proposal = record.get("proposal") or {}
            verdict = proposal.get("verdict")
            if verdict in counts:
                counts[verdict] += 1
            else:
                untriaged += 1
            if (record.get("decision") or {}).get("status") == "pending":
                pending += 1
        return {**counts, "pending_confirmation": pending, "untriaged": untriaged}

    # --------------------------------------------------------------- writes
    def save_run(self, record: dict) -> dict:
        incident_id = record["incident_id"]
        with self._lock:
            existing = self._state.get(incident_id) or {"runs": [], "decision": _empty_decision()}
            runs = existing.get("runs") or []
            runs.append(record)
            existing["runs"] = runs[-MAX_RUNS_PER_INCIDENT:]
            existing["latest"] = record
            # A new proposal never inherits a previous decision.
            existing["decision"] = _empty_decision()
            existing["updated_at"] = _utc_now()
            self._state[incident_id] = existing
            self._flush()
            return json.loads(json.dumps(existing))

    def set_decision(self, incident_id: str, decision: dict) -> dict:
        with self._lock:
            existing = self._state.get(incident_id)
            if not existing or not existing.get("latest"):
                raise KeyError(incident_id)
            existing["decision"] = decision
            existing["updated_at"] = _utc_now()
            self._state[incident_id] = existing
            self._flush()
            return json.loads(json.dumps(existing))
