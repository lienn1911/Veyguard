"""One append-only, hash-chained SQLite event table for AI and analyst actions."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def _canonical(record):
    return json.dumps(
        {key: value for key, value in record.items() if key != "hash"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def _create(db):
    db.execute("""CREATE TABLE IF NOT EXISTS audit_events (
        seq INTEGER PRIMARY KEY, event_id TEXT NOT NULL UNIQUE, ts TEXT NOT NULL,
        event TEXT NOT NULL, incident_id TEXT, actor TEXT NOT NULL,
        payload TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL,
        source_key TEXT UNIQUE)""")
    db.execute("""CREATE TRIGGER IF NOT EXISTS audit_events_no_update
        BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END""")
    db.execute("""CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
        BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END""")


def _insert(db, event, incident_id, actor, payload, *, ts=None, source_key=None, event_id=None):
    if (
        source_key
        and db.execute("SELECT 1 FROM audit_events WHERE source_key = ?", (source_key,)).fetchone()
    ):
        return None
    previous = db.execute("SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
    record = {
        "seq": previous[0] + 1 if previous else 1,
        "event_id": event_id or f"AUD-{uuid.uuid4().hex[:12].upper()}",
        "ts": ts
        or datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "event": event,
        "incident_id": incident_id,
        "actor": actor,
        "payload": payload or {},
        "prev_hash": previous[1] if previous else GENESIS,
    }
    record["hash"] = hashlib.sha256(_canonical(record).encode("utf-8")).hexdigest()
    db.execute(
        "INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            record["seq"],
            record["event_id"],
            record["ts"],
            event,
            incident_id,
            actor,
            json.dumps(record["payload"], ensure_ascii=False, default=str),
            record["prev_hash"],
            record["hash"],
            source_key,
        ),
    )
    return record


def initialize(db_path, legacy_jsonl=None):
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if legacy_jsonl is None:
        candidate = db_path.parent / "audit" / "triage-audit.jsonl"
        legacy_jsonl = candidate if candidate.exists() else None
    with closing(sqlite3.connect(db_path, timeout=30)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        _create(db)
        historical = []
        legacy = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'"
        ).fetchone()
        if legacy:
            for row_id, ts, incident_id, event, details in db.execute(
                "SELECT id, timestamp, incident_id, event, details FROM audit_log ORDER BY id"
            ).fetchall():
                try:
                    payload = json.loads(details or "{}")
                except json.JSONDecodeError:
                    payload = {"legacy_details": details}
                if not isinstance(payload, dict):
                    payload = {"items": payload}
                historical.append(
                    (
                        ts,
                        event,
                        incident_id,
                        f"analyst:{payload.get('analyst_id', 'unknown')}",
                        payload,
                        f"sqlite:{row_id}",
                        None,
                    )
                )
        if legacy_jsonl and Path(legacy_jsonl).exists():
            for line_number, line in enumerate(
                Path(legacy_jsonl).read_text(encoding="utf-8").splitlines(), 1
            ):
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                historical.append(
                    (
                        item.get("ts"),
                        item.get("event", "legacy.unknown"),
                        item.get("incident_id"),
                        item.get("actor", "system:triage-agent"),
                        item.get("payload"),
                        f"jsonl:{line_number}",
                        item.get("event_id"),
                    )
                )
        for ts, event, incident_id, actor, payload, source_key, event_id in sorted(
            historical, key=lambda item: (item[0] or "", item[5])
        ):
            _insert(
                db,
                event,
                incident_id,
                actor,
                payload,
                ts=ts,
                source_key=source_key,
                event_id=event_id,
            )


def append(
    db_path,
    event,
    *,
    incident_id=None,
    actor="system:triage-agent",
    payload=None,
    legacy_jsonl=None,
):
    initialize(db_path, legacy_jsonl)
    with closing(sqlite3.connect(db_path, timeout=30)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        return _insert(db, event, incident_id, actor, payload)


def append_in_transaction(
    db, event, *, incident_id=None, actor="system:triage-agent", payload=None
):
    """Append alongside a case change in the caller's SQLite transaction."""
    return _insert(db, event, incident_id, actor, payload)


def entries(db_path, *, limit=None, incident_id=None, legacy_jsonl=None):
    initialize(db_path, legacy_jsonl)
    with closing(sqlite3.connect(db_path, timeout=30)) as db:
        query = "SELECT seq, event_id, ts, event, incident_id, actor, payload, prev_hash, hash FROM audit_events"
        values = []
        if incident_id:
            query += " WHERE incident_id = ?"
            values.append(incident_id)
        query += " ORDER BY seq DESC"
        if limit is not None:
            query += " LIMIT ?"
            values.append(limit)
        rows = db.execute(query, values).fetchall()
    return [
        dict(
            seq=row[0],
            event_id=row[1],
            ts=row[2],
            event=row[3],
            incident_id=row[4],
            actor=row[5],
            payload=json.loads(row[6]),
            prev_hash=row[7],
            hash=row[8],
        )
        for row in reversed(rows)
    ]


def verify(db_path, *, legacy_jsonl=None):
    records = entries(db_path, legacy_jsonl=legacy_jsonl)
    previous = GENESIS
    for index, record in enumerate(records):
        if (
            record["seq"] != index + 1
            or record["prev_hash"] != previous
            or record["hash"] != hashlib.sha256(_canonical(record).encode("utf-8")).hexdigest()
        ):
            return {
                "ok": False,
                "checked": index,
                "reason": f"audit chain broken at seq {record['seq']}",
            }
        previous = record["hash"]
    return {"ok": True, "checked": len(records), "reason": None}
