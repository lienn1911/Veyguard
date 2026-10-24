"""Append-only audit log: chain integrity, tamper detection, isolation per incident."""

from __future__ import annotations

import json
import sqlite3

from services.audit_log import AuditLog
from services.unified_audit import GENESIS as GENESIS_HASH


def test_chain_links_and_verifies(tmp_path):
    log = AuditLog(tmp_path / "audit.db")
    first = log.append("triage.started", incident_id="INC-1", payload={"run_id": "R1"})
    second = log.append("triage.completed", incident_id="INC-1", payload={"verdict": "Likely Attack"})

    assert first["seq"] == 1
    assert first["prev_hash"] == GENESIS_HASH
    assert second["seq"] == 2
    assert second["prev_hash"] == first["hash"]
    assert log.verify()["ok"] is True


def test_entries_are_append_only_and_ordered(tmp_path):
    log = AuditLog(tmp_path / "audit.db")
    for index in range(4):
        log.append("triage.tool_call", incident_id="INC-1", payload={"index": index})

    entries = log.entries()
    assert [entry["seq"] for entry in entries] == [1, 2, 3, 4]
    assert len(log.entries(limit=2)) == 2
    assert log.entries(limit=2)[-1]["seq"] == 4


def test_entries_can_be_filtered_by_incident(tmp_path):
    log = AuditLog(tmp_path / "audit.db")
    log.append("triage.started", incident_id="INC-1")
    log.append("triage.started", incident_id="INC-2")

    assert len(log.entries(incident_id="INC-2")) == 1


def test_tampering_breaks_verification(tmp_path):
    path = tmp_path / "audit.db"
    log = AuditLog(path)
    log.append("triage.started", incident_id="INC-1", payload={"verdict": "Needs Review"})
    log.append("triage.completed", incident_id="INC-1", payload={"verdict": "Needs Review"})

    with sqlite3.connect(path) as db:
        db.execute('DROP TRIGGER audit_events_no_update')
        db.execute('UPDATE audit_events SET payload = ? WHERE seq = 1',
                   (json.dumps({'verdict': 'Likely Benign'}),))

    result = log.verify()
    assert result["ok"] is False
    assert "broken" in result["reason"]


def test_resume_after_restart_keeps_the_chain(tmp_path):
    path = tmp_path / "audit.db"
    AuditLog(path).append("triage.started", incident_id="INC-1")

    reopened = AuditLog(path)
    third = reopened.append("triage.completed", incident_id="INC-1")

    assert third["seq"] == 2
    assert reopened.verify()["ok"] is True
