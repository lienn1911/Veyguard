"""Append-only audit log: chain integrity, tamper detection, isolation per incident."""

from __future__ import annotations

import json

from services.audit_log import GENESIS_HASH, AuditLog


def test_chain_links_and_verifies(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    first = log.append("triage.started", incident_id="INC-1", payload={"run_id": "R1"})
    second = log.append("triage.completed", incident_id="INC-1", payload={"verdict": "Likely Attack"})

    assert first["seq"] == 1
    assert first["prev_hash"] == GENESIS_HASH
    assert second["seq"] == 2
    assert second["prev_hash"] == first["hash"]
    assert log.verify()["ok"] is True


def test_entries_are_append_only_and_ordered(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    for index in range(4):
        log.append("triage.tool_call", incident_id="INC-1", payload={"index": index})

    entries = log.entries()
    assert [entry["seq"] for entry in entries] == [1, 2, 3, 4]
    assert len(log.entries(limit=2)) == 2
    assert log.entries(limit=2)[-1]["seq"] == 4


def test_entries_can_be_filtered_by_incident(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append("triage.started", incident_id="INC-1")
    log.append("triage.started", incident_id="INC-2")

    assert len(log.entries(incident_id="INC-2")) == 1


def test_tampering_breaks_verification(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("triage.started", incident_id="INC-1", payload={"verdict": "Needs Review"})
    log.append("triage.completed", incident_id="INC-1", payload={"verdict": "Needs Review"})

    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["payload"]["verdict"] = "Likely Benign"  # silent edit
    lines[0] = json.dumps(record)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = log.verify()
    assert result["ok"] is False
    assert "hash" in result["reason"] or "broken link" in result["reason"]


def test_resume_after_restart_keeps_the_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLog(path).append("triage.started", incident_id="INC-1")

    reopened = AuditLog(path)
    third = reopened.append("triage.completed", incident_id="INC-1")

    assert third["seq"] == 2
    assert reopened.verify()["ok"] is True
