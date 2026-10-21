import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from contextlib import closing

from services.guardrails import validate_guardrails
from services.unified_audit import append as append_audit, append_in_transaction, initialize as initialize_audit

DB_PATH = Path(os.environ.get("SOC_TRIAGE_DB_PATH", Path(__file__).resolve().parents[1] / "data" / "audit.db"))

SAFE_ACTIONS = {
    "REVIEW_NETWORK_FLOWS": "Review related network flows",
    "CHECK_RELATED_ALERTS": "Check related security alerts",
    "REVIEW_INCIDENT_TIMELINE": "Review the incident timeline",
    "ESCALATE_TO_ANALYST": "Escalate for analyst investigation",
}


def init_db(db_path=DB_PATH):
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    db = sqlite3.connect(db_path)

    try:
        db.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                incident_id TEXT,
                event TEXT,
                details TEXT
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS decisions (
                recommendation_id TEXT PRIMARY KEY,
                incident_id TEXT,
                action TEXT,
                description TEXT,
                evidence_ids TEXT,
                decision TEXT,
                analyst_id TEXT
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS task_completions (
                recommendation_id TEXT PRIMARY KEY,
                completed_by TEXT NOT NULL,
                completed_at TEXT NOT NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS case_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                analyst_id TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                text TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        db.commit()

    finally:
        db.close()
    initialize_audit(db_path)


# 2. Save audit event
def log_event(incident_id, event, details, db_path=DB_PATH):
    init_db(db_path)
    append_audit(db_path, event, incident_id=incident_id,
                 actor=f"analyst:{details.get('analyst_id', 'unknown')}" if isinstance(details, dict) else 'system:recommendations',
                 payload=details if isinstance(details, dict) else {'items': details})


# 3. Generate safe recommendations
def generate_recommendations(data, incident_id, db_path=DB_PATH):
    incident = next(
        (i for i in data["incidents"]
         if i["incident_id"] == incident_id),
        None,
    )

    if incident is None:
        raise ValueError("Incident not found")

    alerts = [
        a for a in data["alerts"]
        if a["alert_id"] in incident["alert_ids"]
        and a["incident_id"] == incident_id
    ]

    if len(alerts) != len(incident["alert_ids"]):
        raise ValueError("Missing or unrelated alerts")

    valid_flows = {
        f["flow_id"] for f in data["flows"]
    }

    evidence = (
        incident["evidence_sample_ids"]
        + incident["alert_ids"]
    )

    if (
        not evidence
        or not set(incident["evidence_sample_ids"]).issubset(valid_flows)
    ):
        raise ValueError("Missing incident evidence")

    alert_types = {a["type"] for a in alerts}

    if not alert_types or alert_types - {
        "PortScan", "DoS", "DDoS", "Benign"
    }:
        raise ValueError("Unknown alert type")

    actions = [
        "REVIEW_NETWORK_FLOWS",
        "CHECK_RELATED_ALERTS",
        "REVIEW_INCIDENT_TIMELINE",
    ]

    if alert_types & {"PortScan", "DoS", "DDoS"}:
        actions.append("ESCALATE_TO_ANALYST")

    recommendations = []

    for action in actions:
        rec_id = hashlib.sha256(
            f"{incident_id}:{action}".encode()
        ).hexdigest()[:12].upper()

        action_evidence = (
            incident["evidence_sample_ids"] if action == "REVIEW_NETWORK_FLOWS"
            else incident["alert_ids"] if action == "CHECK_RELATED_ALERTS"
            else evidence
        )
        recommendations.append({
            "id": f"REC-{rec_id}",
            "incident_id": incident_id,
            "action": action,
            "description": SAFE_ACTIONS[action],
            "evidence_ids": action_evidence,
        })

    return recommendations


# 4. Approve or reject recommendations
def save_decision(
    data, incident_id, recommendation_id,
    decision, analyst_id, verdict,
    db_path=DB_PATH,
):
    if decision not in {"APPROVED", "REJECTED"}:
        raise ValueError("Invalid decision")

    if not isinstance(analyst_id, str) or not analyst_id.strip():
        raise ValueError("Analyst ID required")

    recommendations = generate_recommendations(
        data, incident_id, db_path
    )

    rec = next(
        (r for r in recommendations
         if r["id"] == recommendation_id),
        None,
    )

    if rec is None:
        raise ValueError("Recommendation not found")

    proposal = {
        "verdict": verdict,
        "evidence_ids": rec["evidence_ids"],
        "actions": [rec["action"]],
    }

    safety = validate_guardrails(
        data, incident_id, proposal
    )

    if safety["status"] == "BLOCKED":
        log_event(
            incident_id,
            "DECISION_BLOCKED",
            {"recommendation_id": recommendation_id,
             "reasons": safety["reasons"]},
            db_path,
        )
        raise ValueError("Guardrail blocked the proposal")

    # REVIEW_REQUIRED does not approve the AI verdict.
    # This decision applies only to investigation steps.
    init_db(db_path)

    with closing(sqlite3.connect(db_path)) as db, db:
        try:
            db.execute("""
                INSERT INTO decisions VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                rec["id"], incident_id,
                rec["action"], rec["description"],
                json.dumps(rec["evidence_ids"]),
                decision, analyst_id,
            ))
            append_in_transaction(db, 'ANALYST_DECISION', incident_id=incident_id,
                                  actor=f'analyst:{analyst_id}', payload={
                                      'recommendation_id': recommendation_id, 'decision': decision,
                                      'analyst_id': analyst_id, 'safety_status': safety['status'],
                                  })

        except sqlite3.IntegrityError:
            raise ValueError(
                "Recommendation already has a decision"
            ) from None

    return {
        "recommendation_id": recommendation_id,
        "decision": decision,
        "safety_status": safety["status"],
    }


# 5. Generate case-note draft
def get_case_note(incident_id, db_path=DB_PATH):
    init_db(db_path)

    with closing(sqlite3.connect(db_path)) as db, db:
        rows = db.execute("""
            SELECT description, evidence_ids
            FROM decisions
            WHERE incident_id = ? AND decision = 'APPROVED'
        """, (incident_id,)).fetchall()

    if not rows:
        raise ValueError("An approved investigation step is required before drafting a case note")

    return {
        "incident_id": incident_id,
        "status": "DRAFT",
        "approved_steps": [
            {"description": description,
             "evidence_ids": json.loads(evidence)}
            for description, evidence in rows
        ],
    }
