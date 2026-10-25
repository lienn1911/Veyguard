"""Exercise a saved live AI result through analyst review without changing production state."""

import json
import hashlib
import shutil
import tempfile
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from services import api, recommendations
from services.config import load_settings
from services.data_store import Dataset
from services.triage import TriageService
from services.unified_audit import entries, verify


ROOT = Path(__file__).resolve().parents[1]


def run(
    incident_id="INC-A787E11F2A22", *, source_state=None, source_audit=None, artifacts_dir=None
):
    settings = load_settings()
    production_paths = (settings.state_path, settings.audit_path, api.DB_PATH)
    before = {
        str(path): hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
        for path in production_paths
    }
    data = json.loads(api.DATA.read_text(encoding="utf-8"))
    timeline = json.loads((ROOT / "src" / "real-timelines.json").read_text(encoding="utf-8"))
    incident = next(item for item in data["incidents"] if item["incident_id"] == incident_id)
    evidence_ids = set(incident["alert_ids"] + incident["evidence_sample_ids"])
    events = next(
        item["events"] for item in timeline["timelines"] if item["incident_id"] == incident_id
    )
    assert events and all(event["evidence_id"] in evidence_ids for event in events)

    with tempfile.TemporaryDirectory(dir=ROOT / "data") as folder:
        scratch = Path(folder)
        state_path = scratch / "triage-results.json"
        shutil.copyfile(source_state or settings.state_path, state_path)
        db_path = scratch / "audit.db"
        if source_audit:
            shutil.copyfile(source_audit, db_path)
        isolated = replace(settings, state_path=state_path, audit_path=db_path)
        dataset = Dataset.load(settings.alerts_path, settings.timelines_path)
        triage = TriageService(isolated, dataset)

        with (
            patch.object(api, "ai_service", return_value=triage),
            patch.object(api, "DB_PATH", db_path),
            patch.object(api, "init_db", lambda _path=None: recommendations.init_db(db_path)),
        ):
            assessment = api.ai_assessment(incident_id)
            assert assessment["status"] == "ready"
            result = assessment["assessment"]
            assert result["evidence_ids"] and set(result["evidence_ids"]).issubset(evidence_ids)
            assert assessment["investigation"]["tool_calls"]

            proposed = recommendations.annotate_ai_next_steps(
                recommendations.generate_recommendations(data, incident_id, db_path),
                result["next_steps"],
            )
            ai_steps = [item for item in proposed if item["ai_suggested"]]
            assert ai_steps
            decision = triage.decide(
                incident_id,
                decision="confirmed",
                analyst="Acceptance Tester",
                note="Isolated workflow test using cited evidence.",
            )
            assert decision["decision"]["status"] == "confirmed"
            approved = recommendations.save_decision(
                data,
                incident_id,
                ai_steps[0]["id"],
                "APPROVED",
                "Acceptance Tester",
                result["verdict"],
                db_path,
            )
            assert approved["decision"] == "APPROVED"
            note = recommendations.get_case_note(incident_id, db_path)
            assert note["status"] == "DRAFT" and note["approved_steps"]
            recommendations.log_event(
                incident_id,
                "CASE_NOTE_DRAFTED",
                {
                    "analyst_id": "Acceptance Tester",
                    "simulation": True,
                    "evidence_ids": ai_steps[0]["evidence_ids"],
                },
                db_path,
            )

            record = api.save_case_record(data, incident_id, "Acceptance Tester")
            assert record["status"] == "saved" and record["record"]["ai_decision"] == "confirmed"
            events_saved = entries(db_path, incident_id=incident_id)
            assert {"ANALYST_DECISION", "CASE_NOTE_DRAFTED", "CASE_RECORD_SAVED"}.issubset(
                {item["event"] for item in events_saved}
            )
            if source_audit:
                assert {
                    "triage.started",
                    "triage.tool_call",
                    "triage.completed",
                    "analyst.decision",
                }.issubset({item["event"] for item in events_saved})
            assert verify(db_path)["ok"]
            if artifacts_dir:
                destination = Path(artifacts_dir)
                destination.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(db_path, destination / "review-audit.db")
                shutil.copyfile(state_path, destination / "review-state.json")
                (destination / "case-note-draft.json").write_text(
                    json.dumps(note, indent=2), encoding="utf-8"
                )

            after = {
                str(path): hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
                for path in production_paths
            }
            return {
                "kind": "isolated-current-case-flow",
                "incident_id": incident_id,
                "ai_run_id": result["run_id"],
                "read_only_tool_calls": len(assessment["investigation"]["tool_calls"]),
                "cited_evidence_ids": len(result["evidence_ids"]),
                "timeline_events_checked": len(events),
                "ai_steps_available": len(ai_steps),
                "ai_step_approved_in_copy": ai_steps[0]["id"],
                "record_saved_in_copy": record["event_id"],
                "audit_chain_valid": True,
                "production_state_changed": before != after,
                "analyst_role": "simulated acceptance tester; not a production analyst decision",
            }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
