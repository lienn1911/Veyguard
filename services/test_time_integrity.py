"""Regression checks for the saved multi-minute case-window hallucination."""

import json
import tempfile
import unittest
from pathlib import Path
from dataclasses import replace
from services.config import load_settings
from services.data_store import Dataset
from services.triage import TriageService
from services.validation import check_case_time_claims, validate_proposal
from services import api
from services.unified_audit import append, entries
from unittest.mock import patch


class TimeIntegrityTests(unittest.TestCase):
    def test_conflict_claim_is_rejected_only_when_contradicted(self):
        case = {"window_start": "2020-01-01T10:00:00", "window_end": "2020-01-01T10:03:00"}
        alerts = [{"timestamp": "2020-01-01T10:03:45"}]
        for text in [
            "The incident window conflicts with the broader linked-alert timeline.",
            "Incident metadata describes a single-minute window, while linked alerts span multiple minutes.",
        ]:
            self.assertEqual(
                check_case_time_claims(text, case, alerts)[0].code, "CONTRADICTED_TIME_CLAIM"
            )
        self.assertFalse(
            check_case_time_claims(
                "Alerts occur in several minute buckets within the case range.", case, alerts
            )
        )
        self.assertFalse(
            check_case_time_claims(
                "There is no case window conflict with related alerts.", case, alerts
            )
        )
        self.assertFalse(
            check_case_time_claims(
                "The incident window conflicts with the alert timeline.",
                case,
                [{"timestamp": "2020-01-01T10:04:00"}],
            )
        )
        report = validate_proposal(
            {
                "incident_id": "I",
                "verdict": "Needs Review",
                "reason": "The incident window conflicts with the broader alert timeline.",
                "evidence_ids": [],
            },
            incident_id="I",
            evidence_ids={},
            evidence_numbers=set(),
            tool_call_count=1,
            incident=case,
            case_alerts=alerts,
        )
        self.assertFalse(report.ok)

    def test_saved_result_cannot_be_adopted_and_storage_is_unchanged(self):
        root = Path(__file__).resolve().parents[1]
        dataset = Dataset.load(root / "src/real-alerts.json", root / "src/real-timelines.json")
        case_id = dataset.incident_ids()[0]
        alert_id = dataset.agent_alerts(case_id)[0]["alert_id"]
        with tempfile.TemporaryDirectory() as folder:
            settings = replace(
                load_settings(),
                state_path=Path(folder) / "state.json",
                audit_path=Path(folder) / "audit.jsonl",
            )
            service = TriageService(settings, dataset)
            proposal = {
                "incident_id": case_id,
                "verdict": "Needs Review",
                "confidence": "low",
                "reason": "The incident window conflicts with the broader linked-alert timeline.",
                "evidence_ids": [alert_id],
                "findings": [],
                "limitations": "",
                "next_steps": [],
            }
            service.store.save_run(
                {
                    "incident_id": case_id,
                    "status": "ok",
                    "run_id": "historic",
                    "proposal": proposal,
                    "investigation": {"tool_calls": [{"tool": "get_related_alerts", "ok": True}]},
                }
            )
            before = settings.state_path.read_bytes()
            projected = service.latest(case_id)["latest"]
            self.assertEqual(projected["error"]["code"], "EVIDENCE_INTEGRITY_FAILED")
            self.assertIsNone(projected["proposal"])
            with self.assertRaisesRegex(ValueError, "validated proposal"):
                service.decide(case_id, decision="confirmed", analyst="tester")
            self.assertEqual(settings.state_path.read_bytes(), before)

    def test_case_tool_exposes_grouped_end_and_fingerprint_detects_change(self):
        root = Path(__file__).resolve().parents[1]
        dataset = Dataset.load(root / "src/real-alerts.json", root / "src/real-timelines.json")
        case_id = dataset.incident_ids()[0]
        details = dataset.agent_incident_details(case_id)
        self.assertEqual(details["window_end"], dataset.require(case_id).incident["window_end"])
        service = object.__new__(TriageService)
        service.dataset = dataset
        before = service._evidence_fingerprint(case_id)
        dataset.incidents[case_id]["window_end"] = "2030-01-01T00:00:00"
        self.assertNotEqual(before, service._evidence_fingerprint(case_id))

    def test_saved_report_withholds_contradiction_without_rewriting_audit(self):
        data = json.loads(api.DATA.read_text(encoding="utf-8"))
        case_id = data["incidents"][0]["incident_id"]
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / "audit.db"
            summary = "The incident window conflicts with the broader alert timeline."
            append(
                db,
                "CASE_RECORD_SAVED",
                incident_id=case_id,
                actor="analyst:test",
                payload={"ai_summary": summary, "ai_verdict": "Needs Review"},
            )
            with patch.object(api, "DB_PATH", db):
                projected = api.case_record(data, case_id)
            self.assertIsNone(projected["record"]["ai_summary"])
            self.assertEqual(projected["record"]["ai_status"], "unavailable")
            self.assertEqual(entries(db)[0]["payload"]["ai_summary"], summary)

    def test_changed_evidence_invalidates_otherwise_valid_saved_run(self):
        root = Path(__file__).resolve().parents[1]
        dataset = Dataset.load(root / "src/real-alerts.json", root / "src/real-timelines.json")
        case_id = dataset.incident_ids()[0]
        with tempfile.TemporaryDirectory() as folder:
            settings = replace(
                load_settings(),
                state_path=Path(folder) / "state.json",
                audit_path=Path(folder) / "audit.jsonl",
            )
            service = TriageService(settings, dataset)
            proposal = {
                "incident_id": case_id,
                "verdict": "Needs Review",
                "reason": "The available connection records need analyst investigation.",
                "evidence_ids": [],
            }
            service.store.save_run(
                {
                    "incident_id": case_id,
                    "status": "ok",
                    "run_id": "fingerprint-test",
                    "proposal": proposal,
                    "evidence_fingerprint": service._evidence_fingerprint(case_id),
                    "investigation": {"tool_calls": [{"tool": "get_incident_details", "ok": True}]},
                }
            )
            self.assertEqual(service.latest(case_id)["latest"]["status"], "ok")
            flow = dataset.evidence_flows(case_id)[-1]
            flow["packet_count"] += 1
            result = service.latest(case_id)["latest"]
            self.assertEqual(result["error"]["code"], "EVIDENCE_INTEGRITY_FAILED")
            self.assertIn(
                "EVIDENCE_CHANGED", [issue["code"] for issue in result["validation"]["issues"]]
            )


if __name__ == "__main__":
    unittest.main()
