import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from services import api
from services.unified_audit import entries, verify


class CaseRecordTests(unittest.TestCase):
    def test_draft_explains_unavailable_ai(self):
        data = json.loads(api.DATA.read_text(encoding="utf-8"))
        incident_id = data["incidents"][0]["incident_id"]
        assessment = {
            "status": "unavailable",
            "assessment": None,
            "error": {"message": "Provider quota reached."},
        }
        with tempfile.TemporaryDirectory(dir=api.ROOT / "data") as folder:
            db_path = Path(folder) / "audit.db"
            with (
                patch.object(api, "DB_PATH", db_path),
                patch.object(api, "ai_assessment", return_value=assessment),
            ):
                record = api.case_record(data, incident_id)["record"]
                self.assertEqual(record["ai_status"], "unavailable")
                self.assertEqual(record["ai_error"], "Provider quota reached.")
                self.assertIsNone(record["ai_verdict"])

    def test_saves_once_without_optional_step_decisions(self):
        data = json.loads(api.DATA.read_text(encoding="utf-8"))
        incident_id = data["incidents"][0]["incident_id"]
        with tempfile.TemporaryDirectory(dir=api.ROOT / "data") as folder:
            db_path = Path(folder) / "audit.db"
            assessment = {
                "status": "ready",
                "assessment": {
                    "summary": "Observed high flow volume in the linked alerts.",
                    "verdict": "Likely Attack",
                    "run_id": "RUN-TEST",
                },
                "decision": {"status": "pending"},
            }
            with (
                patch.object(api, "DB_PATH", db_path),
                patch.object(api, "ai_assessment", return_value=assessment),
            ):
                self.assertEqual(api.case_record(data, incident_id)["status"], "ready")
                first = api.save_case_record(data, incident_id, "analyst")
                second = api.save_case_record(data, incident_id, "analyst")
                self.assertEqual(first["event_id"], second["event_id"])
                self.assertEqual(first["record"]["ai_summary"], assessment["assessment"]["summary"])
                self.assertEqual(
                    sum(item["event"] == "CASE_RECORD_SAVED" for item in entries(db_path)), 1
                )
                self.assertTrue(verify(db_path)["ok"])


if __name__ == "__main__":
    unittest.main()
