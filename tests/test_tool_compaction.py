"""Compact model messages must retain every citable alert and its measurements."""

import unittest
import json
from pathlib import Path

from services.data_store import Dataset
from services.tools import ToolRegistry, ToolOutcome, bound_outcome
from services.triage import MAX_TOOL_RESULT_CHARS, Trace


class ToolCompaction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.dataset = Dataset.load(
            root / "src" / "real-alerts.json", root / "src" / "real-timelines.json"
        )

    def test_every_alert_remains_available_and_payload_is_bounded(self):
        for incident_id in self.dataset.incident_ids():
            with self.subTest(incident_id=incident_id):
                registry = ToolRegistry(self.dataset, incident_id)
                related = registry.execute("get_related_alerts", {"incident_id": incident_id})
                self.assertTrue(related.ok)
                expected = [
                    self.dataset.alerts[alert_id]
                    for alert_id in self.dataset.incidents[incident_id]["alert_ids"]
                ]
                self.assertEqual(
                    [item["alert_id"] for item in related.data["alerts"]],
                    [item["alert_id"] for item in expected],
                )
                self.assertEqual(
                    [item["flow_count"] for item in related.data["alerts"]],
                    [item["flow_count"] for item in expected],
                )
                self.assertEqual(
                    [item["rule_basis"] for item in related.data["alerts"]],
                    [item["rule_basis"] for item in expected],
                )
                # Long investigation windows contain 61 distinct alerts;
                # retain their citable IDs while bounding growth per alert.
                self.assertLess(len(related.as_text()), max(8000, 250 * len(expected)))
                statistics = registry.execute(
                    "get_incident_statistics", {"incident_id": incident_id}
                )
                self.assertEqual(
                    statistics.data["group_totals"]["flows"],
                    self.dataset.incidents[incident_id]["flow_count"],
                )
                self.assertNotIn("alert_totals", statistics.data)

    def test_long_alerts_can_be_retrieved_in_bounded_json_pages(self):
        case_id = max(
            self.dataset.incident_ids(),
            key=lambda key: len(self.dataset.incidents[key]["alert_ids"]),
        )
        registry = ToolRegistry(self.dataset, case_id)
        expected = self.dataset.incidents[case_id]["alert_ids"]
        offset, collected = 0, []
        for _ in range(len(expected)):
            page = bound_outcome(
                registry.execute(
                    "get_related_alerts",
                    {
                        "incident_id": case_id,
                        "offset": offset,
                    },
                ),
                MAX_TOOL_RESULT_CHARS,
            )
            self.assertTrue(page.ok)
            self.assertLessEqual(len(page.as_text()), MAX_TOOL_RESULT_CHARS)
            payload = json.loads(page.as_text())["data"]
            collected.extend(row["alert_id"] for row in payload["alerts"])
            if not payload.get("truncated"):
                break
            self.assertGreater(payload["next_offset"], offset)
            offset = payload["next_offset"]
        self.assertEqual(collected, expected)

    def test_omitted_records_do_not_enter_validation_trace(self):
        case_id = max(
            self.dataset.incident_ids(),
            key=lambda key: len(self.dataset.incidents[key]["alert_ids"]),
        )
        outcome = ToolRegistry(self.dataset, case_id).execute(
            "get_related_alerts", {"incident_id": case_id}
        )
        bounded = bound_outcome(outcome, MAX_TOOL_RESULT_CHARS)
        self.assertTrue(bounded.data["truncated"])
        trace = Trace()
        trace.add(1, bounded, 0)
        omitted = outcome.data["alerts"][-1]["alert_id"]
        self.assertNotIn(omitted, json.dumps(trace.payloads))
        self.assertEqual(
            len(outcome.data["alerts"]), len(self.dataset.incidents[case_id]["alert_ids"])
        )

    def test_oversized_single_record_returns_valid_error_not_partial_json(self):
        outcome = ToolOutcome(
            "get_related_alerts", True, data={"alerts": [{"alert_id": "X" * 20000}]}
        )
        bounded = bound_outcome(outcome, MAX_TOOL_RESULT_CHARS)
        self.assertFalse(json.loads(bounded.as_text())["ok"])
        self.assertLessEqual(len(bounded.as_text()), MAX_TOOL_RESULT_CHARS)

    def test_alert_offset_cannot_be_negative_or_boolean(self):
        registry = ToolRegistry(self.dataset, self.dataset.incident_ids()[0])
        for offset in (-1, True, "10"):
            self.assertFalse(
                registry.execute(
                    "get_related_alerts",
                    {"incident_id": registry.active_incident_id, "offset": offset},
                ).ok
            )


if __name__ == "__main__":
    unittest.main()
