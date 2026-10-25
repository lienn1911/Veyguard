"""Evidence-bound next-step recommendations from the AI investigation."""

import json
import unittest
from pathlib import Path

from services.recommendations import annotate_ai_next_steps, generate_recommendations
from services.timeline import reconstruct_timelines
from services.validation import validate_proposal


DATA = json.loads(
    (Path(__file__).resolve().parents[1] / "src" / "real-alerts.json").read_text(encoding="utf-8")
)
CASE = DATA["incidents"][0]
CASE_ID = CASE["incident_id"]
FLOW_ID = CASE["evidence_sample_ids"][0]


def proposal(action="REVIEW_NETWORK_FLOWS", evidence_id=FLOW_ID):
    return {
        "incident_id": CASE_ID,
        "verdict": "Needs Review",
        "confidence": "low",
        "reason": "Observed linked traffic requires further analyst investigation.",
        "evidence_ids": [FLOW_ID],
        "findings": [],
        "next_steps": [
            {
                "action": action,
                "reason": "Inspect the linked flow evidence before deciding.",
                "evidence_ids": [evidence_id],
            }
        ],
        "limitations": "",
    }


def validate(value, seen=None):
    return validate_proposal(
        value,
        incident_id=CASE_ID,
        evidence_ids={FLOW_ID: "flow"},
        evidence_numbers=set(),
        tool_call_count=1,
        seen_evidence_ids=seen,
    )


class AINextStepTests(unittest.TestCase):
    def test_ai_step_is_evidence_bound_and_shown_first(self):
        report = validate(proposal(), {FLOW_ID})
        self.assertTrue(report.ok, report.issue_messages())
        checks = annotate_ai_next_steps(
            generate_recommendations(DATA, CASE_ID), report.proposal["next_steps"]
        )
        self.assertEqual(checks[0]["action"], "REVIEW_NETWORK_FLOWS")
        self.assertTrue(checks[0]["ai_suggested"])
        self.assertEqual(checks[0]["ai_evidence_ids"], [FLOW_ID])
        self.assertEqual(len(checks), len(generate_recommendations(DATA, CASE_ID)))

    def test_prohibited_action_and_unseen_evidence_are_rejected(self):
        self.assertFalse(validate(proposal("CLOSE_INCIDENT"), {FLOW_ID}).ok)
        self.assertFalse(validate(proposal(), set()).ok)

    def test_timeline_reconstructs_ordered_evidence_events(self):
        timeline = next(
            item
            for item in reconstruct_timelines(DATA)["timelines"]
            if item["incident_id"] == CASE_ID
        )
        self.assertEqual(
            timeline["events"],
            sorted(
                timeline["events"],
                key=lambda item: (
                    item["timestamp"],
                    item.get("source_row", float("inf")),
                    item["evidence_id"],
                ),
            ),
        )
        self.assertEqual(
            {event["evidence_id"] for event in timeline["events"]},
            set(CASE["alert_ids"] + CASE["evidence_sample_ids"]),
        )


if __name__ == "__main__":
    unittest.main()
