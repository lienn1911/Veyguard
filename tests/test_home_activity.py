from unittest.mock import patch
from services.api import recent_review_activity
from services.unified_audit import append


def test_recent_home_activity_filters_before_limit_and_keeps_newest_first(tmp_path):
    db = tmp_path / "audit.db"
    expected = []
    for index in range(7):
        event = append(
            db,
            "ANALYST_DECISION",
            incident_id="INC-CURRENT",
            actor="analyst:Reviewer",
            payload={"decision": "APPROVED", "recommendation_id": str(index)},
        )
        expected.append(event["event_id"])
    for index in range(20):
        append(db, "triage.tool_call", incident_id="INC-CURRENT", payload={"tool": str(index)})
    append(db, "CASE_RECORD_SAVED", incident_id="INC-OLD")
    with patch("services.api.DB_PATH", db):
        result = recent_review_activity(["INC-CURRENT"])
        assert [event["event_id"] for event in result] == list(reversed(expected[-5:]))
        assert all(event["actor"] == "analyst:Reviewer" for event in result)
        assert recent_review_activity([]) == []
