"""Review order is evidence-based, separate from risk, and only humans override it."""

import copy
import json
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest
from services import api
from services.review_priority import (
    suggested_priority,
    effective_priority,
    save_priority,
    latest_overrides,
)
from services.unified_audit import entries, verify


def fixture_case(n=3, flow_count=6000, ports=100):
    alerts = [
        {
            "alert_id": f"ALT-{i}",
            "flow_count": flow_count,
            "destination_port_count": ports,
            "source_ip": "192.0.2.1",
            "dataset_labels": {"BENIGN": flow_count},
        }
        for i in range(n)
    ]
    incident = {
        "incident_id": "INC-PRIORITY001",
        "alert_ids": [row["alert_id"] for row in alerts],
        "flow_count": n * flow_count,
        "window_start": "2026-01-01T00:00:00",
        "window_end": f"2026-01-01T00:{n - 1:02d}:00",
    }
    return {"alerts": alerts, "incidents": [incident]}, incident


@pytest.mark.parametrize(
    "n,flows,ports,expected",
    [(1, 100, 1, "Low"), (3, 6000, 100, "Medium"), (10, 10000, 250, "High")],
)
def test_explained_thresholds(n, flows, ports, expected):
    data, case = fixture_case(n, flows, ports)
    result = suggested_priority(data, case)
    assert result["level"] == expected
    assert result["reasons"]
    assert result["source"] == "rules"


def test_rate_includes_last_minute():
    data, case = fixture_case(2, 3000, 1)
    assert suggested_priority(data, case)["score"] == 0


@pytest.mark.parametrize("value", [None, -1, float("nan"), True, "6000"])
def test_missing_or_invalid_measurement_is_not_low(value):
    data, case = fixture_case()
    case["flow_count"] = value
    assert suggested_priority(data, case)["level"] == "Not assessed"


def test_missing_alert_and_invalid_time_are_not_assessed():
    data, case = fixture_case()
    data["alerts"].pop()
    assert suggested_priority(data, case)["score"] is None
    data, case = fixture_case()
    case["window_end"] = "invalid"
    assert suggested_priority(data, case)["level"] == "Not assessed"


def test_ai_state_and_ground_truth_cannot_downgrade_review_order():
    data, case = fixture_case(10, 10000, 250)
    baseline = suggested_priority(data, case)
    for status in ("unavailable", "pending", "Needs Review", "Likely Benign", "Likely Attack"):
        modified = copy.deepcopy(data)
        modified["ai_status"] = status
        for alert in modified["alerts"]:
            alert["dataset_labels"] = {"PortScan": 1}
            alert["verdict"] = status
        assert suggested_priority(modified, case) == baseline


def test_manual_override_and_reset_are_append_only(tmp_path):
    data, case = fixture_case()
    db = tmp_path / "audit.db"
    manual = save_priority(
        data,
        case["incident_id"],
        "High",
        "Critical asset needs immediate review",
        "human",
        True,
        db,
    )
    assert manual["source"] == "analyst"
    assert manual["level"] == "High"
    assert manual["updated_at"]
    with sqlite3.connect(db) as con:
        restored = effective_priority(data, case, latest_overrides(con)[case["incident_id"]])
    assert restored == manual
    reset = save_priority(
        data,
        case["incident_id"],
        "automatic",
        "Reviewed evidence and restored the rule suggestion",
        "human",
        True,
        db,
    )
    assert reset["level"] == "Medium" and reset["source"] == "rules"
    events = entries(db)
    assert len(events) == 2
    assert events[-1]["payload"]["previous_level"] == "High"
    assert events[-1]["payload"]["level"] is None
    assert all(row["actor"] == "analyst:human" for row in events)
    assert verify(db)["ok"]


@pytest.mark.parametrize(
    "level,reason,confirmation",
    [
        ("Critical", "valid long reason", True),
        ("Low", "short", True),
        ("Low", "valid long reason", False),
        ("Low", "valid long reason", "true"),
    ],
)
def test_invalid_changes_do_not_write(tmp_path, level, reason, confirmation):
    data, case = fixture_case()
    db = tmp_path / "audit.db"
    with pytest.raises(ValueError):
        save_priority(data, case["incident_id"], level, reason, "human", confirmation, db)
    assert not db.exists()


def test_http_priority_binds_authenticated_reviewer(tmp_path):
    from tests.test_reviewer_attribution import Request

    data, case = fixture_case()
    source = tmp_path / "alerts.json"
    source.write_text(json.dumps(data))
    with patch.object(api, "DATA", source), patch.object(api, "DB_PATH", tmp_path / "audit.db"):
        forged = Request(
            f"/api/cases/{case['incident_id']}/priority",
            {
                "analyst": "someone-else",
                "level": "High",
                "reason": "Test reason long enough",
                "confirmed": True,
            },
        )
        api.Handler.do_POST(forged)
        assert forged.response[0] == 400
        real = Request(
            f"/api/cases/{case['incident_id']}/priority",
            {
                "analyst": "actual-analyst",
                "level": "High",
                "reason": "Test reason long enough",
                "confirmed": True,
            },
        )
        api.Handler.do_POST(real)
        assert real.response[0] == 200
        assert real.response[1]["review_priority"]["analyst"] == "actual-analyst"
