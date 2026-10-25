"""Explicit human resolution is required even after a record has been saved."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from services import api, recommendations
from services.unified_audit import append, entries, verify


def test_resolution_requires_saved_record_and_exact_confirmation():
    data = json.loads(api.DATA.read_text(encoding="utf-8"))
    case_id = data["incidents"][0]["incident_id"]
    with tempfile.TemporaryDirectory(dir=api.ROOT / "data") as folder:
        db = Path(folder) / "audit.db"
        with (
            patch.object(api, "DB_PATH", db),
            patch.object(api, "init_db", lambda: recommendations.init_db(db)),
        ):
            with pytest.raises(ValueError, match="Save the case record"):
                api.resolve_case(data, case_id, "human", "Evidence checked and explained", True)
            append(
                db,
                "CASE_RECORD_SAVED",
                incident_id=case_id,
                actor="analyst:human",
                payload={"case_summary": "isolated fixture"},
            )
            for confirmation in (False, None, 1, "true"):
                with pytest.raises(ValueError, match="Explicit analyst confirmation"):
                    api.resolve_case(
                        data, case_id, "human", "Evidence checked and explained", confirmation
                    )
            with pytest.raises(ValueError, match="10-1000"):
                api.resolve_case(data, case_id, "human", "short", True)
            assert not any(row["event"] == "CASE_RESOLVED" for row in entries(db))
            result = api.resolve_case(
                data, case_id, "human", "Evidence checked and explained", True
            )
            repeated = api.resolve_case(
                data, case_id, "human", "Evidence checked and explained", True
            )
            assert result["event_id"] == repeated["event_id"]
            resolved = [row for row in entries(db) if row["event"] == "CASE_RESOLVED"]
            assert len(resolved) == 1
            assert resolved[0]["actor"] == "analyst:human"
            assert verify(db)["ok"]
