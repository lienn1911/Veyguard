"""HTTP attribution regressions: a signed-in user cannot forge the reviewer."""

import io
import json
from unittest.mock import patch

import pytest
from services.api import Handler
from services import api


class Request:
    allowed_origin = Handler.allowed_origin
    route = Handler.route
    request_body = Handler.request_body

    def __init__(self, path, body):
        encoded = json.dumps(body).encode()
        self.path = path
        self.rfile = io.BytesIO(encoded)
        self.headers = {"Content-Type": "application/json", "Content-Length": str(len(encoded))}
        self.response = None

    def require_session(self):
        return {"username": "actual-analyst"}

    def require_csrf(self, session):
        pass  # CSRF behaviour is covered separately by test_auth_local.

    def send_json(self, status, payload, extra_headers=None):
        self.response = status, payload


@pytest.mark.parametrize("action", ["notes", "approval", "record", "ai-decision", "resolve"])
def test_forged_analyst_cannot_write_any_review_action(action):
    data = json.loads(api.DATA.read_text(encoding="utf-8"))
    case_id = data["incidents"][0]["incident_id"]
    path = f"/api/cases/{case_id}/{action}"
    request = Request(
        path,
        {
            "analyst": "forged-person",
            "text": "example",
            "reason": "A sufficiently long reason",
            "confirmed": True,
            "decisions": {},
        },
    )
    with (
        patch.object(api, "add_note") as note,
        patch.object(api, "save_decision") as approve,
        patch.object(api, "resolve_case") as resolve,
    ):
        Handler.do_POST(request)
        assert request.response[0] == 400
        assert "match" in request.response[1]["error"].lower()
        for operation in (note, approve, resolve):
            operation.assert_not_called()


def test_retired_task_completion_cannot_write():
    request = Request("/api/tasks/TASK-TEST/complete", {"analyst": "actual-analyst"})
    with patch.object(api, "append_in_transaction") as audit_write:
        Handler.do_POST(request)
        assert request.response[0] == 410
        audit_write.assert_not_called()
