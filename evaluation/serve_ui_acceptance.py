"""Serve the production build with isolated analyst state for manual UI QA.
No model calls are allowed in this server. Historical results are read-time revalidated.
"""

import os, json, shutil, mimetypes, sys
from pathlib import Path
from dataclasses import replace
from urllib.parse import urlsplit, unquote

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = "--fixture" in sys.argv
PORT = int(
    next(
        (arg.split("=", 1)[1] for arg in sys.argv if arg.startswith("--port=")),
        "8787" if FIXTURE else "8786",
    )
)
WORK = (
    ROOT
    / "data"
    / os.environ.get("SOC_TRIAGE_UI_WORKDIR", "final-ui-fixture" if FIXTURE else "final-ui-test")
)
WORK.mkdir(exist_ok=True)
os.environ["SOC_TRIAGE_DB_PATH"] = str(WORK / "audit.db")
os.environ["SOC_TRIAGE_EXTRA_ORIGINS"] = "http://127.0.0.1:" + str(PORT)
from services import api, auth
from services.config import load_settings
from services.triage import TriageService
from services.data_store import Dataset

settings = load_settings()
source = ROOT / "evaluation/final-workflow-20261024/state.json"
if not source.exists():
    source = settings.state_path
shutil.copyfile(source, WORK / "state.json")
isolated = replace(settings, state_path=WORK / "state.json", audit_path=WORK / "audit.jsonl")
api._ai_service = TriageService(
    isolated,
    Dataset.load(settings.alerts_path, settings.timelines_path),
    provider_factory=lambda: (_ for _ in ()).throw(
        RuntimeError("UI test server does not call external models")
    ),
)
if FIXTURE:
    from services.providers.mock_provider import MockProvider

    class PlanFixture(MockProvider):
        def complete(self, *args, **kwargs):
            turn = super().complete(*args, **kwargs)
            if turn.text and turn.text.lstrip().startswith("{"):
                proposal = json.loads(turn.text)
                flow_id = next(
                    value for value in proposal["evidence_ids"] if value.startswith("FLOW-")
                )
                proposal["next_steps"] = [
                    {
                        "action": "REVIEW_NETWORK_FLOWS",
                        "reason": "Offline UI fixture: inspect these linked connection records before drawing a conclusion.",
                        "evidence_ids": [flow_id],
                    }
                ]
                turn = replace(turn, text=json.dumps(proposal))
            return turn

    api._ai_service = TriageService(
        replace(isolated, provider="mock"),
        Dataset.load(settings.alerts_path, settings.timelines_path),
        provider_factory=PlanFixture,
    )
    fixture_case = "INC-A787E11F2A22"
    fixture_run = api._ai_service.investigate(fixture_case)
    assert fixture_run["status"] == "ok", fixture_run.get("error")
    original_assessment = api.ai_assessment

    def fixture_assessment(incident_id):
        if incident_id != fixture_case:
            return original_assessment(incident_id)
        stored = api._ai_service.latest(incident_id)
        r = stored["latest"]
        # Production UI's ready-state contract is exercised with an explicitly labelled
        # offline fixture. The stored provider remains mock; this is never a live AI result.
        return {
            "status": "ready",
            "mode": "live",
            "provider": "OFFLINE UI FIXTURE",
            "run_id": r["run_id"],
            "decision": stored["decision"],
            "investigation": r["investigation"],
            "assessment": {
                **r["proposal"],
                "summary": r["reason"],
                "run_id": r["run_id"],
                "requires_confirmation": r["requires_confirmation"],
            },
        }

    api.ai_assessment = fixture_assessment
auth.AUTH_FILE = WORK / "account.json"
auth.USERNAME = "AcceptanceTester"
if not auth.AUTH_FILE.exists():
    auth._write_account(
        {
            "username": auth.USERNAME,
            "password_hash": auth._hash_password("Local-QA-only-2026!"),
            "password_version": 1,
        }
    )


class Handler(api.Handler):
    def do_GET(self):
        path = urlsplit(self.path).path
        if path.startswith("/api/"):
            return super().do_GET()
        candidate = (ROOT / "dist" / unquote(path).lstrip("/")).resolve()
        base = (ROOT / "dist").resolve()
        if not candidate.is_relative_to(base):
            return self.send_error(404)
        if not candidate.is_file():
            candidate = base / "index.html"
        body = candidate.read_bytes()
        if candidate.name == "index.html":
            body = body.replace(
                b"<body>",
                b'<body><div style="position:fixed;z-index:99999;bottom:0;left:0;right:0;text-align:center;background:#fff3cd;color:#59440a;font:12px sans-serif;padding:5px">OFFLINE UI TEST - simulated AI fixture when enabled - no production decisions or external model calls</div>',
            )
        self.send_response(200)
        self.send_header(
            "Content-Type", mimetypes.guess_type(candidate)[0] or "application/octet-stream"
        )
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if urlsplit(self.path).path in (
            "/api/ai/settings",
            "/api/ai/auto-analysis",
        ) or self.path.endswith("/ai-assessment"):
            return self.send_json(
                403,
                {
                    "error": "External model calls and settings changes are disabled in UI acceptance mode."
                },
            )
        return super().do_POST()


if __name__ == "__main__":
    print(
        "Isolated UI acceptance server http://127.0.0.1:" + str(PORT) + " fixture=" + str(FIXTURE),
        flush=True,
    )
    api.ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
