"""Register the verified live demonstration run, without importing simulated review.

The default command is a read-only preflight. Pass --apply to register the
already completed AI run in the normal case store and append its provenance to
the shared audit trail. No model call is made.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import replace
from pathlib import Path

from services.config import load_settings
from services.data_store import Dataset
from services.triage import TriageService
from services.unified_audit import verify


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "evaluation" / "final-live-workflow-20261024.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(*, apply: bool = False) -> dict:
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    if (
        not report.get("passed")
        or not report.get("production_unchanged")
        or report.get("provider") != "codex"
    ):
        raise ValueError("The isolated live acceptance did not pass its integrity checks.")
    for name, expected in report["inputs"].items():
        if sha256(ROOT / name) != expected:
            raise ValueError(f"Acceptance input has changed: {name}")

    settings = load_settings()
    if (settings.provider, settings.model) != (report["provider"], report["model"]):
        raise ValueError("The active AI provider differs from the verified run.")
    dataset = Dataset.load(settings.alerts_path, settings.timelines_path)
    source = ROOT / report["run_artifacts"] / "state.json"
    run = json.loads(
        (ROOT / report["run_artifacts"] / "live-result.json").read_text(encoding="utf-8")
    )
    incident_id = report["incident_id"]
    if (
        run.get("run_id") != report["run_id"]
        or run.get("incident_id") != incident_id
        or run.get("status") != "ok"
    ):
        raise ValueError("The saved run does not match the verified acceptance report.")
    isolated = TriageService(replace(settings, state_path=source), dataset)
    source_result = isolated.latest(incident_id)
    if (
        source_result["latest"]["status"] != "ok"
        or source_result["latest"]["run_id"] != run["run_id"]
    ):
        raise ValueError("The saved run failed current evidence validation.")

    target = TriageService(settings, dataset)
    existing = target.store.get(incident_id) or {}
    if any(item.get("run_id") == run["run_id"] for item in existing.get("runs", [])):
        return {"status": "already_registered", "incident_id": incident_id, "run_id": run["run_id"]}
    if (existing.get("decision") or {}).get("status") not in (None, "pending"):
        raise ValueError("A formal analyst decision exists; do not replace its AI run.")
    if not apply:
        return {
            "status": "ready_to_register",
            "incident_id": incident_id,
            "run_id": run["run_id"],
            "model_call": False,
            "simulated_approval_imported": False,
        }

    target.store.save_run(run)
    target.audit.append(
        "triage.verified_run_registered",
        incident_id=incident_id,
        actor="system:demo-import",
        payload={
            "run_id": run["run_id"],
            "source": str(source.relative_to(ROOT)),
            "acceptance_report_sha256": sha256(REPORT),
            "evidence_fingerprint": run["evidence_fingerprint"],
            "analyst_decision_imported": False,
        },
    )
    if (
        target.latest(incident_id)["latest"]["status"] != "ok"
        or not verify(target.audit.path)["ok"]
    ):
        raise RuntimeError("Registration was written but post-write integrity verification failed.")
    return {
        "status": "registered",
        "incident_id": incident_id,
        "run_id": run["run_id"],
        "audit_valid": True,
        "model_call": False,
        "simulated_approval_imported": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    print(json.dumps(run(apply=parser.parse_args().apply), indent=2))
