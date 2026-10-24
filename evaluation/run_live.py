"""Run isolated, evidence-bound AI investigations against a frozen case manifest.

This runner never changes the application's saved triage results or analyst
decisions. A development smoke manifest checks wiring, not model accuracy.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import statistics
import uuid
from collections import Counter
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from services.config import load_settings
from services.data_store import Dataset
from services.triage import TriageService

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "evaluation" / "development_workflow_20261024.json"
DEFAULT_ALERTS = ROOT / "src" / "real-alerts.json"
DEFAULT_TIMELINES = ROOT / "src" / "real-timelines.json"
PROMPT_FILE = ROOT / "services" / "prompts.py"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def check_manifest(manifest: dict, alerts_path: Path, timelines_path: Path) -> Dataset:
    if manifest.get("kind") not in {"development-smoke-only", "independent-ai-holdout"}:
        raise ValueError("Manifest kind must be development-smoke-only or independent-ai-holdout")
    for key, path in (
        ("alerts_sha256", alerts_path),
        ("timelines_sha256", timelines_path),
        ("prompt_sha256", PROMPT_FILE),
    ):
        if manifest.get(key) != sha256(path):
            raise ValueError(f"{key} does not match {path}; freeze a new manifest before running")
    dataset = Dataset.load(alerts_path, timelines_path)
    case_ids = manifest.get("case_ids")
    if (not isinstance(case_ids, list) or not case_ids
            or any(not isinstance(case_id, str) for case_id in case_ids)
            or len(case_ids) != len(set(case_ids))):
        raise ValueError("Manifest needs a nonempty list of unique case_ids")
    if any(case_id not in dataset.incidents for case_id in case_ids):
        raise ValueError("Manifest cites a case absent from the supplied alert data")
    if manifest["kind"] == "independent-ai-holdout":
        labels = manifest.get("reference_labels")
        if (not isinstance(labels, dict) or set(labels) != set(case_ids)
                or any(value not in ("Attack", "Benign", "Ambiguous") for value in labels.values())):
            raise ValueError("Independent holdout needs an Attack, Benign, or Ambiguous reference label for every case")
        digest = re.compile(r"[0-9a-fA-F]{64}\Z")
        source_hash = manifest.get("source_archive_sha256")
        development_hashes = manifest.get("development_archive_sha256")
        if (not isinstance(source_hash, str) or not digest.fullmatch(source_hash)
                or not isinstance(development_hashes, list) or not development_hashes
                or any(not isinstance(value, str) or not digest.fullmatch(value) for value in development_hashes)
                or source_hash.lower() in {value.lower() for value in development_hashes}):
            raise ValueError("Independent holdout needs a source archive hash distinct from all declared development archives")
        if not isinstance(manifest.get("reviewed_by"), str) or not manifest["reviewed_by"].strip():
            raise ValueError("Independent holdout needs a named reviewer for prior-exposure and label checks")
        try:
            datetime.fromisoformat(manifest["frozen_at"].replace("Z", "+00:00"))
        except (KeyError, AttributeError, ValueError) as error:
            raise ValueError("Independent holdout needs an ISO frozen_at timestamp") from error
    return dataset


def summarize(runs: list[dict], manifest: dict) -> dict:
    complete = [item for item in runs if item["status"] == "ok"]
    output = {
        "cases": len(manifest["case_ids"]),
        "runs": len(runs),
        "status_counts": dict(Counter(item["status"] for item in runs)),
        "verdict_counts": dict(Counter(item["verdict"] for item in complete)),
        "median_tool_calls": statistics.median(item["tool_calls"] for item in runs) if runs else None,
        "median_duration_ms": statistics.median(item["duration_ms"] for item in runs) if runs else None,
        "invalid_proposals": sum(item["status"] == "rejected" for item in runs),
        "invalid_proposal_rate": (sum(item["status"] == "rejected" for item in runs) / len(runs)) if runs else None,
        "evidence_validation_failures": sum(
            any(issue.get("code") in {"UNKNOWN_EVIDENCE", "MISSING_EVIDENCE", "UNSUPPORTED_STATISTIC"}
                for issue in item["validation_issues"]) for item in runs
        ),
    }
    if manifest["kind"] == "independent-ai-holdout":
        labels = manifest["reference_labels"]
        attack = [item for item in runs if labels[item["incident_id"]] == "Attack"]
        benign = [item for item in runs if labels[item["incident_id"]] == "Benign"]
        output["reference_scoring"] = {
            "unit": "case-run; repeats of one case are correlated and must not be counted as independent cases",
            "attack_runs": len(attack),
            "attack_called_likely_benign": sum(item["verdict"] == "Likely Benign" and item["status"] == "ok" for item in attack),
            "benign_runs": len(benign),
            "benign_called_likely_attack": sum(item["verdict"] == "Likely Attack" and item["status"] == "ok" for item in benign),
            "needs_review_runs": sum(item["verdict"] == "Needs Review" and item["status"] == "ok" for item in runs),
        }
    return output


def run(manifest: dict, dataset: Dataset, settings, runs_per_case: int, output_path: Path) -> dict:
    if manifest["kind"] == "independent-ai-holdout" and settings.is_mock:
        raise ValueError("A mock provider cannot produce independent AI performance results")
    run_root = output_path.parent / (output_path.stem + "-state")
    run_root.mkdir(parents=True, exist_ok=False)
    results = []
    for case_id in manifest["case_ids"]:
        for repetition in range(1, runs_per_case + 1):
            directory = run_root / f"{case_id}-{repetition}"
            directory.mkdir()
            isolated = replace(settings, state_path=directory / "state.json", audit_path=directory / "audit.db")
            service = TriageService(isolated, dataset)
            result = service.investigate(case_id)
            trace = result.get("investigation") or {}
            results.append({
                "incident_id": case_id,
                "repetition": repetition,
                "run_id": result["run_id"],
                "provider": result["provider"],
                "model": result["model"],
                "status": result["status"],
                "verdict": result.get("verdict"),
                "evidence_ids": result.get("evidence_ids") or [],
                "technique_mappings": result.get("technique_mappings") or [],
                "tool_calls": len(trace.get("tool_calls") or []),
                "tool_sequence": [call.get("tool") for call in trace.get("tool_calls") or []],
                "tool_errors": trace.get("tool_errors", 0),
                "duration_ms": result.get("duration_ms"),
                "validation_issues": (result.get("validation") or {}).get("issues") or [],
                "error_code": (result.get("error") or {}).get("code"),
                "audit_verified": service.audit.verify()["ok"],
                "analyst_decision": "pending",
            })
    report = {
        "kind": manifest["kind"],
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "manifest_sha256": hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest(),
        "inputs": {key: manifest[key] for key in ("alerts_sha256", "timelines_sha256", "prompt_sha256")},
        "pipeline_sha256": {name: sha256(ROOT / 'services' / name) for name in (
            'tools.py', 'triage.py', 'validation.py', 'safety.py', 'guardrail_bridge.py',
            'guardrails.py', 'data_store.py', 'providers/codex_provider.py')},
        "label_source": manifest.get('label_source'),
        "reference_review": manifest.get('reviewed_by'),
        "limitations": manifest.get('limitations', manifest.get('note')),
        "provider": settings.provider,
        "model": settings.model,
        "temperature": settings.temperature,
        "max_steps": settings.max_steps,
        "max_tool_calls": settings.max_tool_calls,
        "runs_per_case": runs_per_case,
        "summary": summarize(results, manifest),
        "runs": results,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--alerts", type=Path, default=DEFAULT_ALERTS)
    parser.add_argument("--timelines", type=Path, default=DEFAULT_TIMELINES)
    parser.add_argument("--check", action="store_true", help="verify inputs and provider without a model call")
    parser.add_argument("--runs", type=int, default=1, help="investigations per case (1-5)")
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    if not 1 <= args.runs <= 5:
        parser.error("--runs must be between 1 and 5")
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        dataset = check_manifest(manifest, args.alerts, args.timelines)
        settings = load_settings()
        if not settings.ready:
            raise ValueError(settings.blocking_reason() or "AI provider is not configured")
        if manifest["kind"] == "independent-ai-holdout" and settings.is_mock:
            raise ValueError("A mock provider cannot produce independent AI performance results")
        if args.check:
            print(json.dumps({"ok": True, "kind": manifest["kind"], "cases": len(manifest["case_ids"]),
                              "provider": settings.provider, "model": settings.model,
                              "note": "Configuration check only; no model request or independence claim"}))
            return
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output = args.output or ROOT / "data" / "evaluation" / f"ai-{stamp}-{uuid.uuid4().hex[:8]}.json"
        if output.exists():
            raise ValueError("Output path already exists; evaluation reports are immutable")
        report = run(manifest, dataset, settings, args.runs, output)
        print(json.dumps({"output": str(output), "summary": report["summary"]}))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
