"""Recheck the three report examples locally; no model calls or analyst decisions."""

import hashlib, json, sqlite3, statistics
from pathlib import Path
from services.data_store import Dataset
from services.validation import validate_proposal

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def audit_read_only(path):
    with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as db:
        rows = db.execute(
            "SELECT seq,event_id,ts,event,incident_id,actor,payload,prev_hash,hash FROM audit_events ORDER BY seq"
        ).fetchall()
    previous = "0" * 64
    for i, row in enumerate(rows, 1):
        r = dict(
            zip(
                (
                    "seq",
                    "event_id",
                    "ts",
                    "event",
                    "incident_id",
                    "actor",
                    "payload",
                    "prev_hash",
                    "hash",
                ),
                row,
            )
        )
        r["payload"] = json.loads(r["payload"])
        canonical = json.dumps(
            {k: v for k, v in r.items() if k != "hash"},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        )
        assert (
            r["seq"] == i
            and r["prev_hash"] == previous
            and r["hash"] == hashlib.sha256(canonical.encode()).hexdigest()
        )
        previous = r["hash"]
    return {"valid": True, "events": len(rows)}


def main():
    dataset = Dataset.load(ROOT / "src/real-alerts.json", ROOT / "src/real-timelines.json")
    sources = [
        (
            "INC-F4ED19468E0C",
            ROOT / "evaluation/live-joint-acceptance-20261024-state/INC-F4ED19468E0C-1/state.json",
        ),
        (
            "INC-AC3AA3CF2A0C",
            ROOT / "evaluation/live-joint-acceptance-20261024-state/INC-AC3AA3CF2A0C-1/state.json",
        ),
        ("INC-A787E11F2A22", ROOT / "data/final-live-acceptance-s7mv0k6_/state.json"),
    ]
    cases = []
    for case, path in sources:
        content = json.loads(path.read_text(encoding="utf-8"))
        stored = content["incidents"][case]
        run = stored.get("latest") or stored["runs"][-1]
        incident = dataset.require(case).incident
        numbers = dataset.canonical_statistic_numbers(case)
        calls = run["investigation"]["tool_calls"]
        check = validate_proposal(
            run.get("proposal") or run,
            incident_id=case,
            evidence_ids=dataset.evidence_ids(case),
            evidence_numbers=numbers,
            canonical_numbers=numbers,
            tool_call_count=len(calls),
            alert_types_by_id={a["alert_id"]: a["type"] for a in dataset.agent_alerts(case)},
            incident=incident,
            case_alerts=dataset.agent_alerts(case),
        )
        assert check.ok, check.as_dict()
        assert run["mode"] == "live" and run["provider"] != "mock" and run["status"] == "ok"
        audit = audit_read_only(path.with_name("audit.db"))
        cases.append(
            {
                "incident_id": case,
                "category": incident["type"],
                "window_start": incident["window_start"],
                "window_end": incident["window_end"],
                "alert_count": len(incident["alert_ids"]),
                "flow_count": incident["flow_count"],
                "run_id": run["run_id"],
                "completed_at": run["completed_at"],
                "duration_seconds": run["duration_ms"] / 1000,
                "tool_calls": len(calls),
                "citation_count": len(run["evidence_ids"]),
                "verdict": run["verdict"],
                "reason": run["reason"],
                "limitations": run["limitations"],
                "next_steps": run["next_steps"],
                "current_validation": check.as_dict(),
                "audit": audit,
                "state_path": str(path.relative_to(ROOT)),
                "state_sha256": digest(path),
            }
        )
    result = {
        "kind": "three-historical-live-case-examples-revalidated",
        "external_model_calls": 0,
        "human_time_savings_measured": False,
        "independent_accuracy_evaluation": False,
        "limitations": "Selected development examples collected at different times and prompt versions. Stored outputs rechecked with current validation and evidence. Duration is historical agent latency, excludes human review, and is not a controlled benchmark or proof of time savings.",
        "inputs": {
            str(p.relative_to(ROOT)): digest(p)
            for p in (
                ROOT / "src/real-alerts.json",
                ROOT / "src/real-timelines.json",
                ROOT / "services/validation.py",
            )
        },
        "cases": cases,
        "summary": {
            "cases": len(cases),
            "validation_passes": len(cases),
            "median_agent_seconds": statistics.median(x["duration_seconds"] for x in cases),
        },
    }
    output = ROOT / "evaluation/report-three-case-evidence-20261024.json"
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "summary": result["summary"],
                "cases": [
                    {
                        k: x[k]
                        for k in (
                            "incident_id",
                            "category",
                            "duration_seconds",
                            "tool_calls",
                            "citation_count",
                            "verdict",
                            "audit",
                        )
                    }
                    for x in cases
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
