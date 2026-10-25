"""Evidence-level joint checks without consulting AI or changing runtime state."""

import json
from pathlib import Path
from services.alerts import DISPLAY_ATTACK_TYPES, DETECTION_RULES, group_alerts
from services.timeline import reconstruct_timelines
from services.evaluate_cidds_holdout import sha256


def check():
    root = Path(__file__).resolve().parents[1]
    data = json.loads((root / "src/real-alerts.json").read_text(encoding="utf-8"))
    stored = json.loads((root / "src/real-timelines.json").read_text(encoding="utf-8"))
    alerts = {row["alert_id"]: row for row in data["alerts"]}
    flows = {row["flow_id"]: row for row in data["flows"]}
    timelines = {row["incident_id"]: row for row in stored["timelines"]}
    problems = []
    events = 0
    for case in data["incidents"]:
        keys = []
        allowed = set(case["alert_ids"] + case["evidence_sample_ids"])
        for event in timelines.get(case["incident_id"], {}).get("events", []):
            events += 1
            identifier = event["evidence_id"]
            evidence = (alerts if event["record_type"] == "alert" else flows).get(identifier)
            if (
                identifier not in allowed
                or evidence is None
                or event["timestamp"] != evidence["timestamp"]
            ):
                problems.append("Untraceable event: " + identifier)
            if event["record_type"] == "flow" and (
                event.get("source_file"),
                event.get("source_row"),
            ) != (evidence.get("source_file"), evidence.get("source_row")):
                problems.append("Source location mismatch: " + identifier)
            keys.append((event["timestamp"], event.get("source_row", float("inf")), identifier))
        if keys != sorted(keys):
            problems.append("Timeline ordering: " + case["incident_id"])
    if reconstruct_timelines(data) != stored:
        problems.append("Stored timeline differs from reconstructed timeline")
    regenerated = group_alerts([dict(row) for row in data["alerts"]])
    if regenerated != data["incidents"]:
        problems.append("Stored incidents differ from grouping reconstruction")
    if {row["type"] for row in data["alerts"]} != set(DISPLAY_ATTACK_TYPES):
        problems.append("Unexpected displayed attack scope")
    if tuple(name for name, _ in DETECTION_RULES) != DISPLAY_ATTACK_TYPES:
        problems.append("Detector rules differ from displayed scope")
    return {
        "kind": "joint-artifact-contract-check",
        "passed": not problems,
        "issues": problems,
        "display_scope": list(DISPLAY_ATTACK_TYPES),
        "cases": len(data["incidents"]),
        "alerts": len(alerts),
        "sample_flows": len(flows),
        "traceable_timeline_events": events,
        "sha256": {
            name: sha256(root / "src" / name)
            for name in ("real-alerts.json", "real-timelines.json")
        },
        "limits": "Reconstruction and source-pointer checks, not raw packet verification or case-level recall.",
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args()
    report = check()
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))
    raise SystemExit(not report["passed"])
