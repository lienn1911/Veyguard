"""Add all rule-matched CIC cases to the bundled demo without renumbering existing cases."""

import argparse
import json
from pathlib import Path

from services.timeline import reconstruct_timelines


def expand_preview(current, full):
    if current.get("provenance", {}).get("dataset") != full.get("provenance", {}).get("dataset"):
        raise ValueError("Current preview and full export must come from the same CIC dataset")

    full_cases = {item["incident_id"]: item for item in full["incidents"]}
    current_cases = current["incidents"]
    ordered_ids = [item["incident_id"] for item in current_cases]
    if len(ordered_ids) != len(set(ordered_ids)):
        raise ValueError("Current preview contains duplicate Case IDs")
    existing_cic_ids = [
        item["incident_id"] for item in current_cases if item["incident_id"] in full_cases
    ]
    if not existing_cic_ids:
        raise ValueError("Current preview has no Case IDs matching the full export")

    # Keep the established Case numbers and any independently imported cases.
    incidents = [full_cases.get(item["incident_id"], item) for item in current_cases]
    incidents.extend(item for item in full["incidents"] if item["incident_id"] not in ordered_ids)
    other_alerts = [item for item in current["alerts"] if item["incident_id"] not in full_cases]
    other_flow_ids = {flow_id for item in other_alerts for flow_id in item["evidence_sample_ids"]}
    other_flows = [item for item in current["flows"] if item["flow_id"] in other_flow_ids]
    alerts = full["alerts"] + other_alerts
    flows = full["flows"] + other_flows

    alert_ids = {item["alert_id"] for item in alerts}
    flow_ids = {item["flow_id"] for item in flows}
    if len(alert_ids) != len(alerts) or len(flow_ids) != len(flows):
        raise ValueError("Full export and additional data have duplicate evidence IDs")
    for incident in incidents:
        if not set(incident["alert_ids"]).issubset(alert_ids) or not set(
            incident["evidence_sample_ids"]
        ).issubset(flow_ids):
            raise ValueError(f"Case {incident['incident_id']} references missing evidence")

    return {
        **current,
        "provenance": {
            **current["provenance"],
            "files": full["provenance"]["files"],
            "mode": "expanded preview",
            "scope": full["provenance"]["scope"],
        },
        "rules": full["rules"],
        "evaluation": {
            **full["evaluation"],
            "exported_incidents": len(incidents),
            "exported_alerts": len(alerts),
        },
        "incidents": incidents,
        "alerts": alerts,
        "flows": flows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("full", type=Path)
    parser.add_argument("current", type=Path)
    parser.add_argument("--alerts-output", type=Path, required=True)
    parser.add_argument("--timelines-output", type=Path, required=True)
    args = parser.parse_args()
    full = json.loads(args.full.read_text(encoding="utf-8"))
    current = json.loads(args.current.read_text(encoding="utf-8"))
    expanded = expand_preview(current, full)
    timelines = reconstruct_timelines(expanded)
    args.alerts_output.write_text(json.dumps(expanded, indent=2) + "\n", encoding="utf-8")
    args.timelines_output.write_text(json.dumps(timelines, indent=2) + "\n", encoding="utf-8")
    print(
        f"Expanded to {len(expanded['incidents'])} Cases, {len(expanded['alerts'])} Alerts, "
        f"{len(expanded['flows'])} linked sample flows"
    )


if __name__ == "__main__":
    main()
