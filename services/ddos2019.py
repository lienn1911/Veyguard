import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from services.alerts import stable_id
from services.timeline import reconstruct_timelines


def parse_timestamp(value):
    for pattern in ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(value.strip(), pattern)
        except ValueError:
            pass
    raise ValueError(f"Unsupported timestamp: {value}")


def read_row(row, source_file, row_number):
    fields = {key.strip().lower(): str(value).strip() for key, value in row.items() if key}
    source = fields.get("source ip", "")
    destination = fields.get("destination ip", "")
    timestamp = fields.get("timestamp", "")
    if not source or not destination or not timestamp:
        raise ValueError(
            f"Missing source IP, destination IP, or timestamp at {source_file}:{row_number}"
        )
    try:
        packets = int(float(fields.get("total fwd packets", "0"))) + int(
            float(fields.get("total backward packets", "0"))
        )
    except ValueError as error:
        raise ValueError(f"Invalid packet count at {source_file}:{row_number}") from error
    return {
        "flow_id": stable_id("FLOW", source_file, row_number),
        "timestamp": parse_timestamp(timestamp).isoformat(),
        "source_ip": source,
        "destination_ip": destination,
        "source_port": fields.get("source port", ""),
        "destination_port": fields.get("destination port", ""),
        "packet_count": packets,
        "dataset_label": fields.get("label", ""),
        "source_file": source_file,
        "source_row": row_number,
        "original_flow_id": fields.get("flow id", ""),
    }


def analyze_csv(path, min_sources=3, min_flows=1000, min_packets=10000):
    groups = defaultdict(
        lambda: {
            "count": 0,
            "packets": 0,
            "sources": set(),
            "ports": set(),
            "labels": Counter(),
            "samples": {},
            "first": None,
            "last": None,
        }
    )
    with Path(path).open(encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        for row_number, row in enumerate(reader, start=2):
            flow = read_row(row, Path(path).name, row_number)
            key = (flow["destination_ip"], flow["timestamp"][:16])
            group = groups[key]
            group["count"] += 1
            group["packets"] += flow["packet_count"]
            group["sources"].add(flow["source_ip"])
            group["ports"].add(flow["destination_port"])
            group["labels"][flow["dataset_label"]] += 1
            group["samples"].setdefault(flow["source_ip"], flow)
            group["first"] = group["first"] or flow
            group["last"] = flow

    alerts = []
    flows = {}
    for (destination, minute), group in sorted(groups.items()):
        if (
            len(group["sources"]) < min_sources
            or group["count"] < min_flows
            or group["packets"] < min_packets
        ):
            continue
        evidence = list(group["samples"].values())[:12]
        for flow in (group["first"], group["last"]):
            if flow["flow_id"] not in {item["flow_id"] for item in evidence}:
                evidence.append(flow)
        evidence.sort(key=lambda item: (item["timestamp"], item["source_row"]))
        for flow in evidence:
            flows[flow["flow_id"]] = flow
        alerts.append(
            {
                "alert_id": stable_id("ALT", Path(path).name, destination, minute, "DDoS"),
                "type": "DDoS",
                "timestamp": evidence[-1]["timestamp"],
                "source_file": Path(path).name,
                "source_ip": "Multiple sources",
                "destination_ip": destination,
                "flow_count": group["count"],
                "destination_port_count": len(group["ports"]),
                "source_port_count": 0,
                "source_count": len(group["sources"]),
                "evidence_sample_ids": [flow["flow_id"] for flow in evidence],
                "dataset_labels": dict(sorted(group["labels"].items())),
                "ddos_reference": bool(group["labels"].get("DDoS")),
                "rule_basis": f"{group['count']} flows and {int(group['packets'])} packets from {len(group['sources'])} observed source IPs in one minute",
            }
        )

    incidents = []
    current = None
    last_time = None
    for alert in sorted(
        alerts, key=lambda item: (item["destination_ip"], item["timestamp"], item["alert_id"])
    ):
        timestamp = datetime.fromisoformat(alert["timestamp"])
        if (
            current is None
            or current["destination_ip"] != alert["destination_ip"]
            or timestamp - last_time > timedelta(minutes=5)
        ):
            current = {
                "incident_id": stable_id(
                    "INC", Path(path).name, alert["destination_ip"], alert["timestamp"]
                ),
                "source_ip": "Multiple sources",
                "destination_ip": alert["destination_ip"],
                "window_start": alert["timestamp"],
                "window_end": alert["timestamp"],
                "alert_ids": [],
                "evidence_sample_ids": [],
                "flow_count": 0,
                "source_file": Path(path).name,
            }
            incidents.append(current)
        alert["incident_id"] = current["incident_id"]
        current["alert_ids"].append(alert["alert_id"])
        current["evidence_sample_ids"].extend(alert["evidence_sample_ids"])
        current["flow_count"] += alert["flow_count"]
        current["window_end"] = alert["timestamp"]
        last_time = timestamp

    result = {
        "provenance": {
            "dataset": "CIC-DDoS2019",
            "file": Path(path).name,
            "mode": "historical-import",
            "scope": "Destination-minute aggregates with sampled source flows",
        },
        "rules": {
            "window_seconds": 60,
            "incident_gap_minutes": 5,
            "ddos_min_sources": min_sources,
            "ddos_min_flows": min_flows,
            "ddos_min_packets": min_packets,
        },
        "evaluation": {
            "groups_scanned": len(groups),
            "rule_matches": len(alerts),
            "incidents": len(incidents),
        },
        "flows": list(flows.values()),
        "alerts": alerts,
        "incidents": incidents,
    }
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Import CIC-DDoS2019 flow CSV as evidence-linked DDoS cases"
    )
    parser.add_argument("csv", type=Path)
    parser.add_argument("--alerts-output", type=Path, required=True)
    parser.add_argument("--timelines-output", type=Path, required=True)
    args = parser.parse_args()
    result = analyze_csv(args.csv)
    args.alerts_output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    args.timelines_output.write_text(
        json.dumps(reconstruct_timelines(result), indent=2) + "\n", encoding="utf-8"
    )
    print(f"{len(result['alerts'])} DDoS alerts; {len(result['incidents'])} cases")


if __name__ == "__main__":
    main()
