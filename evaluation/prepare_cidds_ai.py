"""Prepare a small external AI diagnostic from original CIDDS labels.

Selection is fixed before model calls: first encountered one-minute group per attack
label, plus two first distinct normal groups in internal week 1. This is a
purposive five-case diagnostic, not a representative accuracy benchmark.
"""

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from services.alerts import classify_group, stable_id
from services.evaluate_cidds_holdout import sha256
from services.timeline import reconstruct_timelines

ROOT = Path(__file__).resolve().parents[1]
MEMBER = "CIDDS-001/traffic/OpenStack/CIDDS-001-internal-week1.csv"


def prepare(archive_path, output):
    sys.path.insert(0, str(ROOT / "data" / "tools"))
    import duckdb

    output.mkdir(parents=True, exist_ok=False)
    data = {
        "provenance": {
            "dataset": "CIDDS-001 external AI diagnostic",
            "source": MEMBER,
            "mode": "evaluation-only",
        },
        "rules": {"window_seconds": 60},
        "alerts": [],
        "flows": [],
        "incidents": [],
    }
    references, groups_selected = {}, []
    with tempfile.TemporaryDirectory(dir=ROOT / "data") as folder:
        csv = Path(folder) / "week1.csv"
        with (
            zipfile.ZipFile(archive_path) as archive,
            archive.open(MEMBER) as source,
            csv.open("wb") as destination,
        ):
            shutil.copyfileobj(source, destination)
        con = duckdb.connect()
        con.execute("SET memory_limit='512MB'")
        con.execute("SET threads=2")
        con.execute("SET max_temp_directory_size='1GB'")
        con.execute("SET temp_directory='" + str(Path(folder) / "spill").replace("'", "''") + "'")
        path = str(csv).replace("'", "''")
        con.execute(f"""CREATE VIEW rows AS SELECT row_number() OVER ()+1 AS source_row,
            trim("Src IP Addr") AS source, trim("Dst IP Addr") AS destination,
            left(trim("Date first seen"),16) AS minute, trim("Src Pt") AS sp,
            trim("Dst Pt") AS dp, try_cast(trim("Packets") AS BIGINT) AS packets,
            CASE WHEN lower(trim("class"))='normal' THEN 'Benign'
                 WHEN lower(trim("attackType"))='portscan' THEN 'PortScan'
                 WHEN lower(trim("attackType"))='dos' THEN 'DoS'
                 WHEN lower(trim("attackType"))='bruteforce' THEN 'BruteForce'
                 ELSE 'OutOfScope' END AS truth
            FROM read_csv('{path}',header=true,all_varchar=true)""")
        candidates = con.execute("""SELECT arg_min(struct_pack(source,destination,minute),source_row),truth
            FROM rows WHERE packets>=0 AND length(minute)=16 AND source<>'' AND destination<>'' AND truth<>'OutOfScope'
            GROUP BY truth""").fetchall()
        normal = next(item[0] for item in candidates if item[1] == "Benign")
        second = con.execute(
            """SELECT source,destination,minute FROM rows WHERE truth='Benign' AND packets>=0
            AND (source<>? OR destination<>? OR minute<>?) ORDER BY source_row LIMIT 1""",
            [normal["source"], normal["destination"], normal["minute"]],
        ).fetchone()
        candidates.append((dict(zip(("source", "destination", "minute"), second)), "Benign"))
        selected = []
        for key, truth in candidates:
            counts = con.execute(
                """SELECT count(*),sum(packets),count(DISTINCT dp),count(DISTINCT sp),
                sum(CASE WHEN dp='21' THEN 1 ELSE 0 END),sum(CASE WHEN dp='22' THEN 1 ELSE 0 END),
                count(DISTINCT truth),min(truth)
                FROM rows WHERE source=? AND destination=? AND minute=?""",
                [key["source"], key["destination"], key["minute"]],
            ).fetchone()
            if counts[6] != 1 or counts[7] != truth:
                raise ValueError("Preselected group has mixed labels; no substitutions allowed")
            selected.append(
                (key["source"], key["destination"], key["minute"], truth, *counts[:6], 1)
            )
        selected.sort(key=lambda row: (row[2], row[0], row[1]))
        if Counter(row[3] for row in selected) != Counter(
            {"Benign": 2, "PortScan": 1, "DoS": 1, "BruteForce": 1}
        ):
            raise ValueError("Expected five diagnostic groups; do not silently substitute cases")
        for source, destination, minute, truth, count, packets, nd, ns, ftp, ssh, _ in selected:
            raw = con.execute(
                "SELECT source_row,sp,dp,packets FROM rows WHERE source=? AND destination=? AND minute=? ORDER BY source_row",
                [source, destination, minute],
            ).fetchall()
            group = {
                "count": count,
                "packets": packets,
                "ports": {row[2] for row in raw},
                "source_ports": {row[1] for row in raw},
                "port_flow_counts": Counter({"21": ftp, "22": ssh}),
            }
            predicted = classify_group(group)
            # Unmatched external groups enter a diagnostic review queue. Never
            # put the offline truth label into the model's incident category.
            kind = predicted or "NeedsReview"
            case_id = stable_id("INC", "external-ai", source, destination, minute)
            alert_id = stable_id("ALT", case_id)
            samples = []
            for row_number, sp, dp, packet_count in raw[:6]:
                flow_id = stable_id("FLOW", MEMBER, row_number)
                samples.append(flow_id)
                data["flows"].append(
                    {
                        "flow_id": flow_id,
                        "timestamp": minute + ":00",
                        "source_ip": source,
                        "destination_ip": destination,
                        "source_port": sp,
                        "destination_port": dp,
                        "packet_count": packet_count,
                        "source_file": MEMBER,
                        "source_row": row_number,
                    }
                )
            data["alerts"].append(
                {
                    "alert_id": alert_id,
                    "incident_id": case_id,
                    "type": kind,
                    "timestamp": minute + ":00",
                    "source_ip": source,
                    "destination_ip": destination,
                    "flow_count": count,
                    "destination_port_count": nd,
                    "source_port_count": ns,
                    "source_count": 1,
                    "evidence_sample_ids": samples,
                    "rule_basis": f"{count} flow records, {packets} packets, {nd} destination ports and {ns} source ports in one minute; "
                    + (
                        "rule matched"
                        if predicted
                        else "no attack rule matched; diagnostic review candidate"
                    ),
                }
            )
            data["incidents"].append(
                {
                    "incident_id": case_id,
                    "type": kind,
                    "source_ip": source,
                    "destination_ip": destination,
                    "window_start": minute + ":00",
                    "window_end": minute + ":00",
                    "flow_count": count,
                    "source_file": MEMBER,
                    "alert_ids": [alert_id],
                    "evidence_sample_ids": samples,
                }
            )
            references[case_id] = "Benign" if truth == "Benign" else "Attack"
            groups_selected.append(
                {
                    "incident_id": case_id,
                    "source": source,
                    "destination": destination,
                    "minute": minute,
                    "dataset_truth": truth,
                    "detector_prediction": predicted,
                }
            )
        con.close()
    alerts = output / "alerts.json"
    timelines = output / "timelines.json"
    alerts.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    timelines.write_text(json.dumps(reconstruct_timelines(data), indent=2) + "\n", encoding="utf-8")
    manifest = {
        "kind": "independent-ai-holdout",
        "frozen_at": datetime.now(timezone.utc).isoformat(),
        "reviewed_by": "Codex automated provenance and label-consistency review; no human expert adjudication",
        "label_source": "Original CIDDS class/attackType; labels not included in model-facing files",
        "selection": "First encountered group key per target attack and first two distinct normal keys in week 1 CSV order; full groups must be pure; no substitution; fixed before AI calls",
        "limitations": "Five purposive groups, shared source with detector holdout, external-domain diagnostic only; not statistically representative or expert-adjudicated AI accuracy.",
        "source_archive_sha256": sha256(archive_path).upper(),
        "development_archive_sha256": [
            "7BDBEF286F8893F31C6DB12105FA097FA5C2DCC6733179037A08129D150EA27A"
        ],
        "alerts_sha256": sha256(alerts).upper(),
        "timelines_sha256": sha256(timelines).upper(),
        "prompt_sha256": sha256(ROOT / "services/prompts.py").upper(),
        "case_ids": list(references),
        "reference_labels": references,
        "selection_records": groups_selected,
        "adapter_sha256": sha256(Path(__file__)).upper(),
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = prepare(args.archive, args.output)
    print(
        json.dumps(
            {
                "cases": len(result["case_ids"]),
                "reference_counts": dict(Counter(result["reference_labels"].values())),
            }
        )
    )
