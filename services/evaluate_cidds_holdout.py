"""Frozen external-domain detection evaluation for CIDDS-001 OpenStack flows.

This adapter is intentionally separate from the CIC-IDS2017 detector. It does
not alter thresholds or feed CIDDS labels into classify_group().
"""

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
import zipfile
from collections import Counter
from pathlib import Path

from services.alerts import classify_group


MEMBERS = tuple(
    f"CIDDS-001/traffic/OpenStack/CIDDS-001-internal-week{week}.csv" for week in range(1, 5)
)
TARGETS = ("PortScan", "DoS", "BruteForce")
ATTACK_TYPES = {"portscan": "PortScan", "dos": "DoS", "bruteforce": "BruteForce"}


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def score_archive(archive_path, directory):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "data" / "tools"))
    import duckdb

    matrix = Counter()
    counts = Counter()
    with zipfile.ZipFile(archive_path) as archive:
        if any(member not in archive.namelist() for member in MEMBERS):
            raise ValueError("CIDDS-001 internal week 1-4 members are required")
        for member in MEMBERS:
            csv_path = directory / Path(member).name
            with archive.open(member) as source, open(csv_path, "wb") as destination:
                shutil.copyfileobj(source, destination, length=4 * 1024 * 1024)
            con = duckdb.connect(str(directory / "holdout.duckdb"))
            con.execute(
                f"SET temp_directory='{str(directory / 'spill').replace(chr(39), chr(39) + chr(39))}'"
            )
            path = str(csv_path).replace("'", "''")
            query = f"""
                WITH rows AS (
                    SELECT trim("Src IP Addr") AS source, trim("Dst IP Addr") AS destination,
                           left(trim("Date first seen"), 16) AS minute,
                           trim("Src Pt") AS source_port, trim("Dst Pt") AS destination_port,
                           try_cast(trim("Packets") AS BIGINT) AS packets,
                           CASE WHEN lower(trim("class")) = 'normal' THEN 'Benign'
                                WHEN lower(trim("attackType")) = 'portscan' THEN 'PortScan'
                                WHEN lower(trim("attackType")) = 'dos' THEN 'DoS'
                                WHEN lower(trim("attackType")) = 'bruteforce' THEN 'BruteForce'
                                ELSE 'OutOfScope' END AS truth
                    FROM read_csv('{path}', header=true, all_varchar=true)
                ), valid AS (
                    SELECT * FROM rows WHERE source <> '' AND destination <> ''
                        AND length(minute) = 16 AND packets >= 0
                )
                SELECT source, destination, minute, count(*) AS n, sum(packets) AS packets,
                       count(DISTINCT destination_port) AS destination_ports,
                       count(DISTINCT source_port) AS source_ports,
                       sum(CASE WHEN destination_port = '21' THEN 1 ELSE 0 END) AS ftp,
                       sum(CASE WHEN destination_port = '22' THEN 1 ELSE 0 END) AS ssh,
                       max(CASE WHEN truth = 'Benign' THEN 1 ELSE 0 END) AS benign,
                       max(CASE WHEN truth = 'PortScan' THEN 1 ELSE 0 END) AS portscan,
                       max(CASE WHEN truth = 'DoS' THEN 1 ELSE 0 END) AS dos,
                       max(CASE WHEN truth = 'BruteForce' THEN 1 ELSE 0 END) AS bruteforce,
                       max(CASE WHEN truth = 'OutOfScope' THEN 1 ELSE 0 END) AS out_of_scope
                FROM valid GROUP BY source, destination, minute
            """
            cursor = con.execute(query)
            while batch := cursor.fetchmany(10000):
                for row in batch:
                    (
                        _,
                        _,
                        _,
                        n,
                        packets,
                        destination_ports,
                        source_ports,
                        ftp,
                        ssh,
                        benign,
                        portscan,
                        dos,
                        bruteforce,
                        out_of_scope,
                    ) = row
                    group = {
                        "count": n,
                        "packets": packets,
                        "ports": range(destination_ports),
                        "source_ports": range(source_ports),
                        "port_flow_counts": {"21": ftp, "22": ssh},
                    }
                    prediction = classify_group(group) or "No rule"
                    attacks = [
                        kind for kind, flag in zip(TARGETS, (portscan, dos, bruteforce)) if flag
                    ]
                    if out_of_scope or len(attacks) > 1:
                        counts["excluded_ambiguous_or_out_of_scope_groups"] += 1
                        continue
                    label = attacks[0] if attacks else "Benign"
                    if attacks and benign:
                        counts["mixed_benign_attack_groups"] += 1
                    matrix[(label, prediction)] += 1
                    counts["scored_groups"] += 1
            counts["members_scored"] += 1
            con.close()
            csv_path.unlink()
    return counts, matrix


def evaluate(archive_path, frozen_manifest):
    manifest = json.loads(Path(frozen_manifest).read_text(encoding="utf-8"))
    expected = manifest["sha256"]
    actual = {
        name: sha256(path)
        for name, path in (
            ("archive", archive_path),
            ("detector", Path(__file__).with_name("alerts.py")),
            ("adapter", Path(__file__)),
        )
    }
    if actual != expected:
        raise ValueError(f"Frozen evaluation hash mismatch: {actual}")
    with tempfile.TemporaryDirectory(prefix="cidds-holdout-") as temp:
        directory = Path(temp)
        scored, matrix = score_archive(archive_path, directory)
    metrics = {}
    for attack in TARGETS:
        tp = matrix[(attack, attack)]
        fp = sum(
            count
            for (label, prediction), count in matrix.items()
            if prediction == attack and label != attack
        )
        fn = sum(
            count
            for (label, prediction), count in matrix.items()
            if label == attack and prediction != attack
        )
        metrics[attack] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
        }
    return {
        "kind": "external_domain_holdout",
        "source": "CIDDS-001 OpenStack internal weeks 1-4",
        "frozen_sha256": actual,
        "groups": dict(scored),
        "confusion": [
            {"truth": truth, "prediction": prediction, "groups": count}
            for (truth, prediction), count in sorted(matrix.items())
        ],
        "per_attack": metrics,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args()
    report = evaluate(args.archive, args.manifest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"groups": report["groups"], "per_attack": report["per_attack"]}))


if __name__ == "__main__":
    main()
