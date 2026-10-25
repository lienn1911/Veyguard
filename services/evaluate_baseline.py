"""Offline, normal-only anomaly baseline for complete CIC-IDS2017 flow archives.

This experiment does not change the product detector. Its unit is a
source/destination/minute group, and dataset labels are used only for evaluation.
"""

import argparse
import csv
import io
import json
import math
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

from services.alerts import finite_number, parse_time, DISPLAY_ATTACK_TYPES, select_archive_members
from services.evaluate_detection import expected_type, sha256_file


MONDAY = "Monday-WorkingHours"
SHIFTED_DAYS = (
    "Tuesday-WorkingHours",
    "Wednesday-workingHours",
    "Friday-WorkingHours-Afternoon-PortScan",
)
RATES = (0.0001, 0.001, 0.01)
FEATURES = (
    "flows",
    "packets",
    "bytes",
    "destination_ports",
    "source_ports",
    "destination_port_entropy",
    "source_port_entropy",
    "sources_to_destination",
)


def entropy(counter):
    total = sum(counter.values())
    return -sum((n / total) * math.log2(n / total) for n in counter.values()) if total else 0.0


def feature_row(group, sources_to_destination):
    return [
        math.log1p(group["flows"]),
        math.log1p(group["packets"]),
        math.log1p(group["bytes"]),
        math.log1p(len(group["destination_ports"])),
        math.log1p(len(group["source_ports"])),
        entropy(group["destination_ports"]),
        entropy(group["source_ports"]),
        math.log1p(sources_to_destination),
    ]


def load_groups(archive, member):
    groups = {}
    source_name = Path(member).name
    reader = csv.DictReader(
        io.TextIOWrapper(archive.open(member), encoding="utf-8-sig", newline="")
    )
    rows = 0
    for row in reader:
        values = {
            key.strip().lower(): value.strip()
            for key, value in row.items()
            if key and value is not None
        }
        if not all(values.get(field) for field in ("source ip", "destination ip", "timestamp")):
            continue
        minute = parse_time(values["timestamp"], source_name).strftime("%Y-%m-%dT%H:%M")
        key = (values["source ip"], values["destination ip"], minute)
        if key not in groups:
            groups[key] = {
                "flows": 0,
                "packets": 0,
                "bytes": 0,
                "destination_ports": Counter(),
                "source_ports": Counter(),
                "labels": Counter(),
            }
        group = groups[key]
        group["flows"] += 1
        group["packets"] += finite_number(values.get("total fwd packets")) + finite_number(
            values.get("total backward packets")
        )
        group["bytes"] += finite_number(values.get("total length of fwd packets")) + finite_number(
            values.get("total length of bwd packets")
        )
        group["destination_ports"][values.get("destination port", "")] += 1
        group["source_ports"][values.get("source port", "")] += 1
        group["labels"][values.get("label", "").strip().lower()] += 1
        rows += 1
    sources = defaultdict(set)
    for source, destination, minute in groups:
        sources[(destination, minute)].add(source)
    keys = sorted(groups, key=lambda key: (key[2], key[0], key[1]))
    features = np.asarray(
        [feature_row(groups[key], len(sources[(key[1], key[2])])) for key in keys], dtype=np.float32
    )
    labels = [groups[key]["labels"] for key in keys]
    return {"name": source_name, "rows": rows, "keys": keys, "features": features, "labels": labels}


def chronological_split(keys, embargo_minutes=5):
    minutes = sorted({key[2] for key in keys})
    if len(minutes) < 15:
        raise ValueError("Monday does not contain enough distinct minutes for time-block splitting")
    first = int(len(minutes) * 0.6)
    second = int(len(minutes) * 0.8)
    if second - first <= embargo_minutes or len(minutes) - second <= embargo_minutes:
        raise ValueError("Not enough minutes remain after split embargo")
    train = set(minutes[:first])
    calibration = set(minutes[first + embargo_minutes : second])
    test = set(minutes[second + embargo_minutes :])
    return {
        "train": np.asarray([i for i, key in enumerate(keys) if key[2] in train]),
        "calibration": np.asarray([i for i, key in enumerate(keys) if key[2] in calibration]),
        "test": np.asarray([i for i, key in enumerate(keys) if key[2] in test]),
        "boundaries": {
            "train_end": minutes[first - 1],
            "calibration_start": minutes[first + embargo_minutes],
            "calibration_end": minutes[second - 1],
            "test_start": minutes[second + embargo_minutes],
        },
    }


def truth(labels):
    return expected_type(labels)


def summarize(scores, labels, cutoff):
    predicted = scores > cutoff
    benign = np.asarray([truth(label) == "Benign" for label in labels])
    attacks = np.asarray([truth(label) in DISPLAY_ATTACK_TYPES for label in labels])
    result = {
        "benign_groups": int(benign.sum()),
        "false_positive_groups": int((predicted & benign).sum()),
        "group_false_positive_rate": round(float((predicted & benign).sum() / benign.sum()), 6)
        if benign.any()
        else None,
        "known_attack_groups": int(attacks.sum()),
        "detected_attack_groups": int((predicted & attacks).sum()),
        "known_attack_recall": round(float((predicted & attacks).sum() / attacks.sum()), 6)
        if attacks.any()
        else None,
        "excluded_mixed_or_other_groups": int((~benign & ~attacks).sum()),
    }
    return result, predicted, benign


def count_false_positive_cases(keys, predicted, benign, gap_minutes=5):
    """Count contiguous flagged benign groups by source/destination pair."""
    from datetime import datetime

    flagged = sorted(
        (keys[i] for i in range(len(keys)) if predicted[i] and benign[i]),
        key=lambda key: (key[0], key[1], key[2]),
    )
    count = 0
    previous = None
    for key in flagged:
        if (
            previous is None
            or key[:2] != previous[:2]
            or (
                datetime.fromisoformat(key[2]) - datetime.fromisoformat(previous[2])
            ).total_seconds()
            > gap_minutes * 60
        ):
            count += 1
        previous = key
    return count


def evaluate(path, max_train_groups=50000):
    from sklearn.ensemble import IsolationForest

    with zipfile.ZipFile(path) as archive:
        selected = dict(
            zip((MONDAY, *SHIFTED_DAYS), select_archive_members(archive, (MONDAY, *SHIFTED_DAYS)))
        )
        monday = load_groups(archive, selected[MONDAY])
        if any(truth(label) != "Benign" for label in monday["labels"]):
            raise ValueError("Monday contains non-Benign groups; do not train this baseline")
        split = chronological_split(monday["keys"])
        training = split["train"]
        if len(training) > max_train_groups:
            training = np.random.default_rng(2017).choice(training, max_train_groups, replace=False)
        model = IsolationForest(n_estimators=100, max_samples=256, random_state=2017, n_jobs=-1)
        model.fit(monday["features"][training])
        calibration_scores = -model.score_samples(monday["features"][split["calibration"]])
        monday_test_scores = -model.score_samples(monday["features"][split["test"]])
        result = {
            "scope": list(DISPLAY_ATTACK_TYPES),
            "evaluation_status": "historical_baseline_experiment_not_independent_rule_validation",
            "archive_sha256": sha256_file(path),
            "evaluator_sha256": sha256_file(__file__),
            "method": "Isolation Forest on normal-only training groups; labels used only for evaluation",
            "unit": "source IP / destination IP / minute group",
            "features": FEATURES,
            "split": {
                "method": "chronological 60/20/20 distinct-minute blocks with a five-minute gap at each boundary",
                "boundaries": split["boundaries"],
                "training_groups_fitted": len(training),
                "calibration_groups": len(split["calibration"]),
                "monday_test_groups": len(split["test"]),
            },
            "files": {monday["name"]: {"flow_rows": monday["rows"], "groups": len(monday["keys"])}},
            "targets": {},
        }
        shifted = []
        for name in SHIFTED_DAYS:
            dataset = load_groups(archive, selected[name])
            shifted.append((dataset, -model.score_samples(dataset["features"])))
            result["files"][dataset["name"]] = {
                "flow_rows": dataset["rows"],
                "groups": len(dataset["keys"]),
            }
        for rate in RATES:
            cutoff = float(np.quantile(calibration_scores, 1 - rate, method="higher"))
            monday_result, monday_predicted, monday_benign = summarize(
                monday_test_scores, [monday["labels"][i] for i in split["test"]], cutoff
            )
            monday_result["false_positive_cases"] = count_false_positive_cases(
                [monday["keys"][i] for i in split["test"]], monday_predicted, monday_benign
            )
            cross_day = {}
            for dataset, scores in shifted:
                summary, predicted, benign = summarize(scores, dataset["labels"], cutoff)
                summary["false_positive_cases"] = count_false_positive_cases(
                    dataset["keys"], predicted, benign
                )
                cross_day[dataset["name"]] = summary
            calibration_false_positives = int((calibration_scores > cutoff).sum())
            result["targets"][str(rate)] = {
                "target_group_false_positive_rate": rate,
                "score_cutoff": cutoff,
                "calibration_false_positive_groups": calibration_false_positives,
                "calibration_actual_rate": round(
                    calibration_false_positives / len(calibration_scores), 6
                ),
                "monday_holdout": monday_result,
                "shifted_day": cross_day,
            }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    report = json.dumps(evaluate(args.archive), indent=2) + "\n"
    if args.output:
        args.output.write_text(report, encoding="utf-8")
    else:
        print(report, end="")


if __name__ == "__main__":
    main()
