import copy
import hashlib
import json
import csv
import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from services.alerts import (
    classify_group,
    needs_review_candidate,
    group_alerts,
    analyze_archive,
    DETECTION_RULES,
    select_archive_members,
    select_preview,
)
from services.evaluate_grouping import evaluate_grouping
from services.evaluate_detection import evaluate_archive, detector_hash, sha256_file, expected_type


class DetectionEvaluationTests(unittest.TestCase):
    def test_dense_port_scan_with_reused_source_ports_matches(self):
        group = {
            "count": 100,
            "packets": 200,
            "ports": set(range(250)),
            "source_ports": {40000, 40001},
        }
        self.assertEqual(classify_group(group), "PortScan")

    def test_response_like_port_sweep_stays_unclassified(self):
        group = {
            "count": 225,
            "packets": 450,
            "ports": set(range(225)),
            "source_ports": set(range(164)),
        }
        self.assertIsNone(classify_group(group))

    def test_unclassified_candidate_is_not_a_known_attack(self):
        group = {"count": 500, "packets": 5000, "ports": {"80"}, "source_ports": {"1000"}}
        self.assertIsNone(classify_group(group))
        self.assertTrue(needs_review_candidate(group))

    def test_full_archive_reports_missed_attack_and_benign_group(self):
        header = [
            "Source IP",
            "Destination IP",
            "Destination Port",
            "Source Port",
            "Timestamp",
            "Total Fwd Packets",
            "Total Backward Packets",
            "Label",
        ]
        with tempfile.TemporaryDirectory() as folder:
            archive_path = Path(folder) / "flows.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                for member, label in [
                    ("Monday-WorkingHours.csv", "BENIGN"),
                    ("Tuesday-WorkingHours.csv", "BENIGN"),
                    ("Wednesday-workingHours.csv", "DoS Hulk"),
                    ("Friday-WorkingHours-Afternoon-PortScan.csv", "BENIGN"),
                ]:
                    buffer = io.StringIO()
                    writer = csv.writer(buffer)
                    writer.writerow(header)
                    writer.writerow(
                        ["10.0.0.1", "10.0.0.2", 80, 1000, "05/07/2017 10:00:00", 1, 1, label]
                    )
                    archive.writestr(member, buffer.getvalue())
            report = evaluate_archive(archive_path)
        self.assertEqual(report["per_type"]["DoS"]["false_negative"], 1)
        self.assertEqual(report["per_type"]["DoS"]["recall"], 0)
        self.assertEqual(report["attack_detection"]["true_positive"], 0)
        self.assertEqual(report["attack_detection"]["false_negative"], 1)
        self.assertEqual(report["attack_detection"]["false_positive"], 0)
        self.assertEqual(report["groups_scanned"], 4)

    def test_repeated_ssh_flows_are_detected_without_login_outcome(self):
        header = [
            "Source IP",
            "Destination IP",
            "Destination Port",
            "Source Port",
            "Timestamp",
            "Total Fwd Packets",
            "Total Backward Packets",
            "Label",
        ]
        with tempfile.TemporaryDirectory() as folder:
            archive_path = Path(folder) / "flows.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                for member in (
                    "Monday-WorkingHours.csv",
                    "Tuesday-WorkingHours.csv",
                    "Wednesday-workingHours.csv",
                    "Friday-WorkingHours-Afternoon-PortScan.csv",
                ):
                    buffer = io.StringIO()
                    writer = csv.writer(buffer)
                    writer.writerow(header)
                    if "Tuesday" in member:
                        for index in range(50):
                            writer.writerow(
                                [
                                    "10.0.0.1",
                                    "10.0.0.2",
                                    22,
                                    1000 + index,
                                    "04/07/2017 09:00:00",
                                    1,
                                    0,
                                    "SSH-Patator",
                                ]
                            )
                    archive.writestr(member, buffer.getvalue())
            report = evaluate_archive(archive_path)
        self.assertEqual(report["attack_detection"]["true_positive"], 1)
        self.assertEqual(report["per_type"]["BruteForce"]["true_positive"], 1)
        self.assertEqual(report["per_type"]["BruteForce"]["missed_without_alert"], 0)


class ScopeAndGroupingTests(unittest.TestCase):
    def alert(self, kind="DoS", source="a", destination="b", minute="00", port=None):
        return {
            "alert_id": f"{kind}-{source}-{destination}-{minute}-{port}",
            "type": kind,
            "source_file": "test.csv",
            "source_ip": source,
            "destination_ip": destination,
            "timestamp": f"2017-07-04T10:{minute}:00",
            "target_port": port,
            "flow_count": 10,
            "evidence_sample_ids": [],
        }

    def test_scope_and_label_independence(self):
        self.assertEqual([name for name, _ in DETECTION_RULES], ["PortScan", "DoS", "BruteForce"])
        group = {
            "count": 50,
            "packets": 100,
            "ports": {"22"},
            "source_ports": {"1"},
            "port_flow_counts": {"22": 50},
        }
        for label in ("BENIGN", "SSH-Patator", "DDoS", ""):
            self.assertEqual(classify_group({**group, "labels": {label: 50}}), "BruteForce")
        self.assertEqual(expected_type(["BENIGN", "SSH-Patator"]), "Mixed")

    def test_incident_ids_separate_rules_and_login_ports(self):
        alerts = [
            self.alert("DoS"),
            self.alert("BruteForce", port="21"),
            self.alert("BruteForce", port="22"),
            self.alert("PortScan"),
        ]
        cases = group_alerts(alerts)
        self.assertEqual(len(cases), 4)
        self.assertEqual(len({case["incident_id"] for case in cases}), 4)
        self.assertEqual(cases, group_alerts(list(reversed(copy.deepcopy(alerts)))))

    def test_case_scoring_reports_mixed_cases_and_rejects_preview(self):
        alerts = [
            dict(self.alert(minute="00"), dataset_labels={"BENIGN": 10}),
            dict(self.alert(minute="01"), dataset_labels={"DoS Hulk": 10}),
        ]
        cases = group_alerts(alerts)
        data = {"provenance": {"mode": "full"}, "rules": {}, "alerts": alerts, "incidents": cases}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "cases.json"
            path.write_text(json.dumps(data))
            report = evaluate_grouping(path)
            self.assertEqual(report["mixed_label_cases"], 1)
            self.assertEqual(report["pure_benign_alert_cases"], 0)
            data["provenance"]["mode"] = "preview"
            path.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, "full detector export"):
                evaluate_grouping(path)

    def test_preview_choice_does_not_use_dataset_truth(self):
        alerts = [dict(self.alert(), ddos_reference=True)]
        cases = group_alerts(alerts)
        first = select_preview(cases, alerts, [], 1)
        alerts[0]["ddos_reference"] = False
        self.assertEqual(first[0], select_preview(cases, alerts, [], 1)[0])

    def test_ambiguous_archive_members_are_rejected(self):
        class Archive:
            def namelist(self):
                return ["a/Monday-WorkingHours.csv", "b/Monday-WorkingHours.csv"]

        with self.assertRaisesRegex(ValueError, "exactly one"):
            select_archive_members(Archive())

    def test_bruteforce_threshold_is_per_login_port(self):
        group = {
            "count": 60,
            "packets": 60,
            "ports": {"21", "22"},
            "source_ports": {"1"},
            "port_flow_counts": {"21": 30, "22": 30},
        }
        self.assertIsNone(classify_group(group))
        group["port_flow_counts"] = {"21": 49, "22": 11}
        self.assertIsNone(classify_group(group))
        group["port_flow_counts"] = {"21": 50, "22": 10}
        self.assertEqual(classify_group(group), "BruteForce")

    def test_pair_and_gap_boundaries(self):
        alerts = [
            self.alert(minute="00"),
            self.alert(minute="05"),
            self.alert(minute="11"),
            self.alert(source="other"),
            self.alert(destination="other"),
        ]
        cases = group_alerts(alerts)
        self.assertEqual(sorted(len(case["alert_ids"]) for case in cases), [1, 1, 1, 2])


class HoldoutEvaluationTests(unittest.TestCase):
    def test_external_holdout_scores_false_positive_miss_and_exclusions(self):
        header = [
            "Source IP",
            "Destination IP",
            "Destination Port",
            "Source Port",
            "Timestamp",
            "Total Fwd Packets",
            "Total Backward Packets",
            "Label",
        ]
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(header)
        # Benign SSH burst is deliberately a false positive.
        for i in range(50):
            writer.writerow(["a", "b", 22, 1000 + i, "04/07/2017 09:00:00", 1, 0, "BENIGN"])
        for source, label in [("c", "DoS Hulk"), ("d", "DDoS"), ("e", "BENIGN")]:
            writer.writerow([source, "b", 80, 1000, "04/07/2017 09:01:00", 1, 0, label])
        payload = buffer.getvalue().encode()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "holdout.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("independent.csv", payload)
            manifest = {
                "purpose": "external_holdout",
                "frozen_at": "2026-10-23",
                "archive_sha256": sha256_file(path),
                "detector_sha256": detector_hash(),
                "development_archive_sha256": ["0" * 64],
                "development_member_sha256": ["1" * 64],
                "members": {"independent.csv": hashlib.sha256(payload).hexdigest()},
            }
            report = evaluate_archive(path, manifest)
            self.assertEqual(report["evaluation_status"], "external_holdout_manifest_verified")
            binary = report["attack_detection"]
            self.assertEqual(
                (binary["false_positive"], binary["false_negative"], binary["true_negative"]),
                (1, 1, 1),
            )
            self.assertEqual(binary["false_positive_rate"], 0.5)
            self.assertEqual(report["excluded_ambiguous_groups"], {"DDoS": 1})
            self.assertEqual(len(report["errors"]), 2)
            self.assertEqual(report, evaluate_archive(path, manifest))
            manifest["development_member_sha256"] = list(manifest["members"].values())
            with self.assertRaisesRegex(ValueError, "overlapping"):
                evaluate_archive(path, manifest)
            manifest["detector_sha256"] = "wrong"
            with self.assertRaisesRegex(ValueError, "Detector differs"):
                evaluate_archive(path, manifest)

    def test_archive_detection_is_label_blind_and_uses_minute_boundary(self):
        header = "Source IP,Destination IP,Destination Port,Source Port,Timestamp,Total Fwd Packets,Total Backward Packets,Label\n"
        with tempfile.TemporaryDirectory() as folder:
            outputs = []
            for label in ("BENIGN", "SSH-Patator"):
                path = Path(folder) / "flows.zip"
                with zipfile.ZipFile(path, "w") as archive:
                    for member in (
                        "Monday-WorkingHours.csv",
                        "Tuesday-WorkingHours.csv",
                        "Wednesday-workingHours.csv",
                        "Friday-WorkingHours-Afternoon-PortScan.csv",
                    ):
                        rows = (
                            "".join(
                                f"a,b,22,{1000 + i},04/07/2017 09:00:59,1,0,{label}\n"
                                for i in range(50)
                            )
                            if "Tuesday" in member
                            else ""
                        )
                        archive.writestr(member, header + rows)
                result = analyze_archive(path)
                alert = result["alerts"][0]
                self.assertEqual(alert["timestamp"], "2017-07-04T09:00:00")
                outputs.append((alert["alert_id"], alert["incident_id"], alert["type"]))
            self.assertEqual(outputs[0], outputs[1])


if __name__ == "__main__":
    unittest.main()
