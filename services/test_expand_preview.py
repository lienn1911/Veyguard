import unittest

from services.expand_preview import expand_preview
from services.timeline import reconstruct_timelines


class ExpandPreviewTests(unittest.TestCase):
    def test_preserves_existing_case_order_and_adds_missing_evidence(self):
        def flow(name):
            return {
                "flow_id": name,
                "timestamp": "2017-07-07T10:00:00",
                "source_ip": "a",
                "destination_port": "80",
                "source_file": "cic.csv",
                "source_row": 2,
            }

        def alert(name, case, flow_name):
            return {
                "alert_id": name,
                "incident_id": case,
                "timestamp": "2017-07-07T10:00:00",
                "type": "DoS",
                "evidence_sample_ids": [flow_name],
            }

        def case(name, alert_name, flow_name):
            return {
                "incident_id": name,
                "alert_ids": [alert_name],
                "evidence_sample_ids": [flow_name],
                "flow_count": 1,
            }

        current = {
            "provenance": {"dataset": "CIC", "additional_dataset": "Yatesbury"},
            "rules": {},
            "evaluation": {},
            "incidents": [case("CIC-1", "A-1", "F-1"), case("OTHER", "A-O", "F-O")],
            "alerts": [alert("A-1", "CIC-1", "F-1"), alert("A-O", "OTHER", "F-O")],
            "flows": [flow("F-1"), flow("F-O")],
        }
        full = {
            "provenance": {"dataset": "CIC", "files": ["cic.csv"], "scope": "samples"},
            "rules": {"window_seconds": 60},
            "evaluation": {"incidents": 2},
            "incidents": [case("CIC-1", "A-1", "F-1"), case("CIC-2", "A-2", "F-2")],
            "alerts": [alert("A-1", "CIC-1", "F-1"), alert("A-2", "CIC-2", "F-2")],
            "flows": [flow("F-1"), flow("F-2")],
        }
        expanded = expand_preview(current, full)
        self.assertEqual(
            [item["incident_id"] for item in expanded["incidents"]], ["CIC-1", "OTHER", "CIC-2"]
        )
        self.assertEqual(expanded["evaluation"]["exported_alerts"], 3)
        self.assertEqual(len(reconstruct_timelines(expanded)["timelines"]), 3)


if __name__ == "__main__":
    unittest.main()
