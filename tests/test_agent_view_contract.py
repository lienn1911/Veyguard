"""The model sees detector output but never dataset provenance or truth labels."""

import json
import re
import unittest
from pathlib import Path

from services.data_store import Dataset
from services.tools import TOOL_NAMES, ToolRegistry


ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_KEYS = {
    "source_file",
    "source_row",
    "original_flow_id",
    "dataset_label",
    "dataset_labels",
    "reference_label",
    "ddos_reference",
}
DATASET_FILE_PATTERN = re.compile(
    r"(?:Monday|Tuesday|Wednesday|Thursday|Friday).*?(?:\.csv|PortScan|DDos)", re.I
)


def inspect(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in FORBIDDEN_KEYS or "label" in key.lower():
                raise AssertionError(f"model-facing field leaked: {key}")
            inspect(item)
    elif isinstance(value, list):
        for item in value:
            inspect(item)
    elif isinstance(value, str):
        if DATASET_FILE_PATTERN.search(value):
            raise AssertionError(f"dataset filename leaked: {value}")


class AgentViewContract(unittest.TestCase):
    def test_every_tool_for_every_preview_case_excludes_truth_and_provenance(self):
        dataset = Dataset.load(
            ROOT / "src" / "real-alerts.json", ROOT / "src" / "real-timelines.json"
        )
        for incident_id in dataset.incident_ids():
            registry = ToolRegistry(dataset, incident_id)
            for name in TOOL_NAMES:
                with self.subTest(incident_id=incident_id, tool=name):
                    result = registry.execute(name, {"incident_id": incident_id})
                    self.assertTrue(result.ok, result.error)
                    inspect(result.data)
            # The analyst keeps the provenance needed to inspect original rows.
            self.assertIn("source_file", dataset.analyst_incident(incident_id))

    def test_new_stored_fields_do_not_automatically_reach_the_model(self):
        payload = json.loads((ROOT / "src" / "real-alerts.json").read_text(encoding="utf-8"))
        payload["alerts"][0]["private_future_label"] = "Friday-PortScan.csv"
        dataset = Dataset(payload)
        incident_id = payload["alerts"][0]["incident_id"]
        inspect(dataset.agent_alerts(incident_id))
        self.assertNotIn("private_future_label", dataset.agent_alerts(incident_id)[0])


if __name__ == "__main__":
    unittest.main()
