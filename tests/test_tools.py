"""Tool-layer guarantees: allowlist, argument validation, read-only, no label leakage."""

from __future__ import annotations

import hashlib
import json

import pytest

from services.data_store import LABEL_FIELDS
from services.tools import (
    TOOL_DEFINITIONS,
    TOOL_NAMES,
    ToolError,
    ToolRegistry,
    validate_arguments,
)


def walk_keys(value, found=None):
    found = found if found is not None else set()
    if isinstance(value, dict):
        for key, item in value.items():
            found.add(key)
            walk_keys(item, found)
    elif isinstance(value, list):
        for item in value:
            walk_keys(item, found)
    return found


def test_only_read_tools_are_registered():
    assert TOOL_NAMES == (
        "get_incident_details",
        "get_related_alerts",
        "get_network_flows",
        "get_incident_statistics",
    )
    for definition in TOOL_DEFINITIONS:
        assert definition["parameters"]["additionalProperties"] is False
        assert "incident_id" in definition["parameters"]["required"]


def test_registry_exposes_no_write_handler(dataset, incidents_by_category):
    registry = ToolRegistry(dataset, incidents_by_category["DoS"])
    for forbidden in (
        "close_incident",
        "dismiss_incident",
        "update_incident",
        "delete_evidence",
        "run_shell",
        "execute_python",
        "approve",
    ):
        outcome = registry.execute(forbidden, {})
        assert outcome.ok is False
        assert outcome.blocked is True
        assert outcome.error["code"] == "TOOL_NOT_ALLOWED"


def test_label_fields_never_reach_the_agent(dataset, incidents_by_category):
    incident_id = incidents_by_category["DoS"]
    registry = ToolRegistry(dataset, incident_id)

    payloads = [
        registry.execute("get_incident_details", {"incident_id": incident_id}).payload(),
        registry.execute("get_related_alerts", {"incident_id": incident_id}).payload(),
        registry.execute("get_network_flows", {"incident_id": incident_id}).payload(),
        registry.execute("get_incident_statistics", {"incident_id": incident_id}).payload(),
    ]

    for payload in payloads:
        # No ground-truth fields, and none of the actual label values for this incident
        # ("DoS Hulk" is the CIC-IDS2017 label; the rule type is just "DoS").
        assert not (walk_keys(payload) & set(LABEL_FIELDS))
        serialized = json.dumps(payload)
        assert "DoS Hulk" not in serialized
        assert "dataset_label" not in serialized
        assert "ddos_reference" not in serialized


def test_analyst_view_keeps_reference_label_separate(dataset, incidents_by_category):
    evidence = dataset.analyst_evidence(incidents_by_category["DoS"])
    assert evidence["flows"], "expected sampled flows"
    assert all("reference_label" in flow for flow in evidence["flows"])
    assert all("dataset_label" not in flow for flow in evidence["flows"])


@pytest.mark.parametrize(
    "arguments,expected_code",
    [
        ({}, "INVALID_ARGUMENTS"),
        ({"incident_id": "INC-OK00000001"}, None),
        ({"incident_id": "INC-OK00000001", "limit": 3}, None),
        ({"incident_id": "INC-OK00000001", "limit": 0}, "INVALID_ARGUMENTS"),
        ({"incident_id": "INC-OK00000001", "limit": 999}, "INVALID_ARGUMENTS"),
        ({"incident_id": "INC-OK00000001", "limit": "6"}, "INVALID_ARGUMENTS"),
        ({"incident_id": "INC-OK00000001", "limit": 2.5}, "INVALID_ARGUMENTS"),
        ({"incident_id": "INC-OK00000001", "extra": 1}, "INVALID_ARGUMENTS"),
    ],
)
def test_argument_validation(arguments, expected_code):
    schema = next(
        definition for definition in TOOL_DEFINITIONS if definition["name"] == "get_network_flows"
    )["parameters"]
    if expected_code is None:
        assert validate_arguments(schema, arguments) == arguments
    else:
        with pytest.raises(ToolError) as excinfo:
            validate_arguments(schema, arguments)
        assert excinfo.value.code == expected_code


def test_arguments_must_be_an_object():
    with pytest.raises(ToolError):
        validate_arguments({"type": "object", "properties": {}}, ["not", "an", "object"])


def test_statistics_separate_group_totals_from_samples(dataset, incidents_by_category):
    incident_id = incidents_by_category["DoS"]
    stats = ToolRegistry(dataset, incident_id).execute("get_incident_statistics", {"incident_id": incident_id}).data
    record = dataset.record(incident_id)

    assert stats["group_totals"]["flows"] == record.alert["flow_count"]
    assert stats["sampled"]["flows_returned"] == len(record.alert["evidence_sample_ids"])
    assert "only" in stats["scope_note"].lower() or "sampled" in stats["scope_note"].lower()


def test_incident_detail_count_is_not_the_sample_count(dataset, incidents_by_category):
    incident_id = incidents_by_category["PortScan"]
    details = ToolRegistry(dataset, incident_id).execute("get_incident_details", {"incident_id": incident_id}).data
    assert details["aggregated_flow_count"] > details["evidence_sample_size"]


def test_dataset_files_are_untouched_by_investigation(dataset, incidents_by_category):
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    paths = [root / "src" / "real-alerts.json", root / "src" / "real-timelines.json"]
    before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}

    registry = ToolRegistry(dataset, incidents_by_category["DoS"])
    for name in TOOL_NAMES:
        registry.execute(name, {"incident_id": incidents_by_category["DoS"]})

    after = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    assert before == after
