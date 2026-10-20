"""Shared fixtures for the Module 2 test suite.

No network and no API key is required: every model interaction is scripted.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Keep test artefacts out of the repository working tree.
_SCRATCH = Path(tempfile.mkdtemp(prefix="soc-triage-tests-"))
os.environ.setdefault("AI_PROVIDER", "mock")
os.environ["AUDIT_LOG_PATH"] = str(_SCRATCH / "audit.jsonl")
os.environ["TRIAGE_STATE_PATH"] = str(_SCRATCH / "state.json")

from services.config import PROVIDER_DEFAULT_MODELS, Settings  # noqa: E402
from services.data_store import Dataset  # noqa: E402
from services.providers.base import AssistantTurn, ToolCall  # noqa: E402
from services.triage import TriageService  # noqa: E402


# --------------------------------------------------------------------------- #
# Model scripting
# --------------------------------------------------------------------------- #
class ScriptedProvider:
    """Replays a fixed list of turns and records what the loop sent."""

    name = "scripted"
    model = "scripted-model"

    def __init__(self, turns):
        self.turns = list(turns)
        self.calls = 0
        self.histories: list[list[dict]] = []

    def complete(self, messages, tools, *, timeout=None):
        self.histories.append([dict(message) for message in messages])
        if self.calls >= len(self.turns):
            raise AssertionError(
                f"provider called {self.calls + 1} times but only {len(self.turns)} turns were scripted"
            )
        turn = self.turns[self.calls]
        self.calls += 1
        if isinstance(turn, BaseException):
            raise turn
        return turn


def tool_turn(*calls: tuple[str, dict]) -> AssistantTurn:
    return AssistantTurn(
        text=None,
        tool_calls=[
            ToolCall(id=f"call_{index}", name=name, arguments=arguments)
            for index, (name, arguments) in enumerate(calls)
        ],
        finish_reason="tool_calls",
    )


def answer_turn(payload) -> AssistantTurn:
    text = payload if isinstance(payload, str) else json.dumps(payload)
    return AssistantTurn(text=text, finish_reason="stop")


def investigation_turn(incident_id: str, limit: int = 6) -> AssistantTurn:
    return tool_turn(
        ("get_incident_details", {"incident_id": incident_id}),
        ("get_related_alerts", {"incident_id": incident_id}),
        ("get_network_flows", {"incident_id": incident_id, "limit": limit}),
        ("get_incident_statistics", {"incident_id": incident_id}),
    )


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="session")
def dataset() -> Dataset:
    return Dataset.load(ROOT / "src" / "real-alerts.json", ROOT / "src" / "real-timelines.json")


@pytest.fixture(scope="session")
def benign_dataset() -> Dataset:
    """A synthetic low-volume incident, used to exercise the Likely Benign path.

    Module 1's current preview only emits rule matches for attack-shaped traffic,
    so there is no benign incident in the artefact. This fixture states that
    explicitly instead of pretending one of the real incidents is benign.
    """
    flows = [
        {
            "flow_id": "FLOW-BENIGN000001",
            "timestamp": "2017-07-05T09:00:00",
            "source_ip": "192.168.10.20",
            "source_port": "51001",
            "destination_ip": "172.217.1.1",
            "destination_port": "443",
            "packet_count": 14.0,
            "dataset_label": "BENIGN",
            "source_file": "synthetic-benign.csv",
            "source_row": 2,
            "original_flow_id": "synthetic-1",
        },
        {
            "flow_id": "FLOW-BENIGN000002",
            "timestamp": "2017-07-05T09:00:00",
            "source_ip": "192.168.10.20",
            "source_port": "51002",
            "destination_ip": "172.217.1.1",
            "destination_port": "443",
            "packet_count": 11.0,
            "dataset_label": "BENIGN",
            "source_file": "synthetic-benign.csv",
            "source_row": 3,
            "original_flow_id": "synthetic-2",
        },
    ]
    alert = {
        "alert_id": "ALT-BENIGN0001",
        "incident_id": "INC-BENIGN0001",
        "type": "Benign",
        "timestamp": "2017-07-05T09:00:00",
        "source_ip": "192.168.10.20",
        "destination_ip": "172.217.1.1",
        "flow_count": 2,
        "destination_port_count": 1,
        "source_port_count": 2,
        "source_count": 1,
        "evidence_sample_ids": [flow["flow_id"] for flow in flows],
        "dataset_labels": {"BENIGN": 2},
        "ddos_reference": False,
        "rule_basis": "2 flows, 25 packets in one minute",
    }
    incident = {
        "incident_id": "INC-BENIGN0001",
        "source_ip": "192.168.10.20",
        "destination_ip": "172.217.1.1",
        "window_start": "2017-07-05T09:00:00",
        "alert_ids": [alert["alert_id"]],
        "evidence_sample_ids": [flow["flow_id"] for flow in flows],
        "flow_count": 2,
        "source_file": "synthetic-benign.csv",
    }
    payload = {
        "provenance": {"dataset": "synthetic fixture", "archive": None, "files": ["synthetic-benign.csv"]},
        "rules": {"window_seconds": 60},
        "evaluation": {"groups_scanned": 1, "rule_matches": 0, "preview_cases": 1},
        "flows": flows,
        "alerts": [alert],
        "incidents": [incident],
    }
    timelines = {
        "timelines": [
            {
                "incident_id": incident["incident_id"],
                "total_flows": 2,
                "sampled_events": 2,
                "events": [
                    {
                        "timestamp": flow["timestamp"],
                        "title": f"{flow['source_ip']} -> port {flow['destination_port']}",
                        "record_type": "flow",
                        "evidence_id": flow["flow_id"],
                        "source_file": flow["source_file"],
                        "source_row": flow["source_row"],
                        "technique": "Unmapped",
                    }
                    for flow in flows
                ],
            }
        ]
    }
    return Dataset(payload, timelines)


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        provider="mock",
        api_keys={"groq": "", "gemini": "", "openrouter": "", "mock": ""},
        models=dict(PROVIDER_DEFAULT_MODELS),
        max_steps=6,
        request_timeout=5.0,
        max_tool_calls=12,
        alerts_path=ROOT / "src" / "real-alerts.json",
        timelines_path=ROOT / "src" / "real-timelines.json",
        audit_path=tmp_path / "audit.jsonl",
        state_path=tmp_path / "state.json",
    )


@pytest.fixture
def service_factory(settings, dataset):
    def build(turns, *, data: Dataset | None = None, **overrides):
        provider = ScriptedProvider(turns)
        triage = TriageService(
            replace(settings, **overrides),
            data or dataset,
            provider_factory=lambda: provider,
        )
        return triage, provider

    return build


@pytest.fixture
def incidents_by_category(dataset) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for incident_id in dataset.incident_ids():
        mapping.setdefault(dataset.record(incident_id).category, incident_id)
    return mapping
