"""HTTP surface: status reporting, triage endpoint, decisions, audit, 404s."""

from __future__ import annotations

from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

import services.ai_api as api_module
from services.audit_log import AuditLog
from services.providers import ProviderRateLimited
from services.triage import TriageService


@pytest.fixture
def client(settings, dataset):
    api_module.services.settings = settings
    api_module.services.dataset = dataset
    api_module.services.error = None
    api_module.services.audit = AuditLog(settings.audit_path)
    api_module.services.triage = TriageService(settings, dataset, audit=api_module.services.audit)
    with TestClient(api_module.app) as test_client:
        yield test_client


def first_incident(client):
    return client.get("/api/incidents").json()["incidents"][0]["incident_id"]


# --------------------------------------------------------------------------- #
# Health / status
# --------------------------------------------------------------------------- #
def test_health_reports_mode_without_secrets(client):
    body = client.get("/api/health").json()
    assert body["ok"] is True
    assert body["ai"]["provider"] == "mock"
    assert body["ai"]["mode"] == "mock"
    assert body["ai"]["key_configured"] is True
    assert body["guardrail"]["connected"] is True
    assert body["recommendations"]["available"] is False
    serialized = str(body)
    assert "api_key" not in serialized.lower() or "key_configured" in serialized


def test_provider_matrix_is_reported(client):
    providers = client.get("/api/settings").json()["providers"]
    by_id = {item["id"]: item for item in providers}
    assert by_id["groq"]["implemented"] is True
    assert by_id["gemini"]["implemented"] is True
    assert by_id["openrouter"]["implemented"] is False
    assert by_id["mock"]["selected"] is True


# --------------------------------------------------------------------------- #
# Read endpoints
# --------------------------------------------------------------------------- #
def test_dataset_summary(client, dataset):
    body = client.get("/api/dataset").json()
    assert body["counts"]["incidents"] == len(dataset.incidents)
    assert body["counts"]["alerts"] == len(dataset.alerts)
    assert set(body["counts"]["alert_categories"]) == {"PortScan", "DoS", "BruteForce"}
    assert body["counts"]["represented_flows"] > body["counts"]["sampled_flows"]


def test_incident_list_shape(client, dataset):
    body = client.get("/api/incidents").json()
    incidents = body["incidents"]
    assert len(incidents) == len(dataset.incidents)
    first = incidents[0]
    assert set(first) >= {
        "incident_id",
        "category",
        "source_ip",
        "destination_ip",
        "window_start",
        "flow_count",
        "triage",
    }
    assert first["triage"]["verdict"] is None
    assert first["triage"]["status"] is None


def test_incident_detail_separates_reference_label(client):
    incident_id = first_incident(client)
    body = client.get(f"/api/incidents/{incident_id}").json()
    assert body["incident"]["incident_id"] == incident_id
    assert body["incident"]["reference_label"]["note"].startswith("CIC-IDS2017")
    assert body["timeline"]["events"]
    assert all(event.get("evidence_id") for event in body["timeline"]["events"])
    assert body["recommendations"]["available"] is False


def test_unknown_incident_returns_404(client):
    response = client.get("/api/incidents/INC-NOPE000000")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "INCIDENT_NOT_FOUND"


# --------------------------------------------------------------------------- #
# Triage
# --------------------------------------------------------------------------- #
def test_triage_endpoint_runs_the_mock_investigation(client):
    incident_id = first_incident(client)

    response = client.post(f"/api/incidents/{incident_id}/triage")
    assert response.status_code == 200

    result = response.json()["triage"]
    assert result["status"] == "ok"
    assert result["verdict"] in ("Likely Attack", "Likely Benign", "Needs Review")
    assert result["mode"] == "mock"
    assert result["evidence_ids"]
    assert result["decision"]["status"] == "pending"
    assert result["prohibited_actions"]

    stored = client.get(f"/api/incidents/{incident_id}/triage").json()
    assert stored["triage"]["run_id"] == result["run_id"]


def test_triage_result_appears_in_incident_list(client):
    incident_id = first_incident(client)
    client.post(f"/api/incidents/{incident_id}/triage")

    incidents = client.get("/api/incidents").json()["incidents"]
    entry = next(item for item in incidents if item["incident_id"] == incident_id)
    assert entry["triage"]["verdict"] == "Likely Attack"
    assert entry["triage"]["decision"] == "pending"


def test_provider_failure_is_a_502_not_a_verdict(client, settings, dataset):
    def explode():
        raise ProviderRateLimited("free tier exhausted", retry_after=30.0)

    api_module.services.triage = TriageService(
        settings, dataset, audit=api_module.services.audit, provider_factory=explode
    )
    incident_id = first_incident(client)

    response = client.post(f"/api/incidents/{incident_id}/triage")

    assert response.status_code == 502
    result = response.json()["triage"]
    assert result["status"] == "error"
    assert result["verdict"] is None
    assert result["error"]["code"] == "PROVIDER_RATE_LIMITED"


def test_unconfigured_live_provider_returns_503(client, settings, dataset):
    unconfigured = replace(
        settings, provider="gemini", api_keys={**settings.api_keys, "gemini": ""}
    )
    api_module.services.settings = unconfigured
    api_module.services.triage = TriageService(unconfigured, dataset, audit=api_module.services.audit)
    incident_id = first_incident(client)

    response = client.post(f"/api/incidents/{incident_id}/triage")

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "PROVIDER_NOT_CONFIGURED"


# --------------------------------------------------------------------------- #
# Analyst decisions
# --------------------------------------------------------------------------- #
def test_decision_requires_an_existing_proposal(client):
    incident_id = first_incident(client)
    response = client.post(
        f"/api/incidents/{incident_id}/decision", json={"decision": "confirmed", "analyst": "a"}
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "NO_PROPOSAL"


def test_decision_requires_analyst_name(client):
    incident_id = first_incident(client)
    client.post(f"/api/incidents/{incident_id}/triage")
    response = client.post(f"/api/incidents/{incident_id}/decision", json={"decision": "confirmed"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "MISSING_ANALYST"


def test_rejection_requires_a_note(client):
    incident_id = first_incident(client)
    client.post(f"/api/incidents/{incident_id}/triage")
    response = client.post(
        f"/api/incidents/{incident_id}/decision",
        json={"decision": "rejected", "analyst": "ana"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_DECISION"


def test_confirming_a_proposal_is_recorded_backend_side(client):
    incident_id = first_incident(client)
    client.post(f"/api/incidents/{incident_id}/triage")

    response = client.post(
        f"/api/incidents/{incident_id}/decision",
        json={"decision": "confirmed", "analyst": "ana.analyst", "note": "Verified in PCAP."},
    )

    assert response.status_code == 200
    assert response.json()["decision"]["status"] == "confirmed"
    assert response.json()["decision"]["analyst"] == "ana.analyst"

    incidents = client.get("/api/incidents").json()["incidents"]
    entry = next(item for item in incidents if item["incident_id"] == incident_id)
    assert entry["triage"]["decision"] == "confirmed"

    audit = client.get(f"/api/audit?incident_id={incident_id}").json()
    events = [entry["event"] for entry in audit["entries"]]
    assert "triage.started" in events
    assert "analyst.decision" in events
    assert audit["verification"]["ok"] is True


def test_a_new_proposal_resets_the_decision(client):
    incident_id = first_incident(client)
    client.post(f"/api/incidents/{incident_id}/triage")
    client.post(
        f"/api/incidents/{incident_id}/decision",
        json={"decision": "confirmed", "analyst": "ana"},
    )
    client.post(f"/api/incidents/{incident_id}/triage")

    stored = client.get(f"/api/incidents/{incident_id}/triage").json()
    assert stored["decision"]["status"] == "pending"


# --------------------------------------------------------------------------- #
# Module 4 boundary
# --------------------------------------------------------------------------- #
def test_recommendations_are_reported_as_unavailable(client):
    incident_id = first_incident(client)
    body = client.get(f"/api/incidents/{incident_id}/recommendations").json()
    assert body["available"] is False
    assert body["items"] == []
    assert body["owner"].startswith("Module 4")


def test_approval_endpoint_refuses_when_module4_is_absent(client):
    incident_id = first_incident(client)
    response = client.post(f"/api/incidents/{incident_id}/recommendations/REC-1/approve")
    assert response.status_code == 501
    assert response.json()["error"]["code"] == "MODULE_NOT_CONNECTED"


# --------------------------------------------------------------------------- #
# CORS
# --------------------------------------------------------------------------- #
def test_cors_allows_configured_origin_only(client):
    allowed = client.options(
        "/api/health",
        headers={
            "Origin": "http://127.0.0.1:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == "http://127.0.0.1:5173"

    denied = client.options(
        "/api/health",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert "access-control-allow-origin" not in denied.headers
