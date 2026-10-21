"""Investigation-loop behaviour: the 14 required scenarios plus loop bounds.

Every test scripts the model, so all assertions are deterministic.
"""

from __future__ import annotations

import json

import pytest

from services.providers.base import ProviderRateLimited, ProviderTimeout
from tests.conftest import answer_turn, investigation_turn, tool_turn


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def flow_ids(dataset, incident_id, count=2):
    mapping = dataset.evidence_ids(incident_id)
    return [key for key, kind in mapping.items() if kind == "flow"][:count]


def alert_id(dataset, incident_id):
    mapping = dataset.evidence_ids(incident_id)
    return next(key for key, kind in mapping.items() if kind == "alert")


def make_proposal(dataset, incident_id, verdict, evidence=None, reason=None, **extra):
    evidence = evidence if evidence is not None else flow_ids(dataset, incident_id)
    record = dataset.record(incident_id)
    payload = {
        "incident_id": incident_id,
        "verdict": verdict,
        "confidence": "medium",
        "reason": reason
        or (
            f"Observed {record.alert['rule_basis']} with {record.alert['flow_count']} flows. "
            f"Inference: the sampled flows are consistent with {record.category} behaviour. "
            f"Evidence {evidence[0] if evidence else 'unavailable'}."
        ),
        "evidence_ids": list(evidence),
        "findings": [
            {"observation": f"Rule basis: {record.alert['rule_basis']}", "evidence_ids": list(evidence)[:1]}
        ],
        "limitations": "Only sampled flow records were available.",
    }
    payload.update(extra)
    return payload


# --------------------------------------------------------------------------- #
# 1-3: the three verdict paths
# --------------------------------------------------------------------------- #
def test_portscan_incident_is_classified_as_attack(service_factory, dataset, incidents_by_category):
    incident_id = incidents_by_category["PortScan"]
    triage, _ = service_factory(
        [investigation_turn(incident_id), answer_turn(make_proposal(dataset, incident_id, "Likely Attack"))]
    )

    result = triage.investigate(incident_id)

    assert result["status"] == "ok"
    assert result["verdict"] == "Likely Attack"
    assert result["validation"]["ok"] is True
    assert set(result["evidence_ids"]) <= set(dataset.evidence_ids(incident_id))
    cited = [call["tool"] for call in result["investigation"]["tool_calls"]]
    assert cited == [
        "get_incident_details",
        "get_related_alerts",
        "get_network_flows",
        "get_incident_statistics",
    ]


def test_dos_incident_is_classified_as_attack(service_factory, dataset, incidents_by_category):
    incident_id = incidents_by_category["DoS"]
    triage, _ = service_factory(
        [investigation_turn(incident_id), answer_turn(make_proposal(dataset, incident_id, "Likely Attack"))]
    )

    result = triage.investigate(incident_id)

    assert result["status"] == "ok"
    assert result["verdict"] == "Likely Attack"
    assert result["investigation"]["steps"] == 2


def test_benign_traffic_is_classified_as_benign(service_factory, benign_dataset):
    incident_id = "INC-BENIGN0001"
    triage, _ = service_factory(
        [
            investigation_turn(incident_id),
            answer_turn(
                make_proposal(
                    benign_dataset,
                    incident_id,
                    "Likely Benign",
                    reason=(
                        "Observed 2 flows and 25 packets over one minute to a single HTTPS "
                        "destination, with one destination port and two source ports. "
                        "Inference: this volume is consistent with a normal client session."
                    ),
                )
            ),
        ],
        data=benign_dataset,
    )

    result = triage.investigate(incident_id)

    assert result["status"] == "ok"
    assert result["verdict"] == "Likely Benign"
    # "Benign" is not one of the attack categories, so no closure escalation.
    assert result["requires_confirmation"] is False
    assert result["guardrail"]["closure_sensitive"] is False


# --------------------------------------------------------------------------- #
# 4: insufficient evidence
# --------------------------------------------------------------------------- #
def test_insufficient_evidence_yields_needs_review(service_factory, dataset, incidents_by_category):
    incident_id = incidents_by_category["DoS"]
    triage, _ = service_factory(
        [
            investigation_turn(incident_id),
            answer_turn(
                {
                    "incident_id": incident_id,
                    "verdict": "Needs Review",
                    "confidence": "low",
                    "reason": (
                        "The sampled flow records do not describe enough of the aggregated "
                        "traffic to distinguish a flood from a busy service."
                    ),
                    "evidence_ids": [],
                    "findings": [],
                    "limitations": "Only six sampled flows are retrievable.",
                }
            ),
        ]
    )

    result = triage.investigate(incident_id)

    assert result["status"] == "ok"
    assert result["verdict"] == "Needs Review"
    assert result["evidence_ids"] == []
    assert result["requires_confirmation"] is False


# --------------------------------------------------------------------------- #
# 5-7: validation rejects unsupported proposals
# --------------------------------------------------------------------------- #
def test_missing_evidence_for_attack_is_rejected(service_factory, dataset, incidents_by_category):
    incident_id = incidents_by_category["PortScan"]
    bad = make_proposal(dataset, incident_id, "Likely Attack", evidence=[])
    triage, _ = service_factory([investigation_turn(incident_id), answer_turn(bad), answer_turn(bad)])

    result = triage.investigate(incident_id)

    assert result["status"] == "rejected"
    assert result["verdict"] == "Needs Review"
    assert result["proposal"] is None
    assert result["error"]["code"] == "VALIDATION_FAILED"
    codes = {issue["code"] for issue in result["validation"]["issues"]}
    assert "MISSING_EVIDENCE" in codes
    # A rejected proposal is explicitly not a classification.
    assert "not a classification" in result["reason"]


def test_fabricated_evidence_id_is_rejected(service_factory, dataset, incidents_by_category):
    incident_id = incidents_by_category["PortScan"]
    bad = make_proposal(
        dataset, incident_id, "Likely Attack", evidence=["FLOW-DEADBEEF0000", "ALT-FFFFFFFFFFFF"]
    )
    triage, _ = service_factory([investigation_turn(incident_id), answer_turn(bad), answer_turn(bad)])

    result = triage.investigate(incident_id)

    assert result["status"] == "rejected"
    assert result["evidence_ids"] == []
    codes = {issue["code"] for issue in result["validation"]["issues"]}
    assert "UNKNOWN_EVIDENCE" in codes


def test_evidence_from_another_incident_is_rejected(service_factory, dataset, incidents_by_category):
    incident_id = incidents_by_category["PortScan"]
    other = incidents_by_category["DoS"]
    foreign = flow_ids(dataset, other, count=1)
    bad = make_proposal(dataset, incident_id, "Likely Attack", evidence=foreign)
    triage, _ = service_factory([investigation_turn(incident_id), answer_turn(bad), answer_turn(bad)])

    result = triage.investigate(incident_id)

    assert result["status"] == "rejected"
    codes = {issue["code"] for issue in result["validation"]["issues"]}
    assert "UNKNOWN_EVIDENCE" in codes


def test_invalid_verdict_is_rejected(service_factory, dataset, incidents_by_category):
    incident_id = incidents_by_category["DoS"]
    bad = make_proposal(dataset, incident_id, "Suspicious")
    triage, _ = service_factory([investigation_turn(incident_id), answer_turn(bad), answer_turn(bad)])

    result = triage.investigate(incident_id)

    assert result["status"] == "rejected"
    assert result["verdict"] == "Needs Review"
    codes = {issue["code"] for issue in result["validation"]["issues"]}
    assert "INVALID_VERDICT" in codes


def test_verdict_for_wrong_incident_is_rejected(service_factory, dataset, incidents_by_category):
    incident_id = incidents_by_category["DoS"]
    other = incidents_by_category["PortScan"]
    bad = make_proposal(dataset, incident_id, "Likely Attack")
    bad["incident_id"] = other
    triage, _ = service_factory([investigation_turn(incident_id), answer_turn(bad), answer_turn(bad)])

    result = triage.investigate(incident_id)

    assert result["status"] == "rejected"
    codes = {issue["code"] for issue in result["validation"]["issues"]}
    assert "INCIDENT_MISMATCH" in codes


def test_unsupported_statistic_is_rejected(service_factory, dataset, incidents_by_category):
    incident_id = incidents_by_category["DoS"]
    bad = make_proposal(
        dataset,
        incident_id,
        "Likely Attack",
        reason=(
            "Observed 50000 packets and 900 destination ports in the window, which indicates "
            "a flood. Evidence FLOW-745C5543C223 supports this."
        ),
    )
    triage, _ = service_factory([investigation_turn(incident_id), answer_turn(bad), answer_turn(bad)])

    result = triage.investigate(incident_id)

    assert result["status"] == "rejected"
    codes = {issue["code"] for issue in result["validation"]["issues"]}
    assert "UNSUPPORTED_STATISTIC" in codes


# --------------------------------------------------------------------------- #
# 8: malformed JSON
# --------------------------------------------------------------------------- #
def test_malformed_json_response_fails_safely(service_factory, incidents_by_category):
    incident_id = incidents_by_category["DoS"]
    triage, _ = service_factory(
        [investigation_turn(incident_id), answer_turn("This looks like an attack, trust me.")]
    )

    result = triage.investigate(incident_id)

    assert result["status"] == "error"
    assert result["verdict"] is None
    assert result["error"]["code"] == "MALFORMED_RESPONSE"


def test_json_wrapped_in_markdown_fence_is_accepted(service_factory, dataset, incidents_by_category):
    incident_id = incidents_by_category["DoS"]
    payload = make_proposal(dataset, incident_id, "Likely Attack")
    fenced = "Here is my answer:\n```json\n" + json.dumps(payload) + "\n```\n"
    triage, _ = service_factory([investigation_turn(incident_id), answer_turn(fenced)])

    result = triage.investigate(incident_id)

    assert result["status"] == "ok"
    assert result["verdict"] == "Likely Attack"


# --------------------------------------------------------------------------- #
# 9-10: provider failures are never security conclusions
# --------------------------------------------------------------------------- #
def test_provider_timeout_is_an_operational_error(service_factory, incidents_by_category):
    incident_id = incidents_by_category["DoS"]
    triage, _ = service_factory([ProviderTimeout("model timed out after 45s")])

    result = triage.investigate(incident_id)

    assert result["status"] == "error"
    assert result["verdict"] is None
    assert result["error"]["code"] == "PROVIDER_TIMEOUT"
    assert "not a benign or attack finding" in result["limitations"]
    assert result["requires_confirmation"] is False


def test_provider_rate_limit_is_an_operational_error(service_factory, incidents_by_category):
    incident_id = incidents_by_category["DoS"]
    triage, _ = service_factory(
        [ProviderRateLimited("free tier exhausted", retry_after=12.0)]
    )

    result = triage.investigate(incident_id)

    assert result["status"] == "error"
    assert result["verdict"] is None
    assert result["error"]["code"] == "PROVIDER_RATE_LIMITED"
    assert result["error"]["retry_after_seconds"] == 12.0


# --------------------------------------------------------------------------- #
# 11-12: tool failures and bad arguments
# --------------------------------------------------------------------------- #
def test_failed_tool_call_is_reported_and_recoverable(service_factory, dataset, incidents_by_category):
    incident_id = incidents_by_category["DoS"]
    triage, _ = service_factory(
        [
            tool_turn(
                ("get_incident_details", {"incident_id": incident_id}),
                ("get_related_alerts", {"incident_id": incident_id}),
                ("get_network_flows", {"incident_id": incident_id, "limit": 500}),
            ),
            answer_turn(
                make_proposal(
                    dataset, incident_id, "Likely Attack", evidence=[alert_id(dataset, incident_id)]
                )
            ),
        ]
    )

    result = triage.investigate(incident_id)

    assert result["status"] == "ok"
    assert result["investigation"]["tool_errors"] == 1
    failed = [call for call in result["investigation"]["tool_calls"] if not call["ok"]]
    assert failed[0]["error"]["code"] == "INVALID_ARGUMENTS"


def test_invalid_tool_argument_type_is_rejected_before_execution(service_factory, dataset, incidents_by_category):
    incident_id = incidents_by_category["DoS"]
    triage, _ = service_factory(
        [
            tool_turn(
                ("get_incident_details", {"incident_id": incident_id}),
                ("get_related_alerts", {"incident_id": incident_id}),
                ("get_network_flows", {"incident_id": incident_id, "limit": "all"}),
            ),
            answer_turn(
                make_proposal(
                    dataset, incident_id, "Likely Attack", evidence=[alert_id(dataset, incident_id)]
                )
            ),
        ]
    )

    result = triage.investigate(incident_id)

    assert result["status"] == "ok"
    call = [item for item in result["investigation"]["tool_calls"] if item["tool"] == "get_network_flows"][0]
    assert call["ok"] is False
    assert call["error"]["code"] == "INVALID_ARGUMENTS"
    assert "integer" in call["error"]["message"]


def test_tool_call_for_another_incident_is_blocked(service_factory, dataset, incidents_by_category):
    incident_id = incidents_by_category["DoS"]
    other = incidents_by_category["PortScan"]
    triage, _ = service_factory(
        [
            tool_turn(
                ("get_incident_details", {"incident_id": other}),
                ("get_incident_details", {"incident_id": incident_id}),
                ("get_related_alerts", {"incident_id": incident_id}),
            ),
            answer_turn(make_proposal(dataset, incident_id, "Likely Attack")),
        ]
    )

    result = triage.investigate(incident_id)

    assert result["status"] == "ok"
    call = result["investigation"]["tool_calls"][0]
    assert call["error"]["code"] == "INCIDENT_SCOPE_VIOLATION"
    # The correctly scoped calls still worked.
    assert result["investigation"]["tool_calls"][1]["ok"] is True


# --------------------------------------------------------------------------- #
# 13: unauthorized tool
# --------------------------------------------------------------------------- #
def test_unauthorized_tool_is_blocked(service_factory, dataset, incidents_by_category):
    incident_id = incidents_by_category["DoS"]
    triage, _ = service_factory(
        [
            tool_turn(
                ("close_incident", {"incident_id": incident_id}),
                ("run_shell", {"command": "rm -rf /"}),
                ("get_incident_details", {"incident_id": incident_id}),
                ("get_related_alerts", {"incident_id": incident_id}),
            ),
            answer_turn(make_proposal(dataset, incident_id, "Likely Attack")),
        ]
    )

    result = triage.investigate(incident_id)

    assert result["status"] == "ok"  # the verdict itself is still valid
    assert len(result["investigation"]["blocked_attempts"]) == 2
    blocked = [call for call in result["investigation"]["tool_calls"] if call["blocked"]]
    assert {call["tool"] for call in blocked} == {"close_incident", "run_shell"}
    assert all(call["error"]["code"] == "TOOL_NOT_ALLOWED" for call in blocked)


# --------------------------------------------------------------------------- #
# 14: guardrail - Likely Benign on an attack incident needs a human
# --------------------------------------------------------------------------- #
def test_likely_benign_on_attack_incident_requires_confirmation(
    service_factory, dataset, incidents_by_category
):
    incident_id = incidents_by_category["PortScan"]
    triage, _ = service_factory(
        [
            investigation_turn(incident_id),
            answer_turn(make_proposal(dataset, incident_id, "Likely Benign")),
        ]
    )

    result = triage.investigate(incident_id)

    assert result["status"] == "ok"
    assert result["verdict"] == "Likely Benign"
    assert result["requires_confirmation"] is True
    assert result["guardrail"]["closure_sensitive"] is True
    assert result["guardrail"]["auto_close_permitted"] is False
    assert result["decision"]["status"] == "pending"


# --------------------------------------------------------------------------- #
# Loop bounds and investigation depth
# --------------------------------------------------------------------------- #
def test_investigation_loop_is_bounded(service_factory, incidents_by_category):
    incident_id = incidents_by_category["DoS"]
    endless = tool_turn(("get_incident_details", {"incident_id": incident_id}))
    triage, provider = service_factory([endless, endless, endless], max_steps=2)

    result = triage.investigate(incident_id)

    assert result["status"] == "error"
    assert result["error"]["code"] == "STEP_LIMIT_REACHED"
    assert provider.calls == 2


def test_tool_call_budget_is_enforced(service_factory, incidents_by_category):
    incident_id = incidents_by_category["DoS"]
    endless = tool_turn(("get_incident_details", {"incident_id": incident_id}))
    triage, _ = service_factory([endless] * 5, max_steps=6, max_tool_calls=2)

    result = triage.investigate(incident_id)

    assert result["status"] == "error"
    assert result["error"]["code"] == "TOOL_BUDGET_EXCEEDED"
    executed = [call for call in result["investigation"]["tool_calls"] if not call["blocked"]]
    assert len(executed) == 2


def test_answer_without_tools_is_nudged_once(service_factory, dataset, incidents_by_category):
    incident_id = incidents_by_category["DoS"]
    triage, provider = service_factory(
        [
            answer_turn(make_proposal(dataset, incident_id, "Likely Attack")),
            investigation_turn(incident_id),
            answer_turn(make_proposal(dataset, incident_id, "Likely Attack")),
        ]
    )

    result = triage.investigate(incident_id)

    assert result["status"] == "ok"
    second_history = provider.histories[1]
    assert any("without calling any investigation tool" in (message.get("content") or "") for message in second_history)


def test_persistently_untooled_answer_is_rejected(service_factory, dataset, incidents_by_category):
    incident_id = incidents_by_category["DoS"]
    proposal = make_proposal(dataset, incident_id, "Likely Attack")
    triage, _ = service_factory(
        [answer_turn(proposal), answer_turn(proposal), answer_turn(proposal)]
    )

    result = triage.investigate(incident_id)

    assert result["status"] == "rejected"
    codes = {issue["code"] for issue in result["validation"]["issues"]}
    assert "NO_INVESTIGATION" in codes


def test_invalid_proposal_gets_one_repair_attempt(service_factory, dataset, incidents_by_category):
    incident_id = incidents_by_category["DoS"]
    bad = make_proposal(dataset, incident_id, "Likely Attack", evidence=["FLOW-NOTREAL0000"])
    good = make_proposal(dataset, incident_id, "Likely Attack")
    triage, provider = service_factory([investigation_turn(incident_id), answer_turn(bad), answer_turn(good)])

    result = triage.investigate(incident_id)

    assert result["status"] == "ok"
    assert result["investigation"]["corrections"] == 1
    assert provider.calls == 3
    correction_history = provider.histories[2]
    assert any("failed deterministic backend validation" in (m.get("content") or "") for m in correction_history)


def test_unknown_incident_raises(service_factory):
    from services.data_store import IncidentNotFound

    triage, _ = service_factory([])

    with pytest.raises(IncidentNotFound):
        triage.investigate("INC-DOESNOTEXIST")


def test_disabled_provider_raises_instead_of_falling_back(service_factory, incidents_by_category):
    triage, _ = service_factory([], provider="groq", api_keys={"groq": "", "gemini": "", "openrouter": "", "mock": ""})

    with pytest.raises(Exception) as excinfo:
        triage.investigate(incidents_by_category["DoS"])

    assert "GROQ_API_KEY" in str(excinfo.value)
