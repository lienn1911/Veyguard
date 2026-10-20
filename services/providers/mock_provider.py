"""Deterministic, offline stand-in for the LLM.

Purpose: the full investigation loop - tool calls, evidence binding, verdict
validation, guardrails, audit trail, UI - must be demonstrable and testable
before any API key exists. This provider follows exactly the same message
protocol as Groq/Gemini, but derives its answer from the tool results it
receives instead of from a language model.

It is selected explicitly with ``AI_PROVIDER=mock``. It is never used as a
silent fallback: when a live provider is misconfigured the API reports an error
instead of quietly switching here.
"""

from __future__ import annotations

import json
from typing import Any, Sequence

from .base import AssistantTurn, ToolCall, dumps


class MockProvider:
    name = "mock"
    model = "mock-triage-model"

    def complete(
        self,
        messages: Sequence[dict],
        tools: Sequence[dict],
        *,
        timeout: float | None = None,
    ) -> AssistantTurn:
        results = _collect_tool_results(messages)
        if not results:
            return AssistantTurn(
                text="Starting a read-only investigation of the incident.",
                tool_calls=[
                    ToolCall(id="mock_call_details", name="get_incident_details", arguments={"incident_id": _incident_id(messages)}),
                    ToolCall(id="mock_call_alerts", name="get_related_alerts", arguments={"incident_id": _incident_id(messages)}),
                    ToolCall(id="mock_call_flows", name="get_network_flows", arguments={"incident_id": _incident_id(messages), "limit": 6}),
                    ToolCall(id="mock_call_stats", name="get_incident_statistics", arguments={"incident_id": _incident_id(messages)}),
                ],
                finish_reason="tool_calls",
            )
        return AssistantTurn(text=_verdict_text(results), finish_reason="stop")


# --------------------------------------------------------------------------- #
# Conversation inspection
# --------------------------------------------------------------------------- #
def _incident_id(messages: Sequence[dict]) -> str:
    for message in messages:
        if message.get("role") == "user":
            marker = "Incident ID:"
            content = message.get("content") or ""
            if marker in content:
                return content.split(marker, 1)[1].split()[0].strip("`.,")
    return ""


def _collect_tool_results(messages: Sequence[dict]) -> dict[str, dict]:
    results: dict[str, dict] = {}
    for message in messages:
        if message.get("role") != "tool":
            continue
        try:
            payload = json.loads(message.get("content") or "{}")
        except json.JSONDecodeError:
            continue
        name = message.get("name") or payload.get("tool")
        if name:
            results[name] = payload
    return results


# --------------------------------------------------------------------------- #
# Verdict synthesis
# --------------------------------------------------------------------------- #
def _verdict_text(results: dict[str, dict]) -> str:
    details = (results.get("get_incident_details") or {}).get("data") or {}
    alerts = ((results.get("get_related_alerts") or {}).get("data") or {}).get("alerts") or []
    flows = ((results.get("get_network_flows") or {}).get("data") or {}).get("flows") or []
    stats = (results.get("get_incident_statistics") or {}).get("data") or {}

    incident_id = details.get("incident_id") or ""
    evidence_pool = [flow.get("flow_id") for flow in flows if flow.get("flow_id")]
    for alert in alerts:
        if alert.get("alert_id"):
            evidence_pool.append(alert["alert_id"])

    if not details or not alerts:
        return dumps(
            {
                "incident_id": incident_id,
                "verdict": "Needs Review",
                "confidence": "low",
                "reason": (
                    "The investigation could not retrieve the incident record or its alerts, "
                    "so no classification can be supported by evidence."
                ),
                "evidence_ids": [],
                "findings": [],
                "limitations": "Incident metadata or related alerts were unavailable from the tools.",
            }
        )

    alert = alerts[0]
    category = alert.get("type") or "Unknown"
    group = stats.get("group_totals") or {}
    flow_count = group.get("flows") or alert.get("flow_count") or 0
    ports = group.get("destination_ports") or alert.get("destination_port_count") or 0
    source_ports = group.get("source_ports") or alert.get("source_port_count") or 0

    # Deterministic, evidence-only heuristic: this mirrors the Module 1 rule
    # thresholds, not the dataset ground-truth label (which is never provided
    # to any provider).
    attack = False
    observation = ""
    if category == "PortScan" and ports >= 100 and source_ports >= 10:
        attack = True
        observation = (
            f"{category} rule matched over {flow_count} flows: {ports} distinct destination "
            f"ports and {source_ports} source ports were contacted inside one minute."
        )
    elif category in ("DoS", "DDoS") and flow_count >= 1000:
        attack = True
        observation = (
            f"{category} rule matched over {flow_count} flows against a single destination, "
            "which is far above interactive traffic volume for a one-minute window."
        )

    cited = evidence_pool[: max(1, min(3, len(evidence_pool)))]
    findings = [
        {
            "observation": observation or "The sampled flows do not show behaviour above the rule thresholds.",
            "evidence_ids": cited[:2],
        }
    ]
    for flow in flows[:2]:
        findings.append(
            {
                "observation": (
                    f"Sampled flow {flow.get('source_ip')} to {flow.get('destination_ip')}:"
                    f"{flow.get('destination_port')} carries {flow.get('packet_count')} packets "
                    f"(CSV row {flow.get('source_row')})."
                ),
                "evidence_ids": [flow.get("flow_id")],
            }
        )

    if attack:
        verdict = "Likely Attack"
        confidence = "medium"
        reason = (
            f"{observation} The behaviour is consistent with the {category} detection rule rather "
            "than with routine user activity, and it is supported by the cited flow records."
        )
        limitations = (
            "Only a sample of the aggregated flows is retrievable through read-only tools; "
            "no packet payloads were inspected."
        )
    else:
        verdict = "Needs Review"
        confidence = "low"
        reason = (
            "The retrieved records do not exclude an attack, but the sampled evidence is not "
            "sufficient to support a confident classification."
        )
        limitations = "Sampled evidence only; analyst review required."

    return dumps(
        {
            "incident_id": incident_id,
            "verdict": verdict,
            "confidence": confidence,
            "reason": reason,
            "evidence_ids": cited,
            "findings": findings,
            "limitations": limitations,
        }
    )
