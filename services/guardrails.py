PROTECTED_ALERTS = {"PortScan", "DoS", "DDoS"}

VALID_VERDICTS = {
    "Likely Attack",
    "Likely Benign",
    "Needs Review",
}

# Only these read-only investigation steps are permitted.
ALLOWED_ACTIONS = {
    "REVIEW_NETWORK_FLOWS",
    "CHECK_RELATED_ALERTS",
    "REVIEW_INCIDENT_TIMELINE",
    "ESCALATE_TO_ANALYST",
}


def validate_guardrails(result, incident_id, proposal):
    """
    Validate an AI proposal against real incident evidence.

    Returns:
        ALLOWED, REVIEW_REQUIRED, or BLOCKED
    """

    blocked = []
    review = []

    if not isinstance(proposal, dict):
        return {
            "status": "BLOCKED",
            "reasons": ["Invalid AI proposal format"],
        }

    allowed_fields = {
        "verdict",
        "evidence_ids",
        "actions",
        "proposed_priority",
    }

    if set(proposal) - allowed_fields:
        blocked.append("Unexpected AI proposal fields")

    # 1. Find the selected incident
    incident = next(
        (
            item for item in result["incidents"]
            if item["incident_id"] == incident_id
        ),
        None,
    )

    if incident is None:
        return {
            "status": "BLOCKED",
            "reasons": ["Incident not found"],
        }

    # 2. Find alerts belonging to this incident
    alerts_by_id = {
        alert["alert_id"]: alert
        for alert in result["alerts"]
    }

    flow_ids = {
        flow["flow_id"] for flow in result["flows"]
    }

    incident_alerts = [
        alerts_by_id[alert_id]
        for alert_id in incident["alert_ids"]
        if alert_id in alerts_by_id
    ]

    if len(incident_alerts) != len(incident["alert_ids"]):
        blocked.append("Incident references missing alerts")

    if not incident_alerts:
        blocked.append("Incident has no alerts")
        
    if any(
            alert["incident_id"] != incident_id
            for alert in incident_alerts
    ):
        blocked.append("Alert belongs to another incident")

    # 3. Collect valid evidence IDs for this incident
    valid_flows = set(incident["evidence_sample_ids"]) & flow_ids

    if len(valid_flows) != len(set(incident["evidence_sample_ids"])):
        blocked.append("Incident references missing flows")

    valid_evidence = valid_flows | {
        alert["alert_id"] for alert in incident_alerts
    }

    # 4. Check the AI verdict
    verdict = proposal.get("verdict")

    if verdict not in VALID_VERDICTS:
        blocked.append("Unknown AI verdict")

    # 5. Validate supporting evidence
    evidence_ids = proposal.get("evidence_ids")

    if (
        not isinstance(evidence_ids, list)
        or not evidence_ids
        or any(not isinstance(eid, str) for eid in evidence_ids)
    ):
        blocked.append("Missing or malformed evidence IDs")
    elif not set(evidence_ids).issubset(valid_evidence):
        blocked.append("Invalid or unrelated evidence IDs")

    # 6. Validate proposed investigation actions
    actions = proposal.get("actions", [])

    if (
        not isinstance(actions, list)
        or any(not isinstance(action, str) for action in actions)
    ):
        blocked.append("Malformed action list")
    else:
        for action in actions:
            if action not in ALLOWED_ACTIONS:
                blocked.append(f"Prohibited or unknown action: {action}")

    # 7. Require review for protected benign verdicts
    alert_types = {
        alert["type"] for alert in incident_alerts
    }

    if alert_types - (PROTECTED_ALERTS | {"Benign"}):
        blocked.append("Unknown alert type")

    if (
        verdict == "Likely Benign"
        and alert_types & PROTECTED_ALERTS
    ):
        review.append(
            "Protected alert detected: analyst confirmation required"
        )

    # 8. Check for automatic priority downgrades
    # Any AI-requested change is prohibited in this MVP.
    if "proposed_priority" in proposal:
        blocked.append("AI priority changes are not permitted")

    # 9. Return final result
    if blocked:
        return {
            "status": "BLOCKED",
            "reasons": blocked + review,
        }

    if review:
        return {
            "status": "REVIEW_REQUIRED",
            "reasons": review,
        }

    return {
        "status": "ALLOWED",
        "reasons": ["Proposal passed safety validation"],
    }
