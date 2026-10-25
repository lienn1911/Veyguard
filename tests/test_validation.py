"""Deterministic validation of model proposals."""

from __future__ import annotations

import pytest

from services.validation import (
    ParseFailure,
    check_numeric_claims,
    collect_numbers,
    extract_json_object,
    normalize_verdict,
    validate_proposal,
)

EVIDENCE = {"FLOW-AAAAAAAAAAAA": "flow", "FLOW-BBBBBBBBBBBB": "flow", "ALT-CCCCCCCCCCCC": "alert"}


def proposal(**overrides):
    payload = {
        "incident_id": "INC-CADF3563BF02",
        "verdict": "Likely Attack",
        "confidence": "medium",
        "reason": "Observed 17752 flows against one destination; inference is a flood.",
        "evidence_ids": ["FLOW-AAAAAAAAAAAA"],
        "findings": [
            {"observation": "17752 flows in one minute", "evidence_ids": ["FLOW-AAAAAAAAAAAA"]}
        ],
        "limitations": "",
    }
    payload.update(overrides)
    return payload


def run_validation(payload, *, numbers=None, tool_calls=3, evidence=None):
    return validate_proposal(
        payload,
        incident_id="INC-CADF3563BF02",
        evidence_ids=evidence or EVIDENCE,
        evidence_numbers=numbers if numbers is not None else {17752.0},
        tool_call_count=tool_calls,
    )


def codes(report):
    return {issue.code for issue in report.issues}


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "text",
    [
        '{"verdict": "Needs Review"}',
        '```json\n{"verdict": "Needs Review"}\n```',
        'Here you go:\n{"verdict": "Needs Review"}\nDone.',
    ],
)
def test_extract_json_object_accepts_common_shapes(text):
    assert extract_json_object(text)["verdict"] == "Needs Review"


@pytest.mark.parametrize("text", ["", "   ", "definitely not json", "[1, 2, 3]"])
def test_extract_json_object_rejects_garbage(text):
    with pytest.raises(ParseFailure):
        extract_json_object(text)


def test_extract_json_object_reports_malformed_code():
    with pytest.raises(ParseFailure) as excinfo:
        extract_json_object('{"verdict": "Likely Attack",}')
    assert excinfo.value.code == "MALFORMED_RESPONSE"


# --------------------------------------------------------------------------- #
# Verdict normalisation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Likely Attack", "Likely Attack"),
        ("likely attack", "Likely Attack"),
        ("  NEEDS  review ", "Needs Review"),
        ("Likely-Benign", None),
        ("Attack", None),
        (None, None),
        (3, None),
    ],
)
def test_normalize_verdict(raw, expected):
    assert normalize_verdict(raw) == expected


# --------------------------------------------------------------------------- #
# Numeric claims
# --------------------------------------------------------------------------- #
def test_collect_numbers_reads_nested_payloads_and_strings():
    numbers = collect_numbers(
        {"group": {"flows": 17752}, "note": "996 destination ports", "list": [1, 2.5]}
    )
    assert {17752.0, 996.0, 1.0, 2.5} <= numbers


def test_supported_statistic_passes():
    assert check_numeric_claims("17752 flows were aggregated.", {17752.0}) == []


def test_fabricated_statistic_is_an_error():
    issues = check_numeric_claims("The window shows 50000 packets.", {17752.0})
    assert issues and issues[0].code == "UNSUPPORTED_STATISTIC"
    assert issues[0].level == "error"


def test_small_numbers_are_only_warnings():
    issues = check_numeric_claims("Only 7 flows were sampled.", {17752.0})
    assert issues and issues[0].level == "warning"


# --------------------------------------------------------------------------- #
# Proposal validation
# --------------------------------------------------------------------------- #
def test_valid_proposal_passes():
    report = run_validation(proposal())
    assert report.ok is True
    assert report.proposal["verdict"] == "Likely Attack"
    assert report.proposal["evidence_ids"] == ["FLOW-AAAAAAAAAAAA"]


def test_unknown_evidence_is_rejected():
    report = run_validation(proposal(evidence_ids=["FLOW-FFFFFFFFFFFF"]))
    assert report.ok is False
    assert "UNKNOWN_EVIDENCE" in codes(report)
    assert report.proposal is None


def test_attack_without_evidence_is_rejected():
    report = run_validation(proposal(evidence_ids=[]))
    assert "MISSING_EVIDENCE" in codes(report)


def test_needs_review_may_have_no_evidence():
    report = run_validation(proposal(verdict="Needs Review", evidence_ids=[]))
    assert report.ok is True
    assert report.proposal["evidence_ids"] == []


def test_invalid_verdict_is_rejected():
    report = run_validation(proposal(verdict="Probably Fine"))
    assert "INVALID_VERDICT" in codes(report)


def test_incident_mismatch_is_rejected():
    report = run_validation(proposal(incident_id="INC-OTHER0000001"))
    assert "INCIDENT_MISMATCH" in codes(report)


def test_short_reason_is_rejected():
    report = run_validation(proposal(reason="bad"))
    assert "MISSING_REASON" in codes(report)


def test_finding_with_foreign_evidence_is_rejected():
    report = run_validation(
        proposal(findings=[{"observation": "something", "evidence_ids": ["ALT-ZZZZZZZZZZZZ"]}])
    )
    assert "UNKNOWN_EVIDENCE" in codes(report)


def test_evidence_list_must_be_a_list():
    report = run_validation(proposal(evidence_ids="FLOW-AAAAAAAAAAAA"))
    assert "INVALID_EVIDENCE_LIST" in codes(report)


def test_zero_tool_calls_is_rejected():
    report = run_validation(proposal(), tool_calls=0)
    assert "NO_INVESTIGATION" in codes(report)


def test_evidence_cap_is_enforced():
    report = run_validation(proposal(evidence_ids=["FLOW-AAAAAAAAAAAA"] * 15))
    # duplicates collapse to one id, so the cap is not tripped by repetition
    assert report.ok is True
    assert report.proposal["evidence_ids"] == ["FLOW-AAAAAAAAAAAA"]


def test_confidence_is_normalised():
    report = run_validation(proposal(confidence="CERTAIN"))
    assert report.ok is True
    assert report.proposal["confidence"] == "low"
