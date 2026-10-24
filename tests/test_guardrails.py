"""Guardrail integration: local rules, Module 5 bridge, and no silent weakening."""

from __future__ import annotations

import sys
import types

import pytest

import services as services_pkg
from services import guardrail_bridge
from services.safety import PROHIBITED_ACTIONS, local_assessment


def test_likely_benign_on_attack_category_needs_a_human():
    assessment = local_assessment("Likely Benign", "PortScan")
    assert assessment.requires_confirmation is True
    assert assessment.closure_sensitive is True
    assert assessment.auto_close_permitted is False
    assert any("Safe-closure" in reason for reason in assessment.reasons)


@pytest.mark.parametrize("category", ["DoS", "DDoS", "PortScan"])
def test_all_attack_categories_are_closure_sensitive(category):
    assert local_assessment("Likely Benign", category).requires_confirmation is True


def test_benign_on_non_attack_category_is_not_escalated():
    assert local_assessment("Likely Benign", "Benign").requires_confirmation is False


@pytest.mark.parametrize("verdict", ["Likely Attack", "Needs Review"])
def test_no_verdict_can_auto_close(verdict):
    assessment = local_assessment(verdict, "DoS")
    assert assessment.auto_close_permitted is False
    assert assessment.severity_change is None


def test_prohibited_actions_are_declared():
    assert "close_incident" in PROHIBITED_ACTIONS
    assert "downgrade_severity" in PROHIBITED_ACTIONS
    assert "modify_evidence" in PROHIBITED_ACTIONS


def test_bridge_uses_connected_module5():
    assessment = guardrail_bridge.assess(
        incident_id="INC-X", category="DoS", verdict="Likely Benign", evidence_ids=["FLOW-1"]
    )
    assert assessment.requires_confirmation is True
    assert assessment.source == "services.guardrails.evaluate_proposal"
    assert guardrail_bridge.module5_status()["connected"] is True


def test_bridge_uses_module5_when_present(monkeypatch):
    fake = types.ModuleType("services.guardrails")

    def evaluate_proposal(*, incident_id, category, verdict, evidence_ids):
        return {"allowed": True, "requires_confirmation": False, "reasons": ["module5 says fine"]}

    fake.evaluate_proposal = evaluate_proposal
    monkeypatch.setitem(sys.modules, "services.guardrails", fake)
    monkeypatch.setattr(services_pkg, "guardrails", fake, raising=False)

    assessment = guardrail_bridge.assess(
        incident_id="INC-X", category="Benign", verdict="Likely Benign", evidence_ids=["FLOW-1"]
    )

    assert assessment.source == "services.guardrails.evaluate_proposal"
    assert "module5 says fine" in assessment.reasons


def test_module5_cannot_weaken_the_local_rule(monkeypatch):
    """A permissive teammate implementation must not unlock auto-closure."""
    fake = types.ModuleType("services.guardrails")
    fake.evaluate_proposal = lambda **_: {"allowed": True, "requires_confirmation": False, "reasons": []}
    monkeypatch.setitem(sys.modules, "services.guardrails", fake)
    monkeypatch.setattr(services_pkg, "guardrails", fake, raising=False)

    assessment = guardrail_bridge.assess(
        incident_id="INC-X", category="PortScan", verdict="Likely Benign", evidence_ids=[]
    )

    assert assessment.requires_confirmation is True
    assert assessment.auto_close_permitted is False


def test_module5_exception_falls_back_safely(monkeypatch):
    fake = types.ModuleType("services.guardrails")

    def broken(**_):
        raise RuntimeError("teammate bug")

    fake.evaluate_proposal = broken
    monkeypatch.setitem(sys.modules, "services.guardrails", fake)
    monkeypatch.setattr(services_pkg, "guardrails", fake, raising=False)

    assessment = guardrail_bridge.assess(
        incident_id="INC-X", category="PortScan", verdict="Likely Benign", evidence_ids=[]
    )

    assert assessment.requires_confirmation is True
    assert any("RuntimeError" in reason for reason in assessment.reasons)


def test_bridge_accepts_positional_signature(monkeypatch):
    fake = types.ModuleType("services.guardrails")
    fake.requires_human_confirmation = lambda incident_id, category, verdict, evidence_ids: {
        "requires_confirmation": True,
        "reasons": ["positional ok"],
    }
    monkeypatch.setitem(sys.modules, "services.guardrails", fake)
    monkeypatch.setattr(services_pkg, "guardrails", fake, raising=False)

    assessment = guardrail_bridge.assess(
        incident_id="INC-X", category="Benign", verdict="Likely Benign", evidence_ids=[]
    )
    assert assessment.requires_confirmation is True
    assert "positional ok" in assessment.reasons


def test_explicit_remote_denial_is_preserved(monkeypatch):
    monkeypatch.setattr(services_pkg.guardrails, 'evaluate_proposal', lambda **_: {
        'allowed': False, 'requires_confirmation': False, 'reasons': ['Denied'],
    })
    assessment = guardrail_bridge.assess(incident_id='INC-TEST', category='DoS',
                                        verdict='Likely Attack', evidence_ids=['ALT-TEST'])
    assert assessment.allowed is False
    assert assessment.auto_close_permitted is False


def test_malformed_remote_result_fails_closed(monkeypatch):
    monkeypatch.setattr(services_pkg.guardrails, 'evaluate_proposal', lambda **_: ['invalid'])
    assessment = guardrail_bridge.assess(incident_id='INC-TEST', category='DoS',
                                        verdict='Likely Benign', evidence_ids=['ALT-TEST'])
    assert assessment.allowed is False
    assert assessment.requires_confirmation is True
