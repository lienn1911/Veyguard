"""Local safety rules that belong to Module 2.

These are *not* a replacement for Module 5 (the safe-closure guardrail, owned by
another teammate). They are the invariants this module enforces on itself so a
misconfigured or missing guardrail cannot turn a model proposal into a closure:

* the agent has no write tools at all (structural, see :mod:`services.tools`);
* a ``Likely Benign`` proposal on a PortScan / DoS / DDoS / BruteForce incident always needs
  an explicit human confirmation before it can be treated as benign;
* nothing in this service may change severity or close an incident.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .data_store import ATTACK_CATEGORIES

CLOSURE_SENSITIVE_VERDICT = "Likely Benign"

#: Actions this service must never be able to perform, surfaced to the UI so the
#: restriction is visible rather than implied.
PROHIBITED_ACTIONS = (
    "close_incident",
    "dismiss_incident",
    "downgrade_severity",
    "execute_remediation",
    "modify_evidence",
    "approve_recommendation",
    "override_analyst_decision",
)


@dataclass
class SafetyAssessment:
    verdict: str
    requires_confirmation: bool
    reasons: list[str] = field(default_factory=list)
    source: str = "module2-local"
    auto_close_permitted: bool = False
    severity_change: str | None = None
    closure_sensitive: bool = False
    allowed: bool = True

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "requires_confirmation": self.requires_confirmation,
            "reasons": self.reasons,
            "source": self.source,
            "auto_close_permitted": self.auto_close_permitted,
            "severity_change": self.severity_change,
            "closure_sensitive": self.closure_sensitive,
            "allowed": self.allowed,
            "prohibited_actions": list(PROHIBITED_ACTIONS),
        }


def local_assessment(verdict: str, category: str) -> SafetyAssessment:
    reasons: list[str] = []
    closure_sensitive = verdict == CLOSURE_SENSITIVE_VERDICT and category in ATTACK_CATEGORIES
    if closure_sensitive:
        reasons.append(
            f"Safe-closure guardrail: a Likely Benign verdict on a {category} incident requires "
            "explicit analyst confirmation before the case may be considered benign."
        )
    if verdict == "Likely Attack":
        reasons.append("Attack verdicts are proposals only; an analyst decides the response.")
    if verdict == "Needs Review":
        reasons.append("Insufficient evidence: analyst review is mandatory.")
    return SafetyAssessment(
        verdict=verdict,
        requires_confirmation=closure_sensitive,
        reasons=reasons,
        source="module2-local",
        closure_sensitive=closure_sensitive,
    )
