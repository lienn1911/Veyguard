"""Adapter onto Module 5's safe-closure guardrail.

Module 5 (``services/guardrails.py``) is owned by a teammate and was empty when
this module was built. Rather than reimplementing it here, this bridge:

1. imports the teammate module if it exposes a compatible entry point,
2. otherwise falls back to :mod:`services.safety` and says so explicitly,
3. never lets the remote result *weaken* the local rule - the effective answer
   is the union of both.

Expected Module 5 contract (documented so the teammate can implement either
signature without touching this module)::

    def evaluate_proposal(
        *, incident_id: str, category: str, verdict: str, evidence_ids: list[str]
    ) -> dict:
        return {
            "allowed": bool,                # may the proposal stand as-is
            "requires_confirmation": bool,  # must a human sign off before closure
            "reasons": list[str],
        }

A function named ``assess_proposal`` or ``requires_human_confirmation`` with a
keyword-compatible signature is also accepted.
"""

from __future__ import annotations

import inspect
from typing import Any

from .safety import SafetyAssessment, local_assessment

_CANDIDATE_FUNCTIONS = (
    "evaluate_proposal",
    "assess_proposal",
    "requires_human_confirmation",
)


def _load_module5() -> tuple[Any | None, str]:
    try:
        from . import guardrails as module5  # type: ignore[attr-defined]
    except Exception as exc:  # ImportError, SyntaxError in a teammate edit, ...
        return None, f"services.guardrails could not be imported ({type(exc).__name__})"
    if module5 is None:
        return None, "services.guardrails is empty"
    for name in _CANDIDATE_FUNCTIONS:
        function = getattr(module5, name, None)
        if callable(function):
            return module5, f"services.guardrails.{name}"
    return None, "services.guardrails exposes no compatible entry point"


def module5_status() -> dict:
    module, detail = _load_module5()
    return {
        "connected": module is not None,
        "detail": detail if module is None else f"connected via {detail}",
        "fallback": None
        if module is not None
        else "Module 2 local safety rules (services/safety.py) are enforced instead.",
    }


def assess(
    *,
    incident_id: str,
    category: str,
    verdict: str,
    evidence_ids: list[str],
) -> SafetyAssessment:
    """Combine Module 5's judgement with the local rule set."""
    local = local_assessment(verdict, category)

    module, detail = _load_module5()
    if module is None:
        local.reasons.append(
            "Module 5 guardrail not connected: " + detail + " Local rules applied."
        )
        return local

    function = next(
        (getattr(module, name) for name in _CANDIDATE_FUNCTIONS if callable(getattr(module, name, None))),
        None,
    )
    if function is None:  # pragma: no cover - guarded by _load_module5
        return local

    payload = {
        "incident_id": incident_id,
        "category": category,
        "verdict": verdict,
        "evidence_ids": list(evidence_ids),
    }
    try:
        accepted = _call(function, payload)
    except Exception as exc:  # a teammate bug must not disable the guardrail
        local.reasons.append(
            f"Module 5 guardrail raised {type(exc).__name__}; local rules applied instead."
        )
        return local

    if not isinstance(accepted, dict):
        local.allowed = False
        local.requires_confirmation = True
        local.reasons.append("Module 5 returned an invalid safety result.")
        return local
    remote_requires = bool(accepted.get("requires_confirmation"))
    remote_reasons = [str(reason) for reason in (accepted or {}).get("reasons") or []]

    return SafetyAssessment(
        verdict=verdict,
        requires_confirmation=local.requires_confirmation or remote_requires,
        reasons=local.reasons + remote_reasons,
        source=detail,
        auto_close_permitted=False,
        closure_sensitive=local.closure_sensitive,
        allowed=accepted.get("allowed", True) is True,
    )


def _call(function: Any, payload: dict) -> dict:
    """Call the teammate function with whichever signature it declares."""
    signature = inspect.signature(function)
    parameters = signature.parameters
    if any(p.kind == p.VAR_KEYWORD for p in parameters.values()):
        return function(**payload) or {}
    kwargs = {name: payload[name] for name in parameters if name in payload}
    return function(**kwargs) or {}
