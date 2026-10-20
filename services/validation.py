"""Deterministic post-validation of a model proposal.

The model is untrusted output. Nothing it returns is displayed as a security
conclusion until this module accepts it:

* the incident must be the one that was requested;
* the verdict must be one of the three allowed strings;
* every cited evidence id must exist *and* belong to that incident;
* mechanically checkable statistics must appear in the evidence the agent was
  shown (a number it invented is a fabrication, not a rounding difference).

A rejected proposal is reported as ``Needs Review`` **plus** an explicit
validation failure, so a human can see that the backend refused the model's
answer rather than agreeing with it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from .providers.base import VERDICTS

MAX_EVIDENCE_IDS = 12
MAX_REASON_CHARS = 1600
MIN_REASON_CHARS = 12

_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)

# A number immediately followed by a traffic statistic keyword is a factual claim.
_CLAIM = re.compile(
    r"(?<![\w.])(\d[\d,]*(?:\.\d+)?)\s+"
    r"(?:destination ports?|source ports?|distinct (?:source )?(?:ip|host)s?"
    r"|distinct sources?|source (?:ip|host)s?|sources?|flows?|packets?|records?|connections?)",
    re.IGNORECASE,
)

# Numeric claims below this threshold are treated as paraphrase tolerance.
_FABRICATION_THRESHOLD = 10


@dataclass
class Issue:
    code: str
    message: str
    level: str = "error"

    def as_dict(self) -> dict:
        return {"code": self.code, "message": self.message, "level": self.level}


@dataclass
class ValidationReport:
    ok: bool
    issues: list[Issue] = field(default_factory=list)
    proposal: dict | None = None

    @property
    def errors(self) -> list[Issue]:
        return [issue for issue in self.issues if issue.level == "error"]

    def issue_messages(self) -> list[str]:
        return [issue.message for issue in self.issues]

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "issues": [issue.as_dict() for issue in self.issues],
        }


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
class ParseFailure(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def extract_json_object(text: str | None) -> dict:
    """Pull the single JSON object out of a model reply."""
    if not text or not text.strip():
        raise ParseFailure("EMPTY_RESPONSE", "The model returned an empty response.")

    candidate = text.strip()
    fenced = _FENCE.search(candidate)
    if fenced:
        candidate = fenced.group(1).strip()

    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        parsed = None

    if parsed is None:
        start = candidate.find("{")
        end = candidate.rfind("}")
        if start == -1 or end <= start:
            raise ParseFailure(
                "MALFORMED_RESPONSE",
                "The model response contained no JSON object.",
            )
        try:
            parsed = json.loads(candidate[start : end + 1])
        except json.JSONDecodeError as exc:
            raise ParseFailure(
                "MALFORMED_RESPONSE",
                f"The model response was not valid JSON ({exc.msg} at char {exc.pos}).",
            ) from exc

    if not isinstance(parsed, dict):
        raise ParseFailure("MALFORMED_RESPONSE", "The model response was JSON but not an object.")
    return parsed


# --------------------------------------------------------------------------- #
# Evidence arithmetic
# --------------------------------------------------------------------------- #
def collect_numbers(value: Any, into: set[float] | None = None) -> set[float]:
    """Every number the agent was actually shown, including inside strings."""
    numbers = into if into is not None else set()
    if isinstance(value, bool) or value is None:
        return numbers
    if isinstance(value, (int, float)):
        numbers.add(float(value))
        return numbers
    if isinstance(value, str):
        for token in re.findall(r"\d[\d,]*(?:\.\d+)?", value):
            try:
                numbers.add(float(token.replace(",", "")))
            except ValueError:
                continue
        return numbers
    if isinstance(value, dict):
        for item in value.values():
            collect_numbers(item, numbers)
    elif isinstance(value, (list, tuple)):
        for item in value:
            collect_numbers(item, numbers)
    return numbers


def check_numeric_claims(text: str, evidence_numbers: set[float]) -> list[Issue]:
    """Flag figures that are presented as observed but never appeared in evidence."""
    issues: list[Issue] = []
    seen: set[str] = set()
    for match in _CLAIM.finditer(text or ""):
        raw = match.group(1)
        keyword = match.group(0)[len(raw) :].strip()
        if raw in seen:
            continue
        seen.add(raw)
        try:
            value = float(raw.replace(",", ""))
        except ValueError:
            continue
        # Tolerate rounding to whole numbers for fractional aggregates.
        if value in evidence_numbers or float(round(value)) in evidence_numbers:
            continue
        level = "error" if value >= _FABRICATION_THRESHOLD else "warning"
        issues.append(
            Issue(
                code="UNSUPPORTED_STATISTIC",
                level=level,
                message=(
                    f'The explanation states "{raw} {keyword}", but that figure does not appear '
                    "in any retrieved evidence."
                ),
            )
        )
    return issues


# --------------------------------------------------------------------------- #
# Proposal validation
# --------------------------------------------------------------------------- #
def normalize_verdict(raw: Any) -> str | None:
    if not isinstance(raw, str):
        return None
    text = " ".join(raw.strip().split())
    for verdict in VERDICTS:
        if text.lower() == verdict.lower():
            return verdict
    return None


def validate_proposal(
    payload: dict,
    *,
    incident_id: str,
    evidence_ids: dict[str, str],
    evidence_numbers: set[float],
    tool_call_count: int,
) -> ValidationReport:
    issues: list[Issue] = []

    # --- incident identity ------------------------------------------------
    claimed_incident = payload.get("incident_id")
    if not isinstance(claimed_incident, str) or claimed_incident.strip() != incident_id:
        issues.append(
            Issue(
                "INCIDENT_MISMATCH",
                f"The response is for {claimed_incident!r} but this investigation covers {incident_id}.",
            )
        )

    # --- verdict ----------------------------------------------------------
    raw_verdict = payload.get("verdict")
    verdict = normalize_verdict(raw_verdict)
    if verdict is None:
        issues.append(
            Issue(
                "INVALID_VERDICT",
                f"Verdict {raw_verdict!r} is not one of: {', '.join(VERDICTS)}.",
            )
        )

    # --- reason -----------------------------------------------------------
    reason = payload.get("reason")
    if not isinstance(reason, str) or len(reason.strip()) < MIN_REASON_CHARS:
        issues.append(Issue("MISSING_REASON", "The response has no usable explanation."))
        reason = re.sub(r"\s+", " ", reason or "").strip()
        issues.append(Issue("MISSING_REASON", "The explanation is missing or too short."))
    else:
        reason = re.sub(r"\s+", " ", reason).strip()
        if len(reason) > MAX_REASON_CHARS:
            reason = reason[:MAX_REASON_CHARS]

    # --- evidence ids -----------------------------------------------------
    raw_ids = payload.get("evidence_ids")
    if raw_ids is None:
        raw_ids = []
    if not isinstance(raw_ids, list):
        issues.append(Issue("INVALID_EVIDENCE_LIST", "evidence_ids must be a list of strings."))
        raw_ids = []

    cited: list[str] = []
    unknown: list[str] = []
    for raw in raw_ids:
        if not isinstance(raw, str):
            unknown.append(repr(raw))
            continue
        candidate = raw.strip()
        if candidate in evidence_ids:
            if candidate not in cited:
                cited.append(candidate)
        else:
            unknown.append(candidate)

    if unknown:
        issues.append(
            Issue(
                "UNKNOWN_EVIDENCE",
                "The response cites evidence that does not belong to this incident: "
                + ", ".join(sorted(set(unknown))[:8])
                + ".",
            )
        )

    if len(cited) > MAX_EVIDENCE_IDS:
        issues.append(
            Issue(
                "TOO_MUCH_EVIDENCE",
                f"At most {MAX_EVIDENCE_IDS} evidence ids may be cited; {len(cited)} were given.",
            )
        )
        cited = cited[:MAX_EVIDENCE_IDS]

    if verdict in ("Likely Attack", "Likely Benign") and not cited:
        issues.append(
            Issue(
                "MISSING_EVIDENCE",
                f"A {verdict} verdict requires at least one valid evidence id.",
            )
        )

    # --- findings ---------------------------------------------------------
    findings: list[dict] = []
    raw_findings = payload.get("findings")
    if isinstance(raw_findings, list):
        for item in raw_findings[:6]:
            if not isinstance(item, dict):
                continue
            observation = item.get("observation")
            if not isinstance(observation, str) or not observation.strip():
                continue
            finding_ids = item.get("evidence_ids")
            valid_ids = [
                value.strip()
                for value in (finding_ids if isinstance(finding_ids, list) else [])
                if isinstance(value, str) and value.strip() in evidence_ids
            ]
            invalid_ids = [
                value.strip()
                for value in (finding_ids if isinstance(finding_ids, list) else [])
                if isinstance(value, str) and value.strip() and value.strip() not in evidence_ids
            ]
            if invalid_ids:
                issues.append(
                    Issue(
                        "UNKNOWN_EVIDENCE",
                        "A finding cites evidence outside this incident: "
                        + ", ".join(sorted(set(invalid_ids))[:5])
                        + ".",
                    )
                )
                continue
            findings.append(
                {"observation": re.sub(r"\s+", " ", observation).strip()[:600], "evidence_ids": valid_ids}
            )

    # --- statistics and investigation depth -------------------------------
    claim_text = " ".join(
        [reason, payload.get("limitations") or ""]
        + [finding["observation"] for finding in findings]
    )
    issues.extend(check_numeric_claims(claim_text, evidence_numbers))

    if tool_call_count == 0:
        issues.append(
            Issue(
                "NO_INVESTIGATION",
                "The verdict was produced without any tool call, so it is not evidence-grounded.",
            )
        )

    confidence = payload.get("confidence")
    if not isinstance(confidence, str) or confidence.strip().lower() not in ("high", "medium", "low"):
        confidence = "low"
    else:
        confidence = confidence.strip().lower()

    ok = not any(issue.level == "error" for issue in issues)
    proposal = {
        "incident_id": incident_id,
        "verdict": verdict,
        "confidence": confidence,
        "reason": reason,
        "evidence_ids": cited,
        "findings": findings,
        "limitations": (payload.get("limitations") or "")[:600]
        if isinstance(payload.get("limitations"), str)
        else "",
    }
    return ValidationReport(ok=ok, issues=issues, proposal=proposal if ok else None)
