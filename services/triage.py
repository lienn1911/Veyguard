"""Module 2 - AI-powered incident triage.

Public surface:

``TriageService.investigate(incident_id)``  run one bounded investigation
``TriageService.latest(incident_id)``       last stored proposal + decision
``TriageService.decide(incident_id, ...)``  record an analyst decision

The loop is intentionally small and boring: ask the model for a turn, execute
allowlisted read-only tools, feed results back, stop at a fixed step budget, then
run deterministic validation. The model never decides whether it is allowed to
act, and the backend never trusts its output.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Sequence

from . import guardrail_bridge
from .audit_log import AuditLog
from .config import Settings
from .data_store import Dataset
from .prompts import NUDGE_TOOL_USE, SYSTEM_PROMPT, correction_prompt, investigation_prompt
from .providers import ChatProvider, ProviderError, ProviderNotConfigured, build_provider
from .safety import PROHIBITED_ACTIONS
from .store import TriageStore
from .tools import ToolOutcome, ToolRegistry
from .validation import (
    ParseFailure,
    ValidationReport,
    collect_numbers,
    extract_json_object,
    validate_proposal,
)

MAX_TOOL_CALLS_PER_TURN = 4
MAX_TOOL_RESULT_CHARS = 8000
MAX_REPAIR_ATTEMPTS = 1


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass
class Trace:
    steps: int = 0
    tool_calls: list[dict] = field(default_factory=list)
    blocked_attempts: list[dict] = field(default_factory=list)
    tool_errors: int = 0
    payloads: list[dict] = field(default_factory=list)
    corrections: int = 0
    nudged: bool = False

    @property
    def executed(self) -> int:
        return len(self.tool_calls)

    def add(self, step: int, outcome: ToolOutcome, duration_ms: float) -> None:
        entry = {
            "step": step,
            "tool": outcome.tool,
            "arguments": outcome.arguments,
            "ok": outcome.ok,
            "duration_ms": round(duration_ms, 2),
            "error": outcome.error,
            "blocked": outcome.blocked,
        }
        self.tool_calls.append(entry)
        if outcome.ok and outcome.data is not None:
            self.payloads.append(outcome.data)
        else:
            self.tool_errors += 1
        if outcome.blocked:
            self.blocked_attempts.append({"tool": outcome.tool, "arguments": outcome.arguments})

    def as_dict(self) -> dict:
        return {
            "steps": self.steps,
            "tool_calls": self.tool_calls,
            "blocked_attempts": self.blocked_attempts,
            "tool_errors": self.tool_errors,
            "corrections": self.corrections,
        }


class TriageService:
    def __init__(
        self,
        settings: Settings,
        dataset: Dataset,
        *,
        audit: AuditLog | None = None,
        store: TriageStore | None = None,
        provider_factory: Callable[[], ChatProvider] | None = None,
    ):
        self.settings = settings
        self.dataset = dataset
        self.audit = audit or AuditLog(settings.audit_path)
        self.store = store or TriageStore(settings.state_path)
        self._provider_factory = provider_factory or (lambda: build_provider(settings))

    # ------------------------------------------------------------------ read
    def latest(self, incident_id: str) -> dict | None:
        self.dataset.require(incident_id)  # KeyError -> 404
        return self.store.get(incident_id)

    def status(self) -> dict:
        return {
            **self.settings.describe(),
            "guardrail": guardrail_bridge.module5_status(),
            "prohibited_actions": list(PROHIBITED_ACTIONS),
        }

    # ----------------------------------------------------------- investigate
    def investigate(self, incident_id: str) -> dict:
        try:
            record = self.dataset.require(incident_id)
        except KeyError as exc:
            raise IncidentNotFound(incident_id) from exc

        settings = self.settings
        if not settings.ready:
            raise ProviderNotConfigured(settings.blocking_reason() or "Provider is not configured.")

        provider = None
        failure: dict | None = None
        try:
            provider = self._provider_factory()
        except ProviderNotConfigured:
            # A configuration problem is not an investigation; surface it as HTTP 503.
            raise
        except ProviderError as exc:
            failure = exc.as_dict()
        except Exception as exc:  # pragma: no cover - defensive
            failure = {
                "code": "PROVIDER_UNAVAILABLE",
                "message": f"Could not construct the provider: {type(exc).__name__}: {exc}",
            }

        provider_name = provider.name if provider else settings.provider
        provider_model = provider.model if provider else settings.model

        run_id = f"TRG-{uuid.uuid4().hex[:10].upper()}"
        started_at = _utc_now()
        started = time.monotonic()
        trace = Trace()

        self.audit.append(
            "triage.started",
            incident_id=incident_id,
            actor="system:triage-agent",
            payload={
                "run_id": run_id,
                "provider": provider_name,
                "model": provider_model,
                "mode": "mock" if settings.is_mock else "live",
                "category": record.category,
            },
        )

        if failure is not None or provider is None:
            return self._error(
                incident_id=incident_id,
                run_id=run_id,
                provider_name=provider_name,
                provider_model=provider_model,
                failure=failure or {"code": "PROVIDER_UNAVAILABLE", "message": "Provider unavailable."},
                trace=trace,
                started_at=started_at,
                started=started,
            )

        registry = ToolRegistry(self.dataset, incident_id)
        messages: list[dict] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": investigation_prompt(incident_id)},
        ]

        while True:
            if trace.steps >= settings.max_steps:
                failure = {
                    "code": "STEP_LIMIT_REACHED",
                    "message": (
                        f"The agent did not reach a verdict within {settings.max_steps} model turns."
                    ),
                }
                break
            if sum(1 for call in trace.tool_calls if not call["blocked"]) >= settings.max_tool_calls:
                failure = {
                    "code": "TOOL_BUDGET_EXCEEDED",
                    "message": (
                        "The investigation exceeded its read-only tool-call budget "
                        f"({settings.max_tool_calls})."
                    ),
                }
                break

            trace.steps += 1
            try:
                turn = provider.complete(messages, ToolRegistry.definitions())
            except ProviderError as exc:
                failure = exc.as_dict()
                break
            except Exception as exc:  # defensive: never let a provider bug become a verdict
                failure = {
                    "code": "PROVIDER_BAD_RESPONSE",
                    "message": f"Provider raised {type(exc).__name__}: {exc}",
                }
                break

            if turn.tool_calls:
                messages.append(
                    {
                        "role": "assistant",
                        "content": turn.text,
                        "tool_calls": [
                            {"id": call.id, "name": call.name, "arguments": call.arguments}
                            for call in turn.tool_calls
                        ],
                    }
                )
                for call in turn.tool_calls[:MAX_TOOL_CALLS_PER_TURN]:
                    if sum(1 for c in trace.tool_calls if not c["blocked"]) >= settings.max_tool_calls:
                        break
                    call_started = time.monotonic()
                    if call.parse_error:
                        outcome = ToolOutcome(
                            tool=call.name,
                            ok=False,
                            arguments={},
                            error={"code": "INVALID_ARGUMENTS", "message": call.parse_error},
                        )
                    else:
                        try:
                            outcome = registry.execute(call.name, call.arguments)
                        except Exception as exc:  # a tool bug must not abort the investigation
                            outcome = ToolOutcome(
                                tool=call.name,
                                ok=False,
                                arguments=call.arguments if isinstance(call.arguments, dict) else {},
                                error={
                                    "code": "TOOL_EXECUTION_FAILED",
                                    "message": f"{type(exc).__name__}: {exc}",
                                },
                            )
                    trace.add(trace.steps, outcome, (time.monotonic() - call_started) * 1000)
                    self.audit.append(
                        "triage.tool_call",
                        incident_id=incident_id,
                        actor="system:triage-agent",
                        payload={
                            "run_id": run_id,
                            "tool": outcome.tool,
                            "ok": outcome.ok,
                            "blocked": outcome.blocked,
                            "error_code": (outcome.error or {}).get("code"),
                        },
                    )
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": call.id,
                            "name": call.name,
                            "content": outcome.as_text()[:MAX_TOOL_RESULT_CHARS],
                        }
                    )
                continue

            text = (turn.text or "").strip()

            # A verdict produced with zero tool calls is not evidence-grounded.
            if trace.executed == 0 and not trace.nudged:
                trace.nudged = True
                messages.append({"role": "assistant", "content": text or "(no answer)"})
                messages.append({"role": "user", "content": NUDGE_TOOL_USE})
                continue

            if not text:
                failure = {
                    "code": "EMPTY_RESPONSE",
                    "message": "The model returned neither tool calls nor an answer.",
                }
                break

            try:
                payload = extract_json_object(text)
            except ParseFailure as exc:
                failure = {"code": exc.code, "message": exc.message}
                break

            report = self._validate(payload, incident_id, trace)
            if report.ok and report.proposal:
                return self._complete(
                    incident_id=incident_id,
                    record=record,
                    run_id=run_id,
                    provider_name=provider_name,
                    provider_model=provider_model,
                    proposal=report.proposal,
                    report=report,
                    trace=trace,
                    started_at=started_at,
                    started=started,
                )

            if trace.corrections < MAX_REPAIR_ATTEMPTS:
                trace.corrections += 1
                messages.append({"role": "assistant", "content": text})
                messages.append(
                    {"role": "user", "content": correction_prompt(report.issue_messages()[:6])}
                )
                continue

            return self._rejected(
                incident_id=incident_id,
                run_id=run_id,
                provider_name=provider_name,
                provider_model=provider_model,
                report=report,
                trace=trace,
                started_at=started_at,
                started=started,
            )

        return self._error(
            incident_id=incident_id,
            run_id=run_id,
            provider_name=provider_name,
            provider_model=provider_model,
            failure=failure or {"code": "UNKNOWN_FAILURE", "message": "Investigation failed."},
            trace=trace,
            started_at=started_at,
            started=started,
        )

    # ------------------------------------------------------------- internals
    def _validate(self, payload: dict, incident_id: str, trace: Trace) -> ValidationReport:
        evidence_numbers = collect_numbers(trace.payloads)
        return validate_proposal(
            payload,
            incident_id=incident_id,
            evidence_ids=self.dataset.evidence_ids(incident_id),
            evidence_numbers=evidence_numbers,
            tool_call_count=trace.executed,
        )

    def _base_record(
        self, *, incident_id, run_id, provider_name, provider_model, trace, started_at, started
    ) -> dict:
        return {
            "run_id": run_id,
            "incident_id": incident_id,
            "provider": provider_name,
            "model": provider_model,
            "mode": "mock" if self.settings.is_mock else "live",
            "started_at": started_at,
            "completed_at": _utc_now(),
            "duration_ms": int((time.monotonic() - started) * 1000),
            "investigation": trace.as_dict(),
            "prohibited_actions": list(PROHIBITED_ACTIONS),
        }

    def _complete(
        self,
        *,
        incident_id,
        record,
        run_id,
        provider_name,
        provider_model,
        proposal,
        report,
        trace,
        started_at,
        started,
    ) -> dict:
        guardrail = guardrail_bridge.assess(
            incident_id=incident_id,
            category=record.category,
            verdict=proposal["verdict"],
            evidence_ids=proposal["evidence_ids"],
        )
        result = {
            **self._base_record(
                incident_id=incident_id,
                run_id=run_id,
                provider_name=provider_name,
                provider_model=provider_model,
                trace=trace,
                started_at=started_at,
                started=started,
            ),
            "status": "ok",
            "verdict": proposal["verdict"],
            "confidence": proposal["confidence"],
            "reason": proposal["reason"],
            "evidence_ids": proposal["evidence_ids"],
            "findings": proposal["findings"],
            "limitations": proposal["limitations"],
            "proposal": proposal,
            "error": None,
            "validation": report.as_dict(),
            "requires_confirmation": guardrail.requires_confirmation,
            "guardrail": guardrail.as_dict(),
        }
        stored = self.store.save_run(result)
        result["decision"] = stored["decision"]
        self.audit.append(
            "triage.completed",
            incident_id=incident_id,
            actor="system:triage-agent",
            payload={
                "run_id": run_id,
                "verdict": proposal["verdict"],
                "confidence": proposal["confidence"],
                "evidence_ids": proposal["evidence_ids"],
                "requires_confirmation": guardrail.requires_confirmation,
                "guardrail_source": guardrail.source,
            },
        )
        return result

    def _rejected(
        self, *, incident_id, run_id, provider_name, provider_model, report, trace, started_at, started
    ) -> dict:
        issues = report.issue_messages()
        result = {
            **self._base_record(
                incident_id=incident_id,
                run_id=run_id,
                provider_name=provider_name,
                provider_model=provider_model,
                trace=trace,
                started_at=started_at,
                started=started,
            ),
            "status": "rejected",
            "verdict": "Needs Review",
            "confidence": None,
            "reason": (
                "The model's proposal was rejected by backend validation, so it is not a "
                "classification. " + " ".join(issues[:4])
            ),
            "evidence_ids": [],
            "findings": [],
            "limitations": "No verified conclusion was produced; analyst review required.",
            "proposal": None,
            "error": {
                "code": "VALIDATION_FAILED",
                "message": "The model response failed deterministic validation.",
                "detail": issues,
            },
            "validation": report.as_dict(),
            "requires_confirmation": True,
            "guardrail": guardrail_bridge.assess(
                incident_id=incident_id,
                category=self.dataset.require(incident_id).category,
                verdict="Needs Review",
                evidence_ids=[],
            ).as_dict(),
        }
        result["decision"] = self.store.save_run(result)["decision"]
        self.audit.append(
            "triage.rejected",
            incident_id=incident_id,
            actor="system:triage-agent",
            payload={"run_id": run_id, "issues": issues[:8]},
        )
        return result

    def _error(
        self, *, incident_id, run_id, provider_name, provider_model, failure, trace, started_at, started
    ) -> dict:
        result = {
            **self._base_record(
                incident_id=incident_id,
                run_id=run_id,
                provider_name=provider_name,
                provider_model=provider_model,
                trace=trace,
                started_at=started_at,
                started=started,
            ),
            "status": "error",
            "verdict": None,
            "confidence": None,
            "reason": (
                "The investigation did not complete, so no verdict exists. "
                f"({failure.get('code')}) {failure.get('message')}"
            ),
            "evidence_ids": [],
            "findings": [],
            "limitations": "Operational failure - this is not a benign or attack finding.",
            "proposal": None,
            "error": failure,
            "validation": {"ok": False, "issues": []},
            "requires_confirmation": False,
            "guardrail": None,
        }
        result["decision"] = self.store.save_run(result)["decision"]
        self.audit.append(
            "triage.error",
            incident_id=incident_id,
            actor="system:triage-agent",
            payload={"run_id": run_id, **{k: failure.get(k) for k in ("code", "message")}},
        )
        return result

    # -------------------------------------------------------------- decision
    def decide(
        self,
        incident_id: str,
        *,
        decision: str,
        analyst: str,
        note: str | None = None,
    ) -> dict:
        stored = self.store.get(incident_id)
        if not stored or not stored.get("latest"):
            raise LookupError("No triage proposal exists for this incident yet.")

        latest = stored["latest"]
        proposal = latest.get("proposal")
        if proposal is None:
            raise ValueError(
                "There is no validated proposal to decide on; run triage again before recording a decision."
            )

        if decision not in ("confirmed", "rejected"):
            raise ValueError("decision must be 'confirmed' or 'rejected'.")

        if decision == "rejected" and not (note or "").strip():
            raise ValueError("A rejection requires a note explaining the analyst's reasoning.")

        payload = {
            "status": decision,
            "analyst": analyst.strip() or "analyst",
            "note": (note or "").strip() or None,
            "at": _utc_now(),
            "run_id": latest.get("run_id"),
            "proposal_verdict": proposal.get("verdict"),
        }
        updated = self.store.set_decision(incident_id, payload)
        self.audit.append(
            "analyst.decision",
            incident_id=incident_id,
            actor=f"analyst:{payload['analyst']}",
            payload={
                "decision": decision,
                "proposal_verdict": proposal.get("verdict"),
                "run_id": latest.get("run_id"),
                "note": payload["note"],
                "requires_confirmation": latest.get("requires_confirmation"),
            },
        )
        return updated
