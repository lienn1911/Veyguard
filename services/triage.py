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
import hashlib
import json
import uuid
from threading import RLock
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
from .tools import ToolOutcome, ToolRegistry, bound_outcome
from .validation import (
    ParseFailure,
    Issue,
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
        data = outcome.data if isinstance(outcome.data, dict) else {}
        items = data.get("alerts") if outcome.tool == "get_related_alerts" else data.get("flows") if outcome.tool == "get_network_flows" else None
        entry = {
            "step": step,
            "tool": outcome.tool,
            "arguments": outcome.arguments,
            "ok": outcome.ok,
            "duration_ms": round(duration_ms, 2),
            "error": outcome.error,
            "blocked": outcome.blocked,
            "result_count": len(items) if isinstance(items, list) else None,
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
        self._progress = {}
        self._progress_lock = RLock()
        self.settings = settings
        self.dataset = dataset
        self.audit = audit or AuditLog(settings.audit_path)
        self.store = store or TriageStore(settings.state_path)
        self._provider_factory = provider_factory or (lambda: build_provider(settings))

    # ------------------------------------------------------------------ read
    def latest(self, incident_id: str) -> dict | None:
        self.dataset.require(incident_id)  # KeyError -> 404
        stored = self.store.get(incident_id)
        latest = (stored or {}).get("latest")
        if not latest or latest.get("status") != "ok":
            return stored
        numbers = self.dataset.canonical_statistic_numbers(incident_id)
        report = validate_proposal(
            latest.get("proposal") or latest, incident_id=incident_id,
            evidence_ids=self.dataset.evidence_ids(incident_id),
            evidence_numbers=numbers, canonical_numbers=numbers,
            tool_call_count=len((latest.get("investigation") or {}).get("tool_calls") or []),
            alert_types_by_id={item["alert_id"]: item["type"] for item in self.dataset.agent_alerts(incident_id)},
            incident=self.dataset.require(incident_id).incident,
            case_alerts=self.dataset.agent_alerts(incident_id),
        )
        fingerprint = latest.get("evidence_fingerprint")
        if fingerprint and fingerprint != self._evidence_fingerprint(incident_id):
            report.issues.append(Issue("EVIDENCE_CHANGED", "Case evidence has changed since this AI investigation."))
            report.ok = False
        if not report.ok:
            # Read-time projection only: preserve the historical run and analyst audit.
            stored["latest"] = {**latest, "status": "rejected", "proposal": None,
                "verdict": "Needs Review", "confidence": None, "reason": "AI result withheld after evidence revalidation.",
                "findings": [], "evidence_ids": [], "next_steps": [], "technique_mappings": [], "limitations": "",
                "validation": report.as_dict(),
                "error": {"code": "EVIDENCE_INTEGRITY_FAILED", "message": "Saved AI result conflicts with current case evidence. Rerun investigation before reviewing it.", "detail": report.issue_messages()}}
            stored["decision"] = {"status": "pending"}
        return stored

    def _evidence_fingerprint(self, incident_id: str) -> str:
        evidence = {"case": self.dataset.agent_incident_details(incident_id),
                    "alerts": self.dataset.agent_alerts(incident_id),
                    "flows": [{key: flow.get(key) for key in ("flow_id", "timestamp", "source_ip", "source_port", "destination_ip", "destination_port", "packet_count")}
                              for flow in self.dataset.evidence_flows(incident_id)],
                    "statistics": self.dataset.agent_statistics(incident_id)}
        return hashlib.sha256(json.dumps(evidence, sort_keys=True, ensure_ascii=False).encode()).hexdigest()

    def status(self) -> dict:
        return {
            **self.settings.describe(),
            "guardrail": guardrail_bridge.module5_status(),
            "prohibited_actions": list(PROHIBITED_ACTIONS),
        }

    # ----------------------------------------------------------- investigate
    def progress(self, incident_id: str) -> dict | None:
        with self._progress_lock:
            item = self._progress.get(incident_id)
            return dict(item) if item else None

    def _set_progress(self, incident_id, stage, percent, description, *, running=True):
        with self._progress_lock:
            previous = self._progress.get(incident_id, {})
            self._progress[incident_id] = {
                'stage': stage, 'percent': max(previous.get('percent', 0), percent),
                'description': description, 'running': running,
            }

    def investigate(self, incident_id: str) -> dict:
        self.dataset.require(incident_id)
        with self._progress_lock:
            self._progress[incident_id] = {'stage': 'prepare', 'percent': 10,
                'description': 'Preparing this case for read-only evidence checks.', 'running': True}
        try:
            result = self._investigate(incident_id)
            if result['status'] == 'ok':
                self._set_progress(incident_id, 'complete', 100, 'Assessment checked and ready for your review.', running=False)
            else:
                self._set_progress(incident_id, 'failed', 0, 'The check did not finish. Review the error before retrying.', running=False)
            return result
        except Exception:
            self._set_progress(incident_id, 'failed', 0, 'The check did not finish. Review the error before retrying.', running=False)
            raise

    def _investigate(self, incident_id: str) -> dict:
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

            self._set_progress(incident_id, 'analyse' if trace.executed else 'evidence', 65 if trace.executed else 30,
                'Comparing the retrieved evidence and drafting findings.' if trace.executed else 'AI is selecting and reading case evidence.')
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
                    self._set_progress(incident_id, 'evidence', 35, "Reading evidence: " + call.name.replace("_", " ") + ".")
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
                    outcome = bound_outcome(outcome, MAX_TOOL_RESULT_CHARS)
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
                            "content": outcome.as_text(),
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

            self._set_progress(incident_id, 'validate', 85, 'Checking evidence references, numeric claims and case boundaries.')
            report = self._validate(payload, incident_id, trace)
            if report.ok and report.proposal:
                self._set_progress(incident_id, 'save', 95, 'Preparing the assessment and recording its audit trail.')
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
        known_ids = set(self.dataset.evidence_ids(incident_id))
        seen_ids: set[str] = set()
        def collect_seen(value):
            if isinstance(value, dict):
                for nested in value.values():
                    collect_seen(nested)
            elif isinstance(value, list):
                for nested in value:
                    collect_seen(nested)
            elif isinstance(value, str) and value in known_ids:
                seen_ids.add(value)
        collect_seen(trace.payloads)
        return validate_proposal(
            payload,
            incident_id=incident_id,
            evidence_ids=self.dataset.evidence_ids(incident_id),
            evidence_numbers=evidence_numbers,
            canonical_numbers=self.dataset.canonical_statistic_numbers(incident_id),
            tool_call_count=trace.executed,
            seen_evidence_ids=seen_ids,
            alert_types_by_id={alert["alert_id"]: alert["type"] for alert in self.dataset.agent_alerts(incident_id)},
            incident=self.dataset.require(incident_id).incident,
            case_alerts=self.dataset.agent_alerts(incident_id),
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
            "evidence_fingerprint": self._evidence_fingerprint(incident_id),
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
        if not guardrail.allowed:
            return self._rejected(
                incident_id=incident_id, run_id=run_id,
                provider_name=provider_name, provider_model=provider_model,
                report=ValidationReport(ok=False, proposal=None, issues=[
                    Issue("GUARDRAIL_BLOCKED", "The safety guardrail rejected this proposal.")]),
                trace=trace, started_at=started_at, started=started,
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
            "technique_mappings": proposal["technique_mappings"],
            "next_steps": proposal["next_steps"],
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
                "next_steps": proposal["next_steps"],
                "technique_mappings": proposal["technique_mappings"],
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
        stored = self.latest(incident_id)
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
        if decision == "confirmed" and proposal.get("verdict") == "Likely Benign" and latest.get("requires_confirmation") and not (note or "").strip():
            raise ValueError("Confirming a Likely Benign verdict for an attack alert requires a written reason.")
        previous = (stored.get("decision") or {}).get("status")
        if previous in ("confirmed", "rejected"):
            raise ValueError("This AI proposal already has an analyst decision. Run a new AI check to review again.")

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
