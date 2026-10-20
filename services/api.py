"""FastAPI application for Module 2 + the read APIs Module 6 needs.

Boundary rules enforced here:

* the browser never receives a credential - ``/api/health`` reports *whether* a
  key is configured, never the key;
* CORS is restricted to the configured Vite origins;
* every error is a structured ``{"error": {"code", "message"}}`` body, so the UI
  can distinguish "the agent could not run" from "the agent concluded X".

Run with::

    python -m services.api
    # or
    uvicorn services.api:app --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# Allow ``python services/api.py`` as well as ``python -m services.api``.
if __package__ in (None, ""):  # pragma: no cover - script entry point
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    __package__ = "services"

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .audit_log import AuditLog, summarize
from .config import ConfigError, Settings, load_settings
from .data_store import ATTACK_CATEGORIES, Dataset, DatasetError, IncidentNotFound
from .guardrail_bridge import module5_status
from .providers import ProviderError, ProviderNotConfigured, describe_providers
from .triage import TriageService


# --------------------------------------------------------------------------- #
# Module 4 integration probe (teammate-owned)
# --------------------------------------------------------------------------- #
def recommendations_status() -> dict:
    """Report whether Module 4 is wired up. Never fabricate recommendations."""
    try:
        from . import recommendations as module4  # type: ignore[attr-defined]
    except Exception as exc:
        return {
            "available": False,
            "items": [],
            "detail": f"services.recommendations could not be imported ({type(exc).__name__})",
            "owner": "Module 4 (teammate)",
        }
    for name in ("get_recommendations", "recommend_next_steps", "build_recommendations"):
        function = getattr(module4, name, None)
        if callable(function):
            return {"available": True, "items": [], "detail": f"services.recommendations.{name}", "owner": "Module 4"}
    return {
        "available": False,
        "items": [],
        "detail": "services.recommendations exposes no compatible entry point yet.",
        "owner": "Module 4 (teammate)",
    }


# --------------------------------------------------------------------------- #
# Service container
# --------------------------------------------------------------------------- #
class Services:
    def __init__(self) -> None:
        self.settings: Settings | None = None
        self.dataset: Dataset | None = None
        self.triage: TriageService | None = None
        self.audit: AuditLog | None = None
        self.error: str | None = None

    def boot(self) -> None:
        self.error = None
        try:
            settings = load_settings()
            self.settings = settings
            dataset = Dataset.load(settings.alerts_path, settings.timelines_path)
            self.dataset = dataset
            self.audit = AuditLog(settings.audit_path)
            self.triage = TriageService(settings, dataset, audit=self.audit)
        except (ConfigError, DatasetError) as exc:
            self.error = str(exc)

    def require_dataset(self) -> Dataset:
        if self.dataset is None:
            raise ApiError(503, "DATASET_UNAVAILABLE", self.error or "Dataset failed to load.")
        return self.dataset

    def require_triage(self) -> TriageService:
        if self.triage is None:
            raise ApiError(503, "SERVICE_UNAVAILABLE", self.error or "Triage service failed to start.")
        return self.triage


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, detail: Any = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.detail = detail


def error_response(status: int, code: str, message: str, detail: Any = None) -> JSONResponse:
    body: dict[str, Any] = {"error": {"code": code, "message": message}}
    if detail is not None:
        body["error"]["detail"] = detail
    return JSONResponse(status_code=status, content=body)


services = Services()


def create_app() -> FastAPI:
    app = FastAPI(
        title="SOC-Triage API",
        version="0.2.0",
        description="Module 2 (AI incident triage) with read-only access to Module 1/3 artefacts.",
    )
    services.boot()

    origins = services.settings.cors_origins if services.settings else ["http://127.0.0.1:5173"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type"],
        max_age=600,
    )

    # ------------------------------------------------------------- errors
    @app.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError) -> JSONResponse:
        return error_response(exc.status, exc.code, exc.message, exc.detail)

    @app.exception_handler(IncidentNotFound)
    async def _not_found(_: Request, exc: IncidentNotFound) -> JSONResponse:
        return error_response(404, "INCIDENT_NOT_FOUND", str(exc))

    @app.exception_handler(ProviderNotConfigured)
    async def _not_configured(_: Request, exc: ProviderNotConfigured) -> JSONResponse:
        return error_response(503, exc.code, exc.message, exc.detail)

    @app.exception_handler(ProviderError)
    async def _provider_error(_: Request, exc: ProviderError) -> JSONResponse:
        return error_response(502, exc.code, exc.message, exc.detail)

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:  # pragma: no cover
        return error_response(500, "INTERNAL_ERROR", f"{type(exc).__name__}: {exc}")

    # -------------------------------------------------------------- health
    @app.get("/api/health")
    def health() -> dict:
        settings = services.settings
        return {
            "ok": services.error is None,
            "service": "soc-triage-api",
            "dataset_error": services.error,
            "ai": services.triage.status() if services.triage else None,
            "providers": describe_providers(settings) if settings else [],
            "guardrail": module5_status(),
            "recommendations": recommendations_status(),
        }

    @app.get("/api/dataset")
    def dataset_summary() -> dict:
        dataset = services.require_dataset()
        summary = dataset.summary()
        counts = services.triage.store.verdict_counts() if services.triage else {}
        return {
            **summary,
            "triage_summary": counts,
            "attack_categories": list(ATTACK_CATEGORIES),
        }

    # ----------------------------------------------------------- incidents
    @app.get("/api/incidents")
    def list_incidents() -> dict:
        dataset = services.require_dataset()
        store = services.triage.store if services.triage else None
        items = []
        for incident_id in dataset.incident_ids():
            analyst = dataset.analyst_incident(incident_id)
            stored = store.get(incident_id) if store else None
            latest = (stored or {}).get("latest") or {}
            decision = (stored or {}).get("decision") or {"status": "pending"}
            items.append(
                {
                    "incident_id": incident_id,
                    "category": analyst["category"],
                    "source_ip": analyst["source_ip"],
                    "destination_ip": analyst["destination_ip"],
                    "window_start": analyst["window_start"],
                    "flow_count": analyst["flow_count"],
                    "rule_basis": analyst["rule_basis"],
                    "triage": {
                        "status": latest.get("status"),
                        "verdict": latest.get("verdict"),
                        "confidence": latest.get("confidence"),
                        "requires_confirmation": bool(latest.get("requires_confirmation")),
                        "triaged_at": latest.get("completed_at"),
                        "run_id": latest.get("run_id"),
                        "decision": decision.get("status", "pending"),
                    },
                }
            )
        return {
            "incidents": items,
            "counts": dataset.summary()["counts"],
            "triage_summary": store.verdict_counts() if store else {},
        }

    @app.get("/api/incidents/{incident_id}")
    def get_incident(incident_id: str) -> dict:
        dataset = services.require_dataset()
        analyst = dataset.analyst_incident(incident_id)
        stored = services.triage.store.get(incident_id) if services.triage else None
        return {
            "incident": analyst,
            "evidence": dataset.analyst_evidence(incident_id),
            "timeline": dataset.timeline(incident_id),
            "triage": (stored or {}).get("latest"),
            "decision": (stored or {}).get("decision"),
            "recommendations": recommendations_status(),
        }

    @app.get("/api/incidents/{incident_id}/evidence")
    def get_evidence(incident_id: str) -> dict:
        return services.require_dataset().analyst_evidence(incident_id)

    @app.get("/api/incidents/{incident_id}/timeline")
    def get_timeline(incident_id: str) -> dict:
        return services.require_dataset().timeline(incident_id)

    # -------------------------------------------------------------- triage
    @app.get("/api/incidents/{incident_id}/triage")
    def get_triage(incident_id: str) -> dict:
        triage = services.require_triage()
        stored = triage.latest(incident_id)
        if not stored:
            return {"incident_id": incident_id, "triage": None, "decision": None}
        return {
            "incident_id": incident_id,
            "triage": stored.get("latest"),
            "decision": stored.get("decision"),
        }

    @app.post("/api/incidents/{incident_id}/triage")
    def run_triage(incident_id: str) -> Any:
        triage = services.require_triage()
        result = triage.investigate(incident_id)
        if result.get("status") == "error":
            # The run is recorded, but an operational failure is not a verdict.
            return JSONResponse(status_code=502, content={"triage": result})
        return {"triage": result}

    @app.post("/api/incidents/{incident_id}/decision")
    async def record_decision(incident_id: str, request: Request) -> dict:
        triage = services.require_triage()
        try:
            body = await request.json()
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}
        decision = str(body.get("decision") or "").strip().lower()
        analyst = str(body.get("analyst") or "").strip()
        note = body.get("note")
        if not analyst:
            raise ApiError(400, "MISSING_ANALYST", "An analyst name is required to record a decision.")
        try:
            updated = triage.decide(incident_id, decision=decision, analyst=analyst, note=note)
        except LookupError as exc:
            raise ApiError(409, "NO_PROPOSAL", str(exc)) from exc
        except ValueError as exc:
            raise ApiError(400, "INVALID_DECISION", str(exc)) from exc
        return {"incident_id": incident_id, "decision": updated.get("decision"), "triage": updated.get("latest")}

    # ------------------------------------------------- Module 4 (not ready)
    @app.get("/api/incidents/{incident_id}/recommendations")
    def get_recommendations(incident_id: str) -> dict:
        services.require_dataset().require(incident_id)
        status = recommendations_status()
        return {"incident_id": incident_id, **status}

    @app.post("/api/incidents/{incident_id}/recommendations/{recommendation_id}/approve")
    def approve_recommendation(incident_id: str, recommendation_id: str) -> Any:
        services.require_dataset().require(incident_id)
        status = recommendations_status()
        if not status["available"]:
            return error_response(
                501,
                "MODULE_NOT_CONNECTED",
                "Module 4 (recommendations and approval) is not connected, so approval cannot be recorded.",
                status["detail"],
            )
        return error_response(
            501,
            "NOT_IMPLEMENTED",
            "Module 4 exposes a read function but no approval endpoint has been defined yet.",
        )

    # --------------------------------------------------------------- audit
    @app.get("/api/audit")
    def get_audit(limit: int = 100, incident_id: str | None = None) -> dict:
        if services.audit is None:
            raise ApiError(503, "SERVICE_UNAVAILABLE", services.error or "Audit log unavailable.")
        records = services.audit.entries(limit=max(1, min(limit, 500)), incident_id=incident_id)
        return {
            "entries": summarize(records),
            "verification": services.audit.verify(),
            "source": "services.audit_log (Module 2 append-only trail; Module 4 owns the project audit log)",
        }

    @app.get("/api/audit/verify")
    def verify_audit() -> dict:
        if services.audit is None:
            raise ApiError(503, "SERVICE_UNAVAILABLE", services.error or "Audit log unavailable.")
        return services.audit.verify()

    # ------------------------------------------------------------- settings
    @app.get("/api/settings")
    def get_settings() -> dict:
        if services.settings is None:
            raise ApiError(503, "SERVICE_UNAVAILABLE", services.error or "Configuration failed to load.")
        return {
            "ai": services.triage.status() if services.triage else services.settings.describe(),
            "providers": describe_providers(services.settings),
            "guardrail": module5_status(),
            "recommendations": recommendations_status(),
        }

    return app


app = create_app()


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    settings = services.settings
    host = settings.api_host if settings else "127.0.0.1"
    port = settings.api_port if settings else 8000
    uvicorn.run(app, host=host, port=port, log_level="info")
