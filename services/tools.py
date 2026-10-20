"""Read-only investigation tools exposed to the triage agent.

Design rules enforced here rather than in the prompt:

* explicit JSON-Schema per tool, validated before execution;
* a hard allowlist - an unknown tool name never reaches any callable;
* every tool is parameterised by ``incident_id`` and refuses to read outside the
  event being investigated (cross-incident snooping is an error, not a default);
* the callables only touch :class:`services.data_store.Dataset` in memory, so
  there is no code path that can write, mutate evidence, or execute a command.

The tool layer returns plain dictionaries, which makes the trace trivially
serialisable for the audit log and the UI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .data_store import Dataset

INCIDENT_ID_SCHEMA = {
    "type": "string",
    "description": "Identifier of the incident under investigation, e.g. INC-CADF3563BF02.",
    "pattern": "^INC-[A-Z0-9]{6,}$",
}

TOOL_DEFINITIONS: tuple[dict, ...] = (
    {
        "name": "get_incident_details",
        "description": (
            "Return the incident record produced by the detection layer: addresses, "
            "time window, aggregated flow count, and how many individual flow records "
            "are retained as evidence."
        ),
        "parameters": {
            "type": "object",
            "properties": {"incident_id": INCIDENT_ID_SCHEMA},
            "required": ["incident_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_related_alerts",
        "description": (
            "Return the detection alerts linked to the incident, including the rule that "
            "fired and the aggregation basis (ports/flows/sources counted in the window)."
        ),
        "parameters": {
            "type": "object",
            "properties": {"incident_id": INCIDENT_ID_SCHEMA},
            "required": ["incident_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_network_flows",
        "description": (
            "Return individual sampled flow records (one TCP/UDP flow each) retained as "
            "evidence for the incident. Use these identifiers as evidence_ids."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "incident_id": INCIDENT_ID_SCHEMA,
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of flow records to return (1-20). Defaults to 6.",
                    "minimum": 1,
                    "maximum": 20,
                },
            },
            "required": ["incident_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_incident_statistics",
        "description": (
            "Return aggregated statistics for the incident: full-window group totals from "
            "the detection layer plus figures computed over the sampled flows only. Cite "
            "these numbers instead of estimating."
        ),
        "parameters": {
            "type": "object",
            "properties": {"incident_id": INCIDENT_ID_SCHEMA},
            "required": ["incident_id"],
            "additionalProperties": False,
        },
    },
)

TOOL_NAMES = tuple(definition["name"] for definition in TOOL_DEFINITIONS)


class ToolError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class ToolOutcome:
    tool: str
    ok: bool
    data: dict | None = None
    error: dict | None = None
    arguments: dict = field(default_factory=dict)
    blocked: bool = False

    def payload(self) -> dict:
        if self.ok:
            return {"ok": True, "tool": self.tool, "data": self.data}
        return {"ok": False, "tool": self.tool, "error": self.error, "blocked": self.blocked}

    def as_text(self) -> str:
        import json

        return json.dumps(self.payload(), ensure_ascii=False, separators=(",", ":"), default=str)


# --------------------------------------------------------------------------- #
# Argument validation (small, explicit, dependency-free)
# --------------------------------------------------------------------------- #
_PY_TYPES = {"string": str, "integer": int, "number": (int, float), "boolean": bool}


def validate_arguments(schema: dict, arguments: Any) -> dict:
    """Validate and normalise tool arguments. Raises :class:`ToolError`."""
    if not isinstance(arguments, dict):
        raise ToolError("INVALID_ARGUMENTS", "Tool arguments must be a JSON object.")

    properties: dict = schema.get("properties") or {}
    required: list[str] = schema.get("required") or []

    if schema.get("additionalProperties") is False:
        unknown = sorted(set(arguments) - set(properties))
        if unknown:
            raise ToolError(
                "INVALID_ARGUMENTS",
                f"Unexpected argument(s): {', '.join(unknown)}. Allowed: {', '.join(sorted(properties))}.",
            )

    missing = [name for name in required if name not in arguments]
    if missing:
        raise ToolError("INVALID_ARGUMENTS", f"Missing required argument(s): {', '.join(missing)}.")

    cleaned: dict[str, Any] = {}
    for name, value in arguments.items():
        spec = properties.get(name) or {}
        expected = spec.get("type")
        if expected in _PY_TYPES and not isinstance(value, _PY_TYPES[expected]):
            raise ToolError(
                "INVALID_ARGUMENTS", f"Argument {name!r} must be of type {expected}."
            )
        if expected == "integer" and isinstance(value, bool):
            raise ToolError("INVALID_ARGUMENTS", f"Argument {name!r} must be an integer.")
        if expected == "string" and isinstance(value, bool):
            raise ToolError("INVALID_ARGUMENTS", f"Argument {name!r} must be a string.")
        if "minimum" in spec and isinstance(value, (int, float)) and value < spec["minimum"]:
            raise ToolError(
                "INVALID_ARGUMENTS", f"Argument {name!r} must be >= {spec['minimum']}."
            )
        if "maximum" in spec and isinstance(value, (int, float)) and value > spec["maximum"]:
            raise ToolError(
                "INVALID_ARGUMENTS", f"Argument {name!r} must be <= {spec['maximum']}."
            )
        cleaned[name] = value
    return cleaned


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #
class ToolRegistry:
    """Allowlisted, read-only execution surface."""

    def __init__(self, dataset: Dataset, active_incident_id: str):
        self.dataset = dataset
        self.active_incident_id = active_incident_id
        self._schemas = {definition["name"]: definition["parameters"] for definition in TOOL_DEFINITIONS}
        self._handlers: dict[str, Callable[[str, dict], dict]] = {
            "get_incident_details": self._incident_details,
            "get_related_alerts": self._related_alerts,
            "get_network_flows": self._network_flows,
            "get_incident_statistics": self._statistics,
        }

    # Exposed to the model. Returning a copy keeps the original list immutable.
    @staticmethod
    def definitions() -> list[dict]:
        return [dict(definition) for definition in TOOL_DEFINITIONS]

    def execute(self, name: str, arguments: Any) -> ToolOutcome:
        if name not in self._handlers:
            return ToolOutcome(
                tool=str(name),
                ok=False,
                arguments=arguments if isinstance(arguments, dict) else {},
                blocked=True,
                error={
                    "code": "TOOL_NOT_ALLOWED",
                    "message": (
                        f"Tool {name!r} is not in the read-only allowlist. "
                        f"Available tools: {', '.join(TOOL_NAMES)}."
                    ),
                },
            )
        try:
            cleaned = validate_arguments(self._schemas[name], arguments)
            self._check_scope(cleaned)
            data = self._handlers[name](self.active_incident_id, cleaned)
        except ToolError as exc:
            return ToolOutcome(
                tool=name,
                ok=False,
                arguments=arguments if isinstance(arguments, dict) else {},
                error={"code": exc.code, "message": exc.message},
            )
        except KeyError:
            return ToolOutcome(
                tool=name,
                ok=False,
                arguments=arguments if isinstance(arguments, dict) else {},
                error={
                    "code": "INCIDENT_NOT_FOUND",
                    "message": f"No incident {self.active_incident_id!r} exists in the dataset.",
                },
            )
        return ToolOutcome(tool=name, ok=True, data=data, arguments=cleaned)

    def _check_scope(self, arguments: dict) -> None:
        requested = arguments.get("incident_id")
        if requested != self.active_incident_id:
            raise ToolError(
                "INCIDENT_SCOPE_VIOLATION",
                (
                    f"This investigation is scoped to {self.active_incident_id}; "
                    f"incident {requested!r} cannot be read."
                ),
            )

    # ------------------------------------------------------------- handlers
    def _incident_details(self, incident_id: str, _: dict) -> dict:
        return self.dataset.agent_incident_details(incident_id)

    def _related_alerts(self, incident_id: str, _: dict) -> dict:
        return {"incident_id": incident_id, "alerts": self.dataset.agent_alerts(incident_id)}

    def _network_flows(self, incident_id: str, arguments: dict) -> dict:
        limit = int(arguments.get("limit") or 6)
        flows = self.dataset.agent_flows(incident_id, limit)
        return {
            "incident_id": incident_id,
            "returned": len(flows),
            "flows": flows,
            "note": (
                "These are the retained evidence records. Only these flow_id values may be "
                "cited as flow evidence."
            ),
        }

    def _statistics(self, incident_id: str, _: dict) -> dict:
        return self.dataset.agent_statistics(incident_id)
