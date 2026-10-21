"""Provider-agnostic model interface.

Every adapter converts the provider's wire format into the small vocabulary
below. The investigation loop in :mod:`services.triage` only ever sees these
types, so swapping ``groq`` for ``gemini`` is a configuration change.

Message vocabulary (plain dicts, easy to log and to unit test)::

    {"role": "system",  "content": str}
    {"role": "user",    "content": str}
    {"role": "assistant", "content": str | None,
     "tool_calls": [{"id": str, "name": str, "arguments": dict}]}
    {"role": "tool", "tool_call_id": str, "name": str, "content": str}
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol, Sequence, runtime_checkable

VERDICTS = ("Likely Attack", "Likely Benign", "Needs Review")


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #
class ProviderError(RuntimeError):
    """Base class for every provider failure.

    ``code`` is stable and surfaces in the API response so the frontend can
    distinguish an operational failure from a security conclusion.
    """

    code = "PROVIDER_ERROR"
    retryable = False

    def __init__(self, message: str, *, detail: str | None = None):
        super().__init__(message)
        self.message = message
        self.detail = detail

    def as_dict(self) -> dict:
        return {"code": self.code, "message": self.message, "detail": self.detail}


class ProviderTimeout(ProviderError):
    code = "PROVIDER_TIMEOUT"
    retryable = True


class ProviderRateLimited(ProviderError):
    code = "PROVIDER_RATE_LIMITED"

    def __init__(self, message: str, *, retry_after: float | None = None, detail: str | None = None):
        super().__init__(message, detail=detail)
        self.retry_after = retry_after

    def as_dict(self) -> dict:
        payload = super().as_dict()
        payload["retry_after_seconds"] = self.retry_after
        return payload


class ProviderAuthError(ProviderError):
    code = "PROVIDER_AUTH_FAILED"


class ProviderUnavailable(ProviderError):
    code = "PROVIDER_UNAVAILABLE"
    retryable = True


class ProviderProtocolError(ProviderError):
    """The provider answered, but not in a shape we can safely interpret."""

    code = "PROVIDER_BAD_RESPONSE"


class ProviderNotConfigured(ProviderError):
    code = "PROVIDER_NOT_CONFIGURED"


# --------------------------------------------------------------------------- #
# Value objects
# --------------------------------------------------------------------------- #
@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    raw_arguments: str | None = None
    parse_error: str | None = None


@dataclass
class AssistantTurn:
    text: str | None = None
    tool_calls: list[ToolCall] = field(default_factory=list)
    finish_reason: str | None = None
    usage: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] | None = None

    @property
    def wants_tools(self) -> bool:
        return bool(self.tool_calls)


@runtime_checkable
class ChatProvider(Protocol):
    name: str
    model: str

    def complete(
        self,
        messages: Sequence[dict],
        tools: Sequence[dict],
        *,
        timeout: float | None = None,
    ) -> AssistantTurn: ...


# --------------------------------------------------------------------------- #
# Helpers shared by adapters
# --------------------------------------------------------------------------- #
def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def loads_object(raw: str | None) -> tuple[dict | None, str | None]:
    """Parse a JSON object string, returning ``(value, error)``."""
    if raw is None:
        return {}, None
    if isinstance(raw, dict):
        return raw, None
    text = str(raw).strip()
    if not text:
        return {}, None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        return None, f"arguments were not valid JSON ({exc.msg})"
    if not isinstance(parsed, dict):
        return None, "arguments must be a JSON object"
    return parsed, None
