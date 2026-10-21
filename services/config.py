"""Typed configuration for the triage service.

Everything is read from environment variables (optionally via a local ``.env``).
Secrets never leave this process: :meth:`Settings.describe` is the only
serialisation path used by the HTTP layer, and it reports presence flags rather
than values.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT / ".env"

# ``override=False`` keeps real environment variables authoritative, which is
# what CI and container deployments expect.
load_dotenv(ENV_FILE, override=False)


class ConfigError(RuntimeError):
    """Raised when the environment cannot produce a usable configuration."""


# Defaults follow the free-tier candidates requested in the project brief.
# Availability must still be confirmed with ``python -m services.preflight``.
PROVIDER_DEFAULT_MODELS = {
    "groq": "openai/gpt-oss-20b",
    "gemini": "gemini-2.5-flash-lite",
    "openrouter": "meta-llama/llama-3.3-70b-instruct:free",
    "mock": "mock-triage-model",
}

PROVIDER_KEY_VARS = {
    "groq": "GROQ_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "mock": None,
}

IMPLEMENTED_PROVIDERS = ("groq", "gemini", "mock")


def _str(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()


def _int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc


def _float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from exc


def _path(name: str, default: str) -> Path:
    value = Path(_str(name, default))
    return value if value.is_absolute() else ROOT / value


@dataclass(frozen=True)
class Settings:
    provider: str
    api_keys: dict[str, str]
    models: dict[str, str]

    max_steps: int = 6
    request_timeout: float = 45.0
    max_tool_calls: int = 12
    max_output_tokens: int = 1200
    temperature: float = 0.0

    alerts_path: Path = ROOT / "src" / "real-alerts.json"
    timelines_path: Path = ROOT / "src" / "real-timelines.json"
    audit_path: Path = ROOT / "data" / "audit" / "triage-audit.jsonl"
    state_path: Path = ROOT / "data" / "state" / "triage-results.json"

    api_host: str = "127.0.0.1"
    api_port: int = 8000
    cors_origins: tuple[str, ...] = ("http://127.0.0.1:5173", "http://localhost:5173")

    # ------------------------------------------------------------------ props
    @property
    def model(self) -> str:
        return self.models[self.provider]

    @property
    def api_key(self) -> str | None:
        return self.api_keys.get(self.provider) or None

    @property
    def is_mock(self) -> bool:
        return self.provider == "mock"

    @property
    def key_configured(self) -> bool:
        return self.is_mock or bool(self.api_key)

    @property
    def ready(self) -> bool:
        """True when a live investigation could actually be attempted."""
        return self.provider in IMPLEMENTED_PROVIDERS and self.key_configured

    def blocking_reason(self) -> str | None:
        if self.provider not in IMPLEMENTED_PROVIDERS:
            return (
                f"AI_PROVIDER={self.provider!r} has no adapter in this build. "
                f"Supported values: {', '.join(IMPLEMENTED_PROVIDERS)}."
            )
        if not self.key_configured:
            var = PROVIDER_KEY_VARS.get(self.provider)
            return (
                f"{var} is not set. Add it to .env to run live triage with "
                f"{self.provider}/{self.model}, or set AI_PROVIDER=mock to demo "
                "the workflow without credentials."
            )
        return None

    def describe(self) -> dict:
        """Safe, secret-free description for the frontend status bar."""
        return {
            "provider": self.provider,
            "model": self.model,
            "mode": "mock" if self.is_mock else "live",
            "key_configured": self.key_configured,
            "ready": self.ready,
            "blocked_reason": self.blocking_reason(),
            "bounds": {
                "max_steps": self.max_steps,
                "max_tool_calls": self.max_tool_calls,
                "request_timeout_seconds": self.request_timeout,
            },
        }


def load_settings() -> Settings:
    provider = (_str("AI_PROVIDER", "mock") or "mock").lower()
    if provider not in PROVIDER_DEFAULT_MODELS:
        raise ConfigError(
            f"Unknown AI_PROVIDER {provider!r}. Supported: {', '.join(PROVIDER_DEFAULT_MODELS)}"
        )

    api_keys = {
        "groq": _str("GROQ_API_KEY"),
        "gemini": _str("GEMINI_API_KEY"),
        "openrouter": _str("OPENROUTER_API_KEY"),
        "mock": "",
    }
    models = {
        "groq": _str("GROQ_MODEL", PROVIDER_DEFAULT_MODELS["groq"]),
        "gemini": _str("GEMINI_MODEL", PROVIDER_DEFAULT_MODELS["gemini"]),
        "openrouter": _str("OPENROUTER_MODEL", PROVIDER_DEFAULT_MODELS["openrouter"]),
        "mock": PROVIDER_DEFAULT_MODELS["mock"],
    }

    max_steps = _int("AI_MAX_STEPS", 6)
    if not 1 <= max_steps <= 12:
        raise ConfigError("AI_MAX_STEPS must be between 1 and 12")

    max_tool_calls = _int("AI_MAX_TOOL_CALLS", 12)
    if not 1 <= max_tool_calls <= 40:
        raise ConfigError("AI_MAX_TOOL_CALLS must be between 1 and 40")

    origins = tuple(
        origin.strip()
        for origin in _str(
            "CORS_ORIGINS", "http://127.0.0.1:5173,http://localhost:5173"
        ).split(",")
        if origin.strip()
    )

    return Settings(
        provider=provider,
        api_keys=api_keys,
        models=models,
        max_steps=max_steps,
        request_timeout=_float("AI_REQUEST_TIMEOUT", 45.0),
        max_tool_calls=max_tool_calls,
        max_output_tokens=_int("AI_MAX_OUTPUT_TOKENS", 1200),
        temperature=_float("AI_TEMPERATURE", 0.0),
        alerts_path=_path("ALERTS_PATH", "src/real-alerts.json"),
        timelines_path=_path("TIMELINES_PATH", "src/real-timelines.json"),
        audit_path=_path("AUDIT_LOG_PATH", "data/audit/triage-audit.jsonl"),
        state_path=_path("TRIAGE_STATE_PATH", "data/state/triage-results.json"),
        api_host=_str("API_HOST", "127.0.0.1"),
        api_port=_int("API_PORT", 8000),
        cors_origins=origins,
    )
