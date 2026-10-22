"""Provider registry / factory.

The only place that knows about concrete providers. ``AI_PROVIDER`` selects one;
there is deliberately no automatic failover, because silently switching models
would make an incident conclusion impossible to reproduce.
"""

from __future__ import annotations

from typing import Any

import httpx

from ..config import IMPLEMENTED_PROVIDERS, Settings
from .base import (
    AssistantTurn,
    ChatProvider,
    ProviderAuthError,
    ProviderError,
    ProviderNotConfigured,
    ProviderProtocolError,
    ProviderRateLimited,
    ProviderTimeout,
    ProviderUnavailable,
    ToolCall,
    VERDICTS,
    dumps,
    loads_object,
)
from .gemini_provider import GeminiProvider
from .groq_provider import GroqProvider
from .mock_provider import MockProvider
from .codex_provider import CodexProvider

__all__ = [
    "AssistantTurn",
    "ChatProvider",
    "ToolCall",
    "VERDICTS",
    "build_provider",
    "describe_providers",
    "dumps",
    "loads_object",
    "ProviderError",
    "ProviderAuthError",
    "ProviderNotConfigured",
    "ProviderProtocolError",
    "ProviderRateLimited",
    "ProviderTimeout",
    "ProviderUnavailable",
]


def build_provider(
    settings: Settings, *, transport: httpx.BaseTransport | None = None
) -> Any:
    """Instantiate the configured provider.

    Raises :class:`ProviderNotConfigured` when the selection is unusable; callers
    turn that into an explicit 503 rather than falling back to something else.
    """
    provider = settings.provider
    if provider not in IMPLEMENTED_PROVIDERS:
        raise ProviderNotConfigured(
            f"No adapter is implemented for AI_PROVIDER={provider!r}. "
            f"Available: {', '.join(IMPLEMENTED_PROVIDERS)}.",
            detail="Set AI_PROVIDER to groq, gemini, codex, or mock.",
        )

    if provider == "mock":
        return MockProvider()

    if not settings.key_configured:
        raise ProviderNotConfigured(
            settings.blocking_reason() or f"{provider} is not configured"
        )

    if provider == "groq":
        return GroqProvider(
            api_key=settings.api_key or "",
            model=settings.model,
            timeout=settings.request_timeout,
            max_output_tokens=settings.max_output_tokens,
            temperature=settings.temperature,
            transport=transport,
        )
    if provider == "gemini":
        return GeminiProvider(
            api_key=settings.api_key or "",
            model=settings.model,
            timeout=settings.request_timeout,
            max_output_tokens=settings.max_output_tokens,
            temperature=settings.temperature,
            transport=transport,
        )
    if provider == "codex":
        return CodexProvider(model=settings.model, timeout=max(settings.request_timeout, 120.0))
    raise ProviderNotConfigured(f"Unhandled provider {provider!r}")  # pragma: no cover


def describe_providers(settings: Settings) -> list[dict]:
    """Static capability matrix for the settings/health UI."""
    return [
        {
            "id": "codex",
            "label": "Codex CLI",
            "implemented": True,
            "default_model": "default",
            "selected": settings.provider == "codex",
            "key_var": None,
            "key_configured": settings.provider == "codex" and settings.key_configured,
        },
        {
            "id": "groq",
            "label": "GroqCloud",
            "implemented": True,
            "default_model": "openai/gpt-oss-20b",
            "selected": settings.provider == "groq",
            "key_var": "GROQ_API_KEY",
            "key_configured": bool(settings.api_keys.get("groq")),
        },
        {
            "id": "gemini",
            "label": "Google Gemini",
            "implemented": True,
            "default_model": "gemini-2.5-flash-lite",
            "selected": settings.provider == "gemini",
            "key_var": "GEMINI_API_KEY",
            "key_configured": bool(settings.api_keys.get("gemini")),
        },
        {
            "id": "mock",
            "label": "Mock (offline, deterministic)",
            "implemented": True,
            "default_model": "mock-triage-model",
            "selected": settings.provider == "mock",
            "key_var": None,
            "key_configured": True,
        },
        {
            "id": "openrouter",
            "label": "OpenRouter (adapter not implemented)",
            "implemented": False,
            "default_model": "meta-llama/llama-3.3-70b-instruct:free",
            "selected": settings.provider == "openrouter",
            "key_var": "OPENROUTER_API_KEY",
            "key_configured": bool(settings.api_keys.get("openrouter")),
        },
    ]
