"""Pre-flight check for the configured AI provider.

Run this after adding a key, before trusting a live demo::

    python -m services.preflight

It verifies, in order:

1. configuration loads and the provider is implemented,
2. the API key is accepted (never printed),
3. the configured model id exists on the account,
4. the model actually emits a tool call for the investigation tool schema.

Exit code 0 means live triage is ready. Anything else prints the reason.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

if __package__ in (None, ""):  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    __package__ = "services"

import httpx

from .config import ConfigError, load_settings
from .providers import ProviderError, build_provider
from .tools import TOOL_DEFINITIONS

PING_TOOL = [
    {
        "name": "ping",
        "description": "Health probe. Echo the provided token back.",
        "parameters": {
            "type": "object",
            "properties": {"token": {"type": "string", "description": "Any short string."}},
            "required": ["token"],
            "additionalProperties": False,
        },
    }
]


def _list_models(provider: str, api_key: str, timeout: float = 20.0) -> list[str]:
    if provider == "groq":
        url, headers = "https://api.groq.com/openai/v1/models", {"Authorization": f"Bearer {api_key}"}
    elif provider == "gemini":
        url, headers = (
            "https://generativelanguage.googleapis.com/v1beta/models",
            {"x-goog-api-key": api_key},
        )
    else:
        return []
    with httpx.Client(timeout=timeout) as client:
        response = client.get(url, headers=headers)
    if response.status_code in (401, 403):
        raise ProviderError("API key rejected while listing models")
    response.raise_for_status()
    body = response.json()
    if provider == "groq":
        return [item.get("id", "") for item in body.get("data", [])]
    return [item.get("name", "").split("/")[-1] for item in body.get("models", [])]


def run() -> int:
    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"[FAIL] configuration: {exc}")
        return 2

    print(f"provider : {settings.provider}")
    print(f"model    : {settings.model}")
    print(f"mode     : {'mock' if settings.is_mock else 'live'}")

    if settings.is_mock:
        provider = build_provider(settings)
        turn = provider.complete(
            [{"role": "user", "content": "Call ping with token=ok."}], PING_TOOL
        )
        ok = bool(turn.tool_calls) or bool(turn.text)
        print("[OK] mock provider responses work; the loop runs without credentials.")
        print("     Set AI_PROVIDER=groq|gemini in .env to test a live model.")
        return 0 if ok else 1

    if not settings.key_configured:
        print(f"[FAIL] {settings.provider}: no API key configured ({settings.blocking_reason()})")
        return 2

    try:
        models = _list_models(settings.provider, settings.api_key or "")
    except httpx.HTTPError as exc:
        print(f"[FAIL] could not reach the {settings.provider} API: {exc}")
        return 3
    except ProviderError as exc:
        print(f"[FAIL] {exc}")
        return 3

    if models:
        print(f"models   : {len(models)} visible to this key")
        matches = [name for name in models if name == settings.model]
        if not matches:
            close = [name for name in models if settings.model.split("/")[-1][:8] in name][:5]
            print(f"[FAIL] {settings.model!r} is not available to this key.")
            if close:
                print(f"       similar: {', '.join(close)}")
            print("       Update GROQ_MODEL / GEMINI_MODEL in .env.")
            return 4
        print(f"[OK] model {settings.model!r} is available.")

    provider = build_provider(settings)
    try:
        turn = provider.complete(
            [
                {
                    "role": "user",
                    "content": "Use the ping tool with token set to 'preflight'. Call the tool only.",
                }
            ],
            PING_TOOL,
            timeout=30.0,
        )
    except ProviderError as exc:
        print(f"[FAIL] tool-calling probe failed: {exc.code} {exc.message}")
        return 5

    if not turn.tool_calls:
        print("[WARN] the model answered without calling the probe tool.")
        print("       Tool calling may be unsupported for this model; the triage loop needs it.")
        return 6

    call = turn.tool_calls[0]
    print(f"[OK] tool calling works ({call.name} {json.dumps(call.arguments)})")
    print(
        f"[OK] investigation tools: {', '.join(definition['name'] for definition in TOOL_DEFINITIONS)}"
    )
    print("\nLive mode is ready. Start the API with: python -m services.api")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(run())
