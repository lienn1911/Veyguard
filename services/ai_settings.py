"""Local AI configuration checks used by the SOC Desk settings page."""

import httpx

from services.preflight import PING_TOOL, _list_models
from services.providers import ProviderError, build_provider


def test_connection(settings):
    if settings.is_mock:
        return {"ok": True, "message": "Demo simulation is ready. No live model is used."}
    try:
        if settings.provider != "codex":
            models = _list_models(settings.provider, settings.api_key or "", timeout=15.0)
            if settings.model not in models:
                return {"ok": False, "message": "This model is not available to the supplied key. Check its model ID."}
        provider = build_provider(settings)
        turn = provider.complete(
            [{"role": "user", "content": "Call the ping tool with token set to 'soc-desk'."}],
            PING_TOOL,
            timeout=120.0 if settings.provider == "codex" else 20.0,
        )
        if not turn.tool_calls or turn.tool_calls[0].name != "ping":
            return {"ok": False, "message": "The model responded, but did not make the required tool call."}
        return {"ok": True, "message": "Codex CLI sign-in and tool calling work. AI check is ready." if settings.provider == "codex" else "Connection and tool calling work. AI check is ready."}
    except ProviderError as exc:
        return {"ok": False, "message": exc.message}
    except httpx.HTTPStatusError as exc:
        return {"ok": False, "message": f"Provider rejected the request (HTTP {exc.response.status_code})."}
    except httpx.HTTPError:
        return {"ok": False, "message": "Could not reach the provider. Check your internet connection."}
