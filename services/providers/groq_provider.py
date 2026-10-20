"""GroqCloud adapter (OpenAI-compatible chat completions API).

Implemented directly against Groq's documented HTTP API using ``httpx``.
Rationale: the request/response shape is the OpenAI tool-calling shape, the
surface we need is three fields, and a pinned SDK adds a dependency without
adding capability. Transport is injectable (``httpx.MockTransport``) so the
whole adapter is unit-testable without a key.
"""

from __future__ import annotations

from typing import Any, Sequence

import httpx

from .base import (
    AssistantTurn,
    ProviderAuthError,
    ProviderProtocolError,
    ProviderRateLimited,
    ProviderTimeout,
    ProviderUnavailable,
    ToolCall,
    dumps,
    loads_object,
)

DEFAULT_BASE_URL = "https://api.groq.com/openai/v1"


class GroqProvider:
    name = "groq"

    def __init__(
        self,
        api_key: str,
        model: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 45.0,
        max_output_tokens: int = 1200,
        temperature: float = 0.0,
        transport: httpx.BaseTransport | None = None,
    ):
        if not api_key:
            raise ProviderAuthError("GROQ_API_KEY is empty")
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_output_tokens = max_output_tokens
        self.temperature = temperature
        self._transport = transport

    # ------------------------------------------------------------------ wire
    def _payload(self, messages: Sequence[dict], tools: Sequence[dict]) -> dict:
        return {
            "model": self.model,
            "messages": [self._message(m) for m in messages],
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": tool["name"],
                        "description": tool["description"],
                        "parameters": tool["parameters"],
                    },
                }
                for tool in tools
            ],
            "tool_choice": "auto",
            "temperature": self.temperature,
            "max_tokens": self.max_output_tokens,
        }

    @staticmethod
    def _message(message: dict) -> dict:
        role = message["role"]
        if role == "assistant":
            out: dict[str, Any] = {"role": "assistant", "content": message.get("content") or ""}
            calls = message.get("tool_calls") or []
            if calls:
                out["tool_calls"] = [
                    {
                        "id": call["id"],
                        "type": "function",
                        "function": {
                            "name": call["name"],
                            "arguments": dumps(call.get("arguments") or {}),
                        },
                    }
                    for call in calls
                ]
            return out
        if role == "tool":
            return {
                "role": "tool",
                "tool_call_id": message["tool_call_id"],
                "name": message.get("name", ""),
                "content": message.get("content") or "",
            }
        return {"role": role, "content": message.get("content") or ""}

    # ------------------------------------------------------------- transport
    def complete(
        self,
        messages: Sequence[dict],
        tools: Sequence[dict],
        *,
        timeout: float | None = None,
    ) -> AssistantTurn:
        payload = self._payload(messages, tools)
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        with httpx.Client(
            timeout=timeout or self.timeout, transport=self._transport, follow_redirects=False
        ) as client:
            try:
                response = client.post(
                    f"{self.base_url}/chat/completions", json=payload, headers=headers
                )
            except httpx.TimeoutException as exc:
                raise ProviderTimeout(
                    f"Groq did not respond within {timeout or self.timeout:.0f}s", detail=str(exc)
                ) from exc
            except httpx.HTTPError as exc:
                raise ProviderUnavailable(f"Groq request failed: {exc}", detail=str(exc)) from exc
        return self._parse(response)

    @staticmethod
    def _parse(response: httpx.Response) -> AssistantTurn:
        if response.status_code == 429:
            retry_after = response.headers.get("retry-after")
            try:
                retry_seconds = float(retry_after) if retry_after else None
            except ValueError:
                retry_seconds = None
            raise ProviderRateLimited(
                "Groq free-tier rate limit reached", retry_after=retry_seconds, detail=_snippet(response)
            )
        if response.status_code in (401, 403):
            raise ProviderAuthError(
                "Groq rejected the API key (check GROQ_API_KEY)", detail=_snippet(response)
            )
        if response.status_code >= 500:
            raise ProviderUnavailable(
                f"Groq returned {response.status_code}", detail=_snippet(response)
            )
        if response.status_code >= 400:
            # 400/404 usually means the model id is unavailable on this account.
            raise ProviderProtocolError(
                f"Groq rejected the request ({response.status_code})", detail=_snippet(response)
            )
        try:
            body = response.json()
        except ValueError as exc:
            raise ProviderProtocolError("Groq returned a non-JSON body", detail=_snippet(response)) from exc
        return _parse_body(body)


def _snippet(response: httpx.Response, limit: int = 400) -> str:
    try:
        return response.text[:limit]
    except Exception:  # pragma: no cover - defensive
        return "<unreadable body>"


def _parse_body(body: Any) -> AssistantTurn:
    if not isinstance(body, dict):
        raise ProviderProtocolError("Groq response was not a JSON object")
    choices = body.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ProviderProtocolError("Groq response contained no choices", detail=_snippet_body(body))
    choice = choices[0] or {}
    message = choice.get("message") or {}
    if not isinstance(message, dict):
        raise ProviderProtocolError("Groq message was not an object")

    calls: list[ToolCall] = []
    for index, raw_call in enumerate(message.get("tool_calls") or []):
        if not isinstance(raw_call, dict):
            raise ProviderProtocolError("Groq returned a malformed tool call")
        function = raw_call.get("function") or {}
        name = function.get("name")
        if not name:
            raise ProviderProtocolError("Groq tool call had no function name")
        arguments, error = loads_object(function.get("arguments"))
        calls.append(
            ToolCall(
                id=str(raw_call.get("id") or f"call_{index}"),
                name=str(name),
                arguments=arguments or {},
                raw_arguments=function.get("arguments"),
                parse_error=error,
            )
        )

    text = message.get("content")
    return AssistantTurn(
        text=text if isinstance(text, str) else (None if text is None else str(text)),
        tool_calls=calls,
        finish_reason=choice.get("finish_reason"),
        usage=body.get("usage") or {},
        raw=body,
    )


def _snippet_body(body: Any, limit: int = 400) -> str:
    try:
        return str(body)[:limit]
    except Exception:  # pragma: no cover
        return "<unreadable>"
