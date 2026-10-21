"""Google Gemini adapter (``generativelanguage`` REST API, v1beta).

Gemini's wire format differs from OpenAI's in three places that matter here:

* conversations are ``contents`` with ``user`` / ``model`` roles,
* tool definitions use ``functionDeclarations`` with an OpenAPI-subset schema
  (``additionalProperties`` is *not* supported and is stripped),
* tool results are ``functionResponse`` parts keyed by function name instead of
  by a call id, so ids are synthesised locally.

Those differences stop at this module boundary.
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
)

DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"

_SUPPORTED_SCHEMA_KEYS = {
    "type",
    "format",
    "description",
    "nullable",
    "enum",
    "items",
    "properties",
    "required",
    "minimum",
    "maximum",
    "title",
}


def to_gemini_schema(schema: Any) -> Any:
    """Project a JSON Schema onto the OpenAPI subset Gemini accepts."""
    if isinstance(schema, list):
        return [to_gemini_schema(item) for item in schema]
    if not isinstance(schema, dict):
        return schema
    cleaned: dict[str, Any] = {}
    for key, value in schema.items():
        if key not in _SUPPORTED_SCHEMA_KEYS:
            continue  # drops additionalProperties, $schema, definitions, ...
        if key == "properties" and isinstance(value, dict):
            cleaned[key] = {name: to_gemini_schema(sub) for name, sub in value.items()}
        elif key == "items":
            cleaned[key] = to_gemini_schema(value)
        else:
            cleaned[key] = value
    return cleaned


class GeminiProvider:
    name = "gemini"

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
            raise ProviderAuthError("GEMINI_API_KEY is empty")
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_output_tokens = max_output_tokens
        self.temperature = temperature
        self._transport = transport
        self._call_seq = 0

    # ------------------------------------------------------------------ wire
    def _payload(self, messages: Sequence[dict], tools: Sequence[dict]) -> dict:
        system_parts: list[str] = []
        contents: list[dict] = []
        for message in messages:
            role = message["role"]
            if role == "system":
                system_parts.append(message.get("content") or "")
            elif role == "user":
                contents.append({"role": "user", "parts": [{"text": message.get("content") or ""}]})
            elif role == "assistant":
                parts: list[dict] = []
                if message.get("content"):
                    parts.append({"text": message["content"]})
                for call in message.get("tool_calls") or []:
                    parts.append(
                        {"functionCall": {"name": call["name"], "args": call.get("arguments") or {}}}
                    )
                if parts:
                    contents.append({"role": "model", "parts": parts})
            elif role == "tool":
                contents.append(
                    {
                        "role": "user",
                        "parts": [
                            {
                                "functionResponse": {
                                    "name": message.get("name") or "tool",
                                    # Gemini requires a struct; wrapping keeps the
                                    # original payload intact for the model.
                                    "response": {"result": _maybe_json(message.get("content"))},
                                }
                            }
                        ],
                    }
                )
        payload: dict[str, Any] = {
            "contents": contents,
            "generationConfig": {
                "temperature": self.temperature,
                "maxOutputTokens": self.max_output_tokens,
            },
        }
        if system_parts:
            payload["systemInstruction"] = {"parts": [{"text": "\n\n".join(system_parts)}]}
        if tools:
            payload["tools"] = [
                {
                    "functionDeclarations": [
                        {
                            "name": tool["name"],
                            "description": tool["description"],
                            "parameters": to_gemini_schema(tool["parameters"]),
                        }
                        for tool in tools
                    ]
                }
            ]
        return payload

    # ------------------------------------------------------------- transport
    def complete(
        self,
        messages: Sequence[dict],
        tools: Sequence[dict],
        *,
        timeout: float | None = None,
    ) -> AssistantTurn:
        payload = self._payload(messages, tools)
        url = f"{self.base_url}/models/{self.model}:generateContent"
        headers = {
            "x-goog-api-key": self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        with httpx.Client(
            timeout=timeout or self.timeout, transport=self._transport, follow_redirects=False
        ) as client:
            try:
                response = client.post(url, json=payload, headers=headers)
            except httpx.TimeoutException as exc:
                raise ProviderTimeout(
                    f"Gemini did not respond within {timeout or self.timeout:.0f}s", detail=str(exc)
                ) from exc
            except httpx.HTTPError as exc:
                raise ProviderUnavailable(f"Gemini request failed: {exc}", detail=str(exc)) from exc
        return self._parse(response)

    def _parse(self, response: httpx.Response) -> AssistantTurn:
        if response.status_code == 429:
            raise ProviderRateLimited("Gemini free-tier rate limit reached", detail=_snippet(response))
        if response.status_code in (401, 403):
            raise ProviderAuthError(
                "Gemini rejected the API key (check GEMINI_API_KEY)", detail=_snippet(response)
            )
        if response.status_code >= 500:
            raise ProviderUnavailable(f"Gemini returned {response.status_code}", detail=_snippet(response))
        if response.status_code >= 400:
            raise ProviderProtocolError(
                f"Gemini rejected the request ({response.status_code})", detail=_snippet(response)
            )
        try:
            body = response.json()
        except ValueError as exc:
            raise ProviderProtocolError("Gemini returned a non-JSON body", detail=_snippet(response)) from exc
        if not isinstance(body, dict):
            raise ProviderProtocolError("Gemini response was not a JSON object")
        if body.get("promptFeedback", {}).get("blockReason"):
            raise ProviderProtocolError(
                f"Gemini blocked the prompt ({body['promptFeedback']['blockReason']})"
            )

        candidates = body.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            raise ProviderProtocolError("Gemini response contained no candidates", detail=_snippet(response))
        candidate = candidates[0] or {}
        parts = ((candidate.get("content") or {}).get("parts")) or []
        if not isinstance(parts, list):
            raise ProviderProtocolError("Gemini content parts were not a list")

        texts: list[str] = []
        calls: list[ToolCall] = []
        for part in parts:
            if not isinstance(part, dict):
                continue
            if isinstance(part.get("text"), str):
                texts.append(part["text"])
            function_call = part.get("functionCall")
            if isinstance(function_call, dict):
                name = function_call.get("name")
                if not name:
                    raise ProviderProtocolError("Gemini functionCall had no name")
                self._call_seq += 1
                args = function_call.get("args")
                calls.append(
                    ToolCall(
                        id=f"gemini_call_{self._call_seq}",
                        name=str(name),
                        arguments=args if isinstance(args, dict) else {},
                        raw_arguments=dumps(args) if args is not None else None,
                    )
                )

        return AssistantTurn(
            text="\n".join(texts).strip() or None,
            tool_calls=calls,
            finish_reason=candidate.get("finishReason"),
            usage=body.get("usageMetadata") or {},
            raw=body,
        )


def _maybe_json(value: Any) -> Any:
    import json

    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _snippet(response: httpx.Response, limit: int = 400) -> str:
    try:
        return response.text[:limit]
    except Exception:  # pragma: no cover
        return "<unreadable body>"
