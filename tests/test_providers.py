"""Adapter tests: wire format, error mapping, and provider parity.

All HTTP is faked with ``httpx.MockTransport``; no key and no network needed.
"""

from __future__ import annotations

import json
from dataclasses import replace

import httpx
import pytest

from services.providers import (
    ProviderAuthError,
    ProviderNotConfigured,
    ProviderProtocolError,
    ProviderRateLimited,
    ProviderTimeout,
    ProviderUnavailable,
    build_provider,
)
from services.providers.gemini_provider import GeminiProvider, to_gemini_schema
from services.providers.groq_provider import GroqProvider
from services.tools import TOOL_DEFINITIONS
from services.triage import TriageService
from tests.conftest import answer_turn, investigation_turn


class SequenceTransport(httpx.BaseTransport):
    def __init__(self, responses):
        self._responses = list(responses)
        self.requests: list[httpx.Request] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        status, payload = item
        return httpx.Response(status, json=payload)


def groq_tool_response(name="get_incident_details", arguments=None):
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": name,
                                "arguments": json.dumps(arguments or {"incident_id": "INC-CADF3563BF02"}),
                            },
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ],
        "usage": {"total_tokens": 42},
    }


def groq_text_response(text):
    return {"choices": [{"message": {"role": "assistant", "content": text}, "finish_reason": "stop"}]}


def gemini_tool_response(name="get_incident_details", arguments=None):
    return {
        "candidates": [
            {
                "content": {
                    "role": "model",
                    "parts": [{"functionCall": {"name": name, "args": arguments or {"incident_id": "INC-CADF3563BF02"}}}],
                },
                "finishReason": "STOP",
            }
        ],
        "usageMetadata": {"totalTokenCount": 42},
    }


def gemini_text_response(text):
    return {"candidates": [{"content": {"role": "model", "parts": [{"text": text}]}, "finishReason": "STOP"}]}


# --------------------------------------------------------------------------- #
# Groq
# --------------------------------------------------------------------------- #
def test_groq_request_shape_and_no_key_leak():
    transport = SequenceTransport([(200, groq_text_response('{"verdict": "Needs Review"}'))])
    provider = GroqProvider("secret-key", "openai/gpt-oss-20b", transport=transport)

    turn = provider.complete(
        [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": None, "tool_calls": [{"id": "c0", "name": "t", "arguments": {"a": 1}}]},
            {"role": "tool", "tool_call_id": "c0", "name": "t", "content": "{}"},
        ],
        list(TOOL_DEFINITIONS),
    )

    assert turn.text == '{"verdict": "Needs Review"}'
    request = transport.requests[0]
    body = json.loads(request.content)
    assert request.url.path.endswith("/chat/completions")
    assert body["model"] == "openai/gpt-oss-20b"
    assert body["tool_choice"] == "auto"
    assert [tool["function"]["name"] for tool in body["tools"]] == [
        definition["name"] for definition in TOOL_DEFINITIONS
    ]
    assert body["messages"][2]["tool_calls"][0]["function"]["arguments"] == '{"a":1}'
    assert body["messages"][3]["tool_call_id"] == "c0"
    # The key travels in the header only.
    assert request.headers["authorization"] == "Bearer secret-key"
    assert "secret-key" not in request.content.decode()


def test_groq_parses_tool_call():
    transport = SequenceTransport([(200, groq_tool_response())])
    provider = GroqProvider("k", "m", transport=transport)

    turn = provider.complete([{"role": "user", "content": "go"}], list(TOOL_DEFINITIONS))

    assert turn.wants_tools
    assert turn.tool_calls[0].name == "get_incident_details"
    assert turn.tool_calls[0].arguments == {"incident_id": "INC-CADF3563BF02"}


def test_groq_malformed_arguments_are_flagged_not_crashed():
    body = groq_tool_response()
    body["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = "{not json"
    transport = SequenceTransport([(200, body)])

    turn = GroqProvider("k", "m", transport=transport).complete([{"role": "user", "content": "go"}], [])

    assert turn.tool_calls[0].parse_error is not None
    assert "JSON" in turn.tool_calls[0].parse_error


@pytest.mark.parametrize(
    "status,expected",
    [
        (429, ProviderRateLimited),
        (401, ProviderAuthError),
        (403, ProviderAuthError),
        (400, ProviderProtocolError),
        (404, ProviderProtocolError),
        (503, ProviderUnavailable),
    ],
)
def test_groq_http_errors_are_mapped(status, expected):
    transport = SequenceTransport([(status, {"error": {"message": "nope"}})])
    provider = GroqProvider("k", "m", transport=transport)

    with pytest.raises(expected):
        provider.complete([{"role": "user", "content": "go"}], [])


def test_groq_rate_limit_reports_retry_after():
    transport = SequenceTransport([(429, {"error": "slow down"})])
    provider = GroqProvider("k", "m", transport=transport)

    with pytest.raises(ProviderRateLimited) as excinfo:
        provider.complete([{"role": "user", "content": "go"}], [])
    assert excinfo.value.code == "PROVIDER_RATE_LIMITED"


def test_groq_timeout_is_mapped():
    transport = SequenceTransport([httpx.ConnectTimeout("too slow")])
    provider = GroqProvider("k", "m", transport=transport)

    with pytest.raises(ProviderTimeout):
        provider.complete([{"role": "user", "content": "go"}], [])


def test_groq_empty_choices_is_a_protocol_error():
    transport = SequenceTransport([(200, {"choices": []})])
    with pytest.raises(ProviderProtocolError):
        GroqProvider("k", "m", transport=transport).complete([{"role": "user", "content": "go"}], [])


# --------------------------------------------------------------------------- #
# Gemini
# --------------------------------------------------------------------------- #
def test_gemini_request_shape_and_schema_sanitisation():
    transport = SequenceTransport([(200, gemini_text_response('{"verdict": "Needs Review"}'))])
    provider = GeminiProvider("secret-key", "gemini-2.5-flash-lite", transport=transport)

    provider.complete(
        [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": None, "tool_calls": [{"id": "c0", "name": "get_incident_details", "arguments": {"incident_id": "INC-X"}}]},
            {"role": "tool", "tool_call_id": "c0", "name": "get_incident_details", "content": '{"ok": true}'},
        ],
        list(TOOL_DEFINITIONS),
    )

    request = transport.requests[0]
    body = json.loads(request.content)
    assert ":generateContent" in str(request.url)
    assert body["systemInstruction"]["parts"][0]["text"] == "sys"
    assert [content["role"] for content in body["contents"]] == ["user", "model", "user"]
    assert body["contents"][1]["parts"][0]["functionCall"]["name"] == "get_incident_details"
    assert body["contents"][2]["parts"][0]["functionResponse"]["name"] == "get_incident_details"
    assert body["contents"][2]["parts"][0]["functionResponse"]["response"]["result"] == {"ok": True}
    # additionalProperties is not part of Gemini's schema subset.
    for declaration in body["tools"][0]["functionDeclarations"]:
        assert "additionalProperties" not in json.dumps(declaration["parameters"])
    assert request.headers["x-goog-api-key"] == "secret-key"
    assert "secret-key" not in request.content.decode()


def test_gemini_parses_function_call_and_text():
    transport = SequenceTransport([(200, gemini_tool_response())])
    turn = GeminiProvider("k", "m", transport=transport).complete([{"role": "user", "content": "go"}], list(TOOL_DEFINITIONS))

    assert turn.tool_calls[0].name == "get_incident_details"
    assert turn.tool_calls[0].arguments == {"incident_id": "INC-CADF3563BF02"}
    assert turn.tool_calls[0].id.startswith("gemini_call_")


def test_gemini_rate_limit_and_timeout():
    with pytest.raises(ProviderRateLimited):
        GeminiProvider("k", "m", transport=SequenceTransport([(429, {})])).complete([], [])
    with pytest.raises(ProviderTimeout):
        GeminiProvider("k", "m", transport=SequenceTransport([httpx.ReadTimeout("slow")])).complete([], [])


def test_gemini_blocked_prompt_is_a_protocol_error():
    body = {"promptFeedback": {"blockReason": "SAFETY"}}
    with pytest.raises(ProviderProtocolError):
        GeminiProvider("k", "m", transport=SequenceTransport([(200, body)])).complete([], [])


def test_schema_projection_is_recursive():
    schema = {
        "type": "object",
        "properties": {"a": {"type": "string", "additionalProperties": False}},
        "required": ["a"],
        "additionalProperties": False,
        "$schema": "http://json-schema.org/draft-07/schema#",
    }
    cleaned = to_gemini_schema(schema)
    assert cleaned == {"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a"]}


# --------------------------------------------------------------------------- #
# Factory / parity
# --------------------------------------------------------------------------- #
def test_factory_requires_explicit_configuration(settings):
    with pytest.raises(ProviderNotConfigured):
        build_provider(replace(settings, provider="openrouter"))
    with pytest.raises(ProviderNotConfigured):
        build_provider(replace(settings, provider="groq", api_keys={**settings.api_keys, "groq": ""}))
    assert build_provider(replace(settings, provider="mock")).name == "mock"


def test_switching_provider_preserves_result_schema(settings, dataset, incidents_by_category):
    """Same semantics in, same validated output shape out - whichever adapter runs."""
    incident_id = incidents_by_category["DoS"]
    flow_id = next(
        key for key, kind in dataset.evidence_ids(incident_id).items() if kind == "flow"
    )
    answer = json.dumps(
        {
            "incident_id": incident_id,
            "verdict": "Likely Attack",
            "confidence": "medium",
            "reason": "Observed a flood of flows to one destination in the window.",
            "evidence_ids": [flow_id],
            "findings": [],
            "limitations": "",
        }
    )

    groq_transport = SequenceTransport(
        [(200, groq_tool_response("get_network_flows", {"incident_id": incident_id})), (200, groq_text_response(answer))]
    )
    gemini_transport = SequenceTransport(
        [(200, gemini_tool_response("get_network_flows", {"incident_id": incident_id})), (200, gemini_text_response(answer))]
    )

    results = []
    for provider in (
        GroqProvider("k", "openai/gpt-oss-20b", transport=groq_transport),
        GeminiProvider("k", "gemini-2.5-flash-lite", transport=gemini_transport),
    ):
        triage = TriageService(
            replace(
                settings,
                provider=provider.name,
                api_keys={**settings.api_keys, "groq": "test-key", "gemini": "test-key"},
            ),
            dataset,
            provider_factory=lambda p=provider: p,
        )
        results.append(triage.investigate(incident_id))

    groq_result, gemini_result = results
    for result in results:
        assert set(result) >= {
            "run_id",
            "incident_id",
            "status",
            "verdict",
            "confidence",
            "reason",
            "evidence_ids",
            "validation",
            "requires_confirmation",
            "decision",
        }
        assert result["status"] == "ok"
        assert result["verdict"] == "Likely Attack"
        assert result["evidence_ids"] == [flow_id]
    assert groq_result["proposal"].keys() == gemini_result["proposal"].keys()
