import json
import re
from unittest.mock import patch

import httpx
import pytest

from chainmark.detector.checksums import generate_verhoeff_checksum
from chainmark.detector.taint_engine import DetectedEntity, SessionTaintEngine
from chainmark.interceptor.proxy import app
from chainmark.vault.token_vault import StreamTokenRestorer, TokenVault


def _valid_aadhaar() -> str:
    base = "45678901234"
    return f"{base}{generate_verhoeff_checksum(base)}"


def test_tokens_use_128_bit_entropy():
    vault = TokenVault()
    token = vault.tokenize_value("AADHAAR", "234567890123", "session_bits")
    assert re.fullmatch(r"\[CM_TOKEN_AADHAAR_[a-f0-9]{32}\]", token)


def test_cross_turn_fragments_are_all_redacted():
    aadhaar = _valid_aadhaar()
    parts = [aadhaar[0:4], aadhaar[4:8], aadhaar[8:12]]
    messages = [
        {"role": "user", "content": f"first part {parts[0]}"},
        {"role": "assistant", "content": "noted"},
        {"role": "user", "content": f"next {parts[1]}"},
        {"role": "user", "content": f"last {parts[2]}"},
    ]

    engine = SessionTaintEngine()
    vault = TokenVault()
    session_id = "regression_jigsaw_redaction"
    detections = engine.process_messages(session_id, messages)

    assembled = [d for d in detections if d.entity_type == "AADHAAR"][0]
    assert assembled.is_fragment_assembly is True
    assert [fragment for _, fragment in assembled.fragments] == parts

    result = vault.redact_texts(
        [message["content"] for message in messages], detections, session_id
    )

    for text in result.texts:
        for part in parts:
            assert part not in text, "fragment leaked into the egress payload"
    assert aadhaar not in " ".join(result.texts)
    assert len(result.tokens_mapped) == 3
    assert result.unresolved == []


def test_cross_turn_redaction_round_trips_exactly():
    aadhaar = _valid_aadhaar()
    parts = [aadhaar[0:4], aadhaar[4:8], aadhaar[8:12]]
    originals = [
        f"first part {parts[0]}",
        f"middle {parts[1]}",
        f"last {parts[2]}",
    ]
    messages = [{"role": "user", "content": text} for text in originals]

    engine = SessionTaintEngine()
    vault = TokenVault()
    session_id = "regression_jigsaw_roundtrip"
    detections = engine.process_messages(session_id, messages)
    result = vault.redact_texts(originals, detections, session_id)

    restored = [vault.detokenize_text(text, session_id) for text in result.texts]
    assert restored == originals


def test_tokens_mapped_only_reports_inserted_tokens():
    vault = TokenVault()
    session_id = "regression_honest_tokens"
    entities = [
        DetectedEntity(entity_type="PAN", raw_value="ABCPE1234F", confidence=1.0)
    ]

    result = vault.redact_texts(
        ["nothing sensitive here", "PAN ABCPE1234F approved"], entities, session_id
    )

    assert "ABCPE1234F" not in " ".join(result.texts)
    assert len(result.tokens_mapped) == 1


def test_verification_reports_unredacted_entity():
    vault = TokenVault()
    session_id = "regression_unresolved"
    entities = [
        DetectedEntity(entity_type="PAN", raw_value="ABCPE1234F", confidence=1.0)
    ]

    with patch("chainmark.vault.token_vault.TokenVault._apply_spans") as fake:
        fake.side_effect = lambda text, spans: (text, [])
        result = vault.redact_texts(["PAN ABCPE1234F approved"], entities, session_id)

    assert len(result.unresolved) == 1
    assert result.tokens_mapped == []


def test_stream_restorer_does_not_hold_ordinary_brackets():
    vault = TokenVault()
    restorer = StreamTokenRestorer(vault, "regression_stream_brackets")

    assert restorer.push("[") == ""
    assert restorer.push("1, 2, 3]") == "[1, 2, 3]"


def test_stream_restorer_reassembles_split_token():
    vault = TokenVault()
    session_id = "regression_stream_token"
    token = vault.tokenize_value("PAN", "ABCPE1234F", session_id)
    restorer = StreamTokenRestorer(vault, session_id)
    split = len(token) // 2

    assert restorer.push("value is " + token[:split]) == "value is "
    assert restorer.push(token[split:] + " done") == "ABCPE1234F done"


@pytest.mark.asyncio
async def test_chat_route_redacts_tool_call_arguments():
    pan = "ABCPE1234F"
    session_id = "regression_tool_calls"
    captured = {}

    async def mock_forward(url, json_body, headers):
        captured.update(json_body)
        arguments = json_body["messages"][0]["tool_calls"][0]["function"]["arguments"]
        assert pan not in arguments
        assert "[CM_TOKEN_PAN_" in arguments
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": "lookup complete",
                            "tool_calls": [
                                {
                                    "id": "call_1",
                                    "type": "function",
                                    "function": {"name": "lookup", "arguments": arguments},
                                }
                            ],
                        }
                    }
                ]
            },
        )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        with patch("chainmark.interceptor.proxy.forward_upstream_request", side_effect=mock_forward):
            response = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "gpt-4o",
                    "messages": [
                        {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call_1",
                                    "type": "function",
                                    "function": {
                                        "name": "lookup",
                                        "arguments": json.dumps({"pan": pan}),
                                    },
                                }
                            ],
                        }
                    ],
                },
                headers={"X-Chainmark-Session-Id": session_id},
            )

    assert response.status_code == 200
    assert captured["messages"][0]["tool_calls"][0]["function"]["arguments"] != ""
    restored = response.json()["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
    assert pan in restored


@pytest.mark.asyncio
async def test_chat_route_redacts_cross_turn_fragments():
    aadhaar = _valid_aadhaar()
    parts = [aadhaar[0:4], aadhaar[4:8], aadhaar[8:12]]
    session_id = "regression_route_jigsaw"
    captured = {}

    async def mock_forward(url, json_body, headers):
        captured.update(json_body)
        return httpx.Response(
            200,
            json={"choices": [{"message": {"role": "assistant", "content": "ok"}}]},
        )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        with patch("chainmark.interceptor.proxy.forward_upstream_request", side_effect=mock_forward):
            response = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "gpt-4o",
                    "messages": [
                        {"role": "user", "content": f"first {parts[0]}"},
                        {"role": "assistant", "content": "go on"},
                        {"role": "user", "content": f"middle {parts[1]}"},
                        {"role": "user", "content": f"last {parts[2]}"},
                    ],
                },
                headers={"X-Chainmark-Session-Id": session_id},
            )

    assert response.status_code == 200
    egress = " ".join(message["content"] for message in captured["messages"])
    for part in parts:
        assert part not in egress
    assert egress.count("[CM_TOKEN_AADHAAR_") == 3


@pytest.mark.asyncio
async def test_chat_route_blocks_when_redaction_cannot_be_verified():
    aadhaar = _valid_aadhaar()
    session_id = "regression_fail_closed"
    upstream_called = False

    async def mock_forward(url, json_body, headers):
        nonlocal upstream_called
        upstream_called = True
        return httpx.Response(200, json={"choices": []})

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        with patch(
            "chainmark.vault.token_vault.TokenVault._apply_spans",
            side_effect=lambda text, spans: (text, []),
        ), patch("chainmark.interceptor.proxy.forward_upstream_request", side_effect=mock_forward):
            response = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "gpt-4o",
                    "messages": [
                        {"role": "user", "content": f"check Aadhaar {aadhaar} now"}
                    ],
                },
                headers={"X-Chainmark-Session-Id": session_id},
            )

    assert response.status_code == 422
    assert upstream_called is False
    detail = response.json()["detail"]
    assert detail["error"] == "chainmark_policy_violation"
    assert "AADHAAR" in detail["entity_types"]
    # The blocked response must not echo the sensitive value.
    assert aadhaar not in response.text


@pytest.mark.asyncio
async def test_streaming_route_restores_split_tokens():
    from chainmark.interceptor.proxy import _stream_openai_response

    vault_session = "regression_stream_route"
    vault = TokenVault()
    import chainmark.interceptor.proxy as proxy_module

    original_vault = proxy_module.vault
    proxy_module.vault = vault
    try:
        token = vault.tokenize_value("PAN", "ABCPE1234F", vault_session)
        split = len(token) // 2
        chunks = [
            {"choices": [{"index": 0, "delta": {"role": "assistant"}}]},
            {"choices": [{"index": 0, "delta": {"content": "PAN " + token[:split]}}]},
            {"choices": [{"index": 0, "delta": {"content": token[split:] + " OK"}, "finish_reason": "stop"}]},
        ]
        upstream_lines = [f"data: {json.dumps(chunk)}" for chunk in chunks] + ["data: [DONE]"]

        class FakeUpstream:
            status_code = 200

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            async def aiter_lines(self):
                for line in upstream_lines:
                    yield line

            async def aread(self):
                return b""

        class FakeClient:
            def stream(self, *args, **kwargs):
                return FakeUpstream()

            async def aclose(self):
                return None

        emitted = []
        async for chunk in _stream_openai_response(
            FakeClient(), "http://upstream", {}, {}, vault_session
        ):
            emitted.append(chunk)

        assert emitted[-1] == "data: [DONE]\n\n"
        content = ""
        for line in emitted:
            if not line.startswith("data: ") or line.strip() == "data: [DONE]":
                continue
            event = json.loads(line[6:].strip())
            for choice in event.get("choices") or []:
                content += (choice.get("delta") or {}).get("content") or ""

        assert content == "PAN ABCPE1234F OK"
        assert token not in content
    finally:
        proxy_module.vault = original_vault


@pytest.mark.asyncio
async def test_uncloak_reports_unresolvable_token():
    transport = httpx.ASGITransport(app=app)
    unknown = "[CM_TOKEN_AADHAAR_" + "0" * 32 + "]"
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/uncloak/regression_unknown_token",
            json={"cloaked_text": f"value {unknown} end"},
        )

    assert response.status_code == 409
    assert response.json()["detail"]["unresolved_count"] == 1
