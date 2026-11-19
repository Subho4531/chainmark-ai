import pytest
import json
import zipfile
import io
import httpx
from fastapi.testclient import TestClient
from unittest.mock import patch

from chainmark.interceptor.proxy import app, session_chains, get_or_create_chain
from chainmark.detector.checksums import generate_verhoeff_checksum


@pytest.fixture
def client():
    return TestClient(app)


def test_health_check(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "PUBLIC KEY" in data["signing_pubkey"]


@pytest.mark.asyncio
async def test_openai_chat_completions_interception():
    base = "45678901234"
    check = generate_verhoeff_checksum(base)
    valid_aadhaar = f"{base}{check}"

    session_id = "test_openai_proxy_session"
    incoming_prompt = f"Please check records for Aadhaar {valid_aadhaar}."

    captured_payload = {}

    async def mock_forward(url, json_body, headers):
        nonlocal captured_payload
        captured_payload = json_body
        received_text = json_body["messages"][0]["content"]
        mock_response_data = {
            "id": "chatcmpl-test",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": f"Confirmed. Verified entity {received_text}.",
                    }
                }
            ],
        }
        return httpx.Response(200, json=mock_response_data)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        with patch("chainmark.interceptor.proxy.forward_upstream_request", side_effect=mock_forward):
            response = await ac.post(
                "/v1/chat/completions",
                json={
                    "model": "gpt-4o",
                    "messages": [{"role": "user", "content": incoming_prompt}],
                },
                headers={"X-Chainmark-Session-Id": session_id},
            )

    assert response.status_code == 200
    res_data = response.json()

    # 1. Assert upstream NEVER saw the raw Aadhaar
    upstream_content = captured_payload["messages"][0]["content"]
    assert valid_aadhaar not in upstream_content
    assert "[CM_TOKEN_AADHAAR_" in upstream_content

    # 2. Assert client response was automatically detokenized
    client_content = res_data["choices"][0]["message"]["content"]
    assert valid_aadhaar in client_content
    assert "[CM_TOKEN_AADHAAR_" not in client_content

    # 3. Assert evidence was recorded
    assert session_id in session_chains
    assert len(session_chains[session_id].events) >= 2


@pytest.mark.asyncio
async def test_gemini_generate_content_interception():
    session_id = "test_gemini_proxy_session"
    raw_pan = "ABCPE1234F"
    incoming_prompt = f"Financial audit report for PAN {raw_pan}"

    captured_payload = {}

    async def mock_forward(url, json_body, headers):
        nonlocal captured_payload
        captured_payload = json_body
        received_text = json_body["contents"][0]["parts"][0]["text"]
        mock_response_data = {
            "candidates": [
                {
                    "content": {
                        "parts": [{"text": f"Audit processed successfully for {received_text}"}]
                    }
                }
            ]
        }
        return httpx.Response(200, json=mock_response_data)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        with patch("chainmark.interceptor.proxy.forward_upstream_request", side_effect=mock_forward):
            response = await ac.post(
                "/v1beta/models/gemini-1.5-flash:generateContent",
                json={
                    "contents": [
                        {"role": "user", "parts": [{"text": incoming_prompt}]}
                    ]
                },
                headers={"X-Chainmark-Session-Id": session_id},
            )

    assert response.status_code == 200
    res_data = response.json()

    # Upstream must receive token only
    upstream_text = captured_payload["contents"][0]["parts"][0]["text"]
    assert raw_pan not in upstream_text
    assert "[CM_TOKEN_PAN_" in upstream_text

    # Client receives detokenized text
    client_text = res_data["candidates"][0]["content"]["parts"][0]["text"]
    assert raw_pan in client_text
    assert "[CM_TOKEN_PAN_" not in client_text


@pytest.mark.asyncio
async def test_evidence_export_endpoint():
    session_id = "test_export_session_new"

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        # Check export endpoint for nonexistent session
        resp = await ac.get("/v1/evidence/export/nonexistent_session_id")
        assert resp.status_code == 404

        # Seed an event
        c = get_or_create_chain(session_id)
        c.append_event("TEST", "raw_input", "clean_output", ["PAN"], ["token_pan"])

        export_resp = await ac.get(f"/v1/evidence/export/{session_id}")
        assert export_resp.status_code == 200
        assert export_resp.headers["content-type"] == "application/zip"

        # Verify zip structure
        zf = zipfile.ZipFile(io.BytesIO(export_resp.content))
        assert "manifest.json" in zf.namelist()
        assert "events.jsonl" in zf.namelist()
        assert "signature.sig" in zf.namelist()
