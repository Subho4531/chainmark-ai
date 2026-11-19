"""
FastAPI Transparent Reverse Proxy Gateway.
Intercepts agent LLM calls, detects multi-turn session-level jigsaw leaks,
tokenizes sensitive entities via AES-256-GCM vault, forwards sanitized prompts,
detokenizes responses on the fly, and seals the transaction in an immutable Merkle DAG.
"""

from typing import Dict, Any, Optional
import os
import json
import hashlib
import time
import httpx
from fastapi import FastAPI, Request, Response, HTTPException, status
from fastapi.responses import StreamingResponse
import uvicorn

from chainmark.core.config import settings
from chainmark.detector.taint_engine import SessionTaintEngine
from chainmark.vault.token_vault import TokenVault
from chainmark.evidence.merkle_chain import MerkleHashChain
from chainmark.evidence.signer import EvidenceSigner


app = FastAPI(
    title="Chainmark AI Gateway",
    description="Cryptographic guard and evidence layer for autonomous AI agents",
    version="0.1.0",
)

# Global runtime services (scoped in memory for Phase 1)
taint_engine = SessionTaintEngine(max_history_turns=settings.SESSION_SLIDING_WINDOW_TURNS)
vault = TokenVault(master_key_hex=settings.VAULT_MASTER_KEY)
signer = EvidenceSigner()
session_chains: Dict[str, MerkleHashChain] = {}


def get_or_create_chain(session_id: str) -> MerkleHashChain:
    if session_id not in session_chains or session_chains[session_id] is None:
        session_chains[session_id] = MerkleHashChain(session_id=session_id)
    return session_chains[session_id]


async def forward_upstream_request(url: str, json_body: Dict[str, Any], headers: Dict[str, str]) -> httpx.Response:
    """
    Helper to forward HTTP POST requests to upstream LLMs.
    """
    async with httpx.AsyncClient(timeout=60.0) as client:
        return await client.post(url, json=json_body, headers=headers)


def resolve_session_id(request: Request, body: Dict[str, Any]) -> str:
    # 1. Header override
    header_sid = request.headers.get("X-Chainmark-Session-Id")
    if header_sid:
        return header_sid.strip()

    # 2. Body user/session field
    if "user" in body and isinstance(body["user"], str) and body["user"]:
        return f"user_{body['user']}"

    # 3. Deterministic hash of system/initial prompt
    messages = body.get("messages", [])
    if messages and isinstance(messages, list) and len(messages) > 0:
        first_content = str(messages[0].get("content", ""))
        digest = hashlib.sha256(first_content.encode("utf-8")).hexdigest()[:12]
        return f"auto_session_{digest}"

    return "default_session"


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "Chainmark AI Gateway",
        "active_policies": settings.ACTIVE_POLICIES,
        "enabled_detectors": settings.ENABLED_DETECTORS,
        "vault_active": True,
        "signing_pubkey": signer.get_public_key_pem(),
    }


@app.post("/v1/chat/completions")
async def handle_openai_chat_completions(request: Request):
    """
    OpenAI-compatible chat completions proxy endpoint.
    Wraps prompt and tool histories, redacts sensitive jigsaw fragments,
    and returns detokenized responses.
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    session_id = resolve_session_id(request, body)
    messages = body.get("messages", [])
    stream_requested = body.get("stream", False)

    chain = get_or_create_chain(session_id)

    # 1. L2 Session Taint & Jigsaw Assembly Scan
    detected_entities = taint_engine.process_messages(session_id, messages)

    # 2. L4 Redaction & Vault Storage
    raw_payload_str = json.dumps(messages, sort_keys=True)
    all_tokens_mapped = []

    if detected_entities:
        sanitized_messages = []
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, str):
                redacted_content, tokens = vault.redact_text(content, detected_entities, session_id)
                msg_copy = dict(msg)
                msg_copy["content"] = redacted_content
                sanitized_messages.append(msg_copy)
                all_tokens_mapped.extend([t[0] for t in tokens])
            else:
                sanitized_messages.append(msg)
        body["messages"] = sanitized_messages
    else:
        body["messages"] = messages

    sanitized_payload_str = json.dumps(body["messages"], sort_keys=True)
    entity_types = [e.entity_type for e in detected_entities]

    # 3. L5 Evidence Spool: Append event to Merkle chain
    chain.append_event(
        event_type="LLM_PROMPT_EGRESS",
        raw_input=raw_payload_str,
        sanitized_output=sanitized_payload_str,
        entities_detected=entity_types,
        tokens_mapped=all_tokens_mapped,
        policy_action="TOKENIZE_AND_FORWARD" if detected_entities else "ALLOW",
    )

    # 4. Prepare upstream request
    upstream_url = f"{settings.UPSTREAM_OPENAI_BASE_URL.rstrip('/')}/chat/completions"
    headers = dict(request.headers)
    # Remove hop-by-hop headers
    headers.pop("host", None)
    headers.pop("content-length", None)

    # Key management: pass-through or managed
    if settings.AUTH_MODE == "managed" and settings.MANAGED_OPENAI_API_KEY:
        headers["authorization"] = f"Bearer {settings.MANAGED_OPENAI_API_KEY}"

    client = httpx.AsyncClient(timeout=60.0)

    # 5. Handle Streaming vs Non-Streaming
    if stream_requested:
        async def event_stream():
            try:
                async with client.stream("POST", upstream_url, json=body, headers=headers) as upstream_resp:
                    if upstream_resp.status_code != 200:
                        err_bytes = await upstream_resp.aread()
                        yield f"data: {json.dumps({'error': err_bytes.decode('utf-8')})}\n\n"
                        return

                    async for line in upstream_resp.aiter_lines():
                        if not line:
                            yield "\n"
                            continue
                        if line.startswith("data: "):
                            data_str = line[6:].strip()
                            if data_str == "[DONE]":
                                yield "data: [DONE]\n\n"
                                break
                            try:
                                chunk_json = json.loads(data_str)
                                delta = chunk_json.get("choices", [{}])[0].get("delta", {})
                                if "content" in delta and delta["content"]:
                                    delta["content"] = vault.detokenize_text(delta["content"], session_id)
                                yield f"data: {json.dumps(chunk_json)}\n\n"
                            except Exception:
                                # Detokenize raw string if parsing fails
                                detok_line = vault.detokenize_text(data_str, session_id)
                                yield f"data: {detok_line}\n\n"
                        else:
                            yield f"{line}\n"
            finally:
                await client.aclose()

        return StreamingResponse(event_stream(), media_type="text/event-stream")

    # Non-streaming response
    try:
        upstream_resp = await forward_upstream_request(upstream_url, body, headers)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to communicate with upstream LLM: {str(e)}")

    if upstream_resp.status_code != 200:
        return Response(
            content=upstream_resp.content,
            status_code=upstream_resp.status_code,
            media_type="application/json",
        )

    resp_json = upstream_resp.json()

    # 6. Detokenize upstream LLM response
    for choice in resp_json.get("choices", []):
        msg = choice.get("message", {})
        if "content" in msg and isinstance(msg["content"], str):
            msg["content"] = vault.detokenize_text(msg["content"], session_id)

    # Record completion in evidence chain
    chain.append_event(
        event_type="LLM_COMPLETION_INGRESS",
        raw_input=upstream_resp.text,
        sanitized_output=json.dumps(resp_json, sort_keys=True),
        entities_detected=[],
        tokens_mapped=[],
        policy_action="DETOKENIZE_FOR_CLIENT",
    )

    return resp_json


@app.post("/v1beta/models/{model_path:path}:generateContent")
async def handle_gemini_generate_content(model_path: str, request: Request):
    """
    Google Gemini-compatible generateContent proxy endpoint.
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    session_id = resolve_session_id(request, body)
    chain = get_or_create_chain(session_id)

    contents = body.get("contents", [])
    raw_payload_str = json.dumps(contents, sort_keys=True)

    # Flatten Gemini contents for entity detection
    text_parts = []
    for c in contents:
        for p in c.get("parts", []):
            if "text" in p and isinstance(p["text"], str):
                text_parts.append({"role": c.get("role", "user"), "content": p["text"]})

    detected_entities = taint_engine.process_messages(session_id, text_parts)
    all_tokens_mapped = []

    if detected_entities:
        for c in contents:
            for p in c.get("parts", []):
                if "text" in p and isinstance(p["text"], str):
                    redacted, tokens = vault.redact_text(p["text"], detected_entities, session_id)
                    p["text"] = redacted
                    all_tokens_mapped.extend([t[0] for t in tokens])
        body["contents"] = contents

    sanitized_payload_str = json.dumps(body["contents"], sort_keys=True)
    entity_types = [e.entity_type for e in detected_entities]

    chain.append_event(
        event_type="GEMINI_PROMPT_EGRESS",
        raw_input=raw_payload_str,
        sanitized_output=sanitized_payload_str,
        entities_detected=entity_types,
        tokens_mapped=all_tokens_mapped,
        policy_action="TOKENIZE_AND_FORWARD" if detected_entities else "ALLOW",
    )

    upstream_url = f"{settings.UPSTREAM_GEMINI_BASE_URL.rstrip('/')}/v1beta/models/{model_path}:generateContent"
    headers = dict(request.headers)
    headers.pop("host", None)
    headers.pop("content-length", None)

    if settings.AUTH_MODE == "managed" and settings.MANAGED_GEMINI_API_KEY:
        headers["x-goog-api-key"] = settings.MANAGED_GEMINI_API_KEY

    try:
        upstream_resp = await forward_upstream_request(upstream_url, body, headers)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to communicate with upstream Gemini: {str(e)}")

    if upstream_resp.status_code != 200:
        return Response(
            content=upstream_resp.content,
            status_code=upstream_resp.status_code,
            media_type="application/json",
        )

    resp_json = upstream_resp.json()

    # Detokenize candidates
    for cand in resp_json.get("candidates", []):
        for part in cand.get("content", {}).get("parts", []):
            if "text" in part and isinstance(part["text"], str):
                part["text"] = vault.detokenize_text(part["text"], session_id)

    chain.append_event(
        event_type="GEMINI_COMPLETION_INGRESS",
        raw_input=upstream_resp.text,
        sanitized_output=json.dumps(resp_json, sort_keys=True),
        entities_detected=[],
        tokens_mapped=[],
        policy_action="DETOKENIZE_FOR_CLIENT",
    )

    return resp_json


@app.get("/v1/evidence/export/{session_id}")
async def export_evidence_pack(session_id: str):
    """
    Downloads the sealed, dual-signed Evidence Pack ZIP for a given session.
    """
    chain = session_chains.get(session_id)
    if not chain or not chain.events:
        raise HTTPException(status_code=404, detail="Session not found or has no recorded events")

    zip_bytes = signer.build_evidence_pack(chain)
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename=evidence_pack_{session_id}.zip"},
    )


@app.get("/v1/evidence/verify/{session_id}")
async def verify_session_evidence(session_id: str):
    """
    Verifies in-memory hash chain integrity for the specified session.
    """
    chain = session_chains.get(session_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Session not found")

    is_valid, err = chain.verify_chain()
    root_hash = chain.get_merkle_root()
    sig = signer.sign_root(root_hash)

    return {
        "session_id": session_id,
        "valid": is_valid,
        "error": err,
        "total_events": len(chain.events),
        "merkle_root": root_hash,
        "signature": sig,
        "public_key": signer.get_public_key_pem(),
    }


def run_server():
    uvicorn.run(app, host=settings.HOST, port=settings.PORT)


if __name__ == "__main__":
    run_server()
