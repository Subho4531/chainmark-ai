"""
FastAPI Transparent Reverse Proxy Gateway.
Intercepts agent LLM calls, detects multi-turn session-level jigsaw leaks,
tokenizes sensitive entities via AES-256-GCM vault, forwards sanitized prompts,
detokenizes responses on the fly, and seals the transaction in an immutable Merkle DAG.

Route contract:
  * Redaction is span-anchored and applied to every egress text unit, including
    tool-call arguments, not just message content.
  * Token accounting only reports tokens that were actually inserted.
  * If a detected value cannot be proven absent from the egress payload the
    request is blocked (fail closed), never forwarded.
"""

from typing import Dict, Any, Optional, List, Sequence, Callable, Tuple
import json
import hashlib
import secrets
from dataclasses import dataclass
import httpx
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import uvicorn

from chainmark.core.config import settings
from chainmark.detector.taint_engine import SessionTaintEngine, DetectedEntity
from chainmark.vault.token_vault import TokenVault, RedactionResult, StreamTokenRestorer
from chainmark.evidence.merkle_chain import MerkleHashChain
from chainmark.evidence.signer import EvidenceSigner


app = FastAPI(
    title="Chainmark AI Gateway",
    description="Cryptographic guard and evidence layer for autonomous AI agents",
    version="0.1.0",
)

# Enable CORS for local React dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global runtime services (scoped in memory for Phase 1)
taint_engine = SessionTaintEngine(max_history_turns=settings.SESSION_SLIDING_WINDOW_TURNS)
vault = TokenVault(master_key_hex=settings.VAULT_MASTER_KEY)
signer = EvidenceSigner()
session_chains: Dict[str, MerkleHashChain] = {}

POLICY_BLOCK_STATUS = 422


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

    # 4. Gemini-native payloads carry "contents", not "messages". Without this
    #    every Gemini tenant would share one taint session and one vault scope.
    contents = body.get("contents", [])
    if contents and isinstance(contents, list) and len(contents) > 0:
        first = contents[0] if isinstance(contents[0], dict) else {}
        parts = first.get("parts") or []
        first_text = ""
        for part in parts:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                first_text = part["text"]
                break
        digest = hashlib.sha256(first_text.encode("utf-8")).hexdigest()[:12]
        return f"auto_session_{digest}"

    return "default_session"


# ----------------------------------------------------------------------
# Egress text units
# ----------------------------------------------------------------------


@dataclass
class TextUnit:
    """A single string that leaves the gateway, plus how to write it back."""

    text: str
    setter: Callable[[str], None]


def _openai_text_units(messages: Sequence[Any]) -> List[TextUnit]:
    """
    Collects every string an upstream model can read from an OpenAI payload:
    message content, multimodal text parts, and tool-call arguments.
    """
    units: List[TextUnit] = []
    for message in messages:
        if not isinstance(message, dict):
            continue

        content = message.get("content")
        if isinstance(content, str):
            units.append(TextUnit(content, lambda value, m=message: m.__setitem__("content", value)))
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    units.append(TextUnit(part["text"], lambda value, p=part: p.__setitem__("text", value)))

        for tool_call in message.get("tool_calls") or []:
            if not isinstance(tool_call, dict):
                continue
            function = tool_call.get("function")
            if isinstance(function, dict) and isinstance(function.get("arguments"), str):
                units.append(
                    TextUnit(
                        function["arguments"],
                        lambda value, f=function: f.__setitem__("arguments", value),
                    )
                )
    return units


def _gemini_text_units(contents: Sequence[Any]) -> List[TextUnit]:
    units: List[TextUnit] = []
    for content in contents:
        if not isinstance(content, dict):
            continue
        for part in content.get("parts") or []:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                units.append(TextUnit(part["text"], lambda value, p=part: p.__setitem__("text", value)))
    return units


def _units_as_messages(units: Sequence[TextUnit]) -> List[Dict[str, Any]]:
    return [{"role": "user", "content": unit.text} for unit in units]


def _block_unredactable(
    chain: MerkleHashChain,
    event_type: str,
    raw_payload_str: str,
    result: RedactionResult,
) -> None:
    entity_types = sorted({entity.entity_type for entity in result.unresolved})
    chain.append_event(
        event_type=event_type,
        raw_input=raw_payload_str,
        sanitized_output="",
        entities_detected=entity_types,
        tokens_mapped=[],
        policy_action="BLOCKED_UNREDACTABLE",
    )
    raise HTTPException(
        status_code=POLICY_BLOCK_STATUS,
        detail={
            "error": "chainmark_policy_violation",
            "reason": "sensitive_value_could_not_be_neutralized",
            "entity_types": entity_types,
        },
    )


def scan_and_redact(
    units: List[TextUnit],
    session_id: str,
    chain: MerkleHashChain,
    event_type: str,
    raw_payload_str: str,
    turn_indices: Optional[Sequence[int]] = None,
) -> Tuple[RedactionResult, List[DetectedEntity]]:
    """
    Detects entities across all egress units, redacts them in place, and blocks
    the request if any detected value survives the redaction pass.
    """
    texts = [unit.text for unit in units]
    detections = taint_engine.process_messages(session_id, _units_as_messages(units))
    result = vault.redact_texts(texts, detections, session_id, turn_indices=turn_indices)

    if result.unresolved and settings.FAIL_CLOSED:
        _block_unredactable(chain, event_type, raw_payload_str, result)

    for unit, sanitized in zip(units, result.texts):
        if unit.text != sanitized:
            unit.setter(sanitized)

    return result, detections


# ----------------------------------------------------------------------
# Ingress detokenization
# ----------------------------------------------------------------------


def _detokenize_openai_response(payload: Dict[str, Any], session_id: str) -> int:
    unresolved = 0
    for choice in payload.get("choices") or []:
        if not isinstance(choice, dict):
            continue
        message = choice.get("message")
        if not isinstance(message, dict):
            continue

        content = message.get("content")
        if isinstance(content, str):
            message["content"], count = vault.detokenize_text_strict(content, session_id)
            unresolved += count
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    part["text"], count = vault.detokenize_text_strict(part["text"], session_id)
                    unresolved += count

        for tool_call in message.get("tool_calls") or []:
            function = (tool_call or {}).get("function") if isinstance(tool_call, dict) else None
            if isinstance(function, dict) and isinstance(function.get("arguments"), str):
                function["arguments"], count = vault.detokenize_text_strict(
                    function["arguments"], session_id
                )
                unresolved += count
    return unresolved


def _detokenize_gemini_response(payload: Dict[str, Any], session_id: str) -> int:
    unresolved = 0
    for candidate in payload.get("candidates") or []:
        if not isinstance(candidate, dict):
            continue
        parts = (candidate.get("content") or {}).get("parts") or []
        for part in parts:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                part["text"], count = vault.detokenize_text_strict(part["text"], session_id)
                unresolved += count
    return unresolved


def _raise_unresolved_ingress(chain: MerkleHashChain, event_type: str) -> None:
    chain.append_event(
        event_type=event_type,
        raw_input="",
        sanitized_output="",
        entities_detected=[],
        tokens_mapped=[],
        policy_action="BLOCKED_UNRESOLVED_TOKEN",
    )
    raise HTTPException(
        status_code=502,
        detail={
            "error": "chainmark_policy_violation",
            "reason": "upstream_response_contained_unresolvable_token",
        },
    )


# ----------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "Chainmark AI Gateway",
        "active_policies": settings.ACTIVE_POLICIES,
        "enabled_detectors": settings.ENABLED_DETECTORS,
        "vault_active": True,
        "fail_closed": settings.FAIL_CLOSED,
        "signing_pubkey": signer.get_public_key_pem(),
    }


@app.post("/v1/chat/completions")
async def handle_openai_chat_completions(request: Request):
    """
    OpenAI-compatible chat completions proxy endpoint.
    Wraps prompts and tool histories, redacts sensitive jigsaw fragments,
    and returns detokenized responses.
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    session_id = resolve_session_id(request, body)
    messages = body.get("messages", [])
    if not isinstance(messages, list):
        raise HTTPException(status_code=400, detail="messages must be a list")
    stream_requested = bool(body.get("stream", False))

    chain = get_or_create_chain(session_id)
    raw_payload_str = json.dumps(messages, sort_keys=True)

    # 1. L2 Session Taint & Jigsaw Assembly Scan over every egress text unit.
    units = _openai_text_units(messages)
    result, detections = scan_and_redact(
        units=units,
        session_id=session_id,
        chain=chain,
        event_type="LLM_PROMPT_EGRESS",
        raw_payload_str=raw_payload_str,
    )
    body["messages"] = messages

    # 2. L5 Evidence Spool: only tokens that were actually inserted are recorded.
    sanitized_payload_str = json.dumps(messages, sort_keys=True)
    chain.append_event(
        event_type="LLM_PROMPT_EGRESS",
        raw_input=raw_payload_str,
        sanitized_output=sanitized_payload_str,
        entities_detected=sorted({entity.entity_type for entity in detections}),
        tokens_mapped=result.tokens_mapped,
        policy_action="TOKENIZE_AND_FORWARD" if result.tokens_mapped else "ALLOW",
    )

    # 3. Prepare upstream request
    upstream_url = f"{settings.UPSTREAM_OPENAI_BASE_URL.rstrip('/')}/chat/completions"
    headers = dict(request.headers)
    for header in ("host", "content-length", "x-chainmark-session-id"):
        headers.pop(header, None)

    # Key management: pass-through or managed
    if settings.AUTH_MODE == "managed" and settings.MANAGED_OPENAI_API_KEY:
        headers["authorization"] = f"Bearer {settings.MANAGED_OPENAI_API_KEY}"

    # 4. Handle Streaming vs Non-Streaming
    if stream_requested:
        client = httpx.AsyncClient(timeout=60.0)
        return StreamingResponse(
            _stream_openai_response(client, upstream_url, body, headers, session_id),
            media_type="text/event-stream",
        )

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

    # 5. Detokenize upstream LLM response (content, parts, tool arguments)
    unresolved = _detokenize_openai_response(resp_json, session_id)
    if unresolved and settings.FAIL_CLOSED:
        _raise_unresolved_ingress(chain, "LLM_COMPLETION_INGRESS")

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


async def _stream_openai_response(
    client: httpx.AsyncClient,
    upstream_url: str,
    body: Dict[str, Any],
    headers: Dict[str, str],
    session_id: str,
):
    """
    Streams SSE while holding back only text that could still turn out to be a
    token split across deltas. Content is reattached to the newest pending
    event, so the client sees one ordered content stream.
    """
    restorer = StreamTokenRestorer(vault, session_id)
    tool_restorers: Dict[int, StreamTokenRestorer] = {}
    pending: List[Dict[str, Any]] = []

    def drain(safe_text: str) -> List[str]:
        events: List[Dict[str, Any]] = []
        target: Optional[Dict[str, Any]] = None
        while pending:
            event = pending.pop(0)
            for choice in event.get("choices") or []:
                delta = choice.get("delta")
                if isinstance(delta, dict):
                    delta.pop("content", None)
                    target = delta
            events.append(event)

        if safe_text and target is not None:
            target["content"] = safe_text
        elif safe_text:
            events.append(
                {
                    "choices": [
                        {"index": 0, "delta": {"content": safe_text}, "finish_reason": None}
                    ]
                }
            )

        return [f"data: {json.dumps(event)}\n\n" for event in events]

    try:
        async with client.stream("POST", upstream_url, json=body, headers=headers) as upstream_resp:
            if upstream_resp.status_code != 200:
                error_bytes = await upstream_resp.aread()
                yield f"data: {json.dumps({'error': error_bytes.decode('utf-8', errors='replace')})}\n\n"
                return

            async for line in upstream_resp.aiter_lines():
                if not line:
                    continue
                if not line.startswith("data: "):
                    yield f"{line}\n"
                    continue

                data_str = line[6:].strip()
                if data_str == "[DONE]":
                    break

                try:
                    event = json.loads(data_str)
                except Exception:
                    # Unparseable chunk: restore what we can and pass it through.
                    yield f"data: {json.dumps(vault.detokenize_text(data_str, session_id))}\n\n"
                    continue

                choices = event.get("choices") or []
                delta = choices[0].get("delta") if choices else None
                safe_text = ""
                pending.append(event)

                if isinstance(delta, dict):
                    content = delta.get("content")
                    if isinstance(content, str) and content:
                        delta["content"] = ""
                        safe_text = restorer.push(content)

                    for tool_call in delta.get("tool_calls") or []:
                        if not isinstance(tool_call, dict):
                            continue
                        index = tool_call.get("index", 0)
                        function = tool_call.get("function") or {}
                        arguments = function.get("arguments")
                        if isinstance(arguments, str) and arguments:
                            tool_restorer = tool_restorers.get(index)
                            if tool_restorer is None:
                                tool_restorer = StreamTokenRestorer(vault, session_id)
                                tool_restorers[index] = tool_restorer
                            function["arguments"] = tool_restorer.push(arguments)

                if safe_text:
                    for emitted in drain(safe_text):
                        yield emitted

        tail = restorer.flush()
        for emitted in drain(tail):
            yield emitted

        for tool_restorer in tool_restorers.values():
            # Complete tokens still buffered in tool arguments are restored.
            # A truncated partial token cannot be resolved and is dropped with
            # the malformed tool call it belongs to.
            tool_restorer.flush()

        yield "data: [DONE]\n\n"
    finally:
        await client.aclose()


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
    if not isinstance(contents, list):
        raise HTTPException(status_code=400, detail="contents must be a list")
    raw_payload_str = json.dumps(contents, sort_keys=True)

    # 1. Detection + redaction over all text parts.
    units = _gemini_text_units(contents)
    result, detections = scan_and_redact(
        units=units,
        session_id=session_id,
        chain=chain,
        event_type="GEMINI_PROMPT_EGRESS",
        raw_payload_str=raw_payload_str,
    )
    body["contents"] = contents

    sanitized_payload_str = json.dumps(contents, sort_keys=True)
    chain.append_event(
        event_type="GEMINI_PROMPT_EGRESS",
        raw_input=raw_payload_str,
        sanitized_output=sanitized_payload_str,
        entities_detected=sorted({entity.entity_type for entity in detections}),
        tokens_mapped=result.tokens_mapped,
        policy_action="TOKENIZE_AND_FORWARD" if result.tokens_mapped else "ALLOW",
    )

    upstream_url = f"{settings.UPSTREAM_GEMINI_BASE_URL.rstrip('/')}/v1beta/models/{model_path}:generateContent"
    headers = dict(request.headers)
    for header in ("host", "content-length", "x-chainmark-session-id"):
        headers.pop(header, None)

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
    unresolved = _detokenize_gemini_response(resp_json, session_id)
    if unresolved and settings.FAIL_CLOSED:
        _raise_unresolved_ingress(chain, "GEMINI_COMPLETION_INGRESS")

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


@app.get("/api/sessions")
async def list_sessions():
    """
    Returns active sessions and compliance summary for the dashboard.
    """
    sessions_list = []
    for sid, chain in session_chains.items():
        if not chain or not chain.events:
            continue
        entities = set()
        for e in chain.events:
            entities.update(e.entities_detected)

        is_valid, _ = chain.verify_chain()
        sessions_list.append({
            "session_id": sid,
            "event_count": len(chain.events),
            "merkle_root": chain.get_merkle_root(),
            "last_active": chain.events[-1].timestamp if chain.events else 0,
            "entities_detected": sorted(list(entities)),
            "tamper_evident_valid": is_valid,
        })
    return sorted(sessions_list, key=lambda x: x["last_active"], reverse=True)


@app.get("/api/sessions/{session_id}")
async def get_session_detail(session_id: str):
    """
    Returns detailed event chain and Merkle DAG for an individual session.
    """
    chain = session_chains.get(session_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Session not found")

    is_valid, err = chain.verify_chain()
    events_data = []
    for e in chain.events:
        events_data.append({
            "sequence": e.sequence,
            "timestamp": e.timestamp,
            "event_type": e.event_type,
            "input_digest": e.input_digest,
            "sanitized_digest": e.sanitized_digest,
            "entities_detected": e.entities_detected,
            "tokens_mapped": e.tokens_mapped,
            "policy_action": e.policy_action,
            "prev_hash": e.prev_hash,
            "node_hash": e.node_hash,
        })

    return {
        "session_id": session_id,
        "is_valid": is_valid,
        "error": err,
        "merkle_root": chain.get_merkle_root(),
        "signature": signer.sign_root(chain.get_merkle_root()),
        "events": events_data,
    }


@app.post("/api/simulate")
async def simulate_prompt(request: Request):
    """
    Simulates a live multi-turn agent interaction for the UI playground.
    Allows comparing 'Protected (Chainmark)' vs 'Unprotected (Raw LLM)'.
    """
    data = await request.json()
    session_id = data.get("session_id", "demo_simulation")
    messages = data.get("messages") or []
    protected = data.get("protected", True)

    chain = get_or_create_chain(session_id)

    # 1. Detection
    detected_entities = taint_engine.process_messages(session_id, messages)

    if not protected:
        # In unprotected mode, raw PII leaks to external LLM
        return {
            "mode": "UNPROTECTED_DIRECT_EGRESS",
            "detected_entities": [
                {
                    "entity_type": e.entity_type,
                    "raw_value": e.raw_value,
                    "is_fragment_assembly": e.is_fragment_assembly,
                    "provenance_turns": e.provenance_turns,
                }
                for e in detected_entities
            ],
            "egress_payload": messages,
            "data_leaked": len(detected_entities) > 0,
            "simulated_llm_response": f"External LLM processed raw prompt: {messages[-1].get('content', '') if messages else ''}",
            "audit_trail_recorded": False,
        }

    # Protected mode: redact every message, fragments included.
    raw_payload_str = json.dumps(messages, sort_keys=True)
    texts = [m.get("content", "") if isinstance(m, dict) else "" for m in messages]
    result = vault.redact_texts(texts, detected_entities, session_id, turn_indices=list(range(len(texts))))

    if result.unresolved and settings.FAIL_CLOSED:
        _block_unredactable(chain, "SIMULATION_PROMPT_EGRESS", raw_payload_str, result)

    sanitized_messages = []
    for message, sanitized in zip(messages, result.texts):
        if isinstance(message, dict):
            copy = dict(message)
            copy["content"] = sanitized
            sanitized_messages.append(copy)
        else:
            sanitized_messages.append(message)

    # Record in Merkle chain
    chain.append_event(
        event_type="SIMULATION_PROMPT_EGRESS",
        raw_input=raw_payload_str,
        sanitized_output=json.dumps(sanitized_messages, sort_keys=True),
        entities_detected=[e.entity_type for e in detected_entities],
        tokens_mapped=result.tokens_mapped,
        policy_action="TOKENIZE_AND_FORWARD" if result.tokens_mapped else "ALLOW",
    )

    # Simulate LLM answering using the token
    last_sanitized = sanitized_messages[-1].get("content", "") if sanitized_messages else ""
    simulated_llm_raw = f"Verified identity record for {last_sanitized}. Status: Cleared for processing."
    detokenized_final = vault.detokenize_text(simulated_llm_raw, session_id)

    chain.append_event(
        event_type="SIMULATION_COMPLETION_INGRESS",
        raw_input=simulated_llm_raw,
        sanitized_output=detokenized_final,
        entities_detected=[],
        tokens_mapped=[],
        policy_action="DETOKENIZE_FOR_CLIENT",
    )

    return {
        "mode": "CHAINMARK_PROTECTED",
        "detected_entities": [
            {
                "entity_type": e.entity_type,
                "raw_value": e.raw_value,
                "is_fragment_assembly": e.is_fragment_assembly,
                "provenance_turns": e.provenance_turns,
            }
            for e in detected_entities
        ],
        "egress_payload": sanitized_messages,
        "tokens_generated": result.tokens_mapped,
        "simulated_llm_raw": simulated_llm_raw,
        "detokenized_client_response": detokenized_final,
        "merkle_root": chain.get_merkle_root(),
        "total_events": len(chain.events),
        "data_leaked": False,
        "audit_trail_recorded": True,
    }


@app.post("/api/tamper/{session_id}")
async def tamper_session(session_id: str):
    """
    Demo endpoint: artificially corrupts a hash in the chain to demonstrate
    how the Merkle DAG immediately catches tampering.
    """
    chain = session_chains.get(session_id)
    if not chain or not chain.events:
        raise HTTPException(status_code=404, detail="Session not found or has no events")

    # Corrupt node_hash of the first event
    chain.events[0].node_hash = "deadbeef" * 8
    is_valid, err = chain.verify_chain()

    return {
        "tampered": True,
        "session_id": session_id,
        "is_valid": is_valid,
        "detected_error": err,
    }


class CloakRequest(BaseModel):
    text: str
    cloak_request_id: Optional[str] = None
    history: Optional[List[Dict[str, Any]]] = None


class UncloakRequest(BaseModel):
    cloaked_text: Optional[str] = None
    cloak_request_id: Optional[str] = None


@app.post("/cloak")
@app.post("/v1/cloak")
async def handle_cloak(payload: CloakRequest):
    """
    Parses input text, detects sensitive entities and split multi-turn fragments,
    replaces them with typed HMAC tokens, stores encrypted values in the vault,
    and commits an event to the Merkle DAG.
    """
    req_id = payload.cloak_request_id or f"cloak_{secrets.token_hex(6)}"
    chain = get_or_create_chain(req_id)

    history = list(payload.history or [])
    scan_messages = history + [{"role": "user", "content": payload.text}]
    detected_entities = taint_engine.process_messages(req_id, scan_messages)

    # Only the current text is egress here; fragments living in history are
    # context, not something this call can retract.
    current_turn = len(scan_messages) - 1
    result = vault.redact_texts(
        [payload.text], detected_entities, req_id, turn_indices=[current_turn]
    )

    if result.unresolved and settings.FAIL_CLOSED:
        _block_unredactable(chain, "CLOAK_OPERATION", payload.text, result)

    cloaked_text = result.texts[0]

    chain.append_event(
        event_type="CLOAK_OPERATION",
        raw_input=payload.text,
        sanitized_output=cloaked_text,
        entities_detected=[e.entity_type for e in detected_entities],
        tokens_mapped=result.tokens_mapped,
        policy_action="CLOAKED_WITH_TOKENS" if result.tokens_mapped else "PASSTHROUGH",
    )

    return {
        "status": "success",
        "cloak_request_id": req_id,
        "original_text": payload.text,
        "cloaked_text": cloaked_text,
        "detected_entities": [
            {
                "entity_type": e.entity_type,
                "raw_value": e.raw_value,
                "token": vault.find_token(e.entity_type, e.raw_value, req_id),
                "confidence": e.confidence,
                "is_fragment_assembly": e.is_fragment_assembly,
                "provenance_turns": e.provenance_turns,
            }
            for e in detected_entities
        ],
        "tokens_mapped": result.tokens_mapped,
        "merkle_root": chain.get_merkle_root(),
        "event_sequence": len(chain.events) - 1,
    }


@app.post("/uncloak/{cloakrequestid}")
@app.get("/uncloak/{cloakrequestid}")
@app.post("/uncloak")
async def handle_uncloak(cloakrequestid: Optional[str] = None, payload: Optional[UncloakRequest] = None):
    """
    Restores tokens in cloaked text back to original plaintext using the AES-256 vault.
    """
    req_id = cloakrequestid or (payload.cloak_request_id if payload else None)
    if not req_id:
        raise HTTPException(status_code=400, detail="Missing cloak_request_id")

    chain = get_or_create_chain(req_id)
    text_to_uncloak = payload.cloaked_text if payload and payload.cloaked_text is not None else ""

    uncloaked_text, unresolved = vault.detokenize_text_strict(text_to_uncloak, req_id)
    matched_tokens = len(vault.TOKEN_RE.findall(text_to_uncloak))

    if unresolved and settings.FAIL_CLOSED:
        chain.append_event(
            event_type="UNCLOAK_OPERATION",
            raw_input=text_to_uncloak,
            sanitized_output="",
            entities_detected=[],
            tokens_mapped=[],
            policy_action="BLOCKED_UNRESOLVED_TOKEN",
        )
        raise HTTPException(
            status_code=409,
            detail={
                "error": "chainmark_vault_miss",
                "reason": "one_or_more_tokens_are_not_resolvable_in_this_session",
                "unresolved_count": unresolved,
            },
        )

    chain.append_event(
        event_type="UNCLOAK_OPERATION",
        raw_input=text_to_uncloak,
        sanitized_output=uncloaked_text,
        entities_detected=[],
        tokens_mapped=[],
        policy_action="UNCLOAKED_FOR_CLIENT",
    )

    return {
        "status": "success",
        "cloak_request_id": req_id,
        "cloaked_text": text_to_uncloak,
        "uncloaked_text": uncloaked_text,
        "tokens_restored_count": matched_tokens - unresolved,
        "tokens_unresolved_count": unresolved,
        "merkle_root": chain.get_merkle_root(),
        "event_sequence": len(chain.events) - 1,
    }


def run_server():
    uvicorn.run(app, host=settings.HOST, port=settings.PORT)


if __name__ == "__main__":
    run_server()
