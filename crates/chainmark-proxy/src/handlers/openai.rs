use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use futures::StreamExt;
use serde_json::{json, Value};
use tokio_stream::wrappers::ReceiverStream;
use chainmark_buffer::StreamTokenRestorer;

use crate::state::AppState;

pub async fn handle_chat_completions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> Result<Response, (StatusCode, Json<Value>)> {
    let session_id = headers
        .get("x-chainmark-session-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| body.get("user").and_then(|u| u.as_str()).map(|s| format!("user_{}", s)))
        .unwrap_or_else(|| "default_session".to_string());

    let stream = body.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);

    state.ensure_hydrated(&session_id).await;

    let messages = match body.get_mut("messages").and_then(|m| m.as_array_mut()) {
        Some(m) => m,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "messages must be an array"})),
            ))
        }
    };

    // 1. Extract all text units: message content and tool arguments
    let mut texts_to_scan: Vec<String> = Vec::new();
    let mut scan_tuples: Vec<(String, String)> = Vec::new();

    for msg in messages.iter() {
        let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("user").to_string();
        if let Some(content) = msg.get("content").and_then(|c| c.as_str()) {
            texts_to_scan.push(content.to_string());
            scan_tuples.push((role.clone(), content.to_string()));
        }

        if let Some(tool_calls) = msg.get("tool_calls").and_then(|t| t.as_array()) {
            for call in tool_calls {
                if let Some(args) = call.get("function").and_then(|f| f.get("arguments")).and_then(|a| a.as_str()) {
                    texts_to_scan.push(args.to_string());
                    scan_tuples.push(("tool_call".to_string(), args.to_string()));
                }
            }
        }
    }

    let scan_refs: Vec<(&str, &str)> = scan_tuples.iter().map(|(r, c)| (r.as_str(), c.as_str())).collect();
    let detected_entities = state.taint_engine.process_messages(&session_id, &scan_refs);

    // 2. Redact sensitive values
    let redaction = state.vault.redact_texts(&texts_to_scan, &detected_entities, &session_id);

    if !redaction.unresolved.is_empty() && state.config.fail_closed {
        state
            .record_event(
                &session_id,
                "LLM_PROMPT_EGRESS",
                &serde_json::to_string(&texts_to_scan).unwrap_or_default(),
                "",
                detected_entities.iter().map(|e| e.entity_type.to_string()).collect(),
                vec![],
                "BLOCKED_UNREDACTABLE",
            )
            .await;

        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "error": "chainmark_policy_violation",
                "reason": "sensitive_value_could_not_be_neutralized"
            })),
        ));
    }

    state.persist_redaction(&session_id, &redaction.tokens_mapped).await;

    // 3. Write sanitized strings back into the request payload
    let mut text_idx = 0;
    for msg in messages.iter_mut() {
        if msg.get("content").and_then(|c| c.as_str()).is_some() {
            if let Some(sanitized) = redaction.texts.get(text_idx) {
                msg["content"] = Value::String(sanitized.clone());
            }
            text_idx += 1;
        }

        if let Some(tool_calls) = msg.get_mut("tool_calls").and_then(|t| t.as_array_mut()) {
            for call in tool_calls {
                if call.get("function").and_then(|f| f.get("arguments")).is_some() {
                    if let Some(sanitized) = redaction.texts.get(text_idx) {
                        call["function"]["arguments"] = Value::String(sanitized.clone());
                    }
                    text_idx += 1;
                }
            }
        }
    }

    // 4. Record egress in Merkle evidence chain
    state
        .record_event(
            &session_id,
            "LLM_PROMPT_EGRESS",
            &serde_json::to_string(&texts_to_scan).unwrap_or_default(),
            &serde_json::to_string(&redaction.texts).unwrap_or_default(),
            detected_entities.iter().map(|e| e.entity_type.to_string()).collect(),
            redaction.tokens_mapped.clone(),
            if redaction.tokens_mapped.is_empty() { "ALLOW" } else { "TOKENIZE_AND_FORWARD" },
        )
        .await;

    // 5. Forward request to upstream
    let upstream_url = format!("{}/chat/completions", state.config.upstream_openai_url.trim_end_matches('/'));
    let mut req = state.http_client.post(&upstream_url).json(&body);

    if let Some(auth) = headers.get(header::AUTHORIZATION) {
        req = req.header(header::AUTHORIZATION, auth);
    }

    let upstream_resp = req.send().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": format!("Upstream communication failure: {}", e)})),
        )
    })?;

    let status = upstream_resp.status();

    if !stream {
        // Non-streaming response
        let resp_text = upstream_resp.text().await.map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": format!("Failed reading upstream response: {}", e)})),
            )
        })?;

        let mut resp_json: Value = serde_json::from_str(&resp_text).unwrap_or(Value::Null);

        // Detokenize response contents
        if let Some(choices) = resp_json.get_mut("choices").and_then(|c| c.as_array_mut()) {
            for choice in choices {
                if let Some(content) = choice.get_mut("message").and_then(|m| m.get_mut("content")).and_then(|c| c.as_str()) {
                    let detokenized = state.vault.detokenize_text(content, &session_id);
                    choice["message"]["content"] = Value::String(detokenized);
                }

                if let Some(tool_calls) = choice.get_mut("message").and_then(|m| m.get_mut("tool_calls")).and_then(|t| t.as_array_mut()) {
                    for call in tool_calls {
                        if let Some(args) = call.get_mut("function").and_then(|f| f.get_mut("arguments")).and_then(|a| a.as_str()) {
                            let detokenized = state.vault.detokenize_text(args, &session_id);
                            call["function"]["arguments"] = Value::String(detokenized);
                        }
                    }
                }
            }
        }

        state
            .record_event(
                &session_id,
                "LLM_COMPLETION_INGRESS",
                &resp_text,
                &serde_json::to_string(&resp_json).unwrap_or_default(),
                vec![],
                vec![],
                "DETOKENIZE_FOR_CLIENT",
            )
            .await;

        return Ok((status, Json(resp_json)).into_response());
    }

    // 6. Streaming SSE Response with Prefix-Hold Ring Buffer
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(100);
    let vault_clone = state.vault.clone();
    let session_clone = session_id.clone();

    tokio::spawn(async move {
        let mut byte_stream = upstream_resp.bytes_stream();
        let mut restorer = StreamTokenRestorer::new(vault_clone, session_clone);

        while let Some(chunk_res) = byte_stream.next().await {
            match chunk_res {
                Ok(bytes) => {
                    if let Ok(text) = std::str::from_utf8(&bytes) {
                        let safe_text = restorer.push(text);
                        if !safe_text.is_empty() {
                            let _ = tx.send(Ok(bytes::Bytes::from(safe_text))).await;
                        }
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(std::io::Error::new(std::io::ErrorKind::Other, e))).await;
                    break;
                }
            }
        }

        let tail = restorer.flush();
        if !tail.is_empty() {
            let _ = tx.send(Ok(bytes::Bytes::from(tail))).await;
        }
    });

    let stream_body = Body::from_stream(ReceiverStream::new(rx));
    let mut response = Response::new(stream_body);
    *response.status_mut() = status;
    response.headers_mut().insert(header::CONTENT_TYPE, "text/event-stream".parse().unwrap());
    response.headers_mut().insert(header::CACHE_CONTROL, "no-cache".parse().unwrap());

    Ok(response)
}
