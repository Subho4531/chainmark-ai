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

pub async fn handle_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> Result<Response, (StatusCode, Json<Value>)> {
    let session_id = headers
        .get("x-chainmark-session-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "default_anthropic_session".to_string());

    let stream = body.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);

    // 1. Extract texts from Anthropic system and messages
    let mut texts_to_scan: Vec<String> = Vec::new();
    let mut scan_tuples: Vec<(String, String)> = Vec::new();

    if let Some(sys) = body.get("system").and_then(|s| s.as_str()) {
        texts_to_scan.push(sys.to_string());
        scan_tuples.push(("system".to_string(), sys.to_string()));
    }

    if let Some(messages) = body.get_mut("messages").and_then(|m| m.as_array_mut()) {
        for msg in messages.iter() {
            let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("user").to_string();
            if let Some(content) = msg.get("content").and_then(|c| c.as_str()) {
                texts_to_scan.push(content.to_string());
                scan_tuples.push((role.clone(), content.to_string()));
            } else if let Some(blocks) = msg.get("content").and_then(|c| c.as_array()) {
                for block in blocks {
                    if let Some(text) = block.get("text").and_then(|t| t.as_str()) {
                        texts_to_scan.push(text.to_string());
                        scan_tuples.push((role.clone(), text.to_string()));
                    }
                }
            }
        }
    }

    let scan_refs: Vec<(&str, &str)> = scan_tuples.iter().map(|(r, c)| (r.as_str(), c.as_str())).collect();
    let detected_entities = state.taint_engine.process_messages(&session_id, &scan_refs);

    // 2. Redaction
    let redaction = state.vault.redact_texts(&texts_to_scan, &detected_entities, &session_id);

    if !redaction.unresolved.is_empty() && state.config.fail_closed {
        state.with_chain(&session_id, |chain| {
            chain.append_event(
                "ANTHROPIC_PROMPT_EGRESS",
                &serde_json::to_string(&texts_to_scan).unwrap_or_default(),
                "",
                detected_entities.iter().map(|e| e.entity_type.to_string()).collect(),
                vec![],
                "BLOCKED_UNREDACTABLE",
            );
        });

        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "error": "chainmark_policy_violation",
                "reason": "sensitive_value_could_not_be_neutralized"
            })),
        ));
    }

    // 3. Write back sanitized text
    let mut text_idx = 0;
    if body.get("system").and_then(|s| s.as_str()).is_some() {
        if let Some(sanitized) = redaction.texts.get(text_idx) {
            body["system"] = Value::String(sanitized.clone());
        }
        text_idx += 1;
    }

    if let Some(messages) = body.get_mut("messages").and_then(|m| m.as_array_mut()) {
        for msg in messages.iter_mut() {
            if msg.get("content").and_then(|c| c.as_str()).is_some() {
                if let Some(sanitized) = redaction.texts.get(text_idx) {
                    msg["content"] = Value::String(sanitized.clone());
                }
                text_idx += 1;
            } else if let Some(blocks) = msg.get_mut("content").and_then(|c| c.as_array_mut()) {
                for block in blocks {
                    if block.get("text").and_then(|t| t.as_str()).is_some() {
                        if let Some(sanitized) = redaction.texts.get(text_idx) {
                            block["text"] = Value::String(sanitized.clone());
                        }
                        text_idx += 1;
                    }
                }
            }
        }
    }

    // 4. Evidence event
    state.with_chain(&session_id, |chain| {
        chain.append_event(
            "ANTHROPIC_PROMPT_EGRESS",
            &serde_json::to_string(&texts_to_scan).unwrap_or_default(),
            &serde_json::to_string(&redaction.texts).unwrap_or_default(),
            detected_entities.iter().map(|e| e.entity_type.to_string()).collect(),
            redaction.tokens_mapped.clone(),
            if redaction.tokens_mapped.is_empty() { "ALLOW" } else { "TOKENIZE_AND_FORWARD" },
        );
    });

    // 5. Upstream call
    let upstream_url = format!("{}/messages", state.config.upstream_anthropic_url.trim_end_matches('/'));
    let mut req = state.http_client.post(&upstream_url).json(&body);

    for (k, v) in headers.iter() {
        if k == "x-api-key" || k == "anthropic-version" || k == "anthropic-beta" {
            req = req.header(k, v);
        }
    }

    let upstream_resp = req.send().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": format!("Upstream Anthropic failure: {}", e)})),
        )
    })?;

    let status = upstream_resp.status();

    if !stream {
        let resp_text = upstream_resp.text().await.map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": format!("Failed reading Anthropic response: {}", e)})),
            )
        })?;

        let mut resp_json: Value = serde_json::from_str(&resp_text).unwrap_or(Value::Null);

        // Detokenize content blocks
        if let Some(blocks) = resp_json.get_mut("content").and_then(|c| c.as_array_mut()) {
            for block in blocks {
                if let Some(text) = block.get_mut("text").and_then(|t| t.as_str()) {
                    let detokenized = state.vault.detokenize_text(text, &session_id);
                    block["text"] = Value::String(detokenized);
                }
            }
        }

        state.with_chain(&session_id, |chain| {
            chain.append_event(
                "ANTHROPIC_COMPLETION_INGRESS",
                &resp_text,
                &serde_json::to_string(&resp_json).unwrap_or_default(),
                vec![],
                vec![],
                "DETOKENIZE_FOR_CLIENT",
            );
        });

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
