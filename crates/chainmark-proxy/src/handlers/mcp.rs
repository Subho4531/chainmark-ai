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

pub async fn handle_mcp_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> Result<Response, (StatusCode, Json<Value>)> {
    let session_id = headers
        .get("x-chainmark-session-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "default_mcp_session".to_string());

    let method = body.get("method").and_then(|m| m.as_str()).unwrap_or("unknown").to_string();

    // Extract text from params.arguments or params.contents
    let mut texts_to_scan: Vec<String> = Vec::new();

    if let Some(args) = body.get_mut("params").and_then(|p| p.get_mut("arguments")) {
        if let Some(s) = args.as_str() {
            texts_to_scan.push(s.to_string());
        } else if let Ok(serialized) = serde_json::to_string(&args) {
            texts_to_scan.push(serialized);
        }
    }

    let scan_refs: Vec<(&str, &str)> = texts_to_scan.iter().map(|t| ("mcp_param", t.as_str())).collect();
    let detected_entities = state.taint_engine.process_messages(&session_id, &scan_refs);

    // Redaction
    let redaction = state.vault.redact_texts(&texts_to_scan, &detected_entities, &session_id);

    if !redaction.unresolved.is_empty() && state.config.fail_closed {
        state.with_chain(&session_id, |chain| {
            chain.append_event(
                "MCP_MESSAGE_EGRESS",
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

    // Write back sanitized text if modified
    if let Some(first_sanitized) = redaction.texts.first() {
        if let Some(params) = body.get_mut("params") {
            if let Some(args) = params.get_mut("arguments") {
                if args.is_string() {
                    *args = Value::String(first_sanitized.clone());
                } else if let Ok(parsed) = serde_json::from_str(first_sanitized) {
                    *args = parsed;
                }
            }
        }
    }

    state.with_chain(&session_id, |chain| {
        chain.append_event(
            "MCP_MESSAGE_EGRESS",
            &serde_json::to_string(&texts_to_scan).unwrap_or_default(),
            &serde_json::to_string(&redaction.texts).unwrap_or_default(),
            detected_entities.iter().map(|e| e.entity_type.to_string()).collect(),
            redaction.tokens_mapped.clone(),
            format!("MCP_{}", method).as_str(),
        );
    });

    // Forward to upstream MCP server
    let upstream_url = format!("{}/message", state.config.upstream_mcp_url.trim_end_matches('/'));
    let req = state.http_client.post(&upstream_url).json(&body);

    let upstream_resp = req.send().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": format!("Upstream MCP failure: {}", e)})),
        )
    })?;

    let status = upstream_resp.status();
    let resp_text = upstream_resp.text().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": format!("Failed reading MCP response: {}", e)})),
        )
    })?;

    let mut resp_json: Value = serde_json::from_str(&resp_text).unwrap_or(Value::Null);

    // Detokenize result contents
    if let Some(content_items) = resp_json.get_mut("result").and_then(|r| r.get_mut("content")).and_then(|c| c.as_array_mut()) {
        for item in content_items {
            if let Some(text) = item.get_mut("text").and_then(|t| t.as_str()) {
                let detokenized = state.vault.detokenize_text(text, &session_id);
                item["text"] = Value::String(detokenized);
            }
        }
    }

    state.with_chain(&session_id, |chain| {
        chain.append_event(
            "MCP_MESSAGE_INGRESS",
            &resp_text,
            &serde_json::to_string(&resp_json).unwrap_or_default(),
            vec![],
            vec![],
            "DETOKENIZE_FOR_CLIENT",
        );
    });

    Ok((status, Json(resp_json)).into_response())
}

pub async fn handle_mcp_sse(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, (StatusCode, Json<Value>)> {
    let session_id = headers
        .get("x-chainmark-session-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "default_mcp_sse_session".to_string());

    let upstream_url = format!("{}/sse", state.config.upstream_mcp_url.trim_end_matches('/'));
    let upstream_resp = state.http_client.get(&upstream_url).send().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": format!("Failed to connect to MCP SSE: {}", e)})),
        )
    })?;

    let status = upstream_resp.status();
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(100);
    let vault_clone = state.vault.clone();

    tokio::spawn(async move {
        let mut byte_stream = upstream_resp.bytes_stream();
        let mut restorer = StreamTokenRestorer::new(vault_clone, session_id);

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
