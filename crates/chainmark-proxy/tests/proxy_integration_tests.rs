use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::post,
    Json, Router,
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use chainmark_proxy::{create_app, state::AppState, ProxyConfig};

#[tokio::test]
async fn test_health_check() {
    let state = AppState::new(ProxyConfig::default());
    let app = create_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["status"], "healthy");
    assert_eq!(body["engine"], "chainmark-core-rust");
    assert!(body["signing_pubkey"].as_str().unwrap().contains("BEGIN PUBLIC KEY"));
}

#[tokio::test]
async fn test_cloak_and_uncloak_roundtrip() {
    let state = AppState::new(ProxyConfig::default());
    let app = create_app(state);

    let payload = json!({
        "text": "User aadhaar is 999999990019 and credit card is 4532015112830366.",
        "cloak_request_id": "test_session_001"
    });

    let cloak_res = app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/cloak")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(cloak_res.status(), StatusCode::OK);
    let bytes = cloak_res.into_body().collect().await.unwrap().to_bytes();
    let cloak_body: Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(cloak_body["status"], "success");
    let cloaked_text = cloak_body["cloaked_text"].as_str().unwrap();
    assert!(!cloaked_text.contains("999999990019"), "Aadhaar must not leak into cloaked text");
    assert!(!cloaked_text.contains("4532015112830366"), "Card must not leak into cloaked text");
    assert!(cloaked_text.contains("[CM_TOKEN_AADHAAR_"));
    assert!(cloaked_text.contains("[CM_TOKEN_CREDIT_CARD_"));

    // Now uncloak
    let uncloak_payload = json!({
        "cloak_request_id": "test_session_001",
        "cloaked_text": cloaked_text
    });

    let uncloak_res = app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/uncloak")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&uncloak_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(uncloak_res.status(), StatusCode::OK);
    let uncloak_bytes = uncloak_res.into_body().collect().await.unwrap().to_bytes();
    let uncloak_body: Value = serde_json::from_slice(&uncloak_bytes).unwrap();

    assert_eq!(uncloak_body["status"], "success");
    let uncloaked_text = uncloak_body["uncloaked_text"].as_str().unwrap();
    assert_eq!(uncloaked_text, "User aadhaar is 999999990019 and credit card is 4532015112830366.");
    assert_eq!(uncloak_body["tokens_unresolved_count"], 0);

    // Verify evidence
    let verify_res = app.clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/evidence/verify/test_session_001")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(verify_res.status(), StatusCode::OK);
    let verify_bytes = verify_res.into_body().collect().await.unwrap().to_bytes();
    let verify_body: Value = serde_json::from_slice(&verify_bytes).unwrap();
    assert_eq!(verify_body["valid"], true);
    assert_eq!(verify_body["total_events"], 2); // cloak event + uncloak event
}

#[tokio::test]
async fn test_multi_turn_jigsaw_assembly() {
    let state = AppState::new(ProxyConfig::default());
    let app = create_app(state);

    let session_id = "jigsaw_session_002";

    // Turn 1
    let payload_turn1 = json!({
        "text": "Part one is 4532 0151",
        "cloak_request_id": session_id,
        "history": []
    });
    let _ = app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/cloak")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&payload_turn1).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Turn 2
    let payload_turn2 = json!({
        "text": "and part two is 1283 0366",
        "cloak_request_id": session_id,
        "history": [
            {"role": "user", "content": "Part one is 4532 0151"}
        ]
    });

    let res_turn2 = app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/cloak")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&payload_turn2).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res_turn2.status(), StatusCode::OK);
    let bytes = res_turn2.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    let detected = body["detected_entities"].as_array().unwrap();
    assert!(!detected.is_empty(), "Jigsaw engine should reconstruct 16-digit card across turns");
    let card_entity = detected
        .iter()
        .find(|e| e["entity_type"] == "CREDIT_CARD")
        .expect("Should find reconstructed CREDIT_CARD entity");
    assert_eq!(card_entity["is_fragment_assembly"], true);
}

#[tokio::test]
async fn test_evidence_export_zip() {
    let state = AppState::new(ProxyConfig::default());
    let app = create_app(state);

    let session_id = "zip_test_session_003";
    let payload = json!({
        "text": "Patient MRN is MRN-12345678 and doctor signed.",
        "cloak_request_id": session_id
    });

    let _ = app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/cloak")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let export_res = app.clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/evidence/export/{}", session_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(export_res.status(), StatusCode::OK);
    assert_eq!(export_res.headers().get("content-type").unwrap(), "application/zip");
    let zip_bytes = export_res.into_body().collect().await.unwrap().to_bytes();
    assert!(zip_bytes.starts_with(b"PK\x03\x04"), "Must be a valid ZIP archive");
}

async fn spawn_mock_openai(received_prompts: Arc<Mutex<Vec<String>>>) -> SocketAddr {
    let app = Router::new().route(
        "/chat/completions",
        post(move |Json(body): Json<Value>| {
            let prompts = received_prompts.clone();
            async move {
                let text = body["messages"][0]["content"].as_str().unwrap().to_string();
                prompts.lock().unwrap().push(text.clone());

                let resp = json!({
                    "id": "chatcmpl-mock",
                    "object": "chat.completion",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": format!("Echoing: {}", text)
                        },
                        "finish_reason": "stop"
                    }]
                });
                Json(resp)
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

#[tokio::test]
async fn test_openai_proxy_interception_and_detokenization() {
    let received_prompts = Arc::new(Mutex::new(Vec::new()));
    let mock_addr = spawn_mock_openai(received_prompts.clone()).await;

    let mut config = ProxyConfig::default();
    config.upstream_openai_url = format!("http://{}", mock_addr);

    let state = AppState::new(config);
    let app = create_app(state);

    let openai_req = json!({
        "model": "gpt-4o",
        "messages": [
            {"role": "user", "content": "My PAN card is ABCPE1234F for taxation."}
        ]
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .header("x-chainmark-session-id", "openai_session_001")
                .body(Body::from(serde_json::to_vec(&openai_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let resp_json: Value = serde_json::from_slice(&bytes).unwrap();

    // 1. Verify upstream NEVER saw plaintext PAN ABCPE1234F
    let captured = received_prompts.lock().unwrap();
    assert_eq!(captured.len(), 1);
    assert!(!captured[0].contains("ABCPE1234F"), "Zero Plaintext Leakage: upstream must not receive raw PAN");
    assert!(captured[0].contains("[CM_TOKEN_PAN_"), "Upstream must receive HMAC token");

    // 2. Verify client response is transparently detokenized back to ABCPE1234F
    let assistant_content = resp_json["choices"][0]["message"]["content"].as_str().unwrap();
    assert!(assistant_content.contains("ABCPE1234F"), "Client response must be restored to original PAN");
    assert!(!assistant_content.contains("[CM_TOKEN_PAN_"), "Client must not receive raw internal tokens");
}

async fn spawn_mock_anthropic(received_prompts: Arc<Mutex<Vec<String>>>) -> SocketAddr {
    let app = Router::new().route(
        "/messages",
        post(move |Json(body): Json<Value>| {
            let prompts = received_prompts.clone();
            async move {
                let text = body["messages"][0]["content"].as_str().unwrap().to_string();
                prompts.lock().unwrap().push(text.clone());

                let resp = json!({
                    "id": "msg_mock",
                    "type": "message",
                    "role": "assistant",
                    "content": [{
                        "type": "text",
                        "text": format!("Echo Anthropic: {}", text)
                    }],
                    "stop_reason": "end_turn"
                });
                Json(resp)
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

#[tokio::test]
async fn test_anthropic_proxy_interception_and_detokenization() {
    let received_prompts = Arc::new(Mutex::new(Vec::new()));
    let mock_addr = spawn_mock_anthropic(received_prompts.clone()).await;

    let mut config = ProxyConfig::default();
    config.upstream_anthropic_url = format!("http://{}", mock_addr);

    let state = AppState::new(config);
    let app = create_app(state);

    let anthropic_req = json!({
        "model": "claude-3-5-sonnet-20241022",
        "messages": [
            {"role": "user", "content": "Doctor note has MRN-98765432 and Aadhaar 999999990019."}
        ]
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/messages")
                .header("content-type", "application/json")
                .header("x-chainmark-session-id", "anthropic_session_001")
                .body(Body::from(serde_json::to_vec(&anthropic_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let resp_json: Value = serde_json::from_slice(&bytes).unwrap();

    // 1. Verify upstream received redacted tokens
    let captured = received_prompts.lock().unwrap();
    assert_eq!(captured.len(), 1);
    assert!(!captured[0].contains("999999990019"), "Zero Plaintext Leakage: upstream must not receive raw Aadhaar");
    assert!(captured[0].contains("[CM_TOKEN_AADHAAR_"), "Upstream must receive Aadhaar token");

    // 2. Verify client receives restored content
    let text = resp_json["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("999999990019"), "Client must receive detokenized response");
}

async fn spawn_mock_mcp(received_args: Arc<Mutex<Vec<String>>>) -> SocketAddr {
    let app = Router::new().route(
        "/message",
        post(move |Json(body): Json<Value>| {
            let store = received_args.clone();
            async move {
                let args_str = serde_json::to_string(&body["params"]["arguments"]).unwrap_or_default();
                store.lock().unwrap().push(args_str.clone());

                let resp = json!({
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": {
                        "content": [{
                            "type": "text",
                            "text": format!("Executed with: {}", args_str)
                        }]
                    }
                });
                Json(resp)
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

#[tokio::test]
async fn test_mcp_streamable_http_proxy() {
    let received_args = Arc::new(Mutex::new(Vec::new()));
    let mock_addr = spawn_mock_mcp(received_args.clone()).await;

    let mut config = ProxyConfig::default();
    config.upstream_mcp_url = format!("http://{}", mock_addr);

    let state = AppState::new(config);
    let app = create_app(state);

    let mcp_req = json!({
        "jsonrpc": "2.0",
        "id": 42,
        "method": "tools/call",
        "params": {
            "name": "process_payment",
            "arguments": "Card to charge is 4532015112830366."
        }
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp/message")
                .header("content-type", "application/json")
                .header("x-chainmark-session-id", "mcp_session_001")
                .body(Body::from(serde_json::to_vec(&mcp_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let resp_json: Value = serde_json::from_slice(&bytes).unwrap();

    // Verify upstream MCP tool call received token
    let captured = received_args.lock().unwrap();
    assert_eq!(captured.len(), 1);
    assert!(!captured[0].contains("4532015112830366"), "Zero Plaintext Leakage: MCP server must not receive raw card");
    assert!(captured[0].contains("[CM_TOKEN_CREDIT_CARD_"));

    // Verify client received detokenized output
    let result_text = resp_json["result"]["content"][0]["text"].as_str().unwrap();
    assert!(result_text.contains("4532015112830366"));
}
