use std::time::{SystemTime, UNIX_EPOCH};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use chainmark_proxy::{create_app, state::AppState, ProxyConfig};

#[tokio::test]
async fn test_postgres_write_through_and_hydration_across_restart() {
    let config = ProxyConfig::from_env();
    assert!(
        config.database_url.is_some(),
        "DATABASE_URL must be configured in .env for PostgreSQL bridge test"
    );

    let session_id = format!(
        "pg_bridge_{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );

    // =========================================================================
    // 1. Instance 1: Cloak PII and persist vault_records + merkle_events to DB
    // =========================================================================
    let state1 = AppState::new_with_db(config.clone()).await;
    assert!(state1.db.is_some(), "Instance 1 must connect to live PostgreSQL");
    let app1 = create_app(state1);

    // Health must report postgres = "connected"
    let health_res = app1
        .clone()
        .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(health_res.status(), StatusCode::OK);
    let health_json: Value =
        serde_json::from_slice(&health_res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(health_json["postgres"], "connected");

    // Cloak sensitive text via Instance 1
    let original_text = "Taxpayer PAN is ABCPE1234F and Aadhaar is 999999990019.";
    let cloak_payload = json!({
        "text": original_text,
        "cloak_request_id": session_id
    });

    let cloak_res = app1
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/cloak")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&cloak_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cloak_res.status(), StatusCode::OK);
    let cloak_json: Value =
        serde_json::from_slice(&cloak_res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let cloaked_text = cloak_json["cloaked_text"].as_str().unwrap().to_string();
    assert!(!cloaked_text.contains("ABCPE1234F"));
    assert!(!cloaked_text.contains("999999990019"));
    assert!(cloaked_text.contains("[CM_TOKEN_PAN_"));
    assert!(cloaked_text.contains("[CM_TOKEN_AADHAAR_"));

    // =========================================================================
    // 2. Simulated Proxy Restart: Fresh AppState with empty RAM caches
    // =========================================================================
    let state2 = AppState::new_with_db(config).await;
    assert!(state2.db.is_some(), "Instance 2 must connect to live PostgreSQL");
    let app2 = create_app(state2);

    // Uncloak using Instance 2 — must hydrate AES-256-GCM vault_records from PostgreSQL
    let uncloak_payload = json!({
        "cloak_request_id": session_id,
        "cloaked_text": cloaked_text
    });

    let uncloak_res = app2
        .clone()
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
    let uncloak_json: Value =
        serde_json::from_slice(&uncloak_res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(uncloak_json["uncloaked_text"], original_text);
    assert_eq!(uncloak_json["tokens_unresolved_count"], 0);

    // Verify Merkle chain continuity across restart (seq 0 from Instance 1 + seq 1 from Instance 2)
    let verify_res = app2
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/evidence/verify/{}", session_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(verify_res.status(), StatusCode::OK);
    let verify_json: Value =
        serde_json::from_slice(&verify_res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(verify_json["valid"], true, "Merkle chain tampered or broken across DB hydration: {:?}", verify_json);
    assert_eq!(verify_json["total_events"], 2);

    // Export evidence pack ZIP (also writes sealed pack into PostgreSQL evidence_packs)
    let export_res = app2
        .clone()
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
    let zip_bytes = export_res.into_body().collect().await.unwrap().to_bytes();
    assert!(zip_bytes.starts_with(b"PK\x03\x04"));

    // Verify /api/sessions reads session back from PostgreSQL
    let sessions_res = app2
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/sessions")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sessions_res.status(), StatusCode::OK);
    let sessions_json: Value =
        serde_json::from_slice(&sessions_res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let list = sessions_json.as_array().unwrap();
    assert!(
        list.iter().any(|s| s["session_id"] == session_id),
        "Session '{}' should appear in DB-backed /api/sessions response",
        session_id
    );
}
