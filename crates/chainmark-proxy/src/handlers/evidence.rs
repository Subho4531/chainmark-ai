use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde_json::json;

use crate::state::AppState;

pub async fn handle_health(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "status": "healthy",
        "service": "Chainmark AI Rust Gateway",
        "engine": "chainmark-core-rust",
        "version": "0.2.0",
        "vault_active": true,
        "fail_closed": state.config.fail_closed,
        "signing_pubkey": state.signer.get_public_key_pem()
    }))
}

pub async fn handle_export_evidence(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let zip_bytes = {
        let chains = state.chains.lock().unwrap();
        let chain = match chains.get(&session_id) {
            Some(c) if !c.events.is_empty() => c,
            _ => {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "Session not found or has no recorded events"})),
                ))
            }
        };

        match state.signer.build_evidence_pack(chain) {
            Ok(bytes) => bytes,
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("Failed to build evidence pack: {}", e)})),
                ))
            }
        }
    };

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "application/zip".parse().unwrap());
    headers.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=evidence_pack_{}.zip", session_id).parse().unwrap(),
    );

    Ok((headers, zip_bytes))
}

pub async fn handle_verify_evidence(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let chains = state.chains.lock().unwrap();
    let chain = match chains.get(&session_id) {
        Some(c) => c,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Session not found"})),
            ))
        }
    };

    let (valid, err) = chain.verify_chain();
    let root = chain.get_merkle_root();
    let sig = state.signer.sign_root(&root);

    Ok(Json(json!({
        "session_id": session_id,
        "valid": valid,
        "error": err,
        "total_events": chain.events.len(),
        "merkle_root": root,
        "signature": sig,
        "public_key": state.signer.get_public_key_pem()
    })))
}

pub async fn handle_list_sessions(State(state): State<AppState>) -> impl IntoResponse {
    let chains = state.chains.lock().unwrap();
    let mut list = Vec::new();

    for (sid, chain) in chains.iter() {
        if chain.events.is_empty() {
            continue;
        }

        let mut entities = std::collections::HashSet::new();
        for e in &chain.events {
            for ent in &e.entities_detected {
                entities.insert(ent.clone());
            }
        }

        let (valid, _) = chain.verify_chain();
        let last_active = chain.events.last().map(|e| e.timestamp).unwrap_or(0.0);

        list.push(json!({
            "session_id": sid,
            "event_count": chain.events.len(),
            "merkle_root": chain.get_merkle_root(),
            "last_active": last_active,
            "entities_detected": entities.into_iter().collect::<Vec<_>>(),
            "tamper_evident_valid": valid
        }));
    }

    Json(list)
}
