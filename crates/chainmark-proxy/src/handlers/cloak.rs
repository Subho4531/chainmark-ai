use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct CloakRequest {
    pub text: String,
    pub cloak_request_id: Option<String>,
    pub history: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
pub struct UncloakRequest {
    pub cloaked_text: Option<String>,
    pub cloak_request_id: Option<String>,
}

pub async fn handle_cloak(
    State(state): State<AppState>,
    Json(payload): Json<CloakRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let req_id = payload
        .cloak_request_id
        .unwrap_or_else(|| format!("cloak_{}", &Uuid::new_v4().to_string()[..8]));

    let mut scan_messages: Vec<(&str, &str)> = Vec::new();

    // Add history if present
    let history_strings: Vec<(String, String)>;
    if let Some(hist) = &payload.history {
        history_strings = hist
            .iter()
            .map(|item| {
                let role = item.get("role").and_then(|r| r.as_str()).unwrap_or("user").to_string();
                let content = item.get("content").and_then(|c| c.as_str()).unwrap_or("").to_string();
                (role, content)
            })
            .collect();
        for (r, c) in &history_strings {
            scan_messages.push((r.as_str(), c.as_str()));
        }
    }
    scan_messages.push(("user", &payload.text));

    let detected_entities = state.taint_engine.process_messages(&req_id, &scan_messages);

    let redaction = state.vault.redact_texts(&[payload.text.clone()], &detected_entities, &req_id);

    if !redaction.unresolved.is_empty() && state.config.fail_closed {
        state.with_chain(&req_id, |chain| {
            chain.append_event(
                "CLOAK_OPERATION",
                &payload.text,
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

    let cloaked_text = redaction.texts.first().cloned().unwrap_or_default();

    let (merkle_root, event_seq) = state.with_chain(&req_id, |chain| {
        let seq = chain.append_event(
            "CLOAK_OPERATION",
            &payload.text,
            &cloaked_text,
            detected_entities.iter().map(|e| e.entity_type.to_string()).collect(),
            redaction.tokens_mapped.clone(),
            if redaction.tokens_mapped.is_empty() { "PASSTHROUGH" } else { "CLOAKED_WITH_TOKENS" },
        ).sequence;
        (chain.get_merkle_root(), seq)
    });

    let detected_json: Vec<_> = detected_entities
        .into_iter()
        .map(|e| {
            let token = state.vault.generate_token_id(e.entity_type, &e.raw_value, &req_id);
            json!({
                "entity_type": e.entity_type.to_string(),
                "raw_value": e.raw_value,
                "token": token,
                "confidence": e.confidence,
                "is_fragment_assembly": e.is_fragment_assembly,
                "provenance_turns": e.provenance_turns,
            })
        })
        .collect();

    Ok(Json(json!({
        "status": "success",
        "cloak_request_id": req_id,
        "original_text": payload.text,
        "cloaked_text": cloaked_text,
        "detected_entities": detected_json,
        "tokens_mapped": redaction.tokens_mapped,
        "merkle_root": merkle_root,
        "event_sequence": event_seq
    })))
}

pub async fn handle_uncloak_path(
    State(state): State<AppState>,
    Path(cloak_request_id): Path<String>,
    payload: Option<Json<UncloakRequest>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let text = payload.and_then(|p| p.cloaked_text.clone()).unwrap_or_default();
    uncloak_core(&state, &cloak_request_id, &text)
}

pub async fn handle_uncloak_body(
    State(state): State<AppState>,
    Json(payload): Json<UncloakRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let req_id = match payload.cloak_request_id {
        Some(id) => id,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Missing cloak_request_id"})),
            ))
        }
    };
    let text = payload.cloaked_text.unwrap_or_default();
    uncloak_core(&state, &req_id, &text)
}

fn uncloak_core(
    state: &AppState,
    req_id: &str,
    text: &str,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (uncloaked, unresolved) = state.vault.detokenize_text_strict(text, req_id);

    if unresolved > 0 && state.config.fail_closed {
        state.with_chain(req_id, |chain| {
            chain.append_event("UNCLOAK_OPERATION", text, "", vec![], vec![], "BLOCKED_UNRESOLVED_TOKEN");
        });
        return Err((
            StatusCode::CONFLICT,
            Json(json!({
                "error": "chainmark_vault_miss",
                "unresolved_count": unresolved
            })),
        ));
    }

    let (root, seq) = state.with_chain(req_id, |chain| {
        let seq = chain.append_event("UNCLOAK_OPERATION", text, &uncloaked, vec![], vec![], "UNCLOAKED_FOR_CLIENT").sequence;
        (chain.get_merkle_root(), seq)
    });

    Ok(Json(json!({
        "status": "success",
        "cloak_request_id": req_id,
        "cloaked_text": text,
        "uncloaked_text": uncloaked,
        "tokens_unresolved_count": unresolved,
        "merkle_root": root,
        "event_sequence": seq
    })))
}
