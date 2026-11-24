use axum::{
    routing::{get, post},
    Router,
};
use tower_http::cors::{Any, CorsLayer};

pub mod config;
pub mod db;
pub mod handlers;
pub mod state;

pub use config::ProxyConfig;
pub use db::PgStore;
pub use state::AppState;

pub fn create_app(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/health", get(handlers::handle_health))
        .route("/v1/chat/completions", post(handlers::handle_chat_completions))
        .route("/v1/messages", post(handlers::handle_messages))
        .route("/mcp/message", post(handlers::handle_mcp_message))
        .route("/mcp", post(handlers::handle_mcp_message))
        .route("/mcp/sse", get(handlers::handle_mcp_sse))
        .route("/cloak", post(handlers::handle_cloak))
        .route("/v1/cloak", post(handlers::handle_cloak))
        .route("/uncloak", post(handlers::handle_uncloak_body))
        .route("/uncloak/:cloak_request_id", post(handlers::handle_uncloak_path).get(handlers::handle_uncloak_path))
        .route("/v1/evidence/export/:session_id", get(handlers::handle_export_evidence))
        .route("/v1/evidence/verify/:session_id", get(handlers::handle_verify_evidence))
        .route("/api/sessions", get(handlers::handle_list_sessions))
        .layer(cors)
        .with_state(state)
}
