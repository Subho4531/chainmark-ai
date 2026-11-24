use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use chainmark_proxy::{config::ProxyConfig, create_app, state::AppState};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = ProxyConfig::from_env();
    let addr = SocketAddr::new(
        config.host.parse().expect("valid IP address"),
        config.port,
    );

    let state = AppState::new_with_db(config).await;
    let app = create_app(state);

    tracing::info!("Chainmark AI Rust Gateway listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.expect("Failed to bind port");
    axum::serve(listener, app).await.expect("Server failed to run");
}
