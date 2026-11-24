use std::env;

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub host: String,
    pub port: u16,
    pub upstream_openai_url: String,
    pub upstream_anthropic_url: String,
    pub upstream_mcp_url: String,
    pub vault_master_key: [u8; 32],
    pub fail_closed: bool,
    pub database_url: Option<String>,
}

impl ProxyConfig {
    /// Reads configuration from environment variables (loading `.env` if present).
    pub fn from_env() -> Self {
        let _ = dotenvy::dotenv();

        let host = env::var("CHAINMARK_HOST")
            .or_else(|_| env::var("HOST"))
            .unwrap_or_else(|_| "0.0.0.0".to_string());
        let port: u16 = env::var("CHAINMARK_PORT")
            .or_else(|_| env::var("PORT"))
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8000);

        let upstream_openai_url = env::var("CHAINMARK_UPSTREAM_OPENAI_URL")
            .unwrap_or_else(|_| "https://api.openai.com/v1".to_string());

        let upstream_anthropic_url = env::var("CHAINMARK_UPSTREAM_ANTHROPIC_URL")
            .unwrap_or_else(|_| "https://api.anthropic.com/v1".to_string());

        let upstream_mcp_url = env::var("CHAINMARK_UPSTREAM_MCP_URL")
            .unwrap_or_else(|_| "http://localhost:3000".to_string());

        let key_hex = env::var("CHAINMARK_VAULT_MASTER_KEY")
            .or_else(|_| env::var("CHAINMARK_MASTER_KEY"))
            .unwrap_or_default();
        let mut key = [42u8; 32];
        if let Ok(bytes) = hex::decode(key_hex.trim()) {
            if bytes.len() == 32 {
                key.copy_from_slice(&bytes);
            }
        }

        let fail_closed = env::var("FAIL_CLOSED")
            .or_else(|_| env::var("CHAINMARK_FAIL_CLOSED"))
            .map(|v| v.to_ascii_lowercase() != "false")
            .unwrap_or(true);

        let database_url = env::var("DATABASE_URL")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        Self {
            host,
            port,
            upstream_openai_url,
            upstream_anthropic_url,
            upstream_mcp_url,
            vault_master_key: key,
            fail_closed,
            database_url,
        }
    }
}

impl Default for ProxyConfig {
    /// Returns in-memory test-friendly defaults without connecting to external DB unless explicitly provided.
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8000,
            upstream_openai_url: "https://api.openai.com/v1".to_string(),
            upstream_anthropic_url: "https://api.anthropic.com/v1".to_string(),
            upstream_mcp_url: "http://localhost:3000".to_string(),
            vault_master_key: [42u8; 32],
            fail_closed: true,
            database_url: None,
        }
    }
}
