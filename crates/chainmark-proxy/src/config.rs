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
}

impl Default for ProxyConfig {
    fn default() -> Self {
        let host = env::var("CHAINMARK_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port: u16 = env::var("CHAINMARK_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8000);

        let upstream_openai_url = env::var("CHAINMARK_UPSTREAM_OPENAI_URL")
            .unwrap_or_else(|_| "https://api.openai.com/v1".to_string());

        let upstream_anthropic_url = env::var("CHAINMARK_UPSTREAM_ANTHROPIC_URL")
            .unwrap_or_else(|_| "https://api.anthropic.com/v1".to_string());

        let upstream_mcp_url = env::var("CHAINMARK_UPSTREAM_MCP_URL")
            .unwrap_or_else(|_| "http://localhost:3000".to_string());

        let key_hex = env::var("CHAINMARK_VAULT_MASTER_KEY").unwrap_or_default();
        let mut key = [42u8; 32];
        if let Ok(bytes) = hex::decode(&key_hex) {
            if bytes.len() == 32 {
                key.copy_from_slice(&bytes);
            }
        }

        Self {
            host,
            port,
            upstream_openai_url,
            upstream_anthropic_url,
            upstream_mcp_url,
            vault_master_key: key,
            fail_closed: true,
        }
    }
}
