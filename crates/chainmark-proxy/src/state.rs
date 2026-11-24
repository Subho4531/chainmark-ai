use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use chainmark_detectors::SessionTaintEngine;
use chainmark_evidence::{EvidenceSigner, MerkleHashChain};
use chainmark_vault::TokenVault;
use reqwest::Client;

use crate::config::ProxyConfig;

#[derive(Clone)]
pub struct AppState {
    pub config: ProxyConfig,
    pub taint_engine: Arc<SessionTaintEngine>,
    pub vault: TokenVault,
    pub signer: Arc<EvidenceSigner>,
    pub chains: Arc<Mutex<HashMap<String, MerkleHashChain>>>,
    pub http_client: Client,
}

impl AppState {
    pub fn new(config: ProxyConfig) -> Self {
        let vault = TokenVault::new(config.vault_master_key);
        let taint_engine = Arc::new(SessionTaintEngine::new(10));
        let signer = Arc::new(EvidenceSigner::new());
        let chains = Arc::new(Mutex::new(HashMap::new()));
        let http_client = Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .expect("valid reqwest client");

        Self {
            config,
            taint_engine,
            vault,
            signer,
            chains,
            http_client,
        }
    }

    pub fn with_chain<F, R>(&self, session_id: &str, f: F) -> R
    where
        F: FnOnce(&mut MerkleHashChain) -> R,
    {
        let mut chains = self.chains.lock().unwrap();
        let chain = chains
            .entry(session_id.to_string())
            .or_insert_with(|| MerkleHashChain::new(session_id));
        f(chain)
    }
}
