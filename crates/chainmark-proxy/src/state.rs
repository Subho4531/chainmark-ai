use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use chainmark_detectors::SessionTaintEngine;
use chainmark_evidence::{EvidenceSigner, MerkleHashChain};
use chainmark_types::EvidenceEvent;
use chainmark_vault::TokenVault;
use reqwest::Client;

use crate::config::ProxyConfig;
use crate::db::PgStore;

#[derive(Clone)]
pub struct AppState {
    pub config: ProxyConfig,
    pub taint_engine: Arc<SessionTaintEngine>,
    pub vault: TokenVault,
    pub signer: Arc<EvidenceSigner>,
    pub chains: Arc<Mutex<HashMap<String, MerkleHashChain>>>,
    pub http_client: Client,
    pub db: Option<PgStore>,
    hydrated_sessions: Arc<Mutex<HashSet<String>>>,
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
            db: None,
            hydrated_sessions: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Initializes `AppState` and connects to PostgreSQL when `config.database_url` is present.
    pub async fn new_with_db(config: ProxyConfig) -> Self {
        let mut state = Self::new(config.clone());
        if let Some(ref url) = config.database_url {
            match PgStore::connect(url).await {
                Ok(store) => {
                    tracing::info!("PostgreSQL persistence bridge connected");
                    state.db = Some(store);
                }
                Err(e) => {
                    tracing::error!("Failed connecting to PostgreSQL ({}); falling back to in-memory store", e);
                }
            }
        } else {
            tracing::warn!("DATABASE_URL not set; running with volatile in-memory vault and chains");
        }
        state
    }

    /// Attaches an initialized `PgStore` (primarily used in tests).
    pub fn with_pg_store(mut self, store: PgStore) -> Self {
        self.db = Some(store);
        self
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

    /// Lazily hydrates a session's persisted vault tokens and Merkle events from PostgreSQL.
    pub async fn ensure_hydrated(&self, session_id: &str) {
        let Some(ref store) = self.db else {
            return;
        };

        {
            let hydrated = self.hydrated_sessions.lock().unwrap();
            if hydrated.contains(session_id) {
                return;
            }
        }

        if let Err(e) = store
            .hydrate_session(session_id, &self.vault, &self.chains)
            .await
        {
            tracing::warn!("Failed hydrating session '{}' from PostgreSQL: {}", session_id, e);
            return;
        }

        self.hydrated_sessions
            .lock()
            .unwrap()
            .insert(session_id.to_string());
    }

    /// Persists newly created AES-256-GCM vault records for `tokens` into PostgreSQL.
    pub async fn persist_redaction(&self, session_id: &str, tokens: &[String]) {
        let Some(ref store) = self.db else {
            return;
        };
        if tokens.is_empty() {
            return;
        }

        let records = self.vault.get_records_by_tokens(tokens);
        if records.is_empty() {
            return;
        }

        let pubkey = self.signer.get_public_key_pem();
        if let Err(e) = store.persist_vault_records(session_id, &pubkey, &records).await {
            tracing::error!("Failed persisting vault records for session '{}': {}", session_id, e);
        }
    }

    /// Appends a Merkle event in memory and persists it atomically to PostgreSQL.
    pub async fn record_event(
        &self,
        session_id: &str,
        event_type: &str,
        raw_input: &str,
        sanitized_output: &str,
        entities_detected: Vec<String>,
        tokens_mapped: Vec<String>,
        policy_action: &str,
    ) -> (String, usize) {
        let (event, root, total): (EvidenceEvent, String, usize) = self.with_chain(session_id, |chain| {
            let ev = chain
                .append_event(
                    event_type,
                    raw_input,
                    sanitized_output,
                    entities_detected,
                    tokens_mapped,
                    policy_action,
                )
                .clone();
            let root = chain.get_merkle_root();
            let total = chain.events.len();
            (ev, root, total)
        });

        let seq = event.sequence;
        if let Some(ref store) = self.db {
            let pubkey = self.signer.get_public_key_pem();
            if let Err(e) = store
                .persist_merkle_event(session_id, &pubkey, &event, &root, total)
                .await
            {
                tracing::error!(
                    "Failed persisting merkle event seq={} for session '{}': {}",
                    seq,
                    session_id,
                    e
                );
            }
        }

        (root, seq)
    }
}
