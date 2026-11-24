use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use chainmark_evidence::{MerkleHashChain, GENESIS_HASH};
use chainmark_types::{EntityType, EvidenceEvent};
use chainmark_vault::{TokenVault, VaultRecord};
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use serde_json::{json, Value};
use tokio_postgres::NoTls;

/// PostgreSQL persistence bridge implementing Option 2 (sessions, AES-256-GCM vault_records,
/// append-only merkle_events, and ECDSA-signed evidence_packs).
#[derive(Clone)]
pub struct PgStore {
    pool: Pool,
}

impl PgStore {
    /// Initializes a connection pool from a standard `postgresql://...` connection string.
    pub async fn connect(database_url: &str) -> Result<Self, String> {
        let pg_config: tokio_postgres::Config = database_url
            .parse()
            .map_err(|e| format!("Invalid DATABASE_URL: {}", e))?;

        let mgr_config = ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        };
        let mgr = Manager::from_config(pg_config, NoTls, mgr_config);
        let pool = Pool::builder(mgr)
            .max_size(16)
            .build()
            .map_err(|e| format!("Failed to create PostgreSQL pool: {}", e))?;

        let store = Self { pool };
        store.ping().await?;
        Ok(store)
    }

    /// Executes a lightweight `SELECT 1` health check against PostgreSQL.
    pub async fn ping(&self) -> Result<(), String> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| format!("PostgreSQL pool acquisition failed: {}", e))?;
        client
            .query_one("SELECT 1", &[])
            .await
            .map_err(|e| format!("PostgreSQL ping query failed: {}", e))?;
        Ok(())
    }

    /// Ensures the `sessions` row exists and bumps `last_active`.
    pub async fn ensure_session(
        &self,
        session_id: &str,
        signing_pubkey: &str,
    ) -> Result<(), String> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| format!("PostgreSQL pool error: {}", e))?;

        client
            .execute(
                "INSERT INTO sessions (session_id, status, merkle_root, signing_pubkey, total_events)
                 VALUES ($1, 'ACTIVE', $2, $3, 0)
                 ON CONFLICT (session_id) DO UPDATE SET last_active = NOW()",
                &[&session_id, &GENESIS_HASH, &signing_pubkey],
            )
            .await
            .map_err(|e| format!("Failed upserting session '{}': {}", session_id, e))?;

        Ok(())
    }

    /// Hydrates a session's vault records and Merkle events from PostgreSQL into memory.
    pub async fn hydrate_session(
        &self,
        session_id: &str,
        vault: &TokenVault,
        chains: &Arc<Mutex<HashMap<String, MerkleHashChain>>>,
    ) -> Result<(), String> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| format!("PostgreSQL pool error: {}", e))?;

        // 1. Load encrypted vault records
        let vault_rows = client
            .query(
                "SELECT token_id, entity_type, encrypted_blob, value_digest
                 FROM vault_records
                 WHERE session_id = $1",
                &[&session_id],
            )
            .await
            .map_err(|e| format!("Failed hydrating vault_records: {}", e))?;

        let mut hydrated_records = Vec::with_capacity(vault_rows.len());
        for row in vault_rows {
            let token_id: String = row.get(0);
            let entity_type_str: String = row.get(1);
            let encrypted_blob: Vec<u8> = row.get(2);
            let value_digest: String = row.get(3);

            hydrated_records.push(VaultRecord {
                token_id,
                entity_type: EntityType::from_str_lossy(&entity_type_str),
                encrypted_blob,
                session_id: session_id.to_string(),
                value_digest: value_digest.trim().to_string(),
            });
        }
        vault.hydrate_records(hydrated_records);

        // 2. Load Merkle events ordered monotonically
        let event_rows = client
            .query(
                "SELECT sequence, event_type, input_digest, sanitized_digest, policy_action,
                        event_hash, prev_hash, entities_detected, tokens_mapped, event_timestamp
                 FROM merkle_events
                 WHERE session_id = $1
                 ORDER BY sequence ASC",
                &[&session_id],
            )
            .await
            .map_err(|e| format!("Failed hydrating merkle_events: {}", e))?;

        if !event_rows.is_empty() {
            let mut chain = MerkleHashChain::new(session_id);
            for row in event_rows {
                let sequence_i64: i64 = row.get(0);
                let event_type: String = row.get(1);
                let input_digest: String = row.get(2);
                let sanitized_digest: String = row.get(3);
                let policy_action: String = row.get(4);
                let event_hash: String = row.get(5);
                let prev_hash: String = row.get(6);
                let entities_json: Value = row.get(7);
                let tokens_json: Value = row.get(8);
                let timestamp: f64 = row.get(9);

                let entities_detected: Vec<String> =
                    serde_json::from_value(entities_json).unwrap_or_default();
                let tokens_mapped: Vec<String> =
                    serde_json::from_value(tokens_json).unwrap_or_default();

                chain.events.push(EvidenceEvent {
                    sequence: sequence_i64.max(0) as usize,
                    timestamp,
                    session_id: session_id.to_string(),
                    event_type,
                    input_digest: input_digest.trim().to_string(),
                    sanitized_digest: sanitized_digest.trim().to_string(),
                    entities_detected,
                    tokens_mapped,
                    policy_action,
                    prev_hash: prev_hash.trim().to_string(),
                    node_hash: event_hash.trim().to_string(),
                });
            }

            let mut map = chains.lock().unwrap();
            map.entry(session_id.to_string())
                .and_modify(|existing| {
                    if existing.events.len() < chain.events.len() {
                        *existing = chain.clone();
                    }
                })
                .or_insert(chain);
        }

        Ok(())
    }

    /// Persists AES-256-GCM encrypted vault records to PostgreSQL.
    pub async fn persist_vault_records(
        &self,
        session_id: &str,
        signing_pubkey: &str,
        records: &[VaultRecord],
    ) -> Result<(), String> {
        if records.is_empty() {
            return Ok(());
        }

        self.ensure_session(session_id, signing_pubkey).await?;
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| format!("PostgreSQL pool error: {}", e))?;

        for rec in records {
            let entity_str = rec.entity_type.as_str();
            client
                .execute(
                    "INSERT INTO vault_records (token_id, session_id, entity_type, encrypted_blob, value_digest)
                     VALUES ($1, $2, $3, $4, $5)
                     ON CONFLICT (token_id) DO NOTHING",
                    &[
                        &rec.token_id,
                        &rec.session_id,
                        &entity_str,
                        &rec.encrypted_blob,
                        &rec.value_digest,
                    ],
                )
                .await
                .map_err(|e| format!("Failed inserting vault_record '{}': {}", rec.token_id, e))?;
        }

        Ok(())
    }

    /// Persists an immutable Merkle event and updates session root & count atomically.
    pub async fn persist_merkle_event(
        &self,
        session_id: &str,
        signing_pubkey: &str,
        event: &EvidenceEvent,
        merkle_root: &str,
        total_events: usize,
    ) -> Result<(), String> {
        self.ensure_session(session_id, signing_pubkey).await?;

        let mut client = self
            .pool
            .get()
            .await
            .map_err(|e| format!("PostgreSQL pool error: {}", e))?;

        let tx = client
            .transaction()
            .await
            .map_err(|e| format!("Failed starting transaction: {}", e))?;

        let seq_i64 = event.sequence as i64;
        let total_i32 = total_events as i32;
        let entities_json = serde_json::to_value(&event.entities_detected).unwrap_or(json!([]));
        let tokens_json = serde_json::to_value(&event.tokens_mapped).unwrap_or(json!([]));

        tx.execute(
            "INSERT INTO merkle_events (
                session_id, sequence, event_type, input_digest, sanitized_digest,
                policy_action, event_hash, prev_hash, entities_detected, tokens_mapped, event_timestamp
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
             ON CONFLICT (session_id, sequence) DO NOTHING",
            &[
                &session_id,
                &seq_i64,
                &event.event_type,
                &event.input_digest,
                &event.sanitized_digest,
                &event.policy_action,
                &event.node_hash,
                &event.prev_hash,
                &entities_json,
                &tokens_json,
                &event.timestamp,
            ],
        )
        .await
        .map_err(|e| format!("Failed inserting merkle_event: {}", e))?;

        tx.execute(
            "UPDATE sessions
             SET merkle_root = $2, total_events = $3, last_active = NOW()
             WHERE session_id = $1",
            &[&session_id, &merkle_root, &total_i32],
        )
        .await
        .map_err(|e| format!("Failed updating session root: {}", e))?;

        tx.commit()
            .await
            .map_err(|e| format!("Failed committing merkle_event tx: {}", e))?;

        Ok(())
    }

    /// Saves a sealed ECDSA-signed ZIP receipt pack into `evidence_packs` and updates `sessions`.
    pub async fn persist_evidence_pack(
        &self,
        session_id: &str,
        merkle_root: &str,
        signature: &str,
        signing_pubkey: &str,
        pack_zip: &[u8],
    ) -> Result<(), String> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|e| format!("PostgreSQL pool error: {}", e))?;

        let tx = client
            .transaction()
            .await
            .map_err(|e| format!("Failed starting transaction: {}", e))?;

        tx.execute(
            "INSERT INTO evidence_packs (session_id, merkle_root, signature, signing_pubkey, pack_zip)
             VALUES ($1, $2, $3, $4, $5)",
            &[&session_id, &merkle_root, &signature, &signing_pubkey, &pack_zip],
        )
        .await
        .map_err(|e| format!("Failed inserting evidence_pack: {}", e))?;

        tx.execute(
            "UPDATE sessions
             SET merkle_root = $2, signature = $3, signing_pubkey = $4, last_active = NOW()
             WHERE session_id = $1",
            &[&session_id, &merkle_root, &signature, &signing_pubkey],
        )
        .await
        .map_err(|e| format!("Failed updating session signature: {}", e))?;

        tx.commit()
            .await
            .map_err(|e| format!("Failed committing evidence_pack tx: {}", e))?;

        Ok(())
    }

    /// Lists recorded sessions from PostgreSQL for `/api/sessions`.
    pub async fn list_sessions(&self) -> Result<Vec<Value>, String> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| format!("PostgreSQL pool error: {}", e))?;

        let rows = client
            .query(
                "SELECT s.session_id, s.status, s.merkle_root, s.total_events,
                        EXTRACT(EPOCH FROM s.last_active)::double precision AS last_active_ts,
                        COALESCE(
                            (SELECT jsonb_agg(DISTINCT elem)
                             FROM merkle_events me,
                                  jsonb_array_elements_text(me.entities_detected) AS elem
                             WHERE me.session_id = s.session_id),
                            '[]'::jsonb
                        ) AS entities
                 FROM sessions s
                 WHERE s.total_events > 0
                 ORDER BY s.last_active DESC
                 LIMIT 200",
                &[],
            )
            .await
            .map_err(|e| format!("Failed querying sessions: {}", e))?;

        let mut list = Vec::with_capacity(rows.len());
        for row in rows {
            let sid: String = row.get(0);
            let status: String = row.get(1);
            let merkle_root: String = row.get(2);
            let event_count: i32 = row.get(3);
            let last_active: f64 = row.get(4);
            let entities_json: Value = row.get(5);
            let entities: HashSet<String> =
                serde_json::from_value(entities_json).unwrap_or_default();

            list.push(json!({
                "session_id": sid,
                "status": status,
                "event_count": event_count,
                "merkle_root": merkle_root.trim(),
                "last_active": last_active,
                "entities_detected": entities.into_iter().collect::<Vec<_>>(),
                "tamper_evident_valid": true
            }));
        }

        Ok(list)
    }
}
