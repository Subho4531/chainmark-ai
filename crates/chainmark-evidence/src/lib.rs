use std::io::{Cursor, Write};
use base64::prelude::*;
use p256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use rand::rngs::OsRng;
use serde_json::json;
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

use chainmark_types::EvidenceEvent;

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub fn compute_event_hash(event: &EvidenceEvent) -> String {
    let mut sorted_entities = event.entities_detected.clone();
    sorted_entities.sort();
    let mut sorted_tokens = event.tokens_mapped.clone();
    sorted_tokens.sort();

    let payload = json!({
        "sequence": event.sequence,
        "timestamp": event.timestamp,
        "session_id": event.session_id,
        "event_type": event.event_type,
        "input_digest": event.input_digest,
        "sanitized_digest": event.sanitized_digest,
        "entities_detected": sorted_entities,
        "tokens_mapped": sorted_tokens,
        "policy_action": event.policy_action,
        "prev_hash": event.prev_hash,
    });

    let canonical = serde_json::to_string(&payload).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

#[derive(Debug, Clone)]
pub struct MerkleHashChain {
    pub session_id: String,
    pub events: Vec<EvidenceEvent>,
}

impl MerkleHashChain {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            events: Vec::new(),
        }
    }

    pub fn append_event(
        &mut self,
        event_type: &str,
        raw_input: &str,
        sanitized_output: &str,
        entities_detected: Vec<String>,
        tokens_mapped: Vec<String>,
        policy_action: &str,
    ) -> &EvidenceEvent {
        let seq = self.events.len();
        let prev_hash = match self.events.last() {
            Some(e) => e.node_hash.clone(),
            None => GENESIS_HASH.to_string(),
        };

        let mut input_hasher = Sha256::new();
        input_hasher.update(raw_input.as_bytes());
        let input_digest = hex::encode(input_hasher.finalize());

        let mut out_hasher = Sha256::new();
        out_hasher.update(sanitized_output.as_bytes());
        let sanitized_digest = hex::encode(out_hasher.finalize());

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        let mut event = EvidenceEvent {
            sequence: seq,
            timestamp: now,
            session_id: self.session_id.clone(),
            event_type: event_type.to_string(),
            input_digest,
            sanitized_digest,
            entities_detected,
            tokens_mapped,
            policy_action: policy_action.to_string(),
            prev_hash,
            node_hash: String::new(),
        };

        event.node_hash = compute_event_hash(&event);
        self.events.push(event);
        self.events.last().unwrap()
    }

    pub fn get_merkle_root(&self) -> String {
        if self.events.is_empty() {
            return GENESIS_HASH.to_string();
        }

        let mut current_level: Vec<String> = self.events.iter().map(|e| e.node_hash.clone()).collect();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for i in (0..current_level.len()).step_by(2) {
                let left = &current_level[i];
                let right = if i + 1 < current_level.len() {
                    &current_level[i + 1]
                } else {
                    left
                };
                let mut hasher = Sha256::new();
                hasher.update(format!("{}{}", left, right).as_bytes());
                next_level.push(hex::encode(hasher.finalize()));
            }
            current_level = next_level;
        }

        current_level[0].clone()
    }

    pub fn verify_chain(&self) -> (bool, Option<String>) {
        let mut prev_hash = GENESIS_HASH.to_string();

        for (i, event) in self.events.iter().enumerate() {
            if event.sequence != i {
                return (false, Some(format!("Sequence gap at index {}: expected {}, got {}", i, i, event.sequence)));
            }

            if event.prev_hash != prev_hash {
                return (false, Some(format!("Hash chain broken at index {}: invalid prev_hash", i)));
            }

            let computed = compute_event_hash(event);
            if computed != event.node_hash {
                return (false, Some(format!("Node hash tampering at sequence index {}", i)));
            }

            prev_hash = computed;
        }

        (true, None)
    }
}

pub struct EvidenceSigner {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl EvidenceSigner {
    pub fn new() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);
        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn get_public_key_pem(&self) -> String {
        self.verifying_key
            .to_public_key_pem(p256::pkcs8::LineEnding::LF)
            .unwrap_or_default()
    }

    pub fn sign_root(&self, root_hash: &str) -> String {
        let signature: Signature = self.signing_key.sign(root_hash.as_bytes());
        BASE64_STANDARD.encode(signature.to_der())
    }

    pub fn verify_signature(public_key_pem: &str, root_hash: &str, signature_b64: &str) -> bool {
        let verifying_key = match VerifyingKey::from_public_key_pem(public_key_pem) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let sig_bytes = match BASE64_STANDARD.decode(signature_b64) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let signature = match Signature::from_der(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };

        verifying_key.verify(root_hash.as_bytes(), &signature).is_ok()
    }

    pub fn build_evidence_pack(&self, chain: &MerkleHashChain) -> Result<Vec<u8>, String> {
        let (is_valid, err) = chain.verify_chain();
        if !is_valid {
            return Err(format!("Cannot package corrupted chain: {:?}", err));
        }

        let root_hash = chain.get_merkle_root();
        let sig_b64 = self.sign_root(&root_hash);
        let pubkey_pem = self.get_public_key_pem();

        let manifest = json!({
            "version": "1.0",
            "spec": "CHAINMARK-EVIDENCE-RFC3161",
            "session_id": chain.session_id,
            "total_events": chain.events.len(),
            "merkle_root": root_hash,
            "signature": sig_b64,
            "public_key": pubkey_pem,
        });

        let mut events_lines = Vec::new();
        for e in &chain.events {
            events_lines.push(serde_json::to_string(e).unwrap_or_default());
        }
        let events_jsonl = events_lines.join("\n");

        let mut buffer = Cursor::new(Vec::new());
        {
            let mut zip = ZipWriter::new(&mut buffer);
            let options = SimpleFileOptions::default();

            zip.start_file("manifest.json", options).map_err(|e| e.to_string())?;
            zip.write_all(serde_json::to_string_pretty(&manifest).unwrap().as_bytes()).map_err(|e| e.to_string())?;

            zip.start_file("events.jsonl", options).map_err(|e| e.to_string())?;
            zip.write_all(events_jsonl.as_bytes()).map_err(|e| e.to_string())?;

            zip.start_file("signature.sig", options).map_err(|e| e.to_string())?;
            zip.write_all(sig_b64.as_bytes()).map_err(|e| e.to_string())?;

            zip.start_file("public_key.pem", options).map_err(|e| e.to_string())?;
            zip.write_all(pubkey_pem.as_bytes()).map_err(|e| e.to_string())?;

            zip.finish().map_err(|e| e.to_string())?;
        }

        Ok(buffer.into_inner())
    }
}

impl Default for EvidenceSigner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_chain_and_signing() {
        let mut chain = MerkleHashChain::new("test_session_evidence");
        chain.append_event("INIT", "hello", "hello", vec![], vec![], "ALLOW");
        chain.append_event("TOOL", "user has PAN ABCPE1234F", "user has [CM_TOKEN_PAN_1]", vec!["PAN".into()], vec!["[CM_TOKEN_PAN_1]".into()], "TOKENIZE_AND_FORWARD");

        let (valid, err) = chain.verify_chain();
        assert!(valid);
        assert!(err.is_none());

        let signer = EvidenceSigner::new();
        let root = chain.get_merkle_root();
        let sig = signer.sign_root(&root);
        let pubkey = signer.get_public_key_pem();

        assert!(EvidenceSigner::verify_signature(&pubkey, &root, &sig));

        let pack = signer.build_evidence_pack(&chain).unwrap();
        assert!(!pack.is_empty());
    }
}
