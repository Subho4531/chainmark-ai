use std::collections::HashMap;
use std::sync::{Arc, Mutex, LazyLock};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use regex::Regex;
use sha2::Sha256;
use thiserror::Error;

use chainmark_types::{DetectedEntity, EntityType, RedactionResult};

type HmacSha256 = Hmac<Sha256>;

pub const TOKEN_PREFIX: &str = "[CM_TOKEN_";
pub const TOKEN_PATTERN: &str = r"\[CM_TOKEN_[A-Z][A-Z0-9_]*_[a-f0-9]{32}\]";

static TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(TOKEN_PATTERN).expect("valid token regex")
});

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("AES encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("AES decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Token collision detected")]
    TokenCollision,
}

#[derive(Debug, Clone)]
pub struct VaultRecord {
    pub token_id: String,
    pub entity_type: EntityType,
    pub encrypted_blob: Vec<u8>, // 12-byte IV + Ciphertext + Tag
    pub session_id: String,
    pub value_digest: String,
}

#[derive(Clone)]
pub struct TokenVault {
    master_key: [u8; 32],
    cipher: Aes256Gcm,
    records: Arc<Mutex<HashMap<String, VaultRecord>>>,
    session_cache: Arc<Mutex<HashMap<String, HashMap<String, String>>>>,
    session_keys: Arc<Mutex<HashMap<String, [u8; 32]>>>,
}

impl TokenVault {
    pub fn new(master_key: [u8; 32]) -> Self {
        let cipher = Aes256Gcm::new_from_slice(&master_key).expect("32 bytes is valid AES key");
        Self {
            master_key,
            cipher,
            records: Arc::new(Mutex::new(HashMap::new())),
            session_cache: Arc::new(Mutex::new(HashMap::new())),
            session_keys: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn session_key(&self, session_id: &str) -> [u8; 32] {
        let mut keys = self.session_keys.lock().unwrap();
        if let Some(&k) = keys.get(session_id) {
            return k;
        }

        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.master_key).expect("valid HMAC key");
        mac.update(format!("chainmark:session:{}", session_id).as_bytes());
        let result = mac.finalize().into_bytes();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result[..32]);
        keys.insert(session_id.to_string(), key);
        key
    }

    pub fn value_digest(&self, entity_type: EntityType, raw_value: &str, session_id: &str) -> String {
        let key = self.session_key(session_id);
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).expect("valid HMAC key");
        mac.update(format!("{}\0{}", entity_type.as_str(), raw_value).as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    pub fn generate_token_id(&self, entity_type: EntityType, raw_value: &str, session_id: &str) -> String {
        let digest = self.value_digest(entity_type, raw_value, session_id);
        let hex_slice = if digest.len() >= 32 { &digest[..32] } else { &digest };
        format!("{}{}_{}]", TOKEN_PREFIX, entity_type.as_str(), hex_slice)
    }

    pub fn tokenize_value(
        &self,
        entity_type: EntityType,
        raw_value: &str,
        session_id: &str,
    ) -> Result<String, VaultError> {
        let digest = self.value_digest(entity_type, raw_value, session_id);

        {
            let mut cache = self.session_cache.lock().unwrap();
            let session_map = cache.entry(session_id.to_string()).or_default();
            if let Some(existing) = session_map.get(&digest) {
                return Ok(existing.clone());
            }
        }

        let token_id = self.generate_token_id(entity_type, raw_value, session_id);

        let mut iv_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut iv_bytes);
        #[allow(deprecated)]
        let nonce = Nonce::from_slice(&iv_bytes);

        let payload = aes_gcm::aead::Payload {
            msg: raw_value.as_bytes(),
            aad: session_id.as_bytes(),
        };

        let ciphertext = self
            .cipher
            .encrypt(nonce, payload)
            .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;

        let mut encrypted_blob = Vec::with_capacity(12 + ciphertext.len());
        encrypted_blob.extend_from_slice(&iv_bytes);
        encrypted_blob.extend_from_slice(&ciphertext);

        let record = VaultRecord {
            token_id: token_id.clone(),
            entity_type,
            encrypted_blob,
            session_id: session_id.to_string(),
            value_digest: digest.clone(),
        };

        self.records.lock().unwrap().insert(token_id.clone(), record);
        self.session_cache
            .lock()
            .unwrap()
            .entry(session_id.to_string())
            .or_default()
            .insert(digest, token_id.clone());

        Ok(token_id)
    }

    pub fn detokenize_value(&self, token_id: &str, session_id: &str) -> Option<String> {
        let records = self.records.lock().unwrap();
        let record = records.get(token_id)?;
        if record.session_id != session_id || record.encrypted_blob.len() < 12 {
            return None;
        }

        #[allow(deprecated)]
        let nonce = Nonce::from_slice(&record.encrypted_blob[..12]);
        let ciphertext = &record.encrypted_blob[12..];

        let payload = aes_gcm::aead::Payload {
            msg: ciphertext,
            aad: session_id.as_bytes(),
        };

        let decrypted = self.cipher.decrypt(nonce, payload).ok()?;
        String::from_utf8(decrypted).ok()
    }

    pub fn detokenize_text_strict(&self, text: &str, session_id: &str) -> (String, usize) {
        if text.is_empty() {
            return (String::new(), 0);
        }

        let mut unresolved = 0;
        let mut last_end = 0;
        let mut out = String::with_capacity(text.len());

        for m in TOKEN_RE.find_iter(text) {
            out.push_str(&text[last_end..m.start()]);
            let token_str = m.as_str();
            match self.detokenize_value(token_str, session_id) {
                Some(plain) => out.push_str(&plain),
                None => {
                    unresolved += 1;
                    out.push_str(token_str);
                }
            }
            last_end = m.end();
        }
        out.push_str(&text[last_end..]);

        (out, unresolved)
    }

    pub fn detokenize_text(&self, text: &str, session_id: &str) -> String {
        let (out, _) = self.detokenize_text_strict(text, session_id);
        out
    }

    pub fn redact_texts(
        &self,
        texts: &[String],
        entities: &[DetectedEntity],
        session_id: &str,
    ) -> RedactionResult {
        let mut result_texts = texts.to_vec();
        let mut tokens_mapped = Vec::new();

        for entity in entities {
            let token = match self.tokenize_value(entity.entity_type, &entity.raw_value, session_id) {
                Ok(t) => t,
                Err(_) => continue,
            };

            let mut inserted = false;

            // 1. Literal replacement in each text
            for text in result_texts.iter_mut() {
                if text.contains(&entity.raw_value) {
                    *text = text.replace(&entity.raw_value, &token);
                    inserted = true;
                }
            }

            // 2. Fragment replacement for assembled entities
            for &(turn_idx, ref fragment) in &entity.fragments {
                if turn_idx < result_texts.len() && result_texts[turn_idx].contains(fragment) {
                    let frag_token = self.generate_token_id(entity.entity_type, fragment, session_id);
                    let _ = self.tokenize_value(entity.entity_type, fragment, session_id);
                    result_texts[turn_idx] = result_texts[turn_idx].replace(fragment, &frag_token);
                    if !tokens_mapped.contains(&frag_token) {
                        tokens_mapped.push(frag_token);
                    }
                }
            }

            if inserted && !tokens_mapped.contains(&token) {
                tokens_mapped.push(token);
            }
        }

        // Re-scan verification (fail closed assertion)
        let mut unresolved = Vec::new();
        for entity in entities {
            for text in &result_texts {
                if text.contains(&entity.raw_value) {
                    unresolved.push(entity.clone());
                    break;
                }
            }
        }

        RedactionResult {
            texts: result_texts,
            tokens_mapped,
            unresolved,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_roundtrip() {
        let master_key = [7u8; 32];
        let vault = TokenVault::new(master_key);
        let session = "test_sess";
        let raw = "456789012341";

        let token = vault.tokenize_value(EntityType::Aadhaar, raw, session).unwrap();
        assert!(token.starts_with("[CM_TOKEN_AADHAAR_"));
        assert!(token.ends_with(']'));

        let restored = vault.detokenize_value(&token, session).unwrap();
        assert_eq!(restored, raw);

        // Different session cannot decrypt
        assert_eq!(vault.detokenize_value(&token, "other_sess"), None);
    }
}
