use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EntityType {
    Aadhaar,
    CreditCard,
    Pan,
    Ssn,
    Mrn,
    Email,
    Phone,
    Iban,
    ApiKey,
    Unknown,
}

impl EntityType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EntityType::Aadhaar => "AADHAAR",
            EntityType::CreditCard => "CREDIT_CARD",
            EntityType::Pan => "PAN",
            EntityType::Ssn => "SSN",
            EntityType::Mrn => "MRN",
            EntityType::Email => "EMAIL",
            EntityType::Phone => "PHONE",
            EntityType::Iban => "IBAN",
            EntityType::ApiKey => "API_KEY",
            EntityType::Unknown => "UNKNOWN",
        }
    }
}

impl std::fmt::Display for EntityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectedEntity {
    pub entity_type: EntityType,
    pub raw_value: String,
    pub confidence: f32,
    pub is_fragment_assembly: bool,
    pub provenance_turns: Vec<usize>,
    pub span: Option<(usize, usize)>,
    pub fragments: Vec<(usize, String)>,
}

impl DetectedEntity {
    pub fn new(entity_type: EntityType, raw_value: impl Into<String>, confidence: f32) -> Self {
        Self {
            entity_type,
            raw_value: raw_value.into(),
            confidence,
            is_fragment_assembly: false,
            provenance_turns: Vec::new(),
            span: None,
            fragments: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceEvent {
    pub sequence: usize,
    pub timestamp: f64,
    pub session_id: String,
    pub event_type: String,
    pub input_digest: String,
    pub sanitized_digest: String,
    pub entities_detected: Vec<String>,
    pub tokens_mapped: Vec<String>,
    pub policy_action: String,
    pub prev_hash: String,
    pub node_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionResult {
    pub texts: Vec<String>,
    pub tokens_mapped: Vec<String>,
    pub unresolved: Vec<DetectedEntity>,
}
