use std::collections::HashMap;
use std::sync::LazyLock;
use regex::Regex;
use chainmark_types::{DetectedEntity, EntityType};

use crate::verhoeff::validate_aadhaar;
use crate::luhn::validate_luhn;
use crate::pan::validate_pan;
use crate::ssn::validate_ssn;

static NUM_FRAGMENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b\d{3,10}\b").expect("valid num fragment regex")
});

static CHUNK_4X4_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b\d{4}[-\s]\d{4}\b").expect("valid 4x4 chunk regex")
});

static STRUCTURED_NUM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b\d{2,8}(?:[-\s]\d{2,8})+\b|\b\d{11,19}\b").expect("valid structured num regex")
});

static PAN_MATCH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z]{5}[-\s]?[0-9]{4}[-\s]?[A-Za-z]{1}\b").expect("valid PAN match regex")
});

static SSN_MATCH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("valid SSN match regex")
});

static MRN_MATCH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:MRN|PAT|EHR)[-:\s]?([A-Z0-9]{6,12})\b").expect("valid MRN match regex")
});

#[derive(Debug, Clone)]
pub struct SessionTurn {
    pub turn_index: usize,
    pub role: String,
    pub content: String,
    pub numeric_fragments: Vec<String>,
}

#[derive(Debug, Default)]
pub struct SessionTaintEngine {
    pub max_history_turns: usize,
}

impl SessionTaintEngine {
    pub fn new(max_history_turns: usize) -> Self {
        Self { max_history_turns }
    }

    pub fn extract_candidate_fragments(&self, text: &str) -> Vec<String> {
        let mut num_matches: Vec<String> = NUM_FRAGMENT_RE
            .find_iter(text)
            .map(|m| m.as_str().to_string())
            .collect();

        for chunk_match in CHUNK_4X4_RE.find_iter(text) {
            let cleaned: String = chunk_match.as_str().chars().filter(|c| c.is_ascii_digit()).collect();
            if !num_matches.contains(&cleaned) {
                num_matches.push(cleaned);
            }
        }

        num_matches
    }

    pub fn scan_single_text(&self, text: &str) -> Vec<DetectedEntity> {
        let mut detections = Vec::new();

        // 1. Structured Numeric IDs: Aadhaar (12 digits) and Cards (11-19 digits)
        for m in STRUCTURED_NUM_RE.find_iter(text) {
            let candidate = m.as_str();
            let cleaned: String = candidate.chars().filter(|c| c.is_ascii_digit()).collect();
            if cleaned.len() == 12 && validate_aadhaar(&cleaned) {
                let mut ent = DetectedEntity::new(EntityType::Aadhaar, candidate, 1.0);
                ent.span = Some((m.start(), m.end()));
                detections.push(ent);
            } else if cleaned.len() >= 11 && cleaned.len() <= 19 && validate_luhn(&cleaned) {
                let mut ent = DetectedEntity::new(EntityType::CreditCard, candidate, 1.0);
                ent.span = Some((m.start(), m.end()));
                detections.push(ent);
            }
        }

        // 2. PAN Card
        for m in PAN_MATCH_RE.find_iter(text) {
            let candidate = m.as_str();
            let cleaned: String = candidate.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
            if validate_pan(&cleaned) {
                let mut ent = DetectedEntity::new(EntityType::Pan, candidate, 1.0);
                ent.span = Some((m.start(), m.end()));
                detections.push(ent);
            }
        }

        // 3. US SSN
        for m in SSN_MATCH_RE.find_iter(text) {
            let candidate = m.as_str();
            if validate_ssn(candidate) {
                let mut ent = DetectedEntity::new(EntityType::Ssn, candidate, 1.0);
                ent.span = Some((m.start(), m.end()));
                detections.push(ent);
            }
        }

        // 4. MRN
        for m in MRN_MATCH_RE.find_iter(text) {
            let mut ent = DetectedEntity::new(EntityType::Mrn, m.as_str(), 0.9);
            ent.span = Some((m.start(), m.end()));
            detections.push(ent);
        }

        detections
    }

    pub fn process_messages(&self, _session_id: &str, messages: &[(&str, &str)]) -> Vec<DetectedEntity> {
        let mut all_detections = Vec::new();

        // 1. Single-turn detections
        for (i, &(_role, content)) in messages.iter().enumerate() {
            let single_entities = self.scan_single_text(content);
            for mut entity in single_entities {
                entity.provenance_turns = vec![i];
                all_detections.push(entity);
            }
        }

        // 2. Multi-turn jigsaw assembly
        let mut turn_fragments: Vec<(usize, Vec<String>)> = Vec::new();
        for (i, &(_role, content)) in messages.iter().enumerate() {
            let nums = self.extract_candidate_fragments(content);
            if !nums.is_empty() {
                turn_fragments.push((i, nums));
            }
        }

        let num_turns = turn_fragments.len();
        for i in 0..num_turns {
            let (turn_i_idx, ref nums_i) = turn_fragments[i];

            // Same turn combinations
            for (a_idx, num_a) in nums_i.iter().enumerate() {
                for num_b in nums_i.iter().skip(a_idx + 1) {
                    let joined = format!("{}{}", num_a, num_b);
                    if joined.len() == 12 && validate_aadhaar(&joined) {
                        let mut ent = DetectedEntity::new(EntityType::Aadhaar, &joined, 1.0);
                        ent.is_fragment_assembly = true;
                        ent.provenance_turns = vec![turn_i_idx];
                        ent.fragments = vec![(turn_i_idx, num_a.clone()), (turn_i_idx, num_b.clone())];
                        all_detections.push(ent);
                    } else if (11..=19).contains(&joined.len()) && validate_luhn(&joined) {
                        let mut ent = DetectedEntity::new(EntityType::CreditCard, &joined, 1.0);
                        ent.is_fragment_assembly = true;
                        ent.provenance_turns = vec![turn_i_idx];
                        ent.fragments = vec![(turn_i_idx, num_a.clone()), (turn_i_idx, num_b.clone())];
                        all_detections.push(ent);
                    }
                }
            }

            // Cross-turn combinations
            for num_a in nums_i {
                for j in (i + 1)..num_turns {
                    let (turn_j_idx, ref nums_j) = turn_fragments[j];
                    for num_b in nums_j {
                        let joined = format!("{}{}", num_a, num_b);
                        if joined.len() == 12 && validate_aadhaar(&joined) {
                            let mut ent = DetectedEntity::new(EntityType::Aadhaar, &joined, 1.0);
                            ent.is_fragment_assembly = true;
                            ent.provenance_turns = vec![turn_i_idx, turn_j_idx];
                            ent.fragments = vec![(turn_i_idx, num_a.clone()), (turn_j_idx, num_b.clone())];
                            all_detections.push(ent);
                        } else if (11..=19).contains(&joined.len()) && validate_luhn(&joined) {
                            let mut ent = DetectedEntity::new(EntityType::CreditCard, &joined, 1.0);
                            ent.is_fragment_assembly = true;
                            ent.provenance_turns = vec![turn_i_idx, turn_j_idx];
                            ent.fragments = vec![(turn_i_idx, num_a.clone()), (turn_j_idx, num_b.clone())];
                            all_detections.push(ent);
                        }

                        // 3-turn concatenation for Aadhaar
                        for k in (j + 1)..num_turns {
                            let (turn_k_idx, ref nums_k) = turn_fragments[k];
                            for num_c in nums_k {
                                let joined_3 = format!("{}{}{}", num_a, num_b, num_c);
                                if joined_3.len() == 12 && validate_aadhaar(&joined_3) {
                                    let mut ent = DetectedEntity::new(EntityType::Aadhaar, &joined_3, 1.0);
                                    ent.is_fragment_assembly = true;
                                    ent.provenance_turns = vec![turn_i_idx, turn_j_idx, turn_k_idx];
                                    ent.fragments = vec![
                                        (turn_i_idx, num_a.clone()),
                                        (turn_j_idx, num_b.clone()),
                                        (turn_k_idx, num_c.clone()),
                                    ];
                                    all_detections.push(ent);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Deduplicate
        let mut by_key: HashMap<(EntityType, String), DetectedEntity> = HashMap::new();
        for d in all_detections {
            let key = (d.entity_type, d.raw_value.clone());
            match by_key.get_mut(&key) {
                Some(existing) => {
                    for turn in d.provenance_turns {
                        if !existing.provenance_turns.contains(&turn) {
                            existing.provenance_turns.push(turn);
                        }
                    }
                    for frag in d.fragments {
                        if !existing.fragments.contains(&frag) {
                            existing.fragments.push(frag);
                        }
                    }
                    if d.confidence > existing.confidence {
                        existing.confidence = d.confidence;
                    }
                    existing.is_fragment_assembly = existing.is_fragment_assembly || d.is_fragment_assembly;
                }
                None => {
                    by_key.insert(key, d);
                }
            }
        }

        by_key.into_values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verhoeff::generate_verhoeff_checksum;

    #[test]
    fn test_taint_engine_jigsaw_assembly() {
        let engine = SessionTaintEngine::new(10);
        let base = "34567890123";
        let check = generate_verhoeff_checksum(base);
        let full = format!("{}{}", base, check);

        let p1 = &full[0..4];
        let p2 = &full[4..8];
        let p3 = &full[8..12];

        let messages = vec![
            ("user", format!("First part is {}", p1)),
            ("assistant", "Noted".to_string()),
            ("tool", format!("Tool returned middle: {}", p2)),
            ("user", format!("Ending digits: {}", p3)),
        ];

        let msg_refs: Vec<(&str, &str)> = messages.iter().map(|(r, c)| (*r, c.as_str())).collect();
        let detections = engine.process_messages("session_test", &msg_refs);

        let aadhaar_matches: Vec<_> = detections.iter().filter(|d| d.entity_type == EntityType::Aadhaar).collect();
        assert!(!aadhaar_matches.is_empty());
        assert_eq!(aadhaar_matches[0].raw_value, full);
        assert!(aadhaar_matches[0].is_fragment_assembly);
        assert_eq!(aadhaar_matches[0].provenance_turns, vec![0, 2, 3]);
    }
}
