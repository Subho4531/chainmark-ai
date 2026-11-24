use regex::Regex;
use std::sync::LazyLock;

static MRN_REGEX_1: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:MRN|PAT|EHR)[-:\s]+([A-Z0-9]{6,12})\b").expect("valid MRN regex 1")
});

static MRN_REGEX_2: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bRECORD[-:\s]*#?([0-9]{6,10})\b").expect("valid MRN regex 2")
});

pub fn validate_mrn(mrn_str: &str) -> bool {
    let cleaned = mrn_str.trim();
    MRN_REGEX_1.is_match(cleaned) || MRN_REGEX_2.is_match(cleaned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mrn_validation() {
        assert!(validate_mrn("Patient MRN-948201 has scheduled appointment"));
        assert!(validate_mrn("EHR: A89201F"));
        assert!(!validate_mrn("Regular text without medical identifiers"));
    }
}
