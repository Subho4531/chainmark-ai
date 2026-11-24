use regex::Regex;
use std::sync::LazyLock;

static SSN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\b(\d{3})-?(\d{2})-?(\d{4})\b$").expect("valid SSN regex")
});

pub fn validate_ssn(ssn_str: &str) -> bool {
    let cleaned = ssn_str.trim();
    if let Some(caps) = SSN_REGEX.captures(cleaned) {
        let area = caps.get(1).map_or("", |m| m.as_str());
        let group = caps.get(2).map_or("", |m| m.as_str());
        let serial = caps.get(3).map_or("", |m| m.as_str());

        // Area: cannot be 000, 666, or 900-999
        if area == "000" || area == "666" || area.starts_with('9') {
            return false;
        }
        // Group: cannot be 00
        if group == "00" {
            return false;
        }
        // Serial: cannot be 0000
        if serial == "0000" {
            return false;
        }
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssn_validation() {
        assert!(validate_ssn("123-45-6789"));
        assert!(validate_ssn("123456789"));
        assert!(!validate_ssn("000-12-3456"));
        assert!(!validate_ssn("666-12-3456"));
        assert!(!validate_ssn("950-12-3456"));
        assert!(!validate_ssn("123-00-6789"));
        assert!(!validate_ssn("123-45-0000"));
    }
}
