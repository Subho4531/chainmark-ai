use regex::Regex;
use std::sync::LazyLock;

static PAN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Z]{5}[0-9]{4}[A-Z]{1}$").expect("valid PAN regex")
});

const VALID_4TH_CHARS: &[char] = &['C', 'P', 'H', 'F', 'A', 'T', 'B', 'L', 'J', 'G'];

pub fn validate_pan(pan_str: &str) -> bool {
    let cleaned = pan_str.trim().to_uppercase();
    if !PAN_REGEX.is_match(&cleaned) {
        return false;
    }

    let fourth_char = match cleaned.chars().nth(3) {
        Some(c) => c,
        None => return false,
    };

    VALID_4TH_CHARS.contains(&fourth_char)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pan_validation() {
        assert!(validate_pan("ABCPE1234F"));
        assert!(validate_pan("abcpe1234f"));
        assert!(!validate_pan("ABCDE1234F")); // 'D' is not valid
        assert!(!validate_pan("ABC1234"));
    }
}
