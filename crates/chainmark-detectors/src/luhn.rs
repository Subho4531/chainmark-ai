pub fn validate_luhn(card_str: &str) -> bool {
    let digits: Vec<u32> = card_str
        .chars()
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() < 11 || digits.len() > 19 {
        return false;
    }

    let mut checksum = 0;
    for (i, &digit) in digits.iter().rev().enumerate() {
        if i % 2 == 1 {
            let doubled = digit * 2;
            checksum += if doubled < 10 { doubled } else { doubled - 9 };
        } else {
            checksum += digit;
        }
    }

    checksum % 10 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_luhn_algorithm() {
        assert!(validate_luhn("49927398716"));
        assert!(!validate_luhn("49927398717"));
        assert!(validate_luhn("79927398713"));
        assert!(!validate_luhn("79927398710"));
    }
}
