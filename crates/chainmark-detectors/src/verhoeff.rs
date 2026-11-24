// Verhoeff dihedral algorithm tables for Indian Aadhaar validation.

pub const VERHOEFF_D: [[usize; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

pub const VERHOEFF_P: [[usize; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

pub const VERHOEFF_INV: [usize; 10] = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

pub fn validate_verhoeff(num_str: &str) -> bool {
    let digits: Vec<usize> = num_str
        .chars()
        .filter_map(|c| c.to_digit(10).map(|d| d as usize))
        .collect();

    if digits.is_empty() {
        return false;
    }

    let mut c = 0;
    for (i, &digit) in digits.iter().rev().enumerate() {
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digit]];
    }

    c == 0
}

pub fn generate_verhoeff_checksum(num_str: &str) -> usize {
    let digits: Vec<usize> = num_str
        .chars()
        .filter_map(|c| c.to_digit(10).map(|d| d as usize))
        .collect();

    let mut c = 0;
    for (i, &digit) in digits.iter().rev().enumerate() {
        c = VERHOEFF_D[c][VERHOEFF_P[(i + 1) % 8][digit]];
    }

    VERHOEFF_INV[c]
}

pub fn validate_aadhaar(aadhaar_str: &str) -> bool {
    let cleaned: String = aadhaar_str.chars().filter(|c| c.is_ascii_digit()).collect();
    if cleaned.len() != 12 {
        return false;
    }

    // First digit cannot be 0 or 1
    if cleaned.starts_with('0') || cleaned.starts_with('1') {
        return false;
    }

    validate_verhoeff(&cleaned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verhoeff_and_aadhaar() {
        let base = "23456789012";
        let check = generate_verhoeff_checksum(base);
        let full = format!("{}{}", base, check);
        assert!(validate_aadhaar(&full));
        assert!(validate_aadhaar(&format!("{}-{}-{}", &full[0..4], &full[4..8], &full[8..12])));

        // Must reject 0 or 1 start
        let invalid_start = format!("03456789012{}", generate_verhoeff_checksum("03456789012"));
        assert!(!validate_aadhaar(&invalid_start));

        // Corrupted digit fails
        let corrupted = format!("{}{}", base, (check + 1) % 10);
        assert!(!validate_aadhaar(&corrupted));
    }
}
