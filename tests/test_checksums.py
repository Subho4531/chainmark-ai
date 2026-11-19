import pytest
from chainmark.detector.checksums import (
    validate_verhoeff,
    generate_verhoeff_checksum,
    validate_aadhaar,
    validate_luhn,
    validate_pan,
    validate_ssn,
    validate_mrn,
)


def test_verhoeff_algorithm():
    # Test valid Verhoeff number generation and validation
    base_11 = "98765432109"
    check_digit = generate_verhoeff_checksum(base_11)
    full_12 = f"{base_11}{check_digit}"

    assert validate_verhoeff(full_12) is True
    # Mutate a digit - must fail
    corrupted = f"{base_11}{(check_digit + 1) % 10}"
    assert validate_verhoeff(corrupted) is False


def test_aadhaar_validation():
    # Valid Aadhaar generated via Verhoeff
    base = "23456789012"
    check = generate_verhoeff_checksum(base)
    valid_aadhaar = f"{base}{check}"

    assert validate_aadhaar(valid_aadhaar) is True
    assert validate_aadhaar(f"{valid_aadhaar[:4]}-{valid_aadhaar[4:8]}-{valid_aadhaar[8:]}") is True

    # Cannot start with 0 or 1
    invalid_start = f"03456789012{generate_verhoeff_checksum('03456789012')}"
    assert validate_aadhaar(invalid_start) is False

    # Short/wrong length
    assert validate_aadhaar("12345678") is False


def test_luhn_algorithm():
    # Valid standard 16-digit card test numbers
    # 49927398716 is a known valid Luhn number
    assert validate_luhn("49927398716") is True
    # Mutating last digit
    assert validate_luhn("49927398717") is False

    # Standard Luhn test
    assert validate_luhn("79927398713") is True
    assert validate_luhn("79927398710") is False


def test_pan_validation():
    # 4th char 'D' is not a valid taxpayer status -> False
    assert validate_pan("ABCDE1234F") is False
    # 'P' is individual -> True
    assert validate_pan("ABCPE1234F") is True
    assert validate_pan("abcpe1234f") is True

    # Invalid length or characters
    assert validate_pan("ABC1234") is False
    assert validate_pan("ABCPE12345") is False
    assert validate_pan("12345ABCDE") is False


def test_ssn_validation():
    assert validate_ssn("123-45-6789") is True
    assert validate_ssn("123456789") is True

    # Disallowed area numbers (000, 666, 900-999)
    assert validate_ssn("000-12-3456") is False
    assert validate_ssn("666-12-3456") is False
    assert validate_ssn("950-12-3456") is False

    # Disallowed group (00) or serial (0000)
    assert validate_ssn("123-00-6789") is False
    assert validate_ssn("123-45-0000") is False


def test_mrn_validation():
    assert validate_mrn("Patient MRN-948201 has scheduled appointment") is True
    assert validate_mrn("EHR: A89201F") is True
    assert validate_mrn("Regular text without medical identifiers") is False
