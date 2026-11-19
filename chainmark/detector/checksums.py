"""
Deterministic mathematical checksums and structured identifier validators.
Implements Verhoeff algorithm for Indian Aadhaar, Luhn for Payment Cards,
strict regex + entity grammar for Indian PAN and US SSN.
"""

import re


# Verhoeff tables
_VERHOEFF_D = [
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
]

_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def validate_verhoeff(num_str: str) -> bool:
    """
    Validate a numeric string against the Verhoeff dihedral checksum.
    Returns True if valid, False otherwise.
    """
    cleaned = re.sub(r"\D", "", num_str)
    if not cleaned:
        return False

    c = 0
    # Process digits in reverse order
    for i, digit in enumerate(reversed(cleaned)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(digit)]]
    return c == 0


def generate_verhoeff_checksum(num_str: str) -> int:
    """
    Compute the Verhoeff check digit for an 11-digit base string.
    """
    cleaned = re.sub(r"\D", "", num_str)
    c = 0
    for i, digit in enumerate(reversed(cleaned)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][int(digit)]]
    return _VERHOEFF_INV[c]


def validate_aadhaar(aadhaar_str: str) -> bool:
    """
    Validates an Indian 12-digit Aadhaar number:
    - Exactly 12 digits
    - First digit cannot be 0 or 1
    - Passes the Verhoeff checksum
    """
    cleaned = re.sub(r"\D", "", aadhaar_str)
    if len(cleaned) != 12:
        return False
    if cleaned[0] in ("0", "1"):
        return False
    return validate_verhoeff(cleaned)


def validate_luhn(card_str: str) -> bool:
    """
    Validates a number using the Luhn mod 10 algorithm.
    Accepts 11 to 19 digits.
    """
    cleaned = re.sub(r"\D", "", card_str)
    if not (11 <= len(cleaned) <= 19):
        return False

    digits = [int(d) for d in cleaned]
    checksum = 0
    # Reverse and alternate doubling every second digit
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled if doubled < 10 else doubled - 9
        else:
            checksum += digit

    return checksum % 10 == 0


_PAN_PATTERN = re.compile(r"^[A-Z]{5}[0-9]{4}[A-Z]{1}$")
_PAN_VALID_4TH_CHAR = set("CPHFATBLJG")  # Individual, Company, HUF, Firm, AOP, Trust, Body, Local, Judicial, Gov


def validate_pan(pan_str: str) -> bool:
    """
    Validates an Indian Permanent Account Number (PAN):
    - Exactly 10 chars: 5 uppercase letters, 4 digits, 1 uppercase letter
    - 4th character must be a valid taxpayer status letter
    """
    cleaned = pan_str.strip().upper()
    if not _PAN_PATTERN.match(cleaned):
        return False
    return cleaned[3] in _PAN_VALID_4TH_CHAR


_SSN_PATTERN = re.compile(r"^(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}$")
_SSN_PLAIN_PATTERN = re.compile(r"^(?!000|666|9\d{2})\d{3}(?!00)\d{2}(?!0000)\d{4}$")


def validate_ssn(ssn_str: str) -> bool:
    """
    Validates a US Social Security Number (SSN):
    - Format 000-00-0000 or 9 contiguous digits
    - Disallows invalid area (000, 666, 900-999), group (00), serial (0000)
    """
    cleaned = ssn_str.strip()
    return bool(_SSN_PATTERN.match(cleaned) or _SSN_PLAIN_PATTERN.match(cleaned))


_MRN_PATTERNS = [
    re.compile(r"\b(?:MRN|PAT|EHR)[-:\s]+([A-Z0-9]{6,12})\b", re.IGNORECASE),
    re.compile(r"\bRECORD[-:\s]*#?([0-9]{6,10})\b", re.IGNORECASE),
]


def validate_mrn(mrn_str: str) -> bool:
    """
    Validates medical record number patterns.
    """
    cleaned = mrn_str.strip()
    for pattern in _MRN_PATTERNS:
        if pattern.search(cleaned):
            return True
    return False
