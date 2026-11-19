import pytest
from chainmark.detector.taint_engine import SessionTaintEngine
from chainmark.detector.checksums import generate_verhoeff_checksum


def test_single_turn_detection():
    engine = SessionTaintEngine()

    base_aadhaar = "23456789012"
    check = generate_verhoeff_checksum(base_aadhaar)
    full_aadhaar = f"{base_aadhaar}{check}"

    messages = [
        {"role": "user", "content": f"Please verify my account with Aadhaar {full_aadhaar} and PAN ABCPE1234F"}
    ]

    detections = engine.process_messages("session_1", messages)
    assert len(detections) == 2

    types = {d.entity_type for d in detections}
    assert "AADHAAR" in types
    assert "PAN" in types


def test_multi_turn_jigsaw_assembly():
    engine = SessionTaintEngine()

    # Generate a valid 12-digit Aadhaar split across 3 turns
    base_aadhaar = "34567890123"
    check = generate_verhoeff_checksum(base_aadhaar)
    full_aadhaar = f"{base_aadhaar}{check}"
    assert len(full_aadhaar) == 12

    part1 = full_aadhaar[:4]
    part2 = full_aadhaar[4:8]
    part3 = full_aadhaar[8:]

    messages = [
        {"role": "user", "content": f"My ID first 4 digits are {part1}."},
        {"role": "assistant", "content": "Please provide the rest."},
        {"role": "tool", "content": f"Tool record found middle: {part2}."},
        {"role": "user", "content": f"And the ending digits are {part3}."},
    ]

    # Individual messages don't have a 12-digit Aadhaar
    assert len(engine.scan_single_text(messages[0]["content"])) == 0
    assert len(engine.scan_single_text(messages[2]["content"])) == 0
    assert len(engine.scan_single_text(messages[3]["content"])) == 0

    # But session processing should assemble the jigsaw!
    detections = engine.process_messages("session_jigsaw_1", messages)
    assert len(detections) >= 1

    aadhaar_detections = [d for d in detections if d.entity_type == "AADHAAR"]
    assert len(aadhaar_detections) == 1

    assembled = aadhaar_detections[0]
    assert assembled.raw_value == full_aadhaar
    assert assembled.is_fragment_assembly is True
    assert assembled.provenance_turns == [0, 2, 3]


def test_no_false_positives_on_arbitrary_numbers():
    engine = SessionTaintEngine()

    # Random 4-digit numbers that do NOT form a valid Aadhaar checksum
    messages = [
        {"role": "user", "content": "Order #4921 has shipped"},
        {"role": "assistant", "content": "Tracking code is 8812"},
        {"role": "user", "content": "Delivery zip code is 1001"},
    ]

    detections = engine.process_messages("session_benign", messages)
    # Checksum fails, so no false positive Aadhaar
    aadhaar_matches = [d for d in detections if d.entity_type == "AADHAAR"]
    assert len(aadhaar_matches) == 0
