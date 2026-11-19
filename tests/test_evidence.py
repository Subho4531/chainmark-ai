import pytest
import os
import io
import json
import zipfile
from chainmark.evidence.merkle_chain import MerkleHashChain
from chainmark.evidence.signer import EvidenceSigner
from chainmark.evidence.verifier_cli import verify_evidence_pack


def test_merkle_chain_integrity():
    chain = MerkleHashChain("session_evidence_1")

    # Add 3 events
    e0 = chain.append_event("INIT", "raw_prompt_1", "sanitized_prompt_1", [], [])
    e1 = chain.append_event("TOOL", "raw_prompt_2", "sanitized_prompt_2", ["AADHAAR"], ["[CM_TOKEN_AADHAAR_1]"])
    e2 = chain.append_event("DONE", "raw_prompt_3", "sanitized_prompt_3", [], [])

    assert e0.sequence == 0
    assert e1.sequence == 1
    assert e2.sequence == 2

    assert e1.prev_hash == e0.node_hash
    assert e2.prev_hash == e1.node_hash

    is_valid, err = chain.verify_chain()
    assert is_valid is True
    assert err is None


def test_ecdsa_signing_and_evidence_pack(tmp_path):
    chain = MerkleHashChain("session_audit_pack")
    chain.append_event("EVENT_1", "input_a", "output_a", ["PAN"], ["token_pan"])
    chain.append_event("EVENT_2", "input_b", "output_b", [], [])

    signer = EvidenceSigner()
    zip_bytes = signer.build_evidence_pack(chain)

    zip_file = tmp_path / "evidence_pack.zip"
    zip_file.write_bytes(zip_bytes)

    # Offline verification must succeed
    assert verify_evidence_pack(str(zip_file)) is True


def test_tamper_detection(tmp_path):
    chain = MerkleHashChain("session_tamper_test")
    chain.append_event("EVENT_1", "clean input", "clean output", [], [])
    chain.append_event("EVENT_2", "sensitive input", "tokenized output", ["SSN"], ["token_ssn"])

    signer = EvidenceSigner()
    valid_zip_bytes = signer.build_evidence_pack(chain)

    # Tamper with events.jsonl inside the zip
    tampered_buffer = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(valid_zip_bytes), "r") as original_zf:
        with zipfile.ZipFile(tampered_buffer, "w") as tampered_zf:
            for item in original_zf.infolist():
                content = original_zf.read(item.filename)
                if item.filename == "events.jsonl":
                    # Mutate one byte in the event log
                    lines = content.decode("utf-8").splitlines()
                    corrupted_event = json.loads(lines[0])
                    corrupted_event["sanitized_digest"] = "f" * 64  # Fake tampered hash
                    lines[0] = json.dumps(corrupted_event)
                    content = "\n".join(lines).encode("utf-8")
                tampered_zf.writestr(item, content)

    tampered_file = tmp_path / "tampered_pack.zip"
    tampered_file.write_bytes(tampered_buffer.getvalue())

    # Offline verification must detect tampering and FAIL
    assert verify_evidence_pack(str(tampered_file)) is False
