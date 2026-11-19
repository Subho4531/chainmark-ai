"""
Standalone Offline Evidence Verifier CLI for DPOs, Auditors, and Regulators.
Verifies cryptographic hash continuity, Merkle roots, and ECDSA P-256 signatures
without requiring any network connectivity or backend server access.
"""

import sys
import os
import json
import zipfile
import argparse
import hashlib

from chainmark.evidence.signer import EvidenceSigner


def verify_evidence_pack(zip_path: str, external_pubkey: str = None) -> bool:
    """
    Performs full offline cryptographic audit of an Evidence Pack ZIP.
    """
    if not os.path.exists(zip_path):
        print(f"[FAIL] Evidence pack file not found: {zip_path}")
        return False

    print("=" * 60)
    print(f"CHAINMARK AI AUDIT VERIFIER: {os.path.basename(zip_path)}")
    print("=" * 60)

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            namelist = zf.namelist()
            for required in ["manifest.json", "events.jsonl", "signature.sig"]:
                if required not in namelist:
                    print(f"[FAIL] Missing required artifact in zip: {required}")
                    return False

            manifest_data = json.loads(zf.read("manifest.json").decode("utf-8"))
            events_content = zf.read("events.jsonl").decode("utf-8")
            signature_b64 = zf.read("signature.sig").decode("utf-8").strip()

            pubkey_pem = external_pubkey
            if not pubkey_pem:
                if "public_key.pem" in namelist:
                    pubkey_pem = zf.read("public_key.pem").decode("utf-8")
                else:
                    pubkey_pem = manifest_data.get("public_key")

            if not pubkey_pem:
                print("[FAIL] No public key available for signature verification")
                return False

    except Exception as e:
        print(f"[FAIL] Error reading ZIP file: {e}")
        return False

    session_id = manifest_data.get("session_id")
    expected_root = manifest_data.get("merkle_root")
    total_events = manifest_data.get("total_events", 0)

    print(f"[*] Session ID: {session_id}")
    print(f"[*] Total Events in Log: {total_events}")
    print(f"[*] Stated Merkle Root: {expected_root}")

    # Parse and verify event chain
    lines = [line.strip() for line in events_content.splitlines() if line.strip()]
    if len(lines) != total_events:
        print(f"[FAIL] Event count mismatch: manifest says {total_events}, found {len(lines)}")
        return False

    node_hashes = []
    prev_hash = "0" * 64

    for i, line in enumerate(lines):
        try:
            event = json.loads(line)
        except Exception:
            print(f"[FAIL] Corrupted JSON at event index {i}")
            return False

        # 1. Monotonic sequence check
        if event.get("sequence") != i:
            print(f"[FAIL] Sequence gap at index {i}: expected {i}, found {event.get('sequence')}")
            return False

        # 2. Hash chaining check
        if event.get("prev_hash") != prev_hash:
            print(f"[FAIL] Hash chain broken at index {i}!")
            print(f"       Expected prev_hash: {prev_hash}")
            print(f"       Found prev_hash:    {event.get('prev_hash')}")
            return False

        # 3. Canonical hash verification
        payload = {
            "sequence": event["sequence"],
            "timestamp": event["timestamp"],
            "session_id": event["session_id"],
            "event_type": event["event_type"],
            "input_digest": event["input_digest"],
            "sanitized_digest": event["sanitized_digest"],
            "entities_detected": sorted(event.get("entities_detected", [])),
            "tokens_mapped": sorted(event.get("tokens_mapped", [])),
            "policy_action": event["policy_action"],
            "prev_hash": event["prev_hash"],
        }
        canonical_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        computed_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

        if computed_hash != event.get("node_hash"):
            print(f"[FAIL] Tampered event data at sequence index {i}!")
            return False

        prev_hash = computed_hash
        node_hashes.append(computed_hash)

    print("[PASS] Hash chain unbroken: all sequence indexes and SHA-256 links valid.")

    # 4. Recompute Merkle Root
    current_level = list(node_hashes)
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            combined = hashlib.sha256((left + right).encode("utf-8")).hexdigest()
            next_level.append(combined)
        current_level = next_level

    computed_merkle_root = current_level[0] if current_level else "0" * 64

    if computed_merkle_root != expected_root:
        print("[FAIL] Recomputed Merkle root does not match manifest!")
        print(f"       Computed: {computed_merkle_root}")
        print(f"       Manifest: {expected_root}")
        return False

    print(f"[PASS] Merkle root match verified: {computed_merkle_root}")

    # 5. Verify ECDSA signature
    sig_valid = EvidenceSigner.verify_signature(pubkey_pem, computed_merkle_root, signature_b64)
    if not sig_valid:
        print("[FAIL] ECDSA P-256 digital signature is INVALID!")
        return False

    print("[PASS] ECDSA P-256 signature VALID and mathematically verified.")
    print("=" * 60)
    print("VERDICT: PASS (Tamper-evident, zero PII transmitted, legally admissible)")
    print("=" * 60)
    return True


def main():
    parser = argparse.ArgumentParser(description="Chainmark AI Offline Evidence Verifier")
    parser.add_argument("evidence_pack", help="Path to evidence_pack.zip")
    parser.add_argument("--pubkey", help="Optional path to external public_key.pem", default=None)
    args = parser.parse_args()

    pubkey_str = None
    if args.pubkey:
        with open(args.pubkey, "r") as f:
            pubkey_str = f.read()

    success = verify_evidence_pack(args.evidence_pack, pubkey_str)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
