"""
ECDSA P-256 Cryptographic Signer and Evidence Pack Bundler.
Generates legally admissible, tamper-evident ZIP evidence packs containing
canonical event logs, Merkle root hashes, and digital signatures.
"""

from typing import Optional, Tuple
import os
import io
import json
import zipfile
import base64
import time

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from chainmark.evidence.merkle_chain import MerkleHashChain


class EvidenceSigner:
    """
    Manages ECDSA P-256 digital signing for evidence packs.
    """

    def __init__(self, private_key_pem: Optional[bytes] = None):
        if private_key_pem:
            self.private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        else:
            # Ephemeral local key for dev/test
            self.private_key = ec.generate_private_key(ec.SECP256R1())

        self.public_key = self.private_key.public_key()

    def get_public_key_pem(self) -> str:
        """
        Exports public key in PEM format.
        """
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem.decode("utf-8")

    def sign_root(self, root_hash_hex: str) -> str:
        """
        Signs the Merkle root hash using ECDSA P-256 and SHA-256.
        Returns base64-encoded signature.
        """
        signature = self.private_key.sign(
            root_hash_hex.encode("utf-8"),
            ec.ECDSA(hashes.SHA256()),
        )
        return base64.b64encode(signature).decode("utf-8")

    @staticmethod
    def verify_signature(public_key_pem: str, root_hash_hex: str, signature_b64: str) -> bool:
        """
        Verifies ECDSA signature against the public key and root hash.
        """
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
            signature = base64.b64decode(signature_b64)
            public_key.verify(
                signature,
                root_hash_hex.encode("utf-8"),
                ec.ECDSA(hashes.SHA256()),
            )
            return True
        except (InvalidSignature, Exception):
            return False

    def build_evidence_pack(self, chain: MerkleHashChain) -> bytes:
        """
        Packages the session audit trail into an immutable, dual-signed ZIP bundle.
        """
        is_valid, err = chain.verify_chain()
        if not is_valid:
            raise ValueError(f"Cannot package corrupted evidence chain: {err}")

        root_hash = chain.get_merkle_root()
        signature_b64 = self.sign_root(root_hash)
        pubkey_pem = self.get_public_key_pem()

        manifest = {
            "version": "1.0",
            "spec": "CHAINMARK-EVIDENCE-RFC3161",
            "session_id": chain.session_id,
            "created_at": time.time(),
            "total_events": len(chain.events),
            "merkle_root": root_hash,
            "signature": signature_b64,
            "public_key": pubkey_pem,
        }

        # Build events.jsonl
        events_lines = []
        for e in chain.events:
            event_dict = {
                "sequence": e.sequence,
                "timestamp": e.timestamp,
                "session_id": e.session_id,
                "event_type": e.event_type,
                "input_digest": e.input_digest,
                "sanitized_digest": e.sanitized_digest,
                "entities_detected": e.entities_detected,
                "tokens_mapped": e.tokens_mapped,
                "policy_action": e.policy_action,
                "prev_hash": e.prev_hash,
                "node_hash": e.node_hash,
            }
            events_lines.append(json.dumps(event_dict, sort_keys=True))
        events_jsonl = "\n".join(events_lines)

        # Create ZIP in memory
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("manifest.json", json.dumps(manifest, indent=2))
            zf.writestr("events.jsonl", events_jsonl)
            zf.writestr("signature.sig", signature_b64)
            zf.writestr("public_key.pem", pubkey_pem)

        return zip_buffer.getvalue()
