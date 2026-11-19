"""
Cryptographic Evidence Engine: Sequential Hash Chaining & Merkle DAG.
Ensures every interception, fragment assembly, and tokenization decision
is recorded as a tamper-evident, monotonically sequenced audit node.
"""

from typing import List, Dict, Any, Optional
import hashlib
import json
import time
from dataclasses import dataclass, asdict


@dataclass
class EvidenceEvent:
    sequence: int
    timestamp: float
    session_id: str
    event_type: str
    input_digest: str
    sanitized_digest: str
    entities_detected: List[str]
    tokens_mapped: List[str]
    policy_action: str
    prev_hash: str
    node_hash: str = ""

    def compute_hash(self) -> str:
        """
        Calculates canonical SHA-256 hash of the event contents.
        """
        payload = {
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "event_type": self.event_type,
            "input_digest": self.input_digest,
            "sanitized_digest": self.sanitized_digest,
            "entities_detected": sorted(self.entities_detected),
            "tokens_mapped": sorted(self.tokens_mapped),
            "policy_action": self.policy_action,
            "prev_hash": self.prev_hash,
        }
        canonical_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


class MerkleHashChain:
    """
    Maintains a sequential, append-only hash chain per session.
    """

    GENESIS_HASH = "0" * 64

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.events: List[EvidenceEvent] = []

    def append_event(
        self,
        event_type: str,
        raw_input: str,
        sanitized_output: str,
        entities_detected: List[str],
        tokens_mapped: List[str],
        policy_action: str = "TOKENIZE_AND_FORWARD",
    ) -> EvidenceEvent:
        """
        Appends a new event node to the chain with strictly monotonic sequence.
        """
        seq = len(self.events)
        prev_hash = self.events[-1].node_hash if self.events else self.GENESIS_HASH

        input_digest = hashlib.sha256(raw_input.encode("utf-8")).hexdigest()
        sanitized_digest = hashlib.sha256(sanitized_output.encode("utf-8")).hexdigest()

        event = EvidenceEvent(
            sequence=seq,
            timestamp=time.time(),
            session_id=self.session_id,
            event_type=event_type,
            input_digest=input_digest,
            sanitized_digest=sanitized_digest,
            entities_detected=entities_detected,
            tokens_mapped=tokens_mapped,
            policy_action=policy_action,
            prev_hash=prev_hash,
        )
        event.node_hash = event.compute_hash()
        self.events.append(event)
        return event

    def get_merkle_root(self) -> str:
        """
        Computes the Merkle Root for all event node hashes in the chain.
        """
        if not self.events:
            return self.GENESIS_HASH

        current_level = [e.node_hash for e in self.events]

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                combined = hashlib.sha256((left + right).encode("utf-8")).hexdigest()
                next_level.append(combined)
            current_level = next_level

        return current_level[0]

    def verify_chain(self) -> Tuple[bool, Optional[str]]:
        """
        Validates internal consistency: sequence monotonicity and hash integrity.
        Returns: (is_valid, error_message_if_any)
        """
        for i, event in enumerate(self.events):
            if event.sequence != i:
                return False, f"Sequence discontinuity at index {i}: expected {i}, got {event.sequence}"

            expected_prev = self.events[i - 1].node_hash if i > 0 else self.GENESIS_HASH
            if event.prev_hash != expected_prev:
                return False, f"Hash chain broken at index {i}: invalid prev_hash"

            computed_hash = event.compute_hash()
            if event.node_hash != computed_hash:
                return False, f"Node hash tampering detected at index {i}"

        return True, None
