"""
Session Taint & Multi-Turn Jigsaw Fragment Assembly Engine.
Tracks conversational turns, identifies sub-threshold fragments across tools and turns,
and reconstructs assembled entities using deterministic checksums.
"""

from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass, field
import re
import time

from chainmark.detector.checksums import (
    validate_aadhaar,
    validate_luhn,
    validate_pan,
    validate_ssn,
    validate_mrn,
)


@dataclass
class DetectedEntity:
    entity_type: str
    raw_value: str
    confidence: float
    is_fragment_assembly: bool = False
    provenance_turns: List[int] = field(default_factory=list)
    span: Optional[Tuple[int, int]] = None


@dataclass
class SessionTurn:
    turn_index: int
    role: str
    content: str
    timestamp: float = field(default_factory=time.time)
    numeric_fragments: List[str] = field(default_factory=list)
    alphanumeric_fragments: List[str] = field(default_factory=list)


class SessionTaintEngine:
    """
    Stateful session taint and jigsaw assembly engine.
    Maintains historical conversation context per session_id and
    detects multi-turn fragment reassembly attacks.
    """

    def __init__(self, max_history_turns: int = 10):
        self.max_history_turns = max_history_turns
        self.sessions: Dict[str, List[SessionTurn]] = {}

    def _extract_candidate_fragments(self, text: str) -> Tuple[List[str], List[str]]:
        """
        Extracts sub-threshold numeric and alphanumeric fragments from text.
        e.g., 4-digit chunks like '4532', '8901', '2348', or 'AADH-4532'.
        """
        # Numeric sequences between 3 and 10 digits
        num_matches = re.findall(r"\b\d{3,10}\b", text)
        # Alphanumeric sequences (e.g. PAN fragments)
        alpha_matches = re.findall(r"\b[A-Z0-9]{3,8}\b", text, re.IGNORECASE)
        return num_matches, alpha_matches

    def scan_single_text(self, text: str) -> List[DetectedEntity]:
        """
        Scans a single text string for fully-formed standalone entities.
        """
        detections: List[DetectedEntity] = []

        # 1. Aadhaar: 12 digits (with optional spaces or hyphens)
        for match in re.finditer(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", text):
            candidate = match.group()
            if validate_aadhaar(candidate):
                detections.append(
                    DetectedEntity(
                        entity_type="AADHAAR",
                        raw_value=candidate,
                        confidence=1.0,
                        span=match.span(),
                    )
                )

        # 2. PAN Card
        for match in re.finditer(r"\b[A-Za-z]{5}[0-9]{4}[A-Za-z]{1}\b", text):
            candidate = match.group()
            if validate_pan(candidate):
                detections.append(
                    DetectedEntity(
                        entity_type="PAN",
                        raw_value=candidate,
                        confidence=1.0,
                        span=match.span(),
                    )
                )

        # 3. Credit / Debit Cards (13 to 19 digits with optional delimiters)
        for match in re.finditer(r"\b(?:\d{4}[-\s]?){3}\d{1,7}\b", text):
            candidate = match.group()
            if validate_luhn(candidate):
                detections.append(
                    DetectedEntity(
                        entity_type="CREDIT_CARD",
                        raw_value=candidate,
                        confidence=1.0,
                        span=match.span(),
                    )
                )

        # 4. US SSN
        for match in re.finditer(r"\b\d{3}-\d{2}-\d{4}\b", text):
            candidate = match.group()
            if validate_ssn(candidate):
                detections.append(
                    DetectedEntity(
                        entity_type="SSN",
                        raw_value=candidate,
                        confidence=1.0,
                        span=match.span(),
                    )
                )

        # 5. MRN (Medical Record Number)
        for match in re.finditer(r"\b(?:MRN|PAT|EHR)[-:\s]?([A-Z0-9]{6,12})\b", text, re.IGNORECASE):
            detections.append(
                DetectedEntity(
                    entity_type="MRN",
                    raw_value=match.group(),
                    confidence=0.9,
                    span=match.span(),
                )
            )

        return detections

    def process_messages(
        self, session_id: str, messages: List[Dict[str, Any]]
    ) -> List[DetectedEntity]:
        """
        Processes a full conversation history messages array:
        1. Evaluates all individual turns for standalone sensitive entities.
        2. Performs cross-turn fragment assembly to detect split PII.
        """
        all_detections: List[DetectedEntity] = []

        # Scan each message in the payload
        for i, msg in enumerate(messages):
            content = msg.get("content", "")
            if not isinstance(content, str):
                continue

            single_turn_entities = self.scan_single_text(content)
            for entity in single_turn_entities:
                entity.provenance_turns = [i]
                all_detections.append(entity)

        # Now perform Multi-Turn Jigsaw Fragment Assembly
        # Collect numeric fragments across all turns
        turn_fragments: List[Tuple[int, List[str]]] = []
        for i, msg in enumerate(messages):
            content = msg.get("content", "")
            if isinstance(content, str):
                nums, _ = self._extract_candidate_fragments(content)
                if nums:
                    turn_fragments.append((i, nums))

        # Check for split Aadhaar: 2 or 3 fragments across different turns
        # e.g. Turn A has '4532', Turn B has '8901', Turn C has '2348'
        # Total 12 digits!
        num_turns = len(turn_fragments)
        for i in range(num_turns):
            turn_i_idx, nums_i = turn_fragments[i]
            for num_a in nums_i:
                # 2-turn concatenation
                for j in range(i + 1, num_turns):
                    turn_j_idx, nums_j = turn_fragments[j]
                    for num_b in nums_j:
                        joined = num_a + num_b
                        if len(joined) == 12 and validate_aadhaar(joined):
                            all_detections.append(
                                DetectedEntity(
                                    entity_type="AADHAAR",
                                    raw_value=joined,
                                    confidence=1.0,
                                    is_fragment_assembly=True,
                                    provenance_turns=[turn_i_idx, turn_j_idx],
                                )
                            )
                        # 3-turn concatenation
                        for k in range(j + 1, num_turns):
                            turn_k_idx, nums_k = turn_fragments[k]
                            for num_c in nums_k:
                                joined_3 = num_a + num_b + num_c
                                if len(joined_3) == 12 and validate_aadhaar(joined_3):
                                    all_detections.append(
                                        DetectedEntity(
                                            entity_type="AADHAAR",
                                            raw_value=joined_3,
                                            confidence=1.0,
                                            is_fragment_assembly=True,
                                            provenance_turns=[turn_i_idx, turn_j_idx, turn_k_idx],
                                        )
                                    )

                # Check for split Credit Cards (15 or 16 digits)
                for j in range(i + 1, num_turns):
                    turn_j_idx, nums_j = turn_fragments[j]
                    for num_b in nums_j:
                        joined_card = num_a + num_b
                        if 13 <= len(joined_card) <= 19 and validate_luhn(joined_card):
                            all_detections.append(
                                DetectedEntity(
                                    entity_type="CREDIT_CARD",
                                    raw_value=joined_card,
                                    confidence=1.0,
                                    is_fragment_assembly=True,
                                    provenance_turns=[turn_i_idx, turn_j_idx],
                                )
                            )

        # Deduplicate detections by (entity_type, raw_value)
        unique_detections: List[DetectedEntity] = []
        seen = set()
        for d in all_detections:
            key = (d.entity_type, d.raw_value)
            if key not in seen:
                seen.add(key)
                unique_detections.append(d)

        return unique_detections
