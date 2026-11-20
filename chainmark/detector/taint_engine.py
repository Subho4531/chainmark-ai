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
    # (turn_index, fragment_text) pairs that combine into raw_value. Fragments
    # must be neutralized in their own turn, since the assembled value never
    # appears literally anywhere in the payload.
    fragments: List[Tuple[int, str]] = field(default_factory=list)


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
        e.g., 4-digit chunks like '4532', '8901', '2348', or hyphenated '4567-8901'.
        """
        # Standalone numeric sequences between 3 and 10 digits
        num_matches = re.findall(r"\b\d{3,10}\b", text)
        
        # Also extract hyphenated or spaced chunks (e.g. '4567-8901' -> '45678901')
        for chunk in re.findall(r"\b\d{4}[-\s]\d{4}\b", text):
            cleaned = re.sub(r"\D", "", chunk)
            if cleaned not in num_matches:
                num_matches.append(cleaned)
                
        # Alphanumeric sequences (e.g. PAN fragments)
        alpha_matches = re.findall(r"\b[A-Z0-9]{3,8}\b", text, re.IGNORECASE)
        return num_matches, alpha_matches

    def scan_single_text(self, text: str) -> List[DetectedEntity]:
        """
        Scans a single text string for fully-formed standalone entities.
        """
        detections: List[DetectedEntity] = []

        # 1. Structured Numeric IDs: Aadhaar (12 digits, Verhoeff) and Cards (11-19 digits, Luhn)
        # Matches space/hyphen delimited groups or continuous digits
        for match in re.finditer(r"\b\d{2,8}(?:[-\s]\d{2,8})+\b|\b\d{11,19}\b", text):
            candidate = match.group()
            cleaned = re.sub(r"\D", "", candidate)
            if len(cleaned) == 12 and validate_aadhaar(cleaned):
                detections.append(
                    DetectedEntity(
                        entity_type="AADHAAR",
                        raw_value=candidate,
                        confidence=1.0,
                        span=match.span(),
                    )
                )
            elif 11 <= len(cleaned) <= 19 and validate_luhn(cleaned):
                detections.append(
                    DetectedEntity(
                        entity_type="CREDIT_CARD",
                        raw_value=candidate,
                        confidence=1.0,
                        span=match.span(),
                    )
                )

        # 2. PAN Card
        for match in re.finditer(r"\b[A-Za-z]{5}[-\s]?[0-9]{4}[-\s]?[A-Za-z]{1}\b", text):
            candidate = match.group()
            cleaned_pan = re.sub(r"[-\s]", "", candidate)
            if validate_pan(cleaned_pan):
                detections.append(
                    DetectedEntity(
                        entity_type="PAN",
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
        num_turns = len(turn_fragments)
        for i in range(num_turns):
            turn_i_idx, nums_i = turn_fragments[i]

            # 1. Check combinations within the same turn
            for a_idx, num_a in enumerate(nums_i):
                for b_idx in range(a_idx + 1, len(nums_i)):
                    num_b = nums_i[b_idx]
                    joined_same = num_a + num_b
                    if len(joined_same) == 12 and validate_aadhaar(joined_same):
                        all_detections.append(
                            DetectedEntity(
                                entity_type="AADHAAR",
                                raw_value=joined_same,
                                confidence=1.0,
                                is_fragment_assembly=True,
                                provenance_turns=[turn_i_idx],
                                fragments=[(turn_i_idx, num_a), (turn_i_idx, num_b)],
                            )
                        )
                    elif 11 <= len(joined_same) <= 19 and validate_luhn(joined_same):
                        all_detections.append(
                            DetectedEntity(
                                entity_type="CREDIT_CARD",
                                raw_value=joined_same,
                                confidence=1.0,
                                is_fragment_assembly=True,
                                provenance_turns=[turn_i_idx],
                                fragments=[(turn_i_idx, num_a), (turn_i_idx, num_b)],
                            )
                        )

            # 2. Check combinations across different turns
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
                                    fragments=[
                                        (turn_i_idx, num_a),
                                        (turn_j_idx, num_b),
                                    ],
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
                                            provenance_turns=[
                                                turn_i_idx,
                                                turn_j_idx,
                                                turn_k_idx,
                                            ],
                                            fragments=[
                                                (turn_i_idx, num_a),
                                                (turn_j_idx, num_b),
                                                (turn_k_idx, num_c),
                                            ],
                                        )
                                    )

                # Check for split Credit Cards (11 to 19 digits)
                for j in range(i + 1, num_turns):
                    turn_j_idx, nums_j = turn_fragments[j]
                    for num_b in nums_j:
                        joined_card = num_a + num_b
                        if 11 <= len(joined_card) <= 19 and validate_luhn(joined_card):
                            all_detections.append(
                                DetectedEntity(
                                    entity_type="CREDIT_CARD",
                                    raw_value=joined_card,
                                    confidence=1.0,
                                    is_fragment_assembly=True,
                                    provenance_turns=[turn_i_idx, turn_j_idx],
                                    fragments=[
                                        (turn_i_idx, num_a),
                                        (turn_j_idx, num_b),
                                    ],
                                )
                            )

        # Deduplicate detections by (entity_type, raw_value), merging provenance
        # so a value repeated in several turns is redacted in every one of them.
        by_key: Dict[Tuple[str, str], DetectedEntity] = {}
        for detection in all_detections:
            key = (detection.entity_type, detection.raw_value)
            existing = by_key.get(key)
            if existing is None:
                by_key[key] = detection
                continue

            for turn in detection.provenance_turns:
                if turn not in existing.provenance_turns:
                    existing.provenance_turns.append(turn)
            for fragment in detection.fragments:
                if fragment not in existing.fragments:
                    existing.fragments.append(fragment)
            existing.confidence = max(existing.confidence, detection.confidence)
            existing.is_fragment_assembly = (
                existing.is_fragment_assembly or detection.is_fragment_assembly
            )

        return list(by_key.values())
