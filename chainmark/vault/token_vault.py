"""
Cryptographic Vault & Semantic Tokenizer.
Implements AES-256-GCM encryption for sensitive values and format-preserving
typed tokens with deterministic session HMACs and streaming detokenization.

Redaction is span-anchored: entities are located in the exact turn they were
detected in, including sub-threshold fragments that only become sensitive when
assembled across turns. Every redaction pass re-scans its own output, so a
value that could not be neutralized is reported instead of silently forwarded.
"""

from typing import Dict, List, Tuple, Optional, AsyncGenerator, Sequence
import os
import hmac
import hashlib
from dataclasses import dataclass, field
import time
import re

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from chainmark.core.config import settings
from chainmark.detector.taint_engine import DetectedEntity


class TokenCollisionError(RuntimeError):
    """Raised when two distinct values map onto the same token id."""


@dataclass
class VaultRecord:
    token_id: str
    entity_type: str
    encrypted_blob: bytes  # IV (12 bytes) + Ciphertext + Tag (16 bytes)
    session_id: str
    value_digest: str
    created_at: float = field(default_factory=time.time)


@dataclass
class RedactionResult:
    """Outcome of a redaction pass over one egress payload."""

    texts: List[str]
    tokens_mapped: List[str]
    unresolved: List[DetectedEntity]
    token_types: Dict[str, str] = field(default_factory=dict)


class TokenVault:
    """
    AES-256-GCM authenticated encrypted vault with semantic HMAC tokenization.
    """

    TOKEN_PREFIX = "[CM_TOKEN_"
    # 128 bits of HMAC output: collisions are not a realistic concern, and a
    # collision is detected rather than silently overwriting a record.
    TOKEN_HEX_CHARS = 32
    TOKEN_PATTERN = r"\[CM_TOKEN_[A-Z][A-Z0-9_]*_[a-f0-9]{32}\]"
    MAX_TOKEN_LENGTH = 128

    # A digit run, optionally split by single hyphens/spaces ("4567 8901 2348").
    _DIGIT_RUN_RE = re.compile(r"\d(?:[-\s]?\d)*")

    def __init__(self, master_key_hex: Optional[str] = None):
        key_hex = master_key_hex or settings.VAULT_MASTER_KEY
        try:
            self.master_key = bytes.fromhex(key_hex)
        except ValueError:
            # Fallback if raw bytes string passed
            self.master_key = hashlib.sha256(key_hex.encode("utf-8")).digest()

        if len(self.master_key) != 32:
            self.master_key = hashlib.sha256(self.master_key).digest()

        self.aesgcm = AESGCM(self.master_key)
        self.TOKEN_RE = re.compile(self.TOKEN_PATTERN)
        # In-memory storage: token_id -> VaultRecord
        self._records: Dict[str, VaultRecord] = {}
        # Session reverse index: session_id -> { value_digest: token_id }
        # Keyed by HMAC digest so raw values are never retained in the index.
        self._session_cache: Dict[str, Dict[str, str]] = {}
        self._session_keys: Dict[str, bytes] = {}

    # ------------------------------------------------------------------
    # Key derivation
    # ------------------------------------------------------------------

    def _session_key(self, session_id: str) -> bytes:
        """
        Derives a per-session HMAC key from the master key using HKDF-style
        HMAC derivation. Never concatenates raw key material into a string.
        """
        cached = self._session_keys.get(session_id)
        if cached is not None:
            return cached
        derived = hmac.new(
            self.master_key,
            f"chainmark:session:{session_id}".encode("utf-8"),
            hashlib.sha256,
        ).digest()
        self._session_keys[session_id] = derived
        return derived

    def _value_digest(self, entity_type: str, raw_value: str, session_id: str) -> str:
        return hmac.new(
            self._session_key(session_id),
            f"{entity_type.upper()}\x00{raw_value}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _generate_token_id(self, entity_type: str, raw_value: str, session_id: str) -> str:
        """
        Generates a deterministic semantic token for a given entity within a session.
        Format: [CM_TOKEN_<ENTITY_TYPE>_<128-bit HMAC hex>]
        """
        digest = self._value_digest(entity_type, raw_value, session_id)
        return f"{self.TOKEN_PREFIX}{entity_type.upper()}_{digest[: self.TOKEN_HEX_CHARS]}]"

    # ------------------------------------------------------------------
    # Token lifecycle
    # ------------------------------------------------------------------

    def tokenize_value(self, entity_type: str, raw_value: str, session_id: str) -> str:
        """
        Encrypts raw_value and stores it in the vault, returning the safe semantic token.
        """
        cache = self._session_cache.setdefault(session_id, {})
        digest = self._value_digest(entity_type, raw_value, session_id)

        existing = cache.get(digest)
        if existing is not None:
            return existing

        token_id = self._generate_token_id(entity_type, raw_value, session_id)
        record = self._records.get(token_id)
        if record is not None:
            if record.value_digest != digest:
                raise TokenCollisionError(
                    "Token id collision detected; refusing to overwrite vault record"
                )
            cache[digest] = token_id
            return token_id

        # AES-256-GCM encryption with fresh 12-byte IV
        iv = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(iv, raw_value.encode("utf-8"), session_id.encode("utf-8"))
        encrypted_blob = iv + ciphertext

        self._records[token_id] = VaultRecord(
            token_id=token_id,
            entity_type=entity_type,
            encrypted_blob=encrypted_blob,
            session_id=session_id,
            value_digest=digest,
        )
        cache[digest] = token_id
        return token_id

    def find_token(self, entity_type: str, raw_value: str, session_id: str) -> Optional[str]:
        """
        Returns the token already issued for a value, without minting a new one.
        """
        digest = self._value_digest(entity_type, raw_value, session_id)
        return self._session_cache.get(session_id, {}).get(digest)

    def detokenize_value(self, token_id: str, session_id: str) -> Optional[str]:
        """
        Retrieves and decrypts the raw value for a given token.
        """
        record = self._records.get(token_id)
        if not record or record.session_id != session_id:
            return None

        iv = record.encrypted_blob[:12]
        ciphertext = record.encrypted_blob[12:]
        try:
            decrypted = self.aesgcm.decrypt(iv, ciphertext, session_id.encode("utf-8"))
            return decrypted.decode("utf-8")
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Span matching
    # ------------------------------------------------------------------

    def _token_spans(self, text: str) -> List[Tuple[int, int]]:
        return [(m.start(), m.end()) for m in self.TOKEN_RE.finditer(text)]

    @staticmethod
    def _overlaps_any(span: Tuple[int, int], blocked: Sequence[Tuple[int, int]]) -> bool:
        start, end = span
        return any(start < b_end and end > b_start for b_start, b_end in blocked)

    def _spans_for_value(self, text: str, value: str) -> List[Tuple[int, int]]:
        """
        Locates a value in text: literal, separator-tolerant (PAN/MRN), or as a
        digit run compared by its normalized digits (Aadhaar/card/fragments).
        Spans inside an already-emitted token are ignored.
        """
        if not text or not value:
            return []

        blocked = self._token_spans(text)
        spans: List[Tuple[int, int]] = []

        def _add(span: Tuple[int, int]) -> None:
            if span[0] >= span[1]:
                return
            if self._overlaps_any(span, blocked):
                return
            if span not in spans:
                spans.append(span)

        # 1. Literal occurrence (case-insensitive: PAN/MRN may be lowercased).
        for match in re.finditer(re.escape(value), text, re.IGNORECASE):
            _add((match.start(), match.end()))

        # 2. Normalized occurrence, tolerating separators and case.
        alnum = re.sub(r"[^A-Za-z0-9]", "", value)
        if not alnum:
            return spans

        if alnum.isdigit():
            for match in self._DIGIT_RUN_RE.finditer(text):
                if re.sub(r"\D", "", match.group()) == alnum:
                    _add((match.start(), match.end()))
        else:
            pattern = (
                r"(?<![A-Za-z0-9])"
                + r"[-\s]?".join(re.escape(char) for char in alnum)
                + r"(?![A-Za-z0-9])"
            )
            for match in re.finditer(pattern, text, re.IGNORECASE):
                _add((match.start(), match.end()))

        return spans

    @staticmethod
    def _apply_spans(
        text: str, spans: Sequence[Tuple[int, int, str]]
    ) -> Tuple[str, List[str]]:
        """
        Rewrites text in a single pass over the original string, so tokens can
        never be corrupted by a later substitution.
        """
        ordered = sorted(spans, key=lambda s: (s[0], -(s[1] - s[0])))
        out: List[str] = []
        used: List[str] = []
        cursor = 0

        for start, end, token in ordered:
            if start < cursor:
                continue
            out.append(text[cursor:start])
            out.append(token)
            cursor = end
            if token not in used:
                used.append(token)

        out.append(text[cursor:])
        return "".join(out), used

    # ------------------------------------------------------------------
    # Redaction
    # ------------------------------------------------------------------

    def redact_texts(
        self,
        texts: Sequence[str],
        entities: List[DetectedEntity],
        session_id: str,
        turn_indices: Optional[Sequence[int]] = None,
    ) -> RedactionResult:
        """
        Redacts every detected entity in an egress payload.

        texts[i] is the text of provenance turn turn_indices[i]. Fragment
        redaction is restricted to the turn the fragment was found in, while a
        fully detected value is redacted wherever it appears in the payload.

        Returns the sanitized texts plus only the tokens actually inserted.
        Any entity still resolvable in the sanitized output is reported as
        unresolved so the caller can fail closed.
        """
        egress = list(texts)
        if turn_indices is None:
            turn_indices = list(range(len(egress)))
        if len(turn_indices) != len(egress):
            raise ValueError("turn_indices must align with texts")

        per_text: Dict[int, List[Tuple[int, int, str]]] = {}
        token_values: Dict[str, str] = {}
        token_types: Dict[str, str] = {}

        def _record(text_index: int, span: Tuple[int, int], value: str, entity_type: str) -> None:
            token = self._generate_token_id(entity_type, value, session_id)
            per_text.setdefault(text_index, []).append((span[0], span[1], token))
            token_values[token] = value
            token_types[token] = entity_type

        for entity in entities:
            # Fully formed value: safe to neutralize anywhere in the payload.
            for index, text in enumerate(egress):
                for span in self._spans_for_value(text, entity.raw_value):
                    _record(index, span, entity.raw_value, entity.entity_type)

            # Sub-threshold fragments: only inside the turn they came from.
            for turn, fragment in entity.fragments:
                if turn not in turn_indices or not fragment:
                    continue
                index = turn_indices.index(turn)
                for span in self._spans_for_value(egress[index], fragment):
                    _record(index, span, fragment, entity.entity_type)

        redacted: List[str] = []
        tokens_mapped: List[str] = []
        for index, text in enumerate(egress):
            new_text, used = self._apply_spans(text, per_text.get(index, []))
            redacted.append(new_text)
            for token in used:
                if token not in tokens_mapped:
                    tokens_mapped.append(token)

        # Persist only the tokens that really made it into the payload.
        for token in tokens_mapped:
            self.tokenize_value(
                token_types.get(token, "UNKNOWN"), token_values[token], session_id
            )

        # Post-condition: nothing sensitive may remain in the sanitized output.
        unresolved: List[DetectedEntity] = []
        for entity in entities:
            leaked = any(
                self._spans_for_value(text, entity.raw_value) for text in redacted
            )
            if not leaked:
                for turn, fragment in entity.fragments:
                    if turn not in turn_indices or not fragment:
                        continue
                    index = turn_indices.index(turn)
                    if self._spans_for_value(redacted[index], fragment):
                        leaked = True
                        break
            if leaked:
                unresolved.append(entity)

        return RedactionResult(
            texts=redacted,
            tokens_mapped=tokens_mapped,
            unresolved=unresolved,
            token_types=token_types,
        )

    def redact_text(
        self, text: str, entities: List[DetectedEntity], session_id: str
    ) -> Tuple[str, List[Tuple[str, str]]]:
        """
        Backwards-compatible single-text wrapper.
        Returns: (sanitized_text, list_of_(token_id, entity_type))
        """
        result = self.redact_texts([text], entities, session_id)
        pairs = [(token, result.token_types.get(token, "UNKNOWN")) for token in result.tokens_mapped]
        return result.texts[0], pairs

    # ------------------------------------------------------------------
    # Detokenization
    # ------------------------------------------------------------------

    def detokenize_text_strict(self, text: str, session_id: str) -> Tuple[str, int]:
        """
        Restores tokens, reporting how many could not be resolved.
        """
        if not text:
            return text, 0

        unresolved = 0

        def _replace(match: re.Match) -> str:
            nonlocal unresolved
            token_id = match.group(0)
            decrypted = self.detokenize_value(token_id, session_id)
            if decrypted is None:
                unresolved += 1
                return token_id
            return decrypted

        return self.TOKEN_RE.sub(_replace, text), unresolved

    def detokenize_text(self, text: str, session_id: str) -> str:
        """
        Scans text for tokens and replaces them with the original decrypted values.
        Unresolvable tokens are left untouched.
        """
        if not text:
            return text
        restored, _ = self.detokenize_text_strict(text, session_id)
        return restored

    async def detokenize_stream(
        self, stream: AsyncGenerator[str, None], session_id: str
    ) -> AsyncGenerator[str, None]:
        """
        Buffers streaming text just long enough to resolve tokens split across
        chunk boundaries.
        """
        restorer = StreamTokenRestorer(self, session_id)
        async for chunk in stream:
            safe = restorer.push(chunk)
            if safe:
                yield safe
        tail = restorer.flush()
        if tail:
            yield tail


class StreamTokenRestorer:
    """
    Incremental detokenizer for streamed content.

    Holds back only text that could be the beginning of a token, and only for
    as long as a token can plausibly be. Ordinary bracketed text (JSON arrays,
    markdown links) is released immediately.
    """

    def __init__(self, vault: TokenVault, session_id: str):
        self._vault = vault
        self._session_id = session_id
        self._buffer = ""
        self.unresolved = 0

    def _is_token_prefix(self, candidate: str) -> bool:
        if not candidate:
            return False
        prefix = self._vault.TOKEN_PREFIX  # "[CM_TOKEN_"
        return prefix.startswith(candidate) or candidate.startswith(prefix)

    def push(self, text: str) -> str:
        if text:
            self._buffer += text

        out: List[str] = []
        while True:
            match = self._vault.TOKEN_RE.search(self._buffer)
            if match:
                out.append(self._buffer[: match.start()])
                restored = self._vault.detokenize_value(match.group(0), self._session_id)
                if restored is None:
                    self.unresolved += 1
                    out.append(match.group(0))
                else:
                    out.append(restored)
                self._buffer = self._buffer[match.end():]
                continue

            bracket = self._buffer.rfind("[")
            if bracket == -1:
                out.append(self._buffer)
                self._buffer = ""
            else:
                suffix = self._buffer[bracket:]
                if (
                    len(suffix) <= self._vault.MAX_TOKEN_LENGTH
                    and self._is_token_prefix(suffix)
                ):
                    out.append(self._buffer[:bracket])
                    self._buffer = suffix
                else:
                    out.append(self._buffer)
                    self._buffer = ""
            break

        return "".join(out)

    def flush(self) -> str:
        restored, unresolved = self._vault.detokenize_text_strict(
            self._buffer, self._session_id
        )
        self.unresolved += unresolved
        self._buffer = ""
        return restored
