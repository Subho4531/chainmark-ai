"""
Cryptographic Vault & Semantic Tokenizer.
Implements AES-256-GCM encryption for sensitive values and format-preserving
typed tokens with deterministic session HMACs and streaming detokenization.
"""

from typing import Dict, List, Tuple, Optional, AsyncGenerator
import os
import hmac
import hashlib
from dataclasses import dataclass, field
import time
import re

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from chainmark.core.config import settings
from chainmark.detector.taint_engine import DetectedEntity


@dataclass
class VaultRecord:
    token_id: str
    entity_type: str
    encrypted_blob: bytes  # IV (12 bytes) + Ciphertext + Tag (16 bytes)
    session_id: str
    created_at: float = field(default_factory=time.time)


class TokenVault:
    """
    AES-256-GCM authenticated encrypted vault with semantic HMAC tokenization.
    """

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
        # In-memory storage: token_id -> VaultRecord
        self._records: Dict[str, VaultRecord] = {}
        # Session reverse index: session_id -> { raw_value: token_id }
        self._session_cache: Dict[str, Dict[str, str]] = {}

    def _generate_token_id(self, entity_type: str, raw_value: str, session_id: str) -> str:
        """
        Generates a deterministic semantic token for a given entity within a session.
        Uses HMAC-SHA256 keyed with the session-specific salt.
        Format: [CM_TOKEN_<ENTITY_TYPE>_<HMAC_PREFIX>]
        """
        session_key = hashlib.sha256(f"{session_id}:{self.master_key.hex()}".encode("utf-8")).digest()
        h = hmac.new(session_key, raw_value.encode("utf-8"), hashlib.sha256).hexdigest()[:8]
        return f"[CM_TOKEN_{entity_type.upper()}_{h}]"

    def tokenize_value(self, entity_type: str, raw_value: str, session_id: str) -> str:
        """
        Encrypts raw_value and stores it in the vault, returning the safe semantic token.
        """
        if session_id not in self._session_cache:
            self._session_cache[session_id] = {}

        if raw_value in self._session_cache[session_id]:
            return self._session_cache[session_id][raw_value]

        token_id = self._generate_token_id(entity_type, raw_value, session_id)

        # AES-256-GCM encryption with fresh 12-byte IV
        iv = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(iv, raw_value.encode("utf-8"), session_id.encode("utf-8"))
        encrypted_blob = iv + ciphertext

        record = VaultRecord(
            token_id=token_id,
            entity_type=entity_type,
            encrypted_blob=encrypted_blob,
            session_id=session_id,
        )
        self._records[token_id] = record
        self._session_cache[session_id][raw_value] = token_id
        return token_id

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

    def redact_text(
        self, text: str, entities: List[DetectedEntity], session_id: str
    ) -> Tuple[str, List[Tuple[str, str]]]:
        """
        Replaces all detected entities in the text with safe typed tokens.
        Returns: (sanitized_text, list_of_(token_id, entity_type))
        """
        if not entities or not text:
            return text, []

        sanitized = text
        token_replacements: List[Tuple[str, str]] = []

        # Sort entities by length descending to prevent partial substring collision
        sorted_entities = sorted(entities, key=lambda e: len(e.raw_value), reverse=True)

        for entity in sorted_entities:
            raw_val = entity.raw_value
            token_id = self.tokenize_value(entity.entity_type, raw_val, session_id)
            token_replacements.append((token_id, entity.entity_type))

            # Replace occurrences of the raw value or raw value with hyphens/spaces
            escaped = re.escape(raw_val)
            sanitized = re.sub(escaped, token_id, sanitized)

            # If numeric (or assembled from split fragments), match spaced/hyphenated variations
            digits_only = re.sub(r"\D", "", raw_val)
            if digits_only and len(digits_only) >= 9:
                spaced_pat = r"\b" + r"[-\s]*".join(list(digits_only)) + r"\b"
                sanitized = re.sub(spaced_pat, token_id, sanitized)

        return sanitized, token_replacements

    def detokenize_text(self, text: str, session_id: str) -> str:
        """
        Scans text for [CM_TOKEN_...] patterns and replaces them with the original decrypted values.
        """
        if not text:
            return text

        def _replace_token(match):
            token_id = match.group(0)
            decrypted = self.detokenize_value(token_id, session_id)
            return decrypted if decrypted is not None else token_id

        return re.sub(r"\[CM_TOKEN_[A-Z_]+_[a-f0-9]{8}\]", _replace_token, text)

    async def detokenize_stream(
        self, stream: AsyncGenerator[str, None], session_id: str
    ) -> AsyncGenerator[str, None]:
        """
        Buffers streaming SSE tokens to ensure tokens split across chunk boundaries
        are safely resolved and detokenized before emitting to client.
        """
        buffer = ""
        token_regex = re.compile(r"\[CM_TOKEN_[A-Z_]+_[a-f0-9]{8}\]")

        async for chunk in stream:
            buffer += chunk

            # While there is a complete token or safe prefix to flush
            match = token_regex.search(buffer)
            if match:
                start, end = match.span()
                # Yield everything before the token
                if start > 0:
                    yield buffer[:start]

                # Detokenize the matched token
                token_str = match.group(0)
                decrypted = self.detokenize_value(token_str, session_id)
                yield decrypted if decrypted is not None else token_str

                # Keep the remainder
                buffer = buffer[end:]
            else:
                # If no complete token, but buffer might contain a partial token start "["
                if "[" in buffer:
                    idx = buffer.rfind("[")
                    # If the partial prefix is longer than a standard token length (~40 chars), flush safe part
                    if len(buffer) - idx > 50:
                        yield buffer
                        buffer = ""
                    else:
                        yield buffer[:idx]
                        buffer = buffer[idx:]
                else:
                    yield buffer
                    buffer = ""

        if buffer:
            # Final detokenize of any leftover text in buffer
            yield self.detokenize_text(buffer, session_id)
