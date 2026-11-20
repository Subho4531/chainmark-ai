import pytest
from chainmark.vault.token_vault import TokenVault
from chainmark.detector.taint_engine import DetectedEntity


def test_token_format_and_reversibility():
    vault = TokenVault()
    session_id = "test_session_1"
    raw_aadhaar = "234567890123"

    token = vault.tokenize_value("AADHAAR", raw_aadhaar, session_id)

    # Check format: [CM_TOKEN_AADHAAR_<32_hex_chars>]
    assert token.startswith("[CM_TOKEN_AADHAAR_")
    assert token.endswith("]")

    # Check detokenization
    decrypted = vault.detokenize_value(token, session_id)
    assert decrypted == raw_aadhaar


def test_session_deterministic_tokenization():
    vault = TokenVault()
    session_id = "session_alpha"
    raw_val = "ABCPE1234F"

    # Same raw value in same session returns same token
    t1 = vault.tokenize_value("PAN", raw_val, session_id)
    t2 = vault.tokenize_value("PAN", raw_val, session_id)
    assert t1 == t2

    # Different session returns different HMAC token for cross-tenant privacy
    t_other = vault.tokenize_value("PAN", raw_val, "session_beta")
    assert t1 != t_other


def test_text_redaction_and_detokenization():
    vault = TokenVault()
    session_id = "session_redact"

    original_text = "The user with PAN ABCPE1234F requested account deletion."
    entities = [
        DetectedEntity(entity_type="PAN", raw_value="ABCPE1234F", confidence=1.0)
    ]

    sanitized, tokens = vault.redact_text(original_text, entities, session_id)
    assert "ABCPE1234F" not in sanitized
    assert "[CM_TOKEN_PAN_" in sanitized
    assert len(tokens) == 1

    # Now detokenize the string
    restored = vault.detokenize_text(sanitized, session_id)
    assert restored == original_text


@pytest.mark.asyncio
async def test_streaming_chunk_detokenization():
    vault = TokenVault()
    session_id = "stream_session"
    raw_val = "ABCPE1234F"
    token = vault.tokenize_value("PAN", raw_val, session_id)

    # Simulate SSE stream where the token is split across chunks
    split_pt = len(token) // 2
    part_1 = token[:split_pt]
    part_2 = token[split_pt:]

    async def mock_chunk_stream():
        yield "Your verified PAN is "
        yield part_1  # partial token
        yield part_2  # remaining token
        yield " and status is active."

    detokenized_chunks = []
    async for chunk in vault.detokenize_stream(mock_chunk_stream(), session_id):
        detokenized_chunks.append(chunk)

    full_output = "".join(detokenized_chunks)
    assert raw_val in full_output
    assert token not in full_output
    assert full_output == "Your verified PAN is ABCPE1234F and status is active."
