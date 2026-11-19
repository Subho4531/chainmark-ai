# Guidelines for AI Agents Working on Chainmark AI

Welcome, Agent. You are contributing to **Chainmark AI**, an enterprise security and cryptographic evidence guard for autonomous AI agents. Every line of code in this repository protects enterprise customer data from unauthorized exposure to external foundation models.

---

## 1. Prime Invariants (Never Violate)

1. **Zero Plaintext Sensitive Leakage**:
   * NEVER log raw user prompts, tool outputs, or sensitive fragments into stdout, log files, or unencrypted storage.
   * All logging must use tokenized strings or SHA-256 digests (`input_digest`, `sanitized_digest`).
2. **Cryptographic Rigor**:
   * All symmetric encryption must be **AES-256-GCM** with a fresh 12-byte initialization vector (IV) generated via `os.urandom(12)` per encryption operation. Never reuse IVs.
   * Asymmetric signatures must use **ECDSA P-256** with **SHA-256**.
   * Sequence numbers in the evidence chain must be strictly monotonic ($0, 1, 2, \dots, n$).
3. **Protocol Compatibility**:
   * The interceptor proxy MUST remain transparently compatible with standard OpenAI REST formats (`/v1/chat/completions`) and Google Gemini formats (`/v1beta/models/{model}:generateContent`).
   * Never introduce proprietary SDK dependencies required on the client side unless wrapped in an optional convenience utility.

---

## 2. Code Quality & Architecture Standards

* **Language & Runtime**: Python 3.11+, managed via `uv`.
* **Typing & Validation**: Strict type annotations on all functions. Use Pydantic v2 for configuration and request schemas.
* **Separation of Concerns**:
  * `chainmark.core`: Global configuration and lifecycle management.
  * `chainmark.detector`: Pattern matching, mathematical checksums (Verhoeff, Luhn), and sliding-window session taint assembly.
  * `chainmark.vault`: AES-256-GCM encryption, HMAC tokenization, and streaming detokenization.
  * `chainmark.evidence`: Sequential hash chaining, Merkle DAG computation, ECDSA signing, and offline verification CLI.
  * `chainmark.interceptor`: FastAPI ASGI gateway and routing.
* **Error Handling**: Fail-closed on security evaluations; graceful degradation on non-critical metrics.

---

## 3. Testing & Verification Rules

* Every new detector, algorithm, or cryptographic component MUST have accompanying deterministic automated tests in the `tests/` directory.
* Run tests using:
  ```bash
  uv run pytest -v
  ```
* Ensure 100% test pass rate before committing any changes.
* Never commit secrets, private keys, or `.env` files to git.
