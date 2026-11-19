# Spec 2: API Route Registry, Data Contracts, and Cloaking Specifications

> **Document Version**: 2.0  
> **Target**: Chainmark AI Gateway (`chainmark.interceptor.proxy`)

---

## 1. Existing Routes and Their Versions

| Route | Method | Version | Purpose | Input | Output |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `/health` | `GET` | v1 | Gateway health, active policies, public key | None | Health JSON with signing public key |
| `/v1/chat/completions` | `POST` | v1 (OpenAI) | Transparent LLM chat proxy with fragment assembly & detokenization | Standard OpenAI payload (`messages`, `model`, `stream`) | OpenAI completion object or SSE chunk stream |
| `/v1beta/models/{model_path:path}:generateContent` | `POST` | v1beta (Gemini) | Transparent Google Gemini proxy with PII tokenization | Standard Gemini payload (`contents`, `parts`) | Gemini response with candidate text parts |
| `/v1/evidence/export/{session_id}` | `GET` | v1 | Download signed ZIP evidence bundle | `session_id` (path) | `application/zip` bundle |
| `/v1/evidence/verify/{session_id}` | `GET` | v1 | Verify in-memory hash chain integrity | `session_id` (path) | Verification JSON (valid, merkle_root, signature) |
| `/api/sessions` | `GET` | v1 (Internal) | List active recorded sessions | None | Array of session summaries |
| `/api/sessions/{session_id}` | `GET` | v1 (Internal) | Fetch full event DAG for a session | `session_id` (path) | Full session event log + Merkle proof |
| `/api/simulate` | `POST` | v1 (Internal) | Playground comparison of protected vs unprotected egress | `session_id`, `messages`, `protected` | Simulation result with egress payload & tokens |
| `/api/tamper/{session_id}` | `POST` | v1 (Internal) | Artificially mutates event hash for tamper-test demo | `session_id` (path) | Tamper confirmation with failure diagnostic |

---

## 2. New Dedicated Cloaking Routes

These routes provide direct functional cloaking (tokenization) and uncloaking (detokenization) for testing model parsing capabilities independently of an external LLM call.

### 2.1 Route: `/cloak`
* **Method**: `POST`
* **Endpoints**: `/cloak` and `/v1/cloak`
* **Version**: `v1`
* **Purpose**: Analyzes input text, detects sensitive entities and split fragments (Aadhaar with Verhoeff check, payment cards with Luhn check, PAN, SSN, MRN), encrypts sensitive values into the AES-256-GCM vault, replaces them with format-preserving typed tokens (`[CM_TOKEN_<TYPE>_<HASH>]`), and commits an event to the Merkle DAG.
* **Input Schema** (`application/json`):
  ```json
  {
    "text": "User Aadhaar is 4567-8901 and suffix is 2341, PAN is ABCPE1234F",
    "cloak_request_id": "req_test_01",
    "history": [
      {"role": "user", "content": "Optional previous turn or fragment"}
    ]
  }
  ```
  * `text` *(required, string)*: The raw text or prompt to be parsed and cloaked.
  * `cloak_request_id` *(optional, string)*: Unique identifier. If omitted, the gateway auto-generates a UUID/nanoid.
  * `history` *(optional, list of messages)*: Prior conversation turns to detect multi-turn fragment jigsaw reassembly.

* **Output Schema** (`200 OK`, `application/json`):
  ```json
  {
    "status": "success",
    "cloak_request_id": "req_test_01",
    "original_text": "User Aadhaar is 4567-8901 and suffix is 2341, PAN is ABCPE1234F",
    "cloaked_text": "User Aadhaar is [CM_TOKEN_AADHAAR_07608f09] and suffix is [CM_TOKEN_AADHAAR_07608f09], PAN is [CM_TOKEN_PAN_a1b2c3d4]",
    "detected_entities": [
      {
        "entity_type": "AADHAAR",
        "raw_value": "456789012341",
        "token": "[CM_TOKEN_AADHAAR_07608f09]",
        "confidence": 1.0,
        "is_fragment_assembly": true,
        "provenance_turns": [0]
      },
      {
        "entity_type": "PAN",
        "raw_value": "ABCPE1234F",
        "token": "[CM_TOKEN_PAN_a1b2c3d4]",
        "confidence": 1.0,
        "is_fragment_assembly": false,
        "provenance_turns": [0]
      }
    ],
    "tokens_mapped": [
      "[CM_TOKEN_AADHAAR_07608f09]",
      "[CM_TOKEN_PAN_a1b2c3d4]"
    ],
    "merkle_root": "41a880de1e36044418d4390e9b0b6df02db638455daa76228ac161df71579ecb",
    "event_sequence": 0
  }
  ```

---

### 2.2 Route: `/uncloak/{cloakrequestid}`
* **Method**: `POST` (also supports `GET`)
* **Endpoints**: `/uncloak/{cloakrequestid}` and `POST /uncloak`
* **Version**: `v1`
* **Purpose**: Restores cloaked text containing `[CM_TOKEN_...]` back to original plaintext using the encrypted AES-256-GCM vault associated with `cloakrequestid`. Records a cryptographically chained uncloak event in the Merkle DAG.
* **Input**:
  * **Path Parameter**: `cloakrequestid: str`
  * **Body** (`application/json`):
    ```json
    {
      "cloaked_text": "Processed verification for [CM_TOKEN_AADHAAR_07608f09] successfully."
    }
    ```
    *(If body is empty, it returns the uncloaked original text associated with the request ID).*

* **Output Schema** (`200 OK`, `application/json`):
  ```json
  {
    "status": "success",
    "cloak_request_id": "req_test_01",
    "cloaked_text": "Processed verification for [CM_TOKEN_AADHAAR_07608f09] successfully.",
    "uncloaked_text": "Processed verification for 456789012341 successfully.",
    "tokens_restored_count": 1,
    "merkle_root": "89ab12cd...",
    "event_sequence": 1
  }
  ```

---

## 3. Simplified Frontend Specification

The complex landing page is scrapped entirely in favor of a **minimalist, hyper-focused model parsing and cloaking workbench**:
* Single clean view with two primary panes:
  1. **Input & Cloak Pane**:
     - Text area for prompt / text.
     - One-click sample test buttons (Split Aadhaar, PAN card, US SSN, Patient MRN).
     - Cloak Request ID field (auto-generated or custom).
     - **"Cloak Text"** button calling `POST /cloak`.
  2. **Model Output & Uncloak Pane**:
     - Displays the cloaked wire payload (`[CM_TOKEN_...]`).
     - Entity badges: entity type, raw value, mathematical validation (Verhoeff/Luhn/Regex), fragment assembly status.
     - Editable LLM output response box containing the tokens.
     - **"Uncloak Response"** button calling `POST /uncloak/{cloakrequestid}`.
     - Restored plaintext output box.
* Top bar with:
  - `/health` indicator.
  - Merkle Root and 1-click Download Evidence Pack.
