# Chainmark AI: Product & Engineering Plan

> **Slogan**: *"Stop the leak, and prove it."*  
> **Team**: Avengers (Google DeepMind | Google Cloud Startup Buildathon India 2026)  
> **Core Value Proposition**: A transparent guard and cryptographic evidence layer for AI agents handling sensitive personal and health data. Intercepts split fragments across multi-turn sessions, swaps them for typed tokens via an encrypted vault, and seals every transaction into an offline-verifiable Merkle DAG evidence pack.

---

## 1. Architectural Blueprint

Chainmark AI implements a 4-zone defense-in-depth architecture:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 SYSTEM ARCHITECTURE                                    │
│                                                                                        │
│  [Z0: UNTRUSTED BOUNDARY]                                                              │
│  • AI Agent Runtime (Google ADK, LangGraph, CrewAI, AutoGen)                           │
│  • Tools, Plugins, MCP Servers, Vector Databases                                       │
│  • External LLM Providers (Google Gemini, OpenAI)                                      │
│                                                                                        │
│  [Z1: CUSTOMER ENVIRONMENT (DATA PLANE)]                                               │
│  • L1 Interceptor: FastAPI transparent reverse proxy (OpenAI & Gemini API compatible) │
│  • L2 Detector & Session Buffer: <3ms multi-turn sliding window jigsaw taint engine    │
│  • L3 Policy Evaluator: Compliance engine (DPDP 2025/2026, HIPAA, GDPR)                │
│  • L4 Redaction Ladder: Format-preserving typed tokenization + AES-256-GCM vault      │
│  • L5 Evidence Spool: Monotonic append-only cryptographic event queue                  │
│                                                                                        │
│  [Z2: EVIDENCE PLANE (ISOLATED RUNTIME)]                                               │
│  • Merkle Tree Subchain Writer: Sequential SHA-256 hash chaining                       │
│  • Evidence Pack Exporter: Dual-signed ZIP bundle (manifest, events.jsonl, signature) │
│  • Standalone Offline Verifier CLI: Mathematical non-leakage proof for auditors/DPOs   │
│                                                                                        │
│  [Z3: HARDWARE TRUST & NOTARY]                                                         │
│  • Customer KMS / HSM (Google Cloud KMS / Local ECDSA P-256)                           │
│  • RFC 3161 Trusted Timestamping Authority (TSA)                                       │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Phased Development Roadmap

### Phase 1: Core Backend & Flight Recorder Engine (Current)
* [x] Git repository initialization and core documentation (`plan.md`, `agents.md`).
* [ ] Dependency management with `uv` (`pyproject.toml`).
* [ ] **Detector & Checksum Engine (`chainmark.detector`)**:
  * Mathematical Verhoeff algorithm for Indian 12-digit Aadhaar.
  * Luhn algorithm for 16-digit Payment Cards.
  * Strict regex for Indian PAN (`[A-Z]{5}[0-9]{4}[A-Z]{1}`) and US SSN (`\d{3}-\d{2}-\d{4}`).
  * Healthcare Medical Record Numbers (MRN).
  * Sliding session memory graph for assembling split fragments across multi-turn agent tool executions.
* [ ] **Cryptographic Vault (`chainmark.vault`)**:
  * AES-256-GCM local authenticated encryption with unique initialization vector per entry.
  * Typed semantic tokens (`[CM_TOKEN_<ENTITY>_<HASH>]`) preserving LLM reasoning context.
  * On-the-fly streaming detokenizer with a 32-token sliding window for SSE responses.
* [ ] **Evidence Plane & Verifier (`chainmark.evidence`)**:
  * Monotonic sequential SHA-256 hash chaining.
  * Merkle root calculation per session batch.
  * ECDSA P-256 signing of evidence roots.
  * Standalone CLI (`chainmark-verify`) runnable on air-gapped machines.
* [ ] **Interceptor Proxy (`chainmark.interceptor`)**:
  * FastAPI reverse proxy supporting OpenAI (`/v1/chat/completions`) and Gemini (`/v1beta/models/...:generateContent`).
  * End-to-end unit test suite with 100% passing tests.

### Phase 2: Google Cloud & DeepMind Ecosystem Integration
* [ ] Google Cloud KMS integration for Customer-Managed Encryption Keys (CMEK).
* [ ] Google Sensitive Data Protection (Cloud DLP) integration for enterprise catalog coverage.
* [ ] Google Model Armor integration for jailbreak prevention and safety scanning.
* [ ] Google ADK (Agent Development Kit) interceptor middleware package.
* [ ] Cloud Run deployment templates and Terraform / Helm charts.

### Phase 3: High-Stakes Verticals (Healthcare & Clinical Trials)
* [ ] HIPAA 18 Safe Harbor identifier policies.
* [ ] FDA 21 CFR Part 11 compliant audit trail formatting with immutable time-stamps.
* [ ] Clinical trial patient recruitment copilot demo: screening fragmented patient charts against ClinicalTrials.gov protocols without PHI egress.

### Phase 4: Frontend Console & Evidence Visualizer
* [ ] React + TypeScript CISO/DPO console.
* [ ] Real-time session taint inspector showing before/after tokenization.
* [ ] Interactive Merkle-tree visualizer with 1-click Evidence Pack download.

---

## 3. Threat Model & Security Invariants

1. **Zero Raw Sensitive Egress**: Under no circumstances may raw PII/PHI be forwarded to upstream LLMs. If an entity is detected or reconstructed, it MUST be replaced with a typed HMAC token.
2. **Fail-Closed Default**: In production environments, any vault or policy evaluation failure halts request egress and returns an HTTP 403 policy violation.
3. **Immutable Sequence**: Evidence chain event nodes must maintain strictly monotonic sequence numbers. Any omitted, altered, or reordered event breaks the Merkle root hash.
4. **Air-Gapped Admissibility**: Regulatory audit evidence packs must be 100% self-contained and verifiable without requiring network connectivity or vendor server access.
