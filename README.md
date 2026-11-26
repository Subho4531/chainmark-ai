# Chainmark AI

Cryptographic guard and evidence flight recorder for autonomous AI agents. Intercepts
OpenAI- and Gemini-compatible LLM traffic, detects sensitive entities (including
multi-turn jigsaw assembly), tokenizes them through an AES-256-GCM vault, and seals
every decision in a tamper-evident Merkle hash chain.

## Repository layout

```
chainmark-ai/
├── chainmark/                  Python package (importable as `chainmark`)
│   ├── core/                   Configuration and process lifecycle
│   ├── detector/               Checksums (Verhoeff/Luhn), patterns, taint engine
│   ├── vault/                  AES-256-GCM vault, tokenization, streaming restore
│   ├── evidence/               Hash chain, Merkle root, ECDSA signing, verifier CLI
│   └── interceptor/            FastAPI gateway and protocol routes
├── tests/                      Deterministic pytest suite
├── frontend/                   React + Vite console / testbench
├── scripts/                    Local development entry points
├── docs/
│   └── specs/                  Product and protocol specifications
├── plan.md                     Architecture and phased roadmap
├── agents.md                   Engineering invariants for contributors
└── pyproject.toml              Package metadata, dependencies, pytest config
```

## Quickstart

```bash
uv sync
uv run pytest -v
```

Run the full stack in Docker (console on :8080, gateway on :8010, cloud API on
:3002, Postgres on :5433):

```powershell
.\scripts\docker_up.ps1
```

See [docs/DOCKER.md](docs/DOCKER.md) for service details, health checks, and
port overrides.

Run the local stack (backend on :8000, frontend on :5173):

```powershell
.\scripts\start_local.ps1
```

or, from any directory:

```bash
uv run python scripts/run_local.py
```

## Gateway surface

| Route | Purpose |
| --- | --- |
| `POST /v1/chat/completions` | OpenAI-compatible intercepted proxy |
| `POST /v1beta/models/{model}:generateContent` | Gemini-compatible intercepted proxy |
| `POST /cloak`, `POST /uncloak` | Tokenize / restore arbitrary text |
| `GET /v1/evidence/export/{session_id}` | Download the signed evidence pack |
| `GET /api/sessions` | Session and compliance summaries for the console |
