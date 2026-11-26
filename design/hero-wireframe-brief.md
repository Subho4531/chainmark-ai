# Hero Wireframe — "The Receipt"

**Concept:** replace the decorative seam animation with a real evidence receipt in the first
viewport. The hero's visual proof is the product: raw values go in, tokens come out, and the
chain verifies.

**Priority:** proof and credibility
**Depth:** new layout, existing brand system (black / cream / orange, pixel display + mono)
**Fidelity:** low-fi annotated wireframe — structure and hierarchy, not final UI

---

## Why the current hero is being replaced

| Current | Problem |
|---|---|
| Bracketed word cycles security / evidence / privacy / compliance | Motion carries the meaning; the claim is generic until it stops |
| Abstract seam diagram with moving packets | Beautiful, but it never shows a real payload or a real verification result |
| Two CTAs + a separate copy-prompt bar | Three competing actions; the setup prompt is visually louder than the secondary CTA |
| No proof above the fold | Credibility arrives only after scrolling to the evals section |
| Tall, sparse composition | The right side is decorative; the left side carries all the information |

---

## New composition

**Asymmetric editorial hero, not a centered SaaS block.**

```
┌ header ──────────────────────────────────────────────────────────────┐
│ mark CHAINMARK AI      nav · nav · nav · nav        Log in  [Sign up]│
├──────────────────────────────────────────────────────────────────────┤
│ SECURITY INFRASTRUCTURE · AGENT EGRESS                               │
│                                                                      │
│ Your agents leave tokens.          ┌ REQUEST 0042 · BILLING AGENT ┐  │
│ You keep the proof.                │ AGENT OUTBOUND / RAW          │  │
│                                    │ to   billing@acme-corp.com    │  │
│ Deterministic detection,           │ card 4242 4242 4242 4242      │  │
│ reversible tokenization, and a     │ iban DE89 3704 0044 0532 …    │  │
│ signed evidence chain you can      │ ─── DETECT → TOKENIZE → SEAL ─│  │
│ verify offline.                    │ MODEL INBOUND / SEALED        │  │
│                                    │ to   cm_mail_7f2a             │  │
│ [Start building] [See a verified run] │ card cm_pan_91c4           │  │
│ > uv run python scripts/run_local.py │ iban cm_iban_3d88           │  │
│                                    │ CHAIN VERIFIED · SEQ 0–41     │  │
│                                    │ ECDSA P-256 · 0 PLAINTEXT     │  │
│                                    └───────────────────────────────┘  │
│                                                                      │
│ VERHOEFF + LUHN   AES-256-GCM   OFFLINE VERIFIER                     │
│ 01 INTERCEPT · 02 DETECT · 03 TOKENIZE · 04 SEAL · 05 RESTORE        │
│                                        chainmark-verify → VERIFIED   │
└──────────────────────────────────────────────────────────────────────┘
```

### Copy (exact)

- **Eyebrow:** `SECURITY INFRASTRUCTURE · AGENT EGRESS`
- **Headline:** `Your agents leave tokens.` / `You keep the proof.`
- **Subhead:** `Deterministic detection, reversible tokenization, and a signed evidence
  chain you can verify offline.`
- **Primary CTA:** `Start building`
- **Secondary CTA:** `See a verified run`
- **Command bar:** `uv run python scripts/run_local.py`
- **Proof chips:** `VERHOEFF + LUHN`, `AES-256-GCM`, `OFFLINE VERIFIER`
- **Stage rail:** `01 INTERCEPT`, `02 DETECT`, `03 TOKENIZE`, `04 SEAL`, `05 RESTORE`
- **Terminal line:** `chainmark-verify → VERIFIED · exit 0`

### Receipt panel content

| Field | Raw (agent outbound) | Sealed (model inbound) |
|---|---|---|
| to | `billing@acme-corp.com` | `cm_mail_7f2a` |
| card | `4242 4242 4242 4242` | `cm_pan_91c4` |
| iban | `DE89 3704 0044 0532 0130 00` | `cm_iban_3d88` |
| task | `summarise the invoice and reply` | `summarise the invoice and reply` |

Panel footer: `CHAIN VERIFIED · SEQ 0–41 · ECDSA P-256 · 0 PLAINTEXT`

---

## Annotation legend

1. **Static claim** — one specific headline; no word carousel carrying the meaning.
2. **Proof in viewport** — the evidence receipt is visible before any scroll.
3. **Raw → token** — the visual shows actual values and their tokens, not abstract packets.
4. **Verify result** — `VERIFIED · exit 0` sits inside the hero, not in section 04.
5. **Crypto specifics** — chips name the checksum, cipher and verifier; no vague claims.
6. **One seam** — one horizontal seam organizes the entire composition and the page story.

---

## What this fixes

- **Hierarchy:** eyebrow → claim → explanation → actions → proof rail. One reading path.
- **Credibility:** real formats (Luhn/Verhoeff, AES-256-GCM, ECDSA P-256) and a real
  verification line replace atmosphere.
- **Action clarity:** two CTAs; the setup command is demoted to a quiet inline bar.
- **Density:** the right column earns its space with product evidence.
- **Mobile:** receipt panel stacks under the copy; stage rail becomes a 2×3 grid; proof
  chips wrap; command bar stays full-width.

## Open decisions for the next pass

- Headline voice: "Your agents leave tokens. You keep the proof." vs. a more literal
  "Nothing sensitive leaves without a signed receipt."
- Whether the receipt panel should animate a single request on load or stay static with
  one highlighted row.
- Whether "See a verified run" opens the testbench, scrolls to evals, or plays a short
  terminal sequence in place.
- Real request IDs, session IDs and token suffixes should come from the product, not
  invented constants.

> The generated image is a sketch: treat its typography and label placement as indicative.
> The copy in this brief is the source of truth for the next build.
