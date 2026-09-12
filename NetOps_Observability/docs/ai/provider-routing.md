# Provider routing & response quality

## Provider abstraction (`src/backend/ai/llm.go`)

The ai package depends only on the `LLMClient` interface
(`Complete(ctx, system, msgs) → (text, provider, err)`). It holds **no** provider
key and makes **no** raw HTTP call. The server wires it to the existing
provider-agnostic proxy (`copilot.go`'s provider chain — bounds, key custody,
redaction, audit). Tests use `MockLLM` (deterministic, offline).

- The **system prompt is server-owned** (LLM01) — the client can't override it or
  inject a system turn.
- **Evidence-only fallback:** if the provider errors or returns empty, the
  orchestrator returns a polished deterministic summary built from the
  Response-Quality layer (not a raw "provider unavailable"). The KB direct-answer
  path (`/playbook`) and product-navigation are deterministic by design.

## Model Router (§10)

`RouteFor(mode)` (`ai/router.go`) is the intent→tier policy: it classifies each
answer mode by the model tier it needs and whether the verifier applies.

| Mode | Tier | LLM | Verify |
|------|------|-----|--------|
| problem_explanation | strong | yes | yes |
| current_state / module_health | fast | yes | yes |
| investigation_plan (KB) / navigation / shift_handoff / time_range / incident_list | deterministic | no | no |

Most answer modes are **deterministic** — built from tools/KB/registry, no
provider call at all — which is why the copilot works key-free. The chosen tier
is recorded in the audit line. Per-tier providers (a fast model vs. a strong one)
plug into the single `LLMClient` seam without touching the orchestrator; today
they resolve through one provider chain + the evidence-only fallback.

## Verifier / unsupported-claim detector (§11, §16)

`VerifyGrounding` (`ai/verify.go`) is a **deterministic** post-check on every
model narrative: it strips bracketed citations the model invented (a "kind:detail"
id not in the evidence bundle) — fabricated grounding is the worst hallucination.
Genuine citations and non-citation brackets are untouched. When it removes
anything the answer is badged **Verified** and a disclaimer notes the removal.
Being deterministic it's always-on and free (no verifier-model call).

## Feedback loop (§14)

Thumbs up/down on an answer POST to `/api/ai/feedback` and persist to
`ai_feedback` (tenant-isolated, **privacy-safe** — rating + intent/mode/
conversation id only, never the question or answer text). `GET /api/ai/feedback`
returns the tenant-scoped aggregate (up/down + per-intent) for the quality loop.
Full conversation-transcript persistence is a deliberate **non-goal** (it would
conflict with the no-PII audit stance).

## Response Quality Layer (`src/backend/ai/quality.go`)

Turns engine vocabulary into NOC-ready language across **every** answer mode:

- `0%` → *Confidence not established*; unclassified correlation → *low-evidence*;
  owner unassigned → *Recommended owner: Needs triage*; `needs ospf_adjacency_change`
  → *OSPF adjacency-change evidence not found*; provider down → *Evidence-only mode*
  (not repeated in the body).
- Deterministic structured fields — status, confidence label, recommended owner,
  next actions, missing evidence, badges — are built from tools/engine, **never**
  trusted to the model. The model only writes the short narrative headline.

## Current-state prioritization

`/status` and "what is going on right now" rank focus by **actionability, not
recency**: confirmed > suspected > undetermined, classified > unclassified,
service-impacting > infra-only, multi-signal/multi-node > single. A suspected,
classified incident outranks a 0%-confidence undetermined correlation.
