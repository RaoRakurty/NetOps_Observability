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

> Routing different intents to different model tiers (fast vs. strong vs. verifier)
> is contracted for a later phase — the seam is the single `LLMClient`, so it's a
> drop-in. Today one provider chain serves all intents with the safe fallback.

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
