# Iris AI — Response Quality Layer, Answer Modes & Ask-Correlix Commands

Status: **shipped** (2026-06-30). Code: `src/backend/ai/` (orchestrator, quality,
tools, registry, schemas), `src/backend/ai_datasource.go` (tenant-scoped reads),
`src/backend/ai_labels.go` (NOC label mirror), `src/frontend/src/tabs/Opsis.tsx`
(panel + reusable answer card + slash menu).

This document is the contract for **how Iris AI answers** — not one-off RCA
formatting. Every answer mode goes through the same governed flow and the same
reusable Response-Quality Layer.

---

## 1. Flow

```
Ask Correlix input (free text OR /command — they converge)
  → Classify()            intent + module(s) + answer mode + entities
  → Policy Engine         module availability + RBAC/PBAC + tool capability gate
  → governed tools        read-only, tenant-scoped (aiDataSource / ModuleDataSource)
  → Response-Quality      quality.go: status, confidence, owner, missing-evidence,
                          next-actions, ranking, scrub, dedup, evidence-only badges
  → LLM narrative         (optional) grounded ONLY in the retrieved evidence;
                          deterministic polished fallback when no provider
  → typed Answer          rendered by the reusable AI answer card
```

Guardrails (CLAUDE.md §3a, §15) hold for every mode: server-owned system prompt,
tenant scoping in the data source (never the model), no secret injection, model
output is escaped React text, read-only by default, audited.

## 2. The Response-Quality Layer (`ai/quality.go`)

Pure, deterministic, unit-tested — runs identically in the model and evidence-only
paths. Reusable across all modes:

| Function | Purpose |
|---|---|
| `StatusLabel` / `MaturitySentence` | confirmed / suspected / candidate / undetermined wording (never overclaims) |
| `ConfidenceLabel` | 0% / undetermined → **"Not established"** (never a bare 0% headline) |
| `FormatMissingEvidence` | `needs ospf_adjacency_change` → "OSPF adjacency-change signal was not found" (key-mapped, deduped) |
| `InferOwner` | domain tokens → team (routing→Network/Routing, firewall→Security, db→Database, …); **"Needs triage"** never bare "unassigned" |
| `NextActionsRCA` / `currentStateNextActions` | concrete operator steps |
| `PriorityScore` / `IsClassified` | operational ranking (confirmed>suspected>candidate>undetermined; classified>unclassified; multi-signal/node; confidence; blast radius) |
| `Scrub` / `dedupeLines` | translate residual internal terms, remove repeats |
| `FallbackBadges` | provider-unavailable → small **badges**, never the main answer |

**RCA maturity** (`MaturitySentence`): a confirmed RCA is only claimed when the
engine marks it confirmed — the layer never promotes undetermined → confirmed.

## 3. Evidence-only fallback (no LLM / disabled / timeout / policy)

The deterministic path produces a **polished operational summary**, and provider
state is a metadata badge:

- main answer: *"Correlix detected a low-evidence incident on leaf4. RCA is
  undetermined — only one signal was observed on one device, and expected
  routing-adjacency evidence (OSPF/IS-IS/BGP) was not found. Recommended owner:
  Network / Routing team, pending confirmation."*
- badges: `Evidence-only mode` · `AI provider not configured`

Never: *"AI provider unavailable — showing an evidence-only summary."* as the body.
The fallback works for every mode (RCA, current-state, module summaries, nav).

## 4. Answer modes (`ai/schemas.go`)

`problem_explanation` · `current_state_summary` · `module_health_summary`
(flow / telemetry / app-identification) · `product_navigation_help` ·
`time_range_outage_summary` + `shift_handoff` (honest disclosure until P3) ·
`unavailable` (disabled / future module). Each answer carries the universal
fields rendered as card badges + sections: `status`, `confidence_label`,
`recommended_owner`, `next_actions`, `missing_evidence`, `mode_badges`,
`evidence_only`.

### Current-state briefing (`/status`, "what's going on")
Ranked by `PriorityScore` (a suspected classified incident outranks an
undetermined 0% one — **not** chosen by recency). Structure: counts → Recommended
focus + "why this is first" → Watch items (undetermined grouped, not dumped) →
Most impacted → Recommended next actions. Single evidence-only badge.

### RCA (`/explain`, "explain this incident")
Summary → status/confidence badges → recommended owner (inferred) → missing
evidence (clean bullets) → next actions → citations. The P-534394 acceptance case
is pinned in `ai/quality_test.go`.

## 5. Module-aware routing

The Application Knowledge Layer (`ai/registry.go`) declares each module's id,
entities, question categories, tools, permissions, freshness, and **availability**
(stable vs future + feature flag). `Classify()` routes module questions via
`moduleRoutes`; a future/disabled module answers with an honest "not enabled yet"
disclosure (never faked data). Live module tools (tenant-scoped, CH row-policy
isolated): flow_analytics (top_talkers, flow_summary), telemetry
(metric_anomalies), app_identification (app_identity_summary, low_confidence_apps).

## 6. Ask-Correlix slash commands (Phase 1)

Free text and `/commands` converge on the same flow — commands are discoverable
shortcuts, not separate logic. The frontend command registry
(`SLASH_COMMANDS` in `Opsis.tsx`) carries command · title · module badge ·
description · availability. Phase 1: `/status` `/top` `/critical` `/explain`
`/talkers` `/anomalies` `/flows` `/handoff` `/itsm` `/where` `/help`. Not-yet-built
commands show a "soon" badge and route to the honest disclosure. Keyboard: `/`
opens, ↑/↓ navigate, Enter/Tab select, Esc dismisses (without closing the panel).

## 7. How to add …

- **an answer mode**: add the `AnswerMode` const + schema struct, a `Classify`
  case, an `answer*` handler that uses the quality layer, and render the new
  sections in `GroundedAnswer`.
- **a module tool**: add a `ModuleQuery` case (one tenant-scoped store read) in
  `ai_datasource.go`, a `moduleTools` entry, and a `moduleRoutes` regex. Ship a
  cross-tenant isolation test (`ai/orchestrator_test.go` template).
- **a slash command**: add a `SLASH_COMMANDS` entry mapping to an existing
  intent/NL question.
- **a NOC label**: add to `ai_labels.go` AND the frontend `labels.ts` (keep parity).

## 8. Testing

All AI tests use a `MockLLM` — **CI needs no provider credentials**. Coverage:
quality formatters, the undetermined-RCA acceptance case (no 0%/provider in body,
inferred owner, clean bullets, evidence-only badge), current-state ranking
(suspected classified beats undetermined 0%, watch grouping, badge-once),
cross-tenant isolation (echo-LLM proves the prompt is tenant-scoped), permission
gate, future-module disclosure. Frontend parity test for `friendlyProblemId`.

> **Product line:** *If an AI explanation is unavailable, Correlix still provides
> an evidence-only operational summary from the correlation engine — what Correlix
> knows, what's missing, the likely owner, and next actions — without inventing
> RCA beyond the available evidence.*
