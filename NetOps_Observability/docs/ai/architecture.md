# Correlix AI — Architecture

Correlix AI is an **application-aware, evidence-grounded NOC copilot**, not a thin
wrapper around an LLM. Correlix tools and evidence remain the system of truth; the
model explains, reasons, summarizes, and recommends — it never invents facts and
never reaches a database directly.

Code lives in `src/backend/ai/` (the pure, transport-free package) and
`src/backend/ai_*.go` (the server wiring that implements the data seams).

## Pipeline

```
Ask Correlix (UI / slash bar)
  → AI Gateway          (handleAIAsk: auth, tenant, rate limit, bounds, audit)
  → Slash parser        (ResolveCommand: "/status" → canonical question)
  → Intent Router       (Classify → Plan{intent, modules, mode, tools})
  → Module Registry     (registry.go: what each module is + availability)
  → Policy Engine        (policy.go: capability/availability/RBAC gate — deterministic)
  → Governed Tools       (tools.go + ai_datasource.go: tenant-scoped, read-only)
  → Evidence Bundle      (cited EvidenceItems, never raw dumps)
  → Network Expert KB    (kb.go: curated supporting knowledge — never truth)
  → Model Router         (llm.go: provider-neutral; mock/none fallback)
  → Response Quality     (quality.go: NOC wording, owner, next actions, badges)
  → Structured Answer    (schemas.go: typed answer mode → UI card)
```

## Key principles (enforced in code)

- **Tenant isolation everywhere.** The only place the AI touches a store is
  `aiDataSource` (`ai_datasource.go`), and every read is tenant-scoped via the
  ClickHouse row policy (`chTenantScope`) or a `(tenant, cross)` store call. A
  non-cross caller can never see another tenant's data (cross-tenant id → 404).
- **The model never decides its own permissions.** `policy.go` (deterministic Go)
  gates every tool by capability (read-only in v1), module availability, and
  RBAC/PBAC before execution.
- **No raw SQL / shell / unrestricted log search exposed to the model.** Tools run
  fixed, allowlisted queries chosen by the tool, never by the model.
- **Honest degradation.** No provider → polished **evidence-only** answer (not a
  raw "provider unavailable"). Unbuilt module/tool → honest "not available yet",
  never faked data.
- **Untrusted data.** Any text inside evidence/logs/tickets is treated as DATA,
  never as instructions (prompt-injection defense, LLM01).

## Answer modes

`schemas.go` defines the typed answer modes the UI renders as cards:
`problem_explanation`, `current_state_summary`, `module_health_summary`,
`investigation_plan` (KB), `product_navigation_help`, plus future-phase
`shift_handoff` / `time_range_outage_summary` (honest disclosure until built).

## What's built vs. contracted

- **Built:** gateway, module registry (15 modules), policy engine, governed tool
  registry (RCA + flow + telemetry + app-id + integrations + ITSM-enrichment),
  evidence bundle, response-quality layer, provider abstraction + mock, `/status`
  & `/explain` & module routes, **Network Expert KB**, **slash commands**.
- **Contracted (later phases):** RAG embeddings (KB is keyword-scored today),
  verifier model + unsupported-claim detector, persisted conversations + feedback
  loop, write-capable (still draft-only) actions behind the P6 action gate, and an
  external read-only MCP server (P7).

See `module-registry.md`, `tool-registry.md`, `network-expert-kb.md`,
`guardrails.md`, `provider-routing.md`, and the how-to guides.
