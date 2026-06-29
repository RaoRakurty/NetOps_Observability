# Correlix AI — High-Level Design (HLD)

**Status:** Design baseline for build · **Date:** 2026-06-29
**Supersedes/merges:** owner's "application-aware NOC copilot" scope expansion (2026-06-29) +
research proposal `docs/design/ai-strategy-and-guardrails-2026-06-29.md`.
**Grounding:** `CLAUDE.md` §3 (zero-trust), §3a (tenant isolation), §15 (OWASP LLM); existing
`src/backend/copilot.go`; paused `docs/design/intent-based-automation.md`.

---

## 0. Core design statement

> **Correlix AI is an application-aware, evidence-grounded NOC copilot that understands Correlix
> modules, live operational state, topology, RCA evidence, telemetry, ITSM context, and product
> workflows through *governed tools* — not through unrestricted database access or hardcoded
> question lists.**

The AI is **not** a fixed menu of phrases ("Explain Problem P-xxxxx"). That is one high-value use
case. The AI must answer broad natural-language questions across the whole product by **classifying
intent → routing to modules → selecting governed read-only tools → grounding the answer in cited
evidence**, all inside tenant/RBAC/PBAC and module-availability constraints.

---

## 1. How this HLD reconciles the two designs

| Concern | Research proposal (mine) | Owner vision (scope expansion) | **HLD resolution** |
|---|---|---|---|
| Breadth | Grounded read-only **RCA/telemetry** assistant | **Whole-application** module-aware copilot, broad NL | **Adopt owner breadth.** RCA Explainer is Phase 1; the platform is built module-generic from day one |
| Tool model | Internal `ReadTool` Go interface | **Module Tool Registry** (typed, per-module) | **Same thing, productized.** `ReadTool` *is* the registry entry; registry groups them by module |
| Routing | Pre-retrieve from question / small read-tool loop | **Intent classifier → module router → tool policy** | **Adopt owner router.** Classifier emits `{intent, modules, time_range, entities, urgency, freshness, permissions, tools, answer_format}` |
| Knowledge | (implicit) | **Application Knowledge Layer + Module Registry** | **Adopt.** Explicit code registry the orchestrator reads for routing + tool selection + availability |
| Grounding | Context envelope + **citation ids** + redaction | evidence-grounded answers, disclose missing data | **Merge.** Owner's "evidence bundle" = my context envelope with citation ids; redaction + missing-evidence disclosure are mandatory |
| Answer shape | prose + cited links | **Answer modes / response schemas** (12 modes) | **Adopt owner modes.** Each mode = a typed response schema the UI renders |
| Tenancy / safety | §3a enforcement, redaction, isolation test | tenant/RBAC/PBAC, module availability, no raw SQL/shell, no cross-tenant | **Identical intent — keep all.** Enforced in-process where claims live |
| Device safety | read-only default; deterministic policy engine; staged ladder | read-only v1; controlled actions = future, human-approved | **Identical.** Writes are a separate, gated, off-by-default subsystem (P6) |
| MCP | **NO now**, conditional YES later (multi-client) | **Phase 7 future** (Correlix MCP server, partner/agent interop) | **Aligned.** No MCP in P0–P6; build internal tool interface so MCP is a thin adapter later |
| Model strategy | provider-agnostic proxy, tiers, self-host seam, no training | (uses existing LLMs) | **Keep proxy as egress chokepoint**; add self-host as a provider; no fine-tuning |

**Net:** the owner vision sets the *product shape*; the research doc supplies the *safety, grounding,
tenancy, and MCP rigor* that makes it shippable. This HLD is their union.

---

## 2. Architecture overview

```
 React "Ask AI" (escaped render, evidence links, answer-mode cards)
        │  question + UI context (active route, selected entity, time range)
        ▼
 /api/ai/ask  ──►  [auth · audit · rate-limit · feature-flag]          (exists: copilot.go middleware)
        │
        ▼
 ┌────────────────────────── AI Orchestrator (Go, in-process) ──────────────────────────┐
 │  1. Intent Classifier      → intent + entities + time_range + urgency + answer_format │
 │  2. Module Router          → target module(s)  (reads Application Knowledge Layer)    │
 │  3. Availability + Policy   → is_module_enabled(tenant) · required perms · allowed tools│
 │  4. Tool Planner           → selects governed READ-ONLY tools from Module Tool Registry │
 │  5. Evidence Bundle Builder→ runs tools (tenant-scoped) → typed context + citation ids │
 │     └─ Redaction (LLM02) · OperatorRestricted honored · bounds/caps                    │
 │  6. Prompt Assembler       → server-owned system prompt + bundle + answer-mode schema  │
 │  7. LLM Provider Proxy      → OpenAI/Gemini/Anthropic/self-host (egress chokepoint)    │
 │  8. Response Builder        → validate to answer-mode schema · attach cited evidence   │
 │  9. AI Audit                → principal, tenant, intent, tools, citations, tokens      │
 └───────────────────────────────────────────────────────────────────────────────────────┘
        ▲ knowledge                         ▲ tools (read-only v1)
 Application Knowledge Layer          Module Tool Registry
 (Module Registry + Product Nav)      (typed tools grouped by module)

 ── P6+ ONLY, SEPARATE subsystem the model CANNOT call ──
 Action Proposal → Policy Engine (deny/allow, blast-radius, window, RBAC, 2-person)
                 → Dry-run/Diff → Human checklist approval → Executor → Audit → Rollback
```

**Enforcement points:** auth/rate/audit at the route (exists); tenant scope + redaction + bounds in
the Evidence Bundle Builder (the *only* place data leaves a store toward a prompt); egress bounds +
key custody at the proxy (exists); device-safety policy in the P6 Executor subsystem (deterministic
Go, outside the model loop).

---

## 3. Application Knowledge Layer (AKL)

Code-resident registry (not docs) the orchestrator reads for routing, tool selection, availability,
and response shaping. Two parts: **Module Registry** and **Product Navigation map**.

### 3.1 Module Registry — schema

```jsonc
{
  "module_id": "event_management",
  "display_name": "Event Management",
  "description": "Events, incidents, anomalies, correlations, and RCA problem groups.",
  "entities": ["event","incident","anomaly","correlation_group","problem"],
  "question_categories": ["active_incidents","problem_explanation","outage_summary",
                          "event_noise","missing_evidence","recommended_owner"],
  "tools": ["get_active_major_incidents","get_problem","get_problem_timeline",
            "get_problem_evidence","get_related_events","get_recommended_owner"],
  "permissions": ["events:read","correlations:read"],   // PBAC/RBAC gate
  "freshness": "live",                                    // live | recent | historical | config
  "sensitivity": "operational",                          // operational | sensitive | restricted
  "availability_flag": "ENABLE_EVENT_MANAGEMENT",        // is_module_enabled() source
  "cross_module": ["topology","itsm","app_identification"],
  "response_modes": ["problem_explanation","current_state_summary","missing_evidence_explanation"]
}
```

### 3.2 Modules to define (placeholders allowed where the product surface is thin)

`command_center`, `event_management`, `correlations_rca`, `topology`, `cloud_app_observability`,
`app_identification`, `telemetry`, `flow_analytics`, `itsm`, `reports`, `integrations`,
`tenant_admin`, `audit`, plus `product_navigation` (special, see §3.3).
Modules not yet real in the repo are registered with `availability: "future"` and answer with a
clean "not available yet" disclosure — never a hallucinated answer.

### 3.3 Product Navigation module

Static config mapping `feature → UI route → required permission → short explanation → related module`,
so the AI answers "where do I configure ServiceNow?", "where's the topology path for this incident?"
with a real deep link the user can click (ties into the existing nav route ids — e.g. Topo =
`#/infrastructure/topology-canvas`, ServiceNow = `#/incident/integrations`).

### 3.4 Module availability

`is_module_enabled(tenant_id, module_id)` and `get_enabled_modules(tenant_id)` resolve from feature
flags + tenant config. The router consults these **before** answering; a disabled module yields a
graceful disclosure ("Cloud App Observability isn't enabled for this tenant; I can still summarize
the network/flow/event signals that are available.").

---

## 4. Module Tool Registry

Typed, read-only (v1) tools grouped by module. Each tool implements one Go interface so the
orchestrator calls them uniformly, tenant scope is enforced once, and an MCP adapter is a thin shell
later (§9).

```go
type AITool interface {
    Name() string                       // e.g. "get_problem_evidence"
    Module() string                     // e.g. "correlations_rca"
    RequiredPerms() []string            // checked against caller claims
    Freshness() Freshness               // live|recent|historical|config
    InputSchema() jsonschema            // validated in
    Run(ctx, claims, args) (ToolResult, error)  // tenant-scoped, bounded, READ-ONLY
}
type ToolResult struct {
    Items     []EvidenceItem  // each with a stable citation id
    Truncated bool            // disclose when capped
    Notes     []string        // freshness / missing-data notes
}
```

**Tool inventory (v1 = read-only).** Implement those backed by current repo data; stub the rest with
explicit `ErrNotImplemented` (clean "not available yet"):

- **command_center:** `get_current_health_summary` · `get_active_major_incidents` ·
  `get_noc_priority_queue` · `get_top_impacted_services` · `get_top_impacted_sites`
- **event_management:** `get_events` · `get_incidents` · `get_anomalies` · `get_correlation_groups` ·
  `get_event_noise_summary` · `get_event_timeline`
- **correlations_rca:** `get_problem` · `get_problem_timeline` · `get_problem_evidence` ·
  `get_candidate_root_domains` · `get_missing_evidence` · `get_recommended_owner`
- **topology:** `get_topology_path` · `get_entity_neighbors` · `get_service_dependency_map` ·
  `get_blast_radius` · `explain_topology_path`
- **cloud_app_observability:** `get_cloud_app_health` · `get_saas_impact_summary` ·
  `get_cloud_dependency_path` · `get_cloud_app_anomalies`
- **app_identification:** `get_app_identity_summary` · `get_low_confidence_app_matches` ·
  `explain_app_identification` · `get_vendor_catalog_match`
- **telemetry:** `get_metric_anomalies` · `get_syslog_summary` · `get_snmp_trap_summary` ·
  `get_probe_health` · `get_interface_health`
- **flow_analytics:** `get_flow_summary` · `get_app_to_db_flow_summary` · `get_top_talkers` ·
  `get_east_west_flow_anomalies` · `get_retransmission_or_retry_summary`
- **itsm:** `get_related_tickets` · `get_ticket_status_summary` · `generate_itsm_update` ·
  `get_ticket_sync_status`
- **reports:** `generate_shift_summary` · `generate_daily_summary` · `generate_executive_summary`
- **integrations:** `get_integration_health` · `get_servicenow_sync_status` ·
  `get_slack_delivery_status` · `get_pagerduty_sync_status`
- **tenant_admin / audit:** `get_ai_audit_summary` · `get_tenant_ai_usage` · `get_policy_events`

All v1 tools are **read-only, tenant-scoped, bounded**. No raw SQL, no shell, no unbounded log dumps,
no cross-tenant search, no autonomous remediation. Write tools (P6) live in the separate gated
subsystem and the model can never call them.

**Backing the read tools (reuse §3a.4 isolation primitives):** ClickHouse via `chTenantScope`,
OpenSearch via per-tenant index + `osTenantFilter`, VictoriaMetrics via device/tenant label filter,
Postgres/topology via `withTenant` + FORCE-RLS. The tool is the *only* place a store is touched for AI.

---

## 5. AI Gateway / Orchestrator — dynamic routing

The orchestrator turns a free-text question + UI context into a governed plan:

```jsonc
// "What happened last night?"
{ "intent":"summarize_time_range", "modules":["event_management","correlations_rca","topology","itsm"],
  "time_range":"previous_night", "entities":[], "urgency":"normal", "freshness":"historical",
  "tools":["get_outage_summary","get_open_incidents","get_problem_evidence","get_itsm_ticket_summary"],
  "answer_format":"noc_shift_summary" }

// "Why is the DC application slow?"
{ "intent":"investigate_service_degradation",
  "modules":["topology","flow_analytics","telemetry","correlations_rca","cloud_app_observability"],
  "tools":["find_impacted_services","get_topology_path","get_metric_anomalies","get_flow_summary","get_related_problems"],
  "freshness":"recent", "answer_format":"investigation_summary" }
```

Stages: **(1) Intent classifier** (small/fast model or rules+model hybrid) → intent + answer_format.
**(2) Entity & time-range extractor** (devices, sites, problem ids like `P-122345`, "last night").
**(3) Module router** (AKL lookup; multi-module allowed). **(4) Availability + permission filter**
(drop modules disabled or not permitted; disclose). **(5) Tool planner** (pick the minimal governed
tools for the intent + freshness). **(6) Evidence bundle builder** (run tools, build cited context,
redact). **(7) Prompt + answer-mode schema → proxy. (8) Response builder** (validate to schema, attach
evidence). The model **never** chooses raw queries; it chooses among *named, governed tools* (or the
router pre-selects them).

**Freshness drives tool choice:** `live` (current health, active incidents, topology status),
`recent` (15m/1h/24h telemetry/flow summaries), `historical` (reports, prior problems, postmortems),
`config` (tenant settings, integrations, availability).

---

## 6. Answer modes (typed response schemas)

The Response Builder validates the model's output into one of these schemas; the UI has a card per
mode. Modes: `problem_explanation`, `current_state_summary`, `time_range_outage_summary`,
`module_health_summary`, `topology_path_explanation`, `evidence_explanation`,
`missing_evidence_explanation`, `itsm_update`, `shift_handoff`, `executive_summary`,
`product_navigation_help`, `investigation_plan`.

```jsonc
// current_state_summary
{ "summary":"", "priority_items":[], "active_incidents":[], "impacted_services":[],
  "impacted_sites":[], "new_since_last_hour":[], "recommended_focus":[], "confidence_notes":[],
  "missing_data":[] }
// product_navigation_help
{ "answer":"", "ui_location":"", "required_permission":"", "related_modules":[], "next_steps":[] }
```

Every schema carries `citations[]` (evidence ids) and a `missing_data` / `disclaimers` field so the
answer is always grounded and honest about gaps and disabled modules.

---

## 7. Guardrails, tenancy & safety (non-negotiable)

1. **Broad NL + strictly governed tools.** The model decides *what to retrieve* only by choosing
   among approved, scoped tools — never raw DB/SQL/shell/log-dump/cross-tenant search.
2. **Tenant/RBAC/PBAC in-process.** Every tool scopes by `principalTenant(claims)` default-closed
   (§3a.1); owner stamped from token (§3a.2); cross-tenant id → 404. Ship a cross-org isolation test
   with every tool (`org_isolation_test.go` template, §3a.5) — no AI tool merges without it.
3. **Redaction before egress (LLM02).** Strip secrets/PII; honor `OperatorRestricted`; sanitize
   prompt logs; raw provider errors stay server-side.
4. **Untrusted ingested data (LLM01).** Log/ticket/event/device text in the bundle is *data*, not
   instructions; "ignore previous instructions…" embedded in a syslog line is never honored.
5. **Evidence-grounded + disclosure.** Answers cite evidence ids (clickable back into RCA/Logs/Topo);
   the model must disclose missing evidence and disabled modules rather than guess.
6. **Bounded (LLM10).** `MaxBytesReader`, msg/char/token caps, per-principal + per-tenant token
   budget, top-N/time-boxed tool results (disclose truncation).
7. **No device path in v1 (LLM06).** Read-only. Writes are a separate, deterministic, human-gated
   Executor subsystem (P6), off by default like `FEATURE_DEVICE_SSH`; the model cannot call it.
8. **Disable-by-config + full AI audit.** `FEATURE_AI` master flag; every ask audited (principal,
   tenant, intent, modules, tools, citations, tokens, latency); no silent failures (§10).

---

## 8. Model strategy

Keep the provider-agnostic proxy as the single egress chokepoint (bounds, redaction, audit, key
custody). Route by task tier (fast/cheap for classify+summarize; reasoning for multi-signal RCA).
Add **self-host (vLLM/Ollama) as just another provider** for air-gapped customers, with a hard
"no external egress" deploy flag (no silent fallback to public APIs). **No fine-tuning / no training
our own model** — strategy is grounding + governed tools on existing LLMs.

---

## 9. MCP — verdict: **NO for P0–P6, conditional YES at P7**

For our architecture today (single trusted backend, in-process Go tools, multi-tenant RLS,
on-prem-capable, stdlib-only) an in-process tool layer beats an MCP server on attack surface, tenant
isolation, dependencies, ops burden, and context cost — and MCP "does not enforce security at the
protocol level" (it's the implementer's job). MCP earns its keep only when **external/customer-owned
LLM agents must consume Correlix telemetry & RCA as tools**, or we must consume external MCP tools, or
a partner ecosystem needs a standard contract (P7). Because v1 tools already implement the `AITool`
interface, a future MCP server is a **thin, optional, off-by-default adapter** over the same
tenant-scoped tools (read tools first; per-tenant audience-scoped OAuth; schema-validated both ways).
Full reasoning + sources: `docs/design/ai-strategy-and-guardrails-2026-06-29.md` §6.

---

## 10. Phased plan (revised; gates from the research doc apply to each)

| Phase | Name | Scope | Device risk | Ship gate |
|---|---|---|---|---|
| **P0** | **AI platform foundation** | AI Gateway · **Application Knowledge Layer** · Module Registry · **Module Tool Registry** · intent classifier · entity/time extractor · module router · **tool policy engine** · **evidence bundle builder** · response-schema system · LLM provider abstraction (exists, extend) · **AI audit tables** · guardrails · **mock LLM provider** · tests | None (read-only) | isolation tests green; mock-LLM tests; redaction; no write path; `FEATURE_AI` off-by-default |
| **P1** | **RCA / Problem Explainer** | "Explain Problem P-xxxxx" end-to-end: evidence-backed RCA summary · timeline · supporting/contradicting/**missing** evidence · recommended owner · ITSM note · **RCA answer card UI ("Ask AI" on the Problem/RCA page)** | None | grounded + cited; missing-evidence disclosed; isolation test |
| **P2** | **Command Center AI** | "What's going on right now?" · NOC priority-queue explanation · active-incident summary · top impacted services/sites · recommended focus | None | live-freshness tools; schema-validated |
| **P3** | **Time-range / Shift Summary** | "Explain the outage last night" · summarize a selected range · shift handoff · recurring-incident summary · unresolved follow-ups | None | historical tools; citations |
| **P4** | **Module-aware Copilot** | topology · telemetry · flow · app-identification · cloud-app-obs · ITSM · integration-health · **product-navigation** questions | None | per-module tools + availability disclosure |
| **P5** | **Runbook Advisor** | safe diagnostic checklist · team handoff · provider escalation notes — **advisory text only, no executor** | None (advisory) | output is data, copy-only |
| **P6** | **Controlled Actions (future, off by default)** | create/update ITSM ticket · post Slack · assign owner · (later) gated device change — **explicit human checklist approval, deterministic policy engine, dry-run, blast-radius caps, two-person, audit, rollback** | High — fully gated | policy tests; dry-run proven; security review |
| **P7** | **External AI ecosystem (future)** | **Correlix MCP server** · partner-safe read-only tools · ChatOps · agent-to-agent | per tool | §9 conditions met; MCP security review |

**This pass:** implement **P0 + P1**, and design the Module Registry so **P2–P4 add without
redesign** (new modules/tools/answer-modes are registry entries, not orchestrator rewrites).

**What we DON'T do yet:** no hardcoded-question mapping; no raw SQL/shell/log-dump; no cross-tenant
search; no autonomous remediation; no model→device path; no MCP server; no vector DB in P1 (defer to
per-tenant-partitioned runbook search if ever); no silent egress on air-gapped deploys; no training.

---

## 11. Definition of done

1. AI not limited to a fixed list of hardcoded questions.
2. Orchestrator classifies broad NL questions.
3. Router maps a question to one or more modules.
4. Module Registry describes modules + available tools (in code).
5. Tool access governed by tenant/RBAC/PBAC + module availability.
6. v1 UI supports **Ask AI on the Problem/RCA page**.
7. Backend supports **Problem Explanation end-to-end**.
8. Architecture includes contracts/stubs for Command Center, topology, telemetry, flow, ITSM, and
   product-navigation AI.
9. All answers evidence-grounded (cited).
10. AI discloses missing evidence or disabled modules.
11. Prompt injection in logs/tickets/events treated as untrusted data.
12. AI audit logging works.
13. AI can be disabled by configuration.
14. Tests pass with the mock LLM provider.
15. Docs explain the AKL, Module Registry, Tool Registry, and future MCP plan.

---

## 12. P0/P1 implementation breakdown (next build)

Stdlib-only Go, behind `FEATURE_AI` (off by default), reusing `copilot.go` middleware + proxy:

- `src/backend/ai/registry.go` — Module Registry + AKL types + the 14 module definitions (+ future stubs).
- `src/backend/ai/tools.go` — `AITool` interface + registry; P1 implements the `correlations_rca` read
  tools (`get_problem`, `get_problem_timeline`, `get_problem_evidence`, `get_missing_evidence`,
  `get_recommended_owner`) over the existing correlation store/`rca-path-view`; others stubbed.
- `src/backend/ai/orchestrator.go` — classify → route → availability/perm filter → plan tools →
  build evidence bundle → assemble prompt → proxy → validate to answer-mode schema → audit.
- `src/backend/ai/schemas.go` — answer-mode response schemas (`problem_explanation` first).
- `src/backend/ai/audit.go` + migration — AI audit table.
- `src/backend/ai/mock_provider.go` — deterministic mock LLM for tests.
- `src/backend/ai_handlers.go` — `POST /api/ai/ask` (auth+audit+ratelimit+flag).
- `org_isolation_test.go`-style test asserting tenant A can't retrieve tenant B's problem/evidence.
- Frontend: "Ask AI" entry on the RCA/Problem (Correlations) page rendering the `problem_explanation`
  card with clickable evidence citations (escaped text only).
- Docs: this HLD + a short README in `src/backend/ai/`.

CI per CLAUDE.md §12 (vet/test/race/staticcheck/gosec/govulncheck). No new third-party module.
