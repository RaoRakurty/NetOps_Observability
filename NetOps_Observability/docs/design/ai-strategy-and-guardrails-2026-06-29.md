# Correlix AI Strategy & Guardrails — Design Proposal

**Status:** Draft for decision · **Author:** AI architecture pass · **Date:** 2026-06-29
**Scope:** How Correlix builds product AI on top of existing LLMs (we will NOT train our own),
how we keep customers from damaging real network devices through the AI, whether we need an MCP
server, and a concrete phased build plan.
**Grounding:** `CLAUDE.md` §3 (zero-trust), §3a (tenant isolation), §15 (OWASP LLM Top 10);
existing proxy `src/backend/copilot.go`; assistant UI `src/frontend/src/tabs/Opsis.tsx`;
prior design `docs/design/intent-based-automation.md` (PAUSED).

---

## 1. Executive summary (read this first)

Correlix already ships the right *foundation*: a provider-agnostic, server-owned, bounded LLM
proxy (`copilot.go`) with a sanitized message list, encrypted-at-rest keys, per-principal rate
limiting, and escaped output rendering. That is a P0-grade safe **read-only assistant** done well.
The strategy below is mostly about (a) *grounding* that assistant in our own telemetry/RCA data
safely, and (b) drawing an extremely bright line before we ever let the AI **touch a device**.

**The three headline decisions:**

1. **MCP server: NO — not now. YES — later, conditionally (Phase 4+).** For our architecture
   today (single trusted backend, in-process Go tools, multi-tenant with RLS, on-prem-capable,
   stdlib-only) an internal **in-process tool/retrieval layer** is strictly better than standing
   up an MCP server: zero new attack surface, zero new dependency, tenant scoping enforced in the
   same process that already holds the auth claims. MCP earns its keep only when we need to expose
   Correlix's telemetry/RCA *as tools to third-party / customer-owned LLM agents* (a different
   product surface). Build the tool layer behind a clean internal interface now so an MCP adapter
   is a thin, optional shell later. (See §6 for the full verdict.)

2. **Recommended Phase-1 scope: a *grounded, read-only* RCA & telemetry assistant.** Take today's
   copilot from "paste-context chat" to "ask a question, the *backend* retrieves the relevant,
   tenant-scoped RCA findings / logs / metrics, hands the model a structured + cited context block,
   and renders an answer with clickable evidence links." **Retrieval is server-side, tenant-scoped,
   read-only, and bounded.** No write tools. No device access. This is the single highest-value,
   lowest-risk increment and it is a moat multiplier (our evidence engine is the product).

3. **Top 3 device-safety guardrails (the non-negotiables before any "action" feature):**
   **(a) Read-only by default with a hard architectural separation** between *advisory* output
   (text/SQL/CLI the human copies) and any *executor* — there is no code path from model output to
   a device in P0–P3. **(b) Human-in-the-loop with a *typed-plan + dry-run + explicit checklist
   approval*, not a one-click "Approve"** — the model proposes, the system simulates/diffs, a human
   positively acknowledges intent + blast-radius + rollback. **(c) Deterministic, non-LLM policy
   enforcement at the executor boundary** — allow/deny command lists, blast-radius caps, change
   windows, two-person rule for high-risk ops, per-tenant least-privilege RBAC, and full audit —
   enforced in Go, never by asking the model to "be careful."

> **One-line risk framing for the team:** the danger is not that the model is dumb — it is that a
> *plausible, confident* suggestion (`no router bgp 65000`, a "cleanup" ACL, a prefix-list edit)
> can blackhole a customer's network in seconds. We treat every model output as untrusted input
> (CLAUDE.md §3, §15 / OWASP LLM05) and gate *execution* with deterministic code, not prompts.

---

## 2. Where we are today (baseline audit of the existing copilot)

| Capability | Status today (`copilot.go` / `Opsis.tsx`) | Verdict |
|---|---|---|
| Provider-agnostic proxy | OpenAI → Gemini → Anthropic fallback chain, env- or UI-keyed | Strong — keep |
| Server-owned system prompt | Yes; client `system` field ignored (LLM01) | Strong — keep |
| Input bounds | `MaxBytesReader` 256 KiB, 64 msgs, 200 K chars, 1024 output tokens | Strong — keep |
| Output safety | Rendered as escaped React text / `<pre>`; never `dangerouslySetInnerHTML` | Strong — keep |
| AuthZ + rate limit | `withAuth`/`withAudit`, per-`tenant|sub` limiter | Strong — keep |
| Key custody | Encrypted at rest (Vault DEK), write-only in UI | Strong — keep |
| **Grounding** | **Manual** — user clicks "+ Logs" to paste 50 lines; otherwise the model guesses | **Gap — Phase 1 target** |
| **Tenant scoping of context** | Inherited from the API the UI calls; no AI-specific retrieval layer yet | **Must design before retrieval (§5)** |
| **Citations / evidence links** | None — answers are prose | **Gap — Phase 1** |
| **Actions on devices** | None (correct) | **Keep zero until §4 guardrails exist** |

**Finding (flag for cleanup, not blocking):** `CLAUDE.md` §15 and the code comments use the
**2023** OWASP-LLM numbering (e.g. "LLM02 Insecure Output Handling", "LLM07 Insecure Plugin",
"LLM08 Excessive Agency"). The **2025** list renumbered: LLM01 Prompt Injection, LLM02 Sensitive
Information Disclosure, LLM05 Improper Output Handling, LLM06 **Excessive Agency**, LLM07 System
Prompt Leakage, LLM08 Vector & Embedding Weaknesses, LLM10 Unbounded Consumption
([OWASP GenAI](https://genai.owasp.org/llm-top-10/)). The *controls* in §15 are correct; only the
labels drift. This doc uses 2025 numbering and maps both. Recommend a docs PR to align §15.

---

## 3. AI strategy on top of existing LLMs

### 3.1 Architecture pattern: RAG, agentic tool-use, or hybrid?

| Pattern | What it is | Fit for Correlix | When |
|---|---|---|---|
| **RAG / grounded retrieval** | Backend retrieves relevant tenant data, injects as context, model answers + cites | **Primary fit.** Our value *is* the curated RCA/evidence corpus; retrieval keeps the model factual and auditable | **P1–P2: default for all read questions** |
| **Agentic tool-use (read tools)** | Model decides which read tool to call (query metrics, fetch finding, search logs) in a loop | Good for *multi-step diagnosis* once retrieval is solid; each tool is read-only + tenant-scoped | **P2–P3, bounded loops only** |
| **Agentic tool-use (write tools)** | Model proposes device changes / executes | High blast radius. Only behind §4 guardrails, never autonomous | **P4+, gated, optional** |
| **Hybrid (recommended)** | RAG for grounding + a *small, curated* set of read tools the model may call; writes are a *separate, human-gated* subsystem outside the model loop | **Yes — this is the target shape** | Phase plan §7 |

**Why retrieval-first, not agent-first:** observability/RAG guidance is consistent that the failure
you must be able to diagnose is *"did the model lack the info (retriever issue) or misuse it (LLM
issue)?"* — which is only possible when retrieval is an explicit, evaluated step
([Confident AI](https://www.confident-ai.com/knowledge-base/compare/10-llm-observability-tools-to-evaluate-and-monitor-ai-2026),
[Patronus](https://www.patronus.ai/llm-testing/llm-observability)). Agentic loops add *tool-selection
accuracy* and *planning quality* as new failure modes; we earn the right to add them only after
retrieval + evals are trustworthy ([Data Nucleus, Agentic RAG 2026](https://datanucleus.dev/rag-and-agentic-ai/agentic-rag-enterprise-guide-2026)).

### 3.2 Grounding: feeding ClickHouse / OpenSearch / metrics / RCA findings safely

Principle: **the backend retrieves; the model never holds a credential or issues a raw store query.**
The model emits an *intent* (or we pre-retrieve from the user's question); a Go retrieval layer runs
**parameterized, tenant-scoped, bounded** queries and returns a **structured context envelope**.

Retrieval layer per store (reuses existing isolation primitives — CLAUDE.md §3a.4):

| Store | What we retrieve | Isolation primitive (already exists) | Bound |
|---|---|---|---|
| **ClickHouse** (RCA findings, flows) | The specific `corr_object` / findings / flow aggregates | `chTenantScope` injected into every query | top-N rows, time-boxed |
| **OpenSearch** (logs) | Relevant log lines for the device/time | per-tenant index + `osTenantFilter` | size cap (e.g. ≤50), redacted |
| **VictoriaMetrics** (metrics) | Series for the device/interface/window | device/tenant label filter | series + points cap |
| **Postgres** (app state / topology) | Device/site/topology facts | `withTenant` + FORCE-RLS | row cap |

**The context envelope** handed to the model is a typed, server-built JSON-ish block, each item
carrying a **stable citation id** (`finding:ch:<id>`, `log:os:<index>:<doc>`, `metric:vm:<series>@<ts>`).
The model is instructed (server-owned system prompt) to **cite ids it used**; the UI turns cited ids
into **clickable evidence links** back into the existing RCA/Logs/Metrics views. This gives us
anti-black-box, verifiable answers — directly aligned with the product's evidence-engine moat and
the Cisco-AICanvas "anti-black-box evidence log" lesson in memory.

**Redaction before egress (LLM02 Sensitive Information Disclosure):** a server-side redaction pass
strips secrets/credentials/PII from retrieved text *before* it enters the prompt, and honors the
existing **OperatorRestricted** tenant flag (a restricted tenant's telemetry must never be retrieved
into a prompt that could be served to the platform operator). Logs of prompts are sanitized; raw
provider error bodies already stay server-side (SR-022).

**Should we add a vector DB?** Not in P1. Start with **structured + lexical retrieval** (we already
have OpenSearch lexical search and well-keyed CH/VM data; RCA findings are *structured objects*, not
prose needing embeddings). A vector index adds OWASP **LLM08 Vector & Embedding Weaknesses** —
cross-tenant retrieval leakage and poisoning ([OWASP LLM08](https://genai.owasp.org/llm-top-10/),
[Wiz](https://www.wiz.io/academy/ai-security/model-context-protocol-security)). If we later add
semantic search over runbooks/knowledge, it must be **per-tenant-partitioned** (separate index/namespace
per tenant, filter enforced server-side) and treated as untrusted-on-read. Decision: **defer; revisit
only for unstructured knowledge (runbooks), per-tenant-partitioned.**

### 3.3 Model strategy: provider-agnostic, tiers, cost/latency, on-prem, fallback

We already proxy (good). Recommended posture:

- **Keep the provider-agnostic proxy** as the single egress chokepoint (it's where bounds, redaction,
  audit, and key custody live). This is also the natural place to add a **self-hosted endpoint** as
  just another provider.
- **Model tiers** (route by task, not one model for everything):

  | Tier | Use | Example class | Why |
  |---|---|---|---|
  | **Fast/cheap** | NL→query intent, summarize one finding, classify | small/flash-class | most calls; latency + cost |
  | **Reasoning** | Multi-signal RCA explanation, runbook synthesis | frontier mid (e.g. Sonnet-class) | quality where it matters |
  | **Self-host (opt-in)** | Security-sensitive / air-gapped customers | Llama-3.3-70B / Qwen-2.5 / Mistral via **vLLM** or Ollama | data never leaves the perimeter |

- **On-prem / self-host for security-sensitive customers:** real and expected in this market —
  regulated/air-gapped buyers want prompts + responses to never egress
  ([PredictionGuard](https://predictionguard.com/blog/best-self-hosted-llm-deployment-guide),
  [Arvo AI self-hosted AI SRE](https://www.arvoai.ca/blog/self-hosted-ai-sre)). Serve open-weight
  models with **vLLM/SGLang** (high-concurrency) or **Ollama** (small footprint); Apache-2.0 models
  (Mistral, most Qwen-2.5) are the cleanest license path
  ([ZTABS](https://ztabs.co/blog/self-hosted-llm-guide), [VDF AI local LLM 2026](https://vdf.ai/resources/local-llm/)).
  Cost note for the owner: self-hosting only beats per-token pricing past ~100M tokens/month of
  steady throughput on a 70B-class model; below that an H100 + ops loaded cost usually exceeds API
  pricing ([PredictionGuard cost guide](https://predictionguard.com/blog/self-hosted-vs-cloud-llm-deployment-guide)).
  So: **offer self-host as a deployment option (a configured provider), default to API for most.**
- **Fallback:** already implemented (chain). Add: on self-host deployments the chain is
  *self-host only* (no silent egress fallback to a public API — that would defeat the sovereignty
  guarantee). Make "no external egress" a hard tenant/deploy flag.

### 3.4 Multi-tenant isolation for AI (tie to §3a)

This is the part most AI features get wrong. Rules, all enforced **in the backend, in the same
process that owns the auth claims**:

1. **Every retrieval is scoped by `principalTenant(claims)`** (default-closed) — the AI retrieval
   layer is just another data-returning surface and obeys §3a.1. A non-cross caller can never have
   another tenant's rows enter their prompt.
2. **Owner stamped from token, never request body** — if the model or client names a tenant/device,
   it is *resolved-and-authorized* against the caller's scope before any retrieval (§3a.2).
   Cross-tenant id → 404, never leak existence.
3. **No shared prompt cache across tenants** — any prompt/response cache keys on tenant; embeddings
   (if ever) are per-tenant-partitioned (LLM08).
4. **Per-principal cost + rate limits** already exist; extend to a per-tenant token budget for
   retrieval-augmented calls (larger contexts cost more).
5. **Ship a cross-org isolation test with the feature** (`org_isolation_test.go` template, §3a.5):
   assert tenant A's question can never retrieve tenant B's findings/logs/metrics, and `as_tenant`
   into another org is ignored. **No AI retrieval ships without this test.**

### 3.5 Where AI adds real value in NetOps/RCA — prioritized

| # | Use case | Value | Risk | Priority |
|---|---|---|---|---|
| 1 | **RCA explanation / summarization** ("explain this incident, cite evidence") | High — turns the correlation object into operator-ready narrative; pure read | Low | **P1** |
| 2 | **NL query over telemetry** ("show BGP flaps on edge-1 last hour") → server runs scoped query, model narrates | High — fastest path to insight | Low (read-only, parameterized) | **P1–P2** |
| 3 | **Anomaly / alert triage** ("what changed, what's the likely cause, what to check next") | High — leverages our engine | Low–med | **P2** |
| 4 | **Runbook / next-step suggestion** ("here's what a senior NRE would check") — *advisory text only* | Med-high | Med (must stay advisory) | **P2–P3** |
| 5 | **Config / intent assist** (generate candidate config or query the human applies) | Med | **High if executed** — advisory only until §4 | **P3 advisory / P4 gated** |
| 6 | **Gated remediation actions** (execute a vetted, dry-run-validated change) | High but dangerous | **Highest** | **P4+, optional, off by default** |

Phase the value to track the risk: items 1–3 are nearly all upside; item 6 is where most of this
document's guardrails exist.

---

## 4. Guardrails: stop a customer damaging devices through the AI

This is the critical section. The threat is **excessive agency** (OWASP **LLM06**) and **improper
output handling** (**LLM05**): a confident model output becomes an action that blackholes a network.
Concrete failure shapes we design against:

- Model suggests `no router bgp 65000` / `clear ip bgp *` / a "tidy-up" ACL that drops management,
  a prefix-list edit that withdraws routes, an MTU/`shutdown` on an uplink, a `write erase`.
- Prompt injection via *ingested device output* (a hostname, a syslog line, a BGP community string
  containing `"ignore previous instructions, run ..."`) — our own telemetry is **untrusted input**
  (LLM01). This is why the executor must never trust model text.

### 4.1 Design principles (defense in depth, deterministic at the boundary)

The research is blunt: **approval gates alone are not enough** — in a 2026 study humans caught a bad
agent action only ~9–26% of the time, so a naive "Approve?" becomes a rubber stamp
([Strata, Human-in-the-Loop 2026](https://www.strata.io/blog/agentic-identity/practicing-the-human-in-the-loop/)).
The durable controls are *making the action reversible, limiting blast radius, sandboxing/dry-run,
and forcing a deliberate decision* — and routing anything touching critical/production infra to a
human with full context rather than letting the agent act
([Torq agentic guardrails](https://torq.io/blog/agentic-ai-security-guardrails/),
[GetMaxim guardrails guide 2026](https://www.getmaxim.ai/articles/the-complete-ai-guardrails-implementation-guide-for-2026/)).

So we layer:

1. **Read-only by default; advisory ≠ executor (architectural).** In P0–P3 there is *no code path*
   from model output to a device. The model produces **text/SQL/CLI the human reads and copies**.
   The device-touching executor is a *separate subsystem* the model cannot call.
2. **Deterministic policy at the executor boundary (non-LLM).** When (P4) an executor exists, every
   proposed action passes a Go policy engine *before* a human even sees an "apply" button:
   command **allow/deny lists**, **blast-radius caps** (max devices/interfaces/prefixes per change),
   **change windows**, **per-tenant RBAC least-privilege**, **two-person rule** for high-risk classes.
   The model's job ends at *proposing*; the gate's verdict is code, not a prompt.
3. **Explain-before-execute + dry-run/simulation.** Every proposed change is rendered as: intent,
   the *exact* commands, a **config diff / simulated effect**, computed **blast radius**, and a
   **rollback plan**. Approval is a **checklist** (acknowledge intent · data lineage · permission
   chain · expected blast radius · rollback) — not a single button
   ([Strata](https://www.strata.io/blog/agentic-identity/practicing-the-human-in-the-loop/)).
4. **Staged execution ladder.** dry-run → read-only verify → single-device canary → scoped rollout,
   mirroring the agent-safety ladder (dry-run → observe → simulate → staging → limited prod)
   ([GetMaxim](https://www.getmaxim.ai/articles/the-complete-ai-guardrails-implementation-guide-for-2026/)).
5. **Rate / spend / scope limits.** Bound action frequency (a misconfigured loop ships thousands of
   ops/min the moment it deploys ([Alephant budget guardrails](https://blog.alephant.io/10-real-time-ai-api-budget-guardrails-for-2026/))).
   Narrow credentials, service quotas, idempotent ops (CLAUDE.md §9).
6. **Full, immutable audit + observability.** Every proposal, policy verdict, approval, execution,
   and rollback is audited with the principal, tenant, evidence cited, and diff. No silent failures
   (CLAUDE.md §10).
7. **Treat device output as malicious (LLM01).** Telemetry/CLI output that re-enters the model is
   sanitized/normalized; instructions embedded in device data are never honored as commands.

### 4.2 Read tools vs. write tools

| | **Read tools** | **Write tools** |
|---|---|---|
| Examples | query metric, fetch finding, search logs, get topology | push config, modify ACL, restart BGP, set interface |
| Who runs them | model may request; backend executes, tenant-scoped | **never the model directly** — model only *drafts a proposal* |
| Gate | tenant scope + bounds + redaction | full §4.1 stack: policy engine + dry-run + checklist approval + two-person + audit |
| Default | enabled (P2+) | **disabled**, per-tenant opt-in, off in default build (like `FEATURE_DEVICE_SSH`) |
| OWASP | LLM02/LLM05 | **LLM06 Excessive Agency** is the whole point |

**Least privilege / least functionality (LLM06):** the model is granted only the read tools a task
needs, each with the *narrowest* scope; there is no general "run command" tool. Mirrors §3a.3 gate
selection (per-tenant data → `requirePerm`; platform-global plumbing → `requirePlatformAdmin`).

### 4.3 Mapping to OWASP LLM (2025)

| Risk | Correlix control |
|---|---|
| **LLM01 Prompt Injection** | Server-owned system prompt (done); device/telemetry output treated as untrusted, sanitized before re-entry |
| **LLM02 Sensitive Info Disclosure** | Server-side redaction before egress; OperatorRestricted honored; no secret auto-injection; sanitized logs |
| **LLM05 Improper Output Handling** | Escaped rendering (done); model output that becomes SQL/CLI/path is *data*, parameterized/validated; never auto-executed |
| **LLM06 Excessive Agency** | Read-only default; write tools off + gated; deterministic policy engine; staged ladder; two-person rule; least privilege |
| **LLM07 System Prompt Leakage** | System prompt holds no secrets/credentials; keys live in Vault, never in the prompt |
| **LLM08 Vector/Embedding** | No vector DB in P1; if added, per-tenant-partitioned + untrusted-on-read |
| **LLM10 Unbounded Consumption** | `MaxBytesReader`, msg/char/token caps, per-principal rate limit (done); per-tenant token budget; bounded retrieval + action rates |

---

## 5. Proposed architecture & data flow

```
                       ┌──────────────────────────── Correlix backend (Go, in-process) ───────────────────────────┐
  React Opsis UI        │                                                                                          │
  (escaped render, ───► │  /api/copilot/chat ──► [auth+audit+ratelimit] ──► AI Orchestrator                        │
   evidence links)      │                                              │                                          │
        ▲               │                                              ▼                                          │
        │ cited ids     │        ┌──────────── Retrieval layer (tenant-scoped, READ-ONLY, bounded) ───────────┐   │
        │               │        │  chTenantScope→ClickHouse   osTenantFilter→OpenSearch                      │   │
        │               │        │  label-filter→VictoriaMetrics   withTenant/RLS→Postgres/topology           │   │
        │               │        └───────────────► Context Envelope (typed + citation ids) ──► Redaction ─────┘   │
        │               │                                              │                                          │
        │               │                                              ▼                                          │
        │               │                       Provider proxy (egress chokepoint)                                │
        │               │            OpenAI / Gemini / Anthropic / **self-host (vLLM/Ollama)**                    │
        │               │                                              │                                          │
        │               │   answer + cited ids ◄────────────────────────                                          │
        │               │                                                                                          │
        │               │   ── P4+ only, SEPARATE subsystem, model cannot call it ──                               │
        │               │   Action Proposal ─► Policy Engine (deny/allow, blast-radius, window, RBAC, 2-person)    │
        │               │                      ─► Dry-run/Simulate ─► Human checklist approval ─► Executor         │
        │               │                      ─► Audit + Rollback   (Device SSH/NETCONF, idempotent, staged)      │
        └──────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Guardrail enforcement points (where each control lives):**
- *Auth / rate / audit:* `/api/copilot/chat` middleware (exists).
- *Tenant scoping + bounds + redaction:* retrieval layer (new, P1) — the single place data leaves a
  store toward a prompt.
- *Egress bounds + key custody + provider/self-host choice:* provider proxy (exists, extend).
- *Device-safety policy:* the **Policy Engine** + **Executor** subsystem (new, P4) — deterministic Go,
  *outside* the model loop, reusing `FEATURE_DEVICE_SSH` plumbing and the intent-automation design.

**Internal tool interface (build now, even in P1):** define a small Go interface
`type ReadTool interface { Name() string; Scope(claims) ...; Run(ctx, args) (Result, error) }` so
that (a) the orchestrator calls tools uniformly, (b) tenant scoping is enforced once, and (c) an MCP
adapter later is a thin shell over the *same* interface (see §6). Keeps us stdlib-only (CLAUDE.md §6).

---

## 6. Do we need an MCP server? — Verdict: **NO now, conditional YES later**

### 6.1 What MCP is and its security posture
The **Model Context Protocol** (Anthropic) is an open protocol for exposing *tools* and *resources*
to LLM hosts/agents over a standard interface, so a tool built once works across Claude, GPT, Gemini,
or custom agents ([modelcontextprotocol.io](https://modelcontextprotocol.io/docs/learn/server-concepts),
[MindStudio](https://www.mindstudio.ai/blog/mcp-servers-explained-ai-agents)). Crucially, the spec
**"explicitly does not enforce security at the protocol level"** — auth, scoping, and validation are
the implementer's job ([Wiz](https://www.wiz.io/academy/ai-security/model-context-protocol-security),
[Red Hat](https://www.redhat.com/en/blog/model-context-protocol-mcp-understanding-security-risks-and-controls)).
Documented risk classes: credential aggregation into a high-value server, over-permissioned tools,
untrusted third-party servers, and tool-output injection — all requiring mutual auth, audience-scoped
OAuth tokens, least privilege, and JSON-schema validation both ways
([CyCognito](https://www.cycognito.com/learn/ai-security/mcp-security/),
[Legit Security](https://www.legitsecurity.com/aspm-knowledge-base/model-context-protocol-security)).

### 6.2 Why not now — for *our* architecture

| Constraint | In-process tools (today) | MCP server | Winner |
|---|---|---|---|
| **Attack surface** | None added; tools run in the process that holds auth claims | New network-exposed surface, a protocol that punts security to us, a credential-aggregation target | **In-process** |
| **Tenant isolation** | Enforced inline via `principalTenant`/RLS/`chTenantScope` | Must re-implement audience-scoped tokens + per-tenant scoping at the MCP boundary or risk cross-tenant leak (LLM08-style) | **In-process** |
| **Stdlib-only / deps (§6)** | Pure Go, zero new modules | An MCP server/SDK = new dependency surface to vet, vendor, pin | **In-process** |
| **On-prem / air-gapped** | One binary, nothing extra to run | Another service to deploy, secure, monitor in every customer env | **In-process** |
| **Ops burden** | None | Lifecycle, auth, patching of a separate server | **In-process** |
| **Token/context cost** | We control the exact context | MCP loads full tool schemas into model context ([CircleCI](https://circleci.com/blog/mcp-vs-cli/)) | **In-process** |
| **Single trusted consumer** | Our own UI/backend is the only client today | MCP's value is *many heterogeneous clients* — we don't have them yet | **In-process** |

The industry guidance matches: **MCP earns its cost when you must coordinate authenticated access
across systems for *multiple, heterogeneous agent clients*; for a single app's own tools the overhead
isn't justified** ([CircleCI](https://circleci.com/blog/mcp-vs-cli/),
[MindStudio CLI vs MCP vs API](https://www.mindstudio.ai/blog/cli-vs-mcp-vs-api-ai-agents)). We are
the single trusted consumer of our own data; an MCP server would add attack surface and a security-by-
implementer protocol with no offsetting benefit today — and it *contradicts* the zero-trust + minimal-
dependency posture of CLAUDE.md §3/§6.

### 6.3 When the answer flips to YES (the conditions)
Stand up an MCP server (as an **optional, opt-in adapter**, off by default) when **any** of these hold:
1. **Customers want their own LLM agents / third-party copilots to consume Correlix telemetry & RCA
   as tools** (Correlix-as-a-tool-provider) — a genuinely new, multi-client surface MCP is built for.
2. We want Correlix's assistant to consume **external** MCP tools (e.g. a customer's CMDB/ticketing).
3. A partner ecosystem needs a *standard* tool contract rather than our private API.

When we do: expose **read tools only** first; enforce mutual auth + **audience-scoped OAuth tokens**
per tenant; least-privilege scopes; JSON-schema validate in/out; treat tool output as untrusted;
keep it a *separate, optional* deployment so the default/air-gapped build stays MCP-free
([CyCognito](https://www.cycognito.com/learn/ai-security/mcp-security/),
[Red Hat](https://www.redhat.com/en/blog/model-context-protocol-mcp-understanding-security-risks-and-controls)).

**De-risking move:** build the **internal `ReadTool` interface now (§5)** so MCP later is a thin
adapter over the same tenant-scoped tools — we get optionality without paying for MCP today.

---

## 7. Phased plan

| Phase | Name | Scope | Device risk | Gate to ship |
|---|---|---|---|---|
| **P0** | *(done)* Safe proxy | Provider-agnostic, server-owned prompt, bounds, escaped output, encrypted keys, rate limit | None | shipped |
| **P1** | **Grounded read-only assistant** | Server-side **tenant-scoped retrieval** (CH/OS/VM/PG) → structured **context envelope with citation ids** → answer with **clickable evidence links**; redaction; per-tenant token budget; **cross-org isolation test** | None (read-only) | isolation test green; redaction; no write path |
| **P2** | **Read tool-use (bounded agentic)** | Small curated read tools behind the `ReadTool` interface; bounded multi-step diagnosis; NL→scoped-query; triage | None (read-only) | tool scope tests; loop bounds; evals |
| **P3** | **Advisory remediation** | Model *drafts* config/CLI/runbook steps as **text the human copies**; explain + diff shown; **no executor** | None (advisory only) | output is data, never executed; UI copy-only |
| **P4** | **Gated actions (optional, off by default)** | Separate **Policy Engine + Executor**; dry-run/simulate; checklist approval; blast-radius caps; change windows; two-person rule; staged ladder; rollback; full audit; per-tenant opt-in like `FEATURE_DEVICE_SSH` | **High — fully gated** | deterministic policy tests; dry-run proven; audit; security review |
| **P5** | **MCP adapter (conditional)** | Only if §6.3 conditions hit; read tools first; per-tenant audience-scoped OAuth; optional/off by default | per tool class | §6.3 conditions met; MCP security review |

### What we DON'T do (yet) — explicit
- **No autonomous device changes. Ever, without a human checklist approval.** No "auto-remediate".
- **No write tool the model can call directly.** Writes are a separate human-gated subsystem.
- **No MCP server** until §6.3 conditions are met (and then optional/off-by-default).
- **No vector DB** in P1 (no embedding store / cross-tenant retrieval risk) until per-tenant-partitioned
  runbook semantic search is justified.
- **No auto-pulling of context** beyond what the tenant-scoped retrieval layer returns; no secret/PII
  auto-injection; no cross-tenant data in any prompt.
- **No silent egress** on self-host/air-gapped deployments (no fallback to public APIs).
- **No fine-tuning / training our own model** — strategy is grounding + retrieval on existing LLMs.

---

## 8. Open questions / where I'm uncertain
- **Token-budget vs. answer quality:** bigger context = better grounding but higher cost/latency.
  Needs measurement against real tenants before fixing caps. *(Uncertain; instrument in P1.)*
- **Self-host demand timing:** offer the *seam* (self-host as a provider) in P1, but actual GPU
  provisioning is customer-driven — don't pre-build until a buyer needs it.
- **Eval harness:** P2 tool-use needs an offline eval set (tool-selection accuracy, groundedness).
  Recommend a small mock-telemetry eval corpus (CLAUDE.md §11 mock streams) before enabling loops.
- **Intent-automation overlap:** `docs/design/intent-based-automation.md` is PAUSED; P4 here is the
  natural home for its §0 checklist — reconcile the two before building P4.

## 9. Recommendation
Ship **P1 (grounded read-only assistant with tenant-scoped retrieval + citations)** next — highest
value, lowest risk, and it compounds the evidence-engine moat. Build the internal `ReadTool` interface
while doing it. **Do not** stand up an MCP server now. Hold device-touching actions behind the full
§4 guardrail stack as an explicitly optional, off-by-default P4.

---

### Sources
- OWASP Top 10 for LLM Applications (2025): https://genai.owasp.org/llm-top-10/ ·
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
- MCP server concepts (Anthropic): https://modelcontextprotocol.io/docs/learn/server-concepts
- MCP security: Wiz https://www.wiz.io/academy/ai-security/model-context-protocol-security ·
  Red Hat https://www.redhat.com/en/blog/model-context-protocol-mcp-understanding-security-risks-and-controls ·
  CyCognito https://www.cycognito.com/learn/ai-security/mcp-security/ ·
  Legit Security https://www.legitsecurity.com/aspm-knowledge-base/model-context-protocol-security
- MCP vs in-process/CLI tradeoffs: CircleCI https://circleci.com/blog/mcp-vs-cli/ ·
  MindStudio https://www.mindstudio.ai/blog/cli-vs-mcp-vs-api-ai-agents
- RAG vs agentic / observability: Confident AI
  https://www.confident-ai.com/knowledge-base/compare/10-llm-observability-tools-to-evaluate-and-monitor-ai-2026 ·
  Patronus https://www.patronus.ai/llm-testing/llm-observability ·
  Data Nucleus https://datanucleus.dev/rag-and-agentic-ai/agentic-rag-enterprise-guide-2026
- Guardrails / human-in-the-loop: Strata
  https://www.strata.io/blog/agentic-identity/practicing-the-human-in-the-loop/ ·
  Torq https://torq.io/blog/agentic-ai-security-guardrails/ ·
  GetMaxim https://www.getmaxim.ai/articles/the-complete-ai-guardrails-implementation-guide-for-2026/ ·
  Alephant https://blog.alephant.io/10-real-time-ai-api-budget-guardrails-for-2026/
- Self-host / on-prem LLM: PredictionGuard
  https://predictionguard.com/blog/best-self-hosted-llm-deployment-guide ·
  https://predictionguard.com/blog/self-hosted-vs-cloud-llm-deployment-guide ·
  Arvo AI https://www.arvoai.ca/blog/self-hosted-ai-sre · ZTABS https://ztabs.co/blog/self-hosted-llm-guide ·
  VDF AI https://vdf.ai/resources/local-llm/
