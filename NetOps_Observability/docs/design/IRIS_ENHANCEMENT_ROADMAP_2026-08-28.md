# Iris AI — enhancement roadmap (2026-08-28)

Fable roadmap for Project 3 item C (auto-troubleshoot · guide engineers ·
human-in-the-loop auto-actions · auto vendor-case opening). It **extends the
existing** `correlix-ai-hld.md` §10 phase plan (P5/P6/P7) and the intelligence
plan — it does NOT reinvent them. Opus builds each phase; Fable specs/grades.

## Ground truth (what Iris is today — build on this, don't duplicate)
Iris = two brains behind one "Iris AI" drawer: a provider-agnostic **free-form
chat proxy** (`/api/copilot/chat`) and a **grounded, cited, tool-using engine**
(`/api/ai/ask` + the flag-gated bounded agent loop). The grounded engine uses one
governed **read-only** tool registry (incidents/RCA, flows, telemetry, app-id,
integrations, ITSM-read, docs). It is **strictly read-only**, tenant-scoped,
cross-tenant→NotFound, cited, arg-name-only audited. OWASP-LLM guardrails are
live (server-owned prompt, sanitizer, body/msg/token caps, rate + daily-budget,
citation verifier, escaped-text rendering). The **P6 action subsystem is
separate and the model CANNOT call it** — that invariant is load-bearing and
every phase below preserves it.

**The four asks map cleanly onto the existing plan.** "Auto-actions" here always
means *human-in-the-loop*, never autonomous.

---

## Phase A — Auto-troubleshoot REACH (near-term, read-only, no new trust boundary)
Make Iris able to actually troubleshoot by giving its grounded loop the evidence
it's currently blind to. All additions are **read-only, policy-gated, cited** —
they extend the existing registry, crossing no new trust boundary.
- **`run_protocol_diagnostic`** — drive the new `protocoldiag` HTTP API (Project 3
  item B): Analyze on operator-supplied output always; Collect via the injected
  CommandRunner *only when wired* (else honest "not configured"). Iris now
  explains a BGP/OSPF/IS-IS symptom against the 15-issue signature catalog and
  cites it — no invented cause (fail-closed, same contract as the page).
- **`get_security_findings`** — read the per-tenant OpenSearch findings store
  (Project 2 decision, once its read API lands): list/facet/trend, tenant-scoped.
  Iris can then answer "what's my exposure on this device/seam."
- **`get_topology_context`** — the read-only topology-graph tool (HLD P4, still
  unwired): neighbors, seam, path context for an entity.
- **Fix the routing inversion** (intelligence-plan finding #1): free-form text
  should reach the GROUNDED engine, not the less-grounded proxy, when a key is
  present. This is the single highest-leverage current fix — it makes every
  typed question cited by default.
- **Deps:** protocoldiag HTTP API (Proj 3 B, in build), findings read API (Proj 2).
- **Guardrails:** each tool re-authorized at execution, cross-tenant→NotFound,
  LLM06 (no secret/credential injection into prompts), LLM07 least privilege.

## Phase B — GUIDE the engineer (P5 Runbook Advisor — advisory text only, no executor)
Turn evidence into a next-step path, still 100% read-only.
- **Guided investigation** — from the grounded evidence bundle, Iris proposes the
  *safe diagnostic checklist* (what to check next, which lane, which device),
  step-by-step, each step cited. Reuses the RCA "Explain this problem" surface.
- **Escalation / TAC drafts** — generate the provider-escalation note + ITSM note
  template from the correlated evidence (the Network Expert KB already intends
  this). **Draft text only** — a shareable artifact the human pastes into a TAC
  case. Nothing is sent. This is the honest precursor to "auto vendor-case."
- **Team handoff** — a summarized, evidence-linked handoff block for shift change.
- **Guardrails:** advisory only; no executor; output stays escaped React text.

## Phase C — Human-in-the-loop CONTROLLED ACTIONS (P6 — separate subsystem the model CANNOT call)
The "auto-actions" and "auto vendor-case opening" asks land HERE, as a
**separate, off-by-default, human-gated** subsystem — mirroring the already-built
**Wireless five-gate** template (`wireless_actions.go`: proposal → policy engine
[deny/allow, blast-radius, window, RBAC, two-person] → dry-run/diff → **human
checklist approval** → executor → audit → rollback; `FEATURE_*_ACTIONS=false`).
The model may only *propose* into this path; it never executes.
- **Order (least→most blast radius):**
  1. **ITSM ticket create/update · Slack post · assign owner** — non-device,
     reversible, low blast radius. Do first.
  2. **Auto vendor-case opening (TAC)** — a Controlled Action that takes the
     Phase-B escalation draft and opens the real case via the vendor/ITSM API,
     **human-approved**. "Auto" = pre-filled + one-click-approved, NOT autonomous.
  3. **Gated device change** — last, highest bar (dry-run + blast-radius caps +
     two-person + rollback + maintenance-window gate).
- **Guardrails:** deterministic policy engine, per-tenant per-action-type
  approval (human by default; opt-in auto-approve only for the safest classes),
  full audit + rollback. The model cannot call the executor (architectural).

## Phase D — REACH / interop (P7)
- Correlix **MCP server** (partner-safe read-only tools) · **ChatOps** (Iris in
  Slack/Teams) · **conversation memory** in the grounded path · agent-to-agent.
- Lower priority; sequence after A–C prove value.

---

## Sequencing + why
- **A first** — pure upside, no new trust boundary, and it's the payoff of Projects
  2 & 3 (findings API + protocoldiag API become Iris-reachable). Ship the routing
  fix within A regardless.
- **B next** — advisory guidance is high-value and still zero-risk (no executor).
- **C only after** A+B and only behind the proven five-gate pattern; never let the
  model call the executor. Start with reversible non-device actions.
- **D last.**

**Non-goals (preserve the architecture):** no write/action tool in the model
loop; no autonomous remediation; no bypass of the human gate; no secret injection
into prompts; every new tool read-only + tenant-scoped + cited. See
[[rca-product-philosophy]], docs/design/correlix-ai-hld.md §10,
docs/design/research/correlix-ai-intelligence-plan.md.
