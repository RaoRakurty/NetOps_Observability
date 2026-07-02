# The Agent Loop (P2) — model-driven tool use, bounded and governed

**Status:** shipped 2026-07-02 (intelligence plan P2, `docs/design/research/correlix-ai-intelligence-plan.md` §3.c–3.d, §4).
**Flag:** `FEATURE_AI_TOOLS=true` (off by default). Rollout: platform-owner/cross-tenant
principals only; `AI_TOOLS_ALL_TENANTS=true` widens to tenant users (planned for P4).

## What it does

When a provider key is configured and the caller is in the rollout, a free-form
`/api/copilot/chat` turn no longer just forwards the conversation: the server hands the
model a **manifest of governed read-only tools** (filtered by the Policy Engine to what
THIS caller may run) and loops — the model requests lookups, the server validates,
authorizes, executes and audits each one against the same tenant-scoped DataSource the
grounded engine uses, feeds bounded results back, and the model answers with citations.
The UI shows "Investigated N sources" plus clickable evidence/doc citations.

Deterministic paths are untouched: slash commands and the key-free mode keep using
`/api/ai/ask`'s classify→tools→schema path. The loop serves the long tail the regex
classifier can't route.

## Bounds (all hard, plan §4.5)

| Bound | Default | Knob |
|---|---|---|
| Tool calls per turn | 4 | `AI_TOOLS_MAX_CALLS` (clamped 1–8) |
| Wall clock per turn | 2 min | — |
| Per-tool-reply prompt budget | 4000 chars | — |
| Output tokens per model call | 1024 | (shared copilot cap) |
| Daily per-tenant token budget | 250k (coarse chars/4 estimate) | `AI_TOOLS_DAILY_TOKENS` (≤0 disables) |
| Rate limit | 20/min per principal | `COPILOT_RATE_PER_MIN` (shared) |

Budget exhaustion **fails closed to chat-without-tools**; over-cap tool requests get an
explicit "budget exhausted" reply and the model must answer with what it has, disclosed
as truncated.

## Security model (CLAUDE.md §15 / §3a; OWASP LLM06:2025)

- **Manifest = first gate.** `ai.Manifest(reg, policy, principal)` only lists tools the
  caller passes `EvaluateTool` for. A tool without declared meta (`ai/toolspec.go`) is
  never listed at all — fail closed.
- **Execution = second gate.** Every model-requested call is re-authorized by the Policy
  Engine, schema-validated (`ai.ParseToolArgs`: flat strings only, required fields,
  nested payloads rejected), then run with the **server-built Principal** — the model
  never supplies a tenant. Cross-tenant/unknown ids come back as a bare "not found".
- **Read-only.** The registry holds only `CapRead` tools; write/execute stay hard-denied
  (HLD P6). No model-driven URL fetch, no un-gated writes — the lethal-trifecta
  exfiltration leg does not exist.
- **Verified narrative.** The final text passes `ai.VerifyGrounding`: any citation id the
  model invented (including a foreign problem id) is stripped; `[doc:…]` ids are checked
  against retrieved chunks.
- **Audit.** One line per tool call (`msg:"tool_call"`): principal, tool, arg NAMES
  (never values), outcome, duration — plus a per-turn `agent_loop` summary. Question
  text never appears.

## Provider seam (`copilot_tools.go`)

Neutral `ai.ToolSpec` / `ai.ToolCall` / `ai.ToolReply` + `agentTurn`, encoded per
provider: OpenAI chat-completions function calling (arguments as JSON string, one
`role:"tool"` message per result), Anthropic Messages tool use (parsed input object,
results in one user message of `tool_result` blocks), Gemini `generateContent`
function calling (correlated by function name). Pure stdlib; tool-call turns are never
streamed; no cross-provider loop resumption — a mid-loop provider failure fails the
turn cleanly (a turn with zero executed lookups falls back to plain chat).

## Tools exposed in P2

Everything already in the registry (RCA problems/evidence, active/actionable incidents,
flows, anomalies, app identity, integrations, ticket status) plus:

- `search_docs` — the P1 BM25 docs index as a tool (honesty floor intact).
- `search_logs` — device syslog, per-tenant index + doc-level `osTenantFilter`,
  ≤50 redacted lines (secret-ish `key=value` masked), fixed window allowlist.
  Deliberately syslog-only: app logs are platform-internal.
- `get_device_health` — device resolved against the tenant-scoped inventory FIRST
  (unknown/cross-tenant → not found), then pinned VictoriaMetrics lookups
  (CPU/memory/ifdown) + inventory freshness.

## Tests

`ai/toolspec_test.go` (manifest filtering, meta coverage, schema shape, arg
validation, docs-tool honesty floor), `copilot_tools_test.go` (wire fixtures per
provider), `copilot_agent_test.go` (runaway model halts at cap; cross-tenant probe →
"not found" + fabricated citation stripped — §3a.5; policy/unknown/bad-args refusals;
per-tenant daily budget; rollout gating).

## Live validation

Requires a configured provider key (none in the lab yet). With a key:
`FEATURE_AI_TOOLS=true`, ask non-routed questions ("is anything wrong with leaf1 and is
there an open ticket?") as the platform owner — expect an answer citing real evidence
ids that click through, with the "Investigated N sources" trail.
