# Iris provider path (`/api/copilot/chat`)

Iris has two answer paths. `/api/ai/ask` is the grounded engine, which works
without a provider key. `/api/copilot/chat`, described here, is the provider path:
the Go API calls an LLM on the operator's behalf. Evaluation is covered in
`docs/ai/evals.md`.

## Configuration

Install defaults live in `deployment/docker/.env`:

```
FEATURE_COPILOT=true
COPILOT_PROVIDER=anthropic           # anthropic, openai or gemini
COPILOT_API_KEY=...                  # the secret
COPILOT_MODEL=...                    # any model the provider supports
```

`COPILOT_PROVIDER_CHAIN` sets the order in which providers are tried. A tenant's
own key takes priority over the platform chain, and a tenant set to
`no_platform_key` gets no platform key (`src/backend/ai_tenant_config.go`).

## How it works

* **Frontend.** The Iris UI (`src/frontend/src/tabs/Iris.tsx`) reaches this route
  through `src/frontend/src/services/api.ts`.
* **Request limits.** `src/backend/copilot.go` checks the feature flag, a
  per-principal rate limit (`COPILOT_RATE_PER_MIN`, default 20) and the AI
  entitlement. It caps the body at 256 KiB, and `ai.SanitizeMessages` caps the
  message count and characters.
* **The server owns the prompt and the conversation (OWASP LLM01).** The system
  prompt is server-controlled. A `system` field in the request body is decoded for
  backward compatibility and **ignored**; it cannot override the prompt.
  `ai.SanitizeMessages` (`src/backend/ai/llm_transport.go`) keeps only `user`
  turns, dropping client-supplied `system` and `assistant` turns.
* **Documentation grounding.** The server retrieves documentation sections for the
  latest question and appends them to the system prompt as a labelled data block.
  `doc:` citations the model invents are stripped.
* **Tools.** When `FEATURE_AI_TOOLS` is on and the caller is in the rollout, the
  turn runs an agent loop over the grounded engine's governed read-only tools,
  under a daily token budget. Every tool call is authorized again when it runs and
  recorded in the decision ledger as hashes. If the loop fails after a lookup has
  run, the turn fails with an error instead of restarting as plain chat.
* **Provider fallback.** Candidates are tried in order. If every provider fails,
  the grounded engine answers with evidence only, and the response says so
  (`fallback: provider_unavailable`).
* **Labelling.** The response carries `is_grounded`. A plain completion is `false`
  because no tenant evidence was read, and the engine fallback is `true`.

## What the model cannot do

* It cannot change its own instructions, or see turns the client wrote in the
  model's voice.
* It cannot execute anything outside the tools the caller's manifest allows.
* Its output is untrusted: the rules for handling it are in `CLAUDE.md` §15.

## Cost notes

Provider calls are billed per token. The per-principal rate limit and the daily
token budget bound usage; larger NOCs should also set provider-side limits.
