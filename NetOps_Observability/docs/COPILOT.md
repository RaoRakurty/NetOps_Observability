# AI Copilot

The Copilot tab in the dashboard is a chat pane that talks to an LLM
through the Go API. The model gets only the messages the user provides
— there's no autonomous tool use, no agent loop, no automatic indexing.
This is deliberate: it keeps the trust boundary clean and the failure
modes predictable. When the model is wrong, the worst that happens is
the operator gets a wrong answer in the chat window.

## Configuration

In `deployment/docker/.env`:

```
FEATURE_COPILOT=true
COPILOT_PROVIDER=anthropic           # or 'openai'
COPILOT_API_KEY=sk-ant-...           # the secret
COPILOT_MODEL=claude-sonnet-4-5      # any model the provider supports
```

Then `docker compose up -d` (the api container picks up the new env).

If you flip `COPILOT_PROVIDER=openai`, set `COPILOT_API_KEY` to your
OpenAI key and `COPILOT_MODEL` to something OpenAI ships (e.g.
`gpt-4o-mini`).

## How it works

* Frontend (`src/frontend/src/tabs/Copilot.tsx`) maintains an in-memory
  chat history. Each turn posts the full history to `/api/copilot/chat`.
* The Go API (`src/backend/copilot.go`) checks the feature flag and
  API key, then forwards to either Anthropic's Messages API or OpenAI's
  Chat Completions API. Responses are streamed back to the SPA
  unmodified.
* A default system prompt nudges the model toward the NetOps role —
  override per-request by sending a `system` field in the POST body.
* The "+ Context" button in the UI fetches the most recent 50 log
  lines from OpenSearch and appends them to the next message. Use this
  to keep the model grounded in actual data instead of inviting it to
  hallucinate.

## What the model can NOT do (yet)

* It cannot run queries on its own. There is no tool-use loop wired up.
* It cannot read findings, devices, or alerts directly. The UI must
  paste any required context into the conversation.
* It does not stream tokens — the full response comes back in one POST
  body. SSE/streaming is straightforward to add when needed; the
  nginx proxy is already configured with `proxy_read_timeout 120s`.

## Why pass through, not embed?

The Go API is the policy/audit/auth boundary. A future hardening pass
will add per-user quotas, prompt logging into ClickHouse for
post-incident review, and PII scrubbing on the way out. Keeping the
LLM call behind that boundary makes those additions one-place changes
rather than scattered UI patches.

## Cost notes

LLM calls are per-token. A Sonnet query with ~50 lines of log context
runs around $0.001-0.01 per turn at current pricing — small operations
might never notice, larger NOCs should set provider-side limits.
