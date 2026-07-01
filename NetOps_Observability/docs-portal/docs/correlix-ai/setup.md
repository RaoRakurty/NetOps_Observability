---
title: Set up Correlix AI
sidebar_label: Setup
sidebar_position: 2
description: Enable the assistant, connect an AI provider, and verify it's live.
---

# Set up Correlix AI

This page walks a **platform administrator** through enabling the assistant, connecting an AI provider (optional), and verifying the result.

## Before you begin

- **Who can do this:** enabling the feature requires access to the deployment host (`.env` file). Configuring the provider, model, and API key in the UI requires a **platform administrator** account — tenant and organization admins can use the assistant but cannot open its settings.
- **Do you need an API key?** No — the assistant answers network questions (live state, incidents, RCA, flows, telemetry, playbooks) from your own data without any provider. A key only adds free‑form conversational chat and model‑written narratives. See [the overview](/correlix-ai/overview#two-answer-paths).

## Step 1 — Enable the feature

The assistant is **off by default**. On the deployment host:

1. Open `deployment/docker/.env`.
2. Set:

   ```bash
   FEATURE_COPILOT=true
   ```

3. Restart the API so it picks up the flag:

   ```bash
   cd deployment/docker
   docker compose restart api
   ```

4. Refresh the browser. The **Correlix AI** button at the foot of the left icon rail now opens the assistant panel. (If the feature is still off, the panel shows *"Correlix AI is turned off. Set `FEATURE_COPILOT=true` in `deployment/docker/.env` and restart the API."*)

At this point the assistant is fully usable in **key‑free grounded mode** — the panel header shows an amber dot with **Grounded engine · key‑free**.

## Step 2 — Open the assistant settings

1. Click the **Correlix AI** button on the icon rail to open the panel.
2. In the panel header, click the **gear icon** (*Assistant settings*).

The settings form shows three fields — **API key**, **Provider**, and **Model** — plus a status badge next to the key field: **not set**, **configured** (a key was saved in the UI), or **via environment** (a key is supplied through the deployment's environment variables).

:::note
If clicking the gear shows nothing, your account is not a platform administrator — the settings form only loads for platform admins.
:::

## Step 3 — Pick a provider and model

1. Under **Provider**, choose one of the tiles:
   - **Anthropic** (Claude) — the default.
   - **OpenAI** (GPT).
2. Under **Model**, pick one of the suggested model chips or type any model ID the provider supports:
   - Anthropic suggestions: `claude-opus-4-8`, `claude-sonnet-4-6`, `claude-haiku-4-5-20251001`
   - OpenAI suggestions: `gpt-4o`, `gpt-4o-mini`, `gpt-4.1`

Switching the provider tile automatically proposes that provider's first suggested model; you can override it.

## Step 4 — Paste the API key

1. In the **API key** field, paste a key for the provider you selected (for example an Anthropic key starting `sk-ant-…`, or an OpenAI key starting `sk-…`).
2. Click **Save**.

The key is **encrypted at rest and never displayed again**. The field afterwards shows `•••••••• (stored — leave blank to keep)` — saving the form with a blank key field keeps the stored key; it never wipes it.

:::warning
Once a key is saved, free‑form questions and grounded evidence summaries are sent to that external provider. Review [what leaves the platform](/correlix-ai/overview#privacy--what-leaves-the-platform) before enabling this in a restricted environment.
:::

**Alternative — key via environment.** Instead of the UI, the key can be supplied in `deployment/docker/.env` (`COPILOT_API_KEY` for the configured provider, or the per‑provider variables `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `GEMINI_API_KEY`). When any environment key is present, the UI key field is disabled and badged **via environment** — clear the variable from `.env` to manage the key in the UI. An environment key always wins over a UI‑stored one.

## Step 5 — Verify it's live

1. Look at the panel header, under the **Correlix AI** title:
   - **Green dot + provider and model** (for example *Claude · claude-sonnet-4-6*) — the provider is connected.
   - **Amber dot + "Grounded engine · key‑free"** — no usable key yet; grounded answers still work.
2. Type a free‑form question (for example *"Why might my edge router be dropping BGP sessions?"*) and send it. A conversational answer confirms the provider round‑trip.
3. Click **What's going on right now?** on the welcome screen. This uses the grounded engine and should return a structured card with counts and citations regardless of the key.

## Optional tuning (environment variables)

| Variable | Effect | Default |
|---|---|---|
| `FEATURE_COPILOT` | Master switch for the assistant | off |
| `COPILOT_PROVIDER` / `COPILOT_MODEL` / `COPILOT_API_KEY` | Default provider, model, and key when nothing is saved in the UI | `anthropic` / `claude-sonnet-4-6` / unset |
| `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY` | Per‑provider keys; any provider with a key joins the fallback chain | unset |
| `COPILOT_PROVIDER_CHAIN` | Comma‑separated fallback order for free‑form chat (providers without keys are skipped) | `openai,gemini,anthropic` |
| `COPILOT_RATE_PER_MIN` | Per‑user assistant request budget per minute (`0` or less disables the limit) | `20` |

Google **Gemini** can participate in the fallback chain via `GEMINI_API_KEY`, but it is not selectable in the settings UI — the UI offers Anthropic and OpenAI.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Panel says *"Correlix AI is turned off"* | `FEATURE_COPILOT` is not `true`. Set it in `deployment/docker/.env` and restart the API. |
| *"Correlix AI isn't connected to an AI provider yet — open the assistant settings (gear icon) and add an API key"* | You asked a free‑form question with no key configured anywhere. Add a key (Step 4), or use the quick actions / slash commands, which work key‑free. |
| *"Correlix AI couldn't reach the AI provider"* | The provider rejected the call (bad key, exhausted quota, or network egress blocked). Re‑paste the key in settings; check the provider account. Provider error details are in the API service logs, never shown to users. |
| *"Correlix AI rate limit exceeded — slow down"* | You exceeded the per‑user budget (20 requests/minute by default). Wait a minute, or raise `COPILOT_RATE_PER_MIN`. |
| Key field is disabled, badge says **via environment** | A key is set in `.env`. Remove it there and restart the API to manage the key from the UI. |
| Answers carry the footer *"Evidence‑only mode: AI provider not configured."* | Not an error — the grounded engine answered deterministically. Add a provider key if you want model‑written narratives. |

## Next steps

- **[Using Correlix AI](/correlix-ai/using)** — slash commands, answer anatomy, and split‑screen mode.
