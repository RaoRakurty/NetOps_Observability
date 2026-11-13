---
title: Set up Iris
description: Check the feature flags, grant workspaces access, add an optional provider key, and verify what the panel header reports.
page_type: task
sidebar_position: 2
---

# Set up Iris

Iris answers without any external provider, so setup is mostly about who may use
it and how much they may spend. A provider key is optional and adds
model-written narratives on top of the same governed evidence.

## Before you begin

- **Platform administrator** for the platform settings and the per-workspace
  access list. A tenant administrator sees only their own workspace settings and
  cannot open the platform form.
- Host access to `deployment/docker/.env` for the feature flags.
- A decision on data egress. Without a key nothing leaves the host. With a key,
  questions and a redacted evidence summary go to that provider.

## Steps

### Step 1 - Turn on Iris AI models

Iris answers from your own network data on every install, with no provider and
no add-on. Written AI answers, model chat and AI investigations are
**model-backed Iris**: the **Iris AI add-on** on your license (Enterprise
includes it; Team and Community add it as a separate line).

On a licensed install, a platform administrator turns them on:

1. Open **Administration → Features**, section **Iris AI**.
2. Turn on **Iris AI models**. Confirm that questions, and the evidence Iris
   gathers, may go to your configured AI provider.
3. To let the model run read-only lookups, also turn on **AI investigations**,
   then tick the workspaces in Step 2.

Both switches start **off** and are set on that page only; no `.env` line sets
them. An installation that already used a model before this release keeps
them on after the upgrade, once. Without the add-on the switches cannot be
turned on, and Iris says so in its panel.

`FEATURE_AI` still turns Iris off entirely (`FEATURE_AI=false`, then restart the
API); it is unset by default, which leaves Iris on.

### Step 2 - Grant workspaces access

1. Open Iris from the sidebar and select the gear, **Assistant settings**.
2. Under **Workspace access**, each workspace has two checkboxes:
   **Assistant** (may use Iris at all) and **Investigations** (may run governed,
   read-only lookups before answering). Assistant is enabled by default;
   investigations are not.
3. Set the per-workspace guardrails beside them: lookups per question (1 to 8,
   platform default 4) and AI tokens per day. A blank field means the platform
   default.

Answers are always scoped to the workspace's own data. A cross-tenant platform
principal is never gated here.

### Step 3 - Add a provider key (optional)

**Platform key.** In the same settings form, choose a provider tile
(**Anthropic**, **OpenAI** or **Gemini**), pick or type a model, paste the key
and select **Save**. The key badge reads **not set**, **configured** when it was
saved in the console, or **via environment** when the deployment supplies it. An
environment key wins, and the field is disabled while one is present.

**Workspace key.** A tenant administrator opens the same gear and sees
**Workspace settings**: their own provider, model and key. A workspace key is
write-only, sealed at rest under that workspace's own key, and used only for
that workspace. It always wins over the platform key. Clearing **Use the
platform AI service when no key is set** means the workspace goes key-free
rather than riding the platform account.

The key is never displayed again. Saving with a blank key field keeps the stored
key; it never wipes it.

:::caution
Once a key is configured, questions and the redacted evidence summary are sent
to that external provider. In a restricted environment, leave Iris key-free:
grounded answers, slash commands and skills all work without a provider.
:::

### Step 4 - Verify

1. Open Iris. Read the line under the title in the panel header:
   - The provider and model, for example `Claude · claude-sonnet-4-6`, when a
     platform key is live.
   - `your key` on a workspace that supplied its own, or `Platform AI service`
     when it rides the platform key.
   - `Grounded engine · key-free` when no usable key is configured. Grounded
     answers still work.
2. Ask a grounded question, for example `/status`, and confirm the card returns
   counts and citations.

## Result

Iris answers for the workspaces you enabled, within the lookup and token
guardrails you set, and the panel header states which path it is on. An answer
produced without a provider carries a footer note saying so, so the answer path
is never ambiguous.

### Environment reference

| Variable | Effect | Default |
|---|---|---|
| `FEATURE_AI` | Turns Iris off entirely when `false`. Wins over `FEATURE_COPILOT`. | unset, which leaves Iris on |
| `FEATURE_COPILOT` | Legacy form of `FEATURE_AI`, honoured when `FEATURE_AI` is unset. It no longer gates model chat. | `true` in compose |
| `FEATURE_AI_TOOLS` | No longer a switch. Read once on upgrade to keep an install that ran AI investigations running them; then **Administration → Features → AI investigations** decides. | `false` |
| `COPILOT_PROVIDER` / `COPILOT_MODEL` | Provider and model when nothing is stored. | `anthropic` / `claude-sonnet-4-6` |
| `COPILOT_API_KEY` | Key for the configured provider. | unset |
| `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY` | Per-provider keys; each one with a key joins the fallback chain. | unset |
| `COPILOT_PROVIDER_CHAIN` | Fallback order for provider-backed answers. | `openai,gemini,anthropic` |
| `COPILOT_RATE_PER_MIN` | Requests per minute per principal. | `20` |
| `AI_TOOLS_MAX_CALLS` | Platform default for lookups per question. | `4` |

## Related

- [Iris overview](/iris-ai/overview)
- [Investigate an incident with Iris](/iris-ai/ask-iris)
- [Feature flags](/reference/feature-flags)
- [Administration](/administration/overview)
