---
title: Correlix AI overview
sidebar_label: Overview
sidebar_position: 1
description: Ask about your network in plain language and get grounded, cited answers.
---

# Correlix AI

**Correlix AI** is the in‑app assistant. Ask about your network in plain language and get answers grounded in your live, tenant‑scoped data — with clickable evidence, never a black box.

Open it from the **Correlix AI** button pinned near the bottom of the left icon rail, or press <kbd>Ctrl/Cmd + K</kbd> and choose **Open Copilot** from the command palette. It slides in as a panel you can float over the page (overlay) or dock beside it (split screen) — see [Using Correlix AI](/correlix-ai/using).

## What you can ask

- **Live operations** — *"What's going on right now?"* returns a current operations summary: confirmed / suspected / undetermined incident counts, the recommended focus incident, and why it should be worked first.
- **Incident triage** — *"Which incident should the NOC focus on first, and why?"* gives a prioritized recommendation with the reasoning spelled out.
- **Root‑cause explanations** — *"Explain the top incident"* resolves the highest‑priority incident from the queue and explains it: likely root cause, supporting evidence, what evidence is still missing, the recommended owner, and next actions.
- **Module questions** — *"Show me the top talkers"*, *"any metric anomalies right now?"*, *"integration health?"* — focused reads of flow analytics, telemetry, application identification, and connector health.
- **Playbooks** — *"How do I troubleshoot a BGP flap?"* returns curated network‑engineering guidance.
- **Product help and navigation** — *"How do I set up SNMP discovery?"*, *"Where do I configure ServiceNow?"*.

Typing <kbd>/</kbd> in the composer opens a menu of ready‑made commands (`/status`, `/top`, `/focus`, `/explain`, `/playbook`, …) that run the same grounded questions with one keystroke. The full table is in [Using Correlix AI](/correlix-ai/using#slash-commands).

## Two answer paths

Correlix AI has two ways of answering, and it always picks one that works:

1. **Grounded answers (no API key required).** Questions about *your network* — live state, incidents, RCA, flows, telemetry — are answered by a deterministic, evidence‑grounded engine that reads your tenant's data directly. Answers come back as a structured card: a narrative, incident counts, a recommended focus, missing evidence, next actions, and **citations that deep‑link into the source view**. This path works out of the box, with no external AI provider configured.
2. **Free‑form chat (provider key required).** When a platform administrator adds an AI provider API key (Anthropic or OpenAI, selectable in the assistant settings), typed free‑form questions are answered conversationally by that provider — and grounded answers get a model‑written narrative instead of the built‑in phrasing. Slash commands and the built‑in quick actions **always** use the grounded engine, key or no key, so triage answers stay deterministic and cited.

When no provider is configured, answers carry a small footer note — *"Evidence‑only mode: AI provider not configured."* — so you always know which path produced the answer.

## Grounding, scoping, and honesty

- **Tenant‑scoped by design.** Every answer is built only from data your tenant owns, further filtered by your own role's permissions (a user without flow access won't get flow answers). The assistant can never see another tenant's data.
- **Cited, not asserted.** Grounded answers attach citations — chips at the bottom of the card that link to the incident, device, or view the fact came from. If a model narrative claims something the evidence bundle doesn't contain, the invented citation is stripped before the answer is shown.
- **Honest about gaps.** Answers show a **Missing evidence** section and *Low evidence* badges when the engine can't confirm a root cause, instead of overclaiming.
- **Read‑only.** The assistant never changes anything on the platform. Draft‑style commands (for example `/itsm`, which drafts a ticket update) produce text only — nothing is sent or written.

## Privacy — what leaves the platform

- **Without a provider key configured: nothing.** All answers are computed inside the platform.
- **With a provider key:** the question and a compact, redacted evidence summary (or, for free‑form chat, your typed conversation) plus the server‑owned assistant instructions are sent to the provider you configured. Content is passed through a redaction step before it leaves. Nothing is auto‑pulled beyond what the answer needs.
- The provider **API key is encrypted at rest and never shown again** after you save it — the settings screen only reports that a key is present and where it came from.
- Audit records for assistant usage capture who asked and the question *category* — never the question text or the retrieved data. Answer feedback (👍/👎) records only the rating and category.

:::warning
Configuring a provider key means operational data — incident summaries, device names, evidence lines, and anything you type into the chat — is sent to that external AI provider. If your organization restricts data egress, leave the assistant in key‑free grounded mode: triage, RCA explanations, and module summaries all work without any provider.
:::

## Cost and rate controls

Each provider call is a paid, per‑token request. Correlix bounds the exposure: response length is capped, request size is bounded, and each user is rate‑limited (20 assistant requests per minute by default, tunable by the platform administrator). Provider errors are never echoed to users — the assistant falls back to the next configured provider, then to the grounded engine.

## Next steps

- **[Set up Correlix AI](/correlix-ai/setup)** — enable the feature, add a provider key, verify it's live.
- **[Using Correlix AI](/correlix-ai/using)** — asking questions, slash commands, and reading an answer card.
