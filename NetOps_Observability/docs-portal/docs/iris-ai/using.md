---
title: Using Iris AI
sidebar_label: Using the assistant
sidebar_position: 3
description: Ask questions, run slash commands, and read grounded answer cards.
---

# Using Iris AI

Day‑to‑day use: opening the panel, the two triage questions every shift starts with, the slash‑command menu, and how to read an answer card. The assistant must be enabled first — see [Setup](/iris-ai/setup).

## Open the assistant

1. Click **Iris AI** — the button pinned near the foot of the left icon rail. The panel slides in from the rail.
2. Alternatively press <kbd>Ctrl/Cmd + K</kbd> and pick **Open Copilot** from the command palette.
3. Press <kbd>Esc</kbd> (or click the **×** in the panel header, or click anywhere outside the panel in overlay mode) to close it.

### Overlay vs. split screen

The panel has two layouts, toggled by the **split‑screen button** in the panel header (next to the gear):

- **Overlay** (default) — the panel floats over the page with a light backdrop; clicking outside closes it. Best for a quick question.
- **Split screen** — the panel docks beside the page and the page content reflows next to it, so you can read an answer and work the incident at the same time. The choice is remembered across sessions.

The header also has a **＋** button (*New conversation*) that clears the thread and starts fresh, and a **?** button (*Help & documentation*) that summarizes what the assistant can answer.

## Start-of-shift triage

1. Open the assistant. On the empty conversation you'll see two primary buttons.
2. Click **What's going on right now?** You get a *Current operations* card: confirmed / suspected / undetermined counts, the **Recommended focus** incident with the reasons it should be worked first, the other active suspected incidents, and any undetermined watch items.
3. Click **Explain the top incident** (or type `/top`). The assistant resolves the highest‑priority incident from the queue itself and returns a full RCA card: likely root cause, supporting evidence, missing evidence, recommended owner, and next actions.
4. Click any **citation chip** at the bottom of a card to jump to the incident, device, or view the fact came from — the panel closes and the app navigates there.

Both actions use the grounded engine, so they work identically with or without a provider key.

:::tip
You can also ask from inside an incident: the **Iris AI** card on an incident's RCA view has an **Explain this problem** button that runs the same grounded explanation for exactly that correlation. See [Incidents](/incidents/overview).
:::

## Slash commands

Type <kbd>/</kbd> as the first character in the composer to open the **Quick questions** menu. Keep typing to filter, use <kbd>↑</kbd>/<kbd>↓</kbd> to move, <kbd>Enter</kbd> or <kbd>Tab</kbd> to run, <kbd>Esc</kbd> to dismiss the menu without closing the panel.

Commands are shortcuts into the *same* grounded engine as natural language — `/status` and *"what is going on right now?"* produce the same answer. A command can take trailing text, which is appended to the question (for example `/playbook bgp flap`).

| Command | Aliases | What it returns |
|---|---|---|
| `/status` | `/now`, `/current` | Current NOC status — active incidents, priority focus, impact, next actions. |
| `/top` | `/top-incident` | Resolves and explains the highest‑priority incident in the queue. |
| `/focus` | `/prioritize` | Which incident the NOC should work first, and why. |
| `/breakdown` | `/suspected` | Active suspected incidents separated from undetermined watch items. |
| `/explain` * | `/rca`, `/problem` | Full RCA for an incident — timeline, evidence, missing evidence, owner, next actions. |
| `/missing` * | `/gaps` | What evidence the engine still needs to confirm the incident. |
| `/owner` * | `/who` | The recommended owning team/domain for the incident. |
| `/handoff` | `/shift`, `/pass-down` | A drafted NOC shift pass‑down summary. |
| `/history` | `/overnight`, `/recap` | What happened in a past window (overnight / last N hours). |
| `/itsm` * | `/ticket` | A drafted ITSM update for the incident — **draft only, never sent**. |
| `/flows` | `/talkers`, `/traffic` | Top talkers and busiest services in the recent window. |
| `/telemetry` | `/anomalies`, `/metrics` | Recent metric anomalies and device health. |
| `/apps` | `/app-id`, `/applications` | Identified applications and low‑confidence matches. |
| `/integrations` | `/connectors` | Connector configuration health (ServiceNow / Slack / …). |
| `/cloud` | `/saas` | SaaS / cloud application health (when that module is enabled). |
| `/topology` | `/topo`, `/path` | Where the topology / path view lives for an incident. |
| `/playbook` | `/runbook`, `/kb` | Curated troubleshooting guidance for a symptom or protocol. |
| `/help` | `/commands`, `/?` | Lists the available commands. |

\* Needs an incident for context. If you run one without an incident open, the assistant automatically resolves the current top‑priority incident and answers about that; if nothing is active, it says so honestly.

All commands are read‑only; `/itsm` and `/handoff` generate draft text only.

## Reading an answer card

Grounded answers render as a structured card rather than a paragraph. From top to bottom:

1. **Kind label** — what type of answer this is: *Live state*, *RCA*, a module name (e.g. *Flow Analytics*), or *Notice*. RCA cards also show the short **incident ID**.
2. **Card title** — e.g. *Current Operations Summary*, so the card is never mislabeled by a single incident's status.
3. **Badge row** — status (*Confirmed* / *Suspected*), a *Confidence* label, and honesty flags like *Low evidence* or *Missing evidence*.
4. **Narrative** — a few grounded sentences answering the question.
5. **Counts strip + legend** (live‑state cards) — **confirmed**, **suspected**, and **undetermined** totals, with a legend explaining what each number counts so they never read as conflicting.
6. **Recommended focus** — the one incident to work first, its own status/confidence badges, and the *why‑first* reasons as bullets.
7. **Sections** — *Active suspected incidents*, *Undetermined watch items*, *Most impacted*, *Recommended owner*, *Missing evidence*, and numbered *Recommended next actions*, as applicable.
8. **Citations** — chips linking every claim to its source view; click to navigate.
9. **Footer** — small disclaimers, and a provider note when applicable (*"Evidence‑only mode: AI provider not configured."*).
10. **Feedback** — *Was this helpful?* 👍/👎. Ratings record only the thumb and the question category — never your text.

Free‑form chat answers (provider‑backed) render as plain conversation text; code blocks in an answer render as scrollable monospace blocks.

## Keyboard reference

| Key | Where | Action |
|---|---|---|
| <kbd>Enter</kbd> | Composer | Send |
| <kbd>Shift + Enter</kbd> | Composer | New line |
| <kbd>/</kbd> (first character) | Composer | Open the quick‑questions menu |
| <kbd>↑</kbd> / <kbd>↓</kbd>, <kbd>Enter</kbd> / <kbd>Tab</kbd> | Quick‑questions menu | Navigate / run |
| <kbd>Esc</kbd> | Quick‑questions menu | Dismiss the menu (panel stays open) |
| <kbd>Esc</kbd> | Panel | Close the assistant |
| <kbd>Ctrl/Cmd + K</kbd> | Anywhere | Command palette (includes **Open Copilot**) |

## Troubleshooting

- **Footer says "Evidence‑only mode: AI provider not configured."** — Normal in key‑free mode; the grounded engine answered. A platform administrator can [add a provider key](/iris-ai/setup#step-4--paste-the-api-key) for model‑written narratives.
- **A free‑form question returns "Iris AI isn't connected to an AI provider yet…"** — No key is configured. Use slash commands and the quick actions (key‑free), or configure a provider.
- **"Iris AI rate limit exceeded — slow down"** — You hit the per‑user budget (default 20 requests/minute). Wait and retry.
- **A context command answers "no active incident"** — Nothing is active in your tenant's queue. Open a specific incident and use its **Iris AI → Explain this problem** card instead.
- **A module answer says the module is unavailable** — That data source isn't enabled on your deployment, or your role lacks read access; the assistant only answers from modules you can see.
