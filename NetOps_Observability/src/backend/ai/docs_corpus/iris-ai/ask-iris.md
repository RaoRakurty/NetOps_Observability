---
title: Investigate an incident with Iris
sidebar_label: Ask Iris
description: Query Iris from the case, the investigation lane or the drawer, then read the skill, the chain, the citations and what is missing.
page_type: task
sidebar_position: 3
---

# Investigate an incident with Iris

Iris answers about the incident in front of you, from your own tenant's
evidence. Use the three places you can ask, the slash commands, and the anatomy
of an answer to know what a claim rests on.

## Before you begin

- Iris enabled for your workspace. See [Set up Iris](/iris-ai/setup).
- Your own permissions still apply. Iris reads only the modules your role can
  read, and never another tenant's rows.
- Expect to be told what is missing. An answer that cannot confirm a cause says
  so and lists the evidence it still needs.

## Steps

### Step 1 - Ask from where you already are

| Where | How | What it asks |
|---|---|---|
| The RCA case | The **Iris AI** card, **Explain this problem** | A grounded explanation of that correlation: cause, supporting evidence, what is missing, recommended owner, next actions. |
| The investigation workspace | The **Iris co-pilot** lane, **Ask Iris** | The same read of the open case, or of the symptom you selected, with the missing evidence named. |
| Anywhere | The **Iris AI** button at the foot of the sidebar, or **Open Copilot** from the command palette | A free conversation carrying the same grounding. |

The drawer opens as an overlay by default and can be docked beside the page with
the split-screen control in its header. The choice is remembered.

### Step 2 - Use a slash command for a fixed question

Type `/` as the first character in the composer to open the quick-questions
menu. A command runs the same grounded engine as the equivalent sentence, with
or without a provider key. Trailing text is appended to the question, for
example `/playbook bgp flap`.

| Command | Aliases | Needs an incident | What it returns |
|---|---|---|---|
| `/status` | `/now`, `/current` | no | Current NOC status: active incidents, priority focus, impact, next actions. |
| `/top` | `/top-incident`, `/top-incidents` | no | Resolves the highest-priority incident from the queue and explains it. |
| `/focus` | `/prioritize` | no | Which incident to work first, and why. |
| `/breakdown` | `/suspected` | no | Suspected incidents separated from undetermined watch items. |
| `/explain` | `/rca`, `/problem`, `/explain-problem` | yes | Full RCA: timeline, evidence, missing evidence, owner, next actions. |
| `/missing` | `/missing-evidence`, `/gaps` | yes | What evidence the engine still needs to confirm this problem. |
| `/owner` | `/who` | yes | The recommended owning domain. |
| `/handoff` | `/shift`, `/pass-down` | no | A drafted shift pass-down. |
| `/history` | `/overnight`, `/recap` | no | What happened in a past window. |
| `/itsm` | `/itsm-update`, `/ticket` | yes | A drafted ITSM update. Draft only, never sent. |
| `/flows` | `/talkers`, `/traffic` | no | Top talkers and busiest services in the recent window. |
| `/telemetry` | `/anomalies`, `/metrics` | no | Recent metric anomalies and device health. |
| `/apps` | `/app-id`, `/applications` | no | Identified applications and low-confidence matches. |
| `/integrations` | `/connectors` | no | Connector configuration health. |
| `/cloud` | `/saas` | no | Cloud and SaaS application health, when that module is enabled. |
| `/topology` | `/topo`, `/path` | no | Opens the topology or path view for an incident. |
| `/playbook` | `/runbook`, `/kb` | no | Curated network-engineering guidance for a symptom or protocol. |
| `/help` | `/commands`, `/?` | no | Lists the available commands. |

A command that needs an incident and is run without one resolves the current
top-priority incident and answers about that. With nothing active, it says so.

### Step 3 - Read the answer

An answer card carries, in order and only where the backend supplied it:

1. **The skill chip.** The method that answered, with its version and layer, for
   example `bgp-session-down v1 · bgp`. Absent means no chip is drawn, never a
   placeholder.
2. **The chain breadcrumb.** When more than one method ran, each hop in authored
   order with how it was chosen: `entry` for the deterministic entry selection,
   `rule` when an authored condition fired, `proposed` when the model picked
   from that skill's own declared hand-offs. See
   [Iris skills and chaining](/iris-ai/skills).
3. **The narrative**, as escaped text.
4. **Recommended owner** and **Recommended next actions**, when the evidence
   supports them.
5. **Missing evidence**, lifted from the collection notes rather than left to
   the narrative. Every budget stop is disclosed here too, so a truncated
   investigation never reads like a complete one.
6. **Citations**, one chip per evidence item, with the read-only tool that
   produced it and how many ids it returned. Select a chip to open the source.
   A citation that is not a same-origin relative path renders as inert text.
7. **Disclaimers**, including the note that the answer came from the grounded
   engine when no provider is configured.

### Step 4 - Rate the answer

Select the thumb under the card at **Was this helpful?**. The rating records the
thumb and the question category, never your text or the retrieved data. A rating
on a concluded investigation is also what writes it to investigation memory. See
[Investigation memory](/iris-ai/memory).

## What you see

A grounded answer names its method, cites its evidence, and states its gaps.
Nothing is executed on your behalf: every Iris tool is read-only, and the draft
commands produce text only.

## Related

- [Iris skills and chaining](/iris-ai/skills)
- [Investigation memory](/iris-ai/memory)
- [Read an RCA case](/investigate/read-an-rca-case)
- [Investigate a symptom](/investigate/investigate-a-symptom)
