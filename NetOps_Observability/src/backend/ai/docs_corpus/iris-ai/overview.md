---
title: Iris
description: The assistant that answers from your own tenant's evidence, names the method it used, and cites every claim.
page_type: index
sidebar_position: 1
---

# Iris

Iris is the assistant built into Correlix. It answers operational questions from
your own tenant's data, states which troubleshooting method it ran, cites the
evidence behind every claim, and says what is missing rather than filling the
gap. This section is for the operator who asks it questions and for the
administrator who turns it on.

Open it from the button pinned at the foot of the left sidebar, labelled **Iris
AI**. It opens docked beside the page; you can switch it to a floating overlay.

| Page | What it gives you |
|---|---|
| [Set up Iris](/iris-ai/setup) | The switches, the AI add-on, the per-workspace settings and the AI provider. |
| [Investigate an incident with Iris](/iris-ai/ask-iris) | Asking, slash commands, how to read an answer, and how to go deeper. |
| [Iris skills and chaining](/iris-ai/skills) | The 25 compiled-in methods, where each applies, and how one hands off to the next. |
| [Investigations](/iris-ai/investigations) | The read-only Investigator, triggered and scheduled investigations, and active probes. |
| [Change assistance](/iris-ai/change-assistance) | Change-plan review, upgrade readiness, upgrade procedures and device baselines — all read-only. |
| [Seasonal answers](/iris-ai/seasonal-answers) | "Is this normal for this time of week?" — how Iris compares with the same hour in earlier weeks. |
| [Fixes and similar incidents](/iris-ai/resolutions) | Recording how a case was fixed, and "last time this was fixed by…". |
| [Teach Iris your names](/iris-ai/iris-settings) | Names and aliases, questions Iris could not answer, and how it decided. |
| [Investigation memory](/iris-ai/memory) | What Iris remembers, when, and why it is never a rule. |

Administrators also have:

| Page | What it gives you |
|---|---|
| [Network context](/administration/network-context) | Facts about your network that Iris may use. |
| [Runbooks and MOPs](/administration/iris-runbooks) | Your own reviewed methods, and the built-in upgrade procedures. |
| [Iris learning](/administration/iris-learning) | Proposed facts and runbooks drawn from recorded fixes, adopted only by people. |
| [Iris actions](/administration/iris-actions) | Approving the two actions Iris may propose. |
| [Iris in Slack and Teams](/administration/iris-chat) | Asking Iris from chat. |
| [Iris over MCP](/administration/iris-mcp) | Read-only Iris for an external AI assistant. |

## How Iris answers

Iris works in two modes, depending on whether model-backed Iris is turned on.
Model-backed Iris needs the **`iris_model` licence add-on** (included with
Enterprise) and the **Iris AI models** switch on the Features page; this applies
whether Iris uses the platform's AI provider or a workspace's own key.

- **Evidence-only (no AI provider).** Every question is answered from your
  workspace's data by Correlix itself: the question's wording picks the answer
  path, and the answer is a structured, cited card. Nothing is sent to an AI
  provider.
- **Model-backed.** One quick model call reads each new question, however it is
  phrased, and picks which answer path handles it from a closed list the server
  writes; a repeated question is answered from a cache. The reasoning-heavy
  answers (an RCA explanation, a troubleshooting finding, a current-state
  summary) also get a model-written narrative over the same evidence, and those
  are exactly the answers the grounding verifier checks. A slow or failing
  model never holds an answer back: Iris tries another configured model, and
  otherwise shows the evidence answer with a one-line note saying why (for
  example, "Model narrative timed out; showing the evidence answer.").

Answers cite documentation as `/docs/<slug>#<anchor>` and open the page in the
in-app Help drawer, so a product answer lands on the page that says it.

## Security stance

Iris is designed against the OWASP Top 10 for LLM applications. These properties
are enforced in code, not requested in a prompt.

- **The system prompt is server-controlled.** A client-supplied `system` field
  or a `system`-role message is ignored, so a caller cannot inject an
  instruction turn.
- **Model output is data, never markup.** Assistant text, skill names, tool
  names and citation labels all render as escaped React text. There is no
  `innerHTML` anywhere on those paths, and a citation renders as a link only
  when it is a same-origin relative path.
- **Nothing is auto-injected.** The backend does not put secrets, credentials,
  another tenant's rows or PII into a prompt. A provider key is write-only and
  sealed at rest.
- **Requests and answers are bounded.** The request body is capped at 256 KiB,
  each principal has a per-minute budget (20 by default), and every provider
  call caps output at 1024 tokens.
- **Invented citations are stripped.** A deterministic verifier removes any
  bracketed evidence id the model produced that is not in the evidence bundle,
  before the answer is shown. It is a guardrail in code, so the model cannot
  talk its way past it.
- **Iris never changes a device.** No configuration, image or command is ever
  pushed to a device; change help (reviews, upgrade procedures, baselines) is
  read-only. Draft-style commands produce text only. Two things go beyond
  reading, both off until a platform administrator turns them on and each
  workspace opts in: **active probes** (a short test sent from Correlix's own
  collector, run only as an authored method step) and **approved actions** (an
  ITSM ticket note or a memory entry, written only after a second person
  approves).

## Related

- [Investigate](/investigate/overview)
- [Feature flags](/reference/feature-flags)
- [Security overview](/security/overview)
