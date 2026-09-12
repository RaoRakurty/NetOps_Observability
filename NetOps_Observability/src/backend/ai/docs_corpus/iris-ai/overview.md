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
AI**. It opens as a slide-over that you can float over the page or dock beside
it.

| Page | What it gives you |
|---|---|
| [Set up Iris](/iris-ai/setup) | The flags, the per-tenant entitlement, and the optional provider key. |
| [Investigate an incident with Iris](/iris-ai/ask-iris) | Asking, slash commands, and how to read an answer. |
| [Iris skills and chaining](/iris-ai/skills) | The 13 compiled-in methods, and how one hands off to the next. |
| [Investigation memory](/iris-ai/memory) | What Iris remembers, when, and why it is never a rule. |

## How Iris answers

Two paths, and Iris always picks one that works.

- **Grounded, no provider key needed.** Questions about your network are
  answered by a deterministic engine that reads your tenant's data through
  governed read-only tools and returns a structured, cited card. Navigation,
  product questions, shift hand-offs, incident lists and time-range summaries
  never call a model at all.
- **Provider-backed narrative.** With an AI provider key configured, the
  reasoning-heavy answers (an RCA explanation, a troubleshooting finding, a
  current-state summary) get a model-written narrative over the same governed
  evidence. Those are exactly the answers the grounding verifier runs on.

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
- **Every tool is read-only.** Iris never changes anything. Draft-style
  commands produce text only, and nothing is sent or written on your behalf.

## Related

- [Investigate](/investigate/overview)
- [Feature flags](/reference/feature-flags)
- [Security overview](/security/overview)
