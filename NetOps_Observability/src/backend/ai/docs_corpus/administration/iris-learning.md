---
title: Decide what Iris learns from your team
sidebar_label: Learning
description: Iris turns how your team fixed incidents and corrected its answers into suggested Network context facts, aliases and runbook drafts; a person adopts each one and a second administrator approves it.
page_type: task
sidebar_position: 15
---

# Decide what Iris learns from your team

**Administration → Iris → Learning** collects suggestions drawn from what your team has already told Correlix. A person decides every one. Nothing changes on its own, and no AI model is retrained: a suggestion reaches Iris only through [Network Context](network-context.md), [Runbooks](iris-runbooks.md) or Iris's aliases, under the same two-person rule.

Where suggestions come from:

- **How incidents were fixed.** When at least **3 incidents on one device** in the last 90 days were recorded with the same fix (for example *a ticket with the provider*, or *it cleared on its own*), Iris suggests a Network context fact about that device.
- **Corrections to Iris's answers.** When at least **2 different people** marked an answer as being about the wrong thing, corrected it to the same site, device or circuit, and used the same words, Iris suggests an **alias** so it understands those words next time.
- **Questions Iris could not answer.** When at least **5 questions** of one kind failed because no tool reads that information or the data was not there, Iris suggests a **runbook draft** — a procedure for a person — for your team to finish.

## Before you begin

- **Permission:** `administration:read` to see suggestions, `administration:write` to adopt one, `administration:admin` to look for new ones, approve or dismiss.
- **Licence:** the `ai.context.author` capability. Adopting a runbook draft also needs `ai.runbook.author`; adopting an alias needs the Iris query capability.
- **Workspace:** suggestions belong to one workspace. From the Global view, choose a workspace first.
- **Platform store:** this needs the Postgres platform store (the default for new installations).
- **People, not keys:** adopting and approving need a signed-in person. An API key can only read.

## Steps

### 1. Look for suggestions

Select **Look now**. Iris reads your workspace's recorded fixes, its question log (the last 30 days) and its aliases, and lists what it found. Running it again updates suggestions nobody has acted on yet; it never re-opens one that was dismissed.

### 2. Decide each suggestion

Each suggestion says why it was made and lists its **sources** — the incidents, corrections or unanswered questions it rests on. An operator's note on a recorded fix is shown to you as a quote. It is never part of the suggested text, and it is never sent to Iris.

- **Fill in the gaps.** A suggested fact leaves the parts only your team knows marked `{{…}}` (for example the carrier and the circuit id). You cannot adopt it until each one is replaced.
- **Adopt** hands the suggestion on, with you as its author:
  - a **fact** becomes a Network context version waiting for review;
  - an **alias** waits for a second administrator;
  - a **runbook draft** is created on the Runbooks page for you to finish and send for review.
- **Dismiss** needs a short reason. A dismissed suggestion is not suggested again.

### 3. A second administrator approves

Adopted facts and aliases are listed under **Second person**. Another administrator — not the person who adopted it — approves it. For an alias, the approval checks again that the words do not already mean something else and that the site, device or circuit is one you can see. A runbook draft is approved on the [Runbooks](iris-runbooks.md) page, where its checks run.

### 4. See what was decided

**Decided** lists what was approved and what was dismissed, with the reason.

## What Iris never does here

- It never activates a fact, an alias or a runbook without a second person.
- It never copies a colleague's question into a suggestion. An alias is suggested only when at least two people used the same words.
- It never reads another workspace's incidents, questions or aliases.
