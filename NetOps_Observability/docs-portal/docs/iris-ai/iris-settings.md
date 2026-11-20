---
title: Teach Iris your names
sidebar_label: Iris vocabulary
description: Add the names your team uses, check how Iris reads a question, see how it decided, and review what it could not answer.
page_type: task
sidebar_position: 9
---

# Teach Iris your names

Your team calls things by its own names — "the DC firewall", "London core".
The **Iris vocabulary** settings let a workspace administrator teach Iris those
names and check how it reads questions. Only your workspace sees them.

Open **Administration → Iris**. The first three steps are on the
**Knowledge** tab, the next three on the **Learning & review** tab. They show
for a workspace administrator whose workspace has Iris turned on; otherwise
the tab says why.

## Steps

### On the Knowledge tab

1. **Names your team uses.** Add a name and what it means (a device, site or
   group). Iris uses it only after you select **Add**.
2. **Check a name.** Type a name to see what Iris would resolve it to. Choosing
   a suggestion fills in step 1; it does not add it.
3. **Try a question.** Type a question and preview how Iris reads it — the
   devices, metrics and time range it understood — before anyone asks it for
   real.

### On the Learning & review tab

1. **Recent questions.** Your workspace's recent questions, with **That's not
   what I meant** to record a correction.
2. **How Iris decided.** For each question, which answer path it took and why.
3. **What Iris could not answer.** Questions Iris could not answer, grouped by
   reason, so you can add a name or a runbook. A reviewer can export them for
   evaluation.

[Iris in Slack and Teams](/administration/iris-chat) is on the **AI models**
tab. [Investigations that start on their own](/iris-ai/investigations) and
[actions Iris proposes](/administration/iris-actions) are on the
**Investigations** tab.

Nothing on this page changes how Iris answers on its own: a name is used only
after you add it, and corrections are kept for review.

## Related

- [Set up Iris](/iris-ai/setup)
- [Network context](/administration/network-context)
