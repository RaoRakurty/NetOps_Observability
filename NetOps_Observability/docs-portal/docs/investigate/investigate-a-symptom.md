---
title: Investigate a symptom
description: Start from an open case or describe a new one, read the answer and the seven evidence lanes behind it, then ask Iris, open a ticket or escalate to TAC.
page_type: task
sidebar_position: 5
---

# Investigate a symptom

The Troubleshooting workspace is where the operator drives and Correlix does the
legwork. You pick an open case, or describe what is wrong, and the workspace
gives you the answer first and every evidence lane behind it, all read at once.

## Before you begin

- Read access to **Investigate** (`infrastructure:read`).
- An open case, or the problem in your own words. A case Correlix correlated
  carries its verdict; a problem you describe starts with none, and the
  evidence lanes still read for it.
- Know that a lane reporting nothing is telling you one of two different facts.
  *Not connected* means the source was never wired on this deployment. *Empty*
  means the source is wired and was quiet. The workspace never collapses them.

## Steps

### Step 1 - Open the workspace

1. Go to **Investigate → Troubleshooting**. The page has one surface: the
   investigation.
2. A bookmark carrying an old `?section=` parameter — `protocol` (the retired
   manual bench) or `pipeline` (the retired collection-pipeline board) — lands
   on the investigation, and the parameter is removed from the address so a
   refresh stays on it. `?case=<id>` still opens the workspace on that case.

:::note
The **Collection pipeline** board is gone. Its step-zero question, "is the
pipeline or the device at fault", is answered beside the evidence lanes; its
collector counts, per-collector rows and flow sources moved to
**Platform → Tools → Stack Health**, in the Collection section.
:::

### Step 2 - Pick an open case or describe a problem

Under **Start troubleshooting**, pick a case under **Open cases**, or describe
the problem under **Describe a problem** and press **Start investigation**.
The card for a case carries an icon for its kind: a pulse for a case Correlix
correlated, a pen for one you described.

- **Open cases** holds both kinds in one list: Correlix's cases first, then
  the ones operators described, each newest first, up to twelve. Each row says
  who the case affects and since when.
- **Describe a problem** opens an investigation with your words as its title
  (up to 200 characters). It joins **Open cases** and is selected, so the next
  step acts on it.

Whichever you pick, the workspace opens **every** evidence lane: no lane is
pre-narrowed for you. (The nine-symptom picker, with its own lanes per
symptom, was retired on 2026-09-06.)

### Step 3 - Read the answer

Under **The answer**, the headline says what Correlix concluded, in plain
words, and never more than the engine said:

- a confirmed cause reads as the cause itself;
- a suspected one reads as the most likely cause, not yet confirmed;
- a recovered problem reads **This problem has recovered**;
- a cause the evidence contradicted reads **The leading cause was ruled out**;
- no verdict at all — always the case for a problem you described — reads
  **No cause confirmed yet**.

Four facts sit under the headline:

| Fact | What it says |
|---|---|
| **Breaking at** | The layer — Physical link, Routing, Overlay / Service or Application — where an evidence lane found a problem on this case's device. Until a lane does, it reads **Unknown**: data in a lane is evidence to read, not a located fault. |
| **Affects** | The devices and sites the case names, or **Nothing named yet**. |
| **Since** | When the case started, or **Not stated**. |
| **Owner** | Who owns the fix. Until the evidence points at one, it says nobody is named yet rather than guessing a team. |

A chip beside them gives the engine's confidence as **High**, **Medium** or
**Low confidence**, or **Not scored**. For a correlated case, **Case path**
draws where on the path the fault sits — the same path view the RCA workspace
shows.

### Step 4 - Read the evidence

Select **Show the evidence**. The lanes keep reading while it is closed: they
are what earn the **Breaking at** line.

| Lane | Open in |
|---|---|
| User experience | WAN circuits |
| Recent changes | Logs |
| Devices & links | Device Monitoring |
| Network path | WAN circuits |
| Routing | Protocol Monitoring |
| Traffic | Flows |
| Alerts & events | Logs |

Each card leads with one sentence of what it found, for example how many
interfaces are down right now, and links to the page that has the full read.
Each lane is in exactly one of five states: **loading**, **error** (the
server's message, verbatim), **not connected**, **empty**, or **ready**.

A lane with nothing to show is not dropped. It folds into one line under the
cards, and the two quiet states stay different facts:

- **Nothing feeds** *lane* — the source was never wired on this deployment, so
  the layer cannot be seen at all.
- **Nothing from** *lane* — the source is wired and was quiet in this window.

For a correlated case, the engine's six-question RCA header sits at the bottom
of the evidence: the same header the RCA workspace renders, one verdict
vocabulary in the product, not two.

### Step 5 - Ask Iris, then hand it off

The buttons under the answer act on the case you picked:

1. **Ask Iris** gives a grounded, cited read of this investigation: what the
   evidence supports, what is missing, and a recommended next step. Nothing is
   executed on your behalf.
2. **Open ticket** sends the case to the configured ticket system. A ticket
   needs a correlated case, so the button is unavailable on a problem you
   described, and the page says so.
3. **Escalate to TAC** collects the diagnostic command outputs for a vendor
   TAC case from the device you choose and builds a redacted bundle on the
   server. Only the commands that failed are listed, each with its reason. See
   [Export a redacted bundle for vendor support](/investigate/send-to-tac).

## Result

The answer, the layer it breaks at and who owns it are on one screen. The
evidence behind it stays one click away, with the layers that have real
evidence, the layers nothing is watching, and the layers that stayed quiet each
shown as a different fact.

## Related

- [Diagnose a BGP, OSPF or IS-IS issue](/investigate/protocol-diagnostics)
- [Read an RCA case](/investigate/read-an-rca-case)
- [Ask Iris about an incident](/iris-ai/ask-iris)
- [Check OSPF and IS-IS adjacency health](/investigate/igp-health)
