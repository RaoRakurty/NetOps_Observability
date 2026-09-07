---
title: Investigate a symptom
description: Start from one of nine canonical workflows or an open case, read seven evidence lanes in parallel, and hand the fault to the seam that owns it.
page_type: task
sidebar_position: 5
---

# Investigate a symptom

The Troubleshooting workspace is where the operator drives and Correlix does the
legwork. You name what is wrong, or pick an open correlation case, and the
workspace opens the evidence lanes that workflow needs, all at once, each one
naming the API it read.

## Before you begin

- Read access to **Investigate** (`infrastructure:read`).
- A symptom in the operator's own words, or the id of an open case. Both entry
  points are equal: a case shows what Correlix concluded, a symptom starts a
  bisection with no verdict.
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

### Step 2 - Pick a symptom or an open case

Under **What's wrong?**, search or select one entry point. The nine canonical
workflows and the lanes each one opens:

| Symptom | Lanes it opens |
|---|---|
| An app is slow or unreachable | Digital experience and probes, Path, What changed, Flows, Device and protocol health, Correlated events |
| A site or device is down | Device and protocol health, Path, What changed, Correlated events, Routing and BGP |
| A link or interface is erroring | Device and protocol health, Flows, What changed, Correlated events |
| A routing adjacency dropped (OSPF / IS-IS) | Routing and BGP, Device and protocol health, What changed, Correlated events |
| BGP or an upstream is unstable | Routing and BGP, Path, What changed, Correlated events, Digital experience and probes |
| DNS, DHCP or authentication is failing | Digital experience and probes, What changed, Correlated events, Flows |
| Wireless clients are struggling | Digital experience and probes, Device and protocol health, Correlated events, What changed |
| A cloud or SaaS service is degraded | Digital experience and probes, What changed, Path, Correlated events, Flows |
| Something looks exposed or compromised | Correlated events, What changed, Flows, Device and protocol health |

Selecting an open case opens **every** lane, because the engine did not
pre-narrow the evidence for you.

### Step 3 - Read the verdict header

- With a **case** selected, the workspace renders the same six-question RCA
  header the RCA workspace renders for that object. There is one verdict
  vocabulary in the product, not two.
- With only a **symptom** selected, the header says plainly that there is no
  correlated verdict and that the layers are being bisected. Under it, the
  layer ladder reports each rung as `evidence available`, `nothing observed in
  this window`, `no source wired for this layer`, `not part of this symptom`, or
  `still reading the sources`. The rungs are Physical, L2 / link, IGP, BGP,
  Path / seam, Application, and Logs and changes. A rung is never counted as
  answered merely because one of its lanes is on screen.

### Step 4 - Read the lanes

Every lane names its source on the card, so nothing on the page is
unverifiable:

| Lane | Reads |
|---|---|
| Digital experience and probes | `/api/paths/health` |
| What changed | `/api/events/feed?class=changes` |
| Device and protocol health | `/api/metrics/query` |
| Path | `/api/probe/paths` |
| Routing and BGP | `/api/metrics/query` |
| Flows | `/api/flows/top` |
| Correlated events | `/api/events/feed` |

Each lane is in exactly one of five states: **loading**, **error** (the server's
message, verbatim), **not connected**, **empty**, or **ready**. The distinction
that matters in practice:

- A metric family that has never been scraped is **not connected**. The lane
  says which collector is not collecting, for example that no routing-protocol
  metric has ever been scraped.
- A family that exists with nothing out of state right now is **empty**.
- No flow exporter ever seen is **not connected**; exporters sending with no
  matching conversation is **empty**.
- The change lane reads the same event store the feed does, so it is wired on
  every deployment. No rows there is honestly **empty**, and the lane footer
  states that proximity in time is not a causal claim.

**Device and protocol health** carries a **Protocol diagnostics** button that
opens the BGP, OSPF and IS-IS panel in place. See
[Diagnose a BGP, OSPF or IS-IS issue](/investigate/protocol-diagnostics).

### Step 5 - Ask Iris, then hand it off

1. In the **Iris co-pilot** lane, select **Ask Iris** for a grounded, cited read
   of this investigation: what the evidence supports, what is missing, and a
   recommended next step. Nothing is executed on your behalf.
2. In **Handoff**, read the owner. Where the evidence has not attributed the
   fault to a seam, the panel says no seam owner is attributed yet rather than
   naming a team.
3. Select **Create ticket** or **Export PDF**. Both are attached to a
   correlation case, so they are unavailable on a symptom-only investigation.

## Result

The layers with real evidence, the layers nothing is watching, and the layers
that stayed quiet are each visible as different facts, in one screen. Where a case
backs the investigation, the same verdict, owner and hand-off actions are on the
page with them.

## Related

- [Diagnose a BGP, OSPF or IS-IS issue](/investigate/protocol-diagnostics)
- [Read an RCA case](/investigate/read-an-rca-case)
- [Ask Iris about an incident](/iris-ai/ask-iris)
- [Check OSPF and IS-IS adjacency health](/investigate/igp-health)
