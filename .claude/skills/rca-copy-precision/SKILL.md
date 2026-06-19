---
name: rca-copy-precision
description: Review and polish RCA/incident UI wording for enterprise NOC readiness. Use when editing RCA Inspector, correlation, evidence, path, ticket, incident, or dashboard copy.
---

# RCA Copy Precision Skill

You are reviewing Correlix RCA/incident UI copy for enterprise NOC demo readiness.

## Core rule

Operator View must be:
- brief
- decision-focused
- evidence-grounded
- not product-branded
- not debug-heavy
- not overclaiming

Debug View may be:
- verbose
- technical
- raw IDs
- weights
- topology/seam tokens
- evidence internals

## Never use product-branded explanatory copy in Operator View

Avoid:
- "Correlix observed..."
- "Correlix has not confirmed..."
- "Correlix needs..."

Use:
- "A signal was observed..."
- "Customer impact is not confirmed yet."
- "Independent evidence is needed before confirming impact."

## RCA language rules

Confirmed:
- "Likely fault location"
- "Customer impact confirmed"
- "Escalate"

Suspected / not confirmed:
- "Evidence localizes to"
- "Customer impact is not confirmed yet"
- "HOLD — suspected only"

Undetermined:
- "Observed near"
- "Insufficient evidence"

Internal/test:
- "Internal monitoring check"
- "Not customer-facing"
- "Do not open customer incident"

## Current screenshot fixture: single BGP/routing signal

If the RCA object has:
- device: wan-r2
- peer: 192.168.100.5
- evidence: one BGP state change
- no device health
- no traffic flow
- no active checks
- verdict: NOT CONFIRMED
- confidence: Low
- state: Open

Render:

Title:
"Possible routing issue"

Status:
"NOT CONFIRMED · Confidence: Low · State: Open"

Affected:
"Device: wan-r2"
"Peer: 192.168.100.5"
"Scope type: Routing adjacency"

Decision:
"HOLD — suspected only. Confirm with peer-side routing, device health, traffic-flow loss, downstream impact, or an independent active check."

Summary:
"A BGP state change was observed on wan-r2 with peer 192.168.100.5. Customer impact is not confirmed yet."

Why suspected:
"A routing/link change was observed on the affected routing adjacency."

Why not confirmed:
"This issue currently rests on a single observed signal. Independent evidence is needed before confirming customer impact."

To confirm:
"Add peer-side BGP/routing state, interface errors or drops, traffic-flow loss, downstream service impact, or an active check from an independent vantage."

Routing context:
"wan-r2 → BGP neighbor changed → 192.168.100.5"

Localization:
"Evidence localizes to: wan-r2"

Ticket:
"Not opened — impact not confirmed."

## Current screenshot fixture: device health + BGP evidence

If the RCA object has:
- device: leaf1
- device health signal: CPU/memory change
- routing/link signal: BGP neighbor change
- no traffic-flow confirmation
- active checks seen but not linked or ignored
- verdict: NOT CONFIRMED
- confidence: Medium
- state: Recovering

Render:

Title:
"Possible device/routing issue"

Status:
"NOT CONFIRMED · Confidence: Medium · State: Recovering"

Recovery:
"Recovering — 5 signals cleared; object will close if no new evidence appears."

Affected:
"Device: leaf1"

Decision:
"HOLD — suspected only. Confirm with peer-side routing, traffic-flow loss, downstream impact, or an independent active check."

Summary:
"Device-health and routing/link signals changed on leaf1. This suggests a possible device/routing issue, but customer impact is not confirmed yet."

Why suspected:
"Device health and BGP neighbor evidence were observed on the same device area."

Why not confirmed:
"The supporting signals are related, but they come from the same device area. Independent evidence is needed before confirming customer impact."

To confirm:
"Add peer-side BGP/routing state, traffic-flow loss, downstream service impact, or an active check from an independent vantage."

Routing context:
"leaf1 → BGP neighbor changed → 10.70.245.122"

Localization:
"Evidence localizes to: leaf1"

## Graph wording rules

Do not show "BGP session up" in an RCA context.

Use:
- "BGP neighbor changed"
- "BGP session recovered"
- "BGP session down"

Do not call routing adjacency context "End-to-end path."

Use:
- "Routing context"
- "Affected link or interface"
- "Ownership boundary involved"
- "Affected device area"

## Evidence card wording

Device health:
- "No signals seen"
- "1 signal used"
- "Seen, not linked"

Routing & link events:
- "1 event seen"
- "1 used"
- "Main evidence"

Traffic flow:
- "No flow signals seen"
- "Traffic loss/drop observed"

Active checks:
- "No checks seen"
- "Seen, not linked"
- "Test checks ignored"

## Operator View must hide

- strength values like "0.38"
- raw IDs
- corr_signal IDs
- corr_edge IDs
- topology tokens
- seam tokens
- edge weights
- grounding tokens
- database/backend names

Debug View may show them.

## Review checklist

Before finalizing RCA UI copy, verify:

1. Does the title match the evidence type?
2. Does the page avoid overclaiming?
3. Does it say not confirmed when impact is not confirmed?
4. Does it show what evidence is missing?
5. Does it give a clear NOC decision?
6. Does it avoid product-branded explanatory copy?
7. Does Operator View hide debug internals?
8. Does the graph label match incident evidence, not only current state?
9. Does ticket wording avoid opening tickets from weak evidence?
10. Is reasoning brief by default?
