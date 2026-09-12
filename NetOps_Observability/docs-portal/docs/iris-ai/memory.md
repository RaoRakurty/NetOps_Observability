---
title: Investigation memory
description: What Iris remembers about a concluded investigation, how an operator's rating decides it, and why memory is evidence and never a rule.
page_type: concept
sidebar_position: 5
---

# Investigation memory

Investigation memory is one row per **concluded** investigation: the entity it
was about, the skill chain that ran, the final verdict, the citations it rested
on, and the operator's judgement of it. It answers a single question: has this
been seen before, and was Correlix right?

## How it works

When a skill chain concludes, the conclusion is held in a bounded in-process
buffer, keyed to the principal and the subject. It is not on disk and not read
by the model. Nothing is remembered yet, because a conclusion without an outcome
is not worth keeping.

The row is written when an operator rates the answer:

| Rating | Recorded outcome | Shown as |
|---|---|---|
| Thumbs up | `confirmed` | operator confirmed |
| Thumbs down | `wrong` | operator marked wrong |
| No rating within 30 minutes | nothing is written | the conclusion is forgotten |

A wrong memory is kept on purpose. Knowing that a past conclusion was rejected
is more useful than forgetting it, provided the outcome is always stated with
it.

### Recall

The `recall_investigations` tool returns at most **5** prior conclusions for the
entity in scope, newest first, each as one bounded evidence item cited
`memory:<id>` with its outcome in operator words. The lookback is a closed
vocabulary of `24h`, `7d`, `30d`, `90d` (the default) and `180d`, so no
model-controlled duration can widen a scan.

Every result carries the rule that makes memory safe, including the empty
result, so an absent memory is never read as nothing having happened:

> Prior investigations are context, not current state. Verify what the device
> and the engine report now before relying on any remembered cause.

The skills that gather memory do so only **after** the live-state step, and the
loader enforces that ordering.

## Why memory is never a rule

Every other Iris tool may declare machine signals that the bounded investigation
loop evaluates against authored `next=` conditions. This one declares none, and
never will.

A remembered conclusion is a hypothesis an operator once accepted or rejected.
Wiring it into the deterministic router would let one past judgement, or one
mis-click on a thumbs-down, silently re-route every future investigation of that
entity, and would make the assistant's path depend on its own history rather
than on the evidence in front of it. Memory informs the narrative. The engine's
facts alone choose the next check.

## Isolation and bounds

- **Tenant-scoped in the store itself.** On Postgres the table carries the
  `tenant_iso` FORCE-RLS policy and every query runs under the caller's tenant.
  There is no unscoped list, and a recall with no entity key returns nothing
  rather than a tenant-wide dump.
- **Resolved through your own inventory.** A device name is resolved in the
  caller's inventory first, so another tenant's device name is not found, rather
  than answering "no memory", which would confirm that the device exists
  somewhere.
- **Bounded at write and at read.** Each tenant keeps at most 200 concluded
  investigations, oldest evicted first. The stored verdict is clipped at 600
  characters, at most 12 citation ids and at most 4 skill names are recorded, and
  every key is clipped at 128 characters.
- **Nothing survives a restart unjudged.** The pending buffer is in memory only,
  capped per principal and overall, and expires after 30 minutes.

## The honest limits

- Memory records what an operator judged, not what was true. The outcome word is
  always shown with the row for that reason: `operator confirmed`,
  `operator marked wrong` or `unverified`.
- A conclusion nobody rated is forgotten. The absence of a memory is not
  evidence that the entity has been healthy.
- Memory never appears without a live-state check ahead of it in the same turn.

## Related

- [Iris skills and chaining](/iris-ai/skills)
- [Investigate an incident with Iris](/iris-ai/ask-iris)
- [Review and rate an RCA verdict](/investigate/rate-an-rca-case)
