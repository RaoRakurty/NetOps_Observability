---
title: Review a proposed wireless remediation
sidebar_label: Review a proposed wireless remediation
description: Read a proposed wireless remediation, approve or reject it with a recorded reason, and understand the five gates every action passes before it can run.
page_type: task
sidebar_position: 8
---

# Review a proposed wireless remediation

Correlix can propose a small, bounded wireless fix from a confirmed incident:
move one radio to a different channel, restart one access point's radio, or
disconnect one client session. It never carries the fix out on its own. A person
approves it, a person executes it, and every transition is recorded.

The approval queue is on **Operations → Action Queue**, beneath the incident
queue, so the decision sits next to the work it belongs to.

## Before you begin

- `FEATURE_WIRELESS_ACTIONS=true` on the deployment. It defaults to off, and
  with it off the routes are not registered: the queue renders nothing at all
  rather than an empty approval list.
- `WIRELESS_ACTION_ALLOWLIST` naming the action kinds this installation permits.
  The default is empty, which means nothing is eligible until an administrator
  opts a kind in.
- `infrastructure:read` to see the queue. `infrastructure:write` to approve,
  reject or execute. Without write access the queue renders read-only and says
  so.
- A confirmed RCA case. A proposal is only accepted when its evidence family
  took part in the case it claims to fix.

## Steps

### Step 1 — Read what is waiting

1. Go to **Operations → Action Queue**.
2. Scroll to **Wireless remediation**.
3. Read the row: what the action does in plain words, the single target it acts
   on, the incident it came from, and who proposed it.

The three action kinds and their blast radius:

| Action | What happens |
|---|---|
| Channel change | One radio moves channel. Clients on it re-associate briefly |
| Radio reset | One access point's radio restarts. Everything on that radio drops and re-joins |
| Client disconnect | One client session is dropped. The client re-associates on its own |

Follow the incident link first. The proposal is only as good as the case behind
it, and the case is where the evidence is.

### Step 2 — Approve or reject

To approve:

1. Write an optional note in the reason field.
2. Select **Approve**.

Approving does not run the action. It records that a named person agreed with
it.

To reject:

1. Write the reason. It is required, and **Reject** stays disabled until it is
   filled in.
2. Select **Reject**.

A rejection with no recorded reason is the gap this workflow exists to close.
The next operator who sees the same proposal reads your reason before raising
it again.

### Step 3 — Execute

1. Select **Execute** on an approved row.
2. Type the target name exactly, as the prompt shows it.
3. Select **Execute now**.

The type-to-confirm step is deliberate. Execution touches a radio that is
serving clients at that moment, and it cannot be taken back.

## Result

An executed action records verification as **pending**, not as done. The
originating observation is re-measured in a settle window before the action
counts as a fix, so a change that did not help is never reported as one.

On a release with no vendor write connector registered, execution fails closed
and records the refusal on the row:

```
gate 4: no executor registered — the vendor write RPC has not earned live validation
```

That is the gate working. The framework, the approvals and the audit trail ship
before any executor, on purpose. Every transition is written to the audit log
with the actor, the action kind, the target and the case it came from.

## The five gates

| Gate | What it enforces |
|---|---|
| 1 Proposal | The action's evidence family took part in the case it claims to fix |
| 2 Eligibility | The kind is on the tenant allowlist, the verdict is confirmed, the target is exactly one entity |
| 3 Approval | A named human approver. A rejection carries a reason |
| 4 Execution | The vendor controller only. Never a device login |
| 5 Verification | A settle-window re-measurement, recorded as pending until it completes |

## Related

- [Monitor wireless](/infrastructure/wireless)
- [Read an RCA case](/investigate/read-an-rca-case)
- [Connect a wireless controller](/infrastructure/nms-integrations)
- [Read the audit log](/administration/audit-log)
