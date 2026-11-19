---
title: Change assistance
description: Ask Iris to review a change plan, check whether a device is ready to upgrade, show a vendor upgrade procedure, or compare a device before and after a change — all read-only.
page_type: task
sidebar_position: 5
---

# Change assistance

Iris helps you prepare and verify a change. It never makes one: it does not
push configuration or images to a device, and it does not open or edit tickets.
Every change answer ends with **No action has been executed.**

## Before you begin

- Iris enabled for your workspace. See [Set up Iris](/iris-ai/setup).
- Live device reads (readiness and baselines) need device access configured for
  Correlix. Without it, Iris tells you the commands to run yourself instead.

## Review a change plan

Ask, for example:

- `review this change plan: upgrade core-sw-1 tonight 02:00 UTC, …` (paste the
  plan, up to 8 KB), or
- `is CHG0012345 ready?` — Iris reads that change record once, read-only,
  through your workspace's own ITSM connection.

Iris checks the plan against a fixed checklist and against your own network:

1. **Scope** — every device the plan names is found in your inventory.
2. **Pre-checks**, **success checks**, **rollback** and a **maintenance window**
   are present.
3. **What it could disturb** — the named devices' neighbours and paths, active
   incidents on them, configuration changes in the last 24 hours, and whether a
   baseline was taken (with its time).

The answer lists what is ready and what is missing, as recommendations. The plan
you paste is treated as quoted text only; it is never sent to an AI model as
instructions.

## Check whether a device is ready to upgrade

Ask, for example, `is edge-1 ready to upgrade to 17.12?`. Iris reads the device
live and answers **ready**, **not ready** (with each reason) or **cannot tell**:
current version, boot image and boot variables, free space on the boot
filesystem, control-processor redundancy, device health, open incidents and
recent changes.

Honest limits: the vendor's compatibility matrix is not checked (every verdict
says so); full parsing exists for Cisco IOS XE today, and other platforms get
the commands with their raw output.

## See a vendor upgrade procedure

Ask, for example, `how do I upgrade a Catalyst 9300?`. Iris shows a built-in,
step-by-step procedure for Cisco IOS XE (install mode), Cisco NX-OS, Juniper
Junos and Arista EOS, each citing the vendor's public guide. A person runs every
step. A workspace administrator can adopt a procedure as a draft MOP and put it
through your normal two-person approval — see
[Runbooks and MOPs](/administration/iris-runbooks).

## Take a baseline before, compare after

On the device page, open the **Change** tab:

1. Select **Take baseline** before the change (optionally with the change
   ticket). Correlix reads the device and stores a snapshot: interfaces, IGP and
   BGP neighbours with prefix counts, the routing table's size by source,
   software version and overlay sessions. The newest 10 baselines per device
   are kept.
2. After the change, select **Compare with baseline**. The comparison lists what
   came back, what did not, and which counts changed, each as an observed line.
   A section that could not be read says **cannot compare** — it is never shown
   as a loss.

You can also ask Iris: `take a baseline of edge-1 before the change` and
`compare edge-1 with its baseline`.

## Related

- [Investigate an incident with Iris](/iris-ai/ask-iris)
- [Iris skills and chaining](/iris-ai/skills)
- [Runbooks and MOPs](/administration/iris-runbooks)
