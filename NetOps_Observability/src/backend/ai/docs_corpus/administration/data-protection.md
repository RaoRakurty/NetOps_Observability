---
title: Read the Data Protection page
sidebar_label: Data Protection
description: Read whether this Correlix appliance can be recovered and how much would be lost, then find what is copied, how to prove a copy with a drill, and how much disk the copies use.
page_type: task
sidebar_position: 25
---

# Read the Data Protection page

**Platform → Security → Data Protection** answers one question at the top, in
plain words: can this appliance be recovered, and how much would be lost? The
rest of the page sits under three headings: **Protect**, **Recover** and
**Storage**.

The procedures for configuring backups, running a drill and restoring are in
[Back up and restore](/deploy/back-up-and-restore) and
[Manage snapshots](/deploy/manage-snapshots). This page tells you how to read
the screen.

## Before you begin

- A platform administrator account. Data Protection is platform-global
  configuration, not per-tenant data. A tenant or organization administrator
  receives `403`. Where a control is shown to an account that cannot change it,
  it reads **Changing this needs a platform administrator.**

## Steps

1. Go to **Platform → Security → Data Protection**.
2. Read the answer card at the top:
   - **Recoverable**: **Yes**, **Not yet** or **Unknown**, with one sentence
     saying why. **Yes** needs a restore that somebody actually proved.
   - **Last good copy**: how long ago the newest good copy was taken.
   - **Would lose**: how much data an outage right now would cost.
   - **Last drill**: **Drill passed** with its age, or **Never**.
   - The one action that matters most right now, as a button.
3. Open **Protect** to see what is copied. One row per store gives whether it
   is copied, the last copy and how long copies are kept. **Not copied yet**
   means the store has no copy. Whether a copy exists anywhere but this host is
   stated here too: with no off-host copy, one disk failure loses both.
4. Open **Recover** to restore from a copy, prove a copy with a drill, and read
   the drill history. The restore points and the audit trail are behind
   disclosures.
5. Open **Storage** for the bytes each store's copies use on disk.

## What you see

A value that was not measured reads **Not measured**. That is different from
**Never**, which means Correlix looked and the event has not happened. Neither
is ever shown as `0` or as a green tick.

Two actions carry their consequence on screen in full, and each needs you to
type the restore point name to confirm:

- An in-place restore closes and overwrites the live indices.
- Deleting a restore point cannot be undone.

Turning off scheduled copies asks for a reason, so whoever finds it off later
knows it was deliberate.

## Related

- [Back up and restore](/deploy/back-up-and-restore)
- [Manage snapshots](/deploy/manage-snapshots)
- [Check the health of the Correlix stack](/administration/stack-health)
