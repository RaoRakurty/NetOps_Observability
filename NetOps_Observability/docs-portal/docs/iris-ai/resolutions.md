---
title: Fixes and similar incidents
description: Record how an RCA case was fixed, and see "last time this was fixed by…" when a similar incident happens.
page_type: task
sidebar_position: 8
---

# Fixes and similar incidents

When you close a case, record what fixed it. The next time a similar incident
happens, the RCA view and Iris can say what fixed it last time — as history,
never as the cause of the new incident.

## Record how a case was fixed

In the RCA case, under **How was this fixed?**:

1. Choose what fixed it: *Rolled back a configuration change*, *Replaced
   hardware*, *The provider fixed it (ticket raised)*, *Rebooted a device*,
   *Changed routing*, *Added capacity*, *No action — it cleared on its own*, or
   *Something else (say what below)*.
2. Add a short note if it helps.
3. Save. Nothing shows as recorded until it is stored. Recording again adds a
   new entry; the newest comes first.

## See similar incidents

The RCA view lists similar past incidents from your own workspace's closed
history. When a past case has a recorded fix, it reads *Last time this was
fixed by …*. Below the similarity threshold it says **No similar incident** and
shows no near misses. A similar incident is context, not the same cause.

Iris uses the same records: asked "have we seen this before?", it answers from
your similar incidents and their recorded fixes, labelled as history, and may
suggest the earlier fix as a recommendation card.

## Related

- [Read an RCA case](/investigate/read-an-rca-case)
- [Iris learning](/administration/iris-learning)
