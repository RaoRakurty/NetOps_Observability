---
title: Operator guide
sidebar_label: Operator guide
description: What an operator does with Correlix during a shift, and the four pages that cover the routine.
page_type: index
sidebar_position: 1
---

# Operator guide

This section is for the operator on shift: the person who picks up what is
happening now, decides what to work first, reads the raw evidence when the
correlated view does not yet have an answer, and hands the result to a ticket.
It assumes devices are already reporting. If they are not, start with
[Onboard your first device](/getting-started/quickstart).

A shift in Correlix has a fixed shape. You open **Overview → Home**, the Command
Center, and read the Action Queue, which lists correlated incidents rather than
raw alerts. You work the queue by RCA state, owner and ticket state. When the
queue is empty and a user still reports a problem, you drop to the surfaces that
show what has not correlated yet: **Operations → Active Alerts**, **Explore →
Events**, **Explore → Logs** and **Investigate → Findings**. Anything you touch
is tracked through its lifecycle on **Operations → Incidents**.

## Pages

| Page | What it covers |
|---|---|
| [Start a shift](/noc-guide/where-to-start) | The on-shift routine: read the Command Center, work the Action Queue in priority order, and the decision path for when the queue is empty. |
| [Read device logs during an incident](/noc-guide/reading-logs) | Scoping a log search to a device and window, reading severity, recognising bursts and flaps, and pivoting from a line to the case that contains it. |
| [From observation to ticket](/noc-guide/from-signal-to-ticket) | How one observation becomes a finding, a correlated group, a graded RCA case, a notification and one ticket. |

## Related

- [Core concepts](/getting-started/concepts)
- [Read an RCA case](/investigate/read-an-rca-case)
- [Work incidents](/incidents/working-incidents)
- [Honest states](/reference/honest-states)
