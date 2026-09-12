---
title: Incidents
sidebar_label: Overview
description: How alerts, logs, traps and findings become one RCA case with a verdict, and where each part of that lives in the console.
page_type: index
sidebar_position: 1
---

# Incidents

Correlix builds two objects out of raw observations: the RCA case an engineer
opens to answer "why", and the operational incident record a team drives to
closure. The operator deciding what to do about a burst of alerts works both.

| Page | What it covers |
|---|---|
| [Read an incident](/incidents/reading-an-incident) | Read one RCA case end to end: verdict, evidence, blast radius, timing, ticket. |
| [Work the incident queue](/incidents/working-incidents) | Triage the RCA candidate list and drive an operational incident to closure. |
| [Anomalies and correlation](/incidents/anomalies-and-correlations) | How observations are grouped, what a verdict claims, and what it refuses to claim. |

## The two objects

Correlix keeps the analysis and the workflow apart, because they answer
different questions and have different lifecycles.

| Object | Where | What it is |
|---|---|---|
| **RCA case** | **Investigate → RCA** | A correlated group of observations with a ranked cause, evidence, and a verdict. Its handle is a Problem ID in the form `P-XXXXXX`. |
| **Incident** | **Operations → Incidents** | The tracked operational record: severity, status, assignee, notes, and an optional projection to a ticket. Its handle is a display id in the form `INC-XXXXXX`. |

An RCA case states what the evidence supports. An incident states what the team
is doing about it. A verdict can change without the incident changing hands, and
an incident can close while the RCA case still says the cause was never
confirmed.

The operational incident record requires the Postgres backend. On the file
backend the incident routes answer `409` with `the incident system requires the
Postgres backend`.

## The verdict ladder

Every RCA case carries one verdict.

| Verdict | What it claims |
|---|---|
| `confirmed` | Independent evidence classes agree in the same window and scope. |
| `suspected` | The evidence points at a cause, and no independent pair confirms customer impact yet. |
| `undetermined` | No cause has enough supporting evidence yet. |
| `contradicted` | The leading cause was ruled out by discriminating evidence. |
| `recovered` | The incident has cleared. |

Verdict reasons are stated in words, never as a percentage. A case that cannot
name a cause says so and names the best hypothesis alongside it, rather than
offering a bare dead end.

Deep coverage of how the verdict is reached lives on
[how RCA works](/investigate/rca-explained).

## What these surfaces refuse to invent

- Affected devices render as **Not yet determined** when the blast radius is
  unknown. Never a bare `0`.
- Window counts and facet counts report **unknown**, not zero, when the store
  read fails. A failed count is a different fact from an empty window.
- The product says **observations**, never `signals`. Repetition shows
  persistence, not additional evidence, so an occurrence count never promotes a
  verdict on its own.
- An empty alert list means no rule is firing right now. It does not mean every
  rule was evaluated.

[Honest states](/reference/honest-states) sets out the whole vocabulary.

## Related

- [How RCA works](/investigate/rca-explained)
- [Work the alert queue](/monitoring/manage-alerts)
- [Incident response](/incident-response/overview)
- [Honest states](/reference/honest-states)
