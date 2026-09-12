---
title: Anomalies and correlation
sidebar_label: Anomalies and correlation
description: How Correlix turns raw observations into findings, groups them into an RCA case, and decides what a verdict is allowed to claim.
page_type: concept
sidebar_position: 4
---

# Anomalies and correlation

Correlation is the step between a flood of raw observations and one case an
engineer can act on. It takes what the collectors, syslog, traps, flows, active
probes and the security lane saw, groups the ones that belong to the same event,
ranks the causes that would explain the group, and states a verdict with the
evidence behind it.

## How it works

### Observations

Everything that enters the correlation window is an **observation**. The product
uses that word everywhere, and never the word `signals`, because the count of
raw rows is not the measure of anything. Repetition shows persistence, not
additional evidence.

An observation carries the evidence class that saw it, the parser fidelity of
the rule that recognised it, and its timestamp.

### Findings

**Investigate → Findings** is titled **Detected Findings**: observations that
deviate from baseline and may contribute to incidents or RCA candidates. A
finding is a deviation, not a verdict. It becomes evidence when correlation
attaches it to a case.

### Grouping

The engine opens a window, attaches the observations that share scope and time,
and closes the window after a quiet period. The window's start is the earliest
observation onset, and its end is the last written evidence time. A closed window
means the engine saw no further symptoms, which is a proxy for recovery and not a
measurement of it.

Where two cases turn out to describe the same event, one is merged into the
other. A merged case has no lifecycle of its own: its recovery, its timing and
its ticket belong to the case it was folded into.

### The independence rule

A verdict is `confirmed` only when independent evidence classes agree in the same
window and scope. Two streams that derive from the same collector are one source,
and the engine counts them that way. This is the rule that stops a single noisy
collector from producing a confident wrong answer.

The case header states the count in words: how many distinct symptoms, how many
independent sources, and over what duration. The raw observation total trails
behind those, deliberately de-emphasised.

### Verdicts

| Verdict | What it claims |
|---|---|
| `confirmed` | Independent evidence classes agree in the same window and scope. |
| `suspected` | The evidence points at a cause, and no independent pair confirms customer impact yet. |
| `undetermined` | No cause has enough supporting evidence yet. |
| `contradicted` | The leading cause was ruled out by discriminating evidence. |
| `recovered` | The incident has cleared. |

The reason is always in words. A single-source case reads that only that source
saw it and a second independent source is needed to confirm. A ruled-out case
reads that the leading cause was ruled out by the evidence, and the sequence
stays visible for the record rather than as a live explanation.

A percentage never stands alone as the reason for a verdict.

## What correlation does not do

- **It does not name a generic owner.** Correlix names the seam and the party
  that owns it. Where the seam has not been narrowed at all, the case says
  `Not yet narrowed — NOC triage` rather than blaming a team.
- **It does not convert one evidence class into another.** Synthetic probe
  failures and flow-volume changes are never turned into affected-user counts
  without an identity or transaction mapping. A quantity Correlix cannot source
  is stated as not measured.
- **It does not report an unknown blast radius as zero.** Affected scope reads
  **Not yet determined** when nothing measured it.
- **It does not treat volume as proof.** An occurrence count never promotes a
  verdict on its own.
- **It does not claim a recovery it did not observe.** Where no ticket supplies
  one, a closed case yields an inferred recovery stamp with capped confidence,
  and an open case yields nothing at all.

## Where each part appears

| Surface | Console path |
|---|---|
| Findings | **Investigate → Findings** |
| RCA candidates | **Investigate → RCA** |
| Operational incidents | **Operations → Incidents** |
| Promoted outage documents | **Analytics → RCA Reports** |

## Related

- [How RCA works](/investigate/rca-explained)
- [Work the incident queue](/incidents/working-incidents)
- [Read an incident](/incidents/reading-an-incident)
- [Honest states](/reference/honest-states)
