---
title: How root-cause analysis works
description: What an RCA case is, the verdict ladder, how evidence is graded, and why a verdict names a seam instead of a team.
page_type: concept
sidebar_position: 2
---

# How root-cause analysis works

An **RCA case** is the object the correlation engine produces when observations
from the same window and the same scope appear to share a cause. It carries a
verdict, the evidence behind it, the party that owns the fault, and what is
still missing. Correlix does not open an RCA case for every observation, and it
does not raise a verdict beyond what the evidence supports.

## How it works

The engine groups observations, ranks hypotheses against its signature catalog,
and then grades the leading hypothesis by **how many independent sources saw
it**. Independence is the whole test. Ten repetitions of one source are one
source, and the case header says so: repetition is drawn as density, never
counted as a second opinion. The console calls each piece of evidence an
**observation**, and a vocabulary check in the product's own test suite keeps
the older word off the screen.

### The verdict ladder

| Verdict | What it means |
|---|---|
| `confirmed` | Independent sources agree. The case names the cause and the owner. |
| `suspected` | Sources agree, but no independent pair confirms customer impact yet. |
| `undetermined` | No cause has enough supporting evidence yet. |
| `contradicted` | The leading cause was ruled out by discriminating evidence. |
| `recovered` | The incident has cleared. |

The header states the reason for the verdict in words and never as a
percentage. A confirmed case reads `Confirmed`, followed by the count of
independent sources that cross-checked it. A single-source case names the one
source that saw the fault and states that a second independent source is needed
to confirm. A case with no supported cause reads `Not confirmed`, followed by
the reason that no cause has enough supporting evidence yet.

`contradicted` is a result, not a failure. Ruling a cause out with evidence is
worth more to the next operator than leaving it open.

### How evidence is graded

Every classified observation carries the fidelity of the parser rule behind it.
The ladder, strongest first:

| Tier | Badge | What it means |
|---|---|---|
| `live_validated` | live validated | Confirmed against live device output. |
| `lab_validated` | lab validated | Confirmed against a lab capture. |
| `doc_claimed` | doc claimed | Vendor documentation only, unconfirmed on the wire. |
| `code` | unverified | Defined in the product, not yet confirmed against a device. |

A row that fuses several rules is graded at the **weakest** tier it contains, so
one unproven rule cannot ride on a proven one. A `doc_claimed` rule can support
a verdict but never confirm it. A row whose rules declared no fidelity renders
**no badge at all**: an absent grade is not a bad grade, and inventing one would
be a claim about the parser that nobody made.

### Who owns the fault

A verdict names the **seam** where ownership changes hands and the party
responsible for it, such as an ISP, a carrier, a cloud provider or an
application team. Correlix never names a generic "NOC" as the owner of a fault.
Where the evidence has not narrowed the seam at all, the case says the owner is
not yet narrowed and routes the case to triage, which is an honest statement
about the evidence rather than an assignment.

## The honest limits

- **A verdict may be a possibility.** An unconfirmed case with a leading
  hypothesis reads `Not confirmed - possibly because of X`. That phrasing is
  correct product behaviour: it hands the operator the best hypothesis and the
  fact that it is unproven, instead of a dead end.
- **Blast radius is not counted when it is not measured.** Where no impact
  telemetry attached, the **Affected** row reads `Not yet determined`. It is
  never a bare `0`, because zero affected devices is a claim nothing measured.
- **An empty list means not evaluated, not clean.** A case with no evidence in a
  panel says which source was quiet and which source was never wired.
- **Confidence is the engine's opinion of itself.** The only external measure of
  RCA quality is the operator verdict recorded on the case. See
  [Review and rate an RCA verdict](/investigate/rate-an-rca-case).

## Related

- [Read an RCA case](/investigate/read-an-rca-case)
- [Investigate a symptom](/investigate/investigate-a-symptom)
- [Events and incidents](/incidents/overview)
- [Glossary](/reference/glossary)
