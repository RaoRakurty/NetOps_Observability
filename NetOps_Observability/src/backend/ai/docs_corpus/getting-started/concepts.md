---
title: Core concepts
sidebar_label: Core concepts
description: The mental model behind Correlix - what it collects, what correlation does with it, what an RCA case and a seam are, and the honesty principle.
page_type: concept
sidebar_position: 2
---

# Core concepts

Correlix rests on six ideas. It collects several independent classes of
measurement about the same network. It correlates them. It produces an RCA case
with a graded verdict. It attributes the fault to a seam. It isolates everything
by tenant. And it never states a fact it did not measure. What follows is that
model. For the definition of a single term, use the
[Glossary](/reference/glossary).

## What Correlix collects

The classes below are independent on purpose. Independence is what makes
agreement between two of them meaningful.

| Class | What it is | Where it comes from |
|---|---|---|
| Metrics | Numeric time series: CPU, memory, interface counters, protocol state. | SNMP polling, and gNMI streaming telemetry delivered into the same metrics plane. |
| Logs | Syslog the devices emit about themselves. | The syslog receiver. See [Send syslog](/send-data/syslog). |
| Flows | Traffic records stating who talked to whom and how much. | NetFlow, IPFIX and sFlow exporters. See [Send flow records](/send-data/flows). |
| Traps | SNMP notifications a device pushes when its state changes. | The trap receiver. See [Send SNMP traps](/send-data/traps). |
| Active probes | Measurement Correlix originates: ICMP reachability, STAMP, hop-by-hop path trace. | The probe collectors. |
| Active verification | The device's own answer to a bounded, read-only command battery. | The SSH gateway, on demand. See [Collect from a device](/investigate/collect-from-a-device). |
| Controller intelligence | What a vendor controller or NMS knows that the device does not report: wireless clients, SD-WAN overlay state, controller events. | Controller and NMS connectors. See [NMS integrations](/infrastructure/nms-integrations). |
| Security findings | Verdicts about an asset: posture, exposure and detection. | The security scanners. See [Security overview](/security/overview). |

Two of these carry a limit worth knowing before you rely on them. Controller
intelligence is a management-plane report rather than a wire measurement, and a
case supported only by a controller is capped at *suspected*. Security findings
are verdicts about an asset rather than a measurement of the path, so a
security-only case can never reach *confirmed* either. Both can corroborate a
case that a measured class already supports.

## What correlation does

Observations that share a time window and a network relationship are grouped into one
object. The engine matches the group's shape against a catalog of known failure
patterns, ranks the causes it considered, and grades the result.

The grade is one of three tiers:

| Tier | What it means | How the console shows it |
|---|---|---|
| `confirmed` | At least two measurement classes agree, reported by at least two observers that share no measurement authority and no shared fate, and every class the matched signature requires is present. | **Confirmed** |
| `suspected` | Supporting observations exist, but the independence bar is not met. | **Suspected** |
| `undetermined` | Too little evidence to place a cause. | **Not confirmed** |

The bar is deliberately harder than "two sources agree". Two readings that come
from the same collector, or two devices that fail together for the same reason,
are not independent, and the engine does not count them as corroboration. A case
that stops short of `confirmed` names the classes it is missing rather than
rounding up.

The confidence value attached to a case is a heuristic rank, not a probability.
Read it as an ordering between hypotheses.

Two further states sit alongside those three grades on a case: `contradicted`,
when the leading cause was ruled out by discriminating evidence, and
`recovered`, when the incident has cleared. See
[How root-cause analysis works](/investigate/rca-explained) for the full
ladder.

## What an RCA case is

An RCA case is the object an operator opens: one problem, with the evidence for
it. It carries a stable problem identifier, the graded verdict, the ranked
hypotheses with the reason each was kept or dropped, the affected devices and
paths, the owner, and an evidence matrix that shows what was found, what is
missing and what conflicts.

The case is versioned. A verdict that strengthens as evidence arrives is a new
version of the same case, not a second case, which is why one root cause
produces one ticket rather than one ticket per alert.

Two rows are worth reading carefully. **Root cause** names an object only when
the verdict is confirmed; otherwise the case states the honest form, *possibly
because of X*. **Owner** appears when the seam is attributed, and **Possible
owner** when it is not.

## Seams and why ownership matters

A seam is a transition in who is responsible for forwarding the packet. There
are five, and the set is closed:

| Seam | How the console labels it | Umbrella |
|---|---|---|
| `DIA` | **ISP** | WAN |
| `DX` | **DX** | WAN |
| `VPN` | **VPN** | WAN |
| `SDWAN` | **SD-WAN** | WAN |
| `CLOUD_BACKBONE` | **Cloud backbone** | Cloud |

LAN and the data center are not seams. Ownership does not change hands inside
them, because the enterprise owns them end to end.

Attribution matters because the next action depends on it. A fault at the ISP
seam is escalated to the provider; a fault inside the LAN is worked internally.
Correlix names the seam and the party that owns it. Where it cannot narrow the
seam it says the seam is not narrowed, which is a different statement from
naming an owner.

## Tenants and organizations

A **tenant** is the isolation unit. Devices, telemetry, incidents and findings
belong to exactly one tenant, and every surface filters by the caller's tenant.
A request for another tenant's resource by identifier answers 404 rather than
revealing that the resource exists.

An **organization** is a set of tenants. Every tenant belongs to exactly one
organization. The organization is where single sign-on, data residency and
org-level administrators bind. It carries no isolation behaviour of its own:
isolation stays at the tenant.

Cross-tenant reading is reserved to the platform owner, and it is derived from
the token rather than from anything in the request.

## The honesty principle

Correlix distinguishes *not measured* from *measured as zero*, and it does so
everywhere, not as a footnote.

- **A panel with no value means the metric is not collected.** It does not mean
  the value is zero. Zero adjacencies is a claim about a device; nothing
  measured it, so nothing reports it.
- **An empty list means not evaluated, not clean.** The security posture
  response says this in the payload: unassessed assets are "NOT a pass, nobody
  looked at those assets".
- **Not connected and empty are different facts.** A source that was never wired
  and a source that was wired and quiet are reported separately.
- **A verdict never outruns its evidence.** *Possibly because of X* is a
  complete and acceptable answer.

[Honest states](/reference/honest-states) lists every state a surface can
return and what each one means.

## Related

- [What Correlix does](/getting-started/overview)
- [Onboard your first device](/getting-started/quickstart)
- [Glossary](/reference/glossary)
- [Honest states](/reference/honest-states)
- [How correlation works](/investigate/rca-explained)
- [Tenants and organizations](/administration/tenants-orgs)
