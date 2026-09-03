---
title: Investigate
description: RCA cases, the symptom-first troubleshooting workspace, protocol diagnostics and IGP adjacency health.
page_type: index
sidebar_position: 1
---

# Investigate

This section is for the operator who has a problem in front of them and needs to
know what broke, who owns it, and what the evidence actually supports. It covers
the RCA case an operator opens, the troubleshooting workspace where the operator
drives, the BGP, OSPF and IS-IS diagnostics that read a device, and the IGP
health surfaces that report an uncollected source as absent instead of as zero.

Iris, the assistant that answers questions about these surfaces, has its own
section: [Iris](/iris-ai/overview).

| Page | What it gives you |
|---|---|
| [How root-cause analysis works](/investigate/rca-explained) | The verdict ladder, the evidence fidelity ladder, and why a case names a seam rather than a team. |
| [Read an RCA case](/investigate/read-an-rca-case) | The six questions the case header answers above the fold, and the panels below it. |
| [Review and rate an RCA verdict](/investigate/rate-an-rca-case) | Record whether the engine was right, and read the 30-day feedback tile. |
| [Investigate a symptom](/investigate/investigate-a-symptom) | Start from one of nine workflows or an open case, and read seven evidence lanes in parallel. |
| [Diagnose a BGP, OSPF or IS-IS issue](/investigate/protocol-diagnostics) | The 15-issue matrix, the read-only command bundle, and the analysis that says plainly when nothing matched. |
| [Collect diagnostics from a device](/investigate/collect-from-a-device) | Turn on the live capture transport, or use the paste path when it is off. |
| [Export a redacted bundle for vendor support](/investigate/send-to-tac) | Hand a vendor TAC the evidence, with secrets masked before the file exists. |
| [Check OSPF and IS-IS adjacency health](/investigate/igp-health) | Adjacencies, flaps, LSDB size and timers, each with the coverage that backs it. |
| [View interfaces by routing instance](/investigate/interfaces-by-routing-instance) | One device's interfaces in the vendor's own dialect, grouped only where the binding is collected. |

## Where these surfaces live

The console groups them under **Investigate**: **RCA**, **Findings**,
**Topology**, a **Paths** group (**Flow Trace**, **Tunnels**, **WAN Paths**) and
**Troubleshooting**. IGP adjacency health sits with the routing boards under
**Analytics → Protocol Monitoring**, and interfaces by routing instance is a tab
on the device page under **Infrastructure → Devices**.

## Related

- [Events and incidents](/incidents/overview)
- [Monitoring and alerting](/monitoring/overview)
- [API reference](/reference/api)
