---
title: Glossary
sidebar_label: Glossary
sidebar_position: 2
description: Definitions of the terms used across Correlix, alphabetized.
---

# Glossary

Alphabetized definitions of the terms used across the Correlix console and these docs. For the connected mental model — how these ideas relate — read **[Key concepts](/getting-started/concepts)**.

**Active measurement** — telemetry Correlix *originates* rather than receives: ICMP echo, STAMP, and path-trace probes that measure latency, jitter, loss, and the hop-by-hop path traffic actually takes. Complements passive planes (metrics, logs, flows) with an outside-in view.

**Alert** — an active, unresolved breach of a *monitor*. Alerts appear under <kbd>Monitoring → Active Alerts</kbd> and can mark an otherwise-reachable device as Degraded.

**Anomaly** — a deviation from a metric's own learned normal, detected automatically with no threshold configured. Anomalies are events, and they feed correlation as signals.

**Correlation** — the grouping of related signals — across telemetry planes and across devices — that share a cause and time window into a single *incident*. Also the console page (<kbd>Monitoring → Correlations</kbd>) where these groupings are inspected.

**Coverage matrix** — the per-device scoreboard at <kbd>Administration → Data Collection → Data Sources</kbd>: one row per device, one column per data source (SNMP metrics, Flows, Syslog, Traps), each cell either receiving or "no data". The primary onboarding checklist.

**Device** — a network element Correlix monitors: router, switch, firewall, load balancer. Devices are discovered over SNMP, added manually, or imported; the fleet lives at <kbd>Infrastructure → Devices</kbd>.

**Discovery** — the scan that finds devices automatically: Correlix walks your management ranges and onboards every host that answers SNMP with a valid credential. Idempotent — re-running updates rather than duplicates.

**Evidence** — the specific signals (with their sources) that support or contradict an incident's *verdict*. Every Correlix conclusion is backed by clickable evidence; a verdict is never stronger than its evidence.

**Event** — anything noteworthy on the timeline: a syslog message, a trap, an alert, an anomaly, a detected change. Browsable at <kbd>Monitoring → Events</kbd>.

**Fault domain** — the part of the network an incident's root cause lives in (a device, a link, a protocol layer, a provider segment). The verdict expresses confidence in the fault domain; the *recommended owner* maps it to a team.

**Flow** — a traffic record (NetFlow, sFlow, or IPFIX) exported by a device, describing who talked to whom, over what, and how much. Explored under <kbd>Flows</kbd> in the Data zone.

**Flow Trace** — the console's hop-by-hop path view (<kbd>Infrastructure → Flow Trace</kbd>), built from active path measurements — how traffic *actually* traverses the network, not just how it should.

**Incident** — the operator-facing unit of trouble: one grouped, root-caused problem produced by correlation, instead of a page per symptom. Managed under <kbd>Monitoring → Incidents</kbd> and the Incident Response Command Center.

**Interface** — a port on a device; the source of throughput, utilization, error, and oper-status metrics that form the backbone of network monitoring.

**Measurement target** — the destination a WAN interface's echo probes measure toward (a peer, next hop, or public anchor) on the [WAN Interface Metrics](/infrastructure/wan-interface-metrics) page.

**Metric** — a numeric time series about a device: CPU, memory, interface counters, protocol state. Polled over SNMP or streamed via gNMI, and explored under <kbd>Metrics</kbd>.

**Monitor** — a rule you define that watches a metric or condition and raises an *alert* when breached. Created at <kbd>Monitoring → Create Monitor</kbd>; the deliberate counterpart to automatic anomaly detection.

**Organization** — an account layer that groups *tenants*, for operators running Correlix for multiple customers or business units. Managed under <kbd>Administration → Identity & Access</kbd>.

**Platform owner** — the cross-tenant super-administrator who manages the platform itself. Some sections (Source Of Truth, Stack) are visible only to the platform owner.

**Recommended owner** — the team an incident's fault domain maps to (routing, provider, security…), so the incident lands with whoever can actually fix it.

**Role** — a named set of permissions. All access in Correlix is role-based and enforced on every surface.

**Seam** — a responsibility boundary in a path — where your network hands off to an ISP, a cloud, or another team. Seams let correlation attribute a fault to the correct *side* of a handoff.

**Site** — a location grouping for devices (data center, branch, region), used for scoping and for placing devices on the Geomap.

**SNMP credential** — the secret Correlix authenticates to a device with: a v2c community string or an SNMPv3 user (auth + privacy). Stored encrypted, write-only, in the SNMP Profile Manager.

**SNMP profile** — a vendor entry in the OID & metric library defining *what* Correlix reads from that vendor's devices. Built-in profiles cover common vendors; most onboardings never edit them.

**Source of Truth (SoT)** — the authoritative *intended* inventory (what should exist), as distinct from the discovered inventory (what answers). Correlix keeps an internal SoT and can exchange records with an external one; see [Automation](/automation/overview).

**Streaming telemetry** — device metrics pushed continuously over gNMI instead of polled over SNMP — higher resolution, where the platform supports it. See [Streaming telemetry (gNMI)](/onboard-devices/streaming-gnmi).

**Syslog** — the log messages devices emit; pointed at Correlix they become events on the timeline and signals for correlation.

**Tenant** — an isolated view of the platform. A tenant only ever sees its own devices, telemetry, and incidents; isolation is enforced everywhere by design.

**Topology Canvas** — the interactive network map (<kbd>Infrastructure → Topology Canvas</kbd>) built automatically from discovered neighbor relationships — you don't draw it by hand.

**Trap** — an SNMP notification a device pushes when something changes (link down, config change, hardware alarm). Received on UDP 162 and treated as events.

**Verdict** — Correlix's stated confidence in an incident's fault domain: **Confirmed** (evidence aligned across independent signals), **Suspected** (supporting signals, not fully validated), or **Undetermined** (a low-evidence watch item).
