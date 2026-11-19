---
title: Analyse flows
description: Explore → Flows shows the busiest links with their utilisation, who is talking on each link, and link capacity, from NetFlow, IPFIX and sFlow records and the interface counters.
page_type: task
sidebar_position: 4
---

# Analyse flows

**Explore → Flows** answers three questions about the network: which links
are busy right now, who is talking on them, and how close each link is to
full. The unit of the page is a **link**: one interface on one device, named
the way the device names it. Interface utilisation is the anchor, and the flow
records explain it.

## Before you begin

- Devices exporting flow records. Correlix listens on UDP 2055 for NetFlow, UDP 4739 for IPFIX and UDP 6343 for sFlow. See [Send flow data](/send-data/flows).
- SNMP collection from the same devices, for utilisation and capacity.
- An account with read access to **Explore**. Every flow query is scoped to your tenant before it runs.
- A window chosen in the top-bar range picker. Only the tab on screen refreshes, every 30 seconds, and nothing refreshes while the browser tab is hidden.

## Right now

The default tab leads with four figures: inbound and outbound traffic now (from
the interface counters), the busiest link by utilisation, and the volume seen in
flow records in the window.

**Busiest links** lists one row per link:

| Column | What it means |
|---|---|
| **Link** | The device's name and the interface's own name, with the link speed under it when the device reports one. |
| **In**, **Out** | Flow volume that entered and left on that interface in the window. |
| **Utilisation** | The busier direction now, in percent of the link speed. A dash means the interface reports no speed. |
| **Change** | Against the previous window of the same length. **New** means nothing was seen before; a dash means it is not known. |
| **Trend** | In plus out over the window, from the interface counters. |

Select a row to open the link: traffic in and out over time, its top talkers,
the services on it (by port), the problems in the window that name the
device, and **What changed** — the talkers, services or applications that moved
most on this link against the window before. **Who is talking here** opens the next tab already filtered to the link.

## Who is talking

Conversations, applications, services, services and ports, and protocols, under
one filter bar. Pick a device and an interface by name, then add an address or
network (`10.1.0.0/16`), a port, a protocol, an application name, the flow
source, or fold both directions of a conversation into one row. Each filter is a
chip you remove on its own.

**Applications** and **Services** answer over the window only: the device,
interface, address, port and protocol filters do not narrow them, and the page
says so. The **Application** chip narrows those two lists by name.

**Countries** and **Networks** appear only once their datasets are loaded (see
**About this data**).

## Capacity

Per-link headroom over the window, read from the interface counters (exact,
and kept 30 days), not from flow records. For each link, grouped by site or by
device:

| Column | What it means |
|---|---|
| **Speed** | The link speed the device reports. |
| **95th percentile** | The busier direction's rate with the busiest 5 % of five-minute samples set aside, so one burst does not read as a full link. |
| **Peak** | The highest five-minute rate. |
| **Headroom** | The speed minus the 95th percentile. |
| **Reaches 90%** | When the link is on course to reach 90 %: a straight line through each complete day's 95th percentile. Given only with 14 days of history and a steady trend; otherwise it says why not. |

A link whose device reports no speed (or an implausible one) is still listed
with its throughput, but gets no percentage, headroom or forecast, and the page
says so. Select a row to open that link in **Right now**. The Overview page's
capacity outlook uses the same calculation, so the two always agree.

## About this data

The drawer states which flow sources are arriving, what the sampling sentence
says, how many records the window holds, whether Correlix's own polling traffic
is shown, and whether the country and network datasets are loaded, with the
script that loads each one.

Counts are scaled by a device's sampling rate when it reports one. A device
that samples without reporting its rate reads low; if you know its rate ("1 in
1000"), enter it under **Declared sampling** in this drawer (needs write access
to infrastructure, for a router your workspace owns). The link figures then
multiply only that router's records that carried no rate, and say "declared, not
reported" beside them. A rate the router reports always wins. Nothing else is
estimated.

A long flow is spread over the minutes it lasted, ending when Correlix received
it, so a router with a 30-minute active timeout no longer lands a half-hour of
traffic in one minute. A router that exports no flow duration (sFlow, NetFlow
v5) is placed in the minute it arrived. Windows are whole minutes.

Device health lives in **Analytics → Device Monitoring**, and TCP flags and scan
signals in **Security → Threat Detection**.

## From an RCA case

The **Traffic flow** lane of an RCA case's evidence timeline has a **See
flows** link. It opens Flows with the interface the flow evidence names
already selected and the case window shaded:

```text
#/explore/flows?device=<exporter address>&if=<interface index>&from=<start>&to=<end>
```

## Related

- [Send flow data](/send-data/flows) for configuring the exporters and the listener ports.
- [Attribute traffic to applications and services](/explore/application-attribution) for how applications and services are named.
- [Search logs](/explore/logs) for individual flow records.
