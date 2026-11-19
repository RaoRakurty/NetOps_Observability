---
title: Investigations
description: The read-only Investigator, investigations that start on their own, active probes, and what Iris reads from a device.
page_type: concept
sidebar_position: 6
---

# Investigations

An investigation goes further than a single answer: Iris works through the
problem in steps, shows each step, and stops inside fixed limits. Everything it
reads goes through the same permissions and tenant boundary as any other answer.

## Before you begin

- **AI investigations** on under **Platform → Configuration → Features**, and
  **Investigations** ticked for your workspace. See [Set up Iris](/iris-ai/setup).
- Investigations need the Iris AI add-on.

## Investigate this

Under a troubleshooting answer, select **Investigate this fully**, or ask
`investigate edge-1`. The Investigator:

1. **Fixes the subject** — the device or incident, checked against what you may
   see.
2. **Reads the correlation engine's verdict first** when an incident is in
   scope. Iris never overrides it.
3. **Uses your own runbooks first** — the approved runbooks linked to that
   incident or device — then the method the question fits.
4. **Runs bounded passes**, repeating only while nothing is yet supported, and
   stops at its limits on passes, lookups, AI tokens and time. Every cut is
   shown.
5. **Writes a diagnosis** with the steps it took.

## Investigations that start on their own

A workspace administrator can arm an investigation in the Iris panel settings
(**AI models** → **Iris vocabulary**, step **8. Investigations on their own**):

- **On a new incident** that matches a severity, text, site or device role, or
- **On a schedule**, every 15 minutes to once a day.

Each run is read-only, runs in that workspace only, never sends active probes,
and stays within the daily run and AI-token limits you set. It runs once per
incident or schedule slot, adds a note to the incident and posts a notice to
your Slack channel (never a page). A run that is skipped says why. This is off
until the workspace turns it on.

## Active probes

With **Iris active probes** on (Features page) and **Active probes** ticked for
the workspace, a method can take one small measurement now — 3 pings, one
traceroute, one DNS lookup or one web request — from the Correlix server toward
one of your own devices or a probe declared on the Digital Experience page.

Safety rules:

- Sent from Correlix's own server, never from a customer device or a third-party
  service.
- Only as a written step of a troubleshooting method. The AI model cannot ask
  for one.
- Loopback, link-local, multicast and cloud-metadata addresses are always
  refused; internal addresses only when they belong to your own device. How
  often one target is probed is capped.
- Results name the target by the name you gave it, and a traceroute shows where
  replies stop, not the addresses of the routers in between.

## What Iris reads from a device

When device access is configured, Iris reads a device live with read-only show
commands, by area:

| Area | What it reads |
|---|---|
| interfaces | state, errors and drops, optics |
| igp | OSPF and IS-IS adjacencies |
| bgp | the BGP neighbour summary |
| routes | a lookup for one prefix |
| l2 | ARP and MAC for an address |
| platform | CPU, memory, environment, uptime and reload reason, clock synchronisation |
| evpn | VXLAN tunnel endpoints and VNIs |
| redundancy | HSRP/VRRP groups and LACP bundles |
| vpn | IPsec security associations per peer — whether each direction is active and the packets and errors carried each way — and IKE phase 1 |
| upgrade | boot variables, free space, control-processor redundancy, routing-table size |
| logs | the device's recent log buffer (bounded) |

Where Correlix has a parser for the platform, the output becomes typed facts
(for example, an IPsec flow that sends but never receives is flagged as
one-way). Where it does not, Iris shows the raw output and says it was not
parsed.

## Related

- [Investigate an incident with Iris](/iris-ai/ask-iris)
- [Runbooks and MOPs](/administration/iris-runbooks)
- [Approve Iris actions](/administration/iris-actions)
