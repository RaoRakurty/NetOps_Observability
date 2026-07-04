---
title: Getting Started overview
sidebar_label: Overview
sidebar_position: 1
description: What you need before you onboard your first device, and the shape of the onboarding journey.
---

# Getting Started

This section gets you from a running Correlix instance to your **first device reporting data**. If you just want the fastest path, jump straight to the **[Quickstart](/getting-started/quickstart)** — it's a numbered, end-to-end procedure you can finish in about 15 minutes.

## How onboarding works (the big picture)

Correlix monitors your network **agentlessly first** — it talks to your devices over standard protocols (SNMP, ICMP, streaming telemetry) and receives telemetry that devices push (syslog, SNMP traps, flow records). You don't install software on your routers, switches, or firewalls.

The journey is always the same four moves, whatever the size of your fleet:

1. **Discover or add** your devices, so Correlix knows what exists — [Onboard Network Devices](/onboard-devices/overview).
2. **Give it credentials** (SNMP v2c community strings or SNMPv3 users) so it can read them — [SNMP profiles & credentials](/onboard-devices/snmp-profiles).
3. **Point pushed telemetry at it** — syslog, traps, and flows that devices send — [Send data](/send-data/overview).
4. **Verify** each device is green on the coverage matrix and its dashboards fill in — [Verify monitoring](/onboard-devices/verify-monitoring).

Everything downstream — dashboards, monitors, anomaly detection, topology, and root-cause correlation — happens automatically on the data you've onboarded. There is no separate "enable analytics" step.

## Before you begin

Have the following ready before you start the Quickstart. Missing one of these is the cause of nearly every stalled onboarding.

| Requirement | Why you need it |
| --- | --- |
| **A Correlix account with admin access** | Adding credentials, devices, and data sources are administrative actions. |
| **Your Correlix URL** | The web console — by default it's served on TCP port **8000** of the host it's installed on (your deployment may differ). |
| **Network reachability** from Correlix to your devices' management IPs | SNMP polling (UDP 161) and ICMP are how Correlix reads devices. |
| **SNMP enabled on the devices** — v2c community *or* SNMPv3 user | Interface, device, and protocol metrics all come from SNMP first. |
| **The credential values** — community string, or SNMPv3 username + auth/priv protocols and passphrases | You'll enter these once, into the SNMP Profile Manager; they're stored encrypted. |
| **Firewall/ACL openings** on the path between devices and Correlix | UDP 161 outbound to devices; UDP 514 (syslog), UDP 162 (traps), and UDP 2055/4739/6343 (flows) inbound. The full list is in [Connectivity requirements](/reference/connectivity-requirements). |

:::info Read-only by default
SNMP monitoring is **read-only** — Correlix polls counters and state; it never changes device configuration. Use a read-only community or user, and prefer SNMPv3 with authPriv where your platform supports it.
:::

## Signing in

Open your Correlix URL in a modern browser and sign in. Depending on how your administrator configured [authentication](/administration/authentication), the sign-in screen offers a **Local account** and, if enabled, directory sign-in (LDAP or TACACS+) and single sign-on buttons. Accounts with MFA enabled are asked for a 6-digit authenticator code after the password. If sign-in fails, see [Troubleshooting → Can't sign in](/reference/troubleshooting).

Once signed in, the left **icon rail** is your main navigation. It's organized into zones:

- **Monitor** — Dashboards, Monitoring, Incident Response, Automation.
- **Infrastructure** — the device fleet: Devices, monitoring dashboards, maps, paths, and tunnels — plus Security.
- **Data** — the raw telemetry planes: Metrics, Flows, Logs.
- **Iris AI** and **Administration** are pinned at the bottom.

Hovering an icon opens a flyout listing that section's pages. You can also press <kbd>Ctrl+K</kbd> (or <kbd>⌘K</kbd>) and type a page name to jump anywhere.

Most onboarding work happens in exactly two places, so learn these first:

- <kbd>Administration → Data Collection</kbd> — SNMP credentials and the **Data Sources** coverage matrix.
- <kbd>Infrastructure → Devices</kbd> — the fleet inventory, where devices are added and their live status shows.

## What "onboarded" looks like

You'll know a device is fully onboarded when:

1. It appears in <kbd>Infrastructure → Devices</kbd> with a **green (Up)** status dot and discovered facts (vendor, model, uptime).
2. Its row in <kbd>Administration → Data Collection → Data Sources</kbd> shows **SNMP metrics** receiving — plus Syslog, Traps, and Flows if you've configured those planes.
3. Its dashboards render real numbers under <kbd>Infrastructure → Device Monitoring</kbd> and <kbd>Infrastructure → Interface Performance</kbd>.

The more telemetry planes a device reports on, the stronger Correlix's root-cause correlation becomes — see [Key concepts](/getting-started/concepts) for why.

## The journey map

| Stage | Where | Doc |
| --- | --- | --- |
| 1. Add a credential | <kbd>Administration → Data Collection → SNMP Profile Manager</kbd> | [SNMP profiles & credentials](/onboard-devices/snmp-profiles) |
| 2. Add or discover devices | <kbd>Infrastructure → Devices</kbd> | [Add manually](/onboard-devices/add-devices-manually) · [Discover](/onboard-devices/snmp-discovery) |
| 3. Confirm collection | <kbd>Administration → Data Collection → Data Sources</kbd> | [Data Sources & coverage](/onboard-devices/data-sources) |
| 4. Send pushed telemetry | Device CLI → Correlix | [Syslog](/send-data/syslog) · [Traps](/send-data/traps) · [Flows](/send-data/flows) |
| 5. Watch it render | <kbd>Infrastructure → Device Monitoring</kbd> | [Verify monitoring](/onboard-devices/verify-monitoring) |
| 6. Get alerted | <kbd>Monitoring → Create Monitor</kbd> | [Create a monitor](/monitoring/create-a-monitor) |

## Next steps

- **[Quickstart](/getting-started/quickstart)** — onboard one device end to end, with a checkpoint after every step.
- **[Key concepts](/getting-started/concepts)** — the vocabulary and mental model (devices, planes, monitors, incidents, evidence, tenants).
- **[Connectivity requirements](/reference/connectivity-requirements)** — the authoritative port table to hand to your firewall team.
