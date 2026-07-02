---
title: Add devices manually
sidebar_label: Add devices manually
sidebar_position: 4
description: Add individual devices by name and management address when discovery isn't the right fit.
---

# Add devices manually

Adding a device by hand takes about a minute: you give Correlix an identifier and a management address, and polling starts immediately with your stored [SNMP credential](/onboard-devices/snmp-profiles).

## When to prefer manual add over discovery

- **A handful of devices** — quicker than configuring a scan range.
- **Devices outside your scanned ranges** — a DMZ box, a branch router on an unusual subnet.
- **Networks where scanning is unwelcome** — strict change-control or IDS-sensitive environments; a manual add touches only the one address you typed.
- **Pre-staging** — you can add a device before it's reachable; it will show **Down** until SNMP answers, then fill in on its own.

For dozens of devices, use [SNMP discovery](/onboard-devices/snmp-discovery) instead; if you already keep an inventory elsewhere, seed it via [Source of Truth import](/automation/overview).

## Before you begin

- SNMP is enabled on the device with a read-only credential (see the device-side examples on [Discover devices](/onboard-devices/snmp-discovery)).
- The matching credential profile exists in the [SNMP Profile Manager](/onboard-devices/snmp-profiles).
- UDP 161 is open from Correlix to the device ([Connectivity requirements](/reference/connectivity-requirements)).

## Add a device

1. Go to <kbd>Infrastructure → Devices</kbd>.
2. Click **+ Add device**. A two-step wizard opens.
3. **Step 1 — Identity** (both fields required):

   | Field | Required | Notes |
   | --- | --- | --- |
   | **Device ID** | yes | The unique identifier Correlix refers to the device by, e.g. `leaf1`, `core-rtr-1`. Choose it to match the device's configured hostname — syslog and other pushed telemetry attribute by name. |
   | **Address** | yes | The device's management IP or resolvable hostname. Correlix polls this address. |

4. **Step 2 — Classification** (optional; you can change these later):

   | Field | Notes |
   | --- | --- |
   | **Display name** | A friendly label shown alongside the ID. Leave blank to skip. |
   | **Vendor** | A vendor hint. Leave blank — Correlix identifies the vendor automatically from the device's SNMP identity on the first poll. |

5. Click **Add device**.

Polling begins on the next cycle (about a minute) using the device's referenced credential profile, or the instance default community if none is set.

## What Correlix fills in for you

You provide an ID and an address; from SNMP, Correlix enriches the record with:

- **Manufacturer** and functional **Type** (Router / Switch / Firewall / Access point / Load balancer / …), inferred from the device's SNMP identity fingerprint;
- model / OS description and **uptime**;
- the **interface list** with speeds, status, and counters;
- **neighbor relationships**, which place the device on the [Topology Canvas](/infrastructure/topology-canvas).

## Reading the inventory table

The Devices page (titled **Inventory & Devices**) refreshes about every 30 seconds and shows, per device: status dot + ID, name, IP address, type, manufacturer, site, description, **Source** badge, and when it was last polled. The status dot is three-state:

| Status | Meaning |
| --- | --- |
| **Up** (green) | Fresh heartbeat within the last ~5 minutes, no active alerts |
| **Degraded** (amber) | Heartbeat is stale (older than ~5 minutes) **or** the device has active warning/critical alerts |
| **Down** (red) | No heartbeat for more than ~15 minutes |

From the same page you can:

- **Filter** by health chip (All / Up / Degraded / Down) or free text.
- Click a row to open the **device workspace** (overview, interfaces, routing).
- Assign the device to a **site** from the Site column — used for scoping and the [Device Geomap](/infrastructure/geomap). (Editable when Correlix's internal inventory is the site authority; read-only when an external system of record is.)
- **Delete** a device you added by mistake.

## Verify

1. Within a minute or two, the device's dot turns **Up** and the Manufacturer/Type columns fill in.
2. <kbd>Administration → Data Collection → Data Sources</kbd> shows the device green for **SNMP metrics**.
3. Open <kbd>Infrastructure → Device Monitoring</kbd> and select the device — CPU and interface panels start rendering.

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Stays **Down**, no facts filled in | Correlix can't reach UDP 161 at the address | Verify the address; check firewalls/ACLs on the path |
| Stays **Down**, reachable from elsewhere | Credential mismatch | Check the device's credential profile reference and the stored secrets |
| **Up** but vendor stayed "Unknown" | Identity not in the recognition table | Harmless; edit the record's vendor if desired — Universal metric profiles still apply |
| Syslog from this device isn't attributed | Device hostname doesn't match the Device ID/name | Align the configured hostname with the inventory name (see [Syslog](/send-data/syslog)) |

## Next

- Point the device's **[syslog](/send-data/syslog)**, **[traps](/send-data/traps)**, and **[flows](/send-data/flows)** at Correlix.
- **[Verify the device is monitored](/onboard-devices/verify-monitoring)**.
