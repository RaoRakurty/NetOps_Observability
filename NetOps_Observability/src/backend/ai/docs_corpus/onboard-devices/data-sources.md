---
title: Data Sources & coverage
sidebar_label: Data Sources & coverage
sidebar_position: 5
description: Use the Data Sources coverage matrix to see, per device, which telemetry planes are actually delivering data right now.
---

# Data Sources & coverage

The **Data Sources** page is your onboarding scoreboard. It shows, for every device, which of the four agentless telemetry planes are **actually delivering data right now** — not what's configured, but what's arriving. That makes it the fastest way to see what's fully onboarded and exactly what's still missing.

Open it at <kbd>Administration → Data Collection → Data Sources</kbd>.

## What the page shows

**Header stats** summarize the fleet: total devices, how many are delivering SNMP metrics, flows, and syslog, and how many are delivering **nothing** ("No data" — your worklist).

Below is the **coverage matrix** — one row per device, one column per plane:

| Column | What turns it on | Judged by |
| --- | --- | --- |
| **Device / Address** | — | The inventory record |
| **SNMP metrics** | A working [credential](/onboard-devices/snmp-profiles) + reachability on UDP 161 | Fresh device metrics received within the last **15 minutes** |
| **Flows** | The device [exporting NetFlow/IPFIX/sFlow](/send-data/flows) to Correlix | The device's address seen as a flow **exporter** in the last 15 minutes |
| **Syslog** | The device [sending syslog](/send-data/syslog) to Correlix | The device's name or address seen on recent log messages |
| **Traps** | The device [sending SNMP traps](/send-data/traps) (and the trap receiver enabled for your instance) | The device's name or address seen on recent traps |
| **Coverage** | — | A badge counting planes delivering: `0/4` red, `1–2/4` amber, `3–4/4` green |

Each cell is a simple dot: green **yes** (receiving) or **—** (no data in the window). The page refreshes about every 30 seconds, so you can watch coverage turn green live as you configure each source.

:::info The matrix reads reality, not configuration
Cells are computed from data actually stored in the last 15 minutes. There are no toggles here — you turn a plane on **at the device** (pointing its syslog/flow/trap export at Correlix) and, for SNMP, by storing a credential. A cell going green is proof the whole path works end to end. A quiet device (e.g. one that simply logged nothing in 15 minutes) can legitimately show "—" for syslog.
:::

## How to read a row

- **SNMP only (1/4)** — the device is *monitored*: health, interfaces, CPU/memory, protocol state. A fine baseline.
- **SNMP + Syslog (2/4)** — you also get events the moment they happen: link down, adjacency changes, hardware alarms.
- **3–4 of 4** — full multi-plane coverage. This is the goal for core and edge devices: root-cause correlation is most confident when a fault is visible in more than one independent plane.

## Using it during onboarding

1. Onboard devices ([discovery](/onboard-devices/snmp-discovery) or [manual](/onboard-devices/add-devices-manually)).
2. Open **Data Sources** and confirm **SNMP metrics** is green everywhere. Fix any red rows first — they're credential or reachability problems (see [Troubleshooting](/reference/troubleshooting)).
3. Configure devices to push **[syslog](/send-data/syslog)**, then **[flows](/send-data/flows)**, then **[traps](/send-data/traps)** — watching each column fill in as you go. Sort by the **Coverage** column (it defaults to worst-first) to keep the least-covered devices at the top of your worklist.
4. When your critical devices read `3/4` or `4/4`, run the final [verification checklist](/onboard-devices/verify-monitoring).

## Troubleshooting a stuck cell

| Cell stuck on "—" | First things to check |
| --- | --- |
| **SNMP metrics** | Credential correct and version matches? UDP 161 open from Correlix? See [SNMP profiles & credentials](/onboard-devices/snmp-profiles) |
| **Flows** | Is the device exporting **from an address that matches its inventory address**? Flow attribution is by exporter address — a device exporting from a different loopback won't match its row. Ports: NetFlow 2055 / IPFIX 4739 / sFlow 6343 |
| **Syslog** | Is the device's configured **hostname** the same as its name in the inventory? Attribution is by the hostname in the message (or source IP). Port 514 |
| **Traps** | Is trap ingestion enabled for your instance? Is the trap destination UDP 162 → Correlix configured on the device? |
| **Whole row** | Device down or unreachable — check its status at <kbd>Infrastructure → Devices</kbd> first |

For platform operators, <kbd>Administration → Data Collection → Collectors</kbd> shows the collection engines themselves (SNMP v2c/v3, streaming telemetry, trap receiver) with per-collector target counts, reachability, and poll timings — useful for separating "this device is broken" from "the collector is unhealthy".

## Next

- **[Send data](/send-data/overview)** — the per-plane device configuration guides.
- **[Verify a device is monitored](/onboard-devices/verify-monitoring)**.
