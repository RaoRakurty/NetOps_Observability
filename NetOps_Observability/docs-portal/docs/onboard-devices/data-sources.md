---
title: Data Sources & coverage
sidebar_label: Data Sources & coverage
sidebar_position: 5
description: Use the Data Sources coverage matrix to see, per device, which telemetry planes are being collected.
---

# Data Sources & coverage

The **Data Sources** page is your onboarding scoreboard. It shows, for every device, which telemetry planes are actually being collected — so you can tell at a glance what's fully onboarded and what still needs attention.

Open it at <kbd>Administration → Data Collection → Data Sources</kbd>.

## The coverage matrix

One row per **device**, one column per **data source**:

| Column | Fed by | How to turn it green |
| --- | --- | --- |
| **SNMP metrics** | SNMP polling | Add a [credential](/onboard-devices/snmp-profiles) + the device |
| **Flows** | NetFlow/sFlow/IPFIX exporters | [Configure flow export](/send-data/flows) to Correlix |
| **Syslog** | Device syslog | [Point syslog](/send-data/syslog) at Correlix |
| **Traps** | SNMP traps | [Point traps](/send-data/traps) at Correlix |

Each cell shows whether that source is **collecting** or shows **No data**. The page also summarizes **collection coverage** across the fleet.

## How to read it

- A device that's green only on **SNMP metrics** is *monitored* — you'll get health, interfaces, and protocol metrics.
- Add **Syslog**, **Traps**, and **Flows** to unlock events, notifications on device‑reported conditions, traffic analytics, and — importantly — **stronger root‑cause correlation** (more independent planes = higher‑confidence verdicts).

:::tip Aim for multi‑plane coverage on your critical devices
Correlation is most confident when a fault shows up in more than one plane (e.g. a syslog event *and* a metric anomaly *and* a trap). Prioritize getting syslog + traps flowing from your core and edge devices.
:::

## Using it during onboarding

1. Onboard devices (discovery or manual).
2. Open Data Sources and confirm **SNMP metrics** is green everywhere.
3. Configure devices to push **syslog, traps, and flows**, then watch those columns fill in.
4. Anything stuck on **No data** → [Troubleshooting](/reference/troubleshooting).

## Next

- **[Send data](/send-data/overview)** — the per‑plane setup guides.
- **[Verify a device is monitored](/onboard-devices/verify-monitoring)**.
