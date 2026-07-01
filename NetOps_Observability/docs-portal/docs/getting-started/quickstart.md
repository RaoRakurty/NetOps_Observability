---
title: Quickstart — onboard your first device
sidebar_label: Quickstart
sidebar_position: 2
description: Add one device, give Correlix its SNMP credentials, and watch it start reporting — in about 15 minutes.
---

# Quickstart: onboard your first device

In about 15 minutes you'll have one device discovered, credentialed, and showing live metrics. We'll onboard a single switch or router over SNMP — the most common starting point.

## Step 1 — Add an SNMP credential

Correlix needs a credential to read your device.

1. Go to <kbd>Administration → Data Collection → SNMP Profile Manager</kbd>.
2. Open the **Credentials** tab (*"Per‑device community / SNMPv3 USM secrets"*).
3. Add a credential:
   - For **SNMP v2c**: enter the **community string** (e.g. your read‑only community).
   - For **SNMP v3**: enter the **username** and the **auth** (SHA/MD5) and **privacy** (AES/DES) protocols and passphrases.
4. Save. Secrets are stored encrypted and are never shown again.

:::tip
Start with a read‑only community/user. You can scope credentials per device or apply a default — see [SNMP profiles & credentials](/onboard-devices/snmp-profiles).
:::

## Step 2 — Add the device

1. Go to <kbd>Infrastructure → Devices</kbd>.
2. Click **Add device**.
3. Fill in:
   - **Name** — a friendly name (e.g. `leaf1`).
   - **IP or hostname** — the device's management address.
   - Optional fields (site, vendor hint) can be left blank; Correlix fills them in from SNMP.
4. Save.

Correlix immediately begins polling the device with the credential from Step 1.

:::note Prefer auto‑discovery?
If SNMP discovery is enabled for your instance, you can point Correlix at a subnet range and it will find devices for you instead of adding them one by one. See [Discover devices](/onboard-devices/snmp-discovery).
:::

## Step 3 — Confirm it's being collected

1. Go to <kbd>Administration → Data Collection → Data Sources</kbd>.
2. Find your device in the **coverage matrix**. Within a poll cycle (about a minute) the **SNMP metrics** column should turn green ("collecting"), not "No data".

The coverage matrix is your onboarding checklist — one row per device, one column per data source (SNMP metrics, Flows, Syslog, Traps).

## Step 4 — See the data

1. Go to <kbd>Infrastructure → Devices</kbd> — your device should show an **up** status dot and basic facts (vendor, model, uptime) discovered over SNMP.
2. Open <kbd>Infrastructure → Device Monitoring</kbd> and select the device — CPU, memory, and interface panels fill in as metrics arrive.
3. Open <kbd>Infrastructure → Interface Performance</kbd> to see per‑interface throughput and utilization.

:::tip Watch it live
Utilization and throughput update every SNMP poll (about once a minute). On the **[WAN Interface Metrics](/infrastructure/wan-interface-metrics)** page each interface even shows a small live throughput sparkline.
:::

## What just happened

You gave Correlix a credential and a device. From there it automatically:

- polled the device and **built its inventory record** (vendor, model, interfaces),
- started **time‑series metrics** (CPU/memory/interfaces),
- placed it on the **topology** as neighbors are learned, and
- made it eligible for **monitors, anomaly detection, and correlation**.

## Next steps

- **[Send syslog](/send-data/syslog)** and **[flow records](/send-data/flows)** so events and traffic are captured too.
- **[Create your first monitor](/monitoring/create-a-monitor)** to get alerted when something changes.
- **[Onboard the rest of your fleet](/onboard-devices/overview)** with discovery and credential profiles.
