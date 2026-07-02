---
title: Quickstart — onboard your first device
sidebar_label: Quickstart
sidebar_position: 2
description: Add one device, give Correlix its SNMP credentials, and watch it start reporting — in about 15 minutes.
---

# Quickstart: onboard your first device

In about 15 minutes you'll sign in, store an SNMP credential, add one switch or router, watch it turn green, and see live metrics on a dashboard. Every step ends with a **checkpoint** so you always know whether to continue or fix something first.

**Before you start**, have ready: your Correlix URL, an admin account, a device management IP that Correlix can reach on UDP 161, and that device's read-only SNMP credential. (Full prerequisites: [Getting Started overview](/getting-started/overview).)

## Step 1 — Sign in

1. Open your Correlix URL in a browser (by default the console is on TCP port **8000** of the host it's installed on).
2. On the sign-in screen, pick your method — **Local account** is always available; LDAP, TACACS+, or single sign-on appear if your administrator enabled them.
3. Enter your username and password. If your account has MFA enabled, enter the 6-digit code from your authenticator app when prompted.

**Checkpoint:** you land on **Home** (the Command Center) with the left icon rail visible. If sign-in fails or your account reports as temporarily locked, see [Troubleshooting → Can't sign in](/reference/troubleshooting).

## Step 2 — Add an SNMP credential

Correlix needs a credential before it can read anything from the device.

1. Go to <kbd>Administration → Data Collection → SNMP Profile Manager</kbd>.
2. Open the **Credentials** tab (*"Per-device community / SNMPv3 USM secrets"*).
3. Add a credential:
   - **SNMP v2c** — enter your **read-only community string**.
   - **SNMP v3** — enter the **username**, the **auth** protocol (SHA/MD5) and passphrase, and the **privacy** protocol (AES/DES) and passphrase. authPriv is recommended.
4. Save.

**Checkpoint:** the credential appears in the list with its secret masked (`••••••`). Secrets are encrypted at rest and never shown again — saving later with the field blank keeps the stored value. Details and default-vs-per-device scoping: [SNMP profiles & credentials](/onboard-devices/snmp-profiles).

:::tip You don't need to touch the Profiles tab
The **Profiles** tab is the vendor OID & metric library. Built-in profiles cover common vendors, so a standard onboarding needs only a credential.
:::

## Step 3 — Add the device

1. Go to <kbd>Infrastructure → Devices</kbd>.
2. Click **+ Add device**.
3. Fill in:
   - **Name** — a friendly identifier (e.g. `leaf1`).
   - **IP or hostname** — the device's management address.
   - Optional fields (site, vendor) can stay blank — Correlix fills them from SNMP.
4. Save. Correlix begins polling immediately with the matching credential from Step 2.

**Checkpoint:** the device appears as a new row in the Devices table.

:::note Onboarding a whole subnet instead?
If SNMP discovery is enabled for your instance, Correlix can scan your management ranges and onboard everything that answers SNMP — see [Discover devices](/onboard-devices/snmp-discovery). This quickstart continues with the single device.
:::

## Step 4 — Watch it go green

Two places confirm collection is actually happening:

1. Stay on <kbd>Infrastructure → Devices</kbd>. Within a poll cycle (about a minute) the device's **status dot turns green (Up)** and its row fills with facts read over SNMP — vendor, model, uptime.
2. Go to <kbd>Administration → Data Collection → Data Sources</kbd>. Find the device's row in the **coverage matrix** — one row per device, one column per data source (SNMP metrics, Flows, Syslog, Traps). The **SNMP metrics** cell should show **receiving**, not "no data".

**Checkpoint:** green status dot on Devices *and* a green SNMP metrics cell on Data Sources. If the dot stays red/amber or the cell stays "no data" after a couple of minutes, it's almost always reachability or a credential mismatch — work through [Troubleshooting → Device stays Down](/reference/troubleshooting).

The status dot is honest about freshness: **Up** means a heartbeat within the last 5 minutes, **Degraded** means it's getting stale (or the device has active alerts), **Down** means nothing heard for over 15 minutes.

## Step 5 — Open a dashboard

1. Go to <kbd>Infrastructure → Device Monitoring</kbd> and select your device.
2. Watch the **CPU, memory, and interface panels** fill in as polls arrive. A panel showing "—" simply means that metric isn't collected yet — honest, not broken.
3. Open <kbd>Infrastructure → Interface Performance</kbd> for per-interface throughput, utilization, and errors across the fleet.

**Checkpoint:** real numbers and charts for your device. Utilization updates every poll (about once a minute); on <kbd>Infrastructure → WAN Interface Metrics</kbd> each interface shows a live throughput sparkline — push traffic across a link and watch it move.

## Step 6 (optional) — Point syslog at Correlix

Metrics tell you *how the device is doing*; syslog tells you *what the device says happened*. It's the highest-value plane to add next.

1. On the device, set the syslog destination to your Correlix address, UDP port **514**, severity `informational` and above. Vendor CLI examples: [Send syslog](/send-data/syslog).
2. Trigger a loggable event (e.g. bounce a lab interface or exit configuration mode).
3. Verify in Correlix:
   - <kbd>Administration → Data Collection → Data Sources</kbd> — the device's **Syslog** column turns green.
   - <kbd>Logs → Log Search</kbd> — search for the device name; recent messages appear.

**Checkpoint:** the device's own log messages are visible in Log Search and count as events on <kbd>Monitoring → Events</kbd>.

## What just happened

You gave Correlix a credential and one address. From there it automatically:

- **built the inventory record** (vendor, model, interfaces, IPs) over SNMP,
- started **time-series metrics** for CPU, memory, and every interface,
- began learning **neighbors** to place the device on the [Topology Canvas](/infrastructure/topology-canvas), and
- made the device eligible for **monitors, anomaly detection, and root-cause correlation** — no extra wiring.

## Next steps

- **[Send flow records](/send-data/flows)** and **[SNMP traps](/send-data/traps)** — each extra plane raises correlation confidence.
- **[Create your first monitor](/monitoring/create-a-monitor)** — get alerted when something you care about changes.
- **[Onboard the rest of the fleet](/onboard-devices/overview)** — discovery, bulk import, and credential scoping.
- **[Verify a device is monitored](/onboard-devices/verify-monitoring)** — the four-layer verification checklist.
