---
title: Verify a device is monitored
sidebar_label: Verify monitoring
sidebar_position: 7
description: Confirm a newly onboarded device is discovered, collecting, and rendering on its dashboards — and what to do when nothing arrives.
---

# Verify a device is monitored

After onboarding, prove the device is fully working — **done means rendered**. Correlix gives you an honest signal at each layer: a panel shows "—" when there's genuinely no data, never a fabricated value, so every check below is trustworthy.

## The verification checklist

Run these in order; each step depends on the one before it.

### 1. Known — the device is in the inventory

1. Go to <kbd>Infrastructure → Devices</kbd>.
2. Find the device (use the filter box). Confirm:
   - the status dot is **Up** (green) — a fresh heartbeat within ~5 minutes;
   - **Manufacturer** and **Type** are filled in (identified from SNMP, not typed by you);
   - the **Polled** column shows a recent time.

**Degraded** (amber) means the heartbeat is stale or the device has active alerts; **Down** (red) means no heartbeat for 15+ minutes — go to the flowchart below.

### 2. Collecting — planes are green

1. Go to <kbd>Administration → Data Collection → Data Sources</kbd>.
2. Find the device's row. **SNMP metrics** should be green; **Syslog**, **Traps**, and **Flows** should be green for whichever planes you configured. (Details of every column: [Data Sources & coverage](/onboard-devices/data-sources).)

### 3. Rendering — dashboards fill in

1. Open <kbd>Infrastructure → Device Monitoring</kbd> and select the device. CPU, memory, and interface panels should populate within a couple of poll cycles.
2. Open <kbd>Infrastructure → Interface Performance</kbd> — per-interface throughput, utilization, and error/discard graphs.
3. For logs: open <kbd>Logs → Log Search</kbd> and filter on the device's name — its syslog messages should appear as they're emitted.
4. For traffic: open the **Flows** section — the device should appear among the exporters, with top talkers building up.

:::tip Live end-to-end proof
On <kbd>Infrastructure → WAN Interface Metrics</kbd>, each interface shows a small **live throughput sparkline**. Generate some traffic across a link and watch its graph move — the quickest way to prove the whole telemetry path is live.
:::

### 4. On the map

- The device appears on the **[Topology Canvas](/infrastructure/topology-canvas)**, with links drawn as neighbors are learned (this can take a few polling cycles after onboarding).
- If you assigned it to a site, it appears on the **[Device Geomap](/infrastructure/geomap)**.

## Interpreting what you see

| Observation | Meaning |
| --- | --- |
| Status **Up**, panels filling | Fully onboarded ✅ |
| Status **Up**, one panel shows "—" | That *specific* metric isn't collected — e.g. utilization needs the interface speed value, a vendor CPU metric needs the vendor profile, or a plane (flows) isn't configured. Honest, not an error. |
| Status **Degraded** | Reachable recently but stale or alerting — check the device's active alerts and reachability. |
| Status **Down** / everything empty | Reachability or credential problem — flowchart below. |

## "Nothing is arriving" — the troubleshooting flowchart

Work top-down; stop at the first test that fails and fix it before moving on.

1. **Is the device in the inventory at all?**
   → *No:* it was never added, or discovery didn't find it — see [Discover devices](/onboard-devices/snmp-discovery) troubleshooting.
   → *Yes:* continue.

2. **Is the status dot Down?**
   → *Yes:* Correlix can't complete SNMP polls.
      1. Confirm basic reachability from a host near Correlix: `ping DEVICE_IP`.
      2. Confirm SNMP answers with your credential (generic example using standard SNMP tools):
         ```bash
         snmpwalk -v2c -c MyR0Community -t 2 DEVICE_IP 1.3.6.1.2.1.1
         ```
         Timeout → UDP 161 blocked, SNMP disabled, or an SNMP ACL excludes Correlix's address. Answer here but Down in Correlix → the **stored** credential differs (wrong version, rotated secret) — re-save it in the [SNMP Profile Manager](/onboard-devices/snmp-profiles).
   → *No (Up/Degraded):* continue.

3. **Is "SNMP metrics" green on Data Sources?**
   → *No:* the device answers identity queries but metric polling fails — usually a v3 auth/privacy protocol mismatch or a too-tight timeout for a WAN device. Check the credential profile's protocols against the device config; raise Timeout/Retries.
   → *Yes:* continue.

4. **Metrics green but no syslog?**
   1. Confirm the device is configured to log to Correlix on UDP/TCP **514** ([Syslog](/send-data/syslog)).
   2. Confirm the device's configured **hostname matches its inventory name** — log attribution is by the hostname carried in the message.
   3. Remember quiet devices legitimately show "—": trigger a harmless event (e.g. log in to the device) and watch <kbd>Logs → Log Search</kbd>.

5. **Metrics green but no flows?**
   1. Confirm export is configured to the right port: NetFlow **2055**, IPFIX **4739**, sFlow **6343** ([Flows](/send-data/flows)).
   2. Confirm the device exports **from the address the inventory knows** — flow attribution is by exporter address.
   3. Flow records batch on the device; allow a few minutes of real traffic before judging.

6. **Metrics green but no traps?**
   1. Trap ingestion must be enabled for your instance ([SNMP traps](/send-data/traps)).
   2. Confirm the device's trap destination is Correlix on UDP **162**, and send a test trap if the platform supports it.

7. **Everything green but a dashboard panel is empty?**
   → The metric behind that panel isn't in the device's profile — extend the [vendor profile](/onboard-devices/snmp-profiles) with the missing value.

Full port matrix: [Connectivity requirements](/reference/connectivity-requirements). Deeper platform diagnostics: [Troubleshooting](/reference/troubleshooting).

## When it's green

A collecting device is automatically eligible for **monitors**, **anomaly detection**, **topology**, and **root-cause correlation** — no extra wiring. Continue to:

- **[Create a monitor](/monitoring/create-a-monitor)**, or
- **[Onboard more devices](/onboard-devices/overview)**.
