---
title: Onboard Network Devices
sidebar_label: Overview
sidebar_position: 1
description: The complete reference for getting your devices into Correlix — discovery, manual add, credentials, streaming telemetry, and verification.
---

# Onboard Network Devices

This section is the complete reference for getting devices into Correlix. Where the [Quickstart](/getting-started/quickstart) walked one device end to end, here each method is documented on its own so you can onboard a whole fleet.

## Choose how to add devices

Correlix supports several ways to get devices in — you can mix them.

| Method | Best for | Page |
| --- | --- | --- |
| **SNMP discovery** | Finding many devices on known subnets automatically | [Discover devices](/onboard-devices/snmp-discovery) |
| **Add device manually** | A handful of devices, or ones outside a scanned range | [Add devices manually](/onboard-devices/add-devices-manually) |
| **Import / Source of Truth** | You already have an inventory (CSV/JSON/NetBox) | [Source of Truth](/automation/overview) |

Whichever you use, every device needs a **credential** to be read.

## The onboarding checklist

For each device, you're aiming for four green checks:

1. ✅ **Known** — the device exists in <kbd>Infrastructure → Devices</kbd>.
2. ✅ **Credentialed** — a working SNMP v2c/v3 credential is attached ([SNMP profiles & credentials](/onboard-devices/snmp-profiles)).
3. ✅ **Collecting** — the device is green on the [Data Sources coverage matrix](/onboard-devices/data-sources).
4. ✅ **Rendering** — its dashboards fill in ([Verify a device is monitored](/onboard-devices/verify-monitoring)).

## Add richer telemetry (optional but recommended)

SNMP polling gets you metrics and inventory. To unlock events, traffic analysis, and stronger root‑cause correlation, also point these planes at Correlix:

- **[Syslog](/send-data/syslog)** — device log messages → events and correlation signals.
- **[SNMP traps](/send-data/traps)** — asynchronous device notifications.
- **[Flow records](/send-data/flows)** — NetFlow/sFlow/IPFIX → traffic and top‑talker analytics.
- **[Streaming telemetry (gNMI)](/onboard-devices/streaming-gnmi)** — high‑resolution model‑driven metrics on platforms that support it.

## Order of operations

The recommended sequence for a new deployment:

1. Create your **[SNMP credentials](/onboard-devices/snmp-profiles)** first.
2. **[Discover](/onboard-devices/snmp-discovery)** or **[add](/onboard-devices/add-devices-manually)** devices.
3. Configure devices to **push [syslog](/send-data/syslog), [traps](/send-data/traps), and [flows](/send-data/flows)** to Correlix.
4. **[Verify](/onboard-devices/verify-monitoring)** coverage, then move on to [monitors](/monitoring/overview) and [dashboards](/dashboards-reports/overview).

Start with **[SNMP profiles & credentials](/onboard-devices/snmp-profiles)**.
