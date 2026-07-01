---
title: Discover devices (SNMP)
sidebar_label: Discover devices
sidebar_position: 3
description: Point Correlix at your management subnets and let it find and inventory devices automatically over SNMP.
---

# Discover devices (SNMP)

Instead of adding devices one by one, you can have Correlix **scan your management subnets** and onboard everything it finds that answers SNMP. This is the fastest way to bring a fleet in.

## Prerequisites

- An **SNMP credential** that works across the range — add it first under [SNMP profiles & credentials](/onboard-devices/snmp-profiles).
- **Reachability** from Correlix to the target subnets on UDP 161.
- The **management subnet ranges** you want scanned (CIDR notation, e.g. `10.20.0.0/24`).

:::warning Scope the range deliberately
Discovery defaults to a broad range. Before pointing it at a real network, **narrow it to your actual management subnets** so you don't scan unintended hosts.
:::

## Run discovery

1. Go to <kbd>Infrastructure → Devices</kbd> and open **Discovery source** (the discovery configuration).
2. Enter the **CIDR range(s)** to scan (comma‑separate multiple ranges).
3. Ensure the **credential** to try is available (from the SNMP Profile Manager).
4. Start discovery.

Correlix walks the range, and for every host that answers SNMP with a valid credential it:

- creates a **device record**,
- reads **system identity** (vendor, model, OS version, hostname, uptime),
- enumerates **interfaces and IP addresses**, and
- begins **polling metrics** on the normal cycle.

Discovery is **idempotent** — re‑running it updates existing devices and adds new ones without creating duplicates.

## Watch devices arrive

- New devices appear in <kbd>Infrastructure → Devices</kbd> with an **up** status dot.
- The [Data Sources coverage matrix](/onboard-devices/data-sources) shows each one turning green for **SNMP metrics**.

## Neighbor‑based topology

As devices are polled, Correlix learns neighbor relationships (LLDP/CDP and routing adjacencies) and draws them on the **[Topology Canvas](/infrastructure/topology-canvas)** automatically — you don't wire the topology by hand.

## If a device doesn't appear

Common causes, in order:

1. **Not reachable** on UDP 161 from Correlix (firewall/ACL).
2. **Credential mismatch** — the community/user doesn't match, or the device is v3‑only.
3. **Outside the scanned CIDR** — widen or add the range.
4. **SNMP disabled** on the device.

See [Troubleshooting](/reference/troubleshooting) for how to confirm each.

## Next

- **[Add richer telemetry](/send-data/overview)** — syslog, traps, flows.
- **[Verify a device is monitored](/onboard-devices/verify-monitoring)**.
