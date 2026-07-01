---
title: Supported devices & vendors
sidebar_label: Supported devices
sidebar_position: 8
description: What Correlix can monitor out of the box, and how coverage extends to any SNMP-capable device.
---

# Supported devices & vendors

Correlix is **vendor‑neutral**. Because it builds on standard protocols, it monitors essentially any device that speaks SNMP, syslog, SNMP traps, or the common flow protocols — across enterprise, data‑center, and service‑provider networks.

## Out of the box

- **Routers, switches, firewalls, load balancers** from the common enterprise and data‑center vendors — recognized automatically, with built‑in metric profiles (interfaces, CPU/memory, environment, protocol state).
- **Streaming telemetry (gNMI)** on supported modern NOS platforms.
- **Flow exporters** — NetFlow v5/v9, IPFIX, and sFlow.
- **Syslog and SNMP traps** from any device (MIB‑driven trap decoding).

## Any SNMP device

Even if a device isn't specifically profiled, Correlix reads the **standard MIBs** (IF‑MIB, HOST‑RESOURCES, ENTITY‑MIB, etc.), so you still get interfaces, availability, and system facts. To pull a vendor‑specific metric, extend the **[vendor profile](/onboard-devices/snmp-profiles#vendor-profiles-oid--metric-library)**.

## Firewalls & application identity

For next‑gen firewalls, Correlix can also consume on‑box **application identification** (App‑ID style) from the device's logs to attribute traffic to real applications. See [Service View](/incidents/overview).

## Not sure if your device is covered?

Add it with a credential — if it answers SNMP, you'll get metrics. If a metric you expect is missing, it's almost always a profile extension away rather than an unsupported device.

## Next

- **[SNMP profiles & credentials](/onboard-devices/snmp-profiles)**
- **[Connectivity requirements](/reference/connectivity-requirements)**
