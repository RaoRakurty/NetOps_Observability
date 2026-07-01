---
title: Streaming telemetry (gNMI)
sidebar_label: Streaming telemetry (gNMI)
sidebar_position: 6
description: Add high-resolution, model-driven streaming telemetry on platforms that support gNMI, alongside SNMP.
---

# Streaming telemetry (gNMI)

On platforms that support it, **gNMI streaming telemetry** gives you higher‑resolution, model‑driven metrics than SNMP polling — the device *pushes* subscribed paths instead of being polled. Correlix normalizes gNMI into the same metric contract as SNMP, so dashboards and correlation treat both sources identically.

## When to use it

- **Data‑center fabrics** (e.g. modern NOS platforms) where sub‑minute resolution matters.
- Metrics SNMP exposes coarsely or not at all (some hardware/queue counters).

SNMP remains the baseline for inventory and liveness; gNMI augments it where available.

## Prerequisites

- The device supports **gNMI** and it is enabled with an account Correlix can use.
- **Reachability** to the device's gNMI port from Correlix.
- Streaming telemetry is **enabled for your instance** (a platform capability — ask your platform owner if you don't see it).

## What Correlix collects

Correlix subscribes to interface, device‑resource, and protocol‑state paths and maps them onto the canonical `device_*` metric names (same as SNMP: `device`, `vendor`, interface name). This means:

- gNMI and SNMP data appear on the **same dashboards**,
- correlation sees them as the **same signal contract**, and
- switching a device from SNMP to gNMI needs **no dashboard changes**.

## Verify

Once a device is streaming, its metrics on <kbd>Infrastructure → Device Monitoring</kbd> and <kbd>Interface Performance</kbd> update at the streaming cadence. Liveness continues to be tracked independently.

## Next

- **[Verify a device is monitored](/onboard-devices/verify-monitoring)**.
