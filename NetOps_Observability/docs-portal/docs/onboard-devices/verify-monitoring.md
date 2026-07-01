---
title: Verify a device is monitored
sidebar_label: Verify monitoring
sidebar_position: 7
description: Confirm a newly onboarded device is discovered, collecting, and rendering on its dashboards.
---

# Verify a device is monitored

After onboarding, confirm the device is fully working. Correlix gives you a clear, honest signal at each layer — an interface shows "—" when there's genuinely no data rather than a fabricated value.

## The four checks

1. **Known** — <kbd>Infrastructure → Devices</kbd> lists the device with an **up** status dot and discovered facts (vendor, model, uptime).
2. **Collecting** — <kbd>Administration → Data Collection → Data Sources</kbd> shows the device green for **SNMP metrics** (and any other planes you configured).
3. **Rendering** — <kbd>Infrastructure → Device Monitoring</kbd> fills CPU/memory/interface panels; <kbd>Interface Performance</kbd> shows per‑interface throughput and utilization.
4. **On the map** — the device appears on the **[Topology Canvas](/infrastructure/topology-canvas)** and, if it has a location, the **[Device Geomap](/infrastructure/geomap)**.

## Interpreting what you see

- **Status up, metrics flowing** → fully onboarded. ✅
- **Status up, but a panel shows "—"** → that specific metric isn't being collected yet (e.g. utilization needs interface speed; a plane like flows isn't configured). This is expected and honest, not an error.
- **Status down / no data** → reachability or credential issue — see [Troubleshooting](/reference/troubleshooting).

:::tip Live confirmation
On <kbd>Infrastructure → WAN Interface Metrics</kbd>, each interface shows a small **live throughput sparkline**. Generating traffic across a link makes its graph move — a quick way to prove telemetry is live end to end.
:::

## When it's green

Once a device is collecting, it's automatically eligible for **monitors**, **anomaly detection**, **topology**, and **root‑cause correlation** — no extra wiring. Continue to:

- **[Create a monitor](/monitoring/overview)**, or
- **[Onboard more devices](/onboard-devices/overview)**.
