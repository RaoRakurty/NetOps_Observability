---
title: WAN Interface Metrics
sidebar_label: WAN Interface Metrics
sidebar_position: 4
description: Per-WAN-interface SLA (latency/jitter/loss/QoE/availability) with a live throughput sparkline.
---

# WAN Interface Metrics

**WAN Interface Metrics** gives every WAN interface its own SLA and a live throughput graph — utilization and status, plus latency, jitter, loss, QoE, and availability measured to a target. Open it at <kbd>Infrastructure → WAN Interface Metrics</kbd>.

## What each row shows

- **Utilization, In/Out throughput, status** — live, from interface metrics.
- **A live sparkline** — a small in‑row graph of recent throughput that advances as it polls.
- **Measured to** — the target this interface's SLA is measured against, and how it was derived.
- **Latency / Jitter / Loss / QoE / Availability** — the resolved SLA (shows "—" until an active probe measures the target).
- **Measured by** — which measurement method produced the SLA.

## How the measurement target is chosen

Each interface is measured to a **derived target** (no manual pairing):

1. an **operator next‑hop** you configure (e.g. the ISP next‑hop), else
2. a **directly‑connected peer** (learned from LLDP/CDP), else
3. a **public‑DNS reachability anchor** (for internet‑facing interfaces).

Interfaces on WAN devices — **plus** any interface directly connected to one — are included, so a WAN router and the core/spine link to it are both measured.

## How the SLA is resolved

Correlix ranks measurement sources by **closeness to the user experience** (application‑level checks are trusted over device‑level probes) and uses the best available for each field. If no active probe is running yet, the SLA fields honestly show "—" while utilization and throughput still populate.

## Related

- **[Connectivity requirements](/reference/connectivity-requirements)**
- **[Tunnels](/infrastructure/overview)**
