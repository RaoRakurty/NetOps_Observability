---
title: Metrics
sidebar_label: Metrics
sidebar_position: 2
description: How Correlix collects device and interface metrics, and how to verify them in the Metrics Explorer.
---

# Metrics

Metrics are the numeric time series behind most of Correlix's dashboards, monitors, and anomaly detection. Unlike the push planes ([syslog](/send-data/syslog), [traps](/send-data/traps), [flows](/send-data/flows)), metrics are **pulled**: Correlix reaches out to your devices, so once a device is onboarded with working credentials there is usually **nothing to configure on the device**.

## How metrics arrive

There are two collection paths, and they land in the same metric names — dashboards and monitors don't care which one fed them:

| Path | How it works | Resolution | Setup |
| --- | --- | --- | --- |
| **SNMP polling** (default) | Correlix polls each device over UDP 161 | ~1 minute | [SNMP profiles & credentials](/onboard-devices/snmp-profiles) — automatic once onboarded |
| **Streaming telemetry (gNMI)** | The device streams updates over a gRPC session Correlix opens | Sub-minute | [Streaming telemetry](/onboard-devices/streaming-gnmi) — supported platforms only |

There is **no device-pushed metric ingest** (no agent to install, no metrics endpoint for devices to POST to). If a platform can't be polled and doesn't support gNMI, its numeric health lives in whatever it reports via [syslog](/send-data/syslog) and [traps](/send-data/traps).

Correlix also *generates* some metrics itself through **active measurement** — path probes that measure latency, jitter, and loss across circuits. Those are configured in the platform, not on devices; see [WAN interface metrics](/infrastructure/wan-interface-metrics).

## Set up metrics for a device

1. Add an SNMP credential (v2c community or v3 user) in [SNMP profiles & credentials](/onboard-devices/snmp-profiles). Read-only access is all Correlix needs.
2. Onboard the device — via [discovery](/onboard-devices/snmp-discovery) or [manually](/onboard-devices/add-devices-manually).
3. Confirm UDP **161** is open from Correlix to the device ([Connectivity requirements](/reference/connectivity-requirements)).
4. Optional, on supported platforms: enable [gNMI streaming](/onboard-devices/streaming-gnmi) for sub-minute resolution on your most important devices.

That's the whole procedure — polling starts automatically.

## What you get

- **Device** — CPU, memory, temperature, uptime, availability.
- **Interfaces** — in/out throughput, utilization, errors and discards, oper/admin status, speed.
- **Protocols** — BGP/OSPF/IS-IS neighbor state and transitions.

## Verify

1. <kbd>Administration → Data Collection → Data Sources</kbd> — the device's **SNMP metrics** column shows collecting.
2. <kbd>Metrics</kbd> — the **Metrics Explorer**. Query an interface throughput or CPU series for the device ad hoc and confirm points are arriving about once a minute (or faster on streaming devices).
3. <kbd>Infrastructure → Device Monitoring</kbd> — CPU/memory/interface panels fill in.
4. The full four-layer checklist (known → collecting → rendering → on the map) is in [Verify a device is monitored](/onboard-devices/verify-monitoring).

A panel showing **"—"** means that specific series genuinely has no data yet (for example, utilization needs the interface speed to have been discovered) — Correlix shows honest gaps rather than fabricated values.

## Tuning

- The default **1-minute poll** matches industry practice for interface statistics and keeps device CPU impact negligible.
- Where you need faster-than-poll resolution (busy WAN edges, microburst-sensitive links), enable **streaming telemetry** on that device rather than polling harder.

## Troubleshooting

**No metrics at all for a device**

1. Wrong or missing credentials are the usual cause — re-check the [SNMP profile](/onboard-devices/snmp-profiles) (community / v3 user, auth and priv settings) against the device config.
2. Confirm reachability: UDP 161 from Correlix to the device, and any SNMP ACL on the device permits Correlix's address.
3. See [Troubleshooting](/reference/troubleshooting) for the full ladder.

**Some panels populated, others "—"**

- Normal during the first minutes after onboarding, and normal permanently for series the platform doesn't expose. It is a per-series statement of "no data", not an error.

**Streaming device showing 1-minute data**

- The gNMI session isn't established — check the device-side gNMI/gRPC config and port against [Streaming telemetry](/onboard-devices/streaming-gnmi). Polling continues as the fallback, so you lose resolution, not coverage.

## Next

- **[Send syslog](/send-data/syslog)** and **[traps](/send-data/traps)** to add the event planes.
- **[Enable flow export](/send-data/flows)** for traffic analytics.
