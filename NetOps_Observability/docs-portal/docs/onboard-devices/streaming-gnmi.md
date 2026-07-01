---
title: Streaming telemetry (gNMI)
sidebar_label: Streaming telemetry (gNMI)
sidebar_position: 6
description: Add high-resolution, model-driven streaming telemetry on platforms that support gNMI, alongside SNMP.
---

# Streaming telemetry (gNMI)

On platforms that support it, **gNMI streaming telemetry** upgrades a device from polled to pushed metrics: the device streams subscribed data the moment it changes, instead of waiting to be asked. Correlix normalizes streamed samples onto **the same metric names as SNMP**, so dashboards, monitors, and correlation treat both transports identically — switching a device to streaming needs no dashboard changes.

## What streaming adds over SNMP polling

- **On-change protocol state.** BGP session state, session flap counters, and per-peer prefixes received are streamed **the instant they change** — a session that tears down and re-establishes inside one polling interval is invisible to a poller but captured by streaming. IS-IS adjacency state streams the same way on supported platforms.
- **Steady sub-minute interface counters.** Interface octets, errors, discards, and packet-mix counters stream on a ~30-second cadence.
- **Metrics SNMP doesn't expose.** On some platforms (e.g. modern data-center NOS), control-plane memory or other health values have no SNMP equivalent — streaming is their only source.
- **One owner per metric.** Where both transports could report the same family (e.g. BGP state), Correlix serves it from exactly **one** transport per device, so nothing is double-counted. SNMP remains the universal floor for devices without streaming.

## Prerequisites

- The device supports **gNMI** (gRPC-based streaming) and you can create a read-only account for Correlix on it.
- Network reachability from Correlix to the device's gNMI port — commonly **57400** (TLS) or a platform-specific port such as 6030; see [Connectivity requirements](/reference/connectivity-requirements).
- Access to your instance's deployment configuration (self-hosted installs), or your platform administrator.

## Step 1 — Enable gNMI on the device

Generic examples for common platforms — adapt to your OS version and security policy:

```text
! Arista EOS style — gNMI via the management API
management api gnmi
   transport grpc default
```

```text
# Cisco IOS-XE style
gnmi-yang
gnmi-yang server
```

Nokia SR Linux serves gNMI (TLS, port 57400) as part of its standard management stack. Whatever the platform: note the **port**, whether it uses **TLS**, and the **username/password** you provisioned.

## Step 2 — Declare the target on the platform

Streaming subscriptions are per-device and are declared in the streaming collector's target list, which lives in the deployment at `deployment/docker/gnmic/gnmic.yaml`:

1. Add a target entry with the device's **address:port**, a **name** that matches the device's inventory name, and the subscription sets for its platform (interface counters, BGP, and — where supported — IGP and control-plane health).
2. Put the device account's password in the deployment's `.env` (the shipped config reads passwords from environment variables — never hard-code them in the file).
3. In `.env`, set `ENABLE_GNMI_COLLECTION=true` so the platform tracks streaming liveness (it defaults to off).
4. Apply:

```bash
docker compose up -d --force-recreate gnmic
docker compose up -d api
```

5. Finally, mark the device as streaming-capable in the inventory by setting the label `gnmi: "true"` on its device record (via the device API or inventory file). This is what tells the SNMP poller to *yield* the streamed metric families (BGP/IS-IS) to streaming on that device — skip it and both transports will try to report BGP.

:::info Managed instances
On a managed deployment you won't edit these files yourself — ask your platform owner to enable streaming for the device and give them the address, port, and account details.
:::

## Step 3 — Verify it's flowing

1. **Dashboards update at streaming cadence.** Open <kbd>Infrastructure → Device Monitoring</kbd> and <kbd>Infrastructure → Interface Performance</kbd> — the device's interface panels now refresh at the ~30-second stream rate. <kbd>Infrastructure → Protocol Monitoring</kbd> shows its BGP session state live.
2. **Raw stream check.** In the **Metrics** explorer, search for series whose names start with the `gnmi_` prefix — the raw stream lands there verbatim, and every sample carries a `source` label equal to the target name. Filtering on your device's target name confirms it is the one streaming.
3. **Collector view (platform operators).** <kbd>Administration → Data Collection → Collectors</kbd> lists the **gNMI** collector with its live target count — the number of devices that have streamed telemetry in the last 5 minutes. Your new device should raise the count within a minute or two.

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Target count doesn't rise | Port blocked, or TLS mismatch (device requires TLS, target declared plaintext — or vice versa) | Test reachability to the gNMI port; align the target's TLS setting with the device |
| Authentication errors in the collector logs | Wrong account/password env var | Re-check the `.env` variable the target references |
| Metrics stream but the device double-reports BGP | Inventory label `gnmi: "true"` not set | Set the label (Step 2.5) so SNMP yields those families |
| Interface panels still update once a minute | Interface families are intentionally SNMP-owned unless coverage parity is proven for your platform | Expected on mixed fleets; protocol state is where streaming shines |

## Next

- **[Verify a device is monitored](/onboard-devices/verify-monitoring)**.
- **[Data Sources & coverage](/onboard-devices/data-sources)** — confirm the rest of the planes.
