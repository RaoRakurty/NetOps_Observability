---
title: Verify a device is being monitored
sidebar_label: Verify a device is monitored
description: Read the collector pool, the coverage matrix and the alerts they raise to prove a device is answering, and tell a silent device from a silent collector.
page_type: task
sidebar_position: 9
---

# Verify a device is being monitored

Verification answers one question: is data from this device arriving and
rendering. Each layer below has its own evidence, and each has an empty state
that means something specific. Work through them in order, because a failure at
one layer explains every layer above it.

## Before you begin

- The device is in the inventory. See
  [Add a device by hand](/onboard-devices/add-devices-manually).
- For the collector pool, a platform administrator account. `GET /api/collectors`
  requires cross-tenant authority, because collector status is a fleet-wide
  aggregate and a tenant-scoped caller would otherwise learn the fleet size.

## Steps

### Step 1 — The device is in the inventory

1. Go to **Infrastructure → Devices**.
2. Find the device and read its status dot.

| State | Condition |
|---|---|
| **Up** | Heartbeat within 5 minutes and no active alert on the device |
| **Degraded** | Heartbeat older than 5 minutes, or an active alert on the device |
| **Down** | No heartbeat for more than 15 minutes |

**Up** is a claim about two things: heartbeat freshness and the alert list. When
the alert query fails, the page says so, and **Up** then means only that the
heartbeat is fresh.

### Step 2 — The collector that should reach it is running and reaching it

Go to **Administration → Data sources → Sensors**, or read the pool directly.
Note that the console tab lists the protocol and trap collectors only; the API
returns all sixteen.

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/collectors
```

Two rows from the lab stack. The first is enabled and failing; the second is
disabled.

```json
{
  "name": "snmpv2c",
  "kind": "protocol",
  "enabled": true,
  "healthy": false,
  "last_tick": "2026-09-03T03:47:29.378961516Z",
  "last_error": "2/2 targets did not answer (last error: read udp 172.18.0.9:51458->172.40.40.12:161: i/o timeout)",
  "targets": 2,
  "reachable": 0,
  "last_poll_ms": 6001
}
```

```json
{
  "name": "lldp",
  "kind": "discovery",
  "enabled": false,
  "healthy": true,
  "last_tick": "0001-01-01T00:00:00Z",
  "targets": 0,
  "reachable": 0
}
```

Read the fields in this order.

| Field | What it tells you |
|---|---|
| `enabled` | Whether the collector's flag is on. Read this first |
| `healthy` | Whether the last cycle succeeded |
| `last_tick` | When the collector last ran. `0001-01-01T00:00:00Z` means never |
| `targets` | How many devices the collector was given |
| `reachable` | How many of them answered |
| `last_error` | The transport error from the last failed cycle, verbatim |
| `last_poll_ms` | How long the last cycle took |

:::caution A disabled collector reports `"healthy": true`
`healthy` says nothing failed. Nothing failed because nothing ran. The `lldp`
row above is disabled, has never ticked, and has no targets. It is not working;
it is switched off. A collector is only doing something when `enabled` is `true`
and `last_tick` is recent.
:::

The `snmpv2c` row is the honest opposite: enabled, ticking every 30 seconds,
and reporting that both of its targets timed out on UDP 161. The error names
the source address, the destination address and the port, which is enough to
take to a firewall team.

The collectors and the flags that enable them:

| Collector | Flag | Default |
|---|---|---|
| `snmpv2c`, `snmpv3` | `ENABLE_SNMP_COLLECTION` | on |
| `snmpmetrics` | `ENABLE_SNMP_METRICS` | on |
| `tunnels` | `ENABLE_TUNNEL_DISCOVERY` | on |
| `gnmi` | `ENABLE_GNMI_COLLECTION` | off |
| `netconf` | `ENABLE_NETCONF_COLLECTION` | off |
| `lldp` | `ENABLE_LLDP_DISCOVERY` | off |
| `cdp` | `ENABLE_CDP_DISCOVERY` | off |
| `bgpls` | `ENABLE_BGPLS_DISCOVERY` | off |
| `snmptrap` | `FEATURE_SNMP_TRAPS` | off |
| `unifi` | `FEATURE_UNIFI` | off |
| `stamp-sender` | `FEATURE_ACTIVE_PROBE` | off |
| `stamp-reflector` | `FEATURE_STAMP_REFLECTOR` | off |
| `traceroute` | `FEATURE_TRACEROUTE` | off |
| `synthetics` | `FEATURE_SYNTHETICS` | off |
| `wan-echo` | `FEATURE_WAN_ECHO` | off |

The full list with descriptions is in
[Feature flags](/reference/feature-flags). `ENABLE_SNMP_COLLECTION` drives both
SNMP collectors; which one polls a device follows from the version of its
credential.

### Step 3 — The planes are delivering

Go to **Administration → Data sources → Data Sources** and read the device's
row. See
[Check the data-source coverage matrix](/onboard-devices/data-sources) for what
each cell claims and what it does not.

### Step 4 — The alerts agree

The collector pool feeds alert rules, so a reachability problem raises an alert
rather than sitting silently in a status field.

| Rule | Condition | For | Severity |
|---|---|---|---|
| `DeviceUnreachable` | A device's target is down on any collector except `netconf` | 2m | critical |
| `CollectorAllTargetsUnreachable` | `reachable` is 0 while `targets` is above 0 | 5m | critical |
| `CollectorPartialReachability` | Under 80% of targets reachable | 10m | warning |
| `NoSamplesIngested` | The collector produced no samples while it had targets | 10m | warning |
| `CollectorPollSlow` | A poll took over 10,000 ms | 10m | warning |

`netconf` is excluded from `DeviceUnreachable` on purpose: it probes every
device's TCP 830 opportunistically, and a device without NETCONF is not
unreachable.

The alerts for the failing lab stack above:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/alerts
```

```json
[
  {
    "id": "CollectorAllTargetsUnreachable|collector=snmpv2c",
    "rule": "CollectorAllTargetsUnreachable",
    "severity": "critical",
    "summary": "Collector snmpv2c cannot reach any target",
    "labels": { "collector": "snmpv2c", "severity": "critical" },
    "fired_at": "2026-09-03T03:32:59.379985203Z"
  },
  {
    "id": "DeviceUnreachable|collector=snmpv2c,device=spine1",
    "rule": "DeviceUnreachable",
    "severity": "critical",
    "device_id": "spine1",
    "summary": "spine1 unreachable from snmpv2c",
    "labels": { "collector": "snmpv2c", "device": "spine1", "severity": "critical" },
    "fired_at": "2026-09-03T03:29:59.379975793Z"
  },
  {
    "id": "NoSamplesIngested|collector=snmpmetrics",
    "rule": "NoSamplesIngested",
    "severity": "warning",
    "summary": "Collector snmpmetrics produced 0 samples",
    "labels": { "collector": "snmpmetrics", "severity": "warning" },
    "fired_at": "2026-09-03T03:37:29.381596952Z"
  }
]
```

Three rules fired on one fault, from three angles: the collector reaches
nothing, a named device is unreachable, and the metric collector produced no
samples. A tenant-scoped operator sees only alerts on devices in their tenant.

### Step 5 — The series exist

1. Go to **Explore → Metrics**.
2. Query a series for the device, for example `device_sysuptime` or
   `device_if_in_octets`.
3. Confirm points are arriving about every 60 seconds, or faster on a streaming
   device.

An empty result here, with a healthy collector and a reachable device, means
that particular series is not in the device's SNMP profile. See
[Supported devices](/onboard-devices/supported-devices).

### Step 6 — The console renders it

1. Open the device from **Infrastructure → Devices**.
2. Check **Infrastructure → Interfaces & Optics** for per-interface counters.
3. Check **Explore → Logs** for its syslog and traps.
4. Check **Explore → Flows** for its traffic.

## Result

A verified device is enabled on a collector that ticked recently, counted in
that collector's `reachable`, green for the planes you configured on the
coverage matrix, and returning points in the metrics explorer. A panel that
shows nothing at that point is a statement that the series has no data, not an
error.

## Where an empty result comes from

| What you see | What it means | What it does not mean |
|---|---|---|
| Collector `enabled: false`, `healthy: true`, `last_tick` at the zero time | The collector never ran | Not that the collector is working |
| Collector `enabled: true`, `reachable: 0`, `last_error` set | Every target failed, and the error names how | Not that the devices are absent from the inventory |
| A coverage cell showing `—` | The store answered and this device was not in the answer | Not that the device is healthy |
| A coverage cell showing `?` | That plane's query failed | Not that the device is silent |
| An empty metric query with a healthy collector | That series is not collected for this platform | Not a value of zero |
| Device **Up** with the alert query failed | The heartbeat is fresh | Not that the device has no active alerts |

The full table for every surface is
[What an empty result means](/reference/honest-states).

## Troubleshooting

| Layer that failed | Most likely cause | Where to go |
|---|---|---|
| Not in the inventory | Never added, or discovery did not reach it | [Configure SNMP discovery](/onboard-devices/snmp-discovery) |
| Collector disabled | The flag is off | [Feature flags](/reference/feature-flags) |
| Collector enabled, nothing reachable | UDP 161 blocked, or an SNMP ACL excludes Correlix | [Connectivity requirements](/reference/connectivity-requirements) |
| Some targets reachable, this one not | Credential mismatch on this device | [Add an SNMP credential](/onboard-devices/snmp-profiles) |
| Reachable but no samples | The metric collector is off, or no profile OID answered | Check `ENABLE_SNMP_METRICS`, then the vendor profile |
| Metrics fine, a push plane empty | Device-side configuration or attribution | [Send data to Correlix](/send-data/overview) |

## Related

- [Check the data-source coverage matrix](/onboard-devices/data-sources)
- [Send data to Correlix](/send-data/overview)
- [What an empty result means](/reference/honest-states)
- [Troubleshooting](/reference/troubleshooting)
