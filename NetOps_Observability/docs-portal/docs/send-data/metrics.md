---
title: Send metrics
sidebar_label: Send metrics
description: Set up the polling and streaming paths that produce metrics, and confirm the series are arriving. Metrics are pulled, never pushed.
page_type: task
sidebar_position: 2
---

# Send metrics

Metrics are the one plane a device does not send. Correlix pulls them: the SNMP
collectors poll each device on UDP 161, and where gNMI is configured the device
streams into a subscription Correlix opened. There is no agent to install and no
endpoint a device can POST metrics to.

This page is therefore about making the pull work. A platform that cannot be
polled and does not speak gNMI contributes only what it reports through
[syslog](/send-data/syslog) and [traps](/send-data/traps).

## Before you begin

- The device is in the inventory. See
  [Add a device by hand](/onboard-devices/add-devices-manually) or
  [Configure SNMP discovery](/onboard-devices/snmp-discovery).
- A read-only SNMP credential the device answers to. See
  [Add an SNMP credential](/onboard-devices/snmp-profiles).
- UDP 161 open from Correlix to the device, and any device-side SNMP ACL
  permitting the Correlix address. See
  [Connectivity requirements](/reference/connectivity-requirements).
- `ENABLE_SNMP_COLLECTION` and `ENABLE_SNMP_METRICS` both `true`. Both default
  to `true`, and metrics need both: the first runs the reachability pollers,
  the second runs the collector that reads the OIDs.

## Steps

1. Store the credential in
   **Administration → Data Collection → SNMP Profiles → Credentials**.
2. Set the device record's `credential_ref` to that profile's id or name. A
   device with no reference falls back to the deployment-wide `SNMP_COMMUNITY`,
   which defaults to `public`.
3. Confirm the device answers on UDP 161 from the Correlix host.
4. On a gNMI platform, add the subscription. See
   [Set up gNMI streaming telemetry](/onboard-devices/streaming-gnmi).

That is the whole procedure. Polling starts on the next cycle.

## Result

Two collectors run against the device.

| Collector | Interval | What it does |
|---|---|---|
| `snmpv2c` or `snmpv3` | 30 seconds | Reachability probe on UDP 161. Which one is chosen follows from the credential version |
| `snmpmetrics` | 60 seconds | Reads the OIDs of the generic profile plus any vendor pack matched by the device's enterprise number |

Confirm the series exist in **Explore → Metrics**. On the lab stack, where both
devices are timing out on UDP 161, the same query returns an empty matrix rather
than an error:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/metrics/query_range?query=device_sysuptime&start=1788409339&end=1788410239&step=300"
```

```json
{"status":"success","data":{"resultType":"matrix","result":[]},"stats":{"seriesFetched": "0","executionTimeMsec":0}}
```

An empty matrix is a statement that no series matched, not a claim that the
value is zero. The reason is on the collector, which reports
`2/2 targets did not answer`. See
[Verify a device is being monitored](/onboard-devices/verify-monitoring).

The **SNMP metrics** column on
[the coverage matrix](/onboard-devices/data-sources) turns green once a
`device_sysuptime` series exists for the device inside the 15-minute window.

## What you get

The generic profile reads 33 objects from standard MIBs on every device: uptime,
interface state and traffic and errors and packet mix, `hrProcessorLoad`,
`entPhySensorValue`, BGP peer state and transitions, OSPF neighbour and area
state, and Power over Ethernet port status. A vendor pack adds
platform-specific CPU, memory, temperature, firewall session and load-balancer
metrics where one exists. The per-vendor detail is in
[Supported devices](/onboard-devices/supported-devices).

Correlix also produces metrics of its own through active measurement, when the
matching collectors are enabled: STAMP path probes (`FEATURE_ACTIVE_PROBE`),
traceroute (`FEATURE_TRACEROUTE`), synthetic HTTP, ICMP and TCP checks
(`FEATURE_SYNTHETICS`), and WAN circuit echo (`FEATURE_WAN_ECHO`). All four
default to off and are configured on the platform, not on devices. See
[WAN interface metrics](/infrastructure/wan-interface-metrics).

## Resolution

The 60-second metric poll is the default and is right for interface statistics.
Where you need finer resolution, enable
[gNMI streaming](/onboard-devices/streaming-gnmi) on that device rather than
polling harder. Streaming does not change the metric names: the canonical gNMI
lane renames mapped paths to the same `device_*` names SNMP emits, so dashboards
and monitors do not care which transport fed them.

Interfaces, CPU and temperature stay SNMP-owned even on a streaming device. The
families gNMI serves are BGP state, IS-IS state and Nokia SR Linux memory.

## Troubleshooting

| Symptom | Cause | What to do |
|---|---|---|
| No series at all for a device | The credential does not match, or UDP 161 is blocked | Check the collector's `last_error` on **Administration → Data Collection → Sensors** |
| Reachable but no samples | `ENABLE_SNMP_METRICS` is off, or no profile OID answered | Check the flag, then the vendor profile |
| Some panels populated, others empty | Those series are not in the device's profile, or the platform does not expose them | Extend the profile with the OID. An empty panel is a per-series statement of no data |
| A streaming device still shows 60-second data | The gNMI subscription is not established | Check the `gnmi` collector's target count. SNMP continues as the floor, so you lose resolution rather than coverage |
| Utilization is empty while throughput is not | `device_if_speed` has not been read for that interface | Utilization is derived from speed. Nothing is estimated in its absence |

## Related

- [Add an SNMP credential](/onboard-devices/snmp-profiles)
- [Set up gNMI streaming telemetry](/onboard-devices/streaming-gnmi)
- [Verify a device is being monitored](/onboard-devices/verify-monitoring)
- [Explore metrics](/explore/metrics)
