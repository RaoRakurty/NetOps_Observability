---
title: Set up gNMI streaming telemetry
sidebar_label: Set up gNMI streaming telemetry
description: Add a gNMI subscription for a device through the gnmic collector, hand the gNMI-owned metric families to it, and confirm the stream is live.
page_type: task
sidebar_position: 7
---

# Set up gNMI streaming telemetry

gNMI streaming replaces polling for the metric families gNMI owns. The device
pushes state as it changes instead of waiting to be asked, so a BGP session that
tears down and re-establishes inside one polling interval is still recorded.

The subscription is run by the `gnmic` sidecar, not by the Go backend. gNMI is
a gRPC protocol and a gRPC client is outside the dependency budget, so the
backend's `gnmi` collector reports liveness rather than holding the stream.

Streaming does not replace SNMP. Interfaces, CPU and temperature stay
SNMP-owned on every device, including streaming ones.

## What gNMI owns and what it does not

The canonical output pipeline ends in an ownership gate that deletes three
families before they reach the metric store. A metric family is served by
exactly one transport per device.

| Family | Owner | Why |
|---|---|---|
| `device_if_*` | SNMP | gNMI interface coverage is a strict subset of SNMP here. No VLANs, loopbacks or sub-interfaces, and speed and admin-state parity is not proven |
| `device_cpu_percent` | SNMP | The SNMP floor already reads it from HOST-RESOURCES-MIB |
| `device_temp_celsius` | SNMP | The SNMP floor already reads it from ENTITY-SENSOR-MIB |
| `device_bgp_peer_state`, `device_bgp_fsm_transitions`, `device_bgp_pfx_in` | gNMI on a device labelled `gnmi: "true"`, SNMP everywhere else | BGP4-MIB is IPv4-only and thin on some platforms |
| `device_isis_adj_state`, `device_isis_adj_hold_seconds`, `device_isis_lsp_count`, `device_isis_spf_runs_total`, `device_isis_area` | gNMI | No SNMP source is configured for IS-IS |
| `device_mem_percent` on Nokia SR Linux | gNMI | The platform has no SNMP source for it |

To move a family to gNMI you have to prove parity against the raw lane, remove
it from the ownership gate, and withdraw it from the SNMP profile for the
affected devices in the same change.

## Before you begin

- Access to the deployment configuration. On a managed deployment, ask the
  platform owner and give them the address, port and account.
- A read-only gNMI account on the device.
- Reachability from Correlix to the device's gNMI port. Nokia SR Linux serves
  gNMI over TLS on 57400; Arista EOS serves it on 6030. The port is a device
  setting, so confirm it rather than assuming.
- The device already in the inventory. See
  [Add a device by hand](/onboard-devices/add-devices-manually).

## Steps

### Step 1 — Enable gNMI on the device

Nokia SR Linux serves gNMI on 57400 as part of its management stack. On Arista
EOS the shipped lab targets use plaintext gRPC on 6030. Note the port, whether
the device requires TLS, and the account you provisioned.

### Step 2 — Add the target

Edit `deployment/docker/gnmic/gnmic.yaml` and add a target keyed by
`address:port`. The `name` becomes the `source` label on every sample, so make
it match the device's inventory name.

```yaml
  172.40.40.11:57400:
    name: spine1
    password: ${SRL_GNMI_PASS}
    subscriptions: [srl-interfaces, srl-cpu, srl-bgp, srl-isis, srl-isis-db, srl-isis-timers]
```

An Arista EOS target uses the OpenConfig subscription sets and declares
plaintext:

```yaml
  172.40.40.21:6030:
    name: leaf1
    password: ${EOS_GNMI_PASS}
    insecure: true
    subscriptions: [oc-interfaces, oc-bgp]
```

The shipped subscription sets are these. Adding another platform means adding
its paths; no other platform's paths ship.

| Set | Paths | Mode |
|---|---|---|
| `oc-interfaces` | OpenConfig interface counters, oper-status, admin-status | sample, 30s |
| `oc-bgp` | OpenConfig session-state, established-transitions, per-AFI prefixes received | on-change, 30s heartbeat |
| `srl-interfaces` | SR Linux native interface statistics, oper-state, admin-state | sample, 30s |
| `srl-cpu` | SR Linux control CPU, memory and temperature | sample, 30s |
| `srl-bgp` | SR Linux native BGP session-state | on-change, 30s heartbeat |
| `srl-isis` | SR Linux IS-IS adjacency state | on-change, 30s heartbeat |
| `srl-isis-db` | SR Linux IS-IS LSP count, SPF runs, area id | sample, 60s |
| `srl-isis-timers` | SR Linux IS-IS adjacency remaining hold time | sample, 30s |

`srl-isis-timers` streams the **remaining** hold time, a countdown reset by every
hello, not the configured hold interval. A sampled series therefore looks like a
sawtooth. What it is evidence for is the floor: a value trending toward zero, or
a series going stale, means hellos stopped arriving.

### Step 3 — Supply the password

The shipped configuration reads device passwords from the environment. Set
`SRL_GNMI_PASS` or `EOS_GNMI_PASS` in `deployment/docker/.env`. Never write a
password into the YAML.

### Step 4 — Turn on the liveness collector

Set `ENABLE_GNMI_COLLECTION=true` in `deployment/docker/.env`. It defaults to
`false`. This flag controls the backend's `gnmi` status collector, not the
`gnmic` sidecar, which runs whenever the service is up.

### Step 5 — Apply

```bash
docker compose up -d --force-recreate gnmic
docker compose up -d api
```

### Step 6 — Hand the owned families to gNMI

Set the label `gnmi: "true"` on the device record. The SNMP collector then
withholds the gNMI-owned families on that device. Without the label, both
transports report BGP for it.

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"id":"spine1","address":"172.40.40.11","labels":{"gnmi":"true"}}' \
  http://localhost:8000/api/devices
```

## Result

The `gnmi` collector reports the number of distinct sources that have streamed
telemetry in the last five minutes. It asks the metric store rather than probing
the device, so `targets` and `reachable` are equal by construction: a source
that reported inside the window is an established stream.

On the lab stack, where streaming is off, the row reads:

```json
{
  "name": "gnmi",
  "kind": "protocol",
  "enabled": false,
  "healthy": true,
  "last_tick": "0001-01-01T00:00:00Z",
  "targets": 0,
  "reachable": 0
}
```

`"healthy": true` on a disabled collector means nothing has failed, because
nothing has run. `last_tick` at the zero time is what says the collector has
never polled. Read the two fields together, and read `enabled` first.

Two metric lanes carry the stream:

- The raw lane writes every subscribed path verbatim under the `gnmi_`
  prefix, tagged with a `source` label equal to the target name. Query it in
  **Explore → Metrics** to confirm a specific device is streaming. It is a
  comparison and debugging surface, and no console panel reads it.
- The canonical lane renames mapped paths to the same `device_*` names SNMP
  emits, converts status enumerations to IF-MIB numerics, applies the ownership
  gate, then deletes anything still path-shaped. An unmapped path cannot reach
  the canonical namespace.

## The correlation lane is separate and not attested

`ENABLE_GNMI_CORRELATION` is a different switch. It selects a second full
`gnmic` configuration that also produces to the event bus, so gNMI metrics can
reach correlation. It defaults to `false` in every shipped profile.

That lane has been built and tested but never live-attested. It has no
mutual-TLS identity and no produce grant on the bus topic, partition-key parity
with the other metric producer is unverified, and it is supported only at a
single bus partition and not under the TLS Compose profile. Turning it on is a
change that needs those gaps closed first.

## Troubleshooting

| Symptom | Cause | What to do |
|---|---|---|
| The target count stays at zero | The port is blocked, or the target's TLS setting disagrees with the device | Test reachability to the gNMI port; add or remove `insecure: true` to match |
| Authentication errors in the `gnmic` log | The password environment variable is unset or wrong | Check the variable the target references in `.env` |
| Both transports report BGP for one device | The `gnmi: "true"` label is missing | Set the label so the SNMP collector yields those families |
| Interface panels still update once a minute | Interfaces are SNMP-owned by design | Expected. The ownership gate deletes `device_if_*` from the gNMI canonical lane |
| A new subscription produces no canonical series | Its path has no rename rule, so the fail-closed step dropped it | Add the mapping, or read the path on the raw `gnmi_` lane |

## Related

- [Supported devices](/onboard-devices/supported-devices)
- [Send metrics](/send-data/metrics)
- [Verify a device is being monitored](/onboard-devices/verify-monitoring)
- [Feature flags](/reference/feature-flags)
