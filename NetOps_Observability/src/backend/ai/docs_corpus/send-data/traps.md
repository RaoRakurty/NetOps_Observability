---
title: Send SNMP traps
sidebar_label: Send SNMP traps
description: Enable the trap receiver, point devices at UDP 162, and understand what a v3 trap proves that a v2c trap does not.
page_type: task
sidebar_position: 4
---

# Send SNMP traps

A trap is a notification a device pushes the instant something happens, so a
link flap, a power-supply failure or a lost neighbour reaches Correlix without
waiting for the next poll. The receiver decodes each trap against a MIB-backed
OID index and turns it into a readable, severity-classified event on the same
lane as syslog.

The receiver is off by default. Confirm it is on before spending time on device
configuration.

## Before you begin

- `FEATURE_SNMP_TRAPS` set to `true`. It defaults to `false`, and with it off
  nothing binds the port. See [Feature flags](/reference/feature-flags).
- UDP 162 open from the device to Correlix. See
  [Connectivity requirements](/reference/connectivity-requirements).
- The device [in the inventory](/onboard-devices/add-devices-manually) with its
  [SNMP credentials](/onboard-devices/snmp-profiles) stored. For v3 traps the
  receiver verifies against those same credentials, resolved by the packet's
  source address.
- The device sending from the management address the inventory holds.

## Steps

1. Confirm the `snmptrap` collector is enabled:

   ```bash
   curl -s -H "Authorization: Bearer $TOKEN" \
     http://localhost:8000/api/collectors
   ```

   On the lab stack the receiver is off, and the row says so:

   ```json
   {
     "name": "snmptrap",
     "kind": "trap",
     "enabled": false,
     "healthy": true,
     "last_tick": "0001-01-01T00:00:00Z",
     "targets": 0,
     "reachable": 0
   }
   ```

   `"healthy": true` here means nothing failed, because nothing ran. Read
   `enabled` first.

2. Configure the trap destination on the device: the Correlix address on UDP 162.
3. Configure the trap categories you want. A destination alone sends nothing.
4. Trigger a test trap. Shutting and re-enabling an unused interface produces
   `linkDown` and `linkUp`.
5. Confirm it arrived in **Explore → Logs** with the **SNMP traps** source selected.

### Configure the trap destination

The blocks below are constructed examples. Unlike the syslog and flow
blocks, this repository holds no validated trap configuration for these
platforms, so they are the conventional syntax rather than something Correlix
has tested. Check each against your own OS version. `MONITOR_HOST` is the
address of the Correlix host.

Cisco IOS and IOS-XE, v2c:

```text
snmp-server host MONITOR_HOST version 2c <community>
snmp-server enable traps snmp linkdown linkup coldstart
snmp-server enable traps bgp
snmp-server enable traps ospf
snmp-server enable traps envmon
snmp-server enable traps config
```

Cisco IOS and IOS-XE, v3 with authentication and privacy, using the same user
Correlix polls with:

```text
snmp-server host MONITOR_HOST version 3 priv <v3-user>
```

Juniper Junos:

```text
set snmp trap-group correlix version v2
set snmp trap-group correlix targets MONITOR_HOST
set snmp trap-group correlix categories link
set snmp trap-group correlix categories routing
set snmp trap-group correlix categories chassis
set snmp trap-group correlix categories configuration
```

### Trap families worth enabling

| Family | Examples | Why |
|---|---|---|
| Link state | `linkDown`, `linkUp` | Interface failures between polls |
| Routing | BGP and OSPF neighbour transitions | Control-plane faults at the moment they occur |
| Environment | Power supply, fan and temperature alarms | Hardware faults a counter poll does not show |
| Chassis | Module failures, `coldStart`, `warmStart` | Reboots and hardware events |
| Configuration | Configuration-change notifications | Correlating an outage with a change |
| Security | `authenticationFailure` | Wrong-credential access attempts against the device |

Enabling every vendor trap on a chatty platform adds volume without diagnostic
value. Choose families rather than turning everything on.

## Result

The trap appears in **Explore → Logs** with a decoded name, a severity, and its
variable bindings rendered by object name rather than raw OID, for example
`ifOperStatus=down(2)`. The **Traps** column for that device turns green on
[the coverage matrix](/onboard-devices/data-sources) within 15 minutes.

On **Administration → Data Collection → Sensors** the `snmptrap` row counts
traps received as `targets` and traps decoded as `reachable`.

## What the receiver accepts

| Version | Accepted | Authentication |
|---|---|---|
| v1 Trap-PDU | Yes | None available in the protocol. Recorded with `authenticated: false` |
| v2c Trap-PDU | Yes | None available in the protocol. Recorded with `authenticated: false` |
| v3 trap and inform | Yes | HMAC verified against the source device's stored USM credentials. Privacy is decrypted |

A v3 trap whose authentication cannot be verified is refused, not stored.
A device configured `noAuthNoPriv` has nothing to verify and is treated as it
always was.

`authenticated` is a field on every trap event. Read it before treating a trap
as proof of anything, because v1 and v2c traps are spoofable by anything that
can reach the port.

## Attribution

Traps are matched to the inventory by the packet's source address. Two rescue
paths cover NAT, and both require proof of identity first.

| Path | Applies to | What it requires |
|---|---|---|
| Source address | All versions | The address is in the inventory |
| `sysName.0` variable binding | All versions | The trap presents the device's community (v1, v2c) or a verified HMAC (v3) |
| v1 agent-address | v1 only | The same proof. The device's own address is carried inside the PDU |

Both rescues read packet content, which anything reaching UDP 162 controls, so
they are gated. Without the gate, a forged `sysName` would be enough to file an
event under a real device.

Source traps from the management or loopback address Correlix knows, and account
for any NAT on the path.

## Decoding and bounds

An unknown vendor OID is not dropped. It is recorded as `enterpriseSpecific` at
`notice` severity with its full OID and variable bindings intact. You lose the
friendly name and the severity mapping, not the data. Standard variable bindings
inside it are still decoded.

A trap is an unauthenticated UDP datagram, so the receiver bounds it: at most 64
variable bindings, 512 characters per decoded value, and 4,096 characters of
concatenated message. When a bound applies, the event carries `truncated` and
`varbinds_dropped`, so a bounded record is never indistinguishable from a
complete one.

## Troubleshooting

| Symptom | Cause | What to do |
|---|---|---|
| Nothing arrives | `FEATURE_SNMP_TRAPS` is off | Check the `snmptrap` collector's `enabled` field |
| Nothing arrives | UDP 162 blocked on the path | Traps are fire-and-forget, so a blocked path produces no error anywhere. Check every firewall |
| Nothing arrives | Categories not enabled on the device | A trap destination alone sends nothing |
| v3 traps are refused | The trap user, authentication or privacy settings differ from the stored credential | Make the device's trap user match the credential the device is onboarded with |
| A trap shows a raw OID | That vendor MIB is not in the index | The trap is still captured at `notice` severity with its OID and bindings |
| Traps attribute to no device | The source address is not an inventory address, and no rescue path had proof | Source traps from the management address, and check for NAT |

## Related

- [Send syslog](/send-data/syslog)
- [Verify a device is being monitored](/onboard-devices/verify-monitoring)
- [Search logs](/explore/logs)
- [Feature flags](/reference/feature-flags)
