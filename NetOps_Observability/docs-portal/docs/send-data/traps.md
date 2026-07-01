---
title: SNMP traps
sidebar_label: SNMP traps
sidebar_position: 4
description: Receive asynchronous SNMP trap notifications from your devices.
---

# SNMP traps

SNMP **traps** are notifications a device pushes the instant something happens — a link flaps, a PSU fails, a routing neighbor drops — so you learn about a fault without waiting for the next poll. Correlix's trap receiver decodes each trap against its MIB library and turns it into a readable, severity-classified event that feeds the timeline and correlation.

## What the receiver supports

- **SNMP v1** traps, **v2c** traps, and **v3** traps and informs (including authentication and privacy/encryption).
- **v3 traps are cryptographically verified** against the sending device's onboarded SNMP v3 credentials — a v3 trap that fails authentication is refused, not indexed. v1/v2c traps are accepted but marked *unauthenticated* (the protocol offers no way to verify them).
- **MIB-driven decoding**: standard and known vendor trap OIDs resolve to a friendly name and severity, and each variable-binding is shown by object name (e.g. `ifOperStatus=down(2)`) instead of a raw OID.
- **Nothing is silently dropped**: a trap with an unrecognized vendor OID is still captured as a generic device notification at notice severity, with its OID and varbinds intact.

## Before you begin

1. The device is [onboarded](/onboard-devices/overview) with working [SNMP credentials](/onboard-devices/snmp-profiles) — for v3 traps, the receiver verifies against these same credentials.
2. **UDP 162** is open from the device to Correlix ([Connectivity requirements](/reference/connectivity-requirements)).
3. Trap reception is enabled on your Correlix instance — it's a deployment-level setting. If in doubt, confirm with your platform administrator before spending time on device configs.

## Step 1 — Configure the trap destination

Point each device at Correlix on UDP 162 (`CORRELIX_IP` is your instance). Match the SNMP version to your security posture — **v3 with auth+priv is recommended**, using the same v3 user the device is onboarded with:

```text
! Cisco IOS / IOS-XE — v2c
snmp-server host CORRELIX_IP version 2c <community>
snmp-server enable traps snmp linkdown linkup coldstart
snmp-server enable traps bgp
snmp-server enable traps ospf
snmp-server enable traps envmon
snmp-server enable traps config

! Cisco IOS / IOS-XE — v3 (authPriv, same user Correlix polls with)
snmp-server host CORRELIX_IP version 3 priv <v3-user>
```

```text
! Arista EOS
snmp-server host CORRELIX_IP version 2c <community>
snmp-server enable traps
```

```text
# Juniper Junos
set snmp trap-group correlix version v2
set snmp trap-group correlix targets CORRELIX_IP
set snmp trap-group correlix categories link
set snmp trap-group correlix categories routing
set snmp trap-group correlix categories chassis
set snmp trap-group correlix categories configuration
```

## Step 2 — Enable the high-value trap families

Devices only send the trap categories you enable. These are the families worth turning on everywhere:

| Family | Examples | Why it matters |
| --- | --- | --- |
| **Link state** | `linkDown` / `linkUp` | Sub-second notice of interface failures, between polls |
| **Routing** | BGP / OSPF neighbor transitions | Control-plane faults the moment they occur |
| **Environment** | PSU, fan, temperature alarms | Hardware failures a counter poll won't show |
| **Chassis / hardware** | Module failures, coldStart/warmStart | Reboots and hardware events |
| **Configuration** | Config-change notifications | Correlate outages with changes |
| **Security** | `authenticationFailure` | Someone probing your devices with wrong credentials |

Avoid enabling *every* vendor trap indiscriminately on chatty platforms — some emit high-volume informational traps that add noise without diagnostic value.

## Step 3 — Verify

1. Trigger a test trap: `shutdown` / `no shutdown` an unused interface is the easiest safe test (it produces `linkDown` + `linkUp`).
2. <kbd>Administration → Data Collection → Data Sources</kbd> — the device's **Traps** column turns green.
3. <kbd>Logs → Log Search</kbd> — pick the **SNMP traps** source; your test trap appears with a decoded name, severity, and varbinds. See [Log Search](/explore/logs).
4. <kbd>Monitoring → Events</kbd> — notable traps show on the event timeline alongside syslog and metric events.

## How traps attribute to devices

- Traps are matched to inventory by the packet's **source IP**.
- **v1 traps** additionally carry the device's own address *inside* the message, so they attribute correctly even through NAT.
- **v2c/v3 traps** carry no in-message address — if a NAT sits between the device and Correlix, make sure the translated source still maps to the device, or have the device source traps from its management/loopback address.

## Troubleshooting

**Nothing arriving**

1. Confirm trap reception is enabled on your instance (deployment setting — ask your platform administrator).
2. Check UDP **162** on every firewall/ACL in the path. Traps are UDP fire-and-forget: a blocked path produces no error anywhere.
3. Confirm trap **categories are enabled** on the device — `snmp-server host` alone sends nothing without `snmp-server enable traps …` (or the Junos `categories` lines).
4. For **v3**: a trap that fails authentication is refused by design. Verify the trap user/auth/priv settings on the device exactly match the v3 credentials the device is onboarded with in Correlix.

**Trap shows a raw OID instead of a name**

- The vendor MIB isn't in the decoding library. The trap is still captured (generic, notice severity) with its full OID and varbinds — you lose the friendly name and severity mapping, not the data. Standard varbinds inside it (interface status, MAC/VLAN context) are still decoded where present.

**Traps attribute to the wrong device / no device**

- The source IP doesn't match an inventory address. Source traps from the management/loopback IP Correlix knows, and check for NAT (see attribution notes above).

## Next

- **[Send flow records](/send-data/flows)** — the third push plane.
- **[Monitoring & alerting](/monitoring/overview)**.
