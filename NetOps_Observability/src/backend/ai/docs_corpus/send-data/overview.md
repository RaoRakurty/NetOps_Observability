---
title: Send data to Correlix
sidebar_label: Overview
description: The four telemetry planes, the port each one arrives on, and the order to configure them in.
page_type: index
sidebar_position: 1
---

# Send data to Correlix

Devices in the inventory produce metrics as soon as SNMP answers. Their events,
notifications and traffic records need one configuration change each, made on
the device. The pages below cover that change per plane, plus the port it
arrives on and the rule that ties each record back to a device.

| Page | What it covers |
|---|---|
| [Send metrics](/send-data/metrics) | How the pulled plane works, and why there is no push path for it. |
| [Send syslog](/send-data/syslog) | Point a device's syslog at Correlix, choose a severity threshold, and get attribution right. |
| [Send SNMP traps](/send-data/traps) | Enable the receiver, set the trap destination, and read what v3 authentication buys you. |
| [Send flow records](/send-data/flows) | Choose NetFlow, IPFIX or sFlow, configure the exporter, and set a sampling rate. |

## The four planes

| Plane | Direction | Transport |
|---|---|---|
| Metrics | Correlix polls the device | SNMP on UDP 161, or a gNMI subscription Correlix opens |
| Syslog | Device sends to Correlix | UDP or TCP 514 |
| SNMP traps | Device sends to Correlix | UDP 162 |
| Flow records | Device sends to Correlix | UDP 2055, 4739 or 6343 |

## Ports

These are the ports the shipped Compose deployment publishes. Confirm them
against your own deployment, because each one is overridable at install time.
The authoritative table, including the pull direction and the browser
requirements, is
[Connectivity requirements](/reference/connectivity-requirements).

| Port | Protocol | Direction | Plane |
|---|---|---|---|
| 161 | UDP | Correlix to device | SNMP polling and discovery |
| 514 | UDP and TCP | device to Correlix | Syslog |
| 5514 | UDP and TCP | device to Correlix | Syslog, the alternate unprivileged port |
| 162 | UDP | device to Correlix | SNMP traps |
| 2055 | UDP | device to Correlix | NetFlow v5 and v9 |
| 4739 | UDP | device to Correlix | IPFIX |
| 6343 | UDP | device to Correlix | sFlow |
| 8000 | TCP | operator to Correlix | Console and REST API |

Syslog is published on both 514 and 5514 so that devices configured with a
default `logging host <address>` reach the collector with no per-device change.
Both host ports map to the same listener.

The environment variables that move them are `SYSLOG_PORT`, `SNMP_TRAP_PORT`,
`NETFLOW_PORT`, `IPFIX_PORT`, `SFLOW_PORT` and `BASE_PORT`.

The shipped deployment serves the console over plain HTTP on 8000. A TLS front
is an opt-in Compose override and the shipped example uses 8443, not 443. There
is no HTTPS listener until you configure one.

## Which plane to configure first

1. **Syslog.** Link transitions, adjacency changes, hardware alarms and
   configuration events arrive as searchable events the moment the device emits
   them, and they feed correlation. One or two lines of device configuration.
2. **SNMP traps.** Notification between polls, which matters for hardware and
   environment faults. The receiver is off by default, so confirm
   `FEATURE_SNMP_TRAPS` before configuring devices.
3. **Flow records.** Traffic analytics, on the devices where traffic visibility
   matters: WAN edges, data-centre cores, internet borders and firewalls.

| To answer | Send |
|---|---|
| What did the device say about the fault, and when | Syslog |
| Did a link, power supply, fan or neighbour fail between polls | Traps |
| Who is talking to whom, over what, and how much | Flow records |
| How has utilization, error rate or CPU trended | Metrics, which need no device change |

You do not need every plane from every device. Metrics plus syslog is a
reasonable floor everywhere, with all four on core and edge devices.

## Why more than one plane

Correlation treats each plane as an independent witness. One plane produces a
lead. The same fault seen on a second plane at the same time on the same device
is corroboration, and the verdict is stated accordingly. Coverage is therefore
a direct input to root-cause quality, which is why the
[coverage matrix](/onboard-devices/data-sources) is per device and per plane.

## Attribution

Every pushed record has to be tied back to an inventory device, and each plane
does it differently.

| Plane | Attributed by |
|---|---|
| Syslog | The hostname carried in the message, falling back to the source address |
| Traps | The source address, with a `sysName` or v1 agent-address rescue that requires proof of identity |
| Flows | The exporter address |

Configure devices to send from the management address the inventory holds, and
keep the device hostname equal to the inventory name. Each plane's page has the
specifics.

## Related

- [Onboard devices](/onboard-devices/overview)
- [Check the data-source coverage matrix](/onboard-devices/data-sources)
- [Connectivity requirements](/reference/connectivity-requirements)
