---
title: Onboard devices
sidebar_label: Overview
description: The order to work in when bringing a fleet into Correlix, and the page that covers each step.
page_type: index
sidebar_position: 1
---

# Onboard devices

Correlix polls devices over SNMP and accepts pushed syslog, traps and flow
records. Onboarding a fleet is therefore a credential, an inventory entry, and
one device-side configuration change per push plane. The pages below cover each
of those for the operator who has a working deployment and a list of management
addresses.

Work in this order. Each page states what you need before you start and what
proves the step worked.

| Page | What it covers |
|---|---|
| [Supported devices](/onboard-devices/supported-devices) | Which vendors Correlix recognizes, which metric families it reads, and what is not claimed. |
| [Add an SNMP credential](/onboard-devices/snmp-profiles) | Store a v1/v2c community or an SNMPv3 USM user, and bind it to devices. |
| [SNMP configuration by vendor](/onboard-devices/vendor-snmp-configs) | The device-side CLI Correlix generates for each vendor it has a template for. |
| [Configure SNMP discovery](/onboard-devices/snmp-discovery) | Scope a bounded subnet sweep and onboard everything that answers. |
| [Add a device by hand](/onboard-devices/add-devices-manually) | Add one device by id and management address. |
| [Set up gNMI streaming telemetry](/onboard-devices/streaming-gnmi) | Add a gnmic subscription for a device, and hand the gNMI-owned families to it. |
| [Check the data-source coverage matrix](/onboard-devices/data-sources) | See, per device, which of the four planes delivered data in the last 15 minutes. |
| [Verify a device is being monitored](/onboard-devices/verify-monitoring) | Read the collector pool, the alerts it raises, and the honest empty states. |

## Discovered, then monitored

Being in the inventory and being monitored are two different states, and the
difference is the one the licence counts.

- **Discovered** — Correlix knows the device exists. Free, unlimited, and never
  refused by a licence: a sweep that finds five hundred devices creates five
  hundred inventory records and uses none of the device allowance.
- **Monitored** — Correlix collects from the device. This is what the device
  ceiling counts (25 on the Community tier), and it is what the collectors poll.

A device you add by hand, declare in the devices file, or bring in from the
source of truth is monitored from the moment it appears: adding it is asking for
it to be collected from. A device found only by the **subnet sweep** is a
candidate — switch monitoring on for it in the Monitoring column of
**Infrastructure → Inventory & Devices** when you want its telemetry. Several
telemetry methods on one device still count as one monitored device, and turning
monitoring off leaves the device, its history and its place in the topology
exactly where they are.

## What each step gives you

Metrics arrive as soon as a device is in the inventory WITH MONITORING ON and a
credential that answers. The other three planes are configured on the device and covered in
[Send data to Correlix](/send-data/overview).

| Plane | Direction | Where it is configured |
|---|---|---|
| Metrics | Correlix polls the device on UDP 161 | [Add an SNMP credential](/onboard-devices/snmp-profiles) |
| Syslog | Device sends to Correlix | [Send syslog](/send-data/syslog) |
| SNMP traps | Device sends to Correlix | [Send SNMP traps](/send-data/traps) |
| Flow records | Device sends to Correlix | [Send flow records](/send-data/flows) |

## Before you start

- Open the ports in [Connectivity requirements](/reference/connectivity-requirements).
  Correlix needs UDP 161 outbound to each device; the push planes need their
  ports inbound.
- Confirm which collectors are enabled on your deployment. Every collector is
  an individual flag, listed in [Feature flags](/reference/feature-flags).
  `ENABLE_SNMP_COLLECTION` and `ENABLE_SNMP_METRICS` default to `true`;
  `ENABLE_SNMP_DISCOVERY`, `ENABLE_GNMI_COLLECTION`, `FEATURE_SNMP_TRAPS` and
  the rest default to `false`.
- Have a read-only SNMP credential ready, or generate one with the
  [SNMP configuration generator](/onboard-devices/vendor-snmp-configs).

## Where the controls live

| Console location | What it does |
|---|---|
| **Infrastructure → Devices** | The inventory. Add a device, filter by health, open a device workspace. |
| **Infrastructure → Discovery & NMS → Subnet Discovery** | Scope the SNMP sweep. Platform administrators only. |
| **Administration → Data sources → SNMP Profiles** | Credentials, the vendor OID library, and the configuration generator. |
| **Administration → Data sources → Data Sources** | The per-device coverage matrix. |
| **Administration → Data sources → Sensors** | Collector pool status. Platform administrators only. |
