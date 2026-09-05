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

## What each step gives you

Metrics arrive as soon as a device is in the inventory with a credential that
answers. The other three planes are configured on the device and covered in
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
