---
title: What Correlix does
sidebar_label: What Correlix does
description: What Correlix collects, what it decides from that data, what it refuses to claim, and the four moves that get a device reporting.
page_type: concept
sidebar_position: 1
---

# What Correlix does

Correlix collects telemetry from network devices, groups the observations that share
a cause into one RCA case, names the seam that owns the fault, and shows the
evidence behind the verdict. It reads devices over standard protocols and
receives what devices push, so nothing is installed on a router, a switch or a
firewall.

## How it works

### It collects

Correlix runs a pool of collectors, each one a named source with its own health.
Some of them read the device (SNMP v2c and v3, gNMI, NETCONF, LLDP and CDP
neighbor discovery, tunnel state, STAMP and ICMP measurement); the rest receive
what the device sends (syslog, SNMP traps, flow records). Controller and NMS
integrations add what a vendor controller knows that the device itself does not
report, and the security scanners add findings about the same assets. The full
list of what one device can feed is in
[Core concepts](/getting-started/concepts); what a given device is actually
feeding today is on
[Data sources and coverage](/onboard-devices/data-sources).

Every collector reports its own state, so a source that is not answering is
visible as a source that is not answering, not as a quiet network. On the lab
stack, the `snmpv2c` collector reports `2/2 targets did not answer` when the
devices refuse SNMP, and Correlix raises `CollectorAllTargetsUnreachable`
against the collector rather than reporting the devices as healthy.

### It correlates

Observations from different collectors that share a time window and a network
relationship become one RCA case with a proposed cause, a set of affected
entities and a graded verdict. The bar is fixed and it is not a majority vote: a
case reads **confirmed** only when at least two measurement classes agree, seen
by at least two observers that share no measurement authority. One loud stream
stays **suspected**, and a case that cannot clear the bar stays **undetermined**
and names the evidence it lacks. [Core concepts](/getting-started/concepts)
explains the model; [Read an RCA case](/investigate/read-an-rca-case) walks a
real one.

### It names an owner

A fault is attributed to a **seam**, the point where responsibility for
forwarding the packet changes hands. Naming the seam is what separates "open an
internal ticket" from "call the carrier". The owner is one of a closed set of
parties (network operations, ISP, carrier, cloud provider, colocation provider,
SD-WAN vendor, application team). When the seam has not been narrowed at all,
the case says so and reads *Not yet narrowed*, rather than naming a party the
evidence does not support.

## What it does not do

- **It does not change device configuration.** SNMP polling is read-only, and
  the collectors that log in to a device run read-only commands.
- **It does not report an unmeasured value as zero.** A panel with no value
  means the metric is not collected. See
  [Honest states](/reference/honest-states).
- **It does not claim a cause it cannot evidence.** An undetermined case is
  labelled undetermined, with the missing evidence named.
- **It does not replace a SIEM.** Security findings are a class of evidence in
  correlation, not a general-purpose log-security product. See
  [Security overview](/security/overview).

## Getting a device reporting

The order is the same for one device and for a fleet.

| Move | Where | Page |
|---|---|---|
| Store a credential | **Administration → Data Collection → SNMP Profiles** | [SNMP profiles and credentials](/onboard-devices/snmp-profiles) |
| Add or discover devices | **Infrastructure → Devices** | [Add devices manually](/onboard-devices/add-devices-manually), [Discover devices](/onboard-devices/snmp-discovery) |
| Point pushed telemetry at Correlix | Device CLI | [Syslog](/send-data/syslog), [Traps](/send-data/traps), [Flows](/send-data/flows) |
| Confirm collection | **Administration → Data Collection → Data Sources** | [Data sources and coverage](/onboard-devices/data-sources) |

Nothing downstream needs enabling. Dashboards, monitors, anomaly detection,
topology and correlation all run on whatever has been onboarded.

## What you need before you start

| Requirement | Why |
|---|---|
| An administrator account | Credentials, devices and data sources are administrative objects. |
| The console address | The console is served on TCP port 8000 of its host unless the installer was given another port. |
| Reachability from Correlix to the device management address | SNMP polling uses UDP 161; reachability probes use ICMP. |
| SNMP enabled on the device, v2c community or SNMPv3 user | Device, interface and protocol metrics are read over SNMP first. |
| The credential values | Entered once, stored encrypted, never displayed again. |
| Firewall openings on the path | UDP 161 outbound; UDP 514, 162 and the flow ports inbound. The authoritative table is [Connectivity requirements](/reference/connectivity-requirements). |

Use a read-only community or user. Prefer SNMPv3 with authPriv where the
platform supports it.

## Related

- [Core concepts](/getting-started/concepts)
- [Onboard your first device](/getting-started/quickstart)
- [Connectivity requirements](/reference/connectivity-requirements)
- [Operator guide](/noc-guide/overview)
