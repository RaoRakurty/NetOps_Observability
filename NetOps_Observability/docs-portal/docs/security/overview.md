---
title: Security & Compliance overview
sidebar_label: Overview
sidebar_position: 1
description: Vulnerability, threat, and compliance posture across your fleet — agentless, from the telemetry you already collect.
---

# Security & Compliance

Correlix tracks the **security posture** of your network devices alongside their health. Everything in this section is **agentless**: it is computed from telemetry the platform already collects (SNMP inventory data, flow records) plus reference data you provision — no scanners to deploy, no agents to install on devices.

## What's in it

| Feature | Console path | What it answers |
| --- | --- | --- |
| **[Vulnerability Management](/security/vulnerability-management)** | <kbd>Security → Vulnerability Management</kbd> | Which devices run an OS version with known CVEs — and which of those CVEs are actively exploited in the wild |
| **[Threat Detection](/security/threat-detection)** | <kbd>Security → Threat Detection</kbd> | Which sources look like they are scanning the network, and what traffic touches high‑risk service ports |
| **[Compliance Monitoring](/security/compliance-monitoring)** | <kbd>Security → Compliance Monitoring</kbd> | Where the live network drifts from your declared inventory, and which devices violate management‑plane policy baselines |

## Where the data comes from

Each board reads a different plane of telemetry you onboard once and reuse everywhere:

- **Vulnerability Management** needs the **SNMP inventory** — the vendor and OS version each device reports — matched against an **advisory feed you provision** (NVD data, optionally the CISA Known Exploited Vulnerabilities catalog). Nothing is bundled or auto‑downloaded, so the platform keeps working fully offline.
- **Threat Detection** needs **[flow records](/send-data/flows)** (NetFlow / IPFIX / sFlow). No new collection is required — every panel is computed from the flows you already export for traffic analytics.
- **Compliance Monitoring** needs your **device inventory** ([onboarded devices](/onboard-devices/overview)); drift checks additionally use an external **Source of Truth** connection, and management‑plane checks use your [SNMP credential profiles](/onboard-devices/snmp-profiles).

The more planes you've onboarded, the more the security views can see. If a board is empty, it tells you exactly what to provision — the empty states are onboarding instructions, not errors.

## "Cannot assess" is never "compliant"

All three boards follow the same honesty rule: **a check that could not run is reported as a gap, not a pass.**

- A device whose OS version can't be read appears under **Coverage gaps** on the Vulnerability Management board — it is *unassessed*, not clean.
- A compliance check whose data source isn't connected renders as **inactive** with the reason, never as passing.
- Absence of findings on an unassessed device means *unknown*, not *safe*.

When you review posture, always read the coverage‑gap and inactive‑check panels alongside the findings — they tell you how much of the fleet the numbers actually cover.

## Required access

The Security boards require a role with **read access to Infrastructure**. Provisioning the vulnerability advisory feed additionally requires shell access to the Correlix host (it is an operator‑run script, by design — see [Vulnerability Management](/security/vulnerability-management)).

## Recommended onboarding order

1. **Onboard devices over SNMP** ([overview](/onboard-devices/overview)) — this alone activates Compliance Monitoring's policy checks and prepares Vulnerability Management.
2. **Enable flow export** ([flow records](/send-data/flows)) — this activates Threat Detection.
3. **Provision the advisory feed** ([procedure](/security/vulnerability-management)) — this activates CVE matching and the known‑exploited compliance check.
4. Optionally **connect an external Source of Truth** ([Automation & Source of Truth](/automation/overview)) — this activates the intent‑drift compliance checks.

:::tip
[Syslog](/send-data/syslog) and other event planes aren't consumed by these three boards directly, but they feed the platform's incident correlation — onboard them anyway so security findings land in a fully observable context.
:::
