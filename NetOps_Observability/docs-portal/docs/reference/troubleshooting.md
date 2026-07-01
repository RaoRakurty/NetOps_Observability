---
title: Troubleshooting onboarding
sidebar_label: Troubleshooting
sidebar_position: 3
description: Fix the common issues when a device won't onboard or a data source stays empty.
---

# Troubleshooting onboarding

Most onboarding issues are reachability or credentials. Work top to bottom.

## A device won't discover / stays down

1. **Reachability** — can Correlix reach the device on **UDP 161**? Check firewalls/ACLs on the path.
2. **SNMP enabled** — is SNMP turned on and allowed from Correlix's source address on the device?
3. **Credential** — does the community/user match, and is the device v2c or v3? Try a per‑device credential. See [SNMP profiles & credentials](/onboard-devices/snmp-profiles).
4. **In range** — for discovery, is the device inside the scanned **CIDR**?

## "SNMP metrics" stays "No data"

- Same checks as above — the device is known but not answering polls.
- Confirm the **credential is attached** to that device (per‑device or default).

## "Syslog" or "Traps" stays "No data"

1. Confirm the device is **configured to send** to Correlix (host + port **514**/**162**).
2. Confirm the **source IP** the device sends from is one Correlix associates with that device (watch for NAT/loopback).
3. Check the path allows **UDP 514 / 162** to Correlix.
4. Generate a test event (e.g. bounce a test interface) and look in <kbd>Logs → Log Search</kbd> / <kbd>Monitoring → Events</kbd>.

## "Flows" stays "No data"

1. Confirm flow **export is enabled** on the device to Correlix's collector IP/port (**2055/4739/6343**).
2. On sampled protocols (sFlow), confirm the **sampling rate** is set.
3. Check the path allows the flow UDP port.

## A metric panel shows "—"

This is **honest, not an error** — that specific metric isn't being collected yet. Common causes: interface **speed** not read (utilization needs it), or a plane (flows) not configured. Confirm on the [Data Sources coverage matrix](/onboard-devices/data-sources).

## Utilization shows 0%

Usually the interface is genuinely idle (little traffic ÷ link speed ≈ 0%). Utilization reflects the last polling window; generate traffic on the link to see it move. See the live sparkline on [WAN Interface Metrics](/infrastructure/wan-interface-metrics).

## Still stuck?

Ask **[Correlix AI](/correlix-ai/overview)** — e.g. *"why isn't leaf1 collecting SNMP?"* — or check the [Connectivity requirements](/reference/connectivity-requirements).
