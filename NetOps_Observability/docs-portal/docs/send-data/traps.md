---
title: SNMP traps
sidebar_label: SNMP traps
sidebar_position: 4
description: Receive asynchronous SNMP trap notifications from your devices.
---

# SNMP traps

SNMP **traps** are asynchronous notifications a device sends the moment something happens (a link flaps, a PSU fails, a neighbor drops) — you don't have to wait for the next poll. Correlix decodes traps using its MIB library and turns high‑value ones into events and correlation signals.

## Configure a device to send traps

Point each device's trap host at Correlix and send on UDP **162**:

```bash
# Cisco IOS / IOS-XE
snmp-server host <correlix-trap-ip> version 2c <community>
snmp-server enable traps

# Arista EOS
snmp-server host <correlix-trap-ip> version 2c <community>
snmp-server enable traps

# Juniper Junos
set snmp trap-group correlix targets <correlix-trap-ip>
```

- Use **SNMP v2c** or **v3** to match your security posture.
- Enable the trap categories you care about (link, environment, routing, config).

## MIB‑driven decoding

Correlix decodes traps against a MIB index, so a raw OID becomes a readable event with the right severity. Unrecognized trap OIDs are still captured as generic device alarms (nothing is silently dropped) and default to a low severity until you add the MIB.

## Verify

1. <kbd>Administration → Data Collection → Data Sources</kbd> — the **Traps** column turns green.
2. <kbd>Monitoring → Events</kbd> — trap events appear on the timeline (a test link flap is an easy way to confirm).

## Next

- **[Send flow records](/send-data/flows)**.
- **[Monitoring & alerting](/monitoring/overview)**.
