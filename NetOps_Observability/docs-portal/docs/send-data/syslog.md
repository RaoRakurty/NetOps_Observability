---
title: Syslog
sidebar_label: Syslog
sidebar_position: 3
description: Point your devices' syslog at Correlix so log events land on the timeline and feed correlation.
---

# Syslog

Syslog turns your devices' own log messages into **events** on the Correlix timeline and into **signals** the correlation engine can use. It's one of the highest‑value planes to onboard after metrics.

## Configure a device to send syslog

On each device, set the syslog destination to Correlix's syslog collector:

- **Destination** — your Correlix syslog endpoint (host/IP).
- **Port / protocol** — UDP **514** (default), or TCP where supported.
- **Severity** — send at least `informational`/`notice` and above so you capture link, protocol, and hardware events.

Vendor CLI examples (adapt to your platform):

```bash
# Cisco IOS / IOS-XE
logging host <correlix-syslog-ip>
logging trap informational

# Arista EOS
logging host <correlix-syslog-ip>
logging level all informational

# Juniper Junos
set system syslog host <correlix-syslog-ip> any info
```

:::info Source IP matters
Correlix identifies the sending device by the syslog **source address**. Make sure devices send from an address Correlix knows (their management IP). If your devices NAT or use a loopback, account for that so events attribute to the right device.
:::

## Verify

1. <kbd>Administration → Data Collection → Data Sources</kbd> — the device's **Syslog** column turns green.
2. <kbd>Logs → Log Search</kbd> — search for the device; recent messages appear.
3. <kbd>Monitoring → Events</kbd> — notable syslog events show on the event timeline.

## What it unlocks

- Link up/down, protocol adjacency changes, hardware alarms, and config‑change events as first‑class events.
- Stronger **correlation** — a syslog event that lines up with a metric anomaly raises verdict confidence.

## Next

- **[Send SNMP traps](/send-data/traps)** and **[flows](/send-data/flows)**.
- **[Search and save log queries](/explore/logs)**.
