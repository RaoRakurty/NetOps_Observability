---
title: Syslog
sidebar_label: Syslog
sidebar_position: 3
description: Point your devices' syslog at Correlix so log events land on the timeline and feed correlation.
---

# Syslog

Syslog turns your devices' own log messages into **searchable events** and into **signals** the correlation engine uses to confirm root cause. It's the highest-value plane to onboard after metrics: link up/down, protocol adjacency changes, hardware alarms, and configuration changes all arrive as first-class events the moment they happen.

## How it works

- The syslog listener accepts both classic **RFC 3164** and structured **RFC 5424** messages, over **UDP 514** and **TCP 514**.
- Each message is attributed to a device primarily by the **hostname carried inside the message** (which survives NAT). Messages whose format carries no usable hostname are keyed to the packet's **source IP** instead.
- Logs from the major vendor families — **Cisco, Arista, Juniper, Nokia, Fortinet, Palo Alto** — are automatically recognized by their log signature and labeled by vendor, so you can filter by vendor in Log Search. Fortinet-format firewall logs (`key="value"` bodies) are additionally parsed **field by field**: the device name, severity, and — on traffic logs — the firewall's own application classification are all extracted and used for attribution and application analytics.
- When a message body carries its own severity level, that overrides the transport-level severity — so what you see in Log Search reflects what the device actually said.

## Before you begin

1. The device is [onboarded](/onboard-devices/overview), so its events attribute to a known device.
2. **UDP 514** (or **TCP 514**) is open from the device to Correlix on any firewall/ACL in the path — see [Connectivity requirements](/reference/connectivity-requirements).
3. You know which source address the device will send from (management IP or loopback) and, ideally, the device's configured hostname matches its name in Correlix's inventory.

## Step 1 — Configure the device

Set Correlix as a syslog destination. Examples for the major vendor families (adapt interface names and addresses to your network; `CORRELIX_IP` is your Correlix instance):

```text
! Cisco IOS / IOS-XE
logging trap informational
logging source-interface Loopback0
logging host CORRELIX_IP
```

```text
! Arista EOS
logging host CORRELIX_IP
logging source-interface Loopback0
logging trap informational
```

```text
# Juniper Junos
set system syslog host CORRELIX_IP any info
set system syslog host CORRELIX_IP source-address <loopback-ip>
```

```text
# FortiGate (FortiOS)
config log syslogd setting
    set status enable
    set server "CORRELIX_IP"
    set port 514
    set mode udp
end
```

```bash
# Linux host — rsyslog forwarder (/etc/rsyslog.d/00-correlix.conf)
*.* @CORRELIX_IP:514        # UDP
# or, for reliable delivery over TCP:
*.* @@CORRELIX_IP:514
# then: systemctl restart rsyslog
```

**UDP or TCP?** UDP is the near-universal default and fine for most fleets. Syslog over UDP is lossy by design — on WAN paths or for devices whose logs you can't afford to drop, prefer TCP where the platform supports it.

## Step 2 — Choose a severity threshold

The threshold controls what the *device* sends; Correlix keeps everything it receives.

| Threshold | Effect | Recommendation |
| --- | --- | --- |
| `errors` (3) and above only | Misses link, protocol, and config events (many log at 4–6) | Too strict |
| **`informational` (6)** | Captures link/protocol/hardware/config events | **Recommended** |
| `debugging` (7) | Includes debug chatter | Only during active troubleshooting |

Facility (e.g. Cisco's default `local7`) doesn't matter to Correlix — any facility is accepted; there's no need to change it.

## Step 3 — Verify

1. Trigger a benign event (e.g. enter and exit config mode, or bounce an unused interface), or just wait for normal log activity.
2. <kbd>Administration → Data Collection → Data Sources</kbd> — the device's **Syslog** column turns green.
3. <kbd>Logs → Log Search</kbd> — pick the **Syslog (devices)** source, search for the device name, and confirm recent messages appear with the right severity. See [Log Search](/explore/logs).
4. <kbd>Monitoring → Events</kbd> — notable syslog events (link changes, protocol transitions) show on the event timeline.

## Troubleshooting

**Nothing arriving at all**

1. Confirm the device is actually sending: most platforms have a counter or debug (e.g. Cisco `show logging` lists configured hosts and message counts).
2. Check the path: UDP 514 open on every firewall/ACL between the device and Correlix? If you configured TCP, is TCP 514 open?
3. Check the severity threshold — if it's `errors`, a quiet, healthy device may legitimately send nothing. Set `informational` and trigger a test event.
4. Verify the destination IP is your Correlix instance (not a stale NMS address).

**Messages arrive but attribute to the wrong device (or an unknown one)**

- Correlix keys syslog to the **hostname in the message**. If the device's configured hostname doesn't match its name in the inventory, events won't attach to it. Fix either side so they match.
- If messages carry no hostname, attribution falls back to the **source IP** — make sure the device sends from the address Correlix knows it by (set a `source-interface` / `source-address` as in the examples above), and account for any NAT in the path.

**Gaps in the log stream**

- UDP loss under load is expected behavior of the protocol, not the platform. Switch that device to TCP, or check for congestion/policing on the path.

**Firewall logs missing fields**

- Fortinet-format logs are parsed field-by-field automatically. Other vendors' firewall logs are ingested and vendor-labeled but shown as message text. On FortiGate, confirm the device is logging the events you expect (e.g. traffic logs require logging enabled on the policy).

## Next

- **[Send SNMP traps](/send-data/traps)** — the second push plane.
- **[Search and save log queries](/explore/logs)**.
