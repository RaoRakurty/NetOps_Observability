---
title: Send syslog
sidebar_label: Send syslog
description: Point a device's syslog at Correlix, pick a severity threshold, and make the messages attribute to the right device and tenant.
page_type: task
sidebar_position: 3
---

# Send syslog

Syslog turns a device's own log messages into searchable events and into
evidence the correlation engine uses. Link transitions, adjacency changes,
hardware alarms and configuration changes all arrive at the moment the device
emits them, which is what a 60-second metric poll cannot give you.

This is the highest-value plane to configure after metrics, and it is one or two
lines of device configuration.

## Before you begin

- The device is [in the inventory](/onboard-devices/add-devices-manually), so
  its events attribute to a known device.
- UDP or TCP 514 open from the device to Correlix. See
  [Connectivity requirements](/reference/connectivity-requirements).
- The address the device will send from. Use the management or loopback address
  the inventory holds.
- The device's configured hostname, ideally equal to its name in the Correlix
  inventory.

## Steps

1. Set the severity threshold on the device. `informational` is the useful
   setting; see the table below.
2. Set the source interface, so the device sends from the address Correlix knows.
3. Set Correlix as a syslog destination on UDP or TCP 514.
4. Trigger a benign event, or wait for normal activity.
5. Confirm the message arrived in **Explore → Logs**.

### Device configuration

These blocks are the platform's own documented examples, from
`docs/INGESTION.md`. Replace `MONITOR_HOST` with the address of the Correlix
host, and the port with `514` or whatever `SYSLOG_PORT` is set to on your
deployment.

Cisco IOS and IOS-XE:

```text
logging trap informational
logging source-interface Loopback0
logging host MONITOR_HOST transport udp port 5514
```

Juniper Junos:

```text
set system syslog host MONITOR_HOST any info
set system syslog host MONITOR_HOST port 5514
```

A Linux host, in `/etc/rsyslog.d/00-netops.conf`:

```text
*.* @MONITOR_HOST:5514       # UDP
# or for TCP with reliable delivery:
*.* @@MONITOR_HOST:5514
```

Then restart `rsyslog`.

The two blocks below are constructed examples. This repository holds no
validated syslog configuration for these platforms, so they are the conventional
syntax rather than something Correlix has tested. Check each against your own OS
version.

Arista EOS:

```text
logging host MONITOR_HOST
logging source-interface Loopback0
logging trap informational
```

Fortinet FortiOS:

```text
config log syslogd setting
    set status enable
    set server "MONITOR_HOST"
    set port 514
    set mode udp
end
```

### Choosing a severity threshold

The threshold controls what the device sends. Correlix keeps everything it
receives.

| Threshold | Effect |
|---|---|
| `errors` (3) and above | Misses link, protocol and configuration events, many of which log at 4 to 6 |
| `informational` (6) | Captures link, protocol, hardware and configuration events |
| `debugging` (7) | Adds debug output. Use during active troubleshooting only |

Facility does not matter. Any facility is accepted, so there is no need to
change the device's default.

### UDP or TCP

Both are accepted on port 514. UDP is the near-universal device default and does
not retransmit, so a congested or policed path drops messages with no error
anywhere. Where the platform supports it and the logs matter, use TCP. The
listener accepts up to 1,024 concurrent TCP connections; a fleet larger than
that needs the limit raised before it grows into it, because a refused
connection is invisible from the device side.

## Result

The message appears in **Explore → Logs** with the **Syslog** source selected, attributed
to the device, with the vendor label and the parsed fields its format supports.
Within 15 minutes the **Syslog** column for that device turns green on
[the coverage matrix](/onboard-devices/data-sources).

Both RFC 3164 and RFC 5424 are parsed.

### What Correlix does to the message

| Step | Behaviour |
|---|---|
| Hostname | The hostname the sender wrote is kept, never overwritten with the peer address. It is the only device identifier that survives NAT |
| Timestamp | The device's own timestamp is kept, never replaced with the receive time |
| Time zone | RFC 3164 carries no zone and no year, so it is read as UTC. Device clocks must run UTC. RFC 5424 messages carry their own offset and are unaffected |
| Vendor label | Derived from the message signature: `fortinet`, `paloalto`, `juniper`, `arista`, `cisco`, and `nokia` from the SR Linux body shape |
| Structured parse | `ios_style.v1` for the `%FACILITY-SEVERITY-MNEMONIC` shape used by Cisco IOS, NX-OS and Arista EOS. `srlinux.v1` for Nokia SR Linux. FortiOS key-value bodies are parsed into `fgt.*` |
| Severity | The level embedded in the body overrides the transport priority when it is stronger, so a `notice` frame carrying `W:` is stored as a warning |
| Coverage | Every message carries `parser_status`, reading `parsed` or `unparsed` |

An `unparsed` message is still stored, searchable and attributed. Only the
derived fields are missing.

FortiOS traffic logs additionally carry the firewall's own application
classification, which is lifted to a vendor-neutral field and feeds application
analytics.

## Attribution and tenancy

Attribution is by the hostname in the message, falling back to the source
address. The identity is matched against a table exported from the device
inventory, keyed by device name and device address.

Three consequences worth knowing before you configure a fleet:

- **A hostname the inventory does not know produces no tenant.** The message is
  stored untagged and visible only to platform principals. It is never assigned
  to a guessed tenant.
- **An identity that maps to more than one tenant is dropped from the table
  entirely.** NAT can collapse several devices onto one address, so the
  ambiguous case fails closed rather than picking one.
- **Message content never sets tenancy.** A FortiGate `devname=` field can
  refine the device name, and only to a name the inventory already maps to the
  tenant the hostname resolved to. It cannot move the event to another tenant.

The correlation consumer re-runs the same lookup and refuses any event whose
tenant it cannot reproduce.

:::caution The listener has no authentication
Port 514 accepts messages from anything that can route to it, and the hostname
in a message is an unverified claim by the sender. A sender that both reaches
the port and knows a real device hostname lands in that device's tenant, because
the registry legitimately maps that hostname there. No application-layer check
closes this. The hardening, in order of effort: restrict the published port to
the management network with a host firewall rule, then move devices to syslog
over TLS with client certificates.
:::

## Troubleshooting

| Symptom | Cause | What to do |
|---|---|---|
| Nothing arrives | The device is not sending | Check the device's own counters, for example `show logging` on Cisco |
| Nothing arrives | The path is blocked | Confirm UDP 514, or TCP 514 if you configured TCP, on every firewall between the device and Correlix |
| Nothing arrives | The threshold is too strict | A quiet, healthy device at `errors` legitimately sends nothing. Set `informational` and trigger a test event |
| Messages arrive but attribute to no device | The hostname matches no inventory name or address | Align the device hostname with the inventory name, or set a source address the inventory holds |
| Messages arrive but are invisible to a tenant operator | The identity is unknown or ambiguous, so the event is untagged | Add the device to the inventory, or resolve the duplicate address |
| Gaps under load | UDP loss on the path | Move that device to TCP, or check for congestion and policing |
| A vendor's fields are missing | No structured parser matches that format | The message is still stored and searchable. `parser_status` reads `unparsed` |

## Related

- [Send SNMP traps](/send-data/traps)
- [Check the data-source coverage matrix](/onboard-devices/data-sources)
- [Search logs](/explore/logs)
- [Connectivity requirements](/reference/connectivity-requirements)
