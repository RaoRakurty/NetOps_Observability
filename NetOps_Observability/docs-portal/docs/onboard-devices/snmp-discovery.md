---
title: Configure SNMP discovery
sidebar_label: Configure SNMP discovery
description: Scope a bounded SNMP subnet discovery scan, choose the probe communities it tries, and read what the sweep found or refused.
page_type: task
sidebar_position: 5
---

# Configure SNMP discovery

SNMP subnet discovery sweeps the management subnets you name and adds every
host that answers SNMP to the inventory. The scan scope is a platform-level
decision, so the configuration is restricted to platform administrators and the
server validates every range before it sweeps anything.

Discovery is bounded on purpose: at most 4,096 addresses across at most 32
ranges, 32 concurrent probes, a two-second budget per host, and one sweep per
minute. A configuration that exceeds those bounds is refused with an error
rather than trimmed.

## Before you begin

- A platform administrator account. `GET` and `PUT /api/discovery/config` both
  require cross-tenant authority, and the console hides the card from
  tenant-scoped users.
- `ENABLE_SNMP_DISCOVERY` set to `true`. It defaults to `false`. See
  [Feature flags](/reference/feature-flags).
- The management subnets you want swept, in CIDR notation, expanding to no more
  than 4,096 addresses in total. A `/20` is the widest single range that fits.
- The read-only community strings the devices answer to. Discovery probes with
  SNMP v2c only.
- UDP 161 open from Correlix to those subnets. See
  [Connectivity requirements](/reference/connectivity-requirements).

:::caution Narrow the range before you enable discovery
The shipped Compose default for `SNMP_CIDR_RANGES` is `10.0.0.0/8`, which
expands to over sixteen million addresses. Correlix refuses it rather than
sweeping it, and the refusal appears on the card as **Sweep refused**. Replace
it with your actual management subnets before enabling discovery.
:::

## Steps

1. Go to **Infrastructure → Discovery & NMS**.
2. Select **Subnet Discovery**. The same card also appears under
   **Administration → Data Collection → Sensors**.
3. In **Scan ranges — CIDR, comma-separated**, enter the subnets to sweep, for
   example `10.20.0.0/24, 10.30.5.0/26`. The meter under the field counts the
   addresses against the 4,096 cap and **Save changes** stays disabled while
   the total is over it.
4. In **Probe communities, comma-separated**, enter the read-only communities.
   Each address is tried against them in order until one answers, so put the
   most common one first. Leave the field blank to keep the communities already
   stored.
5. Turn on **Discovery enabled**.
6. Turn on **Allow non-private ranges** only if your network uses public address
   space internally. Without it, any range outside RFC 1918 is refused.
7. Select **Save changes**.
8. Select **Scan now** to sweep immediately instead of waiting for the next
   cycle.

## Result

Saving schedules a sweep and the card reports **Saved — a sweep has been
scheduled.** The state chip moves to **Active**, and the header shows **Last
sweep**, **Devices discovered** and the number of ranges in scope. While
enabled, Correlix sweeps every five minutes; a manual **Scan now** is
rate-limited to one per minute.

Read the same state over the API. Captured from the lab stack, where discovery
is off and no ranges are configured:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/discovery/config
```

```json
{
  "config": {
    "enabled": false,
    "ranges": [],
    "community_set": true,
    "allow_non_private": false,
    "interval_sec": 0
  },
  "limits": {
    "max_hosts": 4096,
    "max_ranges": 32
  },
  "stats": {
    "last_poll": "2026-09-03T04:23:06.32218124Z",
    "devices": 0
  }
}
```

`community_set` is the only thing the response says about the communities. The
values are sealed at rest and the API never returns them.

`"devices": 0` here means the sweep is disabled, not that the subnets are empty.
The two are different facts and the card distinguishes them: a disabled scan
shows the state chip **Off**, and a refused scan shows **Needs attention** with
the refusal text.

## What a discovered device looks like

For each address that answers, Correlix reads `sysName`, then reads
`sysObjectID` and `sysDescr` to resolve the vendor. The inventory row carries
`"source": "snmp"`.

The device id is the sanitized `sysName` with an eight-character hash of the
address appended, for example `core-sw1-a94f2c1b`. The address suffix is
deliberate: a factory-default `sysName` repeats across a fleet, and two devices
that folded to the same id used to overwrite each other silently. The unhashed
`sysName` is kept as the device **name**, which is what pushed telemetry is
attributed by.

Addresses already in the inventory from any source are not probed. Discovery
looks only for devices it does not have, so it cannot duplicate a device you
added by hand or imported.

Found devices are sticky across sweeps. A device that misses one probe does not
disappear from the inventory.

## The refusals, in the server's own words

Validation runs before any packet is sent, and the message is what the card
shows.

| Condition | Message |
|---|---|
| Total expansion over the cap | `ranges expand to more than 4096 addresses — narrow them to your management subnets (a /20 is the widest single range)` |
| A range outside RFC 1918 without the acknowledgement | `"203.0.113.0/24" is not private (RFC 1918) address space — enable "allow non-private ranges" only if your network uses that space internally` |
| Loopback, link-local, multicast or reserved space | `"127.0.0.0/8" is not a scannable unicast range` |
| Not CIDR | `"10.20.0.5" is not valid CIDR notation (e.g. 10.20.0.0/24)` |
| IPv6 | `"2001:db8::/32": only IPv4 ranges are supported` |
| More than 32 ranges | `at most 32 ranges are allowed` |
| Enabled with no range | `at least one CIDR range is required to enable discovery` |

Loopback, link-local, multicast and reserved space stay refused even with
**Allow non-private ranges** on.

## What discovery does not find

- **Devices that answer only SNMPv3.** The sweep probes with v2c. Add those
  devices with [a manual entry](/onboard-devices/add-devices-manually) or an
  import; once in the inventory they poll with their v3 credential normally.
- **Devices outside the configured ranges.** Nothing is scanned that you did not
  name.
- **Devices behind an ACL that excludes the Correlix address.** The probe times
  out and the address is treated as not answering.

An empty result means nothing answered in the ranges you scoped. It does not
mean the network is empty.

## Troubleshooting

| Symptom | Cause | What to do |
|---|---|---|
| The card shows **Sweep refused** | A range failed validation | Read the message on the card and correct the range |
| The card shows a read failure instead of the form | The saved configuration could not be read or decrypted | Discovery is disabled until it is re-saved. Save the configuration again; a successful save clears the failure |
| A device is absent and you expect it | Wrong community, v3-only device, outside the range, or SNMP not enabled | Check in that order. The sweep tries each community per address in turn |
| A device appears with no vendor | Its enterprise number and description matched no vendor profile | Collection is unaffected. The generic SNMP profile still applies |

## Related

- [Add an SNMP credential](/onboard-devices/snmp-profiles)
- [Add a device by hand](/onboard-devices/add-devices-manually)
- [Check the data-source coverage matrix](/onboard-devices/data-sources)
- [Connectivity requirements](/reference/connectivity-requirements)
