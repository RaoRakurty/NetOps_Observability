---
title: Configure SNMP discovery
sidebar_label: Configure SNMP discovery
description: Scope a bounded SNMP subnet discovery scan that tries your platform SNMP profiles, and read what the sweep found or refused.
page_type: task
sidebar_position: 5
---

# Configure SNMP discovery

SNMP subnet discovery sweeps the management subnets you name and adds every
host that answers SNMP to the inventory. The scan scope is a platform-level
decision, so the configuration is restricted to platform administrators and the
server validates every range before it sweeps anything.

Discovery has no credentials of its own. SNMP credentials live in one place,
[SNMP Profiles](/onboard-devices/snmp-profiles), and the sweep tries the
**platform-owned** profiles — v1/v2c and v3 — in profile-name order for each
address until one answers. Tenant-owned profiles are never used by the scan: a
scanned device is platform-owned until it is assigned to a tenant. A device the
sweep finds is **bound to the profile that answered** (its `credential_ref` is
set at discovery), so polling uses the credential discovery proved works.

**Every device a sweep finds is monitored and uses the licence.** There is no
per-device monitoring switch: a device in the inventory with a management
address is collected from, up to your licence's device limit (25 on the
Community tier). When there are more devices than the licence covers, the first
ones found are collected from and the rest stay in the inventory marked **Over
licence limit**, with a banner on **Infrastructure → Devices**
saying how many.

:::warning Keep discovery scopes narrow
Because a swept device uses the licence, a wide scope can fill the device limit
with hosts you did not mean to monitor — and the devices you care about, if
they are found later, wait behind them. Sweep only the management subnets of
devices you want collected from. To free a slot, delete the device you do not
want; the next device in line starts being collected from automatically. See
[Licensing](/administration/licence).
:::

Discovery is bounded on purpose: at most 4,096 addresses across at most 32
ranges, 32 concurrent probes, a two-second budget per host, and one sweep per
minute. A configuration that exceeds those bounds is refused with an error
rather than trimmed.

## Where to find it

**Administration → Data sources → Subnet Discovery** is where you set the IP
ranges the scan sweeps, switch scanning on, and read what the last sweep found.
It sits next to **SNMP Profiles**, where the credentials the sweep tries are
kept, and **Telemetry Coverage**. To connect a network management system or a
vendor controller instead, use **Infrastructure → NMS Integrations** (see
[Connect a vendor controller](/infrastructure/nms-integrations)). Subnet
Discovery is platform-wide: a tenant account sees an explanation instead of the
form, and discovered devices appear in **Infrastructure → Devices**
automatically.

## Before you begin

- A platform administrator account. `GET` and `PUT /api/discovery/config` both
  require cross-tenant authority, and the console hides the page from
  tenant-scoped users.
- `ENABLE_SNMP_DISCOVERY` set to `true`. It defaults to `false`. See
  [Feature flags](/reference/feature-flags).
- The management subnets you want swept, in CIDR notation, expanding to no more
  than 4,096 addresses in total. A `/20` is the widest single range that fits.
- At least one **platform-owned** SNMP profile the devices answer to — a v1/v2c
  community or a v3 USM profile — in
  **Administration → Data sources → SNMP Profiles**. See
  [Add an SNMP credential](/onboard-devices/snmp-profiles). With no platform
  profile the sweep is refused rather than probing with `public`, and
  `SNMP_COMMUNITY` is not used by discovery.
- UDP 161 open from Correlix to those subnets. See
  [Connectivity requirements](/reference/connectivity-requirements).

:::caution Narrow the range before you enable discovery
The shipped Compose default for `SNMP_CIDR_RANGES` is `10.0.0.0/8`, which
expands to over sixteen million addresses. Correlix refuses it rather than
sweeping it: the state chip shows **Needs attention** and **Last scan stopped**
carries the refusal. Replace
it with your actual management subnets before enabling discovery.
:::

## Steps

1. Go to **Administration → Data sources → Subnet Discovery**
   (`#/admin/discovery`). The page walks through three numbered steps.
2. **Step 1 — Add SNMP credentials.** The step shows how many platform SNMP
   profiles the scan will try. If it shows **No SNMP profiles**, select
   **Add an SNMP profile** (or **Open SNMP Profiles**) and add one; discovery
   has no community field of its own.
   Each address is tried against the profiles in profile-name order until one
   answers, so name the most common credential so it sorts first.
3. **Step 2 — Choose subnets.** In **Subnets to scan, comma-separated**, enter the
   subnets to sweep, for example `10.20.0.0/24, 10.30.5.0/26`. The meter under
   the field counts the addresses against the 4,096 cap and **Save** stays
   disabled while the total is over it. Turn on **Allow public address ranges**
   only if your network uses public address space internally. Without it, any
   range outside RFC 1918 is refused.
4. **Step 3 — Turn on scanning.** Turn on **Scanning on** and select **Save**.
5. Select **Scan now** to sweep immediately instead of waiting for the next
   cycle. It stays unavailable until scanning is on and saved.

## Result

Saving schedules a sweep and the page reports **Saved. A scan has been
scheduled.** The state chip moves to **Active**, and **Results** shows **Last
scan**, **Devices found** and **Subnets scanned**. While
enabled, Correlix sweeps every five minutes; a manual **Scan now** is
rate-limited to one per minute. The device table lists each device found with
its name, address, vendor and **Answered with** — the SNMP profile that
answered, which is also the profile the device is now bound to.

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

The response carries no credential field: credentials belong to SNMP Profiles,
whose secrets are sealed at rest and never returned. A `PUT` that still carries
a non-empty `community` is refused with `400`.

`"devices": 0` here means the sweep is disabled, not that the subnets are empty.
The two are different facts and the page distinguishes them: a disabled scan
shows the state chip **Off**, and a refused scan shows **Needs attention** with
the refusal under **Last scan stopped**.

## What a discovered device looks like

For each address that answers, Correlix reads `sysName`, then reads
`sysObjectID` and `sysDescr` to resolve the vendor. The inventory row carries
`"source": "snmp"` and a `credential_ref` naming the SNMP profile that
answered.

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

Validation runs before any packet is sent, and the message is what the page
shows under **Last scan stopped** (the API's `last_error`).

| Condition | Message |
|---|---|
| Total expansion over the cap | `ranges expand to more than 4096 addresses — narrow them to your management subnets (a /20 is the widest single range)` |
| A range outside RFC 1918 without the acknowledgement | `"203.0.113.0/24" is not private (RFC 1918) address space — enable "allow non-private ranges" only if your network uses that space internally` |
| Loopback, link-local, multicast or reserved space | `"127.0.0.0/8" is not a scannable unicast range` |
| Not CIDR | `"10.20.0.5" is not valid CIDR notation (e.g. 10.20.0.0/24)` |
| IPv6 | `"2001:db8::/32": only IPv4 ranges are supported` |
| More than 32 ranges | `at most 32 ranges are allowed` |
| Enabled with no range | `at least one CIDR range is required to enable discovery` |
| No platform-owned SNMP profile to try | `discovery sweep refused: no SNMP profiles to try — add the credentials your devices use under Administration → Data sources → SNMP Profiles` |

Loopback, link-local, multicast and reserved space stay refused even with
**Allow public address ranges** on.

## What discovery does not find

- **Devices whose credential is not a platform-owned profile.** A credential
  stored only in a tenant's profile is never tried by the sweep. Add the device
  with [a manual entry](/onboard-devices/add-devices-manually) or an import, or
  store the credential as a platform profile.
- **Devices outside the configured ranges.** Nothing is scanned that you did not
  name.
- **Devices behind an ACL that excludes the Correlix address.** The probe times
  out and the address is treated as not answering.

An empty result means nothing answered in the ranges you scoped. It does not
mean the network is empty.

## Troubleshooting

| Symptom | Cause | What to do |
|---|---|---|
| **Needs attention** with **Last scan stopped** | A range failed validation, or no platform-owned SNMP profile exists | Read the message; correct the range or add a platform SNMP profile |
| **Settings unreadable** instead of the form | The saved configuration could not be read or decrypted | Discovery is disabled until it is re-saved. Save the configuration again; a successful save clears the failure |
| A device is absent and you expect it | No platform profile matches its credential, outside the range, or SNMP not enabled | Check in that order. The sweep tries each platform profile per address in turn |
| A device appears with no vendor | Its enterprise number and description matched no vendor profile | Collection is unaffected. The generic SNMP profile still applies |

## Upgrading from a discovery community

Earlier releases stored a probe community on the discovery configuration
itself. On upgrade, a stored value is migrated once into a platform-owned v2c
SNMP profile named **Migrated discovery community** — a comma-separated list
becomes one profile per community (**Migrated discovery community**,
**Migrated discovery community 2**, …), sealed like any other profile secret.
The discovery configuration is re-saved without it, and the API logs
`discovery community migrated to SNMP profile` with the profile names, never the
secret. The migration is idempotent. Manage the migrated profiles in SNMP
Profiles like any other.

## Related

- [Add an SNMP credential](/onboard-devices/snmp-profiles)
- [Add a device by hand](/onboard-devices/add-devices-manually)
- [Check the data-source coverage matrix](/onboard-devices/data-sources)
- [Connectivity requirements](/reference/connectivity-requirements)
