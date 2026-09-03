---
title: Add a device by hand
sidebar_label: Add a device by hand
description: Add one device to the inventory by id and management address, and read the response that says whether it was created or absorbed into an existing record.
page_type: task
sidebar_position: 6
---

# Add a device by hand

Adding a device by hand puts one entry in the inventory with an id and a
management address. Polling starts on the next cycle using the credential the
device references, or the deployment-wide default community.

Use this instead of [discovery](/onboard-devices/snmp-discovery) for a device
that answers only SNMPv3, a device outside the ranges you sweep, a network where
scanning is not welcome, or a device you want to pre-stage before it is
reachable. A pre-staged device reads **Down** until SNMP answers, then fills in
on its own.

## Before you begin

- A role with `infrastructure` write permission.
- The device's management IP or a resolvable hostname.
- A [credential](/onboard-devices/snmp-profiles) that the device answers to,
  and the profile id or name to reference from the device record.
- UDP 161 open from Correlix to the device. See
  [Connectivity requirements](/reference/connectivity-requirements).

## Steps

1. Go to **Infrastructure → Devices**.
2. Select **+ Add device**.
3. On the **Identity** step, enter a **Device ID**. Both fields on this step are
   required.
4. Enter the **Address**, an IP or a resolvable hostname. Correlix polls this
   address.
5. Go to the **Classification** step.
6. Enter a **Display name**, or leave it blank. This is the name pushed
   telemetry is attributed by, so match the device's configured hostname.
7. Leave **Vendor** blank unless you want to override what SNMP reports.
   Correlix resolves the vendor from `sysObjectID` on the first poll.
8. Select **Add device**.

To do the same over the API:

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"id":"spine1","name":"spine1","address":"172.40.40.11","credential_ref":"core-switches"}' \
  http://localhost:8000/api/devices
```

## Result

The device appears in the inventory table, which reloads every 30 seconds. Its
**Source** badge reads **Manual**. Within a poll cycle the **Type** and
**Manufacturer** columns fill in from SNMP, and the **Polled** column updates.

Captured from the lab stack after two devices were added this way:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/devices
```

```json
[
  {
    "id": "spine1",
    "name": "spine1",
    "address": "172.40.40.11",
    "vendor": "nokia",
    "os": "SR Linux",
    "type": "switch",
    "tenant_id": "t_d3d501aa08e2395893b378a453b8af67",
    "source": "manual",
    "last_seen": "2026-09-03T02:58:15.80813818Z"
  },
  {
    "id": "spine2",
    "name": "spine2",
    "address": "172.40.40.12",
    "vendor": "nokia",
    "os": "SR Linux",
    "type": "switch",
    "tenant_id": "t_d3d501aa08e2395893b378a453b8af67",
    "source": "manual",
    "last_seen": "2026-09-03T02:58:15.839914873Z"
  }
]
```

`tenant_id` is stamped from your token. A tenant-scoped caller cannot assign a
device to another tenant, and any `tenant_id` in the request body is ignored.

## When the create is absorbed

Correlix merges records that share an identity token: a management address, a
serial, or a normalized name. A create that lands on an existing device is
absorbed rather than written as a second row, and the response says so.

| Status | Meaning | Headers |
|---|---|---|
| `201` | A new row was written under the id you asked for | `X-Device-Canonical-Id` |
| `200` | The create was absorbed into an existing device. No row was written under your id | `X-Device-Requested-Id` and `X-Device-Canonical-Id` |

Read `X-Device-Canonical-Id` on every create. A `200` means the device exists
under a different id, and telemetry that carries the name you asked for will not
attribute to it.

Omitting `id` is allowed. Correlix derives one from the name and address using
the same rule discovery uses: the sanitized name with an eight-character hash of
the address appended. A request with no id, no name and no address is refused.

## Reading the inventory

| Column | What it carries |
|---|---|
| **Device** | Status dot and device id |
| **Name** | Display name |
| **IP address** | The polled management address |
| **Type** | Router, Switch, Firewall, Load balancer, AP, WLC, Cloud GW or Generic |
| **Manufacturer** | The vendor resolved from `sysObjectID` or `sysDescr` |
| **Site** | Site assignment, editable when Correlix is the site authority |
| **Description** | Model or OS description |
| **Source** | Manual, SNMP, Static or Source of Truth |
| **Polled** | Time of the last heartbeat |

The status dot has three states, computed from the heartbeat age and the active
alerts:

| State | Condition |
|---|---|
| **Up** | Heartbeat within 5 minutes and no active alert on the device |
| **Degraded** | Heartbeat older than 5 minutes, or the device has an active alert |
| **Down** | No heartbeat for more than 15 minutes |

**Up** is a statement about the heartbeat and the alert list together. When the
alert query fails, the page says so, because **Up** would otherwise be read as
healthy on evidence that was not gathered.

## Troubleshooting

| Symptom | Cause | What to do |
|---|---|---|
| Stays **Down** with no facts filled in | Correlix cannot reach UDP 161 at that address | Check the address, then the firewalls and device ACLs on the path |
| Stays **Down** but reachable from elsewhere | The referenced credential does not match the device | Check `credential_ref` and re-save the profile secret |
| **Up** but the manufacturer is empty | The enterprise number and description matched no vendor profile | Collection is unaffected. Set the vendor on the record if you want it labelled |
| The create returned `200` | Dedupe absorbed it | Use the id in `X-Device-Canonical-Id`, or remove the record that holds the address |
| Syslog from the device attributes nowhere | The hostname in the message matches no inventory name or address | Align the device hostname with the inventory name. See [Send syslog](/send-data/syslog) |

## Related

- [Add an SNMP credential](/onboard-devices/snmp-profiles)
- [Configure SNMP discovery](/onboard-devices/snmp-discovery)
- [Verify a device is being monitored](/onboard-devices/verify-monitoring)
- [Send data to Correlix](/send-data/overview)
