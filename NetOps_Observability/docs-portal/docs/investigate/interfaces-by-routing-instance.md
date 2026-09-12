---
title: View interfaces by routing instance
description: Read one device's interfaces in the vendor's own dialect, grouped only where the interface-to-instance binding is actually collected.
page_type: task
sidebar_position: 10
---

# View interfaces by routing instance

This tab answers "which interfaces are in which routing instance on this
device", in the word that device's vendor uses, and it says plainly when the
binding is not collected instead of inventing a default group.

## Before you begin

- `infrastructure:read`, and a device in your own inventory. A device from
  another tenant and a device that does not exist return the identical 404.
- The vendor's word for the concept. Correlix reads every dialect as one
  canonical concept and shows each operator their own: **VRF** by default,
  **routing-instance** on Juniper, **VPRN** on Nokia, **VPN instance** on
  Huawei.
- The interface state series behind the grouping. Utilisation needs a link-speed
  series, and error rates need error counters. Absent measurements render as
  `null`, never as `0`.

## Steps

1. Go to **Infrastructure → Devices** and open a device.
2. Select the **By VRF** tab. The label carries the device's own dialect, so on
   the Nokia lab spine it reads **By VPRN**.
3. Read the coverage line at the top of the panel before the tables. It states
   the one fact you need first: whether the instance an interface belongs to is
   collected here.
4. Read the transport line. `gNMI` is stamped by the collector. `SNMP` is an
   inference from an absent transport stamp and says so.
5. Read the groups. Interfaces with no collected binding are listed in an
   unnamed bucket whose membership is `not_collected`, never under a group named
   `default`.

## What you see

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/devices/spine1/interfaces/by-vrf
```

```json
{
  "device": {"id": "spine1", "name": "spine1", "vendor": "nokia"},
  "window": "5m",
  "dialect": {"term": "VPRN", "term_plural": "VPRNs", "vendor": "nokia", "vendor_known": true},
  "coverage": {
    "vrf_labels": false,
    "transport": "none",
    "transport_inferred": false,
    "interfaces": 0,
    "in_groups": 0,
    "ungrouped": 0,
    "utilisation": false,
    "errors": false,
    "truncated": false,
    "notes": [
      "No interface state series exists for this device — nothing is collecting device_if_oper_status for it, so there are no interfaces to group.",
      "The device does report routing instances on its BGP control-plane series; they are listed under routing_instances. That lane carries the instance name but not which interfaces belong to it."
    ]
  },
  "groups": null,
  "routing_instances": [{"name": "default", "source": "bgp_control_plane"}]
}
```

Read that answer carefully, because it separates three facts that a lesser
panel would fuse into one green screen:

- Nothing collects interface state for this device right now, so there are no
  interfaces to group. The panel state is **not connected**, not **empty**.
- The device nevertheless is known to have a routing instance called `default`,
  from the BGP control-plane series. That lane carries the instance name and not
  which interfaces belong to it, so the instance is listed separately and no
  interface is claimed to be in it.
- `vrf_labels` is `false` because the label is **probed on every request**, not
  assumed. The grouping lights up by itself on the day a deployment collects the
  binding.

### When interfaces are collected but the binding is not

No interface series carries a routing-instance label on either transport today:
SNMP IF-MIB has no VRF column, and the gNMI interface subscriptions sit outside
the `/network-instances` tree that carries the instance name.

On a device whose interface state **is** collected, the response therefore
reports `vrf_labels: false` and returns the interfaces ungrouped. Both notes are
attached:

```text
VPRN membership is not collected on this transport: the canonical interface series carry {device, vendor, ifName, transport} and no vrf label. SNMP IF-MIB has no VRF column, and the gNMI interface subscriptions sit outside the /network-instances tree that carries the instance name.
These interfaces are shown ungrouped on purpose. They are NOT reported as members of a default VPRN — that would be a claim about the device that no collected series supports.
```

Where some series carry a label and some do not, the labelled ones are grouped
and the rest are listed separately rather than folded into an instance.

### How a row is qualified

| Value | Behaviour |
|---|---|
| `oper` / `admin` | Decoded from the IF-MIB numbering both transports normalise onto. An unrecognised value is `unknown`, never rounded to up or down. |
| `in_util_pct` / `out_util_pct` | `null` when no link-speed series was returned. There is no capacity to divide by, so no percentage is shown. |
| `in_errors_per_s` / `out_errors_per_s` | `null` when the error counters are not collected. Null means not collected, not zero errors. |
| Row colour | An interface with no state series gets no colour at all: not green, not red. An administratively down interface is an intended state, not a fault. |
| Group counts | `up`, `down` and `unknown` are counted separately. An interface whose state was never read is not down. |

The window defaults to 5 minutes and accepts 1 minute to 24 hours. Where a
vendor profile does not match the device, the panel says which industry-majority
term it fell back to, so the word is never mistaken for an identification.

## Related

- [Check OSPF and IS-IS adjacency health](/investigate/igp-health)
- [Investigate a symptom](/investigate/investigate-a-symptom)
- [API reference](/reference/api)
