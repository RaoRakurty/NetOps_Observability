---
title: Check OSPF and IS-IS adjacency health
description: Read adjacencies, flaps, LSDB size, SPF runs and timers, each reported only as far as the collected evidence supports.
page_type: task
sidebar_position: 9
---

# Check OSPF and IS-IS adjacency health

The IGP surfaces answer two different questions that a PromQL tile cannot tell
apart: is this adjacency down, and is anything watching this protocol at all.
Every response carries a coverage block, and a source that is not collected is
reported as absent with the reason attached, never as a zero and never as
healthy.

## Before you begin

- `infrastructure:read`.
- A device id from your own inventory when you want the per-device view. A
  device in another tenant and a device that does not exist return the identical
  404.
- Understand the two evidence classes. **Change events** are syslog and SNMP-trap
  adjacency changes from the correlation spine. **Live adjacency state** is a
  collected metric series. Either can be present without the other.

## Steps

1. Go to **Analytics → Protocol Monitoring**.
2. Scroll to **OSPF — IGP health** or **IS-IS — fabric IGP**. The PromQL tiles
   at the top of each group are the fleet counters; the block below them is the
   adjacency view that reads `/api/protocols/{ospf|isis}/*`.
3. Choose a window: **1h**, **6h**, **24h** or **7d**.
4. Choose **All devices**, or one device for the per-device roll-up and health.
5. Read the coverage strip **before** you read any number under it. Each chip is
   one source: Change events, Live adjacency state, LSDB / LSP count, Areas, SPF
   runs, Timers. An uncollected chip carries the server's own reason.
6. Read the adjacency table. The **State** column names where the state came
   from: `live` when a live series backs it, `last reported` when only an event
   does, `not reported` when neither does.

## What you see

### A protocol that is collected

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/protocols/isis/health?device=spine1"
```

```json
{
  "adjacencies_down": 0,
  "adjacencies_up": 4,
  "adjacency_changes": 0,
  "areas": {"areas": ["49.0001"]},
  "coverage": {"events": true, "live_series": true, "lsdb": true,
               "areas": true, "spf_runs": true, "timers": true},
  "device": "spine1",
  "flaps": 0,
  "levels": ["L2"],
  "lsdb": {"lsp_count": 6, "scope_label": "isis_level", "by_scope": [{"scope": "L2", "count": 6}]},
  "neighbor_count": 4,
  "notes": null,
  "protocol": "isis",
  "source": "events+live_series",
  "spf_runs": {"runs": 10, "scope_label": "isis_level", "by_scope": [{"scope": "L2", "count": 10}]},
  "stability": {"flaps_per_hour": 0, "score": 100,
    "basis": "0 adjacency down-transitions over 24h, counted from syslog/trap adjacency-change events"},
  "timers": {"scope_kind": "adjacency", "rows": [
    {"device": "spine1", "scope": "0100.0000.0011", "ifname": "ethernet-1/1.0", "level": "L2", "hold_seconds": 30}
  ]},
  "window_seconds": 86400
}
```

Every coverage flag is true, so every number is a measurement: four adjacencies
up in area `49.0001` at level L2, six LSPs, ten SPF runs, and a 30-second hold
countdown per adjacency. `stability.basis` states what the score was computed
from rather than presenting a bare 100.

The fleet roll-up for the same protocol lists both spines, each with four
adjacencies, six LSPs and area `49.0001`:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/protocols/isis/summary
```

```json
{"coverage":{"events":true,"live_series":true,"lsdb":true,"areas":true,"spf_runs":true,"timers":true},
 "devices":[{"device":"spine1","flaps":0,"adjacencies":4,"down_adjacencies":0,"lsp_count":6,"spf_runs":10,"areas":["49.0001"]},
            {"device":"spine2","flaps":0,"adjacencies":4,"down_adjacencies":0,"lsp_count":6,"spf_runs":6,"areas":["49.0001"]}],
 "event_count":0,"notes":null,"protocol":"isis","source":"events+live_series","window_seconds":86400}
```

### A protocol that nothing is collecting

On the same deployment, OSPF answers honestly. Only the event class is
available, every other source is absent, and each absence carries the reason:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/protocols/ospf/summary
```

```json
{
  "coverage": {"events": true, "live_series": false, "lsdb": false,
               "areas": false, "spf_runs": false, "timers": false},
  "devices": [],
  "event_count": 0,
  "notes": [
    "no live series collected for this device; adjacency history is from syslog/trap events only (device_ospf_nbr_state is SNMP-owned via OSPF-MIB ospfNbrTable and the OpenConfig ospfv2 gNMI path is unvalidated)",
    "no LSDB/LSA-count series is collected for these devices (device_ospf_lsdb_count comes from OSPF-MIB ospfAreaLsaCount and only materializes on a device that answers ospfAreaTable); LSDB size is not reported rather than reported as zero",
    "OSPF area membership is not collected for these devices (device_ospf_area comes from OSPF-MIB ospfAreaTable; ospfNbrTable carries no area and the OpenConfig ospfv2 gNMI path is unvalidated here)",
    "no SPF-run counter is collected for these devices (device_ospf_spf_runs_total comes from OSPF-MIB ospfSpfRuns, which is PER AREA and needs a device that answers ospfAreaTable)",
    "no OSPF timer series is collected for these devices (device_ospf_if_hello_seconds / device_ospf_if_dead_seconds come from OSPF-MIB ospfIfTable and are PER INTERFACE — OSPF-MIB's ospfNbrTable has no hello or dead column, so a per-neighbour OSPF timer cannot be collected over SNMP)"
  ],
  "protocol": "ospf",
  "source": "events",
  "window_seconds": 86400
}
```

Nothing here reads as zero adjacencies or as a healthy OSPF. LSDB size, areas,
SPF runs and timers each render as **not collected** with that note as the
detail. In the console, a count that was never measured is that phrase, never a
digit and never a green tick.

### How a state is qualified

| Field | Behaviour |
|---|---|
| `up` | The live verdict only. It is `null` whenever no live series exists, because an event-only adjacency is not evidence of the state right now. |
| `current_state` | The live decoded state, else the state of the most recent event, else `null`. |
| `state_source` | `live_series`, `events` or `none`. The row is coloured only from a live verdict; an event-only row gets no colour. |
| `hold_seconds` | A sampled countdown where a timer series exists, `null` otherwise. It is never defaulted to `0`, which would mean the adjacency is expiring right now. |

OSPF has no per-neighbour timer column in OSPF-MIB, so the hold column exists
only for IS-IS.

### Panel states

The adjacency, roll-up and health panels use the same five states as the
investigation lanes. **Not connected** is reserved for the case where neither
evidence class answered, which means the protocol is not observed here. If a source
answered and the window was quiet, that is **empty**, which is a different and
much better fact.

## Related

- [Investigate a symptom](/investigate/investigate-a-symptom)
- [Diagnose a BGP, OSPF or IS-IS issue](/investigate/protocol-diagnostics)
- [View interfaces by routing instance](/investigate/interfaces-by-routing-instance)
- [API reference](/reference/api)
