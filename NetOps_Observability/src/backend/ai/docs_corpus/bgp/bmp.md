---
title: Point a router at the BMP receiver
sidebar_label: Receive BMP
sidebar_position: 9
description: Turn on the BMP receiver, configure a router to push its Adj-RIB-In over TCP, and read the bounded per-tenant feed back.
page_type: task
---

# Point a router at the BMP receiver

BMP is the one live BGP feed that needs no external service. Your own router
opens a TCP session to Correlix and pushes a copy of what its BGP RIB-In sees.
Correlix terminates the session, parses the frames, and serves a bounded
per-tenant read API over what arrived.

Correlix configures nothing on any device. Turning the receiver on is an
environment change on the platform; pointing a router at it is a command a
network engineer types on the router. The whole surface is read-only toward the
network.

## Before you begin

- **`FEATURE_BMP=true`.** The default is off. With the flag off no port is
  bound, no goroutine starts, and the three read routes answer `404`.
- **TCP reachability to the receiver.** `BMP_LISTEN` is the in-container bind
  address and defaults to `:11019`, the IANA-registered `bmp` port. `BMP_PORT`
  is the host port mapped to it. See
  [connectivity requirements](/reference/connectivity-requirements).
- **The router in the device inventory.** The session's source address is
  resolved against inventory and the tenant is stamped from the device row that
  answers. A source address that resolves to nothing is refused and
  disconnected. It is never admitted untenanted.
- **`infrastructure:read`** to read the feed back.

## Steps

### Step 1. Enable the receiver

```
FEATURE_BMP=true
BMP_LISTEN=:11019         # in-container bind address
BMP_PORT=11019            # host port mapped to it
```

Restart the stack, then confirm the routes answer.

### Step 2. Add the router to inventory

Onboard the router with the address it will source the BMP session from. Without
that row the connection is refused, and the refusal is counted.

### Step 3. Configure the router

Replace `MONITOR_HOST` with the host running the stack.

**Cisco IOS-XR**

```
bmp server 1
 host MONITOR_HOST port 11019
 description Correlix BMP receiver
 update-source Loopback0
 initial-refresh delay 30
 stats-reporting-period 60
!
router bgp 65000
 neighbor 192.0.2.10
  bmp-activate server 1
```

**Cisco IOS-XE**

```
router bgp 65000
 bmp server 1
  address MONITOR_HOST port-number 11019
  initial-refresh delay 30
  update-source Loopback0
  exit-bmp-server-mode
 bmp buffer-size 200
 neighbor 192.0.2.10 bmp-activate all
```

**Juniper Junos**

```
set routing-options bmp station correlix station-address MONITOR_HOST
set routing-options bmp station correlix station-port 11019
set routing-options bmp station correlix local-address 10.0.0.1
set routing-options bmp station correlix connection-mode active
set routing-options bmp station correlix route-monitoring pre-policy
set routing-options bmp station correlix statistics-timeout 60
```

**Nokia SR OS**

```
configure router bgp monitor
    admin-state enable
    station "correlix"
        admin-state enable
        connection router-instance "Base" station-address ip-address MONITOR_HOST port 11019
        all-route-monitoring pre-policy
        stat-report-interval 60
    exit
exit
```

### Step 4. Confirm the session

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/bgp/bmp/sessions
```

```json
{
  "count": 1,
  "coverage": {
    "receiver_enabled": true,
    "sessions_up": 0,
    "complete": false,
    "notes": [
      "Every BMP session is closed; the records below are historical and the peer states are reported as unknown, not as up.",
      "This is a bounded monitoring feed of recent updates, not a converged RIB: a prefix that is absent has simply not been seen recently."
    ]
  },
  "sessions": [
    {
      "id": "bmp-1",
      "device_id": "bmp-sender-proof-245c0ffc",
      "remote_addr": "172.18.0.1:36350",
      "router": "bmp-proof",
      "router_descr": "synthetic BMP sender (scripts/bmp-synthetic-session.py)",
      "state": "closed",
      "opened_at": "2026-09-03T03:31:57Z",
      "closed_at": "2026-09-03T03:32:02Z",
      "close_reason": "router terminated: administratively closed",
      "peers": [
        {
          "address": "192.0.2.1",
          "as": 65001,
          "bgp_id": "192.0.2.1",
          "rib": "adj-rib-in-pre-policy",
          "state": "unknown",
          "changed_at": "2026-09-03T03:32:02Z",
          "down_reason": "bmp session closed",
          "announced_prefixes": 3,
          "withdrawn_prefixes": 0
        }
      ],
      "peers_partial": false,
      "messages": {
        "initiation": 1,
        "peer_up": 1,
        "route_monitoring": 3,
        "termination": 1
      },
      "updates_held": 3,
  …
```

Before any router has connected, the same route answers with the receiver up and
the feed empty:

```json
{
  "count": 0,
  "coverage": {
    "receiver_enabled": true,
    "sessions_up": 0,
    "complete": false,
    "notes": [
      "No router is exporting BMP to this platform. This is an empty FEED, not an empty routing table — point a router's BMP export at the receiver (see the ingestion guide)."
    ]
  },
  "sessions": []
}
```

### Step 5. Read the updates

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/bgp/bmp/updates?prefix=203.0.113.0/24&limit=100"
```

`?prefix=` matches the prefix itself or anything inside it. `?peer=` and
`?session=` narrow further, `?limit=` accepts 1 to 1000, and `?cursor=` walks
the keyset. An unknown query parameter is refused, and a limit outside the range
is refused rather than clamped.

## What you see

The console shows the same data at **Analytics → Metric Dashboards → BGP
Operations**, in the **Peers — sessions and transit** section. That table merges
two witnesses without conflating them: a BMP session, which is your router
telling Correlix what it learned, and `device_bgp_peer_state`, which is an SNMP
or gNMI sample of the same session from outside. Each row says which witness is
talking. A peer with no observed state renders **UNKNOWN**, described as an
absent measurement rather than a healthy peer.

Every response carries a `coverage` block. Read it before the data:

| Field | What it tells you |
|---|---|
| `receiver_enabled` | The receiver is running. It is always true where these routes exist. |
| `sessions_up` | How many routers are exporting right now. |
| `complete` | `false` when anything was dropped, skipped, or not decoded. |
| `notes` | The sentences naming what is missing and why. |

Per session and in the aggregate, Correlix counts `updates_dropped`,
`parse_errors` and `unsupported_elements`. A non-zero count means the stored view
is incomplete, and the response says so rather than looking like a quiet
network.

### What is decoded, and what is not

Only IPv4 and IPv6 unicast are decoded, through the classic NEXT_HOP and NLRI
fields and through MP_REACH and MP_UNREACH per RFC 4760. VPN address families,
EVPN, flowspec, link-state and ADD-PATH-encoded NLRI are counted as unsupported
and skipped. They are never partially decoded, because half a VPN route rendered
as an IPv4 prefix is a wrong number on an operator's screen.

An announcement carries AS_PATH with AS4 merged, NEXT_HOP, ORIGIN, MED,
LOCAL_PREF and communities including RFC 8092 large communities. A withdrawal
carries none of them, because a withdrawal has none.

### Receiver bounds

| Bound | Value |
|---|---|
| `max_connections` | 64 |
| `max_message_bytes` | 1048576 |
| `max_session_records` | 256 |
| `max_updates_per_session` | 4096 |

The bounds are published on `/api/bgp/bmp/stats` alongside the counters, so a
non-zero dropped count can be read against what it was measured against. The
ring drops the oldest update and increments the counter. A new connection is
refused rather than evicting a live session.

## Related

- [Configure BGP alerting](/bgp/alerting), where a BMP peer going down raises `bgp_peer_down`
- [Review bogon sightings](/bgp/bogons), which screens this feed
- [Optional modules and their flags](/deploy/optional-modules)
- [What an empty result means](/reference/honest-states)
