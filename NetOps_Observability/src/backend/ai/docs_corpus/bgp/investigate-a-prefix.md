---
title: Investigate a BGP prefix
sidebar_label: Investigate a prefix
sidebar_position: 3
description: Read the routing status, visibility, RPKI verdict, collector paths, update churn and registry ownership for one prefix or ASN on a single screen.
page_type: task
---

# Investigate a BGP prefix

This is the outage-call procedure. For one prefix or ASN it tells you whether
the resource is announced, how much of the global table sees it, and which
origin AS is behind it. It also gives you the ROA verdict, the paths that reach
it, its update churn, and who the registry says owns it.

## Before you begin

- **`infrastructure:read`.**
- **Outbound HTTPS to `stat.ripe.net` and `rdap.arin.net`.** These panels are
  live lookups, not stored telemetry. See
  [connectivity requirements](/reference/connectivity-requirements).
- **A corporate TLS-inspection CA, if your egress re-signs TLS.** Set
  `OUTBOUND_HTTPS_CA_FILE` to a PEM bundle. It is added to the trust set for
  outbound requests. It never replaces the trust set and never disables
  verification.

## Steps

1. Go to **Analytics → Metric Dashboards → BGP Operations**.
2. Type the prefix or ASN into the **Prefix or ASN** box, or select one of the
   watched chips beneath it.
3. Select **Investigate**.
4. Read the **Verdict** bar first. It carries the resource, the incident class,
   the last-seen origin AS, the visibility percentage across RIPE RIS full-feed
   peers, and the RPKI chip.
5. Work down the left column for the time story: **Current paths from route
   collectors**, then the updates timeline.
6. Work down the right column for the standing evidence: **RPKI origin
   validation**, **Incidents**, **Peers**, **Bogons**, **Ownership & contacts**,
   **Geofeed (RFC 8805)** and **ASPA**.

### The same data from the API

One call returns the page-load bundle:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/bgp/resource?resource=8.8.8.0/24&view=status"
```

```json
{
  "kind": "prefix",
  "resource": "8.8.8.0/24",
  "routing_status": {
    "resource": "8.8.8.0/24",
    "announced": null,
    "visibility": {"v4": {"ris_peers_seeing": 111, "total_ris_peers": 111},
                   "v6": {"ris_peers_seeing": 0, "total_ris_peers": 0}},
    "first_seen": {"prefix": "8.8.8.0/24", "origin": "21284", "time": "2002-11-06T16:00:00"},
    "last_seen": {"prefix": "8.8.8.0/24", "origin": "15169", "time": "2026-09-03T00:00:00"}
  },
  "rpki_origin": "AS15169",
  "rpki": {"resource": "15169", "prefix": "8.8.8.0/24", "status": "valid",
           "validator": "routinator",
           "validating_roas": [{"origin": "15169", "prefix": "8.8.8.0/24",
                                "max_length": 24, "validity": "valid"}]}
}
```

Two other views answer from the same route:

| View | What it returns |
|---|---|
| `?view=updates&hours=8` | Announcement and withdrawal records over a window of 1 to 72 hours, default 8. Each record carries a timestamp, a type of `A` or `W`, and the collector `source_id`. |
| `?view=whois` | The RDAP registry object for the resource. |

An unknown view is refused rather than silently defaulted.

## Result

The verdict bar names the resource and its state, and each panel below it stands
or falls on its own. A panel that could not be measured says which lookup
failed, in the response and on the screen:

| Field | Meaning |
|---|---|
| `routing_status_error` | The routing lookup did not answer. Nothing below it is a clean verdict. |
| `rpki_error` | The ROA verdict could not be fetched, or the origin AS was not determinable because the prefix is not announced. |
| `paths_error` | Collector path data was unavailable. |

The RPKI verdict judges the origin **actually in the table**. Correlix resolves
the announced origin from the live routing status and validates that pair, so a
verdict is never taken from a request parameter.

## Where the data comes from

- **RIPE NCC RIS / RIPEstat** provides routing status, updates, collector state
  and the RPKI validation. RIPE requires visible credit for this data, and the
  page carries it in its footer.
- **RDAP** provides ownership. Correlix calls ARIN's redirecting endpoint, which
  follows through to the authoritative registry, so all five RIRs are covered
  from one base URL.
- Both sit behind a per-resource TTL cache: 60 seconds for routing status and
  RPKI, 24 hours for registry ownership. The cache holds at most 512 entries and
  evicts the stalest.

## Related

- [Watch a prefix or an ASN](/bgp/watchlist)
- [View AS paths for a prefix](/bgp/as-paths)
- [Check RPKI origin validation](/bgp/rpki)
- [Root-cause analysis explained](/investigate/rca-explained)
