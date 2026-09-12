---
title: Review bogon sightings
sidebar_label: Review bogons
sidebar_position: 8
description: Read the reserved-address set Correlix has in force and any bogon prefix seen on this tenant's own BMP feed or update ring.
page_type: task
---

# Review bogon sightings

A bogon is an address block that must never appear in the global routing table:
RFC-reserved or special-purpose space, and space IANA has not delegated to any
registry. A bogon on your feed is either a misconfiguration inside your own
network or somebody announcing space they do not hold.

## Before you begin

- **`infrastructure:read`**, and one tenant selected. Sightings are per-tenant
  data drawn from that tenant's own feeds.
- **`FEATURE_BGP_ALERTS=true`**, if you want sightings. The sighting register is
  fed by the watchlist evaluator. The set in force is answered with or without
  it.
- **`FEATURE_BGP_BOGON_FEED=true`**, if you also want the Team Cymru
  full-bogons list. The default is off.

## Steps

1. Go to **Analytics → Metric Dashboards → BGP Operations**.
2. Read **Bogons — set in force and sightings** in the right-hand column.
3. Check the chips: how many embedded blocks are compiled, the transcription
   date of those tables, and whether the full-bogons feed is on.
4. Read the **Bogons seen** block for prefixes actually observed, grouped by the
   reserved block that matched.

From the API:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/bgp/bogons?as_tenant=lab"
```

```json
{
  "feed": {"enabled": false, "entries": 0, "fetched_at": "0001-01-01T00:00:00Z",
           "note": "Only the embedded RFC/IANA special-purpose set is in force. Set FEATURE_BGP_BOGON_FEED=true to also fetch the Team Cymru full-bogons list (unallocated-by-RIR space, which changes daily)."},
  "set": {"blocks": 31, "date": "2026-09-02",
          "source": "IANA IPv4/IPv6 Special-Purpose Address Registries (RFC 6890) + the RFCs listed in bogon.go",
          "note": "IPv4 has had no unallocated unicast /8 since the IANA free pool was exhausted on 2011-02-03, so the embedded IPv4 set is the special-purpose registry only. IPv6 outside 2000::/3 is reported as unallocated by rule, not by a snapshot."},
  "sightings": []
}
```

## Result

The response has three parts, and each answers a different question.

| Part | What it answers |
|---|---|
| `set` | Which blocks are in force right now, where they came from, and how old the transcription is. |
| `feed` | Whether the optional daily feed is enabled, how many rows it holds, when it was last fetched, and any fetch error. |
| `sightings` | Which bogon prefixes have actually been seen, with the block that matched, the source, the peer, the origin AS, and first and last seen. |

Three rules govern the answer:

- **The embedded set is offline and dated.** It is the IANA IPv4 and IPv6
  Special-Purpose Address Registries, the rows whose "Globally Reachable" column
  is false, plus the RFCs those rows cite. The response carries the source and
  the transcription date so you can see how old the offline half is.
- **IPv6 outside `2000::/3` is judged by rule, not by a snapshot.** RFC 4291
  defines global unicast as `2000::/3`, so anything outside it that is not
  already a listed special-purpose block is reported as undelegated. A rule
  derived from the address architecture cannot go stale.
- **A feed outage never un-flags a prefix.** The fetched half is held separately
  from the embedded half. On a failed refresh the previous rows stay in place,
  the error is recorded in `feed.error`, and the console says that the embedded
  set is still in force and nothing has been un-flagged.

Sightings carry a `source` of `watchlist`, `feed` or `bmp`, and the register
holds at most 200 rows per tenant, evicting the stalest.

An empty sighting list with the evaluator running is a measured result: no bogon
has been seen on this tenant's feeds. An empty list with the evaluator off is
not, and the response says so in its `note`.

## Related

- [Configure BGP alerting](/bgp/alerting)
- [Point a router at the BMP receiver](/bgp/bmp)
- [Feature flags and their defaults](/reference/feature-flags)
