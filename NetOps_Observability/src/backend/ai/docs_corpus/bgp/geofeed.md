---
title: Find a published geofeed
sidebar_label: Find a geofeed
sidebar_position: 6
description: Read the RFC 8805 geolocation feed a holder published for its own address space, discovered per RFC 9092 from the registry object.
page_type: task
---

# Find a published geofeed

A geofeed is a CSV a holder publishes to say where its own address space is
used. It is the authoritative answer to "which country is this /24 actually in",
and it beats a commercial geolocation guess. Correlix discovers the feed from
the registry object and parses it conservatively.

## Before you begin

- **`infrastructure:read`.**
- **Outbound HTTPS**, both to `stat.ripe.net` for the registry object and to
  whatever host the holder published the feed on.
- **A prefix or an ASN.** For an ASN, Correlix checks the first 6 announced
  prefixes and says so in the response `note`.

## Steps

1. Go to **Analytics → Metric Dashboards → BGP Operations**.
2. Investigate a prefix or an ASN.
3. Read the **Geofeed (RFC 8805)** section in the right-hand column.
4. Check the chips for rows scanned, rows kept and rows dropped before reading
   the entries themselves.

From the API:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/bgp/geofeed?resource=104.28.0.0/16"
```

```json
{
  "resource": "104.28.0.0/16",
  "published": true,
  "source_url": "https://api.cloudflare.com/local-ip-ranges.csv",
  "entries": [
    {"prefix": "104.28.8.1/32", "country": "AD"},
    {"prefix": "104.28.8.10/32", "country": "AG"}
  ],
  "rows_scanned": 139012,
  "rows_kept": 500,
  "rows_dropped": 0,
  "truncated": true,
  "fetched_at": "2026-09-03T04:10:34.506937814Z"
}
```

## Result

| Field | What it tells you |
|---|---|
| `published` | Whether a geofeed URL was found for the resource. `false` with no `error` means the registry carries no geofeed. That is a fact about the registry object, not a failure. |
| `source_url` | The URL the feed was read from, as published in the registry. |
| `rows_scanned` / `rows_kept` / `rows_dropped` | Rows read, rows accepted, and rows discarded because the prefix or the ISO 3166-1 country was not valid. |
| `truncated` | The answer hit the 500-row response cap. |
| `error` | The discovery or the fetch failed. Set instead of a result, never alongside a partial one. |

Correlix parses a published feed conservatively:

- **Discovery follows RFC 9092.** Both forms are accepted: a `geofeed:`
  attribute on the registry object, and the `Geofeed: <url>` remark.
- **A malformed row is dropped, never repaired.** The dropped count travels with
  the answer, so a feed that is quietly emitting garbage does not look like a
  short, healthy feed.
- **Rows outside the queried resource are discarded**, so a third party's feed
  cannot inject claims about somebody else's address space into your answer.
- **Every bound is declared**: 12 MiB of body, 250,000 lines parsed, 500 rows
  returned, and a six-hour cache.

A geofeed URL is a string a third party wrote into a public registry object, so
it is treated as hostile input. The fetch runs through an SSRF gate with two
halves: the URL must be HTTPS with a public host, and the address DNS actually
resolved to is re-checked at dial time. A redirect is re-screened by the same
rule.

## Related

- [Investigate a BGP prefix](/bgp/investigate-a-prefix)
- [Outbound reachability requirements](/reference/connectivity-requirements)
