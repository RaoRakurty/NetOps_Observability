---
title: Watch a prefix or an ASN
sidebar_label: Watch a prefix or ASN
sidebar_position: 2
description: Watch the prefixes and ASNs this tenant cares about, so the RPKI sweep, the near-live feed and the alert evaluator all follow one list.
page_type: task
---

# Watch a prefix or an ASN

The watchlist is the one list every other BGP surface reads. The RPKI sweep
validates it, the near-live update feed follows it, and the alert evaluator
classifies it. Adding a resource here is what turns a one-off lookup into
something Correlix keeps checking.

## Before you begin

- **`infrastructure:read` to view the list, `infrastructure:write` to change
  it.** See [role and permission administration](/administration/overview).
- **One tenant selected.** The watchlist is per-tenant data. A cross-tenant
  principal must scope into a concrete tenant before writing. The route refuses
  the write otherwise.

  ```json
  {"error":"select a tenant to edit its watchlist (cross-tenant writes are refused)"}
  ```

- **A watchlist store.** Correlix keeps the watchlist in PostgreSQL under the
  `tenant_iso` FORCE-RLS policy when the relational store is active, and in a
  tenant-keyed JSON register at `/data/bgp_watchlist.json` (`BGP_WATCHLIST_FILE`)
  otherwise. A deployment with neither answers:

  ```bash
  curl -s -H "Authorization: Bearer $TOKEN" \
    http://localhost:8000/api/bgp/watchlist
  ```

  ```json
  {"error":"BGP watchlist requires the relational store"}
  ```

- **The resource in canonical form**, or something Correlix can canonicalize: a
  CIDR prefix (`203.0.113.0/24`), a bare address, which is read as its host
  prefix, or an ASN (`AS64500` or `64500`). `AS0` is reserved by RFC 7607 and is
  refused.

## Steps

1. Go to **Analytics → Metric Dashboards → BGP Operations**.
2. Type the prefix or ASN into the **Prefix or ASN** box.
3. Select **Investigate**. The verdict bar and every panel below it now answer
   about that resource.
4. Select **Watch this prefix** in the **Verdict** section header. For an ASN
   the same control reads **Watch this ASN**.
5. To stop watching, select **Watching — remove** on the same control.

To do it from the API instead, post the resource. The tenant is stamped from
the token, and any tenant in the body is ignored:

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"resource":"203.0.113.0/24","note":"customer block"}' \
  http://localhost:8000/api/bgp/watchlist
```

The response carries `ok`, the canonical `resource` and its `kind`
(`prefix` or `asn`). Re-adding a resource updates only its note. The body is
bounded at 4 KiB and the note is cut to 300 bytes on a character boundary.

Delete with the same canonical form:

```bash
curl -s -X DELETE -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/bgp/watchlist?resource=203.0.113.0/24"
```

## Result

`GET /api/bgp/watchlist` returns the caller's own entries, newest first, under
`watchlist`. Two annotations ride with them:

| Field | What it tells you |
|---|---|
| `watched_bogons` | Watched prefixes that fall inside a reserved block. This is arithmetic on the address, so it is answered even with the evaluator off. |
| `incidents` | The current incident class per watched prefix, when `FEATURE_BGP_ALERTS` is on. |
| `incidents_note` | Present instead of `incidents` when the evaluator is off: "Incident classification is off. Set FEATURE_BGP_ALERTS=true to run the watchlist evaluator. No incident here means NOT EVALUATED, not healthy." |

In the console the watched resources appear as chips under the search box. A
chip carries a coloured dot when its prefix has an open incident class.

Deleting a resource another tenant owns returns `404`. The resource does not
exist for this caller, and the route never reveals that it exists for someone
else.

## Related

- [Investigate a BGP prefix](/bgp/investigate-a-prefix)
- [Configure BGP alerting](/bgp/alerting)
- [Check RPKI origin validation](/bgp/rpki)
- [What an empty result means](/reference/honest-states)
