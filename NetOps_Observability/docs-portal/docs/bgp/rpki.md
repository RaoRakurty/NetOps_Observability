---
title: Check RPKI origin validation
sidebar_label: Check RPKI validation
sidebar_position: 4
description: Check one prefix, or every prefix on the watchlist, against published ROAs, with "could not check" kept separate from "no ROA published".
page_type: task
---

# Check RPKI origin validation

RPKI origin validation answers whether the AS announcing a prefix is authorized
to do so by a published ROA. Correlix validates the origin **actually in the
routing table**, not one supplied in a request, so the verdict describes the
real announcement.

## Before you begin

- **`infrastructure:read`.**
- **Outbound HTTPS to `stat.ripe.net`.** The verdict comes from the RIPEstat
  `rpki-validation` data call, which is served by a Routinator validator.
- **A watchlist**, if you want the sweep rather than a single lookup. See
  [watch a prefix or an ASN](/bgp/watchlist).

## Steps

1. Go to **Analytics → Metric Dashboards → BGP Operations**.
2. Read the **RPKI origin validation** section in the right-hand column. With a
   prefix selected it validates that prefix. With none selected it validates the
   prefixes on this tenant's watchlist and shows the chip **from your
   watchlist**.
3. Read the summary chips first. They count the verdicts, worst first.
4. Open a row for the origin AS, the ROAs that covered the decision, the
   validator that answered, and the time the verdict was fetched.

To validate one prefix from the API:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/bgp/rpki?resource=8.8.8.0/24"
```

```json
{
  "from_watchlist": false,
  "max_prefixes": 50,
  "results": [
    {
      "prefix": "8.8.8.0/24",
      "origin": "AS15169",
      "state": "valid",
      "validator": "routinator",
      "roas": [
        {
          "origin": "15169",
          "prefix": "8.8.8.0/24",
          "max_length": 24,
          "validity": "valid"
        }
      ],
      "fetched_at": "2026-09-03T03:48:41.888259432Z"
    }
  ],
  "truncated": false
}
```

Omit `resource` to sweep the caller's watchlist. `from_watchlist` then reports
`true`.

## Result

Every result carries exactly one of four states. The route promises these four
and normalizes the upstream spellings onto them, so no client string-matches a
validator:

| State | What it means | What it does not mean |
|---|---|---|
| `valid` | A ROA covers this announcement from this origin. | Nothing about the path beyond the origin. |
| `invalid` | The announcement violates a published ROA. `reason` is `origin_as` when a ROA names a different origin, or `max_length` when the announcement is more specific than the ROA allows. | Not necessarily an attack. A stale ROA and a hijack look identical here. |
| `unknown` | No ROA covers this prefix. | Not a failure, and not a pass. |
| `unavailable` | The verdict could not be measured: the validator did not answer, or the origin AS was not determinable because the prefix is not announced. | Never counted as `valid`, and never merged into `unknown`. |

An unrecognized upstream status becomes `unavailable` with the raw status quoted
in `error`. It is never downgraded to `valid`.

Results are ordered worst first: `invalid`, then `unavailable`, then `unknown`,
then `valid`, and by prefix within a state. The console keeps the same order and
keeps "could not check" visually distinct from "no ROA published", because
collapsing the two would overstate your coverage.

The sweep is bounded at 50 prefixes. When a watchlist is longer, `truncated` is
`true` and the console says that only the first 50 are validated. Verdicts are
cached for five minutes, so a page refresh does not re-query the validator.

## Related

- [Investigate a BGP prefix](/bgp/investigate-a-prefix)
- [Configure BGP alerting](/bgp/alerting), where an `invalid` verdict becomes the `rpki_invalid` incident class
- [What an empty result means](/reference/honest-states)
