---
title: Review exposures
description: "Work the findings table: facet by severity, verdict, seam and standard, switch between current verdicts and full history, and page with a cursor."
page_type: task
sidebar_position: 5
---

# Review exposures

Exposures is the findings workbench. It is where you narrow several hundred
verdicts down to the ones that matter for one severity, one seam, one standard
or one search phrase, and then open each one.

## Before you begin

- A role with `infrastructure:read`.
- At least one completed scan. The list is empty until one has run, and the
  empty state says so: an empty list means nothing was assessed, not that the
  estate is clear.

## Steps

1. Go to **Security → Exposures**.
2. Choose **Current verdicts** or **Full history** in the toolbar. Current
   verdicts is the default and collapses to the latest verdict per check.
3. Narrow with the facet panel on the left. Four facet groups are clickable:
   **Severity**, **Verdict**, **Seam** and **Standard**.
4. Type a phrase in the search box and select **Search**. The search runs over
   the observed, intended and remediation text.
5. Select a row to open the finding detail.
6. Select **Load more** to fetch the next page. Rows are appended and never
   re-ordered.
7. Select **Clear N filters** to start over.

## What you see

The status line above the table reads `N of M shown`, followed by either
`latest verdict per check` or `every recorded verdict, including superseded
ones`. The facet counts come from `GET /api/security/findings/facets`, which
answers five facet groups over the same filter set:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/security/findings/facets
```

On the lab stack, with 192 findings recorded:

| Facet group | Counts |
|---|---|
| `severity` | critical 6, high 78, medium 48, low 54, info 6 |
| `status` | unknown 192, and `pass`, `warn`, `fail`, `not_applicable`, `error` all 0 |
| `framework` | AC-17, AC-2, AC-4, AU-2, AU-6, AU-8, CIS-NET-1.1 through CIS-NET-10.1, CM-7, IA-2, IA-3, IA-5, PCI-2.1 |
| `evidence_class` | `posture`, `exposure`, `signal` |
| `seam` | empty when no finding carries a resolved seam |

Read that `status` row as the product intends it. All 192 findings sitting in
`unknown` means the checks ran and could not reach a verdict, most often
because no running configuration was on file. It is not 192 passes.

Every status key is emitted even when it is zero, because an absent facet and a
zero facet mean different things. The `Evidence lane` group is a read-only
breakdown of the current result set: the findings query has no evidence-class
filter, and making the group look clickable would promise a narrowing the API
cannot perform.

## Filters the API accepts

`GET /api/security/findings` accepts these query parameters, and rejects
anything else with a `400` naming the parameter:

| Parameter | Values |
|---|---|
| `severity` | `critical`, `high`, `medium`, `low`, `info`; comma-separated, up to 20 |
| `status` | `pass`, `warn`, `fail`, `not_applicable`, `error`, `unknown` |
| `seam` | A seam type or seam id |
| `framework` | A standards tag such as `AC-4` or `PCI-2.1` |
| `device` | An entity id, device uid or hostname |
| `q` | Free text over the narrative and title fields, up to 256 characters |
| `since`, `until` | The window, up to 365 days; 30 days when neither is given |
| `current` | `true` collapses to the latest verdict per finding identity |
| `limit` | 1 to 500; 100 when absent |
| `cursor` | The `next_cursor` from the previous page |
| `as_tenant` | Narrows into one tenant; it can only narrow, never widen |

A misspelled value is a `400`, not an empty result. `?severity=hgih` answering
`200` with nothing would read exactly like "you have no high findings".

`offset` and `envelope` are refused with a `400` telling you to page with
`cursor`. Accepting a parameter and then ignoring it would serve page one under
a `200`.

## Paging

The response carries `items`, `next_cursor` and `total`. A cursor is advertised
only on a full page: a short page is the end of the result set, and dangling a
cursor that returns nothing makes an exhausted list look infinite.

In current-verdict mode the API pages by offset and is bounded at 10000
findings. Walking past that bound is refused with a `400` suggesting you narrow
the filters or page the full verdict history with `current=false`.

## Related

- [Investigate a security finding](/security/investigate-a-finding)
- [Create a saved findings view](/security/saved-views)
- [Review threat detections](/security/threat-detection)
- [Continuous threat and exposure management](/security/ctem)
