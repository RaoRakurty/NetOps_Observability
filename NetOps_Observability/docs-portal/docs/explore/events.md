---
title: Review the event feed
description: Read syslog, SNMP traps and active alerts on one timeline, page it honestly, and query the unified feed API that also carries configuration changes and audit actions.
page_type: task
sidebar_position: 5
---

# Review the event feed

**Explore → Events** merges the observations already collected into one time-sorted stream: device syslog, SNMP traps, and active alerts from the rules engine. Nothing new is collected. The value is the single timeline you can hold against a metric chart or a flow surge.

## Before you begin

- An authenticated session. Each source is read over the same tenant-scoped surface its own explore page uses.
- Devices sending syslog or traps. See [Send syslog](/send-data/syslog) and [Send SNMP traps](/send-data/traps).
- A window chosen in the top-bar range picker. The feed reloads every 30 seconds within that window.

## Steps

### Step 1 - Read the header

Four counters head the page: **Total events** in this window, **Syslog**, **SNMP traps** and **Active alerts**. The first three are true window totals taken from the store's own hit count, not the length of the page on screen. The chip beside the title states the difference directly, in the form `N of M signals loaded`, counting every row in the window against every row on screen.

### Step 2 - Filter the stream

1. Type in the **Search events…** box. It matches the event text and the source.
2. Select a type: **All**, **syslog**, **trap** or **alert**.
3. Sort by any column. The default is newest first.

The columns are **Time**, **Type**, **Severity**, **Source** and **Event**. A syslog line is rendered as a readable summary with its subsystem beside it, and the raw text stays available in the detail pane.

### Step 3 - Page the rest of the window

Where the window holds more than is loaded, the panel meta reads `showing N of M in window` and a **Load more** control appears, labelled with how many of the total are loaded. Selecting it fetches the next page of syslog and traps at the current per-type offsets. Active alerts are always complete, so they are never paged.

### Step 4 - Open one event

Select a row. The detail pane shows the time, the type spelled out, the source, the correlation link state, the humanized message where one exists, and the raw message. The correlation link reads `Pending correlation` until the case wiring lands, which is stated rather than left blank.

## What you see

A merged, newest-first timeline for the window you chose.

Read failures are never rendered as a quiet network. Where one source fails, the page states which one and what that costs you: `syslog and SNMP traps could not be read — this view is incomplete and an absent event does not mean it did not happen.` The empty-state hint is suppressed while that message stands, so a failed read is never mistaken for an empty window.

### The unified feed API

Behind the wider event model sits `/api/events/feed`, the read-only, keyset-paginated view over the normalized-observation spine. It is the same store the correlation engine reads, and there is no second event table. It carries more than the console's merged stream: device events, correlated observations, configuration changes, and **audit** actions, so "what changed" includes the humans and the API clients.

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/events/feed?from=24h&limit=1"
```

```json
{
  "items": [
    {
      "signal_id": "a077dfa6-613e-57c2-bb1f-8aef8aaa5309",
      "ts": "2026-09-03T04:27:03.700Z",
      "source": "audit",
      "kind": "audit_change",
      "severity": "info",
      "entity_type": "service",
      "entity_id": "internal",
      "modality_class": "management_plane",
      "observer_type": "platform",
      "title": "Audit change — internal",
      "attrs": {"actor": "", "method": "POST", "path": "/api/internal/vmalert/api/v2/alerts", "status": 200},
      "correlation_id": null
    }
  ],
  "next_cursor": "…",
  "total": 3823,
  "facets": {
    "source": {"audit": 2984, "security": 839},
    "severity": {"crit": 26, "high": 343, "info": 3244, "warn": 210},
    "kind": {"audit_change": 2984, "security_exposure": 130, "security_posture": 704, "security_signal": 5}
  }
}
```

The parameters:

| Parameter | What it does |
|---|---|
| `from`, `to` | The window. `from` defaults to 24 hours. |
| `source` | One of `flow`, `probe`, `metric`, `alert`, `topology`, `syslog`, `sot_drift`, `trap`, `cloud`, `app_identity`, `controller`, `verification`, `audit`. An unknown value returns 400. |
| `severity` | One of `info`, `warn`, `high`, `crit`. |
| `entity_type` | One of `device`, `interface`, `path`, `segment`, `site`, `service`, `prefix`, `app`, `cloud_resource`, or one of the six wireless entity types. |
| `kind`, `entity`, `site`, `q` | Text filters, shape-validated rather than escaped. |
| `class=changes` | Restricts the feed to discrete change events: the change-specific sources, `audit`, and any kind ending in `_change`. |
| `cursor`, `limit` | Keyset paging. `limit` defaults to 100 and caps at 500. |

Three properties of that response are deliberate:

- **`total` is the true window count**, computed over the filter and independent of the cursor. It is never the capped page length.
- **A failed count reports unknown, never zero.** Where the count query fails, `total` is `-1` and the console reads it as unknown. A window count of zero would be a claim that nothing happened.
- **A failed facet reports `null`, not `{}`.** An empty object means the window genuinely holds no events in that dimension. `null` means the facet read failed. Collapsing the two once produced triage chips reading zero critical beside a total in the thousands.

A cursor is returned only on a full page. A short page is the end of the window, so a cursor that would return nothing is never handed back.

One gap is worth knowing. The `source` allowlist gates filtering, not visibility. The capture above holds `security` rows in its facets while `security` is not an accepted `source` value, so those rows appear in the unfiltered feed and in the facet counts but cannot be filtered to on their own. An allowlist gap makes a source un-filterable; it never hides a row.

## Related

- [Search logs](/explore/logs) for the raw records behind a syslog or trap row.
- [Manage alerts](/monitoring/manage-alerts) for the rules behind an alert row.
- [Audit log](/administration/audit-log) for the human and API actions the feed carries as `audit` events.
