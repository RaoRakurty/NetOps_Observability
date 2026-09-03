---
title: Search logs
description: Search device syslog, traps, firewall logs and sampled flow records, read the retention floor and the exact match count, page a bounded result set, and export it.
page_type: task
sidebar_position: 3
---

# Search logs

**Explore → Logs** is full-text search over the records devices actually sent. It is the only explore plane that returns raw documents, one per row, with the whole document behind each. A **Cloud Logs** sub-tab covers the cloud plane.

## Before you begin

- An authenticated session. Every search runs against a tenant-scoped surface, so another tenant's records are never returned.
- Devices sending syslog or traps. See [Send syslog](/send-data/syslog) and [Send SNMP traps](/send-data/traps).
- The **App logs** source is the platform's own container and API logs, and is offered to the platform owner only. The backend refuses it for anyone else.

## Steps

### Step 1 - Choose a log source and a window

1. Choose a source from the first dropdown: **All**, **App logs**, **Syslog (devices)**, **Firewall logs**, **SNMP traps** or **Flows**. It sets the `signal` parameter on the search.
2. Choose a range: **Last 15m**, **Last 1h**, **Last 6h** or **Last 24h**, or let the top-bar range picker drive it.
3. Choose a page size.

**Firewall logs** is a convenience filter over the syslog index. It narrows to records a firewall vendor parser produced, or that carry the vendor-neutral application contract, so it works across vendors rather than matching a vendor name.

### Step 2 - Read the retention floor before you read the results

Under the search form, the page states how far back the visible store actually goes, so an empty result can be told apart from a window that predates the data:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/logs/retention?signal=syslog"
```

```json
{"days":13,"oldest":"2026-08-21T00:00:00Z","signal":"syslog","total":2172327}
```

The line reads `This store holds N logs — going back to <timestamp> (N days of history).` The total is an exact count over the same tenant-scoped surface the search reads, not a capped estimate. Each source is its own store with its own retention, so the line is re-read when you change the dropdown. Where a source has nothing stored, it reads `No logs stored yet for this signal.`

### Step 3 - Run the search and read the count

Type a query and run it. The results heading states exactly what you are looking at:

- `Results — showing N of M matched` when the window holds more than the loaded page.
- `Results (N — all matches)` when every match is loaded.

The match count is exact. The search asks the store to track total hits rather than accepting the ten-thousand-document estimate cap.

The flows source is the one exception, and it says so. It reads a 1-in-50 sample, and a note under the heading states `Flow search reads a 1:N sample — totals are estimates (×N). Exact flow analytics live in the Flows tab (unsampled store).`

### Step 4 - Page through a bounded result set

Every truncated list says it is truncated and offers the rest.

1. Select **Load more**. Its label states the arithmetic: how many rows it will fetch, and how many of the total are already loaded.
2. Repeat until the button disappears.

Interactive paging ends at 10,000 rows. Past that the page says so and points at the export path for the full set, because the search engine's paging window ends there. Each page is fetched with an offset against the same frozen query and window, so an appended page belongs to the same result set.

### Step 5 - Export

- Select rows to export just those, in **CSV**, **JSON**, **NDJSON** or **Excel**.
- With no selection, use the export-all controls to take the entire result set in any of the same four formats.

A large export is queued rather than blocked, and the page reports it: `Large export (N rows) queued — preparing…`, where `N` is the matched count reported by the export request, or a question mark when the count is not known.

### Step 6 - Save the search

Select the save control, name the search, and find it again under **Explore → Saved Searches**.

## What you see

Rows in time order, each with time, source, level, application and message, and the full document behind the row. Where the search returns nothing, the page reads `No results. Try widening the time range or relaxing the filter.` Read that against the retention floor above: no results inside a window the store does not cover is an artifact of the window, not evidence of a quiet network.

The routes behind the page:

| Route | What it does |
|---|---|
| `POST /api/logs/search` | Runs the query, bounded by size and offset, and returns hits plus an exact total. `GET` is accepted too. |
| `GET /api/logs/retention` | The retention floor for one source: exact total, oldest timestamp, days of history. |
| `GET /api/logs/indices` | The indices behind the sources. |
| `GET /api/logs/export` | The whole result set, synchronous or queued. |
| `POST /api/logs/export/rows` | Only the rows you selected. |

## Related

- [Review the event feed](/explore/events) for syslog and traps merged with active alerts on one timeline.
- [Analyse flows](/explore/flows) for the unsampled flow store.
- [Reading logs](/noc-guide/reading-logs) for what the fields mean during an incident.
