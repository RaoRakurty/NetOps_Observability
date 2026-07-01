---
title: Log Search
sidebar_label: Log Search
sidebar_position: 2
description: Search device logs, traps, and flow records with full query syntax; export results; save searches you run often.
---

# Log Search

Once devices are sending **[syslog](/send-data/syslog)**, search everything they say at <kbd>Logs → Log Search</kbd>. The search box accepts anything from bare text to full field-level query syntax, and every result row opens into the complete underlying record.

## Run a search

1. Go to <kbd>Logs → Log Search</kbd>.
2. Type a query in the search box. `*` matches everything; see [Query syntax](#query-syntax) below for field filters.
3. Pick a **signal** from the dropdown next to the box — this selects which log family you search:

   | Signal | What it searches |
   | --- | --- |
   | **All** | Every log family at once |
   | **Syslog (devices)** | Network-device syslog |
   | **fw_logs** | Firewall logs only — a convenience filter over device syslog that narrows to records produced by a firewall (FortiGate, Palo Alto, Versa) or carrying an application identity. It is combined with your query automatically. |
   | **SNMP traps** | Trap events, rendered as readable summaries |
   | **Flows** | Raw flow records (useful for finding one specific conversation; for aggregate traffic analysis use [Flow analytics](/explore/flows)) |

   Platform operators additionally see **App logs** — the platform's own internal logs. Tenant users don't see (and can't query) that option.

4. Set the **time range** with the global picker in the top bar (e.g. **Last 1 hour**).
5. Choose how many results to return — **100 / 200 / 500 / 1000 / 5000 hits**.
6. Click **Search** (or press Enter).

Results are sorted **newest first** and capped at the hit count you chose. The results header shows both numbers: `Results (200 / 14,382 matched)` means 200 rows are loaded out of 14,382 total matches — narrow the query or the time range to converge on what you're after.

:::tip Search from anywhere
Typing into the global **Search…** box in the top bar and pressing Enter lands you here with the query pre-filled — see the [overview](/explore/overview#the-global-search-box).
:::

## Query syntax

The box accepts standard **Lucene query-string syntax**: bare text, field filters, boolean logic, wildcards, and ranges. All of the following work:

| Syntax | Example | Matches |
| --- | --- | --- |
| Bare text | `bgp` | Any record containing "bgp" in any field |
| Quoted phrase | `"neighbor down"` | The exact phrase, in order |
| Field filter | `level:error` | Records whose `level` field is `error` |
| `AND` | `src_addr:10.0.0.5 AND dst_port:22` | Both conditions |
| `OR` | `level:error OR level:warn` | Either condition |
| `NOT` | `bgp NOT keepalive` | First term without the second |
| Grouping `( )` | `(level:error OR level:warn) AND host:core-sw1` | Boolean logic with explicit precedence |
| Wildcard `*` / `?` | `host:edge-*` | `*` = any characters, `?` = one character |
| Field exists | `_exists_:app_id` | Records that have the field at all — e.g. only flows with an identified application |
| Range | `dst_port:[1024 TO 65535]` or `dst_port:>=1024` | Numeric/date ranges, inclusive with `[ ]` |

Field names vary by signal (a syslog record has `host` and `severity`; a flow record has `src_addr`, `dst_addr`, `dst_port`). The reliable way to learn what's available: run a broad search, click a result row, and read the **Document** panel — every field you see there is queryable by name.

Worked examples:

- SSH sessions toward one server: `dst_addr:10.0.0.5 AND dst_port:22` (signal: **Flows**)
- Everything a device said, errors first: `host:core-sw1` (signal: **Syslog (devices)**), then sort by **Level**
- Firewall traffic identified as a specific app: `app_id:*dropbox*` (signal: **fw_logs**)

If the query can't be parsed, an **Error:** line appears under the search bar with the reason — fix the syntax and re-run.

## Read the results

Each row shows five columns:

- **Time** — record timestamp (sortable).
- **Source** — where it came from: the device hostname for syslog, the source IP for flow records.
- **Level** — severity, color-coded; the row's left edge carries the same accent so scanning for red is fast.
- **Application** — the identified application (from firewall application control or the platform's traffic classifier) when the record carries one; `—` otherwise.
- **Message** — a normalized, human-readable summary where one exists (traps read as "Arista Layer-2 FDB trap…", not a raw OID), else the raw message.

Click any column header to sort. **Click a row** to open the full record: the headline fields plus the complete **Document** — every field of the underlying record, pretty-printed. This is where you find exact field names to refine your query.

## Export results

Two export modes sit above the results table, in **CSV**, **JSON**, **NDJSON**, or **Excel**:

- **Export selected** — tick the checkbox on specific rows (or the header checkbox for all loaded rows); export buttons appear as soon as at least one row is selected.
- **Export all** — exports the **entire matched set** for the current query, signal, and time range, not just the loaded rows. Small sets download immediately; large ones are queued (`Large export (N rows) queued — preparing…`) and download automatically when ready.

## Save a search

1. Get the query, signal, and results the way you want them.
2. Click **★ Save** next to the Search button.
3. Name it (e.g. `BGP neighbor down across the fleet`) and confirm.

The saved search stores the **query and the signal** — the time range stays live, so reopening it later searches the *current* window, which is what you want for a recurring check.

## Use saved searches

1. Go to <kbd>Logs → Saved Searches</kbd>. The table lists each search's **Name**, **Query**, **Signal**, and last-updated time.
2. Click **Open** to apply the query and jump straight back to Log Search with results.
3. Click **✕** to delete one (with confirmation).

Saved searches are also findable by name from the global search box and the <kbd>⌘K</kbd> palette.

## Troubleshooting

**No results:**

- **Time range too narrow** — widen the top-bar range first; it's the most common cause.
- **Wrong signal** — a `src_addr:` query returns nothing under **Syslog (devices)**; flow fields live under **Flows**.
- **Devices aren't sending yet** — verify the feed per [Send syslog](/send-data/syslog); a device must be configured to export before anything can match.
- **Over-exact field filter** — field values are often lowercase-analyzed; try the bare text form (`error` instead of `level:Error`) or a wildcard.

**Error under the search bar** — the query didn't parse. Check unbalanced quotes/parentheses and that `AND`/`OR`/`NOT` are uppercase.

**"App logs" option missing** — it's restricted to the platform operator by design; tenant users never search platform-internal logs.

Everything here is **tenant-scoped** — you only ever search your own logs, enforced at query time.
