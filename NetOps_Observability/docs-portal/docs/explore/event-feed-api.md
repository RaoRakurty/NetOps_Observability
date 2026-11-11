---
title: Event feed API
description: The read-only, keyset-paginated feed of device events, configuration changes and audit actions behind the What changed panel, with its parameters and its counting rules.
page_type: reference
sidebar_position: 7
---

# Event feed API

To read syslog, SNMP traps, flow records and firewall logs on one timeline in the console, open **Explore → Logs**. Its **Events** tab is the default. See [Search logs](/explore/logs). The alerts that are firing now are on **Operations → Active Alerts**. See [Manage alerts](/monitoring/manage-alerts).

## The unified feed API

Behind the wider event model sits `/api/events/feed`, the read-only, keyset-paginated view over the normalized-observation spine. It is the same store the correlation engine reads, and there is no second event table. It carries more than the log search: device events, correlated observations, configuration changes, and **audit** actions, so "what changed" includes the humans and the API clients.

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
- [Manage alerts](/monitoring/manage-alerts) for the alerts behind an `alert` row.
- [Audit log](/administration/audit-log) for the human and API actions the feed carries as `audit` events.
