# Data retention map — how much history we keep, and what "resolved" means for storage

> Owner questions (2026-07-18): *"How much historical data needs to be stored?
> Do we delete once it's resolved?"*
> Status: **answering design** — consolidates what is already shipped and binding
> (#101 correlation data contract) into one per-lane map, states the resolved-object
> lifecycle explicitly, and lists the open decisions. The correlation lane's deep
> design lives in [`correlation-data-contract.md`](correlation-data-contract.md);
> this page is the whole-platform view.

---

## 1. The direct answers

**Do we delete once it's resolved? — No.** Resolution changes an object's
*tier*, never its *existence*. Deleting on resolve would destroy the three
things the history exists for:

1. **Engine calibration (#67 P4 / Stream 4)** — replay calibration needs the
   full incident corpus, especially resolved incidents (they carry the ground
   truth of what the root cause turned out to be).
2. **Audit & post-incident review** — "what did the platform know, when, and
   what did it conclude" must survive the incident itself.
3. **Reliability analytics (#84)** — TTA/TTM/recovery percentiles are computed
   *over resolved incidents*; delete-on-resolve would empty the metrics.

**How much history? — time-tiered, profile-driven, never silently lost.**
Hot stores keep a bounded, profile-chosen window; the monthly cold-export cron
writes closed month-partitions to Parquet (`data/clickhouse-cold/`) *ahead of*
the TTL horizon, so aging out of the hot tier is a **move, not a delete**.
Keep-forever is an explicit contract knob (`…_DAYS=0`), not an accident.

## 2. Lifecycle of a correlation/RCA object (shipped, #101)

```
open ──────────────► closed / merged ─────────► cold Parquet ─────► hot TTL drop
 kept in hot store    hot for CLOSED_DAYS       exported monthly     whole month-
 INDEFINITELY —       (prod 90d, lab 60d);      BEFORE the horizon   partitions drop;
 TTL is
 `WHERE state != 'open'`                        restorable to        cold copy remains
                                                netops_restore
```

- An **open** object is never TTL'd, no matter how old (`corr_current` TTL
  carries `WHERE state != 'open'`).
- Version history (`corr_objects/edges/evidence`) stays hot for HISTORY_DAYS;
  replay input (`corr_signals_archive`) for ARCHIVE_DAYS.
- Restore path: `scripts/ch-cold-restore.sh` → isolated `netops_restore` DB
  (never live tables), per-(tenant,month) file granularity.
- Safety: 7-day floor on every knob; TTL changes are metadata-only; expiry
  drops whole month-partitions (≤1-month lag = export grace window).

## 3. Per-lane retention map (live values, 2026-07-18)

| Lane | Store | Hot retention (this lab) | Knob / profile | Cold tier | Today's size |
|---|---|---|---|---|---|
| Correlation objects (current) | CH `corr_current` | open: forever · closed/merged: **60d** | `CORR_RETENTION_CLOSED_DAYS` (prod 90) | Parquet export | 15 MiB |
| Correlation version history | CH `corr_objects/edges/evidence` | **90d** | `CORR_RETENTION_HISTORY_DAYS` (prod 180, extended 730, 0=forever) | Parquet export | 255 MiB |
| Replay signal archive | CH `corr_signals_archive` | **45d** | `CORR_RETENTION_ARCHIVE_DAYS` (prod 90) | Parquet export | 693 MiB |
| Live signal window | CH `corr_signals` | 30d | fixed | — (derived) | 78 MiB |
| Findings | CH `findings` | 90d | fixed TTL | none yet | 22 MiB |
| Flows | CH `flows` | 7d | fixed TTL | none (raw firehose) | 140 MiB |
| Path/tunnel history | CH `path_*`, `tunnels` | 90d | fixed TTL | none | ~33 MiB |
| Logs | OpenSearch `netops-*` | **14d** (ISM auto-delete) | `OPENSEARCH_LOG_RETENTION_DAYS` | none (Export-all UI for ad-hoc) | — |
| Metrics | VictoriaMetrics | **30d** | `VICTORIA_RETENTION` | none | — |
| Event bus | Kafka `netops.*` | 72h / 512MB — transit, not a store (#96e) | `BUS_RETENTION_MS/BYTES` | n/a | — |
| Incidents, timelines, time-metrics | PG | **unbounded** | none | n/a | ~35 MB |
| Audit events | PG `audit_events` | **unbounded** | none | n/a | 9.6 MB |
| Ticket links / connector run history | PG | **unbounded** | none | n/a | ~13 MB |

**Reading the table:** raw/high-volume lanes (flows, logs, bus) are short and
that is correct — they are *evidence inputs* whose distilled conclusions live in
the correlation lane; the correlation lane is the system of record and carries
the long horizons plus the only cold tier. PG lanes are the human-workflow
record (incidents, audit) — tiny by volume, currently kept forever.

## 4. Storage budget (this lab, measured)

- ClickHouse total for the corr family: **~1.0 GiB compressed** (bounded:
  ~4 GiB steady-state at current write rate under the 45d archive TTL).
- The #111 churn fix (stop create-then-merge per sweep) cuts ~90% of the
  ~20M archive rows/day; steady-state drops accordingly. Retention design does
  NOT depend on that fix — TTLs bound the worst case either way.
- Sizing interlock: hot horizons are a *disk input* to the #102 resource
  planner; a customer choosing `extended` (730d) must size disk from the
  planner, not defaults.

## 5. Open decisions (owner)

1. **PG history bounds before scale (Stream 6).** `incidents`,
   `incident_time_metrics`, `audit_events`, `connector_run_history` have no
   retention. Volumes are trivial today (≤35 MB), so nothing is urgent — but
   SaaS needs an explicit contract: propose keep-forever for `incidents` +
   `audit_events` (they ARE the record; compliance wants them), bounded prune
   for `connector_run_history` (e.g. 90d) and `integration_events`.
2. **Per-tenant retention contracts.** Knobs are global today. SaaS
   contract-tier retention (tenant A: 90d, tenant B: 730d) is roadmapped in
   the data contract (§8 — schema is already tenant-led everywhere); decide
   when a paying customer needs it, not before.
3. **Findings cold tier.** `findings` (90d fixed) has no export; if customers
   treat findings as a compliance record, extend the cold-export job to it.
4. **Customer-facing retention page.** This map should surface in docs-portal
   (procurement asks exactly these two questions). Fold into the first-customer
   acceptance checklist gate 1 ("retention explicit").

## 6. What this means for the two questions, in one line each

- **How much?** Distilled RCA record: 90–180d hot + full history in cold
  Parquet (restorable); raw inputs: 7–30d; human record (incidents/audit):
  forever (pending decision 1).
- **Delete on resolve?** Never. Resolution starts a *clock* (CLOSED_DAYS in
  hot), and the cold export runs before that clock expires.
