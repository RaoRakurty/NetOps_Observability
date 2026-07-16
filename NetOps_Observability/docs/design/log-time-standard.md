# Log-Time Standard — timestamp correctness across the pipeline

Status: **audit complete, clear-cut defects fixed (2026-07-16)**; the
recommended standard in Part 2 is a **draft pending reconciliation with
owner-provided research** (see the note at the top of Part 2).

Trigger: owner report — *"time on the logs looks wrong to me"* (Correlix host
itself is NTP-synced, so the suspicion was timestamp **handling**, not clocks).

This document is deliberately split into:

* **Part 1 — Audited facts.** What the pipeline *actually does*, per log
  family, per hop, verified against source (file:line) and against live data
  on the running stack. These are observations, not opinions; they stay true
  regardless of which standard we adopt.
* **Part 2 — Recommended standard.** The binding rules we propose, distilled
  from industry practice (sources cited). This part is the one to reconcile
  with the owner's own research; changing it does not invalidate Part 1.
* **Part 3 — Defects.** What was broken, what was fixed now, and what is
  designed as follow-up slices.

---

## Part 1 — Audited facts (per family, per hop)

Verified 2026-07-16 against the live stack (`:8000`, host clock
`2026-07-16T21:53Z`, host TZ = UTC, all containers run without any `TZ` env —
i.e. UTC).

### Root cause of the reported symptom (live evidence)

Storage is correct; **display was wrong**. `/api/findings` (and every other
ClickHouse-backed endpoint) returns zone-less strings:

```json
{ "ts": "2026-07-16 21:56:03.562" }   // ClickHouse toString(DateTime64) — no T, no Z
```

The SPA rendered these with `new Date(f.ts).toLocaleString()`. JavaScript
parses a zone-less datetime string as **browser-local** time, so a finding
that happened at 21:56 UTC displays as *21:56 in the viewer's zone* — shifted
by the viewer's whole UTC offset (7 h for a PDT browser). Meanwhile
OpenSearch-backed rows (`"timestamp": "2026-07-16T21:53:35Z"` — verified raw
doc) parse correctly and render browser-local. **Two views of the same
incident showed clocks hours apart, neither labeled.** `tabs/Correlations.tsx`
even carried a `new Date(o.created_at + "Z")` hack — proof the naive-string
problem had already been hit once and patched locally instead of centrally.

Corroborating live checks:

* FortiGate lane ground truth: stored `timestamp: 2026-07-07T01:57:29Z` vs the
  device's own `eventtime=1783389449840331717` (epoch ns) =
  `2026-07-07T01:57:29.840Z` — **exact match**, and the device runs in
  `tz=-0700`, so origin-offset handling through syslog-ng→Vector→OpenSearch is
  correct.
* Fresh SR Linux syslog and Arista traps stored within seconds of host `date`.
* ClickHouse flows: `ts` (insert-time default) ran ~1 s after
  `time_received_ns` in steady state — semantically wrong under lag/replay
  (see F3) but not the visible symptom.
* ClickHouse server timezone: `UTC` (implicit container default — now pinned).

### Per-family findings table

Legend: **origin** = timestamp made by the source; **preserved** = carried
unchanged; **re-stamped** = replaced with pipeline receive time; **assumed** =
parsed with a configured/implicit zone.

| # | Family | Origin | Hops (each: what happens to time) | Verdict |
|---|--------|--------|-----------------------------------|---------|
| F1 | Device syslog, RFC 5424 (SR Linux, FortiGate…) | device clock, offset-stamped | syslog-ng (`syslog-parser()`, `keep-timestamp` default yes → offset **preserved**; `deployment/docker/syslog-ng/syslog-ng.conf:31`) → RFC 5424 relay → Vector `syslog_in` (parses to UTC; `deployment/docker/vector/vector.yaml:58`) → Kafka JSON (`timestamp` RFC 3339 Z) → router → OpenSearch (stored `...Z`, verified live) | **OK** (live-verified exact vs FortiGate eventtime) |
| F2 | Device syslog, RFC 3164 (no TZ, no year) | device clock, **zone-less** | syslog-ng assumed the timestamp was in **its own local zone** — i.e. whatever TZ the container happens to run in (implicitly UTC today, since compose sets no TZ anywhere). A device logging local time, or a base-image/host TZ change, silently shifts every message | **LATENT DEFECT — fixed**: `recv-time-zone("UTC")` + `keep-timestamp(yes)` pinned explicitly (`syslog-ng.conf` options); per-device/site zone override = follow-up S1. RFC 3164's missing *year* is inferred by syslog-ng (year-rollover edge; note only) |
| F3 | Flows (NetFlow/IPFIX/sFlow) | goflow2 **receive** stamp only — `time_received_ns` is the only time field configured (`deployment/docker/goflow2/goflow2.yaml`); flow start/end are **not captured** | goflow2 stdout → Vector docker_logs (`.timestamp` = stdout-read time) → Kafka → router → ClickHouse `netops.flows.ts DateTime64(3) DEFAULT now64(3)` (`clickhouse/init.sql:19`) = **INSERT-time re-stamp** (bus lag/replay would misplace flows) | **DEFECT — fixed**: router now derives `ts` from `time_received_ns` (`vector-router/vector.yaml` flows_decoded). Flow start/end capture = follow-up S2 |
| F4 | Cloud raw logs — AWS S3/CloudWatch lanes (ALB, WAF, VPC flow, Resolver DNS) | provider record carries its own UTC event time (ALB field 1 ISO; WAF `timestamp` epoch-ms; VPC flow `start`/`end` epoch-s; DNS `query_timestamp` ISO) | poller tagged every raw line with `timestamp=_now_iso()` — **ingest-time re-stamp** (`cloud-ingest/poller.py:211`), misplacing batch-delivered records by the S3 delivery lag (ALB ~5 min, VPC flow up to ~10 min, arbitrarily more on backfill) | **DEFECT — fixed**: `cloud_tag.event_ts_for()` parses the record's own event time per family; `ingested_at` records receive time so skew stays observable (`cloud-ingest/cloud_tag.py`) |
| F5 | Cloud change lane (CloudTrail / Activity / Audit) | provider `EventTime` (tz-aware UTC) | `poller.py:407,415` passes `EventTime.isoformat()` through | **OK** |
| F6 | Cloud lanes — GCP / Azure | provider RFC 3339 UTC | GCP: `gcp_log_lanes.py` carries `e["timestamp"]` through; Azure: `occuredTime` / `_iso_from_ms` (epoch-ms → aware UTC, `azure_logs.py:252`); `Last-Modified` strptime is `.replace(tzinfo=utc)`-corrected (`azure_logs.py:182`) | **OK** |
| F7 | Cloud host logs (workload syslog → `cloud_host_log`) | device clock via RFC 5424 | Vector formats origin `.timestamp` as RFC 3339 (`vector/vector.yaml:487`), `now()` only as parse-failure fallback | **OK** |
| F8 | SNMP traps | **no origin wall-clock exists** (PDU carries relative sysUpTime) | receiver stamps receive time `time.Now().UTC().Format(RFC3339Nano)` (`collectors/snmptrap.go:787`) → Vector → OpenSearch (`...Z`, verified live) | **OK** — receive-time is the correct and only choice for traps; the standard documents it as such |
| F9 | Collector metric events | sample time | `time.UnixMilli(ts).UTC().Format(RFC3339Nano)` (`collectors/metric_events.go:111`) | **OK** |
| F10 | Correlation service (anomalies/findings) | event ts from bus + processing time | tz-aware UTC throughout (`datetime.now(timezone.utc)`); **but** inserts zone-less datetime strings into ClickHouse `DateTime64` columns, which CH interprets in the **server** timezone | **LATENT DEFECT — fixed**: server TZ pinned `<timezone>UTC</timezone>` (`clickhouse/custom-settings.xml`); string-insert → epoch-insert migration = follow-up S4 |
| F11 | Go API read path | — | time *ranges* built RFC 3339 UTC (`logs.go:139`); Go-native fields (`FiredAt time.Time`) marshal RFC 3339 with zone — OK. **But** every ClickHouse-backed endpoint returns `toString(ts)` zone-less strings (`flows.go:387`, `correlations.go:190`, `cloud_signals.go:559`, `ai_datasource.go:52`…) | **WIRE-FORMAT DEFECT** — display fixed client-side by the shared parser (F12); emitting RFC 3339 at the API = follow-up S3 |
| F12 | Frontend rendering | — | `new Date(naive).toLocaleString()` parsed CH strings as browser-local (Findings, RCA, panels…); rendering was **unlabeled** and **mixed-zone** across views; ns-epoch fields rendered "Invalid Date" | **ROOT-CAUSE DEFECT — fixed**: shared `lib/time.ts` (zone-less ⇒ UTC contract parse, epoch auto-ranging, labeled formatting, Local/UTC toggle); ~45 call sites across 26 files migrated; `LogTime` and TopBar wired |
| F13 | Container TZ config | — | **no** `TZ` env / localtime mounts anywhere in compose — every service runs UTC, but only implicitly | **OK, now partially pinned** (syslog-ng + ClickHouse explicit); rule R7 makes it policy |

---

## Part 2 — Recommended standard (draft)

> **Reconciliation note (owner request):** the owner will supply his own
> research on log time/date handling. This section is the *proposed* standard
> distilled from the sources below; treat every rule as amendable. Part 1
> (facts) and Part 3 (what was changed) stand regardless. When the owner's
> research lands, reconcile rule-by-rule and mark each rule
> `adopted / amended / replaced`.

### The rules

* **R1 — UTC on the wire and at rest.** Every stored/transported timestamp is
  UTC, serialized RFC 3339 (`2026-07-16T21:56:03.562Z`) in JSON/logs, or UTC
  epoch (unit explicit in the field name, e.g. `_ns`) in binary/columnar
  stores. ClickHouse `DateTime64` columns rely on the server TZ being pinned
  UTC (done) until writers move to epoch inserts (S4).
* **R2 — Origin time is preserved, never re-stamped.** When the source
  provides a time (syslog, cloud provider records, flow exports), that is the
  record's `timestamp` end-to-end. If the source provides an offset, honor it
  (RFC 5424 path — works today, F1).
* **R3 — Receive time is recorded *alongside*, not *instead*.** Every ingest
  hop that can, records `ingested_at` (OTel `ObservedTimestamp` semantics) so
  origin-vs-receive skew is observable. Sources with no origin wall-clock
  (SNMP traps) legitimately use receive time as `timestamp` — documented, not
  accidental.
* **R4 — Zone-less inputs get an *explicit, configured* zone assumption —
  never the container's local zone.** RFC 3164 syslog is the canonical case:
  the assumption is pinned in config (`recv-time-zone("UTC")`), and deviating
  devices get a per-device/site setting (S1) — not a silent shift. Parsers
  must refuse (not guess) zone-less provider strings (`cloud_tag.py`
  `_parse_provider_iso` returns "" for naive strings).
* **R5 — Clock-skew detection.** Flag records whose origin time differs from
  receive time beyond a family-specific tolerance (S5). A device with a wrong
  clock must surface as a *finding*, not as silently misplaced logs.
* **R6 — Display: viewer's local time by default, explicit zone label always,
  one-click UTC toggle.** Times render via ONE shared utility
  (`src/frontend/src/lib/time.ts`): browser-local with the zone token shown
  ("14:56:03 PDT", toggle label "PDT (UTC−7)" — customer language, never
  "browser TZ"), a top-bar Local/UTC knob persisted per user, and tooltips
  carrying the RFC 3339 UTC instant. Zone-less strings from the API parse as
  UTC **by contract** (R1), never browser-local.
* **R7 — Pipeline containers run UTC, explicitly.** No `TZ` envs on pipeline
  services; components whose *parsing* depends on a zone pin it in their own
  config (syslog-ng, ClickHouse — done) so a base-image default can never
  shift data.
* **R8 — Every new ingest lane ships with a time-audit note** (origin field,
  zone semantics, receive-stamp) and parse tests including zone-less,
  DST-boundary, and half-hour-offset (IST) cases.

### Sources

* Elastic — [Considerations for timestamps in centralized logging platforms](https://www.elastic.co/blog/considerations-for-timestamps-in-centralized-logging-platforms) (origin time + `event.created` receive time, UTC normalization).
* OpenTelemetry — [Logs Data Model](https://opentelemetry.io/docs/specs/otel/logs/data-model/) (`Timestamp` vs `ObservedTimestamp` — the R2/R3 split).
* [RFC 3339](https://datatracker.ietf.org/doc/html/rfc3339) (wire format), [RFC 5424](https://datatracker.ietf.org/doc/html/rfc5424) (syslog TIMESTAMP with offset).
* syslog-ng — [Timezones and daylight saving](https://syslog-ng.github.io/admin-guide/020_The_concepts_of_syslog-ng/004_Timezones_and_daylight_saving.html) (`recv-time-zone()`, `keep-timestamp()`; RFC 3164 zone-less semantics).
* Vector — [issue #22704: manual timezone for BSD syslog](https://github.com/vectordotdev/vector/issues/22704) (industry-wide RFC 3164 assumption problem).
* Graylog — [Time Zones: A Logger's Worst Nightmare](https://graylog.org/post/time-zones-a-loggers-worst-nightmare/) (send-UTC-from-devices guidance).
* Datadog — [Custom time frames](https://docs.datadoghq.com/dashboards/guide/custom_time_frames/), [Logs not showing expected timestamp](https://docs.datadoghq.com/logs/guide/logs-not-showing-expected-timestamp/) (store UTC, display local, UTC toggle).
* Grafana — [dashboard timezone options](https://community.grafana.com/t/set-dashboard-to-timezone-other-than-utc-or-local-browser/9010) (browser-local default + UTC option).

---

## Part 3 — Defects and disposition

### Fixed now (this change set)

| Defect | Fix | Tests |
|--------|-----|-------|
| D1 (F12, root cause): CH naive strings parsed browser-local; unlabeled mixed-zone rendering; ns-epoch "Invalid Date" | `src/frontend/src/lib/time.ts` — `parseTs` (zone-less ⇒ UTC contract, epoch s/ms/µs/ns auto-range), labeled `fmtDateTime/fmtTime/fmtDate`, `tzLabel` ("PDT (UTC−7)"), Local/UTC mode with `useTzMode`; TopBar toggle; `LogTime` rewired; ~45 call sites in 26 files migrated (incl. removal of the `+ "Z"` hack); page remounts on toggle | `src/frontend/src/lib/time.test.ts` (28 cases: naive-as-UTC, offsets incl. IST +05:30, DST-boundary render, epoch units, garbage); suite run under `TZ=America/Los_Angeles` and `TZ=Asia/Kolkata` |
| D2 (F4): AWS raw cloud-log lanes re-stamped with ingest time | `cloud_tag.event_ts_for()` per family (ALB/WAF/VPC-flow/DNS); doc `timestamp` = event time, `ingested_at` = receive time, fallback honest | `test_cloud_tag.py` (+3 tests: per-family extraction, never-guess-zone, event-time-wins + skew kept) |
| D3 (F3): ClickHouse flow `ts` = insert time | router `flows_decoded` sets `ts` from `time_received_ns` | `vector validate` green (pure VRL; no test harness for configs) |
| D4 (F2): syslog-ng RFC 3164 zone assumption implicit (container-local) | `recv-time-zone("UTC")` + `keep-timestamp(yes)` pinned with rationale | `syslog-ng --syntax-only` green |
| D5 (F10): CH server TZ unpinned while writers insert zone-less strings | `<timezone>UTC</timezone>` in `clickhouse/custom-settings.xml` | config-only; verified live server already UTC |

### Follow-up slices (designed, not built)

* **S1 — Per-device/site timezone for RFC 3164 sources.** Admin surface: a
  `log_timezone` attribute on device (default UTC), applied either as
  per-source `time-zone()` blocks in a generated syslog-ng include, or as a
  Vector remap keyed by the device→TZ enrichment CSV (same mechanism as
  device→tenant). Needed only when a customer device cannot log UTC.
* **S2 — Flow start/end capture.** Add `time_flow_start_ns` /
  `time_flow_end_ns` to the goflow2 formatter fields, CH columns + router
  mapping, and use flow-start as the analytic time axis. Schema migration →
  own slice.
* **S3 — API wire format to RFC 3339.** Replace `toString(ts)` with an
  explicit UTC RFC 3339 rendering in every CH-backed SELECT (Go API +
  correlation `/findings`). The client already tolerates both; migrating
  removes the naive string class entirely. Coordinate with any non-SPA
  consumers (report renderer, notifiers).
* **S4 — Epoch inserts.** Correlation service + Vector CH sinks insert epoch
  numbers instead of zone-less strings, removing the server-TZ dependency R1
  notes.
* **S5 — Clock-skew flagging.** Ingest-side delta between origin `timestamp`
  and `ingested_at` (now recorded on cloud lanes; syslog/vector can compare
  against `now()` in the normalize remap): beyond tolerance (e.g. |Δ| > 5 min
  for syslog; family-specific for batch cloud lanes) → stamp
  `clock_skew_s` on the record + raise a per-device finding. Renders R5 real.
* **S6 — Chart axes obey the Local/UTC toggle.** ECharts axes currently
  browser-local always; wire the axis label formatter through `lib/time.ts`.
* **S7 — History note.** Records ingested before D2/D3 carry receive/insert
  times; no re-ingestion is proposed (cloud fixtures/lab data — cost outweighs
  value). If a customer-facing backfill ever matters, replay from Kafka/S3 is
  the mechanism.
