# Log-Time Standard — timestamp correctness across the pipeline

Status: **audit complete; defects D1–D5 and follow-up slices S3–S6 + S5
shipped; Part 2 is the ADOPTED standard (reconciled 2026-07-17,
owner-delegated)** — see the per-rule verdicts at the top of Part 2.

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

## Part 2 — Adopted standard

> **Reconciliation record (2026-07-17, delegated by the owner):** each rule
> was checked against authoritative sources (RFC 3339/5424/3164, the OTel
> Logs Data Model, ClickHouse DateTime64 semantics, the ECMA-262 Date-parsing
> divergence, and the normalization practice documented by Splunk / Datadog /
> Elastic / Grafana) **and** against what Part 1 audited about this codebase.
> Verdicts: **R1 AMENDED** (strengthened — the S4 caveat is gone, epoch
> inserts shipped), **R2 ADOPTED**, **R3 ADOPTED**, **R4 ADOPTED**,
> **R5 AMENDED** (per-family tolerances + META-finding semantics, shipped as
> S5), **R6 ADOPTED**, **R7 ADOPTED**, **R8 AMENDED** (post-S4/S5 test
> requirements added). No rule was REJECTED — the external research
> uniformly corroborated the draft; per-rule provenance notes are inline.

### The rules (adopted)

* **R1 — UTC on the wire and at rest.** *(AMENDED 2026-07-17 — strengthened;
  shipped as S3 `f8c2209` + S4 `84ad149`.)* Every stored/transported
  timestamp is UTC: serialized RFC 3339 **with the `Z` designator**
  (`2026-07-16T21:56:03.562Z`) in JSON/logs/APIs, and a **scaled-integer UTC
  epoch** (unit explicit — epoch-ms for `DateTime64(3)`, `_ns`-suffixed
  fields for nanoseconds) in binary/columnar stores. Rationale (provenance):
  ECMA-262 parses a zone-less date-time as **local** time (and, divergently,
  a date-only string as UTC) — so an unlabeled wire string WILL be
  misinterpreted by some consumer; ClickHouse interprets an inserted STRING
  in the server/column timezone but an inserted INTEGER as a scaled UTC Unix
  timestamp — so epoch inserts are structurally timezone-proof where strings
  are configuration-dependent. The server-TZ pin (R7) remains as defense in
  depth, no longer as a correctness dependency.
* **R2 — Origin time is preserved, never re-stamped.** *(ADOPTED 2026-07-17.)*
  When the source provides a time (syslog, cloud provider records, flow
  exports), that is the record's `timestamp` end-to-end. If the source
  provides an offset, honor it (RFC 5424 path — works today, F1).
  Provenance: identical to the OTel Logs Data Model `Timestamp` ("when the
  event occurred, measured by the origin clock") and Elastic's
  origin-time-first guidance; Part 1's D2/D3 defects were exactly violations
  of this rule.
* **R3 — Receive time is recorded *alongside*, not *instead*.** *(ADOPTED
  2026-07-17.)* Every ingest hop that can, records `ingested_at` (OTel
  `ObservedTimestamp` semantics; Datadog's `event_time` vs `ingestion_time`
  distinction) so origin-vs-receive skew is observable — this is what makes
  R5 implementable at all. Sources with no origin wall-clock (SNMP traps)
  legitimately use receive time as `timestamp` — documented, not accidental
  (F8), matching the OTel conversion rule "use Timestamp if present,
  otherwise ObservedTimestamp".
* **R4 — Zone-less inputs get an *explicit, configured* zone assumption —
  never the container's local zone.** *(ADOPTED 2026-07-17.)* RFC 3164
  syslog is the canonical case: its TIMESTAMP carries **no year and no
  zone**, and RFC 5424 (A.1) merely says the relay's zone MAY be used for
  conversion — i.e. the standard itself leaves the assumption to
  configuration, so we pin it (`recv-time-zone("UTC")`), matching the
  receiver-side guidance Elastic/Vector document for BSD syslog. Deviating
  devices get a per-device/site setting — resolved as **S1
  designed-out-until-needed** (see Part 3): with the UTC pin explicit, the
  platform-wide default is correct and safe, R5 now *detects* any device
  actually logging non-UTC local time, and the admin surface is built only
  when such a device exists. Parsers must refuse (not guess) zone-less
  provider strings (`cloud_tag._parse_provider_iso` returns "" for naive
  strings). The RFC 3164 missing *year* is inferred by syslog-ng
  (year-rollover edge; noted, accepted).
* **R5 — Clock-skew detection.** *(AMENDED 2026-07-17 — per-family
  tolerances + META-finding semantics; shipped as S5 `55f8023`.)* Flag
  records whose origin time differs from receive time beyond a
  **family-specific** tolerance: syslog 300 s; batch cloud lanes sized ~2–3×
  their documented delivery lag (lb 900 s, flow 1800 s, waf 600 s, dns
  900 s) so legitimate S3 delivery lag never fabricates a finding. A device
  with a wrong clock surfaces as a per-device `clock_skew` *finding* (and a
  lagging lane as a per-lane one) — never as silently misplaced logs.
  Findings are META evidence: recorded for operators, never fed to the RCA
  engine window (a wrong clock must not lend a fake corroborating plane).
  Provenance: streaming-pipeline practice (flag `future_timestamp` beyond a
  max-drift budget; monitor event-time vs ingest-time delta per source).
* **R6 — Display: viewer's local time by default, explicit zone label always,
  one-click UTC toggle.** *(ADOPTED 2026-07-17; chart axes closed by S6
  `e4f62c7`.)* Times render via ONE shared utility
  (`src/frontend/src/lib/time.ts`): browser-local with the zone token shown
  ("14:56:03 PDT", toggle label "PDT (UTC−7)" — customer language, never
  "browser TZ"), a top-bar Local/UTC knob persisted per user, tooltips
  carrying the RFC 3339 UTC instant, and chart axes/crosshairs obeying the
  same knob (`fmtAxisTick`). Zone-less strings from the API parse as UTC
  **by contract** (R1), never browser-local. Provenance: store-UTC /
  display-per-user-preference is the uniform practice across Splunk (per-user
  timezone setting), Datadog (Preferences → Time zone) and Grafana
  (browser-local default + UTC option).
* **R7 — Pipeline containers run UTC, explicitly.** *(ADOPTED 2026-07-17.)*
  No `TZ` envs on pipeline services; components whose *parsing* depends on a
  zone pin it in their own config (syslog-ng, ClickHouse — done) so a
  base-image default can never shift data. Post-S4 the ClickHouse pin is
  defense in depth (integer inserts are TZ-proof), kept deliberately.
  Provenance: Splunk deployment best practice — run every server in the
  logging infrastructure on UTC.
* **R8 — Every new ingest lane ships with a time-audit note** (origin field,
  zone semantics, receive-stamp) **and parse tests**. *(AMENDED
  2026-07-17.)* Tests must cover: zone-less, DST-boundary, and
  half-hour-offset (IST) parse cases; the epoch **scaled-integer insert**
  form for any ClickHouse-bound writer (S4 contract); and the lane's
  clock-skew **tolerance choice** with a stated delivery-lag rationale (S5 —
  `FAMILY_SKEW_TOLERANCE_S` is the template).

### Sources

* Elastic — [Considerations for timestamps in centralized logging platforms](https://www.elastic.co/blog/considerations-for-timestamps-in-centralized-logging-platforms) (origin time + `event.created` receive time, UTC normalization).
* OpenTelemetry — [Logs Data Model](https://opentelemetry.io/docs/specs/otel/logs/data-model/) (`Timestamp` vs `ObservedTimestamp` — the R2/R3 split).
* [RFC 3339](https://datatracker.ietf.org/doc/html/rfc3339) (wire format), [RFC 5424](https://datatracker.ietf.org/doc/html/rfc5424) (syslog TIMESTAMP with offset).
* syslog-ng — [Timezones and daylight saving](https://syslog-ng.github.io/admin-guide/020_The_concepts_of_syslog-ng/004_Timezones_and_daylight_saving.html) (`recv-time-zone()`, `keep-timestamp()`; RFC 3164 zone-less semantics).
* Vector — [issue #22704: manual timezone for BSD syslog](https://github.com/vectordotdev/vector/issues/22704) (industry-wide RFC 3164 assumption problem).
* Graylog — [Time Zones: A Logger's Worst Nightmare](https://graylog.org/post/time-zones-a-loggers-worst-nightmare/) (send-UTC-from-devices guidance).
* Datadog — [Custom time frames](https://docs.datadoghq.com/dashboards/guide/custom_time_frames/), [Logs not showing expected timestamp](https://docs.datadoghq.com/logs/guide/logs-not-showing-expected-timestamp/) (store UTC, display local, UTC toggle).
* Grafana — [dashboard timezone options](https://community.grafana.com/t/set-dashboard-to-timezone-other-than-utc-or-local-browser/9010) (browser-local default + UTC option).

Added at reconciliation (2026-07-17):

* [RFC 3164](https://datatracker.ietf.org/doc/html/rfc3164) — BSD syslog TIMESTAMP: no year, no zone (the R4 canonical case); RFC 5424 A.1: relay zone "MAY be used" on conversion — i.e. an explicit configured assumption is required.
* ClickHouse — [DateTime64](https://clickhouse.com/docs/sql-reference/data-types/datetime64): an inserted **integer** is "an appropriately scaled Unix Timestamp (UTC)"; an inserted **string** "is treated as being in column timezone" — the R1/S4 rationale.
* ECMA-262 / MDN — [Date parsing](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/parse): zone-less date-times parse as **local** time while date-only forms parse as UTC (a documented divergence from ISO 8601) — why the wire must always carry `Z` (R1) and why the SPA parses zone-less strings by contract (R6).
* Splunk — [How time zones are processed](https://docs.splunk.com/Documentation/SplunkCloud/latest/Search/Abouttimezones): `_time` stored UTC, rendered per user's timezone preference; deployment best practice = every server on UTC (R6/R7).
* Datadog — event_time vs ingestion_time distinction (R3); OTel Logs Data Model `Timestamp`/`ObservedTimestamp` (already cited) remains the R2/R3 anchor.

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
| S3 (F11, shipped 2026-07-17, `f8c2209`): API wire format — every CH-backed SELECT returned zone-less `toString()` datetime strings | `chISO()` (`src/backend/ch_time_wire.go`) renders `concat(replaceOne(toString(x,'UTC'),' ','T'),'Z')` — RFC 3339 UTC — across all Go API CH SELECTs (findings/tunnels, correlations list + timeline slice + graph, timeintel, cloud signals/handlers/overview/ingestion, events feed, path graph, AI datasource, health score) **and** the correlation service `/findings`. Timeline window round-trip de-shadowed (`ts_iso` aliases + CH-native WHERE literals); `isDatetimeToken` accepts RFC 3339; the one strict server-side parser (`cloud_ingestion.go`) moved to dual-format `parseCHTime` (parseChTS / timeintel / ticketing / report parsers were already dual-format) | `ch_time_wire_test.go`: fragment pin, dual-format parser matrix, `isoTS` passthrough, plus a source-wide regression guard failing any new zone-less datetime `toString()`; `correlations_test.go` token contract updated deliberately |
| S4 (F10/R1, shipped 2026-07-17, `84ad149`): writers inserted zone-less datetime strings ClickHouse reads in the **server** timezone | Every CH datetime insert is now a UTC **epoch-ms integer** (DateTime64(3) scaled Unix timestamp — immune to server/column TZ): correlation `_ch_dt` (signals.py + engine.py → corr_signals/objects/current/archive), write-amp `window_start` (main.py), Vector router flow `ts` (`to_int(floor(time_received_ns/1e6))`), and the Go writers (`appid_fusion_store.go` event_time/fused_at, `path_graph_store.go` chTime). `_parse_ch_dt` accepts int / digit-string / zone-less / RFC 3339, so from_ch_row round-trips both stored and in-process rows; `signal_id` derivation (source\|native_id\|ts-ms) is format-independent — no identity churn | `test_ch_epoch_inserts.py` (writer format, parser matrix, byte-faithful round trip, identity stability); `test_episodes.py` frozen-schema pin updated deliberately; `vector validate` green; full correlation suite 643 passed |
| S6 (F12 tail, shipped 2026-07-17, `e4f62c7`): ECharts time axes always rendered browser-local, contradicting the Local/UTC knob | `fmtAxisTick` in `lib/time.ts` (tiered like ECharts defaults: midnight ⇒ "Jul 16", whole minute ⇒ "14:56", else "14:56:03", honoring the active TzMode) + `timeAxisTicks()` fragment in `theme/charts.ts` (axis labels **and** the crosshair pill via `fmtDateTime`); applied to every visible `type:"time"` axis (board panels, Overview/Flows/MetricsExplorer panels) — charts rebuild on toggle via the existing page remount | `lib/time.test.ts` +5 cases (UTC/local tiers, mode override, garbage ⇒ empty), suite run under `TZ=America/Los_Angeles` and `TZ=Asia/Kolkata`; `tsc -b` + full vitest 635 passed |
| S5 (R5, shipped 2026-07-17, `55f8023`): no clock-skew detection — a wrong device clock or a lagging ingest lane surfaced as silently misplaced records | Ingest-side stamping + a per-device/per-lane finding, tolerance **per family**: syslog — Vector `syslog_normalized` compares origin vs `now()`, stamps `clock_skew_s` past 300 s (timestamp itself never rewritten, R2/R3); cloud — `cloud_tag.clock_skew_s()` with `FAMILY_SKEW_TOLERANCE_S` (lb 900 s, flow 1800 s, waf 600 s, dns 900 s — batch S3 delivery lag inside the envelope is legitimate, not a finding). Finding: new canonical kind **`clock_skew`** (registered in `producers.EMITTED_KINDS`, `confirmability.KIND_MODALITY` = management_plane, `cloud_producers.CLOUD_KINDS`, and **INTENTIONAL_BLIND** in coverage.py so the #99 orphan-producer gate passes) raised per device (main.py `handle_syslog`, cooldown 900 s) and per lane (poller → `cloud_events.clock_skew_event` on netops.cloud, throttle 1800 s → `handle_cloud`). META evidence by design: persisted to corr_signals for operators but **never** `buffer_signal()`ed — a wrong clock cannot lend a fake modality plane to a real fault | `test_clock_skew.py` (producer matrix, wire adapter, registration in every gate), `test_cloud_tag.py` +4 (per-family envelope, signed direction, never-guess), `test_cloud_events.py` clock_skew_event shape; correlation suite 647 passed, cloud-ingest suite 194 passed, mypy clean, `vector validate` green on both configs |

### Remaining slices (S3–S6 + S5 shipped — see the fixed table above)

* **S1 — Per-device/site timezone for RFC 3164 sources.** **RESOLVED
  2026-07-17: designed-out-until-triggered (decision delegated).** Not
  built, and correctness does not currently require it: (a) the zone
  assumption is now explicit and platform-wide-correct
  (`recv-time-zone("UTC")`, D4) — every audited device logs UTC or carries
  an RFC 5424 offset (F1/F2); (b) S5 clock-skew flagging now *detects* the
  exact failure S1 would fix — a device logging non-UTC local time surfaces
  as a per-device `clock_skew` finding with a stable ~whole/half-hour offset
  — so the need is observable, never silent; (c) building a tenant-scoped
  per-device TZ admin surface with zero known consumer devices adds a config
  plane (and its isolation/RLS/test surface) speculatively, against
  verify-before-building. **Build trigger:** the first `clock_skew` finding
  whose offset is a stable zone-like delta on a device that cannot be
  reconfigured to log UTC. **Plan of record when triggered** (unchanged from
  the original design): a `log_timezone` attribute on the device (default
  UTC, tenant-scoped per §3a), applied as a Vector remap keyed by a
  device→TZ enrichment CSV (same mechanism as device→tenant), admin surface
  per the config-form conventions (shared primitives, required-field legend,
  customer-facing language), cross-org isolation test included.
* **S2 — Flow start/end capture.** Add `time_flow_start_ns` /
  `time_flow_end_ns` to the goflow2 formatter fields, CH columns + router
  mapping, and use flow-start as the analytic time axis. Schema migration →
  own slice.
* **S7 — History note.** Records ingested before D2/D3 carry receive/insert
  times; no re-ingestion is proposed (cloud fixtures/lab data — cost outweighs
  value). If a customer-facing backfill ever matters, replay from Kafka/S3 is
  the mechanism.
