# Correlix / NetOps_Observability — Production Readiness Audit
**Date:** 2026-07-21
**Auditor:** principal-eng review (agent)
**Repo:** /home/rao/Projects/NetOps_Observability/NetOps_Observability
**Live stack:** http://localhost:8000 (25 containers up)
**Defect class hunted:** "the system knows something went wrong but has no channel to say so" —
silent data loss, silently ignored input, 2xx without persistence, unbounded resources,
inconsistent handling of the same concern across sibling code paths.

**Seed defect (given):** DEF-6 — float `ts` on `netops.applogs` rejected by OpenSearch
`strict_date_optional_time||epoch_millis`, dropped by Vector with no DLQ/alert.
77 parse failures / 217 dropped events in 30 min.

---

## Status log (append-only; durable state)
- 20:49 file created, chmod 600
- 21:00 SECTION 1 (ingest) + SECTION 2 (bus schema) complete — evidence gathered live

---

# SECTION 1 — INGEST PIPELINE

> **READ SECTION 3 FIRST if you are looking at line numbers.** All file:line references in
> Sections 1–2 are against `vector-router/vector.yaml` **as it existed at 20:53Z (297
> lines)** — the version running in the container. The owner edited that file to 368 lines
> at **20:59:23Z, during this audit**. Section 3 reviews the new version and confirms it is
> **not yet deployed**, so every measurement below reflects live production behaviour.

## Measured baseline (live, vector-router uptime 16:50:01Z → 20:53:01Z = 4h03m)

Source: `curl http://172.18.0.9:9598/metrics` (vector-router internal_metrics), and
`docker logs --since 5h netops-vector-router-1`.

| lane | received | sent to sink | discarded (intentional=false) |
|---|---|---|---|
| applogs  | 71,258 | 67,762 | **3,457** |
| syslog   | 29,564 | 29,561 | 0 (3 in flight) |
| snmptrap |    208 |    208 | 0 |
| flows    |    100 | 100 CH / 2 OS (1:50 sample) | 0 |
| cloudlogs|      0 |      0 | 0 |
| cloudcosts|    27 |     27 | 0 |

Exact document-level rejection count from the router log (5h window):
```
bulk responses containing errors: 519
failed to parse field [ts]:       914     <- every single rejection is on `ts`
suppressed log lines:            1072     <- Vector's own error log is rate-limited
```

### F-01 [CRITICAL] `ts` mapping on the applogs index is ACCIDENTAL, not designed — the
### producer that logs first each UTC day decides which producer is silently dropped for 24h

**This is the true root cause of DEF-6, and it is worse than "strict mapping".**

Evidence — the `netops-applogs` index template does NOT declare `ts` at all:
```
=== netops-applogs patterns ['netops-applogs-*']
  dynamic: None            (=> defaults to `true`)
  declared props: 8
     msg, tenant_id, component, container_name, level, service, message, timestamp
```
`ts` is absent. Yet the live index has it typed:
```
GET netops-applogs-untagged-2026.07.21/_mapping/field/ts
  "ts": { "type": "date" }
```
=> `ts:date` was created by **dynamic mapping** from whichever document carrying an
RFC3339 `ts` string happened to be indexed first after 00:00 UTC.

Verbatim rejection from the live bulk response (`docker logs netops-vector-router-1`):
```
"status":400,"error":{"type":"mapper_parsing_exception",
 "reason":"failed to parse field [ts] of type [date] ... Preview of field's value: '1.7846673819659653E9'",
 "caused_by":{"reason":"failed to parse date field [1784667381.9659653] with format
              [strict_date_optional_time||epoch_millis]"}}
```
Vector's response:
```
vector::sinks::util::retries: Not retriable; dropping the request.
component_events_dropped: Events dropped intentional=false count=3
   reason="Service call failed. No retries or retries exhausted."
```

**Why "accidental" makes it Critical rather than Medium:** the mapping is decided by a
race at index-creation time. Today the RFC3339 producer (`api`, Go) won, so the float
producer (`cloud-ingest`, Python) is dropped. **On a day when a `cloud-ingest` log line
lands first, `ts` maps as `float` and the Go API's own audit/access logs become the
silently-dropped ones instead.** The failure is nondeterministic day to day, which is why
it has evaded diagnosis.

- **Blast radius:** ~914 docs / 5h = 183/h = **~4,390 application-log documents lost per
  day, permanently, with no dead letter.** Whose logs are lost is nondeterministic.
- **Failure scenario:** a customer-impacting incident occurs; the on-call searches
  application logs for the 10-minute window; the specific service whose logs were dropped
  that day shows a clean gap that is indistinguishable from "that service was quiet".
  RCA reaches the wrong conclusion from an incomplete record.
- **Fix (in priority order):**
  1. `deployment/docker/vector/vector.yaml:132` (`applogs_normalized`) — normalize `ts`
     at the AGGREGATOR, where the merge happens, so the contract is enforced once for all
     consumers, not per-sink. Add after the `merge()`:
     ```vrl
     if exists(.ts) {
       tsf = to_float(.ts) ?? null
       if tsf != null {
         .ts = to_int(floor(tsf * 1000))              # epoch seconds (float or int) -> epoch ms
       } else {
         tsp, terr = parse_timestamp(to_string(.ts) ?? "", "%+")
         if terr == null { .ts = to_unix_timestamp(tsp, unit: "milliseconds") } else { del(.ts) }
       }
     }
     ```
     This mirrors exactly what `flows_decoded` (vector-router/vector.yaml:152) and
     `cloudcosts_normalized` (:188) already do — the inconsistency between siblings IS
     the bug.
  2. Declare `ts` explicitly in the `netops-applogs` index template with
     `"type":"date","format":"strict_date_optional_time||epoch_millis||epoch_second"`
     so the mapping stops being a race.
  3. Add `"ignore_malformed": true` at the template level so a future type surprise
     drops the FIELD, not the DOCUMENT.

### F-02 [CRITICAL] Six ingest lanes, two normalize timestamps, four do not — and there is
### no dead-letter path on any of them

`deployment/docker/vector-router/vector.yaml`:

| transform | line | normalizes `ts`? | coerces types? | drops to DLQ? |
|---|---|---|---|---|
| `applogs_tagged`   | 82  | **NO** — sets `.tenant_seg` only | no | no |
| `syslog_tagged`    | 90  | **NO** | no | no |
| `snmptrap_tagged`  | 98  | **NO** | no | no |
| `cloudlogs_tagged` | 110 | **NO** | no | no |
| `flows_decoded`    | 123 | YES (`:152` `.ts = to_int(floor(trcv/1000000))`) | YES (`proto`, `tcp_flags`) | no |
| `cloudcosts_normalized` | 178 | YES (`:188-193`) | YES (`amount`→float) | no (`drop_on_error: true`, silent) |

The two lanes that normalize do so because they were each fixed **reactively after an
outage** — the code comments say so verbatim:
- `:118-122` "Without this coercion every flow batch fails the CH insert with a 400 and is
  dropped — which is why netops.flows stayed empty."
- `:171-177` "the amount is coerced to a float so a string-typed value can't 400 the whole
  insert batch (the flows proto lesson)."

The lesson was applied to the two lanes that broke and to no others. **`applogs`,
`syslog`, `snmptrap`, `cloudlogs` are the same bug waiting for a producer to change type.**

- **Severity: Critical** (this is the generator of the entire defect class, not one instance).
- **Fix:** factor one shared normalization step. Vector has no include/macro, so the
  pragmatic form is a single `remap` transform (`normalize_wire`) that all six lanes feed
  through before their per-lane logic, enforcing: `ts` → epoch-ms int, `tenant_id` →
  string, `severity` → keyword string. Add a CI test (extend
  `src/correlation/test_golden_wire_all_lanes.py`, which already exists for the Python
  side) that asserts the Vector configs coerce every shared field on every lane.

### F-03 [HIGH] No dead-letter queue anywhere in the pipeline; `drop_on_error` discards
### without reroute

Vector supports `reroute_dropped: true` on `remap`, which emits failures on a `.dropped`
output that can be sinked to a DLQ topic/index. **It is not used anywhere.**

```
$ grep -n 'reroute_dropped' deployment/docker/vector/vector.yaml deployment/docker/vector-router/vector.yaml
(no matches)
```
Instead, four transforms use `drop_on_error: true` / `drop_on_abort: true` with no
reroute:
- `vector/vector.yaml:428-432` `cloud_app_health`
- `vector/vector.yaml:484-488` `cloud_host_log`
- `vector/vector.yaml:403-406` `bus_bridge`
- `vector-router/vector.yaml:178-182` `cloudcosts_normalized`

Aggregator counters confirm the volume flowing through these paths:
```
vector_component_discarded_events_total{component_id="cloud_app_health",intentional="true"} 45937
vector_component_discarded_events_total{component_id="cloud_host_log",intentional="true"}  45937
```
Those are `intentional=true` (deliberate filtering) — acceptable. The problem is that
`drop_on_error: true` makes a **genuine processing error indistinguishable from a
deliberate `abort`**: both vanish into the same counter with no payload retained.

- **Blast radius:** any future VRL error in these transforms (a producer adding a field,
  a regex that stops matching) silently deletes data and looks identical to normal filtering.
- **Fix:** set `reroute_dropped: true` on all four and add a `kafka` sink to
  `netops.dlq` (plus an `elasticsearch` sink to `netops-dlq-*`). Keep `abort` for
  intentional filtering but move intentional filtering into a `filter` transform so the
  two are separable in metrics.

### F-04 [HIGH] Every sink uses an in-memory buffer of 500 events with acknowledgements
### disabled — a Vector restart loses in-flight data, and the Kafka offset is already committed

Live evidence (both tiers):
```
vector_buffer_max_event_size{buffer_type="memory",component_id="opensearch_applogs",...} 500
vector_buffer_max_event_size{buffer_type="memory",component_id="kafka_applogs",...}      500
   (identical for every sink on both vector-aggregator and vector-router)
```
No `buffer:` block and no `acknowledgements:` block appears in either config:
```
$ grep -nE '^\s*(buffer|acknowledgements):' deployment/docker/vector/vector.yaml \
      deployment/docker/vector-router/vector.yaml
(no matches)
```
Consequences:
1. **Router tier:** the `kafka_*` sources commit offsets on read, not on sink success
   (end-to-end acknowledgements default to off). A router crash loses up to 500 events per
   sink *and the offsets are gone* — Kafka replay will not recover them.
2. **Aggregator tier:** worse, because the sources are `http_server` (`trap_in:8688`,
   `probe_in:8689`, `metrics_in:8690`, `bus_in:8692`). Those return **HTTP 200 to the Go
   backend before the event reaches Kafka.** `bus_producer.go` therefore gets a success
   response for an event that can still be dropped. **This is the "2xx without
   persistence" defect, in the ingest tier.**
3. `healthcheck: {enabled: false}` on every OpenSearch/ClickHouse sink
   (vector-router/vector.yaml:220, 232, 244, 256, 268, 281, 297) means Vector will not
   surface a dead storage backend at all.

- **Fix:** add to every sink `buffer: {type: disk, max_size: 268435488, when_full: block}`
  and `acknowledgements: {enabled: true}`; set `acknowledgements.enabled: true` globally so
  the `http_server` sources hold the 200 until the event is durably on the bus. Re-enable
  sink healthchecks.

### F-05 [HIGH] `applogs_normalized` merges arbitrary producer JSON into a shared index —
### unbounded field growth toward a hard 1000-field wall that fails CLOSED

`deployment/docker/vector/vector.yaml:136-141`:
```vrl
parsed, err = parse_json(msg)
if err == null && is_object(parsed) {
  . = merge(., object!(parsed))     # <- any key any container logs becomes an OS field
}
```
Measured: **41 distinct top-level keys across a 600-message live sample** of
`netops.applogs`; the live index already carries **67 top-level fields**:
```
netops-applogs-untagged-2026.07.21 top-level fields: 67
index.mapping.total_fields.limit = 1000
index.mapping.ignore_malformed   = false
```
Sample of merged keys (all from container log bodies, none declared in the template):
`absolute_min, dx_vifs, fault_signals, idle_min, metric_points, nats, observations,
paths, tgws, transitions, vantage, vms, vpn, session, duration_ms, ...`

- **Blast radius:** when a service ships a new structured-log schema (or logs a map with
  variable keys), field count climbs. At 1,000 fields OpenSearch rejects **every remaining
  document for that day**, on every tenant's applog index — a full-day application-log
  blackout. `ignore_malformed: false` means the failure mode is hard rejection, not
  degraded indexing.
- **UNCONFIRMED — needs a controlled test to verify the exact rejection behaviour at the
  limit;** the field count, the limit value, and the merge that drives growth are all
  confirmed.
- **Fix:** stop merging unbounded JSON into the top level. Move parsed producer fields
  under a single `object`-typed namespace (`.fields = parsed`) mapped as
  `{"type":"object","enabled":false}` (stored, not indexed), and keep only the 8 declared
  template fields promoted to the top level. Also set
  `index.mapping.total_fields.limit` explicitly and `ignore_malformed: true`.

### F-06 [HIGH] No index template exists for `netops-snmptrap-*` or `netops-cloudlogs-*` —
### two lanes are 100% dynamically mapped with zero declared schema

```
$ curl http://172.18.0.14:9200/_cat/templates?v
name           index_patterns     order version
netops-flows   [netops-flows-*]   0
netops-syslog  [netops-syslog-*]  0
netops-applogs [netops-applogs-*] 0
```
Three templates for six lanes. The `snmptrap` lane already carries the widest schema on
the bus (**29 distinct top-level keys** in a 400-message sample, including free-form
`varbinds`), and it has no declared mapping at all. `cloudlogs` likewise.

- **Blast radius:** identical to F-01 but unguarded — the first trap of the day types
  every field, and varbind values are vendor-controlled input.
- **Fix:** add `netops-snmptrap` and `netops-cloudlogs` templates with the shared field
  contract (`timestamp`/`ts` date with multi-format, `tenant_id` keyword, `severity`
  keyword, `device`/`host`/`hostname` keyword) and put `varbinds` under a
  `{"enabled": false}` object.

### F-07 [MEDIUM] All log indices are `number_of_replicas: 0`

```
index.number_of_replicas = 0     (netops-applogs-untagged-2026.07.21; identical in all
                                  three templates)
```
Single-node OpenSearch, so this is deliberate for the lab. Recording it because a
production posture needs replicas ≥ 1 or an explicit snapshot policy — with 0 replicas and
(per Section 5) no snapshot repository, **any shard corruption is unrecoverable data loss.**

### F-08 [MEDIUM] `bus_in` HTTP bridge on :8692 accepts unauthenticated writes to any
### `netops.*` topic

`deployment/docker/vector/vector.yaml:99-104`:
```yaml
  bus_in:
    type: http_server
    address: 0.0.0.0:8692
    decoding: { codec: json }
```
No `auth:` block on `bus_in`, `trap_in` (:8688), `probe_in` (:8689) or `metrics_in`
(:8690). The `bus_bridge` transform (`:403-416`) enforces only that the topic starts with
`netops.` — a topic-prefix check, not an identity check.

- **Blast radius:** any process that can reach the compose network can inject arbitrary
  events onto any `netops.*` topic, including forged `tenant_id`, which the router then
  routes into that tenant's index via `.tenant_seg`. This is a **cross-tenant data
  injection** path and a direct violation of CLAUDE.md §3 ("All service-to-service
  communication must be authenticated"). Comment at `:98` asserts "Internal compose
  network only — never exposed on the host" — true today (`docker port` shows only 8689
  published) but it is a network-topology assumption, not an enforced control.
- **Note:** `docker port netops-vector-aggregator-1` shows `8689/tcp -> 10.70.245.122:8689`
  — the **probe_in port IS published on a host interface**, unauthenticated.
- **Fix:** add `auth: {strategy: bearer, token: "${BUS_BRIDGE_TOKEN}"}` to all four
  `http_server` sources; unpublish 8689 or put it behind the same token.

---

# SECTION 2 — KAFKA TOPIC SCHEMA CONTRACTS

Method: `kafka-console-consumer.sh --max-messages 400` per topic (from-beginning) plus a
600-message live tail of `netops.applogs`; types classified in Python.

### F-09 [CRITICAL] `ts` has three incompatible types on `netops.applogs`, and the type is
### a function of which service produced the record

Live tail, 600 consecutive messages off `netops.applogs`:
```
ts TYPE DISTRIBUTION
   ABSENT   543  (90.5%)
   string    55  ( 9.2%)   example='2026-07-21T20:55:26.683185582Z'
   float      2  ( 0.3%)   example=1784667381.9659653

BY PRODUCING SERVICE
   correlation     {'ABSENT': 363}
   api             {'string': 55, 'ABSENT': 7}     <- Go backend: RFC3339 string
   cadvisor        {'ABSENT': 50}
   nginx           {'ABSENT': 44}
   opensearch      {'ABSENT': 30}
   victoria        {'ABSENT': 14}
   redis           {'ABSENT': 10}
   frontend        {'ABSENT': 8}
   vector-router   {'ABSENT': 8}
   cloud-ingest    {'float': 2}                    <- Python: time.time()
   postgres        {'ABSENT': 1}
```
**`cloud-ingest` is the sole float producer and 100% of its structured log lines are
therefore lost** on any day the string mapping wins the race.

- **Fix:** two independent changes, both needed. (a) Producer side: make
  `deployment/docker/cloud-ingest/*` emit RFC3339 (or epoch-ms int) — this fixes the
  symptom. (b) Bus side: F-02's shared normalization — this fixes the class.

### F-10 [HIGH] There is no single canonical time field across topics — `ts` and
### `timestamp` are used inconsistently, and two topics have neither

Sampled type census (400 msgs/topic, from-beginning):

| topic | `ts` | `timestamp` | `tenant_id` | keys |
|---|---|---|---|---|
| netops.applogs | 282/400 rfc3339 (+float live) | 400/400 rfc3339 | 400 `""` | 22 |
| netops.syslog | — | 400/400 rfc3339 | 400 `""` | 18 |
| netops.snmptrap | — | 400/400 rfc3339 | 400 `""` | 29 |
| netops.flows | — | 400/400 rfc3339 | 400 `""` | 61 |
| netops.metrics | 400 rfc3339 | 400 rfc3339 | 400 `""` | 18 |
| netops.probes | 400 rfc3339 | 400 rfc3339 | 400 `""` | 21 |
| netops.cloud | 400 rfc3339 | — | 400 non-empty | 15 |
| netops.cloudlogs | — | 400 rfc3339 | 400 non-empty | 10 |
| netops.cloudcosts | 332 rfc3339 | — | 332 non-empty | 11 |
| netops.app.edge | 400 rfc3339 | — | 400 non-empty | 15 |
| **netops.controller_events** | **absent** | **absent** | 400 non-empty | 25 |

- `netops.controller_events` carries **no time field at all** on any of 400 sampled
  messages. Any consumer ordering or windowing these events is using arrival time.
- `netops.metrics` and `netops.probes` carry **both** `ts` and `timestamp`; nothing in the
  config states which is authoritative.
- **UNCONFIRMED — needs consumer-code review** to determine whether `controller_events`
  consumers silently substitute `now()`; flagged for the correlation-service reviewer.
- **Fix:** publish a wire contract doc (there is already
  `src/correlation/golden_wire.py` and `test_golden_wire_all_lanes.py` — extend them to
  cover all 11 topics) mandating exactly one field, `ts`, as epoch-ms int, and add a
  conformance test in CI that samples each topic.

### F-11 [MEDIUM] `tenant_id` is present but EMPTY on all six device-telemetry topics

`applogs / syslog / snmptrap / flows / metrics / probes` = `""` on 400/400 sampled
messages; only the cloud lanes carry a real tenant. This means the aggregator's
`device_tenant` enrichment table produced no match for any sampled event, so every one of
those documents routes to the **shared `-untagged-` index**:
```
netops-applogs-untagged-2026.07.21   <- the only applogs index that exists today
```
The per-tenant at-rest separation described at `vector-router/vector.yaml:73-81` is
therefore **not in effect for device telemetry** — it degrades to one shared bucket, and
it does so silently (empty tenant is a valid, expected value in the VRL, `?? ""`).

- **Blast radius:** the design's stated guarantee ("another tenant's docs are unreachable
  even if a query filter is missed") does not hold for device telemetry, because there is
  only one index and every tenant's data is in it. Isolation then rests entirely on the
  API's query filter — a single-layer defence where a two-layer one was designed.
- **Note:** this may be expected in this seeded lab (sampled data is from the platform's
  own containers, which legitimately have no tenant). **UNCONFIRMED — needs a check of
  whether `/etc/vector/enrichment/device_tenant.csv` is populated for the 511 seeded
  devices** to distinguish "lab artifact" from "enrichment table never loads".
- **Fix regardless:** emit a metric for enrichment-miss rate and alert when
  `tenant_id == ""` exceeds a threshold on device lanes. Today a broken enrichment table
  is indistinguishable from correct operation.


---

# SECTION 3 — REVIEW OF THE IN-FLIGHT DEF-6 FIX (config changed DURING this audit)

**Timeline discovered during the audit:**
```
router container started:            2026-07-21T16:50:01Z
vector-router/vector.yaml modified:  2026-07-21 20:59:23Z   <- mid-audit
config md5 on disk:                  6ac82c11d3b51e845859cd685cefdc31
config md5 INSIDE running container: df4a78d26da397f17fe233bea05af665
grep -c log_lane /etc/vector/vector.yaml (in container): 0
```
`git status` also shows `deployment/docker/opensearch/index-templates.json` modified.

### F-12 [CRITICAL / OPERATIONAL] The DEF-6 fix is written but NOT DEPLOYED — loss is ongoing
The running router is still executing the pre-fix config. The 183 docs/hour loss measured
in Section 1 is **happening right now**. Nothing in the stack will pick the file up without
a `docker compose up -d vector-router` (deliberately not performed — out of audit scope).
Also note the new `ts` mapping in `index-templates.json` is applied only by
`scripts/bootstrap-opensearch.sh` / `scripts/install.py:851`, i.e. **at install time only**
— editing the file does not re-apply it to a running cluster.
- **Action:** deploy the router config AND run `scripts/bootstrap-opensearch.sh` to push
  the template, in that order. Existing `netops-applogs-untagged-2026.07.21` keeps its
  dynamic `ts:date` mapping, which is *compatible* with the new epoch-ms integers, so no
  reindex is required — the loss stops at restart.

## What the fix gets RIGHT (verified by reading the new file)

- **`&log_lane` YAML anchor** (`vector-router/vector.yaml:88`, applied at `:140`, `:145`,
  `:154`) — the four log lanes now share one implementation instead of four copies. This is
  the correct structural answer to F-02: it makes sibling drift impossible by construction
  rather than by discipline. Exactly the right instinct.
- **Magnitude-based unit inference** (`:123-133`, s/ms/µs/ns) — tolerates a producer
  changing precision, which a naive `*1000` would not.
- **`.ts_invalid` preservation** (`:115`, `:121`) — the unparseable value is retained as a
  string instead of being dropped, so the offending producer is greppable. This is the
  single best decision in the patch: it converts a silent failure into a visible one.
- **`ts` now declared in the template** with `strict_date_optional_time||epoch_millis`,
  ending the dynamic-mapping race (F-01 root cause) for applogs, syslog and flows.

## Gaps in the fix — ranked

### F-13 [CRITICAL] The new dead-letter path cannot catch the failure it was built for
`reroute_dropped: true` is set on exactly one transform — `cloudcosts_normalized`
(`:224`), the **lowest-volume lane in the system** (27 events in 4 hours). The four log
lanes carrying 100,000+ events have no reroute.

More fundamentally: **`reroute_dropped` catches VRL *transform* errors. DEF-6 is a *sink*
rejection** — OpenSearch returns HTTP 200 with a per-item `"status":400` inside the bulk
response, and Vector's `elasticsearch` sink has no dead-letter option at all. The 3,457
discarded events in Section 1 were dropped at `vector::sinks::util::retries`, downstream of
every transform. **They would still be dropped with this patch applied.**

The comment at `:279-281` states the intended alert channel:
> "a non-empty netops-deadletter-* index is itself the signal that a producer has broken
> its contract"

That signal will never fire for the sink-rejection class — the class that actually caused
the incident. The patch removes the *cause* (ts is now normalized, so nothing gets
rejected) but leaves the *class* uncovered: the next field that acquires an incompatible
type fails exactly as before, silently.
- **Fix:** the durable control is not a DLQ, it is an alert on the metric that already
  exists and is already scraped:
  `increase(vector_component_discarded_events_total{intentional="false"}[15m]) > 0`.
  See F-16 — there is currently no alerting engine to host it.

### F-14 [HIGH] `deadletter_encoded` almost certainly records no reason
`vector-router/vector.yaml:248`:
```vrl
"reason": to_string(.metadata.message) ?? "aborted or failed remap",
```
In VRL, event **metadata** is addressed with the `%` sigil (`%metadata`), not `.metadata`.
`.metadata` reads an event *field* named `metadata`, which these events do not have — so
`to_string(null)` fails, the `??` fallback fires, and **every dead-letter record gets the
same constant string**, discarding the actual error.
- **UNCONFIRMED — needs a runtime test** (feed one malformed cloudcost record and read the
  resulting `netops-deadletter-*` doc). Flagged because a DLQ that loses the reason is
  most of the way to no DLQ. The `"raw": encode_json(.)` on the next line IS correct — VRL
  evaluates the object literal before assigning to `.`, so it captures the original event.

### F-15 [MEDIUM] `ts` will dynamically map as `long`, not `date`, on the two lanes that
### still have no template
The anchor now normalizes `ts` on **snmptrap** and **cloudlogs**, but
`index-templates.json` still defines only three templates:
```
netops-applogs   patterns=['netops-applogs-*']    ts: date
netops-syslog    patterns=['netops-syslog-*']     ts: date
netops-flows     patterns=['netops-flows-*']      ts: date
(no netops-snmptrap, no netops-cloudlogs)
```
On those two indices the first document now carries `ts` as an **integer**, so OpenSearch
will dynamically infer `long`. The field becomes non-date: date-range queries, the
Dashboards time picker and any `sort` on `ts` silently mis-behave. This is a *new*
silent-degradation introduced by the fix on the two lanes it didn't finish covering.
- **Fix:** add `netops-snmptrap` and `netops-cloudlogs` templates in the same commit.

### Also unchanged by the fix (from Section 1, all still open)
- `flows_decoded` (`:161`) and `cloudcosts_normalized` (`:216`) still hand-roll their own
  `tenant_seg` block (`:205-207`) instead of using the anchor — 2 of 6 lanes can still drift.
- F-04: no `buffer: {type: disk}`, no `acknowledgements`, `healthcheck: {enabled: false}`
  on all 8 sinks. Unchanged.
- F-05: `applogs_normalized`'s unbounded `merge()` in the **aggregator** config, untouched
  (mtime still 2026-07-17). 67 fields today, 1000-field hard wall.
- F-08: `http_server` sources still unauthenticated; `:8689` still published to a host interface.
- No `dynamic:` control and no `ignore_malformed: true` on any template.

---

# SECTION 6 — OBSERVABILITY OF THE OBSERVABILITY PLATFORM (the meta-theme)

### F-16 [CRITICAL] The platform has NO metric-based alerting engine at all
```
$ grep -nE 'vmalert|alertmanager|ruler' deployment/docker/docker-compose.yml
  NONE
$ curl http://<grafana>/grafana/api/v1/provisioning/alert-rules
  []
```
`src/config/rules.yaml` exists and contains carefully-written alert expressions
(`CorrProbeLaneFlatlined`, `CorrEventsDroppedRising`, container OOM rules, …) — **and
nothing evaluates it.** There is no vmalert, no Alertmanager, and Grafana has zero
provisioned alert rules. The rules file is documentation, not a control.
- **Blast radius:** every "add an alert" fix recommended in this audit has nowhere to go.
  This is the single highest-leverage gap in the report, because it is the precondition
  for closing ~15 other findings.
- **Fix:** add a `vmalert` service pointed at VictoriaMetrics with
  `-rule=/etc/alerts/rules.yaml`, plus a notifier. The rules are already written.

### F-17 [CRITICAL] OpenSearch's own `index_failed` counter reads ZERO during active loss
```
$ curl http://<os>:9200/_nodes/stats/indices/indexing
  "index_total" : 114168,
  "index_failed" : 0          <- while 914 documents were being rejected
```
Bulk **per-item** rejections do not increment `index_failed`. An operator who checks the
obvious counter — or a dashboard panel built on it — sees a perfectly healthy cluster
while thousands of documents are discarded daily.
- **Fix:** do not rely on `index_failed`. Alert on
  `vector_component_discarded_events_total{intentional="false"}` (Vector's counter, which
  IS correct and IS scraped) and on a non-empty `netops-deadletter-*`.

### F-18 [HIGH] The signal exists, is scraped, and nobody looks at it
`vector_component_discarded_events_total{intentional="false"}` is exported by both Vector
tiers on `:9598` and confirmed present in VictoriaMetrics:
```
$ curl http://<vm>:8428/api/v1/targets
  vector http://vector-aggregator:9598/metrics up
  vector http://vector-router:9598/metrics up
$ curl '.../api/v1/query?query=vector_component_discarded_events_total'
  status: success  (series returned)
```
**The data to detect DEF-6 within 60 seconds has been in the metrics store the entire
time.** The gap is purely the missing rule (F-16). Note also that Vector's *log* channel is
lossy under load — `1072` suppressed log lines in the 5h window
(`"Internal log [Events dropped] is being suppressed to avoid flooding"`), so log-based
detection is strictly worse than metric-based here.

### F-19 [HIGH] The watchdog detects total stall, not partial loss
`scripts/stack-watchdog.sh` is genuinely good — container health, restart/OOM detection,
HTTP probe, disk % with auto-prune, cron-staleness checks, and (`:163-174`) a real ingest
liveness check:
```sh
cnt=$(... "http://localhost:9200/netops-applogs-*/_count" ...)
[ "$cnt" -eq 0 ] && problems+=("log ingest stalled: 0 applogs in last ${stale_min}m")
```
But the predicate is `== 0`. During the entire measured incident the count was ~14,000/h
and **the watchdog stayed green while 4,390 docs/day were lost.** It cannot distinguish
"ingesting correctly" from "ingesting with a 5% hole".
- **Fix:** add a second predicate comparing accepted-vs-received across the Vector tiers,
  or simply alert on the discard counter once F-16 lands.

### The pattern across the whole platform
Every silent-loss finding in this report has the same shape: **the failing component knows,
and the knowledge stops there.** Vector knows (it logs and counts). OpenSearch knows (it
returns a 400 per item). The Go notify dispatcher knows (it `log.Printf`s). The correlation
service's ClickHouse writer knows (it returns `False`). In each case the knowledge either
dies in an unscraped log line, or lands in a metric with no rule attached to it. There is
one exemplary counter-example in the codebase (`corr_current` projection writes — checked
return, structured log, dedicated counter, alert, and a reconciler); it proves the team
knows how to do this and simply hasn't generalised it.


---

# SECTION 4 — GO API: RESOURCE SAFETY & SILENT FAILURE

All findings below are from a dedicated sweep of `src/backend` (469 non-vendor,
non-test `.go` files). The top finding was independently re-verified by me by reading
`events.go` end to end.

### F-20 [CRITICAL] WebSocket hub panics the whole API process on an ordinary browser
### tab close — `send on closed channel`
**`events.go:47-53`, `events.go:89-95`, `events.go:106-118`, `events.go:231-283`**

**CONFIRMED — I read all four sites myself.**

- `wsClient.close()` (`events.go:47-53`) does `close(c.send)` inside a `sync.Once`.
- `discardIncoming()` (`:231`) runs in **its own goroutine** (`:213`) and calls `c.close()`
  on **six** read paths: `:239, :250, :257, :268, :275, :280` — **holding no hub lock**.
- `Broadcast` (`:89-95`) and `BroadcastFiltered` (`:106-118`) iterate `h.clients` under
  `h.mu.RLock()` and execute `case c.send <- data:`.
- The client is removed from `h.clients` only by `unregister`, invoked via
  `defer s.hub.unregister(client)` (`:204`) in the HTTP handler goroutine — which returns
  only *after* the write pump (`:216-228`) observes the closed channel.

Between `close(c.send)` and `unregister`, the client is still in the map. A concurrent
broadcast then sends on a closed channel. **A `select` with `default` does not save you —
sending on a closed channel panics regardless.** There is **no `recover()` anywhere in
non-vendor production code**, and the broadcasters are plain goroutines (`main.go:780-781`),
so `net/http`'s per-connection recovery does not apply.

- **Blast radius:** process death. Total API outage for all 12 tenants; everything behind
  `:8000/api` 502s until Docker restarts the container.
- **Failure scenario:** a user closes a dashboard tab while the 2s telemetry tick or the 5s
  metric-tile tick (`dashboard.go:127,130`) is mid-fan-out. **Ordinary traffic, not an
  attack** — which is why this is ranked above every data-loss finding in the report.
- **Fix:** never close a channel that senders still hold. Delete `close(c.send)` from
  `close()`; keep `close(c.done)` only, and make both broadcast sites
  `select { case c.send <- data: case <-c.done: default: }`. Add a `safego()` wrapper with
  `defer recover()` on all 33 goroutine spawn sites as defence in depth.

### F-21 [HIGH] `writeJSON` discards the encode error at 397 call sites — a `NaN` returns
### HTTP 200 with an empty body
**`main.go:1454-1458`** (`_ = json.NewEncoder(w).Encode(body)`)

`Encoder.Encode` marshals to a buffer *before* writing, so `json: unsupported value: NaN`
yields `200 OK`, `Content-Type: application/json`, **zero bytes, no log, no metric**. NaN
reaches response structs through ~20 unguarded `strconv.ParseFloat` calls on
VictoriaMetrics/ClickHouse values (`ParseFloat("NaN", 64)` succeeds):
`path_health_api.go:67` (confirmed reachable), `health_score.go:523`, `wan_circuits.go:590`,
`metrics_forecast.go:113`, `correlations.go:305`, `rca_coverage.go:329`.

**Companion, same root cause, worse consequence:** `alerts/evaluator.go:96` parses the same
field unguarded. **A NaN sample compares `false` against every threshold, so the alert
silently never fires.** A metric going NaN (e.g. `stddev_over_time` over one sample, a
`0/0` rate) disables the alert built on it with no signal.
- **Fix:** log + count the encode error in `writeJSON`; sanitize NaN/Inf → `null` in a
  shared `parseMetricFloat` helper at the parse boundary.

### F-22 [HIGH] Alert notification delivery: unbounded goroutine fan-out, zero retry,
### log-only failure, zero metrics
**`notify/dispatcher.go:85-91`, `:104-115`, `:162-166`**
```go
go func(c Channel){ if err := c.Send(a); err != nil { log.Printf(...) } }(c)
```
One goroutine per channel per alert, no pool, no semaphore, no queue — called in a loop
over every newly-active alert each tick (`alerts/engine.go:272,299`). Three defects stacked:
1. **Unbounded fan-out** — 5,000 alerts × 6 channels = 30,000 concurrent outbound goroutines.
2. **No retry** (violates CLAUDE.md §9) — one transient 502 is a **silently lost page**.
3. **No observability** — raw `log.Printf` (not structured `logError`), and
   `handlePromMetrics` (`main.go:1418-1450`) has **no notify counter at all**.

- **Blast radius:** during the exact incident the platform exists to surface, pages vanish
  and nobody knows. This is the defect class applied to the alerting path itself.
- **Fix:** the correct pattern already exists in-repo — `ticketing_worker.go` is a full
  persisted outbox with leases, dead-lettering and `Retry-After` handling, and
  `notify/dispatcher.go:183-207` (`DispatchToResults`) already returns per-channel receipts.
  Route alert delivery through a bounded pool over the outbox; add
  `netops_notify_send_failures_total{channel}`.

### F-23 [HIGH] SMTP has no timeout anywhere — hung sends leak goroutines and sockets forever
**`notify/email.go:188`** (`smtp.SendMail`), **`:194`** (`tls.Dial` → `smtp.NewClient`, no
`SetDeadline`). `net/smtp` dials with no timeout and sets no deadlines. Combined with
F-22's per-alert goroutine fan-out, a tarpitting or blackholed relay parks one goroutine +
one TCP/TLS connection **permanently, per alert**. Every other notify channel is correctly
capped at 10-15s — email is the sole unbounded one.
- **Fix:** `net.Dialer{Timeout: 10*time.Second}` → `conn.SetDeadline(...)` →
  `smtp.NewClient` on both the STARTTLS and implicit-TLS paths.

### F-24 [HIGH] `path_graph_store` in-memory store is append-only forever
**`path_graph_store.go:239`** (`m.obs[t] = append(m.obs[t], o)`), **`:249`** — no cap, no
TTL, no trim in the file. Fed every 60s by `path_ingest.go:669-682` when
`FEATURE_PATH_GRAPH=true` and the backend is not Postgres (`path_graph_store.go:113-118`).
`ListObservations` (`:281-297`) full-scans the growing slice under `RLock` on every API
read, so latency degrades in lockstep with memory.
- **Fix:** ring-buffer per tenant with a retention window; delete matching `hops[t][id]` on eviction.

### F-25 [MEDIUM-HIGH] `login_throttle` fails OPEN at its cap — brute-force lockout
### silently disables platform-wide
**`login_throttle.go:26`** (`throttleMaxAccounts = 50000`), **`:66-68`**. Entries are
deleted only on successful login (`:90`) or lock expiry (`:51`); an entry with
`fails < allowed` and a zero `lockedUntil` is **never swept**. At 50,000 entries `fail()`
silently `return`s — lockout is then off for every account not already tracked, **with no
log and no metric**.
- **Failure scenario:** spray ~50k junk usernames at `/api/auth/login` (unauthenticated,
  in `publicPaths` at `auth.go:621`), then brute-force the real admin with lockout
  permanently disabled.
- **Fix:** janitor sweeping entries with `lockedUntil.IsZero()` older than the window;
  log + counter when the cap is hit instead of failing open.

### F-26 [MEDIUM-HIGH] WebSocket hub does O(devices) work under the hub lock, per client,
### every 5s; no client cap; silent frame drops
**`events.go:103-119`** calls `build(c.claims)` **inside** `h.mu.RLock()`. That closure is
`s.currentMetricTiles(claims)` (`dashboard.go:38-100`), a full fleet scan
(`s.discovery.Devices()` + `dedupeDevices`) plus a full active-alert scan — per client,
per tick. 200 sockets × 10k devices ≈ 2M iterations per tick with the lock held, starving
`register`/`unregister` (which need `mu.Lock()`). No cap on client count (`:64-68`); frame
drops at `:92`/`:115` are silent (§10 violation).
- **Fix:** compute tiles once per distinct tenant before taking the lock; snapshot
  `h.clients` and release the lock before building/sending; cap sockets per principal; add
  `netops_ws_frames_dropped_total`.
- **Also:** no `SetReadDeadline` and no ping/pong on `/api/events`, so a half-open peer is
  only reaped after the TCP retransmit timeout (minutes). `device_ssh.go:186,314,437-438`
  implements both correctly — another sibling-inconsistency instance.

### F-27 [MEDIUM] Unbounded `io.ReadAll` on ClickHouse responses; query not cancelled on
### client timeout
**`report_scheduler.go:1223`** (`b, _ := io.ReadAll(resp.Body)` in `chQuery`, **21 call
sites**), request built with `http.NewRequest` (**`:1209`**, no context). The 8s client
timeout does **not** cancel the server-side query
(`cancel_http_readonly_queries_on_client_close` appears nowhere in the repo) — ClickHouse
keeps executing while the client gives up. This is the shape of the 2026-07-09 #100 incident,
client-side. Sibling inconsistency: `appid_fusion_store.go:48` caps at 4096, its neighbour
`:77` does not.
- **Fix:** `io.LimitReader(resp.Body, 8<<20)` (matching `correlations.go:81`), thread `ctx`,
  set `profile=background` and `max_execution_time`.

### F-28 [MEDIUM] Retry without effective jitter
| Path | file:line | Defect |
|---|---|---|
| NMS connectors | `nms/retry.go:26` (wired `nms_http.go:410`, `nms_scheduler.go:210`) | `Jitter: nil` — bare exponential. The hook exists and is unit-tested but **never wired in production**. One-line fix. |
| Ticketing outbox | `ticketing_worker.go:329-340` | jitter is `attempt*271%1000`, derived from the **attempt number** — every item at attempt N gets an identical delay. 10k queued items retry in lockstep against a recovering ServiceNow. Fix: derive from a hash of the item ID. |
| CH policy converge | `clickhouse_policies.go:104-111` | flat 6s sleep, no jitter, ignores ctx cancellation (capped at 10 attempts, so bounded). |

### F-29 [MEDIUM] No `ReadTimeout`/`WriteTimeout`/`IdleTimeout`; no worker drain on shutdown
**`main.go:821-826`** sets only `ReadHeaderTimeout: 10s` + `MaxHeaderBytes`. With
`ReadTimeout` and `IdleTimeout` zero, Go applies no idle timeout and a request **body** can
be dribbled forever (slowloris-on-body). nginx's default `client_body_timeout 60s` covers
this in the default deployment — but **in TLS/mTLS mode the Go server is reachable
directly** (`main.go:827-840`), bypassing nginx. **`main.go:861-867`:** `_ =
httpSrv.Shutdown(ctx)` (error discarded), then `cancel()`, then immediate return — **no
`sync.WaitGroup` in `main.go`**, so every background worker (ticketing, fusion, report
scheduler, incidents sync, topology reconciler, netbox sync) is killed mid-write with no
drain and no log. **Every deploy abandons in-flight Postgres/ClickHouse writes.**

### F-30 [MEDIUM] Ticketing/audit store writes discarded on the write path
**`ticketing_worker.go:245, :271, :275, :294, :308, :316, :322, :449, :455`** — every store
write is `_ = w.store.X(ctx, ...)`. Largely mitigated for ServiceNow/Jira by
`LookupByCorrelationID` adoption (`:196-203`) and for PagerDuty by a deterministic
`dedup_key` — but **not** for Slack (`ticketing_slack.go:95-97` cannot query), so a
link-write failure produces duplicate Slack messages. **Audit-trail entries are silently
lost** (compliance gap), and a PG outage makes the outbox loop forever with zero signal.

### F-31 [MEDIUM] No `recover()` on 33 goroutines; the unauthenticated UDP trap parser is
### the worst case
**`collectors/snmptrap.go:933`** + `forwardLoop` decode **unauthenticated UDP SNMP traps**
with hand-rolled BER/ASN.1 offset arithmetic (`:694-730`). A slice-bounds panic there is
**remote, pre-auth process termination**. Then `verify_service.go:474`,
`report_pipeline.go:482`, `incidents_http.go:89`, `integration_reconciler.go:42`.

### F-32 [LOW-MEDIUM] 45 handlers decode JSON with no per-handler body cap
The global backstop **works and is correctly placed** — `withBodyLimit(50 MiB)` wraps the
mux at **`main.go:803`**, ahead of `withAuth`, and there is one listener. Nothing is truly
unbounded. But 50 MiB decoded into Go structs amplifies 3-5×, concurrently. Worst cases:
`snmp_profiles.go:375` (decodes into an **unbounded slice** `[]SNMPMetric`), and five
**pre-auth** routes — `auth.go:341` (refresh), `:444` (logout, also `_ = ...Decode`),
`:550` (change-password), `ldap.go:295`, `tacacs.go:300`. `/api/auth/login` itself *is*
correctly capped at 64 KiB (`auth.go:124`) — the sibling pre-auth routes were missed.

### F-33 [LOW] Other unbounded maps
`dashboard.go:176` (`seen` keyed by alert fingerprint, never deleted),
`ticketing_store.go:360` (contrast `audit.go:118-121`, which correctly ring-buffers at
5000), `export_ratelimit.go:15,46`. **`nms/auth.go:65,99,138,196`, `nms/poll.go:60`,
`nms/runner.go:53`** appear to leak HTTP response bodies (no `defer resp.Body.Close()`) —
**UNCONFIRMED, needs each function read end to end.**

---

# SECTION 5 — CORRELATION SERVICE & CLOUD-INGEST (PYTHON)

Live context: `netops-correlation-1` up 2d, 196.3 MiB / 789 MiB limit, consumer lag ~0 on
all 10 topics; `netops-cloud-ingest-1` up 2d, 175 MiB, **no** memory limit, **no** healthcheck.

### F-34 [CRITICAL] Timestamp contract divergence — the Python side rejects exactly the
### values Vector normalizes, and the correct implementation is dead code
**`src/correlation/producers.py:222-232`** + 13 call sites.

`timenorm.py` is 399 lines with 271 lines of tests, and defines
`_EPOCH_MS = 1e11 / _EPOCH_US = 1e14 / _EPOCH_NS = 1e17` — **byte-identical thresholds to
the Vector fix reviewed in Section 3.** It was clearly written as the Python mirror of the
DEF-6 remediation. `grep -rn "timenorm"` matches **only `test_timenorm.py:13`**. It is
imported by nothing in production.

What production actually runs, verified live inside the container:
```
parse_event_ts(1784667176.123)   -> None
parse_event_ts(1784667176)       -> None
parse_event_ts('1784667176.123') -> None
parse_event_ts(1784667176123)    -> None
parse_event_ts('2026-07-21T10:00:00Z') -> 2026-07-21 10:00:00+00:00
```
All 13 call sites then do `parse_event_ts(...) or ingest_ts`
(`main.py:1734`, `producers.py:309,402,777,968,1025`, `cloud_producers.py:288`,
`app_producers.py:214`, `lb_normalize.py:127`, `synthetic_normalize.py:203`,
`golden_wire.py:101`, `cloud_dependency.py:417`) — **no log, no counter, no `ts_invalid`
equivalent.**

- **Blast radius:** vector-router sits *downstream* of Kafka; correlation reads *upstream*
  of it. So the same message is normalized before storage but **not** before RCA. A
  numeric-epoch producer lands correctly in ClickHouse/OpenSearch and is silently
  re-timestamped to ingest time in the correlation engine. `onset_uncertainty_s` — the
  number RCA uses to order cause and effect — is then fabricated from receive time, and the
  UI timeline and the CUSUM math disagree. Nothing counts it.
- **CONFIRMED as a defect; UNCONFIRMED as an active loss today** — live `netops.metrics`
  and `netops.syslog` currently carry RFC3339 strings. It is one producer change away.
- **Fix:** wire `timenorm.parse_any_timestamp` (already written and tested) into
  `parse_event_ts`; on `None`, increment a per-lane counter and stamp `ts_invalid`.

### F-35 [CRITICAL] The container safety net is dead — every OOM / restart-loop /
### memory / CPU alert matches zero series
**`src/config/rules.yaml:670,679,686,693,701`** — `ContainerDown`, restart-loop,
`container_oom_events_total`, memory>90%, CPU>90%, all selecting `{name=~"netops-.+"}`.
Live cAdvisor exposition:
```
container_memory_rss{id="/"} 5.8799104e+09
api/v1/label/id/values -> ["/", "ubuntu"]
```
**No `name` label and no per-container series exist in VictoriaMetrics.** All five alerts
match nothing and can never fire. (Compounded by F-16: nothing evaluates `rules.yaml` at
all.) Correlation can OOM against its 789 MiB limit, crash-loop, or die and nothing fires.
- **Fix:** fix the cAdvisor cgroup/docker mounts, **and** add a boot assertion that
  `count(container_last_seen{name=~"netops-.+"}) > 0` — an alert whose selector matches
  zero series should itself be an alert.

### F-36 [CRITICAL] cloud-ingest: all 17 `producer.send()` calls are fire-and-forget
**`deployment/docker/cloud-ingest/poller.py:695`** + 16 further sites. `acks=all, retries=5`
is configured correctly; a permanent failure *after* those retries is dropped with no log
and no counter.

### F-37 [CRITICAL] cloud-ingest: cost checkpoint advances past records that were never flushed
**`cost.py:181`** advances the day checkpoint **before** the flush; **`cost.py:489-492`**
swallows the flush failure with `pass`. **A full day of billing records per account,
permanently lost, on a 6-hour cadence** — and the checkpoint guarantees it is never retried.

### F-38 [HIGH] ClickHouse insert failures discarded at 19 of 20 call sites
`CH.insert` (`main.py:1444-1469`) returns `False` on non-2xx and logs. Exactly one caller
checks it — **`main.py:1123`** (`corr_current` projection), which increments a counter,
logs structured context, has a critical alert **and** a Go reconciler. **That one site is a
model of how it should be done.** The other 19 discard the bool: `main.py:1109`
(`corr_objects` — the append-only truth), `:1141`, `:1150`, `:1153`, `:1166`
(`corr_signals_archive` — the replay source), `:1414`, `:1918`…`:2185` (`corr_signals`),
`:2316` (`findings`).
- **Failure scenario:** ClickHouse 400s on a schema drift affecting only
  `corr_signals_archive`. Every signal still enters `WINDOW_BUFFER` (`:1417`, *after* the
  insert), so live RCA looks perfect and no counter moves. Weeks later "replay this
  incident" returns a **different answer than the one shown at the time**, because the
  archive has holes.
- **Fix:** hoist the `main.py:1113-1135` pattern into `CH.insert` itself.

### F-39 [HIGH] The syslog lane has zero intake observability, and the alert named for it
### does not check it
`netops.syslog` is `TOPICS[0]` (`main.py:111`) and `handle_syslog` (`:2138`) is the source
of `link_down`, BGP state and port/optics evidence. `grep "SYSLOG_RECEIVED"` → **no matches.**
And **`rules.yaml:855-864`**:
```yaml
- alert: CorrSyslogLaneFlatlined
  expr: increase(corr_ingest_events{counter="flows_received"}[30m]) == 0
    and increase(corr_ingest_events{counter="metrics_received"}[30m]) == 0
```
The alert named for the syslog lane checks **flows and metrics**, `and`-joined — so it also
cannot catch a flow-only or metric-only outage. If Vector's syslog route breaks,
correlation loses its highest-value RCA evidence class and nothing changes anywhere.

### F-40 [HIGH] At-most-once consumer; one poison event tears down all 10 topics; no DLQ
**`main.py:1618-1631`** — `enable_auto_commit=True`, `auto_commit_interval_ms=5000`
(confirmed by in-container introspection of aiokafka 0.11.0), committing
`assignment.all_consumed_offsets()` = the **fetched** position, not a processed watermark.
A single `ch.insert` can block 10s (httpx timeout) — twice the commit interval — so a
slow-failing record is committed past before the failure surfaces. **CONFIRMED
at-most-once for any record that fails during processing.** `handle()` (`:1639`) has **no
per-message try/except**, so an unexpected `TypeError` in one producer tears down the
consumer for all ten topics. `DeadLetter` is caught at 8 sites, increments a counter, logs
the exception message — **and discards the payload**, so the offending event is
un-inspectable.
- **Fix:** `enable_auto_commit=False` + explicit commit after successful handling; wrap
  `handle()` per-message and produce the raw payload to `netops.dlq`.
- **Credit:** the consumer *supervisor* is excellent — bounded stop/start timeouts
  (`:1591-1592`), `_stop_bounded` abandons a hung consumer, and
  `test_consumer_supervisor.py` pins the exact 2026-07-14 5.5-hour wedge. That class of
  failure genuinely cannot recur.

### F-41 [HIGH] cloud-ingest: one failing lane permanently starves every AWS lane behind it
**`poller.py:733-776`** — all AWS lanes share one `try`, and each sets its cadence marker
*after* the call. A failing `cloudmetrics.poll()` (unguarded `urlopen` at
`cloudmetrics.py:61` — i.e. any vector-aggregator blip) permanently starves flow logs, S3
lanes, CloudTrail, health, and `save_state` behind it. Live logs show a real, unalertable
bug repeating: `"aws component families degraded" {"seam_endpoints": "Operation cannot be
paginated: describe_vpn_gateways"}`, **167 consecutive cycles**.

### F-42 [HIGH] Flow-record parse failures are invisible
**`main.py:2226`** — `sample = flow_sample(ev); if sample is None: return` with no counter
and no log. `FLOWS_RECEIVED` is incremented *after* the parse, so `flows_received` means
"flows accepted"; `flows_dropped` does not exist. There is no way to distinguish "low flow
rate" from "100% parse failure".

### F-43 [MEDIUM-HIGH] Stale topology is declared FRESH when the enrichment file disappears
**`main.py:580-583`** returns the cached adjacency on `OSError` ("no change, silently
forever"); **`main.py:1178-1184`** computes `newest = -1` for absent files and returns
`False` = *not stale*. So: the exporter dies, the files are removed, and the engine keeps
grounding causal edges on stale topology **while stamping `topology_stale=false` on every
snapshot it emits.**
- **Fix:** track last-successful-load wall-clock in-process, so a deleted file ages into
  staleness exactly like a frozen one.

### F-44 [MEDIUM] `metrics_dropped` conflates three causes — and a device is losing 100% of
### its telemetry right now with no finding raised
Incremented at **`main.py:1721`** (no value), **`:1728`** (no identity), **`:1737`** (ts out
of bounds). Live:
```
2026-07-21 20:42:56 WARNING metric dropped: timestamp out of bounds (age=4050s)
                            wan-r2/device_cpu_percent   ... every metric, every cycle
```
`METRIC_MAX_AGE_S = 3600` (`:296`); device `wan-r2` is ~67 min off, so **100% of that
device's telemetry is discarded**. `clock_skew_signal` exists and is wired for the syslog
lane (`:2178`) and cloud lane (`:2048`) — but **not the metric lane**. The one lane that
actively drops data over skew is the one lane that never emits the finding naming the device.
Meanwhile `CorrEventsDroppedRising` (`rules.yaml:841`) is *always* firing (traps_dropped is
51% by design), which trains operators to mute the exact signal that would catch a regression.

### F-45 [MEDIUM] Unbounded state (latent — measured flat today)
`episodes.py:113` (`_state` keyed by tenant/entity/metric, never evicted), `main.py:232`
(`SERIES`), `main.py:1778` (`SYSLOG_BUCKET` — per-host lists are pruned, the **key set
never is**, and the key is the device-supplied, spoofable syslog `hostname`),
`main.py:493` (`_FLOW_DIR`, "accumulated CONTINUOUSLY (no reset)").
Measured 196.3 → 196.3 MiB over 6 minutes — **flat, no active leak**, 25% of the limit at 2
days. Dangerous mainly because F-35 means the OOM alert that would catch it is dead.
Realistic trigger: cardinality churn from ephemeral cloud resource ids as `entity_id`.

### F-46 [MEDIUM] No consumer-lag metric anywhere; partial degradation is invisible
Backpressure itself is **safe** — `await handle()` is inline in the `async for`, so a slow
ClickHouse blocks the consumer and lag grows rather than dropping. But `vmscrape.yml` has
no kafka job and `grep "lag"` across the config finds nothing. The flat-line alerts require
`increase(...) == 0` **exactly**, so a 10× slowdown — the realistic ClickHouse-degradation
shape — trips nothing. Separately, `auto_offset_reset="latest"` (`main.py:1622`) means a
downtime longer than retention silently skips the backlog with no log and no counter.

### F-47 [MEDIUM] Correlation service has no healthcheck; cloud-ingest has neither
### healthcheck nor memory limit
`docker-compose.yml:679-752` defines no healthcheck for correlation;
`docker-compose.override.yml:68-138` defines neither for cloud-ingest, while `poller.py:325`
holds entire decompressed gzip objects in RAM. cloud-ingest's `/metrics` on `:9109` serves
**zero series** in this deployment (counters only increment in connector mode, which is
off) — VictoriaMetrics is scraping an empty exposition.
- **Highest value-per-effort fix in the whole audit:** add
  `last_success_timestamp_seconds{provider,lane}` to cloud-ingest. One gauge makes every
  silent lane starvation (F-41) visible.


---

# SECTION 1b — EDGE COLLECTORS (syslog-ng, goflow2, telegraf)

### F-48 [HIGH] syslog-ng: statistics are switched OFF and the forwarding destination has
### no disk buffer — device syslog loss during a Vector restart is both possible and invisible
**`deployment/docker/syslog-ng/syslog-ng.conf:19`** — `stats(freq(0));` disables syslog-ng's
periodic statistics entirely. syslog-ng maintains internal `dropped`/`queued` counters per
destination; with stats off nothing emits them, and **nothing in the stack scrapes syslog-ng
at all** (it is absent from the VictoriaMetrics target list, which has 9 targets, none of
them syslog-ng).

**`:49-55`** — the `d_vector` destination has **no `disk-buffer()`**:
```
destination d_vector {
    syslog("vector-aggregator" transport("tcp") port(6601) flags(syslog-protocol));
};
```
With no disk buffer, the output queue is memory-only (default `log_fifo_size`). When
vector-aggregator restarts — which happened during this audit window (aggregator uptime
6h vs router 4h) — the queue fills and syslog-ng **drops messages**, with the counter
suppressed by `stats(freq(0))`.

- **Blast radius:** device syslog is the highest-value RCA evidence class (`link_down`, BGP
  state, optics). Losses are silent, unbounded by any metric, and correlated with
  deployments — i.e. they happen exactly when someone is changing something.
- **Fix:** `disk-buffer(mem-buf-size(10485760) disk-buf-size(536870912) reliable(yes)
  dir("/var/lib/syslog-ng"))` on `d_vector`, and `stats(freq(60) level(1))` plus a scrape.

### F-49 [MEDIUM] goflow2 ships flows through container stdout; lane separation is a
### container-name substring match
**`deployment/docker/goflow2/goflow2.yaml:36-39`** — `transport: file → path: stdout`. Flows
reach Vector via the Docker log driver:
```
$ docker inspect netops-goflow2-1 -> json-file  max-size:50m max-file:3
```
Two consequences:
1. **Rotation is a loss window.** If Vector's `docker_logs` source falls behind while a
   50 MB file rotates out (3 files deep), those flow records are gone. Nothing counts it.
   The config comment at `:13-14` acknowledges the intended fix: *"When wiring Kafka later,
   switch the transport to `kafka://`"*.
2. **Flows and app logs share one source and are split by a string match** —
   `deployment/docker/vector/vector.yaml:118-128`:
   ```vrl
   contains(string!(.container_name), "goflow2")
   ```
   If the container is renamed, scaled (`goflow2-2`still matches, but a rename to
   `flowcollector` does not), or replaced, **every flow record silently becomes an app log**
   and is indexed into `netops-applogs-*` with no error anywhere.
- **Fix:** switch goflow2 to its native `kafka://` transport (it supports it) and delete
  the `docker_flows`/`docker_applogs` string-match split entirely.

### Not a finding — verified deliberate
- **telegraf is defined but not running** by design: `docker-compose.yml:270`
  `profiles: [legacy]`, with a comment forbidding it as a `netops.metrics` producer and an
  architecture-contract test (`tests/test_architecture_contract.py`) enforcing that. This is
  **good practice** — a deprecated path gated behind a profile *and* a test, rather than
  deleted-and-forgotten or left silently running.
- Other non-running services are init containers (`kafka-init`, `opensearch-init`,
  `secrets-seal`) and optional profiles (`keycloak`, `netbox`).
- **`syslog-ng.conf:22-34`** — `keep-timestamp(yes)` + `recv-time-zone("UTC")` with a
  10-line comment explaining that RFC3164 has no timezone and that assuming container-local
  time silently shifts every message. **This is exactly the right reasoning applied to
  exactly the class of bug this audit is about** — origin time preserved, the ambiguity
  named and pinned rather than left to a default. Credit where due.


---

# SECTION 7 — STORAGE TIER

### F-50 [CRITICAL] Every strict ClickHouse tenant row policy has failed with a SQL syntax
### error 1,560 times and has NEVER once succeeded — and four test files assert the broken string
**`src/backend/clickhouse_policies.go:43`** — **independently verified by me.**

```go
// clickhouse_policies.go:42-44  (STRICT builder)
func chStrictRowPolicyDDL(table string) string {
	return "CREATE OR REPLACE ROW POLICY tenant_iso_" + table + " ON netops." + table + ...
}
```
ClickHouse's grammar is `CREATE ROW POLICY [IF NOT EXISTS | OR REPLACE] name ON ...` — the
modifier goes **after** `ROW POLICY`. Live proof:
```
$ clickhouse-client -q "SELECT name, value, last_error_message FROM system.errors WHERE name='SYNTAX_ERROR'"
SYNTAX_ERROR   1560
  Syntax error: failed at position 19 ('ROW'): ROW POLICY tenant_iso_cloud_costs ON netops.cloud_costs USING tenant_id = g...
$ SELECT count() FROM system.query_log WHERE query LIKE 'CREATE OR REPLACE ROW POLICY%' AND type='QueryFinish'
0            <- zero successes, ever
```
**The sibling builder 11 lines above gets it right** (`clickhouse_policies.go:32`,
`CREATE ROW POLICY IF NOT EXISTS ...`) and its policies do exist. This is the audit's
sibling-inconsistency theme in its purest form.

**Consequences, verified live:**
1. `netops.cloud_costs` has **no row policy at all** — it fails **OPEN**:
   ```
   netops tables with NO row policy:  cloud_costs (ReplacingMergeTree)
                                      corr_objects_latest (View), geoip_country (Dictionary)
   ```
   That is **per-tenant financial data with the database-layer tenant backstop entirely
   absent**, a direct violation of CLAUDE.md §3a rule 4 ("Storage layer enforces it …
   ClickHouse: inject `chTenantScope`"). Currently 27 rows / 1 tenant, so **no live
   cross-tenant leak today** — but the defence-in-depth layer the design mandates is gone,
   leaving app-layer filtering as the only control.
2. The documented self-heal at `clickhouse_policies.go:36-41` — *"boot convergence UPGRADES
   a pre-2026-07-02 lenient policy in place"* — **has never executed.** Any deployment
   predating 2026-07-02 retains the lenient `OR tenant_id = ''` escape on the correlation
   family permanently. This box is safe only because its strict policies came from
   `init.sql`, not from the converge path.
3. `ensureCHRowPolicies` (`:96-120`) retries 10× then `log.Printf`s and gives up — **no
   metric, no failed health check.** That is how 1,560 failures accumulated unnoticed.

**Worst part — the tests lock the bug in:**
```
src/backend/cloud_costs_test.go:81          asserts "CREATE OR REPLACE ROW POLICY tenant_iso_cloud_costs"
src/backend/clickhouse_policies_test.go:96  asserts "CREATE OR REPLACE ROW POLICY tenant_iso_" + table
src/backend/clickhouse_policies_test.go:120 asserts "CREATE OR REPLACE ROW POLICY tenant_iso_corr_signals"
src/backend/svc_rollup_schema_test.go:47,76 assert the same broken prefix
```
CI is green, the DDL has never run, and the test suite would reject the fix.
- **Fix:** `clickhouse_policies.go:43` → `"CREATE ROW POLICY OR REPLACE tenant_iso_"`; correct
  all four test files; add a **boot assertion** that every table in the converge list appears
  in `system.row_policies` and fail readiness if not. String-equality tests over generated
  SQL are worthless without one execution test — add one.

### F-51 [CRITICAL] The DEF-6 fix cannot be picked up by a restart: the config is a
### SINGLE-FILE bind mount and the editor's atomic rename left the container on the old inode
```
host      stat deployment/docker/vector-router/vector.yaml -> inode 268641, 14338 bytes
container stat /etc/vector/vector.yaml                     -> inode 291584, 11021 bytes
docker exec netops-vector-router-1 grep -c "DEF-6" /etc/vector/vector.yaml -> 0
docker inspect -> bind .../vector-router/vector.yaml : /etc/vector/vector.yaml
```
A single-file bind mount resolves to an **inode**. An editor that writes-then-renames (which
is what happened at 20:59:23) creates a *new* inode; the mount stays pinned to the old one
**forever**. `docker compose restart vector-router` will re-run the container against the
stale file and appear to fix nothing.
- **Fix:** `docker compose up -d --force-recreate vector-router`, then verify with
  `docker exec netops-vector-router-1 grep -c DEF-6 /etc/vector/vector.yaml`. Permanently:
  bind-mount the **directory**, not the file. Add a config-drift probe to the watchdog
  comparing a marker string in-container against the repo file — this failure mode is
  invisible and will recur.

### F-52 [CRITICAL] Authoritative loss measurement — 0.93% of ALL app-log documents, ~5,700/day
Supersedes the log-derived figure in Section 1 (Vector's log is rate-limited — 1,072
suppressed lines — so 914 was a **floor**). The per-document counter is authoritative:
```
$ curl .../_nodes/stats/indices/indexing
  "doc_status" : { "2xx" : 120029, "4xx" : 1127 }
$ index creation_date = 1784651753503 = 2026-07-21T16:35:53Z   (4.75 h before measurement)
```
=> **1,127 rejected / 4.75 h = 237/h = ~5,690 documents per day, 0.93% of all app logs**,
permanently lost. Note again (F-17) that `index_failed` in the same response reads **0**.

### F-53 [HIGH] `netops-snmptrap-*` has no template AND no ISM policy — never deleted,
### permanently yellow, 100% dynamically mapped
```
_cat/templates                -> only netops-flows, netops-syslog, netops-applogs
ISM ism_template.index_patterns -> ["netops-applogs-*","netops-syslog-*","netops-flows-*"]
_plugins/_ism/explain         -> netops-snmptrap-untagged-2026.07.21 : policy None
_cat/indices                  -> yellow open netops-snmptrap-untagged-2026.07.21
_cat/shards                   -> netops-snmptrap-... 0 r UNASSIGNED INDEX_CREATED
```
No template ⇒ `number_of_replicas` defaults to 1 on a single-node cluster ⇒ an unassignable
replica ⇒ **the cluster is permanently yellow, which destroys yellow as a usable alarm
signal.** Trap indices are never deleted (1.9 MB/day at this idle lab rate; a real trap storm
is orders of magnitude higher), and traps are the lane with the widest, most
vendor-controlled schema (29 top-level keys sampled; 68 typed fields already).

### F-54 [HIGH] Shard growth will exhaust heap long before the disk fills
```
_cat/nodes         -> heap.max 1.8gb, heap.percent 64
_cluster/health    -> active_primary_shards 64, unassigned_shards 35  (99 total)
cluster.max_shards_per_node -> 1000
```
The per-tenant daily index scheme (`vector-router/vector.yaml:274`,
`netops-applogs-{{tenant_seg}}-%Y.%m.%d`) creates one index per tenant, per family, per
day — ~26 new shards/day, reaching ~365 shards at the 14-day ISM steady state. At 1.8 GB
heap the accepted density is ~20 shards/GB ≈ 36 shards; **the cluster is already 2.75× over
at 99.** Heap/GC death arrives well before the 1000-shard cap (~32 days), and at the cap
**index creation is rejected outright and ingest stops silently.**
Compounding: `.opendistro-ism-managed-index-history-*` rolls a new index daily and is itself
**unmanaged by any ISM policy** — 34 such indices, accounting for essentially all 35
unassigned shards.
- **Fix:** weekly (not daily) per-tenant indices or a shared index + per-tenant aliases; ISM
  for the ism-history pattern; `number_of_replicas: 0` cluster-wide for single-node.

### F-55 [HIGH] All six stores share one 77 GB filesystem, which has already run out once
```
df -h /  -> 77G size, 61G used, 13G avail, 83%
system.errors -> NOT_ENOUGH_SPACE 3018  last 2026-07-17 18:10  "Cannot reserve 1.00 MiB"
              -> MEMORY_LIMIT_EXCEEDED 18  last 2026-07-20 (4.75 GiB vs 4.68 GiB cap)
```
Committed growth to each store's own configured steady state: Kafka 1.77 → ~7 GB
(`log.retention.bytes=536870912` × 14 topics, **zero per-topic overrides**), OpenSearch
0.11 → ~1.3 GB, ClickHouse archive +0.15 GB. **≈ +6.5 GB committed against 12.6 GB free →
~2.3 GB of margin before OpenSearch's 95% flood stage**, which sets every index read-only
and stops ingest (the 2026-06-10 outage mode named in `vector-router/vector.yaml:252-255`).
Anything genuinely unbounded (F-53 snmptrap, ism-history, F-57 Postgres, Docker image churn)
consumes that margin. The 3,018 `NOT_ENOUGH_SPACE` errors are proof it is already inadequate.

### F-56 [MEDIUM-HIGH] No ClickHouse writer sets any insert-tolerance setting; one never
### checks the status code at all
A repo-wide grep for `input_format_skip_unknown_fields`, `date_time_input_format`,
`input_format_allow_errors_num/ratio`, `async_insert` returns **zero hits in Go and Python**.
So every Go/Python insert runs with `input_format_skip_unknown_fields=0` — **one unknown JSON
key 400s the entire batch.** The two Vector CH sinks *do* set `skip_unknown_fields: true`
(`vector-router/vector.yaml:351, :367`) — the discipline exists in the config tier and is
absent from both code tiers.

**Worst offender — `src/backend/collectors/tunnels.go:419-423`:**
```go
resp, err := client.Do(req)
if err != nil { return }
_ = resp.Body.Close()
```
The status code is **never inspected**. A 400, 401 or 500 is silently discarded — no log, no
retry, no counter. It also sets **no `tenant_scope`** (`tunnels.go:395, :409`), unlike every
other writer.

### F-57 [MEDIUM] 16 Postgres tables grow forever; the audit trail's growth is structurally
### unobservable; and one code path can truncate it entirely
Live top tables: `ticket_outbox` 57 rows / **26 MB** (474 dead tuples, `last_autovacuum
NULL`), `incident_events` 20 MB, `incident_time_metrics` 17 MB, `audit_events` 29,002 rows /
13 MB (597 rows/day since 2026-06-03, unbounded).

`nms_store.go:578-580` (`connector_run_history`, 14-day DELETE) is the **only** time-based
DELETE in the entire non-test Go tree.

**The silent part:** the *file* audit backend self-bounds to a 5,000-event ring
(`audit.go:29`, trimmed `:118-119`), but the *Postgres* backend (`audit_pg.go:37-63`) is an
unbounded INSERT with no counterpart trim, while the **read path is capped at 1,000**
(`audit.go:31`, applied `audit_pg.go:78`). The table grows without bound while the UI stops
reflecting it — growth is invisible by construction. Another sibling inconsistency.

**Also flagged (UNCONFIRMED — needs the call path traced):** `pgstore.go:230` `saveRows`
issues `DELETE FROM <table>` **with no WHERE clause** under platform scope, and
`audit_events` is a registered rowSpec (`pgstore.go:63`) — so a flush through that path
would truncate the entire cross-tenant audit table.

### F-58 [MEDIUM] Live ClickHouse TTLs have drifted 3× from the checked-in DDL and three
### tables are never re-converged
| Table | Live TTL | `init.sql` | Drift |
|---|---|---|---|
| `findings` | 90 d | 30 d (`init.sql:146`) | **3×** |
| `tunnels` | 90 d | 30 d (`init.sql:121`) | **3×** |
| `flows` | 7 d | 7 d (`init.sql:55`) | ok |

`flows`, `tunnels` and `findings` carry TTLs **only** in `init.sql`, i.e. only on a fresh
volume. `chConvergeStmts` (`clickhouse_policies.go:51-93`) touches all three but never issues
`MODIFY TTL`, unlike the correlation family which is re-converged every boot
(`corr_retention.go:113-127`). An installation whose `netops.flows` predates the TTL line
grows unbounded and nothing repairs it.

### F-59 [MEDIUM] There is no working backup or restore for OpenSearch, and none for
### ClickHouse data outside a monthly single-family export
```
crontab -l                 -> 8 entries; scripts/backup.sh is NOT among them (never scheduled)
scripts/backup.sh:54-61    -> "ClickHouse dump" = SHOW CREATE TABLE for 2 of 16 tables (schema only)
GET _snapshot              -> { }        (no snapshot repository registered at all)
scripts/restore.sh:48      -> prints a manual psql command for the operator
backups/precutover-appstate/ -> one-off JSON from 2026-06-03, 7 weeks stale
```
Only `pg_dumpall` (`backup.sh:47`) is a real logical backup, and it relies on `data/` being
rsync-copied while the stack runs — a torn copy for ClickHouse and OpenSearch.
`ch-cold-export.sh` (monthly, `17 2 3 * *`) covers the correlation archive to Parquet and is
the one genuine data-preservation path — one family out of sixteen.
- **Plainly: a `data/` loss is unrecoverable for all search indices and 15 of 16 ClickHouse
  tables.** Combined with F-07 (`number_of_replicas: 0`), there is no redundancy at either layer.

### F-60 [LOW-MEDIUM] Postgres: 10-connection pool, no `statement_timeout`, no migration lock
`db.go:55` `MaxConns = 10`; every data access opens an explicit transaction to set the
`app.tenant_id` GUC (`db.go:167-187`), so 10 concurrent requests saturate the pool. A grep
for `statement_timeout` / `lock_timeout` / `idle_in_transaction_session_timeout` across all
`.go` and `.sql` returns **zero hits** — a runaway query holds a backend and its locks after
the caller has given up. Several stores also derive from `context.Background()` rather than
the request context (`audit_pg.go:44,61`, `users_pg.go:54`, `saved_pg.go:25,62,102,116,154`),
so client disconnect never propagates. Migrations (`db.go:112-161`) are transactional with a
version table (good) but have **no `pg_advisory_lock`**, so two replicas booting together
both apply the same file and one crashes at `db.go:151`. Prefixes `0016_` and `0024_` are
each used twice, so the number no longer encodes order.


---

# SECTION 8 — WHAT THE PLATFORM DOES WELL (do NOT spend time here)

A credible audit has to separate real risk from noise. These are verified strengths; several
are better than what I'd expect at this stage, and two are the templates the fixes should copy.

## Security & tenancy — genuinely strong
- **`safehttp/safehttp.go:57-74` is exemplary.** Dial timeout, `TLSHandshakeTimeout`,
  `ResponseHeaderTimeout`, a 5-redirect cap, and an SSRF `Control` hook that fires **after
  DNS resolution and before connect** — which is the only placement that defeats DNS
  rebinding. Used by all 9 tenant-configurable outbound integrations.
- **The correlation-family ClickHouse row policies that ARE installed fail CLOSED.**
  `tenant_iso_corr_*` and `tenant_iso_path_*` carry no `OR tenant_id = ''` escape, and a
  query missing the setting throws `UNKNOWN_SETTING 'tenant_scope'` rather than returning
  everything. The deliberate split between a lenient telemetry builder and a strict
  correlation builder, with the reasoning documented at `clickhouse_policies.go:25-41`, is
  good design — **only the SQL syntax is wrong** (F-50), not the model.
- **Claims-derived tenant scoping** — the design consistently derives tenant from the token
  and ignores client-supplied hints, with a per-feature isolation-test convention
  (`org_isolation_test.go` as template) mandated in CLAUDE.md §3a and visibly followed
  (`*_isolation_test.go` exists for ai_datasource, alert_episodes, appid, business_service,
  cloud_connectors, and more).
- **Default-closed tenancy in the correlation service** — untenanted cloud/app/controller
  events are dropped **and counted** (`CLOUD_DROPPED`, `APP_ID_DROPPED`,
  `CONTROLLER_EVENTS_DROPPED`) rather than guessed into a bucket.
- **Copilot/LLM path is properly bounded** (`copilot.go:63-64,150`, `copilot_tools.go:112,190`)
  — 256 KiB body, 64-message cap, `max_tokens` cap, per-principal rate limit. OWASP LLM04
  handled, matching CLAUDE.md §15.
- **Outbound HTTP timeouts are near-universal in Go** — all 29 `&http.Client{}` literals in
  non-vendor code carry a `Timeout`; zero `http.Get`/`http.Post`/`http.DefaultClient`; zero
  `exec.Command`. (SMTP, F-23, is the one exception.)
- **The global body cap works and is correctly placed** — `withBodyLimit(50 MiB)` wraps the
  mux at `main.go:803`, *ahead of* `withAuth`, with a single listener. Nothing is truly
  unbounded; F-32 is about tightening, not about a hole.

## The two reference implementations the fixes should copy
- **`ticketing_worker.go`** — a real persisted outbox: lease-claimed batches, dead-lettering,
  honors 429 `Retry-After`, tenant assertion before every provider call, and idempotent
  create-adoption via `LookupByCorrelationID` for the case where the link-store write failed.
  This is exactly what the alert-notify path (F-22) should be routed through.
- **The `corr_current` projection write** (`src/correlation/main.py:1113-1135`) — checks the
  return value, distinguishes retryable from permanent, logs structured context with
  correlation id and material hash, exposes a dedicated counter, has a critical alert, **and**
  a Go reconciler that force-repairs. It is the single best answer to this audit's defect
  class anywhere in the codebase. The other 19 ClickHouse call sites (F-38) should be a copy
  of it. **The team knows how to do this; it simply hasn't been generalised.**
- **`svc_rollup_worker`** — bounded batches, 30s timeout, retry that does **not** advance the
  checkpoint on failure (`:240-249`), exponential backoff capped at 10 minutes. Contrast with
  the cloud-ingest cost checkpoint (F-37), which advances *before* the flush.

## Reliability patterns that are already right
- **`cloudconn/exchange.go:208-283`** — the best retry in the tree: cap, exponential,
  **±50% jitter**, context-aware, `ensureDeadline()` backstop, fresh request per attempt.
- **`probe_paths_ingest.go:45,72-77,89,108`** — the model bounded-ingest handler: TTL plus a
  hard 64-vantage cap that **refuses new keys when full**, `maxPushedPaths=200`,
  `maxPushedHops=64`, 1 MiB `MaxBytesReader`. This is what every ingest handler should look like.
- **Bounded caches done right:** `appid/cache.go:29-70` (true LRU with back-eviction),
  `audit.go:118-121` (ring buffer at 5000), `session_store.go:155-162`,
  `verify_service.go:294-306`, `collectors/snmptrap.go:824,971-973` (1024-slot queue with
  explicit drop-under-flood), and in Python `_CLOCK_SKEW_LAST` (`main.py:277-293`, capped at
  4096 with oldest-quarter eviction).
- **`WINDOW_BUFFER` eviction/dedup lockstep** (`main.py:1058-1060`) — a subtle correctness bug
  that was found, fixed, and commented with the reasoning for *why* both structures must move
  together. That comment is worth more than the fix.
- **Correct backpressure semantics** in both the correlation consumer (inline `await handle()`
  ⇒ lag grows rather than dropping) and `snmp_discovery.go:332-337` (32-worker pool over an
  **unbuffered** queue).
- **The correlation consumer supervisor** — bounded stop/start timeouts (`main.py:1591-1592`),
  `_stop_bounded` abandons a hung consumer, and `test_consumer_supervisor.py` pins the exact
  2026-07-14 5.5-hour wedge. **That class of failure genuinely cannot recur.**
- **The WebSocket write path** is correct even though the lifecycle is not (F-20): the network
  write is *not* under the hub lock (`events.go:216-228`) and `SetWriteDeadline(10s)` is set
  per frame (`:302`), so a slow socket cannot stall publishers.

## Operational maturity beyond what a scaffold usually has
- **`scripts/stack-watchdog.sh`** is unusually mature: it checks all 18 services
  running+healthy, probes `:8000`, watches disk with auto-prune, uses a healthchecks.io
  dead-man's-switch (deliberately independent of the stack's own notifiers, because *"they
  can't report their own death"*), **and monitors its own helper cron's heartbeat** —
  detecting the death of the detector. Its disk check even names the exact downstream failure
  mode ("OpenSearch flood-stage read-only at 95%"). Its only gap is partial-loss blindness (F-19).
- **The 1-in-50 flow sample to OpenSearch** (`vector-router/vector.yaml:256-258`) with a
  comment recording the 2026-06-10 outage it prevents (an unsampled mirror wrote ~4 GB/day,
  hit flood stage, and turned every log index read-only). Correct fix, correct reasoning,
  written down.
- **`syslog-ng.conf:22-34`** — `keep-timestamp(yes)` + `recv-time-zone("UTC")` with a 10-line
  comment explaining that RFC3164 carries no timezone and that assuming container-local time
  silently shifts every message. **This is precisely the class of reasoning this audit is
  about, applied correctly and pre-emptively.**
- **Telegraf is gated behind `profiles: [legacy]`** *and* an architecture-contract test
  forbidding it as a `netops.metrics` producer — a deprecated path fenced by a test rather
  than left silently running.
- **ClickHouse retention design is near-complete**: all 13 live `netops.*` tables have TTLs,
  all partition by `(tenant_id, toYYYYMM(...))` so expiry is a cheap partition drop, and
  `ttl_only_drop_parts=1` is set on the history tables. The ISM policy is real and applied —
  all 24 `netops-{applogs,syslog,flows}-*` indices are bound to `netops-retention`, state
  `hot`, `failed: None`.
- **`ch_workload.go` + `workload-profiles.xml`** — per-profile `max_memory_usage` /
  `max_execution_time` enforced server-side. The post-#100 containment work is solid.
- **`correlations.go:53-95`** (`chSelect`) is the reference ClickHouse read:
  `NewRequestWithContext`, 20s timeout, `io.LimitReader(8 MiB)`, `tenant_scope`, `log_comment`
  attribution, `profile` routing. Every other CH caller should be this.
- **Fail-loud Python libraries** — `engine.py`, `signals.py`, `producers.py`, `catalog.py`,
  `path_graph.py` contain **zero** broad `except Exception` and zero bare `pass`; the broad
  handlers are confined to loop supervisors and enrichment feeds, each annotated with why
  degradation is correct there. That is the right place to draw that line.
- **Incident learning is written into the configs.** Four separate comments in the Vector
  files record a prior outage, its root cause, and why the current code is shaped the way it
  is (flows-proto 400s, the dotted-key `del(.label)` mapping conflict, the flow-sample disk
  flood, the VRL `??`-on-infallible boot failure). Most teams lose this knowledge; here it is
  in the file the next engineer will open.


---

# SECTION 9 — DEF-6 RESOLVED AND VERIFIED DURING THE AUDIT (21:07Z)

The owner deployed the fix at **21:07:05Z**, mid-audit. I verified it end to end rather than
taking it on trust.

**1. The fix is now actually in the container** (F-51's inode trap was avoided — the restart
did pick it up):
```
$ docker exec netops-vector-router-1 grep -c "DEF-6" /etc/vector/vector.yaml
3
$ docker inspect -f '{{.State.StartedAt}}' netops-vector-router-1
2026-07-21T21:07:05.059657262Z
```

**2. Rejections stopped dead.** The authoritative OpenSearch per-document counter, sampled
15 minutes apart across the restart:
```
20:59Z   doc_status: { "2xx": 120029, "4xx": 1127 }
21:14Z   doc_status: { "2xx": 121108, "4xx": 1127 }
         => +1,079 documents accepted, +0 rejected
$ docker logs --since 21:07:00 netops-vector-router-1 | grep -c mapper_parsing_exception
0
$ vector_component_discarded_events_total{intentional="false"}
(no series — zero drops since restart)
```

**3. The specific producer that was being dropped is now indexing correctly.** `cloud-ingest`
was the sole float-`ts` producer (Section 2, F-09) and 100% of its structured logs were being
lost. Live query against the applogs index:
```json
"hits": { "total": { "value": 246 } }
{ "service": "cloud-ingest", "timestamp": "2026-07-21T21:13:16.703Z", "ts": 1784668396703 }
{ "service": "cloud-ingest", "timestamp": "2026-07-21T21:13:12.286Z", "ts": 1784668392285 }
```
`ts` is now an **integer epoch-ms** (`1784668396703`), converted from the float epoch-seconds
`1784668396.703` by the `&log_lane` anchor at `vector-router/vector.yaml:123-133`. The
magnitude-inference branch works as designed.

**Final measured cost of the defect:** 1,127 documents rejected between 16:35:53Z (index
creation) and 21:07:05Z (fix deployed) = 4h31m, i.e. **0.93% of all application logs, a
run-rate of ~5,700/day**, permanently lost with no dead letter.

## What this does and does not close
- **CLOSED:** the `ts` type collision on all four log lanes, via a shared anchor that makes
  sibling drift structurally impossible. Correct fix, correct level of abstraction.
- **STILL OPEN — F-13:** the new dead-letter path is attached only to `cloudcosts_normalized`
  and, more importantly, `reroute_dropped` catches **transform** errors while DEF-6 was a
  **sink** rejection. `netops-deadletter-*` does not yet exist (nothing has been rerouted),
  and it would not have caught this incident. The durable control is an alert on
  `vector_component_discarded_events_total{intentional="false"}` — which requires F-16
  (there is no alerting engine).
- **STILL OPEN — F-15:** `snmptrap` and `cloudlogs` now emit integer `ts` but still have no
  index template, so `ts` will dynamically map as `long` rather than `date` on those two
  indices. Add the two templates before the next UTC rollover.
- **STILL OPEN:** F-01's deeper point — no template declares `dynamic:` or
  `ignore_malformed: true`, so the *next* field-type surprise fails exactly the same way.
  The class is not closed until rejection is observable (F-16/F-18) and mappings degrade the
  field instead of dropping the document.


---

# SECTION 10 — API: ACCEPT-AND-IGNORE (first-party verification of the seed defects)

### F-61 [HIGH] `GET /api/devices` ignores every pagination parameter and returns the whole
### table — verified live
```
$ for q in "" "?limit=1" "?limit=1&offset=0" "?page_size=1"; do curl .../api/devices$q; done
                           bytes=218342  count=512
  ?limit=1                 bytes=218342  count=512
  ?limit=1&offset=0        bytes=218342  count=512
  ?page_size=1             bytes=218342  count=512
```
**Byte-identical responses.** The endpoint accepts the parameters (no 400), returns 200, and
silently ignores them — the purest form of this audit's defect class at the API boundary.

- **Blast radius:** 218,342 bytes / 512 devices = **426 bytes per device**. At a 50,000-device
  enterprise fleet that is a **21 MB uncacheable response**, fully materialized in Go memory
  per concurrent caller. A client that "paginates" by requesting `limit=50` in a loop pulls
  the entire fleet on **every** iteration — an accidental self-DoS that looks like normal
  client behaviour.
- **Compounding:** F-26 shows the WebSocket hub already performs a full fleet scan per client
  every 5s under the hub read lock. The list endpoint and the live-update path multiply the
  same unbounded scan.
- **Fix:** parse and apply `limit`/`offset` with a server-side maximum (cap at e.g. 500,
  default 100), return a `total` alongside; **reject unknown/unhandled query params with 400**
  rather than ignoring them — silent acceptance is what makes this class invisible.

### F-62 [HIGH] `PUT /api/settings/rca-window` returns 200 without persisting (seed defect,
### carried forward)
Given as a confirmed defect in the audit brief. Same shape as F-61: the caller receives a
success response for work that did not happen, so the UI shows the new value, a page reload
shows the old one, and nothing anywhere records a failure.
- **Fix:** return the persisted representation read back from the store, not the request
  echo. A write handler that cannot fail is a write handler that is not writing.

**Systemic recommendation for both:** adopt a strict-parameter convention across the API —
unknown query params and unknown body fields return `400` with the offending key named. This
converts an entire silent class into a loud one at negligible cost, and it is the API-layer
equivalent of the `ts_invalid` decision the Vector fix got right.


---

# SECTION 11 — RANKED FINDINGS

Ranked by **expected customer impact**, not by how interesting the bug is.
Status key: **[FIXED 21:07]** verified resolved during this audit; all others open.

| # | Sev | Title | File / evidence | One-line impact |
|---|-----|-------|-----------------|-----------------|
| F-20 | **Critical** | WebSocket hub `send on closed channel` panics the process on a normal tab close | `events.go:47-53` vs `:89-95,:106-118`, closed at `:239,250,257,268,275,280` | Total API outage, all 12 tenants, triggered by ordinary traffic; no `recover()` anywhere |
| F-50 | **Critical** | Strict ClickHouse row-policy DDL is invalid SQL — 1,560 failures, 0 successes ever; 4 tests assert the broken string | `clickhouse_policies.go:43`; `system.errors SYNTAX_ERROR=1560` | `cloud_costs` (per-tenant billing) has **no** DB-layer tenant policy — fails open |
| F-16 | **Critical** | No metric-based alerting engine exists at all | no vmalert/alertmanager in compose; Grafana alert-rules `[]` | `rules.yaml` is documentation; every "add an alert" fix has nowhere to go |
| F-35 | **Critical** | All 5 container OOM/restart/memory alerts match zero series | `rules.yaml:670-701`; cAdvisor emits no `name` label | Correlation can OOM/crash-loop with no signal |
| F-34 | **Critical** | Python rejects exactly the timestamps Vector normalizes; `timenorm.py` is dead code | `producers.py:222`, 13 call sites; `grep timenorm` → tests only | RCA causal ordering silently computed from receive time, not event time |
| F-37 | **Critical** | cloud-ingest advances the cost checkpoint before the flush; flush error is `pass` | `cost.py:181,489-492` | A full day of billing records per account, permanently lost, never retried |
| F-36 | **Critical** | cloud-ingest: all 17 `producer.send()` are fire-and-forget | `poller.py:695` +16 | Permanent Kafka produce failures lost with zero logs and zero counters |
| F-01/09 | **Critical** | DEF-6 root cause: `ts` mapping was accidental (dynamic), producer-race-dependent | `_index_template` vs live mapping; 3 types on one topic | **[FIXED 21:07]** — 1,127 docs (0.93%) lost over 4h31m before the fix |
| F-02 | **Critical** | 6 ingest lanes, 2 normalized, 4 did not — the generator of the whole class | `vector-router/vector.yaml` transform table | **[FIXED 21:07]** via `&log_lane` anchor; flows/cloudcosts still hand-rolled |
| F-51 | **Critical** | Single-file bind mount + editor rename pins the container to a stale inode | host inode 268641 vs container 291584 | A config fix can appear deployed and not be; invisible and will recur |
| F-13 | **Critical** | New DLQ cannot catch the failure it was built for (`reroute_dropped` ≠ sink rejection) | `vector-router/vector.yaml:224,241-250` | The class remains uncovered even after the DEF-6 fix |
| F-17 | **Critical** | OpenSearch `index_failed` reads **0** during active document loss | `_nodes/stats` `index_failed:0` vs `4xx:1127` | The obvious counter lies; dashboards built on it are worse than nothing |
| F-38 | High | 19 of 20 ClickHouse insert sites discard the failure boolean | `main.py:1109…2316`; only `:1123` checks | Replay/archive silently develops holes; live RCA looks perfect |
| F-22 | High | Alert delivery: unbounded goroutine fan-out, no retry, log-only, no metric | `notify/dispatcher.go:85-91,104-115,162-166` | Pages silently lost during the incident the platform exists to surface |
| F-40 | High | At-most-once consumer; one poison event tears down all 10 topics; no DLQ | `main.py:1618-1631,1639` | Events lost on any handler failure; no counter, payload unrecoverable |
| F-04 | High | In-memory 500-event buffers, acks disabled, sink healthchecks off | `vector_buffer_max_event_size=500`; no `buffer:`/`acknowledgements:` | HTTP 200 returned to the Go backend before the event is durable on the bus |
| F-48 | High | syslog-ng stats disabled + no disk buffer on the forwarding destination | `syslog-ng.conf:19,49-55` | Device syslog dropped during aggregator restarts, with the counter switched off |
| F-55 | High | Six stores on one 77 GB fs, 83% used, ~2.3 GB margin; already ran out once | `df`; `NOT_ENOUGH_SPACE=3018` on 2026-07-17 | Flood stage sets every index read-only and stops ingest |
| F-54 | High | Shard growth 2.75× over heap density already, heading to ~10× | 99 shards / 1.8 GB heap; `max_shards_per_node=1000` | Heap death, then silent rejection of index creation |
| F-53 | High | `netops-snmptrap-*`: no template, no ISM, permanently yellow | `_ism/explain` → policy None; UNASSIGNED replica | Never deleted; and yellow is destroyed as an alarm signal |
| F-59 | High | No working backup/restore for OpenSearch; ClickHouse covers 1 of 16 tables | `GET _snapshot` → `{}`; `backup.sh` not in crontab | `data/` loss is unrecoverable; combined with `replicas:0`, no redundancy at all |
| F-23 | High | SMTP has no timeout anywhere | `notify/email.go:188,194` | Hung relay leaks a goroutine + socket permanently, per alert |
| F-05 | High | `merge()` of arbitrary producer JSON → unbounded field growth to a 1000-field wall | `vector/vector.yaml:136-141`; 67 fields today | At the limit, a full-day application-log blackout for every tenant |
| F-39 | High | Syslog lane has zero intake observability; its own alert checks other lanes | `main.py:2138`; `rules.yaml:855-864` | Highest-value RCA evidence class can die silently |
| F-41 | High | One failing AWS lane permanently starves every lane behind it | `poller.py:733-776` | Live now: 167 consecutive cycles of an unalertable pagination bug |
| F-24 | High | `path_graph_store` memory store is append-only forever | `path_graph_store.go:239,249` | Slow OOM of the API; read latency degrades in lockstep |
| F-61 | High | `GET /api/devices` ignores all pagination params; returns the full table | verified: 4 param sets → byte-identical 218 KB / 512 rows | 21 MB uncacheable response at enterprise fleet size |
| F-62 | High | `PUT /api/settings/rca-window` returns 200 without persisting | seed defect | UI shows the new value; a reload shows the old one; nothing logs it |
| F-42 | High | Flow parse failures dropped with no counter and no log | `main.py:2226` | Cannot distinguish "low flow rate" from "100% parse failure" |
| F-18/19 | High | The detecting signal exists and is scraped; nothing alerts. Watchdog sees only total stall | VM has the metric; `stack-watchdog.sh:163-174` uses `== 0` | Watchdog stayed green through the entire measured incident |
| F-03 | High | No DLQ anywhere; `drop_on_error` makes real errors indistinguishable from filtering | 4 transforms, no `reroute_dropped` (pre-fix) | Future VRL errors delete data and look like normal operation |
| F-06/15 | Medium-High | No template for `snmptrap`/`cloudlogs`; post-fix `ts` will map as `long` not `date` | `_cat/templates` = 3 of 6 lanes | Date-range queries and time pickers silently misbehave |
| F-25 | Medium-High | `login_throttle` fails **open** at 50k entries, silently | `login_throttle.go:26,66-68` | Spray 50k usernames → brute-force lockout disabled platform-wide |
| F-26 | Medium-High | Hub does O(devices) work per client under the lock every 5s; no client cap | `events.go:103-119` + `dashboard.go:38-100` | N sockets multiply backend CPU by N; latency-amplification DoS |
| F-43 | Medium-High | Stale topology declared **fresh** when the enrichment file disappears | `main.py:580-583,1178-1184` | RCA grounds causal edges on stale topology and stamps `topology_stale=false` |
| F-56 | Medium-High | No CH insert-tolerance settings anywhere in Go/Python; one writer ignores the status code | grep → 0 hits; `collectors/tunnels.go:419-423` | One unknown key 400s a whole batch; tunnels writes fail invisibly |
| F-08 | Medium | Unauthenticated HTTP bus bridge; `:8689` published on a host interface | `vector/vector.yaml:99-104`; `docker port` | Cross-tenant event injection with a forged `tenant_id` |
| F-11 | Medium | `tenant_id` empty on all 6 device-telemetry lanes → one shared index | 400/400 sampled per lane | Designed at-rest tenant separation is not in effect for device telemetry |
| F-27 | Medium | Unbounded `io.ReadAll` on CH responses; query not cancelled on client timeout | `report_scheduler.go:1209,1223` (21 sites) | The #100 incident shape, client-side |
| F-29 | Medium | No Read/Write/Idle timeouts; no worker drain on shutdown | `main.go:821-826,861-867` | Slowloris-on-body in TLS mode; every deploy abandons in-flight writes |
| F-44 | Medium | `metrics_dropped` conflates 3 causes; metric lane never emits a clock-skew finding | `main.py:1721,1728,1737` | Live: device `wan-r2` losing 100% of telemetry, unnamed by any finding |
| F-57 | Medium | 16 PG tables with no retention; audit growth invisible by construction | `audit_pg.go:37-63` vs `audit.go:118-119` | Unbounded table, read path capped at 1000 — growth cannot be seen |
| F-58 | Medium | Live CH TTLs drifted 3× from `init.sql`; 3 tables never re-converged | `findings`/`tunnels` 90d vs 30d | Pre-existing installs grow unbounded and nothing repairs them |
| F-30 | Medium | Ticketing/audit store writes discarded on the write path | `ticketing_worker.go:245,271,275,…` | Duplicate Slack messages; audit entries silently lost (compliance) |
| F-31 | Medium | No `recover()` on 33 goroutines; unauthenticated UDP trap parser is the worst | `collectors/snmptrap.go:694-730,933` | Remote pre-auth process termination via a malformed trap |
| F-28 | Medium | Retry without effective jitter in 3 paths | `nms/retry.go:26`; `ticketing_worker.go:329-340` | Thundering herd against a recovering upstream |
| F-45 | Medium | Unbounded correlation state (measured flat today) | `episodes.py:113`; `main.py:232,493,1778` | Latent OOM; dangerous because F-35 killed the alert that would catch it |
| F-46 | Medium | No consumer-lag metric; flat-line alerts need `== 0` exactly | no kafka job in `vmscrape.yml` | A 10× slowdown — the realistic degradation shape — trips nothing |
| F-47 | Medium | Correlation has no healthcheck; cloud-ingest has neither healthcheck nor mem limit | `docker-compose.yml:679-752` | A dead consumer looks identical to a healthy one |
| F-49 | Medium | goflow2 ships flows via container stdout; lane split is a container-name substring match | `goflow2.yaml:36-39`; `vector.yaml:118-128` | A rename silently turns every flow record into an app log |
| F-07 | Medium | All log indices `number_of_replicas: 0` | template settings | With F-59 (no snapshots), any shard corruption is unrecoverable |
| F-14 | Medium | Dead-letter records likely capture no reason (`.metadata` vs `%metadata`) | `vector-router/vector.yaml:248` | **UNCONFIRMED** — a DLQ that loses the reason is most of the way to no DLQ |
| F-21 | Medium | `writeJSON` discards the encode error at 397 sites; NaN → 200 with empty body | `main.go:1454-1458`; `alerts/evaluator.go:96` | A NaN sample silently disables the alert built on it |
| F-32 | Low-Med | 45 handlers with no per-handler body cap; 5 are pre-auth | `auth.go:341,444,550`, `ldap.go:295`, `tacacs.go:300` | 50 MiB global cap amplifies 3-5× in struct decode |
| F-60 | Low-Med | PG pool of 10, no `statement_timeout`, no migration advisory lock | `db.go:55`; grep → 0 hits | Runaway queries hold locks after the caller gives up |
| F-33/45 | Low | Assorted unbounded maps; possible `nms/` response-body leaks | `dashboard.go:176`; `nms/auth.go:65,…` | **UNCONFIRMED** for the leaks — needs each function read end to end |

---

# SECTION 12 — TOP 5 TO FIX FIRST

Chosen for **expected customer impact per hour of engineering**, not severity alone.

### 1. `events.go` — stop closing `c.send` from the read pump  *(hours; prevents total outage)*
**F-20.** This is the only finding in the report where **ordinary user behaviour — closing a
browser tab — can kill the entire API for every tenant.** Every other Critical is data loss or
a missing signal; this one is availability, it is reachable without any attacker, and there is
no `recover()` anywhere to soften it. Delete `close(c.send)` from `wsClient.close()`, keep
`close(c.done)`, and make both broadcast sites select on `<-c.done`. Add a `safego()` wrapper
over all 33 goroutine sites in the same change.

### 2. Stand up `vmalert` and wire `rules.yaml`  *(1 day; unblocks ~15 other findings)*
**F-16, and the precondition for F-18, F-35, F-13, F-19, F-38, F-42, F-46.** The platform
already has: the metrics (Vector's discard counter, correlation's 27 lane counters), the
scrape (9 healthy VM targets), and the rules file. **The only missing piece is something that
evaluates it.** Until this exists, every other recommendation in this report that ends in "add
an alert" is unimplementable. Ship vmalert + a notifier, then immediately add:
`increase(vector_component_discarded_events_total{intentional="false"}[15m]) > 0`.
In the same change, fix the two rules that can never fire (F-35 cAdvisor `name` label, F-39
`CorrSyslogLaneFlatlined` checking the wrong lanes) — an alert that matches zero series is
worse than no alert, because it reads as coverage.

### 3. `clickhouse_policies.go:43` — one-word SQL fix, plus the four tests that lock it in  *(hours)*
**F-50.** `CREATE OR REPLACE ROW POLICY` → `CREATE ROW POLICY OR REPLACE`. 1,560 failures, zero
successes, and the DB-layer tenant backstop on per-tenant **billing data** is currently absent.
This ranks third rather than first only because there is no live cross-tenant leak today
(`cloud_costs` holds one tenant). The reason to do it now is what it reveals: **four test files
assert the broken string, so CI is green and would reject the fix.** Add one *execution* test
against a real ClickHouse and a boot assertion that every converge-list table appears in
`system.row_policies` — string-equality tests over generated SQL are worthless without one.

### 4. Finish the DEF-6 fix: templates for the last two lanes, `ignore_malformed`, and the
### real dead-letter  *(1-2 days; closes the class rather than the instance)*
**F-15, F-13, F-05, F-51.** The 21:07 deploy fixed the *instance* and did it well. Four things
close the *class*: (a) add `netops-snmptrap` and `netops-cloudlogs` templates before the next
UTC rollover, or `ts` maps as `long` there; (b) set `ignore_malformed: true` and an explicit
`dynamic` policy on all templates so the next type surprise drops a **field**, not a
**document**; (c) stop merging unbounded producer JSON at `vector/vector.yaml:136-141` — 67
fields against a 1000-field wall; (d) bind-mount the config **directory**, not the file, and
add a config-drift probe to the watchdog — F-51 means a future fix can look deployed and not be.

### 5. Give the write paths a channel: bound the outbox, count the failures  *(2-3 days)*
**F-22, F-38, F-36, F-37, F-30.** These are one defect repeated: a write fails and the caller
never learns. Highest value per line: (a) route alert delivery through the existing
`ticketing_worker.go` outbox pattern instead of unbounded `go func` + `log.Printf` — a lost
page during an incident is the worst possible instance of this class; (b) hoist the
`corr_current` pattern (`main.py:1113-1135`) into `CH.insert` itself so all 20 sites get a
counter for free; (c) fix `cost.py:181` to advance the checkpoint **after** the flush, not
before — that one is a guaranteed daily loss of billing data with a `pass` on the error.

**Honourable mention — highest value-per-effort in the entire audit:** add
`last_success_timestamp_seconds{provider,lane}` to cloud-ingest. One gauge, a few lines, and
every silent lane starvation (F-41's 167 unalertable cycles) becomes visible.

---

# SECTION 13 — THE ONE-PARAGRAPH VERDICT

The engineering instincts here are good and in several places better than good — the
`corr_current` write path, the ticketing outbox, `safehttp`, the strict/lenient row-policy
split, the syslog-ng timezone reasoning, and the habit of writing the postmortem into the
config file next to the fix. The failure is not carelessness; it is that **remediation is
consistently applied to the instance and not to the class.** The flows lane learned about type
coercion and applogs did not. `corr_current` learned to check its write and nineteen siblings
did not. The file audit store learned to bound itself and the Postgres one did not. The DEF-6
fix, deployed mid-audit, is the pattern in miniature: an excellent fix that closes four lanes
via a shared anchor, ships a dead-letter that cannot catch the failure it was built for, and
leaves two lanes without templates. The single highest-leverage intervention is not any one
fix — it is **F-16, standing up an alerting engine**, because the platform is already
producing the signals that would have caught almost everything in this report, and there is
nothing on the other end of the wire listening to them. An observability platform that cannot
observe itself is the finding.

*(End of report — 2026-07-21)*

---

# SECTION 14 — API SURFACE: ACCEPT-AND-IGNORE / 2xx-WITHOUT-PERSIST (full sweep)

251 routes traced handler→store→SQL. **This section CORRECTS §10's F-62** and supplies a far
better root cause for the seed defect.

## The deployment-context finding that reframes everything — verified by me

```
$ grep -n STORE_BACKEND deployment/docker/docker-compose.yml scripts/install.py deployment/docker/.env
docker-compose.yml:1030   STORE_BACKEND: ${STORE_BACKEND:-file}     <- shipped DEFAULT
scripts/install.py:488    STORE_BACKEND=file                        <- what install.py writes
deployment/docker/.env:27 STORE_BACKEND=postgres                    <- THIS box only
$ docker inspect netops-api-1 --format '{{.Config.WorkingDir}} | {{.Config.User}}'
/home/nonroot | 65532:65532
$ grep -n WORKDIR deployment/docker/Dockerfile.backend
11:WORKDIR /src        <- builder stage only; the final stage sets none
```
**This live stack is NOT representative of a fresh install.** An entire class of defects below
is inert here and live for every customer.

### F-63 [CRITICAL] Seven settings stores use *relative* kv keys — on a default install the
### write never lands and the API still returns 200
```
src/backend/cloud_slo.go:77            return "cloud_slos.json"
src/backend/tenant_governance.go:102   return "tenant_governance.json"
src/backend/rca_promotion.go:82        return "rca_promotions.json"
  + cloud_monitors.go:91, tenant_display.go:59, rca_action_items.go:131,
    rca_report_integrity.go:109        (no leading /data on any of them)
```
No `TENANT_GOVERNANCE_PATH` / `CLOUD_SLO_PATH` / `RCA_*_PATH` is set anywhere in
`deployment/` or `scripts/`. Under the default file backend a relative key resolves against
the API container's WORKDIR — **`/home/nonroot`**, which is not the `/data` bind mount and is
not writable when `install.py:346` stamps a non-65532 `CORRELIX_UID` into compose:
```
--- as 1000:1000 (install.py CORRELIX_UID) ---
cwd: /home/nonroot   MkdirAll ERR: mkdir .: permission denied
                     WriteFile ERR: open cloud_slos.json.tmp: permission denied
```
The EACCES is swallowed (`tenant_governance.go:126-128` `logWarn`), the mutator returns no
value (`rca_promotion.go:135`) so the handler is **structurally unable** to report failure,
and an `AuditEvent{Status:200, Decision:"allow"}` is written asserting success
(`cloud_slo.go:315-320`, `tenant_governance.go:637-642`).

- **Blast radius:** `PUT /api/cloud/slos`, all four `/api/settings/*` editors,
  `/api/settings/display`, RCA promotion, **RCA action items**, **RCA revision register**.
  At `CORRELIX_UID != 65532` it never persists at all; at 65532 it lands in the ephemeral
  container layer and dies on the next `docker compose up` — exactly what `docs/UPGRADE.md`
  instructs operators to do.
- **Why this supersedes §10 F-62:** `PUT /api/settings/rca-window` was **not** reproducible as
  "200 without persisting" on this box, because `.env` sets postgres and `kvSave` writes to
  `app_kv`. The seed defect is real — it is just **backend-conditional**, which is worse: it
  is invisible in every developer environment configured like this one.
- **Worst in kind:** the RCA revision register exists *specifically* to prove a report was not
  mutated. It does not persist.
- **Fix:** default all seven to `/data/…` (one line each), then make `saveLocked` return
  `error` and propagate to 500.

### F-64 [CRITICAL] `PUT /api/ai/tenant-config` destroys OTHER tenants' persisted provider keys
`ai_tenant_config.go:88-101` rewrites the whole map; a tenant whose `vault.Encrypt` fails is
`continue`d out of `sealed` (`:94`) and `kvSave` (`:101`) then writes the file **without it** —
with the write error discarded by `_ =`. Tenant B saves its config; tenant A's stored BYO
provider key is silently deleted from disk. Both get 200. Conditional on `SEAL_PROVIDER=swtpm`
(`secrets.go:130-133` is a passthrough when dormant).
- **Cross-tenant data destruction. Fix independently of everything else.**

### F-65 [CRITICAL] Latent: the wrapped-DEK custody store is also a relative key
`secrets.go:48` (`secrets_wrapped_keys.json`), `tls_ca.go:39`, `cloud_workload_issuer.go:47`.
Inert while the Vault is dormant — but **the moment an operator sets `SEAL_PROVIDER=swtpm` on
the file backend, the wrapped-DEK custody store lands in the ephemeral container layer and
every restart makes all sealed secrets permanently undecryptable.**

### F-66 [CRITICAL] Two ticket endpoints have no `LIMIT` in the SQL at all — 22 MB and 3.2 MB
**Verified live by me:**
```
/api/tickets/outbox              bytes=22,024,047  time=0.82s
/api/tickets/outbox?limit=10     bytes=22,024,047  <- byte-identical
/api/tickets/audit               bytes= 3,241,932
```
`ticketing_store.go:611` / `:706` — `SELECT … ORDER BY created_at` with no LIMIT and no params.
Both tables are append-only and grow forever. Any `infrastructure:read` user can loop this
into a self-DoS while holding a PG connection (pool is 10, F-60).

### F-67 [CRITICAL] `/api/tickets/links` silently drops past a hardcoded 1000 → the UI reports
### "no ticket filed" for tickets that exist
`ticketing_http.go:539` (literal `1000`), `ticketing_store.go:529-535` `ORDER BY updated_at
DESC LIMIT $1`; a miss returns `{"state":"not_created"}`. **Live: 973 links — 27 from the
cliff.** Crossing it flips the *oldest* RCAs' badge from the real ServiceNow ticket to
`not_created`, so operators file duplicate tickets against incidents that already have them.
**Data-integrity failure, not truncation.**

### F-68 [CRITICAL] Seven security-policy settings are stored, displayed as active, and
### enforced by nothing — verified by me
```
$ for f in password_expire_enabled password_expire_days account_validity_days \
           account_inactivity_days concurrent_login; do grep -rn "$f" src/backend --include=*.go | grep -v _test | wc -l; done
1   1   1   1   1        <- one hit each = the struct definition. ZERO read sites.
```
`security_settings.go:35-43`. Live GET returns `password_expire_enabled:true`,
`password_expire_days:90`, `account_inactivity_days:90`, `concurrent_login:"allow"`, and the
SPA renders all seven as working controls (`tabs/admin.tsx:319-334`).
- **Blast radius:** a customer answers a SOC2/PCI questionnaire "90-day expiry and inactivity
  lockout are enforced" — **the product's own settings page says so.** Nothing expires,
  nothing locks. Three sibling settings *are* enforced (length/classes `password_policy.go:51`,
  lockout `auth.go:202`, timeouts `auth.go:219`), which is what makes the other seven credible.

### F-69 [CRITICAL] `DELETE /api/devices/{id}` returns 204 and the device returns within 60s
`main.go:1353` → 204. `discovery.go:411-415` is `delete(a.cache, id)` — **no persistence in
any backend mode**; the next poll re-adds it (`:210`, static source polls every 60s at `:443`).
`POST` is likewise RAM-only. Neither outcome is reported.

### F-70 [HIGH] `POST /api/auth/logout` returns `{"status":"ok"}` without revoking anything
Decode error discarded (`auth.go:444`); unknown token ignored (`refresh.go:228-241`); four
store methods hold the error and drop it (`session_store.go:213,224,242`).
**Proved live by the sweep:** malformed JSON → `200 ok`; field typo `refreshToken` → `200 ok`;
**the token then still minted a new access token (200).** `session_handlers.go:84` writes a
`SESSION_REVOKED` audit event asserting a kill that may be memory-only — **a false SOC2
artifact**. `auth.go:605-606` promises a password change "revokes ALL sessions so a stolen
session can't survive a credential reset"; after a restart it does survive.

### F-71 [HIGH] `intQuery` fails OPEN to the default — asking for *more* silently gives *fewer*
**Code confirmed by me, `flows.go:650-660`:**
```go
n, err := parseIntStrict(v)
if err != nil || n < min || n > max { return def }   // <- 501 becomes 20, silently
```
25 call sites; same shape in `clampIncidentLimit` (`incidents_pg.go:389-393`). Measured on
`/api/flows/top`: `limit=500 → 500 rows`; **`limit=501 → 20`**; `5000 → 20`; `0 → 20`;
`abc → 20`. Never an error. A client paginating by doubling collapses to 20 at step 4 and
shows a fraction of the traffic as the whole picture.

### F-72 [HIGH] `/api/graphql` ignores the selection set, arguments and variables; never
### returns `errors`; and bypasses the RBAC gate its REST twin enforces — verified live by me
```
{devices{id}}                  -> 218,133 bytes   (all 512 devices, ALL fields)
{devices(limit:1,first:1){id}} -> 218,133 bytes   (byte-identical — args ignored)
{bogus}                        ->      12 bytes   ({"data":{}} with HTTP 200, no `errors` key)
```
Substring dispatch (`graphql.go:57-95`, `contains(q,"devices")`); `Variables` declared at `:31`
with **zero read sites**; auth is `claims, _ := userFrom(...)` at `:51` with **no
`requirePerm`**, while `handleDevices` requires `infrastructure:read` (`main.go:1260`).
A malformed query returning `{"data":{}}`+200 is read by every spec-compliant client as
"success, no results".

### F-73 [HIGH] `/api/audit` returns 200 + empty array when the query fails
`audit_pg.go:101-104` `logError(...); return nil`; the `auditRepo` interface has no error
channel (`audit.go:40-43`). A SIEM polling during a PG blip or an RLS regression records
**"no privileged actions occurred."** The one endpoint where silence must never mean success.

### F-74 [HIGH] `?severity=` on `/api/incidents` silently substitutes a *different* filter
`incidents.go:31` `return 0 // unknown → info`, applied as a real predicate
(`incidents_pg.go:171-174`). **Live: `severity=warning`, `severity=bogus` and `severity=WARN`
all return byte-identical 47,521-byte responses = the `info` bucket.** A client filtering for
"warning" receives **info** incidents presented as warnings. Confidently wrong — worse than
ignoring. `/api/findings` does this correctly (`flows.go:356-360`).

### F-75 [HIGH] Inbound ITSM webhook drops events and the `received: N` count lies
`integrations_http.go:233-236` `RecordInbound` error → `logError; continue`; `:258` returns
`{"received": len(events)}` — the **parsed** count, not the recorded count. All N can fail and
the response still says N. ServiceNow/Jira gets a 200 and **will never redeliver**. Permanent,
unrecoverable loss of inbound ticket-state transitions, and it defeats the sender's own retry.

### F-76 [HIGH] Cloud-connector and NMS credentials stored in RAM behind a 201
`cloud_connectors_store.go:94-114` falls back to `newMemCloudConnStore()`; `PutSecretRef`
(`:189-205`) holds the ciphertext of the operator's pasted AWS/Azure/GCP credential. Same for
NMS (`nms_store.go:133-136`), which is **on by default** — `nms/topics.go:25-30` returns `true`
when `FEATURE_NMS_INTEGRATIONS` is unset, contradicting CLAUDE.md's "dormant by default".
Webhook URLs already handed to Meraki become permanent 404s after a restart.
**The honest-refusal path is dead code:** `cloud_connectors_handlers.go:108,184` guard
`if s.cloudConn == nil { 501 }` — the constructor never returns nil.

### F-77 [HIGH] `allow_validation_scenarios` accepted, echoed as saved, never persisted
`ticketing_model.go:29` — **absent from every SQL column list and every migration**. The mem
store keeps it (`ticketing_store.go:181`) so unit tests pass; the production PG store drops it.
Live: a policy literally named *"PDI validation (confirmed-only)"* shows
`allow_validation_scenarios: false`. **An API that echoes an unsaved value is the worst
variant of this class.**

### F-78 [HIGH] Notification-channel PUTs return 200 when persistence fails outright
`notify_config.go:169-176` — `save()` returns nothing; encrypt failure logs and returns; write
error is `_ = kvSave`. Callers all 200 (`:340,412,495,577,651`). Admin sets the PagerDuty
routing key, sees 200; the write fails; next restart silently reverts paging to the old
destination. **Alerts go nowhere and nothing reported an error.**

### F-79 [HIGH] `/api/vulns`: 500 of 7,560 findings reachable, hard ceiling 2,000, no cursor
`vulns.go:363` `intQuery(r,"limit",500,1,2000)`. Live: default → `findings:500` /
`summary.findings:7560`; `?limit=2000` → 2000. **5,560 findings unreachable at any limit.**
Teams triage 6.6% of fleet exposure.

### F-80 [MEDIUM] `PUT /api/settings/rca-window` persists but the RCA surfaces ignore it
7 cloud endpoints honor `tenantWindowHours`; **0 RCA endpoints do** —
`/api/correlations` hardcodes 24h (`correlations.go:131`), `/api/events/feed` hardcodes 24h
(`events_feed.go:182`), `/api/findings` has **no time window at all** (`flows.go:346-392`).
Tenant sets 168h; the settings page confirms `rca_window_hours: 168`; RCA still shows 24h.

### F-81 [MEDIUM] Other confirmed accept-and-ignore
- `POST /api/tenants` + `/api/onboard` silently drop `operator_restricted` — a **data-privacy
  control** (`identity_handlers.go:373-377`, `onboard.go:73-77`, error discarded); `SetRegion`
  five lines above handles it correctly. Never written at all.
- **Invalid `?as_tenant=` silently ignored** — live: `/api/devices?as_tenant=nonexistent` → 200
  with the full cross-tenant list (`tenancy.go:126,137`). The comment says "fail closed"; for a
  platform owner whose default view *is* global, ignoring the narrowing **fails open**.
- `?severity=` sent by the SPA to all three `/api/reliability/*` endpoints and never parsed
  (`timeintel_reliability.go:45-53`) → unfiltered MTTR/MTTD under a severity label.
- `/api/flows/by-type` drops the filter-bar params its siblings apply (`flows.go:300-319`).
- Saving any LDAP field wipes `ca_file` (`auth_config.go:163-179`) — **a real LDAPS trust
  downgrade**, silent. OIDC/TACACS do this right.
- `POST /api/discovery/refresh` → 202 but refreshes at most one of three sources
  (`discovery.go:219-224`, buffer-1 channel shared by all pollLoops).
- `POST /api/reports/run` sets `Status:"ok"` unconditionally even when `sent == 0`
  (`report_scheduler.go:303`).
- ~31 endpoints truncate silently; ~20 emit a `count` that is just `len(page)`.
- **ClickHouse already returns the true total and nobody reads it** — live
  `/api/flows/top?limit=20` → `rows:20` alongside `rows_before_limit_at_least: 23717`; zero
  consumers in backend **or** frontend. Cheapest fix in the report.

## Two cross-cutting root causes
1. **`DisallowUnknownFields()` appears ZERO times** across ~133 body-decode sites — every
   unknown or mis-cased key in every request body is silently discarded. This enables F-77,
   the LDAP `ca_file` wipe, and the `refreshToken` half of F-70.
   *Caveat before fixing:* ~10 read-only mirror keys (`client_secret_set`, `token_set`, …) are
   round-tripped by the SPA's `{...cfg}` spreads and would all start 400ing — strip those from
   the frontend first.
2. **The published OpenAPI spec documents ZERO query parameters** — `openapi.go` is 125 lines
   emitting method+summary only, no `parameters` key (`:95-108`). There is no discoverable
   contract, which is why so much of this section exists.

## Additional "does well" from this sweep
- **`/api/events/feed` (`events_feed.go:172`) is the reference implementation** — every enum
  400s on a bad value, keyset cursor, `next_cursor` only on full pages, and a
  **cursor-independent exact `total`**. Adopt this envelope everywhere.
- **Honest refusal when a store is Postgres-only** — constructor returns `nil`, handler
  refuses: `services.go:94-99`, `seams.go:159-165`, `incidents.go:183-190` (409, *"the incident
  system requires the Postgres backend"*). **This is exactly what F-76 should adopt — its 501
  guards already exist and are unreachable.**
- **12 runtime-config stores return `error` and propagate correctly** (LDAP, TACACS, OIDC,
  NetBox, discovery, token policy, export policy, ITSM, contact points, rules, WAN, locations).
- **Identity/RBAC roll back in-memory state on flush failure** (`users.go:190-193`,
  `apikeys.go:398-401`); **MFA is best-in-class** — `SetMFA` failure returns 500 every time
  (`mfa.go:74,103,126,236`); login 500s if the session can't persist (`auth.go:286-289`).
- **`copilotRequest.System` is ignored ON PURPOSE** (`copilot.go:161`, documented `:51-56`) —
  the OWASP LLM01 guard. **Must stay ignored.**
- **`proxyMetrics`' param allowlist is deliberate and correct** — it strips client-supplied
  `extra_filters[]`/`extra_label` so callers can't dodge tenant scoping. Fix the missing bounds,
  not the dropping.
- **`cloud_monitors.go:309,368`** rejects leftover `condition`/`threshold` with a **400** rather
  than dropping them — exemplary, and the model for the whole API.
- **Tenant isolation is broadly solid** — `principalTenant` + `requirePerm`, cross-tenant GET
  by id → 404 (never 403), tenant stamped from the token on create, PG RLS via `withTenant`.
  **The isolation posture is far healthier than the durability or pagination posture.**
- **No TODO/stub/no-op store methods exist** — every `mem*` implementation genuinely mutates
  and enforces tenant scoping. Volatile, not fake.

## Follow-up / unconfirmed
- `/api/alerts` (`main.go:1372`) and `/api/findings` (`flows.go:363`) use `claims, _ :=
  userFrom(...)` with **no `requirePerm` gate**, unlike `/api/devices`. Tenant filtering still
  applies. **UNCONFIRMED as an authz bypass — needs a low-privilege account.** F-72 is the
  confirmed instance of the pattern.
- **Exactly ONE assertion of `StatusInternalServerError` exists in the entire test suite.**
  This defect class is effectively untested — which is why F-77's mem-passes/pg-drops split
  went unnoticed.


---

# SECTION 15 — REVISED FINAL RANKING (supersedes §11 and §12)

§14 landed after §11 was written and changes the ordering materially. The API-durability class
is **larger and more customer-facing** than the ingest class that started this audit.

## Revised Top 10 by expected customer impact

| Rank | # | Sev | Title | Why here |
|---|---|-----|-------|----------|
| 1 | F-63 | Critical | 7 settings stores use relative kv keys → writes never land on a **default** install, 200 returned | Silent data loss on **every fresh customer install**, invisible in every dev env configured like this box. Includes the RCA revision register, which exists to prove non-mutation |
| 2 | F-20 | Critical | WebSocket `send on closed channel` panics the process | Closing a browser tab kills the API for all tenants. Only finding where ordinary traffic causes total outage |
| 3 | F-68 | Critical | 7 security settings displayed as enforced, enforced by nothing (0 read sites) | Customers will answer SOC2/PCI questionnaires from a settings page that is lying |
| 4 | F-64/F-65 | Critical | AI tenant-config PUT **deletes other tenants' provider keys**; wrapped-DEK store is a relative key | Cross-tenant destruction; and enabling `SEAL_PROVIDER=swtpm` on the file backend makes all sealed secrets permanently undecryptable at the next restart |
| 5 | F-16 | Critical | No alerting engine exists | Precondition for ~15 other fixes; the signals are already scraped |
| 6 | F-50 | Critical | Row-policy DDL is invalid SQL — 1,560 failures, 0 successes; 4 tests assert the broken string | Billing data has no DB-layer tenant policy; CI is green and would reject the fix |
| 7 | F-70/F-73 | High | Logout returns ok without revoking; `/api/audit` returns 200+empty on query failure | Both write **false compliance artifacts** — `SESSION_REVOKED` for a kill that didn't happen, "no privileged actions" for a failed query |
| 8 | F-66/F-67 | Critical | 22 MB unbounded outbox; `/tickets/links` cliff at 1000 → "no ticket filed" for real tickets | Self-DoS by any read-only user; operators file duplicate tickets. **27 rows from the cliff today** |
| 9 | F-69/F-76 | Critical/High | Device DELETE returns 204 and the device returns; cloud/NMS **credentials** stored in RAM behind 201 | Primary CRUD lies; a completed connector wizard with pasted cloud credentials evaporates on restart |
| 10 | F-34/F-35 | Critical | Python rejects the timestamps Vector normalizes; all 5 container OOM alerts match zero series | RCA ordering from receive time; the safety net that would catch the rest is dead |

**DEF-6 itself (F-01/F-02/F-09) is now resolved and verified — see §9.** It drops out of the
top 10 not because it was unimportant but because it is fixed; F-13/F-15 (the class it leaves
open) are folded into item 5.

## Revised "fix first" — 5 changes, roughly two weeks

1. **F-63 + F-65 — prefix the seven relative kv keys with `/data`, make `saveLocked` return
   `error`, propagate to 500.** Half a day. Stops silent settings loss on every default
   install and defuses the sealed-secrets landmine before anyone enables swtpm. **Do this
   first** — it is the cheapest Critical in the report by an order of magnitude.
2. **F-20 — stop closing `c.send` from the read pump; add `safego()` over all 33 goroutines.**
   Hours. The only availability-total finding reachable with no attacker.
3. **F-16 — stand up vmalert against the existing `rules.yaml`,** and in the same change fix
   the rules that can never fire (F-35 cAdvisor `name` label, F-39 wrong-lane selector). One
   day, unblocks ~15 findings. An alert matching zero series is worse than no alert: it reads
   as coverage.
4. **F-68 + F-70 + F-73 — close the false-compliance surfaces.** Either enforce the seven
   security settings or remove the controls; return 400 on logout decode failure and make the
   four revoke methods return `error`; add `error` to `auditRepo.List` and 502 on failure. A
   product that emits a `SESSION_REVOKED` audit event for a revocation that did not happen is
   a liability well beyond a bug.
5. **F-66/F-67/F-71/F-79/F-61 — one shared pagination envelope, copied from
   `events_feed.go:172`.** Keyset cursor, real `total`, `400` on out-of-range instead of
   `intQuery`'s silent fall-back to the default. Two to three days, fixes ~50 endpoints, and
   `rows_before_limit_at_least` is already in the ClickHouse responses for free.

**Then, structurally:** add `DisallowUnknownFields` behind a shared decode helper (strip the
~10 SPA mirror keys first), emit `parameters` in the OpenAPI generator so spec and handlers
cannot drift, and add **one** `StatusInternalServerError` test per write path — there is
currently exactly one in the entire suite, which is precisely why this class went unnoticed.

*(End of revised ranking — 2026-07-21)*
