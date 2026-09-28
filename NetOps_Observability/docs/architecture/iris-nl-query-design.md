<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Correlix -->

# Iris NL query — catalog, AST, validator, planner (design of record for N-C1…N-C5)

**Date:** 2026-09-26 · **Parent:** `iris-natural-language-platform.md` §4–§5 Phase C (tracker 337)
**Status:** design of record. Premises marked ✔ were re-verified against the code in the main session
before this document was committed; ⚠ items are open leads.

## 0. Premise corrections that shape the design

1. ✔ **No existing VM range helper returns a generic series.** `vmRange` keys series by
   `device\x1findex` (`metrics_forecast.go:193`), so BGP-peer and circuit series (no `index`) merge;
   `vmQueryRangeByIf` drops any series without `device`+`ifName` (`wan_circuits.go:525-528`) and reads
   the body with no size cap. → One new root helper `vmRangeSeries` (bounded read), added to the
   structural guard `vm_call_scope_guard_test.go`. `vmInstantScoped` is reusable as is.
2. ✔ **Circuits carry no provider/carrier attribute** (`wan/wan.go`). "Comcast circuits" resolves only
   through the N-C2 alias table or a seam's `ControlPlaneOwner` (`internal/seam/seam.go:79`).
3. ✔ **The circuit label `local_device` is the device NAME** (`wan_circuits.go:281`); gNMI series carry
   `device=<gnmic target name>`. Entity narrowing matches id OR name.
4. **Incidents are site-filterable today:** `corr_current.affected` is keyed JSON (`sites`, `devices`,
   `apps`), with a `has(JSONExtract(affected,…))` precedent (`cloud_signals.go:349`); incident class is
   `corr_current.seam_type` ∈ {DX, VPN, SDWAN, DIA, CLOUD_BACKBONE}.
5. ✔ **ClickHouse literal quoting was unsafe** (doubled `'` only) — fixed in commit b53ffca4
   (`sqlInList`, reports, servicecat now escape `\` and `'`). The planner uses the safe quoter only;
   `internal/chschema.chQuote` is exported as `chschema.Quote` for it.
6. **Change data is thin until N-D1/D2:** `ChangeQuery` has no `Until`/`Actor`/`Objects`
   (`internal/dem/experience/store.go:53`); config captures carry no actor. The AST expresses
   "who changed it"; the data arrives with Phase D.

⚠ **Lead (lab):** `regexAlternation` places `regexp.QuoteMeta` output (`\.`) inside a double-quoted
MetricsQL string (`metrics_query.go:141,156`). If MetricsQL rejects `\.`, a scoped tenant whose device
names contain dots gets query errors (fails closed, looks like an outage). The planner's own builder
escapes `\` → `\\` so it is unaffected; the existing path needs a lab check.

## 1. N-C1 Semantic Schema Catalog

**Storage:** one embedded JSON file `internal/nlquery/catalog/catalog.v1.json`, strict decode
(`DisallowUnknownFields`, same as `internal/vendorprofile/load.go`). JSON because it needs no dependency
(§6), and the Go drift tests, the offline harness and `/api/ai/schema/search` read the same artifact; its
SHA-256 is the `catalog_version` stamped in provenance. **Executable physical forms (MetricsQL
templates, CH column expressions) live in Go** (`plan/templates.go`) keyed by canonical name, so editing
the JSON can never inject query text; a test asserts Go-key-set == catalog-key-set.

**Types** (`catalog/types.go`): `Catalog{SchemaVersion, Entities, Metrics, Dimensions, Relationships}`;
`EntityType{Name, Description, IDPrefix, IDPattern, NameFields, Aliases, Resolver(closed: site_store |
discovery | label_pair | wan_projection | alias_table | corr_current | change_ledger), MetricLabels,
Sensitivity}`; `Metric{Name, Description, Unit, Aliases, EntityTypes, Backend, PhysicalMetrics,
Labels, Aggregations, DefaultAgg, Operators, ValueEnum, DefaultThreshold, BaselineOK, FanoutHint,
Scope("device_scoped" | "gated:N-B5"), Emitters[{File, Contains}], Quality, Examples}`;
`Dimension{Entity, Name, Type, Aliases, Enum, Operators, Filterable, Groupable, Display, Sensitivity}`;
`Relationship{From, To, Via(closed), Cardinality}`.

**Entities (v1):** site (`site:<slug>`, site store, own tenant; devices at a site via `sotSiteFor`, only
devices passing `canSeeDevice`) · device (`device:<id>`, VM matcher `device=~"<id>|<name>"`) · interface
(`interface:<device_id>/<ifName>`) · circuit (`circuit:<wan id>`, `wanProject(ctx, deviceVisibilityFor)`;
labels `circuit`, `local_device`(name), `local_if`) · bgp_peer (`bgp_peer:<device_id>/<ip>[@vrf]`, ip
via `netip.ParseAddr`) · provider (`provider:<slug>` → alias table / seam owner; else
`unmapped_provider`) · application · incident (`incident:<uuid>`) · change (`change:<id>`) ·
probe_target (`probe:<dst>`, gated).

**Metrics (v1, VictoriaMetrics):** if_in_bps / if_out_bps (`rate(device_if_*_octets[5m])*8`) ·
if_util_in_pct / if_util_out_pct (÷ `device_if_speed*1e6 > 0`) · if_oper_status {up:1, down:2,
lowerLayerDown:7} · if_flaps (`changes(device_if_oper_status[w])`) · if_in/out_errors, if_in/out_discards
(rates) · bgp_session_state {established:6} ("down" = ne 6) · bgp_flaps
(`increase(device_bgp_fsm_transitions[w])`) · bgp_prefixes_received (gNMI only, `afi_safi` label) ·
cpu_util_pct (`avg by (device)`) · mem_util_pct · circuit_loss_pct / circuit_latency_ms /
circuit_jitter_ms / circuit_qoe (**gated:N-B5**; latency/jitter ABSENT when recv=0 — gaps are not zero) ·
probe_rtt_ms / probe_loss_pct / probe_pdv_ms / probe_owd_ms (**gated**, labels `dst`,`probe` only).
**Alias collision rule:** an alias may be shared only across disjoint entity types; the compiler picks by
target type, else asks.

**Dimensions:** change — filterable `type` (enum == `change.go` constants == migration 0044 CHECK),
`class` (`wan` = NETWORK_CHANGE + ROUTE_CHANGE), `actor` (sensitivity personal), `object`,
`object_kind`, `site`, `app`, `seam`, `source`; time `event_at`; `summary/before/after` display-only
(before/after via the D3 diff API). incident — `state`, `verdict_tier`, `top_confidence`, `seam_class`
(sdwan→SDWAN; wan→SDWAN,VPN,DIA,DX; isp/internet→DIA; cloud→DX,CLOUD_BACKBONE), `owner`;
`affected.{sites,devices,apps}` as entity filters; default constraint `chaos_fixture='' AND
debug_excluded=0`, reported in `constraints_applied`.

**Relationships (≤ 2 hops):** site→device (sot_site) · device→interface / bgp_peer (label) ·
circuit→device/interface (wan_circuit_local/remote) · circuit→site (via the local device's `sotSiteFor`,
not `Endpoint.Site`) · provider→circuit (alias_table, seam_owner) · incident→site/device/app
(affected_json) · change→site/app/object (change_field).

**Drift test:** every `Emitter{File, Contains}` literally present (`collectors/profiles.go`,
`deployment/docker/gnmic/gnmic.yaml` + helm copy, `collectors/echo.go`, `collectors/stamp.go`); every
physical metric has an emitter; template set == catalog set and each template references only its
declared physical metrics; change enum == constants == CHECK; seam enum == engine keys. **B5 tripwire:**
for gated metrics, assert the emitter label string has no `device=`/`hostname=`/`source=` — when N-B5
lands the test goes red and forces the catalog flag flip in the same change.

## 2. N-C3 CorrelixQueryAST v1 (`internal/nlquery/ast`)

```go
type QueryType string // metric_series|metric_topk|metric_filter|compare_windows|change_list|incident_list|incident_explain
type AST struct {
  V int `json:"v"` /* ==1 */; Type QueryType `json:"query_type"`; Target string `json:"target"`
  Metric, Agg string; Refs []EntityRef `json:"entities"`; Filters []Filter; Predicate *Predicate
  Time TimeRange `json:"time_range"`; CompareTo *TimeRange; GroupBy []string; OrderBy []OrderKey
  Limit int; IncidentID string
}
type EntityRef struct{ Type, ID string }                  // resolved ids only, never names
type Filter    struct{ Field, Op string; Values []string } // eq|ne|in
type Predicate struct{ Op string; Value, Value2 float64 }  // gt|ge|lt|le|eq|ne|between|above_baseline|increased_by
type OrderKey  struct{ Field, Dir string }
type TimeRange struct{ Kind string /* absolute|relative|incident|incidents */; From, To *time.Time
  Last, Offset string /* ^[1-9][0-9]{0,3}[mhd]$ */; Anchor *Anchor }
type Anchor      struct{ IncidentID string; Incidents *IncidentSet; Before, After string }
type IncidentSet struct{ Filters []Filter; Refs []EntityRef; Time TimeRange; Max int }
```

Decode: ≤ 16 KiB, `DisallowUnknownFields`, a second `Decode` must be `io.EOF`. **No tenant field
exists**, so `tenant`/`tenant_id`/`as_tenant` are unknown-field rejects. Calendar words become absolute
times in the compiler using a validated IANA zone (default UTC), recorded in provenance.
**Not representable:** raw label names / SQL / MetricsQL / DSL; regex or free-text match; cross-metric
arithmetic; joins outside catalog relationships; writes; "all time". `flow_top`, `log_search` are
reserved → `unsupported_query_type` in v1.

## 3. Validator (`internal/nlquery/validate`)

Order: strict decode → field matrix per type → canonical metric (alias rejected WITH its canonical
suggestion) → metric applies to target, refs reachable ≤ 2 hops → ref id pattern + visibility (**missing
and foreign return the byte-identical `unknown_entity`**) → agg/op/value range/enum → filters (≤ 128
printable chars) → group/order fields → time sanity (from < to, end ≤ now+5m, anchors visible) → limits
→ sensitivity (restricted = display-only) → `scope_unavailable` for gated metrics on non-cross callers
(**never an empty result**, which would read "no loss").

| limit | value | on exceed |
|---|---|---|
| window: series/topk/filter/compare | 7 d | reject `window_too_large` |
| window: change_list/incident_list | 30 d | reject |
| window missing | metrics 1 h; changes/incidents 24 h | constrain + note |
| points per series | 360 (step from 30s/1m/5m/15m/1h grid) | auto |
| series returned | 50 series; topk ≤ 100 | `limitk(n+1)`, truncated |
| est. series (entities × FanoutHint) | 2 000 | reject `too_broad` |
| rows | changes 100/500; incidents 20/200 | clamp + note |
| refs / devices after site expansion | 20 / 500 | reject |
| compare windows | exactly 2, equal length, offset ≤ 30 d | reject |
| anchor incidents | ≤ 50; before/after ≤ 24 h | keep newest 50, truncated |
| group_by / order_by | ≤ 2 / ≤ 1 | reject |

Policy: a missing bound or oversized limit is constrained and reported; an oversized window is rejected
(shrinking it silently answers a different question). Error shape: `{"valid":false,"errors":[{"path",
"code","got"(≤64),"suggestions"[≤3]}],"constraints_applied":[{"path","from","to","reason"}]}`. Closed
codes: unknown_field, unknown_query_type, missing_field, forbidden_field_for_type, unknown_metric,
metric_not_applicable, invalid_entity_id, unknown_entity, relationship_not_allowed, unknown_dimension,
operator_not_allowed, aggregation_not_allowed, invalid_value, invalid_time, window_too_large, too_broad,
unsupported_query_type, scope_unavailable, unmapped_provider. Suggestions: Damerau–Levenshtein ≤
max(2, len/4) over canonical names + aliases, target-valid first, lexical tie-break.

## 4. N-C4 planner + adapters (`internal/nlquery/plan`, `internal/nlquery/mql`)

The planner never sees claims or a tenant. The root implements:

```go
type Scope interface {
  MetricRange(ctx, e mql.Expr, from, to time.Time, step time.Duration, maxSeries int) ([]Series, bool, error)
  MetricInstant(ctx, e mql.Expr, at time.Time, maxSeries int) ([]Sample, bool, error)
  Incidents(ctx, IncidentQuery) ([]IncidentRow, bool, error) // typed — no SQL crosses
  Incident(ctx, id string) (IncidentDetail, error)            // ErrNotFound: missing == foreign
  Changes(ctx, ChangeQuery) ([]ChangeRow, bool, error)
  Sites(ctx, ids []string) ([]SiteRef, error)                 // invisible ids omitted
  Devices(ctx, DeviceFilter) ([]DeviceRef, error)
  Circuits(ctx, CircuitFilter) ([]CircuitRef, error)
  Now() time.Time
}
```

Root: `nlqScope{s *server; claims jwtClaims}` via `s.nlqScopeFor(claims)` in `ai_troubleshoot_deps.go`
(no new root file). VM → `vmRangeSeries` / `vmInstantScoped` with `metricsScopeFiltersFor(claims)`.
Incidents → `correlationsListSQL` via `chSelect(ctx, chTenantScopeFor(claims), sql, "iris:nlquery")` +
`tenantIDExcludeCondFor` + enum IN-lists + `affected` `hasAny`, quoted with `chschema.Quote`. Incident
→ the N-B1 `RCAResult` seam. Changes → experience store `ListChanges(principalTenant)` + the config
capture arm via `aiRecentChanges` until N-D2, merged, deduped by id, `source` kept.

**MetricsQL builder:** `mql.Expr{s string}` with an unexported field — only the builder constructs one;
the root accepts only `mql.Expr`, so model text cannot reach VM. Labels from the catalog only
(`^[a-zA-Z_][a-zA-Z0-9_]*$`); values `regexp.QuoteMeta` then `\`→`\\`, `"`→`\"`.

Per type: metric_series → template(sel, step) in `limitk(max+1, …)`; site refs expand to
`device=~"ids|names"` (circuits: `local_device=~"names"`); site grouping in Go after fetch.
metric_topk → `topk(k, <agg>_over_time(expr[w]))` instant at window end. metric_filter →
`<agg>_over_time(expr[w]) > v`; `above_baseline` → `> quantile_over_time(0.95, expr[7d] offset w)`
(only when BaselineOK). compare_windows → two queries with `offset`; "changed most" →
`topk(k, abs(A − A offset d))`. change_list → Changes (anchor: Incidents ≤ 50, one bounded Changes per
window; each row `temporal` unless the engine's chain names it). incident_list/explain → Incidents /
Incident. **Gated metrics run only for cross-tenant principals until N-B5**; the planner never adds its
own scope matcher. `ResultSet{QueryID, ASTHash, CatalogVersion, Type, Window, Compare, Columns, Series
(catalog dims only — raw labels incl. circuit `tenant` stripped), Rows, Truncated, Constraints, Notes,
Provenance{Source, Entities, Evidence, ExecutedAt, DurationMs, Physical(json:"-", /explain for
admins)}}`.

## 5. Chokepoint guard (three layers)

1. **Import allowlist** (`internal/nlquery/import_guard_test.go`, `go/parser` over every non-test file):
   stdlib {context, embed, encoding/json, errors, fmt, math, sort, strconv, strings, time, unicode,
   crypto/sha256, encoding/hex, io} + nlquery's own packages only. `net`, `net/http`, `os`,
   `database/sql`, `chhttp`, `platformdb`, `oslog`, `ai` all fail → the planner cannot reach a backend.
2. **Root structural guard** (`nlquery_scope_guard_test.go`): `nlqScope` is the only root implementer;
   each VM method calls `metricsScopeFiltersFor(h.claims)`, each CH method `chTenantScopeFor` +
   `tenantIDExcludeCondFor`, changes take tenant from `principalTenant`; `vmRangeSeries` joins
   `vmReadHelpers`.
3. **Behaviour:** an httptest VM asserts every request carries `extra_filters[]`; a fake CH asserts the
   `tenant_scope` setting.

## 6. Deterministic grammar (N-C5)

Normalize (lower-case, `internal/asciifold`, number words) → tokenize → slot-fill from catalog aliases
(longest match), the C2 resolver, and a closed TIME grammar. No match → model fallback (structured
output against the AST JSON schema + schema-RAG + example-RAG, ≤ 2 repair rounds, same validator).

1 "what happened in this incident" → incident_explain · 2 "what happened (to|at|in) X [TIME]" →
incident_list(24 h, newest, 5) · 3 "who changed (it|that|the policy)" → change_list(anchor −30m/+10m,
refs=affected) · 4 "show exactly what (he|she|they) changed" → change_list(change ref, 1) as DIFF ·
5 "show everything ACTOR changed TIME" · 6 "what else did they change" (actor from state, exclude id) ·
7 "only CLASS changes" (add filter) · 8 "show the last N UNIT" (rewrite time) · 9 "which PROVIDER
circuits had (unusual|high) METRIC TIME" → metric_filter(above_baseline | DefaultThreshold) ·
10 "only SITE / PROVIDER" (replace ref of that type) · 11 "were there bgp flaps on those
circuits/devices" → metric_filter(bgp_flaps > 0, refs from prior result) · 12 "what changed DUR before
every CLASS incident TIME" → change_list(incidents anchor) · 13 "show SITE [wan] METRIC for the last
DUR" → metric_series · 14 "compare it with (yesterday|last week)" → compare_windows · 15 "which
interfaces changed most" → compare_windows topk |Δ| · 16 "top N ENTITY by METRIC [TIME]" →
metric_topk · 17 "(open|confirmed) incidents [at SITE] [TIME]" → incident_list.

**Model fallback (`internal/nlquery/modelc`, shipped 2026-09-27).** Runs ONLY on Unparsed, only with a
provider the caller may use (their BYO or the platform chain, strong tier, charged to the tenant's daily
budget; `IRIS_NLQ_MODEL_FALLBACK=false` disables it). Pre-checks spend no call: an unbound reference
("it", "that device"), a name-like word (identifier or capitalised) the caller's resolver did not find in
a question that cannot carry it as a list filter, or no catalog vocabulary at all. The prompt is the
server-constant system prompt + AST JSON schema, and one digest-tagged data block holding the question,
the entities the caller's resolver found in it (exact rungs only), lexically chosen catalog fragments and
≤ 4 examples (`examples.v1.json`, placeholder ids). The reply `{"ast", "unmatched_names"}` is decoded
strictly; a tenant/org key, an honest null or a non-empty `unmatched_names` ends the fallback. Guards
before the validator: every entity id must be one resolved for THIS question (foreign ≡ missing), every
resolved mention must narrow the query (no silent widening), string filter values and incident ids must
come from the question (or the incident on screen). ≤ 2 repair rounds with closed codes only; still
invalid ⇒ Unparsed. Accepted results carry `source: "model"`; the router's data arm discloses it.

## 7. Tests

Catalog (strict load, uniqueness, alias collisions, relationship endpoints, drift + B5 tripwire, Go⇔JSON
parity) · AST (tables, `FuzzDecodeAST` never panics / never accepts tenant-like fields, canonical
round-trip) · validator (one case per rule and code, deterministic suggestions, constrain vs reject) ·
mql (escaping table incl. `"}` break-out, golden MetricsQL per template, no non-catalog label) · planner
(fake Scope: site expansion, compare offsets, anchor fan-out bound, provenance) · **§3a
`nlquery_isolation_test.go`** (two orgs: foreign ref ≡ missing `unknown_entity`; site expansion never
includes another tenant's device even when its `Labels["site"]` has the same slug; `as_tenant` ignored;
restricted operator gets the sentinel scope; foreign `incident_explain` → not found; `tenant` in AST
JSON → decode error) · pgintegration for new `ChangeQuery` fields under RLS.

**Golden corpus:** canonical at `internal/nlquery/testdata/golden/<category>.json` (go-test reachable,
gate module self-contained); `tests/iris/nlquery/golden/` holds only a README pointer. Case format:
`{id, category, question, context{incident_id?, prior_ast?, tz}, expect{intent,
entities[{input,type,id,method}], ast, alternates[], result_semantics{kind, min_rows?,
must_include_refs[]}}, paraphrases[]}` against a fixed two-tenant fixture inventory.

## 8. Build order

1 `nlquery/catalog` · 2 `nlquery/ast` · 3 `nlquery/validate` · 4 `nlquery/mql` · 5 `nlquery/plan` +
import guard · 6 `dem/experience` ChangeQuery `Until/Actor/Objects` in SQL (+ pgintegration) ·
7 export `chschema.Quote` · 8 root wiring (`vmRangeSeries` + guard list, `nlqScope`, catalog load in
`newServer` — failure logs and disables NL routes, never aborts boot) · 9 root guard/isolation/adapter
tests · 10 golden seed, then N-C5 (grammar + routes). **Blocked slices:** circuit/provider flagship
(Parts 52, 63) on N-B5 + N-C2 aliases; Part 51 actor answers on N-D1/D2.

## 9. N-C7 Conversations (`internal/irisconvo`, `compile/refer.go`)

**Premise correction (found 2026-09-27).** Before N-C7, `it / that / there / those / them` were framing
vocabulary, so a first-turn "show cpu on it" or "cpu on that device" compiled to CPU on EVERY device —
a silent widening the coverage rule exists to prevent. The rule is now: **a referential phrase must be
BOUND or the question is Unparsed, naming the phrase.** Existential "there" ("are there any…", "were
there changes") is not a reference.

**State = references, never prose.** Per conversation the server holds: the last validated AST, entity
refs (most recent first: what the question named → what the answer returned → earlier turns), and —
redefined by each change list — the actors ("they") and change ids ("what ELSE"). Result-derived ids are
built as catalog canonical ids and kept only if they match the catalog's `id_pattern`; every query built
from state is validated again against the caller's CURRENT visibility (stale or foreign ref ≡
`unknown_entity`). The client supplies only the question: `prior_ast`, `state` or `tenant` in a message
body is a 400.

**Binding (deterministic).** Typed phrase ("that site", "the same router") → the most recent entity of
that type; untyped ("it") → the most recent entity of a type the question can use; plural ("those
circuits", "them") → every recent entity of the first match's type (≤ 10); "there" → a site; "they" in a
change question → the previous change list's actors. With an incident on screen, the change path's
pronouns bind to the incident (existing behaviour). Bound refs carry `resolution_method =
"conversation"`.

**Ownership & bounds.** One principal (`sub`) in one tenant scope (`principalTenant`; the Global view is
its own scope). Another tenant, a same-tenant colleague, and an `as_tenant` walk get the same 404 as a
never-existing id. 50 turns (409 past it), 50 conversations per owner (LRU), 7-day idle TTL. PG:
`iris_conversations` (0053, FORCE-RLS `tenant_iso` + owner filter, `FOR UPDATE` serialises the turn
cap); file mode: memory (working state — not imported at cutover).

**API.** `POST /api/ai/conversations` · `GET /api/ai/conversations/{id}` (turns only — state never
leaves the server) · `POST /api/ai/conversations/{id}/messages` → the compile answer + result + the
recorded turn. A "not found" answer is a 200 turn with `error`, never a 404 (which the client reads as
"conversation gone").

**Not yet (N-C7 remainder):** editable-chip → AST regeneration (with N-E3/E4), the Part 2 §50
multi-turn corpus scored like the golden corpus, and Part 2 §69's 14 routine questions end to end.

## 10. N-C8 Query capture + operator corrections (`internal/irisquerylog`)

**One record per compiled question** — from the `/api/ai/ask` data arm (`router`), `/api/ai/query/compile`
(`query_compile`), `/api/ai/query/execute` (`query_execute`, no question text) and conversation turns
(`conversation`, with the conversation id). Fields (Part 2 §22, as they exist here): tenant and principal
(from the token), timestamp, question (≤ 1000 runes), intent, outcome (`answered · compiled · clarify ·
declined · unparsed · invalid · error`), query type, AST hash, catalog version, validation error codes
(≤ 20), entities with their `resolution_method` (≤ 20), row/series COUNTS, duration. **Never** result rows,
series points or model prose. The response carries `query_log_id` so the answer can be corrected.

**Capture never fails the question.** A failed write is counted
(`netops_iris_query_capture_total{result="failed"}`), logged, and the answer goes out without an id. The
write is detached from the request's cancellation and bounded to 3 s.

**Corrections** (`POST /api/ai/queries/{id}/corrections {kind, note?, ast?}`): kind is closed
(`wrong_entity · wrong_metric · wrong_window · wrong_filter · other`); the note is ≤ 500 runes; the corrected
query is decoded strictly (`ast.Decode`: a smuggled tenant field is a 400) and validated against the caller's
CURRENT scope (a foreign entity is the same 422 as a missing one); the validated form and its hash are kept.
Only the asker may correct their own record — another tenant, a colleague (admins included) and an
`as_tenant` walk get the same 404 as an unknown id. ≤ 5 corrections per record (row lock in PG). They are
for OFFLINE evaluation: nothing reads them back into the compiler, resolver or any model.

**Reads** (`GET /api/ai/queries[?scope=tenant][&limit≤100]`): the caller's own; `scope=tenant` is the
caller's workspace for its admins (`administration:admin`), never another tenant.

**Bounds & storage.** 30-day retention and 5 000 records per tenant, both pruned on write inside the
tenant's transaction. PG: `iris_query_log` (0054, FORCE-RLS `tenant_iso`, principal filter on top); file
mode: memory (evaluation telemetry, not a system of record).

**UI.** "That's not what I meant" under an Iris data answer and under Try-a-question; the rewording box is
compiled by the server and attached only if it validates. "Recent questions" is step 4 of the vocabulary
panel.

**Not yet:** chip edits as corrections (needs N-C7's chip → AST regeneration); an offline export of
corrections into the N-C6 harness.
