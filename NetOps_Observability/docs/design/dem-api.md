# DEM API — the Digital Experience aggregation surface

Status: **as-built, 2026-09-05.** Source: `src/backend/internal/dem/experience/http.go`,
the route literals in `src/backend/main.go`, and the entries under the
*Digital Experience* tag in `src/backend/internal/openapi/openapi.go`.
Field names below are the `json:` tags. `openapi_test.go` pins the route
constants, the registered literals and the published document together, so a
documented route that 404s and an undocumented route that works are both build
failures.

The catalogue routes beneath this layer (`/api/dem/targets*` and
`/api/dem/experience`) are unchanged by this slice and are documented in
[`DEM_PLUMBING_2026-09-05.md`](DEM_PLUMBING_2026-09-05.md).

---

## 1. The eight routes

| Method | Path | Gate |
|---|---|---|
| `GET` | `/api/dem/overview` | `infrastructure:read` |
| `GET` | `/api/dem/incidents` | `infrastructure:read` |
| `GET` | `/api/dem/incidents/{id}` | `infrastructure:read` |
| `GET` | `/api/dem/incidents/{id}/evidence` | `infrastructure:read` |
| `GET` | `/api/dem/incidents/{id}/timeline` | `infrastructure:read` |
| `GET` | `/api/dem/incidents/{id}/path` | `infrastructure:read` |
| `GET` / `POST` | `/api/dem/journeys` | `infrastructure:read` / `infrastructure:write` |
| `GET` / `PUT` / `DELETE` | `/api/dem/journeys/{id}` | read / write / write |
| `GET` | `/api/dem/synthetics/coverage` | `infrastructure:read` |
| `GET` / `POST` | `/api/dem/changes` | `infrastructure:read` / `infrastructure:write` |
| `GET` | `/api/dem/data-health` | `infrastructure:read` |

Why `infrastructure` and not a platform gate is answered in
[`dem-privacy.md`](dem-privacy.md) §6.1.

---

## 2. Rules that apply to every route

**Tenant scope.** Each request resolves to exactly one concrete tenant. A
caller who resolves to none, to `*`, or who is a cross-tenant principal is
refused with `400`:

```
select a tenant to see its digital experience
(it is per-tenant data; cross-tenant access is refused)
```

**Query parameters are closed.** Every handler calls
`httppage.RejectUnknownQuery` with an explicit allow-list. A parameter that is
not on it is a `400` naming the offender. `as_tenant`, `limit`, `offset` and
`envelope` are always allowed by the platform's paging layer. A misspelt
parameter must fail loudly rather than be swallowed and answered `200` with the
whole table.

**Window.** `?window=` accepts `1h` (default when absent) or `24h`, and nothing
else. `dem.ParseWindow` refuses anything else rather than silently substituting
a default; an operator-supplied range is an unbounded query against a shared
time-series database.

**Methods.** A wrong method gets `405` with an `Allow` header naming what the
route serves.

**Write bodies.** Bounded by `http.MaxBytesReader` at 64 KiB and decoded with
`DisallowUnknownFields`. An unknown field is `400 invalid <thing> payload`. The
write wire types carry **no tenant field**, so a tenant in the body cannot be
expressed.

**404, never 403.** An id that belongs to another tenant, an id that does not
exist, and an id whose shape is wrong are all `404` and indistinguishable. Shape
is checked before the store is touched, so a path-traversal-shaped id never
reaches a key lookup. An unparseable incident id is a `404` rather than a `400`,
because a `400` would confirm that a well-formed id from another tenant is "the
right shape".

**Unbuilt surface.** If the module failed to construct, every handler nil-checks
its receiver and answers `404` rather than degrading into an unscoped read.

---

## 3. Honest not-measured shapes

Nothing on this surface returns a fabricated number. Every aggregate carries
`measured`, and when it is false a **stable** `reason` code plus a `note` or
`detail` sentence says why. The codes are shared with `internal/dem` so one word
means one thing across both layers.

| Reason | Where it comes from | The sentence |
|---|---|---|
| `feature_off` | `FEATURE_DEM` is off | "Digital experience collection is off. Nothing on this screen was measured; an empty table here does not mean everything is well." |
| `no_targets` | No target and no journey declared | "No experience target and no journey is declared for this tenant, so nothing is being measured." |
| `query_failed` | The metrics store did not answer | "The metrics store did not answer, so no experience score is shown. This is not a healthy result." |
| `no_samples` | The window holds no measurement | "No measurement reached this window." |
| `no_score_policy` | No weights for this application class | "no scoring policy is loaded for this application class, so no score can be published" |
| `below_evidence_minimum` | Fewer than two dimensions measured | "fewer than 2 dimensions were measured in this window, so no experience score is published — this is an absent result, not a good or a bad one" |
| `no_dimensions_measured` | Nothing produced this dimension | "nothing produced this dimension in this window" |
| `journey_not_measured` | No required step of a journey is measured | "no required step of this journey is measured, so it has no success rate — this is an absent result, not a healthy one" |
| `step_not_bound` | A step has no `target_id` | "this step is declared but bound to no measurement, so nothing observes it" |
| `step_no_measurement` | The bound target reported nothing | "the target bound to this step reported nothing in this window" |
| `no_journeys` | The tenant has declared none | "No journey is declared for this tenant. Correlix cannot report on a workflow nobody described, and it will not guess one." |
| `paused` | The target is paused | "this target is paused, so nothing was measured in this window" |

A `query_failed` response is a `200` with `measured: false`, not a `500`. The
surfaces still render; they render the absence. `dem_experience_query_errors_total`
is incremented and the failure is logged.

---

## 4. Pagination

Two routes page: `GET /api/dem/incidents` and `GET /api/dem/changes`. Both use
`internal/httppage`.

| Parameter | Default | Ceiling |
|---|---|---|
| `limit` | 100 | 500 |
| `offset` | 0 | `httppage.MaxOffset` |
| `envelope` | false | strict `1/0/true/false` |

A malformed or out-of-range value is a `400` naming the parameter and its legal
range. Every paged response carries both headers and body fields:

| Header | Body field | Meaning |
|---|---|---|
| `X-Total-Count` | `total` | The true number of rows matching the filter, not the number returned. |
| `X-Page-Limit` | `limit` | The limit actually applied. |
| `X-Page-Offset` | `offset` | The offset actually applied. |
| `X-Page-Complete` | `complete` | `true` only when this response **is** the whole matching set. |
| `X-Page-Max-Limit` | — | The server-side ceiling, so a client can size its walk. |

---

## 5. `GET /api/dem/overview`

Query: `window`.

```jsonc
{
  "window": "1h",
  "enabled": true,
  "measured": true,
  "reason": "",                       // stable code when measured is false
  "note": "",                         // the operator sentence
  "score":  { /* ExperienceScore */ },
  "journeys": [ /* JourneyHealth */ ],
  "incidents": [ /* IncidentSummary */ ],
  "changes": [ /* ChangeEvent */ ],
  "data_health": { /* DataHealth */ },
  "hotspots": [ /* Hotspot */ ],
  "business_impact": 177.6,           // absent unless a journey declared a value
  "business_impact_currency": "USD",
  "business_impact_note": "",         // set only when a total was WITHHELD (§5.3)
  "ai_investigator": { "available": false, "reason": "…" },
  "generated_at": "2026-09-05T12:00:00Z",
  "policy_version": 1
}
```

`journeys`, `incidents` and `changes` are always arrays, never `null`.

`score` is an `ExperienceScore` (every field in
[`dem-domain-model.md`](dem-domain-model.md) §13.2). Two of its fields matter to
a client and are easy to misread:

- **`aggregation` reads `worst_weighted`.** That is the arithmetic, not a label:
  each dimension's per-subject points are folded with the worst subject carrying
  0.4 of the weight, so one dead target cannot disappear into an average. The
  constants `worst_of` and `p95_of` also exist in the vocabulary and are the
  **per-observer** modes; nothing emits them today, because a subject measured
  from one vantage has no second observer to take a worst or a percentile of.
  Whatever the field says, the UI says it too.
- **`policy_version` and `policy_name`** travel with every score, and the same
  `policy_version` appears at the top level of this response and of
  `GET /api/dem/data-health`. A score whose weight set cannot be reconstructed is
  not auditable.

### 5.1 `Hotspot`

`dimension` · `key` · `band` · `measured` · `reason` · `score` · `subjects` ·
`failing`.

Seven dimensions are always present, and five of them are always
`measured: false`. **The absence is rendered rather than omitted**, because a
missing breakdown is invisible and a present one that says why is not:

| Dimension | State today |
|---|---|
| `app` | Measured, from the mean journey success per application. `band` from the 70/30 bands. |
| `site` | Present, `not_measured`: "ranked by open experience incidents; a per-site score needs a prober at that site". `subjects` and `failing` are both the count of open incidents touching that site, not a journey count. |
| `isp`, `device`, `browser`, `version`, `network` | Present, `not_measured`: "this breakdown needs first-party real-user telemetry, which is not collected yet". |

### 5.2 Business impact roll-up

`RollUpBusinessImpact` is a pure function over the window's incidents with three
outcomes, and only one of them produces a number:

| Case | `business_impact` | `business_impact_currency` | `business_impact_note` |
|---|---|---|---|
| One currency declared | The rounded total | That currency | absent |
| **More than one currency** | **absent** | absent | "Business impact is declared in more than one currency in this window, so no single total is shown. The per-incident figures are correct." |
| No incident declared a value | absent | absent | absent |

Adding dollars to euros is not a total. The per-incident figures stay correct
and stay on screen; a single number nobody can act on would be worse than none.
The note is what stops the withheld total reading as "no business impact", so a
client must render it whenever it is present.

### 5.3 `AIAvailability`

`available` · `reason`. When the investigator is off, the reason is the full
sentence, so the UI renders a **disabled panel with an explanation** rather than
hiding a feature: a hidden feature is indistinguishable from a missing one.

---

## 6. `GET /api/dem/incidents`

Query: `window`, `severity`, `app`, `journey`, plus paging. An unknown severity
is a `400` naming the five legal values.

```jsonc
{
  "window": "1h", "measured": true, "reason": "", "note": "",
  "incidents": [ /* IncidentSummary */ ],
  "total": 1, "returned": 1, "limit": 100, "offset": 0, "complete": true
}
```

### 6.1 `IncidentSummary`

| Field | Note |
|---|---|
| `id`, `title`, `severity`, `status` | `status` is `open` in this slice. |
| `app`, `journey` | The first affected application and journey. |
| `detected_at`, `first_impact_at`, `duration_sec` | Duration is measured from first impact and floored at zero. |
| `leading_cause`, `leading_cause_class`, `likely_layer` | From the leading hypothesis. `likely_layer` is `LayerFor(cause_class)`: `device`, `LAN`, `WAN`, `ISP`, `DNS`, `cloud edge`, `application`, `network`, `measurement`. |
| `confidence`, `verdict_tier` | `0` / `undetermined` when there is no leading hypothesis. |
| `owner`, `seam` | Empty is honest and renders as "owner not determined". |
| `journey_success_pct`, `business_impact`, `currency` | Absent when not measured or not declared. |
| `impact_not_measured` | The list of impact dimensions nothing produced. **The UI renders this instead of a zero.** |
| `evidence_count`, `contradiction_count`, `missing_evidence_count` | Supporting, contradicting and missing. The second and third are as prominent as the first by design. |

---

## 7. `GET /api/dem/incidents/{id}` and its three sub-resources

`{id}` must match `exp-` plus 20 hex characters. Anything else is `404`. The
only accepted sub-paths are `evidence`, `timeline` and `path`; any other suffix
is `404`.

### 7.1 The incident itself

```jsonc
{
  "window": "1h",
  "incident": { /* ExperienceIncident — every field in dem-domain-model.md §7 */ },
  "ai_investigator": { "available": false, "reason": "…" },
  "evidence_packet_available": true
}
```

`evidence_packet_available` is false when every evidence item is above the data
class that may leave the platform, so no model briefing could be built at all.
That is a real state, and the UI must render it as "the investigator cannot be
used on this incident" rather than as a broken button.

### 7.2 `…/evidence`

```jsonc
{
  "incident_id": "exp-…",
  "evidence":         [ /* EvidenceItem, supporting AND contradicting */ ],
  "missing_evidence": [ /* MissingEvidence */ ],
  "hypotheses":       [ /* Hypothesis, graded and ranked */ ]
}
```

The three lists together are what the Evidence tab's ALL / SUPPORTING /
CONTRADICTING / MISSING filter operates on. `missing_evidence` is a **list of
records**, not an absence, and each carries the modality class it would have
contributed.

### 7.3 `…/timeline`

```jsonc
{
  "incident_id": "exp-…",
  "timeline": [ /* TimelineEntry — at, kind, summary, source, ref, observation */ ],
  "changes":  [ /* ChangeRelevance — change, score, reasons, precedes_impact,
                   touches_affected_cohort */ ]
}
```

Every timeline entry carries `observation`. An inferred entry on a timeline that
looks measured is how a story becomes a fact, and the acceptance test refuses an
entry without it.

### 7.4 `…/path` — a reference, not a path

```jsonc
{
  "incident_id": "exp-…",
  "path_observation_id": "obs-91827",
  "measured": true,
  "note": "fetch the ordered spine from the service path graph API using this observation id; it is the single source of hop order"
}
```

and when nothing was observed:

```jsonc
{
  "incident_id": "exp-…",
  "path_observation_id": "",
  "measured": false,
  "reason": "no forward path was observed for this incident's subject in this window, so there is no path to render — this is an absent measurement, not a clean path"
}
```

**This route never returns hops.** DEM references a `PathObservation` by id and
never copies it. The ordered spine is served by the service path graph API,
which stays the single source of hop order, and whose renderer contract forbids
the UI from re-laying it out. See
[`service-path-graph-contract.md`](service-path-graph-contract.md) §7.

---

## 8. Journeys

### 8.1 `GET /api/dem/journeys`

Query: `window`.

```jsonc
{
  "window": "1h", "measured": true, "reason": "", "note": "",
  "journeys": [ /* JourneyDefinition */ ],
  "health":   [ /* JourneyHealth, sorted failing-first */ ],
  "count": 2, "limit": 100
}
```

With nothing declared, `reason` is `no_journeys` and `note` is "No journey is
declared for this tenant. Correlix cannot report on a workflow nobody described,
and it will not guess one."

### 8.2 `POST /api/dem/journeys`

Body — note the absence of any tenant field:

```jsonc
{
  "name": "Checkout",
  "app": "checkout",
  "description": "",
  "business_importance": "critical",
  "business_value_per_success": 40,
  "currency": "USD",
  "entry_step_id": "browse",
  "steps": [
    { "id": "browse", "label": "Browse", "next": ["cart"], "target_id": "dem-…" },
    { "id": "cart",   "label": "Cart",   "next": ["pay", "browse"], "target_id": "dem-…" },
    { "id": "pay",    "label": "Pay",    "terminal_success": true,  "target_id": "dem-…" }
  ],
  "slo": { "success_pct": 99, "window": "1h" }
}
```

`201` with the stored definition, including its minted `jny-…` id and
`version: 1`. Validation failures are `400` with the specific reason — a
dangling edge, a duplicate step id, a step that is both terminals, no success
terminal, an entry step that is not a step, a value with no currency, a fan-out
above 8, or more than 40 steps. `ErrFull` at 100 journeys per tenant is also a
`400`.

Note the `cart` step's `next` includes `browse`: **loops are legal** and are not
flattened into a line.

### 8.3 `GET /api/dem/journeys/{id}`

```jsonc
{
  "journey": { /* JourneyDefinition */ },
  "window": "1h",
  "health": { /* JourneyHealth, or an honest not-measured shell */ }
}
```

When the journey has no measured required step in the window, `health` is a
shell carrying `reason: "journey_not_measured"` and the sentence, never an
omitted key.

### 8.4 `PUT` / `DELETE /api/dem/journeys/{id}`

`PUT` takes the same body as `POST` and **increments `version`**;
`tenant_id`, `id`, `created_at` and `created_by` are preserved from the stored
record and cannot be changed. An observation recorded against the old version is
therefore never silently re-attributed.

`DELETE` returns `{"deleted": "jny-…"}`. The measurements the journey's steps
were bound to are unaffected.

---

## 9. `GET /api/dem/synthetics/coverage`

Query: `window`.

```jsonc
{
  "window": "1h",
  "coverage": {
    "window": "1h",
    "actions": [ /* ActionCoverage, worst-covered first */ ],
    "critical_actions": 3, "protected_actions": 2, "untested_actions": 1,
    "thin_actions": 1, "broken_tests": 0, "flaky_tests": 0,
    "coverage_pct": 66.67,
    "detail": "2 actions are protected out of 3 declared actions."
  },
  "reliability_note": "Per-check reliability needs per-RUN records; the prober publishes aggregate series today, so every check's reliability reads as unknown rather than as trustworthy. A check nobody has graded is not a check that passed."
}
```

Two honest shapes matter here:

- **`coverage_pct` is absent when nothing is declared**, and `detail` reads
  "No journey step is declared, so there is nothing to have coverage of. This is
  not 100% coverage."
- **Every `reliability_grade` is `unknown` today**, and `reliability_note` says
  why in the response body rather than in a footnote somewhere else.

The definitions are built from the catalogue: each journey step's bound target
becomes one `SyntheticDefinition` with the vantage `prober@<site>`. There is no
second registry, so a step cannot be "covered" by a check the prober never runs.

---

## 10. Changes

### 10.1 `GET /api/dem/changes`

Query: `window`, `type`, `app`, `site`, plus paging. An unknown `type` is a
`400` naming it.

```jsonc
{
  "window": "1h",
  "changes": [ /* ChangeEvent, newest first */ ],
  "total": 1, "returned": 1, "limit": 100, "offset": 0, "complete": true,
  "note": ""
}
```

When the window is empty the `note` is the one sentence a change feed most needs:

> No change was recorded in this window. That may be correct — a quiet estate
> reports nothing — but it is not proof that nothing changed: only the producers
> that are wired report here.

The lookback is `window + 90 min`, so a change just before the window opened is
still a candidate cause and one from last week is not.

### 10.2 `POST /api/dem/changes`

Body — again with no tenant field:

```jsonc
{
  "type": "APPLICATION_DEPLOY",
  "actor": "ci",
  "object": "checkout-api",
  "object_kind": "service",
  "summary": "checkout-api v42 deployed to production",
  "before": "v41", "after": "v42",
  "release_id": "v42", "rollback_ref": "v41",
  "site": "", "app": "checkout", "seam": "",
  "cohort": { "app_version": "v42" },
  "event_at": "2026-09-05T11:28:00Z",
  "source": "configdrift",
  "source_object": "pipeline-9912"
}
```

`201` with the stored event, including its minted `chg-…` id. Rules:

- `event_at` is optional and defaults to now. A non-RFC3339 value is a `400`.
- `source` defaults to `manual` and must be one of the declared sources.
- `actor` defaults to the authenticated subject; `producer` on the provenance is
  **always** the authenticated subject regardless of the body.
- `observation` is stamped `observed` and `data_class` `customer_metadata`.
- **The insert is idempotent.** A repeated id returns the already-recorded event
  unchanged: a change is an immutable fact, and a replayed producer must not
  rewrite history.

---

## 11. `GET /api/dem/data-health`

Query: `window`.

```jsonc
{
  "window": "1h",
  "enabled": true,
  "policy_version": 1,
  "data_health": {
    "window": "1h",
    "sources": [ /* SourceHealth, problems first */ ],
    "anchor_sources_flowing": 1,
    "can_confirm": false,
    "explanation": "Only 1 independent kind of instrument is reporting. Correlix can suspect a cause but cannot confirm one: confirmation requires two independent observations, and that is a property of the evidence, not of the analysis."
  }
}
```

All ten sources on the ladder are always listed —
`synthetic`, `pathgraph`, `configdrift`, `cloud`, `bgp`, `flow`, `sdwan`,
`wireless`, `rum`, `agent` — including the ones with no producer, which report
`off` with "no producer for this source is deployed yet". A source absent from
the list is a source nobody notices is missing.

`can_confirm` is the single field that tells an operator why every incident
reads `suspected`. It is `anchor_sources_flowing >= 2`, and it is `false` on
every deployment today.

---

## 12. Worked example — the acceptance scenario on the wire

Abridged, with the values computed in
[`dem-evidence-confidence.md`](dem-evidence-confidence.md) §10.

`GET /api/dem/incidents?window=1h`:

```jsonc
{
  "window": "1h", "measured": true,
  "incidents": [{
    "id": "exp-…", "title": "Checkout journey degraded",
    "severity": "critical", "status": "open",
    "app": "checkout", "journey": "jny-…",
    "detected_at": "2026-09-05T12:00:00Z",
    "first_impact_at": "2026-09-05T11:32:00Z",
    "duration_sec": 1680,
    "leading_cause": "hop 7 (AS3356, ISP-A transit) lost 8% of probes and added 180 ms",
    "leading_cause_class": "transit_degradation",
    "likely_layer": "ISP",
    "confidence": 0.8, "verdict_tier": "confirmed",
    "owner": "ISP A / carrier", "seam": "wan-isp-a",
    "journey_success_pct": 91.6,
    "business_impact": 177.6, "currency": "USD",
    "impact_not_measured": [
      "affected users and sessions — they can only be counted from first-party real-user telemetry, which is not collected yet",
      "error rate — no real-user or application error telemetry reached this window"
    ],
    "evidence_count": 7, "contradiction_count": 2, "missing_evidence_count": 2
  }],
  "total": 1, "returned": 1, "limit": 100, "offset": 0, "complete": true
}
```

`GET /api/dem/incidents/{id}/evidence` — the two hypotheses, abridged to the
graded fields:

```jsonc
{
  "incident_id": "exp-…",
  "hypotheses": [
    {
      "id": "hyp-…", "cause_class": "transit_degradation",
      "cause_entity": "AS3356 (ISP-A transit)",
      "seam": "wan-isp-a", "owner": "ISP A / carrier",
      "state": "CONFIRMED", "verdict_tier": "confirmed", "confidence": 0.8,
      "confidence_factors": [
        { "name": "support",       "value": 1,    "reason": "as much fresh, reliable observation as this measure counts" },
        { "name": "independence",  "value": 1,    "reason": "independent observations from active_probe, control_plane and real_user across 5 observers" },
        { "name": "alignment",     "value": 1,    "reason": "share of supporting evidence that falls inside the incident window (a change counts only when it precedes first impact)" },
        { "name": "specificity",   "value": 1,    "reason": "names a concrete cause and the seam that owns it" },
        { "name": "contradiction", "value": 1,    "reason": "nothing measured contradicts it" },
        { "name": "completeness",  "value": 0.8,  "reason": "expected but absent: agent and flow — missing telemetry is not agreement" }
      ],
      "independence": {
        "anchor_modalities": ["active_probe", "control_plane", "real_user"],
        "observers": ["prober@branch-1", "prober@branch-2", "prober@branch-3", "ripestat", "rum:browser"],
        "independent_pair": ["rum-checkout-errors", "syn-branch-1"]
      },
      "supporting_evidence_ids": ["bgp-as3356", "path-isp-a", "rum-checkout-errors", "syn-branch-1", "syn-branch-2", "syn-branch-3"],
      "gate_reasons": null
    },
    {
      "id": "hyp-…", "cause_class": "application_regression",
      "cause_entity": "checkout-api", "owner": "application team",
      "state": "REJECTED", "verdict_tier": "undetermined", "confidence": 0.26,
      "contradicting_evidence_ids": ["cohort-v42-healthy", "svc-checkout-api"],
      "gate_reasons": ["a measured observation refutes it outright, so it is rejected regardless of what else points at it"]
    }
  ],
  "missing_evidence": [
    { "source": "flow",  "independence_group": "passive_flow",     "reason": "not_configured", "detail": "…" },
    { "source": "agent", "independence_group": "device_telemetry", "reason": "not_configured", "detail": "…" }
  ]
}
```

The rejected hypothesis is returned, ranked last, with what refuted it named.
"We considered the deploy and ruled it out" is one of the most valuable things
the product can say, and it is not something a client has to reconstruct.

---

## 13. Owner Phase D routes that were NOT built, and why

The owner's Phase D lists a wider surface. Seven of its routes are absent from
this slice. Each omission is a decision recorded in
[`dem-repository-assessment.md`](dem-repository-assessment.md) §6, not an
oversight.

| Route | Why it was not built |
|---|---|
| `GET /api/dem/sessions` | `ExperienceSession` is a **contract only**. Nothing produces a session: there is no first-party RUM snippet, no desktop agent and no browser runner. A route returning an empty list would be indistinguishable from a route returning "no sessions were bad", which is the opposite claim. (Assessment §6.2.) |
| `GET /api/dem/sessions/{id}` | Same. There is nothing to fetch by id. |
| `GET /api/dem/journeys/{id}/observations` | `JourneyObservation` is a contract only. A per-traversal record needs either per-run synthetic records (`SyntheticRun`, which nothing writes) or first-party RUM. `ComputeJourneyHealth` gives real, honest journey health today from the bound targets' measured windows; a traversal list would have to be fabricated. (Assessment §3 G6.) |
| `POST /api/dem/events` | The RUM ingest lane. Wiring it end to end needs a Kafka topic, a Vector route, a ClickHouse table in **two** places and a row policy — and no producer exists. Phase P is explicit that infrastructure is added when there is a requirement, not before. The shapes, their validation, the pseudonymous-user discipline and the `EventSink` seam ship now so the lane can be added without changing them. (Assessment §6.2; the exact cost is in [`dem-architecture.md`](dem-architecture.md) §5.3.) |
| `POST /api/dem/business-events` | Same lane, same reason. `BusinessEvent` is validated and ready; nothing emits one. |
| `POST /api/dem/synthetic-runs` | `SyntheticRun` needs a runner that records per-run outcomes. The prober publishes aggregate series. Accepting runs from an unauthenticated or unmodelled producer would let a caller manufacture the reliability grade that gates incident severity. (Assessment §3 G6.) |
| `POST /api/dem/ai/investigate` | The owner's own instruction is that this route is added **only after the evidence contract exists**. It now does, and `BuildPacket` / `ValidateInvestigation` are the two halves of the contract on either side of the provider call — but the provider call itself lives in `ai/*` and was not built in this slice. (Assessment §3 G7.) |
| `GET /api/dem/synthetics` (the bare list) | The catalogue already serves it as `GET /api/dem/targets`. A second list route over the same rows would be two names for one thing, and the coverage model — not a list of tests — is what Phase H actually asks for. |

Two further Phase D expectations were narrowed rather than met:

- **Filters.** Phase D asks every list route to filter on environment,
  geography, browser/device, ISP/network, release/version and feature flag. Only
  `window`, `severity`, `app` and `journey` (incidents) and `window`, `type`,
  `app`, `site` (changes) are implemented, and every other parameter is
  **refused**. A filter over a dimension nothing produces is a filter that
  always returns nothing, and silently accepting it would be worse than
  refusing it.
- **"Do not load all rows into memory."** Honoured at the store: the Postgres
  change query pushes its time predicate and `LIMIT` into SQL, and both paging
  routes go through `httppage`. The incident list is derived from an assembly
  bounded by the 500-target and 100-journey ceilings, so the working set is
  bounded by the catalogue rather than by the caller.

---

## Related

- [`dem-domain-model.md`](dem-domain-model.md) — every field these responses carry.
- [`dem-evidence-confidence.md`](dem-evidence-confidence.md) — what `confidence`, `verdict_tier` and `gate_reasons` mean.
- [`dem-privacy.md`](dem-privacy.md) — the gate, the isolation posture and the 404 rule.
- [`dem-ui.md`](dem-ui.md) — what a client must do with these shapes.
- [`DEM_PLUMBING_2026-09-05.md`](DEM_PLUMBING_2026-09-05.md) — the catalogue and per-target score routes beneath.
