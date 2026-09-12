# DEM domain model — every canonical object, its fields and its invariants

Status: **as-built, 2026-09-05.** Source: `src/backend/internal/dem/experience/*.go`
and `src/backend/internal/platformdb/migrations/0044_dem_experience.sql`. Field
names are the `json:` tags, because those are what the API and the SPA see.

Authority for the design is `docs/design/DEM_2026-09-05.md` §M and the owner's
Phase C. Where the code went further or elsewhere, the code is documented here
and the difference is recorded in
[`dem-architecture.md`](dem-architecture.md) §9.

Every object in this package carries a `Provenance` block, is validated at the
boundary, and is bounded. Validation **refuses**; it does not truncate. The one
exception is `clip()`, which bounds a string that is already trusted to exist
but not to be small, without splitting a UTF-8 rune.

---

## 0. Reading this document

Three properties are stated for every object and they are not the same
question.

| Property | What it means |
|---|---|
| **Observed / inferred** | How the fact was arrived at. Carried per object in `provenance.observation` as one of `observed`, `inferred`, `unknown`, `simulated`. An explicit enum rather than a boolean, so "we did not look" is expressible and cannot be coerced into "inferred". |
| **Immutable** | The object is a record of something that happened. Re-reporting it does not rewrite it. |
| **Versioned** | The object has a `version` that increments on change, so a later edit never silently rewrites what an earlier record referred to. |

---

## 1. Provenance — on every fact

`provenance.go`. The block every object embeds, written once so no future
object can quietly omit it.

| Field | Type | Rule |
|---|---|---|
| `source` | string | The producing subsystem. Closed vocabulary (§1.1). Validation refuses an unknown value. |
| `source_object` | string, ≤128 B | The upstream object's own id. This is how a path-degradation item carries the immutable `PathObservation` id. |
| `producer` | string, ≤128 B | The concrete producer instance: a prober id, a collector id. |
| `event_at` | RFC3339 | When the thing being described **happened**. Required — a fact with no time cannot be correlated. |
| `observed_at` | RFC3339 | When Correlix **learned** of it. Defaults to `event_at` when absent. The two are different and the difference is diagnostic. |
| `observation` | enum | `observed` \| `inferred` \| `unknown` \| `simulated`. Required. |
| `data_class` | enum | One of the eight classes in [`dem-privacy.md`](dem-privacy.md) §1. Required. |
| `schema_name` | string | Always `correlix.dem.experience`. Stamped by `Normalize`, never accepted from a caller. |
| `schema_version` | int | Always `1`. Bumping it is a deliberate, documented act. |
| `external_schema` / `external_version` | string, ≤128 B | The foreign schema an adapter translated **from** — OpenTelemetry, a vendor API. An upstream convention change is then a diff in these two fields rather than a silent change in meaning. |

`Age(now)` is `now − observed_at`, floored at zero: a producer clock ahead of
ours reports as fresh, never as "fresher than possible".

### 1.1 Source vocabulary

`synthetic` · `pathgraph` · `correlation` · `configdrift` · `cloud` · `bgp` ·
`rum` · `flow` · `sdwan` · `wireless` · `agent` · `service_health` · `manual`.

Three of these have producers today: `synthetic` and `pathgraph` (the prober and
the traceroute registry beneath it) and whichever source a change producer
declares on `POST /api/dem/changes` (default `manual`). The rest are declared so
that their absence is visible on the Data Health surface.

### 1.2 Bounds

`MaxIDBytes` 128 · `MaxLabelBytes` 128 · `MaxSummaryBytes` 512 ·
`MaxDetailBytes` 2048 · `MaxListLen` 200 · `MaxChangeValueBytes` 2000 ·
`MaxContextEntries` 24 · `MaxJourneySteps` 40 · `MaxJourneysPerTenant` 100 ·
`MaxStepNextFanout` 8 · `MaxPacketEvidence` 40 · `MaxPacketHypotheses` 8 ·
`MaxPacketChanges` 12 · `MaxAnswerBytes` 8000.

---

## 2. Data classes

`provenance.go`. Eight values, **ordered least to most sensitive**, and the
order is load-bearing: `DataClassRank` and the AI packet redactor read it.

`public` (0) · `internal` (1) · `customer_metadata` (2) ·
`pseudonymous_user` (3) · `pii` (4) · `regulated` (5) · `credential` (6) ·
`secret` (7).

An **unknown** class ranks above every known one. A class nobody declared is a
class whose handling rules are unknown, so "is this safe to send to a model"
answers no. `MayLeaveThePlatform(c)` is true only at or below
`pseudonymous_user`. Full treatment in [`dem-privacy.md`](dem-privacy.md).

The vocabulary is deliberately a **superset** of `pathgraph`'s four data classes
(`live` / `synthetic` / `replay` / `lab`), which describe how a *measurement*
was produced. These describe how a *value* must be handled. They answer
different questions and are kept as separate fields for that reason: a `live`
measurement can carry a `pseudonymous_user` value, and conflating the two is how
a PII rule gets applied to the wrong column.

---

## 3. EvidenceItem

`evidence.go`. The atom every experience verdict is made of. **Observed or
inferred per its provenance. Immutable in practice** (derived per read from
immutable measurements; `TestDetectDoesNotMutateItsInput` pins that `Detect`
does not rewrite it). Not persisted, not versioned.

| Field | Type | Meaning and rule |
|---|---|---|
| `id` | string | Required. Derived ids are stable and readable: `syn-avail-<target>`, `syn-avail-ok-<target>`, `syn-lat-<target>`, `path-<target>`, `jny-<journey>-<step>`, `chg-<change id>`. |
| `tenant_id` | string | Lower-cased. |
| `incident_id` | string | Set when the item is attached to an incident. |
| `kind` | enum | What the item **claims**: `synthetic_result`, `journey_outcome`, `path_observation`, `path_degradation`, `service_health`, `change`, `cohort_comparison`, `real_user_metric`, `business_outcome`, `correlation`, `source_health`. Unknown is refused. |
| `entity` / `entity_kind` | string | What the item is **about** — a target id, a seam, a hop, a service, a journey step. Opaque; nothing in this package parses it. `entity_kind` names the vocabulary so the UI can link it. |
| `summary` | string, ≤512 B | **Required.** Evidence an operator cannot read is not evidence. |
| `detail` | string, ≤2048 B | Optional. |
| `value` / `baseline` / `deviation` | `*float64` | Pointers, not sentinels: `0` is a legitimate measurement and must be distinguishable from "not set". Only meaningful together. `deviation` is in baseline sigmas, or `value/baseline − 1` when no sigma exists. |
| `unit` | string | `%`, `ms`, and so on. |
| `stance` | enum | `supports` \| `contradicts` \| `neutral`. Empty defaults to `neutral`. A neutral item is rendered and never scored — it is context for a human, not input to a number. A supporting item that names a `cause_class` no hypothesis in the incident carries is **demoted to `neutral`** by `attachChangeEvidence`: it points at something nobody proposed, so treating it as unattached (and therefore bearing on every hypothesis) would be the opposite of what it says. |
| `supports_hypothesis_ids` / `contradicts_hypothesis_ids` | []string | Deduplicated, sorted, capped at `MaxListLen`. An item that names no hypothesis bears on **every** hypothesis in the set, which is the shape a single-hypothesis incident naturally has. |
| `decisive` | bool | Marks a contradiction that **refutes** rather than weakens. **Only a contradicting item may be decisive** — validation refuses otherwise. |
| `app` / `site` / `journey_id` / `step_id` | string | Scope: where this observation applies. What lets an incident be assembled per application, per site or per workflow without a caller pre-grouping the evidence. |
| `cohort` | `Cohort` | The population the observation belongs to. Without it a cohort comparison cannot be stated at all. |
| `cause_class` / `cause_entity` / `seam` / `owner` | string | The causal pointer of a **supporting** item: the class of thing being blamed, the concrete thing, the handoff that owns it and the team or provider. Hypotheses are generated from these, so the mapping from observation to blamed thing lives with the adapter that produced the observation and can be reviewed. |
| `contradicts_causes` | []string | The cause classes a **contradicting** item refutes. Validated against the closed cause vocabulary. |
| `independence_group` | enum | **The modality class.** Required and validated. Two items sharing it are one opinion however many observers reported it. |
| `observer` | string | The distinct vantage or collector. The independence rule needs both a second modality **and** a second observer. An item that will not name its observer is treated as sharing one anonymous vantage with every other unnamed item of its class. |
| `reliability` | float 0..1 | A property of the **source**, not of the number. Zero is replaced by `DefaultReliability(source)` at validation. Out of range is refused. |
| `expected_interval_sec` | int ≥ 0 | The source's declared cadence. It is what turns an age into a freshness: 90 s is fresh for a daily change feed and stale for a 15 s probe. `0` means no cadence declared, and freshness then decays on the package default. |
| `provenance` | `Provenance` | Embedded. |

### 3.1 Reliability defaults

Declared as data in one place so the numbers are reviewable rather than
scattered through the scorer. The ordering is the argument: a measurement taken
on the path outranks a controller's summary of it, which outranks an inference
from a change record.

| Source | Reliability | Source | Reliability |
|---|---|---|---|
| `rum` | 0.95 | `agent` | 0.80 |
| `synthetic` | 0.90 | `sdwan` | 0.75 |
| `pathgraph` | 0.90 | `wireless` | 0.75 |
| `flow` | 0.85 | `configdrift` | 0.70 |
| `bgp` | 0.85 | `cloud` | 0.70 |
| `correlation` | 0.80 | `manual` | 0.60 |
| `service_health` | 0.80 | *(ungraded)* | 0.50 |

Nothing is `1.0`. No single source is beyond doubt, and a `1.0` would let one
item saturate support on its own.

### 3.2 Modality classes

The independence vocabulary, and the load-bearing concept of the whole model.

| Class | Anchor-capable | In `signals.py` | Note |
|---|---|---|---|
| `active_probe` | Yes | Yes | A synthetic check from a vantage. |
| `passive_flow` | Yes | Yes | Flow records / application response time. |
| `control_plane` | Yes | Yes | Routing, BGP, adjacency. |
| `device_telemetry` | Yes | Yes | SNMP / gNMI / syslog from the device. |
| `management_plane` | No | Yes | An NMS controller's own opinion. Corroborates, never confirms. |
| `active_verification` | No | Yes | The device's own read-only answer. |
| `security` | No | Yes | A rule or benchmark verdict. |
| `real_user` | **Yes** | **No — DEM only** | First-party RUM. The only class that observes the experience from the seat it is actually had in, which is why it may anchor. When the RUM producer ships, this class must be added to `signals.py` or the two graders will disagree. |
| `change_record` | No | **No — DEM only** | A deployment, config, flag, cloud or route change. Support-only **on purpose**: a change is not a measurement of the experience, and "it happened just before" is correlation by clock. This constant is what makes "temporal proximity alone cannot confirm causality" structural rather than a review comment. |
| `business` | No | **No — DEM only** | A business outcome. Support-only: it measures the consequence, never the mechanism. |

The three DEM additions are each declared support-only or, in `real_user`'s
case, anchor-capable-and-not-yet-produced, so adding them can only ever lower a
verdict, never raise one past a gate the Python engine would have held shut.

---

## 4. MissingEvidence

`evidence.go`. **Missing telemetry is data.** An expected source that produced
nothing is a first-class record, not an absence.

| Field | Rule |
|---|---|
| `source` | A `Provenance` source. Validated; unknown is refused. |
| `independence_group` | The modality class the missing evidence *would* have carried. This is what makes "we are missing our only second opinion" mechanically visible. Optional, validated when present. |
| `reason` | `not_configured` \| `no_data` \| `stale` \| `permission_denied` \| `error` \| `not_supported`. These mirror the appobs readiness vocabulary, so one word means one thing across the product. |
| `detail` | The operator sentence, ≤2048 B. |
| `required` | When true, its absence **blocks** `CONFIRMED` outright. Set by `DataHealth.MissingFrom()` only for a source that is both anchor-capable and configured. |

"Something is missing" is not a diagnosis: validation refuses a record that
names no source or no reason.

---

## 5. Independence

`evidence.go`. The Go twin of `src/correlation/verdicts.EvidenceCoverage`. Not a
stored object — computed by `AssessIndependence` over the **supporting** items
of one hypothesis. It answers exactly one question: may this evidence anchor a
`CONFIRMED` verdict?

| Field | Meaning |
|---|---|
| `anchor_modalities` | The distinct anchor-capable classes present. Sorted. |
| `modalities` | All distinct classes present, anchor-capable or not. Corroboration is shown even when it cannot confirm. |
| `observers` | The distinct vantages. An unnamed observer becomes `unnamed:<modality>`, so unnamed items share one vantage. |
| `independent_pair` | The two item ids that satisfy the rule: different anchor modality **and** different observer. Empty when none does, and that emptiness is the reason a verdict stays `SUSPECTED`. |
| `reasons` | Mechanical explanations for a failed gate, in operator language. Never a generic label. |

`Satisfied()` is exactly `len(independent_pair) == 2`.

---

## 6. Hypothesis

`hypothesis.go`. One candidate explanation. Not persisted; derived per read.

Declared fields (a caller or generator sets these):

| Field | Rule |
|---|---|
| `id` | Required. Generated ids are `hyp-` + 8 bytes of `sha256(tenant\|subject\|cause_class\|cause_entity)`, so the same evidence always produces the same hypothesis id. |
| `tenant_id` | Lower-cased. |
| `incident_id` | Set when attached. |
| `cause_class` | Required, validated against the closed vocabulary (§6.1). |
| `cause_entity` | The concrete thing blamed — an ASN, a seam, a hop, a service, a release. Empty means the hypothesis names no cause, and its specificity ceiling says so. |
| `explanation` | **Required.** Must read as a claim about evidence, never as a verdict the evidence does not carry. |
| `seam` / `owner` | Which handoff owns the fix, and which team or provider that is. An empty owner is honest and renders as "owner not determined", never as a default team. |
| `blast_radius` | Who is affected, in a sentence. |
| `first_impact_at` | Anchors the change-before-effect rule. |
| `alternative_hypothesis_ids` | What else was considered. It is what turns a ranked list into an argument rather than an assertion. |

Graded fields — **written by `Grade`, never by a caller**, which is what stops
anything stamping a state the evidence does not support: `state`,
`verdict_tier`, `confidence`, `confidence_factors`, `independence`,
`supporting_evidence_ids`, `contradicting_evidence_ids`, `missing_evidence`,
`gate_reasons`.

### 6.1 Cause classes

Closed, because the list drives ownership routing and an unroutable cause is a
cause nobody fixes. It deliberately does not collapse every cloud or application
fault into "connectivity down".

`transit_degradation` · `last_mile` · `wan_overlay` · `lan_access` ·
`dns_resolution` · `tls_termination` · `cloud_edge` · `cloud_policy` ·
`application_regression` · `dependency_failure` · `capacity_saturation` ·
`config_change` · `routing_change` · `client_endpoint` · `synthetic_artifact` ·
`unknown`.

`LayerFor(cause)` (`http.go`) maps each onto the layer name the seam ribbon
uses — `device`, `LAN`, `WAN`, `ISP`, `DNS`, `cloud edge`, `application`,
`network`, `measurement` — which is the "likely layer" column of the incident
list.

### 6.2 States and windows

The state machine, the six confidence factors and every constant behind them
are documented in [`dem-evidence-confidence.md`](dem-evidence-confidence.md).
The `Window` type belongs here:

| Field | Default | Rule |
|---|---|---|
| `start` / `end` | The requested window | UTC. |
| `Tolerance` | `2m` | Widens the window for **measurements**: a probe recorded 30 s after the window closed still describes it. Not serialized. |
| `ChangeLookback` | `90m` | How far **before** first impact a change may have happened and still be a candidate cause. Beyond it, "there was a deploy yesterday" is history, not evidence. Not serialized. |

Both are deliberately modest. A generous window is how a temporal coincidence
becomes a "cause".

---

## 7. ExperienceIncident

`incident.go`. The one object the product is judged on, and **not** a second
incident store: it is the DEM evidence packet for the platform's existing
`internal/incident.Incident`.

| Field | Rule |
|---|---|
| `id` | `exp-` + 10 bytes of `sha256(tenant\|kind\|subject\|window_start)`. Deterministic, so a shared link keeps working. |
| `tenant_id` | |
| `incident_id` / `promoted` | The platform incident this packet belongs to. Empty and `false` today: **nothing promotes an experience incident into `internal/incident` yet.** That is stated, never hidden behind a synthesised id. |
| `title` | `"<journey> journey degraded"` or `"<app> experience degraded"`. |
| `severity` | `info` \| `low` \| `medium` \| `high` \| `critical` — the platform's ladder, so a promoted incident needs no translation. |
| `status` | Always `open` in this slice. |
| `detected_at` / `first_impact_at` / `recovered_at` | `first_impact_at` is the earliest `event_at` among supporting, non-change evidence, falling back to the window start. `recovered_at` is modelled and never set. |
| `window` | The `Window` the verdict is about. |
| `affected_apps` / `affected_journeys` / `affected_sites` | Sites are the distinct sites of supporting evidence. |
| `impact` | §7.1. |
| `slo_impact_pct` | How much of the objective this incident consumed, when one was declared. **Nil when none was** — never a default budget. |
| `hypotheses` | Ranked. Rejected ones sort last and are **never dropped**: "we considered the deploy and ruled it out" is one of the most valuable things the product can say. |
| `leading_hypothesis_id` / `confidence` / `verdict_tier` | The leading hypothesis's. With no leading hypothesis they are `""` / `0` / `undetermined`, and the UI says "no cause has enough evidence yet" rather than showing the best of a bad set. |
| `evidence` / `missing_evidence` / `changes` | The full set, the gaps, and the correlation-ranked changes. |
| `path_observation_id` | **A reference.** The first path-shaped evidence item's `provenance.source_object`. The ordered spine is fetched from the frozen path contract's own API and is never copied here. |
| `owner` / `seam` | Inherited from the leading hypothesis. |
| `recommended_actions` | §7.3. |
| `verification` | §7.4. |
| `timeline` | Impact, evidence, changes and detection on one axis, sorted, capped at `MaxListLen`. Every entry carries its `observation` mode. |
| `score_ref` | `"<journey id>@<window>"`, so the incident and the score cannot disagree about which window they describe. |

### 7.1 Impact

Every count is a pointer, and the reason is the product: **a nil user count is
rendered as "not measured", never as 0.** "No users affected" and "we cannot
count users" are opposite claims.

| Field | Rule |
|---|---|
| `users` / `sessions` / `transactions` | `*int`. All nil today — they can only be counted from first-party real-user telemetry, which is not collected yet. |
| `journey_success_pct` / `journey_success_before` / `error_pct` / `p95_ms` | `*float64`. `journey_success_pct` comes from the measured `JourneyHealth`. `error_pct` is taken from a real-user-metric item carrying a `%` value, so it is nil today. |
| `business_value_lost` / `currency` | From the journey's declared value per success. Absent unless the operator declared one. |
| `affected_cohorts` / `unaffected_cohorts` | The **contrast**. The unaffected list is not decoration: it is what rules a deployment out. |
| `not_measured` | The impact dimensions nothing produced, each with its sentence. Never empty in this slice, because users and sessions always appear in it. |

### 7.2 Cohort

`journey.go`. Eight optional dimensions: `site`, `isp`, `region`,
`device_type`, `browser`, `app_version`, `network_type`, `feature_flag`.

`Key()` renders the non-empty dimensions as `site=… · isp=…`, and an entirely
empty cohort keys as `all`. Empty dimensions are **omitted** rather than
rendered as "unknown", so two cohorts differing only in a dimension nobody
recorded are one cohort, not two.

Only `site` and `app_version` are populated today: `site` from the target's own
label, `app_version` from whatever a change producer declares.

### 7.3 RemediationAction

A **proposal**. Nothing in this package executes anything; the platform's Action
Queue owns execution, approval and audit.

| Field | Rule |
|---|---|
| `id` | `act-<hypothesis id>`, plus `-verify` for the companion. |
| `type` | `traffic_shift` \| `provider_escalation` \| `rollback` \| `config_revert` \| `failover` \| `investigate` \| `open_ticket` \| `fix_synthetic`. |
| `target` | What would be acted on. |
| `proposed_by` | `correlix` for a rule-derived proposal, the AI's identifier for a model-suggested one. **Always shown**: an operator must know whether a model or a rule proposed the change. |
| `summary` / `expected_outcome` / `risk` / `reversible` / `rollback_plan` | Everything an operator needs to judge the proposal before approving it. |
| `evidence_ids` | The hypothesis's supporting evidence. |
| `approval_state` | `not_required` \| `required` \| `granted` \| `refused`. |
| `execution_state` | `proposed` \| `queued` \| `running` \| `succeeded` \| `failed`. Always `proposed` here. |
| `verification_plan` | **Required by construction.** An action nobody can verify is not a recommendation, it is a hope. |

The mapping from cause class to action type is data in `RecommendActions`. One
rule overrides it: **an unconfirmed hypothesis never proposes a change to
production.** It proposes the change *and* a companion `investigate` action
whose verification plan is the hypothesis's own gate reasons.

### 7.4 Verification

| Field | Rule |
|---|---|
| `attempted` | False before any remediation has been verified. Always false in this slice. |
| `recovered` | Set **only** when the evidence agrees. An action completing is a fact about the action, not about the experience. |
| `detail` | The sentence that says exactly that. |
| `checks` | Three planned `VerificationCheck`s: the failing checks pass again (`synthetic`), the implicated path no longer degrades (`pathgraph`), the affected cohort returns to baseline (`rum` — which reports as not measured, because first-party real-user telemetry is not collected yet). |

`VerificationCheck` carries `name`, `source`, `measured`, `passed` and `detail`.
`measured` is the honesty flag: a check that could not run is not a check that
passed.

### 7.5 TimelineEntry

`at` · `kind` (`detected` \| `impact` \| `change` \| `evidence` \| `action` \|
`recovery`) · `summary` · `source` · `ref` · **`observation`**. The last is
required by the acceptance test: an inferred entry on a timeline that looks
measured is how a story becomes a fact.

### 7.6 ChangeRelevance

One change scored against one incident. `score` 0..1, `reasons` in operator
language, `precedes_impact`, `touches_affected_cohort`. The weights are exported
because a ranked list whose weights are secret is a ranked list nobody can argue
with: proximity 0.35, scope 0.35, cohort 0.20, class 0.10. Ordering is by score,
then by recency. See [`dem-evidence-confidence.md`](dem-evidence-confidence.md)
§8.

---

## 8. JourneyDefinition, JourneyStep, JourneyObservation, JourneyHealth

`journey.go`. A journey is the workflow a person is actually trying to complete.
It is **not** a linear Sankey: steps branch, are optional, and may loop, and a
definition that could not express that would force every real workflow to be
lied about at modelling time.

### 8.1 JourneyDefinition — persisted, versioned

| Field | Rule |
|---|---|
| `id` | `jny-` + 16 crypto-random bytes in hex. Minted by the store, never by a caller. |
| `tenant_id` | **Stamped from the token.** The create wire type has no tenant field at all. A concrete tenant is required; `""` and `*` are refused. |
| `name` | Required, ≤128 B. |
| `app` | Label-safe. |
| `description` | ≤2048 B. |
| `business_importance` | `critical` \| `high` \| `normal` \| `low`. Defaults to `normal`. Drives triage order and the coverage model's "which untested action matters most". Also `CHECK`ed in the database. |
| `business_value_per_success` / `currency` | The value of **one** successful traversal. Optional, and business impact is shown only when the operator declared a value. A value without a currency is refused: an unlabelled number is not an amount. |
| `entry_step_id` | Must be one of the steps. Defaults to the first. |
| `steps` | 1..40. |
| `slo` | `ExperienceSLO` (§8.4). |
| `version` | **Increments on every update.** An observation records the version it traversed, so a redesign never silently rewrites history. Also `CHECK (version > 0)`. |
| `created_by` / `created_at` / `updated_at` | `created_by` is the authenticated subject; `created_at`/`created_by` survive an update unchanged. |

Validation refuses a graph that cannot be walked, and walking it is the only
thing a journey is for:

- a dangling `next` edge (a step pointing at an unknown step);
- a duplicate step id;
- a step that is both a success and a failure terminal;
- a fan-out above `MaxStepNextFanout` (8);
- an `entry_step_id` that is not one of the steps;
- **no success terminal at all** — a journey with no way to succeed cannot have
  a success rate;
- an SLO percentage outside 0..100, or a negative latency objective.

Loops are legal and are not an error: a step may appear in its own reachable
set, which is what a retry is.

### 8.2 JourneyStep

`id` · `label` (defaults to the id) · `optional` · `next[]` ·
`terminal_success` · `terminal_failure` · `target_id` · `slo_success_pct` ·
`slo_latency_ms`.

`target_id` binds the step to an `internal/dem` catalogue target — the step's
measurement today, and the whole measurement path. There is no second synthetic
registry. **An empty `target_id` means the step is declared but not measured**,
which the health surface reports as a coverage gap rather than as success.

A step's own SLO of `0` inherits the journey's. There is no invented default.

### 8.3 JourneyObservation — immutable, contract-only today

One actual traversal. The type, its validation and its constructor exist and are
tested; **nothing produces one**, because a per-traversal record needs either
per-run synthetic records or first-party RUM. No surface fabricates one.

`id` · `tenant_id` · `journey_id` · `journey_version` · `started_at` ·
`ended_at` · `success` · `abandoned` · `failed_step_id` · `steps_completed[]`
(in order — branching is recorded as what actually happened, not fitted to a
fixed column set) · `duration_ms` · `errors[]` · `business_value` / `currency` ·
`trace_ids[]` · `path_observation_id` · `synthetic_run_id` · `cohort` ·
`provenance`.

Validation refuses an observation that contradicts itself: a successful
traversal naming a failed step; a failed traversal naming neither a failed step
nor abandonment; `ended_at` before `started_at`; a business value with no
currency. `synthetic_run_id` is never hidden — a synthetic success is not proof
that a person succeeded.

### 8.4 ExperienceSLO

`success_pct` · `latency_ms` · `window`. `Declared()` is `success_pct > 0`. An
undeclared objective is **never** substituted with a plausible number: a score
against a threshold nobody set is a fiction.

### 8.5 JourneyHealth and StepHealth — derived

`ComputeJourneyHealth(def, window, measurements)` is pure. Four rules carry it:

1. **A step with no bound target is not measured, never "fine"**
   (`step_not_bound`).
2. A bound step whose target reported nothing is `step_no_measurement`; a step
   whose target reported a not-measured verdict carries that verdict's own
   reason.
3. **Success composes multiplicatively over required steps.** A journey succeeds
   only if every required step does, so the product is the honest composition.
   The mean would show a journey with one dead step as "83 % healthy". Worked:
   `1.00 × 0.95 × 0.90 = 0.855` → `85.5`, and the mean would have said `95`.
4. **Optional steps are measured and shown but never gate the journey.**

`failing_step_id` is the **first** required, measured step that misses its
objective, in graph order. `steps_measured` / `steps_declared` expose the
coverage behind the number. When no required step is measured, `measured` is
false with `journey_not_measured` and the sentence "this is an absent result,
not a healthy one".

`business_impact` is the shortfall against the objective applied to the
traversals actually observed: `((slo_success_pct − success_pct) / 100) ×
max_samples × value_per_success`. It is deliberately conservative and never
extrapolates to traffic that was not measured.

Not-measured reason codes only a journey has: `step_not_bound`,
`step_no_measurement`, `journey_not_measured`, `no_journeys`.

---

## 9. ChangeEvent — persisted, immutable

`change.go`. The normalized record of something a human or a system **changed**,
from any producer, on one timeline. "What changed?" is the question an operator
asks second and a dashboard usually answers worst, because each producer keeps
its own list.

| Field | Rule |
|---|---|
| `id` | `chg-` + 16 crypto-random bytes in hex when the caller supplies none. |
| `tenant_id` | Stamped from the token. Concrete tenant required. |
| `type` | Nine values, the owner's Phase C.6 list unchanged: `APPLICATION_DEPLOY`, `CONFIG_CHANGE`, `FEATURE_FLAG_CHANGE`, `CLOUD_CHANGE`, `NETWORK_CHANGE`, `SECURITY_POLICY_CHANGE`, `DNS_CHANGE`, `ROUTE_CHANGE`, `INFRASTRUCTURE_CHANGE`. Upper-cased, validated, and `CHECK`ed in the database. |
| `actor` | Who or what made the change. Defaults to the authenticated subject. Never a credential. |
| `object` / `object_kind` | **Required.** A change to nothing cannot be correlated. |
| `summary` | Required, ≤512 B. |
| `before` / `after` | ≤2000 B each. A change record is a **pointer to** a diff, not a copy of a configuration: an unbounded blob here is how a credential ends up in a change feed. |
| `release_id` / `rollback_ref` | |
| `site` / `app` / `seam` | Place the change on the experience map, which is what lets the ranker ask "does this change even touch the failing path" rather than only "did it happen recently". |
| `cohort` | The population the change reached. The field that makes the acceptance scenario decidable: a deploy whose cohort does not intersect the affected cohort is **contradicted**, not merely unproven. |
| `provenance` | `event_at` is when the change happened, not when we learned of it. The distinction is the whole basis of the change-before-effect rule, which is why it is an indexed column rather than a field inside the JSON. |

**Immutability is enforced in both backends.** Postgres inserts
`ON CONFLICT (tenant_id, change_id) DO NOTHING`; the file store returns the
already-recorded event unchanged. `TestFileStoreChangesAreImmutableAndScoped`
pins that a replayed id does not rewrite history.

`CauseClassForChange` maps each type onto the cause class a hypothesis blaming
it carries — declared as data so the detector never invents a mapping inline:

| Change type | Cause class | Change type | Cause class |
|---|---|---|---|
| `APPLICATION_DEPLOY` | `application_regression` | `SECURITY_POLICY_CHANGE` | `cloud_policy` |
| `FEATURE_FLAG_CHANGE` | `application_regression` | `DNS_CHANGE` | `dns_resolution` |
| `CLOUD_CHANGE` | `cloud_edge` | `ROUTE_CHANGE` | `routing_change` |
| `CONFIG_CHANGE` | `config_change` | `INFRASTRUCTURE_CHANGE` | `config_change` |
| `NETWORK_CHANGE` | `config_change` | *(unmapped)* | `unknown` |

---

## 10. SyntheticDefinition and SyntheticRun

`synthetic.go`. Contracts for the coverage model. **No browser runner is
faked.**

### 10.1 SyntheticDefinition

`id` · `tenant_id` · `name` · `kind` · `version` · `target_id` · `journey_id` ·
`step_id` · `vantages[]` · `app` · `site` · `created_at` · `updated_at`.

Nine kinds: `HTTP`, `API`, `DNS`, `TLS`, `BROWSER`, `JOURNEY`, `NETWORK`,
`LARGE_PAYLOAD`, `DIRECTIONAL_PATH`. **Four have a runner today** —
`HTTP`, `API`, `DNS`, `NETWORK` — and `HasRunner(kind)` says which. A definition
of an unexecutable kind is accepted but reported as having no runner, never
silently never-run.

`vantages` are what make a synthetic capable of a multi-vantage agreement claim.
One vantage can never be its own second opinion, and the coverage model grades
a single-vantage step as `thin` for exactly that reason.

The coverage surface builds these definitions **from the catalogue**: every
target a journey step binds to is a definition of the kind that step is
protected by, with the vantage `prober@<site>`. There is no second registry — a
parallel definition store would let a step be "covered" by a check the prober
never runs.

### 10.2 SyntheticRun — immutable, contract-only today

One execution. `id` · `tenant_id` · `definition_id` · **`definition_version`**
(pins the run to the definition *as it was*, so a test edited after the fact
never appears to have always been what it is now) · `vantage_id` ·
`started_at` / `ended_at` · `outcome` · `fail_reason` · `steps[]` ·
`duration_ms` / `ttfb_ms` / `status_code` · `path_observation_id` ·
`artifact_ref` · `session_ref` · `retries` · `runner_version` ·
`selector_stable` · `provenance`.

`outcome` is `success` \| `failure` \| **`error`** \| `skipped`. The `error`
value is separate on purpose: the *runner* failing is not the same as the target
failing, and conflating them is how a broken prober becomes a fleet outage.

`vantage_id` is **required**: a measurement with no vantage cannot be an
independent observation. A successful run carrying a fail reason is refused.
`artifact_ref` is a pointer to a screenshot or HAR held by whatever stores
artifacts, never the artifact — which is how a run record stays small and how a
screenshot never lands in a JSON response.

Nothing produces `SyntheticRun` records yet.

### 10.3 SyntheticReliability

Grades whether a check's **results** can be trusted, from its runs.

`definition_id` · `grade` · `score` (0..1) · `reason` · `runs` · `failures` ·
`flips` · `runner_errors` · `retried_runs` · `vantages` ·
`disagreeing_vantages`.

| Grade | When |
|---|---|
| `unknown` | Fewer than `MinRunsForReliability` (10) runs. Three runs cannot tell a flaky check from an outage. |
| `broken` | The runner itself errored on half or more of the attempts, so the check is not measuring the service at all. |
| `flaky` | The flip ratio reached `FlakyFlipRatio` (0.2). A check that changes its mind on a fifth of its runs cannot raise a high-severity incident on its own. |
| `noisy` | Any flips, or a retry ratio above 0.2. Usable as corroboration, weaker alone. |
| `solid` | Consistent results across its runs. |

`score = clamp01(1 − flipRatio×2 − errRatio×1.5 − retryRatio×0.5)`.
`Trustworthy()` is `solid` or `noisy` only.

`severityFor` consults this: an incident whose **only** supporting evidence is
an untrustworthy synthetic is capped at `low`, whatever the miss looks like.
That is the owner's Phase H rule enforced in code rather than left to a
reviewer. It is provably wired (`TestFlakySyntheticCannotRaiseAHighSeverityIncident`)
and, until per-run records exist, never fires in production because the
reliability map is empty.

### 10.4 Coverage model

`ActionCoverage` per journey step — the closest thing Correlix has to a "real
user action" today: `journey_id` · `step_id` · `label` · `app` ·
`business_importance` · `interaction_volume` (`*int`, **nil** — an action nobody
measures is not an action nobody performs) · `synthetics` · `vantages` ·
`last_success` · `reliability_grade` · `state` · `detail`.

| State | Meaning |
|---|---|
| `untested` | Nothing measures it. Its health is unknown — not good. |
| `broken` | Checks exist but none can be trusted, so it is effectively untested. Counted in `untested_actions`. |
| `stale` | No check protecting it has succeeded, so it cannot be said to work. |
| `thin` | Protected from a single vantage. Enough to notice a failure, not enough to confirm one. A thin action counts in **both** `thin_actions` and `protected_actions`: it is protected, weakly. |
| `protected` | Two or more vantages. |

`CoverageReport` aggregates: `critical_actions`, `protected_actions`,
`untested_actions`, `thin_actions`, `broken_tests`, `flaky_tests`,
`coverage_pct` and `detail`. **`coverage_pct` is nil when nothing is declared**,
and the sentence says "This is not 100 % coverage."

---

## 11. ExperienceEvent, ExperienceSession, BusinessEvent — CONTRACTS ONLY

`event.go`. **State this plainly wherever these appear: nothing produces them in
this slice.** There is no first-party RUM snippet, no desktop agent and no
browser runner. There is no route, no Kafka topic and no ClickHouse table. What
ships is the shape, its validation, the pseudonymous-user discipline, the
actor-type vocabulary, the external-schema fields an OpenTelemetry adapter fills
in, and the `EventSink` seam the ingest route will attach to. The next slice
adds the lane; the shapes will not have to change to get there, which is the
entire point of writing them now.

### 11.1 ExperienceEvent

`id` · `tenant_id` · `session_id` · **`user_ref`** · `app` (required) ·
`environment` · `release` · `type` · `action` · `route` · `success` ·
`duration_ms` · `error` · `status_code` · `vitals` · `journey_id` · `step_id` ·
`feature_flags` · `cohort` · `trace_id` / `span_id` · `actor_type` · `agent` ·
`business_context` · `provenance`.

Seven event types: `page_view`, `interaction`, `api_call`, `error`,
`navigation`, `web_vital`, `journey_step`.

Rules validation enforces:

- `user_ref` must be a **pseudonymous** reference. A value containing a direct
  identifier marker is **refused, not hashed** — silently pseudonymising a
  caller's mistake teaches the caller that sending real identifiers is fine.
- An event carrying a `user_ref` and declaring no class is classified
  `pseudonymous_user`, default-closed, never `internal`.
- An event carrying a `user_ref` classified **below** `pseudonymous_user` is
  refused rather than silently upgraded: quietly rewriting a security
  classification would hide a producer that is mislabelling its data.
- `status_code` must be `0` or a real 100..599 HTTP status.
- An `agent` context is valid only for an `AI_AGENT` actor.
- `feature_flags` and `business_context` are bounded at `MaxContextEntries`
  (24) entries with `MaxLabelBytes` keys and values. A beacon is a measurement,
  not a document store.

`WebVitals` — `lcp_ms`, `inp_ms`, `cls`, `ttfb_ms`, `fcp_ms` — is all pointers:
an unreported vital is absent, never `0`. A `0` CLS is excellent and a `0` LCP
is impossible, so a shared zero would be read two different wrong ways.

`AgentContext` is the Phase N reservation, declared now and provider-neutral:
`agent_id`, `agent_version`, `model`, `provider`, `conversation_id`, `run_id`,
`tool_name`, `tool_duration_ms`, `retries`, `tokens_in`, `tokens_out`,
`cost_micros`, `outcome`. Nothing populates it.

### 11.2 ExperienceSession

`id` · `tenant_id` · `actor_type` · `user_ref` · `started_at` / `ended_at` ·
`app` · `release` · `environment` · `cohort` · **`replay_ref`** · `events` ·
`errors` · `journeys_attempted` · `journeys_succeeded` · `health` · `agent` ·
`provenance`.

Actor types: `HUMAN`, `SYNTHETIC`, `API_CLIENT`, **`AI_AGENT`** — reserved now
so an agent traversal does not need a schema change later, and so a synthetic
run can never be silently counted as a person.

`health` is `good` \| `degraded` \| `failed` \| `unknown`. **`unknown` is the
default and is never rendered as good.**

`replay_ref` is a pointer to a session replay held elsewhere, never the replay.
It is a separate field on purpose: replay access is role-controlled and audited,
and a reference is what an access check can be attached to. A session declaring
no class is classified `pseudonymous_user`.

### 11.3 BusinessEvent

`id` · `tenant_id` · **`business_event_type`** · `app` · `journey_id` ·
`session_id` · `success` · `value` / `currency` · `quantity` · `cohort` ·
`attributes` · `provenance`.

`business_event_type` is a free, label-safe string **on purpose** — login,
purchase, booking, payment, report, claim, an API transaction, or whatever this
tenant's business actually does. Hard-coding e-commerce semantics here would
make the model wrong for most customers on day one. A `value` with no `currency`
is refused.

### 11.4 EventSink

```go
type EventSink interface {
    WriteEvents(ctx context.Context, events []ExperienceEvent) error
    WriteBusinessEvents(ctx context.Context, events []BusinessEvent) error
}
```

It **must return an error rather than dropping silently**: a dropped experience
event is a user whose bad day the product never saw. No implementation exists.

---

## 12. DataSourceHealth

`datahealth.go`. Extends the readiness vocabulary the platform already speaks —
the appobs Data Sources tab's seven states — rather than inventing a second
one, and adds the two fields that make it an *experience* source rather than an
*ingestion* source.

`SourceHealth`: `source` · `label` · `independence_group` · `configured` ·
`state` · `detail` · `last_seen` · `expected_interval_sec` ·
`freshness_seconds` · `events_in_window` · `lag_seconds` · `errors` ·
`last_error` · `coverage` / `coverage_covered` / `coverage_total` ·
`confidence_influence` · `anchor_capable`.

States: `flowing` · `stale` · `off` · `permission_denied` · `misconfigured` ·
`no_data` · `not_supported`.

**`Healthy(state)` returns true for exactly one value, `flowing`.** Everything
else — including "we have not looked" — is not healthy, and that function is the
single place that decides it. There is no code path that renders an absent
source as green.

| Derived field | Rule |
|---|---|
| `coverage` | `covered / total`, **nil when there is no denominator**. Coverage is stated, never assumed: "flowing" from one of forty sites is not a healthy source. |
| `confidence_influence` | How much this source's current state is lowering diagnostic confidence, 0..1. Derived, never declared: `permission_denied`/`misconfigured`/`no_data` → 0.4, `stale` → 0.3, `off`/`not_supported` → 0.15, anything else non-healthy → 0.2, **plus 0.2 when the source is anchor-capable**. Zero when flowing. |
| `anchor_capable` | `MayAnchorVerdict(independence_group)`. A tenant with no anchor-capable second source can never reach confirmed, and the surface says so rather than leaving it to be discovered. |

`DataHealth` aggregates: `window`, `sources` (problems first, then
anchor-capable, then alphabetical), `anchor_sources_flowing`, **`can_confirm`**
(`anchor_sources_flowing >= 2`) and an `explanation` that is always populated.

`MissingFrom()` turns the health picture into the incident's missing-evidence
records. A source is marked **`required`** — the absence that *blocks*
confirmation — only when all three hold: it is **anchor-capable**, it is
**configured**, and it has **reported at least once** (`LastSeen != nil`).

Each clause removes a different way of being wrong. A corroborating source being
off lowers confidence without blocking anything, because it could never have
confirmed a verdict in the first place. A source that has **never** produced
anything is a capability the deployment does not have, not a gap in a capability
it has, and treating it as blocking would make every incident in every such
deployment permanently unconfirmable. A source that reported and then went quiet
is a real gap and does block, because something that was working has stopped.

With today's adapters no source reaches all three conditions, so nothing is
`required` on any deployment. Every source is either `flowing`, and therefore
not missing, or has never reported in the window. Missing telemetry still costs
confidence through the completeness factor.

---

## 13. ExperienceScore and ScorePolicy

`score.go`, `policy.go`, `score-policy.yaml`. Distinct from `internal/dem`'s
per-target verdict, and deliberately so: that one answers "was this check
healthy"; this one answers "was the experience good", over six dimensions, for
a subject a business cares about.

### 13.1 Dimensions

Closed vocabulary — a policy naming a dimension this package does not compute is
a policy that silently drops weight, so the loader refuses it.

`journey_success` · `availability` · `responsiveness` ·
`error_free_interaction` · `network_quality` · `user_friction`.

### 13.2 ExperienceScore

`subject` · `subject_kind` (`tenant` \| `app` \| `site` \| `journey`) ·
`window` · `app_class` · `aggregation` · `measured` · `reason` · `detail` ·
`score` (`*float64`) · `band` · `previous_score` · `delta` · `dimensions` ·
**`policy_version`** / `policy_name` · `measured_dimensions` /
`declared_dimensions`.

`DimensionScore`: `name` · `measured` · `reason` · `points` (0..100 on the
dimension's own scale) · `weight` (the share carried **after** redistribution) ·
`max` · `score` (`points × weight`) · `delta_contribution` (`*float64`, absent
when there is no previous score) · `detail` · `samples` · `evidence_ref`.

Four rules, all of them the reason the file exists:

1. **Decomposable.** A score always carries its dimensions, their weights, their
   values, and each one's contribution to the change since the previous score.
2. **Versioned.** `policy_version` is stored with every score. A weight change
   must never silently rewrite yesterday's numbers.
3. **Gated.** A dimension that was not measured contributes nothing and its
   weight is redistributed over the dimensions that were. Below
   `MinMeasuredDimensions` (**2**) the score is **not rendered** — reason
   `below_evidence_minimum`, band `not_measured`, `score` nil. One dimension is
   a metric, not an experience.
4. **Banded, and the bands never move.** Good ≥ 70, Fair 31–69, Poor ≤ 30.
   `Band()` is only ever called on a measured score.

Reason codes: `no_dimensions_measured` (nothing produced this dimension),
`below_evidence_minimum`, `no_score_policy`.

### 13.3 ScorePolicy

`name` · `version` · `classes` (class → dimension → weight) · `source`
(`embedded` or the override path, so an operator can tell a shipped policy from
an overridden one).

The shipped policy is `correlix.dem.score` version 1, with five classes:

| Class | journey_success | availability | responsiveness | error_free | network_quality | user_friction |
|---|---|---|---|---|---|---|
| `default` | 0.30 | 0.25 | 0.20 | 0.10 | 0.10 | 0.05 |
| `web` | 0.35 | 0.20 | 0.25 | 0.10 | 0.05 | 0.05 |
| `real_time` | 0.20 | 0.20 | 0.15 | 0.05 | **0.35** | 0.05 |
| `thick_client` | 0.25 | **0.30** | 0.20 | 0.10 | 0.10 | 0.05 |
| `infrastructure` | — | **0.50** | 0.20 | 0.10 | 0.20 | — |

A dimension a class does not name is **not scored** for that class — absent from
the composite rather than weighted at zero, so the UI can say "this class does
not measure that" instead of showing a permanent `0`. `infrastructure` is the
worked example: DNS, auth, print and file services have no workflow and no
friction to speak of.

`Validate()` refuses a policy with no name, a non-positive version, no classes,
no `default` class, a class with no weights, or **a class whose weights do not
sum to 1.0** within `1e-6`. A composite that does not sum to its parts is not
decomposable.

The reader in `policy.go` is a strict, closed-grammar reader, not a YAML parser,
because no YAML module is on the CLAUDE.md §6 allowlist and the repository's
precedent is `alerts/engine.go`'s `parseRulesYAML`. It accepts exactly three
indent levels and refuses, **with the line number**, a tab, a list, an unknown
top-level key, a duplicate key, an unknown dimension, a weight outside `(0, 1]`
and an unexpected indent. An operator override (`DEM_SCORE_POLICY_FILE`) is
applied only if it parses **and** validates; a bad override is loud and the
embedded policy stands, because a scoring policy that silently half-applied
would be worse than one that was ignored.

### 13.4 What is actually measured today

`tenantScore` in `assemble.go` supplies:

| Dimension | Source | State |
|---|---|---|
| `journey_success` | `WorstWeightedMean` over the measured journeys' `SuccessPct` | Measured when at least one declared journey has a measured required step. |
| `availability` | `WorstWeightedMean` over per-target `Availability.Points` | Measured when any target produced a scorable availability window. |
| `responsiveness` | `WorstWeightedMean` over per-target `Latency.Points` | Measured only where a **declared** latency budget exists — otherwise there is no threshold to be scored against. |
| `network_quality` | `WorstWeightedMean` over per-target `PathStability.Points` | Measured only where a forward path was observed. Absent means not measured, not "good". |
| `error_free_interaction` | — | **`not_configured`.** Measured from first-party real-user telemetry, which is not collected yet. |
| `user_friction` | — | **`not_configured`.** Retries, re-authentication, roaming and abandonment need real-user or endpoint telemetry, which is not collected yet. |

With two of six permanently unmeasured, a tenant needs at least two of the
remaining four to publish a score at all.

### 13.5 How per-subject points are folded

Each of the four measurable dimensions above is computed from many subjects: one
figure per declared journey, or one per catalogue target. `WorstWeightedMean`
folds them:

```
value = mean × (1 − WorstShare) + worst × WorstShare      WorstShare = 0.4
```

An empty set returns `ok = false`, so a caller cannot turn "nothing was
measured" into a zero.

The weight on the worst subject is `internal/dem`'s `weightWorst`, for the same
reason it exists there: **a plain mean is how one dead target disappears into a
green tile.** Nine perfect subjects and one dead one folds to `54`, not to the
arithmetic mean of `90`, and `TestWorstWeightedMeanIsWhatTheLabelSays` pins that
number. A pure worst-of would go the other way and make one paused check the
whole story.

`ExperienceScore.Aggregation` reports `worst_weighted`, which is what the
arithmetic does. `AggWorstOf` and `AggP95Of` remain declared as the
**per-observer** modes of §M.4; they become meaningful only when a subject is
measured from more than one vantage, and with a single prober there is no second
observer to take a worst or a percentile of.

---

## 14. AI investigator contracts

`investigator.go`. Reduced projections, documented here because they are part of
the domain model even though the orchestrator lives elsewhere.

`Packet`: `incident_id` · `title` · `severity` · `window` · `impact` ·
`hypotheses` (≤8 `PacketHypothesis`) · `evidence` (≤40 `PacketEvidence`) ·
`missing_evidence` · `changes` (≤12) · `source_health` · `allowed_actions` ·
`path_observation_id` · **`redacted[]`** · **`evidence_ids[]`**.

`PacketEvidence` is deliberately a **reduced** projection of `EvidenceItem`:
`id`, `kind`, `stance`, `summary`, `entity`, `independence_group`, `observer`,
`reliability`, `observed_at`, `observation`, `supports`, `contradicts`. Raw
payloads, producer ids and anything above `pseudonymous_user` never appear.

`Investigation` — the JSON tags **are** the output schema the model must
produce: `answer` · `confidence` · `hypotheses` · `supporting_evidence_ids` ·
`contradicting_evidence_ids` · `missing_evidence` · `recommended_next_queries` ·
`recommended_actions` · `assumptions` · **`attribution`** (stamped by the
validator, never by the model) · **`downgraded`**.

The enforcement is in [`dem-privacy.md`](dem-privacy.md) §5.

---

## Related

- [`dem-architecture.md`](dem-architecture.md) — the layering and the pipeline.
- [`dem-evidence-confidence.md`](dem-evidence-confidence.md) — the maths and the state machine.
- [`dem-api.md`](dem-api.md) — how these objects appear on the wire.
- [`dem-privacy.md`](dem-privacy.md) — the classes, redaction and retention.
- [`service-path-graph-contract.md`](service-path-graph-contract.md) — `Endpoint` / `PathDefinition` / `PathObservation` / `PathHop`, referenced by id and never copied.
