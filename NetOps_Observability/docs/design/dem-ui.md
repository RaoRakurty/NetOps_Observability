# DEM UI — the contract the Digital Experience screens must satisfy

Status: **contract, 2026-09-05.** The backend described here is built and
shipped; the screens are being built in parallel by another agent. This document
therefore states **what must be true**, not what a given file contains. Where a
component name appears it is either one that already exists in the repository
and was read, or it is explicitly marked as a requirement rather than a fact.

Authority: `docs/design/DEM_2026-09-05.md` §M.6 (navigation and screens) and the
owner's Phase E, Phase F and Phase R. The data contract is
[`dem-api.md`](dem-api.md); the meaning of every number is
[`dem-evidence-confidence.md`](dem-evidence-confidence.md).

---

## 1. Information architecture

**No IA rewrite.** Digital Experience lands in the existing Operations section
as one leaf with sub-tabs, exactly the way `AppObservability.tsx` already works.

```
Operations → Digital Experience        #/operations/digital-experience
```

The leaf currently exists as a deliberate stub (`pages/DigitalExperience.tsx`)
with no nav entry, and its own header comment names this route as the intended
one. Wiring it means adding the leaf to the `operations` children in `nav.tsx`
and a lazy chunk to `ROUTE_CHUNKS`.

### 1.1 The seven sub-tabs

Sub-tabs are page-local state seeded from the **third hash segment**, which is
the established pattern: `#/operations/digital-experience/<tab>`. Re-read the
hash on `hashchange`, so clicking a flyout sub-item while already on the page
switches the tab.

| # | Tab | Route suffix | Backed by |
|---|---|---|---|
| 1 | Experience | *(default, empty suffix)* | `GET /api/dem/overview` |
| 2 | Incidents | `incidents` | `GET /api/dem/incidents`, then `…/{id}` and its three sub-resources |
| 3 | Journeys | `journeys` | `GET /api/dem/journeys`, `POST`/`PUT`/`DELETE /api/dem/journeys/{id}` |
| 4 | Service Paths | `paths` | The **existing** path graph surface. DEM contributes only a `path_observation_id`. |
| 5 | Synthetics | `synthetics` | `GET /api/dem/synthetics/coverage`, plus the existing `GET /api/dem/targets` catalogue |
| 6 | Changes | `changes` | `GET /api/dem/changes`, `POST /api/dem/changes` |
| 7 | Data Health | `data-health` | `GET /api/dem/data-health` |

Users & Sessions, Releases, AI Investigator and Automation are **panels inside
these tabs**, not tabs of their own, until their producers exist. A tab whose
only possible content is "no producer" teaches an operator to ignore a tab.

### 1.2 Whether Digital Experience becomes the Operations landing

§M.6 proposes it becomes the Operations landing when the DEM feature is on for
the tenant. §M.11 lists "whether Digital Experience is the Operations landing
for ALL tenants or per-tenant" as an **open owner decision**. Until it is taken,
build it as a leaf and leave the landing alone.

### 1.3 Feature gating

Gate on the `enabled` field the API returns, not on a client-side flag. Every
response carries `enabled`, and when it is false the surfaces still render with
`reason: "feature_off"` and the sentence

> Digital experience collection is off. Nothing on this screen was measured; an
> empty table here does not mean everything is well.

Render that sentence. Do not hide the tab, and do not render an empty table.

---

## 2. The Experience overview

The owner's Phase E layout, in this order.

### 2.1 Top cards

Five cards: **Experience SLO**, **Journey Success**, **Impacted Users**,
**Business Impact**, **Active Experience Incidents**.

Each card must show the current value, compare a baseline, show direction of
change, support click-through, and expose a tooltip explaining how the number
was made. Three of the five have honest states that must be designed for, not
worked around:

| Card | Source | Honest state |
|---|---|---|
| Experience SLO | `score.score`, `score.band`, `score.previous_score`, `score.delta` | When `score.measured` is false, render `score.reason` and `score.detail`. **Never 0, never 100, never an empty gauge that reads as good.** |
| Journey Success | mean over `journeys[].success_pct` where `measured` | When no journey is measured, the reason is `journey_not_measured`. |
| Impacted Users | `incidents[].impact_not_measured` | **Always not measured today.** The card must render "not measured — affected users can only be counted from first-party real-user telemetry, which is not collected yet". A `0` here would read as "nobody is affected", which is the opposite claim. |
| Business Impact | `business_impact`, `business_impact_currency`, `business_impact_note` | Absent unless a journey declared a value per success. Absent is not zero. When `business_impact_note` is present the total was **withheld** because the window declares more than one currency; render the note, because a blank card would read as "no business impact". The per-incident figures on the incident rows stay correct and stay visible. |
| Active Incidents | `incidents.length` | A genuine count. |

### 2.2 A — Active Experience Incidents

Columns, in the owner's order: **Severity · Incident · Journey/App · Impact ·
Business impact · Likely layer · Leading cause · Confidence · Owner · Duration**.

Every column has a field: `severity`, `title`, `journey`/`app`,
`journey_success_pct` + `impact_not_measured`, `business_impact` + `currency`,
`likely_layer`, `leading_cause`, `confidence` + `verdict_tier`, `owner`,
`duration_sec`.

`owner` may be empty. Render "owner not determined", **never a default team**.

### 2.3 B — Journey Health

Render each declared journey and its steps from `journeys[]`. Per step show
`success_pct` against `slo_success_pct`, `p95_ms` against `slo_latency_ms`, and
`samples`. The failing step (`failing: true`, and the journey's
`failing_step_id`) is the one to highlight.

Three rules the data enforces and the UI must not undo:

- A step with `measured: false` renders its `reason` and `detail`. A `step_not_bound`
  step is a **coverage gap**, drawn differently from a failing one — nothing
  observes it, so it is neither good nor bad.
- The journey's `success_pct` is the **product** of its required steps, not the
  mean. Show `steps_measured` of `steps_declared` beside it, because the number
  rests on that coverage.
- `optional` steps are shown and never gate the journey.

### 2.4 C — What changed

`changes[]` from the overview, newest first. On an incident this becomes the
correlation-ranked list (§3.6).

When the list is empty, render the API's `note` verbatim rather than "no
changes":

> No change was recorded in this window. That may be correct — a quiet estate
> reports nothing — but it is not proof that nothing changed: only the producers
> that are wired report here.

### 2.5 D — Experience Hotspots

`hotspots[]`, one row per dimension. **Render all seven dimensions, including
the five that are always `measured: false`.** Each carries its own `reason`
sentence. Omitting them would hide the fact that the breakdown does not exist;
rendering an empty chart would imply it does and found nothing.

| Dimension | Today |
|---|---|
| `app` | Measured, banded. |
| `site` | Ranked by open incidents, with the reason that a per-site score needs a prober at the site. |
| `isp`, `device`, `browser`, `version`, `network` | Not measured: needs first-party real-user telemetry. |

### 2.6 E — Telemetry Confidence

The owner's example is a list of sources with states. **Never hard-code these
states.** They come from `data_health.sources[]`, and every one of the ten
sources on the ladder is always present.

Per source render: `label`, `state`, `last_seen` / `freshness_seconds`,
`events_in_window`, `coverage` (absent means "coverage is not knowable for this
source" — never render it as 100 %), `anchor_capable`, and
`confidence_influence`.

Above the list, render `data_health.explanation` and `can_confirm`. That
sentence is the answer to the question an operator will otherwise ask support:

> Only 1 independent kind of instrument is reporting. Correlix can suspect a
> cause but cannot confirm one: confirmation requires two independent
> observations, and that is a property of the evidence, not of the analysis.

---

## 3. The Experience Incident

The highest-priority screen. §M.6 fixes the section order, and it is the owner's
Phase F order: **impact → timeline → experience path → hypotheses → evidence →
changes → ownership → recommended action → recovery validation.**

The existing RCA workspace components under
`src/frontend/src/components/rca/*` are composed **by import only**. They were
not modified by this slice and another agent's investigation page depends on
them; anything that would require changing them is deferred.

### 3.1 Header

Title, severity, status, started, impacted users, business impact, leading
hypothesis, confidence, owner. From `IncidentResponse.incident` plus its
`Summarize`d equivalents.

### 3.2 Impact

`impact`: users, sessions, transactions, error %, p95, journey success, business
value, affected cohorts — **and `not_measured`.**

Every count is a pointer in the JSON. A missing key means not measured. The
contrast between `affected_cohorts` and `unaffected_cohorts` is not decoration:
it is what rules a deployment out, and it must be visually paired, not put in
two distant panels.

### 3.3 Experience path

Reuse the service path graph. DEM supplies **only** `path_observation_id` via
`GET /api/dem/incidents/{id}/path`; the ordered spine is fetched from the path
API, which is the single source of hop order.

The path contract's renderer rule is binding here: the UI is a dumb layout of
the spine. It must not compute hop order, must not lay out from node degree, and
must not fall back to a star. When `measured` is false, render the reason:

> no forward path was observed for this incident's subject in this window, so
> there is no path to render — this is an absent measurement, not a clean path

Per-edge state, latency/loss, provenance, confidence, freshness and owner come
from the path API's own spine, and observed, inferred, unknown, degraded,
healthy and no-data must be **visually distinct**. An inferred edge must never
be presented as observed.

### 3.4 Timeline

`GET …/timeline`. One axis carrying impact, evidence, changes and detection.
Every entry has an `observation` mode and it must be visible on the entry —
an inferred entry on a timeline that looks measured is how a story becomes a
fact.

### 3.5 Hypotheses

`hypotheses[]` from `…/evidence`, already ranked. For each: confidence, cause
class, cause entity, explanation, supporting / contradicting / missing evidence,
seam and owner.

**A rejected hypothesis is rendered, last, with what refuted it.** It is not
filtered out. "We considered the deploy and ruled it out" is one of the most
valuable things the product says, and dropping it would throw the value away.

### 3.6 Changes

`changes[]` from `…/timeline` is `ChangeRelevance`, already ordered by
correlation rather than by clock. Render `score`, every entry in `reasons[]`,
`precedes_impact` and `touches_affected_cohort`.

A change with `precedes_impact: false` is shown — an operator wants to see what
was done during an incident — and must be marked as unable to have caused it.
A change with `touches_affected_cohort: false` carries the reason "its cohort
does not include the affected population", which is a *contradiction*, not a
low score, and should read as one.

### 3.7 Evidence

The ALL / SUPPORTING / CONTRADICTING / MISSING filter, over `evidence[]` and
`missing_evidence[]`.

**MISSING is a first-class filter over a real list**, not an empty state. Each
`MissingEvidence` shows its source, the modality class it would have carried,
its reason code and its detail, and whether it is `required` — the ones that
**block** confirmation.

Per evidence item show: stance, kind, summary, entity, observer, modality class
(`independence_group`), reliability, and observed-vs-inferred. Value, baseline
and deviation only when present.

### 3.8 Ownership

`seam` and `owner` from the leading hypothesis. Empty renders as "owner not
determined".

### 3.9 Recommended action

`recommended_actions[]`. Each carries type, target, summary, expected outcome,
risk, reversibility, rollback plan, approval state and **verification plan**.
`proposed_by` is always shown: an operator must know whether a rule or a model
proposed the change.

When the leading hypothesis is not `CONFIRMED`, the API returns a second,
companion `investigate` action whose verification plan is the gate reasons
themselves. Render both, and render the companion as the safer one.

### 3.10 Recovery validation

`verification`. `attempted` is false and `recovered` is false in this slice, and
`checks[]` is a **plan**, not a result. Label it as a plan. The `detail` line
is the rule and should be rendered:

> Recovery is marked only when the synthetic evidence, the path and — where it
> exists — the real-user evidence all agree. An action completing is not
> recovery.

The third planned check reports as not measured, with the reason that first-party
real-user telemetry is not collected yet. Render that state; do not hide the
check.

---

## 4. The honesty rules the UI must enforce

These are not style preferences. Each one is a claim the backend refuses to make
and the UI must not make on its behalf.

| # | Rule |
|---|---|
| H1 | **UNKNOWN and NO DATA are never HEALTHY.** Six states must be visually distinct: `HEALTHY`, `DEGRADED`, `FAILED`, `UNKNOWN`, `NO DATA`, `DISABLED`. The last three must not share the healthy hue. `Healthy(state)` is true for exactly one value, `flowing`. |
| H2 | **Every not-measured surface renders its reason.** Every aggregate carries `measured` plus a stable `reason` code and a human sentence. Render the sentence. A blank cell, a dash or an empty chart is a claim nobody made. |
| H3 | **Never render a fabricated zero.** A nil `users`, `sessions`, `error_pct` or `business_impact` means not measured. `0` and "we cannot count" are opposite claims. |
| H4 | **Observed and inferred are visually distinct**, on the path, on the timeline and on every evidence row. An inferred edge is never presented as observed. |
| H5 | **A score always shows its policy version and its dimension breakdown.** `policy_version` and `policy_name` travel with every score; every dimension carries `points`, `weight`, `max`, `score`, `samples`, `detail`, and — when a previous score exists — `delta_contribution`. "Why did it fall" is arithmetic, and the arithmetic must be on screen. |
| H6 | **An unmeasured dimension is shown as unmeasured**, with its reason, and its weight redistribution is visible. It is absent from the composite, not weighted at zero. |
| H7 | **Below the evidence minimum, no score is rendered.** `measured: false`, `band: not_measured`, `score` absent, `reason: below_evidence_minimum`. Not 0, not 100, not a grey gauge that reads as fine. |
| H8 | **Bands are fixed and never inverted**: Good ≥ 70, Fair 31–69, Poor ≤ 30. |
| H9 | **A confidence always shows its factors.** Six named factors, each with a value and a reason sentence. A bare "0.80" is not the product. |
| H10 | **An unconfirmed verdict always shows its gate reasons.** `gate_reasons[]` is rendered verbatim. "Not confirmed" without a reason teaches an operator to ignore the distinction. |
| H11 | **The aggregation mode is stated on screen.** `score.aggregation` reads `worst_weighted` today, meaning each dimension's per-subject points were folded with the worst subject carrying 0.4 of the weight. Say what the field says. Do not translate it into "average". |
| H12 | **Coverage is stated, never assumed.** An absent `coverage` means the denominator is unknown. Do not render it as 100 %. Zero declared actions is not 100 % coverage, and the API's `detail` says so. |
| H13 | **Reliability reads `unknown`, and the note explaining why is rendered.** A check nobody has graded is not a check that passed. |
| H14 | **A disabled feature renders disabled, with its reason.** `ai_investigator.available: false` plus its sentence. A hidden feature is indistinguishable from a missing one. |
| H15 | **Contradicting and missing evidence are as prominent as supporting evidence.** `contradiction_count` and `missing_evidence_count` sit beside `evidence_count` in the API for that reason. |

### 4.1 Progressive disclosure

Phase R's hierarchy, and the reason the incident sections are in the order they
are:

```
Impact → Cause → Evidence → Path → Timeline → Deep telemetry
```

Avoid a wall of widgets. Every panel below the fold should be collapsible, and
the fold should land after Impact and the leading cause.

---

## 5. Design tokens

Use the second-generation tokens in `src/frontend/src/styles.css`. Do not
introduce a DEM-specific palette; the visual grammar is the platform's.

| Purpose | Tokens |
|---|---|
| Surfaces | `--panel`, `--panel-solid`, `--panel-border`, `--bg` |
| Text | `--fg`, `--muted` |
| Severity | `--sev-critical`, `--sev-error`, `--sev-warning`, `--sev-notice`, `--sev-info`, `--sev-debug`, `--sev-ok` and their `-bg` twins. The incident severity ladder maps directly: `critical` → `--sev-critical`, `high` → `--sev-error`, `medium` → `--sev-warning`, `low` → `--sev-notice`, `info` → `--sev-info`. |
| Score bands | `good` → `--good` / `--sev-ok`, `fair` → `--warn` / `--sev-warning`, `poor` → `--bad` / `--sev-critical`. |
| **Not measured** | `--muted` on `--hover`, **never a severity hue**. A not-measured cell must not borrow the palette of a state. This is the single most important token decision on the screen: an unmeasured dimension tinted green is H1 violated in CSS. |
| Type scale | `--fs-micro` (chips only, never body copy), `--fs-meta`, `--fs-sm`, `--fs-base`, `--fs-md`, `--fs-lg`, `--fs-xl`, `--fs-2xl`, `--fs-3xl` for the hero score numeral. |
| Spacing / radius | `--sp-1`…`--sp-7`, `--r-1`…`--r-4`. |
| Glass surfaces | `--glass-bg`, `--glass-border`, `--glass-blur`, `--glass-shadow` for the overview's card grammar. |
| Accent | `--accent`, `--accent-soft`, `--accent-ring` for focus and selection. |

Two additions are needed and should be tokens rather than inline values, because
they encode meaning rather than decoration:

- **An observed/inferred distinction** on path edges, timeline entries and
  evidence rows. A dashed stroke plus a distinct border token, never colour
  alone — see §6.
- **A "not measured" hatch or texture** for a cell that has no value, so the
  state survives a screenshot in greyscale.

---

## 6. Accessibility

| Requirement | How |
|---|---|
| **Never colour alone.** | Every band, severity, source state, stance and observation mode carries a text label or a shape as well as a hue. Observed versus inferred must survive greyscale, so it is a stroke style, not a colour. |
| **Contrast.** | Body text at WCAG AA against its surface. `--fs-micro` is for chips only and never for a value a reader must read. |
| **Score and confidence are explained in text.** | Phase R requires accessible explanations for every chart legend, score and confidence value. The API already supplies the sentences: `score.dimensions[].detail`, `confidence_factors[].reason`, `gate_reasons[]`, `data_health.explanation`, `changes[].reasons[]`. Put them in the accessible name or an adjacent description, not only in a hover tooltip. |
| **Tooltips are not the only carrier.** | A tooltip-only explanation is unreachable by keyboard and by touch. Every "how this number was made" must also be reachable as expandable text. |
| **Landmarks and labels.** | Each panel is a `<section role="region">` with an `aria-label`, following the existing board pattern. |
| **Live regions.** | A not-measured or error state uses `role="status"` so a screen reader hears the reason when a refresh changes it. Do not announce every poll. |
| **Reduced motion.** | Every animation sits behind `@media (prefers-reduced-motion: reduce)`, as the rest of `styles.css` already does. A timeline scrubber must be usable without motion. |
| **Keyboard.** | The timeline scrubber, the evidence filter and the sub-tabs are all keyboard-operable with visible focus using `--accent-ring`. |
| **Tables.** | Real `<table>` semantics with a header row for the incident list, the evidence table and the coverage table. A grid of `<div>`s is not navigable. |
| **Numbers with units.** | A percentage, a millisecond value and a currency amount each carry their unit in the accessible name. `91.6` alone is not a fact. |

---

## 7. Two things the UI must not overstate

**The aggregation mode is `worst_weighted`, not an average and not a worst-of.**
Each dimension's per-subject points are folded as
`mean × 0.6 + worst × 0.4`, so nine perfect subjects and one dead one reads
`54` rather than `90`. A tooltip that explains the number as "the average across
your targets" would be wrong in the direction that matters, because the whole
point of the fold is that one dead subject stays visible. The per-observer modes
`worst_of` and `p95_of` exist in the vocabulary and are not emitted, because a
subject measured from one vantage has no second observer; do not offer a toggle
between modes the API does not produce.

**"Confirmed" is rare, and that is correct.** On every deployment today
`data_health.can_confirm` is `false`, so incidents read `suspected` or
`supported`. The UI must not compensate by styling either as if it were
`confirmed`, and must not bury the explanation. The Telemetry Confidence panel
exists precisely so that the operator learns *why* — one kind of instrument is
reporting — rather than concluding the product is timid.

The reason is the independence rule, not a missing source. No missing source is
marked `required` on any deployment today, so no gate reason ever names one; the
gate reasons an operator sees are about modality and observer count. Rendering
`missing_evidence` as though it were the blocker would point them at the wrong
fix.

---

## 8. What a client must not do

- Do not compute a score, a band, a confidence or a hop order client-side. All
  four are server-computed and the arithmetic must not be duplicated.
- Do not re-rank changes by timestamp. They arrive ranked by correlation, and
  reordering them by clock reverses the point of the feature.
- Do not filter out rejected hypotheses, contradicting evidence or missing
  evidence.
- Do not render `dangerouslySetInnerHTML` for anything derived from an AI
  answer. Assistant text is escaped React text only (CLAUDE.md §15 LLM02).
- Do not send a query parameter the API does not declare. Every handler refuses
  unknown parameters with a `400`, deliberately.
- Do not retry a `400`. It names what was wrong.

---

## Related

- [`dem-api.md`](dem-api.md) — the shapes every panel above binds to.
- [`dem-evidence-confidence.md`](dem-evidence-confidence.md) — what the factors and gate reasons mean.
- [`dem-domain-model.md`](dem-domain-model.md) — every field and its invariant.
- [`service-path-graph-contract.md`](service-path-graph-contract.md) §7 — the renderer contract for the experience path.
- [`frontend-redesign.md`](frontend-redesign.md) — the platform's visual grammar.
