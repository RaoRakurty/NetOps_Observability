# DEM roadmap — what shipped, what is contracts-only, and what comes next

Status: **as-built plus ordered plan, 2026-09-05.** The "shipped" column is a
statement about code that exists and is tested. The "next" sections are an
ordering proposal, not a commitment, and every open owner decision is listed in
§5 rather than resolved here.

Authority: `docs/design/DEM_2026-09-05.md` §M.10 (delivery) and §M.11 (open
decisions), plus `docs/design/dem-repository-assessment.md` §6.

---

## 1. What shipped in this slice

### 1.1 The causality domain (`internal/dem/experience`)

| Capability | State |
|---|---|
| Provenance on every fact, with observed / inferred / unknown / simulated and the eight-class privacy ladder | Built, validated at every boundary. |
| `EvidenceItem` with stance, modality class, observer, reliability and freshness | Built. Negative evidence is produced mechanically by the adapters, not curated. |
| `MissingEvidence` as a first-class record that lowers confidence and can block confirmation | Built. |
| The six-factor confidence maths, every constant exported | Built and table-tested to the decimal. See [`dem-evidence-confidence.md`](dem-evidence-confidence.md). |
| `Hypothesis` with `CANDIDATE → SUSPECTED → SUPPORTED → CONFIRMED / REJECTED`, mapped onto the correlation engine's verdict tiers | Built. The independence rule is the same one `src/correlation/verdicts.py` applies, written once in Go. |
| `JourneyDefinition` with branching, optional steps and loops; `JourneyHealth` composed multiplicatively | Built, persisted (PG migration `0044`, FORCE-RLS). |
| `ChangeEvent` normalizer over nine change types, plus `RankChanges` by correlation rather than clock | Built, persisted, immutable. |
| The published, decomposable, versioned, gated, banded experience score with `score-policy.yaml` and a strict closed-grammar reader | Built. Five application classes. Per-subject points are folded by `WorstWeightedMean` (worst subject at 0.4), and `aggregation` reports `worst_weighted`, which is what the arithmetic does. |
| Business impact rolled up only when it can be totalled | Built. `RollUpBusinessImpact` withholds the total across mixed currencies and returns the reason instead. |
| `ExperienceIncident` derived from evidence at read time, deterministically | Built. `Detect` is pure. |
| `RemediationAction` proposals with a mandatory verification plan, and a companion `investigate` action whenever the cause is unconfirmed | Built. Nothing executes. |
| `Verification` as a **plan**, never a claim of recovery | Built. |
| `SourceHealth` / `DataHealth` over the ten-source ladder, with coverage, anchor capability and confidence influence | Built. `CanConfirm` states the ceiling in one field. |
| `SyntheticDefinition` / `SyntheticRun` / `SyntheticReliability` / the coverage model | Built as contracts; `GradeReliability` and `BuildCoverage` are tested. |
| The AI investigator contract: closed packet, evidence-id whitelist, no-confirmation downgrade, redaction disclosure, own feature flag | Built. No provider call. |
| Eight aggregation routes, all tenant-scoped, all documented in OpenAPI | Built. See [`dem-api.md`](dem-api.md). |
| Nine self-observability counters | Built. |

### 1.2 Storage and wiring

- Migration `0044_dem_experience.sql`: `dem_journeys` and `dem_change_events`,
  both `ENABLE` + `FORCE ROW LEVEL SECURITY` with the `tenant_iso` policy.
  Additive, idempotent, and its rollback drops only those two tables.
- A file backend for both objects behind the same `Store` interface, keyed by
  tenant, which reports a corrupt file rather than starting silently empty.
- Wiring in `probe_handlers.go` inside the `DEM-EXPERIENCE-BEGIN/END` block, and
  eight route literals in `main.go`. No new root file.
- A cross-org isolation test at the router level
  (`src/backend/dem_experience_isolation_test.go`) and the store-level half in
  `store_test.go`.

### 1.3 The acceptance gate

The owner's Phase T scenario is encoded as `TestPhaseTAcceptanceScenario` and
passes: one incident, `CONFIRMED` transit hypothesis at 0.80 confidence across
three anchor modalities, the deployment `REJECTED` by the unaffected cohort,
RUM + synthetic + path evidence present alongside the contradictory backend and
cohort evidence, the affected hop referenced by its immutable observation id,
ownership attributed to the failing seam, a traffic-shift action with both a
rollback and a verification plan, and no claim of recovery. The full arithmetic
is in [`dem-evidence-confidence.md`](dem-evidence-confidence.md) §10.

---

## 2. What is contracts-only

Stated plainly, because a contract that is described as a capability is the
worst kind of documentation.

| Contract | What exists | What does not | Consequence today |
|---|---|---|---|
| `ExperienceEvent` | Shape, validation, pseudonymous-user discipline, actor types including `AI_AGENT`, `WebVitals`, `AgentContext`, external-schema fields | No route, no topic, no table, **no producer** | The `error_free_interaction` and `user_friction` score dimensions report `not_configured`. Affected users and sessions report as not measured on every incident. |
| `ExperienceSession` | Shape, validation, `ReplayRef` as a separate pointer field, health states with `unknown` as the default | Same | No session surface exists, and the owner's `/sessions` routes were not built. |
| `BusinessEvent` | Shape, validation, extensible `business_event_type` | Same | Business impact is computed from a journey's **declared** value per success, never from observed transactions. |
| `JourneyObservation` | Shape, validation, immutability rules, cohort and correlation handles | Nothing writes one | Journey health is computed from the bound targets' measured windows. There is no per-traversal view, no abandonment rate and no step-conversion funnel. |
| `SyntheticRun` | Shape, validation, `definition_version` pinning, reliability inputs | Nothing writes one | **Every check's reliability reads `unknown`.** `Assemble` passes an empty `Bundle.Reliability`, so `severityFor` finds no grade and treats the check as trustworthy: the flaky-check severity cap is wired and tested but cannot fire in production. That is tracker **253** and it is the right default — inventing a grade for a check nobody has measured would be worse than having none. |
| `EventSink` | The interface | No implementation | The ingest lane has somewhere to attach without changing any shape. |
| AI investigator | Packet builder, output schema, whitelist validator, downgrade rule, feature flag | No provider call, no route | `ai_investigator.available` is false unless both flags are on, and even then no route accepts a question. |
| `ExperienceIncident.IncidentID` / `Promoted` | Modelled | No promotion path | An experience incident never becomes a platform incident. |

---

## 3. The ordered next slices

### 3.1 Track T0 — the producers, in build order

This is the highest-value work, because it is the only work that lifts
`can_confirm` from false to true. Every one of these is a new function in
`assemble.go` plus the five registration points in
[`dem-architecture.md`](dem-architecture.md) §8.

| Order | Producer | Modality | Anchor? | What it unlocks | The hard part |
|---|---|---|---|---|---|
| 1 | **Flow-derived application response time** (client/server network latency, application latency, retransmits from flow records) | `passive_flow` | **Yes** | The second anchor class. `can_confirm` becomes true for any tenant with flow. `responsiveness` gains a source that needs no declared budget. | Mapping a flow record to an `app`/`site` scope that matches the journey's, and to an `Observer` distinct from the prober's. |
| 2 | **SD-WAN IPFIX per-tunnel SLA** (BFD loss/latency/jitter per tunnel per site; Cisco cleanest, Versa/Fortinet/Prisma via their APIs) | `management_plane` | No | Real `network_quality` per site, and `wan_overlay` / `last_mile` cause attribution with a named tunnel. | It is a controller's own summary, so it corroborates and never confirms. Do not be tempted to promote it. |
| 3 | **Wireless onboarding funnel + client metrics** (assoc → auth → DHCP → DNS, RSSI/SNR/retries/roams) | `management_plane` | No | `lan_access` and `client_endpoint` attribution, and the first real `user_friction` input. | The client id is PII the moment it becomes a label. It must be a per-tenant salted hash before it leaves the collector (`DEM_DATA_MODEL_2026-09-05.md` §5). |
| 4 | **Microsoft Graph `callRecords`** (Teams call quality per user, agentless) | `management_plane` | No | Real-time-class experience with no endpoint install. | Per-user data at `pseudonymous_user` class, and a consent posture that does not exist yet (§5). |
| 5 | **RIPEstat / CrUX** (Internet routing events; public-web field data as a global baseline) | `control_plane` (RIPEstat) / `public` baseline (CrUX) | RIPEstat yes | A third anchor class for transit hypotheses, and the only external baseline the product can honestly quote. | CrUX is a *baseline*, not an observation of this tenant. It must never be scored as evidence about the tenant's own users. |

**Do the first one first.** Everything else in this roadmap is more valuable
after a second anchor class exists, because until then every incident is capped
at `SUPPORTED`.

### 3.2 The `netops.experience` lane and the RUM snippet

The first-party browser RUM snippet is Tier 4 of the source ladder and the
producer that makes `real_user` — the only other anchor-capable class DEM
declares — real.

Sequence, and it matters:

1. Build the lane first (topic, Vector route, ClickHouse table in **both**
   `deployment/docker/clickhouse/init.sql` and `internal/chschema` +
   `ConvergeStmts()`, a **strict** row policy). The exact cost is
   [`dem-architecture.md`](dem-architecture.md) §5.3.
2. Implement `EventSink` against it.
3. Add `POST /api/dem/events` and `POST /api/dem/business-events`, bounded and
   authenticated.
4. Ship the snippet.
5. Add `real_user` to `ModalityClass` in `src/correlation/signals.py` **in the
   same change**, or the Go and Python graders will disagree about what
   "independent" means.
6. Only then add `GET /api/dem/sessions` and `…/{id}`, because only then is
   there something to list.

Retention on the new table must be set **per data class**, not inherited from
`customer_metadata` (§5).

### 3.3 Per-run synthetic records and real reliability grading

`GradeReliability` is written and tested and grades nothing, because the prober
publishes aggregate series. Making it real means:

1. The prober records one `SyntheticRun` per check per interval, with its
   vantage, outcome, retries and — separately — whether the **runner** failed
   rather than the target.
2. A bounded store for runs, with a retention horizon short enough that
   reliability is computed over a recent window (`MinRunsForReliability` is 10).
3. `Assemble` populates `Bundle.Reliability` instead of an empty map, at which
   point the flaky-check severity cap starts firing.
4. `POST /api/dem/synthetic-runs` for external runners, once there is an
   authenticated producer to accept it from. Accepting runs from an unmodelled
   producer would let a caller manufacture the reliability grade that gates
   incident severity.
5. `GET /api/dem/journeys/{id}/observations` becomes possible, because a run is
   half of a traversal.

### 3.4 Incident promotion into `internal/incident`

`ExperienceIncident.IncidentID` and `Promoted` are modelled and unwired.
`internal/incident` is the platform's Postgres+RLS system of record and
`Repo.Ingest` dedups by key, but **nothing promotes a correlation object into it
today** — the only caller is the alert engine's `ingestAlertIncident`. So this
slice is not "wire DEM to incidents"; it is "build the promotion path, and DEM
is its first user".

Design questions to answer first, none of which are settled:

- **What triggers promotion?** Automatic on `CONFIRMED`, automatic on a
  severity threshold, or an operator action. Automatic promotion on a derived
  object means the platform incident store gains a row whose evidence can change
  underneath it, which is exactly the drift the derive-at-read decision avoids.
- **What is the dedup key?** `IncidentID` is deterministic per
  `(tenant, kind, subject, window_start)`, so a degradation spanning two windows
  produces two ids. Promotion needs a stable key across windows, which the
  derived id is not.
- **What happens on recovery?** The platform incident has a lifecycle; the DEM
  packet does not.

### 3.5 The AI investigator's provider call

Both halves of the contract exist. What is missing is the middle:

1. `POST /api/dem/ai/investigate`, gated on `FEATURE_COPILOT` **and**
   `FEATURE_DEM_AI_INVESTIGATOR`, authenticated, audited.
2. An orchestrator in `ai/*` that builds the packet, calls the provider with a
   **server-controlled** system prompt, bounds the request and caps output
   tokens (CLAUDE.md §15 LLM04), and passes the answer through
   `ValidateInvestigation`.
3. Rendering as escaped React text with the attribution line always visible, and
   the `downgraded` flag shown when the model overreached.

The rule that must not be relaxed: the model never marks a cause confirmed, and
never gathers its own evidence.

### 3.6 Session replay and mobile

Deliberately last, and both need platform infrastructure that does not exist.

**Session replay** needs a recorder, a blob store with its own retention, an
access-control and audit path for a class of data more sensitive than anything
the platform holds today, and a redaction pipeline for form fields. `ReplayRef`
is a pointer field kept separate from every other session attribute precisely so
that an access check can be attached to it when there is something to check.
Nothing is recorded, stored or served today.

**Native mobile SDKs** need a published SDK, a versioning and deprecation
policy, and a crash/ANR model DEM does not have. `ActorType` and the cohort's
`device_type` / `network_type` dimensions are the extension points.

Neither should be built "to declare the feature complete". The owner's Phase S
is explicit about that, and the contracts are the deliverable until the
infrastructure exists.

---

## 4. Smaller items, worth doing before the big ones

| Item | Why |
|---|---|
| **The per-observer aggregation modes.** `AggWorstOf` and `AggP95Of` are declared and unused. They become meaningful only when a subject is measured from more than one vantage. | Not blocking. The tenant score already folds per-subject points correctly and says so (`worst_weighted`); the per-observer toggle is a Tier-3 site-prober feature, so it lands with that work rather than before it. |
| **Per-journey, per-app and per-site scores.** `ComputeScore` already accepts the subject kinds; only the tenant score is built. | The overview's hotspot breakdown is thin without them, and the incident's `score_ref` points at a journey score that is not computed. |
| **Change-feed adapters.** `ChangeEvent` and `POST /api/dem/changes` exist; nothing pushes config drift, cloud changes, BGP route changes or deployments into them automatically. | "What changed" is only as good as its producers, and the API's own empty-state note says so. This is the cheapest large win on the list. |
| **A `dem_experience_*` alert rule or two**, tied to the counters in `metrics.go`. | The nine counters are exposed and nothing watches them. `query_errors` rising against `views_served` is the signal that the surface is honest-but-blind. |
| **A `required` missing source that can actually fire.** `MissingFrom` marks a source blocking only when it is anchor-capable, configured, and has reported at least once. No adapter reaches all three today, so the branch is correct and unreachable. | Not a defect: it becomes reachable the moment a Track T0 producer reports and later goes quiet, which is exactly the case it exists for. Worth a note in the runbook when the first producer ships. |

---

## 5. Open owner decisions

Carried forward from §M.11 and from the assessment's §6, none of them resolved
by this slice.

| # | Decision | Where it blocks | Current behaviour |
|---|---|---|---|
| O1 | **`FeatureDEM` and the packaging unit.** §M.9 proposes synthetics + Tier-0 + the Experience overview in every tier; journeys + RUM + business events at Team; AI Investigator, desktop agent and replay at Enterprise. The unit is proposed as the monitored device (C4 rule) for network-side DEM and per monitored application for RUM. | The entitlement constant. `internal/entitlement`'s vocabulary is **CLOSED and LOCKED by the owner spec of 2026-09-04**; adding a value "takes an owner decision, not a diff", and §M.11 lists DEM packaging as open. Inventing the constant would pre-empt a decision the design itself defers. | DEM is gated on the `FEATURE_DEM` environment flag. No entitlement is consulted. **This is the decision that blocks shipping DEM as a priced capability.** |
| O2 | **Is Digital Experience the Operations landing for all tenants, or per-tenant?** | The nav. | It is a leaf, not the landing. |
| O3 | **First-party-only RUM?** | Whether the snippet may post to anything but Correlix, and whether third-party RUM data may be ingested at all. | No RUM exists. The design assumes first-party only. |
| O4 | **The endpoint-agent privacy posture.** What a desktop agent may observe, what it publishes about its own footprint, and what the operator can opt out of. | Tier 5 of the source ladder. | No agent exists. `agent` is on the source ladder reporting "no producer for this source is deployed yet". |
| O5 | ~~**Business-value currency handling.**~~ **CLOSED 2026-09-05.** The roll-up is withheld across mixed currencies rather than computed. | — | `RollUpBusinessImpact` returns no total and a note saying why; per-journey and per-incident figures stay correct and stay visible. A conversion policy remains a product question, but nothing incorrect is published while it is unanswered, so it no longer blocks shipping to a multi-currency tenant. |
| O6 | **Retention by data class** for the experience event lane, before it is built. | The ClickHouse TTL on `netops.experience`. §M.8 requires retention by class; the class is on every object; no store can apply a different TTL per class today. | Nothing is stored, so nothing is retained wrongly. |
| O7 | **Consent, residency and subject access** for user-level experience data. | The RUM producer and Graph `callRecords`. | No user-level data is collected. |
| O8 | **The sensitive-data-access audit hook.** §M.8 names the existing module as the control for replay and user-level data; nothing calls it because nothing reaches that class. | The first producer of `pseudonymous_user` data. | Must be added in the same change as that producer, not after it. |

---

## Related

- [`dem-architecture.md`](dem-architecture.md) — the extension points every Track T0 producer uses.
- [`dem-domain-model.md`](dem-domain-model.md) — the contracts that ship unpopulated.
- [`dem-api.md`](dem-api.md) §13 — the Phase D routes that were not built, and why.
- [`dem-privacy.md`](dem-privacy.md) — what must be true before user-level data is collected.
- [`dem-repository-assessment.md`](dem-repository-assessment.md) — the Phase A assessment these decisions were taken against.
- [`DEM_2026-09-05.md`](DEM_2026-09-05.md) §M — the design of record.
