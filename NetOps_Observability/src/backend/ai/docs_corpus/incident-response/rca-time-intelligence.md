---
title: RCA Time Intelligence
sidebar_label: RCA Time Intelligence
sidebar_position: 5
description: Definitions and formulas for the incident time decomposition — what each phase metric means, how every timestamp is measured, and what honestly stays unknown.
---

# RCA Time Intelligence

RCA Time Intelligence decomposes **every incident into measured time phases** — detection, correlation, root-domain isolation, owner identification, evidence readiness, acknowledgement, mitigation, recovery, resolution — so you can see exactly *where time was saved or lost*.

Two things it deliberately is **not**:

- It is **not an "MTTR dashboard"**. MTTR is never shown as one ambiguous number; it is split into phases with separate clocks (recovery is not resolution, acknowledgement is not detection).
- It never claims credit it can't prove. Every timestamp is **source-attributed** (observed, inferred, ITSM, user-entered), and a phase whose start or end was never observed renders as **incomplete, naming the missing event** — never a fabricated zero.

The hero metric is **MTTI — time to isolate**: how long from the first signal until Correlix identified the likely root domain, seam, and owner with evidence-backed confidence. That is the part of the incident clock Correlix itself shrinks.

## Where you see it

- **Per incident** — the **Time Impact** card on every incident's detail view (<kbd>Monitoring → Correlations</kbd>, open a row; see [Reading an incident](/incidents/reading-an-incident#step-4--read-the-time-impact-card)). It shows the lifecycle timeline, each phase's elapsed time, and the current bottleneck.
- **Across the fleet** — the **Recovery Scorecard** (<kbd>Monitoring → Recovery Scorecard</kbd>): percentile rollups (p50/p90/p95), the MTTI trend, MTBF and repeat rate, chronic offenders, and an owner-domain breakdown.

:::note Roles required
Reading time metrics and the Recovery Scorecard needs infrastructure read access. Supplying manual lifecycle timestamps needs infrastructure write access. Triggering a snapshot backfill is a platform-operator action. All reads are scoped to your tenant.
:::

## The lifecycle events, and where each timestamp comes from

Every metric is a difference between two **lifecycle events**. Each event's timestamp is taken from a specific source of truth and labeled with how it was obtained:

| Event | What it marks | Measured from | Source label |
| --- | --- | --- | --- |
| `impact_started` | True onset of user impact | Not directly observable. When absent, the calculator stands in the earliest customer-impacting signal — and flags the result **inferred**. An operator can supply the real onset. | inferred / user_entered |
| `first_signal` | Earliest signal onset in the incident | The correlation window's start (the minimum signal onset time) | observed |
| `detected` | When Correlix first saw the incident | The earliest ingest time of the incident's signals. Never earlier than the onset itself (clock-skew guard); when ingest time is unknown it falls back to the onset. | observed |
| `correlation_completed` | Signals grouped into one incident | The correlation object's persist time | observed |
| `root_domain_identified` | Root domain / seam isolated ★ | The persist time once the verdict reaches **suspected** or **confirmed** | observed |
| `owner_identified` | Responsible owner named | The same instant as isolation, when the top hypothesis names an owner — the owner is intrinsic to the grounded hypothesis, so its *timing* is flagged **inferred** | inferred |
| `evidence_ready` | Evidence policy satisfied | The persist time once the incident's missing-evidence list is empty | observed |
| `ticket_created`, `acknowledged`, `mitigation_started`, `mitigated`, `recovered`, `resolved`, `closed` | The human / workflow response | The incident's **ticket audit ledger** (see below), or operator-supplied timestamps | itsm / user_entered |

Each stamp also carries a **confidence** (0–1). Isolation, owner, and evidence stamps inherit the verdict's confidence; when the engine reports none, confidence floors at 0.5 — a grounded verdict never claims certainty it didn't have.

### Where the workflow timestamps come from (ITSM)

The human-response events derive from the incident's append-only **ticket audit ledger** — the same history you see on the [External ticket card](/incident-response/rca-ticketing#the-ticket-card-on-an-incident):

- Only **successful** audit entries count (a failed or retrying action did not move the ticket), and the **first** occurrence of each action wins — the instant that phase began.
- **Ticket created** and **Resolved** populate from Correlix's own ticketing worker the moment it files or resolves a ServiceNow incident. If the audit row is missing but a live ticket link exists, the link's timestamps stand in.
- **Acknowledged, mitigation started, mitigated, recovered, closed** populate from the inbound ServiceNow state sync, which polls each live ticket's current state and records a phase **only where ServiceNow provides a real timestamp** (work start, resolved/closed times, or the optional `u_correlix_*` custom fields for precise mitigated/recovered instants). No ServiceNow timestamp → the phase stays unmeasured.
- The workflow counts as **connected** once a ticket exists for the incident. Before that, the Time Impact card says so honestly instead of pretending a ticket phase is pending.

### Operator-supplied timestamps

Operators (infrastructure write access) can record the phases the platform cannot observe — impact onset, ticket created, acknowledged, mitigation started, mitigated, recovered, resolved, closed — directly on the incident. Three rules keep this honest:

- **Engine-owned phases are never editable by hand** — first signal, detection, correlation, isolation, owner, evidence. A human must not be able to fake the isolation evidence that MTTI and MTTC measure.
- **User-entered timestamps win** over derived ones for the same event, and are labeled `user_entered` in the timeline.
- **Every manual edit is audited** — who, which incident, which phase. Closing an incident additionally records a verification state: *verified clear* (recovery evidence confirmed), or an explicit, labeled override (*signal still present*, *recovery unobserved*, or *partial recovery*). There is no silent or free-text override.

## The phase metrics — formulas

All phases are computed from the lifecycle above. A metric is **complete** only when both its endpoints exist:

| Metric | Field | Formula | Notes |
| --- | --- | --- | --- |
| Time to detect | `ttd` | `detected − impact_started` | With no observed onset, impact is inferred from the first signal → flagged inferred |
| Time to correlate | `ttc` | `correlation_completed − first_signal` | Correlix's correlation speed |
| **Time to isolate ★** | `tti` | `root_domain_identified − first_signal` | **The hero metric (MTTI)** — first signal to evidence-backed root domain / seam / owner |
| Time to evidence | `tte` | `evidence_ready − first_signal` | Until the evidence policy is satisfied |
| Time to acknowledge | `tta` | `acknowledged − ticket_created` | Deliberately ticket→ack, **not** impact→ack |
| Time to mitigate | `ttm` | `mitigated − detected` | Impact reduced — not necessarily fully repaired |
| Recovery time | `ttr_recovery` | `recovered − impact_started` | User impact gone |
| Resolution time | `ttr_resolution` | `closed − impact_started` | Ticket closed, root cause documented — a **separate** clock from recovery |

Mechanics that apply to every metric:

- **Missing endpoint → incomplete metric.** The result names the missing event (e.g. *missing recovered*) and carries no duration. It is never rendered as zero.
- **Inferred inputs propagate.** If either endpoint was inferred, the metric is flagged `is_inferred`; its confidence is the *minimum* of the two endpoints' confidences.
- **Clock skew never yields negative time.** An out-of-order pair clamps to 0 rather than reporting a nonsense negative duration; the source and confidence labels carry the uncertainty.
- Every result records its `calculation_version`, so a formula change never silently mixes with old numbers.

## The current bottleneck

Alongside the metrics, each incident reports its **current bottleneck** — the *earliest lifecycle phase that has not completed*, walked in order. It is phase-consistent by construction: a later phase (say, provider repair) can never be blamed while an earlier one (evidence, ticket, acknowledgement) is still unmet.

| Bottleneck | Meaning |
| --- | --- |
| `root_isolation` | Root domain / seam not yet isolated — correlation still localising the fault |
| `owner_assignment` | Isolated, but no owner named yet |
| `evidence_bundle` | Evidence bundle not yet ready |
| `workflow_not_connected` | Everything Correlix measures is done; ticket / recovery / closure need ITSM or operator workflow evidence — a **visibility gap, not a process failure** |
| `ticket_creation` | Evidence ready; waiting for the ticket |
| `acknowledgement` | Ticket filed; waiting for acknowledgement |
| `provider_repair` | Acknowledged and the isolated seam is provider-owned (ISP, carrier, cloud, SaaS, SD-WAN, colo) — the provider repair clock is the limiting phase. Reported **only** after isolation, evidence, ticket, and acknowledgement |
| `mitigation` | Acknowledged; mitigation in progress (non-provider owner) |
| `recovery` | Mitigated; awaiting a service recovery signal |
| `closure` | Recovered; waiting for ticket closure |
| `resolved` | Closed — no open bottleneck |

The Recovery Scorecard's **Top time-loss driver** is the most common bottleneck across the window's incidents.

## Fleet rollups — the Recovery Scorecard

The scorecard aggregates per-incident decompositions over a window (7/30/90 days):

- **Percentiles first.** Every phase shows p50 (the normal case) and p90/p95 (the long tail); the mean is secondary only — averages hide the tail that actually hurts the NOC.
- **Customer-impacting by default.** Incidents whose object is Correlix's own stack (platform self-monitoring) are excluded unless you switch on *Include internal/platform events*. The footnote always states which view you're seeing.
- **Owner domains.** Each incident is classified ISP / LAN / SD-WAN / Cloud / App / Internal Platform / Unknown from the engine's seam owner, and the breakdown table shows per-domain incident counts, MTTI p90, recovery p90, repeat rate, and top time-loss driver.
- **MTBF (repeat failure interval)** — the mean gap between successive incidents on the *same object*. The object identity is the most specific stable key available (root entity → seam → device → interface → app path → provider → failure signature). Merged/suppressed child incidents and planned maintenance are excluded; only objects with ≥ 2 qualifying incidents contribute. Shown as *No repeats yet* until a repeat exists.
- **Repeat rate** — the fraction of qualifying incidents whose object failed more than once in the window.
- **Chronic offenders** — objects with ≥ 2 unplanned incidents, ranked by incident count (ties broken toward the more frequent, i.e. smaller MTBF), with last-seen time and dominant owner domain. The answer to "which circuit keeps failing".
- **MTTF** applies to **non-repairable assets only** (optics, modules, circuits explicitly marked non-repairable) — never to logical services. Without asset birth/install times a lifetime cannot be computed, so Correlix reports the count of failed non-repairable assets and **never fabricates an MTTF duration**.
- **Filters**: owner, provider, device, and failure signature scope every rollup, trend, and offender list.

Two honesty limits specific to the fleet view:

- **Detection time (`ttd`) is per-incident only.** The fleet path has no per-object ingest measurement, where detection would falsely read as zero — so `ttd` is excluded from rollups and shown only on the incident's Time Impact card, where it is truly measured.
- **Workflow phases roll up only once their evidence exists.** Acknowledgement, recovery, and resolution percentiles populate from incidents that actually carry ITSM or operator timestamps; until then the scorecard shows *Not measured — recovery evidence not connected* or *Not available — ITSM workflow required* rather than inventing numbers.

## Snapshots vs. live scan

Where the scorecard's numbers physically come from matters for what you see:

- **Snapshots (the normal case).** A background worker recomputes every incident's time decomposition on a cycle (every 15 minutes by default, 30-day lookback) and persists one durable snapshot per incident. Rollups read these snapshots — they survive the hot store's retention window, are deduplicated to one row per incident (a calculation-version bump never double-counts), and are bounded at the most recent **20,000** incidents per window. The API reports `source: snapshots`.
- **Live scan (cold start only).** On a fresh install or before the first backfill pass has run, rollups fall back to deriving directly from the most recent **5,000** correlation objects. The API reports `source: live_scan`.
- **Capping is disclosed, never silent.** If a window holds more incidents than the bound, the response sets `capped` with the applied `scan_cap`, and the scorecard footnote reads *"Large windows use the most recent N incidents"* — the older excess is excluded, and you're told so.

The per-incident Time Impact card is not affected by any of this: it always derives live from the incident's own record, ticket ledger, and manual events.

## What renders as unknown or not measured — and why

| You see | Why |
| --- | --- |
| A phase row reading **Not measured** | No ITSM or operator-workflow evidence is connected for that phase — a visibility gap, not a process failure |
| **Inferred** tag on a timestamp | The stamp was derived (impact onset from first signal; owner timing at the isolation instant), not directly observed |
| An incomplete metric naming a **missing event** | One endpoint never occurred or was never observed; no duration is invented |
| **Insufficient evidence** on MTTI cards | Not enough incidents in the window reached an evidence-backed isolation |
| **No repeats yet** on MTBF | No object failed twice in the window — MTBF needs at least two incidents on one object |
| An MTTF count but no MTTF duration | Asset birth times are unknown; a lifetime would be a fabrication |
| *"Large windows use the most recent N incidents"* | The window exceeded the snapshot (20,000) or live-scan (5,000) bound; capping is disclosed |
| Internal/platform incidents absent | The default view is customer-impacting only; use *Include internal/platform events* to widen it |

## Troubleshooting

- **The scorecard is empty or much smaller than expected.** On a fresh install the first snapshot backfill hasn't run yet (it runs on a 15-minute cycle); until then a bounded live scan serves the window. A platform operator can trigger a backfill pass immediately.
- **Recovery and closure columns never populate.** Those phases require ITSM evidence ([connect ServiceNow](/incident-response/integrations#servicenow) and enable [RCA Auto-Ticketing](/incident-response/rca-ticketing)) or operator-entered timestamps on the incident. Correlix will not guess them.
- **Acknowledged/mitigated timestamps missing even with tickets flowing.** Ticket create/resolve come from Correlix's outbound worker; the granular human phases arrive via the inbound ServiceNow state sync and only where ServiceNow records a real timestamp (work start, resolve/close, or the `u_correlix_*` custom fields).
- **MTTI looks identical to correlation time.** In the current engine, correlation and isolation are grounded together, so MTTC tracks isolation closely — expected, not a bug.

## The result

One incident clock, split into phases you can act on: proof of how fast detection → correlation → isolation ran, and an honest account of where recovery waited — on evidence, on a ticket, on an owner, or on a provider's repair clock.
