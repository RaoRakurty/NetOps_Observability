# RCA Evidence Summary — replacing "Signals: 300" with evidence quality

Owner directive 2026-07-18. Status: **SHIPPED** (evidence summary + density bars + aside vocabulary — commits 649b2a83…f2e6015c; header "Affected" row 2026-09-02).

## 1. The problem

The incident summary today says:

```
Signals
300 tied to this case
(300 in window)
```

A "signal" is one raw telemetry observation (one probe failure, one syslog
pattern hit, one flow anomaly, one cloud event). A packet-loss probe on a
5-second cadence during a 20-minute outage emits 240 of them. The count is
technically true and semantically misleading: **NOC engineers read "signals"
as independent clues**, so 240 repeats of ONE symptom render as 240 pieces of
evidence. The UI exaggerates evidence quantity while saying nothing about
evidence *quality* — the exact opposite of what a Tier-1/2 engineer needs in
the first 5 seconds:

- Is this incident real?
- How confident is the system, and why?
- What independent evidence exists?
- What should I investigate first?

## 2. The four-layer mental model

| Layer | Definition | Example | Engine source (already computed) |
|---|---|---|---|
| **Observation** | one raw telemetry event | one probe failure | `corr_signals` rows (`Signal`) |
| **Symptom** | one distinct manifestation | packet loss on path A→B | distinct `kind`(+scope) groups in the object |
| **Evidence** | independent cross-source confirmation | loss + BGP flap + HTTP 5xx | `verdicts.py coverage()`: `modality_coverage`, `observer_coverage`, `independent_pair`, `trusted_modalities` |
| **Root cause** | most probable causal event | core router BGP instability | top hypothesis + `possible_cause` (cause-honesty, #113 pt 4) |

Nothing new is detected. **Every number in this design already exists in the
engine** — the verdict logic has never treated 300 repeats as confirmation (a
`confirmed` tier requires a mutually-independent cross-modality pair). This is
a render-contract change: surface the reasoning the engine already does.

### Why this hierarchy earns operator trust

Operators trust what they can interrogate. "300 signals" is a black-box count;
"4 symptoms, 3 independent sources" is an argument with named parts — each line
answers a question an engineer would ask next, and each expands into the raw
rows behind it. Trust also survives the *negative* case: when there's one
symptom from one source, the summary honestly reads weak ("1 symptom · 1
source · suspected — single-modality, cannot confirm"), which is exactly when
an engineer should be skeptical. A layout that can only look impressive is
advertising; one that can look weak is instrumentation.

### Why repetition raises confidence but is not independence

240 repeated probe failures prove **persistence** (the condition is real and
ongoing, not a blip — sustained duration is an input to the promotion gate) and
**freshness** (still failing 20 s ago). They cannot prove **breadth**: a broken
probe target, a bad vantage point, or one flapping interface produces the same
240 rows. Independence comes only from *different failure physics agreeing* —
an active probe, a routing-plane event, and a passive user-experience metric
have no shared failure mode, so their agreement is information. The engine
encodes this (probes "support, never confirm"); the UI must render repetition
as *density over time* attached to a symptom, never as a count seated next to
"evidence".

## 3. Terminology decision

| Term | Verdict | Rationale |
|---|---|---|
| **Symptoms** | ✅ UI headline | matches operator language ("what's it doing?") |
| **Independent sources** | ✅ UI headline | says the thing that matters: independence |
| **Observations** | ✅ UI, de-emphasized | honest name for raw rows; "collected", not "found" |
| **Likely root cause** / "possibly because of X" | ✅ UI | matches cause-honesty wording (#113 pt 4) |
| **Evidence** | ✅ section title only ("Evidence Summary") | umbrella noun, never a count by itself |
| **Signals** | ❌ UI (keep internal) | the word that caused the misread; stays in engine/API/docs |
| **Events** | ❌ | collides with the cloud events feed + syslog events |
| **Measurements** | ❌ | implies metrics only; excludes logs/BGP |
| **Findings** | ❌ UI | already the correlation service's API noun; keep internal |

Rule: **a raw count never appears without its unit of meaning.** "300
observations" is fine; "300" next to a case title is not.

## 4. Compact incident card (NOC wall / list row)

```
┌──────────────────────────────────────────────────────────────────┐
│ ● SEV-1   Core router BGP instability — possible cause  [CONFIRMED]
│           edge-core-01 · middle-mile seam · Owner: TransitCo NOC │
│                                                                  │
│   4 symptoms   3 independent sources   22 min, ongoing           │
│                                                                  │
│   Packet loss      ████████████████████░░  since 14:02  ▶       │
│   BGP flaps        ██░░██░░██░░░░░░░░░░░░  since 14:03           │
│   HTTP 5xx         ░░░░████████████████░░  since 14:05           │
│   DNS timeouts     ░░░░░░██████░░░░░░░░░░  since 14:07           │
│                                                                  │
│   300 observations collected · last 18 s ago                     │
└──────────────────────────────────────────────────────────────────┘
```

- **Line 1**: severity dot, root-cause hypothesis (the *answer*), verdict badge.
- **Line 2**: where + who — seam + owner (#113 pts 1–2), the "act on it" line.
- **Line 3**: the three headline numbers. Large type. These ARE the evidence.
- **Symptom rows**: name + **time-density bar** (one bar = one symptom's
  observations bucketed over the case window; ink density = recurrence) +
  onset time. The 240-repeat problem becomes one saturated bar labeled
  "Packet loss" — repetition made visible without inflating anything.
- **Last line**: raw volume + freshness, smallest type, muted.

## 5. Expanded RCA view (drawer / report first section)

Extends the shipped "Incident at a glance" (#113 pt 2):

```
┌────────────────────────────────────────────────────────────────────┐
│ INCIDENT AT A GLANCE                                               │
│                                                                    │
│ Where      edge-core-01 (middle-mile seam) — on measured path      │
│ What       BGP session instability degrading customer app access   │
│            — possibly because of repeated BGP flaps at edge-core-01│
│            (unconfirmed until change-correlation completes)        │
│ Owner(s)   TransitCo NOC (possible — seam owner) · escalate: NetEng│
│                                                                    │
│ CAUSALITY PATH                 (broken segment in red)             │
│   app ──▶ lb-01 ──▶ fw-02 ══▶ ✖ edge-core-01 ──▶ cloud-edge ──▶ saas
│                                                                    │
│ EVIDENCE                                                           │
│ Verdict    CONFIRMED — independent pair: synthetic HTTP (probe)    │
│            + BGP state (routing plane) agree within 90 s           │
│                                                                    │
│   Symptom          Source        First    Last     Density (22 min)│
│   Packet loss      probes        14:02    18 s ago ████████████████│
│   BGP flaps        device/BGP    14:03    2 m ago  ██░░██░░██░░░░░░│
│   HTTP 5xx         synthetics    14:05    24 s ago ░░░░████████████│
│   DNS timeouts     resolver logs 14:07    9 m ago  ░░░░░░██████░░░░│
│                                                                    │
│ Evidence still missing: config-change feed for edge-core-01 (not   │
│ ingested) · NetFlow east of seam (no exporter)                     │
│                                                                    │
│ ▸ 300 raw observations (expand for source rows)                    │
└────────────────────────────────────────────────────────────────────┘
```

Key moves: the verdict line **names its reason** (which independent pair);
`evidence_missing` renders as first-class ("what would raise confidence"
— already stored per object); raw observations are the *last*, collapsed line.

## 6. Confidence: tier + reason, not a percentage

The prompt's mock shows "Confidence: High (94%)". **Deliberately rejected.**
The engine produces categorical verdicts (`undetermined / suspected /
confirmed`) from named structural facts (independent pair present, modality
coverage, contradictions). A percentage would be manufactured precision with
no calibrated model behind it — the exact "asserting false things" the
truthfulness epic removed, and it invites "why 94 and not 91?" during a SEV-1.
Render instead: **badge (tier) + one-line reason** ("confirmed — cross-checked
by 2 independent sources"). If calibrated probabilities ever exist (#67 P4
replay calibration), the percentage can return *with provenance*.

## 7. Visual hierarchy, color, iconography

Type scale (largest → smallest): verdict badge + root-cause line → the three
headline numbers (symptoms / sources / duration) → symptom rows → owner/path →
raw observation count (muted, collapsed).

Color: red = confirmed-broken only (path break, confirmed verdict accent);
amber = suspected/degraded; neutral gray = undetermined + all counts (a count
is not a health state); blue = links/actions. Never color observation volume.

Icons: ⛗ symptom-kind glyphs (loss/route/http/dns) on rows; ✓ only on the
independence line when a confirming pair exists; ▶ progressive disclosure.
Badges: verdict tier, seam owner class, "ongoing/recovered", promotion state
(#113 pt 3). No sparkline-everything: **one density bar per symptom** is the
only always-on visualization.

Progressive disclosure: card → drawer (per-symptom sources + missing
evidence) → raw observation table → full RCA document (promotion-gated).
Each level answers one question; nobody meets a 300-row table by accident.

## 8. Why this survives a SEV-1

Under pager stress, working memory collapses to ~3 items. The card gives
exactly three loaded numbers and one sentence of cause — an IC can read it
aloud on the bridge verbatim ("four symptoms, three independent sources,
22 minutes, confirmed, likely BGP at edge-core-01, TransitCo owns the seam").
Tier-1 gets "is it real" (verdict + why); Tier-2 gets "what first" (top of
causality path + densest earliest symptom); the executive gets the same card
and no percentage to argue with. Nothing requires scanning a table before the
first decision, and nothing shown is un-expandable — speed *and* audit.

## 9. Implementation map (when approved)

| UI element | Source (exists today) |
|---|---|
| symptoms count/rows | distinct `kind` groups over object signals (`buildRcaReport` SignalSummary) |
| independent sources | `verdict.modality_coverage` / `observer_coverage` / `independent_pair` |
| duration / ongoing | object window + `*_clear` recovery state |
| density bars | bucket per-symptom observation timestamps (new, render-only) |
| verdict + reason | `verdict_tier` + `verdict.reasons[]` |
| possible cause / owner / path | shipped #113 at-a-glance fields |
| evidence missing | `corr_objects.evidence_missing` |
| raw count (collapsed) | today's SignalSummary count |

Surfaces to change: `rca_report.go` (+`_html`) evidence section, workspace
`RcaWorkspace`/`rcaCase.ts` aside, Correlations list card. No engine change;
one new render-side bucketing helper + tests per §11.
