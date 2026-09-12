# Phase A — P-027379 before-state audit (evidence accounting + coverage)

Case: display `P-027379` = correlation `02737923-1f7a-57a2-ae88-6d650c608b51`,
tenant `global`, state merged, verdict **confirmed 1.0**, plane_count 2,
window `2026-07-15 20:20:33 → 20:32:21 UTC` (11m48s = 708s), hypothesis
`sig.ent.cloud.ipsec-tunnel-down`. All values below derived from live stored
records (ClickHouse) + the actual report view model (`rca-report?format=json`),
2026-07-15 ~21:00 UTC. No code changes in this phase.

## 1. Every rendered number — layer, origin, records behind it

| Rendered | Value | TRUE layer | Origin (code) | Records verified |
|---|---|---|---|---|
| "4 observers" (p.1) | 4 | observers of ATTACHED anomalies | `anomObservers` map, `rca_report.go:826-829` | {prober, lan-vantage-1, api, ipsec:lab-vpn-edge} |
| "6 independent observers" (p.3) | 6 | observers of ALL window-slice signals (not case-linked; NOT independence-deduped) | `observers` map `rca_report.go:817-819` → `UniqueObservers` `:291` → `signal_summary.unique_observers` | adds device-telemetry + flow observer ids to the 4 above |
| Verdict gate pair | 2 | provenance-independent confirming sources | Python `verdicts.py` Witness model | ipsec:lab-vpn-edge × lan-vantage-1 |
| "147 total observations" | 147 | ALL lane observations in window slice | `signal_summary.total` = Σ lane totals | 5 device + 2 control + 13 flow + 127 active = 147 ✓ |
| "127 active-check observations" | 127 | active_probe lane total (incl. clears/OK) | `laneTotal["active_probe"]` | coverage lane row `observations: 127` |
| "124 failed check observations" | 124 | probe detector sub-summary (RTT/loss series) | `signal_summary.probe.observations/failed` | 124/124 failed |
| "8 tied to case" | 8 | case-linked normalized signals | `signal_summary.attached` | corr_current `signal_count=8` ✓ |
| "7 anomalous signals" | 7 | attached anomaly signals | `signal_summary.anomalous` | prober rtt×?+loss, lan rtt, api rtt+loss, ipsec status (per-kind grouping below) |
| "4 evidence groups" | 4 | canonical anomaly nodes | `signal_summary.evidence_group_count` | evidence edges connect 4 nodes: ipsec_tunnel_status, prober:rtt, lan-vantage-1:rtt, {api,prober}:loss |
| "4 recovery signals" | 4 | `_clear` kinds in window | `signal_summary.clears` | rtt_anomaly_clear rows |
| "Affected vantages: api, lan-vantage-1, prober" | 3 | probe-lane observer ids, unclassified | `signal_summary.probe.affected_vantages` + `scope.vantages` | `api` stamped `observer_type=vantage_agent` at ingest (misclassification, see §3) |

**Root defect confirmed:** every count is real at SOME layer; the report mixes
layers under one vocabulary ("observers", "observations") with zero
reconciliation. The independence-deduplicated number (2) appears only inside
the verdict-gate sentence.

## 2. Coverage before-state (rendered vs true math)

All four lanes render `availability: available`, **`coverage: full`** (from
`rcaLaneWindowCoverage` min/max-window test, `rca_report_wording.go:373`) and
device/flow render **`state: normal`** ("none tied to this case as anomalous").
True intervals against the 708s incident:

| Lane | Rendered | Actual window | Leading gap | Trailing gap | True overlap | Should read (per spec) |
|---|---|---|---|---|---|---|
| Device health | Available · Full · **Normal** | 20:22:31→20:31:47 | **1m58s** | **34s** | 556s = **78.5%** | Partial/Substantial · "No anomaly observed during available coverage" |
| Routing/link | Available · **Full** · Anomalous | 20:20:33→20:20:52 | — | — | **19s event** | Point-in-time/event-based · Anomalous event observed |
| Traffic flow | Available · Full · **Normal** | 20:20:50→20:30:08 | 17s | **2m13s** | 558s = **78.8%** | Partial/Substantial · Inconclusive for full incident |
| Active checks | Available · Full · Anomalous | 20:20:46→20:32:21 | 13s | 0 | 695s = **98.2%** | Substantial/Complete (13s leading gap shown) |

Internal-gap analysis and expected-cadence comparison (owner constraint 5) are
not computable in the render layer today — nothing stores per-lane cadence;
Phase C derives expected cadence from the observed inter-arrival distribution +
prober schedule config, and marks it `unknown` where genuinely underivable.

**Impact wording**: `counts_toward_confidence` already exists per lane
(device/flow=false, control/active=true — a real eligibility seed to build on),
but impact wording does NOT consume it: "Real-user impact: none detected"
renders despite flow's 78.8% coverage + 2m13s trailing gap, while the mgmt
summary contradicts it — the two renderers derive impact independently
(`rca_report.go:1003-1010` multi-class gate vs summary text path).

## 3. Observer classification before-state

`corr_signals` already carries `observer_type/observer_location/
observer_trust_domain/modality_class/collection_path` (good bones). Defects:
- `api` ingests as `observer_type=vantage_agent` — the API container is not a
  network vantage (wave #7 dropped its TRUST, not its TYPE).
- `prober` is a process identity; its attrs carry `agent_host=prober`,
  `vantage_type=private_location` — the registry must decide whether it is a
  distinct network origin from `lan-vantage-1` (they run on different hosts:
  lab host vs LAN vantage VM — genuinely distinct) — classification must be
  explicit, not name-inferred.
- No `unknown` kind exists; unclassified observers silently pass through
  (owner constraint 1: they must render as explicitly `unknown`).

## 4. Lineage inventory (what records CAN support)

| Layer | Lineage present today | Verdict |
|---|---|---|
| Raw path runs (`path_observations`) | `run_id` per execution (25 runs in window: 13 prober + 12 lan, all failed), `vantage_id`, method, status | ✅ execution/measurement counts derivable |
| Synthetic check results (api lane) | `execution_id` in attrs (wave #7) | ✅ |
| Derived anomaly signals (prober/lan RTT/loss) | NO execution linkage (z-score detector output: integral/peak over many runs) | ⚠️ independence via (observer_id, agent_host, modality, stream) provenance — NEVER execution_id (constraint 2 satisfied by design) |
| Evidence groups | anomaly-node edges in `corr_evidence` (signal_id all-zeros; node ids carry observer+kind) + hypothesis blob | ✅ groups enumerable |
| Independence | Python `verdicts.py` Witness model — different observer + no shared measurement infrastructure, fail-closed on co-location ambiguity | Initial read: design is sound and under-claims (good). FULL audit = first task of Phase B (constraint 3): verify co-location table covers api/prober same-host case + add regression tests before building on it |
| Configured tests | NOT stored historically (prober schedule config is current-state only) | ❌ for THIS case → render "unavailable (predates accounting model)" — constraint 4; derivable go-forward from schedule registry |
| Collector health history | not stored per-lane | ❌ legacy → `unknown` in coverage engine |

## 5. Layer reconciliation ladder (constraint 10 — before-state, hand-derived)

```
147 window-slice observations (all lanes)
 └─ 127 active-probe lane │ 13 flow │ 5 device │ 2 control-plane
     └─ 124 probe RTT/loss series measurements (all failed)
 └─ 8 case-linked normalized signals
     └─ 7 anomalous + (4 clears tracked separately)
         └─ 4 canonical evidence groups (ipsec-status, prober-rtt, lan-rtt, loss)
             └─ 4 anomaly observers → 2 provenance-independent confirming sources
                 └─ verdict gate: ipsec:lab-vpn-edge × lan-vantage-1 → confirmed
```
Today NO rendered artifact shows this ladder; Phase D adds it (customer-concise
+ operator-full).

## 6. STOP-CHECK (owner rule: stop if records can't support defensible accounting)

**PASS — proceed to Phase B.** The stored records support a defensible,
derivation-only accounting model at every layer except two named historical
gaps, both of which the approved constraints already prescribe honest handling
for: `configured_test_count` → "unavailable" on pre-model cases (constraint
4/9); collector-health history → `unknown` coverage dimension on legacy lanes.
No fabrication required anywhere.

## 7. Verdict-gate independence AUDIT (Phase B constraint 3 — DONE)

Full end-to-end read of the Witness independence model
(`src/correlation/verdicts.py` `Witness.independent_of` :96-109, `witness_of`
:144-177, `coverage` :215-303, `assess` :324-399) and its fate primitive
(`src/correlation/signals.py` `ProbeFate.shares_fate_with` :180-189,
`derive_probe_authority` :139-152). **Verdict: the gate is SOUND for its purpose
(gating `confirmed`); it under-claims rather than over-claims.** No confirming
defect found; one bounded residual is documented and mitigated by Phase B. The
four required behaviors are now pinned by regression tests
(`test_verdicts.py::test_audit_a…d`, green):

- **(a) same-host observers not independent.** `independent_of` returns False on
  equal `observer_id`, on shared measurement `authority`, and on shared `fate`
  (`shares_fate_with`: equal `agent_host` **or** `source_egress` **or**
  seam+target+schedule). api + prober stamped the same `agent_host` collapse via
  fate; and both are `active_probe`, so the cross-modality requirement
  (`a.modality != b.modality`, verdicts.py :255) makes them unable to form a
  confirming pair regardless — defense in depth. Test `test_audit_a…`.
- **(b) RTT + loss from one stream not independent.** Same `observer_id` →
  `independent_of` False at :102; `coverage` dedups to one witness. Test
  `test_audit_b…`.
- **(c) control-plane × LAN vantage IS independent.** Different observer,
  different modality, control-plane carries no fate key so the fate check is
  skipped (both-non-None guard, :106-108) → independent → `confirmed`. This is
  exactly the P-027379 pair `ipsec:lab-vpn-edge × lan-vantage-1`. Test
  `test_audit_c…`.
- **(d) absent co-location never fabricates a confirm (fail-closed).** Unknown
  `collection_path` collapses to one conservative authority bucket
  (`authority = f"unknown:{kind}"`, :167-169) → not independent; a lone
  low/unclassified probe lacks a trusted witness (`Witness.trusted` :87-94) →
  never confirms. Unknown provenance can only WEAKEN evidence. Test
  `test_audit_d…`.

**Residual (documented, not a defect):** the fate primitive is *subtractive* —
it removes independence when co-location is KNOWN (stamped `agent_host`/egress),
and treats two `None`-fate witnesses as independent (`_fate_of` :120-137, by
design). So two genuinely co-located sources of DIFFERENT modality that fail to
stamp `agent_host` would be deemed independent. This is a data-completeness gap,
not a fabrication: independence is anchored by observer + modality + authority
(all fail-closed on the unknown), with fate as a refinement. Phase B closes it
from both ends — the additive `observer_kind`/co-location ingest stamp
(`signals.py::classify_observer_kind`, `to_ch_row`) makes co-location knowable
go-forward, and the Go accounting layer re-derives the SAME fate relation
(`rca_independence.go::sourceProvenance.sharesFateWith`) so a shared
host/egress collapses api+prober into one independence group at read time even
for legacy rows.

**Misclassification note (a Go/presentation concern, NOT a gate defect):**
`verdicts.py` never reads `observer_type`, so `api`'s ingest mis-stamp
(`observer_type=vantage_agent`) does **not** affect the verdict — it only
corrupted the report layer's flat vantage list. Fixed structurally in Phase B by
the observer classification registry (`rca_observer_registry.go`), whose hard
rule bars `api`/collectors/workers from `logical_vantage` even against a policy
override (`TestAccounting_ApiNeverVantage`).
