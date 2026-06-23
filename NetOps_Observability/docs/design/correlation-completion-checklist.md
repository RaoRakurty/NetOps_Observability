# Correlation Engine — Completion Checklist (the path to "100% as designed")

Correlation is the product's crux. This is the **grounded, evidence-backed** list of what
"100% complete" means — derived from a 2026-06-23 audit of the design (`correlation-engine.md`
§2–§6) against live code + the running system (NOT brainstormed). Companion to `ROADMAP.md`.

**Definition of "100% complete":** the engine realizes its design's **core guarantees**
AND **covers the fault classes that matter**. Two things are *consciously excluded* from
the 100% bar (documented decisions, not omissions): the §4.2 **same-site / same-ASN**
grounding rungs (low value; adjacency covers the interior) and **G2b** (independence-aware
verdict gate for NAT'd traps; risk > value). Reviving them is a deliberate future choice.

We finish these **one at a time, to 100%** (impl → tests → live validation → docs → commit).

---

## ✅ DONE — verified solid (the foundation; don't re-audit without cause)

These were checked against code + live data and are complete + tested:
- **Canonical Signal spine** — all mandatory fields (observer block, modality, entity, clock) enforced by every producer; dead-letter on missing.
- **Episode detection** — two-sided CUSUM + onset uncertainty + clear hysteresis + frozen baseline.
- **Admission gate** — no edge without grounding; ungrounded pairs → gap-hints, never edges.
- **Edge weighting** — temporal × topo × reinforce, all three live, clamped, persisted.
- **Verdict gate** — ≥2 modality classes × ≥2 independent observers + trusted-witness + per-signature required-modalities; the independence model (observer/authority/fate). 100% to spec.
- **Discriminators / competing hypotheses** — `else_prefer` firing, fixture-validated.
- **Honesty invariants** — `undetermined` first-class, `evidence_missing` mechanically derived, rank≠verdict orthogonal.
- **Versioned snapshots + quiesce-close**, **replay determinism** (engine_version pin + golden fixtures, CI-gated), **tenancy isolation** (per-tenant windows, mixed-tenant rejected).

---

## ⛏ TO 100% — nail these one at a time, in this order

### C1 · Object MERGE  ✅ *(DONE 2026-06-23)*
**Was:** MISSING — overlapping incidents emitted as separate objects (split-brain). **Done:**
`find_merges` (pure, deterministic) in `engine.py` + wiring in `engine_cycle` — a stale open
object that overlaps a live one this cycle (Jaccard(entity_ids) ≥ 0.4 + window overlap) is
tombstoned `state='merged'` + `merged_into=<survivor>`. **Replay-safe by construction:** only a
lifecycle state + backlink, never a re-key/re-rank (which would breach the §4.2 grounding gate
AND the replay contract) — per-object replay reproduces content unchanged. 5 unit tests
(coalesce / disjoint / below-threshold / window-overlap / determinism), full suite 161 green,
replay regressions pass, deployed live (engine clean). *Deferred refinement:* richer
content-union semantics + the §4.4 diameter≤6 guard (current rule = entity-overlap + window).

### C2 · #76 engine-side internal-stack exclusion — verify + close  ✅ *(DONE 2026-06-23)*
**Was:** PARTIAL. Verified live a real leak — object `29b66970` (`prober->netbox` + `api->netbox`)
showed internal self-monitoring *formed a correlation object*: the `DEBUG_ONLY` classification only
gated the **verdict**, not **object formation** (contradicting verdicts.py Decision #1: "debug_only…
never open, attach, or contribute"). (No non-probe internal signals exist today — verified — so the
leak was probe-only.) **Done:** `buffer_signal` now drops `probe_authority == 'debug_only'` at the
single window-entry chokepoint — the signal stays searchable in `corr_signals` (Debug view intact)
but never enters object formation. Replay-safe (run_window unchanged; archive sliced from the window).
+2 tests (debug_only excluded / low-authority still buffers); 163 suite green; deployed + live-verified
(0 internal objects forming, customer objects unaffected, 0 errors).

### C3 · Degradation markers (storm-mode + stale-topology)  ✅ *(DONE 2026-06-23)*
**Was:** PARTIAL — degradation undeclared + no stale w_topo cap (§8 honesty gap). **Done:**
`_topology_stale` (seam/links mtime age > `CORR_TOPO_STALE_S`) + storm detection (buffer ≥90% of
maxlen) computed per cycle in `engine_cycle`, threaded into `run_window`. Stale → `build_edges` caps
`w_topo ≤ w_topo_stale_cap` (0.4, a new EngineConfig tunable → auto-bumps the engine-version pin, so
replay reports the change honestly). Both flags are **declared** on the snapshot, embedded in the
grounding-context blob — but **only when degraded**, so a healthy object's blob (hence content_hash +
replay pin) is byte-identical to pre-C3 (no churn/drift). `replay.degradation()` rehydrates the flags
→ a degraded object replays under the same flags (deterministic). 4 tests (cap / healthy-blob-unchanged
/ degraded-declares / transition-versions); 167 suite green; deployed + live-verified (0 false
positives on the healthy stack, healthy blobs unchanged). *Deferred nicety:* per-edge `[STALE_TOPOLOGY]`
text note (object-level declaration + capped w_topo already make it auditable).

### C4 · G4 — OSI causal-layer enrichment + layer-stack UI  🟠 *(research-gated — pass running)*
**Status:** coarse today (entity-type layer prior). Per-signal `osi_layer`/`causal_layer`; per-kind
layer in direction inference; layer coverage in evidence; same-layer-duplicate confirmation guard;
RCA Layer-Stack panel (root→symptom→impact). **Gate:** the competitive research pass (in flight)
decides what meets/exceeds the market bar before coding. **100%-done =** research diff recorded →
engine + UI shipped → existing confirms still pass.

### C5 · Catalog + signal coverage — VLAN / STP / HSRP-VRRP / MAC / firewall  🟠 *(the big coverage axis)*
**Status:** PARTIAL — 10 signatures; ~15 distinct kinds. Grounding is protocol-agnostic & done, so
each new family = Layer-2 signal kind (collect+normalize) + Layer-3 signature dict + fixture (the
three-layer model). Missing fault classes: VLAN misconfig, STP topology/loop, HSRP/VRRP failover,
MAC-move/flap, firewall/policy-drop, dedicated IGP (OSPF parser exists but no lab events). **Owner-gated**
in part (multi-vendor collection, #73). **100%-done (per family) =** canonical kind in `producers.py`
+ signature + CI fixture + live validation. Sequenced under #73.

### C6 · passive_flow modality  ✅ *(DONE 2026-06-23)*
**Was:** MISSING — `handle_flow` a stub; the 4th modality absent. **Done:** the passive_flow lane is
wired end-to-end. `flow_sample` (pure) extracts `(sampler, sampler:ifN, bytes×rate)` from a flow
record (bus field-name variants; honest `sampler:ifIndex` entity — production resolves `device:ifName`,
same seam as G2). `handle_flow` cheaply **aggregates** per-interface volume (firehose-safe: O(1)/flow,
no signal-per-flow); `_flush_flow_aggregator` feeds each per-interface byte-rate through the **existing
CUSUM** each engine cycle → `flow_volume_anomaly` `passive_flow` episodes (provenance: `Source.FLOW` /
`PASSIVE_FLOW` / `FLOW_EXPORTER`). `feed_episode_detector` parameterized for provenance + returns
whether it emitted (honest counters on `/healthz`). **Live-validated on real tgen traffic** (~60–74k
flows processed, 5 interface entities aggregated, flush error-free) — the *anomaly→signal* emission is
unit-proven (`test_flow_volume_episode_carries_passive_flow_provenance`: baseline→spike), since a live
volume anomaly needs a multi-minute CUSUM baseline. +3 tests; 170 suite green; deployed; tgen stopped
after validation. *Future catalog growth (not C6):* DDoS / top-talker-shift / port-scan signatures on
top of this volume series.

### C7 · Direction inference — topology up/down vote  ⛔ *(BLOCKED on a directed-topology input — re-audited 2026-06-23)*
**Status:** the topo up/down vote correctly **abstains** (2-of-3 → 2 available votes: onset + layer).
RE-AUDIT found it is **blocked, not merely unbuilt**: the engine receives only **undirected**
adjacency (`TopologyAdjacency` = unordered device pairs) and **role-ambiguous** seams (a seam is an
ownership *boundary*, not a causal *direction*). There is **no directed traffic-path topology** to vote
from. Live cost: ~46% of edges (`direction_basis="none"`, 445/957 in 3h) get no direction — notably
**same-layer cross-device (fabric) pairs**: when `_LAYER[a]==_LAYER[b]` the layer vote abstains, so
with no topo vote only onset remains (1 of 2) → direction never claimed even on clear onset.
**Building it now = speculative directional modeling** (the §4.3 design explicitly defers it; the
*research-before-implementing* rule applies to direction/scoring policy). **Unblock path (research-gated,
like G4):** a directed topology source — (a) **seam-anchored tier inference** (BFS hop-distance from
seam egress → "deeper = upstream"; derivable but a heuristic that assumes north-south traffic and
breaks on east-west fabric — validate first), or (b) export **BGP-LS SPF / IGP link direction** to the
engine. The 2-of-3 design is safe meanwhile: a wrong topo vote can't force a false claim (it needs a
2nd agreeing vote), and the engine never claims direction it can't support.

### C8 · G2 trap entity_id canonicalization — finish the lab/NAT remnant  🟡
**Status:** PARTIAL. G2a shipped the production path (sysName/agent-addr/source-IP + ambiguity guard,
zero-regression); the lab's v2c-over-NAT traps still carry source-IP ids. **100%-done =** a path that
canonicalizes the lab case (or an explicit, documented "not recoverable under this NAT" with the
production path proven). Note: deeper independence handling = the consciously-excluded G2b.

### C9 · P4 — replay-driven calibration  🟢 *(maturity, not a blocker)*
**Status:** constants are deterministic defaults (`tau`, floors, thresholds, weights). Design defers
tuning to P4 (replay over labeled incidents). **100%-done =** calibration harness + re-fit constants
with the config-hash bumped, replay-clean.

---

## ✖ Consciously NOT in the 100% bar (documented decisions)
- **§4.2 same-site / same-ASN grounding rungs** — low value; adjacency covers the interior; no input feeds them.
- **G2b independence-aware gate for unresolved traps** — regression risk > value; lab can't validate.

(Both remain documented in `correlation-engine.md` §4.2 + the grounding-foundation memory; revivable.)

---

*Derived from the 2026-06-23 design-vs-implementation audit. Update an item's status in the
SAME commit that changes it (one-topic-to-100% discipline). Next review: when C1 closes.*
