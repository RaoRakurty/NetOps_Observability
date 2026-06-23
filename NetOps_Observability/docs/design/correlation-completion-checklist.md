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

### C4 · G4 — OSI causal-layer enrichment + layer-stack UI  ✅ *(DONE 2026-06-23)*
Research-cleared as **differentiating** (no leader ships an evidence-grounded cross-layer causal
stack — Dynatrace=app-deps, ThousandEyes=traceroute). **Engine half (prior):** `layers.py` — a per-KIND
causal-layer taxonomy (device→physical→link→network→transport→service→application, with OSI labels),
wired into the §4.3 layer-prior vote (finer than the old entity-type layer: it distinguishes L2
link from L3 routing on the *same* DEVICE entity, a tie the old vote couldn't break). Falls back to
entity-type when a kind is unmapped (backward-compatible). `ENGINE_SEMVER`→2.1.0 (honest replay pin).
**Decision — same-layer-duplicate confirmation guard REJECTED:** `local-link-fault` legitimately
confirms via two LINK-layer witnesses (control-plane link_state ⟂ device-telemetry interface-counter
on one link) — real corroboration, not duplication; the cross-modality + independence gate already
blocks true duplicates. **C4-UI DONE:** `ObjectSnapshot.layer_coverage()` — a pure projection of the
object's nodes to the full bottom-up ladder (every layer observed/not, per-layer kinds + entities +
peak severity, root→impact span, and UNMAPPED kinds surfaced not dropped). Stored in its OWN
`corr_objects.layer_coverage` column (idempotent `ALTER ADD COLUMN`) — NOT in the hypotheses blob, so
content_hash / the replay pin are untouched (no version churn; replay reproduces it deterministically).
Go `loadCorrSlice` SELECTs it + `rca_path_view.go` passes it through verbatim (engine owns the taxonomy;
the API never re-derives a layer). Frontend: a **Layer stack** block in the RCA Verdict Banner
(Topology Canvas → Investigate → pinned incident) — top-down L7→hardware, severity-tinted observed
dots, **Root/Impact** pills, and a **blind-spot** flag on any unobserved layer *between* root and impact
(the honest "what the evidence can't see" no leader surfaces). +3 Python +2 Go +3 vitest tests; full
suites green; ruff/mypy/vet clean; deployed + **live-validated** (object `a69a3c26` bgp-peer-flap →
`/rca-path-view` returns root=impact=Network/L3, severity high; multi-layer gap/blind-spot path
unit-proven, displays when a link⟂transport incident forms).

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
**Unblock = ARCHITECTED (2026-06-23, `docs/design/directed-topology-rca.md`).** Decision: a
**DirectedTopology oracle** — source-agnostic `orient(a,b)` fusing **measured > observed > computed**
direction (traceroute paths · NetFlow direction · routing SPF) with honest abstention — feeds vote #2;
the 2-of-3 safety stays intact. The tier-inference heuristic is REJECTED (the research shows leaders
use observed/measured direction, never inferred-from-undirected; it breaks on east-west fabric).
Keystone = a shared **EntityResolver** (IP→device, ifIndex→ifName — data already in discovery +
`ifNameMap`), which also closes G2. Sequenced: **C7.1** resolver · **C7.2** oracle + vote-#2 wiring
(buildable now, safe no-op until fed) · **C7.3** NetFlow source · **C7.4** traceroute source ·
**C7.5** routing source. Each plugs behind the oracle seam so `_direction` changes once.

> **Progress:** **C7.2 ✅** (`directed_topology.py` oracle + `_direction` vote-#2 wiring, prior).
> **C7.1 ✅ (DONE 2026-06-23)** — the EntityResolver foundation. Go: the SNMP metrics collector now
> publishes `ifIndex→ifName` to Redis alongside the existing interface-IP→ifName map; a new
> `entity_resolver_enrichment.go` exporter fuses those with discovery's mgmt-IP→device into
> tenant-scoped `entity_resolver.json` (mirrors `topology_links.json`: atomic, 60s, no-op without the
> shared volume). Python: `entity_resolver.py` — a pure, tenant-scoped `EntityResolver`
> (`device_for_ip` / `iface_for_ip` / `ifname` / `device_iface`); an unresolved OR **ambiguous**
> (same IP → two devices) endpoint returns None (abstain, never guess). `main.py` loads it mtime-cached
> + per-tenant (tenant rows ∪ global, never cross-tenant) + `/healthz` coverage. +8 Python tests
> (incl. the zero-leak tenant-scoping isolation test); ruff/mypy/vet clean; Go + 193 Python suites green.
> **Live-validated** on the clos lab: exported 10 devices / 36 iface-IPs / 144 ifIndexes; the engine
> resolves `172.40.40.41→dmz-fw`, `10.0.0.14→leaf4:Loopback0`, `(spine2,1073808128)→spine2:system0`.
> *Available to C7.3+ and the G2/C8 canonicalizer; not yet consumed (no source registered until C7.3).*
> **Next: C7.3** — register the NetFlow direction source on the oracle, resolving through this bridge.

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
