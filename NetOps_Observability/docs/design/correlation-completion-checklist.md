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

### C7 · Direction inference — topology up/down vote  🟢 *(UNBLOCKED — fusion complete; C7.1–C7.5 DONE incl. routing SPF producer)*
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
>
> **C7.3 ✅ (DONE 2026-06-23)** — the NetFlow direction source, the first source to FIRE vote #2.
> `flow_direction.py`: a pure DirectedTopology source over directed per-device-pair volume —
> dominant direction wins (≥ `CORR_FLOW_DOMINANCE`, default 0.6), BALANCED → AMBIGUOUS (never an
> assumed direction — bidirectional honesty), no flow → UNKNOWN. `handle_flow` resolves each flow's
> src/dst through the C7.1 resolver (cached per mtime — firehose-safe) and accumulates a directed
> byte total; `engine_cycle` builds the per-tenant oracle (its volume ∪ global) and threads it into
> `run_window`, so vote #2 now directs **same-layer fabric pairs** the engine couldn't before.
> **Replay-safety (the crux):** a directed edge's orientation is EMBEDDED per snapshot
> (`grounding_context.orientations`) and replay reconstructs a `frozen_oracle` from it — direction
> never depends on live volume at replay time. This forced a latent fix: **adjacency grounding is now
> also embedded** (`grounding_context.adjacency`), so an adjacency-grounded fabric edge replays against
> the same links (pre-C7 it could not — seam-only objects were the only replay-safe ones). Both embed
> ONLY when used → seam/containment objects' blobs are byte-identical (no churn). `ENGINE_SEMVER`→2.2.0
> (replay honestly reports the logic change). +8 tests (source dominance/balanced/abstain, sample
> resolve-or-abstain, end-to-end fabric-pair direction, **replay determinism via the embedded
> orientation**, undirected-blob-unchanged); 201 Python suite green; ruff/mypy clean; deployed clean.
> **Live-validated on the clos lab** (deterministic, against real resolver data): a flow between two
> real device IPs resolves `→(dmz-fw, lan-sw1)`, the oracle returns A_UPSTREAM via netflow (conf 0.95),
> and balanced volume abstains. Live directed EDGES populate when real device-to-device flows run
> (tgen idle now; v1 coverage is src/dst→device — the in_if/out_if→neighbour fabric-transit refinement
> + a rolling/decay volume window are documented follow-ons).
>
> **C7.4 ✅ (DONE 2026-06-23)** — the active-path-trace source, **precedence-1** (measured beats
> observed). A traceroute/probe path is the measured forwarding path: hop order IS direction (an
> earlier hop is upstream). Go: `probe_paths_enrichment.go` exports ordered hop-IP lists
> (`probe_paths.json`) from the prober's Redis paths (mirrors the other enrichers; NOT tenant-tagged —
> hops resolve per-tenant downstream → zero-leak). Python: `path_direction.py` resolves hop IPs →
> devices via the C7.1 resolver and exposes the ordering as a Source — a-before-b → A_UPSTREAM
> (transitively), both orders seen (ECMP/loop) → AMBIGUOUS, else abstain. Wired FIRST in the oracle
> (before NetFlow). **Conservative v1 fusion validated**: when traceroute and NetFlow CONFLICT the
> oracle returns AMBIGUOUS (abstains) — a contradiction can never manufacture a false direction; when
> they AGREE the edge is directed and the highest-precedence source (traceroute) is recorded. Replay-
> safe via the same embedded-orientation mechanism. +6 tests (hop-order transitive, unresolved-hop
> drop, both-orders→AMBIGUOUS, end-to-end + replay determinism, conflict→abstain, agree→directed);
> 207 Python suite green; ruff/mypy/vet clean; deployed clean. **Live on the clos lab**: the exporter
> shipped **5 real measured paths**, the engine loaded all 5; the direction logic is proven on real
> device IPs (a 3-device path → dmz-fw→lan-sw1→lan-sw2 ordering, A_UPSTREAM conf 0.90). The current
> real paths are prober→external traces (8.8.8.8 / aws-tgw) traversing one known device each → honestly
> 0 device-to-device pairs (abstain); intra-fabric traces yield directed pairs when run.
>
> **C7.5 ✅ (DONE 2026-06-23, producer deferred)** — the routing (BGP-LS / IGP SPF) source,
> **precedence-3** (computed < observed < measured), completing the three-source fusion. The routers'
> SPF yields a directed forwarding DAG (each device's next hop toward every destination), covering
> backbone paths with neither a probe nor flows. `routing_direction.py` (pure): a Source over the
> forwarding set `{(upstream,downstream)}` — a→b only → A_UPSTREAM, both ways (transit) → AMBIGUOUS,
> else abstain. Wired LAST in the per-tenant oracle (`routing_direction.json` contract: `[{from,to}]`).
> Wired LAST in the per-tenant oracle. **The SPF PRODUCER is now BUILT** (was deferred): `bgpls_spf.go`
> — a pure, deterministic BFS-nexthop SPF (`forwardingPairs`) over the link-state graph: for every
> destination node, each node's next hop toward it is a directed (upstream→downstream) forwarding pair,
> exactly the "earlier hop is upstream" rule. (Hop-count for now — the BGP-LS parser doesn't yet extract
> the IGP-metric TLV; exact for a uniform-cost fabric, metric-weighting is a clean refinement.) The
> bgpls collector computes pairs from its merged LSDB (`buildRoutingPairs`, node names via the same
> `bgplsNodeName` as the links) and publishes them; `routing_direction_enrichment.go` exports
> `routing_direction.json`; the Python source consumes it. **Honest data status:** the BGP-LS LSDB is
> still **empty** (peer 172.40.40.21 isn't redistributing link-state — needs `distribute link-state` /
> an OSPF-LSDB source on the device), so the producer correctly emits `[]` and the source abstains — a
> safe no-op (the engine already directs via NetFlow C7.3 + traceroute C7.4). It activates the moment
> the LSDB fills. +5 Python tests (forwarding direct/both-ways/absent, drop-incomplete, **the full
> 3-source fusion**) +6 Go tests: 4 SPF (linear next hops, stub asymmetry, determinism, empty) **+2
> FULL-STREAM integration that GENERATE a synthetic BGP-LS LSDB through the real wire parser → RIB →
> buildRoutingPairs → SPF** — an OSPF (proto-3) line and an IS-IS leaf/spine slice (hostname-resolved +
> link withdrawal), asserting the directed pairs are correct. 212 Python + full Go suite green;
> ruff/mypy/vet clean. **The whole stream is validated without the lab:** the live fabric isn't emitting
> BGP-LS (cEOS won't originate IS-IS; the Cisco OSPF domain has no adjacencies — both diagnosed
> 2026-06-23), so correctness is proven by the generated-LSDB Go stream tests PLUS a cross-service check
> on the deployed stack — a generated fabric result written to the shared enrichment volume is loaded by
> the live correlation service and oriented correctly (a both-ways leaf↔spine link → AMBIGUOUS, the
> bidirectional-honesty behaviour; non-adjacent → abstain). Deployed `routing_direction_pairs=0`
> (empty live LSDB, abstaining honestly); activates the moment a real LSDB arrives (this lab's fabric if
> OSPF/BGP-LS origination is configured, or the owner's other labs).
>
> **C7 STATUS: vote #2 is LIVE.** The DirectedTopology oracle fuses three sources behind one seam
> (`_direction` changed once, in C7.2, and never again); direction is claimed only on a 2-of-3 agreement
> with the orientation embedded + replay-deterministic. Today it fires from NetFlow (C7.3) and
> traceroute (C7.4) when device-to-device data exists; the routing source (C7.5) activates the moment a
> BGP-LS SPF export lands. **Remaining follow-ons (not blockers):** the BGP-LS→SPF→`routing_direction.json`
> producer; the NetFlow in_if/out_if→neighbour fabric-transit refinement; a rolling/decay flow-volume
> window; and the precedence-based "trust measured over computed on conflict" fusion upgrade (today's v1
> conservatively abstains on any conflict).

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
