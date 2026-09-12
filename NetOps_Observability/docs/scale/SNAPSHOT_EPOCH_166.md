# Tracker 166 — the snapshot/drain epoch

**Date:** 2026-08-21 · **Branch:** `feat/observability-platform` · **Base:** `5d7d6892`
**Status:** design (Phases 1–3). Implementation follows this document, not the other way round.

The bounded-cohort scheduler is not the defect. Its *placement of preparation* is.
This document maps every calculation the cohort loop repeats, defines the epoch
that will own the ones that are safe to hoist, and states the invalidation rules
that make the reuse sound.

---

## Phase 1 — the repeated-preparation map

One `engine_cycle()` call == one cohort transaction. Everything below runs once
per **cohort** today. `W` = retained signals in the window, `N` = retained nodes,
`S` = seams, `L` = topology links, `G` = path-graph size, `E` = carried edges,
`K` = components, `C` = candidate pairs, `t` = tokens+refs per node.

### Caller-side (`main.py::_engine_cycle_inner`)

| # | Preparation | Site | Input | Complexity | Per cohort today | Safe once per epoch |
|---|---|---|---|---|---|---|
| 1 | `_prune_buffer` | `main.py:2045` | `WINDOW_BUFFER` | O(W) | yes | **Epoch boundary only** — it *is* the 165 retention mechanism; see §Phase 3.2 |
| 2 | `_flush_flow_aggregator` | `main.py` | flow aggregate | O(F) | yes | yes — epoch start |
| 3 | partition by tenant | `main.py` | `WINDOW_BUFFER` | O(W) | yes | **yes** |
| 4 | `_cycle_max_ts = max(...)` | `main.py` | `WINDOW_BUFFER` | O(W) | yes | **yes** |
| 5 | `pending_signals()` | `main.py:2325` | W × `_PROCESSED_IDS` | O(W) | yes | **yes** — compute once, partition into cohorts |
| 6 | `topology_links_by_tenant()` | `main.py:980` | link inventory | O(L) | yes | **yes** |
| 7 | `seam_inventory()` + tenant filter | `main.py:1144` | seams | O(S) | yes/tenant | **yes** |
| 8 | `TopologyAdjacency.from_links` | `engine.py` | links | O(L) | yes/tenant | **yes** |
| 9 | `resolve_path_order(probe_paths(), …)` | `path_direction.py:26` | probe paths | O(P) | yes/tenant | **yes** |
| 10 | `forwarding_pairs(routing_direction())` | `routing_direction.py:31` | routes | O(R) | yes/tenant | **yes** |
| 11 | `path_graph_inventory()` | `main.py:1189` | path graph | O(G) | yes/tenant | **yes** |
| 12 | `discovery_paths_for(tenant, pgv, window)` | `main.py:1347` | window + 4 feeds | O(W+G) | yes/tenant | **yes** |
| 13 | `_carried_edges_for(tenant, window)` | `main.py:2276` | window + edge cache | O(W+E) | yes/tenant | **split** — the `live` key set is O(W) once per epoch; the cache filter must stay per cohort (cohort *n−1*'s edges must be visible to cohort *n*) |

### Engine-side (`engine.py::run_window` → `build_edges` → `_candidate_pairs`)

| # | Preparation | Site | Input | Complexity | Per cohort today | Safe once per epoch |
|---|---|---|---|---|---|---|
| 14 | `sorted(window)` | `engine.py:1806` | window | O(W log W) | yes | **yes** |
| 15 | `build_nodes(sigs)` | `engine.py:1811` | sigs | O(W) | yes | **yes** |
| 16 | `identity_sigs` filter | `engine.py:1817` | sigs | O(W) | yes | **yes** |
| 17 | `for_tenant` + `PathIndex` | `path_graph.py:789` | path graph | O(G) | yes | **yes** |
| 18 | `cohort_idx` (keys → indices) | `engine.py:1838` | nodes | O(N) | yes | cohort-specific, but becomes O(cohort) with a key→index map built once |
| 19 | `toks/refs/declared/windows/devs` | `engine.py:869` | nodes | O(N) | yes | **yes — named target** |
| 20 | `seams_sorted`, `seam_evs` | `engine.py:874` | seams | O(S log S) | yes | **yes** |
| 21 | `seam_ident`, `seam_token` | `engine.py:877` | nodes × seams | **O(N·S)** | yes | **yes — largest single item measured** |
| 22 | `memb` (`paths.node_memberships`) | `engine.py:884` | nodes × path graph | **O(N·G)** | yes | **yes** |
| 23 | `route_hits` | `engine.py:887` | nodes | O(N) | yes | **yes** |
| 24 | candidate inverted index | `engine.py:820` | Σ(toks∪refs) | **O(N·t)** | yes | **yes — named target** |
| 25 | bucket sweep `for members in index.values()` | `engine.py:823` | all buckets | O(B) | yes | **partially** — needs a node→buckets reverse map so a cohort visits only its own buckets |
| 26 | seam groups | `engine.py:827` | seams × buckets | O(S·ev·b) | yes | **yes** (group *membership*; emission stays cohort-filtered) |
| 27 | `dev_index` | `engine.py:832` | nodes | O(N) | yes | **yes** |
| 28 | adjacency pair sweep | `engine.py:836` | links × dev buckets | O(L·d) | yes | **yes** to index; emission cohort-filtered |
| 29 | `obs_index` | `engine.py:845` | Σ memberships | O(N·m) | yes | **yes** |
| 30 | `routed` list | `engine.py:851` | nodes | O(N) | yes | **yes** |
| 31 | `work_sink` `fresh` accounting | `engine.py:982` | nodes × signals | O(W) | yes (profiler on) | **yes** |

### Genuinely per-cohort (NOT hoistable) — but two are super-linear

| # | Work | Site | Complexity | Note |
|---|---|---|---|---|
| 32 | candidate emission `_link` | `engine.py:797` | O(Σ&#124;bucket∩cohort&#124;·&#124;bucket&#124;) | genuine; **bounded by cohort × bucket size, not by cohort alone** — a hot token bucket is still a large term |
| 33 | scoring loop | `engine.py:1000` | O(C) | genuine |
| 34 | carried-edge union | `engine.py:1845` | O(N+E) | genuine (E grows with the estate) |
| 35 | `_components(nodes, edges)` | `engine.py:1566` | O(N+E·α) | genuine |
| 36 | `_fold_seam_bridged_components` | `engine.py:1702` | **O(K²·S)** | genuine but **quadratic in component count** — flagged as a separate defect |
| 37 | `comp_edges = tuple(e for e in edges if e.from_node in comp_keys)` | `engine.py:1866` | **O(K·E)** | genuine but **should be one bucketing pass, O(E)** — flagged as a separate defect |
| 38 | per-component ranking / verdict / attribution | `engine.py:1868+` | O(K·…) | genuine |

**Items 36 and 37 are new findings from this mapping.** They are not preparation
and cannot be hoisted into the epoch, but they are super-linear in state that the
carried-edge cache grows to ~384k entries, and they run once per cohort. They are
recorded here so the epoch fix is not credited with — or blamed for — their cost.

### Measured fixed cost (offline, this box)

Synthetic 1K-style estate, one tenant, 40 seams, no path graph. Times are the
snapshot-wide preparation only (items 14, 15, 19, 20, 21, 24, 27):

| retained nodes | sort | build_nodes | per-node | seam_ident/token | cand. index | dev_index | **fixed/txn** | ×8 cohorts |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 5,000 | 58 ms | 112 ms | 131 ms | 130 ms | 28 ms | 5 ms | **463 ms** | 3.7 s |
| 13,000 | 188 ms | 365 ms | 358 ms | 458 ms | 85 ms | 15 ms | **1.47 s** | 11.8 s |
| 25,000 | 306 ms | 677 ms | 751 ms | 846 ms | 254 ms | 23 ms | **2.86 s** | 22.9 s |
| 50,000 | 604 ms | 1,214 ms | 1,341 ms | 2,351 ms | 444 ms | 41 ms | **5.99 s** | **47.9 s** |

Prepared-state peak allocation at 50,000 nodes: **85.8 MiB** (this is the memory
the epoch will hold; see Phase 5 budget).

The live failing run retained 50–53k signals, so **≈6 s of pure re-derivation per
cohort, ≈48 s across 8 cohorts** is attributable to items 14–31 alone. That is a
real and sufficient reason to hoist them. It does **not** by itself account for the
observed ~150 s engine cycle — the remainder is items 32–38, which is why they are
mapped rather than assumed away.

---

## Phase 2 — the snapshot/drain epoch

### Definition

An **epoch** is one immutable retained-signal snapshot plus everything derived
purely from it, drained by one or more bounded cohorts.

```
  epoch_begin
    prune (165 retention)                       — the only mutation point
    flush flow aggregator
    freeze WINDOW_BUFFER  -> snapshot           — an immutable tuple
    partition snapshot by tenant
    per tenant: seams, adjacency, oracle, path index, discovery, nodes,
                prepared node metadata, candidate index         [ONCE]
    pending = snapshot \ processed_frontier
    while pending and cohorts < DRAIN_LIMIT:
        cohort = select(pending, COHORT_SIZE)   — tenant-fair round-robin
        per tenant: carried_edges refresh       [per cohort — see §3.4]
                    emit candidates for cohort  [per cohort]
                    score, form objects, persist
        advance frontier                        — only past the 160 boundary
        fairness yield
    discard prepared state
  epoch_end
```

### Ownership

The epoch owns, for its lifetime and no longer:

* the retained-signal snapshot (an immutable `tuple`)
* the per-tenant node tuple
* prepared node metadata (`toks`, `refs`, `declared`, `windows`, `devs`,
  `seam_ident`, `seam_token`, `memb`, `route_hits`)
* the candidate index and its reverse (node → buckets) map
* the per-tenant static context (seams, adjacency, directed oracle, path index,
  discovery paths)
* the pending list admitted to this epoch and its cohort partitioning

It does **not** own carried edges — those are process-lifetime state
(`_TENANT_EDGES`) and must be re-read per cohort.

### Explicit answers the directive requires

| Question | Answer |
|---|---|
| Do new arrivals join the current epoch? | **No.** Signals ingested while an epoch runs stay pending and are admitted by the *next* epoch. This is exactly the pre-166 semantics for arrivals (they waited for the next cycle) and it is what makes the snapshot immutable. |
| Semantic expiry during an epoch? | Pruning happens **only at epoch start**. Within an epoch, no signal is evicted, so no signal can expire mid-drain and no cohort can be scored against a window that shrank under it. The epoch must therefore be bounded in wall time — see the drain limit below. |
| Topology / seam mutation during an epoch? | Frozen at epoch start. A seam or link change landing mid-epoch is applied at the next epoch. `topology_stale` is likewise evaluated once and declared on every snapshot the epoch produces — the degradation declaration stays honest because it describes the inputs actually used. |
| Failure in cohort *n*? | Cohorts 1…*n−1* are already past their persistence boundary and their frontier advance stands. Cohort *n* does not advance the frontier, so its signals stay pending and are replayed by the next epoch. The exception propagates out of the drain loop; `engine_loop`'s existing handler logs and the loop continues. |
| Is prepared state safe after a retry? | Yes — the retry happens in a **new** epoch built from a fresh snapshot. Prepared state is never carried across an epoch boundary, so a retry can never see state derived from a window that has since changed. |
| When is prepared state destroyed? | At `epoch_end`, unconditionally, including on the exception path. It is a local, not a module-level cache; there is no process-lifetime growth. |

### Bounding the epoch

`CORR_ENGINE_DRAIN_COHORTS` (default 20) already bounds cohorts per drain. Because
pruning is now deferred to the epoch boundary, that bound also bounds how long
retention can be deferred. With the hoist in place a cohort is expected to cost far
less than the ~150 s observed, but the bound must be validated against the horizon:
**20 cohorts × cohort wall time must stay well inside the 516.527 s horizon**, or
evidence admitted at epoch start could expire before the next prune. This is a new
gate and is measured in Phase 9 and Phase 13.

---

## Phase 3 — immutability and invalidation

For each dependency: can it change during an epoch, and what do we do about it?

| Dependency | Can change mid-epoch? | Treatment |
|---|---|---|
| retained node set | Yes — the Kafka consumer appends to `WINDOW_BUFFER` concurrently | **Freeze**: the epoch copies `WINDOW_BUFFER` into an immutable tuple at epoch start. `run_window` already snapshots with `tuple(window)`; the epoch lifts that to the epoch boundary. |
| entity tokens / refs / device identity | No — derived purely from the frozen signal set; `Node` is immutable | **Freeze** (falls out of the above) |
| seam state | Yes — `seam_inventory()` reads mutable module state | **Freeze** at epoch start; invalidate at epoch end |
| topology links / adjacency | Yes — refreshed by the Go exporter | **Freeze** at epoch start |
| path graph / observations | Yes | **Freeze** at epoch start (`PathIndex` built once) |
| membership (`memb`) | No — pure function of frozen nodes + frozen path index | **Freeze** |
| tenant ownership | No — windows are single-tenant by construction and `run_window` refuses a mixed window | unchanged |
| scoring configuration (`EngineConfig`) | No — module constant | **Assert identity** in the reuse guard |
| carried edges | **Yes, by design** — cohort *n−1* adds edges cohort *n* must see | **Never frozen.** Re-read per cohort. |
| processed frontier | **Yes, by design** — advances per cohort | **Never frozen.** Re-read per cohort. |

### The reuse guard

Prepared state is reused only when it provably belongs to the current inputs. The
guard is **object identity**, not a content hash:

```python
prep.window is window and prep.seams is seams and prep.adjacency is adjacency
and prep.paths is paths and prep.cfg is cfg
```

Identity is O(1) and cannot produce a false positive: two different tuples are
never the same object, so a stale prep can never be silently accepted. A false
*negative* (a genuinely equal but distinct tuple) merely rebuilds — correct, just
slower. This is deliberately the conservative direction.

`build_edges` keeps its existing signature and behaviour when no prep is supplied;
the prepared path must be provably equivalent, not merely believed to be.

### Negative controls (required)

Invalidation logic that cannot go red is not invalidation logic. The following
must exist as tests and must fail if the guard is removed:

1. A prep built from window A, passed with window B, is **rejected** (rebuilt), and
   the result equals the unprepped result for B.
2. A prep built with seams S1, passed with seams S2, is rejected.
3. A prep built with adjacency A1, passed with A2, is rejected.
4. A prep built with path index P1, passed with P2, is rejected.
5. Mutating the guard to always-accept makes at least one of 1–4 fail (mutation test).

---

## What this does not change

Tracker 165's 516.527 s horizon, lateness floor, future-skew clamp, per-tenant
stream-time watermarks, co-partitioning gate, useful-evidence policy and RCA
degradation semantics are untouched. This is a placement change for pure
computation. Cohort size stays at 5,000 and the drain limit at 20 for the first
re-run, per Phase 7.

---

## Phase 1 addendum — what a bounded transaction ACTUALLY spends its time on

The prep table above measures preparation in isolation. To find out whether
preparation is the *dominant* term, one complete bounded-cohort `run_window` was
profiled under `cProfile` (14,000 nodes, 5,000-node cohort, 20 site-token buckets,
40 seams, no path graph). **Wall 124.97 s.** Top entries by cumulative time:

| Function | ncalls | tottime | cumtime | What it is |
|---|---:|---:|---:|---|
| `run_window` | 1 | 0.46 | **124.95** | whole transaction |
| `build_edges` | 1 | **21.48** | **83.71** | prep + emission + scoring |
| `_grounded` | **2,911,423** | 9.41 | 25.88 | **the cohort emitted 2.9 M candidate pairs** |
| `scoring.rank` | 10 | — | 20.72 | per-object ranking |
| `catalog.kinds` | 4,816,000 | 6.57 | 12.81 | clause matching inside `rank` |
| `_direction` | 2,077,933 | 6.19 | 12.43 | per-admitted-pair direction vote |
| `_fold_seam_bridged_components` | 1 | — | 4.60 | **O(K²·S)** fold |
| ↳ `engine.py:1739 <setcomp>` | 10 | **4.45** | 4.46 | `seam_ids` — **O(K·E)** edge rescan |
| `engine.py:1862 <genexpr>` | 2,077,943 | **4.12** | 4.12 | `comp_edges` filter — **O(K·E)** edge rescan |
| `_components` | 1 | 1.49 | 3.20 | union-find |
| `_candidate_pairs` | 1 | 0.11 | **3.28** | **index build + cohort linking — 2.6 % of the transaction** |
| ↳ `_link` | 1,040 | 1.75 | 3.12 | cohort-restricted emission |

### Three conclusions, stated against the evidence

1. **The candidate index is not the bottleneck it was believed to be.**
   `_candidate_pairs` in total is **3.28 s of a 125 s transaction (2.6 %)**, and the
   index build inside it is 0.11 s. Hoisting it is still correct — it is pure
   re-derivation paid once per cohort — but it will not on its own move the live
   number.

2. **The per-node preparation IS worth hoisting, and its cost scales with the
   retained window, not with the cohort.** Measured standalone at **5.99 s per
   transaction at 50,000 nodes** (§Phase 1 table) — ≈48 s across 8 cohorts on the
   live window size. That is real, recurring, and entirely removable.

3. **The dominant term at this candidate density is emission + scoring, not
   preparation.** 2.9 M `_grounded` calls in one 5,000-node cohort. `_link` is
   O(&#124;bucket ∩ cohort&#124;·&#124;bucket&#124;) — linear in cohort size but **multiplied by bucket
   size**, so a hot token bucket keeps a "bounded" cohort expensive. This is
   tracker 167's territory (cost per surviving candidate, sound prefilters) and it
   is being recorded here, not fixed here.

   **Honesty note on this measurement:** the density is a property of the synthetic
   estate (20 site tokens over 14,000 nodes ⇒ ~700-node buckets). The live estate's
   candidate density is **not yet measured** — that is exactly what Phase 14H
   requires. So the correct prediction from this profile is *"the hoist removes a
   measured ~48 s of the live cycle; whether the remaining cycle is acceptable
   depends on live candidate density, which is unmeasured."* It is **not**
   *"the hoist fixes 166."* That verdict waits for the live re-run.

### Two new defects found by the profile (in scope: both run once per cohort)

* **`engine.py:1866`** — `comp_edges = tuple(e for e in edges if e.from_node in comp_keys)`
  runs inside the per-component loop, so it rescans the whole edge set once per
  component: **O(K·E)**. 4.12 s here with ~200 k edges; the live carried-edge cache
  plateaus at **~384 k**. Fix: bucket edges by component root in one O(E) pass.
* **`engine.py:1739`** — the `seam_ids` set-comprehension inside
  `_fold_seam_bridged_components` does the same rescan per component: **O(K·E)**,
  4.45 s. Same fix.

Neither is preparation and neither can be hoisted into the epoch, but both are
per-cohort costs that the cohort split multiplies, and both are one-pass fixes.

---

## Phases 4/5/8 — implemented

`engine.prepare_run_window()` builds a `WindowPrep` — sorted signals, nodes,
identity pool, `PathIndex`, tenant-scoped discovery, per-node metadata
(`toks/refs/declared/windows/devs/seam_ident/seam_token/memb/route_hits`), the
`_CandidateIndex` (link groups + the node→groups reverse map + adjacency pairs),
and a `key → node index` map. `main._begin_epoch()` builds one per tenant per
drain sweep and `_close_epoch()` discards it on every path including failure.

Two things make the reuse sound rather than merely fast:

* **One implementation.** `build_edges`/`run_window` do not branch on whether a
  prep was supplied — an absent or non-matching prep is *rebuilt* through the
  same `prepare_window`/`prepare_run_window` the epoch uses. A prepped and an
  unprepped transaction cannot drift apart because there is no second code path.
* **The reverse map.** A prebuilt index alone does not bound emission: a cohort
  would still have to sweep every bucket to discover which ones it touches.
  `node_groups` means a cohort visits only the groups it actually sits in.

Observability (`epoch_state()` and `corr_engine_*` metrics):
`epochs`, `preparations`, `prep_seconds_{last,max,total}`, `prep_nodes`,
`epoch_seconds_{last,max}`, `cohorts_{last,max}`. The invariant to alert on is
`preparations / epochs == tenant count` — if that ratio starts tracking
`cohorts_total` instead, the defect is back.

Tests: `test_snapshot_epoch_166.py` (26) and `test_epoch_drain_166.py` (13).
Both include the controls that make them non-vacuous — an unprepped run *must*
prepare per transaction, and an always-true reuse guard *must* produce a wrong
answer. Suite: **1385 passed, 9 skipped** (1346 before this work).

## Phase 9 — the fixed-snapshot benchmark, and the honest verdict

Same 6,000-node snapshot, drained by 1/2/4/8 cohorts, before and after:

| cohorts | preps before | preps after | index builds before | index builds after | wall before | wall after |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1 | 1 | 1 | 1 | 34.90 s | 32.90 s |
| 2 | **2** | **1** | **2** | **1** | 64.04 s | 61.18 s |
| 4 | **4** | **1** | **4** | **1** | 77.90 s | 80.10 s |
| 8 | **8** | **1** | **8** | **1** | 95.08 s | 97.67 s |

Output **IDENTICAL** at every cohort count. Prepared-state memory 21.5 MiB at
6,000 nodes, flat across cohort counts.

A second independent run of the same benchmark against the final code:

| cohorts | preps before → after | index builds before → after | wall before | wall after |
|---:|---:|---:|---:|---:|
| 1 | 1 → 1 | 1 → 1 | 38.66 s | 30.41 s |
| 2 | **2 → 1** | **2 → 1** | 57.86 s | 63.69 s |
| 4 | **4 → 1** | **4 → 1** | 76.40 s | 68.68 s |
| 8 | **8 → 1** | **8 → 1** | 93.49 s | 95.18 s |

Output IDENTICAL at every K in both runs. **The wall-clock deltas disagree in
sign between the two runs (−8.3 s to +5.8 s), which settles the question: at
6,000 nodes the saving is smaller than the run-to-run variance.**

**The invariant is achieved: prep/index cost is now independent of cohort count.
The wall-clock saving is below measurement noise at this snapshot size.**

That is the honest result and it must not be dressed up. Preparation at 6,000
nodes is 0.9 s of a 33 s transaction; at 50,000 nodes it is 6.0 s. It was never
more than a few per cent of the cycle. **Hoisting it was correct and necessary
— it is now impossible for cohort count to multiply it — but it is not what
made the live cycle 150 s.**

## The actual cause of the 150 s cycle: candidate density

`scale-miniladder.py` injects 100 % `%LINK-3-UPDOWN` on
`GigabitEthernet0/{seq % 48}` across the estate.
`producers.syslog_control_signal` (`producers.py:520`) stamps
`entity_tokens=(host, ifname)` — **a bare interface name as a global
correlation token.**

Measured on a faithful reproduction (1,000 devices × 48 interfaces = 48,000
nodes):

| | |
|---|---:|
| index groups | 1,048 |
| largest group sizes | 1000, 1000, 1000, 1000, 1000, 1000 … |
| Σ C(g,2) over all groups | **25,104,000** |
| candidates emitted by ONE 5,000-node cohort | **4,854,740** |
| emission time | 2.25 s |
| **scoring at the measured 30 µs/candidate** | **145.6 s** |
| scoring at 70 µs/candidate | 339.8 s |
| `prepare_window` for the whole 48,000-node snapshot | **1.34 s** |

**145.6 s of modelled scoring against a ~150 s observed engine cycle.** The
per-transaction fixed cost is 1.34 s of it — under 1 %.

There are 48 index groups of 1,000 nodes each: one per interface *name*, because
`GigabitEthernet0/5` is a token every device in the estate emits.

### This is a product defect, not a harness artifact

Real networks reuse interface names across devices — every switch has a
`GigabitEthernet0/1`. Reproduced end to end with two unrelated devices:

```
signals:
  entity_id='dc1-switch-a:GigabitEthernet0/5'   tokens=('dc1-switch-a', 'GigabitEthernet0/5')
  entity_id='branch-77-rtr:GigabitEthernet0/5'  tokens=('branch-77-rtr', 'GigabitEthernet0/5')

objects formed: 1
  EDGE interface:dc1-switch-a:GigabitEthernet0/5:link_state_change
    -> interface:branch-77-rtr:GigabitEthernet0/5:link_state_change
       grounding=topo:shared:GigabitEthernet0/5  rank=7  weight=0.452  (threshold 0.3)
  verdict=suspected
```

A rank-7 shared-token pair admits at `w_t · 0.5 · w_r ≥ 0.3`, i.e. whenever the
two activity intervals are within `300 · ln(1/0.6) = 153 s`. So **any two
same-named interfaces anywhere in the estate flapping within 153 s of each other
are welded into one correlation object.** The verdict is correctly capped at
`suspected` (§3/§4 — no authoritative edge), so this cannot produce a false
*confirmed* RCA, but it does:

* inflate `affected()` and merge Jaccard — the exact failure tracker 154 records
  having already been caused once by rank-7 refs being indistinguishable;
* generate 25.1 M candidate pairs per full window at 1K scale, which is the
  throughput wall; and
* explain the carried-edge cache plateau at **~384 k entries** — those are
  overwhelmingly spurious same-name edges.

**Filed as tracker 168.** The fix is to stop emitting a bare interface name as a
global token (qualify it as `{host}:{ifname}`, which is already the `entity_id`,
or drop it — the `host` token plus containment already carries the real
relation). That is a one-line change in `producers.py` with a large blast radius
on correlation semantics, so it needs its own row and its own equivalence work;
it is deliberately NOT bundled into 166.

### What this means for the tracker disposition

* **166's named defect is fixed and proven fixed** — prep/index is once per
  epoch, equivalence exact, invariant mutation-tested.
* **166 will not pass live qualification on this fix alone.** The measurement
  says the fix removes ~1 % of the cycle at 1K scale.
* **167 is on 166's critical path**, and 168 is very likely the largest single
  lever inside it: removing the bare-ifname token would cut candidate generation
  by roughly the 48 × C(1000,2) term — the overwhelming majority of the 25.1 M.
