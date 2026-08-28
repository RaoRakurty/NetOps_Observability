# Per-stage, per-cohort cost profile of the drain sweep — OFFLINE, 2.5K-shaped

**Purpose.** `docs/scale/P1_2P5K_VERDICT_2026-08-28.md` §4 established *how much*
the 2.5K load epoch costs (20 cohorts × ~190 s = 3,881 s) and *how much* of it is
redundant (8,941 of 14,605 component evaluations were untouched components ranked
anyway). It did not establish **which stage of a cohort burns the time**. This
report does, so `docs/design/DECISION_EVIDENCE_SPLIT_P2_2026-08-28.md` §3/§4/§5
is designed against measured shares. It is the artefact that design's §3 refers to
as "the offline profile (`p2_cohort_profile.md`, §8)".

**Script:** `src/correlation/bench_profile_p2.py` (new; nothing in `engine.py` /
`main.py` was modified — every measurement is a wrapper installed around a public
callable for the duration of the run and removed afterwards).

**Everything below is SYNTHETIC.** Read §7 before quoting a number as a live
number.

---

## 1. Method

| | |
|---|---|
| code under test | the REAL sweep: `main._begin_epoch` → N × `main.engine_cycle(epoch)` → `main._epoch_lifecycle` → `main._close_epoch`, i.e. `engine_loop`'s body, with the **uncommitted P1 working tree** (cohort-touch gate ON, epoch-cadence lifecycle ON) |
| signals | generated through the REAL producer `producers.syslog_control_signal` from the scale harness's ratified `EVENT_MIX_REALISTIC` weights (`scripts/scale-miniladder.py`) → the same six kinds (`link_state_change` 46 %, `bgp_adjacency_change` 18 %, `ospf_adjacency_change` 12 %, `lldp_neighbor_change` 9 %, `stp_topology_change` 8 %, `device_alarm` 7 %) |
| storm mode | **declared** (`epoch.storm = True`) — the live 2.5K leg ran storm-declared (`corr_storm_deduped_total` 44,165) and the storm cohort size is what makes an epoch 20 cohorts |
| persistence | **MOCKED.** `main.ch` counts rows and serialized bytes; `ch_insert`, dedup tokens, the projection dual-write, the child-row paging and the archive slice all still run. Row *building* is real and measured; the HTTP insert is not |
| attribution | thread-local span stack → **inclusive** and **exclusive (self)** time per stage, so `rank` nested inside `run_window` is never double-counted. All work is awaited sequentially (`_offload` / `_snap_call`), so no two spans are ever open concurrently |
| excluded | the byte-accounting `json.dumps` the mock sink adds (timed separately, subtracted from every share); the engine's per-version INFO log line (silenced — real cost, different cost curve in a container) |
| box | 4-core lab host, Python 3.10, legs run **sequentially** (an earlier contended pair was discarded and re-run) |

### Legs

| leg | devices | window signals (epoch 1) | arrivals before epoch 2 | cohort size | cohorts × epochs | per-device burst | net wall | **s / cohort** |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| **A** | 500 | 7,000 | 3,500 | 200 | 20 × 2 | 1 (harness round-robin) | 131.0 s | **3.27** |
| **B** | 500 | 7,000 | 3,500 | 200 | 20 × 2 | 6 (clustered flaps) | 62.4 s | **1.56** |
| **C** | 2,500 | 35,000 | 17,500 | **1,000 (live)** | 10 × 2 | 1 | 348.8 s | **17.44** |

Live reference: 2,500 devices, 35,053 pending, storm cohort 1,000, 20 cohorts per
epoch, **≈190 s per cohort**.

`burst` is the one deliberate departure from the harness's uniform round-robin
(`device = seq % n_devices`): with `burst=k` a device emits `k` consecutive events
before the stream moves on. Round-robin makes every cohort touch every component
(gate hit rate → 0); the live epoch touched 178 components per 1,000-signal cohort
(5.6 signals per touched component), which `burst≈6` reproduces. Both regimes are
reported because the true live regime sits between them.

**Leg C is the headline** — live device count, live window size, live cohort size.

**CPU budget, stated honestly:** the brief asked for ≤ ~15 min. The three legs
above cost ≈ 9.5 min (A 141 s + B 64 s + C 369 s); a fourth run (leg C repeated to
add the rank-key instrumentation, §5) and ~5 min of discarded contended runs put
the session total at ≈ 21 min. Scale was cut in two places to stay near budget:
leg C drains **10 cohorts per epoch instead of the live 20**, and legs A/B run at
1/5 of live device count. Neither cut changes a share — a cohort's stage mix is
flat from cohort 4 onward (§4) — but it does mean the absolute per-epoch seconds
here are half an epoch, not a whole one.

---

## 2. Headline — stage × share of cohort wall × absolute seconds (leg C)

20 cohorts, 348.8 s net, **17.44 s per cohort**.

| stage | plane | calls | excl s | % net wall | s / cohort |
|---|---|--:|--:|--:|--:|
| **rank** (scoring.rank → score_template → verdicts.assess) | Decision | 22,075 | 110.86 | **31.8 %** | 5.543 |
| **hypotheses_blob** | Evidence/digest | 50,035 | 57.14 | **16.4 %** | 2.857 |
| **content_hash** | reconcile | 74,497 | 35.91 | **10.3 %** | 1.795 |
| run_window body (comp/edge assembly, cid, orientations, ObjectSnapshot ctor) | Decision | 20 | 25.59 | 7.3 % | 1.279 |
| archive slice select (`_archive_slice`) | Evidence | 21,157 | 15.54 | 4.5 % | 0.777 |
| corr_current badges | Evidence | 21,157 | 8.54 | 2.4 % | 0.427 |
| build_edges / candidate generation | Decision | 20 | 5.94 | 1.7 % | 0.297 |
| material_hash | Decision | 28,239 | 5.88 | 1.7 % | 0.294 |
| to_object_row | Evidence | 21,157 | 5.43 | 1.6 % | 0.272 |
| prepare_run_window (once per epoch) | prepare | 2 | 4.86 | 1.4 % | 0.243 |
| evidence row pages | Evidence | 12,487 | 4.62 | 1.3 % | 0.231 |
| archive row build | Evidence | 82,470 | 4.30 | 1.2 % | 0.215 |
| components (union-find) | Decision | 20 | 2.79 | 0.8 % | 0.140 |
| edge row pages | Evidence | 12,487 | 2.54 | 0.7 % | 0.127 |
| data-class gate | Decision | 242,930 | 1.42 | 0.4 % | 0.071 |
| lifecycle: find_merges | lifecycle | 2 | 0.64 | 0.2 % | 0.032 |
| materialize: storm dedup | Decision | 22,075 | 0.48 | 0.1 % | 0.024 |
| reconciliation: find_continuation | reconcile | 18,314 | 0.45 | 0.1 % | 0.023 |
| rank tie-break (seam affinity) | Decision | 22,075 | 0.40 | 0.1 % | 0.020 |
| evidence row count | Evidence | 21,157 | 0.07 | 0.0 % | 0.004 |
| materialize: app-identity projection | Decision | 22,075 | 0.06 | 0.0 % | 0.003 |
| components (seam fold) | Decision | 20 | 0.00 | 0.0 % | 0.000 |
| _unattributed (asyncio/executor glue, unpatched residual)_ | — | — | 55.32 | 15.9 % | 2.766 |
| **total (net of byte-accounting)** | | | **348.78** | **100 %** | **17.44** |

Grouped:

| group | leg C | leg A | leg B |
|---|--:|--:|--:|
| rank (+ tie-break, verdict gates) | **32.3 %** | 34.9 % | 32.7 % |
| digests (blob + content_hash + material_hash) | **28.4 %** | 25.9 % | 12.6 % |
| unattributed (executor/asyncio glue) | 15.9 % | 14.8 % | 31.6 % |
| persist row building | 11.8 % | 12.0 % | 13.8 % |
| materialize (run_window body, dedup, identities) | 7.5 % | 8.8 % | 6.7 % |
| build_edges | 1.7 % | 1.5 % | 0.7 % |
| prepare_run_window | 1.4 % | 0.9 % | 1.2 % |
| components | 0.8 % | 1.0 % | 0.6 % |
| lifecycle (merge/quiesce/cap) | 0.2 % | 0.1 % | 0.1 % |
| reconciliation (find_continuation) | 0.1 % | 0.0 % | 0.0 % |

Two structural facts fall straight out:

1. **`rank` + digests = 60.7 % of cohort wall** (leg C). Every other stage the
   design worries about — edges, components, continuation, merge/quiesce/cap — is
   **under 3 % combined**. Tracker 166's prep hoist and tracker 162's continuation
   index did their job; there is nothing left to win there.
2. **The lifecycle hoist (P1 change H) is already down in the noise** (0.2 %).
   Its value was never CPU — it was the 65-minute deferral of prune/quiesce.

---

## 3. `hypotheses_blob` is built TWICE per persisted version

`content_hash` embeds the blob (`engine.py::_content_hash_uncached` →
`"hypotheses": self.hypotheses_blob()`), and `hypotheses_blob` is deliberately
**not** cached on the instance (tracker 156 RSS argument). `_persist_snapshot`
then builds it again (P1 §3 built it *once per persist* instead of 3–4×, which is
where the earlier win came from). Leg C call accounting:

```
hypotheses_blob calls   50,035
content_hash computed   27,830   (34,253 served from the P1 instance cache)
versions persisted      21,157
27,830 + 21,157 = 48,987 ≈ 50,035
```

At 1.14 ms per build, the ~21 k redundant builds are **≈24 s of 348.8 s = 6.9 % of
cohort wall** — recoverable by a *short-lived* blob cache (cleared with the cycle,
like `_CYCLE_ROW_CACHE`) or by having `_persist_snapshot` hand its blob to
`content_hash`. No RSS exposure: nothing survives the cycle.

Digest-cache behaviour also reproduces the P1 verdict §4 finding exactly:

| leg | content computed | content cached | material computed | **material cached** |
|---|--:|--:|--:|--:|
| A | 7,415 | 14,282 | 5,548 | **0** |
| B | 3,955 | 33,105 | 3,387 | **0** |
| C | 27,830 | 34,253 | 18,659 | **0** |

`material_hash` never hits its cache: the object is re-materialized per version, so
the per-instance cache can never serve a second read.

---

## 4. Per-cohort shape: the first-sight cohort dominates

Leg C, epoch 1 (10 cohorts over a frozen 35,000-signal window):

| epoch | cohort | wall s | components | touched | memo hits | ranked | new memo keys | versions |
|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| 1 | 1 | **40.50** | 6,905 | 740 | 0 | 6,905 | 6,905 | 6,906 |
| 1 | 2 | 10.52 | 3,535 | 740 | 2,795 | 740 | 550 | 551 |
| 1 | 3 | 9.63 | 1,850 | 740 | 1,110 | 740 | 275 | 551 |
| 1 | 4–10 | 8.5–12.4 | 1,850 | 740 | 1,110 | 740 | **0** | 550 |
| 2 | 1 | **33.68** | 1,850 | 740 | 0 | 1,850 | 1,850 | 1,515 (336 damped) |
| 2 | 2–10 | 13.7–21.4 | 1,850 | 740 | 1,110 | 740 | 0 | 550 |

- The **first cohort of every epoch costs 3–4× a steady cohort** — it is the cohort
  that pays `rank` + materialize for every component in the window, because the
  intra-epoch memo starts empty. This is P1's structural limit stated in wall time.
- `components` falls 6,905 → 3,535 → 1,850 and then *stops moving*: components
  MERGE as cohorts admit nodes and edges are progressively discovered, and once the
  graph has assembled the memo keys stop churning (`new memo keys = 0` from cohort
  4). **In the live load epoch that churn evidently continued all epoch** — that is
  the only mechanism that explains a 14 % hit rate over 20 cohorts (see §7).
- Epoch 2 costs ~1.6× epoch 1 per cohort at the same component count: the window
  is at its 50,000 cap and `OPEN_OBJECTS` is at the tracker-163 cap of 5,000
  (2,311 objects were force-closed by the epoch-1 lifecycle pass).

Memo counters per epoch:

| leg | epoch | components | touched | memo hits | hit % | ranked |
|---|--:|--:|--:|--:|--:|--:|
| C | 1 | 25,240 | 7,400 (29.3 %) | 11,675 | 46.3 % | 13,565 |
| C | 2 | 18,500 | 7,400 (40.0 %) | 9,990 | 54.0 % | 8,510 |
| A | 1 | 8,748 | 2,960 (33.8 %) | 4,555 | 52.1 % | 4,193 |
| A | 2 | 7,400 | 2,960 (40.0 %) | 4,218 | 57.0 % | 3,182 |
| B | 1 | 17,812 | 680 (3.8 %) | 15,533 | 87.2 % | 2,279 |
| B | 2 | 15,978 | 680 (4.3 %) | 14,330 | 89.7 % | 1,648 |
| **live load epoch** | — | 14,605 | 3,566 (24.4 %) | 2,098 | **14.4 %** | 12,507 |

The synthetic touch ratio brackets live (3.8 % … 33.8 % vs live 24.4 %), but **no
synthetic leg reproduces live's 14 % hit rate** — see §7.

---

## 5. Cross-epoch reuse — the measurement P2 §3 needs

For every component MATERIALIZED in each epoch (the memo is written only on a
miss, i.e. only after a real rank + materialize), the run records the node-key set,
`material_hash`, `content_hash`, `correlation_id`, and two candidate memo keys:

- **DecisionKey** — the P2 §3 key: node keys **+ their signal ids** + carried-edge
  identities + engine/topology version + storm/stale flags.
- **rank key** (coarser, proposed here) — the projection `rank` can actually see:
  the SET of `node.key | kind | severity | entity_type | entity_id | deviation`,
  plus `catalog_version`. Deliberately the same projection `material_hash` already
  uses for its `evidence` field.

| | leg A | leg B | **leg C (live-shaped)** |
|---|--:|--:|--:|
| components materialized in epoch 1 | 1,546 | 2,099 | 7,730 |
| components materialized in epoch 2 | 370 | 1,168 | 1,850 |
| **identical node-key set in both** | 260 (**70.3 %** of epoch 2) | 466 (**39.9 %**) | 475 (**25.7 %**) |
| …of those, identical `material_hash` | 95 (36.5 %) | 394 (84.6 %) | **475 (100 %)** |
| …of those, identical `content_hash` | 57 | 249 | **0** |
| …of those, identical `correlation_id` | 260 | 466 | **0** |
| …of those, identical **DecisionKey** (P2 §3) | 65 | 289 | **0** |
| …of those, identical **rank key** | **260 (100 %)** | **466 (100 %)** | **475 (100 %)** |
| DecisionKey hit share of epoch-2 materializations | 17.6 % | 24.7 % | **0.0 %** |
| rank-key hit share of epoch-2 materializations | **70.3 %** | **39.9 %** | **25.7 %** |
| distinct rank keys / rank keys mapping to two different rankings | 1,656 / **0** | 2,801 / **0** | 9,105 / **0** |

*(The leg-C rank-key column comes from `legC2.json`, a re-run of the identical
leg-C configuration after the rank-key instrumentation was added. It reproduced
every other reuse figure of `legC.json` EXACTLY — 7,730 / 1,850 / 475 / 100 % /
0 % / 0 — which is also a determinism check on the fixture. Its timings are not
used: it ran alongside the pytest suite.)*

### What this says

1. **The cross-epoch reuse ceiling is the node-key-set survival rate**: 25.7 % at
   live shape, 39.9–70.3 % at the smaller shapes. Components that MERGE, SPLIT or
   lose a node to window eviction get a different key and must be re-derived —
   correctly.
2. **Inside that ceiling, the verdict is almost always unchanged.** At live shape
   **100 %** of the surviving components had an identical `material_hash` in epoch
   2 — same evidence kinds/severities, same edges, same ranking, same owner. The
   full re-rank + re-materialize produced an operator-identical object.
3. **The P2 §3 DecisionKey would have hit 0 % of them at live shape.** It hashes
   *signal ids*, and between epochs (a) new arrivals land on existing nodes and
   (b) the window is at its 50,000 cap and evicts, so essentially every component's
   signal-id set moves even when nothing an operator would act on changed.
   `correlation_id` moved for all 475 too (the earliest node aged out → the #111
   re-key), which the continuation path then repaired.
4. **A coarser key recovers the whole ceiling**: the rank key was identical for
   **100 %** of the key-set-identical components in all three legs, and across
   1,656 + 2,801 + 9,105 distinct rank keys **not one** mapped to two different
   rankings. That is empirical support (on this workload, not a proof) for
   "`rank`'s output is a function of the evidence projection + catalog version".

**Recommendation for P2 §3:** split the memo into two levels rather than one.
*(a)* a **verdict/rank memo** keyed on the evidence projection above — it skips
`rank` (31.8 % of cohort wall) even when the snapshot must be rebuilt; *(b)* the
full snapshot memo keyed on the DecisionKey — it additionally skips materialize +
digests, but only fires when literally nothing arrived, which at live window
pressure is ~0 % across an epoch boundary. Keeping only *(b)* buys nothing at 2.5K.

---

## 6. Persistence (mocked) — rows and bytes per version

Leg C (21,157 versions persisted, 336 damped):

| table | rows | rows/version | bytes | **bytes/version** |
|---|--:|--:|--:|--:|
| `netops.corr_objects` | 21,157 | 1.0 | 757,863,979 | **35,821** |
| `netops.corr_edges` | 619,777 | 29.3 | 263,374,790 | 12,449 |
| `netops.corr_evidence` | 619,777 | 29.3 | 251,898,861 | 11,906 |
| `netops.corr_signals_archive` | 82,470 | 3.9 | 67,496,790 | 3,190 |
| `netops.corr_current` | 21,157 | 1.0 | 25,632,511 | 1,212 |
| **all** | **1,364,338** | **64.5** | **1,366,266,931** | **64,578** |

Leg A (larger components: 145.8 rows and **116,660 bytes** per version, of which
`corr_objects` alone is 54,417 — the hypotheses blob). Leg B (small components):
19.7 rows, 33,759 bytes per version.

- **`corr_objects` is 55 % of the bytes and one row.** The blob is the payload,
  and it is also what makes `content_hash` expensive (§3).
- **4 inserts per version** (objects + current + edges + evidence) plus a
  conditional archive slice — exactly the live shape. At the live 7 ms per insert
  that is ~28 ms per version = **≈15 s per leg-C cohort of ClickHouse wait that
  this profile does NOT pay**. Add it back and a leg-C cohort is ~33 s, ~47 % I/O.
  (The live A/B measured 17.5 % because live persists far fewer versions per unit
  of compute — see §7.)
- **Versions per material change is NOT reproduced.** Live: 37,640 versions for
  1,919 material changes = 19.6 : 1. Here: 21,157 versions, only 336 damped —
  because the synthetic feeds genuinely new evidence to a touched component every
  cohort, so nearly every version IS a material change. This profile therefore
  says nothing about the damping ratio; the live number stands.

---

## 7. What the synthetic does NOT reproduce (read before quoting)

1. **Per-cohort wall: 17.4 s here vs ~190 s live** (same device count, same window
   size, same cohort size). The gap is real and only partly explained:
   - persistence I/O is mocked (≈15 s/cohort at live insert latency, §6);
   - live components are ~2.5× larger in signal count (live ~48 signals per
     component vs 19 here), and `rank`/blob/`content_hash` all scale with that;
   - live runs the correlation container next to the whole compose stack (Kafka
     consumer, OpenSearch/CH sinks) on the same 4 cores, sharing the GIL with the
     consumer loop; this profile has the box to itself.
   Treat the **shares** as transferable and the **absolute seconds** as a floor.
2. **The intra-epoch memo hit rate is far better here (46–90 %) than in the live
   load epoch (14 %).** Mechanism, visible in §4: memo keys stop churning after
   cohort 3 in the synthetic because the component graph finishes assembling.
   Live's components kept merging (or splitting) for the whole epoch, so untouched
   components kept missing. **Consequence: this profile UNDER-states how much of
   live's cohort is `rank`** — the live load epoch ranked 85.6 % of evaluations,
   leg C ranked 53.7 %. If anything, `rank`'s 32 % is a lower bound for live.
3. **Component identity churn** (the thing that defeats both memos) is a property
   of the real topology/token graph. The synthetic's device-scoped bursts under-mix
   the estate; there are no seams, no adjacency, no path graph, no discovery paths,
   no app-identity signals, no cloud evidence, single tenant.
4. **Damping / versions-per-material-change** (§6) — not reproduced.
5. **Signal mix** is syslog-only control-plane, the 5 % of the production mix that
   classifies. No metric/flow/probe modalities, so cross-modality corroboration and
   the `worst_data_class` / verification paths are exercised only lightly.
6. **`_engine_cycle_inner`'s own asyncio work** (cohort selection, per-snapshot
   loop, `await _loop_yield()`) sits in the 15.9 % unattributed bucket together with
   executor round-trips; it was not broken out.
7. **Arrivals between epochs are a fixture parameter** (`--arrivals`,
   `--arrival-device-share 0.4`), and they set the cross-epoch reuse ceiling of §5.
   The *ratios inside* the ceiling (material-stable 100 %, DecisionKey 0 %) are
   properties of the code and the window cap, not of that parameter.
8. The engine's per-version INFO log line is silenced; in the container it is real
   (21,157 lines for leg C).

---

## 8. Implications for the P2 design

| P2 design item | what the profile says |
|---|---|
| §3 cross-epoch decision memo | **Right lever, wrong key.** Ceiling = 25.7 % of epoch-2 materializations at live shape; the signal-id-based DecisionKey realizes **0 %** of it, an evidence-projection ("rank key") realizes **100 %** of it. Ship the two-level memo (§5 recommendation) or the lever will measure as a no-op at 2.5K. |
| §4 Evidence plane deferral | Deferring `to_object_row` + edge/evidence pages + archive slice + badges removes **11.8 %** of cohort wall; adding `hypotheses_blob` (16.4 %) to the Evidence item would remove **28 %** — but the design keeps the blob in `corr_objects`, and `content_hash` (10.3 %) rebuilds it anyway. **Fix §3-of-this-report first (≈7 % for free), then re-decide** whether the blob belongs in the synchronous row at all. |
| §4 epoch budget | Cheap and correct: the first cohort of an epoch is 3–4× a steady cohort, so a budget that ends an epoch early re-pays that first-sight cost more often. Budget in **cohorts of measured cost**, not seconds alone, or a short budget makes throughput worse. |
| §5 priority-aware materialization | Ordering is free (the storm sort is already ~0 % of wall). The value is entirely in *what lands first*, not in CPU. |
| lifecycle / continuation / edges / prep | **Do not spend design effort here** — 0.1–1.7 % each after 162/166/P1. |

### Two measured micro-levers (cProfile, one first-sight `run_window`, leg-A shape)

`python3 bench_profile_p2.py --devices 500 --signals 7000 --cprofile` — top
`tottime` in a single 9.36 s `run_window` (of which `scoring.rank` is 7.12 s, 76 %):

| function | calls | tottime | cumtime |
|---|--:|--:|--:|
| `catalog.py:57 Clause.kinds` | 248,508 | 0.928 | 1.415 |
| `verdicts.py:230 coverage` | 23,323 | 0.686 | 2.702 |
| `scoring.py:180 score_template` | 23,323 | 0.628 | 6.499 |
| `uuid.py:722 uuid5` | 68,103 | 0.497 | 1.298 |
| `signals.py:663 Signal.signal_id` | 66,769 | 0.269 | 1.707 |

- **`Clause.kinds()` recomputes `frozenset(self.kind.split("|"))` on every call**
  (248 k times per cohort). The catalog is immutable for the process lifetime —
  precompute it once at model build. ≈15 % of a `run_window`, zero semantic risk.
- **`Signal.signal_id` is a uuid5 (SHA-1) recomputed per lookup**, 66.8 k times in
  one `run_window` (1.7 s, 18 %). The instance-level cache was correctly rejected
  for RSS (tracker 156), but `run_window` builds `trigger_signal` by
  `min(comp_sigs, key=(ts, signal_id))` per component — a **per-call** dict, thrown
  away with the transaction, has no RSS exposure. Same trick as `_window_index`.

Together these two are ~30 % of `rank`+ctor time in a first-sight cohort and need
no architecture change at all.

---

## 9. Reproduce

```bash
cd NetOps_Observability/src/correlation

# leg C — live device count / window / cohort size (≈6 min)
python3 bench_profile_p2.py --devices 2500 --signals 35000 --arrivals 17500 \
    --cohorts 10 --epochs 2 --cohort-size 1000 --burst 1 --json /tmp/legC.json

# leg A — 1/5 scale, harness round-robin stream (≈2.5 min)
python3 bench_profile_p2.py --devices 500 --signals 7000 --arrivals 3500 \
    --cohorts 20 --epochs 2 --burst 1 --cprofile --json /tmp/legA.json

# leg B — 1/5 scale, clustered per-device flaps (≈1 min)
python3 bench_profile_p2.py --devices 500 --signals 7000 --arrivals 3500 \
    --cohorts 20 --epochs 2 --burst 6 --json /tmp/legB.json

# gate off (pre-P1 shape) for an A/B of the cohort-touch gate itself
python3 bench_profile_p2.py --no-gate ...
```

Raw JSON for the runs quoted here: `legA.json`, `legB.json`, `legC.json`,
`legC2.json` (rank-key re-run of leg C), the generated tables `all_tables.txt`
and the table generator `analyze.py` — all in this scratchpad directory.

`src/correlation` pytest suite was re-run after the script was added: see §10.

---

## 10. Suite status

`bench_profile_p2.py` is a standalone script (no `test_` prefix, no import from
any test), but it lives under `src/correlation`, so the suite was re-run after it
landed:

```
python3 -m pytest src/correlation -q -x
1600 passed, 9 skipped in 174.86s
```

`engine.py` and `main.py` are untouched — `git status` shows exactly one new
untracked file, `src/correlation/bench_profile_p2.py`.
