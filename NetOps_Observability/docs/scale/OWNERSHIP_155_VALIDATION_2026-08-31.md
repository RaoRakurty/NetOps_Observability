# Tracker 155 — correlation state follows partition ownership: the validation arc (155a → 155d)

**CLOSED 2026-08-31.** Four live runs on the reference box measured the defect,
graded three fixes against it, and ended with the primary assertion PASSING on
both disturbed arms. This doc is the close-out record for tracker row 155, which
is deleted from `docs/TRACKER.md` on the strength of it.

| run | evidence | subject code | primary result |
|---|---|---|---|
| **155a** | `/var/tmp/scale-runs/ownership-155a-08302235` | pre-fix HEAD | defect MEASURED — positive-story pass **1.00 → 0.00** on every disturbed arm |
| **155b** | `/var/tmp/scale-runs/ownership-155b-08310318` | `931efffb` | seeding runs perfectly, adoption **1 / 32 = 3.1 %**, pass still **0.00** |
| **155c** | `/var/tmp/scale-runs/ownership-155c-08311027` | `557dbef7` | identity HOLDS across the move; the **orphan-write half** named, pass still 0.00 |
| **155d** | `/var/tmp/scale-runs/ownership-155d-08311609` | `7c86223d` | **PASS** — positive pass **1.00 / 1.00**, one object per story, 0 duplicate versions |

Protocol was held fixed from 155b onward: `arm_driver.py` / `analyze.py` /
`accounting.py` / `lineage*.py` reused verbatim, scenario
`docs/design/examples/twin-scenario-example.yaml` seed 20260816, 9-minute arms,
control + restart + exit-join, the move aimed at the replica owning the story
tenant's partition at emission + ~360 s, `open_objects > 0` precondition checked
before every disturbance. 155d changed only the observation surface (five new
counter names, two new log greps).

---

## 1. The defect, as measured (155a, 2026-08-30)

**Nothing durable was lost. IDENTITY fragmented.** Across three disturbed arms
(restart, restart-keep, exit-join; moves at emit +374.4 / +389.9 / +426.8 s):

- **0 committed-offset rewinds** on every partition, whole-arm and across the
  move; **0 duplicate** `(correlation_id, version)` or
  `(correlation_id, version, signal_id, subject_id)` tuples; evidence conserved
  (identical twin journals, `produce_failures == []`).
- **Detection 1.00 and specificity 1.00 on every arm** — the engine never stopped
  seeing the incident and never welded unrelated ones.
- **The story broke into one object per move.** `dx-flap-1` came back as **1**
  object in control, **2** in restart-keep (one move), **3** in restart and **3**
  in exit-join (two rebalances each). `single_incident` was the **only** failing
  clause in all three, so **positive-story pass 1.00 → 0.00**.

Root cause: `correlation_id = uuid5(tenant, earliest-node.key, onset_ms)` is
derived from the acquiring replica's in-memory window, which starts empty for a
partition it has just acquired — so the incident re-keys, and the pre-move object
freezes at its last version, orphaned.

## 2. The three-fix ladder

**`931efffb` — reconstruct identity, not state (validated by 155b).** On assign,
schedule a bounded tenant-scoped load of the still-OPEN objects of the partitions
just acquired and register an identity PLACEHOLDER (id, tenant, window, version,
blast radius). 155b showed the mechanism itself ran exactly as designed —
**5 / 5 / 9 / 13 placeholders in 75 / 84 / 96 / 85 ms, 0 failures, 0 skipped, 0
fabricated rows, conservation exact** — and the pass rate STILL sat at 0.00:
**1 adoption across 32 placeholders (3.1 %)**, on the WRONG replica, and it
DEMOTED the row it continued (thin `suspected` v7 replacing a 9-node `confirmed`
v6 under `corr_current` latest-write-wins). Three named defects: the placeholder
window was frozen at the durable `window_end`, so the refilled window's first
snapshot always started after it (misses of **18.0 / 35.4 / 10.1 s**); a revoked
owner could still adopt and write; and the first post-adoption persist recomputed
`confirmed → suspected` from a half-refilled window.

**`557dbef7` — slack, revoked-owner guard, verdict floor (validated by 155c).**
Match slack `CORR_OWNERSHIP_SEED_SLACK_S` (derived = `RETENTION_REQUIRED_S`,
516.5 s) on the placeholder only; discard unadopted placeholders on revoke;
refuse a seed-descended object's FIRST version on a partition no longer owned;
floor the published tier at the durable one until the refill horizon expires.
155c: **identity continuity HOLDS** — one id, strictly increasing versions, in
both arms and across two consecutive handoffs; adoption **8 / 25 = 32 %**
(50 % / 42.9 % on the replicas that ended up owning the story partition);
conservation exact; the verdict floor fired **exactly once**, on the only version
in the run carrying `grounding_context.ownership_handoff`. Pass was still 0.00,
now for a different and precisely named reason: **the old owner still writing for
partitions it had lost.** Restart: c5 minted a FRESH object `3eec17dd` **13 s
after** revoking → 2 objects, `single_incident` FAIL. Exit-join: an already-adopted
`b0f0fd7f` kept being continued for **six minutes** past revocation, writing a
DUPLICATE v7 that latest-write-wins made current → `seam_owner` read `app_team`
instead of `carrier`, and durability assertion 8 FAILED.

**`7c86223d` — state follows ownership (validated by 155d).** The rule made
general: a registration may only live, and only write, while this replica owns
its tenant's partition. Flush-and-release on revoke (`_handoff_flush` writes one
further OPEN version of the last consistent snapshot, most-recently-updated
first, under one `CORR_REVOKE_BUDGET_S`; `_release_lost_partitions` forgets, in
the ASSIGN callback, exactly what did not come back — aiokafka revokes eagerly),
plus a persist-time ownership guard on every object and an admission guard where
objects enter `OPEN_OBJECTS`.

## 3. The 155d verdict (2026-08-31, image `2d617a1ba1fa`, repo `7c86223d`)

**Primary assertion: PASS on both disturbed arms.**

| arm | 155a | 155b | 155c | **155d** |
|---|---|---|---|---|
| control | 2/2, pos 1.00 | 2/2, 1.00 | 2/2, 1.00 | **2/2, pos 1.00**, 1 story object |
| restart | 1/2, **0.00**, 3 objs | 1/2, 0.00, 2 objs | 1/2, 0.00, 2 objs | **2/2, pos 1.00** — `ff9a5126` v1..v10, no post-revoke mint |
| exit-join | 1/2, **0.00**, 3 objs | 1/2, 0.00, 3 objs | 1/2, 0.00, `seam_owner` FAIL + dup v7 | **2/2, pos 1.00** — `dfb4ea67` v1..v10, `seam_owner='carrier'`, no orphan v7 |

- **One id per story, gapless across the handoff.** Restart `ff9a5126` v1–v10 all
  written by c6 across its own bounce; exit-join `dfb4ea67` v1–v6 on c5, **v7–v10
  on c6** — the handoff is visible in the writer column and invisible in the
  identity. `corr_current` ends on v10 `confirmed`
  `sig.ent.middle-mile.private-interconnect-bgp-down` in both.
- **0 duplicate `(correlation_id, version)`** per arm and run-wide (115 rows /
  28 objects, 16:10–17:15Z). **Negative control:** the identical query over the
  155c window still returns `b0f0fd7f` v7 n=2 — the zero is a real negative, not
  a broken query.
- **Handoff counters.** `flushed` restart c5 +8 (4 objects/329 ms for [0,1];
  4/210 ms for [0,1,2,3]), exit-join c6 +26 (12/407 ms for [2,3]; 14/652 ms for
  [0,1,2,3]), control 0 — flushes appear exactly where partitions moved.
  `unflushed` **0 on every replica in every arm** (no budget exhaustion, no failed
  write). `released` c6 +12 for the partitions it did not get back; 0 elsewhere
  (restart's c5 held only unadopted placeholders, which leave by the D2a path —
  `seed_revoked` +14).
- **Conservation exact** (`seeded == adoptions + expired + revoked +
  unowned_dropped + pending`, `balanced=True`) on every replica in every arm:
  restart c5 14=0+0+14+0+0, c6 14=6+0+0+0+8; exit-join c5 14=0+0+14+0+0,
  c6 17=8+8+1+0+0, c7 12=4+0+0+0+8.
- **Flush cost.** Worst flush **652 ms** = **13.0 % of the 5 s revoke budget** and
  ≈1.1 % of the 60 s rebalance timeout (the artefact rounds it 1.2 %). Absolute
  revoke→assign rose from 14–35 ms (155c, no flush) to **249–701 ms** — ~20× on a
  tiny base, bounded by the budget by construction. A same-replica no-state
  control on the same image measured 35 ms, so the delta is the flush, not the
  image.
- **Adoption on the true acquiring owner:** restart c6 **6/14 = 42.9 %**,
  exit-join c6 **2/3 = 66.7 %**, c7 **4/12 = 33.3 %**; overall **12/43 = 27.9 %**
  across the disturbed arms (155c: 32 %). The denominator is not comparable
  across runs — 155d's c5 legitimately gave back all 14 of its placeholders 10 s
  later.
- **Verdict floor fired on exactly 3 versions**, all exit-join, all carrying
  `grounding_context.ownership_handoff` and nothing else (`dfb4ea67` v7,
  `788c9fbd` v5, `fe3635e0` v6); `seed_verdict_carried_total` c6 +1, c7 +2 = 3,
  matching exactly. The story's `dfb4ea67` v7 (17:04:26.153Z, 4 s after c6 took
  the partition) published the durable `confirmed` /
  `private-interconnect-bgp-down` while honestly recording
  `recomputed_verdict_tier='suspected'`,
  `recomputed_top_hypothesis='sig.ent.app.saas-experience-degraded'` — **precisely
  the hypothesis that in 155c became the spurious second object** that failed
  `single_incident`. The floor folds the weak recomputation into the same object
  instead of minting a rival. No arm ends weaker than it started (v6 `confirmed`
  pre-move → v7..v10 `confirmed` in both).
- **Durability.** 0 offset rewinds on every partition, whole-run and across the
  move. `corr_evidence` grows monotonically with version and loses no version
  (control 118 rows / 7 versions, restart 145/13, exit-join 124/11), 0 duplicate
  tuples. The handoff dip is visible and expected: `dfb4ea67` v7 carries 1
  evidence row and recovers to 15 by v8.
- **Detection / specificity 1.00** in all three arms; the negative control
  `no-merge-1` passes `forbid.cross_tenant_merge` and `forbid.confirmed`
  everywhere — adoption did not weld unrelated incidents. Fabrication scan clean
  (0 zero-node, 0 zero-signal, 0 empty-hypothesis rows).
- **Restore PASS.** Two healthy replicas (c6, c7) on the subject image, 24
  partitions each, aggregation plane ON (`p3.k3.v1`), twin residue zero.

## 4. Honest caveats

1. **The persist and admission guards were only partially exercised.**
   `corr_ownership_unowned_persist_dropped_total` stayed **0 in both arms** — no
   revoked owner ever attempted a persist, because `_release_lost_partitions` had
   already forgotten those registrations (`released_total=12`). The persist guard
   is therefore a **backstop behind the release, not the mechanism that produced
   this pass**. `corr_ownership_unowned_admission_dropped_total` stayed **0 in
   the restart arm** (the old owner there was a dead process, so nothing could
   attempt a post-revoke mint) and ticked **156 on c6 in the exit-join arm**,
   where a live old owner did keep receiving events for partitions it had just
   lost. Both guards remain proven only by their unit mutants.
2. **Graceful shutdown skips the handoff flush** — filed as tracker **199**.
   SIGTERM → `consumer.stop()` → LeaveGroup never invokes
   `on_partitions_revoked`, so `_handoff_flush` never fires for the DEPARTING
   replica's own open objects. Measured on c6 in the restart arm: "Shutting down"
   16:35:14.198Z → "LeaveGroup request succeeded" 16:35:14.318Z (**120 ms**), with
   **14 open objects** in memory and **no flush line** in its log. Every flush in
   this run came from the SURVIVING replica's eager revoke. The arms still passed
   because the acquirer seeds from the last ordinary durable row — correct, but
   staler — so the residue bound `7c86223d` establishes is **not applied on the
   deployment / rolling-restart path**.
3. **Tracker 187 "spans the move" is proven at the VERSION level only, not
   terminal.** `corr_affected_history_truncated_total == 0` everywhere, and the
   monotone radius is carried by the flush; but the terminal-affected superset
   check needs an object to CLOSE, and 155c proved no object can close on this
   rig (tracker **196** — the tenant-idle eviction backstop is inert while any
   assigned partition has never been read). 155d did not attempt the terminal
   tail for that reason. Residual open objects after the run (c6 3, c7 12) are
   torn-down twin objects of the same pre-existing kind.
4. **The ambient `corr_signals` duplicate persists** (tracker **198**): control
   357 rows / 356 unique / **1 dup**, restart 319 / 317 / **2**, exit-join
   344 / 343 / **1**. The CONTROL arm has no rebalance at all and still carries a
   duplicate in both 155c and 155d — which is exactly row 198's point. The
   restart arm's 2 is one above ambient and is **not** attributable to the move on
   this evidence.
5. **Rig artefact, no measurement affected.** The exit-join arm aborted once at
   the twin's registry gate before emission (16:43:08Z, evidence kept at
   `arm-exitjoin-aborted-registrygate/`): the chain reads its device baseline 1 s
   after the previous teardown, while replicas still cache the deleted fleet, so
   it waited for a total that was never reachable. Re-run alone at 16:55:25Z, it
   passed the gate in 52 s. Chain-sequencing bug in the harness, not a product
   defect — a future chain should gate on `registry_identities` settling first.

## 5. What this closes

Tracker row **155 is deleted**. All three of its WORK items are discharged:
(a) the loss was quantified against twin ground truth across ordinary
rebalances (155a); (b) the answer is **reconstruct identity + transfer the last
consistent snapshot**, not accept-and-bound; (c) §11 coverage is 69 cases in
`test_ownership_seed_155.py` with every guard mutation-verified, plus the live
arms above. The owner's condition on **automatic `BUS_PARTITIONS` sizing**
("frozen until the orphan-write half closes", 2026-08-17) is now MET on the
evidence in §3 — lifting the freeze is an owner call, not a consequence of this
doc. Carried forward as their own rows: **196** (terminal-row unreachability),
**198** (ambient signal duplicate), **199** (graceful-shutdown flush gap).
