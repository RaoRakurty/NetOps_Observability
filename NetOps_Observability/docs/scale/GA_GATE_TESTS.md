# GA Gate Tests — evidence map for the scale-test defect classes

Single index of the tests that make the 2026-08 scale-test defect classes
structurally impossible to reintroduce, and where each runs. The defect classes
and P0s are from `CORRELIX_SCALE_TEST_REPORT.md` §8 and
`SCALE_TEST_FINDINGS.md`; every test listed in classes **1–3** exists and passes
on `feat/observability-platform`.

**Class 4 is the exception and is marked as such:** it is a declared GA
correctness gate whose tests are NOT yet built. It is listed because a gate
recorded only in a tracker row is not a gate — but do not read its rows as
existing coverage.

**Gates**
- **G1 (per-PR, blocking)** — `.github/workflows/backend-ci.yml`
  (`go vet` / `go test ./...` / `go test -race` / staticcheck / gosec /
  govulncheck), `correlation-ci.yml` (full `pytest` + `ruff`),
  `ingest-contract-ci.yml` (`python3 -m pytest tests/`).
- **G2 (nightly)** — `perf-nightly.yml` (wall-clock canaries, `PERF_CANARY=1`),
  `fuzz-nightly.yml`.
- **G3 (pre-release)** — `release-bundle.yml` + `fresh-install-integrity.yml`
  artifact/install verification, `scripts/soak-go-no-go.sh` on the scale rig.

All tests below are **deterministic accounting tests** (operation counts,
bytes, structure sizes) unless marked as a wall-clock canary — the PR gate
never depends on runner speed.

---

## Defect class 1 — hidden super-linear cost (O(N²) onboarding; scale P0 #1)

The device store rewrote the whole fleet on every write: 155 → 63 → 25
creates/s over the first 2k devices (`SCALE_TEST_FINDINGS.md`, "Device
inventory / onboarding").

| Guarding test | Gate | GA criterion evidenced |
|---|---|---|
| `src/backend/internal/discovery/devstore_records_test.go::TestPerDevicePutWritesO1Records` | G1 backend-ci | Store layer: N-th Put writes exactly 1 record, bounded bytes — bulk onboarding is linear |
| `devstore_records_test.go::TestLegacyBlobMigratesToPerRecordStore` / `::TestMigrationCrashRerunsIdempotently` | G1 backend-ci | Upgrade path to the per-record store loses no device/tombstone and re-runs safely |
| `devstore_records_test.go::TestPutFailureLeavesMemoryConsistent` / `::TestRemoveTombstoneWriteFailureRollsBack` / `::TestPrefixLoadFailureRefusesWrites` | G1 backend-ci | A 2xx never stands for a write that did not land (per-record failure paths) |
| `src/backend/onboarding_cost_test.go::TestDeviceCreateHTTPCostIsO1Records` | G1 backend-ci | **Full API path**: create #590 costs the same backend records/bytes/calls as create #10 through the real router+auth+handler+store wiring |
| `src/backend/onboarding_cost_test.go::TestDeviceListHTTPBackendBudget` | G1 backend-ci | Read-side budget contract: `GET /api/devices` performs **0** backend calls (served from the in-memory aggregator cache), independent of fleet size |
| `src/correlation/test_engine_complexity.py` (brute-force-equivalence + operation-count suite) | G1 correlation-ci | Engine pairing stays equal to the O(N²) reference while doing bounded work (scale P0 #2's complexity half) |
| `src/correlation/test_perf_canary.py` (`perf_canary` marker) | G2 perf-nightly | Wall-clock catastrophic-regression canary for the correlation hot paths (explicitly NOT on the PR gate) |

## Defect class 2 — silent failure (loss counted but visible nowhere; DLQ P0)

238k dead-letter payloads were lost at runtime while only
`QUARANTINE_WRITE_FAILURES` incremented (`SCALE_TEST_FINDINGS.md`,
"Correlation dead-letter durability").

| Guarding test | Gate | GA criterion evidenced |
|---|---|---|
| `src/correlation/test_ga_failure_accounting.py::test_every_failure_counter_is_surfaced_on_healthz` | G1 correlation-ci | **Counter-exposure contract**: every module-level failure/drop counter (AST-discovered, so new orphans fail the suite) surfaces on `/healthz` → `/metrics` → alerts |
| `test_ga_failure_accounting.py::test_counter_discovery_finds_the_known_failure_counters` | G1 correlation-ci | The discovery itself cannot silently go blind (pins the known counter set) |
| `test_ga_failure_accounting.py::test_zero_unexplained_event_loss` | G1 correlation-ci | **Event accounting invariant**: consumed == persisted + deadlettered + counted rejections over a mixed valid/forged/poison batch — zero unexplained losses |
| `test_ga_failure_accounting.py::test_burst_drains_to_steady_state_memory` | G1 correlation-ci | 12k-event burst leaves every module-level container bounded and drained back to steady state |
| `src/correlation/test_durability.py::test_startup_probe_refuses_uncreatable_dlq_dir` / `::test_startup_probe_refuses_unwritable_existing_dir` / `::test_boot_refuses_before_any_task_starts_when_probe_fails` | G1 correlation-ci | **DLQ boot fail-fast**: an unwritable dead-letter dir refuses boot instead of failing 238k times at runtime |
| `test_durability.py::test_startup_probe_passes_writable_dir_and_creates_it` / `::test_startup_probe_is_a_noop_when_dlq_dir_unset` | G1 correlation-ci | The fail-fast probe has no false positives (writable dir passes; unset is a loud warning, not a refusal) |
| `test_durability.py::test_rejected_insert_is_counted_per_table` / `::test_rejected_critical_write_raises_so_the_offset_is_not_advanced` / `::test_malformed_payload_is_written_to_the_durable_dlq` / `::test_dead_letter_file_is_size_capped` | G1 correlation-ci | No ClickHouse write or poison event is lost silently (F-38/F-40 counters + durable, size-capped DLQ) |
| `tests/test_install_data_dirs.py::test_ensure_data_dirs_covers_tls_and_deadletter` | G1 ingest-contract-ci | The installer hands `data/correlation/deadletter` (and `data/tls`) to the service uid — the root cause of the 238k loss cannot recur at install time |

## Defect class 2b — a GREEN signal that proves nothing

The sibling of class 2, and the harder half: not a failure nobody surfaced, but a
CHECK that passes vacuously. Two live instances, both found after the artifacts
they covered had already been reported as validated:

* **Alert rules were never behaviourally tested.** `preflight-configs.sh` ran
  `promtool check rules` on `rules.yaml` only, and mounted only that file for unit
  tests — so a `*.test.yaml` naming a `rules-scale-slo.yaml` alert resolved ZERO
  rules, and **promtool reports an empty result set as SUCCESS**. A test asserting
  on a nonexistent alert was green.
* **A measurement tool that MANUFACTURES failures.** The twin's accuracy scorer
  issued one blob-carrying ClickHouse scan per entity (390 queries, ~21 min);
  under a giant object **13 queries were lost to `Code: 241` and each lost query
  was reported as a MISS** — a failure that never happened. This is the worst
  member of the class: promtool and `-dryRun` merely fail to DETECT a problem,
  whereas this INVENTS one, and every accuracy number computed from it is wrong
  in an unknown direction. Fixed to two lean phases: 8 queries, 103 s, 0 lost.
  The general rule: **a lost measurement must never be recorded as a negative
  result** — it is a THIRD outcome, and the tool must say so.
* **"Validated" meant "parses".** `rules-scale-slo.yaml` was reported as
  "vmalert `-dryRun` validated". True — and much weaker than it sounds: a dry run
  proves the file LOADS, never that a rule fires. Syntax-loads vs
  behaviourally-covered reads identically in a status report, which is how it
  survived. Keep this distinction in every future validation claim.

| Guarding test | Gate | GA criterion evidenced |
|---|---|---|
| `tests/test_alert_rule_coverage.py::test_every_rule_file_is_promtool_checked` | G1 ingest-contract-ci | Every `rules*.yaml` is named in the preflight check — a NEW rule file cannot repeat the unvalidated-for-its-whole-life story |
| `tests/test_alert_rule_coverage.py::test_every_rule_file_is_mounted_for_unit_tests` | G1 ingest-contract-ci | Every rule file is mounted for the promtool TEST run (checked-but-unmounted is the exact original defect; mutation-verified by deleting the mount) |
| `tests/test_alert_rule_coverage.py::test_referenced_alerts_all_exist` | G1 ingest-contract-ci | Every asserted `alertname` exists — promtool's empty-set-is-success semantics can no longer hide a typo or a rename |
| `tests/test_alert_rule_coverage.py::test_each_test_file_names_at_least_one_alert` | G1 ingest-contract-ci | A test file that asserts on nothing fails instead of passing |
| `tests/test_alert_rule_coverage.py::test_rule_files_exist` | G1 ingest-contract-ci | The discovery globs cannot go empty — **the four guards above cannot themselves become vacuous** (the same trap, one level up) |
| `src/config/rules-tests/correlation-consumer-state.test.yaml` (11 promtool cases) | G1 fresh-install-integrity | The scale-SLO rules fire when they should AND stay SILENT when they should (startup ≠ idle; an 8-minute rebalance blip ≠ a 15-minute idle alert; one replica at zero partitions ≠ a parallelism ceiling) |

## Defect class 2c — event-loop starvation (P1 thrash, twice)

A uniform fault signature across ~1000 devices folds the access layer into a few
GIANT correlation objects (measured **750 nodes / 48,375 edges**); per-object
pure-CPU serialization cost ~7.5 s EACH on the event loop, 10–15 per cycle =
75–110 s of starvation, which **cumulatively** expired the consumer heartbeat (no
single call exceeded 1.60 s — the first diagnosis, "one >30 s block", was wrong).
The revoke hook then amplified it by running up to 60 s of ClickHouse I/O inside
the rejoin. Natural drain fell to **9.5 events/s**; post-fix **~3,680/s**.

Refuted hypothesis, recorded so nobody re-runs the experiment: **not DLQ fsync.**
p50 102 µs; a burst driving ~2.3k synchronous DLQ writes/s per replica produced
633 ms max loop drift and ZERO stalls. A batching prototype was built and
**reverted** — it broke the immediate-durability invariant of class 2 for a saving
measurably off the critical path.

| Guarding test | Gate | GA criterion evidenced |
|---|---|---|
| `src/correlation/test_loop_blocking.py` (6 cases) | G1 correlation-ci | Size-unbounded pure-CPU work is OFF the loop (inline 2.40 s → offloaded 0.39 s worst latency), with wire bytes and dedup tokens byte-identical |
| `src/correlation/test_consume_poll_cadence.py` (7 cases) | G1 correlation-ci | Poll cadence survives heavy processing; membership tuning pinned; revoke commits flush-before-commit and never advance past unpersisted work (F-38) |
| revoke-budget bounds + arithmetic cases | G1 correlation-ci | Each revoke leg is bounded (5 s, 2× backstop ≤ ⅙ of `rebalance_timeout`); a flush that misses budget **skips the commit** rather than waiting — F-38 preserved by not acknowledging |
| `corr_loop_lag_stalls_total` + `CorrelationEventLoopStalling` alert | G2 nightly / runtime | **The standing regression guard for this entire class**: any nonzero increase means the loop is being starved again, whatever the new cause |

## Defect class 3 — warn-and-continue error swallows (§16.1; installer P0)

`ensure_data_dirs` printed `[info] Fix: sudo chown -R ...` and continued —
two broken deployments in one week.

| Guarding test | Gate | GA criterion evidenced |
|---|---|---|
| `tests/test_install_data_dirs.py::test_both_paths_failing_fails_the_install` / `::test_ingress_key_both_paths_failing_fails_the_install` / `::test_ingress_key_missing_fails_instead_of_chowning_nothing` | G1 ingest-contract-ci | The replacement contract: when ownership cannot be established, the install **fails** (exit 1) with the remedy — never warn-and-continue |
| `tests/test_install_data_dirs.py::test_permission_error_falls_back_to_pinned_helper_container` / `::test_stale_root_owned_child_triggers_fallback` / `::test_wedged_docker_daemon_is_bounded_and_fails` | G1 ingest-contract-ci | The non-root path succeeds via the pinned helper container, and the fallback itself is bounded and loud |
| `tests/test_error_swallow_guard.py::test_no_literal_swallow_patterns_in_scripts` | G1 ingest-contract-ci | `except OSError: pass/continue` and bare `except Exception: pass` are structurally banned in `scripts/*.py` **and** `scripts/*.sh` (heredocs included) |
| `tests/test_error_swallow_guard.py::test_oserror_handlers_escalate_or_are_reviewed` | G1 ingest-contract-ci | **Every** OSError/PermissionError handler in `scripts/*.py` escalates or carries a reviewed, line-pinned allowlist entry (new swallows require a conscious allowlist edit; stale entries fail) |
| `tests/test_error_swallow_guard.py::test_chown_remedy_never_ships_as_warn_and_continue` | G1 ingest-contract-ci | The exact defect shape — a chown remedy delivered via `warn`/`info`/`print` in a function that never escalates — can never ship again |

---

## Defect class 4 — state that does not follow ownership (tracker 155)

**⚠ THIS GATE IS DECLARED BUT NOT YET SATISFIED.** Unlike classes 1–3 above,
the tests in this section **do not exist yet**. The class is recorded here
because it is a *hard GA correctness gate* (owner, 2026-08-17), and a gate that
is only written down in a tracker row is not a gate.

Correlation window state (`OPEN_OBJECTS`, `main.py:910`) is a plain in-process
dict with **no rehydration path** — no restore, no checkpoint, no transfer.
`on_partitions_revoked` flushes and commits durable output but evicts no window
state; `on_partitions_assigned` records ownership and reconstructs nothing. So
whenever partitions move between members, the acquiring replica begins with an
empty window for those tenants and the previous owner holds orphaned state.
Evidence accumulated across the move is lost **silently** — nothing errors, and
lag returns to zero exactly as it would on a healthy transition.

Provenance matters for prioritising it: `fa69894b` (tenant-keyed
co-partitioning, scale P0) introduced the range assignor and multi-replica
consumption together. Before it, correlation was a single consumer and this was
a rare restart-only edge. **A scale fix converted a restart edge into a routine
one.**

| Required test | Gate | GA criterion it must evidence | Status |
|---|---|---|---|
| RCA ground-truth accuracy unchanged across an **ordinary replica restart** under `--scale N>1` | G3 | The common case. A deploy or crash must not silently degrade RCA | ❌ not built |
| …across a **scale-up** (`N` → `N+1`) and a **scale-down** (`N` → `N-1`) | G3 | Ownership movement without a partition-count change is the frequent path | ❌ not built |
| …across a **rolling restart** and a **rapid repeated rebalance** | G3 | Rebalance storms must not compound the loss | ❌ not built |
| …across a **partition increase** (2 → 4) with the documented drain | G3 | The migration procedure in `scale-correlation.md` is actually safe | ❌ not built |
| No tenant observes another tenant's state after any of the above | G3 | §3a isolation survives ownership movement | ❌ not built |
| Consumer state enum reports **cold-window** distinctly from **zero-partitions** and **never-joined** | G1 | The gap is operator-visible rather than silent (Phase 1, in flight) | ❌ not built |

**The assertion that decides the gate** is RCA ground-truth accuracy against the
digital twin, compared before and after ownership movement — *not* "lag drained"
and *not* "containers healthy". Lag measures offsets, not window continuity;
both stay green while evidence is being lost. The twin already records ground
truth and already scores accuracy (`scripts/lab/twin/`), so the instrument
exists; only the scenarios are missing.

**Consequence while this gate is unsatisfied:** automatic EPS→`BUS_PARTITIONS`
sizing stays **frozen** (`docs/RESOURCE_SIZING.md`). Auto-sizing a knob that
moves ownership would multiply an unmeasured correctness surface — and that
freeze holds regardless of how good the throughput calibration turns out.

---

## What this map does NOT claim

The G1/G2 suites prove the defect **classes** cannot silently return; they are
not scale certification. The `CORRELIX_SCALE_TEST_REPORT.md` §8 verdict stands:
GA **scale** sign-off additionally needs the L2+ rig runs (throughput at
target EPS, HA/replica, soak — G3 territory, `scripts/soak-go-no-go.sh`)
now that both P0 fixes have landed.

It also does not claim class 4 is covered. Classes 1–3 are guarded; **class 4 is
an open GA correctness gate with no tests behind it** (tracker 155). Until it
passes, "the scale P0s landed and CI is green" is true but insufficient — the
P0 that unlocked horizontal scale is the same change that made ownership
movement routine, and nothing yet proves correctness survives it.

Known allowlisted §16.1 residue (reviewed 2026-08-16, tracked in
`tests/test_error_swallow_guard.py` `ALLOWLIST`): four secondary chown
swallows in `scripts/install.py` (enrichment seed, processors seed,
appid/cloud fixtures, vuln dir) still pass-and-continue with an
"api adopts on first write" rationale — flagged `TODO: route via chown_tree`;
they are pinned by file+line so they cannot multiply silently.
