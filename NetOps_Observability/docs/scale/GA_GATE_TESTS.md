# GA Gate Tests — evidence map for the scale-test defect classes

Single index of the tests that make the 2026-08 scale-test defect classes
structurally impossible to reintroduce, and where each runs. The defect classes
and P0s are from `CORRELIX_SCALE_TEST_REPORT.md` §8 and
`SCALE_TEST_FINDINGS.md`; every test listed exists and passes on
`feat/observability-platform`.

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

## What this map does NOT claim

The G1/G2 suites prove the defect **classes** cannot silently return; they are
not scale certification. The `CORRELIX_SCALE_TEST_REPORT.md` §8 verdict stands:
GA **scale** sign-off additionally needs the L2+ rig runs (throughput at
target EPS, HA/replica, soak — G3 territory, `scripts/soak-go-no-go.sh`)
now that both P0 fixes have landed.

Known allowlisted §16.1 residue (reviewed 2026-08-16, tracked in
`tests/test_error_swallow_guard.py` `ALLOWLIST`): four secondary chown
swallows in `scripts/install.py` (enrichment seed, processors seed,
appid/cloud fixtures, vuln dir) still pass-and-continue with an
"api adopts on first write" rationale — flagged `TODO: route via chown_tree`;
they are pinned by file+line so they cannot multiply silently.
