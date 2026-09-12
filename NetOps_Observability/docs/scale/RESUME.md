# CORRELIX GA qualification — resume brief

**Read this first when picking the work back up.** One page of orientation, then
the paste-ready prompt at the bottom.

Last updated: 2026-08-22 · branch `feat/observability-platform`

---

## READ FIRST — 2026-08-22 evening: the ratified bar is GREEN

`SOAK_READINESS_VERDICT_2026-08-22.md` is the current truth. **T-nominal
(ratified workload) = FULL PASS — tracker 166's bar is MET** (completion 340s,
accounting exact, 1000/1000 devices). **S1 storm = FAIL on a measured
single-owner ingest wall** (49s loop stalls → Kafka ejection churn → ~150–250
eps effective; invariants held, zero loss) → new trackers **172** (storm-
priority scheduling — the next implementation item), **173** (refusal-stream
livelock), **174** (loop-independent health/metrics). **Nominal 72h soak = RUNNING** (launched 2026-08-22 ~23:30Z, ends ~08-25
late evening; SOAK_72H_100EPS — disk-sized rate, test-pinned; cron suspended
with #SOAK-SUSPENDED markers; sampler → soak-metrics-2026-08-22.csv).
**Pre-2.5K engine work COMPLETE IN CODE, awaiting post-soak deploy:** 172
ingest-priority (`eb609b45`), 163 OPEN_OBJECTS cap (`97b2600c`), 162
continuation index (`dd3f2154`) — one deploy after the soak report, then S1
re-qualification, then the first 2.5K characterization. Nightly cron = T-nominal;
weekly S1 stays on deliberately (it fails honestly until 172). Much of the
older material below is superseded by the 2026-08-22 docs
(PREGA_ARCHITECTURE_REVIEW, EPS_BASELINE_PROPOSAL, STRESS_GATE_REDEFINITION,
ARCHIVE_REDESIGN v2 — all ratified/implemented).

## The 30-second version

Two correctness defects were found and fixed and are **live-qualified**: tracker
**168** (a device-local interface name acting as a global correlation identity,
which welded the entire estate into one RCA object) and tracker **170** (the
qualification harness reporting PASS while the engine had evaluated 3 % of the
workload). The harness now tells the truth, and the truth is that **tracker 166
still FAILs**: the engine cannot evaluate the 1K workload inside the
qualification budget.

The bottleneck has moved **four times**, each time to a per-object cost that was
invisible when 168's weld produced a single object. The current one is measured
and specific: **`_archive_slice` writes a ~8,500-row, window-sized slice per RCA
object — 98.6 % of all correlation persistence time, 0.47 objects/sec.**

## Where the bodies are buried

| Tracker | State | Notes |
|---|---|---|
| 165 retention | **PASS — frozen** | 516.527 s is a correctness contract, not a tunable |
| 168 identity scope | **PASS — live-qualified** | 2,586 objects audited, 0 multi-device welds. Do not weaken either defence layer |
| 170 completion gate | **PASS — validated live twice** | it failed both post-168 runs correctly |
| 167 template index | **PASS offline**, live-deployed | live selectivity still unvalidated, but the BLOCKER is gone: the harness now has `--event-mix realistic` (six kinds). A 1K run at that mix is what converts it to PASS-live |
| **166 scheduler** | **FAIL** | *cannot complete one cohort in budget*; blocked on archive persistence |
| 171 maintenance | OPEN, non-blocking | worst prune gap 1,363 s vs ~180 s intended; catch-up always succeeded |
| 169 CI | **OPEN — merge blocker** | see below; re-pinned 2026-08-22, currently green |
| 156 archive slice | **now the blocker** | its own row predicted this: "sized by the whole WINDOW rather than by the object" |
| 72h soak | **BLOCKED** | |

## The one thing to understand before touching anything

Every bottleneck so far has been the same defect in a different place: **work
performed per RCA object whose size is set by something global — the catalog,
the window — rather than by the object.**

1. `build_edges` candidate explosion → fixed by **168**
2. 100 templates scored per object → fixed by **167**
3. `Catalog.version_hash` re-serialising the catalog per object (48.6 % of a
   cycle) → fixed 2026-08-22
4. **`_archive_slice` writing a window-sized slice per object → CURRENT**

Pre-168 there was one object, so all four were harmless. 168 corrected the
identity model, the real shape is ~1,000 small objects, and each of these became
O(objects × global) in turn.

**Do not point-fix #4 and re-run.** An architectural review was recommended and
not yet done — see the next section. Three waves have been spent discovering the
next bottleneck by running an hour-long qualification.

## The architecture review is DONE — read it first

`docs/scale/PREGA_ARCHITECTURE_REVIEW_2026-08-22.md` (charter:
`/var/tmp/Re-architect.md`). Verdict: **KEEP CURRENT ARCHITECTURE WITH ONE
TARGETED STRUCTURAL CHANGE** — re-shape the archive persistence model (156
residual) for the many-small-objects regime; everything else survives
falsification. The targeted change now has a full design:
`ARCHIVE_REDESIGN_156_2026-08-22.md` — **v2 after two adversarial peer
reviews (both REJECTED v1's Layer 2; L1 approved with changes)**: the shipped
design is the component-only slice — one membership-rule change, no schema
change, no migration, ~48× storage win, replay proven clean on the fixture
and gated on a corpus-wide falsification test. One owner decision pends:
Inspector ambient-context sourcing (§5 of the doc). New finding in the review: the harness's null-keyed injection splits
one tenant 50/50 across both replicas (measured 64,740/64,480), so every
per-replica capacity figure is a per-HALF-tenant figure and production
single-tenant capacity is ~2× overstated — fix harness keying before grading
the next run. The three questions below are answered in §§7, 11–12, 18 of the
review.

## Gates are redefined (proposal) — 2026-08-22

`STRESS_GATE_REDEFINITION_2026-08-22.md`: two test families (T = provisioning,
graded on sustainable throughput at 90 %; S = storm, graded on invariants +
DEBS-style recovery, never real-time keep-up). Storm profiles externally
anchored: S1 design storm (10 % blast radius, ~10× aggregate, 15 min, drain
≤3×), S1-long (60 min), S2 escalation ramp (NEW — the slow-escalation failure
class), S3 = today's stress relabelled engineering probe (invariants + trend
only), S4 chatter probe (NEW — sub-10 s flap noise). Nightly cron should move
from S3 to Family-T nominal once ratified. Evidence: ~60-source research
corpus (ISA-18.2/EEMUA-191, IMC/SIGCOMM/ToN measurements, streaming-benchmark
methodology). Notably: IBM Netcool/Impact is sized at 350–500 eps sustained —
our measured single-owner ceiling is industry-typical for correlators.
Awaiting owner ratification (§8 of the doc).

## Watchdog + TLS rotation (2026-08-23, during soak)

Stack-watchdog installed as user cron (1-min cadence, ntfy phone alerts —
it was NEVER previously installed despite CLAUDE.md describing it). Its first
cycle caught served TLS certs on kafka/opensearch/postgres/vector-aggregator
expiring at soak hour ~18 (17:26-17:28Z). Rotated 02:50-03:00Z with ZERO soak
impact: kafka via dynamic keystore reload (all 3 listeners, no broker
downtime), postgres/clickhouse/nginx via config reload, restart-class
services restarted (correlation NOT touched — already fresh). All wire certs
verified to Aug 26. Maintenance event recorded in the soak log. Session-
independent soak-completion ntfy notifier armed. KNOWN-OPEN observations for
the post-soak sweep: `CorrProbeLaneFlatlined` critical is CHRONIC since
08-19 (probe lane → engine intake dead — investigate); one
`CHMemoryLimitExceeded` at 02:40Z (likely the OS-purge merge churn —
attribute via ch-query-budget-check.sh); `rotate-tls-services.sh` has a
compose-invocation path bug (looks for docker-compose.yml in CWD — run from
deployment/docker or fix `dc()` to pass -f files explicitly).

Soak hour-15 checkpoint (2026-08-23 ~14:00Z, session watch):
  * Green: lag 9-19 all samples, disk 14-15G free, replicas restarts=0,
    accounting lanes clean. Old-session stray sampler (61MB ndjson) killed.
  * RSS slope is REAL and time-driven, not volume-driven: corr-1 (owner)
    ~8.7 MiB/h AND corr-2 (standby, syslog_received=0) ~7.5 MiB/h — the
    standby leaks with ZERO events, so suspect per-cycle/per-scrape growth,
    not per-event state. Projection at soak end: ~866 MiB (69% of cap) /
    ~625 MiB — survivable, no intervention. Hour-15 /metrics baselines saved
    (scratchpad metrics-baseline-h15-*.txt) for the hour-24 diff.
  * corr_deadletters 2.85M explained and BENIGN for the soak: the real lab
    spines (spine1/spine2, SR Linux) stream syslog into the collector;
    unregistered -> F-11 identity_unattributable refusal + sealed quarantine
    (live-fire zero-trust validation with real devices). Flood was ~63 eps
    of sr_grpc_server DEBUG "BuildAndStart" churn (gnmic gRPC redial loop,
    seq ~1.6M) until ~10:53Z, now ~2 eps. DLQ file cap-rotated (40MB total),
    quarantine ring bounded (200), accounting is mlx-prefix-scoped: soak
    validity untouched. SWEEP: register-or-silence spine1/2 (gnmic target
    auth/TLS churn? debug level shipped to collector), and consider a
    refusal-rate alert (63 eps of sealed refusals for 12h was invisible).
  * SWEEP (observability defect): VM scrape of correlation is REPLICA-BLIND —
    service-DNS round-robin, no instance label; VM recorded the standby's
    zeros while the owner held 2.85M deadletters. Per-replica scrape targets
    (or 174's sidecar as the scrape endpoint, per-container) post-soak.

TLS rotation hardening wave (2026-08-23 afternoon, owner-directed; benchmark
doc = docs/security/TLS_ROTATION_BENCHMARK_2026-08-23.md):
  * rotate-tls-services.sh v2: dc() compose-path fix; DAILY cron (05:07);
    NEED-BASED restart class (restart only when held cert < 72h, wire-probed
    or recorded via scripts/.rotate-tls.loaded); qualification guard (hot
    legs run, restarts defer during live miniladder runs); floor-based
    verification (48h) for not-due/deferred endpoints. Proven live twice
    against the running soak (hot class now on the Aug-30 mint, zero
    restarts, soak untouched).
  * stack-watchdog.sh: TLS heartbeat checks (DEGRADED / 26h check-stale /
    10d act-stale) AND a REAL bug fixed live: scaled services (correlation
    x2) broke docker inspect (newline-joined cids) -> false "state=" DOWN
    every minute since the second replica existed; now probes every replica
    and keys restart/OOM tracking per container.
  * tls_ca.go: re-issue loop jittered +-10% (crypto/rand, unit-tested) —
    effective at next api restart (post-soak batch).
  * rules.yaml: TLSReissueLoopSuspect dead-man (api served cert < 72h =
    mint loop dead; vmalert -dryRun-validated, hot-reloaded live).
  * STAGED for post-soak restart: opensearch-security.yml
    ssl_cert_reload_enabled (SEC-019.1 part 4) — then move opensearch from the
    sweep's restart class to a reload leg.
  * Watchdog fix exposed + fixed a LOST CRON: host-hygiene (10-min disk
    sweeper) vanished from the crontab during 2026-08-22's cron surgery
    (heartbeat frozen at Aug 22 18:00) — reinstalled 2026-08-23; disk-full
    protection active again during the disk-sensitive soak.

SOAK ABORTED AT HOUR 26 (2026-08-24 ~00:41Z) — harness vehicle, not platform:
  * Cause (proven): each produce chunk execs a console-producer JVM (512M
    default heap) INSIDE kafka's ~1.08 GiB cgroup, ~88% full after 26h of
    page-cache accrual -> direct-reclaim stalls (memory.events max=43,521;
    tool-JVM start 7.8s at idle) -> 3 chunks crossed the 90s timeout ->
    burst aborted honestly. Broker: 0 restarts, 0 OOM kills, consumers fine.
  * Fixes SHIPPED (34ffc3ab): kafka_tool pins tool heap -Xmx192m; lab .env
    KAFKA_MEM_LIMIT 1109m->1536m (applies at kafka recreate, pending).
  * Secondary finds: redis/valkey served an EXPIRED cert for 7h (missing
    from the rotation sweep entirely) — hot-reload leg added + executed,
    healthy again; grading also flagged memflat (corr-1 71->379 MiB is
    restart-baseline vs plateau — sampler shows FLAT h16-26; CH 1298->2020
    of 5.2G — attribute post-mortem) and stability (4 consumer restarts =
    the operator-approved TLS-rotation window; 1 replica log unreadable).
  * First 26h were CLEAN at ~102 eps: lag 9-19 throughout, zero loss,
    RSS plateaued, disk stable. The run FAILS as a 72h soak; the evidence
    from its first 26h stands as characterization, not qualification.
  * DECISION PENDING (owner): restart soak on the current build, or take
    the queued deploy batch FIRST (172+163+162+174 + tls jitter + OS
    reload flag + F-18 image) and soak the GA-candidate build — saves a
    whole 72h cycle later; recommended.
  * OWNER RATIFIED (2026-08-24): deploy batch FIRST, then soak the
    GA-candidate. EXECUTED same night: kafka recreated at 1536m; correlation
    x2 on the new image (172 ingest-priority + 163 open-objects cap + 162
    ContinuationIndex + 174 sidecar + archive v2 + ch-retry); api rebuilt
    (TLS jitter live); opensearch recreated (ssl_cert_reload flag ACTIVE —
    single-file bind mounts need recreate, not restart, after an inode-
    replacing edit); F-18 confirmed already live in the router's mounted
    config; healthchecks (base+tls) migrated to the :8094 sidecar. TWO
    deploy-caught 174 defects fixed (6a644bac): lifespan never CALLED
    _start_health_sidecar (nothing listened), and the sidecar read TLS env
    names no deployment sets (would have served plaintext) — both now
    pinned by tests. Replicas are named correlation-2/-3 after the scale
    recreate (update any tooling that assumes correlation-1).
  * Gate in progress: T-nominal smoke on the new build
    (data/miniladder/gate-smoke-2026-08-24.log). PASS -> start the fresh
    72h soak (soak-72h profile) with sampler/notifier re-armed at the new
    container names. The nightly/weekly cron stays #SOAK-SUSPENDED.
  * GATE HISTORY (2026-08-24 night): run 1 red on two one-liners (archive
    slice lost to a DEFINITE CH code-241 rejection the retry contract
    wrongly excluded — fixed in aae727b5 with a definite-rejection retry
    lane on all tables; memflat judged a hardcoded '-1' replica name after
    the scale-recreate renamed replicas — now pattern-discovers and judges
    EVERY replica). Run 2 green everywhere except stability: 2 consumer
    restarts caused by the BROKER briefly fencing itself (own KRaft
    heartbeat socket timeout 9.7s at 05:32) — evidence CONTAMINATED by this
    session running the full pytest suite + builds on the same host
    mid-run; accounting still balanced exactly through the blip. Run 3 on
    a QUIET host: ALL PHASES PASS (burst 400/s exact, drain 75s,
    completion 389s, accounting exact, memflat 9 containers, stability 0
    restarts, cleanup verified).
  * 72h SOAK #2 LIVE: started 2026-08-24T06:27:55Z on the GA-candidate
    build, ends ~2026-08-27T06:30Z. Log data/miniladder/
    soak-72h-2026-08-24.log; sampler soak-metrics-2026-08-24.csv (replica-
    name agnostic, 30-min cadence); session monitor + every-minute
    watchdog + daily rotate-tls (self-defers restarts) + 10-min host-
    hygiene all armed. Replicas: netops-correlation-2/-3.
  * HOUR-20 CATCH (2026-08-25 02:30Z): the recreate had silently DOWNGRADED
    correlation to the planner's stale 789m .env value — the qualified
    1280m + CORR_WINDOW_BUFFER=150000 lived only in compose.mem125.yml,
    which COMPOSE_FILE never included. Memory cap restored LIVE via
    `docker update --memory 1280m` (zero restarts, soak evidence intact);
    .env now sets CORRELATION_MEM_LIMIT=1280m AND appends compose.mem125.yml
    to COMPOSE_FILE so every future `up` carries the qualified values.
    CORR_WINDOW_BUFFER stays 50000 until the post-soak recreate (does not
    bind at soak amplitude: window ~3.4k signals; all three gate runs
    passed on 50000) — restore-by-recreate is the first post-soak step.

## Superseded: the originally recommended review (3 questions)

1. **State and enforce the invariant** — "per-object work must be sized by the
   object, not the window or the catalog" — then audit every per-object path
   (object construction, content hashing, continuation, merge detection,
   attribution, archive slice) and table its true sizing. This says whether a
   fifth bottleneck is already waiting.
2. **Bounded cohorts × object formation.** Nodes not yet scored have no edges and
   can form singleton objects that are persisted, then merged later. Live it
   looks contained (~800 objects vs 1,000 devices, the severity open-floor
   filters most) but 166 and 156 were designed independently and their
   interaction has never been reviewed.
3. **Persistence model vs the new object shape.** ~8 ClickHouse inserts per
   object, serialised, on the event loop, at 0.47 objects/sec. Reasonable for a
   handful of large objects; never examined for a thousand small ones. Batching
   / offload / one archive write per cohort are all plausible — choosing is an
   architecture call, not an optimisation.

Then fix, then re-run. Not before.

## Measured numbers you will want

Latest run `082201589waa` (2026-08-22, 1000 devices / 12 min / 182 eps):

* Kafka transport drain **24 s** · devices **1000/1000** · injected **131,041**
* **cohorts advanced 2**, pending **129,220 and completely flat for all 2,160 s**
* `corr_signals_archive`: 1,130 inserts, p50 **152 ms**, **222.4 s of 232.4 s**
  total correlation insert time (**98.6 %**); every other corr table ~2.5 s
* object persistence **0.47/sec**; slice sizes observed **8,461** and **8,904** rows
* `epoch_seconds_max` **221 / 230 s** (was 3,956 s pre-167)
* RSS **338 / 328 MiB of 1280** · 0 CommitFailed / UnknownMember / restarts / rebalances
* offline `run_window` **495.86 → 186.63 s (2.66×)** from the cache fixes — and
  the run still got *worse* on the gate, because the bottleneck had moved

Secondary defect, real but not dominant (1 abort/replica): a ClickHouse
`ReadTimeout` raises `CHInsertRejected` out of `_persist_snapshot` past
`_mark_processed`, so the whole cohort is discarded and retried.
`P(cohort commits) = (1 − p)^objects`; CH-side insert latency reached 14,395 ms.

## Two things that are still unratified

* **The GA workload contract.** → PARTIALLY RESOLVED 2026-08-22: see
  `EPS_BASELINE_PROPOSAL_2026-08-22.md` (externally-grounded bands, promotion
  ratio 5/15/30 %, 1K→10K ladder; owner ratified 1K-in-one-tenant as the
  starting envelope). Original text kept below for context.
   182 eps at ~100 % promotion is a synthetic
  figure. The planner says 5,000 raw syslog EPS for 1,000 devices; the harness's
  own help text implies ~200. All current points are `CHARACTERIZATION ONLY`.
  See `docs/scale/GA_WORKLOAD_CONTRACT_1K.md`. **166's remaining PASS criteria
  are throughput criteria, so the target being unratified is a real blocker.**
* **166 mechanism vs 166 capacity.** Everything 166 built is proven live
  (preparation 3 per 17 epochs, cohorts bounded, frontier and edges bounded,
  memory flat). It stays FAIL only on throughput, which is 167's territory. The
  owner may want to split the row; it has been offered and not decided.

## Tracker 169 — read this before assuming CI is clean

`ingest-contract-ci` runs all of `tests/`. `test_error_swallow_guard.py` is
**line-keyed by design**, so inserting code above a reviewed handler makes it go
red until the handler is re-read and re-pinned. That happened on 2026-08-22
(tracker 170 inserted ~210 lines) and all five sites were re-read, confirmed
behaviourally unchanged, and re-pinned with a written justification. **That is
the intended workflow, not an exemption.** Never allowlist a NEW site to get
green, and never weaken the guard.

## Lab state

**Re-check before trusting the baseline below.** The `scale-miniladder-nightly`
cron fired on this branch at 03:17 on 2026-08-22 (run `08220317gmp4`) and ran
~45 min. It FAILED on drain / correlation_completion / accounting / memflat, and
it is confounded — **both correlation replicas restarted mid-run** (the harness
correctly refuses to call an unreadable engine idle), so its verdicts are not
usable as 166 evidence. Two things in it are worth reading anyway, because they
independently reproduce the defect fixed this session on the PRE-FIX image:
`netops.corr_objects` insert failures **3** (the un-retried engine-cycle path —
each one discarded a cohort) and **71** rows dead-lettered `ch_insert_transport`
(the batcher exhausting all four retries against the 10 s client timeout — which
is why the timeout bump matters to both paths, not just the engine's). It also
flagged a fresh **memory leak slope** on `netops-correlation-1`, 474 → 639 MiB
(×1.35 against a ×1.3 gate) after input stopped — new, not previously tracked,
and worth a look before the next qualification run.


Stack is up on `compose.mem125.yml` (1280 MiB/replica, 2 replicas, BUS_PARTITIONS
4). Correlation image carries 166+167+168 plus the cache fixes. Last run's
cleanup deleted 1000 devices and purged CH+OS. A standing **~2 EPS** external
UDP/514 source is refused as `identity_unattributable`; it cannot contaminate
run-scoped accounting (DLQ is counted by runid grep and refusals withhold the
hostname).

---

## Paste-ready resume prompt

```
Continue CORRELIX GA qualification from the current branch.

DO NOT start the mini-ladder or the 72-hour soak.
DO NOT point-fix the archive slice and immediately re-run.

STATE
  165 PASS/frozen · 168 PASS live · 170 PASS live · 167 PASS offline (live
  selectivity unvalidated) · 166 FAIL · 171 OPEN non-blocking · 169 OPEN
  (re-pinned, currently green) · 1280 MiB floor unchanged · soak BLOCKED.

WHY 166 FAILS NOW
  Not throughput-in-general. The engine cannot complete a SINGLE cohort inside
  the 2,160 s budget. Measured: `corr_signals_archive` is 98.6% of correlation
  persistence time (1,130 inserts, p50 152 ms, 222.4 s of 232.4 s), object
  persistence 0.47/sec, ~8,500-row window-sized archive slice PER OBJECT. This
  is tracker 156's residual `_archive_slice`, which its own row predicted.

THE PATTERN THAT MATTERS
  Four bottlenecks, all the same defect: per-object work sized by something
  GLOBAL (catalog, window) rather than by the object. Harmless pre-168 when
  there was one object; O(objects x global) now that there are ~1,000.

FIRST TASK — the architectural review, before any more code
  1. State the invariant "per-object work is sized by the object" and audit
     every per-object path against it; produce a sizing table. Is a fifth
     bottleneck already waiting?
  2. Review the bounded-cohort x object-formation interaction (singleton
     objects for not-yet-scored nodes, persisted then merged). 166 and 156 were
     designed independently.
  3. Review the persistence model for ~1,000 small objects rather than a few
     large ones: ~8 CH inserts/object, serialised, on the loop.
  No code changes in that step. Then fix, then re-run one clean 1K.

ALREADY FIXED 2026-08-22 (do not redo)
  * The ClickHouse-timeout cohort discard. `ch_insert` had NO retry at all --
    tracker 160's retry machinery was wired only into the batcher -- and the
    httpx timeout was hard-coded 10.0s against a measured 14,395ms commit, so
    an UNKNOWN outcome was reported as a positive refusal. ch_insert now honours
    the same bounded-retry contract as the batcher, gated on provable
    idempotence (CH_DEDUP_SAFE_TABLES, justified per-table from init.sql;
    corr_signals and corr_signals_archive deliberately excluded), and
    CORR_CH_TIMEOUT_S defaults to 30s. 15 tests, both-direction mutation proofs.
    NOT deployed -- the running image predates it.
  * The 167 harness gap. scale-miniladder.py gained --event-mix realistic (six
    distinct kinds, verified through the real classifier, deterministic in seq).
    `single` stays the default and is byte-identical to before over 3,000
    events, so every 166 capacity number stays comparable. 11 tests.

HOUSE RULES
  Measure before optimising — the bottleneck has moved every single time.
  Mutation-test every guard; a check that cannot go red is not a check.
  Never weaken 165 retention, 168 identity scoping, or the 170 completion gate.
  Report FAIL as FAIL; do not bank partial evidence from an invalid run.
```
