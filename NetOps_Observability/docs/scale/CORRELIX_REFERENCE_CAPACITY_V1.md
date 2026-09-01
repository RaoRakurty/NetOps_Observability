# CORRELIX REFERENCE CAPACITY — V1 (permanent qualification profile)

**Filed 2026-09-01 on owner directive (post-Project-1).** This document is the
**permanent, versioned qualification profile** for the Correlix single-host
reference configuration. It pins every input that gives the qualification its
meaning — hardware, workload, scenario digests, memory caps, scorer version,
gates — so that **any future build can rerun this exact qualification and be
compared against the V1 baseline run of record.**

> **Versioning rule (owner, 2026-09-01 — binding).** Future builds MUST be able
> to rerun this exact qualification. Any **semantic** change — a different
> workload shape, seed, digest, device count, rate, cap, gate clause, scorer
> semantics, SLO wording, or aggregation-plane configuration — requires a
> **NEW versioned profile (`CORRELIX_REFERENCE_CAPACITY_V2.md`)**, never a
> silent modification of V1. This file changes only to fix typos or add
> cross-references; its numbers and digests are frozen.

**V1 baseline run of record: `storm-s11`** (run `090121382mk4`, run dir
`/var/tmp/scale-runs/storm-s11-09012138`, 2026-09-01, post-ultra-fix-wave
images at `0f8ea9d4`) — **9/9 gates, the first perfect run in programme
history**, every clause of the ratified SLO met (4/4), and the first leg graded
under the §8(e) environment clause (11 GiB root-fs free, load1 2.9 at launch).
Full scorecard: §9. It supersedes `storm-s09` (run `09010750fq0u`, 8/9 — sole
FAIL the onboard-ratio harness artifact, tracker 202), which remains cited in
§9.1 as the **pre-fix-wave baseline** for comparison; s09's grading:
`PROJECT1_DONE_2026-09-01.md` §5.

---

## 1. Hardware assumptions — the reference box

| item | value |
|---|---|
| CPU | 4 cores, Intel Xeon E5-2683 v4 @ 2.1 GHz |
| RAM | 15 GiB |
| Disk | 77 GB |
| Deployment | full Docker-Compose stack on one host (`docker-compose.yml` + `compose.offline-images.yml` + `compose.tls.yml` + `compose.mem125.yml` + `compose.lab.yml`) |

Every V1 number was measured on this box (`HOST_CEILING_2026-08-31.md`,
"Box under test"). A rerun on different hardware is a different measurement and
must say so; it does not re-baseline V1.

## 2. Workload definition

| parameter | value | source |
|---|---|---|
| device count | **2,500** (`mlx-<runid>-NNNNN`, addresses in 198.18/15) | `t-storm-2.5k` profile |
| event rate | **~1,000 eps sustained** (lane plan `[("fleet", 1.0, "production", 1000.0)]`) | `scripts/scale-miniladder.py` `WORKLOAD_PROFILES["t-storm-2.5k"]` |
| burst duration | **15 minutes** (900 s, 90 × 10,000-event chunks) | same |
| total events | **900,001** (900,000 burst + 1 pipeline canary) | accounting gate, exact on every graded leg |
| shard count | **1** — tenant-keyed producer (`producer_key_mode=tenant`, key `global`): the whole tenant stream lands on one partition → one correlation replica carries the storm | `HOST_CEILING_2026-08-31.md` §5 |
| correlation replica count | **2** (`--scale correlation=2`; one carrier + one idle under the single-tenant workload) | deployment contract |

## 3. Scenario definition — `t-storm-2.5k` (pinned)

| parameter | value |
|---|---|
| profile / scenario | `t-storm-2.5k` → scenario `storm-2.5k` (`STORM_SCENARIO_2K5`, shape `chain.DEFAULT_SHAPE`) |
| seed | **20260829** (`SCENARIO_SEED_DEFAULT`) |
| storm share | **~1.78 % of the 900,000-event plan** (the "2 %" rung — the conservative low-share configuration); the rest is disjoint background noise |
| stories | **345 labelled incidents** over **5 templates**: `upstream_link_failure`, `local_link_fault`, `bgp_peer_flap`, `ospf_adjacency_flap`, `enterprise_outage` |
| scenario mass | 16,060 scenario events; 990-device disjoint noise pool; background never shares a cause entity with an incident |
| determinism | the scenario is a **pure function of (profile, seed, device list)** — same seed ⇒ same digest ⇒ byte-identical stream |

**Pinned digests (from the profile tests — these are the qualification's
identity):**

- **Scenario digest** (`tests/test_storm_scenario_profile.py`
  `DEFAULT_SCENARIO_DIGEST`, seed 20260829 over the fixture `mlx-storm-*`
  device names):
  `f9d126d41c3fdf209dcba5b37c402a7f0ba19352f420e95289948972c36c33be`
  — verified unchanged across the `chain.StormShape` refactor at commit
  `f943af36` (same 16,060 events, 345 incidents, 990-device noise pool before
  and after). Note: the digest is a function of the device *names*, so a live
  run with real `mlx-<runid>-*` ids hashes differently; what is pinned is that
  the fixture plan does not move, and a live run's own digest + seed are
  recorded in its `ground-truth.json`.
- **Profile-registry digest** (`tests/test_workload_profiles.py`
  `PRE_LADDER_PROFILE_DIGEST`, the 15 pre-ladder profiles canonicalised as of
  commit `2a4c66e5`, `t-storm-2.5k` and `t-nominal-2.5k` included):
  `5c634edce461d95d42991ec59ac9ef9cc8948827d3b7425d38c52609e60a5082`
  — a changed rate, window, mix, lane split or class on any pinned profile
  turns this red and re-bases every recorded number.

Both pins are enforced by the test suite; a rerun of V1 REQUIRES both tests
green on the build under qualification.

## 4. The SLO — Option A, verbatim (ratified, owner 2026-08-30, `237b1161`)

> *Under a 15-minute 1,000-eps storm on 2,500 devices, the platform MUST
> evaluate the whole workload within 45 minutes of burst end, lose nothing
> (injected == persisted, 0 DLQ), stay within memory caps, and keep RCA accuracy
> ≥ 93 %. T1 p95 is measured and published every run but is not a pass/fail
> gate.*

The SLO's authority is `P4_PROGRAMME_WRITEUP_2026-08-29.md` §8 and
`docs/audit/INVARIANTS.md` §10. V1 qualifies against this statement and no
other; a reworded SLO is a V2.

## 5. Scorer version

**Twin scorer v2 — commit `06450430`** (tracker 191: `affected_includes` over
the union of the objects touching the story + deterministic `best`). The v1
scorer's UUID coin-flip clause is retired; any accuracy number quoted for a V1
rerun MUST state `scorer_version: 2`. On v2 the baseline corpus scores
**345/345 = 100.00 %** (detection 1.000, specificity 1.000), and
4,278/4,278 labelled stories at or below the rate ceiling across the programme.

## 6. Memory caps — per-service cap table (the rig's qualification values)

Sources: `deployment/docker/docker-compose.yml` (`${*_MEM_LIMIT}` stanzas),
`deployment/docker/compose.mem125.yml` (the correlation sizing overlay), and
the installed `deployment/docker/.env` at qualification. The harness reads the
same caps (plan-sized, per container) for its `memflat` headroom clause.

| service | cap | notes |
|---|--:|---|
| correlation (×2 replicas) | **1,280 MiB each** | `compose.mem125.yml` / `CORRELATION_MEM_LIMIT=1280m`; `CORR_WINDOW_BUFFER=150000` (a resource ceiling, not the horizon) |
| api | **565 MiB** | `API_MEM_LIMIT=565m` |
| ClickHouse | **5,326 MiB cgroup**; effective `max_server_memory_usage` **4,096 MiB** | `CLICKHOUSE_MEM_LIMIT=5326m`; the 85 % p99 MemoryTracking clause is judged against the server cap |
| OpenSearch | **3,774 MiB** (heap 1,887 MiB) | `OS_MEM_LIMIT=3774m` / `OPENSEARCH_HEAP=1887m` |
| Kafka | **1,536 MiB** | `KAFKA_MEM_LIMIT=1536m` |
| VictoriaMetrics | **1,602 MiB** | `VICTORIA_MEM_LIMIT=1602m` |
| vector-aggregator / vector-router | **512 MiB each** | compose default `VECTOR_MEM_LIMIT` |

**How the harness judges them** (`scripts/scale-miniladder.py`,
`MEM_SERVICES = api, clickhouse, correlation, kafka, opensearch,
vector-aggregator, vector-router, victoria`): stateless services (api,
correlation) on `docker stats`; cache-bearing services on **cgroup anonymous
memory** (page cache excluded — ~68 % of docker-stats "RSS" was reclaimable
cache, measured); ClickHouse additionally on its OWN accounting — **zero new
`MEMORY_LIMIT_EXCEEDED`** (`system.errors` delta, with the like-units exemption
`22bdaeb1`+`c0faf797` for the backfill's own 512 MiB per-query budget refusing
as designed, sole producer verified) and **p99 MemoryTracking < 85 %** of the
effective `max_server_memory_usage`. Growth clause: end-of-run ≤ warm
(end-of-burst) × 1.3 with a 64 MiB jitter floor; headroom clause: no key
container above 85 % of its own cap.

## 7. Aggregation-plane default — ON, the conservative ~2 %-share configuration

`CORR_AGGREGATION_PLANE` is **ON by default** in the shipped compose
(`a9d9a10c`, `deployment/docker/docker-compose.yml:1201` →
`CORR_AGGREGATION_PLANE: ${CORR_AGGREGATION_PLANE:-1}`). The **image default
remains OFF** (`src/correlation/main.py`) so the A/B overlay contract holds;
`CORR_AGGREGATION_PLANE=0` in `.env` is the documented fallback (with a
measured cliff at the 25 % storm rung — the OFF arm was INCOMPLETE there).

V1 qualifies the plane **at the ~2 % (achieved 1.78 %) storm share** — the
conservative configuration on which neutrality was proven (T1 within ±10 % on
every clause, accuracy Δ 0.00 pp). The plane's own accounting MUST close
exactly on every V1 rerun: `corr_agg_observed_total` ==
Σ`forwarded{class}` + `suppressed` (s09: 54,767 = 49,902 + 4,865, 8.88 %
suppressed — digit-identical observed count to s06/s07/s08 on the
deterministic workload). Moving this default is a semantic change → V2 (see
`docs/audit/INVARIANTS.md` §10a).

## 8. Expected run metadata — how a V1 rerun is graded

**(a) The nine harness gates** (`scripts/scale-miniladder.py`,
`t-storm-2.5k`, recorded in `report.json` `phases[]`):

1. `preflight` — stack up + healthy, consumers ACTIVE, residue 0, baselines captured
2. `onboard` — 2,500 devices created via the API, identity-verified (not count-verified)
3. `burst` — registry propagation + canary, then 900,000 events @ 1,000 eps in 900 s
4. `drain` — consumer lag back to ≤ baseline + ε within budget
5. `correlation_completion` — pending 0 on both replicas within the 2,700 s budget
6. `accounting` — injected == persisted, exact; 0 DLQ; per-device coverage; quarantine stable
7. `memflat` — §6's memory clauses, per container
8. `stability` — 0 CommitFailed / 0 UnknownMember / 0 restarts / 0 rebalances; stalls judged against the LIVE session timeout (tracker 190 derivation string read, not assumed)
9. `cleanup` — every created device deleted + whole-namespace verify, CH+OS purged, residue 0

**(b) The TTUR query** — the clean-scope SQL of
`RUN_PLAN_P3_AB_2026-08-29.md` **§5.3**, verbatim (per-incident
`min(window_start)` inside the leg's burst window, storm-aggregate `AGG_CID`
excluded, scope from the leg's own `report.json`), emitted to the run dir as
`ttur.tsv` + `ttur-scope.json` by `scripts/scale-rca-latency.py`. T1 p95 is
published, never gated (SLO clause). *(Terminology: T1 = time to first
correlated version — an engineering lifecycle metric, not TTUR proper; see the
terminology notes in `HOST_CEILING_2026-08-31.md` / `PROJECT1_DONE_2026-09-01.md`
and tracker 205.)*

**(c) The twin scoring recipe** — against the run's own seeded ground truth
(`ground-truth.json`, digest + seed recorded by the harness):

```bash
python3 scripts/lab/twin/twin.py score --runid <runid> --run-root data/miniladder
```

on **scorer v2** (`06450430`), reading resident `corr_objects` (device-registry
purge does not block a re-score). Report `accuracy-report.{json,md}` +
`twin-score.log` in the run dir.

**(d) Pass bar for a V1 rerun:** every SLO clause of §4 met (completion
≤ 2,700 s after burst end, accounting exact 900,001 == 900,001 + 0 DLQ + 0
counted rejections, memory caps held per §6, accuracy ≥ 93 % on scorer v2), the
aggregation accounting of §7 exact, and no unexpected replica ejection or
restart. Both baseline legs (`storm-s11`, and `storm-s09` before it) met all of
these; tracker 203 wraps this
document into the rerunnable release regression suite.

**(e) Qualification environment (added 2026-09-01):** a V1-graded leg additionally requires **≥ 10 GiB root-fs free at preflight and a quiet host** (no concurrent CI suites/builds during the leg) — motivated by `storm-s10` (run `09012025x578`, **excluded from qualification for environment violation**): concurrent CI disk draw pushed the root-fs through OpenSearch's flood-stage watermark mid-burst and the router's OS sink discarded 291,296 syslog evidence docs (`/var/tmp/scale-runs/storm-s10-09012025/s10-discard-diagnosis.md`; tracker 209/210).

## 9. Baseline evidence — `storm-s11` (the V1 leg of record)

**Designated 2026-09-01 (late session): `storm-s11`, run `090121382mk4` — the
first 9/9 VERDICT PASS in programme history**, on the complete ultra-review fix
wave, and the first leg run and graded under the §8(e) environment clause.

| clause | s11 reading |
|---|---|
| gates | **9/9 PASS — first ever** (incl. onboard ratio 0.747 ≥ 0.6 floor, the clause s09 failed; stop=none) |
| completion | **94.8 s** engine completion (23 m 41 s total after burst end, drain 1,320 s / peak lag 423,155 included) of the 2,700 s budget |
| losslessness | **900,001 == 900,001 + 0 DLQ + 0 counted rejections**; 2,500/2,500 devices covered; 53,965 `corr_signals` rows |
| memory | **memflat PASS all 9**: carrier ×1.011 FLAT at 82.5 % of cap, idle replica ×1.033 at 7.0 %, api 22.7 %, CH p99 MemoryTracking 32.3 % (peak 42.9 %) with 82 backfill-negotiation refusals exempted (sole producer verified), OS 63.2 %, Kafka 43.5 % |
| accuracy | **345/345 = 100.00 %** `scorer_version: 2` (16 ClickHouse queries; emission journal absent by design for miniladder runs) |
| T1 p95 (published, not gated) | **876 s** (p50 80, p99 1,363, max 1,734; T-last p95 2,020; inc 1,624, versions 10,371, sigs 80,853) — inside the 816–912 s clean-leg band |
| aggregation accounting | exact, **cumulative across s10+s11** on the deploy's containers (started 19:31Z, not recreated between legs): observed 109,534 = forwarded 99,838 + suppressed 9,696 (8.85 %); observed = exactly 2 × 54,767 — the deterministic workload's digit-identical per-leg count (metrics-final.txt carries the cumulative-scope note) |
| stability | 0 CommitFailed / 0 UnknownMember / 0 restarts / 0 rebalances over 2,803 s; worst loop stall 6,649 ms = 11.1 % of the 60 s session timeout (read live from both replicas) |
| cleanup | 2,500 devices deleted + whole-namespace verified, CH+OS purged (OS 900,001 docs in 213 s), residue 0 |
| environment (§8e) | **11 GiB root-fs free, load1 2.9 at launch** — first leg graded under the clause; PASS |
| scenario | seed 20260829, digest `0e1a8d7b4e707c505ae1bc505464be69aa26231d040cfce0fe38c779786404d5`, 345 incidents / 16,060 scenario events, storm share 1.78 % achieved exactly |
| images | correlation `23dc2b88e966` (identical on both replicas; built 2026-09-01T19:23:57Z), api `f6c67a4d0195` (OCI revision `0f8ea9d467bb…`, built 19:24:14Z) — the complete ultra-review fix wave at `0f8ea9d4`; plane ON (`a9d9a10c`); deployed 19:31Z |

Artifacts in the run dir: `report.{json,md}`, `metrics-final.txt` (both
replicas, mTLS :8443, cumulative-scope-noted), `ttur.tsv` + `ttur-scope.json`
(§8(b) clean-scope SQL verbatim), `accuracy-report.{json,md}` +
`twin-score.log` (scorer v2), `ground-truth.json`, `lag-curve.json`,
`correlation-completion.json`, `burst-chunks.json`.

### 9.1 Pre-fix-wave baseline — `storm-s09` (superseded 2026-09-01, retained for comparison)

| clause | s09 reading |
|---|---|
| completion | **93.7 s** engine completion (24 m 07 s total after burst end, drain included) of the 2,700 s budget |
| losslessness | **900,001 == 900,001 + 0 DLQ + 0 counted rejections**; 2,500/2,500 devices; 53,981 `corr_signals` rows |
| memory | **memflat PASS — first ever at 2,500 devices**: all 9 key containers within ×1.3 and under 85 % of caps; carrier ×0.954 FLAT at 78.0 %; api 33.4 %; CH p99 37.5 % with 558 refusals exempted (the 512 MiB budget working as designed) |
| accuracy | **345/345 = 100.00 %** scorer v2 (detection 1.000, specificity 1.000, 0 fails in any template) |
| T1 p95 (published, not gated) | **912 s** (p50 88, p99 1,384, max 1,756; T-last p95 2,293) — inside the 816–912 s clean-leg band |
| aggregation accounting | observed 54,767 = forwarded 49,902 + suppressed 4,865 (8.88 %) — exact |
| images | correlation `a9e99871e812` (`36036db5`), api `eefcc527730a` (`eb29c87a`), plane ON (`a9d9a10c`) |

Grading detail and the honest artifacts (onboard-ratio clause, tracker 202):
`PROJECT1_DONE_2026-09-01.md` §5/§7.
