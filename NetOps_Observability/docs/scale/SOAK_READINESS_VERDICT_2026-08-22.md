# Soak-readiness verdict — first qualification under the ratified gates

**Date:** 2026-08-22 (evening wave) · **Runs:** four T-nominal attempts
(final: `08221930…` rc=0) + one S1 design storm (`082220005r1a` rc=1)
**Workload:** the OWNER-RATIFIED contract — 1K devices in ONE tenant,
tenant-keyed, promotion-realistic (`EPS_BASELINE_PROPOSAL`,
`STRESS_GATE_REDEFINITION`, both ratified earlier today).

---

## The verdict

**Family-T (provisioning): PASS — tracker 166's ratified bar is MET.**
**S1 (design storm): FAIL on capacity — a real, newly-measured single-owner
INGEST wall, with invariants intact.**

**72-hour soak: START-ELIGIBLE in its primary form** — Family-T nominal +
S4 chatter, the form that tests what a soak exists to test (memory drift,
lifecycle, retention, maintenance over 72 h). The embedded S1 exercise is
EXCLUDED until the storm fix lands; storm-inclusive soak and GA storm claims
stay gated on it.

## T-nominal — the first fully-green qualification in the programme

All phases PASS at 400 raw EPS / ~5 % promotion / one owner replica:

| Gate | Result |
|---|---|
| burst | 360,001 events @ exactly 400/s, tenant-keyed |
| transport drain | **23 s** (budget 2,700) |
| correlation completion (170) | **340 s, pending 0, oldest 0.0 s, cohorts +9** |
| accounting | **EXACT: 360,001 == 360,001 + 0 DLQ + 0 rejections; 1000/1000 devices** |
| memflat / stability / cleanup | flat · 0 CommitFailed / 0 UnknownMember / 0 restarts · stack left clean |

Three latent defects were found and fixed across the four attempts, each
caught by the harness's own honesty gates and each mutation-pinned:
mix-dependent canary (`ce42088d`), legacy-loop modulus starvation — exactly
100/1000 devices covered (`7aa5b022`), and **F-18: OpenSearch bulk-retry
duplication under server slowness, fixed with Kafka-coordinate document ids**
(`3dc65096` — a production-grade platform fix: at-least-once indexing is now
idempotent across syslog/snmptrap/applogs/cloudlogs/DLQ lanes).

## S1 — the storm found the wall the architecture review predicted

Injection itself was perfect: 3,600,001 events at 3,975/s, lanes exactly per
spec (storm 3.276 M / background 324 k), all tenant-keyed onto ONE partition —
the production topology.

**What failed, causally:**

1. One owner replica must ingest 3,975 raw eps AND correlate ~1,200 admitted
   sig/s on one GIL (`cpus: 2` unusable). Engine cycles under storm produced
   event-loop stalls up to **49.3 s > the 30 s Kafka session timeout** →
   the broker EJECTED the member mid-stall → rebalance → consumer restart
   (8 restarts, 117 UnknownMember, 5 CommitFailed) → effective consumption
   **~150–250 eps**. Final lag 3.21 M of 3.6 M; full drain ETA ~4–6 h vs the
   45-min ratified budget. Partition-level proof: p0/p1/p2 lag 0, p3 (the
   tenant) lag 3.07 M.
2. **Post-storm livelock decay state (NEW):** refused events (devices deleted
   at cleanup) never advance the stream watermark, so semantic expiry stalls
   and the engine re-correlates a frozen dead window at ~1 core while the
   consumer starves at ~2.7 eps. Cleared by replica restart; needs a real fix
   (watermark advance or idle-eviction on refusal-only streams).
3. **Observability starvation (NEW):** under the same stalls, `/metrics` and
   `/healthz` (served from the loop) stop answering within probe timeouts —
   Docker health flapped, the harness's completion probe read a replica as
   unreadable/changed. In an orchestrator that ACTS on health, this is a
   self-inflicted restart-during-storm. Containers in fact never crashed:
   restarts=0, OOM=false.

**What HELD under a 15-minute 10× storm (the invariant half of the S-gate):**
zero event loss (Kafka held everything; the 2 lost writes were best-effort
`netops.findings` rows, counted), memory flat and far from caps
(memflat PASS), no process crash/OOM, tenant isolation intact. The 71/1000
"uncovered devices" accounting finding is an artifact of grading coverage
while 89 % of the stream was still queued — expected-secondary of the wall,
not a loss.

## Why this is the review's prediction, not a surprise

`PREGA_ARCHITECTURE_REVIEW` §8 named the single-owner ceiling and noted every
historical run had hidden it behind the null-key split; §20 Test B was
designed to measure it. S1 measured it for free, harder than the planned
experiment: **the ceiling binds at the INGEST tier, not just scoring**, via
stall→ejection→rebalance churn.

## The two fixes, in order

1. **Storm-priority scheduling (near-term, targeted — new tracker 172):**
   under declared `storm_mode` (hysteresis just shipped), the engine defers /
   shrinks cycles so the CONSUMER keeps wire speed; the backlog is evaluated
   within the recovery budget. This is precisely the ratified subset
   degradation contract ("evaluate less during storm, declared") and the
   industry pattern (criticality tiers: ingest CRITICAL, correlation
   deferrable). Expected effect: consumption returns to the ~2,000+ eps
   handle-path ceiling during storms; drain ≤3× becomes reachable at S1
   amplitude. Also fixes finding 3's worst stalls by construction.
2. **Option B — process-parallel scoring (capacity, per review §19):** frees
   the GIL for good and raises sustained per-owner throughput. Trigger
   formally FIRED by this measurement; scope per the review (pure scoring
   stage in workers, deterministic re-sort, state stays put). Build after
   172 is measured, not concurrently.

Plus two smaller rows: **173** watermark/livelock on refusal-only streams;
**174** loop-independent health/metrics serving (thread-served snapshot), and
S1-scale cleanup hardening (purge raced a 2.8 M backlog; OS purge timed out —
completed manually via async delete_by_query this session).

## Lab state after the wave

Backlog drained via replica restart (dead-window livelock cleared); leftover
2.25 M OS docs purged (async task); stack healthy; nightly cron = T-nominal
(the ratified regression gate), weekly S1 stays enabled deliberately — it
will FAIL until 172 lands, and that is the honest signal.

## Recommendation to the owner

1. **Start the 72 h soak now** in its primary form (nominal + S4 chatter,
   promotion-realistic, static membership) — every gate it depends on is
   green, and delaying it buys nothing the storm work needs.
2. Approve **tracker 172 (storm-priority scheduling)** as the next
   implementation item; S1 re-qualification follows it.
3. Option B remains the sustained-capacity track, sequenced after 172's
   measurement.
