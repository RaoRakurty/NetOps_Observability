#!/usr/bin/env python3
"""scale-miniladder.py — G2 self-judging nightly scale-regression harness.

Proves, on EVERY run and on ANY hardware, that the stack still holds the
RELATIVE/invariant properties whose loss produced this release's three scale
defects — without asserting a single absolute-throughput number:

  1. Onboarding stays LINEAR      (would have caught the O(N^2) per-device
                                   persistence collapse — fleet rewrite on
                                   every create; fixed in f65b9ac0).
  2. Correlation lag DRAINS       (would have caught "lag never drains":
                                   after a 10x-nominal burst stops, consumer
                                   lag must return to baseline within a
                                   bounded multiple of the burst duration).
  3. NOTHING is lost silently     (would have caught the 238k silent
                                   DLQ-drop: every injected event is either
                                   persisted, in a DLQ we can count, or in an
                                   explicitly-counted rejection — an
                                   unexplained delta FAILS the run).

Phases (each emits PASS/FAIL + evidence into the run dir):
  preflight   REFUSES the run outright if another harness process holds the
              run lock (live pid), or if ANY `mlx-` device of ANY run id is
              still in the device store — a leftover fleet sits on the same
              198.18/15 addresses, so the API's dedupe absorbs this run's
              creates into it and every number becomes unattributable
              (2026-08-29; override MLX_ALLOW_FOREIGN_RESIDUE=1, logged
              loudly). Then: stack up + healthy (watchdog-style container
              checks, API login,
              ACTIVE bus consumers — a broker that authenticates but denies
              its consumers, as after the 2026-08-16 wiped-ACL incident, fails
              HERE, not 40 minutes in) and baseline capture: per-container
              RSS, Kafka end offsets + consumer-group lag, ClickHouse row
              counts, VictoriaMetrics active series, correlation durability
              counters, Vector loss counters.
  onboard     create N devices via the API (names `mlx-<runid>-NNNNN`,
              addresses in 198.18/15 — RFC 2544 benchmark space, unroutable
              on purpose). Creation rate over the LAST window must be
              >= linearity-floor x the FIRST window's rate. Records an
              `onboard_stop_reason`: `absorbed` (dedupe folded creates into
              other devices) or `shortfall` (fewer own devices than requested)
              SKIP the workload and go straight to cleanup — the fleet the
              burst would be judged on is not the one that was planned;
              `none` carries on, so a pure LINEARITY-ratio FAIL still runs its
              burst and stands as an independent verdict.
  burst       gate on registry propagation (created devices must reach the
              correlation engine's identity registry, else every injected
              event is tenant-refused into the DLQ), prove the pipeline with
              one canary event, then inject syslog at --eps for
              --burst-minutes via the broker's console producer (mTLS
              listener on the TLS variant), keyed to the created devices with
              real mnemonics. `--event-mix single` (default) emits only
              %LINK-3-UPDOWN — ONE correlation signal kind, the workload every
              recorded capacity number was measured on. `--event-mix realistic`
              emits a weighted mix yielding six distinct kinds, which is what
              tracker 167's signal-kind template index must be judged against.
  drain       consumer lag must return to <= baseline + epsilon within
              --drain-factor x burst duration; the lag curve is recorded.
  accounting  injected == OpenSearch-persisted (exact, hostname-prefix count)
              + run-attributable DLQ lines + explicitly-counted Vector loss.
              Plus: every burst device appears in corr_signals (silent
              per-device eviction check) and quarantine WRITE failures must
              not move (the metric-less 238k-drop signal, healthz-only).
  memflat     leak slope: end-of-run memory per key container <= its
              END-OF-BURST (warm) figure x --mem-factor, with a 64 MiB jitter
              floor — a leak keeps climbing after input stops, a warmed cache
              does not. The INSTRUMENT is docker stats only for the stateless
              services (api, correlation); everything that caches is judged on
              its cgroup ANONYMOUS memory, because docker stats' MemUsage
              carries page cache + slab (~68% of it, measured) and made the
              verdict a coin toss on cache state. PLUS the OOM path: no key
              container above --mem-headroom-percent of its own plan-sized cap,
              and for ClickHouse its OWN accounting: ZERO new
              MEMORY_LIMIT_EXCEEDED (system.errors delta — query_log sees only
              the statement raises, background threads raise the rest), p99
              MemoryTracking < 85% of the effective max_server_memory_usage
              (peak reported, and warned about at/above the cap: the peak is
              one-second RSS transients, p99 is the level the store actually
              runs at), and MaxPartCountForPartition back within
              +20% of preflight and under parts_to_delay_insert/2. The
              cold-baseline->warm step is recorded as evidence only (a 2-min
              burst cannot separate first-touch cache materialization from a
              slow leak — that is the lab run + soak).
  cleanup     ALWAYS runs (also on failure/^C): delete every created device —
              INCLUDING the rows dedupe absorbed, which no list can see — plus
              the devices that absorbed them, then VERIFY the whole `mlx-`
              namespace is empty (a per-prefix "0 remain" is exactly what hid
              the 2026-08-29 residue); purge run-tagged telemetry from
              ClickHouse (corr_signals) and OpenSearch (syslog lane) so
              `clean-slate.sh --verify` still passes after a run. The stack
              is left as found.
  report      report.md + report.json in the run dir; exit 0 only if every
              phase passed.

Usage:
  scale-miniladder.py [--devices N] [--burst-minutes M] [--eps R] [flags]
  scale-miniladder.py --dry-run          # print the full plan, touch nothing
  scale-miniladder.py --help

Credentials (never on argv, never logged): admin login is read from
MLX_ADMIN_USER / MLX_ADMIN_PASSWORD when set, else from ADMIN_USERNAME /
ADMIN_INITIAL_PASSWORD in --env-file (deployment/docker/.env) — the same
source clean-slate.sh --verify uses. OpenSearch service passwords
(OS_API_PASSWORD / OS_BOOTSTRAP_PASSWORD) come from the same file and ride a
curl config on stdin inside the container, exactly like
docs/ops/OBSERVABILITY_AUDIT.md prescribes.

Nightly cron (lab host). Cron's environment is hostile (CLAUDE.md 16.2): PATH
is /usr/bin:/bin, no profile — this script sets its own PATH and needs only
docker + python3. Log to the run root; the summary heartbeat
(<run-root>/last-run.json) is refreshed every run so "the job stopped
running" is itself detectable by the watchdog. Sample line (do NOT install
blindly — pick the hour your lab is idle):

  17 3 * * * /usr/bin/python3 /home/rao/Projects/NetOps_Observability/NetOps_Observability/scripts/scale-miniladder.py --devices 1000 --burst-minutes 5 >> /home/rao/Projects/NetOps_Observability/NetOps_Observability/data/miniladder/cron.log 2>&1

CI feasibility (Deliverable-2 verdict, 2026-08-16): the full TLS stack DOES
boot on GH-hosted runners — .github/workflows/fresh-install-integrity.yml's
`tls-install-boot` job runs `install.py --tls=yes` end-to-end on
ubuntu-latest and asserts the mesh serves. A reduced nightly profile
(200 devices, 2-minute burst) therefore reuses that bring-up in
.github/workflows/scale-miniladder-nightly.yml. The FULL G2 gate
(1000 devices, 5-minute burst) stays on the lab host via the cron line above:
GH runners are 4-vCPU/16 GiB shared VMs whose absolute numbers are
meaningless and whose 6-hour cap the L1-scale run can approach — the CI leg
guards the invariants at small scale, the lab leg is the GA evidence.

Exit codes: 0 = all phases PASS (and cleanup verified zero device residue in
the whole `mlx-` namespace); 1 = any phase FAILED, or device residue was left
behind (report still written); 2 = aborted before touching the stack (usage /
preflight refusal / another run holds the lock).

Residue purge: `--cleanup-only [PREFIX]` deletes every `mlx-`-prefixed device
left by an interrupted run, verifies to zero and purges its telemetry. It runs
no workload and refuses an unreachable stack.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import math
import os
import random
import re
import shutil
import signal
import string
import subprocess
import sys
import time
import typing
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# docker stats MemUsage units. Module scope (a pure constant table): as a class
# attribute ruff RUF012 flags the mutable default, and scripts/ is under the
# pinned-ruff blocking gate (fresh-install-integrity `scripts-lint`).
_MEM_UNITS: dict[str, int] = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3,
                              "TiB": 1024**4, "kB": 1000, "MB": 1000**2, "GB": 1000**3}


# Cron-proof PATH (CLAUDE.md 16.2): docker lives in /usr/bin or /usr/local/bin
# on supported hosts; never rely on an interactive profile. APPLIED IN main(),
# not at import: as module-scope code it leaked into every process that merely
# IMPORTED this file for its parsers — which hid the developer's ~/.local/bin
# and made the shellcheck-based suites fail with "No such file or directory:
# shellcheck" whenever a harness test was collected in the same pytest run.
CRON_PATH = "/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)

# The enterprise-outage chain's WIRE VOCABULARY and PHASE TIMELINE are shared
# with the network digital twin (`scripts/lab/twin/stories.py`) so one fault
# story cannot exist as two drifting copies. Stdlib-only, no back-import — see
# the module docstring. The path insert is guarded because this file is also
# imported (never run) by the test suites, which set sys.path themselves.
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)
import enterprise_outage_chain as chain  # the shared chain (path set above)

DOCKER_TIMEOUT = 30          # bound EVERY docker call (16.3) — a wedged dockerd
KAFKA_TOOL_TIMEOUT = 90      # JVM tools (console producer, consumer-groups)
HTTP_TIMEOUT = 15
MUTATION_TIMEOUT = 180       # ClickHouse ALTER DELETE settle bound

# ---------------------------------------------------------------------------
# INJECTION INTEGRITY — the producer must never lose a record quietly
# (defect 2026-08-29, run p2-s04b-08290858: "901 events UNEXPLAINED").
#
# ROOT CAUSE. `kafka-console-producer.sh` is an ASYNCHRONOUS producer whose
# per-record failures reach an `ErrorLoggingCallback` that only LOGS them; the
# process still exits 0. Worse, its own defaults are a demo toy rather than an
# injection vehicle — measured on the broker we run (apache/kafka 4.1.1,
# `kafka-console-producer.sh --help`):
#
#     --request-timeout-ms          default 1500     (ack deadline!)
#     --message-send-max-retries    default 3
#
# A 1.5 s ack deadline cannot survive a loaded broker. During that run the
# broker was saturated enough that its OWN internal 2 s BROKER_HEARTBEAT
# requests to itself were timing out continuously for the whole 15 min burst
# (`docker logs netops-kafka-1`, 08:55–09:15). On the chunk whose produce call
# took 22.73 s, 901 of 10,000 records exhausted their 3 retries, were expired
# and dropped — and `produce()` below returned `(True, "")` because rc was 0
# and threw the stderr away, which is exactly the §16.1 accept-and-ignore
# defect. The accounting gate (which balances INJECTED against OpenSearch docs)
# then reported a platform "silent drop" that had never happened: measured,
# the topic gained exactly the 869,100 records OpenSearch held, and Vector
# delivered every one of them.
#
# THE FIX, in two independent halves — both are required:
#   1. Settings that turn a busy broker into BACKPRESSURE, never expiry: a 30 s
#      ack deadline, retries bounded only by a 180 s delivery deadline, and
#      idempotent produce so those retries cannot duplicate a record (a
#      duplicate is just as dishonest as a loss — it inflates the balance).
#      `--request-timeout-ms` / `--message-send-max-retries` MUST be passed as
#      the dedicated flags: ConsoleProducer writes its own option defaults into
#      the producer properties, so a `--producer-property request.timeout.ms=…`
#      is not guaranteed to survive them.
#   2. Never trust the exit code alone: the console producer's record failures
#      exist ONLY on stderr, so stderr is read and any send error fails the
#      produce loudly with the reason attached.
# ---------------------------------------------------------------------------
PRODUCER_ACK_TIMEOUT_MS = 30000      # was ConsoleProducer's 1500 ms default
PRODUCER_DELIVERY_TIMEOUT_MS = 180000  # total per-record deadline (bounds §9)
PRODUCER_MAX_BLOCK_MS = 120000       # buffer-full ⇒ BLOCK the send, never drop
PRODUCER_RETRY_BACKOFF_MS = 250
PRODUCER_MAX_RETRIES = 2147483647    # bounded in TIME by delivery.timeout.ms
PRODUCER_HARDENING_ARGS = [
    "--request-required-acks", "-1",
    "--request-timeout-ms", str(PRODUCER_ACK_TIMEOUT_MS),
    "--message-send-max-retries", str(PRODUCER_MAX_RETRIES),
    "--retry-backoff-ms", str(PRODUCER_RETRY_BACKOFF_MS),
    "--producer-property", f"delivery.timeout.ms={PRODUCER_DELIVERY_TIMEOUT_MS}",
    "--producer-property", f"max.block.ms={PRODUCER_MAX_BLOCK_MS}",
    # acks=all + retries>0 + max.in.flight<=5 ⇒ idempotence is accepted; it
    # makes the now-unbounded retries safe (no duplicate on an ambiguous ack).
    "--producer-property", "enable.idempotence=true",
    "--producer-property", "max.in.flight.requests.per.connection=5",
]
# A clean console-producer run prints NOTHING on stderr (verified live against
# apache/kafka 4.1.1 with an empty stdin: no banner, no SLF4J notice). So any
# stderr at all is a finding. These two patterns name the two shapes that mean
# "records were dropped"; everything else is reported as an anomaly rather than
# guessed at.
PRODUCER_SEND_ERROR_RE = re.compile(
    r"Error when sending message|"
    r"org\.apache\.kafka\.common\.errors\.\w*(Timeout|Retriable|"
    r"NotEnoughReplicas|RecordTooLarge)\w*Exception")
PRODUCER_STDERR_ANOMALY_RE = re.compile(r"\bERROR\b|\bException\b|\bFATAL\b")

# TRANSIENT-FAILURE RETRY (defect 2026-08-29, run p2-s012d-08290411). Under
# load — the correlation engine draining a 21k backlog, ClickHouse busy — the
# platform API's socket read timed out and a raw `TimeoutError('timed out')`
# unwound straight out of cleanup(). The run ended
# `RESIDUE LEFT: UNKNOWN (never verified)` with the devices still standing,
# and the same crash had already killed a concurrent `--cleanup-only`.
#
# CLAUDE.md §9 requires every network call to retry with backoff + jitter, so
# there is ONE policy here and every urllib call site uses it: five attempts,
# exponential backoff with FULL jitter (uniform 0..ceiling — the shape that
# actually de-synchronises retries), a per-sleep cap and a total sleeping
# budget. Nothing retries forever and nothing retries an answer the server
# MEANT (see `_http_transient_reason`).
HTTP_RETRY_ATTEMPTS = int(os.environ.get("MLX_HTTP_RETRY_ATTEMPTS", "5"))
HTTP_RETRY_BASE_S = float(os.environ.get("MLX_HTTP_RETRY_BASE_S", "0.5"))
HTTP_RETRY_CAP_S = float(os.environ.get("MLX_HTTP_RETRY_CAP_S", "8"))
# Wall bound on the SLEEPING of one call site (the per-attempt HTTP_TIMEOUT is
# bounded separately). 5 attempts of 0.5/1/2/4s ceilings sleep <= 7.5s, so 30s
# is headroom, not a second policy.
HTTP_RETRY_TOTAL_S = float(os.environ.get("MLX_HTTP_RETRY_TOTAL_S", "30"))
# The only statuses worth repeating: the server is saying "not now", not "no".
HTTP_RETRY_STATUSES = frozenset({429, 502, 503, 504})
# Transport errnos that mean "the peer was busy/absent", never "the request was
# wrong". ECONNREFUSED covers a container mid-restart; ECONNRESET/EPIPE a proxy
# that dropped a busy connection; ETIMEDOUT the kernel-level version of the
# read timeout that caused the defect.
HTTP_RETRY_ERRNOS = frozenset({
    errno.ECONNREFUSED, errno.ECONNRESET, errno.ECONNABORTED, errno.EPIPE,
    errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ENETRESET, errno.ETIMEDOUT,
    errno.EAGAIN,
})

# Containers whose memory growth is asserted in memflat (compose service names).
MEM_SERVICES = [
    "api", "clickhouse", "correlation", "kafka", "opensearch",
    "vector-aggregator", "vector-router", "victoria",
]

# ── memflat instruments (2026-08-29) ───────────────────────────────────────
#
# THE DEFECT THIS EXISTS FOR. `docker stats` MemUsage is cgroup
# `memory.current - inactive_file`: it INCLUDES page cache and reclaimable
# slab. Measured on the ClickHouse container that failed the gate:
#
#     anon 984 MiB + active_file 1,516 MiB + slab_reclaimable 621 MiB
#       = 3.14 GiB reported by docker stats
#     ...against ClickHouse's own MemoryResident of 994 MiB.
#
# ~68 % of what memflat called ClickHouse "RSS" was reclaimable kernel cache,
# so the x1.3 slope was decided by where the page cache happened to sit at the
# warm sample: run p2-s04-08290653 sampled warm 4,314 -> end 3,281 MiB (x0.76,
# PASS) and run p2-s04b-08290858 warm 2,246 -> end 3,854 MiB (x1.72, FAIL) —
# THE SAME CODE, the difference being that s04b's warm sample landed just after
# the previous run's cleanup dropped the cache. Meanwhile the real memory risk
# in both runs went unreported: peak MemoryTracking 4,566 MiB = 95.2 % of the
# 4,794 MiB server cap, with merges alone at 3,978 MiB (83 %).
#
# So: page-cache-bearing (stateful) services are judged on cgroup ANONYMOUS
# memory — the pages that cannot be reclaimed and therefore the ones that OOM
# the container — and ClickHouse additionally answers to its OWN accounting
# (MemoryTracking / merge memory vs max_server_memory_usage) and to the parts
# it leaves behind. The docker-stats ratio survives only where nothing caches:
# see docs/scale/P2_CLICKHOUSE_MEMFLAT_2026-08-29.md §(c).
MEM_STATELESS_SERVICES = ("api", "correlation")
# ClickHouse's own caps, as fractions of the effective max_server_memory_usage.
# THE BOUND IS ON p99, NOT ON THE PEAK — see the CH_MEM_ERROR header below for
# why. The peak is always REPORTED, and warned about once it reaches the cap.
CH_MEMORY_TRACKING_MAX_PCT = float(
    os.environ.get("MLX_CH_MEMORY_TRACKING_MAX_PCT", "85"))
CH_MEMORY_TRACKING_PEAK_WARN_PCT = float(
    os.environ.get("MLX_CH_MEMORY_TRACKING_PEAK_WARN_PCT", "100"))

# `clean-slate.sh --verify` fails a stack whose max consumer-group
# CURRENT-OFFSET exceeds this ("the bus data dir was not reset",
# clean-slate.sh:243). Pinned here so the harness warns about the SAME number
# that script judges, not a different one that happens to share a threshold.
# How many runs of onboard-rate history last-run.json carries (tracker 175).
ONBOARD_RATE_HISTORY = int(os.environ.get("MLX_ONBOARD_RATE_HISTORY", "30"))

# ── THE ONBOARD WALL BUDGET (host-ceiling ladder, 2026-08-30) ──────────────
#
# WHAT ONBOARDING ACTUALLY COSTS, MEASURED — not assumed. `onboard()` has no
# deadline of its own and must not grow one: it is one bounded, retried HTTP
# create per device (`http_retry`), and a create that is merely SLOW is
# evidence (the O(N^2) linearity verdict), never a reason to abandon a fleet
# half-built. What the phase needs is an HONEST EXPECTATION, because a 10K
# rung's onboard is minutes of apparent silence and whatever runs the harness
# — `scripts/scale-ab-driver.py --leg-timeout`, cron, an operator — has to
# budget for it.
#
# The measurement, from this harness's own run dirs (`data/miniladder`):
#   * 2,500 devices in 79.7 s wall — 31.4/s aggregate, first-window 35.0/s
#     decaying to 26.4/s inside the run (report 20260828T014955Z);
#   * 1,000 devices in 29.6 s — 33.8/s (report 20260829T031701Z);
#   * and 15.4/s once the device store carried 35,427 deletion tombstones
#     (tracker 175, `tombstone_debt` below) — the SLOW case, which is the one
#     a budget has to survive.
# So the plan rate is ~30/s and the FLOOR is the tombstone-laden 15/s.
#
# A PLANNING FIGURE OF ~5,600 s FOR A 10K ONBOARD ("10,000 at ~30/s") was in
# circulation when these rungs were authored. It does not survive its own
# arithmetic — 10,000 / 30 = 333 s — nor the runs above, so it is recorded
# here as rejected rather than silently averaged into the budget. The number
# below is derived from the measured rates only.
ONBOARD_RATE_PLAN_PER_S = float(
    os.environ.get("MLX_ONBOARD_RATE_PLAN_PER_S", "30"))
ONBOARD_RATE_FLOOR_PER_S = float(
    os.environ.get("MLX_ONBOARD_RATE_FLOOR_PER_S", "15"))
# Fixed cost before the first create returns (login, preflight residue list).
ONBOARD_BUDGET_BASE_S = float(
    os.environ.get("MLX_ONBOARD_BUDGET_BASE_S", "300"))


def onboard_budget_s(devices: int) -> float:
    """The wall time the onboard phase is EXPECTED to need for `devices`.

    A floor plus per-device time at the measured SLOW rate, so it scales with
    `--devices` instead of being a constant that quietly stops covering the
    fleet: 1,000 -> 367 s, 2,500 -> 467 s, 5,000 -> 633 s, 10,000 -> 967 s.

    INFORMATIONAL ONLY. Nothing aborts on it — it is reported in the phase
    evidence, warned about when overrun, and printed by --dry-run so the run's
    caller can size its own timeout. Overrunning it is a measurement (the
    tombstone-debt correlation tracker 175 is about), never a verdict.
    """
    n = max(0, int(devices))
    return ONBOARD_BUDGET_BASE_S + n / max(1e-9, ONBOARD_RATE_FLOOR_PER_S)


CLEAN_SLATE_OFFSET_BOUND = int(
    os.environ.get("MLX_CLEAN_SLATE_OFFSET_BOUND", "100000"))

# ── ClickHouse memory: what MemoryTracking IS, and what the gate judges ────
#
# THE FALSE PREMISE THIS REPLACES (docs/scale/P2_CLICKHOUSE_PEAK_S06_2026-08-29.md,
# runs p2-s05-08291138 and p2-s06-08291421).
# The gate used to DISCARD every `system.metric_log` sample whose
# `CurrentMetric_MergesMutationsMemoryTracking` read above its own
# `CurrentMetric_MemoryTracking`, on the reasoning that merge memory is a
# subset of the tracked total, and to answer UNKNOWN whenever the two printed
# peaks came out that way. On ClickHouse 24.8 the reasoning is wrong. Live, on
# an idle server:
#
#   system.metrics   MemoryTracking = 692.12 MiB
#   async_metrics    MemoryResident = 692.10 MiB     <- identical to 2 dp
#
# `CurrentMetric_MemoryTracking` is the global tracker HARD-SET TO PROCESS RSS
# once per second by AsynchronousMetrics (`MemoryTracker::setRSS`). It is NOT a
# sum of per-query/per-merge allocations, so a child tracker such as
# MergesMutationsMemoryTracking is not bounded by it and legitimately reads
# ABOVE it — 34 of hour-14's 3,600 samples on s06, 50 of hour-11's on s05, one
# stretch holding for 48 consecutive seconds. The filter was discarding exactly
# the diagnostic samples, and the invariant was refusing to judge readings that
# were never impossible. Both are gone.
#
# WHAT THE GATE JUDGES INSTEAD:
#
#   (a) THE CUSTOMER-VISIBLE FACT — the `system.errors` delta for
#       MEMORY_LIMIT_EXCEEDED across the run. ANY increase is a FAIL. It must
#       be read from `system.errors` / `system.error_log`, never from
#       `system.query_log`: run s06 raised 17 and query_log recorded 2, because
#       the other 15 were raised in BACKGROUND threads (metric_log merges),
#       which query_log never observes. A query_log-only count under-reports 8x.
#   (b) p99 of MemoryTracking below CH_MEMORY_TRACKING_MAX_PCT of the cap.
#       p99, NOT max: s05 (clean) and s06 (17 errors) have the same median
#       (1.25-1.40 GiB) and near-identical p99 (~1.57 vs ~1.60 GiB). What
#       separates them is 13 one-second RSS transients. A max-based gate cannot
#       tell a sustained regression from a transient — and did not: it failed
#       s05 on a transient it should only have reported.
#   (c) The PEAK, always reported, and WARNED about at/above the cap when no
#       error fired: a transient that touched the ceiling and cost nobody any
#       work is a warning, not a verdict.
#
# `MergesMutationsMemoryTracking` is reported as INFORMATIONAL ONLY and carries
# NO verdict, because in 24.8 it is not bounded by the total and there is no
# honest fraction-of-cap to assert on. If a merge-memory assertion is ever
# wanted it belongs on `part_log.peak_memory_usage` — which has never logged a
# single `database='system'` row, i.e. it is blind to precisely the merges that
# drove s06's peak, so it would need pairing with (a) regardless.
CH_MEM_ERROR = "MEMORY_LIMIT_EXCEEDED"
CH_MEM_ERROR_CODE = 241
CH_MEM_ERROR_TOTAL_SQL = (
    f"SELECT toInt64(sum(value)) FROM system.errors "
    f"WHERE name = '{CH_MEM_ERROR}'")
# The metric_log aggregate, as ONE source text the live gate and the offline
# `--rescore-memflat` both use: peak, p99 and the informational merge peak.
# UNFILTERED — see the header above for why there is nothing to filter out.
# Callers append the window predicate (ch_window_bound).
CH_PEAK_SELECT = (
    "SELECT toInt64(max(greatest(CurrentMetric_MemoryTracking, 0))), "
    "toInt64(quantileExact(0.99)(greatest(CurrentMetric_MemoryTracking, 0))), "
    "toInt64(max(greatest(CurrentMetric_MergesMutationsMemoryTracking, 0))), "
    # count() AND the earliest sample IN the window. The second one exists
    # because a table can be RECREATED: ClickHouse renames metric_log on an
    # <engine> change, and a builder can drop it outright — on 2026-08-29 both
    # metric_log and error_log were recreated mid-afternoon and every earlier
    # run's history went with them. A window whose first sample lands long
    # after the window opened was only partly instrumented, and the gate says
    # so instead of quoting a p99 over the tail it happens to have.
    "count(), toString(min(event_time)) FROM system.metric_log WHERE ")
# How far the first in-window sample may sit past the window start before the
# instrument is called partial. One flush interval of slack, not more.
CH_WINDOW_COVERAGE_SLACK_S = 120.0

# ── correlation memory anchor: settle after the backlog reaches zero ────────
#
# THE DEFECT THIS EXISTS FOR (same run). memflat anchored correlation's slope
# on the sample taken "the instant injection stops" — with 22,736 signals
# still PENDING in the engine. The engine then legitimately builds objects for
# that backlog for another ~33 minutes, so the phase read 470 -> 647 MiB
# (x1.37) and called a backlog drain a leak. A growing working set while a
# queue is draining is work, not a leak; the leak question can only be asked
# once the queue is empty. Anchor = the first per-replica sample with
# `corr_engine_pending == 0`, end = a sample at least CORR_MEM_SETTLE_S later.
CORR_MEM_SETTLE_S = float(os.environ.get("MLX_CORR_MEM_SETTLE_S", "120"))
CORR_MEM_SETTLE_MAX_S = float(
    os.environ.get("MLX_CORR_MEM_SETTLE_MAX_S", "300"))
# Parts must come back down after input stops: within +20 % of the preflight
# MaxPartCountForPartition (or +8 parts, whichever is the larger envelope — a
# baseline of 3 parts must not fail on a 4th), and never within a factor of two
# of parts_to_delay_insert, where inserts start being throttled.
CH_PART_COUNT_GROWTH_MAX = float(
    os.environ.get("MLX_CH_PART_COUNT_GROWTH_MAX", "1.2"))
CH_PART_COUNT_FLOOR = int(os.environ.get("MLX_CH_PART_COUNT_FLOOR", "8"))
CH_PART_SETTLE_MAX_S = float(os.environ.get("MLX_CH_PART_SETTLE_MAX_S", "600"))
CH_PART_SETTLE_INTERVAL_S = float(
    os.environ.get("MLX_CH_PART_SETTLE_INTERVAL_S", "15"))

# Services that must be running (and healthy where a healthcheck exists) for
# the run to mean anything. Subset of the watchdog's list: only what the
# harness actually exercises — optional profiles (grafana, osd, exporters)
# are the watchdog's job, not a scale gate.
REQUIRED_SERVICES = [
    "api", "clickhouse", "correlation", "kafka", "nginx", "opensearch",
    "postgres", "vector-aggregator", "vector-router", "victoria",
]


def _ch_counter(raw: str) -> int:
    """A ClickHouse memory counter as a non-negative int.

    `MergesMutationsMemoryTracking` legitimately reads a small NEGATIVE value
    when no merge is running (the tracker is a signed delta), and reading it as
    UInt64 wraps that to ~1.8e19 — which arrives as "17,592,186,044,416 MiB =
    367,008,512,659 % of the cap" and fails the gate on an idle server. Signed
    parse, floored at 0: no merge running is 0 bytes of merge memory."""
    return max(0, int(float(raw.strip())))


def ch_number(stack, query: str) -> float:
    """One numeric ClickHouse scalar. -1.0 means UNANSWERED — never 0, so a
    failed probe can never read as a healthy measurement.

    Module level so the offline `--rescore-memflat` path asks the server the
    SAME questions the gate asks, from the same source text."""
    ok, out = stack.ch(query)
    if not ok:
        warn(f"ClickHouse probe failed ({out[:160]}) for: {query[:90]}")
        return -1.0
    head = out.strip().splitlines()[0].split("\t")[0] if out.strip() else ""
    try:
        return float(head)
    except ValueError:
        return -1.0


def ch_memory_cap(stack) -> tuple[float, str]:
    """The effective `max_server_memory_usage` in bytes, and where it came
    from. Ours is configured 0 = "derive from the ratio", so the cap is
    `max_server_memory_usage_to_ram_ratio x CGroupMemoryTotal`. If the cgroup
    total is invisible the cap is HOST-derived — the very trap that makes
    `merges_mutations_memory_usage_soft_limit` inert here — so the source is
    reported with the number."""
    configured = ch_number(
        stack, "SELECT toFloat64(value) FROM system.server_settings "
               "WHERE name = 'max_server_memory_usage'")
    if configured > 0:
        return configured, "server_settings.max_server_memory_usage"
    ratio = ch_number(
        stack, "SELECT toFloat64(value) FROM system.server_settings "
               "WHERE name = 'max_server_memory_usage_to_ram_ratio'")
    total = ch_number(stack, "SELECT value FROM system.asynchronous_metrics "
                             "WHERE metric = 'CGroupMemoryTotal'")
    source = "ratio x CGroupMemoryTotal"
    if total <= 0:
        total = ch_number(stack, "SELECT value FROM system.asynchronous_metrics "
                                 "WHERE metric = 'OSMemoryTotal'")
        source = ("ratio x OSMemoryTotal (CGroupMemoryTotal unseen — this "
                  "cap is HOST-derived and larger than the container)")
    if ratio > 0 and total > 0:
        return ratio * total, source
    return -1.0, "unreadable"


def ch_ts(value: str | None) -> str:
    """A ClickHouse DateTime literal, or "" if it is not exactly one.

    Zero trust on our own server's clock (§3): these strings are spliced into
    SQL, so a value that does not match the literal shape is DROPPED rather
    than quoted and hoped for."""
    text = (value or "").strip()
    return text if re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}",
                                text) else ""


def ch_window_bound(start: str, end: str) -> str:
    """`event_time` predicate for a run window. "" when there is no window —
    the caller must then refuse to answer, never widen to all of history."""
    start, end = ch_ts(start), ch_ts(end)
    if not start:
        return ""
    bound = f"event_time >= toDateTime('{start}')"
    if end:
        bound += f" AND event_time <= toDateTime('{end}')"
    return bound


def ch_memory_error_window(stack, start: str, end: str) -> tuple[int, str, str]:
    """MEMORY_LIMIT_EXCEEDED raised in [start, end], from `system.error_log`.

    error_log is the only table that sees them all — see the CH_MEM_ERROR
    header. Returns (count, source, state); the count is -1 for every state but
    "ok", because a table that cannot answer must NEVER answer 0:

      ok         the table demonstrably spans the window; the count is real.
      empty      the table holds no row at all. Consistent with a spotless
                 server AND with a table recreated since the run, and nothing
                 in it can tell those apart.
      uncovered  the table's earliest row is AFTER the window opened — it was
                 recreated or TTL-pruned and simply does not hold the run.
                 This is not hypothetical: on 2026-08-29 a config change
                 recreated error_log and metric_log mid-afternoon, and a naive
                 count then reported "0 errors" for a run that raised 17.
      error      the probe failed.
    """
    bound = ch_window_bound(start, end)
    if not bound:
        return -1, "no run window on ClickHouse's clock", "error"
    ok, out = stack.ch(
        f"SELECT toInt64(sumIf(value, code = {CH_MEM_ERROR_CODE} AND {bound})), "
        f"toInt64(count()), toString(min(event_time)) FROM system.error_log")
    if not ok:
        return -1, f"system.error_log unreadable ({out[:120]})", "error"
    cells = out.strip().splitlines()[0].split("\t") if out.strip() else []
    if len(cells) < 3:
        return (-1, f"system.error_log answer unparseable ({out.strip()[:80]!r})",
                "error")
    try:
        count, rows, earliest = int(float(cells[0])), int(cells[1]), cells[2]
    except ValueError:
        return (-1, f"system.error_log answer unparseable ({out.strip()[:80]!r})",
                "error")
    if rows <= 0:
        return -1, ("system.error_log holds no row at all — it cannot tell "
                    "'no error has ever been raised' from a table recreated "
                    "since the run"), "empty"
    # Fixed-width DateTime literals compare lexicographically as instants.
    if ch_ts(earliest) and ch_ts(earliest) > ch_ts(start):
        return -1, (f"system.error_log only goes back to {earliest}, after this "
                    f"window opened at {ch_ts(start)} — the table was recreated "
                    f"or TTL-pruned and does not hold this run"), "uncovered"
    return count, (f"system.error_log over {ch_ts(start)} -> "
                   f"{ch_ts(end) or '(now)'}"), "ok"


def ch_window_gap_s(start: str, first_sample: str) -> float:
    """Seconds between a window opening and its first sample. -1.0 = unknown."""
    start, first_sample = ch_ts(start), ch_ts(first_sample)
    if not start or not first_sample:
        return -1.0
    fmt = "%Y-%m-%d %H:%M:%S"
    # Both stamps come from the SAME clock (ClickHouse's `now()`), so only
    # their difference is meaningful. The tzinfo is stamped on both purely to
    # keep them aware — it cancels in the subtraction and is never displayed.
    def _at(text: str) -> datetime:
        return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)

    return (_at(first_sample) - _at(start)).total_seconds()


def ch_memory_error_victims(stack, start: str, end: str, total: int) -> str:
    """Who paid, as far as `system.query_log` can say — and how many it cannot.

    query_log only ever sees statements. The background raises (the
    `system.metric_log` merges that drove run s06's peak) are invisible to it,
    so the shortfall is STATED rather than left as a silent under-count."""
    bound = ch_window_bound(start, end)
    if not bound:
        return "victims unnamed (no run window)"
    ok, out = stack.ch(
        f"SELECT query_kind, arrayStringConcat(tables, ','), count() "
        f"FROM system.query_log WHERE exception_code = {CH_MEM_ERROR_CODE} "
        f"AND {bound} GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 5")
    if not ok:
        return f"victims unnamed (system.query_log unreadable: {out[:100]})"
    named, parts = 0, []
    for line in out.strip().splitlines():
        cells = line.split("\t")
        if len(cells) < 3:
            continue
        try:
            count = int(cells[2])
        except ValueError:
            continue
        named += count
        parts.append(f"{count}x {cells[0] or 'unknown-kind'} on "
                     f"{cells[1] or '(no table)'}")
    if not parts:
        return ("NO victim in system.query_log — every raise was in a "
                "BACKGROUND thread (merges/flushes), which query_log never sees")
    if total > named:
        parts.append(f"the other {total - named} were raised in BACKGROUND "
                     f"threads and query_log cannot name them")
    return "; ".join(parts)


# ── clause (2a) exemption: budgeted-backfill NEGOTIATION is not a fault ─────
#
# WHY THIS EXISTS (run 08311437us3b, 2026-08-31 14:38-15:35). The clause failed
# that run on 4 MEMORY_LIMIT_EXCEEDED the platform raised BY DESIGN. Since
# 9ed38cbb the timeintel backfill's wide fetch NEGOTIATES with the server: a
# sub-fetch that does not fit is REFUSED against the worker's own budgeted
# `max_memory_usage` (241) or read cap (307), the splitter halves the key list
# and retries until it fits, the pass folds the pages and advances its
# watermark. The refusal IS the mechanism working — bounded by the worker's own
# budget, no other query lost work, and the pass completed. A gate that reddens
# on that is noise, and noise is how a real regression gets ignored.
#
# WHAT IS EXEMPT — BOTH halves are required, and neither may be guessed at:
#
#   ATTRIBUTABLE  `system.query_log` names the refused statement as the
#                 budgeted backfill's own: `log_comment` (or `user`) carries
#                 the worker's attribution tag — `worker:timeintel-backfill`
#                 for the wide fetch, `worker:timeintel-backfill-pick` for the
#                 pick (timeintel_backfill.go, both set via chWorkerQueryTuned
#                 -> chhttp `log_comment`). A refusal query_log cannot name is
#                 a BACKGROUND victim (a merge, a flush) and still counts —
#                 that is exactly the s06 shape this clause was written for.
#
#   RECOVERED     the worker's OWN pass evidence says the negotiation ended in
#                 WORK: a `backfill pass complete` line with pages > 0 inside
#                 this run's window, read from the api container's structured
#                 log. Without it the identical refusals are the STALL shape
#                 (refused, split, refused again, watermark never advances) —
#                 the defect 9ed38cbb fixed — and that must stay red.
#
# An unreadable query_log or unreadable api log exempts NOTHING (-1, never 0):
# a gate that cannot see must not forgive, and it must not be able to mistake
# "I could not look" for "nothing was attributable".
#
# HOW MUCH is exempt (run 083117507rl2, 2026-08-31 — the units defect). The
# first cut subtracted ATTRIBUTED QUERY ROWS (`system.query_log`, one per
# refused statement) from RAISED ERROR INCREMENTS (`system.errors` /
# `error_log`) — but ClickHouse bumps the 241 counter once per throwing
# THREAD plus the query-level rethrow, so a refused query running
# max_threads=2 raises 2+ increments for its single row. Measured: 370
# increments against 365 rows in one window, 1160 against 1133 over the
# table's whole history. The subtraction therefore manufactured ~5 phantom
# "unexempted" errors on every negotiating run BY CONSTRUCTION, with zero
# real victims behind them (part_log: 0 errored merges; the server log holds
# exactly the 365 raises). Unlike units are never compared again.
#
# So with (a) attribution > 0 and (b) a completed pass, the gate decides HOW
# MUCH to exempt by verifying the backfill was the SOLE 241 producer:
#
#   (c) query_log holds ZERO in-window 241 rows from any producer NOT tagged
#       worker:timeintel-backfill* (ch_memory_error_foreign_producers), and
#   (d) part_log holds ZERO error != 0 rows in the window — merges produce
#       no query_log row, so (c) alone cannot clear them; an OOM'd merge
#       shows up here (ch_part_log_errored).
#
# Both zero -> the ENTIRE raised delta is the backfill's own negotiation and
# all of it is exempt. Either finds foreign work -> fall back to the per-row
# subtraction (which under-exempts, never over-exempts) and NAME the foreign
# producers in the note. Either probe unreadable with nothing foreign found
# -> exempt NOTHING: sole-producer status is unverified, and the rule above
# holds — a gate that cannot see must not forgive.
CH_BACKFILL_TAG_PREFIX = "worker:timeintel-backfill"
BACKFILL_PASS_COMPLETE = "backfill pass complete"


def ch_memory_error_backfill_attributed(stack, start: str,
                                        end: str) -> tuple[int, str, str]:
    """(count, tags, source) — the 241s `system.query_log` attributes to the
    budgeted backfill worker.

    -1 is UNREADABLE, never 0: a query_log that cannot answer must neither
    exempt anything nor read as "none attributable"."""
    bound = ch_window_bound(start, end)
    if not bound:
        return -1, "", "no run window"
    ok, out = stack.ch(
        f"SELECT log_comment, user, count() FROM system.query_log "
        f"WHERE exception_code = {CH_MEM_ERROR_CODE} AND {bound} "
        f"GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 25")
    if not ok:
        return -1, "", f"system.query_log unreadable ({out[:100]})"
    total, tags = 0, []
    for line in out.strip().splitlines():
        cells = line.split("\t")
        if len(cells) < 3:
            continue
        try:
            count = int(cells[2])
        except ValueError:
            continue
        tag, user = cells[0].strip(), cells[1].strip()
        # Prefix, because the worker deliberately carries TWO tags (the wide
        # fetch and the pick) and both are the same budgeted pass.
        if not (tag.startswith(CH_BACKFILL_TAG_PREFIX)
                or user.startswith(CH_BACKFILL_TAG_PREFIX)):
            continue
        total += count
        tags.append(f"{count}x {tag or user}")
    return total, "; ".join(tags), (
        f"system.query_log log_comment/user starting '{CH_BACKFILL_TAG_PREFIX}'")


def ch_memory_error_foreign_producers(stack, start: str,
                                      end: str) -> tuple[int, str, str]:
    """(count, producers, source) — in-window 241 rows `system.query_log`
    holds from ANY producer NOT tagged as the budgeted backfill worker.

    Check (c) of the full-delta exemption (CH_BACKFILL_TAG_PREFIX header): a
    zero here, beside a zero from `ch_part_log_errored`, proves the backfill
    was the sole 241 producer the window has statement evidence of, so the
    whole raised-increment delta is its own. -1 is UNREADABLE, never 0 — an
    instrument that cannot answer verifies nothing. `trimBoth` mirrors the
    attribution probe's Python-side `.strip()`, so no row can read as
    attributed there and foreign here over whitespace."""
    bound = ch_window_bound(start, end)
    if not bound:
        return -1, "", "no run window"
    ok, out = stack.ch(
        f"SELECT toInt64(count()) AS foreign_241, "
        f"arrayStringConcat(groupUniqArray(10)(if(log_comment != '', "
        f"log_comment, if(user != '', user, '(no log_comment, no user)'))), "
        f"'; ') FROM system.query_log "
        f"WHERE exception_code = {CH_MEM_ERROR_CODE} AND {bound} "
        f"AND NOT (startsWith(trimBoth(log_comment), "
        f"'{CH_BACKFILL_TAG_PREFIX}') "
        f"OR startsWith(trimBoth(user), '{CH_BACKFILL_TAG_PREFIX}'))")
    if not ok:
        return -1, "", (f"system.query_log foreign-producer probe unreadable "
                        f"({out[:100]})")
    cells = out.strip().splitlines()[0].split("\t") if out.strip() else []
    try:
        count = int(float(cells[0]))
    except (IndexError, ValueError):
        return -1, "", (f"foreign-producer answer unparseable "
                        f"({out.strip()[:80]!r})")
    producers = cells[1].strip() if len(cells) > 1 else ""
    return count, producers, (
        f"system.query_log {CH_MEM_ERROR_CODE}s not tagged "
        f"'{CH_BACKFILL_TAG_PREFIX}*' over the window")


def ch_part_log_errored(stack, start: str, end: str) -> tuple[int, str]:
    """(count, source) — part operations (merges above all) that ENDED IN
    ERROR inside the window, from `system.part_log`.

    Check (d) of the full-delta exemption: merges never produce a query_log
    row, so check (c) alone cannot clear them — a merge that hit 241 shows
    up here as `error != 0`. A cheap COUNT; -1 is UNREADABLE, never 0."""
    bound = ch_window_bound(start, end)
    if not bound:
        return -1, "no run window"
    ok, out = stack.ch(
        f"SELECT toInt64(countIf(error != 0)) FROM system.part_log "
        f"WHERE {bound}")
    if not ok:
        return -1, f"system.part_log unreadable ({out[:100]})"
    try:
        count = int(float(out.strip().splitlines()[0].split("\t")[0]))
    except (IndexError, ValueError):
        return -1, (f"system.part_log answer unparseable "
                    f"({out.strip()[:80]!r})")
    return count, "system.part_log rows with error != 0 over the window"


def backfill_passes_completed(blob: str | None) -> int:
    """Completed backfill passes (pages > 0) in ONE container-log blob.

    The worker emits applog JSON lines on stdout (internal/applog), so the line
    is parsed as JSON and its `pages` read — a substring count would also match
    the WARN line that says a pass ended EARLY, which is the stall shape this
    exemption must never absorb. -1 means the blob could not be read."""
    if blob is None:
        return -1
    done = 0
    for line in blob.splitlines():
        if BACKFILL_PASS_COMPLETE not in line:
            continue
        brace = line.find("{")
        if brace < 0:
            continue
        try:
            event = json.loads(line[brace:])
        except (ValueError, TypeError):
            continue
        if not isinstance(event, dict):
            continue
        if event.get("msg") != BACKFILL_PASS_COMPLETE:
            continue
        try:
            pages = int(event.get("pages", 0))
        except (TypeError, ValueError):
            continue
        if pages > 0:
            done += 1
    return done


def clean_slate_offset_note(bus_max_current: int, planned: int) -> tuple[str, str]:
    """("" | "log" | "warn", message) about clean-slate.sh --verify's bound.

    Three states, and only one of them is a WARNING:

      already spent  the bus is ALREADY past the bound, so this run changes
                     nothing about it — a fact to state, not a warning.
      this run spends it  the signal is intact and this run's injection is
                     what will cost it: the operator can still reset first.
      intact         silence.

    A -1 (unreadable describe) answers nothing: UNKNOWN is not "fine", and it
    is not a warning about this run either — it is said once, quietly.
    """
    if bus_max_current < 0:
        return "log", ("max consumer CURRENT-OFFSET unreadable — whether "
                       "clean-slate.sh --verify still reads this bus as reset "
                       "is UNKNOWN")
    if bus_max_current > CLEAN_SLATE_OFFSET_BOUND:
        return "log", (f"clean-slate.sh --verify already reads this bus as "
                       f"not-reset (max consumer CURRENT-OFFSET "
                       f"{bus_max_current} > {CLEAN_SLATE_OFFSET_BOUND}); this "
                       f"run does not change that")
    if bus_max_current + planned > CLEAN_SLATE_OFFSET_BOUND:
        return "warn", (f"this run's planned injection ({planned}) will push "
                        f"the max consumer CURRENT-OFFSET from "
                        f"{bus_max_current} past clean-slate.sh --verify's "
                        f"{CLEAN_SLATE_OFFSET_BOUND} bound "
                        f"(clean-slate.sh:243) — that verify signal is intact "
                        f"now and will not be after this run, until the next "
                        f"bus reset")
    return "", ""


def mib(value: float | None) -> str:
    """Bytes as MiB for a verdict line. A negative/absent number is printed as
    `unmeasured`, never as 0 MiB — an unread probe must never look flat."""
    if value is None or value < 0:
        return "unmeasured"
    return f"{value / 1024**2:.0f} MiB"


def log(msg: str) -> None:
    print(f"miniladder: {msg}", flush=True)


def warn(msg: str) -> None:
    print(f"miniladder: WARNING: {msg}", file=sys.stderr, flush=True)


def die(msg: str, code: int = 2) -> None:
    print(f"miniladder: ERROR: {msg}", file=sys.stderr, flush=True)
    sys.exit(code)


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def env_flag(name: str) -> bool:
    """An opt-in env switch. Read at CALL time, never cached at import, so a
    deliberate override is visible to the phase that honours it (and testable
    without reimporting the module)."""
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


# ── DISK HEADROOM + HOST QUIET (tracker 210) ────────────────────────────────
# WHY. `storm-s10` (run 09012025x578) started with 10.8 GiB root-fs free while
# concurrent CI suites drew ~3.1 GiB and pushed node_load1 to 16-38. The host
# crossed OpenSearch's flood-stage watermark (5 % of the 77 GiB root = ~3.85
# GiB) by ~0.4 GiB mid-burst, every index went read-only-allow-delete for 11
# minutes, and the vector router's OS sink DISCARDED 291,296 syslog evidence
# docs as retry-exhausted. The Kafka->engine lane was intact, so accounting
# still balanced and the harness reported gates green — the leg was graded, and
# only a later diagnosis found the evidence copy was gone. Either factor alone
# would not have crossed. Preflight let it run.
#
# WHAT THIS IS NOT. This gate REFUSES BEFORE THE LEG RUNS. It grades nothing,
# scores nothing and changes NO gate semantics: every clause of
# `docs/scale/CORRELIX_REFERENCE_CAPACITY_V1.md` is evaluated exactly as before
# on any leg that starts. A V1 rerun on a quiet host is byte-for-byte the run
# it was, so this is not a semantic change and does not require a V2 profile.
# `--allow-unquiet` proceeds and stamps UNQUIET into the preflight evidence AND
# into report.json's `parameters`, so a graded verdict can never silently come
# from an unquiet host.
HOST_QUIET_FS = "/"                # the root filesystem s10 filled
MIN_FREE_GIB_DEFAULT = 10.0        # V1 section 8(e)
MAX_LOAD1_DEFAULT = 6.0            # s11 launched at 2.9; s10 at 16-38
LOADAVG_PATH = "/proc/loadavg"
GIB = 1024 ** 3


def read_load1(path: str | None = None) -> tuple[float, str]:
    """(load1, error). An UNREADABLE load average is reported as an error, never
    as 0.0 — an unmeasured host must not look quiet (16.1).

    The path defaults to the MODULE constant read at CALL time, not to a
    def-time binding, so a test (and an operator running on a host with a
    relocated procfs) can point it elsewhere.
    """
    path = path or LOADAVG_PATH
    try:
        with open(path, encoding="utf-8") as fh:
            fields = fh.read().split()
    except OSError as exc:
        return -1.0, f"cannot read {path}: {exc.strerror or exc}"
    if not fields:
        return -1.0, f"{path} is empty"
    try:
        return float(fields[0]), ""
    except ValueError:
        return -1.0, f"{path} first field {fields[0]!r} is not a number"


def disk_free_gib(path: str | None = None) -> tuple[float, float, str]:
    """(free GiB, total GiB, error) for the filesystem holding `path`.

    Same call-time default as read_load1()."""
    path = path or HOST_QUIET_FS
    try:
        usage = shutil.disk_usage(path)
    except OSError as exc:
        return -1.0, -1.0, f"cannot stat {path}: {exc.strerror or exc}"
    return round(usage.free / GIB, 2), round(usage.total / GIB, 2), ""


def host_quiet_readings(min_free_gib: float, max_load1: float,
                        fs_path: str | None = None,
                        loadavg_path: str | None = None) -> dict:
    """The two numbers the gate judges, plus the bounds they are judged against."""
    fs_path = fs_path or HOST_QUIET_FS
    free_gib, total_gib, disk_error = disk_free_gib(fs_path)
    load1, load_error = read_load1(loadavg_path)
    return {"filesystem": fs_path, "free_gib": free_gib, "total_gib": total_gib,
            "disk_error": disk_error, "load1": load1, "load1_error": load_error,
            "min_free_gib": min_free_gib, "max_load1": max_load1}


def host_quiet_problems(readings: dict) -> list[str]:
    """The violations in a reading set (empty = quiet host).

    An UNREADABLE probe is a violation, not a pass: the whole point of the gate
    is that nobody was measuring when s10 ran.
    """
    problems: list[str] = []
    if readings.get("disk_error"):
        problems.append(
            f"root-fs headroom is UNKNOWN ({readings['disk_error']}) — an "
            f"unmeasured filesystem is not a headroom guarantee")
    elif float(readings.get("free_gib", -1)) < float(readings["min_free_gib"]):
        problems.append(
            f"{readings['filesystem']} has {readings['free_gib']:.1f} GiB free, "
            f"below the {readings['min_free_gib']:.0f} GiB floor — storm-s10 "
            f"crossed OpenSearch's flood-stage watermark mid-burst from 10.8 GiB "
            f"and the router's OS sink discarded 291,296 evidence docs "
            f"(--min-free-gib / --allow-unquiet)")
    if readings.get("load1_error"):
        problems.append(
            f"host load is UNKNOWN ({readings['load1_error']}) — an unmeasured "
            f"host is not a quiet one")
    elif float(readings.get("load1", -1)) > float(readings["max_load1"]):
        problems.append(
            f"host load1 {readings['load1']:.2f} exceeds the "
            f"{readings['max_load1']:.2f} bound — concurrent work distorts every "
            f"timing clause (storm-s11 launched at 2.9, storm-s10, excluded for "
            f"environment violation, at 16-38) (--max-load1 / --allow-unquiet)")
    return problems


def run(cmd: list[str], timeout: int, input_text: str | None = None) -> tuple[int, str, str]:
    """Bounded subprocess. Never raises on non-zero exit — callers must look
    at rc and REPORT stderr (16.1: no swallowed errors)."""
    try:
        p = subprocess.run(
            cmd, input=input_text, capture_output=True, text=True,
            timeout=timeout, check=False,
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s: {' '.join(cmd[:4])} ..."
    except FileNotFoundError as exc:
        return 127, "", str(exc)


# curl exit codes we can actually hit through `docker exec … curl --config -`,
# plus the two `run()` synthesises. An empty error message is not a diagnosis:
# every failure names its code AND what the code means (16.1).
CURL_EXIT_MEANINGS: dict[int, str] = {
    1: "unsupported protocol",
    2: "curl failed to initialise",
    3: "malformed URL",
    6: "could not resolve host",
    7: "failed to connect — is OpenSearch listening?",
    18: "partial transfer (connection closed early)",
    22: "HTTP error >= 400 returned to curl --fail",
    26: "read error on the request body",
    28: "TIMED OUT",
    35: "TLS handshake failed",
    47: "too many redirects",
    52: "empty reply from server",
    55: "send failed",
    56: "receive failed (connection reset)",
    58: "problem with the local client certificate",
    60: "peer certificate not verifiable with the given CA",
    77: "CA cert file unreadable",
    124: "the harness's own subprocess bound expired",
    127: "binary not found in the container (curl / docker)",
}


def curl_exit_meaning(rc: int, timeout: float = 0) -> str:
    """Human meaning for a curl/run exit code — never an empty string."""
    if rc == 28:
        return (f"TIMED OUT after {timeout:.0f}s (curl max-time)" if timeout
                else "TIMED OUT (curl max-time)")
    if rc == 124:
        return f"the harness's own subprocess bound expired ({timeout:.0f}s + 35s)"
    return CURL_EXIT_MEANINGS.get(rc, "unknown curl exit code — see `man curl`")


def _http_transient_reason(exc: BaseException) -> str:
    """Non-empty reason when `exc` is a TRANSIENT transport failure.

    Deliberately NARROW (16.1 — a retry that hides a real answer is a swallowed
    error): socket read timeouts, connection refused/reset/aborted, the
    unreachable-network errnos, and the four server-side "try again" statuses.
    A 4xx other than 429 is the server's considered answer about the REQUEST and
    is never retried — repeating it cannot change it, and repeating a 404 in the
    device purge would turn "this device is already gone" into 5x the calls.
    """
    if isinstance(exc, urllib.error.HTTPError):
        # HTTPError is a URLError is an OSError — it MUST be tested first, or
        # the errno branch below would see a status-carrying exception.
        return f"HTTP {exc.code}" if exc.code in HTTP_RETRY_STATUSES else ""
    if isinstance(exc, urllib.error.URLError):
        # urllib wraps the real socket error in `.reason`; that is where the
        # `TimeoutError('timed out')` of the 2026-08-29 crash actually lives.
        return (_http_transient_reason(exc.reason)
                if isinstance(exc.reason, BaseException) else "")
    if isinstance(exc, TimeoutError):        # socket.timeout since Python 3.10
        return "socket timeout"
    if isinstance(exc, ConnectionError):     # refused / reset / aborted / pipe
        return type(exc).__name__
    if isinstance(exc, OSError) and exc.errno in HTTP_RETRY_ERRNOS:
        return errno.errorcode.get(exc.errno, f"errno {exc.errno}")
    return ""


def _annotate_exc(exc: BaseException, suffix: str) -> None:
    """Fold `suffix` into the exception's OWN message, keeping its TYPE.

    The caller's `except` clauses (and the operator's traceback) must still see
    the original class — a wrapper exception would break every `except OSError`
    in this file — but a bare `TimeoutError('timed out')` in a log tells nobody
    that five attempts and 7s of backoff were already spent on it.
    """
    if isinstance(exc, urllib.error.HTTPError):
        exc.msg = f"{exc.msg}{suffix}"          # str(HTTPError) reads .msg
    elif isinstance(exc, urllib.error.URLError):
        exc.reason = f"{exc.reason}{suffix}"    # str(URLError) reads .reason
        exc.args = (exc.reason,)
    elif exc.args:
        exc.args = (f"{exc.args[0]}{suffix}",) + tuple(exc.args[1:])
    else:
        exc.args = (suffix.strip(),)


def http_retry(what: str, call: typing.Callable[..., typing.Any], *args: object,
               attempts: int = HTTP_RETRY_ATTEMPTS,
               base_s: float = HTTP_RETRY_BASE_S,
               cap_s: float = HTTP_RETRY_CAP_S,
               total_s: float = HTTP_RETRY_TOTAL_S) -> typing.Any:
    """Run `call(*args)` under the ONE bounded retry policy (§9).

    Backoff is exponential with FULL jitter: sleep uniform(0, min(cap,
    base * 2**(n-1))), clamped to whatever is left of the total sleeping
    budget. Every retry is LOGGED with the attempt number, the exception and
    the delay (16.1) — a silent retry is indistinguishable from a hang, which
    is the failure mode this harness exists to make impossible.

    Only `_http_transient_reason` failures are retried; everything else is
    re-raised on the first attempt, untouched. Once the budget is spent the
    ORIGINAL exception is re-raised, its message carrying the attempt count.

    IDEMPOTENCE. Every call site routed through here is safe to repeat: GET and
    the device DELETE by construction, and POST /api/devices because the
    handler keys the write by the caller's id — `handleDevices` calls
    `s.discovery.Upsert(d)` (src/backend/main.go:2368) and Upsert stores by
    `d.ID` (src/backend/internal/discovery/discovery.go:569-590,
    `store.Put(d)` + `a.cache[d.ID] = d`), so a repeated create OVERWRITES the
    same row and can never manufacture a second device. Callers that are not
    idempotent must not use this helper.
    """
    attempts = max(1, attempts)
    slept = 0.0
    for attempt in range(1, attempts + 1):
        try:
            return call(*args)
        except Exception as exc:  # classified below; anything else re-raises
            reason = _http_transient_reason(exc)
            if not reason:
                raise
            left = total_s - slept
            if attempt >= attempts or left <= 0:
                _annotate_exc(
                    exc, f" [{what}: gave up after {attempt} attempt(s), "
                         f"{slept:.1f}s of backoff]")
                warn(f"{what}: {reason} — GIVING UP after {attempt} "
                     f"attempt(s) and {slept:.1f}s of backoff ({exc!r})")
                raise
            ceiling = min(cap_s, base_s * (2 ** (attempt - 1)))
            delay = min(random.uniform(0.0, ceiling), left)
            warn(f"{what}: {reason} on attempt {attempt}/{attempts} "
                 f"({exc!r}) — retrying in {delay:.2f}s")
            time.sleep(delay)
            slept += delay
    # Unreachable: the loop either returns or raises.
    raise RuntimeError(f"{what}: retry loop fell through")


def http_ingress_status(base_url: str) -> int:
    """GET `base_url`/ under the retry policy. Raises on a FINAL failure — the
    callers of this one (preflight, --cleanup-only) must refuse a stack they
    cannot see, so an unreachable ingress stays an exception."""
    url = base_url.rstrip("/") + "/"

    def once() -> int:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            return int(r.status)

    return int(http_retry(f"GET {url}", once))


def env_get(env_file: str, key: str) -> str:
    """First KEY= value from the compose .env. Missing file/key -> '' (callers
    decide whether empty is fatal)."""
    try:
        with open(env_file, encoding="utf-8") as f:
            for line in f:
                if line.startswith(key + "="):
                    return line.rstrip("\n").split("=", 1)[1]
    except OSError:
        pass
    return ""


def parse_prom_metrics(body: str) -> dict[str, float]:
    """Prometheus text -> {series: value}, keeping LABELLED series apart.

    Both forms are stored: the bare name (so unlabelled series read as before)
    and, for a labelled sample, its full `name{labels}` key. Storing only the
    bare name silently collapses every multi-series counter onto its LAST
    sample — `corr_versions{outcome="persisted"}` and `{outcome="damped"}` both
    wrote to "corr_versions", so a completion check reading "persisted" was in
    fact reading "damped". A malformed value is skipped, never guessed at.
    """
    m: dict[str, float] = {}
    for line in body.splitlines():
        if line.startswith("#") or " " not in line:
            continue
        name, _, val = line.partition(" ")
        try:
            v = float(val)
        except ValueError:
            continue
        m[name.split("{")[0]] = v
        if "{" in name:
            m[name] = v
    return m


class Stack:
    """Access layer for the live stack: API, broker, stores, metrics.
    Every call is bounded; every failure carries its stderr."""

    def __init__(self, env_file: str, base_url: str, project: str):
        self.env_file = env_file
        self.project = project
        self.base_url = base_url.rstrip("/")
        compose_files = env_get(env_file, "COMPOSE_FILE")
        self.tls = "compose.tls.yml" in compose_files
        self.token = ""
        self._cids: dict[str, str] = {}
        # Every API call that exhausted its retries. Counted, not hidden: a run
        # whose teardown fought the transport is a different run from one that
        # did not, and the report says so.
        self.http_transport_failures = 0

    # -- containers ---------------------------------------------------------
    def cid(self, service: str) -> str:
        if service not in self._cids:
            rc, out, err = run(
                ["docker", "ps", "-q",
                 "--filter", f"label=com.docker.compose.project={self.project}",
                 "--filter", f"label=com.docker.compose.service={service}"],
                DOCKER_TIMEOUT)
            if rc != 0:
                warn(f"docker ps for {service} failed: {err.strip()}")
            self._cids[service] = out.split()[0] if out.split() else ""
        return self._cids[service]

    def cids(self, service: str) -> list[str]:
        """EVERY running container id of a compose service.

        `cid()` returns only the first. The stability diagnosis used it, so with
        `--scale correlation=2` it inspected ONE replica and reported the other
        as clean by never looking at it (2026-08-20).
        """
        rc, out, err = run(
            ["docker", "ps", "-q",
             "--filter", f"label=com.docker.compose.project={self.project}",
             "--filter", f"label=com.docker.compose.service={service}"],
            DOCKER_TIMEOUT)
        if rc != 0:
            warn(f"docker ps for {service} failed: {err.strip()}")
            return []
        return out.split()

    def service_states(self) -> list[dict]:
        rc, out, err = run(
            ["docker", "ps", "-a",
             "--filter", f"label=com.docker.compose.project={self.project}",
             "--format", "{{.Label \"com.docker.compose.service\"}}\t{{.ID}}"],
            DOCKER_TIMEOUT)
        if rc != 0:
            warn(f"docker ps -a failed: {err.strip()}")
            return []
        rows = []
        for line in out.splitlines():
            if "\t" not in line:
                continue
            svc, cid = line.split("\t", 1)
            rc2, out2, err2 = run(
                ["docker", "inspect", "--format",
                 "{{.State.Status}}\t{{if .State.Health}}{{.State.Health.Status}}{{end}}\t{{.State.ExitCode}}",
                 cid.strip()], DOCKER_TIMEOUT)
            if rc2 != 0:
                warn(f"docker inspect {svc} failed: {err2.strip()}")
                continue
            parts = (out2.strip() + "\t\t").split("\t")
            rows.append({"service": svc, "status": parts[0],
                         "health": parts[1], "exit_code": parts[2]})
        return rows

    @staticmethod
    def _mem_bytes(cell: str) -> int:
        m = re.match(r"([0-9.]+)\s*([A-Za-z]+)", cell.strip())
        if m and m.group(2) in _MEM_UNITS:
            return int(float(m.group(1)) * _MEM_UNITS[m.group(2)])
        return -1

    def api_data_dir(self) -> tuple[str, str]:
        """(host path of the api's `/data`, reason). "" = NOT host-reachable.

        The device store is `/data/devices.json` INSIDE the api container
        (main.go:1152), with its per-record subtree at
        `/data/devices.json.d/{manual,suppressed}/<sha256hex(id)>`. Whether
        this harness can even SEE that subtree depends on how the deployment
        mounts /data: a bind mount is a host path we can count; a named volume
        or an image-internal directory is not reachable from here at all, and
        the honest answer is then "unknown", never "zero".
        """
        ac = self.cid("api")
        if not ac:
            return "", "no running api container"
        rc, out, err = run(
            ["docker", "inspect", ac, "--format",
             "{{range .Mounts}}{{.Type}}|{{.Source}}|{{.Destination}}\n{{end}}"],
            DOCKER_TIMEOUT)
        if rc != 0:
            return "", f"docker inspect api failed: {err.strip()[:160]}"
        for line in out.splitlines():
            fields = line.strip().split("|")
            if len(fields) != 3 or fields[2] != "/data":
                continue
            if fields[0] != "bind":
                return "", (f"the api's /data is a {fields[0]} volume "
                            f"({fields[1]}), not a host bind mount — the "
                            f"device store is not reachable from this harness")
            return fields[1], "api /data bind mount"
        return "", "the api container has no /data mount"

    def mem_stats(self) -> dict[str, dict]:
        """Per-container {"used","limit"} bytes via docker stats.

        The LIMIT matters as much as the usage: it is the only self-relative
        yardstick for "is this container heading for an OOM kill" that holds on
        any hardware — the resource plan sizes it per host (#102), so a fixed
        MiB threshold would be a lie on the next box."""
        rc, out, err = run(
            ["docker", "stats", "--no-stream",
             "--format", "{{.Name}}\t{{.MemUsage}}"], 60)
        if rc != 0:
            warn(f"docker stats failed: {err.strip()}")
            return {}
        stats: dict[str, dict] = {}
        for line in out.splitlines():
            if "\t" not in line:
                continue
            name, mem = line.split("\t", 1)
            used, _, limit = mem.partition("/")
            u = self._mem_bytes(used)
            if u >= 0:
                stats[name] = {"used": u, "limit": self._mem_bytes(limit)}
        return stats

    def mem_sample(self) -> dict[str, int]:
        """Per-container RSS-ish working set in bytes (usage only).

        NOT RSS: this is docker stats' `memory.current - inactive_file`, which
        carries page cache and reclaimable slab (see the MEM_STATELESS_SERVICES
        header). Honest for a container that caches nothing; for anything that
        touches disk use `anon_sample()`."""
        return {n: v["used"] for n, v in self.mem_stats().items()}

    def container_names(self, services: tuple | list) -> dict[str, list[str]]:
        """{compose service -> [container names]} for this project, one call."""
        rc, out, err = run(
            ["docker", "ps",
             "--filter", f"label=com.docker.compose.project={self.project}",
             "--format", "{{.Label \"com.docker.compose.service\"}}\t{{.Names}}"],
            DOCKER_TIMEOUT)
        if rc != 0:
            warn(f"docker ps for container names failed: {err.strip()}")
            return {}
        wanted = set(services)
        found: dict[str, list[str]] = {}
        for line in out.splitlines():
            if "\t" not in line:
                continue
            svc, name = line.split("\t", 1)
            if svc in wanted and name.strip():
                found.setdefault(svc, []).append(name.strip())
        return {k: sorted(v) for k, v in found.items()}

    def cgroup_anon(self, container: str) -> int:
        """ANONYMOUS bytes of one container's cgroup — the memory that cannot
        be reclaimed and therefore the memory that OOM-kills it.

        Read from the container's own `memory.stat` (v2 `anon`; v1 falls back
        to `total_rss`). -1 means UNREADABLE, never 0: a gate must not read a
        failed probe as a flat container."""
        rc, out, err = run(
            ["docker", "exec", container, "cat", "/sys/fs/cgroup/memory.stat"],
            DOCKER_TIMEOUT)
        if rc != 0:
            rc, out, err = run(
                ["docker", "exec", container, "cat",
                 "/sys/fs/cgroup/memory/memory.stat"], DOCKER_TIMEOUT)
        if rc != 0:
            warn(f"cgroup memory.stat unreadable in {container}: {err.strip()[:200]}")
            return -1
        fields: dict[str, int] = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].lstrip("-").isdigit():
                fields[parts[0]] = int(parts[1])
        for key in ("anon", "total_rss", "rss"):   # v2, then v1
            if key in fields:
                return fields[key]
        warn(f"no anon/rss field in {container}'s memory.stat")
        return -1

    def anon_sample(self, services: tuple | list) -> dict[str, int]:
        """{container name -> anonymous bytes} for the given compose services."""
        sample: dict[str, int] = {}
        for names in self.container_names(services).values():
            for name in names:
                sample[name] = self.cgroup_anon(name)
        return sample

    # -- API ----------------------------------------------------------------
    def login(self) -> None:
        user = os.environ.get("MLX_ADMIN_USER") or env_get(self.env_file, "ADMIN_USERNAME")
        pw = os.environ.get("MLX_ADMIN_PASSWORD") or env_get(self.env_file, "ADMIN_INITIAL_PASSWORD")
        if not user or not pw:
            raise RuntimeError(
                "no admin credentials: set MLX_ADMIN_USER/MLX_ADMIN_PASSWORD or "
                f"provide ADMIN_USERNAME/ADMIN_INITIAL_PASSWORD in {self.env_file}")
        body = json.dumps({"username": user, "password": pw}).encode()
        req = urllib.request.Request(
            f"{self.base_url}/api/auth/login", data=body,
            headers={"Content-Type": "application/json"})
        # Retried like every other call (§9): a login that times out because
        # the box is busy is not a credential problem, and it used to abort a
        # whole teardown. It stays RAISING on a final failure — every caller
        # (preflight, --cleanup-only, the 401 re-login) treats "cannot log in"
        # as a refusal, not as data.
        tok = http_retry("POST /api/auth/login", self._login_once, req)
        if not tok:
            raise RuntimeError("API login returned no token (password rotated since install?)")
        self.token = tok

    @staticmethod
    def _login_once(req: urllib.request.Request) -> str:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            return str(json.load(r).get("token", ""))

    @staticmethod
    def _api_once(req: urllib.request.Request) -> tuple[int, object]:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                return r.status, raw.decode(errors="replace")

    def api(self, method: str, path: str, body: dict | None = None) -> tuple[int, object]:
        """Authenticated API call; re-logins ONCE on 401 (1h token TTL vs
        multi-phase runs). Returns (status, parsed-json-or-text).

        TRANSIENT FAILURES ARE RETRIED, then REPORTED — never raised (defect
        2026-08-29). A socket read timeout used to escape this method as a raw
        `TimeoutError`, unwind cleanup and end the run with
        `RESIDUE LEFT: UNKNOWN (never verified)`. It now goes through the one
        bounded policy (`http_retry`) and, if the budget is spent, comes back
        as `(0, "transport: ...")`.

        That status is not a swallow (16.1): every caller in this file already
        reads a non-2xx as "this answer is not evidence" — `devices_with_prefix`
        turns it into a list ERROR (residue UNKNOWN, never zero, F-69),
        `delete_devices` into a named failure string — and the exception's own
        repr rides in the body. What changes is that ONE unreachable call no
        longer costs the whole teardown.

        Retry safety: see `http_retry`'s IDEMPOTENCE note — POST /api/devices
        upserts by the caller's id (src/backend/main.go:2368), so a repeated
        create cannot make a second device.
        """
        for attempt in (0, 1):
            data = json.dumps(body).encode() if body is not None else None
            req = urllib.request.Request(
                self.base_url + path, data=data, method=method,
                headers={"Authorization": f"Bearer {self.token}",
                         "Content-Type": "application/json"})
            try:
                return http_retry(f"{method} {path}", self._api_once, req)
            except urllib.error.HTTPError as e:
                if e.code == 401 and attempt == 0:
                    self.login()
                    continue
                return e.code, e.read().decode(errors="replace")[:300]
            except (urllib.error.URLError, OSError) as exc:
                # Reported, not swallowed: the caller sees status 0 and the
                # exception, and every caller treats it as "not evidence".
                self.http_transport_failures += 1
                warn(f"{method} {path}: transport FAILED after retries "
                     f"({exc!r}) — reported as HTTP 0, not raised")
                return 0, f"transport: {exc!r}"
        return 0, "unreachable"

    # -- Kafka --------------------------------------------------------------
    def _kafka_conn(self, config_flag: str = "--command-config") -> list[str]:
        """Connection args for the in-container Kafka CLI tools. The admin
        tools take --command-config; the console producer alone spells it
        --producer.config (same SSL client config either way)."""
        if self.tls:
            return ["--bootstrap-server", "kafka:9094",
                    config_flag, "/tmp/kafka-tls/admin.properties"]
        return ["--bootstrap-server", "kafka:9092"]

    def kafka_tool(self, tool: str, args: list[str], input_text: str | None = None,
                   timeout: int = KAFKA_TOOL_TIMEOUT,
                   config_flag: str = "--command-config") -> tuple[int, str, str]:
        kc = self.cid("kafka")
        if not kc:
            return 1, "", f"no running kafka container in project {self.project}"
        cmd = ["docker", "exec"]
        if input_text is not None:
            cmd.append("-i")
        # SOAK_72H abort post-mortem (2026-08-24, hour 26): every tool call
        # starts a JVM INSIDE the broker's cgroup, whose default heap is 512M
        # (bin/kafka-run-class.sh) against a ~1.08 GiB container limit already
        # ~88% occupied by the broker + page cache. Each start forced direct
        # reclaim (memory.events max=43,521); three produce chunks crossed the
        # 90 s timeout and the burst aborted honestly. Cap the TOOL heap —
        # 192M is ample for console-producer/consumer-groups piping ~1k lines
        # — so the injection vehicle stops fighting the broker for its cgroup.
        # The broker's own KAFKA_HEAP_OPTS is set by its entrypoint at boot
        # and is NOT affected by this per-exec env.
        cmd += ["-e", "KAFKA_HEAP_OPTS=-Xmx192m -Xms64m"]
        cmd += [kc, f"/opt/kafka/bin/{tool}"] + self._kafka_conn(config_flag) + args
        return run(cmd, timeout, input_text)

    def end_offset(self, topic: str) -> int:
        """Sum of the LOG-END-OFFSETs across EVERY partition of `topic`.

        THE DEFECT THIS FIXES (2026-08-29). This asked for `<topic>:0` and
        returned partition 0 alone, while keyed injection deliberately puts a
        whole tenant on ONE partition — measured: the harness's traffic lands
        on partition 3. So the preflight offset heuristic and the accounting
        baseline both looked at a partition the run never wrote to, and read a
        900,000-event injection as "nothing happened". A topic-wide number is
        the only one either caller can mean."""
        rc, out, err = self.kafka_tool(
            "kafka-get-offsets.sh", ["--topic", topic])
        if rc != 0:
            warn(f"kafka-get-offsets {topic} failed: {err.strip()[:200]}")
            return -1
        total, seen = 0, 0
        for line in out.splitlines():
            # `topic:partition:offset`; a partition with no leader prints an
            # empty offset, which is missing evidence, not a zero.
            parts = line.strip().rsplit(":", 2)
            if len(parts) != 3 or parts[0] != topic:
                continue
            try:
                total += int(parts[2])
            except ValueError:
                warn(f"kafka-get-offsets {topic}: unreadable offset in {line.strip()!r}")
                return -1
            seen += 1
        if not seen:
            warn(f"kafka-get-offsets {topic}: no partition rows in output")
            return -1
        return total

    def group_lag(self, group: str) -> dict:
        """{topic: {current,end,lag}}, plus `_total` lag, `_members` count,
        `_rows` (describe rows seen) and `_uncommitted` (partitions a member
        holds but has never committed).

        A group with committed offsets but zero MEMBERS is a dead consumer —
        exactly the wiped-ACL failure shape.

        ####################################################################
        # MEMBERSHIP IS PARSED INDEPENDENTLY OF LAG. DO NOT RE-COUPLE THEM.
        #
        # `kafka-consumer-groups.sh --describe` prints `-` in CURRENT-OFFSET
        # AND LAG for a partition a LIVE member has been assigned but has not
        # committed yet, while CONSUMER-ID carries a real id. Captured live
        # (2026-08-17, apache/kafka 4.1.1):
        #   GROUP  TOPIC  PARTITION CURRENT-OFFSET LOG-END-OFFSET LAG CONSUMER-ID …
        #   probe… netops.verification 0  -   0   -   console-consumer-c3be… …
        #
        # The first version of this parser did `int(f[5])` FIRST and
        # `continue`d on ValueError, so every such row was dropped before the
        # member count — the group read as `{_total: 0, _members: 0}`, which
        # is byte-identical to the dead-consumer verdict. On the lab host that
        # never showed: traffic had always committed offsets by run time. In
        # CI it is the NORMAL state of a fresh install (nothing produced yet,
        # correlation commits manually at N=100/T=5s, Vector commits on
        # consume) — it failed run 31991056443's preflight with
        # "netops-correlation has NO active consumer" while every container
        # was Up+healthy and install.py's own gate had just PASSED on the
        # same broker 27s earlier.
        ####################################################################
        """
        rc, out, err = self.kafka_tool(
            "kafka-consumer-groups.sh", ["--describe", "--group", group])
        if rc != 0:
            return {"_error": err.strip()[:300], "_total": -1, "_members": 0,
                    "_rows": 0, "_uncommitted": 0, "_max_current": -1}

        def num(cell: str) -> int | None:
            """Numeric cell, or None for Kafka's `-` (no committed offset)."""
            return int(cell) if cell.isdigit() else None

        topics: dict[str, dict] = {}
        total = members = rows = uncommitted = 0
        # The MAX committed CURRENT-OFFSET over this group's describe rows —
        # the exact statistic `clean-slate.sh --verify` maxes over (its
        # "<=100000 self-telemetry bound" check, clean-slate.sh:243). Kept
        # beside the per-topic MIN, which lag needs and this does not.
        max_current = -1
        for line in out.splitlines():
            f = line.split()
            if len(f) < 7 or f[0] != group:
                continue
            rows += 1
            # MEMBERSHIP FIRST — it does not depend on any offset being set.
            if f[6] != "-":
                members += 1
            cur, end, lag = num(f[3]), num(f[4]), num(f[5])
            if lag is None:
                uncommitted += 1
            if cur is not None:
                max_current = max(max_current, cur)
            # Aggregate across partitions of the same topic (single-partition
            # today, but a repartitioned topic must not silently lose lag).
            t = topics.setdefault(f[1], {"current": -1, "end": -1, "lag": 0})
            if cur is not None:
                t["current"] = cur if t["current"] < 0 else min(t["current"], cur)
            if end is not None:
                t["end"] = max(t["end"], end)
            if lag is not None:
                t["lag"] += max(lag, 0)
                total += max(lag, 0)
        topics["_total"] = total
        topics["_members"] = members
        topics["_rows"] = rows
        topics["_uncommitted"] = uncommitted
        topics["_max_current"] = max_current
        return topics

    def produce(self, topic: str, lines: list[str],
                key: str | None = None) -> tuple[bool, str]:
        """Produce lines; when `key` is given, every record carries it as the
        Kafka MESSAGE KEY (parse.key + tab separator — JSON payloads cannot
        contain a raw tab, json.dumps escapes them).

        WHY THE KEY MATTERS (2026-08-22 architecture review, qualification-
        validity finding): the production pipeline (Vector) keys every topic by
        TENANT (`__key = tenant_id`), so one tenant's stream lands on ONE
        partition and one correlation replica owns it whole. This harness used
        to inject with NULL keys — round-robin across all partitions — which
        split one tenant 50/50 across both replicas (measured: pending
        64,740/64,480 in run `082201589waa`), a topology production cannot
        produce. Every per-replica capacity figure from null-keyed runs is a
        per-HALF-tenant figure. Keyed injection is therefore the default; the
        legacy shape survives only behind an explicit `--producer-key none`.

        RETURNS (ok, reason). `ok` means EVERY line reached the broker — not
        merely that the tool exited 0. See PRODUCER_HARDENING_ARGS above for
        why those are two different claims and what it cost to learn that.
        """
        if key is not None:
            if "\t" in key:
                return False, f"producer key may not contain a tab: {key!r}"
            payload = "\n".join(f"{key}\t{line}" for line in lines) + "\n"
            extra = ["--property", "parse.key=true",
                     "--property", "key.separator=\t"]
        else:
            payload = "\n".join(lines) + "\n"
            extra = []
        # Producer time scales with payload; bound generously but finitely.
        # The tool bound must outlive delivery.timeout.ms, or a batch still
        # legitimately retrying is killed by `docker exec` — trading a silent
        # drop for a loud one, but a needless one.
        tool_timeout = max(KAFKA_TOOL_TIMEOUT,
                           PRODUCER_DELIVERY_TIMEOUT_MS // 1000 + 60,
                           30 + len(lines) // 500)
        rc, _, err = self.kafka_tool(
            "kafka-console-producer.sh",
            ["--topic", topic] + PRODUCER_HARDENING_ARGS + extra,
            input_text=payload, timeout=tool_timeout,
            config_flag="--producer.config")
        stderr = err.strip()
        if rc != 0:
            return False, (f"kafka-console-producer exit {rc}: "
                           f"{stderr[:400] or '[no output]'}")
        # rc == 0 IS NOT SUCCESS (16.1). The async send callback logs a dropped
        # record and leaves the exit code alone, so the stderr is the only
        # evidence that a record was lost — read it, count it, and fail.
        if not stderr:
            return True, ""
        dropped = [ln for ln in stderr.splitlines()
                   if PRODUCER_SEND_ERROR_RE.search(ln)]
        if dropped:
            return False, (
                f"kafka-console-producer exited 0 but LOGGED {len(dropped)} "
                f"send failure(s) of {len(lines)} records on {topic} — records "
                f"were dropped, not delivered (first: {dropped[0].strip()[:240]})")
        if PRODUCER_STDERR_ANOMALY_RE.search(stderr):
            return False, (
                f"kafka-console-producer exited 0 with unrecognised stderr on "
                f"{topic} — unknown is not clean: {stderr[:400]}")
        # Stderr with no error/exception marker: not a known loss shape, so it
        # does not fail the produce — but it is never discarded either. It goes
        # to the launcher log where the operator sees it (16.1).
        warn(f"kafka-console-producer stderr on {topic}: {stderr[:400]}")
        return True, ""

    def registry_tenant(self, identity: str) -> str:
        """The tenant the correlation engine's registry maps `identity` to —
        the SAME source Vector keys production records from. Empty/unreadable
        registry or unknown identity resolves to "global" (canon_tenant's
        default), never to a guess: keying with the wrong tenant would split
        the stream exactly like the null-key defect this exists to fix."""
        cc = self.cid("correlation")
        if not cc:
            return "global"
        rc, out, _err = run(["docker", "exec", cc, "sh", "-c",
                             "cat /data/enrichment/device_tenant.csv 2>/dev/null || true"],
                            DOCKER_TIMEOUT)
        if rc != 0 or not out.strip():
            return "global"
        for line in out.splitlines()[1:]:
            parts = line.split(",", 1)
            if len(parts) == 2 and parts[0].strip() == identity:
                return parts[1].strip() or "global"
        return "global"

    # -- ClickHouse ---------------------------------------------------------
    def ch(self, query: str, timeout: int = 60) -> tuple[bool, str]:
        cc = self.cid("clickhouse")
        if not cc:
            return False, "no running clickhouse container"
        rc, out, err = run(
            ["docker", "exec", cc, "clickhouse-client", "--query",
             query + " SETTINGS tenant_scope='__all__'"], timeout)
        if rc != 0:
            return False, err.strip()[:400]
        return True, out.strip()

    def ch_mutation(self, query: str) -> tuple[bool, str]:
        """ALTER ... DELETE with synchronous mutation (bounded)."""
        cc = self.cid("clickhouse")
        if not cc:
            return False, "no running clickhouse container"
        rc, out, err = run(
            ["docker", "exec", cc, "clickhouse-client", "--query",
             query + " SETTINGS tenant_scope='__all__', mutations_sync=1"],
            MUTATION_TIMEOUT)
        if rc != 0:
            return False, err.strip()[:400]
        return True, out.strip()

    def ch_now(self) -> str:
        """ClickHouse's own wall clock, as a DateTime literal. The metric_log
        window must be bounded on the SERVER's clock, not the harness host's —
        a few seconds of drift silently changes which run's peak is judged."""
        ok, out = self.ch("SELECT toString(now())")
        return out.strip() if ok else ""

    # -- OpenSearch ---------------------------------------------------------
    def os_req(self, role_env: str, user: str, url_path: str,
               body: dict | None = None, timeout: int = 25) -> tuple[bool, dict | str]:
        """In-container curl with creds via a stdin curl config, never argv
        (OBSERVABILITY_AUDIT.md section 0). TLS variant only differs in
        scheme/CA/creds — both handled here."""
        oc = self.cid("opensearch")
        if not oc:
            return False, "no running opensearch container"
        if self.tls:
            pw = env_get(self.env_file, role_env)
            if not pw:
                return False, f"{role_env} missing from {self.env_file}"
            cfg = (f'url = "https://opensearch:9200{url_path}"\n'
                   f"max-time = {timeout}\nsilent\n"
                   f'cacert = "/usr/share/opensearch/config/tls/ca.pem"\n'
                   f'user = "{user}:{pw}"\n')
        else:
            cfg = f'url = "http://localhost:9200{url_path}"\nmax-time = {timeout}\nsilent\n'
        if body is not None:
            data = json.dumps(body).replace("\\", "\\\\").replace('"', '\\"')
            cfg += f'header = "Content-Type: application/json"\ndata = "{data}"\n'
        rc, out, err = run(["docker", "exec", "-i", oc, "curl", "--config", "-"],
                           timeout + 35, cfg)
        if rc != 0:
            # 2026-08-28: a `curl --silent` that hits `max-time` exits 28 with
            # NOTHING on stdout or stderr, and this line used to return
            # `(err or out).strip()` — i.e. the EMPTY STRING. The live
            # `--cleanup-only` run reported "OpenSearch syslog purge failed: "
            # with no reason at all while 10.3 M docs stayed behind. The exit
            # code is the whole diagnosis; it is never dropped again (16.1).
            detail = (err or out).strip()[:400]
            return False, (f"curl exit {rc} ({curl_exit_meaning(rc, timeout)}) "
                           f"on {url_path}" + (f": {detail}" if detail else
                                               " [no output from curl]"))
        try:
            return True, json.loads(out)
        except json.JSONDecodeError:
            return False, out.strip()[:400]

    def os_count(self, index: str, prefix_field: str, prefix: str) -> int:
        ok, res = self.os_req(
            "OS_API_PASSWORD", "svc_api", f"/{index}/_count",
            {"query": {"prefix": {prefix_field: prefix}}})
        if not ok or not isinstance(res, dict):
            warn(f"OpenSearch count on {index} failed: {res}")
            return -1
        return int(res.get("count", -1))

    # -- correlation service ------------------------------------------------
    def corr_get(self, path: str) -> tuple[bool, str]:
        cc = self.cid("correlation")
        if not cc:
            return False, "no running correlation container"
        if self.tls:
            py = ("import urllib.request,ssl;"
                  "ctx=ssl.create_default_context(cafile='/certs/ca.pem');"
                  "ctx.load_cert_chain('/certs/svid/correlation.crt','/certs/svid/correlation.key');"
                  f"print(urllib.request.urlopen('https://correlation:8443{path}',timeout=8,context=ctx).read().decode())")
        else:
            py = ("import urllib.request;"
                  f"print(urllib.request.urlopen('http://correlation:8000{path}',timeout=8).read().decode())")
        rc, out, err = run(["docker", "exec", cc, "python", "-c", py], 30)
        if rc != 0:
            return False, err.strip()[:400]
        return True, out

    def registry_missing(self, identities: list[str]) -> list[str]:
        """Which of `identities` the correlation engine's registry does NOT hold.

        TRACKER 161. Reads the enrichment CSV the engine actually loads, rather
        than trusting a count from /healthz — the count is a fleet-wide total
        and cannot say whether THESE devices are attributable. Returns [] when
        the file cannot be read, and the caller keeps its count check as the
        backstop, so an unreadable file never reads as "all present".
        """
        cc = self.cid("correlation")
        if not cc or not identities:
            return []
        rc, out, err = run(["docker", "exec", cc, "sh", "-c",
                            "cat /data/enrichment/device_tenant.csv 2>/dev/null || true"],
                           DOCKER_TIMEOUT)
        if rc != 0 or not out.strip():
            warn(f"registry read failed ({err.strip()[:120]}) — falling back to the "
                 f"count check, which cannot see per-identity gaps")
            return []
        present = set()
        for line in out.splitlines()[1:]:
            ident = line.split(",", 1)[0].strip()
            if ident:
                present.add(ident)
        return [i for i in identities if i not in present]

    def corr_healthz(self) -> dict:
        ok, out = self.corr_get("/healthz")
        if not ok:
            return {"_error": out}
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return {"_error": out[:300]}

    def corr_replicas(self) -> list[dict]:
        """Per-replica engine metrics, read from EACH replica deterministically.

        TRACKER 170. `corr_get`/`corr_metric` reach the service through the
        compose DNS name `correlation`, which Docker ROUND-ROBINS across
        replicas — so a "the engine is idle" reading was whichever replica
        answered, and with --scale correlation=2 that is a coin toss. Global
        completion cannot be established from one arbitrary replica.

        Each entry carries the container id and its start time so a mid-run
        RESTART is detectable: a restarted engine reports pending=0 and reset
        counters, which is indistinguishable from "finished" unless identity is
        pinned (mutant 7).

        Connects to the replica's OWN address while still verifying the server
        certificate against its real SPIFFE name — the IP is the routing
        target, `correlation` remains the verified identity. Never disables
        certificate or hostname verification.
        """
        # The compose NAME and the container's RSS ride along with the engine
        # reading (2026-08-29): memflat's correlation slope is anchored on the
        # first sample where THIS replica's `corr_engine_pending` is 0, which
        # needs pending and memory read from the same replica at the same
        # instant. One `docker stats` for the whole stack, not one per replica.
        stats = self.mem_stats()
        out: list[dict] = []
        for cc in self.cids("correlation"):
            rc, insp, err = run(
                ["docker", "inspect", cc, "--format",
                 ("{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"
                  "|{{.State.StartedAt}}|{{.Name}}")],
                DOCKER_TIMEOUT)
            if rc != 0 or "|" not in insp:
                out.append({"container": cc[:12], "error":
                            f"inspect failed: {err.strip()[:160]}"})
                continue
            fields = insp.strip().split("|")
            ip = fields[0]
            started = fields[1] if len(fields) > 1 else ""
            # `.Name` is "/netops-correlation-3"; docker stats keys by the
            # bare name. -1 (never 0) when the container has no stats row.
            name = fields[2].lstrip("/") if len(fields) > 2 else ""
            rss = int(stats.get(name, {}).get("used", -1)) if name else -1
            if not ip:
                out.append({"container": cc[:12], "name": name,
                            "error": "no container IP"})
                continue
            probe = (
                "import socket,ssl,sys\n"
                "ctx=ssl.create_default_context(cafile='/certs/ca.pem')\n"
                "ctx.load_cert_chain('/certs/svid/correlation.crt','/certs/svid/correlation.key')\n"
                f"s=ctx.wrap_socket(socket.create_connection(('{ip}',8443),timeout=8),"
                "server_hostname='correlation')\n"
                "s.sendall(b'GET /metrics HTTP/1.1\\r\\nHost: correlation\\r\\n"
                "Connection: close\\r\\n\\r\\n')\n"
                "b=b''\n"
                "while True:\n"
                "    d=s.recv(65536)\n"
                "    if not d: break\n"
                "    b+=d\n"
                "sys.stdout.write(b.split(b'\\r\\n\\r\\n',1)[1].decode('utf-8','replace'))\n")
            rc, body, err = run(["docker", "exec", cc, "python", "-c", probe], 40)
            if rc != 0:
                out.append({"container": cc[:12], "name": name, "ip": ip,
                            "started_at": started, "rss": rss,
                            "error": f"metrics probe failed: {err.strip()[:160]}"})
                continue
            out.append({"container": cc[:12], "name": name, "ip": ip,
                        "started_at": started, "rss": rss,
                        "metrics": parse_prom_metrics(body)})
        return out

    def corr_completion_state(self) -> dict:
        """The three engine-completion facts, aggregated across replicas.

        Aggregation is deliberate (tracker 170 phase 4): pending SUMS (any
        replica still holding work means the workload is not evaluated),
        oldest-pending-age takes the MAX (the worst replica bounds the claim),
        and cohorts SUM as a progress counter. `readable` is reported so an
        unreadable replica can never be silently treated as idle.
        """
        reps = self.corr_replicas()
        readable = [r for r in reps if "metrics" in r]
        g = lambda r, k: r["metrics"].get(k, -1.0)
        return {
            "replicas": len(reps),
            "readable": len(readable),
            "unreadable": [r.get("container") for r in reps if "metrics" not in r],
            "errors": [r.get("error") for r in reps if "error" in r],
            "pending_sum": sum(max(g(r, "corr_engine_pending"), 0.0) for r in readable),
            "oldest_pending_age_max": max(
                (g(r, "corr_engine_oldest_pending_age_seconds") for r in readable),
                default=-1.0),
            "cohorts_sum": sum(max(g(r, "corr_engine_cohorts_total"), 0.0) for r in readable),
            "per_replica": {
                r["container"]: {
                    "started_at": r.get("started_at"),
                    # Compose name + RSS at the same instant as `pending`:
                    # memflat anchors this replica's leak slope on the sample
                    # where its own pending first reads 0. "" / -1 = unknown.
                    "name": r.get("name", ""),
                    "rss": int(r.get("rss", -1)),
                    "pending": g(r, "corr_engine_pending"),
                    "cohorts_total": g(r, "corr_engine_cohorts_total"),
                    "oldest_pending_age_s": g(r, "corr_engine_oldest_pending_age_seconds"),
                    "epochs_total": g(r, "corr_engine_epochs_total"),
                    "window_signals": g(r, "corr_window_signals"),
                    # ── 2026-08-29 (run p2-s012-08290116). Pending 0 + cohorts
                    # advancing is NOT completion if the cohorts produced
                    # nothing: a bookkeeping ValueError inside the engine's
                    # cohort loop discarded every tenant's snapshots while the
                    # frontier still advanced, and this gate passed in 14 s on a
                    # run with zero incidents. These are read PER REPLICA (a
                    # sum would let a healthy replica mask a broken partner) and
                    # a missing counter stays -1.0 == UNKNOWN, never 0.
                    "windows_rejected": g(r, "corr_engine_windows_rejected_total"),
                    "profiler_errors": g(r, "corr_engine_profiler_errors_total"),
                    "versions_persisted": g(r, 'corr_versions{outcome="persisted"}'),
                    "versions_damped": g(r, 'corr_versions{outcome="damped"}'),
                    "signals_dropped_window_rejected": g(
                        r, 'corr_signals_dropped_total{reason="window_rejected"}'),
                } for r in readable},
        }

    def corr_metric(self, name_with_labels: str) -> float:
        ok, out = self.corr_get("/metrics")
        if not ok:
            return -1.0
        for line in out.splitlines():
            if line.startswith(name_with_labels + " "):
                try:
                    return float(line.rsplit(" ", 1)[1])
                except ValueError:
                    return -1.0
        return 0.0  # counter not yet minted == 0 observed

    # -- VictoriaMetrics ----------------------------------------------------
    def vm_query(self, expr: str) -> float:
        vc = self.cid("victoria")
        if not vc:
            warn("no running victoria container")
            return -1.0
        url = ("http://127.0.0.1:8428/api/v1/query?query=" +
               urllib.parse.quote(expr, safe=""))
        rc, out, err = run(["docker", "exec", vc, "wget", "-qO-", url], DOCKER_TIMEOUT)
        if rc != 0:
            warn(f"VM query failed ({expr[:60]}): {err.strip()[:200]}")
            return -1.0
        try:
            res = json.loads(out)["data"]["result"]
            return float(res[0]["value"][1]) if res else 0.0
        except (json.JSONDecodeError, KeyError, IndexError, ValueError):
            return -1.0

    def dlq_run_reasons(self, runid: str, identity_shas: dict | None = None) -> dict:
        """Run-attributable DLQ lines BROKEN DOWN BY REASON (tracker 159).

        A bare count cannot distinguish "the pipeline dropped something" from
        "zero-trust attribution refused an event it could not attribute to a
        tenant, counted it, and sealed the payload" — which is §3a working. The
        accounting gate needs the reasons to judge the difference, so it reads
        them rather than a total.

        Returns {} on ANY failure — the caller treats an unreadable DLQ as
        unknown and FAILS, never as clean.

        IDENTITY-AWARE (2026-08-19). Grepping for the runid CANNOT see the most
        important category. A tenant-refusal record deliberately withholds the
        payload and the plaintext hostname (F-11 / INV-F11-10) and keeps only
        `identity_sha` = sha256(identity) — so a run's own refusals contain the
        runid nowhere and matched nothing. Measured on ladder 08191832j027:
        **133,349 refused events from this run's devices, and the gate reported
        95.** Passing `identity_shas` (sha256 of every device name -> index)
        makes that category visible without weakening F-11: the ladder knows its
        own device names, so it can compute the same digest the router does.
        """
        cc = self.cid("correlation")
        if not cc:
            return {}
        rc, out, err = run(
            ["docker", "exec", cc, "sh", "-c",
             "cat /data/deadletter/* 2>/dev/null || true"],
            DOCKER_TIMEOUT)
        if rc != 0:
            warn(f"DLQ reason read failed: {err.strip()[:200]}")
            return {}
        shas = identity_shas or {}
        reasons: dict = {}
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                # Only attribute an unparseable line to this run if the runid is
                # literally in it — otherwise a neighbour's corruption would be
                # charged to us.
                if runid in line:
                    reasons["(unparseable DLQ line)"] = (
                        reasons.get("(unparseable DLQ line)", 0) + 1)
                continue
            if not isinstance(rec, dict):
                if runid in line:
                    reasons["(non-object DLQ line)"] = (
                        reasons.get("(non-object DLQ line)", 0) + 1)
                continue
            # Attributable to THIS run either by the runid appearing in the
            # record, or by the sealed identity digest of one of our devices.
            mine = (runid in line) or (rec.get("identity_sha") in shas)
            if not mine:
                continue
            reason = str(rec.get("reason") or "(no reason field)")
            reasons[reason] = reasons.get(reason, 0) + 1
        return reasons

    def dlq_run_lines(self, runid: str) -> int:
        """Run-attributable correlation DLQ lines (payloads carry the device
        hostname, hence the runid)."""
        cc = self.cid("correlation")
        if not cc:
            return -1
        rc, out, err = run(
            ["docker", "exec", cc, "sh", "-c",
             f"cat /data/deadletter/* 2>/dev/null | grep -c -- '{runid}'"],
            DOCKER_TIMEOUT)
        # grep -c exits 1 on zero matches — that is a real 0, not an error.
        if rc not in (0, 1):
            warn(f"DLQ grep failed: {err.strip()[:200]}")
            return -1
        try:
            return int(out.strip() or "0")
        except ValueError:
            return -1


# TRACKER 159. DLQ reasons that are the system working as designed rather than
# losing data. `identity_unattributable` is the §3a tenant check refusing an
# event whose identity it cannot attribute: the event is counted, its payload is
# sealed in the router quarantine (F-11), and nothing is silently dropped.
# Anything NOT listed here fails the accounting gate at a single occurrence.
# How long cleanup waits for the consumer backlog before deleting devices.
# Deleting them earlier turns every in-flight event into a refusal (see
# cleanup()). Bounded: teardown must always happen, drained or not.
CLEANUP_DRAIN_WAIT_S = float(os.environ.get("MLX_CLEANUP_DRAIN_WAIT_S", "300"))
# Pre-purge settle wait (was an inline 600 inside cleanup()): how long cleanup
# waits for the consumer to finish its last inserts before purging telemetry.
CLEANUP_PREPURGE_WAIT_S = float(os.environ.get("MLX_CLEANUP_PREPURGE_WAIT_S", "600"))
# EXPLICIT, GENEROUS budget for the device purge (2026-08-28 residue defect,
# run p1-on-08281911: an interrupted 2,500-device run left every device
# standing). One DELETE is a bounded HTTP_TIMEOUT call, so 2,500 devices need
# minutes, not seconds — and the purge RE-LISTS between passes. The budget is
# a floor plus per-device time so it scales with --devices instead of silently
# truncating a large fleet's teardown.
CLEANUP_DEVICE_BUDGET_BASE_S = float(
    os.environ.get("MLX_CLEANUP_DEVICE_BUDGET_BASE_S", "600"))
CLEANUP_DEVICE_BUDGET_PER_DEVICE_S = float(
    os.environ.get("MLX_CLEANUP_DEVICE_BUDGET_PER_DEVICE_S", "1.5"))
# Delete/verify passes before the purge gives up and reports residue LOUDLY.
DEVICE_PURGE_MAX_PASSES = int(os.environ.get("MLX_DEVICE_PURGE_MAX_PASSES", "12"))
# Page size asked of /api/devices. The endpoint may CAP the page BELOW this
# (2,500 observed), so the pager follows what came back, never what was asked.
DEVICE_PAGE_LIMIT = int(os.environ.get("MLX_DEVICE_PAGE_LIMIT", "5000"))
# Guard against a list endpoint that never says "complete".
DEVICE_PAGE_MAX_PAGES = int(os.environ.get("MLX_DEVICE_PAGE_MAX_PAGES", "200"))
# Every device this harness has EVER created carries this id prefix; nothing
# else may be purged by --cleanup-only (blast-radius guard, 16.3 dry-run rule).
DEVICE_PREFIX_ROOT = "mlx-"
# Progress cadence for the purge — cleanup must never be silent for minutes
# (the 2026-08-28 defect: 900 s of bounded waits with no output at all, so the
# operator could not tell a working cleanup from a hung one).
PURGE_PROGRESS_EVERY = int(os.environ.get("MLX_PURGE_PROGRESS_EVERY", "250"))
# CROSS-RUN COLLISION GUARDS (2026-08-29 — see the section header below).
# The single-writer lock over the harness's device namespace: one file holding
# the owning pid + run id. A run refuses to start while a LIVE pid holds it;
# a stale lock (dead pid) is reclaimed loudly.
RUN_LOCK_PATH = os.environ.get("MLX_RUN_LOCK", "/var/tmp/scale-runs/.lock")
# Deliberate-override switch for the foreign-residue refusal. Loud on use: it
# is the operator saying "those mlx- devices are not mine and I accept them".
ALLOW_FOREIGN_RESIDUE_ENV = "MLX_ALLOW_FOREIGN_RESIDUE"
# How many distinct run ids a residue message names before it says "+N more".
RESIDUE_RUN_IDS_SHOWN = int(os.environ.get("MLX_RESIDUE_RUN_IDS_SHOWN", "5"))

# OpenSearch residue purge (2026-08-28, first live `--cleanup-only mlx-`).
# A SYNCHRONOUS `_delete_by_query?refresh=true` over 10.3 M syslog docs cannot
# finish inside any sane HTTP bound: curl hit `max-time = 300`, exited 28 with
# an EMPTY body, and the harness reported "OpenSearch syslog purge failed: "
# with no reason while every document stayed behind. The delete is now
# submitted ASYNC (`wait_for_completion=false`) and progress is measured by
# RE-COUNTING the prefix — deliberately NOT by polling `_tasks`, because
# `netops_bootstrap` (deployment/docker/opensearch/security/roles.yml) holds no
# `cluster:monitor/tasks/lists` permission and must not gain one to clean a lab.
# It DOES hold `indices_all` on `netops-*`, so the final `_refresh` below is
# within its rights.
OS_PURGE_SUBMIT_TIMEOUT_S = int(os.environ.get("MLX_OS_PURGE_SUBMIT_TIMEOUT_S", "60"))
OS_PURGE_BUDGET_BASE_S = float(os.environ.get("MLX_OS_PURGE_BUDGET_BASE_S", "60"))
# Measured floor to plan against: ~2,000 docs/s deleted on the lab box.
OS_PURGE_SECONDS_PER_DOC = float(
    os.environ.get("MLX_OS_PURGE_SECONDS_PER_DOC", "0.0005"))
OS_PURGE_BUDGET_MAX_S = float(os.environ.get("MLX_OS_PURGE_BUDGET_MAX_S", "10800"))
# ADAPTIVE BUDGET (defect 2026-08-29, /var/tmp/scale-runs/cleanup-only-08290543.log).
# The estimate above assumes 2,000 docs/s (`OS_PURGE_SECONDS_PER_DOC`). On a
# LOADED box — engine draining, ClickHouse busy — the same delete_by_query ran
# at ~1,000 docs/s: the 198s budget expired with 81,001 of 276,001 docs still
# there while the server-side task was working perfectly well, and the harness
# reported residue it had merely stopped waiting for. So the deadline is now
# re-estimated from the MEASURED rate once two counts exist, with a safety
# factor, and only the HARD cap or a genuine STALL ends the wait.
OS_PURGE_ETA_SAFETY = float(os.environ.get("MLX_OS_PURGE_ETA_SAFETY", "1.5"))
# Consecutive polls whose count did NOT decrease before the purge is declared
# stalled. Three (not one) because delete_by_query's progress is visible only
# after a refresh interval, so a single flat poll is normal.
OS_PURGE_STALL_POLLS = int(os.environ.get("MLX_OS_PURGE_STALL_POLLS", "3"))
OS_PURGE_POLL_S = float(os.environ.get("MLX_OS_PURGE_POLL_S", "30"))
OS_SYSLOG_INDEX = "netops-syslog-*"

# Preflight drain ETA (resume brief 2026-08-28 gap): when the baseline lag
# refusal fires, observe the backlog briefly so the refusal carries a number
# the operator can plan against. HARD-BOUNDED — preflight must not become a
# waiting room.
LAG_ETA_BUDGET_S = float(os.environ.get("MLX_LAG_ETA_BUDGET_S", "60"))
LAG_ETA_INTERVAL_S = float(os.environ.get("MLX_LAG_ETA_INTERVAL_S", "15"))
LAG_ETA_SAMPLES = int(os.environ.get("MLX_LAG_ETA_SAMPLES", "3"))
# Signals during cleanup are IGNORED with a message; this many of them means
# the operator really wants out, and we abort — loudly, naming the residue.
CLEANUP_ABORT_AFTER_SIGNALS = int(
    os.environ.get("MLX_CLEANUP_ABORT_AFTER_SIGNALS", "3"))
# TRACKER 170: how close to zero the worst replica's oldest-pending age must
# be to call the engine idle. Not zero: the gauge is computed against the
# newest retained event, so a just-drained engine can read a few seconds.
CORR_IDLE_AGE_S = float(os.environ.get("MLX_CORR_IDLE_AGE_S", "30"))

# Stability observation (2026-08-20). The previous window ended with the drain
# phase and missed three CommitFailedError events that followed it.
STABILITY_SETTLE_MAX_S = float(os.environ.get("MLX_STABILITY_SETTLE_MAX_S", "600"))
STABILITY_GRACE_S = float(os.environ.get("MLX_STABILITY_GRACE_S", "180"))
# ── TRACKER 190: the session timeout is READ, never assumed ────────────────
#
# THE DEFECT. The stability gate's one arithmetic clause — "did the worst
# event-loop stall reach the point where the broker can eject this member?" —
# compared against a constant 30000 ms hard-coded HERE, while the engine has run
# CORR_SESSION_TIMEOUT_MS=60000 since the P1 max-poll-thrash work (main.py, see
# the arithmetic comment above that constant). The gate was not measuring the
# engine's group-membership contract; it was measuring a stale copy of it. The
# drift happened to be conservative — it would fail a 45 s stall the broker
# would have tolerated — but a gate whose threshold is a guess is not a gate,
# and the next drift can just as easily run the other way.
#
# THE FIX. The engine publishes the contract (`corr_session_timeout_ms` on
# /metrics); the harness READS it from every replica it already scrapes. If the
# replicas disagree, or the gauge is absent (an engine image older than the
# gauge), the clause is UNKNOWN and UNKNOWN IS NOT PASS — the same rule the
# unreadable-replica clause has always followed. The env override survives, but
# it is now an OVERRIDE with a stated derivation, not a silent default.
SESSION_TIMEOUT_GAUGE = "corr_session_timeout_ms"
_sto = os.environ.get("MLX_KAFKA_SESSION_TIMEOUT_MS", "").strip()
# None (not 30000) when unset: "nobody told us" must be distinguishable from
# "somebody said 30000", or the refusal path can never fire.
KAFKA_SESSION_TIMEOUT_OVERRIDE_MS: int | None = int(_sto) if _sto else None

DLQ_EXPECTED_REASONS = frozenset({"identity_unattributable"})

# ...and even an expected reason fails above this share of injected events.
# Measured basis: the worst observed ladder run refused 786 of 600,001 (0.13%),
# which is the registry-propagation edge at the start of a burst. 1% leaves that
# headroom while still failing a ~10x regression.
DLQ_EXPECTED_MAX_FRACTION = 0.01

# ── The burst is WORK-boxed, never TIME-boxed (2026-08-29) ─────────────────
#
# THE DEFECT THIS EXISTS FOR. The two 2.5K T-nominal runs of 2026-08-29 were
# supposed to be the same ratified workload; they were not:
#
#   p2-s04-08290653   injected 900001 events in 900s (~1000/s; fleet=900000)
#   p2-s04b-08290858  injected 870001 events in 904s  (~963/s; fleet=870000)
#                     ...and still printed [PASS] burst.
#
# The lane loop was bounded by the WALL CLOCK (`while elapsed < duration`) and
# generated each chunk's quota from the rate sampled at that moment. When the
# producer ran slow (run b: median chunk produce 7.95 s, 22 chunks over 10 s,
# peak 31.65 s) the loop fell behind its own pacing, three of the ninety 10 s
# chunks never came around, and 30,000 events were NEVER GENERATED. The fleet
# had silently become a function of the achieved send rate — and every
# downstream TTUR/completion number is a comparison that assumes an identical
# workload. So:
#
#   * the plan is a pure function of the PROFILE (rate x duration on a nominal
#     chunk clock) — `_lane_schedule()`; two runs of one profile plan the same
#     events to the event, whatever the box is doing that day;
#   * a slow injector EXTENDS the window (up to BURST_WINDOW_MAX_FACTOR x the
#     profile window) instead of shrinking the workload;
#   * a fleet not injected whole inside that bound FAILS burst, naming the
#     shortfall, the achieved rate and the elapsed time. A truncated workload
#     is not a slower run of the same experiment — it is a different one.
BURST_CHUNK_SECS = 10
# How far the window may stretch to absorb a slow injector before the run is
# called: 1.5x the profile window (a 15 min burst may take up to 22.5 min).
# Past that the box is not merely slow, and a burst that long has stopped
# being the profile's arrival shape anyway.
BURST_WINDOW_MAX_FACTOR = float(
    os.environ.get("MLX_BURST_WINDOW_MAX_FACTOR", "1.5"))


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

# ── Scenario-driven storm workload (tracker 183) ────────────────────────────
#
# THE DEFECT THIS EXISTS FOR. The ratified `t-nominal-2.5k` profile pins every
# device's state FOR LIFE: `_syslog_event` sets `state = "down" if seq % 2 == 0
# else "up"` and `_burst_lanes` sets `dev_i = ln["seq"] % 2500`; 2,500 is even,
# so a device's parity — and therefore its state — never changes. Measured on
# the ratified run (docs/scale/P3_AGGREGATION_OPPORTUNITY_2026-08-29.md §4,
# two independent sources agreeing to +/-1 event): 900,001 raw events, 44,280
# promoted signals, **0 state transitions, 0 recovery events**, exactly ONE
# source / ONE vantage per identity, and no identity repeating inside 120 s.
#
# That workload therefore cannot exercise ANY of the causal-significance
# dimensions the storm-plane work is being designed against (owner memo
# §17/§18): recovery, contradiction, corroboration, independent vantage,
# blast-radius expansion. It also carries no ground-truth cause label, which is
# why `scripts/scale-rca-latency.py` has to state in its own docstring that T4
# is a PROXY and causal correctness "CANNOT be scored from persisted data"
# (tracker 177's gap).
#
# `t-storm-2.5k` keeps the ratified THROUGHPUT exactly — 2,500 devices, 900 s,
# 1,000 raw eps, the same 90 x 10,000 chunk plan, so completion / TTUR /
# accounting numbers stay comparable with `t-nominal-2.5k` — and changes only
# the STRUCTURE of the stream:
#
#   * a SEEDED fault-injection SCENARIO supplies the causally-significant
#     events (flap/recovery cycles, repeated confirmation, multi-vantage
#     corroboration, contradictory healthy observations, blast-radius waves);
#   * the existing production-mix generator fills the REST of every chunk with
#     background noise, so the chunk plan is met to the event;
#   * the scenario is a PURE FUNCTION of (profile, seed, device list) — two
#     runs of one seed plan the identical stream, event for event;
#   * the run dir gets a `ground-truth.json` naming each incident's cause
#     entity, onset, recovery and affected set, so T4 correctness can be scored
#     later (contract in `scripts/scale-rca-latency.py`, section GROUND TRUTH).
#
# `t-nominal-2.5k` is deliberately NOT touched: it remains the throughput floor
# and the A/B baseline (memo §23 wants the exact same workload replayed).

SCENARIO_SEED_DEFAULT = 20260829
# Incidents may claim at most this share of the fleet; everything else is the
# NOISE POOL. The two sets are DISJOINT by construction, which is what makes
# the "noise never shares a cause entity with an incident" clause checkable
# rather than hopeful.
#
# 0.60 -> 0.65 (2026-08-29, enterprise_outage): the four original templates
# claim 910 of 2,500 devices; the site-scale outage template adds 15 sites x 40
# devices = 600, for 1,510. At 0.60 the budget is 1,500 and `_build` would have
# silently truncated the LAST template rather than failing — the failure mode
# `test_all_four_cause_kinds_are_instantiated` exists to catch. 0.65 = 1,625
# leaves 115 devices of headroom and still leaves 990 devices (39.6 %) in the
# noise pool, which is what the disjointness clause rests on.
# THE DEFAULT ONLY. The budget is a `chain.StormShape` knob now
# (`shape.device_budget`), because the storm-share ladder needs a bigger
# scenario population than 0.65 at its higher rungs; this constant is the
# DEFAULT shape's value and is pinned equal to it by
# tests/test_storm_scenario_profile.py.
SCENARIO_DEVICE_BUDGET = 0.65
# Interface indices 0..47 belong to the background mix (`if_n = seq % 48`);
# scenario faults take 48..95, so an incident entity_id (`host:ifname`) can
# never collide with a background one even if the pools were ever to overlap.
SCENARIO_IF_BASE = 48
SCENARIO_IF_SPAN = 48
# Peer addresses. The background mix only ever emits host octets {1, 2, 9, 50}
# (`10.{oct2}.{oct3}.1` and friends), so scenario peers take 200+ and can never
# be mistaken for a background adjacency by the engine's shared-token welding.
SCENARIO_PEER_HOST_BASE = 200
SCENARIO_PEER_HOST_SPAN = 50
# Memo §18 "repeated confirmation": a re-report counts as a repeat only inside
# this window. PLAN offsets are capped well under it (MAX_OFFSET) because the
# emitted timestamp is quantized by the 10 s chunk clock — a repeat planned at
# +40 s can be emitted up to ~10 s later than a repeat planned at +0 s, and
# must STILL be inside 60 s of it.
SCENARIO_REPEAT_WINDOW_S = 60.0
SCENARIO_REPEAT_MAX_OFFSET_S = 40.0
# THE PER-CHUNK QUOTA GUARD (redesigned for the P3 storm-share ladder).
#
# The old guard refused a scenario only when a 10 s chunk's planned scenario
# events EXCEEDED that chunk's whole ratified quota. That was enough while the
# scenario was ~2 % of the fleet, and it is not enough at 50 %: a chunk filled
# to the brim by the scenario leaves the background nothing to inject, so the
# noise devices fall silent, per-device `corr_signals` coverage fails forty
# minutes later, and the "background never carries a cause entity" clause
# stops being observable because there is no background.
#
# So the guard now reserves HEADROOM: every chunk keeps at least this share of
# its ratified quota for the background, whatever the storm share. It is a
# SPREAD requirement, not a volume one — a scenario that plans its mass evenly
# across the window passes it at 50 % (measured peak 7,192 of a 10,000 quota),
# and one that piles a site's route churn into six chunks fails it however
# small its total is.
SCENARIO_CHUNK_HEADROOM = 0.10
# A storm whose peak chunk is many times its mean chunk is a SPIKE, not a
# storm: its mass lands in a handful of chunks and the run measures a burst
# the ratified plan never ratified. MEASURED at the default seed on 2,500
# devices over 900 s: `storm-2.5k` 4.67x (833 peak / 178 mean — the small
# scenario is the lumpiest, because a single site's route-churn phase is a
# large share of its total), `storm-10-2.5k` 2.24x, `storm-25-2.5k` 1.95x,
# `storm-50-2.5k` 1.53x — the ladder gets SMOOTHER as it grows, because it
# grows by overlapping more incidents rather than by deepening any one of
# them. The bound leaves room for a seed to be unluckier than this one and
# still refuses a genuine spike; the per-chunk headroom rule above is the
# hard constraint, this is the shape constraint.
SCENARIO_CHUNK_PEAK_OVER_MEAN_MAX = 8.0
GROUND_TRUTH_FILE = "ground-truth.json"
GROUND_TRUTH_SCHEMA = "correlix.scale.ground-truth/1"
# The SAME incidents in the network digital twin's record shape, so
# `scripts/lab/twin/twin.py score --runid <id> --run-root data/miniladder`
# scores a mini-ladder run with the twin's existing scorer instead of a second
# one. The run dir is already named `<UTC>-<runid>`, which is exactly the
# `*-<runid>` glob `twin.find_run_dir` uses. See `StormScenario.twin_records`
# for why this is a projection, not a rival schema.
TWIN_GROUND_TRUTH_FILE = "ground_truth.jsonl"
TWIN_STATE_FILE = "state.json"

# ── The scenario itself ─────────────────────────────────────────────────────
#
# Sized so the causal population is LARGE ENOUGH TO MEASURE without changing
# the promoted-signal volume enough to make the A/B against t-nominal-2.5k
# dishonest: the scenario contributes ~0.8 % of the raw fleet, against a
# background whose measured promotion is 4.92 %. The storm profile changes the
# SHAPE of the signal stream, not its scale — that is the whole point of
# keeping the throughput floor.
#
# Template fields:
#   cause_kind                what the ground truth calls the fault
#   instances_per_1k_devices  instance count scales with --devices
#   devices_per_instance      total devices the instance owns (cause + blast)
#   onset_window              (lo, hi) seconds into the burst, uniform
#   recovery_after_s          (lo, hi) seconds after onset; None = never
#   repeats                   (lo, hi) EXTRA re-reports of a symptom, <= 40 s
#   reassert_every_s          an unrecovered fault re-reports on this period
#   blast_waves               shares of the affected set arriving per wave
#   wave_gap_s                seconds between blast-radius waves
#   contradiction_devices     affected devices that emit a healthy observation
#                             while the fault is still active
#   cycles / cycle_gap_s      flap templates only: down->up repeated N times
#   expected_owner_class      the class the RCA verdict SHOULD attribute
#   expected_seam_class       the seam class the RCA SHOULD land on
#
# expected_owner_class / expected_seam_class are SCENARIO LABELS, not values
# the lab can currently produce: mlx- devices are onboarded with no seam
# configuration, so the engine has nothing to attribute ownership to. They are
# written into ground-truth.json so an owner-correctness dimension can be
# scored the day the harness provisions seams — until then a scorer must treat
# them as informational (stated in the ground-truth contract).
STORM_SCENARIO_2K5: dict = {
    "name": "storm-2.5k",
    # The DECLARED repetition/dynamics of this workload. `chain.DEFAULT_SHAPE`
    # reproduces the plan exactly as it was before the shape existed — every
    # accessor returns the constant it replaced, so the RNG call sequence and
    # therefore the scenario digest are unchanged (pinned by
    # tests/test_storm_scenario_profile.py::test_the_default_shape_is_todays_plan).
    "shape": chain.DEFAULT_SHAPE,
    "description": ("seeded fault-injection scenario for the 2.5K rung: "
                    "upstream link failures with blast-radius waves, local "
                    "link faults, BGP peer flaps with recovery, and 3x-cycling "
                    "OSPF adjacency flaps, over a disjoint background pool"),
    "templates": (
        {
            # An aggregation uplink fails and takes a set of access devices
            # with it. The access devices all peer with the SAME upstream
            # address, so their BGP-down signals share an entity token — the
            # multi-vantage / corroboration structure memo §18 asks for.
            "cause_kind": "upstream_link_failure",
            "instances_per_1k_devices": 8.0,
            "devices_per_instance": 25,          # 1 cause + 24 affected
            "onset_window": (30.0, 520.0),
            "recovery_after_s": (150.0, 300.0),
            "repeats": (2, 5),
            "reassert_every_s": 120.0,
            "blast_waves": (0.5, 0.3, 0.2),
            "wave_gap_s": 60.0,
            "contradiction_devices": 2,
            "expected_owner_class": "upstream_transport",
            "expected_seam_class": "wan_transport",
        },
        {
            # A single device's own link dies and never comes back inside the
            # window: the uncorroborated, unrecovered case. One vantage on
            # purpose — not every fault is confirmed by a second observer.
            "cause_kind": "local_link_fault",
            "instances_per_1k_devices": 60.0,
            "devices_per_instance": 1,
            "onset_window": (30.0, 700.0),
            "recovery_after_s": None,
            "repeats": (2, 6),
            "reassert_every_s": 150.0,
            "expected_owner_class": "device_local",
            "expected_seam_class": "lan_access",
        },
        {
            # Two devices peering with the same off-fleet route reflector lose
            # it together and get it back: two INDEPENDENT vantages on one
            # cause, with a real recovery transition.
            "cause_kind": "bgp_peer_flap",
            "instances_per_1k_devices": 40.0,
            "devices_per_instance": 2,
            "onset_window": (40.0, 760.0),
            "recovery_after_s": (45.0, 110.0),
            "repeats": (1, 3),
            "reassert_every_s": 0.0,             # short fault: no re-assertion
            "expected_owner_class": "peer_transit",
            "expected_seam_class": "wan_transport",
        },
        {
            # The chronic flapper: down -> up, three times over. Six state
            # transitions and three recoveries on ONE identity — the class
            # t-nominal-2.5k contains exactly zero of.
            "cause_kind": "ospf_adjacency_flap",
            "instances_per_1k_devices": 24.0,
            "devices_per_instance": 1,
            "onset_window": (40.0, 560.0),
            "recovery_after_s": (25.0, 45.0),    # per cycle: time to re-adjacency
            "repeats": (1, 2),
            "reassert_every_s": 0.0,
            "cycles": 3,
            "cycle_gap_s": 90.0,
            "expected_owner_class": "igp_internal",
            "expected_seam_class": "lan_core",
        },
        {
            # THE ENTERPRISE SITE OUTAGE — one causally ordered chain, at
            # scale. A site's core uplink fails and the whole site degrades in
            # a fixed causal order: uplink down -> IGP adjacency loss -> a
            # second core port flapping -> the eBGP session to transit
            # flapping -> route churn and an update burst -> the access layer
            # reconverging (STP) and re-homing hosts (MAC moves) -> recovery,
            # or not.
            #
            # The vocabulary and the phase bands are NOT defined here: they
            # come from `scripts/enterprise_outage_chain.py`, which the network
            # digital twin's `_tpl_enterprise_outage` imports too. One story,
            # one definition; this template is its 2,500-device replication.
            "cause_kind": "enterprise_outage",
            "instances_per_1k_devices": 6.0,     # 15 sites at 2,500 devices
            "devices_per_instance": 40,          # 2 core/dist + 38 access
            "onset_window": (30.0, 520.0),
            "recovery_after_s": chain.PHASE_BAND["recovery"],
            "repeats": chain.REPEAT_RANGE,
            "reassert_every_s": 0.0,             # the chain re-reports on its
            #                                      own schedule (phases), not
            #                                      on a flat period
            # THESE FOUR ARE THE SHAPE'S, not the template's: the values
            # below are the DEFAULT SHAPE's and are kept here so the template
            # still reads as a complete story, but `StormScenario` takes them
            # from `spec["shape"]` (`chain.StormShape`) so a ladder rung can
            # declare a different repetition/dynamics without a second
            # template. `tests/test_storm_scenario_profile.py` pins that the
            # default shape reproduces exactly these numbers.
            "no_recovery_share": chain.NO_RECOVERY_SHARE,
            "flap_cycles_range": chain.FLAP_CYCLE_RANGE,
            "churn_eps_range": chain.CHURN_EPS_RANGE,
            # The throughput-bounded duration band + event budget — see the
            # module constants for the measured arithmetic behind them.
            "churn_duration_range": chain.CHURN_DURATION_RANGE_SCALE,
            "churn_max_events": chain.CHURN_MAX_EVENTS_SCALE,
            "stp_share_range": chain.STP_SHARE_RANGE,
            "mac_share_range": chain.MAC_SHARE_RANGE,
            "expected_owner_class": "upstream_transport",
            "expected_seam_class": "wan_transport",
        },
    ),
}

# ── the storm-share LADDER (P3, 2026-08-29) ─────────────────────────────────
#
# WHY A LADDER. `t-storm-2.5k` fixed the DYNAMICS of the 2.5K workload but not
# its MASS: its scenario is 1.78 % of the raw fleet plan, so 98.2 % of what the
# engine sees is still the repeat-free production background (measured:
# `docs/scale/P3_AGGREGATION_OPPORTUNITY_2026-08-29.md` — 0 % collapse under a
# 60 s event-time bucket, 0 transitions, 0 recoveries). An Aggregation Plane
# A/B run against that can only ever touch ~2 % of the stream, so it cannot
# decide anything.
#
# The rungs below hold the RATIFIED THROUGHPUT EXACTLY — the same 2,500
# devices, 900 s, 1,000 raw eps, the same 90 × 10,000 chunk plan — and vary
# ONLY the share of that plan the seeded scenario carries. The background
# shrinks to make room, event for event, so completion / TTUR / accounting
# stay comparable across the whole ladder and against `t-nominal-2.5k`.
#
# Devices, per rung (`--devices 2500`, measured at plan time and written into
# ground truth as `devices.scenario` / `devices.noise_pool`):
#
#   rung                target share   scenario devices   noise devices
#   t-storm-2.5k              1.78 %              1,510             990
#   t-storm-10-2.5k          10 %                 ~2,270            ~230
#   t-storm-25-2.5k          25 %                 ~2,290            ~210
#   t-storm-50-2.5k          50 %                 ~2,300            ~200
#
# The higher rungs reach their share by running MANY OVERLAPPING INCIDENTS
# (`shape.incident_density` allocation rounds — a device carrying two faults
# inside fifteen minutes is ordinary) rather than by making any one site
# bursty: the route-churn phase gets LONGER as well as denser, onsets spread
# further across the window, and the per-chunk guard below checks the result
# fits the ratified quota with headroom for the background.
SCENARIO_STORM_LADDER: tuple = ((0.10, "storm-10-2.5k"),
                                (0.25, "storm-25-2.5k"),
                                (0.50, "storm-50-2.5k"))


def storm_spec_for_share(share: float, name: str) -> dict:
    """`STORM_SCENARIO_2K5` re-shaped to carry `share` of the raw fleet plan.

    The TEMPLATES are untouched — same five cause kinds, same causal story,
    same vocabulary. Only the SHAPE changes, and every knob the templates read
    goes through it (`StormScenario._shape_*`), so a rung is a pure function of
    its target share: `storm_spec_for_share(x, n)` always yields the same spec.
    """
    shape = chain.StormShape.for_share(share, name=name)
    spec = dict(STORM_SCENARIO_2K5)
    spec["name"] = name
    spec["shape"] = shape
    spec["description"] = (
        f"{STORM_SCENARIO_2K5['description']} — shaped to carry "
        f"{share:.0%} of the ratified raw fleet plan "
        f"(incident density {shape.incident_density}x, repeat factor "
        f"{shape.repeat_factor}, churn {shape.churn_density} eps/site)")
    return spec


SCENARIO_SPECS: dict = {"storm-2.5k": STORM_SCENARIO_2K5}
SCENARIO_SPECS.update({name: storm_spec_for_share(share, name)
                       for share, name in SCENARIO_STORM_LADDER})

# ── the HOST-CEILING ladder (5K / 10K fleets, 2026-08-30) ───────────────────
#
# WHY THESE RUNGS. The storm-share ladder above varies the STRUCTURE of a
# 2,500-device workload. The host-ceiling programme
# (`docs/projects/01-SCALE-TESTING.md` §ladder) varies the FLEET instead, to
# find the largest estate this box carries to a graded verdict — so these
# rungs hold the storm share FIXED at the ratified `t-storm-2.5k` value
# (`chain.DEFAULT_SHAPE`, target 1.78 %) and change nothing but scale. The two
# axes are never varied at once, or a rung's verdict would be about both.
#
# NOTHING IN THE SCENARIO NEEDS RE-SIZING FOR THEM, and that is a property of
# the generator rather than luck: `_build` derives each template's instance
# count as `instances_per_1k_devices x len(devices) / 1000`, so the scenario
# grows with the fleet, while the profile's rate grows with the fleet by the
# same factor (the T-family's ratified 0.4 eps/device) — the SHARE is
# therefore invariant. Measured on this generator, seed 20260829, 900 s:
#
#   fleet     raw plan    scenario events   share     peak chunk   peak/mean
#    2,500      900,000            16,060   1.784 %   8.3 % quota      4.67x
#    5,000    1,800,000            31,791   1.766 %   7.0 % quota      3.96x
#   10,000    3,600,000            63,736   1.770 %   4.4 % quota      2.50x
#
# — every rung inside the ±10 % band the ladder tests hold against the 1.7844 %
# target, and the plan gets SMOOTHER with scale (more incidents overlapping the
# same window), so the per-chunk headroom and anti-spike guards get easier, not
# tighter, as the fleet grows.
#
# WHY A NAMED SPEC PER RUNG rather than reusing `storm-2.5k`: the scenario name
# is what `ground-truth.json`, `shape_record` and the twin records carry, and a
# 10,000-device run must not report itself as `storm-2.5k`. The plan digest is
# a function of the spec's CONTENT, the device list, the seed and the window —
# never of the name — so on one device list all three names hash to the same
# digest (pinned by tests/test_storm_scenario_profile.py): one story, three
# fleets.
SCENARIO_FLEET_LADDER: tuple = ((5000, "storm-5k"), (10000, "storm-10k"))


def storm_spec_for_fleet(devices: int, name: str) -> dict:
    """`STORM_SCENARIO_2K5` under its own NAME, for a larger fleet.

    Same five templates, same `chain.DEFAULT_SHAPE`, therefore the same
    declared storm share as `t-storm-2.5k`. `devices` sizes the DESCRIPTION
    only — the instance counts come from the run's actual device list, so a
    rung run at the wrong `--devices` still plans a consistent scenario (its
    share is what moves, and ground truth records it).
    """
    spec = dict(STORM_SCENARIO_2K5)
    spec["name"] = name
    spec["description"] = (
        f"the ratified t-storm-2.5k fault-injection story at {devices} "
        f"devices — same five cause kinds, same DEFAULT_SHAPE (target "
        f"{chain.DEFAULT_SHAPE.storm_share_of_raw:.2%} of the raw fleet plan), "
        f"instance counts scaled by the fleet "
        f"(instances_per_1k_devices x {devices} / 1000)")
    return spec


SCENARIO_SPECS.update({name: storm_spec_for_fleet(devices, name)
                       for devices, name in SCENARIO_FLEET_LADDER})

# Rotation applied to the scenario device population between allocation rounds
# (`shape.incident_density` > 1). A round-0 rotation of ZERO is what keeps the
# default plan byte-identical; the stride is a prime well clear of every
# template's slice width, so the DEVICE-scoped cause of `ospf_adjacency_flap`
# lands on a different device each round. `_build` refuses a duplicate cause
# entity outright (16.1) rather than letting two incidents weld into one.
SCENARIO_ROUND_ROTATION = 977

# THE BACKGROUND, MEASURED (docs/scale/P3_AGGREGATION_OPPORTUNITY_2026-08-29.md
# §1/§2, two independent sources — an offline re-instantiation of the ratified
# generator and the live Kafka window — agreeing to ±1 event on 900,001 raw
# events of the `production` mix). These two numbers are what let the harness
# state, at PLAN time and without a stack, how many signals the WHOLE stream
# puts in front of the engine:
#   * 4.92 % of raw production-mix lines promote to a Signal at all;
#   * of those, a 60 s event-time bucket key removes 0.0 % — the background is
#     a FAN-OUT stream (31,955 distinct identities in 15 min), so it offers an
#     Aggregation Plane nothing. Every reachable repeat is in the scenario.
# They are constants of the MIX, not of a run, and a change to
# EVENT_MIX_REALISTIC / EVENT_MIX_NOISE invalidates them.
PRODUCTION_MIX_PROMOTION_PCT = 4.92
PRODUCTION_MIX_K3_REDUCTION_PCT = 0.0


# ── Ratified workload profiles (STRESS_GATE_REDEFINITION_2026-08-22 §5/§6) ──
#
# A profile OVERRIDES eps/burst-minutes/event-mix and, for storm profiles,
# defines LANES: (name, device-share, mix, eps or a rate function of elapsed
# seconds). `--devices` is never overridden. "legacy" applies nothing and keeps
# the historical single-lane loop byte-identical for continuity with the
# evidence trail. All rates compose with the RATIFIED 1K bands
# (EPS_BASELINE_PROPOSAL §5): nominal 400 raw fleet, S1 = 10 % blast radius at
# storm amplitude + background nominal ≈ 4,000 raw / ~1,200 admitted.
WORKLOAD_PROFILES: dict = {
    "legacy": {"workload_class": "LEGACY_ARGS"},
    # T-family and S3 run through the LANES path too (a single fleet-wide
    # lane): the legacy single-lane loop keeps its historical correlated
    # modulus (device = seq % N, mix = seq % L), which under a noise-bearing
    # mix starves fixed devices of classifying events FOREVER — the second
    # T-nominal run's accounting caught exactly 100/1000 devices covered.
    # Only --profile legacy may use the legacy loop, and only with the
    # fully-classifying mixes it always had.
    "t-nominal": {
        "workload_class": "T_NOMINAL",
        "burst_minutes": 15,
        "lanes": [("fleet", 1.0, "production", 400.0)],
    },
    "t-p95": {
        "workload_class": "T_P95",
        "burst_minutes": 15,
        "lanes": [("fleet", 1.0, "production", 800.0)],
    },
    "s1": {
        "workload_class": "S1_DESIGN_STORM",
        "burst_minutes": 15,
        "lanes": [
            # (lane, device_share, mix, eps): 10 % of devices carry the storm
            # at control-plane-heavy mix; the rest stay at nominal production.
            ("storm", 0.10, "storm", 3640.0),
            ("background", 0.90, "production", 360.0),
        ],
    },
    "s1-long": {
        "workload_class": "S1_LONG_STORM",
        "burst_minutes": 60,
        "lanes": [
            ("storm", 0.10, "storm", 3640.0),
            ("background", 0.90, "production", 360.0),
        ],
    },
    "s2-ramp": {
        "workload_class": "S2_ESCALATION_RAMP",
        "burst_minutes": 75,   # 60 min ramp + 15 min hold
        "lanes": [
            # Storm lane RAMPS 40 -> 3,640 eps over 3,600 s then holds — the
            # slow-escalation storm class (field log: 5k -> 741k pps over ~5 h).
            ("storm", 0.10, "storm",
             lambda t: 40.0 + (3600.0 * min(1.0, t / 3600.0))),
            ("background", 0.90, "production", 360.0),
        ],
    },
    "s3-stress": {
        # Today's saturation probe, relabelled: estate-wide, 100 % promotion,
        # ~20-200x measured reality. CHARACTERIZATION/defect-finding ONLY —
        # graded on invariants + throughput trend, never absolute completion.
        "workload_class": "S3_SATURATION_PROBE",
        "burst_minutes": 5,
        "lanes": [("fleet", 1.0, "single", 2000.0)],
    },
    # ── 2.5K rung (EPS ladder, pre-staged; run with --devices 2500) ──────
    # Rates per the ratified ladder: nominal 0.4 eps/device; S1 = 10 % blast
    # radius at storm amplitude over a nominal estate (10x fleet aggregate).
    # First characterization runs AFTER the 1K rung closes (soak + S1 pass).
    "t-nominal-2.5k": {
        "workload_class": "T_NOMINAL_2K5",
        "burst_minutes": 15,
        "lanes": [("fleet", 1.0, "production", 1000.0)],
    },
    # The SAME throughput as t-nominal-2.5k — identical lanes, identical
    # burst_minutes, therefore the identical 90 x 10,000 chunk plan — with a
    # SEEDED fault-injection scenario supplying the causally-significant events
    # and the production mix filling the rest of every chunk. t-nominal-2.5k
    # stays the throughput floor and the A/B baseline; this profile is the one
    # that can exercise recovery / contradiction / corroboration /
    # blast-radius expansion and carries ground truth for T4 correctness.
    # See the SCENARIO_SEED_DEFAULT header above for why it had to exist.
    "t-storm-2.5k": {
        "workload_class": "T_STORM_2K5",
        "burst_minutes": 15,
        "lanes": [("fleet", 1.0, "production", 1000.0)],
        "scenario": "storm-2.5k",
    },
    # ── the P3 storm-share ladder ────────────────────────────────────────
    # Identical lanes, identical burst_minutes, therefore the identical
    # 90 x 10,000 chunk plan as t-nominal-2.5k and t-storm-2.5k. The ONLY
    # difference between the rungs is how much of that plan the seeded
    # scenario carries; the background fills the rest from the (shrinking)
    # noise pool. See SCENARIO_STORM_LADDER for the device split per rung.
    "t-storm-10-2.5k": {
        "workload_class": "T_STORM_10_2K5",
        "burst_minutes": 15,
        "lanes": [("fleet", 1.0, "production", 1000.0)],
        "scenario": "storm-10-2.5k",
    },
    "t-storm-25-2.5k": {
        "workload_class": "T_STORM_25_2K5",
        "burst_minutes": 15,
        "lanes": [("fleet", 1.0, "production", 1000.0)],
        "scenario": "storm-25-2.5k",
    },
    "t-storm-50-2.5k": {
        "workload_class": "T_STORM_50_2K5",
        "burst_minutes": 15,
        "lanes": [("fleet", 1.0, "production", 1000.0)],
        "scenario": "storm-50-2.5k",
    },
    "s1-2.5k": {
        "workload_class": "S1_DESIGN_STORM_2K5",
        "burst_minutes": 15,
        "lanes": [
            ("storm", 0.10, "storm", 9100.0),
            ("background", 0.90, "production", 900.0),
        ],
    },
    # ── the HOST-CEILING ladder (5K / 10K rungs, 2026-08-30) ─────────────
    #
    # `docs/projects/01-SCALE-TESTING.md` §ladder — the largest fleet this box
    # carries to a graded verdict. Run each rung with its OWN device count
    # (`--devices 5000` / `--devices 10000`); `--devices` is never overridden
    # by a profile, and a rung run at the wrong count measures a rate per
    # device nobody ratified.
    #
    #   * EPS is CARRIED BY THE LANE, not derived from `--devices` — the
    #     profile machinery only ever reads the lane's rate — so it is written
    #     out here at the T-family's ratified 0.4 eps/device: 2,500 -> 1,000,
    #     5,000 -> 2,000, 10,000 -> 4,000 raw. Per-device load is therefore
    #     IDENTICAL across the ladder, which is what makes a completion or
    #     TTUR difference between rungs a statement about the box.
    #   * THE WINDOW stays 15 min, like every other T rung — and that is what
    #     keeps the ratified 2,700 s budgets: both the drain and the
    #     correlation-completion caps are `--drain-factor` (3.0) x
    #     `burst_seconds` (900). An INCOMPLETE at 2,700 s is the MEASURED
    #     finding for that rung (§ladder), never a reason to widen the cap.
    #   * THE STORM SHARE is unchanged at the ratified ~1.78 %
    #     (`chain.DEFAULT_SHAPE`): the ceiling hunt varies SCALE, and the
    #     storm-share ladder above is the other axis (see
    #     SCENARIO_FLEET_LADDER for the measured share at each fleet).
    #   * ONBOARDING scales with the fleet and nothing else does: expect
    #     `onboard_budget_s()` — ~633 s at 5,000 and ~967 s at 10,000 against
    #     the measured 15-30 creates/s — and size the caller's timeout
    #     (`scale-ab-driver.py --leg-timeout`) accordingly. Tracker 175
    #     (device-store tombstone debt) is the thing that moves that number;
    #     the phase reports the budget and the achieved rate beside it.
    "t-nominal-5k": {
        "workload_class": "T_NOMINAL_5K",
        "burst_minutes": 15,
        "lanes": [("fleet", 1.0, "production", 2000.0)],
    },
    "t-storm-5k": {
        "workload_class": "T_STORM_5K",
        "burst_minutes": 15,
        "lanes": [("fleet", 1.0, "production", 2000.0)],
        "scenario": "storm-5k",
    },
    "t-nominal-10k": {
        "workload_class": "T_NOMINAL_10K",
        "burst_minutes": 15,
        "lanes": [("fleet", 1.0, "production", 4000.0)],
    },
    "t-storm-10k": {
        "workload_class": "T_STORM_10K",
        "burst_minutes": 15,
        "lanes": [("fleet", 1.0, "production", 4000.0)],
        "scenario": "storm-10k",
    },
    "soak-72h": {
        # The 72h soak (owner-launched 2026-08-22): continuous background at
        # 100 raw eps (0.1 eps/device — inside the MEASURED production band of
        # 0.05-0.26 eps/device; the 400-eps planning nominal is proven
        # separately by T-nominal) + the S4 chronic-chatter lane throughout.
        # Rate sized to lab disk (~500 B/event end-to-end footprint; 25.9M
        # events over 72h). The embedded S1 exercise is EXCLUDED until
        # tracker 172 lands (SOAK_READINESS_VERDICT §recommendation).
        "workload_class": "SOAK_72H_100EPS",
        "burst_minutes": 4320,
        "lanes": [
            ("chatter", 0.005, "single", 0.35),
            ("background", 0.995, "production", 100.0),
        ],
    },
    "s4-chatter": {
        "workload_class": "S4_CHATTER_PROBE",
        "burst_minutes": 60,
        "lanes": [
            # 0.5 % of devices in chronic sub-10s flap loops (the 250/hr
            # device class) riding on a nominal estate: correlation-tier
            # impact must be ~zero (suppression/dedup absorbs it).
            ("chatter", 0.005, "single", 0.35),   # ~250 events/hr/device — the measured chronic-flap class
            ("background", 0.995, "production", 400.0),
        ],
    },
}


def lane_chunk_plan(lanes: list, duration_s: int) -> list[dict]:
    """The RATIFIED CHUNK PLAN of a lane profile: how many events each lane
    injects in each `BURST_CHUNK_SECS` chunk of `duration_s`.

    Module level so the BURST and `--dry-run` read ONE definition of what a
    profile will send. A dry run that prints a different number from the one
    the burst injects is not a dry run (16.3): it was printing `--eps` — a
    value no lane profile ever uses — while the run planned the lane rates.

    Fractional rates carry per lane, so a 0.35 eps lane still integrates
    exactly over the window rather than truncating every chunk to zero.
    """
    accs = [0.0] * len(lanes)
    plan: list[dict] = []
    for start in range(0, duration_s, BURST_CHUNK_SECS):
        end = min(start + BURST_CHUNK_SECS, duration_s)
        row: dict = {}
        for i, (name, _share, _mix, rate) in enumerate(lanes):
            # Integrate the rate over the chunk's seconds — exact for the ramp
            # profiles, identical to rate*chunk_secs for flat ones.
            inc = (sum(rate(t) for t in range(start, end)) if callable(rate)
                   else float(rate) * (end - start))
            accs[i] += inc
            k = int(accs[i])
            accs[i] -= k
            row[name] = k
        plan.append(row)
    return plan


class ScenarioEvent(typing.NamedTuple):
    """One planned fault-injection line.

    `t` is PLAN time (seconds from burst t0), which decides only WHICH 10 s
    chunk the line is injected in — the wire timestamp is wall clock at produce
    time, exactly like every background line (mixing generator event-time with
    engine wall-clock is the skew caveat `scale-rca-latency.py` already carries;
    this profile does not add a second clock to it).

    `entity` is the entity_id the correlation classifier WILL derive from the
    line (`host:ifname` for interface-scoped kinds, `host` for device-scoped
    ones) — kept here so the harness can measure identity-level dynamics
    without re-implementing the parser.

    An EMPTY `symptom` means the line PROVABLY does NOT promote — the
    classifier returns None for it. Such lines are emitted on purpose: a real
    enterprise outage produces symptoms this engine cannot see (BGP route
    churn), and a scenario that quietly substituted a message that DOES
    classify would be scoring the engine against a network that does not
    exist. They are counted separately by `dynamics()` and named in ground
    truth's `parser_coverage` (`scripts/enterprise_outage_chain.py`).
    """

    t: float
    device: str
    appname: str
    message: str
    severity: str
    incident_id: str
    symptom: str      # the correlation `kind` this line classifies to, or ""
    #                   when the line provably does not promote at all
    state: str        # "down" | "up"
    role: str         # onset|expansion|flap|flap_up|churn|repeat|reassert|
    #                   recovery|contradiction. ANCHOR roles (onset/expansion/
    #                   flap) open a fresh symptom; a `repeat` is always within
    #                   SCENARIO_REPEAT_MAX_OFFSET_S of its anchor. `flap_up`
    #                   is the UP half of a flap cycle (the fault is still
    #                   open); `recovery` is reserved for the incident really
    #                   ending, so "recovery follows every fault" stays a
    #                   checkable invariant.
    entity: str       # the entity_id the classifier derives
    etype: str = ""   # enterprise_outage only: the chain event type this line
    #                   realizes, the key into `chain.parser_coverage()`


class StormScenario:
    """A SEEDED, DETERMINISTIC fault-injection scenario over a device fleet.

    A scenario is a list of incidents carrying GROUND TRUTH — cause kind, cause
    entity, onset, recovery, blast radius, expected owner/seam class — plus the
    syslog lines that make those incidents observable. It exists because the
    ratified `t-nominal-2.5k` stream has zero state transitions, zero
    recoveries and one vantage per identity (see the header above
    `SCENARIO_SEED_DEFAULT`), so nothing in memo §17/§18 can be exercised or
    scored against it.

    DETERMINISM CONTRACT. The whole plan — incidents, event list, chunk
    buckets, noise pool — is a pure function of (spec, device list, seed,
    window). No wall clock, no process entropy, no dict-ordering dependence:
    every random draw comes from `_rng(label)`, a Mersenne Twister seeded with
    a SHA-256 of `seed:label` (stable across interpreter versions and
    platforms, which `hash()` is not). `digest()` is the one number that proves
    it, and `tests/test_storm_scenario_profile.py` re-plans the same seed twice
    and compares byte for byte.

    NOISE DISJOINTNESS. `noise_pool` is the devices NO incident touches. The
    burst fills the rest of each chunk's ratified quota from that pool alone,
    so a background line can never carry an incident's cause entity — the
    property `test_noise_never_shares_a_cause_entity` pins. Fault interfaces
    (48..95) and peer host octets (200+) additionally sit outside every range
    the background mix can generate, so the two populations cannot collide even
    if the pools were ever allowed to overlap.

    VANTAGE, IN A SYSLOG-ONLY HARNESS. The harness produces to `netops.syslog`
    and nothing else, and the classifier stamps every signal's observer as the
    EMITTING DEVICE — so two vantages on one *entity_id* is not expressible.
    What is expressible, and what the engine actually welds on, is two vantages
    on one CAUSE: several devices independently reporting an adjacency loss
    toward the same peer address (a shared `entity_tokens` entry), plus the
    cause device's own view of its failed interface. `vantages` in the ground
    truth is therefore the set of DISTINCT DEVICES that observed the cause, and
    a scorer must read it that way.
    """

    def __init__(self, spec: dict, devices: list[str], seed: int,
                 window_s: float, chunk_secs: int = BURST_CHUNK_SECS,
                 profile: str = "", runid: str = "") -> None:
        if not devices:
            raise ValueError("scenario needs a non-empty device list")
        self.spec = spec
        # The DECLARED repetition/dynamics of this workload (P3). Every knob
        # the templates read goes through it, so "how repetitive is this
        # stream" is a parameter of the profile rather than a by-product of
        # how five templates happened to be sized. `chain.DEFAULT_SHAPE` is
        # today's plan exactly — same bands, same draws, same digest.
        self.shape: chain.StormShape = spec.get("shape") or chain.DEFAULT_SHAPE
        if not isinstance(self.shape, chain.StormShape):   # 16.1: never guess
            raise TypeError(
                f"scenario spec {spec.get('name')!r} carries a 'shape' that is "
                f"not a chain.StormShape ({type(self.shape).__name__})")
        self.devices = list(devices)
        self.seed = int(seed)
        self.window_s = float(window_s)
        self.chunk_secs = int(chunk_secs)
        self.profile = profile
        self.runid = runid
        self.incidents: list[dict] = []
        self.events: list[ScenarioEvent] = []
        self.noise_pool: list[str] = []
        self.template_counts: dict[str, dict] = {}
        # The allocation round currently being built. It is what keeps a
        # REUSED device's fault names distinct (`_ifname`), and it is 0 for
        # every shape whose incident density is 1.0 — i.e. for today's plan.
        self._round = 0
        self._cause_entities: set = set()
        self.rounds_built = 1
        self._build()
        self.events.sort(key=lambda e: (e.t, e.device, e.appname, e.message,
                                        e.role))
        n_chunks = max(1, int((self.window_s + self.chunk_secs - 1)
                              // self.chunk_secs))
        self.buckets: list[list[ScenarioEvent]] = [[] for _ in range(n_chunks)]
        for e in self.events:
            self.buckets[min(int(e.t // self.chunk_secs), n_chunks - 1)].append(e)

    # -- deterministic randomness -------------------------------------------
    def _rng(self, label: str) -> random.Random:
        """A Mersenne Twister seeded from SHA-256(seed:label).

        NOT `random.Random(f"{seed}:{label}")`: string seeding is documented but
        goes through a version-dependent path, and NOT `hash()`, which is salted
        per process. A digest keeps the plan reproducible across machines and
        interpreter versions — which is the entire point of a seeded scenario.
        """
        digest = hashlib.sha256(f"{self.seed}:{label}".encode()).digest()
        return random.Random(int.from_bytes(digest[:8], "big"))

    # -- line shapes (each pinned against the REAL classifier in tests) ------
    @staticmethod
    def _link_line(ifname: str, state: str) -> tuple[str, str, str]:
        return ("LINK-3-UPDOWN",
                f"%LINK-3-UPDOWN: Interface {ifname}, changed state to {state}",
                "err")

    @staticmethod
    def _bgp_line(peer: str, state: str) -> tuple[str, str, str]:
        word = "Down" if state == "down" else "Up"
        return ("BGP-5-ADJCHANGE",
                f"%BGP-5-ADJCHANGE: neighbor {peer} {word}",
                "notice")

    @staticmethod
    def _ospf_line(peer: str, ifname: str, state: str) -> tuple[str, str, str]:
        # "down beats up" in `_state_of`, so the down arm may name FULL; the up
        # arm must contain no down-token at all ("LOADING", never "INIT").
        tail = "from FULL to DOWN" if state == "down" else "from LOADING to FULL"
        return ("OSPF-5-ADJCHG",
                f"%OSPF-5-ADJCHG: Process 1, Nbr {peer} on {ifname} {tail}",
                "notice")

    @staticmethod
    def _lldp_line(ifname: str, state: str) -> tuple[str, str, str]:
        verb = "removed" if state == "down" else "added"
        return ("LLDP-5-NEIGHBOR",
                f"%LLDP-5-NEIGHBOR: neighbor {verb} on interface {ifname}",
                "notice")

    @staticmethod
    def _alarm_line(fan: int) -> tuple[str, str, str]:
        # Deliberately an UNRECOGNIZED mnemonic at warning severity: it falls
        # through to the classifier's generic device-alarm net (the same arm
        # EVENT_MIX_REALISTIC uses, pinned by tests/test_event_mix_167.py).
        return ("ENVMON-4-FAN_FAILED", f"%ENVMON-4-FAN_FAILED: Fan {fan} failed",
                "warning")

    # -- naming: outside every range the background mix can produce ---------
    def _ifname(self, n: int) -> str:
        """The fault interface for instance `n` in the CURRENT allocation
        round.

        Round 0 is exactly `GigabitEthernet0/48..95` — outside the 0..47 the
        background mix can emit — and every later round takes the next
        48-wide block. That is what lets two incidents share a device without
        sharing a cause entity: the interface carries the round.
        """
        return (f"GigabitEthernet0/"
                f"{SCENARIO_IF_BASE + (n % SCENARIO_IF_SPAN) + SCENARIO_IF_SPAN * self._round}")

    @staticmethod
    def _peer_ip(n: int) -> str:
        """A unique peer address per instance, host octet >= 200.

        Unique for n < 251*251*SCENARIO_PEER_HOST_SPAN by construction (a plain
        positional decomposition) — a modular product would silently alias two
        incidents onto one address and weld them into a false merge.
        """
        return (f"10.{n % 251}.{(n // 251) % 251}."
                f"{SCENARIO_PEER_HOST_BASE + (n // (251 * 251)) % SCENARIO_PEER_HOST_SPAN}")

    # -- emission -----------------------------------------------------------
    def _emit(self, iid: str, t: float, device: str, line: tuple[str, str, str],
              symptom: str, state: str, role: str, entity: str,
              etype: str = "") -> bool:
        """Append one planned line. Anything outside [0, window) is DROPPED —
        it would never be injected, and ground truth that claims an event the
        stream does not contain is worse than no ground truth."""
        if t < 0.0 or t >= self.window_s:
            return False
        appname, message, severity = line
        self.events.append(ScenarioEvent(
            round(float(t), 3), device, appname, message, severity, iid,
            symptom, state, role, entity, etype))
        return True

    # -- the shared enterprise-outage chain ---------------------------------
    def _chain(self, iid: str, t: float, dev: str, etype: str,
               line: tuple[str, str, str], role: str, ifname: str = "") -> bool:
        """Emit one line of the shared chain vocabulary.

        The symptom, the state and the entity are all read from
        `enterprise_outage_chain`, which derives them from the REAL producer's
        behaviour — the harness never restates the parser in its own words, so
        it cannot describe a signal the engine does not create.
        """
        return self._emit(iid, t, dev, line,
                          chain.signal_kind(etype),
                          chain.CHAIN_BY_TYPE[etype].state,
                          role,
                          chain.entity_of(etype, dev, ifname),
                          etype)

    def _link(self, iid, t, dev, ifname, state, role) -> bool:
        return self._emit(iid, t, dev, self._link_line(ifname, state),
                          "link_state_change", state, role, f"{dev}:{ifname}")

    def _bgp(self, iid, t, dev, peer, state, role) -> bool:
        return self._emit(iid, t, dev, self._bgp_line(peer, state),
                          "bgp_adjacency_change", state, role, dev)

    def _ospf(self, iid, t, dev, peer, ifname, state, role) -> bool:
        return self._emit(iid, t, dev, self._ospf_line(peer, ifname, state),
                          "ospf_adjacency_change", state, role, dev)

    def _lldp(self, iid, t, dev, ifname, state, role) -> bool:
        return self._emit(iid, t, dev, self._lldp_line(ifname, state),
                          "lldp_neighbor_change", state, role, f"{dev}:{ifname}")

    def _alarm(self, iid, t, dev, fan, role) -> bool:
        # State is deliberately EMPTY: the classifier's generic device-alarm net
        # yields no `state` attribute, and claiming one here would let the
        # dynamics counters report transitions the engine can never see.
        return self._emit(iid, t, dev, self._alarm_line(fan),
                          "device_alarm", "", role, dev)

    # -- timing helpers -----------------------------------------------------
    def _onset(self, tpl: dict, rng: random.Random) -> float:
        # A bigger storm must SPREAD, not pile up: `shape.onset_span` widens
        # every template's onset band toward the whole window so the extra
        # incidents overlap instead of stacking into the same chunks.
        lo, hi = self.shape.onset_window(tpl["onset_window"], self.window_s)
        hi = min(float(hi), self.window_s - 10.0)
        lo = min(float(lo), hi)
        return round(rng.uniform(lo, hi), 1)

    @staticmethod
    def _jit(rng: random.Random, band: tuple) -> float:
        """A seeded draw from `band`, jittered by ±`chain.JITTER_FRACTION`.

        The jitter is applied AFTER the draw and deliberately NOT clamped back
        into the band: fifteen sites of one template must not fire their phases
        on the same clock, or the stream carries a periodicity no real estate
        has and the aggregation plane is measured against an artefact. Phase
        ORDER is never left to the draw — `_build_enterprise_outage` clamps
        each phase monotonically after the phase that causes it.
        """
        lo, hi = float(band[0]), float(band[1])
        v = rng.uniform(lo, hi) if hi > lo else lo
        return round(v * rng.uniform(1.0 - chain.JITTER_FRACTION,
                                     1.0 + chain.JITTER_FRACTION), 2)

    def _recovery(self, tpl: dict, rng: random.Random, onset: float,
                  span: tuple | None = None) -> float | None:
        """Recovery time, or None when the fault is still open at window close.

        A scenario in which EVERY fault recovers is as unrealistic as one in
        which none does; letting the window truncate some recoveries is
        deliberate, and the ground truth records `recovery_ts: null` for them.
        """
        rng_span = span if span is not None else tpl.get("recovery_after_s")
        if not rng_span:
            return None
        lo, hi = rng_span
        t = onset + rng.uniform(float(lo), float(hi))
        return None if t >= self.window_s - 5.0 else round(t, 1)

    def _repeat_offsets(self, tpl: dict, rng: random.Random) -> list[float]:
        """Offsets of the EXTRA re-reports of a symptom (memo §18 'repeated
        confirmation'). Bounded by SCENARIO_REPEAT_MAX_OFFSET_S so the emitted
        spread survives the 10 s chunk quantization and still counts as a
        repeat inside SCENARIO_REPEAT_WINDOW_S."""
        n = self.shape.draw_repeats(rng, tpl["repeats"])
        if n <= 0:
            return []
        step = SCENARIO_REPEAT_MAX_OFFSET_S / n
        return [round(3.0 + step * k, 1) for k in range(n)]

    def _reassert_times(self, tpl: dict, t0: float,
                        until: float | None) -> list[float]:
        """A fault nobody fixed keeps being logged. These are the low-causal-
        information repeats memo §19 puts in P3 — the mass an Aggregation Plane
        is allowed to collapse, and which t-nominal-2.5k does not contain."""
        period = self.shape.reassert_every_s(tpl.get("reassert_every_s"))
        if period <= 0.0:
            return []
        end = min(self.window_s if until is None else until, self.window_s)
        out: list[float] = []
        t = t0 + period
        while t < end:
            out.append(round(t, 1))
            t += period
        return out

    # -- construction -------------------------------------------------------
    def _build(self) -> None:
        """Allocate devices to incidents and build every one of them.

        ONE ROUND, OR SEVERAL. At `shape.incident_density == 1.0` this is the
        original single pass: a shuffled device order, a cursor that advances
        template by template, and everything past the cursor becomes the noise
        pool. That path is byte-identical to the plan before the shape existed.

        Above 1.0 the scenario needs more incidents than one pass over the
        fleet can carry, so it makes SEVERAL passes over the SAME scenario
        population — which is what a real estate does: a device can be caught
        by two faults inside fifteen minutes. Each round rotates the
        population by `SCENARIO_ROUND_ROTATION` (round 0 rotates by zero) and
        takes the next 48-wide block of fault interfaces, so a reused device
        never re-uses a cause entity. The noise pool is every device NO round
        ever claimed, which keeps the background-disjointness clause exactly
        as strong as it was.
        """
        order = list(self.devices)
        self._rng("layout").shuffle(order)
        budget = int(len(order) * self.shape.device_budget)
        # The scenario POPULATION: rounds rotate inside it, so the devices the
        # background may speak for can never be eaten by a later round.
        population = order[:budget]
        rounds = max(1, math.ceil(float(self.shape.incident_density) - 1e-9))
        self.rounds_built = rounds
        claimed: set = set()
        idx = 0
        per_kind_inst: dict = {}
        counts: dict = {}
        for rnd in range(rounds):
            self._round = rnd
            k = (rnd * SCENARIO_ROUND_ROTATION) % max(1, len(population))
            ring = population[k:] + population[:k]
            cursor = 0
            for tpl in self.spec["templates"]:
                kind = str(tpl["cause_kind"])
                builder = getattr(self, f"_build_{kind}", None)
                if builder is None:                 # 16.1: never silently skip
                    raise ValueError(
                        f"scenario template {kind!r} has no builder")
                want_total = round(
                    self.shape.instances_per_1k(tpl["instances_per_1k_devices"])
                    * len(order) / 1000.0)
                # Spread this template's instances evenly over the rounds, so
                # every round is about the size of one fleet pass and no round
                # can overrun the device budget on its own.
                want = want_total // rounds + (1 if rnd < want_total % rounds
                                               else 0)
                per = int(tpl["devices_per_instance"])
                row = counts.setdefault(kind, {
                    "instances_planned": want_total, "instances_built": 0,
                    "devices_per_instance": per, "devices": 0,
                    "truncated_by_device_budget": False})
                for _inst in range(want):
                    if cursor + per > len(ring):
                        row["truncated_by_device_budget"] = True
                        break                        # device budget exhausted
                    devs = ring[cursor:cursor + per]
                    cursor += per
                    idx += 1
                    inst_global = per_kind_inst.get(kind, 0)
                    per_kind_inst[kind] = inst_global + 1
                    builder(f"I{idx:04d}", idx, tpl, devs,
                            self._rng(f"{kind}:{inst_global}"))
                    row["instances_built"] += 1
                    row["devices"] += per
                    claimed.update(devs)
        self._round = 0
        for kind, row in counts.items():
            row["truncated_by_device_budget"] = (
                row["truncated_by_device_budget"]
                or row["instances_built"] < row["instances_planned"])
            self.template_counts[kind] = row
        self.noise_pool = [d for d in order if d not in claimed]
        if not self.noise_pool:
            # Unreachable while `shape.device_budget` < 1.0 — every round
            # allocates inside `population = order[:budget]`, so the devices
            # past the budget are never claimed however many rounds run — and
            # kept anyway: the disjointness clause rests entirely on this pool
            # existing, so the day someone widens the budget the scenario must
            # refuse rather than quietly let the background start emitting
            # from incident devices.
            raise ValueError(
                f"scenario claimed every one of {len(order)} devices — no "
                f"background pool left to fill the chunk plan from "
                f"(device budget {self.shape.device_budget:.0%})")

    def _record(self, iid: str, tpl: dict, cause_entity: dict, onset: float,
                recovery: float | None, blast: list[str], vantages: list[str],
                symptom_kinds: list[str], **extra) -> None:
        inc = {
            "incident_id": iid,
            "cause_kind": str(tpl["cause_kind"]),
            "cause_entity": cause_entity,
            "onset_ts": round(onset, 1),
            "recovery_ts": None if recovery is None else round(recovery, 1),
            "blast_radius": sorted(set(blast)),
            "vantages": sorted(set(vantages)),
            "symptom_kinds": sorted(set(symptom_kinds)),
            "expected_owner_class": str(tpl["expected_owner_class"]),
            "expected_seam_class": str(tpl["expected_seam_class"]),
        }
        inc.update(extra)
        # A cause entity claimed twice would weld two incidents into one — a
        # FALSE MERGE (memo §25) no scorer could tell from an engine defect.
        # Device reuse across allocation rounds makes that reachable, so it is
        # refused here rather than discovered in the scoring.
        eid = str(cause_entity.get("entity_id") or "")
        if eid in self._cause_entities:
            raise ValueError(
                f"scenario {self.spec.get('name')!r}: cause entity {eid!r} is "
                f"claimed by two incidents ({iid} and an earlier one) — two "
                f"faults would weld into one object; widen "
                f"SCENARIO_ROUND_ROTATION or lower shape.incident_density")
        self._cause_entities.add(eid)
        self.incidents.append(inc)

    # ---- template: an upstream link fails and takes access devices with it -
    def _build_upstream_link_failure(self, iid, idx, tpl, devs, rng) -> None:
        # `shape.vantages_per_cause` bounds how many devices independently
        # observe ONE cause: every affected device reports its adjacency loss
        # toward the shared upstream address, so the affected set IS the
        # vantage count and the shape clamps it.
        cause_dev = devs[0]
        affected = list(devs[1:self.shape.vantage_devices(len(devs))])
        upif = self._ifname(idx)
        peer = self._peer_ip(idx)
        onset = self._onset(tpl, rng)
        recovery = self._recovery(tpl, rng, onset)

        # The cause device's own view: its uplink went down, it keeps saying so
        # until (if ever) it comes back.
        self._link(iid, onset, cause_dev, upif, "down", "onset")
        for off in self._repeat_offsets(tpl, rng):
            self._link(iid, onset + off, cause_dev, upif, "down", "repeat")
        for t in self._reassert_times(tpl, onset, recovery):
            self._link(iid, t, cause_dev, upif, "down", "reassert")
        if recovery is not None:
            self._link(iid, recovery, cause_dev, upif, "up", "recovery")

        # Blast radius arrives in WAVES — memo §17's "blast-radius expansion",
        # the class the engine is supposed to treat as high causal information.
        shares = self.shape.blast_waves()
        groups: list[list[str]] = []
        start = 0
        for w, share in enumerate(shares):
            n = (len(affected) - start if w == len(shares) - 1
                 else round(float(share) * len(affected)))
            groups.append(affected[start:start + n])
            start += n
        waves: list[dict] = []
        seen: list[str] = [cause_dev]
        contradictions: list[dict] = []
        # Memo §17/§18's contradictory healthy observation, as a SHARE of the
        # affected set rather than a fixed device count, so it scales with the
        # blast radius the shape asks for.
        n_contra = self.shape.contradiction_devices(len(affected))
        for w, group in enumerate(groups):
            at = onset + w * float(tpl["wave_gap_s"])
            if at >= self.window_s or not group:
                continue
            emitted: list[str] = []
            for j, dev in enumerate(group):
                t0 = at + 0.5 * j          # deterministic intra-wave stagger
                acc_if = self._ifname(idx + j + 1)
                role = "onset" if w == 0 else "expansion"
                # The corroborating vantage: an adjacency loss toward the SAME
                # upstream address, from a device that is not the cause.
                ok = self._bgp(iid, t0, dev, peer, "down", role)
                # ...and the device's own local symptom.
                self._link(iid, t0 + 1.0, dev, acc_if, "down", role)
                for off in self._repeat_offsets(tpl, rng):
                    self._bgp(iid, t0 + off, dev, peer, "down", "repeat")
                for t in self._reassert_times(tpl, t0, recovery):
                    self._bgp(iid, t, dev, peer, "down", "reassert")
                if recovery is not None:
                    self._bgp(iid, recovery, dev, peer, "up", "recovery")
                    self._link(iid, recovery + 1.0, dev, acc_if, "up", "recovery")
                # A CONTRADICTORY healthy observation while the fault is open
                # (memo §17/§18): the link reports up, then down again.
                if w == 0 and j < n_contra:
                    ct = t0 + 25.0
                    if (recovery is None or ct + 10.0 < recovery) and \
                            self._link(iid, ct, dev, acc_if, "up", "contradiction"):
                        self._link(iid, ct + 5.0, dev, acc_if, "down", "reassert")
                        contradictions.append({"device": dev,
                                               "at": round(ct, 1),
                                               "entity_id": f"{dev}:{acc_if}"})
                if ok:
                    emitted.append(dev)
            if emitted:
                waves.append({"at": round(at, 1), "devices": sorted(emitted)})
                seen.extend(emitted)

        affected_seen = [d for d in seen if d != cause_dev]
        self._record(
            iid, tpl,
            {"entity_type": "interface", "device": cause_dev, "interface": upif,
             "entity_id": f"{cause_dev}:{upif}", "peer": peer},
            onset, recovery, blast=seen,
            # Every affected device observed the cause through the shared peer
            # address; the cause device observed its own interface.
            vantages=[cause_dev] + affected_seen,
            symptom_kinds=["link_state_change", "bgp_adjacency_change"],
            blast_radius_waves=waves,
            contradictions=contradictions,
            flap_cycles=1)

    # ---- template: one device, one link, no recovery -----------------------
    def _build_local_link_fault(self, iid, idx, tpl, devs, rng) -> None:
        dev = devs[0]
        ifname = self._ifname(idx)
        onset = self._onset(tpl, rng)
        self._link(iid, onset, dev, ifname, "down", "onset")
        for off in self._repeat_offsets(tpl, rng):
            self._link(iid, onset + off, dev, ifname, "down", "repeat")
        # Corroboration by MODALITY rather than by vantage: the same interface
        # also loses its LLDP neighbor and raises a chassis alarm.
        self._lldp(iid, onset + 2.0, dev, ifname, "down", "onset")
        self._alarm(iid, onset + 8.0, dev, SCENARIO_IF_BASE + (idx % SCENARIO_IF_SPAN),
                    "onset")
        for t in self._reassert_times(tpl, onset, None):
            self._link(iid, t, dev, ifname, "down", "reassert")
        self._record(
            iid, tpl,
            {"entity_type": "interface", "device": dev, "interface": ifname,
             "entity_id": f"{dev}:{ifname}", "peer": None},
            onset, None, blast=[dev], vantages=[dev],
            symptom_kinds=["link_state_change", "lldp_neighbor_change",
                           "device_alarm"],
            blast_radius_waves=[{"at": round(onset, 1), "devices": [dev]}],
            contradictions=[], flap_cycles=1)

    # ---- template: a shared BGP peer flaps, seen from two devices ----------
    def _build_bgp_peer_flap(self, iid, idx, tpl, devs, rng) -> None:
        peer = self._peer_ip(idx)
        onset = self._onset(tpl, rng)
        recovery = self._recovery(tpl, rng, onset)
        vantages: list[str] = []
        for j, dev in enumerate(devs):
            t0 = onset + 0.4 * j
            if self._bgp(iid, t0, dev, peer, "down", "onset"):
                vantages.append(dev)
            for off in self._repeat_offsets(tpl, rng):
                self._bgp(iid, t0 + off, dev, peer, "down", "repeat")
            if recovery is not None:
                self._bgp(iid, recovery + 0.4 * j, dev, peer, "up", "recovery")
        self._record(
            iid, tpl,
            {"entity_type": "peer", "device": devs[0], "interface": None,
             # The cause is the PEER, not either device: `entity_id` is the
             # shared token both devices' signals carry (`entity_tokens`), which
             # is what the engine welds on.
             "entity_id": peer, "peer": peer},
            onset, recovery, blast=list(devs), vantages=vantages,
            symptom_kinds=["bgp_adjacency_change"],
            blast_radius_waves=[{"at": round(onset, 1),
                                 "devices": sorted(devs)}],
            contradictions=[], flap_cycles=1)

    # ---- template: an OSPF adjacency that cycles down/up N times -----------
    def _build_ospf_adjacency_flap(self, iid, idx, tpl, devs, rng) -> None:
        dev = devs[0]
        peer = self._peer_ip(idx)
        ifname = self._ifname(idx)
        onset = self._onset(tpl, rng)
        cycles = int(tpl.get("cycles") or 1)
        gap = float(tpl.get("cycle_gap_s") or 0.0)
        last_up: float | None = None
        cycle_log: list[dict] = []
        for c in range(cycles):
            down_at = onset + c * gap
            if down_at >= self.window_s:
                break
            self._ospf(iid, down_at, dev, peer, ifname, "down",
                       "onset" if c == 0 else "flap")
            for off in self._repeat_offsets(tpl, rng):
                self._ospf(iid, down_at + off, dev, peer, ifname, "down",
                           "repeat")
            up_at = self._recovery(tpl, rng, down_at)
            if up_at is not None:
                self._ospf(iid, up_at, dev, peer, ifname, "up", "recovery")
                last_up = up_at
            cycle_log.append({"down_at": round(down_at, 1),
                              "up_at": None if up_at is None else round(up_at, 1)})
        self._record(
            iid, tpl,
            {"entity_type": "device", "device": dev, "interface": ifname,
             "entity_id": dev, "peer": peer},
            onset, last_up, blast=[dev], vantages=[dev],
            symptom_kinds=["ospf_adjacency_change"],
            blast_radius_waves=[{"at": round(onset, 1), "devices": [dev]}],
            contradictions=[], flap_cycles=len(cycle_log),
            cycles=cycle_log)

    # ---- template: an enterprise SITE outage, one causal chain ------------
    def _build_enterprise_outage(self, iid, idx, tpl, devs, rng) -> None:
        """A whole site degrades in ONE causally ordered chain (2026-08-29).

        The site is 2 core/distribution routers + 38 access switches. Its core
        uplink fails and everything that follows, follows FROM that, in this
        order (bands and vocabulary from `scripts/enterprise_outage_chain.py`,
        shared with the network digital twin's `_tpl_enterprise_outage`):

          t0        %LINK / %LINEPROTO down on the core's uplink  ← THE CAUSE
          +1–3 s    %OSPF-5-ADJCHG FULL→DOWN toward the upstream neighbour
          +2–10 s   a SECOND core port flaps 2–4 × (LINK/LINEPROTO + the
                    adjacency to the distribution router, logged from BOTH
                    ends — two independent vantages on one cause)
          +5–15 s   the eBGP session to transit flaps Down → Up → Down
          +10–60 s  route churn at 5–20 eps for 30–45 s, plus a dense
                    router-update burst and a %BGP-3-NOTIFICATION
          +20–90 s  the access layer: a TCN on EVERY switch in the STP domain,
                    a real port transition on 20–60 % of them, MAC moves on
                    10–30 % as hosts re-home
          +150–300 s recovery — LINK/LINEPROTO up, adjacency up, session up,
                    STP back to forwarding — for all but the `no_recovery_share`
                    of sites, which are HARD OUTAGES and never come back.

        WHAT THE ENGINE CANNOT SEE. The route-churn phase is deliberately built
        from the vendor-standard `%BGP-5-NBR_RESET`, which the classifier
        PROVABLY drops, and `%BGP-4-MAXPFX`, which promotes only through the
        generic device-alarm net. Substituting a message that classifies would
        have made the stream look like something a real router does not emit;
        instead the outcome is recorded per event type in ground truth's
        `parser_coverage`, so a scorer never charges the engine for a symptom
        it was never given.

        ORDERING. Every phase offset is a seeded draw with ±20 % jitter, then
        clamped to at least 0.5 s after the phase that causes it, and recovery
        is clamped to at least 5 s after the LAST fault event of the incident.
        Causal order therefore holds for every seed, not just this one.
        """
        if len(devs) < 3:                        # 16.1: never build it wrong
            raise ValueError(
                f"enterprise_outage needs at least 3 devices per site (core + "
                f"distribution + access), got {len(devs)} — fix "
                f"devices_per_instance")
        core, dist = devs[0], devs[1]
        access = list(devs[2:])
        upif = self._ifname(idx)                    # the CAUSE entity
        flapif = self._ifname(idx + 1)
        # Four distinct off-fleet addresses, all host octet ≥ 200 and unique
        # across incidents (`_peer_ip` is injective well past these strides), so
        # no two sites can weld through a shared peer token.
        peer_ospf = self._peer_ip(idx + 5000)       # nbr across the dead uplink
        peer_transit = self._peer_ip(idx + 10000)   # upstream eBGP peer
        peer_dist = self._peer_ip(idx + 15000)      # the dist router, from core
        peer_core = self._peer_ip(idx + 20000)      # the core router, from dist
        vlan = 200 + (idx % 100)
        first = len(self.events)

        # ── the phase clock: seeded, jittered, monotonically causal ────────
        t0 = self._onset(tpl, rng)
        t_ospf = t0 + self._jit(rng, chain.PHASE_BAND["ospf_neighbor_down"])
        t_flap = max(t_ospf + 0.5,
                     t0 + self._jit(rng,
                                    chain.PHASE_BAND["ospf_interface_flap"]))
        t_bgp = max(t_flap + 0.5,
                    t0 + self._jit(rng, chain.PHASE_BAND["bgp_session_flap"]))

        # ── phase 1: the cause ────────────────────────────────────────────
        self._chain(iid, t0, core, "link_down", chain.link(upif, "down"),
                    "onset", upif)
        self._chain(iid, t0 + 1.0, core, "lineproto_down",
                    chain.lineproto(upif, "down"), "onset", upif)
        for off in self._repeat_offsets(tpl, rng):
            self._chain(iid, t0 + off, core, "link_down",
                        chain.link(upif, "down"), "repeat", upif)

        # ── phase 2: the IGP notices ──────────────────────────────────────
        self._chain(iid, t_ospf, core, "ospf_neighbor_down",
                    chain.ospf_adj(peer_ospf, upif, "down"), "onset")
        for off in self._repeat_offsets(tpl, rng):
            self._chain(iid, t_ospf + off, core, "ospf_neighbor_down",
                        chain.ospf_adj(peer_ospf, upif, "down"), "repeat")

        # ── phase 3: a second core port flaps, seen from BOTH ends ────────
        cycles = rng.randint(*self.shape.flap_cycle_range())
        cycle_log: list[dict] = []
        tc = t_flap
        for c in range(cycles):
            role = "onset" if c == 0 else "flap"
            self._chain(iid, tc, core, "link_down", chain.link(flapif, "down"),
                        role, flapif)
            self._chain(iid, tc + 0.5, core, "lineproto_down",
                        chain.lineproto(flapif, "down"), role, flapif)
            self._chain(iid, tc + 1.0, core, "ospf_neighbor_down",
                        chain.ospf_adj(peer_dist, flapif, "down"), role)
            self._chain(iid, tc + 1.4, dist, "ospf_neighbor_down",
                        chain.ospf_adj(peer_core, flapif, "down"), role)
            up = tc + self._jit(rng, (4.0, 12.0))
            self._chain(iid, up, core, "link_up", chain.link(flapif, "up"),
                        "flap_up", flapif)
            self._chain(iid, up + 0.5, core, "lineproto_up",
                        chain.lineproto(flapif, "up"), "flap_up", flapif)
            self._chain(iid, up + 1.0, core, "ospf_neighbor_up",
                        chain.ospf_adj(peer_dist, flapif, "up"), "flap_up")
            self._chain(iid, up + 1.4, dist, "ospf_neighbor_up",
                        chain.ospf_adj(peer_core, flapif, "up"), "flap_up")
            cycle_log.append({"down_at": round(tc, 1),
                              "up_at": round(up + 1.4, 1)})
            tc = up + self._jit(rng, (6.0, 18.0))

        # ── phase 4: the transit session flaps Down → Up → Down ───────────
        self._chain(iid, t_bgp, core, "bgp_session_down",
                    chain.bgp_adj(peer_transit, "down"), "onset")
        for off in self._repeat_offsets(tpl, rng):
            self._chain(iid, t_bgp + off, core, "bgp_session_down",
                        chain.bgp_adj(peer_transit, "down"), "repeat")
        b_up = t_bgp + self._jit(rng, (8.0, 20.0))
        self._chain(iid, b_up, core, "bgp_session_up",
                    chain.bgp_adj(peer_transit, "up"), "flap_up")
        b_down2 = b_up + self._jit(rng, (6.0, 18.0))
        self._chain(iid, b_down2, core, "bgp_session_down",
                    chain.bgp_adj(peer_transit, "down"), "flap")

        # ── phase 5: route churn + the router-update burst ────────────────
        t_churn = max(b_down2 + 0.5,
                      t0 + self._jit(rng, chain.PHASE_BAND["route_churn"]))
        rate = rng.uniform(*self.shape.churn_eps_range())
        dur = rng.uniform(*self.shape.churn_duration_range())
        n_planned = max(1, round(rate * dur))
        # The throughput budget (see chain.CHURN_MAX_EVENTS_SCALE): the phase
        # keeps its RATE — the arrival shape the aggregation plane is measured
        # against — and stops early when the budget is spent. Both numbers ride
        # into the timeline, so a truncated churn phase is never silent.
        cap = int(self.shape.churn_max_events or 0)
        n_churn = min(n_planned, cap) if cap > 0 else n_planned
        step = 1.0 / rate
        dur_emitted = round(n_churn * step, 1)
        for k in range(n_churn):
            at = t_churn + k * step
            if k % 5 == 4:
                # the prefix count crossing its threshold as the table churns
                self._chain(iid, at, core, "bgp_maxprefix",
                            chain.bgp_maxpfx(peer_transit, 12000 + k * 7),
                            "churn")
            else:
                self._chain(iid, at, core, "bgp_route_churn",
                            chain.bgp_nbr_reset(peer_transit), "churn")
        burst_at = t_churn + dur_emitted * 0.55
        burst_n = max(3, round(rate * 3.0))
        for k in range(burst_n):
            self._chain(iid, burst_at + k * (3.0 / burst_n), core,
                        "bgp_router_update_burst",
                        chain.bgp_nbr_reset(peer_transit), "churn")
        self._chain(iid, burst_at + 3.0, core, "bgp_notification",
                    chain.bgp_notification(peer_transit), "churn")

        # ── phase 6: the access layer reconverges ─────────────────────────
        t_acc = max(t_churn + 0.5,
                    t0 + self._jit(rng, chain.PHASE_BAND["access_layer"]))
        order = list(access)
        rng.shuffle(order)
        n_stp = max(1, round(rng.uniform(*tpl["stp_share_range"])
                             * len(order)))
        n_mac = max(1, round(rng.uniform(*tpl["mac_share_range"])
                             * len(order)))
        stp_devs = order[:n_stp]
        mac_devs = order[:n_mac]
        stp_ifs: dict[str, str] = {}
        # The TCN floods the WHOLE STP domain — every switch in the site logs
        # it. That is both the physics and what keeps every scenario device
        # audible: a site device with no event at all would fail accounting's
        # per-device `corr_signals` coverage forty minutes later.
        for j, dev in enumerate(order):
            self._chain(iid, t_acc + 0.2 * j, dev, "stp_topology_change",
                        chain.stp_tcn(), "expansion")
        for j, dev in enumerate(stp_devs):
            pif = self._ifname(idx + 2 + j)
            stp_ifs[dev] = pif
            at = t_acc + 1.0 + 0.3 * j
            self._chain(iid, at, dev, "stp_port_block",
                        chain.stp_port(pif, "down"), "expansion", pif)
            for off in self._repeat_offsets(tpl, rng):
                self._chain(iid, at + off, dev, "stp_port_block",
                            chain.stp_port(pif, "down"), "repeat", pif)
        for j, dev in enumerate(mac_devs):
            pa, pb = self._ifname(idx + 2 + j), self._ifname(idx + 3 + j)
            # Unique per (site, device): the bare MAC is a GLOBAL entity token
            # by design, so a reused address would weld two sites into one
            # false correlation object.
            mac = chain.mac_address(idx * 4096 + j)
            at = t_acc + 2.0 + 0.3 * j
            self._chain(iid, at, dev, "mac_move",
                        chain.mac_flap(mac, vlan, pa, pb), "expansion")
            for off in self._repeat_offsets(tpl, rng):
                self._chain(iid, at + off, dev, "mac_move",
                            chain.mac_flap(mac, vlan, pa, pb), "repeat")

        # ── phase 7: recovery, or a hard outage ───────────────────────────
        hard = rng.random() < self.shape.no_recovery_share()
        last_fault = max((self.events[i].t
                          for i in range(first, len(self.events))), default=t0)
        recovery: float | None = None
        if not hard:
            drawn = t0 + self._jit(rng, chain.PHASE_BAND["recovery"])
            # Recovery is never allowed to precede a fault, whatever the draw.
            # The 20 s tail is the STP restore fan-out below: a recovery whose
            # own events fall outside the window would be ground truth naming
            # events the stream does not contain.
            rec = max(drawn, last_fault + 5.0)
            if rec < self.window_s - 20.0:
                recovery = round(rec, 1)
        if recovery is not None:
            self._chain(iid, recovery, core, "link_up", chain.link(upif, "up"),
                        "recovery", upif)
            self._chain(iid, recovery + 1.0, core, "lineproto_up",
                        chain.lineproto(upif, "up"), "recovery", upif)
            self._chain(iid, recovery + 2.0, core, "ospf_neighbor_up",
                        chain.ospf_adj(peer_ospf, upif, "up"), "recovery")
            self._chain(iid, recovery + 3.0, core, "bgp_session_up",
                        chain.bgp_adj(peer_transit, "up"), "recovery")
            for j, dev in enumerate(stp_devs):
                self._chain(iid, recovery + 4.0 + 0.3 * j, dev,
                            "stp_port_forward",
                            chain.stp_port(stp_ifs[dev], "up"), "recovery",
                            stp_ifs[dev])

        mine = self.events[first:]
        kinds = sorted({e.symptom for e in mine if e.symptom})
        timeline = [
            {"phase": "uplink_down", "at": round(t0, 1), "offset_s": 0.0},
            {"phase": "ospf_neighbor_down", "at": round(t_ospf, 1),
             "offset_s": round(t_ospf - t0, 1)},
            {"phase": "ospf_interface_flap", "at": round(t_flap, 1),
             "offset_s": round(t_flap - t0, 1), "cycles": cycle_log},
            {"phase": "bgp_session_flap", "at": round(t_bgp, 1),
             "offset_s": round(t_bgp - t0, 1),
             "transitions": [{"at": round(t_bgp, 1), "state": "down"},
                             {"at": round(b_up, 1), "state": "up"},
                             {"at": round(b_down2, 1), "state": "down"}]},
            {"phase": "route_churn", "at": round(t_churn, 1),
             "offset_s": round(t_churn - t0, 1),
             "rate_eps": round(rate, 2),
             "duration_planned_s": round(dur, 1),
             "duration_emitted_s": dur_emitted,
             "events_planned": n_planned + burst_n + 1,
             "events": n_churn + burst_n + 1,
             "truncated_by_throughput_budget": n_churn < n_planned,
             "update_burst_at": round(burst_at, 1),
             "update_burst_events": burst_n},
            {"phase": "access_layer", "at": round(t_acc, 1),
             "offset_s": round(t_acc - t0, 1),
             "tcn_devices": len(order), "stp_port_devices": n_stp,
             "mac_move_devices": n_mac},
        ]
        if recovery is not None:
            timeline.append({"phase": "recovery", "at": recovery,
                             "offset_s": round(recovery - t0, 1)})
        self._record(
            iid, tpl,
            {"entity_type": "interface", "device": core, "interface": upif,
             "entity_id": f"{core}:{upif}", "peer": peer_transit},
            t0, recovery, blast=devs,
            # The two devices that observed the CAUSE (the core its own port,
            # the distribution router the adjacency it lost). The access layer
            # observed CONSEQUENCES, which is a blast radius, not a vantage.
            vantages=[core, dist],
            symptom_kinds=kinds,
            blast_radius_waves=[
                {"at": round(t_flap, 1), "devices": [dist]},
                {"at": round(t_acc, 1), "devices": sorted(order)}],
            contradictions=[], flap_cycles=len(cycle_log),
            timeline=timeline,
            hard_outage=hard,
            site={"core": core, "distribution": dist,
                  "access_devices": len(access),
                  "stp_port_devices": sorted(stp_devs),
                  "mac_move_devices": sorted(mac_devs)},
            unpromotable_events=sum(1 for e in mine if not e.symptom),
            event_types=sorted({e.etype for e in mine if e.etype}))

    # -- measurement + ground truth -----------------------------------------
    def dynamics(self) -> dict:
        """The properties this profile exists to create, MEASURED on the plan.

        Every one of these is 0 on `t-nominal-2.5k` (P3_AGGREGATION_OPPORTUNITY
        §4) except the raw counts — which is why they are computed and written
        out rather than asserted in a comment.
        """
        # Only PROMOTED lines can form an identity: a line the classifier
        # drops (empty symptom) contributes no signal, so counting it as an
        # identity — or worse, as a state transition — would report dynamics
        # the engine cannot possibly observe. They get their own counter.
        by_identity: dict[tuple, list[ScenarioEvent]] = {}
        for e in self.events:
            if not e.symptom:
                continue
            by_identity.setdefault((e.entity, e.symptom), []).append(e)
        transitions = recoveries = repeats = 0
        repeating_identities = 0
        for evs in by_identity.values():
            prev_state = ""
            repeated_here = False
            for i, e in enumerate(evs):
                if prev_state and e.state != prev_state:
                    transitions += 1
                    if e.state == "up":
                        recoveries += 1
                prev_state = e.state
                if i and (e.t - evs[i - 1].t) <= SCENARIO_REPEAT_WINDOW_S:
                    repeats += 1
                    repeated_here = True
            if repeated_here:
                repeating_identities += 1
        observers: dict[str, set] = {}
        for inc in self.incidents:
            observers[inc["incident_id"]] = set(inc["vantages"])
        etypes: dict[str, int] = {}
        for e in self.events:
            if e.etype:
                etypes[e.etype] = etypes.get(e.etype, 0) + 1
        unpromotable = sum(1 for e in self.events if not e.symptom)
        return {
            "scenario_events": len(self.events),
            "incidents": len(self.incidents),
            "identities": len(by_identity),
            # Lines the classifier PROVABLY drops — the symptoms a real
            # enterprise outage emits and this engine cannot see. Named per
            # type in `parser_coverage`; a backlog item, not a harness bug.
            "unpromotable_events": unpromotable,
            "promoted_events": len(self.events) - unpromotable,
            "chain_events_by_type": dict(sorted(etypes.items())),
            "state_transitions": transitions,
            "recoveries": recoveries,
            "repeats_within_60s": repeats,
            "identities_repeating_within_60s": repeating_identities,
            "multi_vantage_incidents": sum(1 for v in observers.values()
                                           if len(v) >= 2),
            "max_vantages_on_one_cause": max((len(v) for v in observers.values()),
                                             default=0),
            "contradictions": sum(len(i.get("contradictions") or [])
                                  for i in self.incidents),
            "blast_radius_expansions": sum(
                max(0, len(i.get("blast_radius_waves") or []) - 1)
                for i in self.incidents),
            "incidents_with_recovery": sum(1 for i in self.incidents
                                           if i["recovery_ts"] is not None),
            "flap_cycles_total": sum(int(i.get("flap_cycles") or 0)
                                     for i in self.incidents),
            "scenario_devices": len(self.devices) - len(self.noise_pool),
            "noise_devices": len(self.noise_pool),
            # A scenario device the window truncated into silence would be a
            # guaranteed accounting FAIL 40 minutes later (`corr_signals covers
            # N/M burst devices`), because the background never speaks for it.
            # It cannot happen at the ratified 900 s window — every template's
            # onset window is bounded well inside it — so this is the sentinel
            # that says so out loud rather than an assumption.
            "silent_scenario_devices": len(self.silent_devices()),
            "max_events_in_one_chunk": max((len(b) for b in self.buckets),
                                           default=0),
            "events_per_s": round(len(self.events) / max(self.window_s, 1e-9), 3),
        }

    def observations(self) -> list:
        """The plan as `chain.Observation`s — the input to the step-0
        aggregation measurement.

        NO PARSER RUNS HERE, and none needs to: every scenario event already
        carries the kind, the entity and the state the REAL classifier derives
        for it (`chain.signal_kind` / `chain.entity_of`, pinned against
        `producers.syslog_control_signal` by
        `test_scenario_lines_classify_as_planned`). A line the parser drops
        carries an empty symptom and rides in as `promoted=False`, so it counts
        as raw mass and never as an identity, a transition or a recovery.
        """
        return [chain.Observation(t=e.t, device=e.device, entity_id=e.entity,
                                  kind=e.symptom, severity=e.severity,
                                  state=e.state, promoted=bool(e.symptom))
                for e in self.events]

    def measured(self, planned_total: int = 0) -> dict:
        """Owner memo §5/§6 metrics for the SCENARIO plane of this plan.

        Pure, offline, and cheap enough to run at plan time: the harness
        writes the numbers into ground truth beside the shape that asked for
        them, so "what did this workload actually contain" is answered before
        a single event reaches the bus.
        """
        raw = int(planned_total) if planned_total else len(self.events)
        return chain.measure_stream(self.observations(), self.window_s,
                                    raw_events=raw)

    def chunk_load(self) -> dict:
        """How the scenario's mass is spread over the ratified chunk plan.

        A storm that is 50 % of the fleet but lands in six chunks is not a
        storm, it is a spike: the background could not be injected, the noise
        devices would go silent and accounting would fail. `peak_over_mean` is
        the number that says which one this is.
        """
        occ = [len(b) for b in self.buckets]
        carrying = [n for n in occ if n]
        mean = sum(occ) / max(1, len(occ))
        return {
            "chunks": len(occ),
            "chunks_carrying_scenario": len(carrying),
            "peak": max(occ, default=0),
            "mean": round(mean, 2),
            "peak_over_mean": round(max(occ, default=0) / max(mean, 1e-9), 3),
        }

    def silent_devices(self) -> list[str]:
        """Scenario devices the window left with no event at all."""
        spoke = {e.device for e in self.events}
        return sorted(set(self.devices) - set(self.noise_pool) - spoke)

    def cause_entities(self) -> set:
        """Every token that identifies a cause: entity ids, cause devices and
        peer addresses. The noise-disjointness check is stated against this."""
        out: set = set()
        for inc in self.incidents:
            ce = inc["cause_entity"]
            for key in ("entity_id", "device", "peer"):
                if ce.get(key):
                    out.add(str(ce[key]))
        return out

    def digest(self) -> str:
        """SHA-256 over the canonical plan. Two runs of one seed on one device
        list must print the same 64 hex characters, or the scenario is not
        deterministic and no A/B built on it means anything."""
        blob = json.dumps({"incidents": self.incidents,
                           "events": [list(e) for e in self.events]},
                          sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()

    def shape_record(self, planned_total: int = 0) -> dict:
        """What this workload was ASKED for, and what it actually contains.

        TARGET is the declared `chain.StormShape` — every knob, plus its
        content digest, so two runs can be compared on the shape they meant to
        have rather than on prose. ACHIEVED is the owner memo §5/§6 metric set
        MEASURED on the plan (`measured()`), plus the storm share that came
        out and the chunk spread it came out with. A rung whose achieved share
        drifts from its target is a mis-sized scenario, and it is visible here
        before the run rather than inferred from the completion number
        afterwards.
        """
        achieved = self.measured(planned_total)
        share = (len(self.events) / planned_total) if planned_total > 0 else 0.0
        target = float(self.shape.storm_share_of_raw)
        achieved["storm_share_of_raw"] = round(share, 6)
        achieved["storm_share_error_pct"] = (
            round(100.0 * (share - target) / target, 3) if target > 0 else 0.0)
        achieved["incidents"] = len(self.incidents)
        achieved["allocation_rounds"] = self.rounds_built
        achieved["scenario_devices"] = len(self.devices) - len(self.noise_pool)
        achieved["noise_devices"] = len(self.noise_pool)
        achieved["incidents_with_recovery"] = sum(
            1 for i in self.incidents if i["recovery_ts"] is not None)
        achieved["recovery_ratio"] = round(
            achieved["incidents_with_recovery"] / max(1, len(self.incidents)), 4)
        achieved["chunk_load"] = self.chunk_load()
        # `promotion_pct` above is scenario signals over the WHOLE raw fleet
        # plan (background included); this is the scenario plane's own rate.
        achieved["scenario_events"] = len(self.events)
        achieved["scenario_promotion_pct"] = round(
            100.0 * achieved["signals"] / max(1, len(self.events)), 4)
        # VANTAGES. `vantages_per_identity` above is 1 by construction and
        # says so honestly: the classifier stamps every signal's observer as
        # the EMITTING DEVICE, so two vantages on one `entity_id` is not
        # expressible in a syslog-only harness. What IS expressible — and what
        # the engine welds on — is several devices independently observing one
        # CAUSE through a shared token, which is this:
        counts_v = [len(i["vantages"]) for i in self.incidents] or [0]
        achieved["vantages_per_cause"] = {
            "mean": round(sum(counts_v) / len(counts_v), 3),
            "max": max(counts_v),
            "multi_vantage_incidents": sum(1 for v in counts_v if v >= 2),
        }
        # THE WHOLE STREAM, not just the scenario plane. The background is the
        # `production` mix, whose promotion rate and (zero) bucket-key
        # collapse are MEASURED constants — see PRODUCTION_MIX_PROMOTION_PCT.
        # This is the number that decides P3: how many signals reach the
        # engine today, and how many would with an ideal 60 s aggregation key.
        bg_raw = max(0, int(planned_total) - len(self.events))
        bg_sig = round(bg_raw * PRODUCTION_MIX_PROMOTION_PCT / 100.0)
        bg_agg = round(bg_sig * (1.0 - PRODUCTION_MIX_K3_REDUCTION_PCT / 100.0))
        total_today = achieved["signals"] + bg_sig
        total_agg = achieved["projection"]["signals_with_K3_aggregation"] + bg_agg
        achieved["stream_projection"] = {
            "raw_events": int(planned_total),
            "background_raw": bg_raw,
            "background_signals": bg_sig,
            "background_promotion_pct": PRODUCTION_MIX_PROMOTION_PCT,
            "background_signals_with_K3_aggregation": bg_agg,
            "scenario_signals": achieved["signals"],
            "signals_today": total_today,
            "signals_with_K3_aggregation": total_agg,
            "signals_removed": total_today - total_agg,
            "reduction_pct": round(
                100.0 * (total_today - total_agg) / max(1, total_today), 3),
            "raw_to_engine_ratio_today": round(
                int(planned_total) / max(1, total_today), 3),
            "raw_to_engine_ratio_aggregated": round(
                int(planned_total) / max(1, total_agg), 3),
        }
        return {
            "target": self.shape.as_dict(),
            "target_digest": self.shape.digest(),
            "achieved": achieved,
            "note": (
                "TARGET is the declared StormShape; ACHIEVED is owner-memo "
                "§5/§6 measured on the PLAN (scenario plane only — the "
                "background is the production mix, whose promotion rate and "
                "zero-repeat structure are measured in "
                "docs/scale/P3_AGGREGATION_OPPORTUNITY_2026-08-29.md). "
                "`projection.signals_with_K3_aggregation` is the ideal "
                "60 s-bucket collapse WITH every state transition and "
                "recovery still forwarded synchronously (memo §17) — an "
                "upper bound on what an Aggregation Plane can remove."),
        }

    def ground_truth(self, planned_total: int = 0) -> dict:
        counts = self.dynamics()
        if planned_total > 0:
            counts["scenario_event_share_of_plan"] = round(
                len(self.events) / planned_total, 6)
        return {
            "schema": GROUND_TRUTH_SCHEMA,
            "profile": self.profile,
            "scenario": self.spec["name"],
            "description": self.spec["description"],
            "seed": self.seed,
            "runid": self.runid,
            "window_s": self.window_s,
            "chunk_secs": self.chunk_secs,
            "planned_total_events": planned_total,
            "digest": self.digest(),
            "devices": {
                "total": len(self.devices),
                "scenario": len(self.devices) - len(self.noise_pool),
                "noise_pool": len(self.noise_pool),
                "budget_share": self.shape.device_budget,
                "allocation_rounds": self.rounds_built,
            },
            "templates": self.template_counts,
            # WHAT THIS WORKLOAD WAS ASKED FOR, AND WHAT IT CONTAINS (P3).
            "shape": self.shape_record(planned_total),
            "counts": counts,
            # WHAT THE ENGINE COULD SEE. Per requested outage symptom: does
            # `producers.syslog_control_signal` promote the vendor-standard
            # line this scenario emits for it? A scorer MUST read this before
            # charging the engine with a miss — a `not_promoted` symptom is a
            # product backlog item, and the run's TTUR/T4 numbers can only be
            # about the symptoms marked `promoted`.
            "parser_coverage": chain.parser_coverage(),
            "parser_coverage_detail": chain.parser_coverage_detail(),
            "not_promoted": list(chain.not_promoted_types()),
            "phase_timeline": [
                {"phase": name, "offset_band_s": list(band)}
                for name, band in chain.PHASE_BANDS],
            "incidents": self.incidents,
            "contract": (
                "Scoring contract: scripts/scale-rca-latency.py, section "
                "'GROUND TRUTH (t-storm profiles)'. Match a persisted incident "
                "to a ground-truth incident by cause entity + onset; "
                "expected_owner_class / expected_seam_class are scenario "
                "labels, informational until the harness provisions seams. "
                "The SAME incidents are also written in the network digital "
                "twin's record shape to ground_truth.jsonl (+ state.json), so "
                "`scripts/lab/twin/twin.py score --runid <id> --run-root "
                "data/miniladder` scores this run with no second scorer."),
        }

    # ── the twin's record shape ────────────────────────────────────────────
    #
    # THE CONVERGENCE. `scripts/lab/twin/scorer.py` already joins labels
    # against the engine's `corr_objects` and emits an accuracy report. It
    # reads a `ground_truth.jsonl` of per-story records and a `state.json` for
    # {runid, prefix, device_tenants}. Everything it needs, this scenario has —
    # the ONE mismatch is that the twin prefixes device names from
    # `state["prefix"]` because its scenario files name devices abstractly,
    # while the mini-ladder's ids are already fully qualified. That is closed
    # by writing `prefix: ""`, not by changing either schema.
    #
    # The two ground truths are therefore NOT rival schemas: `ground-truth.json`
    # stays the mini-ladder's own contract (per-run, plan-level, digest,
    # dynamics, chunk accounting — none of which the twin models), and
    # `ground_truth.jsonl` is the SAME incidents projected into the twin's
    # per-story record so its scorer runs unchanged. Everything the twin's
    # record has no place for rides in `labels`, which the scorer ignores.
    def twin_records(self) -> list[dict]:
        """Every incident as one `ground_truth.jsonl` record (twin shape)."""
        out: list[dict] = []
        for inc in self.incidents:
            ce = inc["cause_entity"]
            devices = list(inc["blast_radius"])
            out.append({
                "story_id": inc["incident_id"],
                "template": inc["cause_kind"],
                "t0_offset_s": inc["onset_ts"],
                # The mini-ladder plans an incident; it does not "fire" it at a
                # wall-clock instant (the chunk clock does). Null, not a lie.
                "fired_at": None,
                "affected": {"devices": devices, "tenants": []},
                "entities": devices,
                "extra_entities": [str(ce["peer"])] if ce.get("peer") else [],
                # Only clauses this workload can honestly be held to: the lab
                # provisions no seams, so no seam/owner clause is asserted (see
                # expected_*_class in `labels`, informational until it does).
                "expect": {"rca": {
                    "verdict_tier_at_least": "suspected",
                    "affected_includes": [str(ce["device"])],
                }},
                "labels": {
                    "source": "scale-miniladder",
                    "scenario": self.spec["name"],
                    "seed": self.seed,
                    "cause_entity": ce,
                    "onset_offset_s": inc["onset_ts"],
                    "recovery_offset_s": inc["recovery_ts"],
                    "blast_radius": devices,
                    "vantages": inc["vantages"],
                    "symptom_kinds": inc["symptom_kinds"],
                    "expected_owner_class": inc["expected_owner_class"],
                    "expected_seam_class": inc["expected_seam_class"],
                    "timeline": inc.get("timeline") or [],
                    "hard_outage": inc.get("hard_outage"),
                    "parser_coverage": chain.parser_coverage(),
                },
            })
        return out

    def twin_state(self) -> dict:
        """The minimal `state.json` `twin.py score` reads. `prefix` is empty
        because mini-ladder device ids are already fully qualified; an empty
        `device_tenants` is honest — this harness onboards one tenant, so no
        cross-tenant-merge clause can be asserted, and none is."""
        return {"runid": self.runid, "prefix": "", "device_tenants": {},
                "source": "scale-miniladder", "scenario": self.spec["name"]}




# ---------------------------------------------------------------------------
# Interrupt discipline and residue purge
#
# THE DEFECT THIS SECTION EXISTS FOR (2026-08-28, run p1-on-08281911). The run
# was signalled after the drain phase. The console printed
#
#     WARNING: interrupted — running cleanup before exit
#     [FAIL] interrupted — run interrupted by signal
#
# ...and then NOTHING: no cleanup verdict, no report.json, and all 2,500
# `mlx-08281911zaz6-*` devices still standing in the device store. Three code
# facts produced that outcome, and each is fixed here:
#
#   1. A SECOND signal during cleanup killed the purge. SIGINT raises
#      KeyboardInterrupt, and the old SIGTERM handler raised it too — from ANY
#      point, including the middle of cleanup. `except Exception` around the
#      cleanup call cannot catch it (KeyboardInterrupt is a BaseException), so
#      it unwound straight out of execute(), skipping both the rest of the
#      purge and report(). SIGHUP was not handled at all: a closing terminal
#      killed the process outright.
#   2. Cleanup was SILENT for up to ~900 s before the first DELETE was even
#      issued (a bounded drain wait, then the deletes, then a 600 s pre-purge
#      wait), so that window looked exactly like a hang — and got signalled.
#   3. The purge deleted only the ids the run happened to hold in memory and
#      verified ONCE. A partial pass left residue nobody re-attempted.
#
# So: cleanup owns its signals, announces every step with counts, deletes by
# LISTED PREFIX (page-loop) and re-verifies to zero (F-69: never trust a 204).
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# CROSS-RUN COLLISION (2026-08-29; manual run mlx-08290322msp1 vs cron run
# mlx-08290317j7hy, both on the same 198.18/15 addresses)
#
# A cron ladder (1,000 devices) and a manual 2,500-device run overlapped. The
# API's cross-source dedupe absorbed 1,000 of the manual run's creates into the
# cron run's devices — POST /api/devices answers 200 with the CANONICAL id
# (src/backend/main.go handleDevices) — but the absorbed record is STILL
# PERSISTED under the id the caller asked for: `discovery.Upsert` stores by id
# and only the READ projection (`Devices()` -> dedupeWithOwners) collapses the
# pair. So the manual run's 1,000 shadow rows were invisible in /api/devices
# for as long as the cron rows existed. BOTH runs then verified "0 remain"
# truthfully against their OWN prefix, and the moment the cron run's devices
# were deleted the manual run's shadow rows surfaced — with no process left
# that knew about them. The next run's onboard collided with exactly those
# 1,000 devices, and its preflight had passed with them standing.
#
# Three guards, all in this file:
#   1. preflight REFUSES to start while any `mlx-` device of ANY run id exists,
#      naming the count, the top run ids and the exact --cleanup-only command
#      (override: MLX_ALLOW_FOREIGN_RESIDUE=1, logged loudly).
#   2. A RUN LOCK (pid + run id) makes two concurrent harness processes
#      impossible: a live holder refuses the start, a dead one is reclaimed.
#      That kills the cron-collision class at the source.
#   3. cleanup purges its own prefix SEEDED WITH THE ABSORBED SHADOW IDS (the
#      rows a prefix LIST cannot see), then the absorbed canonical ids, then
#      sweeps the whole `mlx-` namespace — safe precisely because the lock
#      proves no other run owns anything in it — and verifies the NAMESPACE to
#      zero. "0 remain" may never be printed while any mlx- device stands.
# ---------------------------------------------------------------------------


class RunLock:
    """Single-writer lock over the harness's device namespace.

    Two harness processes against one stack corrupt each other's evidence and
    each other's teardown (2026-08-29). The lock is a file holding this
    process's pid and run id; ownership is decided by PID LIVENESS, not by the
    file's existence, so a killed run cannot block the lab forever.
    """

    def __init__(self, path: str = "", runid: str = "") -> None:
        self.path = path or RUN_LOCK_PATH
        self.runid = runid
        self.held = False
        self.holder: dict = {}

    @staticmethod
    def pid_alive(pid: int) -> bool:
        """True unless the pid is provably gone. An UNKNOWN answer reads as
        ALIVE: refusing a run costs minutes, stealing a live run's lock costs
        the run (16.1 — the error is reported, never assumed harmless)."""
        if pid <= 0:
            return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True                  # live process owned by another user
        except OSError as exc:           # pragma: no cover - platform
            warn(f"run lock: could not probe pid {pid} ({exc}) — treating it "
                 f"as ALIVE and refusing rather than stealing the lock")
            return True
        return True

    def _read(self) -> dict:
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            # Never silent: a corrupt lock is a real condition, and it names no
            # owner we can defer to, so it is reclaimable — loudly.
            warn(f"run lock: {self.path} is unreadable ({exc}) — it names no "
                 f"live owner, so it will be treated as stale")
            return {"unreadable": str(exc)}
        return data if isinstance(data, dict) else {"unreadable": "not an object"}

    @staticmethod
    def _holder_pid(holder: dict) -> int:
        try:
            return int(holder.get("pid", 0))
        except (TypeError, ValueError):
            return 0

    def _stamp(self, fd: int) -> None:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"pid": os.getpid(), "runid": self.runid,
                       "started": utcnow(),
                       "argv": " ".join(sys.argv[1:])[:400]}, f)
            f.write("\n")

    def acquire(self) -> tuple[bool, str]:
        """(held, message). The message is ALWAYS printable — a refusal names
        the holder and what to do about it."""
        parent = os.path.dirname(self.path)
        if parent:
            try:
                os.makedirs(parent, exist_ok=True)
            except OSError as exc:
                return False, (f"run lock: cannot create {parent} ({exc}) — "
                               f"refusing to run unlocked; set MLX_RUN_LOCK to "
                               f"a writable path")
        for attempt in (1, 2):
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            except FileExistsError:
                holder = self._read()
                self.holder = holder
                pid = self._holder_pid(holder)
                who = (f"pid {pid or 'unknown'} run "
                       f"{holder.get('runid') or 'unknown'} started "
                       f"{holder.get('started') or 'unknown'}")
                if pid and self.pid_alive(pid):
                    return False, (
                        f"another scale-miniladder process holds {self.path} "
                        f"({who}). Two runs on one stack absorb each other's "
                        f"devices into one another and blind both teardowns "
                        f"(2026-08-29 cron collision) — wait for it to finish, "
                        f"or kill pid {pid} and re-run.")
                if attempt == 1:
                    warn(f"run lock: STALE lock at {self.path} ({who} is not "
                         f"running) — reclaiming it")
                    try:
                        os.unlink(self.path)
                    except FileNotFoundError:
                        # Benign race, still SAID: another process reclaimed
                        # the same stale lock a moment before we did.
                        log(f"run lock: {self.path} was already reclaimed by "
                            f"another process — retrying the create")
                    except OSError as exc:
                        return False, (f"run lock: stale lock {self.path} could "
                                       f"not be removed ({exc})")
                    continue
                return False, (f"run lock: {self.path} was taken by another "
                               f"process while a stale lock was being reclaimed "
                               f"— refusing to race it")
            except OSError as exc:
                return False, f"run lock: cannot create {self.path} ({exc})"
            else:
                try:
                    self._stamp(fd)
                except OSError as exc:
                    try:
                        os.unlink(self.path)
                    except OSError as rm_exc:
                        warn(f"run lock: could not remove the half-written lock "
                             f"{self.path} ({rm_exc})")
                    return False, (f"run lock: could not stamp {self.path} "
                                   f"({exc})")
                self.held = True
                return True, (f"run lock: acquired {self.path} "
                              f"(pid {os.getpid()}, run {self.runid or 'n/a'})")
        return False, f"run lock: could not acquire {self.path}"   # pragma: no cover

    def release(self) -> None:
        """Release on EVERY exit path (including interrupt/abort). A failure to
        release is reported, not swallowed — the next run reclaims it as stale
        because this pid will be gone."""
        if not self.held:
            return
        self.held = False
        holder = self._read()
        pid = self._holder_pid(holder)
        if pid and pid != os.getpid():
            warn(f"run lock: {self.path} now names pid {pid}, not this process "
                 f"({os.getpid()}) — leaving it alone")
            return
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            warn(f"run lock: {self.path} was already gone at release")
        except OSError as exc:
            warn(f"run lock: could not release {self.path} ({exc}) — the next "
                 f"run will reclaim it as stale")


class CleanupAborted(Exception):
    """The operator insisted (Nth signal) while cleanup was running.

    Deliberate, never silent: the caller names the residue it is leaving and
    the exact command that finishes the job.
    """


class InterruptGuard:
    """Signal policy for a run whose teardown deletes thousands of devices.

    Before cleanup a signal unwinds the run INTO cleanup (KeyboardInterrupt).
    During cleanup signals are IGNORED with a message, because the alternative
    is exactly the 2026-08-28 residue defect — until `abort_after` of them,
    which is the operator plainly saying "leave it"; that aborts loudly.
    """

    def __init__(self, abort_after: int = CLEANUP_ABORT_AFTER_SIGNALS) -> None:
        self.abort_after = max(1, abort_after)
        self.signals_seen = 0
        self.cleanup_signals = 0
        self.in_cleanup = False
        self.installed: list[str] = []

    def install(self) -> None:
        """Own SIGINT/SIGTERM/SIGHUP. An uninstallable handler is REPORTED
        (16.1), never assumed harmless — it means residue on interrupt."""
        for signame in ("SIGINT", "SIGTERM", "SIGHUP"):
            sig = getattr(signal, signame, None)
            if sig is None:
                continue
            try:
                signal.signal(sig, self.handle)
            except (ValueError, RuntimeError) as exc:
                # ValueError = not the main thread / signal unknown to this
                # platform: the other handlers still install, so report by
                # name and carry on. An OSError here is a kernel-level refusal
                # and is deliberately NOT caught — it raises before any device
                # exists, which is the safe failure (16.1: never continue past
                # an error we cannot characterize).
                warn(f"could not install a {signame} handler ({exc}) — that "
                     f"signal will kill this run WITHOUT cleanup, leaving "
                     f"device residue")
                continue
            self.installed.append(signame)

    def handle(self, signum: int, _frame: object) -> None:
        try:
            name = signal.Signals(signum).name
        except ValueError:                       # pragma: no cover - platform
            name = f"signal {signum}"
        self.signals_seen += 1
        if not self.in_cleanup:
            warn(f"{name} received — unwinding into CLEANUP. This run's "
                 f"devices are still in the stack; let cleanup finish.")
            raise KeyboardInterrupt(name)
        self.cleanup_signals += 1
        if self.cleanup_signals >= self.abort_after:
            warn(f"{name} #{self.cleanup_signals} during cleanup — ABORTING "
                 f"cleanup as instructed")
            raise CleanupAborted(name)
        left = self.abort_after - self.cleanup_signals
        warn(f"{name} IGNORED — cleanup is running (deleting this run's devices "
             f"and purging its telemetry). Send it {left} more time(s) to abort "
             f"and LEAVE RESIDUE behind.")

    def enter_cleanup(self) -> None:
        self.in_cleanup = True
        self.cleanup_signals = 0

    def leave_cleanup(self) -> None:
        self.in_cleanup = False


def cleanup_step(name: str, problems: list[str],
                 fn: typing.Callable[..., typing.Any], *args: object,
                 default: typing.Any = None, **kwargs: object) -> typing.Any:
    """Run ONE teardown step so that its final failure is loud but not fatal.

    Cleanup is a sequence of independent steps — devices, then ClickHouse, then
    OpenSearch — and each one is worth attempting whatever happened to the
    previous. On 2026-08-29 the first of them raised a `TimeoutError` from the
    API client and took the whole teardown with it: no ClickHouse purge, no
    OpenSearch purge, no re-verify, and a final line reading
    `RESIDUE LEFT: UNKNOWN (never verified)`.

    A step that fails here is RECORDED in `problems` and warned by name (16.1
    — this is reporting, not `|| true`), the caller's phase goes FAIL on it,
    and the next step still runs. `CleanupAborted` and `KeyboardInterrupt` are
    the operator talking and always propagate.
    """
    try:
        return fn(*args, **kwargs)
    except (CleanupAborted, KeyboardInterrupt):
        raise
    except Exception as exc:  # noqa: BLE001 — recorded as a problem, never hidden
        problems.append(
            f"teardown step {name!r} FAILED after its retries ({exc!r}) — the "
            f"remaining steps still ran; residue below is the RE-VERIFIED count")
        warn(f"cleanup: step {name!r} raised {exc!r} — recorded as a problem; "
             f"continuing with the next step")
        return default


def empty_purge_ev(prefix: str = "", budget_s: float = 0.0,
                   list_error: str = "") -> dict:
    """The purge evidence skeleton — also what a purge STEP that raised leaves
    behind, so a failed step reads as "nothing verified" rather than KeyErrors
    in the report."""
    return {"prefix": prefix, "budget_s": budget_s, "passes": 0,
            "deleted": 0, "delete_failed": 0, "first_delete_error": "",
            "list_error": list_error, "remaining": -1, "verified_zero": False,
            "out_of_budget": False}


def devices_with_prefix(stack: Stack, prefix: str,
                        page_limit: int = DEVICE_PAGE_LIMIT,
                        max_pages: int = DEVICE_PAGE_MAX_PAGES,
                        ) -> tuple[list[str], str]:
    """Every device id starting with `prefix`, following the endpoint's OWN
    page size. Returns (ids, error) — error non-empty means the answer is
    INCOMPLETE and must never be read as "nothing left" (F-69).

    /api/devices caps a page (2,500 observed against a 5,000 ask), so paging
    advances by the rows that came BACK, not by the limit that was requested,
    and only stops when the envelope says the page covered the fleet.
    """
    seen: dict[str, None] = {}
    offset, pages = 0, 0
    while True:
        st, resp = stack.api(
            "GET", f"/api/devices?envelope=1&limit={page_limit}&offset={offset}")
        if st != 200 or not isinstance(resp, dict):
            return list(seen), (f"device list failed at offset {offset}: "
                                f"HTTP {st} {str(resp)[:120]}")
        rows = resp.get("devices")
        if not isinstance(rows, list):
            return list(seen), (f"device list at offset {offset} has no "
                                f"`devices` array (envelope contract changed?)")
        for d in rows:
            did = str(d.get("id", "")) if isinstance(d, dict) else ""
            if did.startswith(prefix):
                seen[did] = None
        pages += 1
        offset += len(rows)
        if not rows:
            return list(seen), ""
        total = resp.get("total")
        if isinstance(total, int) and offset >= total:
            return list(seen), ""
        if resp.get("complete") is True and not isinstance(total, int):
            return list(seen), ""
        if pages >= max_pages:
            return list(seen), (f"device list did not terminate after "
                                f"{max_pages} pages ({offset} rows read) — "
                                f"paging contract broken; residue unknown")


def run_id_of(device_id: str) -> str:
    """The run id embedded in an `mlx-<runid>-NNNNN` device id ("" if the id is
    not in the harness namespace). Residue is only actionable when the operator
    can see WHICH run left it."""
    if not device_id.startswith(DEVICE_PREFIX_ROOT):
        return ""
    return device_id[len(DEVICE_PREFIX_ROOT):].split("-", 1)[0]


def residue_by_run(ids: typing.Iterable[str]) -> list[tuple[str, int]]:
    """[(run_id, count)] worst-first — the shape a refusal message needs."""
    counts: dict[str, int] = {}
    for did in ids:
        rid = run_id_of(did) or "unknown"
        counts[rid] = counts.get(rid, 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


def residue_summary(ids: typing.Iterable[str],
                    top: int = RESIDUE_RUN_IDS_SHOWN) -> str:
    """"1000 device(s) from 1 run id(s): 08290317j7hy=1000"."""
    ids = list(ids)
    by_run = residue_by_run(ids)
    shown = ", ".join(f"{rid}={n}" for rid, n in by_run[:top])
    more = (f" (+{len(by_run) - top} more run id(s))"
            if len(by_run) > top else "")
    return (f"{len(ids)} device(s) from {len(by_run)} run id(s): "
            f"{shown}{more}")


def foreign_residue(stack: Stack, own_prefix: str) -> tuple[list[str], str]:
    """Every `mlx-` device that is NOT this run's, plus a list error.

    An error means the answer is INCOMPLETE and must never be read as "the
    namespace is clean" (same F-69 rule the prefix pager follows).
    """
    ids, err = devices_with_prefix(stack, DEVICE_PREFIX_ROOT)
    return sorted(d for d in ids if not d.startswith(own_prefix)), err


def delete_devices(stack: Stack, ids: list[str], deadline: float,
                   ) -> tuple[int, list[str], bool]:
    """DELETE each id. 404 counts as gone. Returns (deleted, failures,
    out_of_budget); failures are STRINGS the caller must print (16.1)."""
    deleted, failures = 0, []
    for i, did in enumerate(ids, 1):
        if time.monotonic() >= deadline:
            return deleted, failures, True
        st, resp = stack.api("DELETE", f"/api/devices/{did}")
        if st in (200, 202, 204, 404):
            deleted += 1
        else:
            failures.append(f"{did}: HTTP {st} {str(resp)[:80]}")
        if PURGE_PROGRESS_EVERY > 0 and i % PURGE_PROGRESS_EVERY == 0:
            log(f"cleanup: deleted {i}/{len(ids)} devices "
                f"({len(failures)} failures so far)")
    return deleted, failures, False


def purge_devices(stack: Stack, prefix: str, budget_s: float,
                  seed_ids: typing.Sequence[str] = (),
                  max_passes: int = DEVICE_PURGE_MAX_PASSES) -> dict:
    """Delete every device under `prefix` and RE-VERIFY to zero.

    Idempotent and re-entrant: each pass LISTS what is actually there, deletes
    it, then lists again. `verified_zero` is only true when a successful list
    came back empty — a 204 is not evidence (F-69), and a list that errored is
    not evidence of absence either.
    """
    t0 = time.monotonic()
    deadline = t0 + max(1.0, budget_s)
    ev: dict = empty_purge_ev(prefix, budget_s)
    targets = list(dict.fromkeys(str(i) for i in seed_ids))
    # A stack that cannot answer at all (the preflight-refusal case: nothing was
    # ever created) must not burn the whole budget retrying. Once we have seen
    # real devices, transient list failures are worth retrying for longer.
    saw_devices = bool(targets)
    list_failures_in_a_row = 0
    while True:
        ev["passes"] += 1
        if targets:
            log(f"cleanup: purge pass {ev['passes']} — deleting "
                f"{len(targets)} devices matching {prefix}")
            deleted, failures, out = delete_devices(stack, targets, deadline)
            ev["deleted"] += deleted
            ev["delete_failed"] += len(failures)
            if failures:
                if not ev["first_delete_error"]:
                    ev["first_delete_error"] = failures[0]
                warn(f"{len(failures)} device deletes FAILED on pass "
                     f"{ev['passes']} (first: {failures[0]})")
            if out:
                ev["out_of_budget"] = True
        # RE-VERIFY by listing. Never trust the delete responses (F-69).
        found, err = devices_with_prefix(stack, prefix)
        ev["list_error"] = err
        if err:
            list_failures_in_a_row += 1
            warn(f"cleanup: device re-verify list failed "
                 f"({list_failures_in_a_row}x) — {err}")
            allowed = max_passes if saw_devices else 3
            if list_failures_in_a_row >= allowed:
                warn(f"cleanup: device list unreadable {list_failures_in_a_row} "
                     f"times in a row — giving up; residue under {prefix} is "
                     f"UNKNOWN, not zero")
                return ev
        else:
            list_failures_in_a_row = 0
            saw_devices = saw_devices or bool(found)
            ev["remaining"] = len(found)
            log(f"cleanup: {len(found)} devices matching {prefix} remain "
                f"after pass {ev['passes']}")
            if not found:
                ev["verified_zero"] = True
                return ev
        if ev["out_of_budget"] or time.monotonic() >= deadline:
            ev["out_of_budget"] = True
            warn(f"cleanup: device purge ran out of its {budget_s:.0f}s budget "
                 f"after {ev['passes']} pass(es) — residue is NOT purged")
            return ev
        if ev["passes"] >= max_passes:
            warn(f"cleanup: device purge gave up after {max_passes} passes — "
                 f"residue is NOT purged")
            return ev
        if err:
            # Transient list failure: retry inside the budget rather than
            # declaring a clean stack we could not see.
            targets = []
            time.sleep(min(5.0, max(0.0, deadline - time.monotonic())))
        else:
            targets = found


def purge_telemetry(stack: Stack, prefix: str) -> tuple[dict, list[str]]:
    """ClickHouse corr_signals + OpenSearch syslog rows for `prefix`, verified.
    Returns (evidence, problems) — problems are printed by the caller."""
    ev: dict = {"ch_signals_left": -1}
    problems: list[str] = []

    # CH and OS are INDEPENDENT steps: a ClickHouse purge that dies must not
    # cost the OpenSearch one (2026-08-29 — one transient failure took the
    # whole teardown). Each is wrapped, each failure is recorded.
    def clickhouse_step() -> None:
        ok, out = stack.ch_mutation(
            f"ALTER TABLE netops.corr_signals DELETE WHERE entity_id LIKE '%{prefix}%'")
        if not ok:
            problems.append(f"ClickHouse corr_signals purge failed: {out}")
        okc, cnt = stack.ch(
            f"SELECT count() FROM netops.corr_signals WHERE entity_id LIKE '%{prefix}%'")
        ev["ch_signals_left"] = int(cnt) if okc and cnt.isdigit() else -1
        if not okc:
            problems.append(f"ClickHouse corr_signals re-count failed: {cnt}")
        elif ev["ch_signals_left"] != 0:
            problems.append(f"{ev['ch_signals_left']} run rows left in corr_signals")

    cleanup_step("clickhouse corr_signals purge", problems, clickhouse_step)
    os_ev, os_problems = cleanup_step(
        "opensearch syslog purge", problems, os_purge_syslog, stack, prefix,
        default=({"os_task": "", "os_deleted": -1, "os_docs_left": -1}, []))
    ev.update(os_ev)
    problems.extend(os_problems)
    return ev, problems


def os_purge_syslog(stack: Stack, prefix: str, budget_s: float | None = None,
                    poll_s: float = OS_PURGE_POLL_S) -> tuple[dict, list[str]]:
    """Delete every `netops-syslog-*` doc whose hostname carries `prefix`, and
    verify to zero by COUNTING.

    Submitted async: at lab scale (10.3 M docs) a synchronous delete outlives
    every HTTP bound. Progress is the count itself — `svc_bootstrap` cannot
    read `_tasks` (and is not being given that permission for a lab teardown),
    so the task id is carried only so a failure can name what is still running
    server-side.
    """
    ev: dict = {"os_task": "", "os_deleted": -1, "os_docs_left": -1}
    problems: list[str] = []
    before = stack.os_count(OS_SYSLOG_INDEX, "hostname.keyword", prefix)
    ev["os_docs_before"] = before
    if before == 0:
        ev["os_docs_left"] = 0
        ev["os_deleted"] = 0
        log(f"cleanup: no {OS_SYSLOG_INDEX} docs match {prefix} — nothing to purge")
        return ev, problems
    if before < 0:
        # A blind pre-count must NOT stop the purge — residue has to go either
        # way — but it is reported, and the budget falls back to the base.
        problems.append(
            f"OpenSearch pre-count for {prefix} failed — purge runs blind, "
            f"progress and ETA are unavailable")
    if budget_s is None:
        budget_s = min(OS_PURGE_BUDGET_MAX_S,
                       OS_PURGE_BUDGET_BASE_S +
                       max(before, 0) * OS_PURGE_SECONDS_PER_DOC)

    ok, res = stack.os_req(
        "OS_BOOTSTRAP_PASSWORD", "svc_bootstrap",
        f"/{OS_SYSLOG_INDEX}/_delete_by_query"
        f"?wait_for_completion=false&conflicts=proceed&slices=auto",
        {"query": {"prefix": {"hostname.keyword": prefix}}},
        timeout=OS_PURGE_SUBMIT_TIMEOUT_S)
    task = str(res.get("task", "")) if ok and isinstance(res, dict) else ""
    ev["os_task"] = task
    if not task:
        problems.append(
            f"OpenSearch delete_by_query submit FAILED (no task id): {res}")
        ev["os_docs_left"] = stack.os_count(OS_SYSLOG_INDEX, "hostname.keyword",
                                            prefix)
        if ev["os_docs_left"] != 0:
            problems.append(
                f"{ev['os_docs_left']} run docs left in {OS_SYSLOG_INDEX}")
        return ev, problems
    log(f"cleanup: OpenSearch delete_by_query submitted as task {task} "
        f"({before} docs matching {prefix}); budget {budget_s / 60:.0f} min, "
        f"progress measured by re-count every {poll_s:.0f}s. NOTE: if a delete "
        f"for this prefix is already running server-side (an earlier run, or a "
        f"manual submit), this one overlaps it — harmless with "
        f"conflicts=proceed, but it doubles the load, so prefer letting the "
        f"first one finish and re-running this to VERIFY")

    t0 = time.monotonic()
    budget_initial_s = max(1.0, budget_s)
    budget_s = budget_initial_s
    deadline = t0 + budget_s
    left, elapsed = before, 0.0
    # Stall detection replaces "the clock ran out" as the reason to stop: a
    # purge that is still deleting gets more time, a purge that has stopped
    # deleting is called out immediately instead of at the end of the budget.
    stall_polls, prev_left, stalled = 0, before, False
    readable_samples = 1 if before >= 0 else 0
    while True:
        nap = min(poll_s, max(0.0, deadline - time.monotonic()))
        if nap > 0:
            time.sleep(nap)
        left = stack.os_count(OS_SYSLOG_INDEX, "hostname.keyword", prefix)
        elapsed = time.monotonic() - t0
        if left < 0:
            # A count we could not read is NOT progress and NEVER "clean". It
            # is not evidence of a stall either, so the stall counter is left
            # alone — an unreadable index says nothing about the delete.
            warn(f"cleanup: OpenSearch count failed {elapsed:.0f}s into the "
                 f"purge — progress UNKNOWN, task {task} still running")
        else:
            readable_samples += 1
            if prev_left >= 0 and left >= prev_left:
                stall_polls += 1
            elif left < prev_left:
                stall_polls = 0
            prev_left = left
            done = (before - left) if before >= 0 else -1
            rate = (done / elapsed) if done > 0 and elapsed > 0 else 0.0
            eta = (f"~{left / rate / 60:.1f} min" if rate > 0 else "no ETA yet")
            log(f"cleanup: OpenSearch purge — {left} docs left "
                f"({rate:.0f} docs/s, {eta}), {elapsed:.0f}s of "
                f"{budget_s:.0f}s, task {task}")
            # RE-ESTIMATE from the measured rate once two counts exist (the
            # pre-count plus one poll). The budget only ever GROWS, never past
            # the hard cap, and the new ETA is printed when it changes — an
            # extension nobody can see is indistinguishable from a hang.
            if readable_samples >= 2 and rate > 0 and left > 0:
                needed = elapsed + (left / rate) * OS_PURGE_ETA_SAFETY
                grown = min(OS_PURGE_BUDGET_MAX_S, needed)
                if grown > budget_s + 1.0:
                    log(f"cleanup: OpenSearch purge slower than the "
                        f"{1 / OS_PURGE_SECONDS_PER_DOC:.0f} docs/s estimate "
                        f"({rate:.0f} docs/s measured) — extending the budget "
                        f"{budget_s:.0f}s -> {grown:.0f}s (ETA {eta}, hard cap "
                        f"{OS_PURGE_BUDGET_MAX_S:.0f}s, task {task}). The "
                        f"server-side delete is progressing; the harness "
                        f"waits for it rather than reporting residue it "
                        f"merely stopped watching.")
                    budget_s = grown
                    deadline = t0 + budget_s
            if stall_polls >= OS_PURGE_STALL_POLLS:
                stalled = True
                warn(f"cleanup: OpenSearch purge STALLED — {left} docs left "
                     f"and the count has not decreased for {stall_polls} "
                     f"consecutive polls ({elapsed:.0f}s in); task {task} is "
                     f"not making progress. Giving up now rather than burning "
                     f"the rest of a {budget_s:.0f}s budget on it.")
                break
            if left == 0:
                # Confirm through an explicit refresh: _count reads the
                # searchable view, which lags the delete by the index's
                # refresh_interval. `indices_all` on netops-* covers this.
                okr, rres = stack.os_req(
                    "OS_BOOTSTRAP_PASSWORD", "svc_bootstrap",
                    f"/{OS_SYSLOG_INDEX}/_refresh", None, timeout=120)
                if not okr:
                    warn(f"cleanup: {OS_SYSLOG_INDEX} _refresh before the final "
                         f"count failed ({rres}) — the zero below is unrefreshed")
                left = stack.os_count(OS_SYSLOG_INDEX, "hostname.keyword", prefix)
                if left == 0:
                    log(f"cleanup: OpenSearch purge verified zero after "
                        f"{elapsed:.0f}s (task {task})")
                    break
                # The refreshed count is the real one: carry it into the
                # stall comparison, or the next poll would measure progress
                # against the unrefreshed zero and read as a stall.
                prev_left = left
                warn(f"cleanup: post-refresh count is {left}, not 0 — the purge "
                     f"is not finished; continuing within budget")
        if time.monotonic() >= deadline:
            break

    ev["os_docs_left"] = left
    ev["os_deleted"] = (before - left) if before >= 0 and left >= 0 else -1
    ev["os_purge_seconds"] = round(elapsed, 1)
    ev["os_purge_budget_s"] = round(budget_s, 1)
    ev["os_purge_budget_initial_s"] = round(budget_initial_s, 1)
    ev["os_purge_budget_extended"] = budget_s > budget_initial_s + 1.0
    ev["os_purge_stalled"] = stalled
    if left != 0:
        shown = left if left >= 0 else "UNKNOWN"
        why = (f"STALLED (the count stopped decreasing for {stall_polls} "
               f"consecutive polls)" if stalled else
               f"the {budget_s:.0f}s budget ran out (hard cap "
               f"{OS_PURGE_BUDGET_MAX_S:.0f}s)")
        problems.append(
            f"{shown} docs left in {OS_SYSLOG_INDEX} after {elapsed:.0f}s — "
            f"{why} — task {task} may still be running "
            f"server-side; re-run `--cleanup-only {prefix}` to re-verify "
            f"(it is idempotent and will resubmit only what is left)")
    return ev, problems


class Harness:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.runid = (datetime.now(timezone.utc).strftime("%m%d%H%M") +
                      "".join(random.choices(string.ascii_lowercase + string.digits, k=4)))
        self.prefix = f"mlx-{self.runid}-"
        self.stack = Stack(args.env_file, args.base_url, args.project)
        # Expanded once, not per event — see _syslog_event.
        self._mix = self._mix_table(self.EVENT_MIX_REALISTIC)
        self._tables = self._composed_tables()
        # Ratified workload profile (STRESS_GATE_REDEFINITION §5/§6): resolves
        # to rate/duration/mix/lane overrides applied in main() after parsing.
        self.profile = WORKLOAD_PROFILES[args.profile]
        # Resolved at burst Gate 1 (registry propagation): the tenant key every
        # injected record carries, or None for the legacy null-key shape.
        self.producer_key: str | None = None
        self.run_dir = args.run_dir or os.path.join(
            REPO_ROOT, "data", "miniladder",
            datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + self.runid)
        self.phases: list[dict] = []
        self.baseline: dict = {}
        self.created_ids: list[str] = []
        # requested name -> canonical id, when dedupe absorbed the create
        self.absorbed: dict[str, str] = {}
        self.stability_t0 = time.monotonic()
        # The RUN's start on the harness's own clock, NEVER reassigned —
        # unlike stability_t0, which is re-anchored at burst start. memflat's
        # backfill pass-evidence window is derived from it so it spans the same
        # run the ClickHouse error clause judges (which opens at PREFLIGHT, not
        # at the burst): a narrower window would hide the recovery evidence for
        # a refusal raised before injection began.
        self.run_mono_t0 = time.monotonic()
        self.injected_total = 0
        self.burst_seconds = 0.0
        self.produce_failures: list[str] = []
        # Accounting identity (tracker 152 §8.3): the internal generator
        # accounts under this harness's own mlx- namespace; `--load-generator
        # twin` swaps these to the delegated twin run's twx- namespace so the
        # balance equation counts the events that were ACTUALLY injected.
        self.acct_prefix = self.prefix
        self.acct_runid = self.runid
        self.twin_run: dict = {}   # twin mode: {runid, run_dir, devices}
        # Per-container RSS at the END OF THE BURST — the leak anchor. Empty
        # until burst() completes; memflat says so and falls back to the cold
        # baseline rather than passing silently on a missing sample.
        self.warm_mem: dict[str, int] = {}
        # The same anchor measured on cgroup ANONYMOUS memory, for the services
        # whose docker-stats figure is mostly page cache (MEM_STATELESS_SERVICES
        # header). Empty for the same reason and reported the same way.
        self.warm_anon: dict[str, int] = {}
        # Running peak of ClickHouse's OWN memory accounting, sampled by this
        # harness at preflight / end of burst / memflat. Used when
        # system.metric_log cannot answer for the run window; -1 = never
        # sampled, which memflat reports rather than reading as zero.
        self.ch_mem_peak: dict[str, int] = {"MemoryTracking": -1,
                                            "MergesMutationsMemoryTracking": -1}
        # How many live `system.metrics` samples the harness folded in. It is
        # a FLOOR under the metric_log peaks and the whole instrument when
        # metric_log is gone, so the count rides in the evidence: "degraded to
        # N point samples" is a different statement from "measured at 1 Hz".
        self.ch_mem_samples = 0
        # Per-correlation-replica {pending, RSS} track, filled by the
        # correlation-completion poll loop and consumed by memflat's
        # pending-zero anchor. Container name -> the derived anchor row; empty
        # when that phase never ran, which memflat reports as UNKNOWN rather
        # than judging a backlog drain as a leak.
        self.corr_mem_track: dict[str, dict] = {}
        # Signal policy (see InterruptGuard): installed by main() so a run
        # started from a closing terminal (SIGHUP) or a `kill` (SIGTERM) still
        # unwinds into cleanup instead of leaving 2,500 devices standing.
        self.interrupts = InterruptGuard()
        # Devices left in the mlx- NAMESPACE after cleanup (this run's and any
        # other run id's — a foreign row is the next run's onboard collision
        # just the same). -1 = never verified (cleanup did not finish) —
        # reported as UNKNOWN, never as 0.
        self.residue_devices = -1
        # Cross-run collision guards (2026-08-29). Set by main() once the run
        # lock is actually held: only an exclusive process may sweep the whole
        # namespace, because a device it does not recognize could otherwise
        # belong to a run that is still standing.
        self.owns_run_lock = False
        # preflight passed -> a workload ran. A run REFUSED at preflight must
        # not delete the residue it refused over: the operator is being sent to
        # `--cleanup-only mlx-` and needs the evidence still there.
        self.preflight_ok = False
        # MLX_ALLOW_FOREIGN_RESIDUE=1 was honoured at preflight: foreign rows
        # are deliberate, so cleanup neither sweeps nor charges them to us.
        self.foreign_residue_allowed = False
        # Why (if at all) the workload must not run after onboarding:
        # "absorbed" | "shortfall" | "none". Set by onboard(); only a
        # non-"none" reason skips burst — a linearity-ratio FAIL does not.
        self.onboard_stop_reason = "none"
        # The seeded fault-injection scenario (`--profile t-storm-*`), built at
        # the top of the burst once the device ids exist. None for every other
        # profile — which is what keeps t-nominal-2.5k byte-for-byte the
        # workload every recorded 2.5K number was measured on.
        self.scenario: StormScenario | None = None
        # Tracker 210: "OK" | "UNQUIET" | "unmeasured". Carried into
        # report.json `parameters` so a verdict can never silently come from an
        # unquiet host.
        self.host_quiet = "unmeasured"

    # -- plumbing -----------------------------------------------------------
    def phase(self, name: str, status: str, evidence: dict, notes: str = "") -> bool:
        entry = {"phase": name, "status": status, "notes": notes,
                 "evidence": evidence, "at": utcnow()}
        self.phases.append(entry)
        log(f"[{status}] {name}" + (f" — {notes}" if notes else ""))
        return status == "PASS"

    def evidence_file(self, name: str, content: str) -> str:
        path = os.path.join(self.run_dir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    # -- phase 1: preflight -------------------------------------------------
    def preflight(self) -> bool:
        ev: dict = {}
        problems: list[str] = []

        # DISK HEADROOM + HOST QUIET (tracker 210) — FIRST, before anything
        # else is probed, so the refusal is instant and has touched nothing.
        # See host_quiet_problems(): this refuses BEFORE the leg runs and
        # changes no gate semantics.
        quiet = host_quiet_readings(self.args.min_free_gib, self.args.max_load1)
        quiet_problems = host_quiet_problems(quiet)
        quiet["violations"] = quiet_problems
        if not quiet_problems:
            self.host_quiet = "OK"
        elif self.args.allow_unquiet:
            self.host_quiet = "UNQUIET"
            quiet["allow_unquiet"] = True
            quiet["verdict"] = "UNQUIET"
            for problem in quiet_problems:
                warn(f"--allow-unquiet: {problem}")
            warn("--allow-unquiet: PROCEEDING on an unquiet host. This leg is "
                 "NOT accounting-graded evidence — report.json records "
                 "host_quiet=UNQUIET in its parameters.")
        else:
            # EARLY RETURN, deliberately. Unlike the residue/consumer clauses
            # (which accumulate so the operator sees every problem at once),
            # this one costs nothing to evaluate and everything after it costs
            # minutes — the bounded consumer settle alone is 180 s. Refusing
            # here means the harness has not touched the stack at all.
            quiet["verdict"] = "REFUSED"
            self.host_quiet = "UNQUIET"
            ev["host_quiet"] = quiet
            self.preflight_ok = False
            return self.phase("preflight", "FAIL", ev, "; ".join(quiet_problems))
        ev["host_quiet"] = quiet

        states = self.stack.service_states()
        ev["services"] = states
        seen = {s["service"] for s in states}
        for req in REQUIRED_SERVICES:
            if req not in seen:
                problems.append(f"required service missing: {req}")
        for s in states:
            if s["status"] == "restarting":
                problems.append(f"{s['service']} is crash-looping")
            elif s["status"] == "exited" and s["exit_code"] != "0":
                problems.append(f"{s['service']} exited {s['exit_code']}")
            elif s["health"] == "unhealthy":
                problems.append(f"{s['service']} is unhealthy")

        # Ingress answers (retried: a busy box is not an absent stack).
        try:
            ev["ingress_status"] = http_ingress_status(self.stack.base_url)
        except (urllib.error.URLError, OSError) as exc:
            problems.append(f"ingress probe {self.stack.base_url}/ failed: {exc}")

        # API auth works (and stays logged in for later phases).
        try:
            self.stack.login()
            ev["api_login"] = "ok"
        except (RuntimeError, urllib.error.URLError, OSError) as exc:
            problems.append(f"API login failed: {exc}")

        # FOREIGN RESIDUE GATE (2026-08-29). Any `mlx-` device of ANY run id is
        # a refusal, not a warning: this harness onboards onto FIXED 198.18/15
        # addresses, so a leftover fleet makes the API's cross-source dedupe
        # absorb our creates into it (POST answers 200 + a canonical id). The
        # absorbed rows still persist under OUR ids but are invisible to a
        # prefix LIST until the absorber is deleted — which is how three runs in
        # a row inherited the same 1,000 devices while every teardown truthfully
        # reported "0 remain" for its own prefix. The old preflight passed with
        # 1,000 mlx- devices standing. It refuses now, first — before the
        # bounded consumer wait, so the refusal is fast.
        if ev.get("api_login") == "ok":
            left, list_err = foreign_residue(self.stack, self.prefix)
            ev["namespace_residue_devices"] = len(left)
            ev["namespace_residue_by_run"] = residue_by_run(left)[:RESIDUE_RUN_IDS_SHOWN]
            ev["namespace_residue_sample"] = left[:10]
            if list_err:
                problems.append(
                    f"the {DEVICE_PREFIX_ROOT} namespace could not be listed "
                    f"({list_err}) — residue is UNKNOWN, and an unknown "
                    f"namespace is not a clean one")
            elif left and env_flag(ALLOW_FOREIGN_RESIDUE_ENV):
                self.foreign_residue_allowed = True
                ev["foreign_residue_allowed"] = True
                warn(f"{ALLOW_FOREIGN_RESIDUE_ENV}=1 — PROCEEDING with "
                     f"{residue_summary(left)} already in the "
                     f"{DEVICE_PREFIX_ROOT} namespace. This run's creates may be "
                     f"ABSORBED by them (200 + canonical id), its per-device "
                     f"accounting is then unattributable, and cleanup will NOT "
                     f"sweep them. This run is not qualification evidence.")
            elif left:
                problems.append(
                    f"{len(left)} {DEVICE_PREFIX_ROOT} device(s) from a previous "
                    f"run are still in the device store ({residue_summary(left)}) "
                    f"— this run would onboard onto the SAME 198.18/15 addresses "
                    f"and be absorbed into them, so its numbers would be "
                    f"unattributable. Purge them first: python3 "
                    f"scripts/scale-miniladder.py --cleanup-only "
                    f"{DEVICE_PREFIX_ROOT}   (deliberate exception: "
                    f"{ALLOW_FOREIGN_RESIDUE_ENV}=1)")

        # ACTIVE bus consumers — offsets alone lie (a dead consumer keeps its
        # committed offsets forever). Both the RCA engine and the ingest
        # router must hold group membership RIGHT NOW.
        # `--describe` intermittently races the coordinator and reports zero
        # members for a live group (same flake the audit doc notes for
        # kafka-exporter), and a consumer mid-rebalance is memberless between
        # kicks — poll over a bounded window before believing "no consumer".
        # A DEAD consumer (the wiped-ACL shape) never shows a member at all.
        #
        # The wait is BOUNDED and configurable because bring-up cost is
        # hardware-dependent, not invariant: on a cold shared CI runner
        # kafka-init spends a JVM per topic and the last topic of the 16
        # appeared ~7 min after the broker came up (run 31991056443:
        # netops.wireless_events log created 03:34:23), so the engine's final
        # rebalance lands minutes after `docker compose up` returns. Waiting
        # longer never weakens the assertion — the verdict is still "a member
        # must be there", only the patience is tuned (--consumer-settle-seconds).
        settle = self.args.consumer_settle_seconds

        def settled_group(group: str) -> dict:
            last: dict = {"_members": 0, "_rows": 0}
            deadline = time.monotonic() + settle
            waited = 0.0
            while True:
                last = self.stack.group_lag(group)
                if last.get("_members", 0) >= 1:
                    if waited:
                        log(f"preflight: {group} showed a member after {waited:.0f}s")
                    return last
                if time.monotonic() >= deadline:
                    return last
                time.sleep(10)
                waited += 10

        def consumer_problem(group: str, g: dict, role: str) -> str:
            """Name the SHAPE of the absence — the three causes need different
            first moves, and 'no active consumer' alone hid that."""
            if g.get("_error"):
                return (f"{group} could not be described after {settle}s — the "
                        f"membership check is BLIND, not passing: {g['_error']}")
            if g.get("_rows", 0) == 0:
                return (f"{group} is UNKNOWN to the broker after {settle}s — the "
                        f"{role} never joined (consumer down, topics never created, "
                        f"or authorization-dead: check `docker compose logs "
                        f"correlation vector-router` and `logs kafka | grep -i denied`)")
            return (f"{group} has rows but NO active member after {settle}s — "
                    f"committed offsets with zero members is the dead-{role} "
                    f"signature (2026-08-16 wiped-ACL incident)")

        corr_lag = settled_group("netops-correlation")
        router_lag = settled_group("netops-router-syslog")
        ev["corr_group"] = corr_lag
        ev["router_syslog_group"] = router_lag
        ev["consumer_settle_seconds"] = settle
        if corr_lag.get("_members", 0) < 1:
            problems.append(consumer_problem("netops-correlation", corr_lag, "engine"))
        if router_lag.get("_members", 0) < 1:
            problems.append(consumer_problem("netops-router-syslog", router_lag, "router"))
        # A stack still digesting an earlier backlog cannot produce a valid
        # drain verdict — the baseline must be near-idle. A bare refusal sent
        # the operator away with no idea whether to wait 2 minutes or 2 hours
        # (resume brief 2026-08-28: "preflight gives no drain-ETA"), so the
        # refusal now carries a measured rate and an ETA.
        if corr_lag.get("_total", -1) > self.args.max_baseline_lag:
            eta = self.lag_drain_eta("netops-correlation",
                                     self.args.max_baseline_lag,
                                     first=corr_lag.get("_total", -1))
            ev["baseline_lag_eta"] = eta
            problems.append(
                f"correlation lag already {corr_lag['_total']} at baseline "
                f"(> {self.args.max_baseline_lag}) — stack is not idle; a drain "
                f"verdict on top of an existing backlog would be meaningless. "
                f"{eta['summary']}")

        # Baselines.
        self.baseline["mem"] = self.stack.mem_sample()
        # The page-cache-free anchor for the stateful services, plus the two
        # ClickHouse baselines memflat's §(c) clauses are judged against: the
        # window start on CH's OWN clock (metric_log is queried by event_time)
        # and the part count an idle store carries before this run's inserts.
        self.baseline["mem_anon"] = self.stack.anon_sample(self._anon_services())
        self.baseline["ch_window_start"] = self.stack.ch_now()
        self.baseline["ch_max_part_count"] = self._ch_number(
            "SELECT value FROM system.asynchronous_metrics "
            "WHERE metric = 'MaxPartCountForPartition'")
        # The customer-visible fact memflat clause (2a) is a DELTA of: how many
        # times the server had already refused work for want of memory before
        # this run put a byte on it. -1 = unread, which memflat reports as
        # UNKNOWN rather than treating as a clean baseline of 0.
        self.baseline["ch_mem_errors"] = self._ch_number(CH_MEM_ERROR_TOTAL_SQL)
        self._ch_sample_metrics()
        self.baseline["kafka_syslog_end"] = self.stack.end_offset("netops.syslog")
        self.baseline["corr_lag_total"] = corr_lag.get("_total", -1)
        self.baseline["router_lag_total"] = router_lag.get("_total", -1)
        for table in ("corr_signals", "flows"):
            ok, out = self.stack.ch(f"SELECT count() FROM netops.{table}")
            self.baseline[f"ch_{table}"] = int(out) if ok and out.isdigit() else -1
            if not ok:
                problems.append(f"ClickHouse count on netops.{table} failed: {out}")
        self.baseline["vm_active_series"] = self.stack.vm_query(
            'vm_cache_entries{type="storage/hour_metric_ids"}')
        self.baseline["vector_discards"] = self.stack.vm_query(
            'sum(vector_component_discarded_events_total{intentional="false"})')
        self.baseline["vector_deadletter_sent"] = self.stack.vm_query(
            'sum(vector_component_sent_events_total{component_id=~"opensearch_deadletter|kafka_deadletter"})')
        hz = self.stack.corr_healthz()
        dur = hz.get("durability", {}) if isinstance(hz, dict) else {}
        self.baseline["quarantine_write_failures"] = dur.get("quarantine_write_failures", -1)
        self.baseline["registry_identities"] = (
            hz.get("tenant_verification", {}).get("registry_identities", -1)
            if isinstance(hz, dict) else -1)
        self.baseline["corr_deadletters"] = self.stack.corr_metric("corr_deadletters")
        # TRACKER 170: the engine-completion baseline. Completion is a
        # statement about PROGRESS across the run, so the counters and the
        # process identity must both be pinned before any workload exists.
        self.baseline["corr_completion"] = self.stack.corr_completion_state()
        self.baseline["os_run_docs"] = self.stack.os_count(
            "netops-syslog-*", "hostname.keyword", self.prefix)
        if "_error" in hz:
            problems.append(f"correlation /healthz unreachable: {hz['_error']}")
        if self.baseline["os_run_docs"] != 0:
            problems.append(
                f"OpenSearch already holds {self.baseline['os_run_docs']} docs "
                f"for prefix {self.prefix} — runid collision?")

        # ── clean-slate --verify's offset bound, RE-BASELINED 2026-08-29 ──
        #
        # THE NOISE THIS REPLACES. The old form compared
        # `kafka_syslog_end + planned` against 100,000. Since `end_offset` was
        # fixed to SUM the LOG-END-OFFSETs of every partition of a topic that
        # never resets, that number is the stack's lifetime syslog volume
        # (73,132,772 on run p2-s05-08291138) — so the condition was true on
        # every run, on every stack, forever. A warning that cannot be false
        # carries no information and trains operators to skip the preflight
        # output, which is worse than not warning at all.
        #
        # `clean-slate.sh --verify` (clean-slate.sh:243) does NOT measure that:
        # it maxes the CURRENT-OFFSET column over the consumer-group describe
        # rows and fails above 100,000 ("the bus data dir was not reset"). So
        # the harness now measures the SAME statistic, from the describes it
        # already ran. It sees two groups, not all of them, which makes its
        # number a LOWER BOUND on clean-slate's — above the bound is proof,
        # below it is inconclusive, and the message says which.
        planned = self._planned_total()
        bus_max_current = max(corr_lag.get("_max_current", -1),
                              router_lag.get("_max_current", -1))
        self.baseline["bus_max_current_offset"] = bus_max_current
        self.baseline["bus_verify_bound"] = CLEAN_SLATE_OFFSET_BOUND
        level, message = clean_slate_offset_note(bus_max_current, planned)
        if level == "warn":
            warn(message)
        elif level == "log":
            log(message)
        ev["baseline"] = self.baseline

        status = "PASS" if not problems else "FAIL"
        self.preflight_ok = status == "PASS"
        return self.phase("preflight", status, ev,
                          "; ".join(problems) if problems else
                          f"{len(states)} services checked, consumers live, baselines captured")

    def lag_drain_eta(self, group: str, target: int, first: int = -1) -> dict:
        """Sample a backlog briefly and turn it into an ETA the operator can
        plan against.

        HARD-BOUNDED by LAG_ETA_BUDGET_S (60 s default): preflight refuses
        fast, it does not become a waiting room. A backlog that is NOT
        shrinking is said so plainly — an ETA invented from a flat or rising
        curve would be worse than none.
        """
        t0 = time.monotonic()
        deadline = t0 + LAG_ETA_BUDGET_S
        samples: list[tuple[float, int]] = []
        if first >= 0:
            samples.append((0.0, first))
        while len(samples) < max(2, LAG_ETA_SAMPLES):
            nap = min(LAG_ETA_INTERVAL_S, max(0.0, deadline - time.monotonic()))
            if nap <= 0:
                break
            time.sleep(nap)
            lag = self.stack.group_lag(group).get("_total", -1)
            if lag < 0:
                warn(f"drain ETA: {group} lag unreadable at "
                     f"{time.monotonic() - t0:.0f}s — ETA is incomplete")
                break
            samples.append((time.monotonic() - t0, lag))
            if time.monotonic() >= deadline:
                break
        ev: dict = {"group": group, "target": target,
                    "samples": [[round(t, 1), v] for t, v in samples],
                    "observed_s": round(samples[-1][0], 1) if samples else 0.0,
                    "rate_per_s": None, "eta_seconds": None}
        if len(samples) < 2 or samples[-1][0] <= 0:
            ev["summary"] = (f"drain ETA: not measurable (only {len(samples)} "
                             f"lag sample(s) in {LAG_ETA_BUDGET_S:.0f}s)")
            log(f"preflight: {ev['summary']}")
            return ev
        (t_a, l_a), (t_b, l_b) = samples[0], samples[-1]
        rate = (l_a - l_b) / (t_b - t_a)          # events/s of BACKLOG REMOVAL
        ev["rate_per_s"] = round(rate, 1)
        if rate <= 0:
            ev["summary"] = (f"drain ETA: NOT draining — lag {l_a} -> {l_b} over "
                             f"{t_b - t_a:.0f}s ({rate:+.0f}/s); it is not "
                             f"shrinking, so there is no ETA (stop the load, or "
                             f"check the correlation consumer)")
        elif l_b <= target:
            ev["eta_seconds"] = 0
            ev["summary"] = (f"drain ETA: already at {l_b} (<= {target}) after "
                             f"{t_b - t_a:.0f}s of observation — retry now")
        else:
            eta = (l_b - target) / rate
            ev["eta_seconds"] = round(eta, 1)
            ev["summary"] = (f"drain ETA: lag {l_a} -> {l_b} over {t_b - t_a:.0f}s "
                             f"({rate:.0f}/s) — ~{eta / 60:.1f} min to reach "
                             f"{target} (retry after that)")
        log(f"preflight: {ev['summary']}")
        return ev

    def device_identity_shas(self) -> dict:
        """sha256(device name) -> device index, for every device this run created.

        The refusal dead-letter record keeps only this digest (F-11 withholds
        the plaintext hostname), so without it a run cannot see its OWN refused
        events. Computing it here uses only names the ladder already owns — it
        reveals nothing the harness did not already know, and it does not weaken
        the sealed-quarantine invariant for anyone else.
        """
        return {hashlib.sha256(name.encode("utf-8", "replace")).hexdigest(): i
                for i, name in enumerate(self.created_ids)}

    # -- phase 2: onboarding linearity --------------------------------------
    def onboard(self) -> bool:
        n = self.args.devices
        k = 100 if n >= 200 else max(10, n // 2)
        durations: list[float] = []
        failures: list[str] = []
        t0 = time.monotonic()
        for i in range(n):
            name = f"{self.prefix}{i:05d}"
            body = {
                "id": name, "name": name,
                # RFC 2544 benchmark space — never routable, so pollers that
                # pick the device up can only time out quietly.
                "address": f"198.18.{i // 250}.{i % 250 + 1}",
                "type": "router", "source": "miniladder-g2",
                "labels": {"mlx_run": self.runid},
            }
            t = time.monotonic()
            st, resp = self.stack.api("POST", "/api/devices", body)
            durations.append(time.monotonic() - t)
            # TRACKER 161: a 201 is not proof the requested identity exists.
            # Cross-source dedupe can absorb a create into an existing device
            # that shares an identity token (management IP), and the API used to
            # answer 201 while echoing the caller's object back. 73 devices were
            # onboarded that way on 2026-08-19 and every event they emitted was
            # unattributable. Trust the CANONICAL identity the API reports, not
            # the status code.
            canonical = ""
            if isinstance(resp, dict):
                canonical = str(resp.get("id") or "")
            if st == 201 and canonical == name:
                self.created_ids.append(name)
            elif st in (200, 201) and canonical and canonical != name:
                # Absorbed into an existing device — record the mapping and do
                # NOT count it as this run's device; nothing downstream will key
                # on the name we asked for.
                self.absorbed[name] = canonical
            else:
                failures.append(f"{name}: HTTP {st} canonical={canonical or '-'} "
                                f"{str(resp)[:100]}")
                if len(failures) >= 10:
                    break
        total_wall = time.monotonic() - t0

        # The CANONICAL ids are teardown state, not just evidence: they are the
        # devices that absorbed ours, and each one HIDES a shadow row persisted
        # under the id we asked for (discovery.Upsert stores by id; only the
        # read projection collapses the pair). Cleanup deletes both.
        canonical_ids = sorted({c for c in self.absorbed.values() if c})
        # STOP REASON (owner decision, 2026-08-29). An onboard FAIL is not one
        # thing, and the two kinds must not be collapsed:
        #
        #   absorbed  — dedupe folded creates into somebody else's devices, so
        #               the events this run injects are attributed elsewhere;
        #   shortfall — fewer own devices than requested (create failures), so
        #               the fleet the burst is judged against is not the fleet
        #               that was planned;
        #   none      — the fleet is WHOLE and attributable. A pure
        #               linearity-ratio FAIL lands here: the O(N^2) verdict is
        #               about creation SPEED, and the burst it carries is still
        #               valid correlation evidence (the P1 verdict leg was
        #               exactly that case), so the run continues and the phase
        #               verdicts stay independent, as they always did.
        #
        # Only a non-"none" reason skips burst/drain/completion/accounting.
        if self.absorbed:
            self.onboard_stop_reason = "absorbed"
        elif len(self.created_ids) < n:
            self.onboard_stop_reason = "shortfall"
        else:
            self.onboard_stop_reason = "none"
        # The EXPECTED wall for this fleet (scales with --devices; see
        # onboard_budget_s). Informational: an overrun is reported, never a
        # verdict — a slow create is exactly what the linearity gate judges.
        budget_s = onboard_budget_s(n)
        ev: dict = {"devices_requested": n, "devices_created": len(self.created_ids),
                    "budget_s": round(budget_s, 0),
                    "over_budget": total_wall > budget_s,
                    "onboard_stop_reason": self.onboard_stop_reason,
                    "devices_absorbed_by_dedupe": len(self.absorbed),
                    "absorbed_mappings": dict(list(self.absorbed.items())[:20]),
                    "absorbed_canonical_ids": canonical_ids[:20],
                    "absorbed_canonical_count": len(canonical_ids),
                    "absorbed_canonical_by_run":
                        residue_by_run(canonical_ids)[:RESIDUE_RUN_IDS_SHOWN],
                    "window": k, "total_wall_s": round(total_wall, 2),
                    "failures": failures[:10]}
        if total_wall > budget_s:
            warn(f"onboard took {total_wall:.0f}s for {n} devices "
                 f"({n / max(total_wall, 1e-9):.1f}/s) — over the "
                 f"{budget_s:.0f}s this fleet is budgeted (floor "
                 f"{ONBOARD_RATE_FLOOR_PER_S:.0f}/s). Not a verdict: check the "
                 f"tombstone debt this run reports (tracker 175) and size the "
                 f"caller's timeout from the measured rate")
        if self.absorbed:
            return self.phase(
                "onboard", "FAIL", ev,
                f"{len(self.absorbed)} of {n} requested devices were ABSORBED by "
                f"dedupe into {len(canonical_ids)} existing device(s) "
                f"({residue_summary(canonical_ids)}) — stale residue on the same "
                f"198.18/15 addresses. Their telemetry would be unattributable, "
                f"so this run cannot prove {n}/{n}: stop={self.onboard_stop_reason} "
                f"— the burst is SKIPPED and the run goes straight to cleanup. "
                f"Clear the residue (--cleanup-only {DEVICE_PREFIX_ROOT}) and "
                f"re-run")
        if failures:
            return self.phase(
                "onboard", "FAIL", ev,
                f"{len(failures)}+ create failures — only "
                f"{len(self.created_ids)} of {n} devices exist "
                f"(stop={self.onboard_stop_reason}): the burst is SKIPPED and "
                f"the run goes straight to cleanup (first: {failures[0]})")

        first_rate = k / max(sum(durations[:k]), 1e-9)
        last_rate = k / max(sum(durations[-k:]), 1e-9)
        ratio = last_rate / first_rate
        ev.update({"first_window_rate_per_s": round(first_rate, 2),
                   "last_window_rate_per_s": round(last_rate, 2),
                   "last_over_first": round(ratio, 3),
                   "floor": self.args.linearity_floor})
        ok = ratio >= self.args.linearity_floor
        return self.phase(
            "onboard", "PASS" if ok else "FAIL", ev,
            f"create rate first {first_rate:.1f}/s -> last {last_rate:.1f}/s "
            f"(ratio {ratio:.2f}, floor {self.args.linearity_floor}) — "
            + ("linear enough" if ok else
               f"SUPER-LINEAR SLOWDOWN (O(N^2) class) — all {n} devices exist "
               f"and are attributable, so the workload still runs and this "
               f"verdict stands on its own")
            + f" [stop={self.onboard_stop_reason}]")

    # -- phase 3: burst ------------------------------------------------------
    #
    # WORKLOAD SHAPE. `--event-mix single` emits one mnemonic (%LINK-3-UPDOWN),
    # which the correlation engine classifies into exactly one signal kind
    # (`link_state_change`). That is the historical workload and stays the
    # DEFAULT: every capacity number recorded against this harness — the whole
    # of tracker 166's evidence trail — was measured on it, and silently
    # changing the workload would invalidate the comparison rather than extend
    # it.
    #
    # It is also, as `docs/scale/TEMPLATE_APPLICABILITY_167.md` says in its own
    # generality caveat, the FRIENDLY case for tracker 167's signal-kind
    # template index: a single-kind window is the easiest possible thing to be
    # selective about, so the measured "22 candidate templates per object of
    # 100" is a property of this workload and not of the platform. 167 is
    # therefore PASS offline with its live selectivity UNVALIDATED — the
    # harness could not produce a workload capable of testing it.
    #
    # `--event-mix realistic` closes that gap: a weighted mnemonic mix chosen so
    # the engine's syslog classifier (`producers.syslog_control_signal`) yields
    # SIX distinct kinds across two entity scopes (device, interface).
    # Selection is deterministic in `seq` — no RNG — so the
    # injected/persisted balance equation the
    # accounting phase depends on stays exactly reproducible, and two runs of
    # the same parameters remain comparable.
    #
    # Weights are per-mnemonic shares of a realistic edge/aggregation estate,
    # not equal thirds: link flaps dominate real syslog, adjacency churn
    # follows, and a tail of unclassified lines becomes canonical
    # `device_alarm` — which is itself worth injecting, because it is the
    # branch every unrecognized vendor mnemonic in the field lands on.
    EVENT_MIX_REALISTIC = (
        # (weight, appname, message template, syslog severity) -> engine kind
        (46, "LINK-3-UPDOWN",
         ("%LINK-3-UPDOWN: Interface GigabitEthernet0/{if_n}, "
          "changed state to {state}"), "err"),                  # link_state_change
        (18, "BGP-5-ADJCHANGE",
         ("%BGP-5-ADJCHANGE: neighbor 10.{oct2}.{oct3}.1 {State} "
          "Interface flap"), "notice"),                         # bgp_adjacency_change
        (12, "OSPF-5-ADJCHG",
         ("%OSPF-5-ADJCHG: Process 1, Nbr 10.{oct2}.{oct3}.2 on "
          "GigabitEthernet0/{if_n} from FULL to {STATE}"), "notice"),  # ospf_adjacency_change
        (9, "LLDP-5-NEIGHBOR",
         ("%LLDP-5-NEIGHBOR: neighbor {verb} on interface "
          "GigabitEthernet0/{if_n}"), "notice"),                # lldp_neighbor_change
        (8, "SPANTREE-6-INTERFACE",
         ("%SPANTREE-6-INTERFACE: GigabitEthernet0/{if_n} moved to "
          "{stp_state}"), "info"),                              # stp_topology_change
        # Deliberately an UNRECOGNIZED mnemonic at warning severity: it must fall
        # through every branch above to the generic device-alarm safety net. The
        # severity matters — that net has a floor and ignores notice/info, so an
        # info-level line here would produce no signal at all and quietly make
        # this a five-kind mix (verified, not assumed: test_event_mix_167.py).
        (7, "ENVMON-4-FAN_FAILED",
         "%ENVMON-4-FAN_FAILED: Fan {if_n} failed", "warning"),  # device_alarm
    )

    # Promotion-realistic NOISE: operational lines the correlation classifier
    # provably yields NO signal for (info/notice severity, no control-plane
    # tokens — each arm is pinned against the REAL classifier by
    # tests/test_event_mix_167.py::test_noise_lines_never_classify). This is
    # what makes the ratified promotion ratio (~5 % plan / ~30 % storm,
    # EPS_BASELINE_PROPOSAL §6) injectable instead of assumed: real syslog is
    # overwhelmingly informational (measured control-plane share 0.49 %).
    EVENT_MIX_NOISE = (
        (35, "SYS-5-CONFIG_I",
         "%SYS-5-CONFIG_I: Configured from console by admin on vty0", "info"),
        (25, "SEC_LOGIN-5-LOGIN_SUCCESS",
         ("%SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: ops] [Source: "
          "10.{oct2}.{oct3}.50] at 12:00:00 UTC"), "notice"),
        (20, "SSH-5-SSH2_SESSION",
         ("%SSH-5-SSH2_SESSION: SSH2 Session request from 10.{oct2}.{oct3}.9 "
          "(tty = 0) succeeded"), "notice"),
        (12, "SYS-6-LOGGINGHOST_STARTSTOP",
         "%SYS-6-LOGGINGHOST_STARTSTOP: Logging to host 10.0.0.2 port 514 started", "info"),
        (8, "SNMP-5-COLDSTART",
         "%SNMP-5-COLDSTART: SNMP agent on host reconfigured", "notice"),
    )

    @staticmethod
    def _mix_table(mix: tuple) -> tuple:
        """Expand the weighted mix into a flat lookup indexed by `seq`.

        Built once per run, not per event: at 2,000 eps for 5 minutes this is on
        the hot path 600,000 times.
        """
        table = []
        for weight, appname, template, severity in mix:
            table.extend([(appname, template, severity)] * weight)
        return tuple(table)

    @classmethod
    def _composed_tables(cls) -> dict:
        """The named mix tables (built once per run):
          realistic  — six classifying kinds, ~100 % promotion (167 validation)
          production — ~5 % promotion: one full realistic table (100 slots)
                       diluted with 1,900 noise slots (EPS baseline §6 plan)
          storm      — ~33 % promotion: storm content IS control-plane
                       (100 realistic + 200 noise slots; gate spec S1)
        """
        realistic = cls._mix_table(cls.EVENT_MIX_REALISTIC)
        noise = cls._mix_table(cls.EVENT_MIX_NOISE)          # len 100
        production = realistic + tuple(noise[i % len(noise)] for i in range(1900))
        storm = realistic + tuple(noise[i % len(noise)] for i in range(200))
        return {"realistic": realistic, "production": production, "storm": storm}

    def _syslog_event(self, device: str, seq: int, mix_name: str | None = None,
                      mix_seq: int | None = None) -> str:
        """One injected syslog line. `mix_name` overrides the run-level mix
        (profiles inject different mixes per LANE); `mix_seq` decorrelates mix
        selection from device selection — `seq % n_devices` (device pick) and
        `seq % len(table)` (mix pick) share factors, so without it a
        noise-bearing mix would starve FIXED devices of classifying events
        forever (the per-device corr_signals accounting check would fail, and
        promotion would be per-device-degenerate rather than uniform)."""
        state = "down" if seq % 2 == 0 else "up"
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        mix_name = mix_name or self.args.event_mix
        if mix_name == "single":
            appname = "LINK-3-UPDOWN"
            message = (f"%LINK-3-UPDOWN: Interface GigabitEthernet0/{seq % 48}, "
                       f"changed state to {state} [mlx seq {seq}]")
            severity = "err"
        else:
            table = self._tables.get(mix_name, self._mix)
            idx = (mix_seq if mix_seq is not None else seq) % len(table)
            appname, template, severity = table[idx]
            message = template.format(
                if_n=seq % 48,
                state=state,
                State=state.capitalize(),
                STATE=state.upper(),
                oct2=(seq // 251) % 251,
                oct3=seq % 251,
                verb="removed" if state == "down" else "added",
                stp_state="discarding" if state == "down" else "forwarding",
            ) + f" [mlx seq {seq}]"
        return json.dumps({
            "hostname": device,
            "appname": appname,
            "message": message,
            "severity": severity,
            "timestamp": ts,
        })

    def burst(self) -> bool:
        # tracker 152 §8.3 composition: the twin generates realistic load,
        # this harness keeps judging. Default path is the internal generator,
        # untouched.
        if getattr(self.args, "load_generator", "internal") == "twin":
            return self._burst_twin()
        return self._burst_internal()

    def _burst_twin(self) -> bool:
        """Delegate the burst to `twin.py run` (kept standing with --keep so
        accounting can count its telemetry; cleanup() tears the twin run down
        after the verdicts). The twin's per-lane emitted counts in
        twin-report.json become the injected side of the balance equation."""
        ev: dict = {}
        twin_py = os.path.join(REPO_ROOT, "scripts", "lab", "twin", "twin.py")
        cmd = [sys.executable, twin_py,
               "--env-file", self.args.env_file,
               "--project", self.args.project,
               "--base-url", self.args.base_url,
               "run", "--scenario", self.args.twin_scenario,
               "--duration-minutes", str(self.args.twin_duration_minutes),
               "--fidelity", self.args.twin_fidelity,
               "--keep"]
        budget = int(self.args.twin_duration_minutes * 60 + 1800)
        t0 = time.monotonic()
        rc, out, err = run(cmd, budget)
        self.burst_seconds = time.monotonic() - t0
        ev["twin_rc"] = rc
        self.evidence_file("twin-stdout.log", out)
        self.evidence_file("twin-stderr.log", err)
        try:
            with open(os.path.join(REPO_ROOT, "data", "twin",
                                   "last-run.json"), encoding="utf-8") as f:
                last = json.load(f)
            with open(os.path.join(last["run_dir"], "twin-report.json"),
                      encoding="utf-8") as f:
                report = json.load(f)
            with open(os.path.join(last["run_dir"], "state.json"),
                      encoding="utf-8") as f:
                state = json.load(f)
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            return self.phase("burst", "FAIL", ev,
                              f"twin run artifacts unreadable ({exc}) — "
                              f"cannot account honestly (twin rc={rc})")
        self.twin_run = {"runid": last.get("runid", ""),
                         "run_dir": last.get("run_dir", ""),
                         "devices": len(state.get("devices") or [])}
        self.acct_prefix = str(state.get("prefix") or "")
        self.acct_runid = str(last.get("runid") or "")
        by_lane = report.get("emitted_by_lane") or {}
        # +1: the twin's canary syslog event rides the same prefix but is not
        # in the schedule counts (lifecycle.canary).
        self.injected_total = int(by_lane.get("syslog") or 0) + 1
        ev.update({
            "twin_runid": self.acct_runid,
            "twin_emitted_by_lane": by_lane,
            "twin_skipped_by_lane": report.get("skipped_by_lane") or {},
            "twin_produce_failures": report.get("produce_failures") or [],
            "twin_accuracy": report.get("accuracy") or {},
            "twin_spread": report.get("spread") or {},
            "injected_total_syslog_lane": self.injected_total,
            "canary_included": True,
        })
        if rc != 0 or not self.acct_prefix or not self.acct_runid:
            return self.phase("burst", "FAIL", ev,
                              f"twin run rc={rc} (see twin-stderr.log)")
        if report.get("produce_failures"):
            return self.phase("burst", "FAIL", ev,
                              "twin reported produce failures — accounting "
                              "would be dishonest")
        return self.phase(
            "burst", "PASS", ev,
            f"twin {self.acct_runid} injected {self.injected_total} syslog-"
            f"lane events (+{sum(v for k, v in by_lane.items() if k != 'syslog')} "
            f"on other lanes) in {self.burst_seconds:.0f}s")

    def _canary_event(self) -> str:
        """The pipeline-proof event: always %LINK-3-UPDOWN (classifies under
        every catalog), always the first created device, fixed seq marker."""
        return self._syslog_event(self.created_ids[0], 999_999, mix_name="single")

    def _build_scenario(self) -> StormScenario | None:
        """Instantiate this profile's fault-injection scenario, or None.

        Pure function of (profile spec, this run's device ids, seed, window) —
        deliberately NOT of the run id, the clock or the box. The run id rides
        into ground-truth.json as a label only.
        """
        name = self.profile.get("scenario")
        if not name:
            return None
        spec = SCENARIO_SPECS.get(str(name))
        if spec is None:                     # 16.1: an unknown spec is a defect
            raise ValueError(f"profile {self.args.profile!r} names unknown "
                             f"scenario {name!r}")
        return StormScenario(
            spec, self.created_ids,
            seed=int(getattr(self.args, "scenario_seed", SCENARIO_SEED_DEFAULT)),
            window_s=int(self.args.burst_minutes * 60),
            chunk_secs=BURST_CHUNK_SECS,
            profile=str(self.args.profile),
            runid=str(getattr(self, "runid", "")))

    def _scenario_line(self, ev: ScenarioEvent, seq: int) -> str:
        """One scenario line, in the SAME envelope `_syslog_event` produces —
        same keys, same order, same `[mlx seq N]` trace marker (plus the
        incident id, so a raw line can be traced back to the ground truth
        without re-running the planner).

        The incident marker is inert to the classifier: it carries no
        interface token, no IP and no state word, so it cannot change how the
        line is parsed (pinned by test_scenario_lines_classify_as_planned).
        """
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        return json.dumps({
            "hostname": ev.device,
            "appname": ev.appname,
            "message": f"{ev.message} [mlx seq {seq} inc {ev.incident_id}]",
            "severity": ev.severity,
            "timestamp": ts,
        })

    def _lane_schedule(self) -> list[dict]:
        """The RATIFIED CHUNK PLAN: how many events each lane injects in each
        10 s chunk of the profile's window.

        Derived from the PROFILE ALONE — rate x duration on a NOMINAL chunk
        clock (chunk i covers seconds [i*10, i*10+10)), never from the wall
        clock and never from the achieved send rate. Two runs of the same
        profile therefore plan the identical fleet, event for event, however
        fast or slow the box injects it; the loop's only freedom is HOW LONG
        it takes (see BURST_WINDOW_MAX_FACTOR).

        Fractional rates carry per lane, so a 0.35 eps lane still integrates
        exactly over the window rather than truncating every chunk to zero.
        """
        return lane_chunk_plan(self.profile.get("lanes") or [],
                               int(self.args.burst_minutes * 60))

    def _planned_total(self) -> int:
        """Events this run intends to inject — the sum of the ratified chunk
        plan for lane profiles, args-derived otherwise. A fixed function of
        the profile in both cases."""
        if not self.profile.get("lanes"):
            return self.args.eps * int(self.args.burst_minutes * 60)
        return sum(sum(row.values()) for row in self._lane_schedule())

    def _lane_states(self) -> list[dict]:
        """Split this run's devices into the profile's lane pools (contiguous
        by creation order, deterministic; the last lane absorbs remainder).

        Under a scenario profile the BACKGROUND pool is narrowed to the
        scenario's noise devices — the ones no incident touches. That, and only
        that, is what makes "a background line never carries an incident's
        cause entity" a structural property instead of a hope.
        """
        lanes = []
        n = len(self.created_ids)
        start = 0
        spec = self.profile["lanes"]
        scen = getattr(self, "scenario", None)
        for i, (name, share, mix, rate) in enumerate(spec):
            cnt = n - start if i == len(spec) - 1 else max(1, round(share * n))
            pool = self.created_ids[start:start + cnt]
            if scen is not None:
                in_lane = set(pool)
                pool = [d for d in scen.noise_pool if d in in_lane]
            lanes.append({"name": name, "mix": mix, "rate": rate,
                          "pool": pool, "acc": 0.0, "seq": 0, "sent": 0})
            start += cnt
        return lanes

    def _burst_lanes(self, ev: dict) -> bool:
        """Multi-lane scheduled injection for the ratified storm profiles
        (S1 / S1-long / S2-ramp / S4-chatter / the T-family): each lane owns a
        device pool, a mix and a rate (constant or a function of elapsed
        seconds — the ramp).

        WORK-BOXED, NOT TIME-BOXED. The chunk plan comes from
        `_lane_schedule()` (profile-fixed), and this loop's job is to inject
        ALL of it: a slow producer stretches the window up to
        BURST_WINDOW_MAX_FACTOR x the profile window, and a fleet still not
        whole at that bound FAILS the phase with the shortfall. Pacing is
        unchanged for a healthy run — chunk i is released at t0 + i*10 s.

        SCENARIO PROFILES (`--profile t-storm-*`) do not change ANY of that.
        The chunk plan is the same profile-fixed quota; the scenario's planned
        events are placed into the chunk their plan time falls in, and the
        BACKGROUND generator fills the rest of that chunk's quota from the
        disjoint noise pool. The fleet total, the pacing and every gate are
        untouched — only the composition of each chunk changes.
        """
        chunk_secs = BURST_CHUNK_SECS
        duration = int(self.args.burst_minutes * 60)
        factor = max(1.0, float(getattr(self.args, "burst_window_factor",
                                        BURST_WINDOW_MAX_FACTOR)))
        window_bound = duration * factor
        plan = self._lane_schedule()
        fleet_planned = sum(sum(row.values()) for row in plan)
        fleet_injected = 0
        self.scenario = self._build_scenario()
        scen = self.scenario
        scen_lane = ""
        if scen is not None:
            if len(self.profile["lanes"]) != 1:
                return self.phase(
                    "burst", "FAIL", ev,
                    f"profile {self.args.profile!r} carries a scenario AND "
                    f"{len(self.profile['lanes'])} lanes — a scenario owns the "
                    f"whole fleet's composition and cannot be split across "
                    f"lanes; the workload would be ambiguous")
            scen_lane = self.profile["lanes"][0][0]
            # A chunk whose scenario events crowd out its ratified quota
            # would force the loop to either overshoot the fleet or drop
            # planned ground-truth events, and would starve the background of
            # the room it needs to keep the noise devices audible. Neither is
            # acceptable, and both are silent — so refuse BEFORE injecting
            # anything. See SCENARIO_CHUNK_HEADROOM for why a bare
            # "fits the quota" test is not enough at a 50 % storm share.
            over = [(i, len(b), plan[i].get(scen_lane, 0))
                    for i, b in enumerate(scen.buckets)
                    if i < len(plan)
                    and len(b) > plan[i].get(scen_lane, 0)
                    * (1.0 - SCENARIO_CHUNK_HEADROOM)]
            if over:
                return self.phase(
                    "burst", "FAIL", ev,
                    f"scenario {scen.spec['name']!r} leaves the background less "
                    f"than {SCENARIO_CHUNK_HEADROOM:.0%} of the ratified chunk "
                    f"quota in {len(over)} chunk(s) (worst: chunk "
                    f"{over[0][0]} wants {over[0][1]} of a {over[0][2]}-event "
                    f"quota) — the scenario is mis-sized for this profile")
            load = scen.chunk_load()
            if load["peak_over_mean"] > SCENARIO_CHUNK_PEAK_OVER_MEAN_MAX:
                return self.phase(
                    "burst", "FAIL", ev,
                    f"scenario {scen.spec['name']!r} is a SPIKE, not a storm: "
                    f"its peak chunk carries {load['peak']} events against a "
                    f"{load['mean']} mean ({load['peak_over_mean']}x, bound "
                    f"{SCENARIO_CHUNK_PEAK_OVER_MEAN_MAX}x) — spread the "
                    f"incidents (shape.onset_span / incident_density) instead "
                    f"of deepening them")
            gt = scen.ground_truth(planned_total=fleet_planned)
            gt_path = self.evidence_file(GROUND_TRUTH_FILE,
                                         json.dumps(gt, indent=1, sort_keys=True))
            twin_recs = scen.twin_records()
            twin_gt_path = self.evidence_file(
                TWIN_GROUND_TRUTH_FILE,
                "".join(json.dumps(r, sort_keys=True) + "\n"
                        for r in twin_recs))
            twin_state_path = self.evidence_file(
                TWIN_STATE_FILE,
                json.dumps(scen.twin_state(), indent=1, sort_keys=True))
            ev["ground_truth"] = {
                "path": gt_path, "schema": gt["schema"],
                "scenario": gt["scenario"], "seed": gt["seed"],
                "digest": gt["digest"], "incidents": len(gt["incidents"]),
                "templates": gt["templates"], "devices": gt["devices"],
                "counts": gt["counts"],
                "shape": gt["shape"],
                "parser_coverage": gt["parser_coverage"],
                "not_promoted": gt["not_promoted"],
                # The twin-scorable projection of the same incidents.
                "twin_ground_truth_path": twin_gt_path,
                "twin_state_path": twin_state_path,
                "twin_records": len(twin_recs),
                "twin_score_cmd": (
                    f"python3 scripts/lab/twin/twin.py score --runid "
                    f"{self.runid} --run-root data/miniladder"),
            }
            log(f"scenario {gt['scenario']} seed={gt['seed']} "
                f"digest={gt['digest'][:16]} — {len(gt['incidents'])} incidents, "
                f"{gt['counts']['scenario_events']} planned events "
                f"({gt['counts']['state_transitions']} transitions, "
                f"{gt['counts']['recoveries']} recoveries) over "
                f"{gt['devices']['scenario']} devices; "
                f"{gt['devices']['noise_pool']} devices carry background")
            sh = gt["shape"]
            log(f"scenario shape {scen.shape.name!r} "
                f"digest={sh['target_digest'][:16]}: target storm share "
                f"{scen.shape.storm_share_of_raw:.2%}, achieved "
                f"{sh['achieved']['storm_share_of_raw']:.2%} "
                f"({sh['achieved']['storm_share_error_pct']:+.1f}%); "
                f"{sh['achieved']['signals']} promoted / "
                f"{sh['achieved']['unpromoted_events']} unpromotable; "
                f"K3 unique {sh['achieved']['unique']['K3']} "
                f"({sh['achieved']['reduction_pct']['K3']:.1f}% collapse); "
                f"chunk peak/mean {load['peak']}/{load['mean']} "
                f"({load['peak_over_mean']}x)")
            # 16.1: the symptoms the engine CANNOT see are stated up front,
            # not discovered in the scoring. A run whose T4 number ignores this
            # line is charging the engine for evidence it never received.
            if gt["not_promoted"]:
                log(f"scenario parser coverage: "
                    f"{gt['counts']['unpromotable_events']} of "
                    f"{gt['counts']['scenario_events']} planned lines PROVABLY "
                    f"do not promote (vendor-standard messages the classifier "
                    f"drops): {', '.join(gt['not_promoted'])} — product "
                    f"backlog, not a harness defect; TTUR/T4 may only be "
                    f"scored on the promoted symptoms")
            silent = scen.silent_devices()
            if silent:
                # Never silent about a silence (16.1): the run will still go
                # ahead, but the operator learns HERE why accounting is about
                # to report short device coverage.
                warn(f"scenario: {len(silent)} scenario device(s) got NO event "
                     f"inside the {int(self.args.burst_minutes * 60)}s window "
                     f"(e.g. {', '.join(silent[:5])}) — accounting's per-device "
                     f"corr_signals coverage WILL be short by that many; the "
                     f"scenario is mis-sized for this window")
        lanes = self._lane_states()
        t0 = time.monotonic()
        seq_global = 0
        scenario_injected = 0
        chunks: list[dict] = []
        bound_hit = False
        for idx, row in enumerate(plan):
            elapsed = time.monotonic() - t0
            if elapsed >= window_bound:
                # Out of window with chunks still unsent. Do NOT quietly
                # shrink the fleet — stop and report the shortfall.
                bound_hit = True
                break
            lines: list[str] = []
            detail: dict = {}
            sc_detail: dict = {}
            for ln in lanes:
                k = row[ln["name"]]
                pool = ln["pool"]
                if scen is not None and ln["name"] == scen_lane:
                    # The scenario's share of this chunk first, in its own
                    # deterministic order; the background then fills the rest
                    # of the ratified quota. Both halves are counted, so the
                    # balance equation is unchanged.
                    bucket = (scen.buckets[idx] if idx < len(scen.buckets)
                              else [])
                    for sev in bucket:
                        lines.append(self._scenario_line(sev, seq_global))
                        seq_global += 1
                    sc_detail[ln["name"]] = len(bucket)
                    k -= len(bucket)
                for _ in range(k):
                    dev_i = ln["seq"] % len(pool)
                    dev = pool[dev_i]
                    # Decorrelated mix index — see _syslog_event's docstring.
                    # Stride 31 is coprime to every table length (100/300/2000),
                    # so EVERY device cycles the WHOLE mix table with period
                    # len(table) regardless of pool size — a device reaches the
                    # classifying block within at most ~len(table)/31 rounds.
                    mix_seq = dev_i + 31 * (ln["seq"] // len(pool))
                    lines.append(self._syslog_event(dev, seq_global,
                                                    mix_name=ln["mix"],
                                                    mix_seq=mix_seq))
                    ln["seq"] += 1
                    seq_global += 1
                # The lane's tally is the RATIFIED quota, scenario + background
                # together — the balance equation counts injected events, not
                # where inside the chunk they came from.
                detail[ln["name"]] = row[ln["name"]]
            tp = time.monotonic()
            ok = True
            if lines:
                ok, err = self.stack.produce("netops.syslog", lines,
                                             key=self.producer_key)
                if not ok:
                    self.produce_failures.append(err)
                    if len(self.produce_failures) >= 3:
                        chunks.append({"i": idx, "t": round(elapsed, 1),
                                       "lanes": detail, "n": len(lines),
                                       "ok": False,
                                       "produce_s": round(time.monotonic() - tp, 2)})
                        break
                else:
                    # Only a chunk that reached the bus counts — towards the
                    # fleet, the lane tallies and the balance equation alike.
                    self.injected_total += len(lines)
                    fleet_injected += len(lines)
                    for ln in lanes:
                        ln["sent"] += detail[ln["name"]]
                    scenario_injected += sum(sc_detail.values())
            chunks.append({"i": idx, "t": round(elapsed, 1), "lanes": detail,
                           "scenario": sc_detail, "n": len(lines), "ok": ok,
                           "produce_s": round(time.monotonic() - tp, 2)})
            ahead = ((idx + 1) * chunk_secs) - (time.monotonic() - t0)
            if ahead > 0:
                time.sleep(ahead)
        self.burst_seconds = time.monotonic() - t0
        rate_achieved = fleet_injected / max(self.burst_seconds, 1e-9)
        actual_eps = self.injected_total / max(self.burst_seconds, 1e-9)
        shortfall = fleet_planned - fleet_injected
        ev.update({
            "workload_class": self.profile["workload_class"],
            "target_events": fleet_planned,
            # The workload contract, stated in three numbers: what the profile
            # ratified, what reached the bus, and how fast it got there.
            "fleet_planned": fleet_planned,
            "fleet_injected": fleet_injected,
            "fleet_shortfall": shortfall,
            "rate_achieved": round(rate_achieved, 1),
            "injected_total": self.injected_total,
            "burst_seconds": round(self.burst_seconds, 1),
            "window_s": duration,
            "window_bound_s": round(window_bound, 1),
            "window_extended": self.burst_seconds > duration + chunk_secs,
            "window_bound_exceeded": bound_hit,
            "actual_eps": round(actual_eps, 1),
            "producer_key_mode": self.args.producer_key,
            "chunks": len(chunks),
            "chunks_planned": len(plan),
            "lanes": {ln["name"]: {"devices": len(ln["pool"]), "mix": ln["mix"],
                                   "sent": ln["sent"]} for ln in lanes},
            "produce_failures": self.produce_failures,
        })
        if scen is not None:
            ev["scenario"] = {
                "name": scen.spec["name"],
                "seed": scen.seed,
                "digest": scen.digest(),
                "planned": len(scen.events),
                "injected": scenario_injected,
                "shortfall": len(scen.events) - scenario_injected,
                "background_injected": fleet_injected - scenario_injected,
                "ground_truth_file": GROUND_TRUTH_FILE,
                "twin_ground_truth_file": TWIN_GROUND_TRUTH_FILE,
                "unpromotable_injected": sum(
                    1 for b in scen.buckets for e in b if not e.symptom),
                "shape_name": scen.shape.name,
                "shape_digest": scen.shape.digest(),
                "storm_share_target": scen.shape.storm_share_of_raw,
                "storm_share_achieved": round(
                    len(scen.events) / max(1, fleet_planned), 6),
                "chunk_load": scen.chunk_load(),
            }
        self.evidence_file("burst-chunks.json", json.dumps(chunks, indent=1))
        if self.produce_failures:
            return self.phase("burst", "FAIL", ev,
                              f"{len(self.produce_failures)} produce failures — accounting "
                              f"would be dishonest (first: {self.produce_failures[0][:160]})")
        if shortfall > 0:
            return self.phase(
                "burst", "FAIL", ev,
                f"[{self.profile['workload_class']}] WORKLOAD TRUNCATED: injected "
                f"{fleet_injected} of the profile's ratified {fleet_planned} events "
                f"(shortfall {shortfall}; {len(chunks)} of {len(plan)} chunks) — the "
                f"injector sustained only ~{rate_achieved:.0f}/s over "
                f"{self.burst_seconds:.0f}s against a {duration}s window extended to a "
                f"{window_bound:.0f}s bound. A short fleet is a DIFFERENT experiment: "
                f"every TTUR/completion comparison downstream assumes this run's "
                f"workload is identical to the last one's")
        lane_txt = ", ".join(f"{ln['name']}={ln['sent']}" for ln in lanes)
        extended = ("" if not ev["window_extended"] else
                    f" [window extended {duration}s -> {self.burst_seconds:.0f}s, "
                    f"bound {window_bound:.0f}s]")
        return self.phase("burst", "PASS", ev,
                          f"[{self.profile['workload_class']}] injected "
                          f"fleet_injected={fleet_injected} of "
                          f"fleet_planned={fleet_planned} events in "
                          f"{self.burst_seconds:.0f}s (rate_achieved="
                          f"{rate_achieved:.0f}/s; {lane_txt}){extended}")

    def _burst_internal(self) -> bool:
        ev: dict = {}
        # Gate 1: registry propagation. The Go API rewrites device_tenant.csv
        # every ~60s; the engine reloads it on mtime change. Without this gate
        # every injected event is tenant-refused (identity_unattributable)
        # straight into the DLQ — proven live 2026-08-16.
        # TRACKER 161: a COUNT cannot prove the right identities are present.
        # On 2026-08-19 this gate passed at 2000 total identities while 73 of
        # THIS run's devices were absent from the registry, and every event they
        # produced was refused. Verify the identities we actually need.
        want = self.baseline.get("registry_identities", 0) + len(self.created_ids)
        deadline = time.monotonic() + 240
        current = -1
        missing: list[str] = []
        while time.monotonic() < deadline:
            hz = self.stack.corr_healthz()
            current = (hz.get("tenant_verification", {}).get("registry_identities", -1)
                       if isinstance(hz, dict) else -1)
            missing = self.stack.registry_missing(self.created_ids)
            if not missing and current >= want:
                break
            time.sleep(10)
        ev["registry_identities"] = {"want_at_least": want, "observed": current,
                                     "missing_identities": len(missing),
                                     "missing_sample": missing[:20]}
        if missing:
            return self.phase("burst", "FAIL", ev,
                              f"{len(missing)} of this run's {len(self.created_ids)} device "
                              f"identities are ABSENT from the correlation engine's registry "
                              f"after 240s (total identities {current}, which is why a "
                              f"count-only gate passed) — their events would be "
                              f"tenant-refused; aborting the burst")
        if current < want:
            return self.phase("burst", "FAIL", ev,
                              f"device registry never propagated to the correlation engine "
                              f"({current} < {want} after 240s) — injected events would be "
                              f"tenant-refused; aborting the burst")

        # Production-faithful keying (2026-08-22): resolve the tenant key from
        # the SAME registry the engine and Vector use, now that Gate 1 proved
        # this run's devices are in it. All of a run's devices share a tenant.
        self.producer_key = (None if self.args.producer_key == "none"
                             else self.stack.registry_tenant(self.created_ids[0]))
        ev["producer_key_mode"] = self.args.producer_key
        ev["producer_key"] = self.producer_key or ""

        # Gate 2: one canary through the whole pipe (topic -> engine -> CH).
        # The canary proves the PIPE, never the mix: it is ALWAYS the single
        # always-classifying %LINK-3-UPDOWN event, independent of the run's
        # profile. Under a promotion-realistic mix the run-mix event at the
        # fixed canary seq can land on a NOISE slot (999,999 % 2000 = 1999 —
        # exactly what failed the first T-nominal run, 08221806kefm): a canary
        # that classifies by luck of the modulus is not a gate.
        canary = self._canary_event()
        ok, err = self.stack.produce("netops.syslog", [canary], key=self.producer_key)
        if not ok:
            return self.phase("burst", "FAIL", ev, f"canary produce failed: {err}")
        self.injected_total += 1
        deadline = time.monotonic() + 150
        canary_seen = False
        while time.monotonic() < deadline:
            okq, out = self.stack.ch(
                f"SELECT count() FROM netops.corr_signals WHERE entity_id LIKE '%{self.prefix}%'")
            if okq and out.isdigit() and int(out) >= 1:
                canary_seen = True
                break
            time.sleep(10)
        ev["canary_signal_seen"] = canary_seen
        if not canary_seen:
            hz = self.stack.corr_healthz()
            ev["healthz_durability"] = hz.get("durability", hz)
            ev["dlq_run_lines"] = self.stack.dlq_run_lines(self.runid)
            return self.phase("burst", "FAIL", ev,
                              "canary event never produced a corr_signal within 150s — "
                              "pipeline broken between the bus and ClickHouse "
                              "(durability/DLQ evidence attached)")

        # Storm profiles take the multi-lane scheduled path; everything else
        # (legacy) keeps the historical single-lane loop below — the same
        # events in the same order, for continuity with the evidence trail.
        if self.profile.get("lanes"):
            return self._burst_lanes(ev)
        return self._burst_single_lane(ev)

    def _burst_single_lane(self, ev: dict) -> bool:
        """The historical single-lane loop (`--profile legacy`), under the same
        workload contract as the lane path: the fleet is eps x duration, a slow
        producer stretches the window up to the bound, and a fleet that is not
        whole FAILS rather than silently redefining the experiment."""
        # The burst proper: eps x 60 x minutes events, paced in chunks. Like
        # the lane path this is WORK-boxed — the fleet is eps x duration, a
        # fixed function of the args, and a slow producer stretches the window
        # (bounded) rather than shrinking the workload.
        chunk_secs = BURST_CHUNK_SECS
        duration = int(self.args.burst_minutes * 60)
        factor = max(1.0, float(getattr(self.args, "burst_window_factor",
                                        BURST_WINDOW_MAX_FACTOR)))
        window_bound = duration * factor
        target = self.args.eps * duration
        fleet_injected = 0
        seq = 0
        t0 = time.monotonic()
        chunks = []
        bound_hit = False
        while seq < target:
            if time.monotonic() - t0 >= window_bound:
                bound_hit = True
                break
            chunk_n = min(self.args.eps * chunk_secs, target - seq)
            lines = [self._syslog_event(self.created_ids[(seq + j) % len(self.created_ids)],
                                        seq + j)
                     for j in range(chunk_n)]
            tp = time.monotonic()
            ok, err = self.stack.produce("netops.syslog", lines,
                                         key=self.producer_key)
            if not ok:
                self.produce_failures.append(err)
                if len(self.produce_failures) >= 3:
                    break
            else:
                self.injected_total += chunk_n
                fleet_injected += chunk_n
            chunks.append({"n": chunk_n, "ok": ok, "produce_s": round(time.monotonic() - tp, 2)})
            seq += chunk_n
            # Pace to the wall clock; if production is slower than the target
            # rate we record the slippage rather than pretend.
            ahead = t0 + (seq / self.args.eps) - time.monotonic()
            if ahead > 0:
                time.sleep(ahead)
        self.burst_seconds = time.monotonic() - t0
        rate_achieved = fleet_injected / max(self.burst_seconds, 1e-9)
        actual_eps = self.injected_total / max(self.burst_seconds, 1e-9)
        shortfall = target - fleet_injected
        ev.update({
            "target_events": target, "injected_total": self.injected_total,
            "fleet_planned": target,
            "fleet_injected": fleet_injected,
            "fleet_shortfall": shortfall,
            "rate_achieved": round(rate_achieved, 1),
            "burst_seconds": round(self.burst_seconds, 1),
            "window_s": duration,
            "window_bound_s": round(window_bound, 1),
            "window_extended": self.burst_seconds > duration + chunk_secs,
            "window_bound_exceeded": bound_hit,
            "actual_eps": round(actual_eps, 1),
            "target_eps": self.args.eps,
            "event_mix": self.args.event_mix,
            "workload_class": self.profile["workload_class"],
            "producer_key_mode": self.args.producer_key,
            "chunks": len(chunks),
            "produce_failures": self.produce_failures,
        })
        self.evidence_file("burst-chunks.json", json.dumps(chunks, indent=1))
        if self.produce_failures:
            return self.phase("burst", "FAIL", ev,
                              f"{len(self.produce_failures)} produce failures — accounting "
                              f"would be dishonest (first: {self.produce_failures[0][:160]})")
        if shortfall > 0:
            return self.phase(
                "burst", "FAIL", ev,
                f"WORKLOAD TRUNCATED: injected {fleet_injected} of the planned "
                f"{target} events (shortfall {shortfall}) — the injector sustained "
                f"only ~{rate_achieved:.0f}/s against a target {self.args.eps}/s over "
                f"{self.burst_seconds:.0f}s, past the {window_bound:.0f}s bound on a "
                f"{duration}s window. A short fleet is a DIFFERENT experiment: every "
                f"comparison downstream assumes an identical workload")
        extended = ("" if not ev["window_extended"] else
                    f" [window extended {duration}s -> {self.burst_seconds:.0f}s, "
                    f"bound {window_bound:.0f}s]")
        return self.phase("burst", "PASS", ev,
                          f"injected fleet_injected={fleet_injected} of "
                          f"fleet_planned={target} events in {self.burst_seconds:.0f}s "
                          f"(rate_achieved={rate_achieved:.0f}/s, target "
                          f"{self.args.eps}/s){extended}")

    # -- phase 4: drain ------------------------------------------------------
    def drain(self) -> bool:
        base = max(self.baseline.get("corr_lag_total", 0), 0)
        eps = self.args.lag_epsilon
        budget = max(self.args.drain_factor * self.burst_seconds, 120.0)
        t0 = time.monotonic()
        curve = []
        drained_at = None
        while time.monotonic() - t0 < budget:
            lag = self.stack.group_lag("netops-correlation")
            total = lag.get("_total", -1)
            curve.append({"t_s": round(time.monotonic() - t0, 1), "lag": total,
                          "members": lag.get("_members", 0)})
            if 0 <= total <= base + eps:
                drained_at = time.monotonic() - t0
                break
            time.sleep(10)
        self.evidence_file("lag-curve.json", json.dumps(curve, indent=1))
        ev = {"baseline_lag": base, "epsilon": eps,
              "budget_s": round(budget, 0),
              "drained_at_s": round(drained_at, 1) if drained_at is not None else None,
              "samples": len(curve),
              "peak_lag": max((c["lag"] for c in curve), default=-1),
              "final_lag": curve[-1]["lag"] if curve else -1,
              "curve_file": "lag-curve.json"}
        if drained_at is None:
            # Automatic first-cut diagnosis: a consumer thrashing on
            # max_poll_interval rebalances (CommitFailed -> UnknownMemberId ->
            # rejoin -> reprocess) is the most likely shape of this failure —
            # count the tell-tale log lines so the report carries the WHY.
            cc = self.stack.cid("correlation")
            if cc:
                since = f"{int(budget) + int(self.burst_seconds) + 120}s"
                rc, out, err2 = run(["docker", "logs", "--since", since, cc], 60)
                blob = out + err2 if rc == 0 else ""
                ev["rebalance_diagnosis"] = {
                    "commit_failed": blob.count("CommitFailedError"),
                    "unknown_member": blob.count("UnknownMemberIdError"),
                    "consumer_restarts": blob.count("consumer failed; restarting"),
                }
            return self.phase("drain", "FAIL", ev,
                              f"consumer lag NEVER returned to <= {base}+{eps} within "
                              f"{budget:.0f}s (final {ev['final_lag']}) — the "
                              f"'lag never drains' defect class "
                              f"(rebalance diagnosis in evidence)")
        # TRACKER 170: this phase proves TRANSPORT drain only — the consumer has
        # read the backlog off Kafka and committed. It says nothing about whether
        # the correlation engine has EVALUATED any of it: the consumer buffers
        # into the engine's window and commits, so lag returns to baseline while
        # the RCA workload is still entirely pending. Run 082120173zup drained in
        # 56s of a 2160s budget with 127,247 of 131,041 signals unevaluated.
        # Correlation completion is a separate, later gate.
        ev["proves"] = "kafka_transport_drain_only"
        return self.phase("drain", "PASS", ev,
                          f"KAFKA TRANSPORT lag drained to baseline+eps in "
                          f"{drained_at:.0f}s (budget {budget:.0f}s, peak "
                          f"{ev['peak_lag']}) — transport only; correlation "
                          f"evaluation is gated separately")

    # -- phase 5b: CORRELATION COMPLETION (tracker 170) ----------------------
    #
    # THE FALSE-GREEN THIS EXISTS TO KILL (run 082120173zup, 2026-08-21). The
    # harness returned PASS on all eight phases while the correlation engine had
    # evaluated 3% of the workload:
    #
    #   drain      PASS — Kafka consumer lag drained in 56s. TRUE, and irrelevant:
    #                     the consumer buffers into the engine's window and
    #                     commits. Transport drain is not evaluation.
    #   accounting PASS — 131,041 == 131,041 corr_signals rows + 0 DLQ. TRUE, and
    #                     irrelevant: those rows are written by handle_syslog on
    #                     the INGEST path, before the engine ever sees them.
    #
    #   reality    1 and 2 cohorts completed on the two replicas, 127,247 signals
    #              never evaluated, pending frozen at 66,179/61,068, oldest
    #              pending 700s against a 516.527s horizon.
    #
    # Neither existing gate is wrong about what it measures. Both were being read
    # as something they never claimed. This phase makes the missing claim.
    #
    # WHAT COMPLETION MEANS HERE, and why each clause is load-bearing:
    #   pending_sum == 0        across ALL replicas — one idle replica proves
    #                           nothing when its partner holds the backlog.
    #   cohorts advanced        strictly, versus the preflight baseline — proves
    #                           the engine did work FOR THIS RUN rather than
    #                           being idle throughout (an engine that never
    #                           started also reports pending 0).
    #   oldest age at idle      the worst replica, back near zero — pending can
    #                           read 0 for an instant mid-drain.
    #   identity unchanged      same containers, same start times — a restarted
    #                           engine reports pending 0 with reset counters,
    #                           which is indistinguishable from "finished".
    #   every replica readable  an unreadable replica is UNKNOWN, never idle.
    def _corr_mem_track(self, state: dict, t_s: float, now: float) -> None:
        """Per-replica RSS beside per-replica pending, one row per poll.

        memflat's correlation clause needs an anchor the ENGINE defines, not
        the injector: the first sample at which THIS replica reports
        `corr_engine_pending == 0`. Everything before that instant is backlog
        drain — the engine is still building objects for work it accepted
        before input stopped, and a working set that grows there is work, not a
        leak (run p2-s05-08291138: 22,736 signals still pending when the old
        anchor was taken, and memflat called the next 177 MiB a leak).

        A pending that returns ABOVE zero after reaching it re-arms the anchor:
        the completion gate itself notes that pending "can read 0 for an
        instant mid-drain", and anchoring on such an instant would recreate the
        very defect. The reset count rides in the evidence.
        """
        for cid_, r in (state.get("per_replica") or {}).items():
            key = r.get("name") or cid_
            pending = float(r.get("pending", -1.0))
            rss = int(r.get("rss", -1))
            row = self.corr_mem_track.setdefault(key, {
                "container": key, "samples": 0, "pending_zero_resets": 0,
                "pending_zero_t_s": None, "pending_zero_monotonic": None,
                "rss_at_pending_zero": -1, "last_pending": -1.0,
                "last_rss": -1, "last_t_s": 0.0,
                # What the engine was still holding when the completion phase
                # opened — i.e. how much of the "growth after input stopped"
                # the old anchor was charging to a leak.
                "first_pending": pending, "first_rss": rss})
            row["samples"] += 1
            row["last_pending"] = pending
            row["last_rss"] = rss
            row["last_t_s"] = round(t_s, 1)
            if row["pending_zero_monotonic"] is None:
                # -1.0 is UNREADABLE, never idle: only an exact 0 anchors, and
                # only against an RSS reading that actually succeeded.
                if pending == 0.0 and rss > 0:
                    row["pending_zero_t_s"] = round(t_s, 1)
                    row["pending_zero_monotonic"] = now
                    row["rss_at_pending_zero"] = rss
            elif pending > 0.0:
                row["pending_zero_resets"] += 1
                row["pending_zero_t_s"] = None
                row["pending_zero_monotonic"] = None
                row["rss_at_pending_zero"] = -1

    def correlation_completion(self) -> bool:
        base = self.baseline.get("corr_completion") or {}
        budget = max(self.args.drain_factor * self.burst_seconds, 120.0)
        idle_age = CORR_IDLE_AGE_S
        t0 = time.monotonic()
        state: dict = {}
        curve: list[dict] = []
        completed_at = None
        while True:
            state = self.stack.corr_completion_state()
            now = time.monotonic()
            self._corr_mem_track(state, now - t0, now)
            curve.append({"t_s": round(now - t0, 1),
                          "pending": state["pending_sum"],
                          "cohorts": state["cohorts_sum"],
                          "oldest_age_s": state["oldest_pending_age_max"],
                          # memflat's leak anchor rides in the same curve, so a
                          # finished run can be re-scored from its evidence.
                          "per_replica": {
                              (r.get("name") or c): {
                                  "pending": r.get("pending", -1.0),
                                  "rss": r.get("rss", -1)}
                              for c, r in (state.get("per_replica") or {}).items()}})
            advanced = state["cohorts_sum"] - float(base.get("cohorts_sum", 0) or 0)
            if (state["readable"] == state["replicas"] and state["replicas"] > 0
                    and state["pending_sum"] == 0
                    and 0 <= state["oldest_pending_age_max"] <= idle_age
                    and advanced > 0):
                completed_at = time.monotonic() - t0
                break
            if time.monotonic() - t0 >= budget:
                break
            time.sleep(10)

        self.evidence_file("correlation-completion.json", json.dumps(curve, indent=1))
        advanced = state["cohorts_sum"] - float(base.get("cohorts_sum", 0) or 0)
        ev = {
            "budget_s": round(budget, 0),
            "completed_at_s": round(completed_at, 1) if completed_at is not None else None,
            "idle_age_threshold_s": idle_age,
            "baseline": {k: base.get(k) for k in
                         ("pending_sum", "cohorts_sum", "replicas", "readable")},
            "baseline_per_replica": base.get("per_replica", {}),
            "final": state,
            "cohorts_advanced": advanced,
            "samples": len(curve),
            "curve_file": "correlation-completion.json",
            "proves": "correlation_engine_evaluated_the_workload",
            # memflat's leak anchor, derived here because this is the only
            # phase that watches the engine drain (see _corr_mem_track).
            "memory_anchor": {k: dict(v) for k, v in self.corr_mem_track.items()},
        }

        problems: list[str] = []
        if state["replicas"] == 0:
            problems.append("no correlation replicas found — completion unknowable")
        if state["unreadable"]:
            problems.append(
                f"{len(state['unreadable'])} replica(s) unreadable "
                f"({', '.join(str(u) for u in state['unreadable'])}) — an "
                f"unreadable engine is UNKNOWN, never idle: {state['errors']}")
        # Restart/reset detection (mutant 7): a restarted engine reports pending 0
        # and reset counters, which reads exactly like a finished one.
        base_ids = set(base.get("per_replica") or {})
        now_ids = set(state.get("per_replica") or {})
        if base_ids and base_ids != now_ids:
            problems.append(
                f"correlation replica set changed during the run "
                f"({sorted(base_ids)} -> {sorted(now_ids)}) — completion cannot "
                f"be established across a restart")
        else:
            for cid_, b in (base.get("per_replica") or {}).items():
                n = (state.get("per_replica") or {}).get(cid_)
                if n and b.get("started_at") and n.get("started_at") != b.get("started_at"):
                    problems.append(
                        f"replica {cid_} RESTARTED mid-run "
                        f"({b['started_at']} -> {n['started_at']}) — its zeroed "
                        f"counters are not evidence of completion")
        if advanced <= 0:
            problems.append(
                f"correlation cohorts did not advance (baseline "
                f"{base.get('cohorts_sum')}, final {state['cohorts_sum']}) — the "
                f"engine did no work attributable to this run")
        if completed_at is None:
            problems.append(
                f"correlation engine INCOMPLETE after {budget:.0f}s: "
                f"pending={state['pending_sum']:.0f} "
                f"oldest_pending_age={state['oldest_pending_age_max']:.1f}s "
                f"cohorts_delta={advanced:.0f}")

        # ── 2026-08-29 (run p2-s012-08290116): "the engine went idle" is not
        # "the engine evaluated the workload". A ValueError raised by the
        # engine's own WORK ACCOUNTING, inside the cohort loop's
        # `except ValueError: continue`, discarded every tenant's snapshots
        # while `_mark_processed` still advanced the frontier. Pending drained
        # to 0, cohorts advanced, and this gate PASSED in 14 s on a run that
        # produced zero incidents. Both clauses below read PER REPLICA — a
        # cross-replica sum would let a healthy replica mask a broken partner —
        # and an unreadable counter is UNKNOWN, which is never PASS.
        base_per: dict = base.get("per_replica") or {}
        final_per: dict = state.get("per_replica") or {}
        counter_deltas: dict[str, dict[str, float]] = {}
        # CLAUSE 1: an engine that rejected a window, or faulted inside its own
        # accounting, did not evaluate everything it was handed.
        for cid_ in sorted(final_per):
            n, b = final_per[cid_], (base_per.get(cid_) or {})
            row: dict[str, float] = {}
            for key, series, cost in (
                    ("windows_rejected", "corr_engine_windows_rejected_total",
                     "tenant window(s) rejected — that evidence was discarded"),
                    ("profiler_errors", "corr_engine_profiler_errors_total",
                     ("profiler/accounting fault(s) — this run's own numbers "
                      "are incomplete"))):
                nv, bv = float(n.get(key, -1.0)), float(b.get(key, -1.0))
                if nv < 0 or bv < 0:
                    problems.append(
                        f"replica {cid_} does not export {series} "
                        f"(baseline={bv:.0f}, final={nv:.0f}) — whether the "
                        f"engine discarded evidence is UNKNOWN, and UNKNOWN is "
                        f"never PASS (engine image too old for this gate?)")
                    continue
                row[key] = nv - bv
                if nv > bv:
                    dropped = float(n.get("signals_dropped_window_rejected", -1.0))
                    problems.append(
                        f"replica {cid_} {series} rose {bv:.0f} -> {nv:.0f} "
                        f"during the run: {nv - bv:.0f} {cost} "
                        f"(signals_dropped{{reason=window_rejected}}="
                        f"{dropped:.0f}) — completion here is not evaluation")
            counter_deltas[cid_] = row
        # CLAUSE 2: HOLLOW COMPLETION. Cohorts advanced but nothing was
        # persisted on the replica that drained them — the exact signature of
        # snapshots computed and then thrown away.
        for cid_ in sorted(final_per):
            n, b = final_per[cid_], (base_per.get(cid_) or {})
            nvc = float(n.get("cohorts_total", -1.0))
            bvc = float(b.get("cohorts_total", -1.0))
            if nvc < 0 or bvc < 0:
                # ── ultra #24 (2026-08-31): an unreadable cohorts_total used
                # to flow into `cohorts_delta` as -1, land in the `<= 0`
                # "drained nothing to judge" continue, and silently EXEMPT this
                # replica from the hollow-completion clause — on exactly the
                # replica it cannot vouch for. Tracker-170's own rule applies
                # here too: UNKNOWN is never PASS.
                problems.append(
                    f"replica {cid_} corr_engine_cohorts_total is unreadable "
                    f"(baseline={bvc:.0f}, final={nvc:.0f}) — whether this "
                    f"replica drained cohorts is UNKNOWN, so the "
                    f"hollow-completion clause cannot be evaluated, and "
                    f"UNKNOWN is never PASS")
                continue
            cohorts_delta = nvc - bvc
            if cohorts_delta <= 0:
                continue            # this replica drained nothing to judge
            nv, bv = (float(n.get("versions_persisted", -1.0)),
                      float(b.get("versions_persisted", -1.0)))
            counter_deltas.setdefault(cid_, {})["cohorts"] = cohorts_delta
            if nv < 0 or bv < 0:
                problems.append(
                    f"replica {cid_} drained {cohorts_delta:.0f} cohort(s) but "
                    f'corr_versions{{outcome="persisted"}} is unreadable '
                    f"(baseline={bv:.0f}, final={nv:.0f}) — whether anything "
                    f"was produced is UNKNOWN, and UNKNOWN is never PASS")
                continue
            counter_deltas[cid_]["versions_persisted"] = nv - bv
            if nv <= bv:
                damped = (float(n.get("versions_damped", -1.0))
                          - float(b.get("versions_damped", -1.0)))
                problems.append(
                    f"HOLLOW COMPLETION: replica {cid_} drained "
                    f"{cohorts_delta:.0f} cohort(s) and persisted NOTHING "
                    f'(corr_versions{{outcome="persisted"}} {bv:.0f} -> '
                    f"{nv:.0f}, damped delta {damped:.0f}) — the frontier "
                    f"advanced over evidence that produced no object")
        ev["counter_deltas"] = counter_deltas
        # `proves` is the phase's original claim and stays exactly what it was;
        # this is the second, independent claim the 2026-08-29 clauses add.
        ev["also_proves"] = ("no_window_was_rejected_and_the_cohorts_that_"
                             "drained_persisted_objects")

        def _sum(field: str) -> float:
            return sum(r.get(field, 0.0) for r in counter_deltas.values())

        counters = (f"windows_rejected +{_sum('windows_rejected'):.0f}, "
                    f"profiler_errors +{_sum('profiler_errors'):.0f}, "
                    f"versions_persisted +{_sum('versions_persisted'):.0f}")
        if problems:
            return self.phase("correlation_completion", "FAIL", ev,
                              "; ".join(problems) + f" [{counters}]")
        return self.phase(
            "correlation_completion", "PASS", ev,
            f"engine evaluated the workload in {completed_at:.0f}s "
            f"(budget {budget:.0f}s): pending 0 across {state['replicas']} "
            f"replica(s), cohorts +{advanced:.0f}, oldest pending age "
            f"{state['oldest_pending_age_max']:.1f}s, {counters}")

    # -- phase 6: consumer stability (whole lifecycle) -----------------------
    #
    # THE FALSE-GREEN THIS REPLACES (2026-08-20). Stability was diagnosed only
    # inside `if drained_at is None:` — so a PASSING drain collected no evidence
    # at all — from `docker logs --since <burst+drain>` on a SINGLE replica.
    # Run 08192339borh reported commit_failed=0 while three CommitFailedError
    # events occurred at 00:01:34, 00:04:42 and 00:08:15, after the window
    # closed. A gate whose observation ends before the failure mode appears is
    # not a gate.
    #
    # Stability is now observed across burst -> drain -> settlement -> a
    # post-settlement grace period, over EVERY replica, and it is collected
    # whether or not drain passed.

    # Regexes matched per LINE, not substring counts. One aiokafka traceback
    # contains "CommitFailedError" twice (`raise Errors.CommitFailedError(` and
    # `aiokafka.errors.CommitFailedError: ...`), so substring counting reported
    # two events for one. Each pattern therefore anchors on the single line that
    # REPORTS the event. Over-counting fails safe but makes the number useless
    # for tracking whether a fix worked.
    STABILITY_PATTERNS: typing.ClassVar[dict] = {
        "commit_failed": r"aiokafka\.errors\.CommitFailedError",
        "unknown_member": r"aiokafka\.errors\.UnknownMemberIdError|UnknownMemberIdError:",
        "consumer_restarts": r"consumer failed; restarting",
        "rebalances": r"rebalance #\d+",
        "loop_stalls": r"event loop STALLED",
    }

    @staticmethod
    def stability_counters(blobs: dict) -> dict:
        """Count instability markers across every replica's log blob.

        Pure so it can be unit-tested and mutation-tested without a stack.
        `blobs` is {container_id: log text}. A container whose logs could not be
        read must arrive as None, and is reported as UNREADABLE rather than
        silently counted as zero — missing evidence is not a clean result.
        """
        out = {k: 0 for k in Harness.STABILITY_PATTERNS}
        out["worst_loop_lag_ms"] = 0
        out["replicas_observed"] = 0
        out["replicas_unreadable"] = 0
        for _cid, blob in sorted(blobs.items()):
            if blob is None:
                out["replicas_unreadable"] += 1
                continue
            out["replicas_observed"] += 1
            for key, pattern in Harness.STABILITY_PATTERNS.items():
                rx = re.compile(pattern)
                out[key] += sum(1 for line in blob.splitlines() if rx.search(line))
            for m in re.finditer(r"worst=(\d+)ms", blob):
                out["worst_loop_lag_ms"] = max(out["worst_loop_lag_ms"], int(m.group(1)))
        return out

    @staticmethod
    def session_timeout_from_replicas(reps: list,
                                     override: int | None = None) -> tuple:
        """(session_timeout_ms | None, derivation) — TRACKER 190.

        The live Kafka session timeout the correlation members run with, taken
        from `corr_session_timeout_ms` on EVERY readable replica's /metrics —
        the same scrape `corr_completion_state` already performs, so this costs
        no extra probe.

        `None` is returned — and the caller must treat the loop-stall clause as
        UNKNOWN, which is not PASS — whenever the value cannot be established:
        no replica was read, the gauge is absent from any readable replica (an
        engine image older than the gauge), or the replicas DISAGREE (a
        half-rolled deploy: the group's real eviction point is then the SMALLEST
        of them, and guessing which member the stall belonged to is exactly the
        assumption this exists to remove).

        An explicit `MLX_KAFKA_SESSION_TIMEOUT_MS` override always wins, but the
        derivation string says so and still reports what the replicas showed —
        an override that silently contradicts the running engine is the original
        defect wearing a different hat.

        Pure: `reps` is the list `Stack.corr_replicas()` returns, so every
        branch is unit-testable without a stack.
        """
        readable = [r for r in reps if "metrics" in r]
        seen: dict = {}
        absent: list = []
        for r in readable:
            raw = r["metrics"].get(SESSION_TIMEOUT_GAUGE)
            name = r.get("container") or r.get("name") or "?"
            if raw is None:
                absent.append(name)
            else:
                seen[name] = int(raw)
        values = sorted(set(seen.values()))

        if not reps:
            observed = "no correlation replica was read"
        elif not readable:
            observed = f"none of {len(reps)} replica(s) could be scraped"
        elif absent and not values:
            observed = (f"{SESSION_TIMEOUT_GAUGE} absent from all "
                        f"{len(readable)} readable replica(s) — engine image "
                        f"predates the gauge")
        elif absent:
            observed = (f"{SESSION_TIMEOUT_GAUGE} absent from "
                        f"{len(absent)} of {len(readable)} readable replica(s) "
                        f"({', '.join(sorted(absent))}); the rest read "
                        f"{'/'.join(str(v) for v in values)}ms")
        elif len(values) > 1:
            observed = ("replicas DISAGREE on " + SESSION_TIMEOUT_GAUGE + ": " +
                        ", ".join(f"{k}={v}ms" for k, v in sorted(seen.items())))
        else:
            observed = (f"session timeout {values[0]}ms read from "
                        f"{len(seen)} replica(s)")

        if override is not None:
            return override, (f"override MLX_KAFKA_SESSION_TIMEOUT_MS="
                              f"{override}ms (replicas: {observed})")
        if len(values) == 1 and not absent and readable:
            return values[0], observed
        return None, observed

    @staticmethod
    def stability_verdict(counters: dict, session_timeout_ms: int | None,
                          derivation: str = "") -> list:
        """Which counters are disqualifying. Pure; returns a list of problems."""
        problems = []
        if counters.get("replicas_observed", 0) == 0:
            problems.append("no replica logs could be read — stability is UNKNOWN, "
                            "which is not PASS")
        if counters.get("replicas_unreadable", 0):
            problems.append(f"{counters['replicas_unreadable']} replica log(s) "
                            f"unreadable — incomplete evidence, not a clean run")
        for key, label in (("commit_failed", "CommitFailedError"),
                           ("unknown_member", "UnknownMemberIdError"),
                           ("consumer_restarts", "consumer restarts")):
            if counters.get(key, 0):
                problems.append(f"{counters[key]} {label} event(s) across the full "
                                f"lifecycle")
        worst = counters.get("worst_loop_lag_ms", 0)
        if session_timeout_ms is None:
            # UNKNOWN, and UNKNOWN IS NOT PASS — the same rule the unreadable-
            # replica clause follows. Never fall back to a constant: a threshold
            # nobody published is what tracker 190 exists to delete.
            problems.append(
                f"Kafka session timeout is UNKNOWN ({derivation}) — the "
                f"worst-stall clause cannot be evaluated (worst observed "
                f"{worst}ms); set MLX_KAFKA_SESSION_TIMEOUT_MS to state it "
                f"explicitly, or run an engine that exports "
                f"{SESSION_TIMEOUT_GAUGE}")
        elif worst >= session_timeout_ms:
            problems.append(
                f"worst event-loop stall {worst}ms EXCEEDS the {session_timeout_ms}ms "
                f"Kafka session timeout — the member can be ejected mid-stall")
        return problems

    # ── ultra #23 (2026-08-31): the lag-settle window must never read an
    # UNREADABLE consumer group as a settled one. `group_lag` answers
    # `_total: -1` when `kafka-consumer-groups.sh --describe` itself fails, and
    # two consecutive -1 readings are byte-identical — the old loop counted
    # them as "lag stopped moving" and reported settled=True on a group it
    # never actually read. Both helpers are pure so the arithmetic is unit- and
    # mutation-testable without a stack.
    @staticmethod
    def settle_step(last: float | None, total: float | None, stable_for: float,
                    epsilon: float, step_s: float = 15.0) -> tuple:
        """One poll of the settle loop -> (last, stable_for, readable).

        A negative (or absent) total is an UNREADABLE group, not a lag value:
        it contributes no stability AND invalidates the previous reading, so
        settlement must be re-established by consecutive REAL readings.
        """
        if total is None or total < 0:
            return None, 0.0, False
        if last is not None and abs(total - last) <= epsilon:
            return total, stable_for + step_s, True
        return total, 0.0, True

    @staticmethod
    def settle_lag_problems(lag_at_settlement: float | None,
                            unreadable_polls: int) -> list:
        """Disqualifying settle facts (pure). UNKNOWN is never PASS: a settle
        window that ended without a readable lag total cannot claim the group
        settled — the problem line names the unreadable source instead of
        letting -1 == -1 read as stable."""
        if lag_at_settlement is None or lag_at_settlement < 0:
            return [(
                f"consumer-group lag for netops-correlation was UNREADABLE at "
                f"settlement ({unreadable_polls} unreadable poll(s); group_lag "
                f"_total=-1 means the describe FAILED, not zero lag) — whether "
                f"the group settled is UNKNOWN, and UNKNOWN is never PASS")]
        return []

    def collect_stability_blobs(self, now: float | None = None) -> tuple:
        """(blobs, since_s) — one log blob per correlation replica.

        Two properties this exists to make testable, because both were the
        original defect and neither is visible from the pure counters:
          * the window spans from `stability_t0` (burst start), not from the
            end of drain, so a failure that appears late is inside it;
          * EVERY replica is read, not `cid()`'s first one.
        A replica whose logs cannot be read maps to None so the counters can
        report it unreadable rather than silently clean.
        """
        now = time.monotonic() if now is None else now
        since = int(now - self.stability_t0) + 60
        blobs = {}
        for cc in self.stack.cids("correlation"):
            rc, out, err2 = run(["docker", "logs", "--since", f"{since}s", cc], 120)
            blobs[cc] = (out + err2) if rc == 0 else None
        return blobs, since

    def stability(self) -> bool:
        """Observe consumer stability across the WHOLE lifecycle."""
        ev: dict = {}
        grace = STABILITY_GRACE_S
        # Settle first: wait for lag to stop moving, then observe the grace
        # window, so a failure that only appears after settlement is inside the
        # observation rather than after it.
        deadline = time.monotonic() + STABILITY_SETTLE_MAX_S
        last = None
        stable_for = 0.0
        unreadable_polls = 0
        while time.monotonic() < deadline:
            total = self.stack.group_lag("netops-correlation").get("_total", -1)
            last, stable_for, readable = self.settle_step(
                last, total, stable_for, self.args.lag_epsilon)
            if not readable:
                unreadable_polls += 1
            if stable_for >= 45.0:
                break
            time.sleep(15)
        ev["lag_at_settlement"] = last if last is not None else -1
        ev["lag_unreadable_polls"] = unreadable_polls
        ev["settled"] = stable_for >= 45.0
        log(f"stability: settled={ev['settled']} lag={last} "
            f"(unreadable polls {unreadable_polls}); observing {grace:.0f}s grace")
        time.sleep(grace)

        blobs, since = self.collect_stability_blobs()
        counters = self.stability_counters(blobs)
        ev.update(counters)
        ev["observation_window_s"] = since
        ev["grace_s"] = grace
        # TRACKER 190: the threshold comes from the ENGINE, read off the same
        # replicas the completion gate scrapes — never from a constant here.
        reps = self.stack.corr_replicas()
        timeout_ms, derivation = self.session_timeout_from_replicas(
            reps, KAFKA_SESSION_TIMEOUT_OVERRIDE_MS)
        ev["session_timeout_ms"] = timeout_ms if timeout_ms is not None else -1
        ev["session_timeout_derivation"] = derivation
        ev["session_timeout_override"] = KAFKA_SESSION_TIMEOUT_OVERRIDE_MS
        ev["session_timeout_per_replica"] = {
            (r.get("container") or "?"):
                r.get("metrics", {}).get(SESSION_TIMEOUT_GAUGE, -1.0)
            for r in reps}
        problems = (self.settle_lag_problems(last, unreadable_polls)
                    + self.stability_verdict(counters, timeout_ms, derivation))
        # INFORMATIONAL ONLY (never a gate): how much of the membership budget
        # the worst stall actually ate. A run well inside the timeout can still
        # be trending, and the number is worth carrying in the report — but the
        # gate stays the ejection point, not a tighter budget somebody picked.
        worst = counters["worst_loop_lag_ms"]
        if timeout_ms:
            ev["stall_budget_used_pct"] = round(100.0 * worst / timeout_ms, 1)
            headroom = (f", worst loop stall {worst}ms = "
                        f"{ev['stall_budget_used_pct']}% of the session timeout")
        else:
            headroom = f", worst loop stall {worst}ms"
        status = "PASS" if not problems else "FAIL"
        return self.phase("stability", status, ev,
                          ("; ".join(problems) + f" [{derivation}]") if problems else
                          f"clean across the full lifecycle ({since}s, "
                          f"{counters['replicas_observed']} replica(s)): 0 CommitFailed, "
                          f"0 UnknownMember, 0 restarts, {derivation}{headroom}")

    # -- phase 5: accounting -------------------------------------------------
    def accounting(self) -> bool:
        ev: dict = {}
        # Settle: the router must have consumed everything we injected before
        # OS counts are meaningful; then wait for the OS count to go stable
        # (bulk flush + refresh).
        deadline = time.monotonic() + 240
        router_total = -1
        while time.monotonic() < deadline:
            router = self.stack.group_lag("netops-router-syslog")
            router_total = router.get("_total", -1)
            if 0 <= router_total <= max(self.baseline.get("router_lag_total", 0), 0) + 10:
                break
            time.sleep(10)
        ev["router_lag_at_settle"] = router_total

        prev = -1
        os_docs = -1
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            os_docs = self.stack.os_count("netops-syslog-*", "hostname.keyword", self.acct_prefix)
            if os_docs >= 0 and os_docs == prev:
                break
            prev = os_docs
            time.sleep(15)

        dlq_run = self.stack.dlq_run_lines(self.acct_runid)
        discards = self.stack.vm_query(
            'sum(vector_component_discarded_events_total{intentional="false"})')
        dl_sent = self.stack.vm_query(
            'sum(vector_component_sent_events_total{component_id=~"opensearch_deadletter|kafka_deadletter"})')
        d_discards = (discards - self.baseline.get("vector_discards", 0)
                      if discards >= 0 and self.baseline.get("vector_discards", -1) >= 0 else -1)
        d_dl = (dl_sent - self.baseline.get("vector_deadletter_sent", 0)
                if dl_sent >= 0 and self.baseline.get("vector_deadletter_sent", -1) >= 0 else -1)

        hz = self.stack.corr_healthz()
        dur = hz.get("durability", {}) if isinstance(hz, dict) else {}
        qwf_now = dur.get("quarantine_write_failures", -1)
        qwf_base = self.baseline.get("quarantine_write_failures", -1)
        d_qwf = qwf_now - qwf_base if qwf_now >= 0 and qwf_base >= 0 else -1
        ch_fail = dur.get("ch_insert_failures", {})

        twin_mode = getattr(self.args, "load_generator", "internal") == "twin"
        if twin_mode:
            # twin device names are not numeric — count devices by stripping
            # the entity's :interface suffix under the twin prefix.
            okq, out = self.stack.ch(
                "SELECT uniqExact(extract(entity_id, "
                f"'{self.acct_prefix}[A-Za-z0-9_.-]+')) "
                f"FROM netops.corr_signals WHERE entity_id LIKE "
                f"'%{self.acct_prefix}%'")
        else:
            okq, out = self.stack.ch(
                "SELECT uniqExact(extract(entity_id, 'mlx-[a-z0-9]+-[0-9]+')) "
                f"FROM netops.corr_signals WHERE entity_id LIKE '%{self.prefix}%'")
        entities = int(out) if okq and out.isdigit() else -1
        okq2, out2 = self.stack.ch(
            f"SELECT count() FROM netops.corr_signals WHERE entity_id LIKE '%{self.acct_prefix}%'")
        signal_rows = int(out2) if okq2 and out2.isdigit() else -1

        # The equation. Each term and what it honestly counts:
        #   injected_total   events this run produced to netops.syslog
        #                    (producer exited 0; canary included).
        #   os_docs          EXACT run docs in netops-syslog-* (prefix query
        #                    on hostname.keyword) — the raw lane is 1:1 with
        #                    injected events, no dedup window applies.
        #   dlq_run          EXACT run-attributable correlation DLQ lines
        #                    (payload carries the device hostname).
        #   d_discards/d_dl  Vector's honest loss counters, STACK-WIDE deltas:
        #                    they cannot be attributed to the run, so organic
        #                    traffic can inflate them — they may only ever
        #                    OVER-explain a deficit, never mask a surplus.
        # PASS = no unexplained loss: injected - os_docs <= counted losses,
        # with zero counted losses required to call the pipeline lossless.
        missing = self.injected_total - os_docs if os_docs >= 0 else -1
        explained = max(d_discards, 0) + max(d_dl, 0) + max(dlq_run, 0)
        problems = []
        if os_docs < 0:
            problems.append("OpenSearch run-doc count unavailable")
        elif missing < 0:
            problems.append(
                f"MORE docs ({os_docs}) than injected ({self.injected_total}) — "
                f"duplication or runid collision")
        elif missing > 0 and missing > explained:
            problems.append(
                f"{missing} events UNEXPLAINED (injected {self.injected_total}, "
                f"persisted {os_docs}, counted losses {explained}) — silent drop")
        elif missing > 0:
            problems.append(
                f"{missing} events lost but explicitly counted "
                f"(discards {d_discards:.0f}, deadletter {d_dl:.0f}, DLQ {dlq_run}) — "
                f"loss is visible, but a lossless pipeline is the bar")
        # TRACKER 159. A non-empty DLQ is not automatically a defect: the
        # zero-trust tenant check refuses events it cannot attribute, counts
        # them, and seals the payload (§3a). Failing on the raw count made this
        # gate unpassable — the lab carries a standing ~2/s background of
        # identity_unattributable — and, worse, meant the one channel where a
        # NEW loss would appear was always red. So judge by REASON, and keep an
        # envelope on the expected ones so a real regression still fails. This
        # is not muting the check: an unreadable DLQ fails, an unexpected reason
        # fails at a single line, and expected reasons fail above the envelope.
        dlq_reasons = self.stack.dlq_run_reasons(
            self.acct_runid, self.device_identity_shas())
        ev["dlq_run_reasons"] = dlq_reasons
        if dlq_run > 0 and not dlq_reasons:
            problems.append(
                f"{dlq_run} run events in the correlation DLQ but the reasons "
                f"could not be read — unknown is not clean")
        unexpected = {r: n for r, n in dlq_reasons.items()
                      if r not in DLQ_EXPECTED_REASONS}
        expected_n = sum(n for r, n in dlq_reasons.items()
                         if r in DLQ_EXPECTED_REASONS)
        envelope = int(self.injected_total * DLQ_EXPECTED_MAX_FRACTION)
        if unexpected:
            problems.append(
                f"unexpected correlation DLQ reasons (any count is a defect): "
                f"{unexpected}")
        if expected_n > envelope:
            problems.append(
                f"{expected_n} events refused as {sorted(DLQ_EXPECTED_REASONS)} "
                f"— above the {DLQ_EXPECTED_MAX_FRACTION:.1%} envelope "
                f"({envelope} of {self.injected_total}). Expected-but-excessive: "
                f"attribution is failing at scale, not merely at the edges")
        if d_qwf != 0:
            problems.append(
                f"quarantine WRITE failures moved by {d_qwf} — events lost with no "
                f"DLQ copy (the 238k-drop class; check /data/deadletter ownership)")
        if any(v for v in ch_fail.values()) if isinstance(ch_fail, dict) else False:
            problems.append(f"correlation ClickHouse insert failures: {ch_fail}")
        if twin_mode:
            # Per-device coverage is the TWIN's verdict (its accuracy scorer
            # judges signal presence per story/device); the ladder judges the
            # balance equation. Coverage rides as evidence, not a gate.
            ev["twin_devices"] = self.twin_run.get("devices", -1)
        elif entities != len(self.created_ids):
            problems.append(
                f"corr_signals covers {entities}/{len(self.created_ids)} burst devices — "
                f"silent per-device signal loss (window eviction?)")

        ev.update({
            "injected_total": self.injected_total,
            "os_persisted_run_docs": os_docs,
            "dlq_run_lines": dlq_run,
            "vector_discards_delta_stackwide": d_discards,
            "vector_deadletter_delta_stackwide": d_dl,
            "quarantine_write_failures_delta": d_qwf,
            "ch_insert_failures": ch_fail,
            "corr_signal_rows_run": signal_rows,
            "corr_entities_covered": entities,
            "devices_expected": len(self.created_ids),
            "unexplained_missing": max(missing, 0) - explained if missing > 0 else 0,
            "tolerance_notes": (
                "os count and dlq lines are exact+run-attributable; vector "
                "deltas are stack-wide (organic traffic may inflate them — "
                "they can only over-explain a deficit). corr_signals rows are "
                "NOT expected to equal injected events (episodic dedup by "
                "design); the invariant is per-device coverage."),
        })
        status = "PASS" if not problems else "FAIL"
        return self.phase("accounting", status, ev,
                          "; ".join(problems) if problems else
                          f"balanced exactly: {self.injected_total} injected == "
                          f"{os_docs} persisted + 0 DLQ + 0 counted rejections; "
                          f"{entities}/{len(self.created_ids)} devices covered in corr_signals")

    # -- phase 6: memory flat ------------------------------------------------
    def memflat(self) -> bool:
        """Two independent memory verdicts.

        ####################################################################
        # THE SLOPE IS ANCHORED ON THE **WARM** SAMPLE, NOT THE COLD BASELINE.
        #
        # The cold baseline is taken at preflight — seconds after a fresh
        # install, when every cache is EMPTY. The first burst then materializes
        # working state that is bounded BY DESIGN, and a cold->end ratio cannot
        # tell that apart from a leak. Measured in CI run 32040415877
        # (60,001 events, 200 devices):
        #   clickhouse   474 -> 1349 MiB (x2.84)  = 25% of its 5326 MiB cap
        #   correlation   59 ->  187 MiB (x3.15)  = 24% of its  789 MiB cap
        #                 (CORR_WINDOW_BUFFER=50000 signals — a capped deque)
        # Every other container moved <=x1.15, including OpenSearch, which
        # indexed all 60k docs on an already-warm JVM. Nothing was leaking and
        # nothing was near a cap, yet the phase FAILED — a red gate every night
        # teaches operators to ignore it, which is worse than no gate.
        #
        # So: the LEAK slope is measured warm->end (caches already
        # materialized, input stopped — a leak keeps climbing there, a cache
        # does not), and the OOM path gets its own check against each
        # container's own limit. The cold->warm step stays in the evidence,
        # unjudged, because a 2-minute burst genuinely cannot separate
        # first-touch materialization from a slow leak. The leak gate proper
        # is the lab's 1000-device/5-minute run and the 72 h soak that
        # docs/scale/CORRELIX_SCALE_TEST_REPORT.md §6 still lists as not run.
        ####################################################################
        """
        settle = self._corr_mem_settle()
        end_stats = self.stack.mem_stats()
        end = {n: v["used"] for n, v in end_stats.items()}
        end_anon = self.stack.anon_sample(self._anon_services())
        cold = self.baseline.get("mem", {})
        warm = self.warm_mem or {}
        cold_anon = self.baseline.get("mem_anon", {}) or {}
        warm_anon = self.warm_anon or {}
        anchor = "warm (end of burst)" if warm else "cold baseline (no warm sample — burst did not complete)"
        ref = warm or cold
        ref_anon = warm_anon or cold_anon
        samples = {"cold": cold, "warm": warm, "end": end, "ref": ref,
                   "cold_anon": cold_anon, "warm_anon": warm_anon,
                   "end_anon": end_anon, "ref_anon": ref_anon}
        rows, problems = [], []
        # Replica discovery by NAME PATTERN, not a hardcoded -1 index: after a
        # `--force-recreate --scale correlation=2` compose numbers replicas
        # -2/-3 and the old form judged a container that no longer existed
        # ("no memory sample", gate red on a rename — 2026-08-24). Every
        # replica present in ANY sample is judged; one that appears without an
        # anchor (scaled up mid-run) still fails honestly as missing evidence.
        seen = (set(cold) | set(warm) | set(end)
                | set(cold_anon) | set(warm_anon) | set(end_anon))
        for svc in MEM_SERVICES:
            pref = f"{self.args.project}-{svc}-"
            names = sorted(n for n in seen
                           if n.startswith(pref) and n[len(pref):].isdigit())
            if not names:
                problems.append(f"{pref}N: no replica seen in any memory sample")
                continue
            for name in names:
                if svc == "correlation":
                    self._memflat_judge_correlation(
                        name, svc, samples, end_stats, rows, problems)
                else:
                    self._memflat_judge(name, svc, samples, end_stats,
                                        rows, problems)
        ch_ev, ch_problems, ch_summary = self._clickhouse_memory_verdict(rows)
        problems += ch_problems
        corr_summary = self._correlation_memory_summary(rows)
        ev = {"factor": self.args.mem_factor, "anchor": anchor,
              "headroom_percent": self.args.mem_headroom_percent,
              "stateless_services": list(MEM_STATELESS_SERVICES),
              "correlation_settle": settle,
              "containers": rows, "clickhouse": ch_ev}
        status = "PASS" if not problems else "FAIL"
        tail = "".join(f" | {s}" for s in (corr_summary, ch_summary) if s)
        return self.phase("memflat", status, ev,
                          ("; ".join(problems) + tail) if problems else
                          f"all {len(rows)} key containers within x{self.args.mem_factor} "
                          f"of the {anchor} sample and under "
                          f"{self.args.mem_headroom_percent}% of their caps{tail}")

    def _anon_services(self) -> tuple:
        """The services judged on cgroup anonymous memory — everything that
        caches, i.e. everything but MEM_STATELESS_SERVICES."""
        return tuple(s for s in MEM_SERVICES if s not in MEM_STATELESS_SERVICES)

    def _memflat_judge(self, name: str, svc: str, samples: dict,
                       end_stats: dict, rows: list, problems: list) -> None:
        """Judge ONE container against the memflat contract.

        The INSTRUMENT depends on the service (2026-08-29): a stateless one is
        judged on docker stats, everything that holds page cache on its cgroup
        `anon`. The docker-stats numbers stay in the row either way — reported,
        not judged, exactly like the cold->warm step above."""
        stateless = svc in MEM_STATELESS_SERVICES
        instrument = "docker_stats" if stateless else "cgroup_anon"
        keys = (("cold", "warm", "end", "ref") if stateless else
                ("cold_anon", "warm_anon", "end_anon", "ref_anon"))
        c, w, e, r = (samples[k].get(name, -1) for k in keys)
        limit = end_stats.get(name, {}).get("limit", -1)
        grew = (e / r) if r > 0 and e > 0 else -1
        pct_limit = round(100.0 * e / limit, 1) if limit > 0 and e > 0 else None
        rows.append({"container": name, "service": svc,
                     "instrument": instrument,
                     "cold_bytes": c, "warm_bytes": w,
                     "end_bytes": e, "limit_bytes": limit,
                     "pct_of_limit": pct_limit,
                     "ratio_vs_anchor": round(grew, 3) if grew > 0 else None,
                     "ratio_cold_to_end": round(e / c, 3) if c > 0 and e > 0 else None,
                     # Unjudged for a stateful service: page cache and slab put
                     # this figure ~3x above the container's real footprint.
                     "docker_stats_end_bytes": samples["end"].get(name, -1),
                     "docker_stats_ratio_unjudged": (
                         None if stateless else
                         self._ratio(samples["end"].get(name, -1),
                                     samples["ref"].get(name, -1)))})
        if r <= 0 or e <= 0:
            problems.append(
                f"{name}: no {instrument} sample (anchor {r}, end {e})"
                + ("" if stateless else
                   " — cgroup memory.stat unreadable, and docker stats cannot "
                   "substitute for it (it is mostly page cache)"))
            return
        # 64 MiB absolute floor: small containers jitter past any ratio.
        if grew > self.args.mem_factor and (e - r) > 64 * 1024**2:
            problems.append(
                f"{name}: LEAK SLOPE ({instrument}) {r / 1024**2:.0f} -> "
                f"{e / 1024**2:.0f} MiB (x{grew:.2f} > x{self.args.mem_factor}) "
                f"after input stopped")
        # The OOM path, self-relative to the plan-sized cap (#102).
        if pct_limit is not None and pct_limit > self.args.mem_headroom_percent:
            problems.append(
                f"{name}: {e / 1024**2:.0f} MiB ({instrument}) is {pct_limit}% of its "
                f"{limit / 1024**2:.0f} MiB cap (> {self.args.mem_headroom_percent}%) "
                f"— one burst from an OOM kill")

    @staticmethod
    def _ratio(value: float, anchor: float) -> float | None:
        return round(value / anchor, 3) if value > 0 and anchor > 0 else None

    # -- memflat, the correlation anchor -------------------------------------
    #
    # THE FALSE FAIL THIS REPLACES (run p2-s05-08291138, 2026-08-29).
    #
    #   [FAIL] memflat — netops-correlation-3: LEAK SLOPE (docker_stats)
    #          470 -> 647 MiB (x1.37 > x1.3) after input stopped
    #
    # "after input stopped" was true and beside the point: 22,736 signals were
    # still PENDING in that replica's engine at the anchor sample, and the
    # engine kept building objects for them for another ~33 minutes (the
    # correlation_completion phase timed the drain at 1,986 s). A working set
    # that grows while a queue drains is the queue, not a leak. The injector
    # does not get to define when the engine is idle — the engine does:
    #
    #   anchor  the FIRST sample where THIS replica reports
    #           corr_engine_pending == 0 (re-armed if pending climbs again)
    #   end     a sample at least CORR_MEM_SETTLE_S later, bounded
    #   slope   unchanged: x{--mem-factor} with the same 64 MiB absolute floor
    #
    # No pending-zero sample => UNKNOWN, carrying rss_at_input_stop /
    # rss_at_pending_zero / rss_end. UNKNOWN is never PASS (it stays a
    # `problems` entry, like every other unmeasurable clause in this file) and
    # it is never reported as a LEAK either — accusing the engine of leaking on
    # evidence that cannot separate a leak from a drain is the defect itself.
    # `api` keeps the input-stop anchor: it holds no backlog.
    def _corr_mem_settle(self) -> dict:
        """Bounded wait so the end sample is past the drain, not inside it.

        Normally free: accounting runs between correlation_completion and
        memflat and usually spends more than the settle on its own."""
        zeros = [row["pending_zero_monotonic"]
                 for row in self.corr_mem_track.values()
                 if row.get("pending_zero_monotonic") is not None]
        ev = {"settle_s": CORR_MEM_SETTLE_S,
              "budget_s": CORR_MEM_SETTLE_MAX_S,
              "waited_s": 0.0,
              "replicas_tracked": len(self.corr_mem_track),
              "replicas_at_pending_zero": len(zeros)}
        if not zeros:
            return ev
        target = max(zeros) + CORR_MEM_SETTLE_S
        t0 = time.monotonic()
        announced = False
        while True:
            now = time.monotonic()
            if now >= target or now - t0 >= CORR_MEM_SETTLE_MAX_S:
                break
            if not announced:           # never a silent wait (§16)
                log(f"memflat: settling {target - now:.0f}s more before the end "
                    f"sample — correlation reached pending 0 less than "
                    f"{CORR_MEM_SETTLE_S:.0f}s ago (budget "
                    f"{CORR_MEM_SETTLE_MAX_S:.0f}s)")
                announced = True
            time.sleep(min(5.0, max(0.5, target - now)))
        ev["waited_s"] = round(time.monotonic() - t0, 1)
        return ev

    def _memflat_judge_correlation(self, name: str, svc: str, samples: dict,
                                   end_stats: dict, rows: list,
                                   problems: list) -> None:
        """Judge ONE correlation replica against the pending-zero anchor."""
        track = self.corr_mem_track.get(name) or {}
        at_stop = samples["warm"].get(name, -1)
        if at_stop <= 0:
            at_stop = samples["cold"].get(name, -1)
        at_zero = int(track.get("rss_at_pending_zero", -1))
        end = samples["end"].get(name, -1)
        limit = end_stats.get(name, {}).get("limit", -1)
        pct_limit = round(100.0 * end / limit, 1) if limit > 0 and end > 0 else None
        zero_at = track.get("pending_zero_monotonic")
        settled_s = (round(time.monotonic() - zero_at, 1)
                     if zero_at is not None else None)
        ratio = self._ratio(end, at_zero)
        row = {"container": name, "service": svc,
               "instrument": "docker_stats",
               "anchor": "corr_engine_pending==0",
               "cold_bytes": samples["cold"].get(name, -1),
               "warm_bytes": samples["warm"].get(name, -1),
               "end_bytes": end, "limit_bytes": limit,
               "pct_of_limit": pct_limit,
               "rss_at_input_stop": at_stop,
               "rss_at_pending_zero": at_zero,
               "rss_end": end,
               "pending_at_first_engine_sample": track.get("first_pending", -1.0),
               "pending_zero_t_s": track.get("pending_zero_t_s"),
               "pending_zero_resets": track.get("pending_zero_resets", 0),
               "last_pending": track.get("last_pending", -1.0),
               "engine_samples": track.get("samples", 0),
               "seconds_from_pending_zero_to_end": settled_s,
               "settle_required_s": CORR_MEM_SETTLE_S,
               "ratio_vs_anchor": ratio,
               # The old anchor, kept as evidence and never judged: on the run
               # that motivated this it read x1.37 and meant "the backlog was
               # still draining", not "the engine leaked".
               "ratio_input_stop_to_end_unjudged": self._ratio(end, at_stop),
               "ratio_cold_to_end": self._ratio(end, samples["cold"].get(name, -1)),
               "verdict": "UNKNOWN"}
        rows.append(row)
        numbers = (f"rss_at_input_stop {mib(at_stop)} -> rss_at_pending_zero "
                   f"{mib(at_zero)} -> rss_end {mib(end)}")
        # The OOM clause is anchor-independent: a container at 90 % of its cap
        # is one burst from a kill whether or not it is draining a backlog.
        if pct_limit is not None and pct_limit > self.args.mem_headroom_percent:
            problems.append(
                f"{name}: {end / 1024**2:.0f} MiB (docker_stats) is {pct_limit}% "
                f"of its {limit / 1024**2:.0f} MiB cap "
                f"(> {self.args.mem_headroom_percent}%) — one burst from an "
                f"OOM kill")
        if end <= 0:
            problems.append(
                f"{name}: no docker_stats end sample (end {end}) — the leak "
                f"clause has no measurement to judge")
            return
        if not track:
            problems.append(
                f"{name}: LEAK SLOPE UNKNOWN — no per-replica engine sample "
                f"(correlation_completion never ran for this replica), so the "
                f"pending-zero anchor does not exist; {numbers}")
            return
        if zero_at is None or at_zero <= 0:
            problems.append(
                f"{name}: LEAK SLOPE UNKNOWN — corr_engine_pending never "
                f"reached 0 on this replica within the completion phase (last "
                f"pending {track.get('last_pending', -1.0):.0f} at "
                f"t+{track.get('last_t_s', -1.0):.0f}s over "
                f"{track.get('samples', 0)} sample(s)); {numbers}. Growth while "
                f"a backlog drains is work, not a leak — this is NOT judged")
            return
        if settled_s is not None and settled_s < CORR_MEM_SETTLE_S:
            problems.append(
                f"{name}: LEAK SLOPE UNKNOWN — the end sample is only "
                f"{settled_s:.0f}s past pending 0 (needs "
                f"{CORR_MEM_SETTLE_S:.0f}s); {numbers}")
            return
        row["verdict"] = "LEAK" if (
            ratio is not None and ratio > self.args.mem_factor
            and (end - at_zero) > 64 * 1024**2) else "FLAT"
        if row["verdict"] == "LEAK":
            problems.append(
                f"{name}: LEAK SLOPE (docker_stats, anchored at "
                f"corr_engine_pending==0) {at_zero / 1024**2:.0f} -> "
                f"{end / 1024**2:.0f} MiB (x{ratio:.2f} > "
                f"x{self.args.mem_factor}) over {settled_s:.0f}s AFTER the "
                f"backlog drained — this is growth with nothing left to "
                f"evaluate")

    def _correlation_memory_summary(self, rows: list) -> str:
        """The three RSS numbers, on the phase line, for every replica."""
        parts = []
        for r in rows:
            if r.get("service") != "correlation":
                continue
            ratio = r.get("ratio_vs_anchor")
            settled = r.get("seconds_from_pending_zero_to_end")
            parts.append(
                f"{r['container']} rss {mib(r['rss_at_input_stop'])} at input "
                f"stop -> {mib(r['rss_at_pending_zero'])} at pending 0 -> "
                f"{mib(r['rss_end'])} end "
                f"(x{'?' if ratio is None else ratio} vs pending-0 anchor, "
                f"settle {'?' if settled is None else f'{settled:.0f}'}s, "
                f"{r.get('verdict', 'UNKNOWN')})")
        return "correlation " + "; ".join(parts) if parts else ""

    # -- memflat, ClickHouse clauses (2) and (3) -----------------------------
    #
    # docs/scale/P2_CLICKHOUSE_MEMFLAT_2026-08-29.md §(c), corrected by
    # docs/scale/P2_CLICKHOUSE_PEAK_S06_2026-08-29.md. A store that writes
    # 50 GiB per run does not answer to an RSS ratio; it answers to its OWN
    # memory accounting and to the parts it leaves behind:
    #
    #   (2a) ZERO new MEMORY_LIMIT_EXCEEDED across the run (`system.errors`
    #        delta, preflight -> memflat). Any increase is a FAIL, named with
    #        the count and with whatever victims query_log can attribute.
    #   (2b) p99 MemoryTracking < CH_MEMORY_TRACKING_MAX_PCT of the effective
    #        max_server_memory_usage. The PEAK is reported beside it, and a
    #        peak at/above the cap with no error behind it is a WARN, not a
    #        FAIL — see the CH_MEM_ERROR header for why p99 and not max.
    #        MergesMutationsMemoryTracking is INFORMATIONAL: no verdict.
    #   (3) MaxPartCountForPartition returns to within +20 % of its preflight
    #       value once input stops, and stays under parts_to_delay_insert / 2.
    #       That is what a stateful store legitimately owes after a burst.
    def _ch_number(self, query: str) -> float:
        return ch_number(self.stack, query)

    def _ch_sample_metrics(self) -> None:
        """Fold a live `system.metrics` reading into the running peak. Cheap,
        and it is the only instrument left if `system.metric_log` is gone.

        The two counters are folded INDEPENDENTLY. On 24.8 MemoryTracking is
        process RSS and MergesMutationsMemoryTracking is a tracker sum, so
        neither bounds the other: a sample where the merge figure is the larger
        is a real reading, and the old code threw the pair away (see the
        CH_MEM_ERROR header)."""
        ok, out = self.stack.ch(
            "SELECT metric, toInt64(value) FROM system.metrics WHERE metric IN "
            "('MemoryTracking', 'MergesMutationsMemoryTracking')")
        if not ok:
            warn(f"ClickHouse system.metrics sample failed: {out[:160]}")
            return
        folded = False
        for line in out.splitlines():
            if "\t" not in line:
                continue
            metric, raw = line.split("\t", 1)
            if metric not in self.ch_mem_peak:
                continue
            try:
                # A negative merge delta is 0 bytes of merge memory, never a
                # UInt64 wrap — _ch_counter is the signed parse plus that floor.
                value = _ch_counter(raw)
            except ValueError:
                continue
            folded = True
            self.ch_mem_peak[metric] = max(self.ch_mem_peak[metric], value)
        if not folded:
            warn("ClickHouse system.metrics sample carried neither memory "
                 "counter — nothing folded into the peak")
            return
        self.ch_mem_samples += 1

    def _ch_memory_cap(self) -> tuple[float, str]:
        return ch_memory_cap(self.stack)

    def _ch_memory_peaks(self) -> tuple[dict, str, dict]:
        """Peak AND p99 MemoryTracking, plus the merge peak, over THIS RUN.

        `system.metric_log` is the instrument, unfiltered: on 24.8 there is no
        sample shape that is "impossible" (CH_MEM_ERROR header), so nothing is
        discarded and nothing needs a rejected-sample census any more.

        metric_log is OPTIONAL, and deliberately so — a builder may lower its
        cadence, and changing its `<engine>` makes ClickHouse rename the table
        on restart. So the harness's own `system.metrics` samples are folded in
        as a FLOOR under the peak. They are a floor and nothing else: a handful
        of point samples cannot carry a p99, so a degraded run reports p99
        UNMEASURED and the verdict says so — it never passes blind.
        """
        peaks = {"MemoryTracking": -1, "MemoryTrackingP99": -1,
                 "MergesMutationsMemoryTracking": -1}
        census = {"window_start": "", "metric_log_samples": -1,
                  "metric_log": "not queried (no run window)",
                  "metric_log_first_sample": "", "metric_log_gap_s": -1.0,
                  "harness_samples": self.ch_mem_samples}
        sources: list[str] = []
        start = ch_ts(self.baseline.get("ch_window_start"))
        if start:
            census["window_start"] = start
            census["metric_log"] = "queried"
            ok, out = self.stack.ch(
                CH_PEAK_SELECT + f"event_time >= toDateTime('{start}')")
            if not ok:
                census["metric_log"] = f"UNAVAILABLE ({out[:120]})"
                warn(f"ClickHouse metric_log peak query failed: {out[:160]} — "
                     f"the peaks degrade to the harness's own samples and the "
                     f"p99 clause cannot be judged")
            elif out.strip():
                cells = out.strip().splitlines()[0].split("\t")
                try:
                    total = int(cells[3])
                except (IndexError, ValueError):
                    total = -1
                    census["metric_log"] = (
                        f"answer unreadable ({out.strip()[:120]!r})")
                    warn(f"ClickHouse metric_log peak query returned an "
                         f"unreadable row ({out.strip()[:120]!r}) — the peaks "
                         f"it carries are not trusted")
                census["metric_log_samples"] = total
                if total > 0:
                    for i, key in enumerate(("MemoryTracking",
                                             "MemoryTrackingP99",
                                             "MergesMutationsMemoryTracking")):
                        try:
                            peaks[key] = _ch_counter(cells[i])
                        except (IndexError, ValueError):
                            peaks[key] = -1
                    if peaks["MemoryTracking"] > 0:
                        sources.append(f"system.metric_log since {start}")
                    first = cells[4] if len(cells) > 4 else ""
                    gap = ch_window_gap_s(start, first)
                    census["metric_log_first_sample"] = ch_ts(first)
                    census["metric_log_gap_s"] = round(gap, 1)
                    if gap > CH_WINDOW_COVERAGE_SLACK_S:
                        census["metric_log"] = (
                            f"PARTIAL — {total} sample(s), the first at {first}, "
                            f"{gap:.0f}s after the window opened at {start}")
                    else:
                        census["metric_log"] = f"{total} sample(s) in the window"
                elif total == 0:
                    census["metric_log"] = (
                        "present but held 0 samples for this run's window")
                    warn("ClickHouse metric_log held 0 samples for this run's "
                         "window — the peaks degrade to the harness's own "
                         "samples and the p99 clause cannot be judged")
            else:
                census["metric_log"] = "returned an empty answer"
                warn("ClickHouse metric_log peak query returned nothing — the "
                     "peaks degrade to the harness's own samples")
        self._ch_sample_metrics()
        census["harness_samples"] = self.ch_mem_samples
        for key, sampled in self.ch_mem_peak.items():
            if sampled > peaks.get(key, -1):
                peaks[key] = sampled
                if "harness system.metrics samples" not in sources:
                    sources.append("harness system.metrics samples")
        return peaks, " + ".join(sources) if sources else "none", census

    def _ch_memory_errors(self) -> tuple[dict, list]:
        """Clause (2a): the MEMORY_LIMIT_EXCEEDED delta across this run.

        `system.errors` is the counter (server-lifetime, and it RESETS on a
        restart — a backwards delta is therefore UNKNOWN, never zero);
        `system.error_log` is the timeline over the run window and the only
        table that sees background-thread raises."""
        start = ch_ts(self.baseline.get("ch_window_start"))
        end = ch_ts(self.stack.ch_now())
        # `or -1` would be a defect here: a baseline of 0 errors is the
        # HEALTHY case and must not read as unmeasured.
        raw_base = self.baseline.get("ch_mem_errors", -1)
        base = int(raw_base) if raw_base is not None else -1
        now = ch_number(self.stack, CH_MEM_ERROR_TOTAL_SQL)
        window, window_source, window_state = ch_memory_error_window(
            self.stack, start, end)
        ev = {"baseline": base, "current": int(now) if now >= 0 else -1,
              "delta": -1, "window_count": window,
              "window_source": window_source, "window_state": window_state,
              "window_start": start, "window_end": end, "victims": "",
              # The exemption ledger (see CH_BACKFILL_TAG_PREFIX). `counted` is
              # what the verdict is taken on; -1 on the attribution/pass rows
              # means the question was never asked (no refusal fired) or the
              # instrument could not answer — never "zero attributable".
              "counted": -1, "backfill_attributed": -1, "backfill_tags": "",
              "backfill_attribution_source": "not examined (no refusal)",
              "backfill_passes": -1,
              "backfill_pass_source": "not examined (no refusal)",
              # Checks (c)/(d) — asked only once (a)+(b) hold.
              "foreign_241": -1, "foreign_241_producers": "",
              "foreign_241_source": "not examined (no exemptable refusal)",
              "part_log_errored": -1,
              "part_log_source": "not examined (no exemptable refusal)",
              "backfill_exempt": 0, "exemption_note": ""}
        problems: list = []
        if base < 0 or now < 0:
            problems.append(
                f"clickhouse: the {CH_MEM_ERROR} counter is UNREADABLE "
                f"(preflight {base}, now {int(now)}) — the clause that carries "
                f"the customer-visible fact cannot be judged, and a memory "
                f"gate must not pass blind"
                + (f" (system.error_log meanwhile counted {window} over the run "
                   f"window)" if window > 0 else ""))
            return ev, problems
        delta = int(now) - base
        ev["delta"] = delta
        if delta < 0:
            problems.append(
                f"clickhouse: the {CH_MEM_ERROR} counter went BACKWARDS "
                f"(preflight {base} -> {int(now)}) — system.errors resets at "
                f"server start, so ClickHouse RESTARTED during this run: the "
                f"error clause is UNKNOWN and the run is not comparable"
                + (f" (system.error_log counted {window} over the window)"
                   if window > 0 else ""))
            return ev, problems
        # The delta and the error_log window are two views of the same fact and
        # either one alone is enough to condemn the run: take the LARGER, never
        # the more convenient.
        raised = max(delta, max(0, window))
        ev["counted"] = raised
        if raised > 0:
            ev["victims"] = ch_memory_error_victims(
                self.stack, start, end, raised)
            # The two independent halves of the exemption. Both are asked ONLY
            # when something was actually refused — a clean run pays for
            # neither probe.
            attributed, tags, attr_source = ch_memory_error_backfill_attributed(
                self.stack, start, end)
            # The pass evidence costs a `docker logs` over the whole run, so it
            # is only read when something IS attributable to the worker. When
            # nothing is, the answer cannot change the verdict.
            if attributed > 0:
                passes, pass_source = self._backfill_pass_evidence()
            else:
                passes, pass_source = -1, ("not examined (no refusal attributed "
                                           "to the backfill worker)")
            ev.update({"backfill_attributed": attributed,
                       "backfill_tags": tags,
                       "backfill_attribution_source": attr_source,
                       "backfill_passes": passes,
                       "backfill_pass_source": pass_source})
            # ATTRIBUTABLE **AND** RECOVERED, or nothing. A -1 on either
            # instrument is unreadable and exempts nothing; a refusal with no
            # completing pass is the STALL shape and must stay red.
            exempt = 0
            if attributed > 0 and passes > 0:
                # HOW MUCH to exempt. `raised` counts error INCREMENTS (one
                # per throwing thread plus the query-level rethrow) and
                # `attributed` counts query ROWS — different units, and
                # subtracting one from the other manufactured ~5 phantom
                # "unexempted" errors on every negotiating run (the
                # CH_BACKFILL_TAG_PREFIX header, run 083117507rl2). So verify
                # the backfill was the SOLE 241 producer — checks (c)+(d) —
                # and exempt the whole raised delta; any foreign evidence
                # falls back to the per-row subtraction, which under-exempts
                # and never over-exempts.
                foreign, producers, foreign_source = (
                    ch_memory_error_foreign_producers(self.stack, start, end))
                part_errored, part_source = ch_part_log_errored(
                    self.stack, start, end)
                ev.update({"foreign_241": foreign,
                           "foreign_241_producers": producers,
                           "foreign_241_source": foreign_source,
                           "part_log_errored": part_errored,
                           "part_log_source": part_source})
                if foreign == 0 and part_errored == 0:
                    exempt = raised
                    branch = ("full-delta exemption: sole producer verified "
                              "(no foreign 241 in system.query_log, no "
                              "errored part op in system.part_log)")
                elif foreign > 0 or part_errored > 0:
                    exempt = min(attributed, raised)
                    foreign_bits = []
                    if foreign > 0:
                        foreign_bits.append(f"{foreign}x foreign 241 from "
                                            f"{producers or '(unnamed)'}")
                    if part_errored > 0:
                        foreign_bits.append(f"{part_errored} errored part "
                                            f"op(s) in system.part_log")
                    branch = (f"partial: foreign producers present — only "
                              f"the {attributed} attributed query row(s) of "
                              f"{raised} raised increment(s) are exempt "
                              f"({'; '.join(foreign_bits)})")
                else:
                    # Neither probe found foreign work, but at least one
                    # could not answer: sole-producer status is UNVERIFIED,
                    # and a gate that cannot see must not forgive.
                    ev["exemption_note"] = (
                        f"nothing exempted: sole-producer verification "
                        f"unreadable ({foreign_source}; {part_source})")
            counted = raised - exempt
            ev["backfill_exempt"] = exempt
            ev["counted"] = counted
            if exempt > 0:
                ev["exemption_note"] = (
                    f"{exempt} backfill-negotiation refusals exempted, pass "
                    f"completed ({tags or 'attributed by log_comment'}; "
                    f"{passes} completed pass(es) — {pass_source}; {branch})")
                log(f"memflat: {ev['exemption_note']}")
            if counted > 0:
                if exempt:
                    head = (f"clickhouse: {counted} UNEXEMPTED {CH_MEM_ERROR} "
                            f"during this run (of {raised} raised; "
                            f"{ev['exemption_note']}) ")
                elif ev["exemption_note"]:
                    head = (f"clickhouse: {counted} {CH_MEM_ERROR} during "
                            f"this run ({ev['exemption_note']}) ")
                else:
                    head = (f"clickhouse: {counted} {CH_MEM_ERROR} during "
                            f"this run ")
                problems.append(
                    head
                    + f"(system.errors delta {delta}"
                    + (f", {window_source} counted {window}" if window >= 0
                       else f", {window_source}")
                    + f") — the store refused work for want of its own memory "
                      f"budget. Victims: {ev['victims']}")
        return ev, problems

    def _backfill_pass_evidence(self, now: float | None = None) -> tuple[int, str]:
        """(passes, source) — `backfill pass complete` lines with pages > 0 in
        the api container log over THIS RUN's window.

        Same seam the stability diagnosis uses (`docker logs --since` over every
        replica of the service), and the same rule: a replica whose log cannot
        be read is UNREADABLE, not clean. -1 when NO replica could be read, so
        the caller exempts nothing rather than forgiving blind."""
        cids = self.stack.cids("api")
        if not cids:
            return -1, ("no running api container — backfill pass evidence "
                        "unreadable")
        now = time.monotonic() if now is None else now
        # From RUN start (not burst start) + a minute of slack, so the evidence
        # window covers the whole window the error clause judges. Floored at a
        # minute: a nonsensical elapsed must not become a `--since -12s`.
        since = max(60, int(now - self.run_mono_t0) + 60)
        passes, read, unread = 0, 0, 0
        for cc in cids:
            rc, out, err2 = run(["docker", "logs", "--since", f"{since}s", cc],
                                120)
            found = backfill_passes_completed((out + err2) if rc == 0 else None)
            if found < 0:
                unread += 1
                continue
            read += 1
            passes += found
        if read == 0:
            return -1, (f"api container log unreadable ({unread} replica(s)) — "
                        f"backfill pass evidence unavailable")
        source = (f"'{BACKFILL_PASS_COMPLETE}' with pages > 0 in {read} api "
                  f"container log(s) over the last {since}s")
        if unread:
            source += f"; {unread} replica(s) unreadable"
        return passes, source

    def _ch_parts_settled(self) -> dict:
        """Clause (3): parts come back down after input stops.

        Bounded settle wait — merges that are still folding the burst's parts
        are legitimate work, a part count that never returns is not."""
        # `or -1` would be a defect here, exactly as it was for ch_mem_errors:
        # a preflight of ZERO parts is the CLEANEST baseline there is (an idle,
        # freshly-merged store), and reading it as "unmeasurable" abandons
        # clause (3) on precisely the runs whose part growth is most legible.
        # Only a MISSING or unparsable value is unmeasurable; `_ch_number`
        # already returns -1 when the probe itself could not answer.
        raw_base = self.baseline.get("ch_max_part_count")
        try:
            base = -1 if raw_base is None else int(raw_base)
        except (TypeError, ValueError):
            base = -1
        delay_at = self._ch_number(
            "SELECT toFloat64(value) FROM system.merge_tree_settings "
            "WHERE name = 'parts_to_delay_insert'")
        envelope = (max(base * CH_PART_COUNT_GROWTH_MAX,
                        base + CH_PART_COUNT_FLOOR) if base >= 0 else -1.0)
        budget = min(max(self.args.drain_factor * self.burst_seconds,
                         CH_PART_SETTLE_INTERVAL_S), CH_PART_SETTLE_MAX_S)
        deadline = time.monotonic() + budget
        t0 = time.monotonic()
        current = -1.0
        while True:
            current = self._ch_number(
                "SELECT value FROM system.asynchronous_metrics "
                "WHERE metric = 'MaxPartCountForPartition'")
            if current < 0 or envelope < 0 or current <= envelope:
                break
            if time.monotonic() >= deadline:
                break
            time.sleep(CH_PART_SETTLE_INTERVAL_S)
        waited = time.monotonic() - t0
        out = {"baseline": base, "current": int(current) if current >= 0 else -1,
               "envelope": round(envelope, 1) if envelope >= 0 else -1,
               "parts_to_delay_insert": int(delay_at) if delay_at > 0 else -1,
               "settle_budget_s": round(budget, 1),
               "settle_waited_s": round(waited, 1),
               "problems": []}
        if base < 0 or current < 0:
            out["problems"].append(
                f"ClickHouse MaxPartCountForPartition unmeasurable (preflight "
                f"{base}, now {int(current)}) — clause (3) cannot be judged")
            return out
        if current > envelope:
            out["problems"].append(
                f"clickhouse: parts NEVER SETTLED — MaxPartCountForPartition "
                f"{int(current)} still above the +"
                f"{(CH_PART_COUNT_GROWTH_MAX - 1) * 100:.0f}% envelope "
                f"{envelope:.0f} (preflight {base}) after {waited:.0f}s of a "
                f"{budget:.0f}s settle budget — merges are not keeping up with "
                f"the parts this run created")
        if delay_at > 0 and current >= delay_at / 2:
            out["problems"].append(
                f"clickhouse: MaxPartCountForPartition {int(current)} is at or "
                f"past HALF of parts_to_delay_insert ({int(delay_at)}) — the "
                f"next run starts inside the insert-throttling band")
        return out

    def _clickhouse_memory_verdict(self, rows: list) -> tuple[dict, list, str]:
        """Clauses (2a), (2b) and (3), plus the one-line summary of all three.

        The order is deliberate: the ERROR clause first, because it is the
        customer-visible fact and the memory levels are only a proxy for it.
        """
        if "clickhouse" not in MEM_SERVICES:
            return {}, [], ""
        problems: list[str] = []
        warnings: list[str] = []
        cap, cap_source = self._ch_memory_cap()
        peaks, peak_source, census = self._ch_memory_peaks()
        err_ev, err_problems = self._ch_memory_errors()
        problems += err_problems
        # An EMPTY error_log beside a zero delta is two instruments agreeing,
        # not a broken cross-check — the common clean run, and warning on it
        # every night is how a gate teaches operators to ignore it. Every other
        # unusable state IS reported.
        if (err_ev["window_state"] not in ("ok", "empty")
                or (err_ev["window_state"] == "empty" and err_ev["delta"] > 0)):
            warnings.append(
                f"clickhouse: system.error_log cannot answer for this run "
                f"({err_ev['window_source']}) — the {CH_MEM_ERROR} count rests "
                f"on the system.errors delta alone, which is a lifetime "
                f"counter and cannot say WHEN inside the run they fired")
        if census.get("metric_log", "").startswith("PARTIAL"):
            warnings.append(
                f"clickhouse: system.metric_log covers only part of this run "
                f"({census['metric_log']}) — the p99 below is over the covered "
                f"tail, not the whole window")
        ev = {"cap_bytes": int(cap) if cap > 0 else -1,
              "cap_source": cap_source,
              "peak_source": peak_source,
              "peak_memory_tracking_bytes": peaks["MemoryTracking"],
              "p99_memory_tracking_bytes": peaks["MemoryTrackingP99"],
              # INFORMATIONAL ONLY. On 24.8 MemoryTracking is process RSS and
              # this is a tracker sum, so it is not bounded by the total and
              # there is no honest fraction-of-cap to assert on. Reported so a
              # reader can see it; never judged.
              "peak_merges_memory_bytes": peaks["MergesMutationsMemoryTracking"],
              "merges_memory_verdict": "INFORMATIONAL — not bounded by the "
                                       "tracked total in ClickHouse 24.8",
              "memory_limit_exceeded": err_ev,
              "sample_census": census,
              "memory_tracking_max_pct": CH_MEMORY_TRACKING_MAX_PCT,
              "memory_tracking_peak_warn_pct": CH_MEMORY_TRACKING_PEAK_WARN_PCT}
        track_pct = p99_pct = None
        degraded = peaks["MemoryTrackingP99"] < 0
        if cap <= 0:
            problems.append(
                "clickhouse: effective max_server_memory_usage unreadable "
                f"({cap_source}) — the OOM clause cannot be judged, and a "
                "memory gate must not pass blind")
        elif peaks["MemoryTracking"] < 0:
            problems.append(
                "clickhouse: MemoryTracking unmeasurable (system.metric_log "
                f"answered nothing for this run's window [{census['metric_log']}] "
                "and no live sample succeeded) — the OOM clause cannot be judged")
        else:
            track_pct = round(100.0 * peaks["MemoryTracking"] / cap, 1)
            if degraded:
                # metric_log is gone, so there is no p99 to judge. The PEAK is
                # judged in its place at the same bound — a STRICTER test than
                # the clause, which is the honest direction to err in, and it
                # is said out loud rather than passed off as the real one.
                warnings.append(
                    f"clickhouse: p99 MemoryTracking UNMEASURED "
                    f"({census['metric_log']}) — DEGRADED to "
                    f"{census['harness_samples']} harness system.metrics "
                    f"sample(s), and the PEAK was judged in the p99's place at "
                    f"the same {CH_MEMORY_TRACKING_MAX_PCT}% bound. That is "
                    f"stricter than the clause: one transient can fail it")
                if track_pct > CH_MEMORY_TRACKING_MAX_PCT:
                    problems.append(
                        f"clickhouse: peak MemoryTracking "
                        f"{peaks['MemoryTracking'] / 1024**2:.0f} MiB is "
                        f"{track_pct}% of its {cap / 1024**2:.0f} MiB server "
                        f"cap (> {CH_MEMORY_TRACKING_MAX_PCT}%), judged in the "
                        f"p99's place because system.metric_log could not "
                        f"answer for this run's window")
            else:
                p99_pct = round(100.0 * peaks["MemoryTrackingP99"] / cap, 1)
                if p99_pct > CH_MEMORY_TRACKING_MAX_PCT:
                    problems.append(
                        f"clickhouse: p99 MemoryTracking "
                        f"{peaks['MemoryTrackingP99'] / 1024**2:.0f} MiB is "
                        f"{p99_pct}% of its {cap / 1024**2:.0f} MiB server cap "
                        f"(> {CH_MEMORY_TRACKING_MAX_PCT}%) — this is the level "
                        f"the store RUNS at, not a transient: it spent 1% of "
                        f"the run at or above it")
                # `not err_ev["backfill_exempt"]` as well as `not
                # err_problems`: an EXEMPTED refusal leaves no problem behind,
                # but "NO MEMORY_LIMIT_EXCEEDED fired" would then be a false
                # sentence in the same report that exempts four of them.
                if (track_pct >= CH_MEMORY_TRACKING_PEAK_WARN_PCT
                        and not err_problems
                        and not err_ev.get("backfill_exempt")):
                    warnings.append(
                        f"clickhouse: peak MemoryTracking "
                        f"{peaks['MemoryTracking'] / 1024**2:.0f} MiB reached "
                        f"{track_pct}% of the {cap / 1024**2:.0f} MiB cap while "
                        f"p99 stayed at {p99_pct}% and NO {CH_MEM_ERROR} "
                        f"fired — a transient that touched the ceiling and cost "
                        f"no work. Reported, not failed")
        ev["memory_tracking_pct"] = track_pct
        ev["p99_memory_tracking_pct"] = p99_pct
        ev["degraded"] = degraded
        parts = self._ch_parts_settled()
        problems += parts.pop("problems")
        ev["parts"] = parts
        ev["warnings"] = warnings
        for line in warnings:
            warn(line)
        ch_row = next((r for r in rows if r.get("service") == "clickhouse"), None)
        slope = "anon unmeasured"
        if ch_row and ch_row.get("ratio_vs_anchor"):
            slope = (f"anon {mib(ch_row['end_bytes'])} "
                     f"(x{ch_row['ratio_vs_anchor']} vs anchor)")
        # All the clauses in one line, always — a number the operator can read
        # is the difference between "the gate is green" and "the store refused
        # 17 pieces of work and nobody said so".
        errs = err_ev["delta"] if err_ev["delta"] >= 0 else "UNKNOWN"
        if err_ev["window_count"] > 0 and err_ev["window_count"] != err_ev["delta"]:
            errs = f"{errs} (error_log {err_ev['window_count']})"
        summary = (
            f"clickhouse {slope}; {CH_MEM_ERROR} +{errs}; "
            f"p99 MemoryTracking {mib(peaks['MemoryTrackingP99'])} = "
            f"{'?' if p99_pct is None else p99_pct}% of cap {mib(cap)} "
            f"(peak {mib(peaks['MemoryTracking'])} = "
            f"{'?' if track_pct is None else track_pct}%; merges "
            f"{mib(peaks['MergesMutationsMemoryTracking'])} INFORMATIONAL, no "
            f"verdict); MaxPartCountForPartition {parts['current']} "
            f"(preflight {parts['baseline']}, envelope {parts['envelope']}, "
            f"delay at {parts['parts_to_delay_insert']})")
        # The exemption is NEVER silent: it rides in the one line the
        # operator always reads, whether the phase passed or failed.
        if err_ev.get("exemption_note"):
            summary += f" | {err_ev['exemption_note']}"
        if warnings:
            summary += " | WARN: " + "; ".join(warnings)
        return ev, problems, summary

    # -- phase 7: cleanup ----------------------------------------------------
    # ── TRACKER 175: the tombstone debt no run ever pays ───────────────
    #
    # WHAT WAS MEASURED. `DELETE /api/devices/{id}` writes a SUPPRESSION
    # tombstone (`.d/suppressed/<sha256hex(id)>`) so a source-owned device
    # stays deleted instead of being re-added by the next poll (audit F-69,
    # devstore.go). It is never removed except by re-creating the same id.
    # This harness creates and deletes 2,500 devices per run, so every run
    # leaves 2,500 permanent files behind. Measured on the lab box on
    # 2026-08-29 after a day of runs: 35,427 tombstones, 142 MB, against ZERO
    # manual devices — and the onboard rate had fallen 30-43/s -> 15.4/s.
    # devstore.go's own LoadPrefix comment records the endgame: "a lab subtree
    # of 38,666 deletion tombstones took >6 min of uninterruptible disk I/O and
    # wedged boot before the api ever reached its listener".
    #
    # WHAT THIS DOES, AND WHY IT DOES NOT DELETE THEM. There is no API and no
    # CLI for forgetting a tombstone: `DevStore` exposes Put / Remove /
    # Devices / IsSuppressed and nothing else, and no HTTP route reaches the
    # suppression set at all. Deleting the files from under a RUNNING api
    # would not be a purge — the api holds the suppression set in memory
    # (`adoptRecords` reads it once at boot) — it would be an unsynchronised
    # write into a live service's private state, which is precisely what
    # §16.3 forbids. So the harness MEASURES the debt, names it, attributes
    # this run's share of it, and records the onboard rate beside it so the
    # correlation is visible run over run. The purge itself needs an API
    # (tracker 175).
    TOMBSTONE_DIR = "devices.json.d/suppressed"

    def tombstone_debt(self) -> dict:
        """Count the device store's suppression tombstones. Read-only."""
        ev: dict = {"reachable": False, "reason": "", "path": "",
                    "suppressed_entries": -1, "this_run": -1,
                    "purge_api": "none — DevStore exposes no tombstone removal"}
        root, reason = self.stack.api_data_dir()
        ev["reason"] = reason
        if not root:
            warn(f"TOMBSTONE DEBT: UNKNOWN — {reason}. The device store's "
                 f"suppression tombstones cannot be counted from here "
                 f"(tracker 175)")
            return ev
        path = os.path.join(root, self.TOMBSTONE_DIR)
        ev["path"] = path
        if not os.path.isdir(path):
            ev["reason"] = f"{path} does not exist (nothing has been deleted yet)"
            ev["reachable"] = True
            ev["suppressed_entries"] = 0
            ev["this_run"] = 0
            return ev
        try:
            with os.scandir(path) as entries:
                total = sum(1 for e in entries if e.is_file())
        except OSError as exc:
            ev["reason"] = f"{path} unreadable: {exc!r}"
            warn(f"TOMBSTONE DEBT: UNKNOWN — {ev['reason']} (tracker 175)")
            return ev
        ev["reachable"] = True
        ev["suppressed_entries"] = total
        # THIS run's share, computed EXACTLY rather than sampled: the record
        # name is sha256hex(device id) (devstore.go), and this harness knows
        # every id it created. No directory scan can attribute a hash-named
        # file to a namespace; recomputing the names can.
        mine = 0
        for did in list(self.created_ids) + list(self.absorbed.values()):
            name = hashlib.sha256(did.encode("utf-8")).hexdigest()
            if os.path.exists(os.path.join(path, name)):
                mine += 1
        ev["this_run"] = mine
        if total:
            warn(f"TOMBSTONE DEBT: {total} suppressed entries in {path} "
                 f"({mine} of them this run's, namespace {self.prefix}). They "
                 f"are never removed except by re-creating the same device id, "
                 f"the api reads ALL of them at boot, and the onboard rate "
                 f"falls as they accumulate (tracker 175). No API exists to "
                 f"purge them — do NOT delete them under a running api")
        return ev

    def cleanup(self) -> bool:
        ev: dict = {}
        problems: list[str] = []
        if self.args.dry_run:
            return True
        # EXPLICIT time budget, announced up front. Cleanup used to be silent
        # for up to ~15 minutes of bounded waits before the first DELETE, which
        # is indistinguishable from a hang — and got signalled (2026-08-28).
        device_budget = (CLEANUP_DEVICE_BUDGET_BASE_S +
                         CLEANUP_DEVICE_BUDGET_PER_DEVICE_S *
                         max(len(self.created_ids), self.args.devices))
        total_budget = (CLEANUP_DRAIN_WAIT_S + device_budget +
                        CLEANUP_PREPURGE_WAIT_S)
        log(f"cleanup: starting — budget up to {total_budget / 60:.0f} min "
            f"(drain wait {CLEANUP_DRAIN_WAIT_S:.0f}s + device purge "
            f"{device_budget:.0f}s + pre-purge wait "
            f"{CLEANUP_PREPURGE_WAIT_S:.0f}s), then the ClickHouse purge and "
            f"an ASYNC OpenSearch purge whose own budget scales with the doc "
            f"count ({OS_PURGE_BUDGET_BASE_S:.0f}s + 1s per "
            f"{1 / OS_PURGE_SECONDS_PER_DOC:.0f} docs). "
            f"Signals during cleanup are ignored — let it finish.")

        # 7·twin: the delegated twin run was kept standing for accounting —
        # tear it down through ITS verified-teardown path now (tracker 152
        # §8.3; twin.py exits non-zero on any teardown residue).
        if self.twin_run.get("runid"):
            twin_py = os.path.join(REPO_ROOT, "scripts", "lab", "twin",
                                   "twin.py")
            rc, out, err = run([sys.executable, twin_py,
                                "--env-file", self.args.env_file,
                                "--project", self.args.project,
                                "--base-url", self.args.base_url,
                                "teardown", "--runid",
                                self.twin_run["runid"]], 1800)
            ev["twin_teardown_rc"] = rc
            if rc != 0:
                problems.append(
                    f"twin teardown rc={rc}: {(err or out).strip()[:200]}")

        # BACKLOG DRAIN GATE (2026-08-19). Deleting the devices while their
        # events are still in flight makes correlation refuse every one of them
        # as identity_unattributable — the registry no longer knows the
        # hostname. Measured on ladder 08191832j027: cleanup began with ~385k
        # events still unconsumed and manufactured **133,349 refusals in two
        # minutes**, all charged to this run's devices. They were invisible
        # because the refusal record withholds the hostname (F-11), and they
        # inflate the lab's standing identity_unattributable rate that tracker
        # 159 is trying to explain.
        #
        # So: wait for the backlog before deleting, and if it will not drain,
        # SAY SO and record how much residue we are about to convert into
        # refusals. This never blocks teardown — an undrained lab must still be
        # cleaned — but it stops the harness quietly polluting its own evidence.
        lag_at_cleanup = self.stack.group_lag("netops-correlation").get("_total", -1)
        if lag_at_cleanup > 0:
            log(f"cleanup: waiting up to {CLEANUP_DRAIN_WAIT_S:.0f}s for the "
                f"correlation backlog ({lag_at_cleanup} events) before deleting "
                f"devices")
            deadline = time.monotonic() + CLEANUP_DRAIN_WAIT_S
            while time.monotonic() < deadline:
                lag_at_cleanup = self.stack.group_lag(
                    "netops-correlation").get("_total", -1)
                if lag_at_cleanup <= 0:
                    break
                time.sleep(15)
        ev["consumer_lag_at_cleanup"] = lag_at_cleanup
        if lag_at_cleanup > 0:
            ev["cleanup_refusals_expected"] = lag_at_cleanup
            warn(f"cleanup starting with {lag_at_cleanup} events still "
                 f"unconsumed — deleting the devices now will refuse them as "
                 f"identity_unattributable; this is harness-induced DLQ traffic, "
                 f"not a product defect, and it is recorded as evidence")

        # 7a+7b. Delete every device under this run's prefix and RE-VERIFY to
        # zero. The purge lists what is ACTUALLY there each pass — the ids this
        # process happens to remember are only a seed, because an interrupt
        # mid-onboard (or a create whose response was lost) leaves devices the
        # run never recorded. Budget is explicit and scales with fleet size.
        #
        # The SEED matters (2026-08-29): a create the API absorbed by dedupe is
        # still PERSISTED under the id we asked for, but the read projection
        # hides it behind the device that absorbed it — so a prefix LIST cannot
        # see it and a list-driven purge cannot delete it. Those ids are exactly
        # `self.absorbed`'s keys; seeding them makes the DELETE happen anyway
        # (delete_devices treats 404 as gone, so an id that was never persisted
        # costs one bounded call).
        shadow_ids = sorted(self.absorbed)
        seed = list(dict.fromkeys(list(self.created_ids) + shadow_ids))
        log(f"cleanup: purging devices under {self.prefix} "
            f"({len(self.created_ids)} created this run, {len(shadow_ids)} "
            f"absorbed shadow row(s) invisible to a list; budget "
            f"{device_budget:.0f}s)")
        purge = cleanup_step(
            "device purge", problems, purge_devices, self.stack, self.prefix,
            device_budget, seed,
            default=empty_purge_ev(self.prefix, device_budget,
                                   "device purge step raised"))
        ev["device_purge"] = purge
        ev["devices_deleted"] = purge["deleted"]
        ev["absorbed_shadow_ids_seeded"] = len(shadow_ids)
        if not purge["verified_zero"]:
            problems.append(
                f"device purge NOT verified to zero: {purge['remaining']} "
                f"devices still match {self.prefix} after {purge['passes']} "
                f"pass(es), {purge['delete_failed']} delete failures "
                f"(first: {purge['first_delete_error'] or purge['list_error'] or 'n/a'})"
                f" — run: python3 scripts/scale-miniladder.py --cleanup-only "
                f"{self.prefix}")

        # 7b-i. The devices that ABSORBED this run's creates. They are the other
        # half of the same residue: each one hides a shadow row of ours, and
        # they are themselves a previous run's leftovers. Deleted ONLY inside
        # the harness namespace — an absorber outside `mlx-` is somebody's real
        # device and this harness never deletes one (blast-radius guard, 16.3).
        if self.absorbed:
            canonical = sorted({c for c in self.absorbed.values() if c})
            mine = [c for c in canonical if c.startswith(DEVICE_PREFIX_ROOT)]
            outside = [c for c in canonical if not c.startswith(DEVICE_PREFIX_ROOT)]
            ev["absorbed_canonical_count"] = len(canonical)
            ev["absorbed_canonical_ids"] = canonical[:50]
            if outside:
                ev["absorbed_canonical_outside_namespace"] = outside[:20]
                warn(f"cleanup: {len(outside)} device(s) that absorbed this "
                     f"run's creates are OUTSIDE the {DEVICE_PREFIX_ROOT} "
                     f"namespace (first: {outside[0]}) — NOT deleting them; "
                     f"they are not this harness's devices. Our shadow rows "
                     f"behind them stay hidden: purge them by id if this "
                     f"recurs.")
            if mine:
                log(f"cleanup: deleting {len(mine)} device(s) that absorbed "
                    f"this run's creates (previous runs' residue)")
                dele, dfail, dbudget = cleanup_step(
                    "absorbed-canonical deletes", problems, delete_devices,
                    self.stack, mine, time.monotonic() + device_budget,
                    default=(0, ["step raised — deletes not attempted"], False))
                ev["absorbed_canonical_deleted"] = dele
                ev["absorbed_canonical_delete_failed"] = len(dfail)
                if dfail:
                    problems.append(
                        f"{len(dfail)} absorbed-canonical device delete(s) "
                        f"FAILED (first: {dfail[0]})")
                if dbudget:
                    problems.append(
                        "absorbed-canonical deletes ran out of their budget — "
                        "residue is NOT purged")

        # 7b-ii. NAMESPACE verify (and sweep). This is what makes "0 remain"
        # mean the stack is actually clean rather than "clean under MY prefix".
        ns_ev, ns_problems, ns_left = cleanup_step(
            "namespace verify/sweep", problems, self.namespace_sweep,
            device_budget,
            default=({"root_prefix": DEVICE_PREFIX_ROOT, "swept": False,
                      "list_error": "namespace sweep step raised"}, [], -1))
        ev["namespace"] = ns_ev
        problems.extend(ns_problems)
        ev["devices_remaining"] = ns_left
        self.residue_devices = ns_left              # -1 = could not verify

        # 7c. Wait (bounded) for the consumer to finish draining before purging:
        # a purge issued while lag is still draining races the engine's late
        # inserts, which then land AFTER the delete and survive as residue —
        # proven live 2026-08-16 (run 08162031su88 left exactly its 100
        # coverage rows behind this way). A drain-phase FAIL does not skip
        # this wait: the whole point is to purge after the last insert.
        log(f"cleanup: waiting up to {CLEANUP_PREPURGE_WAIT_S:.0f}s for the "
            f"consumer to finish its last inserts before purging telemetry")
        drain_deadline = time.monotonic() + CLEANUP_PREPURGE_WAIT_S
        lag = -1
        while time.monotonic() < drain_deadline:
            lag = self.stack.group_lag("netops-correlation").get("_total", -1)
            if 0 <= lag <= 100:
                break
            time.sleep(15)
        else:
            problems.append(
                f"consumer lag still {lag} after {CLEANUP_PREPURGE_WAIT_S:.0f}s "
                f"pre-purge wait — purge may race late inserts")
        ev["pre_purge_lag"] = lag

        # Purge run telemetry so the stack (and clean-slate.sh --verify)
        # is left as found. corr_objects/evidence TTL out on their own and are
        # not part of --verify; noted honestly rather than silently skipped.
        log(f"cleanup: purging ClickHouse + OpenSearch rows for {self.prefix}")
        tel_ev, tel_problems = cleanup_step(
            "telemetry purge", problems, purge_telemetry, self.stack,
            self.prefix,
            default=({"ch_signals_left": -1, "os_docs_left": -1}, []))
        ev.update(tel_ev)
        problems.extend(tel_problems)
        ev["residuals_note"] = (
            "corr_objects/evidence and correlation DLQ entries tagged with this "
            "run TTL/rotate out on their own; VictoriaMetrics holds no run "
            "series (devices were never polled successfully)")

        # FINAL RE-VERIFY (defect 2026-08-29). Whatever happened above — a step
        # that failed after its retries, a purge that ran out of budget, a
        # sweep that was skipped — the LAST thing cleanup does is ask the stack
        # what is actually left, and THAT answer is the residue this run
        # reports. Never a step's optimism, and never a stale count from before
        # the telemetry purge. A list that fails after its own retries is
        # UNKNOWN (-1) and says so; it is not zero.
        final_ids, final_err = cleanup_step(
            "residue re-verify", problems, devices_with_prefix, self.stack,
            DEVICE_PREFIX_ROOT,
            default=([], "residue re-verify step raised"))
        if final_err:
            ev["final_verify_error"] = final_err
            problems.append(
                f"final residue re-verify FAILED ({final_err}) — residue under "
                f"{DEVICE_PREFIX_ROOT} is UNKNOWN, not zero. Purge with: "
                f"python3 scripts/scale-miniladder.py --cleanup-only "
                f"{DEVICE_PREFIX_ROOT}")
            self.residue_devices = -1
        else:
            # A run started with MLX_ALLOW_FOREIGN_RESIDUE=1 was TOLD to leave
            # the other run ids standing, so it is answerable for its own
            # prefix only — the same accounting namespace_sweep uses.
            answerable = ([d for d in final_ids if d.startswith(self.prefix)]
                          if self.foreign_residue_allowed else final_ids)
            ev["final_residue_devices"] = len(answerable)
            ev["final_namespace_devices"] = len(final_ids)
            if len(answerable) != ns_left:
                warn(f"cleanup: re-verified residue is {len(answerable)} "
                     f"device(s), not the {ns_left} the purge steps reported — "
                     f"the RE-VERIFIED count is the one this run stands behind")
            self.residue_devices = len(answerable)
            if answerable:
                # A run that leaves devices behind is a FAILED teardown even if
                # every individual step reported success — the re-verify is the
                # only claim this harness makes about the stack it hands back.
                problems.append(
                    f"{len(answerable)} device(s) remain after teardown "
                    f"(re-verified: {residue_summary(answerable)}) — run: "
                    f"python3 scripts/scale-miniladder.py --cleanup-only "
                    f"{DEVICE_PREFIX_ROOT}")
                self.residue_left("verified after every teardown step ran")

        # AFTER the namespace sweep: this run's share of the debt is only
        # complete once every device it created has actually been deleted.
        #
        # Its failures go to their OWN list, not `problems`: the tombstone
        # count is diagnostic evidence about a PLATFORM debt (tracker 175),
        # not a teardown obligation. A device store this harness cannot count
        # is not a teardown this run got wrong, and failing the phase on it
        # would put a red cleanup on every deployment whose /data is not a
        # host bind mount. cleanup_step still warns by name, and the reason is
        # recorded in the evidence — reported, never silent.
        debt_problems: list[str] = []
        ev["tombstones"] = cleanup_step(
            "tombstone debt", debt_problems, self.tombstone_debt,
            default={"reachable": False, "reason": "tombstone count raised"})
        if debt_problems:
            ev["tombstones"]["error"] = "; ".join(debt_problems)

        ev["http_transport_failures"] = getattr(
            self.stack, "http_transport_failures", 0)
        if ev["http_transport_failures"]:
            warn(f"cleanup: {ev['http_transport_failures']} API call(s) "
                 f"exhausted the retry policy during this run — the box was "
                 f"refusing/timing out under load; recorded as evidence")

        status = "PASS" if not problems else "FAIL"
        # 16.1: a degraded teardown is LOUD, line by line, with counts — not a
        # single collapsed notes string nobody reads until the report.
        for prob in problems:
            warn(f"cleanup: {prob}")
        left_note = (f"0 {DEVICE_PREFIX_ROOT} devices of ANY run id remain"
                     if not ev["namespace"].get("foreign_remaining")
                     else (f"0 of this run's devices remain; "
                           f"{ev['namespace']['foreign_remaining']} foreign "
                           f"{DEVICE_PREFIX_ROOT} device(s) left standing on "
                           f"purpose ({ALLOW_FOREIGN_RESIDUE_ENV}=1)"))
        return self.phase("cleanup", status, ev,
                          "; ".join(problems) if problems else
                          f"{ev['devices_deleted']} devices deleted+verified "
                          f"({left_note}), telemetry purged (CH+OS)")

    def namespace_sweep(self, budget_s: float) -> tuple[dict, list[str], int]:
        """Verify — and, when this process is provably the only harness run,
        PURGE — the WHOLE `mlx-` namespace, not just this run's prefix.

        THE 2026-08-29 DEFECT. Two overlapping runs each verified their own
        prefix to zero and both were telling the truth; 1,000 devices survived
        anyway, because the absorbed shadow rows only became visible once the
        OTHER run's devices were deleted. A per-prefix verdict therefore cannot
        support the sentence "the stack is left as found" — only a
        namespace-wide one can.

        Sweeping is gated on OWNING THE RUN LOCK (nothing else can be standing
        in the namespace) AND on this run having actually started (a run
        refused at preflight must leave the residue it refused over in place —
        the operator was sent to `--cleanup-only`, and deleting the evidence
        under them would be the second surprise of the day). A deliberate
        MLX_ALLOW_FOREIGN_RESIDUE=1 run never sweeps and is never charged for
        the rows it was told to expect.

        Returns (evidence, problems, remaining) where `remaining` is the number
        of mlx- devices this run is answerable for; -1 means UNKNOWN.
        """
        ev: dict = {"root_prefix": DEVICE_PREFIX_ROOT,
                    "owns_run_lock": self.owns_run_lock,
                    "swept": False}
        problems: list[str] = []
        found, err = devices_with_prefix(self.stack, DEVICE_PREFIX_ROOT)
        if err:
            ev["list_error"] = err
            problems.append(
                f"the {DEVICE_PREFIX_ROOT} namespace could not be listed "
                f"({err}) — residue is UNKNOWN, not zero")
            return ev, problems, -1
        own = [d for d in found if d.startswith(self.prefix)]
        foreign = sorted(d for d in found if not d.startswith(self.prefix))
        ev["own_remaining"] = len(own)
        ev["foreign_remaining"] = len(foreign)
        ev["foreign_by_run"] = residue_by_run(foreign)[:RESIDUE_RUN_IDS_SHOWN]
        ev["foreign_sample"] = foreign[:10]
        if not found:
            return ev, problems, 0
        if foreign:
            warn(f"cleanup: FOREIGN RESIDUE in the harness namespace — "
                 f"{residue_summary(foreign)}")
        if self.foreign_residue_allowed:
            ev["foreign_residue_allowed"] = True
            warn(f"cleanup: leaving {len(foreign)} foreign "
                 f"{DEVICE_PREFIX_ROOT} device(s) standing because this run was "
                 f"started with {ALLOW_FOREIGN_RESIDUE_ENV}=1 — the NEXT run "
                 f"will refuse on them unless they are purged: python3 "
                 f"scripts/scale-miniladder.py --cleanup-only "
                 f"{DEVICE_PREFIX_ROOT}")
            return ev, problems, len(own)
        if not (self.owns_run_lock and self.preflight_ok):
            why = ("this process does not hold the run lock, so another "
                   "harness run may own them"
                   if not self.owns_run_lock else
                   "this run was REFUSED at preflight over exactly this "
                   "residue — it is left in place for the operator who was "
                   "sent to --cleanup-only")
            problems.append(
                f"{len(found)} {DEVICE_PREFIX_ROOT} device(s) remain "
                f"({residue_summary(found)}) and were NOT swept: {why}. Purge "
                f"with: python3 scripts/scale-miniladder.py --cleanup-only "
                f"{DEVICE_PREFIX_ROOT}")
            return ev, problems, len(found)
        log(f"cleanup: sweeping the whole {DEVICE_PREFIX_ROOT} namespace — "
            f"{len(found)} device(s) left, {len(foreign)} of them from other "
            f"run ids ({residue_summary(foreign) if foreign else 'none'}). This "
            f"process holds the run lock, so no other harness run owns them.")
        sweep = purge_devices(self.stack, DEVICE_PREFIX_ROOT, budget_s)
        ev["sweep"] = sweep
        ev["swept"] = True
        if sweep["verified_zero"]:
            ev["own_remaining"] = 0
            ev["foreign_remaining"] = 0
            return ev, problems, 0
        left = sweep["remaining"]
        shown = left if left >= 0 else "UNKNOWN"
        problems.append(
            f"the {DEVICE_PREFIX_ROOT} namespace is NOT verified empty: {shown} "
            f"device(s) still standing after {sweep['passes']} sweep pass(es), "
            f"{sweep['delete_failed']} delete failure(s) (first: "
            f"{sweep['first_delete_error'] or sweep['list_error'] or 'n/a'}) — "
            f"run: python3 scripts/scale-miniladder.py --cleanup-only "
            f"{DEVICE_PREFIX_ROOT}")
        return ev, problems, left

    # -- report --------------------------------------------------------------
    def report(self) -> bool:
        overall = all(p["status"] == "PASS" for p in self.phases) and bool(self.phases)
        doc = {
            "harness": "scale-miniladder",
            "runid": self.runid,
            "generated": utcnow(),
            "overall": "PASS" if overall else "FAIL",
            "parameters": {
                "devices": self.args.devices,
                "burst_minutes": self.args.burst_minutes,
                "eps": self.args.eps,
                "event_mix": self.args.event_mix,
                "profile": self.args.profile,
                "workload_class": self.profile["workload_class"],
                "producer_key": self.args.producer_key,
                "load_generator": self.args.load_generator,
                "linearity_floor": self.args.linearity_floor,
                "drain_factor": self.args.drain_factor,
                "lag_epsilon": self.args.lag_epsilon,
                "mem_factor": self.args.mem_factor,
                # Tracker 210: the host the numbers were measured on. UNQUIET
                # means the disk/load gate was overridden with --allow-unquiet
                # and this run is not accounting-graded evidence.
                "host_quiet": self.host_quiet,
                "min_free_gib": self.args.min_free_gib,
                "max_load1": self.args.max_load1,
                "allow_unquiet": bool(self.args.allow_unquiet),
                "tls_variant": self.stack.tls,
                "base_url": self.stack.base_url,
            },
            "phases": self.phases,
        }
        with open(os.path.join(self.run_dir, "report.json"), "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1)

        lines = [
            f"# G2 scale mini-ladder — run {self.runid}",
            "",
            f"- **Overall: {'PASS' if overall else 'FAIL'}**",
            f"- Generated: {doc['generated']}",
            (f"- Stack: {self.stack.base_url} (TLS variant: {self.stack.tls}, "
             f"project `{self.args.project}`)"),
            (f"- Parameters: {self.args.devices} devices, "
             f"{self.args.burst_minutes} min burst @ {self.args.eps} eps target, "
             f"event mix `{self.args.event_mix}`, "
             f"linearity floor {self.args.linearity_floor}, "
             f"drain budget {self.args.drain_factor}x burst, "
             f"lag epsilon {self.args.lag_epsilon}, mem factor {self.args.mem_factor}"),
            "",
            "| Phase | Status | Notes |",
            "|---|---|---|",
        ]
        for p in self.phases:
            notes = " ".join(p["notes"].replace("|", "\\|").split())
            lines.append(f"| {p['phase']} | {p['status']} | {notes} |")
        lines += ["", "## Evidence", ""]
        for p in self.phases:
            lines.append(f"### {p['phase']} ({p['status']})")
            lines.append("```json")
            lines.append(json.dumps(p["evidence"], indent=1, default=str)[:6000])
            lines.append("```")
            lines.append("")
        lines.append("Raw evidence files (lag curve, burst chunks) sit next to this "
                      "report in the run directory.")
        with open(os.path.join(self.run_dir, "report.md"), "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

        # Heartbeat for the watchdog (16.2): a cron job that silently stops
        # running must itself be detectable.
        #
        # TRACKER 175: it also carries the ONBOARD-RATE TREND. The tombstone
        # debt is invisible inside one run — every run sees a rate that looks
        # merely slow — and only shows as a slope across runs (30-43/s ->
        # 15.4/s over one day on the lab box). A per-run number nobody can
        # compare is not evidence; the last ONBOARD_RATE_HISTORY runs' first-
        # window create rate, beside the tombstone count that day, is.
        hb_path = os.path.join(os.path.dirname(self.run_dir), "last-run.json")
        hb = {"ts": doc["generated"], "runid": self.runid,
              "overall": doc["overall"], "run_dir": self.run_dir,
              "onboard_rate_first": self._phase_value(
                  "onboard", "first_window_rate_per_s"),
              "onboard_rate_last": self._phase_value(
                  "onboard", "last_window_rate_per_s"),
              "devices": self.args.devices,
              "tombstones": (self._phase_value("cleanup", "tombstones") or {})
              .get("suppressed_entries", -1)}
        hb["onboard_rate_history"] = self._rate_history(hb_path, hb)
        with open(hb_path, "w", encoding="utf-8") as f:
            json.dump(hb, f, indent=1)
        trend = hb["onboard_rate_history"]
        if len(trend) >= 2 and trend[0].get("rate") and trend[-1].get("rate"):
            first, last = trend[0]["rate"], trend[-1]["rate"]
            if first > 0:
                log(f"onboard-rate trend over the last {len(trend)} run(s): "
                    f"{first:.1f}/s -> {last:.1f}/s (x{last / first:.2f}); "
                    f"device-store tombstones now {hb['tombstones']} "
                    f"(tracker 175)")
        log(f"report written: {os.path.join(self.run_dir, 'report.md')}")
        return overall

    def _phase_value(self, phase: str, key: str):
        """One evidence value from a phase this run recorded, or None.

        None means "this run did not record it" — never a substituted 0, which
        would enter the trend as a real measurement."""
        for entry in self.phases:
            if entry.get("phase") == phase:
                return (entry.get("evidence") or {}).get(key)
        return None

    def _rate_history(self, hb_path: str, hb: dict) -> list[dict]:
        """This run appended to the previous heartbeat's trend, bounded.

        A heartbeat that cannot be read starts the history at this run rather
        than failing the report: the trend is diagnostic evidence, and losing
        it must never cost the run its verdict. It is WARNED, not swallowed."""
        history: list = []
        try:
            with open(hb_path, encoding="utf-8") as f:
                history = (json.load(f) or {}).get("onboard_rate_history") or []
        except FileNotFoundError:
            history = []          # first run against this run-root
        except (OSError, json.JSONDecodeError, AttributeError) as exc:
            warn(f"previous {hb_path} unreadable ({exc!r}) — the onboard-rate "
                 f"trend restarts at this run")
            history = []
        if not isinstance(history, list):
            warn(f"{hb_path} carried a non-list onboard_rate_history — "
                 f"the trend restarts at this run")
            history = []
        history.append({"ts": hb["ts"], "runid": hb["runid"],
                        "devices": hb["devices"], "rate": hb["onboard_rate_first"],
                        "tombstones": hb["tombstones"]})
        return history[-ONBOARD_RATE_HISTORY:]

    # -- orchestration -------------------------------------------------------
    def execute(self) -> int:
        os.makedirs(self.run_dir, exist_ok=True)
        log(f"run {self.runid} -> {self.run_dir}")
        aborted_early = False
        try:
            if not self.preflight():
                # A broken stack means nothing was created — report and stop
                # without inventing results for phases that never ran.
                aborted_early = True
            else:
                self.onboard()
                self.stability_t0 = time.monotonic()
                if self.onboard_stop_reason != "none":
                    # 2026-08-29: run mlx-08290322msp1 FAILED onboard (1,000 of
                    # 2,500 creates absorbed by dedupe into a concurrent run's
                    # devices) and then injected its full burst anyway — 900k
                    # events keyed to devices whose identity the engine
                    # attributes to somebody else. A fleet the run cannot
                    # attribute ("absorbed"), or a fleet smaller than the one
                    # planned ("shortfall"), makes every downstream number
                    # noise: the workload is SKIPPED and teardown runs
                    # immediately. A linearity-ratio FAIL is NOT this case —
                    # it reads "none" and carries on (owner decision).
                    warn(f"onboard stop={self.onboard_stop_reason} — skipping "
                         f"burst/drain/completion/accounting/memflat/stability "
                         f"and going straight to cleanup: "
                         + ("creates were absorbed into other devices, so this "
                            "run's events would be attributed elsewhere"
                            if self.onboard_stop_reason == "absorbed" else
                            f"only {len(self.created_ids)} of "
                            f"{self.args.devices} requested devices exist, so "
                            f"the burst would be judged against a fleet that "
                            f"was never built"))
                    self.phase(
                        "workload", "SKIPPED",
                        {"onboard_stop_reason": self.onboard_stop_reason,
                         "devices_requested": self.args.devices,
                         "devices_created": len(self.created_ids),
                         "devices_absorbed_by_dedupe": len(self.absorbed),
                         "skipped_phases": ["burst", "drain",
                                            "correlation_completion",
                                            "accounting", "memflat",
                                            "stability"]},
                        f"burst and everything downstream skipped "
                        f"(stop={self.onboard_stop_reason}) — the onboarded "
                        f"fleet is not the one this run would be judged on")
                elif self.created_ids:
                    if self.burst():
                        # Leak anchor: sampled the instant injection stops, so
                        # the workload's caches/buffers are materialized but
                        # nothing new is arriving (see memflat's header).
                        self.warm_mem = self.stack.mem_sample()
                        self.warm_anon = self.stack.anon_sample(
                            self._anon_services())
                        self._ch_sample_metrics()
                        self.drain()
                        # TRACKER 170: transport drain and ingest accounting
                        # both pass while the engine has evaluated nothing. The
                        # correlation-completion gate runs here, and the overall
                        # verdict depends on it like any other phase.
                        self.correlation_completion()
                        self.accounting()
                    # A burst FAIL still leaves a warmed stack worth judging —
                    # unchanged behaviour; only an onboard FAIL skips these.
                    self.memflat()
                    # AFTER everything else: instability that appears late is
                    # the whole reason this phase exists.
                    self.stability()
        except KeyboardInterrupt:
            warn("interrupted — running the FULL cleanup before exit "
                 "(device purge + telemetry purge); further signals are "
                 "ignored while it runs")
            self.phase("interrupted", "FAIL", {}, "run interrupted by signal")
        finally:
            self.run_cleanup()
        # The guard stays armed through report(): a signal that lands between
        # the purge and the evidence would otherwise cost the run its report,
        # which is exactly the 2026-08-28 shape one step later.
        overall = False
        try:
            overall = self.report()
        except (CleanupAborted, KeyboardInterrupt) as exc:
            warn(f"report interrupted ({exc!r}) — the run's evidence is "
                 f"incomplete; the stack was already cleaned above")
        finally:
            self.interrupts.leave_cleanup()
        self.verdict(overall)
        if aborted_early:
            return 2
        if self.residue_devices != 0 and not getattr(self.args, "skip_cleanup", False):
            # Residue is a run outcome, not a footnote: the next run's onboard
            # collides with it. (--skip-cleanup leaves it ON PURPOSE and keeps
            # its historical exit code.)
            return 1
        return 0 if overall else 1

    def run_cleanup(self) -> None:
        """Cleanup, with the signal policy that makes it survivable.

        Everything below is failure handling that USED to be missing: a second
        signal aborted the purge through `except Exception` (KeyboardInterrupt
        is a BaseException), report() never ran, and the residue was never
        named. Now cleanup owns the signals while it runs, and every exit path
        states the residue and the command that finishes the job.
        """
        # Armed for the whole teardown INCLUDING report(); execute() disarms.
        self.interrupts.enter_cleanup()
        if getattr(self.args, "skip_cleanup", False):
            self.residue_devices = len(self.created_ids)
            self.phase(
                "cleanup", "SKIPPED",
                {"reason": "--skip-cleanup (diagnostic run)",
                 "residue_devices": self.residue_devices,
                 "residue_warning": (
                     "devices, corr_signals, corr_objects and OpenSearch "
                     "docs are STILL PRESENT and will be counted by the "
                     "next run's baselines")},
                "cleanup deliberately skipped for investigation — this "
                "run is NOT qualification evidence")
            return
        try:
            self.cleanup()
        except CleanupAborted as exc:
            self.residue_left(f"cleanup aborted on repeated {exc} during teardown")
            self.phase("cleanup", "FAIL",
                       {"aborted_by_signal": str(exc),
                        "residue_devices": self.residue_devices},
                       f"cleanup ABORTED by repeated {exc} — residue left")
        except KeyboardInterrupt as exc:
            # Belt and braces: a KeyboardInterrupt can still arrive from a
            # handler this process does not own (e.g. one installed by an
            # embedding runner). It must NOT escape past report().
            self.residue_left(f"cleanup interrupted ({exc!r})")
            self.phase("cleanup", "FAIL",
                       {"aborted_by_signal": repr(exc),
                        "residue_devices": self.residue_devices},
                       f"cleanup interrupted: {exc!r} — residue left")
        except Exception as exc:  # noqa: BLE001 — cleanup must never mask the run error silently
            warn(f"cleanup raised: {exc!r}")
            self.residue_left(f"cleanup crashed: {exc!r}")
            self.phase("cleanup", "FAIL",
                       {"error": repr(exc),
                        "residue_devices": self.residue_devices},
                       f"cleanup crashed: {exc!r}")

    def residue_left(self, why: str) -> None:
        """Name the residue and the exact command that clears it (16.1)."""
        left = self.residue_devices
        shown = "UNKNOWN (never verified)" if left < 0 else str(left)
        warn(f"RESIDUE LEFT: {shown} devices matching {self.prefix} — {why}. "
             f"Purge with: python3 scripts/scale-miniladder.py --cleanup-only "
             f"{self.prefix}  (or --cleanup-only {DEVICE_PREFIX_ROOT} to clear "
             f"the whole harness namespace, which is what the NEXT run's "
             f"preflight refuses on)")

    def verdict(self, overall: bool) -> None:
        """The last line of a run always states the residue count — a clean
        stack is a claim, and an unverified one must never look like zero."""
        left = self.residue_devices
        if left == 0:
            residue = (f"residue: 0 devices (verified) in the "
                       f"{DEVICE_PREFIX_ROOT} namespace")
        elif left > 0:
            residue = (f"residue: {left} devices matching {self.prefix} or "
                       f"another {DEVICE_PREFIX_ROOT} run id — run "
                       f"--cleanup-only {DEVICE_PREFIX_ROOT}")
        else:
            residue = (f"residue: UNKNOWN (device purge never verified) — run "
                       f"--cleanup-only {self.prefix}")
        log(f"VERDICT {'PASS' if overall else 'FAIL'} run {self.runid}: {residue}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="scale-miniladder.py",
        description="G2 self-judging scale-regression harness (see module docstring; "
                    "--help shows flags, the header shows the cron line).")
    ap.add_argument("--devices", type=int, default=1000,
                    help="devices to create for the onboarding probe (default 1000)")
    ap.add_argument("--burst-minutes", type=int, default=5,
                    help="ingest burst duration in minutes (default 5)")
    ap.add_argument("--burst-window-factor", type=float,
                    default=BURST_WINDOW_MAX_FACTOR,
                    help="how far the burst window may stretch to absorb a slow "
                         "injector before the phase FAILS, as a multiple of the "
                         f"profile window (default {BURST_WINDOW_MAX_FACTOR}). The "
                         "fleet size is NEVER reduced to fit the window")
    ap.add_argument("--eps", type=int, default=2000,
                    help="target injected events/second — pick ~10x your nominal "
                         "syslog rate and ABOVE the ~1k/s correlation drain ceiling "
                         "so the drain proof is not vacuous (default 2000)")
    ap.add_argument("--linearity-floor", type=float, default=0.6,
                    help="last-window/first-window creation-rate floor (default 0.6)")
    ap.add_argument("--drain-factor", type=float, default=3.0,
                    help="drain budget as a multiple of burst duration (default 3.0)")
    ap.add_argument("--lag-epsilon", type=int, default=100,
                    help="allowed lag above baseline to count as drained (default 100)")
    ap.add_argument("--max-baseline-lag", type=int, default=5000,
                    help="refuse to run when correlation lag already exceeds this "
                         "at preflight — the drain verdict needs a near-idle "
                         "baseline (default 5000)")
    ap.add_argument("--mem-factor", type=float, default=1.3,
                    help="max end/WARM container memory ratio — the leak slope "
                         "after injection stops (default 1.3). The cold->warm "
                         "step is evidence, not a verdict: a short burst cannot "
                         "separate first-touch cache materialization from a leak")
    ap.add_argument("--mem-headroom-percent", type=float, default=85.0,
                    help="fail when a key container ends above this percentage "
                         "of ITS OWN plan-sized memory cap (#102) — the OOM "
                         "path, self-relative so it holds on any host "
                         "(default 85)")
    ap.add_argument("--min-free-gib", type=float, default=MIN_FREE_GIB_DEFAULT,
                    help=f"refuse to start when the root filesystem has less "
                         f"free space than this (default "
                         f"{MIN_FREE_GIB_DEFAULT:.0f} GiB, the V1 section 8(e) "
                         f"floor). storm-s10 started at 10.8 GiB, crossed "
                         f"OpenSearch's flood-stage watermark mid-burst and lost "
                         f"291,296 evidence docs (tracker 209/210)")
    ap.add_argument("--max-load1", type=float, default=MAX_LOAD1_DEFAULT,
                    help=f"refuse to start when host load1 exceeds this "
                         f"(default {MAX_LOAD1_DEFAULT}). storm-s11 launched at "
                         f"2.9; storm-s10, excluded for environment violation, "
                         f"at 16-38")
    ap.add_argument("--allow-unquiet", action="store_true",
                    help="proceed despite a --min-free-gib / --max-load1 "
                         "violation, recording UNQUIET in the preflight evidence "
                         "and in report.json parameters. The leg is then NOT "
                         "accounting-graded evidence")
    ap.add_argument("--consumer-settle-seconds", type=int, default=180,
                    help="bounded wait for the correlation + router consumer "
                         "groups to show a live member at preflight. Bring-up "
                         "cost is hardware-dependent (a cold CI runner spends a "
                         "JVM per topic in kafka-init, so the engine's final "
                         "rebalance can land minutes after compose returns); "
                         "patience is tuned here, the assertion never is "
                         "(default 180)")
    ap.add_argument("--run-dir", default="",
                    help="run directory (default <repo>/data/miniladder/<ts>-<runid>)")
    ap.add_argument("--env-file",
                    default=os.path.join(REPO_ROOT, "deployment", "docker", ".env"),
                    help="compose .env for credentials/topology (default repo's)")
    ap.add_argument("--base-url", default="",
                    help="API base URL (default http://localhost:<BASE_PORT from .env>)")
    ap.add_argument("--project", default="",
                    help="compose project name (default COMPOSE_PROJECT_NAME or netops)")
    ap.add_argument(
        "--skip-cleanup", action="store_true",
        help="DIAGNOSTIC ONLY. Leave devices, ClickHouse rows and OpenSearch "
             "docs in place so the run can be investigated afterwards. The "
             "2026-08-19 927/1000 coverage gap could not be diagnosed because "
             "cleanup purges the run's rows before anything can query them. "
             "Never use for qualification: the next run inherits the residue.")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the full plan and exit; touches nothing")
    ap.add_argument(
        "--rescore-memflat", default="", metavar="RUN_DIR",
        help="OFFLINE RE-SCORE, no run. Re-judges a FINISHED run's memflat "
             "verdict from its own report.json + correlation-completion.json "
             "and a READ-ONLY system.metric_log query for that run's window, "
             "using the current clauses. Writes "
             f"{RESCORE_FILE} into RUN_DIR and NEVER touches the run's own "
             "report files. Exit 0 = re-scored PASS, 1 = not PASS, 2 = could "
             "not re-score.")
    ap.add_argument("--rescore-window-start", default="", metavar="TS",
                    help="ClickHouse window start for --rescore-memflat as "
                         "'YYYY-MM-DD HH:MM:SS' (default: the window recorded "
                         "in the run's memflat evidence; runs before "
                         "2026-08-29 carry none, so it must be given)")
    ap.add_argument("--rescore-window-end", default="", metavar="TS",
                    help="ClickHouse window end for --rescore-memflat "
                         "(default: open — everything since the start)")
    ap.add_argument(
        "--cleanup-only", nargs="?", const=DEVICE_PREFIX_ROOT, default=None,
        metavar="PREFIX", dest="cleanup_only",
        help="RESIDUE PURGE, no run. Deletes every device whose id starts with "
             f"PREFIX (default '{DEVICE_PREFIX_ROOT}' — the harness namespace, "
             "and the ONLY namespace this mode will touch), re-verifies to "
             "zero, then purges the matching ClickHouse/OpenSearch rows. "
             "Idempotent: safe to run twice, and on an already-clean stack. "
             "Refuses to run if the stack is unreachable. Exit 0 only when "
             "zero devices remain. Use it after an interrupted run says "
             "RESIDUE LEFT.")
    # tracker 152 §8.3 — twin composition. Default is the internal generator,
    # byte-identical to the pre-flag behavior.
    ap.add_argument("--profile", choices=tuple(sorted(WORKLOAD_PROFILES)),
                    default="legacy",
                    help="Ratified workload profile (gate spec §5/§6): overrides "
                         "eps / burst-minutes / event-mix (and defines lanes for "
                         "storm profiles). 'legacy' keeps raw args and the "
                         "historical single-lane injection loop, byte-identical. "
                         "T-family = provisioning gates (must fully complete); "
                         "S-family = storm gates (invariants + recovery); "
                         "t-storm-* = a T-family throughput with a SEEDED "
                         "fault-injection scenario (recovery / contradiction / "
                         "corroboration / blast-radius expansion) and a "
                         "ground-truth.json in the run dir. "
                         "--devices is never overridden.")
    ap.add_argument("--scenario-seed", type=int, default=SCENARIO_SEED_DEFAULT,
                    dest="scenario_seed",
                    help="seed for the fault-injection SCENARIO of a scenario "
                         "profile (--profile t-storm-*). The scenario is a pure "
                         "function of (profile, seed, device list): the same "
                         "seed plans the identical incidents and the identical "
                         "event stream on any box, which is what makes an A/B "
                         "across engine changes honest (memo section 23). "
                         "Ignored by every non-scenario profile. Default "
                         f"{SCENARIO_SEED_DEFAULT} — the RATIFIED seed; change "
                         "it only for a deliberately different scenario, and "
                         "say so on every number the run produces.")
    ap.add_argument("--producer-key", choices=("tenant", "none"), default="tenant",
                    help="Kafka message key for injected events. 'tenant' "
                         "(default) keys every record by the created devices' "
                         "registry tenant — the PRODUCTION topology (Vector keys "
                         "by tenant, so one replica owns the whole tenant). "
                         "'none' is the legacy null-key shape, which round-robins "
                         "one tenant across all partitions/replicas — kept ONLY "
                         "for explicit comparison runs; its per-replica numbers "
                         "are per-half-tenant and must be labelled as such.")
    ap.add_argument("--event-mix", choices=("single", "realistic"), default="single",
                    help="internal generator workload shape. 'single' (default) "
                         "emits only %%LINK-3-UPDOWN, i.e. ONE correlation signal "
                         "kind — the historical workload every recorded capacity "
                         "number was measured on. 'realistic' emits a weighted "
                         "mnemonic mix yielding six distinct kinds across two "
                         "entity scopes, which is what tracker 167's signal-kind "
                         "template index has to be judged against; a single-kind "
                         "window is its friendly case. Deterministic in sequence "
                         "number either way, so accounting stays exact.")
    ap.add_argument("--load-generator", choices=("internal", "twin"),
                    default="internal", dest="load_generator",
                    help="burst-phase load source: internal (default; the "
                         "built-in syslog loop) or twin (delegate to "
                         "scripts/lab/twin/twin.py run — the ladder keeps "
                         "judging; the twin's twin-report.json counts feed "
                         "accounting)")
    ap.add_argument("--twin-scenario", default="",
                    help="scenario file for --load-generator twin")
    ap.add_argument("--twin-duration-minutes", type=float, default=10.0,
                    help="twin run duration (twin mode only; default 10)")
    ap.add_argument("--twin-fidelity", choices=("hostname", "source_ip"),
                    default="hostname",
                    help="fidelity mode passed through to twin.py (default "
                         "hostname)")
    args = ap.parse_args(argv)
    if (args.cleanup_only is not None and
            not args.cleanup_only.startswith(DEVICE_PREFIX_ROOT)):
        # Blast-radius guard (16.3): this mode deletes devices. It may only
        # ever address the harness's own namespace.
        ap.error(f"--cleanup-only prefix must start with '{DEVICE_PREFIX_ROOT}' "
                 f"(got {args.cleanup_only!r}) — this mode never deletes "
                 f"anything outside the harness namespace")
    if args.load_generator == "twin" and not args.twin_scenario:
        ap.error("--load-generator twin requires --twin-scenario FILE")
    if args.devices < 10 or args.devices > 20000:
        ap.error("--devices must be between 10 and 20000")
    if args.burst_minutes < 1 or args.burst_minutes > 60:
        ap.error("--burst-minutes must be between 1 and 60")
    if args.eps < 10 or args.eps > 20000:
        ap.error("--eps must be between 10 and 20000")
    return args


def main(argv: list[str]) -> int:
    os.environ["PATH"] = CRON_PATH          # see CRON_PATH: process-entry only
    args = parse_args(argv)
    # Ratified profile overrides (gate spec §5): a profile is authoritative for
    # rate/duration/mix. --devices and every judging knob stay the user's.
    _prof = WORKLOAD_PROFILES[args.profile]
    for _k in ("eps", "burst_minutes", "event_mix"):
        if _k in _prof:
            setattr(args, _k, _prof[_k])
    if not args.project:
        args.project = env_get(args.env_file, "COMPOSE_PROJECT_NAME") or "netops"
    if not args.base_url:
        port = env_get(args.env_file, "BASE_PORT") or "8000"
        args.base_url = f"http://localhost:{port}"

    if args.dry_run and args.cleanup_only is not None:
        # 16.3 dry-run-before-destructive: say exactly what would be deleted.
        print("scale-miniladder DRY RUN (--cleanup-only) — nothing will be touched")
        print(f"  stack   : {args.base_url} (project {args.project})")
        print(f"  would delete EVERY device whose id starts with "
              f"{args.cleanup_only!r}, re-verify to zero (page-loop), then "
              f"purge netops.corr_signals rows and netops-syslog-* docs "
              f"matching it")
        return 0
    if args.dry_run:
        # THE PROFILE'S plan, not --eps: a lane profile never reads --eps, and
        # printing it told a 10K rung's operator 2,000/s while the run would
        # inject 4,000/s. Same function the burst plans from.
        _lanes = _prof.get("lanes") or []
        _duration = int(args.burst_minutes * 60)
        if _lanes:
            _plan = lane_chunk_plan(_lanes, _duration)
            planned = sum(sum(row.values()) for row in _plan)
            rate_note = (f"{planned / max(1, _duration):.0f}/s across "
                         f"{len(_lanes)} lane(s)")
        else:
            planned = args.eps * _duration
            rate_note = f"{args.eps}/s"
        print("scale-miniladder DRY RUN — nothing will be touched")
        print(f"  stack           : {args.base_url} (project {args.project}, "
              f"env {args.env_file})")
        print(f"  run lock         : {RUN_LOCK_PATH} (refuses to start while a "
              f"live pid holds it; a stale lock is reclaimed)")
        _q = host_quiet_readings(args.min_free_gib, args.max_load1)
        print(f"  host quiet gate  : root-fs {_q['free_gib']} GiB free (floor "
              f"{args.min_free_gib:.0f}), load1 {_q['load1']} (bound "
              f"{args.max_load1}) -> "
              f"{'QUIET' if not host_quiet_problems(_q) else 'REFUSE'}"
              f"{' [--allow-unquiet: would PROCEED, stamped UNQUIET]' if args.allow_unquiet else ''}")
        print(f"  phase 1 preflight: REFUSES on any leftover {DEVICE_PREFIX_ROOT} "
              f"device of any run id ({ALLOW_FOREIGN_RESIDUE_ENV}=1 overrides), "
              f"{len(REQUIRED_SERVICES)} required services, "
              f"active bus consumers (bounded wait {args.consumer_settle_seconds}s), "
              f"baselines (RSS/offsets/lag/CH/VM/durability)")
        print(f"  phase 2 onboard  : create {args.devices} devices "
              f"(mlx-<runid>-NNNNN @ 198.18/15); last/first window rate floor "
              f"{args.linearity_floor}; expect ~"
              f"{args.devices / ONBOARD_RATE_PLAN_PER_S:.0f}s at the measured "
              f"{ONBOARD_RATE_PLAN_PER_S:.0f}/s, budget "
              f"{onboard_budget_s(args.devices):.0f}s (informational)")
        print(f"  phase 3 burst    : registry gate + canary, then {planned} syslog "
              f"events @ {rate_note} for {args.burst_minutes} min to "
              f"netops.syslog")
        print(f"  phase 4 drain    : lag back to baseline+{args.lag_epsilon} within "
              f"{args.drain_factor}x burst")
        print("  phase 5 account  : injected == OS-persisted + run DLQ + counted "
              "rejections (exact); per-device corr_signals coverage; zero "
              "quarantine-write-failure movement")
        print(f"  phase 6 memflat  : {', '.join(MEM_SERVICES)} <= x{args.mem_factor} "
              f"of their END-OF-BURST figure (cgroup anon, except "
              f"{'/'.join(MEM_STATELESS_SERVICES)} on docker stats), under "
              f"{args.mem_headroom_percent}% of their own caps; CORRELATION is "
              f"anchored instead on the first sample where each replica reports "
              f"corr_engine_pending==0, judged {CORR_MEM_SETTLE_S:.0f}s later "
              f"(no such sample = UNKNOWN, never a leak verdict); clickhouse also "
              f"zero new {CH_MEM_ERROR} (system.errors delta, cross-checked "
              f"against system.error_log — query_log misses background raises) "
              f"and p99 MemoryTracking < {CH_MEMORY_TRACKING_MAX_PCT}% of "
              f"max_server_memory_usage (peak reported, warned at "
              f"{CH_MEMORY_TRACKING_PEAK_WARN_PCT}%; merge memory "
              f"informational only) and parts back within "
              f"+{(CH_PART_COUNT_GROWTH_MAX - 1) * 100:.0f}% of preflight")
        cbudget = (CLEANUP_DEVICE_BUDGET_BASE_S +
                   CLEANUP_DEVICE_BUDGET_PER_DEVICE_S * args.devices)
        print(f"  phase 7 cleanup  : delete EVERY mlx-<runid>- device (page-loop "
              f"list + the absorbed shadow ids, budget {cbudget:.0f}s), the "
              f"devices that absorbed them, then sweep and re-verify the whole "
              f"{DEVICE_PREFIX_ROOT} namespace to zero, then purge CH/OS run "
              f"telemetry; runs on interrupt too, and signals during it are "
              f"ignored")
        print("  report           : report.md + report.json + last-run.json heartbeat")
        return 0

    if args.rescore_memflat:
        # Read-only and run-lock-free ON PURPOSE: it deletes nothing, writes
        # only its own file, and must stay usable while a run holds the lock.
        # Ahead of the env-file gate too: re-scoring a finished run needs the
        # run's evidence and a ClickHouse container, not this stack's secrets.
        return rescore_memflat(args)

    if not os.path.isfile(args.env_file):
        die(f"env file not found: {args.env_file} (use --env-file)")

    if args.cleanup_only is not None:
        return cleanup_only(args)

    harness = Harness(args)
    # RUN LOCK (2026-08-29). Two harness processes against one stack absorb each
    # other's devices into one another and blind BOTH teardowns. Taken before a
    # single device exists, so a refusal costs nothing and touches nothing.
    lock = RunLock(runid=harness.runid)
    held, msg = lock.acquire()
    if not held:
        die(msg)                          # exit 2: nothing was touched
    log(msg)
    harness.owns_run_lock = True
    # SIGINT/SIGTERM/SIGHUP all unwind into cleanup; signals arriving DURING
    # cleanup are ignored with a message so the device purge cannot be killed
    # halfway (2026-08-28 residue defect — see InterruptGuard).
    harness.interrupts.install()
    try:
        return harness.execute()
    finally:
        # EVERY exit path, including an interrupt that unwound through
        # cleanup: a lock left behind would be reclaimed as stale later, but
        # only after making the next operator read a scary message.
        lock.release()


# ── offline re-score of a finished run's memflat verdict ───────────────────
#
# WHY THIS EXISTS. The two memflat defects fixed on 2026-08-29 (the ClickHouse
# metric_log plausibility filter and correlation's pending-zero anchor) each
# turned a live FAIL into what the evidence actually says. A run costs an hour;
# re-running one to find out what the corrected clauses say about it is not the
# answer. This re-scores a FINISHED run from its own saved evidence plus a
# read-only `system.metric_log` query for that run's window.
#
# It NEVER writes to the run's own report files — the original verdict is the
# record of what the gate said at the time — only `memflat-rescore.md` beside
# them. It touches nothing else: no devices, no purge, no run lock needed.
# VERSIONED ON PURPOSE. The v1 file was written by the plausibility-filter
# clause; this one is written by the clause that replaced it (error delta +
# p99, docs/scale/P2_CLICKHOUSE_PEAK_S06_2026-08-29.md). Two files that say
# different things about the same run must not share a name — a v2 re-score
# silently overwriting a v1 one would destroy the record of what changed.
RESCORE_FILE = "memflat-rescore-v2.md"
# `--mem-factor`'s default, restated for the offline path: a re-score judges a
# FINISHED run, so it must use the threshold that run was judged by, not
# whatever this invocation happens to pass on the command line.
MEM_FACTOR_RESCORE = 1.3


def _rescore_clickhouse(stack, start: str, end: str) -> tuple[dict, list[str]]:
    """Clauses (2a) and (2b) again, over the same window, with the corrected
    instrument: the MEMORY_LIMIT_EXCEEDED count first, then p99 with the peak
    beside it, and the merge peak as INFORMATION with no verdict.

    A finished run has no preflight `system.errors` baseline to subtract, so
    the error input here is the `system.error_log` count over the window — the
    same table the live clause cross-checks against, and the only one that sees
    background-thread raises. If error_log cannot answer, the clause says so
    and refuses; it never reads silence as zero.
    """
    ev: dict = {"window_start": ch_ts(start), "window_end": ch_ts(end) or "(now)"}
    problems: list[str] = []
    cap, cap_source = ch_memory_cap(stack)
    ev["cap_bytes"], ev["cap_source"] = cap, cap_source

    # -- (2a) the customer-visible fact ------------------------------------
    # A FINISHED run has no preflight `system.errors` baseline to subtract, so
    # error_log is the whole clause here — and it only answers when it
    # demonstrably spans the window. "0 rows in a window the table does not
    # cover" is the exact shape of a false all-clear.
    count, source, state = ch_memory_error_window(stack, start, end)
    ev["memory_limit_exceeded"] = count
    ev["memory_limit_exceeded_source"] = source
    ev["memory_limit_exceeded_state"] = state
    ev["victims"] = ""
    if count < 0:
        problems.append(
            f"{CH_MEM_ERROR} count UNAVAILABLE ({source}) — clause (2a) is "
            f"UNKNOWN, and system.query_log cannot stand in for it: it sees "
            f"only statement raises")
    elif count > 0:
        ev["victims"] = ch_memory_error_victims(stack, start, end, count)
        problems.append(
            f"{count} {CH_MEM_ERROR} in the window ({source}) — the store "
            f"refused work for want of its own memory budget. "
            f"Victims: {ev['victims']}")

    # -- (2b) the levels ----------------------------------------------------
    bound = ch_window_bound(start, end)
    if not bound:
        problems.append("no run window on ClickHouse's clock — the memory "
                        "levels cannot be re-scored")
        return ev, problems
    ok, out = stack.ch(CH_PEAK_SELECT + bound)
    if not ok:
        ev["metric_log"] = f"UNAVAILABLE ({out[:160]})"
        problems.append(
            f"system.metric_log unreadable for the window ({out[:160]}) — no "
            f"p99 and no peak: clause (2b) is UNKNOWN. This is the degraded "
            f"path, not a PASS")
        return ev, problems
    cells = out.strip().splitlines()[0].split("\t") if out.strip() else []
    if len(cells) < 5:
        ev["metric_log"] = f"answer unreadable ({out.strip()[:120]!r})"
        problems.append(f"system.metric_log returned {len(cells)} column(s), "
                        f"expected 5 — the window cannot be re-scored")
        return ev, problems
    try:
        peak = _ch_counter(cells[0])
        p99 = _ch_counter(cells[1])
        merges = _ch_counter(cells[2])
        ev["total_samples"] = int(cells[3])
    except (IndexError, ValueError):
        ev["metric_log"] = f"answer unparseable ({out.strip()[:120]!r})"
        problems.append(f"system.metric_log answer unparseable: {out[:200]}")
        return ev, problems
    # The three numbers are published ONLY once the window is known to hold
    # samples: `max()`/`quantileExact()` over an empty set are 0 in ClickHouse,
    # and 0 MiB printed as a peak would read as the flattest server on earth.
    if ev["total_samples"] <= 0:
        ev["metric_log"] = ("0 samples in the window — the table does not hold "
                            "this run (recreated, dropped or TTL-pruned)")
        problems.append("system.metric_log held 0 samples for the window — "
                        "clause (2b) is UNKNOWN, never a PASS")
        return ev, problems
    ev["peak_memory_tracking_bytes"] = peak
    ev["p99_memory_tracking_bytes"] = p99
    ev["peak_merges_memory_bytes"] = merges
    ev["metric_log"] = f"{ev['total_samples']} sample(s) in the window"
    ev["merges_memory_verdict"] = ("INFORMATIONAL — not bounded by the tracked "
                                   "total in ClickHouse 24.8")
    gap = ch_window_gap_s(start, cells[4])
    ev["first_sample"] = ch_ts(cells[4])
    if gap > CH_WINDOW_COVERAGE_SLACK_S:
        ev["metric_log"] = (
            f"PARTIAL — {ev['total_samples']} sample(s), the first at "
            f"{ch_ts(cells[4])}, {gap:.0f}s after the window opened")
    if cap <= 0:
        problems.append(f"effective max_server_memory_usage unreadable "
                        f"({cap_source}) — clause (2b) is UNKNOWN")
        return ev, problems
    ev["memory_tracking_pct"] = round(
        100.0 * ev["peak_memory_tracking_bytes"] / cap, 1)
    ev["p99_memory_tracking_pct"] = round(
        100.0 * ev["p99_memory_tracking_bytes"] / cap, 1)
    ev["warnings"] = []
    if str(ev["metric_log"]).startswith("PARTIAL"):
        ev["warnings"].append(
            f"system.metric_log covers only part of the window "
            f"({ev['metric_log']}) — the p99 is over the covered tail")
    if ev["p99_memory_tracking_pct"] > CH_MEMORY_TRACKING_MAX_PCT:
        problems.append(
            f"p99 MemoryTracking {mib(ev['p99_memory_tracking_bytes'])} is "
            f"{ev['p99_memory_tracking_pct']}% of the {mib(cap)} cap "
            f"(> {CH_MEMORY_TRACKING_MAX_PCT}%) — a sustained level, not a "
            f"transient")
    elif ev["memory_tracking_pct"] >= CH_MEMORY_TRACKING_PEAK_WARN_PCT:
        ev["warnings"].append(
            f"peak MemoryTracking {mib(ev['peak_memory_tracking_bytes'])} "
            f"reached {ev['memory_tracking_pct']}% of the {mib(cap)} cap while "
            f"p99 stayed at {ev['p99_memory_tracking_pct']}% — a transient. "
            + ("It is reported, not failed: no MEMORY_LIMIT_EXCEEDED followed "
               "it" if count == 0 else
               "The FAIL above is the error clause, not this one"))
    return ev, problems


def _rescore_correlation(run_dir: str, memflat_ev: dict) -> tuple[dict, list[str]]:
    """Clause (1) for correlation, anchored at pending 0, from saved evidence.

    Three sources, in order of fidelity: a memflat evidence row already scored
    by the fixed harness; the completion curve's per-replica {pending, rss}
    samples (recorded since 2026-08-29); nothing — which is UNKNOWN, and the
    reason is printed rather than a verdict invented from the old anchor."""
    rows = [r for r in (memflat_ev.get("containers") or [])
            if r.get("service") == "correlation"
            or "-correlation-" in str(r.get("container", ""))]
    out: dict = {"replicas": {}}
    problems: list[str] = []
    scored = [r for r in rows if r.get("anchor") == "corr_engine_pending==0"]
    if scored:
        out["source"] = "memflat evidence (already scored at the pending-zero anchor)"
        for r in scored:
            out["replicas"][r["container"]] = {
                "rss_at_input_stop": r.get("rss_at_input_stop", -1),
                "rss_at_pending_zero": r.get("rss_at_pending_zero", -1),
                "rss_end": r.get("rss_end", -1),
                "ratio_vs_anchor": r.get("ratio_vs_anchor"),
                "verdict": r.get("verdict", "UNKNOWN")}
            if r.get("verdict") == "LEAK":
                problems.append(f"{r['container']}: LEAK SLOPE at the "
                                f"pending-zero anchor (x{r.get('ratio_vs_anchor')})")
            elif r.get("verdict") != "FLAT":
                problems.append(f"{r['container']}: UNKNOWN at the pending-zero "
                                f"anchor")
        return out, problems

    curve_path = os.path.join(run_dir, "correlation-completion.json")
    curve: list = []
    if os.path.isfile(curve_path):
        try:
            with open(curve_path, encoding="utf-8") as f:
                curve = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            problems.append(f"{curve_path} unreadable ({exc!r}) — correlation "
                            f"cannot be re-scored")
            return out, problems
    if not any(isinstance(e, dict) and e.get("per_replica") for e in curve):
        out["source"] = "none"
        problems.append(
            "UNKNOWN: this run predates the per-replica {pending, rss} curve "
            "(added 2026-08-29), so the first sample at which each replica "
            "reported corr_engine_pending == 0 — and its RSS there — was never "
            "recorded. The input-stop anchor in the run's own report cannot "
            "separate a leak from a backlog drain, which is exactly why it is "
            "not reused here. Re-run to get a judged correlation slope")
        return out, problems

    out["source"] = f"correlation-completion.json ({len(curve)} samples)"
    ends = {r.get("container"): r.get("end_bytes", -1) for r in rows}
    track: dict[str, dict] = {}
    for entry in curve:
        for name, rep in (entry.get("per_replica") or {}).items():
            pending = float(rep.get("pending", -1.0))
            rss = int(rep.get("rss", -1))
            row = track.setdefault(name, {"pending_zero_t_s": None,
                                          "rss_at_pending_zero": -1,
                                          "last_pending": -1.0,
                                          "last_t_s": entry.get("t_s", -1.0),
                                          "first_pending": pending})
            row["last_pending"] = pending
            row["last_t_s"] = entry.get("t_s", -1.0)
            if row["pending_zero_t_s"] is None:
                if pending == 0.0 and rss > 0:
                    row["pending_zero_t_s"] = entry.get("t_s", -1.0)
                    row["rss_at_pending_zero"] = rss
            elif pending > 0.0:
                row["pending_zero_t_s"] = None
                row["rss_at_pending_zero"] = -1
    for name, row in sorted(track.items()):
        end = int(ends.get(name, -1))
        ratio = (round(end / row["rss_at_pending_zero"], 3)
                 if row["rss_at_pending_zero"] > 0 and end > 0 else None)
        rec = {"rss_at_pending_zero": row["rss_at_pending_zero"],
               "rss_end": end, "pending_zero_t_s": row["pending_zero_t_s"],
               "last_pending": row["last_pending"],
               "ratio_vs_anchor": ratio, "verdict": "UNKNOWN"}
        out["replicas"][name] = rec
        if row["pending_zero_t_s"] is None:
            problems.append(f"{name}: UNKNOWN — corr_engine_pending never "
                            f"reached 0 (last {row['last_pending']:.0f} at "
                            f"t+{row['last_t_s']}s)")
        elif ratio is None:
            problems.append(f"{name}: UNKNOWN — no end RSS in the report's "
                            f"memflat evidence to compare against")
        else:
            leak = (ratio > MEM_FACTOR_RESCORE
                    and (end - row["rss_at_pending_zero"]) > 64 * 1024**2)
            rec["verdict"] = "LEAK" if leak else "FLAT"
            if leak:
                problems.append(f"{name}: LEAK SLOPE at the pending-zero anchor "
                                f"({mib(row['rss_at_pending_zero'])} -> "
                                f"{mib(end)}, x{ratio})")
    return out, problems


def rescore_memflat(args: argparse.Namespace) -> int:
    """`--rescore-memflat DIR`. Read-only; exit 0 PASS, 1 not-PASS, 2 refused."""
    run_dir = args.rescore_memflat
    if not os.path.isdir(run_dir):
        die(f"--rescore-memflat: {run_dir} is not a directory")
    report_path = os.path.join(run_dir, "report.json")
    memflat_ev: dict = {}
    original = "(no report.json — the run had not written one)"
    if os.path.isfile(report_path):
        try:
            with open(report_path, encoding="utf-8") as f:
                report = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            die(f"--rescore-memflat: {report_path} unreadable ({exc!r})")
        for phase in report.get("phases", []):
            if phase.get("phase") == "memflat":
                memflat_ev = phase.get("evidence") or {}
                original = f"{phase.get('status')} — {phase.get('notes', '')}"
    start = args.rescore_window_start.strip()
    if not start:
        start = str((memflat_ev.get("clickhouse") or {})
                    .get("sample_census", {}).get("window_start", "") or "")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", start):
        die("--rescore-memflat: no ClickHouse window start. This run's report "
            "does not carry one (runs before 2026-08-29 do not), so pass "
            "--rescore-window-start 'YYYY-MM-DD HH:MM:SS' — the preflight "
            "instant of the run being re-scored")
    end = args.rescore_window_end.strip()
    if end and not re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", end):
        die("--rescore-memflat: --rescore-window-end must be "
            "'YYYY-MM-DD HH:MM:SS'")
    stack = Stack(args.env_file, args.base_url, args.project)
    ch_ev, ch_problems = _rescore_clickhouse(stack, start, end)
    corr_ev, corr_problems = _rescore_correlation(run_dir, memflat_ev)
    verdict = "PASS" if not (ch_problems or corr_problems) else "FAIL/UNKNOWN"
    lines = [
        f"# memflat re-score — {os.path.basename(run_dir)}",
        "",
        f"Re-scored {utcnow()} by scale-miniladder.py --rescore-memflat.",
        "READ-ONLY: the run's own report files are untouched; this is what the",
        "corrected clauses (2026-08-29) say about the evidence that run left.",
        "",
        f"* original memflat verdict: {original}",
        f"* re-scored verdict: **{verdict}**",
        "",
        "## clause (2) — ClickHouse's own memory accounting",
        "",
        (f"* window: `{ch_ev['window_start']}` -> `{ch_ev['window_end']}` "
         f"(ClickHouse's clock)"),
        f"* cap: {mib(ch_ev.get('cap_bytes', -1))} ({ch_ev.get('cap_source')})",
        (f"* **{CH_MEM_ERROR}: "
         f"{ch_ev.get('memory_limit_exceeded', -1)}** "
         f"({ch_ev.get('memory_limit_exceeded_source', 'no source')})"),
    ]
    if ch_ev.get("victims"):
        lines.append(f"* victims: {ch_ev['victims']}")
    if "peak_memory_tracking_bytes" in ch_ev:
        lines += [
            f"* samples: {ch_ev.get('metric_log', 'unknown')}",
            (f"* p99 MemoryTracking: "
             f"**{mib(ch_ev['p99_memory_tracking_bytes'])}** "
             f"= {ch_ev.get('p99_memory_tracking_pct', '?')}% of cap "
             f"(limit {CH_MEMORY_TRACKING_MAX_PCT}%) — THE JUDGED NUMBER"),
            (f"* peak MemoryTracking: "
             f"**{mib(ch_ev['peak_memory_tracking_bytes'])}** "
             f"= {ch_ev.get('memory_tracking_pct', '?')}% of cap "
             f"(reported; warned at "
             f"{CH_MEMORY_TRACKING_PEAK_WARN_PCT}%, never failed on its own)"),
            (f"* peak MergesMutationsMemoryTracking: "
             f"{mib(ch_ev['peak_merges_memory_bytes'])} — "
             f"{ch_ev.get('merges_memory_verdict', 'INFORMATIONAL')}: on 24.8 "
             f"`CurrentMetric_MemoryTracking` is process RSS set from the OS "
             f"once a second, not a sum of child trackers, so a child may "
             f"legitimately read above it and there is no honest "
             f"fraction-of-cap to assert on"),
        ]
    else:
        lines.append(f"* memory levels: {ch_ev.get('metric_log', 'UNAVAILABLE')} "
                     f"— DEGRADED, and reported as UNKNOWN rather than PASS")
    for line in ch_ev.get("warnings", []):
        lines.append(f"* WARN: {line}")
    lines += ["", "clause (2): " + ("PASS" if not ch_problems
                                    else "; ".join(ch_problems)), ""]
    lines += ["## clause (1) — correlation, anchored at corr_engine_pending == 0",
              "", f"* source: {corr_ev.get('source', 'none')}"]
    for name, rec in sorted(corr_ev.get("replicas", {}).items()):
        lines.append(
            f"* {name}: rss_at_input_stop "
            f"{mib(rec.get('rss_at_input_stop', -1))} -> rss_at_pending_zero "
            f"{mib(rec.get('rss_at_pending_zero', -1))} -> rss_end "
            f"{mib(rec.get('rss_end', -1))} "
            f"(x{rec.get('ratio_vs_anchor')}, {rec.get('verdict')})")
    lines += ["", "correlation: " + ("PASS" if not corr_problems
                                     else "; ".join(corr_problems)), ""]
    doc = "\n".join(lines)
    out_path = os.path.join(run_dir, RESCORE_FILE)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(doc)
    print(doc)
    log(f"re-score written: {out_path} (the run's own report is untouched)")
    return 0 if verdict == "PASS" else 1


def cleanup_only(args: argparse.Namespace) -> int:
    """Residue purge with no run, UNDER THE RUN LOCK.

    This mode DELETES devices: it must never run against a stack a live run
    owns, or it deletes that run's fleet mid-flight (2026-08-29). The lock is
    released on every exit path — including the `die()` refusals below, which
    raise SystemExit through the finally.
    """
    lock = RunLock(runid="cleanup-only")
    held, msg = lock.acquire()
    if not held:
        die(msg)
    log(msg)
    try:
        return _cleanup_only_locked(args)
    finally:
        lock.release()


def _cleanup_only_locked(args: argparse.Namespace) -> int:
    """Delete every `PREFIX*` device, verify to zero, purge the matching
    telemetry. Exit 0 ONLY on verified zero."""
    prefix = args.cleanup_only
    stack = Stack(args.env_file, args.base_url, args.project)
    interrupts = InterruptGuard()
    interrupts.install()
    log(f"cleanup-only: purging residue under {prefix} on {stack.base_url}")

    # Refuse on an unreachable stack. "0 devices remain" from a stack we cannot
    # talk to is the same false green this harness exists to kill.
    try:
        log(f"cleanup-only: ingress {stack.base_url}/ -> HTTP "
            f"{http_ingress_status(stack.base_url)}")
    except (urllib.error.URLError, OSError) as exc:
        die(f"--cleanup-only: stack unreachable at {stack.base_url} ({exc}) — "
            f"refusing to report a clean stack we cannot see")
    try:
        stack.login()
    except (RuntimeError, urllib.error.URLError, OSError) as exc:
        die(f"--cleanup-only: API login failed ({exc}) — cannot purge")

    # Purge under the same policy as a run's teardown: signals are ignored
    # while it runs, and the Nth aborts loudly with the residue named.
    interrupts.enter_cleanup()
    budget = (CLEANUP_DEVICE_BUDGET_BASE_S +
              CLEANUP_DEVICE_BUDGET_PER_DEVICE_S * max(args.devices, 1))
    problems: list[str] = []
    purge = empty_purge_ev(prefix, budget, "purge step never ran")
    tel_ev: dict = {"ch_signals_left": -1, "os_docs_left": -1}
    remaining = -1
    try:
        # Same policy as a run's teardown (2026-08-29): each step is bounded
        # and its FINAL failure is a recorded problem, not the end of the
        # cleanup. A transient socket timeout killed this path too.
        purge = cleanup_step(
            "device purge", problems, purge_devices, stack, prefix, budget,
            default=empty_purge_ev(prefix, budget, "device purge step raised"))
        if not purge["verified_zero"]:
            problems.append(
                f"{purge['remaining']} devices still match {prefix} after "
                f"{purge['passes']} pass(es) "
                f"({purge['delete_failed']} delete failures; first: "
                f"{purge['first_delete_error'] or purge['list_error'] or 'n/a'})")
        tel_ev, tel_problems = cleanup_step(
            "telemetry purge", problems, purge_telemetry, stack, prefix,
            default=({"ch_signals_left": -1, "os_docs_left": -1}, []))
        problems.extend(tel_problems)
        # RE-VERIFY last, after everything else has run: the number this mode
        # exits on is what the stack says NOW, never a step's own optimism.
        final_ids, final_err = cleanup_step(
            "residue re-verify", problems, devices_with_prefix, stack, prefix,
            default=([], "residue re-verify step raised"))
        remaining = -1 if final_err else len(final_ids)
        if final_err:
            problems.append(
                f"final residue re-verify FAILED ({final_err}) — residue under "
                f"{prefix} is UNKNOWN, not zero")
    except CleanupAborted as exc:
        warn(f"RESIDUE LEFT: cleanup-only aborted on repeated {exc} — rerun "
             f"python3 scripts/scale-miniladder.py --cleanup-only {prefix}")
        return 1
    finally:
        interrupts.leave_cleanup()

    for prob in problems:
        warn(f"cleanup-only: {prob}")
    log(f"cleanup-only: {purge['deleted']} device deletes issued, "
        f"{'UNKNOWN' if remaining < 0 else remaining} remain (re-verified); "
        f"ClickHouse rows left {tel_ev.get('ch_signals_left')}, "
        f"OpenSearch docs left {tel_ev.get('os_docs_left')}")
    if problems or remaining != 0:
        shown = "UNKNOWN (never verified)" if remaining < 0 else str(remaining)
        warn(f"RESIDUE LEFT: {shown} devices matching {prefix} — cleanup-only "
             f"FAILED with {len(problems)} problem(s) above. Purge with: "
             f"python3 scripts/scale-miniladder.py --cleanup-only {prefix}")
        return 1
    log(f"cleanup-only: residue: 0 devices matching {prefix} (verified), "
        f"telemetry purged")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
