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
              and for ClickHouse two clauses of its OWN accounting — peak
              MemoryTracking < 85% and peak merge memory < 50% of the effective
              max_server_memory_usage, and MaxPartCountForPartition back within
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
import os
import random
import re
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
CH_MEMORY_TRACKING_MAX_PCT = float(
    os.environ.get("MLX_CH_MEMORY_TRACKING_MAX_PCT", "85"))
CH_MERGE_MEMORY_MAX_PCT = float(
    os.environ.get("MLX_CH_MERGE_MEMORY_MAX_PCT", "50"))

# `clean-slate.sh --verify` fails a stack whose max consumer-group
# CURRENT-OFFSET exceeds this ("the bus data dir was not reset",
# clean-slate.sh:243). Pinned here so the harness warns about the SAME number
# that script judges, not a different one that happens to share a threshold.
# How many runs of onboard-rate history last-run.json carries (tracker 175).
ONBOARD_RATE_HISTORY = int(os.environ.get("MLX_ONBOARD_RATE_HISTORY", "30"))

CLEAN_SLATE_OFFSET_BOUND = int(
    os.environ.get("MLX_CLEAN_SLATE_OFFSET_BOUND", "100000"))

# ── ClickHouse memory samples: the PLAUSIBILITY predicate (2026-08-29) ──────
#
# THE DEFECT THIS EXISTS FOR (run p2-s05-08291138).
# `CurrentMetric_MergesMutationsMemoryTracking` is a SIGNED, cross-thread
# delta. It does not merely dip slightly below zero on an idle server —
# `_ch_counter` already floors that case — it also UNDERFLOWS into huge
# positive readings that persist for whole seconds. Straight from that run's
# `system.metric_log`, one row, one second apart from its neighbours:
#
#   11:43:06  MemoryTracking 2,952 MiB   MergesMutations 3,071 MiB
#   11:43:07  MemoryTracking 1,086 MiB   MergesMutations 3,966 MiB   <- impossible
#   ...
#   11:43:52  MemoryTracking 1,278 MiB   MergesMutations 4,084 MiB   <- the "peak"
#
# Merge memory is a SUBSET of the total the server tracks, so a sample whose
# merge figure exceeds its own MemoryTracking is not a measurement. The gate
# took `max()` of each column INDEPENDENTLY over the window with no such
# check, and reported "peak MERGE memory 4,084 MiB is 99.7% of the 4,096 MiB
# server cap" — failing memflat on a run whose real peaks over the same window
# were 1,950 MiB and 421 MiB (max merge 421 MiB at 12:17:53, MemoryTracking
# 1,361 MiB on that row). 50 of the window's 3,711 samples were impossible;
# those 50 decided the verdict.
#
# So every sample is filtered by the ONE invariant that must hold in any real
# reading, and the number of samples REJECTED is carried in the evidence — a
# filter that hides how much it threw away is its own defect (§10).
CH_PLAUSIBLE_SAMPLE = (
    "CurrentMetric_MemoryTracking >= 0 AND "
    "CurrentMetric_MergesMutationsMemoryTracking <= CurrentMetric_MemoryTracking")

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
# aiokafka session timeout the correlation consumer runs with; a loop stall at
# or beyond this can cost the member its partitions.
KAFKA_SESSION_TIMEOUT_MS = int(os.environ.get("MLX_KAFKA_SESSION_TIMEOUT_MS", "30000"))

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
    "s1-2.5k": {
        "workload_class": "S1_DESIGN_STORM_2K5",
        "burst_minutes": 15,
        "lanes": [
            ("storm", 0.10, "storm", 9100.0),
            ("background", 0.90, "production", 900.0),
        ],
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
        # Live `system.metrics` readings discarded as physically impossible
        # (CH_PLAUSIBLE_SAMPLE). Counted, never hidden: a filter that does not
        # say how much it threw away is its own defect.
        self.ch_mem_implausible = 0
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
        ev: dict = {"devices_requested": n, "devices_created": len(self.created_ids),
                    "onboard_stop_reason": self.onboard_stop_reason,
                    "devices_absorbed_by_dedupe": len(self.absorbed),
                    "absorbed_mappings": dict(list(self.absorbed.items())[:20]),
                    "absorbed_canonical_ids": canonical_ids[:20],
                    "absorbed_canonical_count": len(canonical_ids),
                    "absorbed_canonical_by_run":
                        residue_by_run(canonical_ids)[:RESIDUE_RUN_IDS_SHOWN],
                    "window": k, "total_wall_s": round(total_wall, 2),
                    "failures": failures[:10]}
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
        lanes = self.profile.get("lanes") or []
        duration = int(self.args.burst_minutes * 60)
        accs = [0.0] * len(lanes)
        plan: list[dict] = []
        for start in range(0, duration, BURST_CHUNK_SECS):
            end = min(start + BURST_CHUNK_SECS, duration)
            row: dict = {}
            for i, (name, _share, _mix, rate) in enumerate(lanes):
                # Integrate the rate over the chunk's seconds — exact for the
                # ramp profiles, identical to rate*chunk_secs for flat ones.
                inc = (sum(rate(t) for t in range(start, end)) if callable(rate)
                       else float(rate) * (end - start))
                accs[i] += inc
                k = int(accs[i])
                accs[i] -= k
                row[name] = k
            plan.append(row)
        return plan

    def _planned_total(self) -> int:
        """Events this run intends to inject — the sum of the ratified chunk
        plan for lane profiles, args-derived otherwise. A fixed function of
        the profile in both cases."""
        if not self.profile.get("lanes"):
            return self.args.eps * int(self.args.burst_minutes * 60)
        return sum(sum(row.values()) for row in self._lane_schedule())

    def _lane_states(self) -> list[dict]:
        """Split this run's devices into the profile's lane pools (contiguous
        by creation order, deterministic; the last lane absorbs remainder)."""
        lanes = []
        n = len(self.created_ids)
        start = 0
        spec = self.profile["lanes"]
        for i, (name, share, mix, rate) in enumerate(spec):
            cnt = n - start if i == len(spec) - 1 else max(1, round(share * n))
            lanes.append({"name": name, "mix": mix, "rate": rate,
                          "pool": self.created_ids[start:start + cnt],
                          "acc": 0.0, "seq": 0, "sent": 0})
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
        """
        chunk_secs = BURST_CHUNK_SECS
        duration = int(self.args.burst_minutes * 60)
        factor = max(1.0, float(getattr(self.args, "burst_window_factor",
                                        BURST_WINDOW_MAX_FACTOR)))
        window_bound = duration * factor
        plan = self._lane_schedule()
        fleet_planned = sum(sum(row.values()) for row in plan)
        fleet_injected = 0
        lanes = self._lane_states()
        t0 = time.monotonic()
        seq_global = 0
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
            for ln in lanes:
                k = row[ln["name"]]
                pool = ln["pool"]
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
                detail[ln["name"]] = k
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
            chunks.append({"i": idx, "t": round(elapsed, 1), "lanes": detail,
                           "n": len(lines), "ok": ok,
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
            cohorts_delta = float(n.get("cohorts_total", -1.0)) - \
                float(b.get("cohorts_total", 0.0) or 0.0)
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
    def stability_verdict(counters: dict, session_timeout_ms: int) -> list:
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
        if worst >= session_timeout_ms:
            problems.append(
                f"worst event-loop stall {worst}ms EXCEEDS the {session_timeout_ms}ms "
                f"Kafka session timeout — the member can be ejected mid-stall")
        return problems

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
        while time.monotonic() < deadline:
            total = self.stack.group_lag("netops-correlation").get("_total", -1)
            if last is not None and abs(total - last) <= self.args.lag_epsilon:
                stable_for += 15.0
            else:
                stable_for = 0.0
            last = total
            if stable_for >= 45.0:
                break
            time.sleep(15)
        ev["lag_at_settlement"] = last
        ev["settled"] = stable_for >= 45.0
        log(f"stability: settled={ev['settled']} lag={last}; observing {grace:.0f}s grace")
        time.sleep(grace)

        blobs, since = self.collect_stability_blobs()
        counters = self.stability_counters(blobs)
        ev.update(counters)
        ev["observation_window_s"] = since
        ev["grace_s"] = grace
        ev["session_timeout_ms"] = KAFKA_SESSION_TIMEOUT_MS
        problems = self.stability_verdict(counters, KAFKA_SESSION_TIMEOUT_MS)
        status = "PASS" if not problems else "FAIL"
        return self.phase("stability", status, ev,
                          "; ".join(problems) if problems else
                          f"clean across the full lifecycle ({since}s, "
                          f"{counters['replicas_observed']} replica(s)): 0 CommitFailed, "
                          f"0 UnknownMember, 0 restarts, worst loop stall "
                          f"{counters['worst_loop_lag_ms']}ms")

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
    # docs/scale/P2_CLICKHOUSE_MEMFLAT_2026-08-29.md §(c). A store that writes
    # 50 GiB per run does not answer to an RSS ratio; it answers to its OWN
    # memory accounting and to the parts it leaves behind:
    #
    #   (2) peak MemoryTracking < 85 % of the effective max_server_memory_usage
    #       AND peak MergesMutationsMemoryTracking < 50 % of it. On the run that
    #       failed this gate for the wrong reason, these read 95.2 % and 83.0 %:
    #       the finding worth gating on, and the one nobody was told about.
    #   (3) MaxPartCountForPartition returns to within +20 % of its preflight
    #       value once input stops, and stays under parts_to_delay_insert / 2.
    #       That is what a stateful store legitimately owes after a burst.
    def _ch_number(self, query: str) -> float:
        return ch_number(self.stack, query)

    def _ch_sample_metrics(self) -> None:
        """Fold a live `system.metrics` reading into the running peak. Cheap,
        and it is the only peak available if `system.metric_log` is disabled.

        The PAIR is judged, never the two counters separately: a reading whose
        merge memory exceeds its own MemoryTracking is physically impossible
        (CH_PLAUSIBLE_SAMPLE) and is discarded whole — folding half of a
        corrupt sample into the peak is how the metric_log defect reached the
        verdict through the fallback path as well."""
        ok, out = self.stack.ch(
            "SELECT metric, toInt64(value) FROM system.metrics WHERE metric IN "
            "('MemoryTracking', 'MergesMutationsMemoryTracking')")
        if not ok:
            warn(f"ClickHouse system.metrics sample failed: {out[:160]}")
            return
        raw_values: dict[str, int] = {}
        for line in out.splitlines():
            if "\t" not in line:
                continue
            metric, raw = line.split("\t", 1)
            if metric not in self.ch_mem_peak:
                continue
            try:                        # SIGNED: the plausibility test needs it
                raw_values[metric] = int(float(raw.strip()))
            except ValueError:
                continue
        track = raw_values.get("MemoryTracking")
        merges = raw_values.get("MergesMutationsMemoryTracking")
        if track is None:
            warn("ClickHouse system.metrics sample carried no MemoryTracking "
                 "row — nothing folded into the peak")
            return
        if track < 0 or (merges is not None and merges > track):
            self.ch_mem_implausible += 1
            warn(f"ClickHouse system.metrics sample DISCARDED as physically "
                 f"impossible: MergesMutationsMemoryTracking {mib(merges)} vs "
                 f"MemoryTracking {mib(track)} (merge memory is a subset of the "
                 f"tracked total) — the counter underflowed; not folded into "
                 f"the peak")
            return
        for metric, value in (("MemoryTracking", track),
                              ("MergesMutationsMemoryTracking", merges)):
            if value is None:
                continue
            # A negative merge delta is 0 bytes of merge memory, never a wrap.
            self.ch_mem_peak[metric] = max(self.ch_mem_peak[metric], 0, value)

    def _ch_memory_cap(self) -> tuple[float, str]:
        return ch_memory_cap(self.stack)

    def _ch_memory_peaks(self) -> tuple[dict, str, dict]:
        """Peak MemoryTracking / merge memory over THIS RUN's window.

        `system.metric_log` is the instrument; the harness's own
        `system.metrics` samples are folded in as a floor, so a disabled
        metric_log degrades the resolution instead of blinding the gate.

        Only PLAUSIBLE samples are aggregated (CH_PLAUSIBLE_SAMPLE) — a row
        whose merge memory exceeds its own MemoryTracking is a counter
        underflow, not a measurement, and taking `max()` across the raw column
        let 50 such rows decide run p2-s05-08291138's verdict. The rejected
        count rides in the returned census so the filtering is never silent.
        """
        peaks = {"MemoryTracking": -1, "MergesMutationsMemoryTracking": -1}
        census = {"window_start": "", "metric_log_samples": -1,
                  "metric_log_plausible": -1, "metric_log_rejected": -1,
                  "live_samples_rejected": self.ch_mem_implausible}
        sources: list[str] = []
        start = str(self.baseline.get("ch_window_start") or "")
        # Zero trust even on our own server's clock: this string is spliced
        # into SQL, so it must match a DateTime literal exactly or be dropped.
        if re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", start):
            census["window_start"] = start
            ok, out = self.stack.ch(
                "SELECT "
                f"maxIf(greatest(CurrentMetric_MemoryTracking, 0), "
                f"{CH_PLAUSIBLE_SAMPLE}), "
                f"maxIf(greatest(CurrentMetric_MergesMutationsMemoryTracking, 0), "
                f"{CH_PLAUSIBLE_SAMPLE}), "
                f"countIf({CH_PLAUSIBLE_SAMPLE}), count() "
                "FROM system.metric_log "
                f"WHERE event_time >= toDateTime('{start}')")
            if ok and out.strip():
                cells = out.strip().splitlines()[0].split("\t")
                try:
                    plausible, total = int(cells[2]), int(cells[3])
                except (IndexError, ValueError):
                    plausible, total = -1, -1
                    warn(f"ClickHouse metric_log peak query returned an "
                         f"unreadable sample census ({out.strip()[:120]!r}) — "
                         f"the peaks it carries are not trusted")
                census["metric_log_samples"] = total
                census["metric_log_plausible"] = plausible
                census["metric_log_rejected"] = (
                    total - plausible if total >= 0 and plausible >= 0 else -1)
                if plausible > 0:
                    for i, key in enumerate(("MemoryTracking",
                                             "MergesMutationsMemoryTracking")):
                        try:
                            peaks[key] = _ch_counter(cells[i])
                        except (IndexError, ValueError):
                            peaks[key] = -1
                    if peaks["MemoryTracking"] > 0:
                        sources.append(f"system.metric_log since {start}")
                    if census["metric_log_rejected"] > 0:
                        warn(f"ClickHouse metric_log: "
                             f"{census['metric_log_rejected']} of {total} samples "
                             f"in this run's window were physically impossible "
                             f"(merge memory above MemoryTracking) and were "
                             f"excluded from the peaks")
                elif total >= 0:
                    warn(f"ClickHouse metric_log held {total} sample(s) for this "
                         f"run's window and NONE was plausible — the peaks fall "
                         f"back to the harness's own samples")
            elif not ok:
                warn(f"ClickHouse metric_log peak query failed: {out[:160]}")
        self._ch_sample_metrics()
        census["live_samples_rejected"] = self.ch_mem_implausible
        for key, sampled in self.ch_mem_peak.items():
            if sampled > peaks.get(key, -1):
                peaks[key] = sampled
                if "harness system.metrics samples" not in sources:
                    sources.append("harness system.metrics samples")
        return peaks, " + ".join(sources) if sources else "none", census

    def _ch_parts_settled(self) -> dict:
        """Clause (3): parts come back down after input stops.

        Bounded settle wait — merges that are still folding the burst's parts
        are legitimate work, a part count that never returns is not."""
        base = int(self.baseline.get("ch_max_part_count", -1) or -1)
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
        """Clauses (2) and (3), plus the one-line summary of all three."""
        if "clickhouse" not in MEM_SERVICES:
            return {}, [], ""
        problems: list[str] = []
        cap, cap_source = self._ch_memory_cap()
        peaks, peak_source, census = self._ch_memory_peaks()
        # THE LAST NET. Whatever the instrument said, the two numbers this
        # phase is about to PRINT must satisfy the physical invariant — merge
        # memory is part of the tracked total. If they do not, the instrument
        # is corrupt in a way the plausibility filter did not catch, and the
        # only honest verdict is UNKNOWN: never a FAIL on an impossible number
        # (which is exactly what run p2-s05-08291138 got), and never a PASS on
        # one either.
        impossible = (peaks["MemoryTracking"] >= 0
                      and peaks["MergesMutationsMemoryTracking"] >= 0
                      and peaks["MergesMutationsMemoryTracking"]
                      > peaks["MemoryTracking"])
        ev = {"cap_bytes": int(cap) if cap > 0 else -1,
              "cap_source": cap_source,
              "peak_source": peak_source,
              "peak_memory_tracking_bytes": peaks["MemoryTracking"],
              "peak_merges_memory_bytes": peaks["MergesMutationsMemoryTracking"],
              "peaks_self_consistent": not impossible,
              "sample_census": census,
              "memory_tracking_max_pct": CH_MEMORY_TRACKING_MAX_PCT,
              "merges_memory_max_pct": CH_MERGE_MEMORY_MAX_PCT}
        track_pct = merge_pct = None
        if cap <= 0:
            problems.append(
                "clickhouse: effective max_server_memory_usage unreadable "
                f"({cap_source}) — the OOM clause cannot be judged, and a "
                "memory gate must not pass blind")
        elif peaks["MemoryTracking"] < 0:
            problems.append(
                "clickhouse: MemoryTracking peak unmeasurable (system.metric_log "
                "returned nothing for this run's window and no live sample "
                "succeeded) — the OOM clause cannot be judged")
        elif impossible:
            problems.append(
                f"clickhouse: memory peaks UNKNOWN — peak MERGE memory "
                f"{mib(peaks['MergesMutationsMemoryTracking'])} EXCEEDS peak "
                f"MemoryTracking {mib(peaks['MemoryTracking'])}, which is "
                f"physically impossible (merge memory is a subset of the "
                f"server's tracked total): the instrument is corrupt "
                f"({census['metric_log_rejected']} of "
                f"{census['metric_log_samples']} metric_log samples already "
                f"rejected as impossible) — clause (2) is NOT judged either way")
        else:
            track_pct = round(100.0 * peaks["MemoryTracking"] / cap, 1)
            if track_pct > CH_MEMORY_TRACKING_MAX_PCT:
                problems.append(
                    f"clickhouse: peak MemoryTracking "
                    f"{peaks['MemoryTracking'] / 1024**2:.0f} MiB is {track_pct}% "
                    f"of its {cap / 1024**2:.0f} MiB server cap "
                    f"(> {CH_MEMORY_TRACKING_MAX_PCT}%) — this run came that "
                    f"close to MEMORY_LIMIT_EXCEEDED")
            if peaks["MergesMutationsMemoryTracking"] < 0:
                problems.append(
                    "clickhouse: merge memory peak unmeasurable "
                    "(MergesMutationsMemoryTracking absent) — clause (2) is "
                    "only half judged")
            else:
                merge_pct = round(
                    100.0 * peaks["MergesMutationsMemoryTracking"] / cap, 1)
                if merge_pct > CH_MERGE_MEMORY_MAX_PCT:
                    problems.append(
                        f"clickhouse: peak MERGE memory "
                        f"{peaks['MergesMutationsMemoryTracking'] / 1024**2:.0f} MiB "
                        f"is {merge_pct}% of the {cap / 1024**2:.0f} MiB server cap "
                        f"(> {CH_MERGE_MEMORY_MAX_PCT}%) — background merges alone "
                        f"can starve the query/insert path")
        ev["memory_tracking_pct"] = track_pct
        ev["merges_memory_pct"] = merge_pct
        parts = self._ch_parts_settled()
        problems += parts.pop("problems")
        ev["parts"] = parts
        ch_row = next((r for r in rows if r.get("service") == "clickhouse"), None)
        slope = "anon unmeasured"
        if ch_row and ch_row.get("ratio_vs_anchor"):
            slope = (f"anon {mib(ch_row['end_bytes'])} "
                     f"(x{ch_row['ratio_vs_anchor']} vs anchor)")
        # All three clauses in one line, always — a number the operator can
        # read is the difference between "the gate is green" and "the store is
        # at 95 % of its own cap and nobody said so".
        caveat = ""
        if impossible:
            caveat += ", UNKNOWN — merge peak above the tracked total"
        if census["metric_log_rejected"] > 0:
            caveat += (f", {census['metric_log_rejected']}/"
                       f"{census['metric_log_samples']} impossible samples "
                       f"excluded")
        summary = (
            f"clickhouse {slope}; peak MemoryTracking "
            f"{mib(peaks['MemoryTracking'])} = "
            f"{'?' if track_pct is None else track_pct}% of cap {mib(cap)} "
            f"(merges {mib(peaks['MergesMutationsMemoryTracking'])} = "
            f"{'?' if merge_pct is None else merge_pct}%{caveat}); "
            f"MaxPartCountForPartition {parts['current']} "
            f"(preflight {parts['baseline']}, envelope {parts['envelope']}, "
            f"delay at {parts['parts_to_delay_insert']})")
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
                         "S-family = storm gates (invariants + recovery). "
                         "--devices is never overridden.")
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
        planned = args.eps * 60 * args.burst_minutes
        print("scale-miniladder DRY RUN — nothing will be touched")
        print(f"  stack           : {args.base_url} (project {args.project}, "
              f"env {args.env_file})")
        print(f"  run lock         : {RUN_LOCK_PATH} (refuses to start while a "
              f"live pid holds it; a stale lock is reclaimed)")
        print(f"  phase 1 preflight: REFUSES on any leftover {DEVICE_PREFIX_ROOT} "
              f"device of any run id ({ALLOW_FOREIGN_RESIDUE_ENV}=1 overrides), "
              f"{len(REQUIRED_SERVICES)} required services, "
              f"active bus consumers (bounded wait {args.consumer_settle_seconds}s), "
              f"baselines (RSS/offsets/lag/CH/VM/durability)")
        print(f"  phase 2 onboard  : create {args.devices} devices "
              f"(mlx-<runid>-NNNNN @ 198.18/15); last/first window rate floor "
              f"{args.linearity_floor}")
        print(f"  phase 3 burst    : registry gate + canary, then {planned} syslog "
              f"events @ {args.eps}/s for {args.burst_minutes} min to netops.syslog")
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
              f"< {CH_MEMORY_TRACKING_MAX_PCT}% / {CH_MERGE_MEMORY_MAX_PCT}% of "
              f"max_server_memory_usage (physically impossible metric_log "
              f"samples excluded) and parts back within "
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
RESCORE_FILE = "memflat-rescore.md"
# `--mem-factor`'s default, restated for the offline path: a re-score judges a
# FINISHED run, so it must use the threshold that run was judged by, not
# whatever this invocation happens to pass on the command line.
MEM_FACTOR_RESCORE = 1.3


def _rescore_clickhouse(stack, start: str, end: str) -> tuple[dict, list[str]]:
    """Clause (2) again, over the same window, with the corrected filter."""
    ev: dict = {"window_start": start, "window_end": end or "(now)"}
    problems: list[str] = []
    cap, cap_source = ch_memory_cap(stack)
    ev["cap_bytes"], ev["cap_source"] = cap, cap_source
    bound = f"WHERE event_time >= toDateTime('{start}')"
    if end:
        bound += f" AND event_time <= toDateTime('{end}')"
    ok, out = stack.ch(
        "SELECT "
        f"maxIf(greatest(CurrentMetric_MemoryTracking, 0), {CH_PLAUSIBLE_SAMPLE}), "
        f"maxIf(greatest(CurrentMetric_MergesMutationsMemoryTracking, 0), "
        f"{CH_PLAUSIBLE_SAMPLE}), "
        f"countIf({CH_PLAUSIBLE_SAMPLE}), count(), "
        "max(CurrentMetric_MemoryTracking), "
        "max(CurrentMetric_MergesMutationsMemoryTracking) "
        f"FROM system.metric_log {bound}")
    if not ok:
        problems.append(f"system.metric_log unreadable for the window: {out[:200]}")
        return ev, problems
    cells = out.strip().splitlines()[0].split("\t") if out.strip() else []
    if len(cells) < 6:
        problems.append(f"system.metric_log returned {len(cells)} column(s), "
                        f"expected 6 — the window cannot be re-scored")
        return ev, problems
    try:
        ev["peak_memory_tracking_bytes"] = _ch_counter(cells[0])
        ev["peak_merges_memory_bytes"] = _ch_counter(cells[1])
        ev["plausible_samples"] = int(cells[2])
        ev["total_samples"] = int(cells[3])
        # What the OLD code would have printed, from the same rows — the
        # difference IS the defect, so it is stated, not implied.
        ev["unfiltered_memory_tracking_bytes"] = _ch_counter(cells[4])
        ev["unfiltered_merges_memory_bytes"] = _ch_counter(cells[5])
    except (IndexError, ValueError):
        problems.append(f"system.metric_log answer unparseable: {out[:200]}")
        return ev, problems
    ev["rejected_samples"] = ev["total_samples"] - ev["plausible_samples"]
    if ev["plausible_samples"] <= 0:
        problems.append("no plausible metric_log sample in the window — "
                        "clause (2) is UNKNOWN")
        return ev, problems
    if cap <= 0:
        problems.append(f"effective max_server_memory_usage unreadable "
                        f"({cap_source}) — clause (2) is UNKNOWN")
        return ev, problems
    ev["memory_tracking_pct"] = round(
        100.0 * ev["peak_memory_tracking_bytes"] / cap, 1)
    ev["merges_memory_pct"] = round(
        100.0 * ev["peak_merges_memory_bytes"] / cap, 1)
    if ev["memory_tracking_pct"] > CH_MEMORY_TRACKING_MAX_PCT:
        problems.append(
            f"peak MemoryTracking {mib(ev['peak_memory_tracking_bytes'])} is "
            f"{ev['memory_tracking_pct']}% of the {mib(cap)} cap "
            f"(> {CH_MEMORY_TRACKING_MAX_PCT}%)")
    if ev["merges_memory_pct"] > CH_MERGE_MEMORY_MAX_PCT:
        problems.append(
            f"peak MERGE memory {mib(ev['peak_merges_memory_bytes'])} is "
            f"{ev['merges_memory_pct']}% of the {mib(cap)} cap "
            f"(> {CH_MERGE_MEMORY_MAX_PCT}%)")
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
    ]
    if "peak_memory_tracking_bytes" in ch_ev:
        lines += [
            (f"* samples: {ch_ev['total_samples']} in the window, "
             f"{ch_ev['rejected_samples']} rejected as physically impossible "
             f"(merge memory above the tracked total)"),
            (f"* peak MemoryTracking: "
             f"**{mib(ch_ev['peak_memory_tracking_bytes'])}** "
             f"= {ch_ev.get('memory_tracking_pct', '?')}% of cap "
             f"(limit {CH_MEMORY_TRACKING_MAX_PCT}%)"),
            (f"* peak MERGE memory: "
             f"**{mib(ch_ev['peak_merges_memory_bytes'])}** "
             f"= {ch_ev.get('merges_memory_pct', '?')}% of cap "
             f"(limit {CH_MERGE_MEMORY_MAX_PCT}%)"),
            (f"* what the UNFILTERED `max()` would have printed — the defect: "
             f"MemoryTracking {mib(ch_ev['unfiltered_memory_tracking_bytes'])}, "
             f"merges {mib(ch_ev['unfiltered_merges_memory_bytes'])}"),
        ]
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
