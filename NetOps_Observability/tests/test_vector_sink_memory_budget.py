# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""A Vector tier's worst-case resident working set must fit its own mem_limit.

WHY THIS EXISTS (tracker 324, proven on the lab box 2026-09-16).
`netops-vector-router-1` had restarted **37 times** since it was created on
2026-09-06. `docker inspect` said `OOMKilled=false` and `ExitCode=0`, so the
restarts read as benign. They were not. The kernel log is unambiguous — 114
memory-cgroup OOM kills in that container's cgroup over the same window:

    Sep 15 10:16:34 kernel: oom-kill:constraint=CONSTRAINT_MEMCG,
      oom_memcg=/system.slice/docker-939e6fb70841....scope,
      task=vector,pid=3793551
    Sep 15 10:16:34 kernel: Memory cgroup out of memory: Killed process
      3793551 (vector) total-vm:2272740kB, anon-rss:507212kB

`docker inspect` put `FinishedAt` at 2026-09-15T10:16:34.866Z — the same
second. `anon-rss:507212kB` is 495 MiB against a 525 MiB cap.

`OOMKilled=false` lied for two independent reasons, and BOTH are worth knowing:
  * PID 1 in these containers is the F-10 enrichment-reload **shell wrapper**,
    not vector. The kernel OOM killer picks the fattest task in the cgroup —
    vector, the child — so the container's init survives and Docker never
    stamps the container as OOM-killed.
  * `State.ExitCode` and `State.OOMKilled` are both cleared when a container is
    RUNNING. Inspecting a container that has already been restarted therefore
    reports the *current* incarnation's zeroes, never the dead one's 137.

WHAT ACTUALLY GREW. Not the buffers — every OpenSearch sink already pinned
`buffer: {type: memory, max_events: 500, when_full: block}` (#209), which is
~2 MiB of events per lane and was measured at 0 on every lane. What was
unbounded was the **in-flight request queue**. Read out of the shipped image
(`docker exec netops-vector-router-1 vector generate '//elasticsearch'`), the
defaults this config did not pin are:

    request:
      retry_attempts: 9223372036854775807     # i.e. forever
      adaptive_concurrency:
        initial_concurrency: 1
        max_concurrency_limit: 200            # <-- per sink
    batch: {}                                 # elasticsearch default 10 MB

So each storage sink was allowed up to 200 concurrent in-flight bulk requests
of up to ~10 MB each. One sink's ceiling alone (≈2 GB) is four times the whole
container budget, and the router runs twelve of them. Under a sustained block —
OpenSearch answering 429 `cluster_block_exception` at the flood-stage watermark
— batches are held in memory for the whole retry envelope, the in-flight set
grows, and the cgroup cap is reached. The kernel reaps vector, the wrapper's
`wait` returns, the container restarts, Kafka replays. Delayed, not lost — but
a restart loop is not a back-pressure strategy.

THIS IS A PRODUCT BEHAVIOUR, NOT A LAB ARTEFACT. The lab's trigger (disk at
94 %) is local; the response to it is not. Any appliance whose OpenSearch is
slow, blocked, full or simply smaller than its ingest rate drives the same
unbounded in-flight growth against the same cgroup cap. CLAUDE.md §9 requires
every queue to be bounded and back-pressure to be explicit; an in-flight set
sized 400x the container is neither.

THE CONTRACT ENFORCED HERE

  1. Every sink in both Vector tiers has a BOUNDED buffer and blocks when it
     fills. `when_full: drop_newest` is silent loss (§9) and is refused.
  2. Every sink that ships over Vector's HTTP request pipeline — the sink types
     that carry `request.adaptive_concurrency` — PINS the four numbers that
     decide its resident ceiling: `batch.max_events`, `batch.max_bytes`,
     `request.adaptive_concurrency.max_concurrency_limit` and a finite
     `request.retry_attempts`. Leaving any of them to the default puts a
     multi-gigabyte ceiling inside a half-gigabyte cgroup.
  2a. Every kafka SOURCE pins `queue.buffered.max.kbytes` and
     `queue.buffered.max.messages`. This queue is librdkafka's, not Vector's —
     no `buffer:` block covers it — and it defaults to 1 GiB per consumer.

  3. The arithmetic closes: summed over a tier's sinks AND sources,

         worst_case = SUM(buffer_events x EVENT_BYTES_CEILING)
                    + SUM(max_concurrency_limit x batch.max_bytes)
                    + SUM(queue.buffered.max.kbytes)

     plus a baseline RSS allowance must fit inside HEADROOM_SHARE of the
     service's compose mem_limit DEFAULT — the value a fresh install gets, not
     whatever a planner run wrote into this host's .env.

  4. The compose default and the resource planner's floor for the same service
     agree, so raising one silently cannot invalidate the arithmetic in (3).

KAFKA *SINKS* ARE OUT OF SCOPE HERE, DELIBERATELY — unlike kafka SOURCES,
which (2a) covers. A sink's PRODUCER queue is librdkafka's
`queue.buffering.max.kbytes` (note: buffer-ING, a different setting from the
consumer's buffer-ED), also a 1 GiB default, and pinning
`batch`/`adaptive_concurrency` on it would be meaningless because it does not
use Vector's request pipeline. That is a real latent exposure, mostly on the
aggregator, which produces to eleven topics; it has no incident behind it, was
not what OOMed the router, and is not bundled into this fix.

Run:  python3 -m pytest tests/test_vector_sink_memory_budget.py -v
"""

from __future__ import annotations

import os
import re

import pytest
import yaml

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))

MIB = 1024 * 1024

# ── the tiers under test ────────────────────────────────────────────────────
# name -> (config path, compose service name)
TIERS = {
    "aggregator": ("deployment/docker/vector/vector.yaml", "vector-aggregator"),
    "router": ("deployment/docker/vector-router/vector.yaml", "vector-router"),
}

# Sink types that ship through Vector's HTTP request pipeline — the ones whose
# `request.adaptive_concurrency` block exists and therefore whose in-flight set
# is what this file bounds. Taken from the shipped image's own `vector generate`
# output, not from documentation.
REQUEST_PIPELINE_TYPES = frozenset(
    {
        "elasticsearch",
        "clickhouse",
        "prometheus_remote_write",
        "http",
        "loki",
    }
)

# Vector's own defaults when a `buffer` block is absent, read from
# `vector generate` against timberio/vector 0.40.0. A sink that omits the block
# still has a bounded buffer — it just has an UNPINNED one, which is fine for
# the arithmetic and refused for the request-pipeline sinks by contract (2).
VECTOR_DEFAULT_BUFFER = {"type": "memory", "max_events": 500, "when_full": "block"}

# ── sizing constants (every one of them measured, not guessed) ──────────────

# Per-event ceiling for the buffer term. Measured on the live router
# 2026-09-16 from vector_component_sent_event_bytes_total / _events_total:
#   opensearch_syslog       660 B     opensearch_secfindings  1182 B
# and the #209 comment records 478 B over a 32.4 M-event sample. 4 KiB is ~6x
# the largest measurement, which is the margin a ceiling is for.
EVENT_BYTES_CEILING = 4096

# Resident cost of the process with every pipeline queue empty. Measured at
# 78-85 MiB on the live router and 85-87 MiB on the aggregator (docker stats,
# 2026-09-16, both idle at ~16 % of a 525 MiB cap). 128 MiB is the allowance.
BASELINE_RSS = 128 * MIB

# The worst case must fit this share of the cap. The remainder absorbs
# allocator fragmentation and the transform-side event copies that no config
# value bounds.
HEADROOM_SHARE = 0.60

# Per-sink sanity ceilings. These are not arbitrary: 4 concurrent requests is
# 8x the concurrency actually observed on this deployment
# (vector_adaptive_concurrency_in_flight, mean 0.5, top bucket <=1), and a
# 1 MiB bulk body is a normal OpenSearch batch while being a tenth of Vector's
# 10 MB default.
MAX_CONCURRENCY_CEILING = 8
MAX_BATCH_BYTES_CEILING = 4 * MIB

# librdkafka's consumer prefetch queue, which is NOT Vector's buffer and is not
# covered by any `buffer:` block. Its defaults are `queue.buffered.max.messages`
# 1,000,000 and `queue.buffered.max.kbytes` 1,048,576 (1 GiB) PER CONSUMER; the
# router runs ten. Sizing this is the SOURCE half of tracker 324 — bounding the
# sinks alone still left the container at 70-83 % of its cap while one lane
# drained a backlog. The default is spelled out so an unpinned source is scored
# at what it actually costs, and blows the budget assertion below.
LIBRDKAFKA_DEFAULT_PREFETCH_KBYTES = 1048576
MAX_PREFETCH_KBYTES_CEILING = 4096


def read(path: str) -> str:
    with open(os.path.join(ROOT, path)) as fh:
        return fh.read()


def vector_cfg(tier: str) -> dict:
    return yaml.safe_load(read(TIERS[tier][0]))


def sinks(tier: str) -> dict:
    return vector_cfg(tier).get("sinks") or {}


def sources(tier: str) -> dict:
    return vector_cfg(tier).get("sources") or {}


def kafka_sources(tier: str) -> list[tuple[str, dict]]:
    return [(n, s) for n, s in sources(tier).items() if s.get("type") == "kafka"]


def prefetch_kbytes(src: dict) -> int:
    """This consumer's prefetch ceiling in KiB — librdkafka's default if unset."""
    opts = src.get("librdkafka_options") or {}
    return int(opts.get("queue.buffered.max.kbytes", LIBRDKAFKA_DEFAULT_PREFETCH_KBYTES))


def compose() -> dict:
    return yaml.safe_load(read("deployment/docker/docker-compose.yml"))


_SIZE_RE = re.compile(r"^(\d+)\s*([kmgKMG])?$")


def parse_size(text: str) -> int:
    """`512m` -> bytes. Compose's own suffix grammar, nothing more."""
    m = _SIZE_RE.match(str(text).strip())
    assert m, f"unparseable compose size {text!r}"
    n = int(m.group(1))
    return n * {None: 1, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30}[
        (m.group(2) or "").lower() or None
    ]


def compose_mem_limit_default(service: str) -> int:
    """The mem_limit a FRESH install gets — the `${X:-default}` fallback.

    Deliberately NOT the value in this host's .env: the planner may have raised
    it, and a contract that only holds after a planner run is not a contract.
    """
    raw = compose()["services"][service]["mem_limit"]
    m = re.match(r"^\$\{[A-Z_0-9]+:-([0-9]+[kmgKMG]?)\}$", str(raw).strip())
    assert m, f"{service}: mem_limit {raw!r} has no literal default to size against"
    return parse_size(m.group(1))


def buffer_of(sink: dict) -> dict:
    return sink.get("buffer") or VECTOR_DEFAULT_BUFFER


def is_request_pipeline(sink: dict) -> bool:
    return sink.get("type") in REQUEST_PIPELINE_TYPES


ALL_TIERS = sorted(TIERS)


def _request_sinks(tier: str) -> list[tuple[str, dict]]:
    return [(n, s) for n, s in sinks(tier).items() if is_request_pipeline(s)]


# ── contract 1: every queue is bounded and blocks ───────────────────────────


@pytest.mark.parametrize("tier", ALL_TIERS)
def test_every_sink_buffer_is_bounded(tier: str) -> None:
    """An unbounded queue is the §9 violation; `drop_newest` is the §9/§10 one.

    A memory buffer must name a finite `max_events`, a disk buffer a finite
    `max_size`, and neither may discard silently: `when_full` has to be `block`
    so a full buffer becomes back-pressure into Kafka (72 h retention) rather
    than events nobody counted.
    """
    offenders = []
    for name, sink in sinks(tier).items():
        buf = buffer_of(sink)
        kind = buf.get("type")
        if kind == "memory":
            size = buf.get("max_events")
        elif kind == "disk":
            size = buf.get("max_size")
        else:
            offenders.append(f"{name}: unknown buffer type {kind!r}")
            continue
        if not isinstance(size, int) or size <= 0:
            offenders.append(f"{name}: {kind} buffer has no finite size ({size!r})")
        if buf.get("when_full") != "block":
            offenders.append(
                f"{name}: when_full={buf.get('when_full')!r} — only `block` "
                f"back-pressures; anything else drops events silently"
            )
    assert not offenders, f"{tier}: " + "; ".join(offenders)


# ── contract 2: the in-flight set is pinned, not defaulted ──────────────────


@pytest.mark.parametrize("tier", ALL_TIERS)
def test_request_pipeline_sinks_pin_their_in_flight_ceiling(tier: str) -> None:
    """Tracker 324. Vector's defaults put a ~2 GB ceiling on EACH such sink.

    `vector generate '//elasticsearch'` against the shipped 0.40.0 image:
    `max_concurrency_limit: 200`, `retry_attempts: 9223372036854775807`,
    `batch: {}` (10 MB). None of that is visible in this repo's config, which
    is exactly why it went unnoticed until the router OOMed 114 times.
    """
    offenders = []
    for name, sink in _request_sinks(tier):
        req = sink.get("request") or {}
        batch = sink.get("batch") or {}
        ac = req.get("adaptive_concurrency") or {}

        limit = ac.get("max_concurrency_limit")
        if not isinstance(limit, int) or limit <= 0:
            offenders.append(
                f"{name}: request.adaptive_concurrency.max_concurrency_limit is "
                f"unpinned — Vector defaults it to 200 in-flight requests"
            )
        elif limit > MAX_CONCURRENCY_CEILING:
            offenders.append(
                f"{name}: max_concurrency_limit {limit} exceeds the "
                f"{MAX_CONCURRENCY_CEILING} this container is sized for"
            )

        attempts = req.get("retry_attempts")
        if not isinstance(attempts, int) or attempts <= 0 or attempts > 1000:
            offenders.append(
                f"{name}: request.retry_attempts={attempts!r} — the default is "
                f"i64::MAX, i.e. a batch held in memory forever"
            )

        max_bytes = batch.get("max_bytes")
        if not isinstance(max_bytes, int) or max_bytes <= 0:
            offenders.append(
                f"{name}: batch.max_bytes is unpinned (10 MB default)"
            )
        elif max_bytes > MAX_BATCH_BYTES_CEILING:
            offenders.append(
                f"{name}: batch.max_bytes {max_bytes} exceeds the "
                f"{MAX_BATCH_BYTES_CEILING}-byte ceiling this container is sized for"
            )

        if not isinstance(batch.get("max_events"), int):
            offenders.append(f"{name}: batch.max_events is unpinned")

        # The buffer has to be stated on these sinks even though the default is
        # already bounded — the arithmetic below is only reviewable if every
        # term of it is written down.
        if not sink.get("buffer"):
            offenders.append(f"{name}: no explicit buffer block")

    assert not offenders, f"{tier}: " + "; ".join(offenders)


# ── contract 3: the arithmetic closes against the cgroup budget ─────────────


def worst_case_bytes(tier: str) -> tuple[int, list[str]]:
    """Resident ceiling of every configured queue in the tier, with workings."""
    total = 0
    workings = []
    for name, sink in sorted(sinks(tier).items()):
        buf = buffer_of(sink)
        term = 0
        if buf.get("type") == "memory":
            term += int(buf["max_events"]) * EVENT_BYTES_CEILING
        # A disk buffer's bytes are on disk, not in the cgroup; its in-RAM cost
        # is the write-ahead page, which the BASELINE_RSS allowance covers.
        if is_request_pipeline(sink):
            req = sink.get("request") or {}
            ac = req.get("adaptive_concurrency") or {}
            batch = sink.get("batch") or {}
            term += int(ac.get("max_concurrency_limit", 200)) * int(
                batch.get("max_bytes", 10_000_000)
            )
        total += term
        if term:
            workings.append(f"{name}={term // MIB} MiB")
    # The SOURCE half (324): librdkafka's consumer prefetch queue is resident in
    # the same cgroup and is bounded by nothing Vector owns. Measured on the
    # live router, bounding only the sinks still let it reach 99.99 % of its cap
    # while one lane drained a backlog, so this term is not optional.
    for name, src in sorted(kafka_sources(tier)):
        term = prefetch_kbytes(src) * 1024
        total += term
        workings.append(f"{name}(prefetch)={term // MIB} MiB")
    return total, workings


@pytest.mark.parametrize("tier", ALL_TIERS)
def test_kafka_sources_pin_their_consumer_prefetch(tier: str) -> None:
    """The SOURCE half of tracker 324, and the one that actually dominated.

    A kafka source's prefetch queue belongs to librdkafka, so no `buffer:`
    block describes it and nothing in Vector's config surface bounds it unless
    it is stated. Left at the defaults each consumer may hold 1 GiB; the router
    runs ten of them inside a 512 MiB container. Measured live: with the sinks
    bounded but the sources unpinned, the router still climbed to 99.99 % of
    its 525 MiB cap draining a single lane's backlog.
    """
    offenders = []
    for name, src in kafka_sources(tier):
        opts = src.get("librdkafka_options") or {}
        kb = opts.get("queue.buffered.max.kbytes")
        if kb is None:
            offenders.append(
                f"{name}: queue.buffered.max.kbytes unpinned — librdkafka "
                f"defaults to {LIBRDKAFKA_DEFAULT_PREFETCH_KBYTES} KiB (1 GiB)"
            )
        elif int(kb) > MAX_PREFETCH_KBYTES_CEILING:
            offenders.append(
                f"{name}: prefetch {kb} KiB exceeds the "
                f"{MAX_PREFETCH_KBYTES_CEILING} KiB this container is sized for"
            )
        if opts.get("queue.buffered.max.messages") is None:
            offenders.append(
                f"{name}: queue.buffered.max.messages unpinned — the byte cap "
                f"alone does not bound a flood of small events"
            )
    assert not offenders, f"{tier}: " + "; ".join(offenders)


@pytest.mark.parametrize("tier", ALL_TIERS)
def test_worst_case_working_set_fits_the_container_budget(tier: str) -> None:
    """The assertion tracker 324 is actually about.

    If this fails, the container will be OOM-killed under sustained sink
    back-pressure — silently, because PID 1 is the wrapper shell and Docker
    will keep reporting `OOMKilled=false`.
    """
    service = TIERS[tier][1]
    cap = compose_mem_limit_default(service)
    allowed = int(cap * HEADROOM_SHARE)
    queues, workings = worst_case_bytes(tier)
    need = queues + BASELINE_RSS
    assert need <= allowed, (
        f"{tier} ({service}): worst-case resident {need // MIB} MiB "
        f"(= {queues // MIB} MiB of queues + {BASELINE_RSS // MIB} MiB baseline) "
        f"exceeds {int(HEADROOM_SHARE * 100)}% of its {cap // MIB} MiB mem_limit "
        f"({allowed // MIB} MiB). Per-sink: {', '.join(workings)}"
    )


# ── contract 4: the budget the arithmetic used cannot drift away ────────────


def test_compose_default_and_planner_floor_agree() -> None:
    """The arithmetic above is sized against the compose default; the resource
    planner (#102) owns the same number as a floor. If they diverge, one of
    them is sizing a container the other does not describe."""
    planner = read("scripts/resource_planner.py")
    m = re.search(
        r'\(\s*"vector"\s*,\s*"VECTOR_MEM_LIMIT"\s*,\s*"VECTOR_CPU_LIMIT"\s*,'
        r"\s*(\d+)\s*\*\s*MIB",
        planner,
    )
    assert m, "resource_planner.py no longer declares a vector memory floor"
    floor = int(m.group(1)) * MIB
    for _, service in TIERS.values():
        assert compose_mem_limit_default(service) == floor, (
            f"{service}: compose default {compose_mem_limit_default(service)} != "
            f"resource_planner floor {floor}"
        )


def test_both_vector_tiers_share_one_budget_line() -> None:
    """Both services read the SAME env var, so one cap must size the heavier of
    the two — which is the reason the router's arithmetic is the binding one."""
    svcs = compose()["services"]
    assert (
        svcs["vector-router"]["mem_limit"] == svcs["vector-aggregator"]["mem_limit"]
    ), "the two vector tiers no longer share a budget; give them separate arithmetic"


# ── the regression this file exists to prevent, stated as itself ────────────


def test_no_storage_sink_relies_on_vectors_200_concurrency_default() -> None:
    """The literal tracker-324 regression: a NEW storage sink added to the
    router without a pinned ceiling reintroduces a 2 GB in-flight allowance
    inside a 512 MiB container, and nothing else in the suite would notice."""
    unpinned = [
        name
        for name, sink in _request_sinks("router")
        if not ((sink.get("request") or {}).get("adaptive_concurrency") or {}).get(
            "max_concurrency_limit"
        )
    ]
    assert not unpinned, (
        "these router storage sinks inherit max_concurrency_limit=200 and "
        f"batch.max_bytes=10 MB: {sorted(unpinned)}"
    )
