"""NetOps Observability — Correlation + AI Engine.

A FastAPI service that:

  * Consumes the netops.syslog, netops.flows, netops.metrics Redpanda
    topics (Kafka-compatible).
  * Runs lightweight stream processing — rolling z-score anomaly
    detection over per-device metric series, severity-weighted event
    correlation, and a stub for RCA.
  * Writes findings into ClickHouse (netops.findings table) so the UI
    can render them as ranked incident cards.
  * Exposes a REST API for the Go layer to query findings and trigger
    on-demand analyses.

The implementation is intentionally minimal — replace the algorithms
with sklearn / Prophet / a real CEP engine as the workload demands. The
service contract (consume from Kafka, emit findings to ClickHouse,
serve /findings) stays stable.
"""

from __future__ import annotations

import asyncio
import csv
import json
import logging
import os
import time
import uuid
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Deque, Dict, Iterable

import httpx
from aiokafka import AIOKafkaConsumer
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from catalog import builtin_catalog
from directed_topology import DirectedTopology
from engine import EngineConfig, ObjectSnapshot, SeamView, TopologyAdjacency, find_merges, run_window
from entity_resolver import EntityResolver
from flow_direction import flow_direction_sample, netflow_direction_source
from path_direction import resolve_path_order, traceroute_direction_source
from routing_direction import forwarding_pairs, routing_direction_source
from episodes import EpisodeDetector
from cloud_producers import cloud_signal_from_event
from producers import (
    episode_signal,
    flow_sample,
    parse_event_ts,
    probe_signals,
    syslog_control_signal,
    trap_control_signal,
)
from replay import replay_object
from signals import (
    DeadLetter,
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    ProbeAuthority,
    ProbeIntent,
    ProbeScope,
    Signal,
    Source,
    VantageType,
    derive_probe_authority,
    derive_probe_scope,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LOG_LEVEL        = os.environ.get("LOG_LEVEL", "info").upper()
KAFKA_BOOTSTRAP  = os.environ.get("KAFKA_BOOTSTRAP", "redpanda:9092")
CLICKHOUSE_URL   = os.environ.get("CLICKHOUSE_URL", "http://clickhouse:8123")
CLICKHOUSE_USER  = os.environ.get("CLICKHOUSE_USER", "netops")
CLICKHOUSE_PASS  = os.environ.get("CLICKHOUSE_PASSWORD", "")

TOPICS = ["netops.syslog", "netops.flows", "netops.metrics", "netops.probes", "netops.snmptrap", "netops.cloud"]

# Device→tenant map exported by the Go API (#20 multi-tenant telemetry). We stamp
# tenant_id onto each finding so it carries the same tenant discriminator as the
# flows/logs the Vector aggregator tags. The file is re-read when its mtime
# changes; an absent file or unmatched device yields "" (global/platform).
TENANT_ENRICHMENT_FILE = os.environ.get("TENANT_ENRICHMENT_FILE", "/data/enrichment/device_tenant.csv")
_tenant_map: Dict[str, str] = {}
_tenant_mtime: float = -1.0


def tenant_for(device: str) -> str:
    """Resolve a device name/id to its tenant id ("" = global). Cheap: re-reads
    the CSV only when its mtime changes."""
    global _tenant_map, _tenant_mtime
    if not device:
        return ""
    try:
        mt = os.path.getmtime(TENANT_ENRICHMENT_FILE)
    except OSError:
        return _tenant_map.get(device, "")
    if mt != _tenant_mtime:
        _tenant_mtime = mt
        fresh: Dict[str, str] = {}
        try:
            with open(TENANT_ENRICHMENT_FILE, newline="") as f:
                reader = csv.reader(f)
                next(reader, None)  # header: identity,tenant_id
                for row in reader:
                    if len(row) >= 2 and row[0]:
                        fresh[row[0]] = row[1]
            _tenant_map = fresh
        except OSError:
            pass
    return _tenant_map.get(device, "")

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("correlation")


# ---------------------------------------------------------------------------
# In-memory state for anomaly detection.
#
# Per-(device, metric) rolling window of recent samples. We keep a fixed
# window size so memory stays bounded; once the window has 20 samples
# we start scoring new arrivals against its mean + stddev.
# ---------------------------------------------------------------------------

WINDOW_SIZE = 200
Z_THRESHOLD = 3.0


@dataclass
class Series:
    values: Deque[float] = field(default_factory=lambda: deque(maxlen=WINDOW_SIZE))

    def mean(self) -> float:
        return sum(self.values) / len(self.values) if self.values else 0.0

    def stddev(self) -> float:
        n = len(self.values)
        if n < 2:
            return 0.0
        m = self.mean()
        return (sum((v - m) ** 2 for v in self.values) / (n - 1)) ** 0.5

    def push(self, v: float) -> None:
        self.values.append(v)


SERIES: Dict[tuple[str, str], Series] = {}

# ---------------------------------------------------------------------------
# Correlation Engine v2 — build ②: episode model (stages [1]+[2] of the
# canonical pipeline). Episodes are written to netops.corr_signals (the frozen
# spine); the legacy z-score→findings path above stays untouched (compat,
# §9 P1). Default-on; CORR_SIGNALS_ENABLED=false disables spine writes only.
# ---------------------------------------------------------------------------

CORR_SIGNALS_ENABLED = os.environ.get("CORR_SIGNALS_ENABLED", "true").lower() != "false"
DETECTOR = EpisodeDetector()
DEADLETTER_COUNT = 0  # exposed via /healthz; provenance is never guessed

# Metric-lane observability counters (exposed via /healthz). The netops.metrics
# lane was historically empty; these prove it is fed and where events are lost.
METRICS_RECEIVED = 0           # consumed from netops.metrics
METRICS_ACCEPTED = 0           # passed schema/identity/timestamp validation
METRICS_DROPPED = 0            # rejected (missing identity/value, bad timestamp)
DEVICE_TELEMETRY_SIGNALS = 0   # device_telemetry signals written to corr_signals
TRAPS_RECEIVED = 0             # consumed from netops.snmptrap (Commit 3)
TRAPS_NORMALIZED = 0           # classified into a control_plane signal
TRAPS_RECANON = 0              # C8: re-attributed to a device via the C7.1 EntityResolver
TRAPS_DROPPED = 0              # unclassified — kept searchable, no RCA signal
CLOUD_RECEIVED = 0             # consumed from netops.cloud (#81 P3G ingestion lane)
CLOUD_SIGNALS = 0             # source=cloud signals written to corr_signals + buffered
CLOUD_DROPPED = 0             # dropped: no tenant (default-closed) / malformed (dead-letter)

# Maximum clock skew (seconds) tolerated on a metric event timestamp. A future
# stamp beyond this, or a stamp older than the correlation window, is dropped
# (Layer-1F): event time must be trustworthy or the onset budget is a lie.
METRIC_FUTURE_SKEW_S = 120.0
METRIC_MAX_AGE_S = 3600.0

# ---------------------------------------------------------------------------
# Correlation Engine v2 — build ⑥: object persistence + replay (stages [3]–[8]).
# The deterministic core lives in engine.py (pure); this block owns the IO:
# an in-memory evidence window, the seam grounding context (exported by the Go
# API into the shared enrichment dir — same plane as device_tenant.csv), the
# periodic evaluation loop that persists versioned snapshots + the archive
# slice (replay-forever guarantee), and the /replay surface.
# ---------------------------------------------------------------------------

CORR_ENGINE_ENABLED = os.environ.get("CORR_ENGINE_ENABLED", "true").lower() != "false"
CORR_ENGINE_INTERVAL_S = float(os.environ.get("CORR_ENGINE_INTERVAL_S", "30"))
CORR_QUIESCE_S = float(os.environ.get("CORR_QUIESCE_S", "900"))
# §8 degradation. Topology is stale when the Go exporter stopped refreshing the
# seam/links files (mtime older than ~2-3 export intervals; export runs every 60s).
CORR_TOPO_STALE_S = float(os.environ.get("CORR_TOPO_STALE_S", "180"))
STORM_BUFFER_FRACTION = float(os.environ.get("CORR_STORM_FRACTION", "0.9"))
# C6 passive_flow: aggregate flow volume per exporting interface, flush each engine
# cycle through CUSUM → passive_flow episodes. Flows are a firehose — accumulation is
# O(1) per flow and the flush is bounded by (samplers × interfaces).
FLOW_CORRELATION_ENABLED = os.environ.get("ENABLE_FLOW_CORRELATION", "true") == "true"
_FLOW_AGG: Dict[tuple, dict] = {}   # (tenant, entity_id) -> {bytes, sampler}
FLOWS_RECEIVED = 0
PASSIVE_FLOW_SIGNALS = 0
# C7.3 NetFlow direction: directed per-pair volume, tenant → {(src_dev,dst_dev): bytes}.
# Accumulated CONTINUOUSLY (no reset) — the dominant direction is the structural
# forwarding direction (the causal prior: A normally upstream of B), stable under a
# fault that breaks but doesn't reverse it; a ratio is steady under steady traffic.
# Bounded by communicating device-pairs. Feeds the oracle's NetFlow source each cycle.
# (Rolling/decay window for faster reversal detection = a documented future refinement.)
_FLOW_DIR: Dict[str, Dict[tuple, float]] = {}
FLOW_DIRECTION_DOMINANCE = float(os.environ.get("CORR_FLOW_DOMINANCE", "0.6"))
FLOW_DIRECTION_PAIRS = 0  # observability: distinct directed device-pairs seen
SEAM_ENRICHMENT_FILE = os.environ.get("SEAM_ENRICHMENT_FILE", "/data/enrichment/seams.json")
# L2/L3 adjacency (LLDP/CDP/BGP-LS links) exported by the Go API — the grounding
# input for the §4.2 "L2/L3 adjacent device" rung (G1). Absent file = no adjacency
# (gate falls back to seam/containment, identical to before — honest, never relaxed).
TOPO_LINKS_FILE = os.environ.get("TOPO_LINKS_FILE", "/data/enrichment/topology_links.json")
# C7.1 EntityResolver inputs (IP→device, interface IP→ifName, (device,ifIndex)→ifName)
# exported by the Go API. The keystone the directed-topology direction sources
# (C7.3–C7.5) + G2 canonicalizer resolve raw IPs/ifIndexes through. Absent → resolver
# abstains (UNKNOWN), never guesses.
ENTITY_RESOLVER_FILE = os.environ.get("ENTITY_RESOLVER_FILE", "/data/enrichment/entity_resolver.json")
# C7.4 measured forwarding paths (traceroute hop order) for the active-path-trace
# direction source — the highest-precedence direction signal. Absent → source abstains.
PROBE_PATHS_FILE = os.environ.get("PROBE_PATHS_ENRICH_FILE", "/data/enrichment/probe_paths.json")
# C7.5 computed forwarding direction (BGP-LS/IGP SPF nexthops) for the routing source —
# the lowest-precedence direction signal. Producer (SPF export) deferred until the
# BGP-LS LSDB yields data; absent → source abstains (the engine directs via flow/trace).
ROUTING_DIRECTION_FILE = os.environ.get("ROUTING_DIRECTION_FILE", "/data/enrichment/routing_direction.json")

ENGINE_CFG = EngineConfig()
CATALOG = builtin_catalog()

# Evidence window: every canonical Signal written to the spine also lands here
# (bounded by event-time age, pruned each cycle — §9 queues bounded).
WINDOW_BUFFER: Deque[Signal] = deque(maxlen=50_000)
# Kafka delivery is at-least-once (auto-commit ~5s): a consumer restart
# re-delivers recent messages, and a duplicated signal_id in the window
# inflates snapshots and churns versions (found by basic testing — stored
# signal_count 14 vs 10 unique). The buffer therefore dedupes by signal id;
# the set is pruned alongside the buffer so memory stays bounded.
_BUFFERED_IDS: set[str] = set()

# Open-object registry: correlation_id → persistence state. CH stays append-
# only; this is the engine's working memory (PG corr_active wiring follows
# with the ops lifecycle build).
OPEN_OBJECTS: Dict[str, dict] = {}
LAST_GAP_HINTS = 0

_seam_cache: tuple[SeamView, ...] = ()
_seam_mtime: float = -1.0
_adj_cache: dict[str, list[dict]] = {}
_adj_mtime: float = -1.0


def topology_links_by_tenant() -> dict[str, list[dict]]:
    """L2/L3 device adjacency for the grounding gate (G1), exported by the Go API
    from LLDP/CDP/BGP-LS, grouped by tenant ("" = global). mtime-cached; absent/
    unreadable file = empty (gate uses only seam/containment — backward compatible).
    Tenant-scoped at use (a tenant grounds on its own links ∪ global), mirroring
    seam_inventory's tenant filter — adjacency never crosses tenants."""
    global _adj_cache, _adj_mtime
    try:
        mt = os.path.getmtime(TOPO_LINKS_FILE)
    except OSError:
        return _adj_cache
    if mt != _adj_mtime:
        _adj_mtime = mt
        try:
            with open(TOPO_LINKS_FILE) as f:
                raw = json.load(f)
            links = raw if isinstance(raw, list) else raw.get("links", [])
            grouped: dict[str, list[dict]] = {}
            for link in links:
                grouped.setdefault(str(link.get("tenant_id") or ""), []).append(link)
            _adj_cache = grouped
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            log.warning("topology links unreadable (%s); keeping previous adjacency", exc)
    return _adj_cache


_er_raw: dict[str, dict[str, list]] = {"devices": {}, "interface_ips": {}, "ifindex": {}}
_er_mtime: float = -1.0


def _entity_resolver_raw() -> dict[str, dict[str, list]]:
    """Parse entity_resolver.json into section → tenant → rows, mtime-cached. Absent/
    unreadable file = empty (resolver abstains — UNKNOWN, never a guess). Tenant-scoped
    at use (a tenant's rows ∪ global), mirroring seam/adjacency — never cross-tenant."""
    global _er_raw, _er_mtime
    try:
        mt = os.path.getmtime(ENTITY_RESOLVER_FILE)
    except OSError:
        return _er_raw
    if mt != _er_mtime:
        _er_mtime = mt
        try:
            with open(ENTITY_RESOLVER_FILE) as f:
                raw = json.load(f)
            grouped: dict[str, dict[str, list]] = {"devices": {}, "interface_ips": {}, "ifindex": {}}
            for section in grouped:
                for row in raw.get(section) or []:
                    grouped[section].setdefault(str(row.get("tenant_id") or ""), []).append(row)
            _er_raw = grouped
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            log.warning("entity resolver unreadable (%s); keeping previous", exc)
    return _er_raw


def entity_resolver_for(tenant: str) -> EntityResolver:
    """A resolver scoped to one tenant: its rows ∪ global ("") — never cross-tenant.
    Cheap to build (dict comprehensions); the engine builds one per tenant per cycle."""
    raw = _entity_resolver_raw()

    def slice_(section: str) -> list:
        return raw[section].get(tenant, []) + raw[section].get("", [])

    return EntityResolver.from_rows(slice_("devices"), slice_("interface_ips"), slice_("ifindex"))


_resolver_cache: dict[str, EntityResolver] = {}
_resolver_cache_mtime: float = -1.0
_ALL_RESOLVER_KEY = "\x00all"   # cache key for the cross-tenant ingest resolver (can't be a tenant id)


def cached_entity_resolver_all() -> EntityResolver:
    """A resolver over ALL devices (every tenant ∪ global), for INGEST ATTRIBUTION
    only — IP→device id, after which the device's tenant is derived via tenant_for().
    This mirrors G2a's all-device source-IP matching and tenant_for's global view; the
    result is routed to its rightful tenant, so it is not a cross-tenant data leak.
    Never used to SERVE tenant-scoped data (that always goes through the per-tenant
    resolver)."""
    global _resolver_cache, _resolver_cache_mtime
    _entity_resolver_raw()
    if _er_mtime != _resolver_cache_mtime:
        _resolver_cache = {}
        _resolver_cache_mtime = _er_mtime
    r = _resolver_cache.get(_ALL_RESOLVER_KEY)
    if r is None:
        raw = _entity_resolver_raw()

        def rows(section: str) -> list:
            return [row for per in raw[section].values() for row in per]

        r = EntityResolver.from_rows(rows("devices"), rows("interface_ips"), rows("ifindex"))
        _resolver_cache[_ALL_RESOLVER_KEY] = r
    return r


def cached_entity_resolver_for(tenant: str) -> EntityResolver:
    """entity_resolver_for, memoized per (tenant, file mtime) — handle_flow is a
    firehose, so the resolver is built only when entity_resolver.json changes, not
    per flow."""
    global _resolver_cache, _resolver_cache_mtime
    _entity_resolver_raw()  # refresh the underlying mtime cache
    if _er_mtime != _resolver_cache_mtime:
        _resolver_cache = {}
        _resolver_cache_mtime = _er_mtime
    r = _resolver_cache.get(tenant)
    if r is None:
        r = entity_resolver_for(tenant)
        _resolver_cache[tenant] = r
    return r


_probe_paths: list[dict] = []
_probe_paths_mtime: float = -1.0


def probe_paths() -> list[dict]:
    """Measured forwarding paths ([{hops:[ip,...]}]) for the C7.4 direction source,
    mtime-cached. Absent/unreadable = empty (source abstains). NOT tenant-scoped here —
    hop IPs are resolved per-tenant downstream, so a tenant orients only its own
    devices (a foreign hop won't resolve → that pair abstains): zero-leak."""
    global _probe_paths, _probe_paths_mtime
    try:
        mt = os.path.getmtime(PROBE_PATHS_FILE)
    except OSError:
        return _probe_paths
    if mt != _probe_paths_mtime:
        _probe_paths_mtime = mt
        try:
            with open(PROBE_PATHS_FILE) as f:
                raw = json.load(f)
            _probe_paths = raw if isinstance(raw, list) else []
        except (OSError, ValueError, TypeError) as exc:
            log.warning("probe paths unreadable (%s); keeping previous", exc)
    return _probe_paths


_routing_dir: list[dict] = []
_routing_dir_mtime: float = -1.0


def routing_direction() -> list[dict]:
    """Computed forwarding pairs ([{from,to}]) for the C7.5 routing source, mtime-
    cached. Absent/unreadable = empty (source abstains — its SPF producer is deferred
    until the BGP-LS LSDB has data). Resolved entities are device ids already, so the
    per-tenant oracle only orients pairs whose devices are in this tenant's component."""
    global _routing_dir, _routing_dir_mtime
    try:
        mt = os.path.getmtime(ROUTING_DIRECTION_FILE)
    except OSError:
        return _routing_dir
    if mt != _routing_dir_mtime:
        _routing_dir_mtime = mt
        try:
            with open(ROUTING_DIRECTION_FILE) as f:
                raw = json.load(f)
            _routing_dir = raw if isinstance(raw, list) else []
        except (OSError, ValueError, TypeError) as exc:
            log.warning("routing direction unreadable (%s); keeping previous", exc)
    return _routing_dir


def seam_inventory() -> tuple[SeamView, ...]:
    """Active seam inventory for the grounding gate, exported by the Go API
    (suggest→confirm→active happens there; only ACTIVE instances ground).
    mtime-cached like tenant_for; absent file = empty inventory (the gate then
    admits only explicit-topology edges — honest, never relaxed)."""
    global _seam_cache, _seam_mtime
    try:
        mt = os.path.getmtime(SEAM_ENRICHMENT_FILE)
    except OSError:
        return _seam_cache
    if mt != _seam_mtime:
        _seam_mtime = mt
        try:
            with open(SEAM_ENRICHMENT_FILE) as f:
                raw = json.load(f)
            _seam_cache = tuple(SeamView.from_dict(d) for d in raw)
        except (OSError, ValueError, KeyError) as exc:
            log.warning("seam inventory unreadable (%s); keeping previous view", exc)
    return _seam_cache


def buffer_signal(sig: Signal) -> None:
    # Decision #76 + verdicts.py Decision #1: a debug_only / platform-self-check probe
    # (e.g. prober->nginx, api->netbox) stays SEARCHABLE — it's already in corr_signals —
    # but must NEVER open or attach to a correlation object. RCA is the CUSTOMER's
    # network, not the platform's own stack. Enforced here, at the single window-entry
    # chokepoint, so run_window stays pure and replay is untouched (the archive is sliced
    # from the window, so excluded signals simply never reach object formation).
    if sig.attrs.get("probe_authority") == ProbeAuthority.DEBUG_ONLY.value:
        return
    # Decision #76 (engine-side): platform self-monitoring — a LOW-authority
    # internal_self_probe (PLATFORM_SELF_CHECK / INTERNAL_COLLECTOR vantage, e.g.
    # prober->clickhouse, api->netbox) is the platform's OWN stack, not the customer
    # network. Like debug_only it stays SEARCHABLE in corr_signals but must never open
    # or attach to a customer RCA object, so the customer-facing RCA list, coverage
    # counts and Network Health Index reflect the monitored network only. (Stack
    # Health watches the platform separately and does not read corr_objects.)
    if sig.attrs.get("probe_scope") == ProbeScope.INTERNAL_SELF_PROBE.value:
        return
    sid = str(sig.signal_id)
    if sid in _BUFFERED_IDS:
        return  # at-least-once redelivery — the window already holds it
    # The deque is maxlen-bounded (§9): once full, append() silently evicts the
    # OLDEST signal. Drop that signal's id from the dedup set in lockstep — else the
    # set leaks unboundedly under a flood AND a later redelivery of an evicted signal
    # would be wrongly deduped (dropped) because its stale id lingers in the set.
    if len(WINDOW_BUFFER) == WINDOW_BUFFER.maxlen:
        _BUFFERED_IDS.discard(str(WINDOW_BUFFER[0].signal_id))
    _BUFFERED_IDS.add(sid)
    WINDOW_BUFFER.append(sig)


def _prune_buffer(now: datetime) -> None:
    horizon = now.timestamp() - ENGINE_CFG.window_s
    while WINDOW_BUFFER and WINDOW_BUFFER[0].ts.timestamp() < horizon:
        _BUFFERED_IDS.discard(str(WINDOW_BUFFER[0].signal_id))
        WINDOW_BUFFER.popleft()


async def _persist_snapshot(snap: ObjectSnapshot, version: int, state: str,
                            window: list[Signal], merged_into: str = "") -> None:
    assert ch is not None
    await ch.insert("netops.corr_objects", [snap.to_object_row(version, state, merged_into)])
    edge_rows = snap.to_edge_rows(version)
    if edge_rows:
        await ch.insert("netops.corr_edges", edge_rows)
    ev_rows = snap.to_evidence_rows(version)
    if ev_rows:
        await ch.insert("netops.corr_evidence", ev_rows)
    # Stage [8] archive: the WHOLE tenant window, not just attached signals —
    # candidate-pool decisions depend on non-attached episodes, so a
    # participating-only archive would break bit-perfect replay. Slices are
    # version-scoped (basic-testing fix): replay re-runs exactly the window
    # THIS version was computed from, not the union of every version's window.
    archive_rows = []
    for s in window:
        row = s.to_ch_row()
        row["archived_for"] = snap.correlation_id
        row["archived_version"] = version
        archive_rows.append(row)
    if archive_rows:
        await ch.insert("netops.corr_signals_archive", archive_rows)
    log.info("corr-object %s v%d %s: top=%s tier=%s nodes=%d edges=%d",
             snap.correlation_id[:8], version, state, snap.ranking.top_hypothesis,
             snap.ranking.verdict_tier.value, len(snap.nodes), len(snap.edges))


def _topology_stale(now: datetime) -> bool:
    """§8: the topology/seam view is STALE when the Go exporter has stopped
    refreshing it (newest of seams.json / topology_links.json older than
    CORR_TOPO_STALE_S). Grounding then resolves against the last-known view with
    w_topo capped, and every snapshot scored under it is declared. An ABSENT file
    is not 'stale' — the grounding gate already handles an empty inventory honestly."""
    newest = -1.0
    for path in (SEAM_ENRICHMENT_FILE, TOPO_LINKS_FILE):
        try:
            newest = max(newest, os.path.getmtime(path))
        except OSError:
            continue
    return newest >= 0 and (now.timestamp() - newest) > CORR_TOPO_STALE_S


async def engine_cycle() -> None:
    """One evaluation: prune window, partition by tenant, run the pure core,
    persist version increments, close quiesced objects."""
    global LAST_GAP_HINTS
    if ch is None:
        return
    now = datetime.now(timezone.utc)
    _prune_buffer(now)
    # C6: flush this cycle's accumulated flow volume → passive_flow episodes BEFORE
    # partitioning, so the new flow signals join the same window they were measured in.
    await _flush_flow_aggregator(now)
    # §8 degradation, declared on every snapshot scored under it (never silent):
    topo_stale = _topology_stale(now)
    storm = len(WINDOW_BUFFER) >= STORM_BUFFER_FRACTION * (WINDOW_BUFFER.maxlen or 1)
    if topo_stale or storm:
        log.warning("engine degradation: topology_stale=%s storm_mode=%s (buffer=%d/%s)",
                    topo_stale, storm, len(WINDOW_BUFFER), WINDOW_BUFFER.maxlen)
    by_tenant: Dict[str, list[Signal]] = {}
    for s in WINDOW_BUFFER:
        by_tenant.setdefault(s.tenant_id, []).append(s)

    seen_this_cycle: set[str] = set()
    gap_hints = 0
    adj_by_tenant = topology_links_by_tenant()  # L2/L3 links for the adjacency rung (G1)
    for tenant in sorted(by_tenant):
        window = by_tenant[tenant]
        seams = tuple(s for s in seam_inventory() if s.tenant_id in (tenant, ""))
        # Tenant-scoped adjacency: this tenant's links ∪ global — never cross-tenant.
        adjacency = TopologyAdjacency.from_links(adj_by_tenant.get(tenant, []) + adj_by_tenant.get("", []))
        # The directed-topology oracle for this tenant, sources in PRECEDENCE order
        # (measured > observed > computed): C7.4 active-path-trace FIRST, then C7.3
        # NetFlow volume, then C7.5 routing (BGP-LS/IGP SPF). Each resolves through
        # this tenant's resolver / device entities → zero-leak. None when none covers
        # → vote #2 abstains (no-op).
        tenant_resolver = cached_entity_resolver_for(tenant)
        before = resolve_path_order(probe_paths(), tenant_resolver)
        vol = {**_FLOW_DIR.get("", {}), **_FLOW_DIR.get(tenant, {})}
        forward = forwarding_pairs(routing_direction())
        sources = []
        if before:
            sources.append(("traceroute", traceroute_direction_source(before)))
        if vol:
            sources.append(("netflow", netflow_direction_source(vol, FLOW_DIRECTION_DOMINANCE)))
        if forward:
            sources.append(("routing", routing_direction_source(forward)))
        directed = DirectedTopology(sources=tuple(sources)) if sources else None
        try:
            snapshots = run_window(window, CATALOG, seams, ENGINE_CFG, adjacency=adjacency,
                                   topology_stale=topo_stale, storm_mode=storm, directed=directed)
        except ValueError as exc:
            log.error("engine window rejected: %s", exc)
            continue
        for snap in snapshots:
            gap_hints += snap.gap_hints
            seen_this_cycle.add(snap.correlation_id)
            reg = OPEN_OBJECTS.get(snap.correlation_id)
            chash = snap.content_hash()
            if reg is None:
                OPEN_OBJECTS[snap.correlation_id] = {
                    "version": 1, "hash": chash, "last_seen": now, "snapshot": snap,
                }
                await _persist_snapshot(snap, 1, "open", window)
            elif reg["hash"] != chash:
                reg["version"] += 1
                reg["hash"] = chash
                reg["last_seen"] = now
                reg["snapshot"] = snap
                await _persist_snapshot(snap, reg["version"], "open", window)
            else:
                reg["last_seen"] = now

    # Merge (§4.4): de-split a cross-cycle identity drift. A stale open object that
    # overlaps a live one this cycle (entity-set + window) is the same incident
    # re-identified after its earliest signal aged out of the window — tombstone it
    # into the survivor (terminal state='merged' + merged_into) so the queue shows
    # ONE incident, not two. Replay-safe: only a lifecycle state + backlink, no
    # re-key/re-rank. Done BEFORE quiesce so a merged object never also quiesce-closes.
    survivors = [OPEN_OBJECTS[c]["snapshot"] for c in seen_this_cycle if c in OPEN_OBJECTS]
    stale_snaps = [OPEN_OBJECTS[c]["snapshot"] for c in OPEN_OBJECTS if c not in seen_this_cycle]
    for merged_cid, survivor_cid in find_merges(survivors, stale_snaps):
        reg = OPEN_OBJECTS.get(merged_cid)
        if reg is None:
            continue
        reg["version"] += 1
        await _persist_snapshot(reg["snapshot"], reg["version"], "merged", [], merged_into=survivor_cid)
        log.info("corr-object %s merged into %s (split-brain de-duplicated)",
                 merged_cid[:8], survivor_cid[:8])
        del OPEN_OBJECTS[merged_cid]

    # Quiesce: an object whose component no longer materializes (episodes aged
    # out / cleared) closes after CORR_QUIESCE_S — terminal version, append-only.
    for cid in list(OPEN_OBJECTS):
        reg = OPEN_OBJECTS[cid]
        if cid in seen_this_cycle:
            continue
        if (now - reg["last_seen"]).total_seconds() >= CORR_QUIESCE_S:
            reg["version"] += 1
            await _persist_snapshot(reg["snapshot"], reg["version"], "closed", [])
            del OPEN_OBJECTS[cid]
    LAST_GAP_HINTS = gap_hints


async def engine_loop() -> None:
    if not (CORR_SIGNALS_ENABLED and CORR_ENGINE_ENABLED):
        log.info("engine v2 object loop disabled")
        return
    log.info("engine v2 object loop: interval=%.0fs window=%.0fs quiesce=%.0fs",
             CORR_ENGINE_INTERVAL_S, ENGINE_CFG.window_s, CORR_QUIESCE_S)
    while True:
        try:
            await engine_cycle()
        except Exception:                                  # noqa: BLE001
            log.exception("engine cycle failed (observable, §10; loop continues)")
        await asyncio.sleep(CORR_ENGINE_INTERVAL_S)


async def feed_episode_detector(
    tenant: str,
    entity_id: str,
    metric: str,
    value: float,
    event_ts: datetime,
    *,
    observer_id: str,
    collection_path: str,
    entity_type: EntityType,
    kind_prefix: str,
    entity_tokens: tuple[str, ...] = (),
    source: Source = Source.METRIC,
    modality: ModalityClass = ModalityClass.DEVICE_TELEMETRY,
    observer_type: ObserverType = ObserverType.DEVICE,
) -> bool:
    """Stage [1]+[2]: run CUSUM over the canonical (entity, metric) series and
    persist episode signals. Identity is the canonical entity_id (device:ifName
    for interfaces, device:peer for BGP) so per-interface/per-peer series do not
    collide on a shared metric name. Provenance is threaded from the event —
    parameterized so a passive_flow volume series carries flow-exporter provenance
    (C6) instead of device telemetry, exactly as probe episodes carry vantage-agent."""
    global DEADLETTER_COUNT, DEVICE_TELEMETRY_SIGNALS
    if not CORR_SIGNALS_ENABLED or ch is None:
        return False
    ev = DETECTOR.observe(tenant, entity_id, metric, event_ts, value, clock_quality="unknown")
    if ev is None:
        return False  # still baselining / within hysteresis — no episode this sample
    try:
        observer = Observer(
            observer_id=observer_id,
            observer_type=observer_type,
            collection_path=collection_path,
            clock_quality="unknown",
        )
        sig = episode_signal(
            ev, observer,
            source=source,
            modality=modality,
            entity_type=entity_type,
            kind_prefix=kind_prefix,
            entity_tokens=entity_tokens,
        )
        row = sig.to_ch_row()
    except DeadLetter as exc:
        DEADLETTER_COUNT += 1
        log.warning("dead-letter (provenance): %s", exc)
        return False
    await ch.insert("netops.corr_signals", [row])
    if modality is ModalityClass.DEVICE_TELEMETRY:
        DEVICE_TELEMETRY_SIGNALS += 1
    # Build ⑥: every spine signal also feeds the engine's evidence window.
    buffer_signal(sig)
    log.info("episode %s: %s/%s peak=%.1fσ ±%.0fs", ev.phase, ev.key[1],
             ev.key[2], ev.peak_deviation, ev.onset_uncertainty_s)
    return True  # an episode signal was emitted this sample


def score(device: str, metric: str, value: float) -> float | None:
    """Return a |z-score| if the value is anomalous, else None."""
    key = (device, metric)
    s = SERIES.setdefault(key, Series())
    if len(s.values) < 20:
        s.push(value)
        return None
    sigma = s.stddev()
    if sigma == 0:
        s.push(value)
        return None
    z = abs((value - s.mean()) / sigma)
    s.push(value)
    if z >= Z_THRESHOLD:
        return z
    return None


# ---------------------------------------------------------------------------
# ClickHouse helpers (HTTP interface).
# ---------------------------------------------------------------------------


class CH:
    def __init__(self, base_url: str, user: str, password: str) -> None:
        self.base = base_url.rstrip("/")
        self.auth = (user, password)
        self.client = httpx.AsyncClient(timeout=10.0)

    async def insert(self, table: str, rows: Iterable[dict]) -> None:
        body = "\n".join(json.dumps(r) for r in rows)
        if not body:
            return
        params = {"query": f"INSERT INTO {table} FORMAT JSONEachRow"}
        r = await self.client.post(
            self.base, params=params, content=body, auth=self.auth,
            headers={"Content-Type": "application/x-ndjson"},
        )
        if r.status_code >= 300:
            log.error("clickhouse insert failed: %s %s", r.status_code, r.text)

    async def query(self, sql: str) -> list[dict]:
        # #20 Phase 2: trusted internal reader — pass tenant_scope=__all__ so the
        # findings row policy doesn't reject the query (ClickHouse errors on an
        # unset custom setting once a policy references getSetting('tenant_scope')).
        r = await self.client.post(
            self.base, params={"default_format": "JSON", "tenant_scope": "__all__"},
            content=sql, auth=self.auth,
        )
        if r.status_code >= 300:
            raise HTTPException(status_code=502, detail=r.text)
        return r.json().get("data", [])

    async def close(self) -> None:
        await self.client.aclose()


ch: CH | None = None


# ---------------------------------------------------------------------------
# Kafka consumer loop.
# ---------------------------------------------------------------------------


async def consume() -> None:
    """Supervised consumer: a poison batch / codec error / broker hiccup is
    logged and retried with backoff, NEVER a silent task death (§10 — the
    pre-build-⑥ consumer died unobserved on a snappy-compressed batch and
    starved the whole engine; this loop is the guarantee that can't recur)."""
    backoff = 1.0
    while True:
        consumer = AIOKafkaConsumer(
            *TOPICS,
            bootstrap_servers=KAFKA_BOOTSTRAP,
            group_id="netops-correlation",
            auto_offset_reset="latest",
            value_deserializer=lambda v: json.loads(v.decode("utf-8")) if v else None,
            enable_auto_commit=True,
        )
        try:
            await consumer.start()
            log.info("consuming topics=%s bootstrap=%s", TOPICS, KAFKA_BOOTSTRAP)
            backoff = 1.0
            async for msg in consumer:
                await handle(msg.topic, msg.value)
        except asyncio.CancelledError:
            raise
        except Exception:                                  # noqa: BLE001
            log.exception("consumer failed; restarting in %.0fs", backoff)
        finally:
            await consumer.stop()
        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, 60.0)


async def handle(topic: str, event: dict | None) -> None:
    if not event or ch is None:
        return

    if topic == "netops.metrics":
        await handle_metric(event)
    elif topic == "netops.syslog":
        await handle_syslog(event)
    elif topic == "netops.flows":
        await handle_flow(event)
    elif topic == "netops.probes":
        await handle_probe(event)
    elif topic == "netops.snmptrap":
        await handle_snmptrap(event)
    elif topic == "netops.cloud":
        await handle_cloud(event)


def metric_identity(ev: dict) -> tuple[str, EntityType, str, tuple[str, ...]] | None:
    """Resolve the canonical entity from a MetricEvent's signal_family + identity.
    Returns (entity_id, entity_type, kind_prefix, entity_tokens) or None when the
    required identity is missing (caller drops + counts). Per-interface/per-peer
    entity_ids keep CUSUM series distinct on a shared metric name."""
    device = str(ev.get("device") or "")
    if not device:
        return None
    family = str(ev.get("signal_family") or "")
    if family == "interface":
        iface = str(ev.get("if_name") or ev.get("index") or "")
        if not iface:
            return None
        return f"{device}:{iface}", EntityType.INTERFACE, "if_metric_anomaly", (device, iface)
    if family == "bgp":
        peer = str(ev.get("peer") or ev.get("index") or "")
        if not peer:
            return None
        # BGP4-MIB has no VRF column; default network-instance is implicit.
        return f"{device}:{peer}", EntityType.DEVICE, "bgp_state_anomaly", (device, peer)
    if family == "device_resource":
        return device, EntityType.DEVICE, "device_resource_anomaly", (device,)
    return None


async def handle_metric(ev: dict) -> None:
    """Canonical MetricEvent (netops.metrics) → device_telemetry signal.

    Wire contract with collectors/metric_events.go: device, metric, value,
    signal_family, if_name/peer/index, collection_path, ts, vendor. Legacy
    Telegraf-shaped events (hostname/name/first-numeric) are still tolerated for
    back-compat but carry no canonical identity."""
    global METRICS_RECEIVED, METRICS_ACCEPTED, METRICS_DROPPED
    METRICS_RECEIVED += 1

    metric = str(ev.get("metric") or ev.get("name") or "")
    raw_value = ev.get("value")
    if raw_value is None:
        # Legacy fallback: first numeric field.
        for k, v in ev.items():
            if isinstance(v, (int, float)) and k not in {"timestamp", "time", "value"}:
                raw_value = v
                break
    if not metric or not isinstance(raw_value, (int, float)) or isinstance(raw_value, bool):
        METRICS_DROPPED += 1
        return
    value = float(raw_value)

    ident = metric_identity(ev)
    if ident is None:
        # No canonical identity → cannot ground a signal. Drop, don't guess.
        METRICS_DROPPED += 1
        return
    entity_id, entity_type, kind_prefix, tokens = ident

    # Timestamp validation (Layer-1F): trust the event clock only within skew.
    now = datetime.now(timezone.utc)
    event_ts = parse_event_ts(ev.get("ts")) or now
    age = (now - event_ts).total_seconds()
    if age < -METRIC_FUTURE_SKEW_S or age > METRIC_MAX_AGE_S:
        METRICS_DROPPED += 1
        log.warning("metric dropped: timestamp out of bounds (age=%.0fs) %s/%s", age, entity_id, metric)
        return

    tenant = str(ev.get("tenant_id") or "") or tenant_for(str(ev.get("device") or ""))
    collection_path = str(ev.get("collection_path") or "snmp_poll")
    METRICS_ACCEPTED += 1

    # Engine v2 stage [1]+[2]: every sample feeds the episode detector (CUSUM
    # needs the full stream, not just crossings) — the canonical corr_signals path.
    await feed_episode_detector(
        tenant, entity_id, metric, value, event_ts,
        observer_id=str(ev.get("device") or ""),
        collection_path=collection_path,
        entity_type=entity_type,
        kind_prefix=kind_prefix,
        entity_tokens=tokens,
    )

    # Legacy rolling z-score finding (back-compat, netops.findings). Keyed on the
    # canonical entity_id so per-interface/per-peer series don't collide on a
    # shared metric name. Superseded by the episode detector above; kept until
    # the findings surface retires.
    z = score(entity_id, metric, value)
    if z is None:
        return
    await emit(
        kind="anomaly",
        severity="warning" if z < 5 else "critical",
        device=str(ev.get("device") or ""),
        component=metric,
        summary=f"{metric} on {entity_id} z={z:.1f}",
        description="Rolling z-score over the baseline window exceeded threshold.",
        score=float(z),
        labels={"metric": metric, "entity": entity_id},
    )


# Severity weights for syslog correlation. A burst of high-severity
# events from one device within a short window is itself a finding.
SEVERITY_WEIGHT = {"emerg": 8, "alert": 7, "crit": 6, "err": 5, "warning": 3, "notice": 2, "info": 1, "debug": 0}
SYSLOG_BUCKET: Dict[str, list[tuple[float, int]]] = {}
SYSLOG_WINDOW = 60.0   # seconds
SYSLOG_THRESHOLD = 30  # cumulative weight


# Probe-authority classification config (Step 3). Registry-sourced fields on the
# event win; otherwise we infer + FAIL CLOSED. See docs/design/probe-authority-model.md.
#
# Active-measurement vantages (e.g. the STAMP prober). Their probes to a CUSTOMER
# target are customer_path evidence (shown as supporting on the affected device);
# their probes to a platform service are internal (target check wins, below).
_MEASUREMENT_PROBE_OBSERVERS = {
    o.strip().lower() for o in os.getenv(
        # back-compat: the old var named the same observers.
        "CORR_MEASUREMENT_PROBE_OBSERVERS", os.getenv("CORR_SYNTHETIC_PROBE_OBSERVERS", "api,prober"),
    ).split(",") if o.strip()
}
# Measurement observers the operator has DECLARED trustworthy. Their customer-path
# probes may anchor a CONFIRMED verdict — still only alongside an independent
# witness of another modality (a probe alone never confirms; verdicts.py enforces
# this). Default EMPTY = conservative: probes SUPPORT (→ suspected), never confirm.
_TRUSTED_PROBE_OBSERVERS = {
    o.strip().lower() for o in os.getenv("CORR_TRUSTED_PROBE_OBSERVERS", "").split(",") if o.strip()
}
# The (confirm-capable, real) vantage a trusted observer maps to. A self-hosted
# STAMP runner reads as the customer's private location.
try:
    _TRUSTED_PROBE_VANTAGE = VantageType(os.getenv("CORR_TRUSTED_PROBE_VANTAGE", "private_location"))
except ValueError:
    _TRUSTED_PROBE_VANTAGE = VantageType.PRIVATE_LOCATION
# The platform's OWN stack services. A probe whose destination is one of these is
# self-monitoring, not customer observability — it must never anchor a customer
# incident (decision #76). Explicit default (was empty) so the classification is
# robust regardless of which agent issued the probe; override via env per deploy.
_INTERNAL_PROBE_TARGETS = {
    t.strip().lower() for t in os.getenv(
        "CORR_INTERNAL_PROBE_TARGETS",
        "nginx,api,frontend,clickhouse,redis,postgres,netbox,grafana,keycloak,"
        "opensearch,victoriametrics,prometheus,redpanda,vector,loki,promtail,"
        "correlation,prober",
    ).split(",") if t.strip()
}
_SERVICE_DEP_TARGETS = {
    t.strip().lower() for t in os.getenv("CORR_SERVICE_DEP_TARGETS", "").split(",") if t.strip()
}


def classify_probe(ev: dict, sig: Signal) -> None:
    """Enrich an active_probe signal IN PLACE with its derived authority/scope +
    fate fingerprint. Registry fields (`probe_intent`/`vantage_type` on the event)
    are authoritative; otherwise infer and fail closed to UNKNOWN→LOW."""
    intent = str(ev.get("probe_intent") or "")
    vantage = str(ev.get("vantage_type") or "")
    src = "registry"
    if intent and vantage:
        try:
            pi, vt = ProbeIntent(intent), VantageType(vantage)
        except ValueError:
            pi, vt, src = ProbeIntent.UNKNOWN, VantageType.UNKNOWN, "unknown"
    else:
        obs = (sig.observer.observer_id or "").lower()
        target = sig.entity_id.split("->", 1)[1].strip().lower() if "->" in sig.entity_id else ""
        # TARGET wins first: probing a platform service is self-monitoring no matter
        # who issued it (decision #76), so it can never leak into a customer incident.
        if target in _INTERNAL_PROBE_TARGETS:
            pi, vt, src = ProbeIntent.PLATFORM_SELF_CHECK, VantageType.INTERNAL_COLLECTOR, "inferred"
        elif target in _SERVICE_DEP_TARGETS:
            pi, vt, src = ProbeIntent.SERVICE_DEPENDENCY, VantageType.PUBLIC_CLOUD_AGENT, "inferred"
        elif obs in _MEASUREMENT_PROBE_OBSERVERS:
            # An active-measurement vantage probing a CUSTOMER path. Scope =
            # customer_path → shown as supporting evidence on the affected device.
            # Authority follows the vantage's DECLARED trust: trusted observers get a
            # confirm-capable vantage; untrusted (default) stay LOW — SUPPORT, never
            # CONFIRM. UNKNOWN with customer_path resolves to LOW (not debug), so the
            # probe is visible, unlike the old LOCAL_CONTAINER→debug_only default.
            if obs in _TRUSTED_PROBE_OBSERVERS:
                pi, vt, src = ProbeIntent.CUSTOMER_PATH, _TRUSTED_PROBE_VANTAGE, "inferred-trusted"
            else:
                pi, vt, src = ProbeIntent.CUSTOMER_PATH, VantageType.UNKNOWN, "inferred"
        else:
            pi, vt, src = ProbeIntent.UNKNOWN, VantageType.UNKNOWN, "unknown"
    sig.attrs["probe_intent"] = pi.value
    sig.attrs["vantage_type"] = vt.value
    sig.attrs["probe_authority"] = derive_probe_authority(pi, vt).value
    sig.attrs["probe_scope"] = derive_probe_scope(pi, vt).value
    sig.attrs["classification_source"] = src
    sig.attrs["agent_host"] = str(ev.get("agent_host") or ev.get("source") or sig.observer.observer_id)
    egress = str(ev.get("source_egress") or ev.get("egress_ip") or "")
    if egress:
        sig.attrs["source_egress"] = egress
    if ev.get("seam_id"):
        sig.attrs["seam_id"] = str(ev["seam_id"])
    if ev.get("schedule_id"):
        sig.attrs["schedule_id"] = str(ev["schedule_id"])


async def handle_probe(ev: dict) -> None:
    """Active-measurement events (STAMP / ICMP / TCP / HTTP) from the Go
    collectors via netops.probes → active_probe signals on the spine
    (#67 build ⑦). The probe path is the evidence class device telemetry
    cannot supply — gray failures are invisible to counters. Each signal is
    classified for probe authority + fate (Step 3) before it enters the spine."""
    global DEADLETTER_COUNT
    if not CORR_SIGNALS_ENABLED or ch is None:
        return
    host = str(ev.get("target") or "")
    tenant = str(ev.get("tenant_id") or "") or tenant_for(host)
    now = datetime.now(timezone.utc)
    try:
        sigs = probe_signals(ev, DETECTOR, tenant, now)
    except DeadLetter as exc:
        DEADLETTER_COUNT += 1
        log.warning("dead-letter (probe): %s", exc)
        return
    for sig in sigs:
        classify_probe(ev, sig)
        await ch.insert("netops.corr_signals", [sig.to_ch_row()])
        buffer_signal(sig)
        log.info("probe signal %s: %s sev=%s value=%.1f scope=%s auth=%s",
                 sig.kind, sig.entity_id, sig.severity.value, sig.value,
                 sig.attrs.get("probe_scope"), sig.attrs.get("probe_authority"))


async def handle_snmptrap(ev: dict) -> None:
    """Normalized SNMP trap (netops.snmptrap) → control_plane signal for the
    high-value families only. Unclassified traps stay searchable in OpenSearch
    and create NO RCA signal (the anti-noise guardrail). The OpenSearch path is
    untouched — this is an ADDITIONAL evidence lane, not a replacement."""
    global DEADLETTER_COUNT, TRAPS_RECEIVED, TRAPS_NORMALIZED, TRAPS_DROPPED, TRAPS_RECANON
    TRAPS_RECEIVED += 1
    if not CORR_SIGNALS_ENABLED or ch is None:
        return
    # G2/C8: the Go receiver (G2a) attributes the trap to an inventory device via
    # source-IP / sysName / agent-addr. When that leaves it UNATTRIBUTED, try the
    # richer C7.1 EntityResolver on the trap's own source address — it also knows
    # INTERFACE IPs, so a trap sourced from a device's interface (not its mgmt IP)
    # still resolves. A NAT-collapsed shared source is ambiguous → stays unresolved
    # (the producer then keeps it searchable but emits no phantom-device RCA signal).
    device = str(ev.get("device") or "")
    if not device:
        recovered = cached_entity_resolver_all().device_for_ip(str(ev.get("host") or ""))
        if recovered:
            ev = {**ev, "device": recovered}
            device = recovered
            TRAPS_RECANON += 1
    tenant = str(ev.get("tenant_id") or "") or tenant_for(device)
    try:
        sig = trap_control_signal(ev, tenant, datetime.now(timezone.utc))
    except DeadLetter as exc:
        DEADLETTER_COUNT += 1
        log.warning("dead-letter (trap): %s", exc)
        return
    if sig is None:
        TRAPS_DROPPED += 1   # unclassified — no RCA signal, kept searchable
        return
    await ch.insert("netops.corr_signals", [sig.to_ch_row()])
    TRAPS_NORMALIZED += 1
    buffer_signal(sig)
    log.info("trap signal %s: %s %s", sig.kind, sig.entity_id, sig.attrs.get("state", ""))


async def handle_cloud(ev: dict) -> None:
    """Cloud App Observability events (netops.cloud) → canonical cloud signals on
    the SAME spine (#81 P3G). Additive evidence lane: the existing engine grounds,
    correlates and verdicts them with no cloud-specific code path. A cloud-only
    picture is suspected-at-best (one vantage); confirmation needs an independent
    observer (probe / underlay / firewall). Tenancy is EXPLICIT — a cloud event
    carries its own tenant_id (there is no device to infer it from); an untenanted
    event is DROPPED, never guessed (default-closed isolation, §3a)."""
    global DEADLETTER_COUNT, CLOUD_RECEIVED, CLOUD_SIGNALS, CLOUD_DROPPED
    CLOUD_RECEIVED += 1
    if not CORR_SIGNALS_ENABLED or ch is None:
        return
    tenant = str(ev.get("tenant_id") or "")
    if not tenant:
        CLOUD_DROPPED += 1
        log.warning("cloud event dropped: no tenant_id (kind=%s)", ev.get("kind"))
        return
    try:
        sig = cloud_signal_from_event(ev, tenant, datetime.now(timezone.utc))
    except DeadLetter as exc:
        DEADLETTER_COUNT += 1
        CLOUD_DROPPED += 1
        log.warning("dead-letter (cloud): %s", exc)
        return
    await ch.insert("netops.corr_signals", [sig.to_ch_row()])
    CLOUD_SIGNALS += 1
    buffer_signal(sig)
    log.info("cloud signal %s: %s sev=%s acct=%s region=%s",
             sig.kind, sig.entity_id, sig.severity.value,
             sig.attrs.get("account", ""), sig.attrs.get("region", ""))


async def handle_syslog(ev: dict) -> None:
    # Control-plane extraction first (#67 build ⑦): adjacency / link-state
    # events become control_plane signals on the spine regardless of burst
    # behavior — one BGP-down is evidence even when nothing else is on fire.
    global DEADLETTER_COUNT
    if CORR_SIGNALS_ENABLED and ch is not None:
        cp_tenant = str(ev.get("tenant_id") or "") or tenant_for(str(ev.get("hostname") or ""))
        try:
            cp_sig = syslog_control_signal(ev, cp_tenant, datetime.now(timezone.utc))
        except DeadLetter as exc:
            DEADLETTER_COUNT += 1
            log.warning("dead-letter (syslog): %s", exc)
            cp_sig = None
        if cp_sig is not None:
            await ch.insert("netops.corr_signals", [cp_sig.to_ch_row()])
            buffer_signal(cp_sig)
            log.info("control-plane signal %s: %s %s",
                     cp_sig.kind, cp_sig.entity_id, cp_sig.attrs.get("state", ""))

    host = str(ev.get("hostname") or "unknown")
    sev  = str(ev.get("severity") or "info").lower()
    weight = SEVERITY_WEIGHT.get(sev, 0)
    if weight == 0:
        return
    now = time.time()
    bucket = SYSLOG_BUCKET.setdefault(host, [])
    bucket.append((now, weight))
    # Drop expired entries.
    cutoff = now - SYSLOG_WINDOW
    SYSLOG_BUCKET[host] = [(t, w) for t, w in bucket if t >= cutoff]
    total = sum(w for _, w in SYSLOG_BUCKET[host])
    if total >= SYSLOG_THRESHOLD:
        await emit(
            kind="correlation",
            severity="warning",
            device=host,
            component="syslog",
            summary=f"Syslog burst on {host}: weighted={total}",
            description=f"≥{SYSLOG_THRESHOLD} severity-points within {int(SYSLOG_WINDOW)}s window.",
            score=float(total),
            labels={"host": host},
        )
        SYSLOG_BUCKET[host] = []   # reset so we don't spam


async def handle_flow(ev: dict) -> None:
    """Accumulate per-(tenant, exporting-interface) flow VOLUME (C6). Cheap by
    design — flows are a firehose, so we aggregate O(1) here and never emit a signal
    per flow; _flush_flow_aggregator turns each per-interface total into one CUSUM
    sample per engine cycle. This is the passive_flow modality lane — the 4th
    independent witness class for the verdict gate (DDoS / top-talker-shift /
    port-scan SIGNATURES are future catalog growth on top of this volume series)."""
    global FLOWS_RECEIVED
    if not (CORR_SIGNALS_ENABLED and FLOW_CORRELATION_ENABLED) or ch is None:
        return
    sample = flow_sample(ev)
    if sample is None:
        return
    FLOWS_RECEIVED += 1
    sampler, entity, bytes_est = sample
    tenant = str(ev.get("tenant_id") or "") or tenant_for(sampler)
    agg = _FLOW_AGG.setdefault((tenant, entity), {"bytes": 0.0, "sampler": sampler})
    agg["bytes"] += bytes_est
    # C7.3: directed per-pair volume. Resolve src/dst → devices (best-effort; abstains
    # when an endpoint is unknown) and accumulate a directed byte total → the oracle's
    # NetFlow direction source.
    global FLOW_DIRECTION_PAIRS
    dsample = flow_direction_sample(ev, cached_entity_resolver_for(tenant))
    if dsample is not None:
        sd, dd, dbytes = dsample
        dirmap = _FLOW_DIR.setdefault(tenant, {})
        if (sd, dd) not in dirmap:
            FLOW_DIRECTION_PAIRS += 1
        dirmap[(sd, dd)] = dirmap.get((sd, dd), 0.0) + dbytes


async def _flush_flow_aggregator(now: datetime) -> None:
    """Feed each accumulated per-interface byte total through CUSUM as ONE
    passive_flow sample this cycle, then reset. The detection interval is the engine
    cycle interval — regular sampling, exactly like a metric poll — so the existing
    episode machinery baselines and fires flow_volume_anomaly episodes."""
    global PASSIVE_FLOW_SIGNALS
    if not _FLOW_AGG:
        return
    snapshot = dict(_FLOW_AGG)
    _FLOW_AGG.clear()
    interval = max(CORR_ENGINE_INTERVAL_S, 1.0)
    for (tenant, entity), a in sorted(snapshot.items()):
        emitted = await feed_episode_detector(
            tenant, entity, "flow_bytes_rate", a["bytes"] / interval, now,
            observer_id=a["sampler"], collection_path="flow_export",
            entity_type=EntityType.INTERFACE, kind_prefix="flow_volume_anomaly",
            entity_tokens=(a["sampler"],),
            source=Source.FLOW, modality=ModalityClass.PASSIVE_FLOW,
            observer_type=ObserverType.FLOW_EXPORTER,
        )
        if emitted:
            PASSIVE_FLOW_SIGNALS += 1  # count ACTUAL passive_flow signals, not flushes


async def emit(**kwargs) -> None:
    device = kwargs.get("device", "")
    row = {
        "id":          str(uuid.uuid4()),
        "kind":        kwargs["kind"],
        "severity":    kwargs["severity"],
        "score":       kwargs["score"],
        "device":      device,
        "component":   kwargs.get("component", ""),
        "summary":     kwargs.get("summary", ""),
        "description": kwargs.get("description", ""),
        "labels":      kwargs.get("labels", {}),
        "tenant_id":   tenant_for(device),  # #20: same tenant discriminator as flows/logs
    }
    assert ch is not None
    await ch.insert("netops.findings", [row])
    log.info("finding: %s %s %s", row["severity"], row["kind"], row["summary"])


# ---------------------------------------------------------------------------
# HTTP API
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global ch
    ch = CH(CLICKHOUSE_URL, CLICKHOUSE_USER, CLICKHOUSE_PASS)
    tasks = [asyncio.create_task(consume()), asyncio.create_task(engine_loop())]
    try:
        yield
    finally:
        for task in tasks:
            task.cancel()
        for task in tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass
        await ch.close()


app = FastAPI(title="netops-correlation", version="0.1.0", lifespan=lifespan)


class Finding(BaseModel):
    ts: str
    id: str
    kind: str
    severity: str
    score: float
    device: str
    component: str
    summary: str
    description: str


@app.get("/healthz")
async def health() -> dict:
    return {
        "status": "ok",
        "engine_v2": {
            "corr_signals_enabled": CORR_SIGNALS_ENABLED,
            "open_episodes": DETECTOR.open_episodes(),
            "deadletter_count": DEADLETTER_COUNT,
            "engine_enabled": CORR_ENGINE_ENABLED,
            "open_objects": len(OPEN_OBJECTS),
            "window_signals": len(WINDOW_BUFFER),
            "seam_inventory": len(seam_inventory()),
            "topology_gap_hints": LAST_GAP_HINTS,
            # C7.1 EntityResolver coverage (global slice) — proves the IP/ifIndex→entity
            # bridge is populated; the directed-topology sources resolve through it.
            "entity_resolver": entity_resolver_for("").coverage(),
            "probe_paths": len(probe_paths()),          # C7.4 measured paths available
            "routing_direction_pairs": len(routing_direction()),  # C7.5 computed fwd pairs
        },
        # Metric/trap lane observability — proves netops.metrics is fed and where
        # events are accepted vs dropped (the lane was historically empty).
        "ingest": {
            "metrics_received": METRICS_RECEIVED,
            "metrics_accepted": METRICS_ACCEPTED,
            "metrics_dropped": METRICS_DROPPED,
            "device_telemetry_signals": DEVICE_TELEMETRY_SIGNALS,
            "traps_received": TRAPS_RECEIVED,
            "traps_normalized": TRAPS_NORMALIZED,
            "traps_recanonicalized": TRAPS_RECANON,  # C8: device recovered via EntityResolver
            "traps_dropped": TRAPS_DROPPED,
            "flows_received": FLOWS_RECEIVED,
            "passive_flow_signals": PASSIVE_FLOW_SIGNALS,
            "flow_entities_tracked": len(_FLOW_AGG),
            # C7.3 NetFlow direction: distinct directed device-pairs observed.
            "flow_direction_pairs": FLOW_DIRECTION_PAIRS,
            # #81 P3G cloud lane: proves netops.cloud is consumed + where events are lost.
            "cloud_received": CLOUD_RECEIVED,
            "cloud_signals": CLOUD_SIGNALS,
            "cloud_dropped": CLOUD_DROPPED,
        },
    }


@app.get("/correlations/{correlation_id}/replay")
async def correlation_replay(correlation_id: str, version: int | None = None) -> dict:
    """Re-run the engine over the object's archived window and report drift
    (design §5: internal surface; the Go API fronts it with authz)."""
    assert ch is not None
    try:
        report = await replay_object(ch, correlation_id, version)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return report.to_dict()


@app.get("/findings", response_model=list[Finding])
async def findings(limit: int = 100, severity: str | None = None) -> list[dict]:
    assert ch is not None
    where = ""
    if severity:
        # Severities are simple enum words (warning/critical/info/...). Restrict
        # to letters so the value cannot carry SQL metacharacters — quote-
        # stripping alone is unsafe because ch.query sends raw SQL and ClickHouse
        # honors backslash escapes. An out-of-shape value is ignored (no filter).
        if severity.isalpha():
            where = f"WHERE severity = '{severity.lower()}'"
    sql = f"""
      SELECT toString(ts) AS ts, id, kind, severity, score, device,
             component, summary, description
        FROM netops.findings
        {where}
       ORDER BY ts DESC
       LIMIT {int(limit)}
       FORMAT JSON
    """  # nosec B608 -- `where` is alpha-validated, `limit` is int()-cast; no injection vector
    return await ch.query(sql)


@app.post("/analyze")
async def analyze() -> dict:
    """On-demand RCA stub. Replace with a real implementation that
    correlates recent findings into incident clusters."""
    return {"status": "scheduled", "note": "RCA is a stub in this scaffold."}
