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
from engine import EngineConfig, ObjectSnapshot, SeamView, TopologyAdjacency, find_merges, run_window
from episodes import EpisodeDetector
from producers import (
    episode_signal,
    parse_event_ts,
    probe_signals,
    syslog_control_signal,
    trap_control_signal,
)
from replay import replay_object
from signals import (
    DeadLetter,
    EntityType,
    Observer,
    ObserverType,
    ProbeIntent,
    Signal,
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

TOPICS = ["netops.syslog", "netops.flows", "netops.metrics", "netops.probes", "netops.snmptrap"]

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
TRAPS_DROPPED = 0              # unclassified — kept searchable, no RCA signal

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
SEAM_ENRICHMENT_FILE = os.environ.get("SEAM_ENRICHMENT_FILE", "/data/enrichment/seams.json")
# L2/L3 adjacency (LLDP/CDP/BGP-LS links) exported by the Go API — the grounding
# input for the §4.2 "L2/L3 adjacent device" rung (G1). Absent file = no adjacency
# (gate falls back to seam/containment, identical to before — honest, never relaxed).
TOPO_LINKS_FILE = os.environ.get("TOPO_LINKS_FILE", "/data/enrichment/topology_links.json")

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


async def engine_cycle() -> None:
    """One evaluation: prune window, partition by tenant, run the pure core,
    persist version increments, close quiesced objects."""
    global LAST_GAP_HINTS
    if ch is None:
        return
    now = datetime.now(timezone.utc)
    _prune_buffer(now)
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
        try:
            snapshots = run_window(window, CATALOG, seams, ENGINE_CFG, adjacency=adjacency)
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
) -> None:
    """Stage [1]+[2]: run CUSUM over the canonical (entity, metric) series and
    persist episode signals. Identity is the canonical entity_id (device:ifName
    for interfaces, device:peer for BGP) so per-interface/per-peer series do not
    collide on a shared metric name. Provenance is threaded from the event."""
    global DEADLETTER_COUNT, DEVICE_TELEMETRY_SIGNALS
    if not CORR_SIGNALS_ENABLED or ch is None:
        return
    ev = DETECTOR.observe(tenant, entity_id, metric, event_ts, value, clock_quality="unknown")
    if ev is None:
        return
    try:
        observer = Observer(
            observer_id=observer_id,
            observer_type=ObserverType.DEVICE,
            collection_path=collection_path,
            clock_quality="unknown",
        )
        sig = episode_signal(
            ev, observer,
            entity_type=entity_type,
            kind_prefix=kind_prefix,
            entity_tokens=entity_tokens,
        )
        row = sig.to_ch_row()
    except DeadLetter as exc:
        DEADLETTER_COUNT += 1
        log.warning("dead-letter (provenance): %s", exc)
        return
    await ch.insert("netops.corr_signals", [row])
    DEVICE_TELEMETRY_SIGNALS += 1
    # Build ⑥: every spine signal also feeds the engine's evidence window.
    buffer_signal(sig)
    log.info("episode %s: %s/%s peak=%.1fσ ±%.0fs", ev.phase, ev.key[1],
             ev.key[2], ev.peak_deviation, ev.onset_uncertainty_s)


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
    global DEADLETTER_COUNT, TRAPS_RECEIVED, TRAPS_NORMALIZED, TRAPS_DROPPED
    TRAPS_RECEIVED += 1
    if not CORR_SIGNALS_ENABLED or ch is None:
        return
    tenant = str(ev.get("tenant_id") or "") or tenant_for(str(ev.get("device") or ev.get("host") or ""))
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


async def handle_flow(_ev: dict) -> None:
    # Placeholder: NetFlow correlation (DDoS detection, top-talker
    # sudden shift, port-scan signatures) goes here.
    return


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
            "traps_dropped": TRAPS_DROPPED,
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
