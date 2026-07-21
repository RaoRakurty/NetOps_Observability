"""NetOps Observability — Correlation + AI Engine.

A FastAPI service that:

  * Consumes the netops.syslog, netops.flows, netops.metrics Kafka
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
import glob
import json
import logging
import os
import time
import uuid
from collections import Counter, OrderedDict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace as dc_replace
from datetime import datetime, timezone
from typing import Deque, Dict, Iterable

import httpx
from aiokafka import AIOKafkaConsumer
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from catalog import builtin_catalog
from cloud_dependency import build_from_records, merge_path_views
from directed_topology import DirectedTopology
from engine import EngineConfig, ObjectSnapshot, SeamView, TopologyAdjacency, find_continuation, find_merges, run_window
from path_assembly import (
    AssembledPath,
    DiscoveredEdge,
    DiscoverySources,
    DnsHead,
    PathAssembler,
    flow_edges_from_pairs,
    inventory_edges_from_topology,
    measured_run_from_observation,
)
from path_graph import PathGraphView
from entity_resolver import EntityResolver
from flow_direction import flow_direction_sample, netflow_direction_source
from path_direction import resolve_path_order, traceroute_direction_source
from routing_direction import forwarding_pairs, routing_direction_source
from episodes import EpisodeDetector
from cloud_log_parsers import (
    cloud_log_event, dns_error_rollup, parse_aws_waf_log, parse_r53_dns_log,
    parse_vpc_flow_log, vpc_accept_rollup, vpc_flow_signal, vpc_pair_rollup,
    waf_block_rollup,
)
from cloud_producers import cloud_signal_from_event
from app_producers import app_identity_from_event
from controller_events import controller_event_to_signal
from verification_producer import verification_signal_from_event
from producers import (
    clock_skew_signal,
    episode_signal,
    flow_sample,
    parse_event_ts,
    port_event_signal,
    probe_signals,
    syslog_control_signal,
    trap_control_signal,
    ts_invalid_count,
)
from replay import replay_object
from flow_app_attribution import AppIdentityIndex, resolve_flow_app
from lb_normalize import normalize_lb_event
from synthetic_normalize import synthetic_app_signal
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
KAFKA_BOOTSTRAP  = os.environ.get("KAFKA_BOOTSTRAP", "kafka:9092")
CLICKHOUSE_URL   = os.environ.get("CLICKHOUSE_URL", "http://clickhouse:8123")
CLICKHOUSE_USER  = os.environ.get("CLICKHOUSE_USER", "netops")
CLICKHOUSE_PASS  = os.environ.get("CLICKHOUSE_PASSWORD", "")

TOPICS = ["netops.syslog", "netops.flows", "netops.metrics", "netops.probes", "netops.snmptrap", "netops.cloud", "netops.app.identities.v1", "netops.controller_events", "netops.app.edge", "netops.verification"]

# #81 P3B runtime source — a file-based cloud-log tailer (dev/demo + on-host log
# drops). Reads *.alb / *.vpc files from CLOUD_LOGS_DIR, parses them with the P3B
# parsers, and feeds the SAME cloud lane as the bus (handle_cloud). Default-CLOSED:
# disabled unless BOTH a dir AND an explicit tenant are set (cloud logs carry no
# tenant — it is assigned at the source, never guessed). The production source is an
# S3/Kinesis poller that produces to netops.cloud; this is the offline-safe sibling.
CLOUD_LOGS_DIR = os.environ.get("CLOUD_LOGS_DIR", "")
CLOUD_LOGS_TENANT = os.environ.get("CLOUD_LOGS_TENANT", "")
CLOUD_LOGS_REFRESH_S = float(os.environ.get("CLOUD_LOGS_REFRESH_S", "30"))
# Bound for the peer-pair volume rollup (cloud-platform-backlog #9): at most this
# many (src,dst) ACCEPT pairs per scan cycle (largest bytes win). Shared knob name
# across the AWS/Azure/GCP flow lanes.
CLOUD_FLOW_PAIR_TOP_K = int(os.environ.get("CLOUD_FLOW_PAIR_TOP_K", "20"))
_cloud_log_offsets: dict[str, int] = {}  # path → bytes consumed (tail-style; in-memory)

# Cloud inventory topology snapshots (deployment/docker/cloud-fixtures/*-topology.json)
# mounted read-only into the correlation container. Feeds the path-causality P1
# INVENTORY discovery source (inventory_edges_from_topology) so a cloud incident gets a
# discovered SRC→DST path WITHOUT a traceroute (cloud hides hops). Default-CLOSED and
# tenant-gated exactly like the cloud-log tailer: a topology fixture carries no tenant,
# so its edges are stamped with CLOUD_LOGS_TENANT and contribute to NO other tenant's
# path (§3a). Off unless a dir is set AND CLOUD_LOGS_TENANT names the owning tenant.
CLOUD_TOPOLOGY_DIR = os.environ.get("CLOUD_TOPOLOGY_DIR", "")
# Runtime layer (static-fixture/runtime split): the live poller's snapshots
# land under gitignored data/; a runtime file SHADOWS the tracked fixture of
# the same name — live data wins, fresh installs fall back to fixtures.
CLOUD_TOPOLOGY_RUNTIME_DIR = os.environ.get("CLOUD_TOPOLOGY_RUNTIME_DIR", "")
_cloud_topo_cache: dict[str, dict] = {}          # filename → parsed topology dict
_cloud_topo_mtimes: dict[str, float] = {}        # filename → last-seen mtime

# Device→tenant map exported by the Go API (#20 multi-tenant telemetry). We stamp
# tenant_id onto each finding so it carries the same tenant discriminator as the
# flows/logs the Vector aggregator tags. The file is re-read when its mtime
# changes; an absent file or unmatched device yields "" (global/platform).
TENANT_ENRICHMENT_FILE = os.environ.get("TENANT_ENRICHMENT_FILE", "/data/enrichment/device_tenant.csv")
_tenant_map: Dict[str, str] = {}
_tenant_mtime: float = -1.0


def canon_tenant(t: str) -> str:
    """Canonical spelling of the platform-global tenant (#113 slice 3 root cause).

    The platform has TWO historical spellings of the same principal: "" (this
    engine's old convention) and "global" (the Go side's canonicalCorrTenant,
    the path-observation exporter, the ClickHouse row policies). The mixed
    spelling split corr objects across two tenants AND broke every per-tenant
    join — most visibly path-attribution discovery, where tenant-"" incidents
    could never match the "global"-stamped path observations, so NO live object
    ever got a causality path. One spelling everywhere: "global". Never
    collapses two real tenant ids (opaque t_… ids pass through untouched)."""
    return "global" if t in ("", "global") else t


def tenant_for(device: str) -> str:
    """Resolve a device name/id to its canonical tenant id ("global" = the
    platform-global tenant — see canon_tenant). Cheap: re-reads the CSV only
    when its mtime changes."""
    global _tenant_map, _tenant_mtime
    if not device:
        return canon_tenant("")
    try:
        mt = os.path.getmtime(TENANT_ENRICHMENT_FILE)
    except OSError:
        return canon_tenant(_tenant_map.get(device, ""))
    if mt != _tenant_mtime:
        _tenant_mtime = mt  # retry on the next mtime change (writer refreshes every 60s)
        fresh: Dict[str, str] = {}
        try:
            with open(TENANT_ENRICHMENT_FILE, newline="") as f:
                reader = csv.reader(f)
                next(reader, None)  # header: identity,tenant_id
                for row in reader:
                    if len(row) >= 2 and row[0]:
                        fresh[row[0]] = row[1]
            _tenant_map = fresh
        except OSError as exc:
            # An unreadable map means every signal falls back to untagged
            # (platform-only). Fail-closed but NOT silent — this exact failure
            # (0600 perms across uids) once disabled tenancy stamping unnoticed.
            log.warning("tenant enrichment file unreadable, tenant map stale/empty: %s", exc)
    return canon_tenant(_tenant_map.get(device, ""))

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


# Legacy z-score series, bounded + LRU. Unbounded before: keyed by
# (device, metric) with no eviction, so cardinality churn (ephemeral cloud
# resource ids arriving as `device`) grew it until the container hit its memory
# limit. Dropping the least-recently-scored series only costs it its warm-up.
SERIES: "OrderedDict[tuple[str, str], Series]" = OrderedDict()
SERIES_MAX = int(os.environ.get("CORR_MAX_SERIES", "200000"))

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
METRICS_DROPPED = 0            # rejected — the SUM of the three causes below
# One "dropped" number cannot be acted on: a device whose clock is an hour off
# loses 100% of its telemetry and looks exactly like a producer emitting rows
# with no value. The cause has to be in the counter, not only in a log line.
METRICS_DROPPED_NO_VALUE = 0     # no metric name / no numeric value
METRICS_DROPPED_NO_IDENTITY = 0  # no canonical entity (device/if/peer missing)
METRICS_DROPPED_STALE_TS = 0     # event timestamp outside the skew/age window
# The syslog lane is TOPICS[0] and the source of link_down / BGP-state / optics
# evidence — the highest-value RCA evidence class — and had NO intake counter at
# all, so a broken Vector syslog route was indistinguishable from a quiet night.
SYSLOG_RECEIVED = 0            # consumed from netops.syslog
SYSLOG_SIGNALS = 0             # control-plane / port / clock-skew signals emitted
DEVICE_TELEMETRY_SIGNALS = 0   # device_telemetry signals written to corr_signals
TRAPS_RECEIVED = 0             # consumed from netops.snmptrap (Commit 3)
TRAPS_NORMALIZED = 0           # classified into a control_plane signal
TRAPS_RECANON = 0              # C8: re-attributed to a device via the C7.1 EntityResolver
TRAPS_DROPPED = 0              # unclassified — kept searchable, no RCA signal
CLOUD_RECEIVED = 0             # consumed from netops.cloud (#81 P3G ingestion lane)
CLOUD_SIGNALS = 0             # source=cloud signals written to corr_signals + buffered
CLOUD_DROPPED = 0             # dropped: no tenant (default-closed) / malformed (dead-letter)
APP_ID_RECEIVED = 0           # consumed from netops.app.identities.v1 (#81 P5 fusion lane)
APP_ID_SIGNALS = 0            # source=app_identity enrichment signals written + buffered
CONTROLLER_EVENTS_RECEIVED = 0  # consumed from netops.controller_events (#95 NMS lane)
CONTROLLER_EVENTS_SIGNALS = 0   # source=controller signals written to corr_signals + buffered
CONTROLLER_EVENTS_DROPPED = 0   # dropped: no tenant/kind identity (default-closed)
VERIFICATION_RECEIVED = 0       # consumed from netops.verification (RCA spec item 8 lane)
VERIFICATION_SIGNALS = 0        # source=verification signals written to corr_signals + buffered
VERIFICATION_DROPPED = 0        # dropped: no tenant/device identity or skipped (default-closed)
APP_ID_DROPPED = 0            # dropped: no tenant (default-closed) / malformed (dead-letter)
PROBES_RECEIVED = 0           # consumed from netops.probes (the 24/7 heartbeat lane — R6 flatline alert)
APP_EDGE_RECEIVED = 0         # consumed from netops.app.edge (#98 P5 LB/proxy/ingress lane)
APP_EDGE_SIGNALS = 0          # canonical app-edge signals written + buffered
APP_EDGE_DROPPED = 0          # dropped: no tenant (default-closed) / unclassifiable
CLOCK_SKEW_SIGNALS = 0        # clock_skew meta-findings written (S5 — never buffered)

# Clock-skew finding cooldown (log-time standard S5): one clock_skew signal per
# (tenant, entity) per window — a device with a wrong clock logs continuously,
# and the finding must not become a firehose. Bounded map (see _clock_skew_due).
CLOCK_SKEW_COOLDOWN_S = float(os.environ.get("CLOCK_SKEW_COOLDOWN_S", "900"))
_CLOCK_SKEW_LAST: Dict[tuple, float] = {}
_CLOCK_SKEW_LAST_CAP = 4096


def _clock_skew_due(tenant: str, entity_id: str) -> bool:
    """True when no clock_skew signal was emitted for (tenant, entity) within
    the cooldown. Bounded: at cap, the oldest entries are dropped (worst case a
    repeat finding — never unbounded growth, §9 bounded queues)."""
    now = time.monotonic()
    key = (tenant, entity_id)
    last = _CLOCK_SKEW_LAST.get(key)
    if last is not None and (now - last) < CLOCK_SKEW_COOLDOWN_S:
        return False
    if len(_CLOCK_SKEW_LAST) >= _CLOCK_SKEW_LAST_CAP:
        for old_key, _ in sorted(_CLOCK_SKEW_LAST.items(), key=lambda kv: kv[1])[:_CLOCK_SKEW_LAST_CAP // 4]:
            _CLOCK_SKEW_LAST.pop(old_key, None)
    _CLOCK_SKEW_LAST[key] = now
    return True

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
# #100 write-side damping: a persisting incident whose window merely refreshes
# (new instances of the SAME evidence) re-persisted a full snapshot + archive
# slice every cycle — 2 versions/min/object for as long as a storm lasted. A new
# version is now written only when the snapshot's material_hash moves (evidence
# kinds / entities / verdict / structure) or this heartbeat elapses (bounds how
# stale signal_count/window_end may look while an incident persists unchanged).
# 0 disables damping (legacy: persist on every content_hash change).
CORR_VERSION_HEARTBEAT_S = float(os.environ.get("CORR_VERSION_HEARTBEAT_S", "900"))
VERSIONS_PERSISTED = 0   # object versions written to ClickHouse (monotonic)
VERSIONS_DAMPED = 0      # persists suppressed by the material-hash gate (monotonic)
# #101: corr_current is the HOT-read source of truth (Command Center serves
# from it), so a lost projection dual-write means a STALE incident list — that
# must be alertable, not WARN-only. Monotonic; exposed on /metrics + /healthz,
# alerted by CorrCurrentProjectionFailing (src/config/rules.yaml), repaired by
# the Go corr_current reconciler.
PROJECTION_WRITE_FAILURES = 0

# --- #101 chaos/storm fixtures -------------------------------------------
# CORR_CHAOS_FIXTURES names INTENTIONAL storm sources: "name=match[,name=match]"
# e.g. "lab_probe_storm_fixture_120=192.0.2.120". A persisted object whose
# affected entities contain a match is tagged with the fixture name in
# corr_current.chaos_fixture: Command Center badges it, the ticketing sweeper
# skips it, and NOC dashboards can tell "known chaos" from a real incident —
# while the storm still exercises damping + bounded IO end to end (that is the
# fixture's job).


def _parse_chaos_fixtures(raw: str) -> dict[str, str]:
    """'name=match,...' → {match_substring: fixture_name}. Malformed pairs are
    dropped loudly (observable, §10) — a silent typo would untag a storm."""
    out: dict[str, str] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair:
            continue
        name, sep, match = pair.partition("=")
        if not sep or not name.strip() or not match.strip():
            log.warning("CORR_CHAOS_FIXTURES: ignoring malformed pair %r", pair)
            continue
        out[match.strip()] = name.strip()
    return out


CHAOS_FIXTURES = _parse_chaos_fixtures(os.environ.get("CORR_CHAOS_FIXTURES", ""))


def _chaos_fixture_for(snap: "ObjectSnapshot") -> str:
    """Fixture name when any affected entity matches a registered chaos source
    ('' = real incident). Substring match: probe entities carry the target in
    path/entity ids (e.g. 'path:prober->192.0.2.120')."""
    if not CHAOS_FIXTURES:
        return ""
    for entities in snap.affected().values():
        for ent in entities:
            for match, name in CHAOS_FIXTURES.items():
                if match in ent:
                    return name
    return ""


# --- #101 per-tenant write-amplification accounting ------------------------
# Bounded-cardinality storm attribution: per-tenant raw/persisted/damped counts
# accumulate in-process and flush every CORR_WA_FLUSH_S seconds as ONE row per
# (tenant, window) into netops.corr_tenant_write_amp (30-day TTL). Prometheus
# exposure is capped at the top-K noisiest tenants of the LAST window — never
# one series per tenant (metric-cardinality rule; the full per-tenant truth
# lives in the rollup table, see docs/runbooks/correlation-storm.md).
CORR_WA_FLUSH_S = float(os.environ.get("CORR_WA_FLUSH_S", "300"))
CORR_WA_TOPK = int(os.environ.get("CORR_WA_TOPK", "5"))
_WA_ENTITY_CAP = 1000  # bounded per-tenant entity Counter under a storm (§9)
TENANT_WA: Dict[str, dict] = {}   # tenant -> raw/persisted/damped + kind/entity Counters
TENANT_WA_LAST: list[dict] = []   # last flushed window rows, sorted, top-K (for /metrics)
_WA_WINDOW_START: datetime | None = None


def _wa_slot(tenant: str) -> dict:
    slot = TENANT_WA.get(tenant)
    if slot is None:
        slot = {"raw_seen": 0, "persisted": 0, "damped": 0,
                "kinds": Counter(), "entities": Counter()}
        TENANT_WA[tenant] = slot
    return slot


def _wa_note_raw(sig: Signal) -> None:
    slot = _wa_slot(sig.tenant_id)
    slot["raw_seen"] += 1
    slot["kinds"][sig.kind] += 1
    # Entity Counter is capped: past the cap only already-seen entities count,
    # so the top-entity answer stays useful (a storm hammers few entities) and
    # memory stays bounded under an adversarial entity spray.
    if sig.entity_id in slot["entities"] or len(slot["entities"]) < _WA_ENTITY_CAP:
        slot["entities"][sig.entity_id] += 1


def _wa_note_outcome(tenant: str, outcome: str) -> None:
    _wa_slot(tenant)[outcome] += 1


async def _flush_tenant_write_amp(now: datetime) -> None:
    """Flush the accumulated per-tenant window to ClickHouse + refresh the
    top-K exposition. Failure is observable and non-fatal; the window resets
    either way (accounting is best-effort, never backpressure)."""
    global TENANT_WA, TENANT_WA_LAST, _WA_WINDOW_START
    if _WA_WINDOW_START is None:
        _WA_WINDOW_START = now
        return
    elapsed = (now - _WA_WINDOW_START).total_seconds()
    if elapsed < CORR_WA_FLUSH_S:
        return
    window_start, TENANT_WA_ROWS, TENANT_WA = _WA_WINDOW_START, TENANT_WA, {}
    _WA_WINDOW_START = now
    if not TENANT_WA_ROWS:
        TENANT_WA_LAST = []
        return
    ages: Dict[str, float] = {}
    for reg in OPEN_OBJECTS.values():
        t = reg["snapshot"].tenant_id
        age = (now - reg.get("opened_at", now)).total_seconds()
        ages[t] = max(ages.get(t, 0.0), age)
    open_counts: Dict[str, int] = {}
    for reg in OPEN_OBJECTS.values():
        t = reg["snapshot"].tenant_id
        open_counts[t] = open_counts.get(t, 0) + 1
    rows = []
    for tenant, wa in TENANT_WA_ROWS.items():
        total = wa["persisted"] + wa["damped"]
        top_kind = wa["kinds"].most_common(1)
        top_entity = wa["entities"].most_common(1)
        rows.append({
            "tenant_id": tenant,
            # Epoch-ms scaled-integer insert (S4/R1) — never server-TZ dependent.
            "window_start": int(window_start.timestamp()) * 1000 + window_start.microsecond // 1000,
            "window_s": int(elapsed),
            "raw_seen": wa["raw_seen"],
            "persisted": wa["persisted"],
            "damped": wa["damped"],
            "damping_ratio": round(wa["damped"] / total, 4) if total else 0.0,
            "top_signal_kind": top_kind[0][0] if top_kind else "",
            "top_entity": top_entity[0][0] if top_entity else "",
            "open_objects": open_counts.get(tenant, 0),
            "max_incident_age_s": int(ages.get(tenant, 0)),
        })
    if ch is not None:
        try:
            await ch_insert("netops.corr_tenant_write_amp", rows)
        except Exception as exc:  # noqa: BLE001 — observable, non-fatal (§10)
            log.warning("tenant write-amp flush failed (window kept in metrics): %s", exc)
    TENANT_WA_LAST = sorted(
        rows, key=lambda r: (r["persisted"] + r["damped"], r["raw_seen"]), reverse=True,
    )[:CORR_WA_TOPK]
# §8 degradation. Topology is stale when the Go exporter stopped refreshing the
# seam/links files (mtime older than ~2-3 export intervals; export runs every 60s).
CORR_TOPO_STALE_S = float(os.environ.get("CORR_TOPO_STALE_S", "180"))
STORM_BUFFER_FRACTION = float(os.environ.get("CORR_STORM_FRACTION", "0.9"))
# Path-causality RCA P2 (design §2.4): assemble the tenant's typed causal paths from
# the LIVE measured path observations and hand them to run_window for the on-path
# attribution enrichment. Additive + killable; a pure no-op when no path is observed.
CORR_PATH_ATTRIBUTION = os.environ.get("CORR_PATH_ATTRIBUTION", "true").lower() not in ("0", "false", "no", "off")
CORR_MAX_DISCOVERY_PATHS = int(os.environ.get("CORR_MAX_DISCOVERY_PATHS", "32"))
_PATH_ASSEMBLER = PathAssembler()
# C6 passive_flow: aggregate flow volume per exporting interface, flush each engine
# cycle through CUSUM → passive_flow episodes. Flows are a firehose — accumulation is
# O(1) per flow and the flush is bounded by (samplers × interfaces).
FLOW_CORRELATION_ENABLED = os.environ.get("ENABLE_FLOW_CORRELATION", "true") == "true"
_FLOW_AGG: Dict[tuple, dict] = {}   # (tenant, entity_id) -> {bytes, sampler}
# #98 Phase 4 — per-application flow volume, populated ONLY for records with a
# confirming attribution (explicit / appid-fusion / operator prefix map). The
# interface aggregation above is untouched: one flow can feed BOTH groundings.
_FLOW_APP_AGG: Dict[tuple, dict] = {}   # (tenant, app_slug) -> {bytes, sampler, source, confidence}
_APPID_INDEX = AppIdentityIndex()       # tenant-scoped dst_ip → fused app identity
FLOWS_RECEIVED = 0
FLOWS_DROPPED = 0   # records flow_sample() could not attribute/measure (F-42)
PASSIVE_FLOW_SIGNALS = 0
_FLOW_DROP_LOG_LAST = -1e9
FLOW_DROP_LOG_EVERY_S = float(os.environ.get("CORR_FLOW_DROP_LOG_EVERY_S", "60"))


def _log_flow_drop(ev: dict) -> None:
    """One sample line per interval naming the fields that were missing — flows
    are a firehose, so the counter is exact and the LOG is rate-limited."""
    global _FLOW_DROP_LOG_LAST
    now = time.monotonic()
    if (now - _FLOW_DROP_LOG_LAST) < FLOW_DROP_LOG_EVERY_S:
        return
    _FLOW_DROP_LOG_LAST = now
    log.warning("flow record dropped: unparseable/unattributable (dropped_total=%d) fields=%s",
                FLOWS_DROPPED, sorted(ev)[:20])
# C7.3 NetFlow direction: directed per-pair volume, tenant → {(src_dev,dst_dev): bytes}.
# Accumulated CONTINUOUSLY (no reset) — the dominant direction is the structural
# forwarding direction (the causal prior: A normally upstream of B), stable under a
# fault that breaks but doesn't reverse it; a ratio is steady under steady traffic.
# Bounded by communicating device-pairs. Feeds the oracle's NetFlow source each cycle.
# (Rolling/decay window for faster reversal detection = a documented future refinement.)
_FLOW_DIR: Dict[str, Dict[tuple, float]] = {}
FLOW_DIR_MAX_PAIRS = int(os.environ.get("CORR_MAX_FLOW_DIR_PAIRS", "100000"))
FLOW_DIRECTION_DOMINANCE = float(os.environ.get("CORR_FLOW_DOMINANCE", "0.6"))
FLOW_DIRECTION_PAIRS = 0  # observability: distinct directed device-pairs seen
SEAM_ENRICHMENT_FILE = os.environ.get("SEAM_ENRICHMENT_FILE", "/data/enrichment/seams.json")
# L2/L3 adjacency (LLDP/CDP/BGP-LS links) exported by the Go API — the grounding
# input for the §4.2 "L2/L3 adjacent device" rung (G1). Absent file = no adjacency
# (gate falls back to seam/containment, identical to before — honest, never relaxed).
TOPO_LINKS_FILE = os.environ.get("TOPO_LINKS_FILE", "/data/enrichment/topology_links.json")
# Service Path Graph (docs/design/service-path-graph-contract.md §2/§7): the EXPLICIT
# relationship inventory — endpoints (address↔entity bindings with a network context
# and a validity window), immutable path observations with ORDERED hops, application→
# endpoint bindings, NAT sessions and (inferred) cloud routes — exported by the Go API
# the same way seams.json is. This is what replaces token overlap as the basis of edge
# admission (§3). Absent file = empty view: the engine still grounds on identity /
# seam / adjacency, and token overlap still forms a CANDIDATE (never authoritative)
# edge — honest degradation, never a relaxed gate.
PATH_GRAPH_FILE = os.environ.get("PATH_GRAPH_FILE", "/data/enrichment/path_graph.json")
# Cloud service dependency map (Wave 3 #9, cloud_dependency.py): per-service
# end-user→DNS→WAF→LB→firewall→app tier chains + volume-weighted flow edges,
# exported as enrichment JSON ({"services": [...], "flows": [...]}). Built into
# path-graph objects (Endpoints / ServiceBindings / inferred RouteRelations /
# flow-observed PathObservations) and MERGED into the Service Path Graph view the
# grounding gate reads — this is what welds an edge-device fault (LB 5xx / WAF
# block / SG-NACL reject / DNS failure) and the app's cloud_health symptom into
# ONE object so the sig.ent.app.edge-* signatures can NAME the tier. Absent file
# = empty view: no cloud dependency records ⇒ no edges, never fabricated.
CLOUD_DEPENDENCY_FILE = os.environ.get(
    "CLOUD_DEPENDENCY_FILE", "/data/enrichment/cloud_dependency.json")
# corr_edges v2 (typed edges + evidence columns) is a ClickHouse migration owned by the
# backend. Until it lands the typed rows are computed and embedded in the snapshot
# (hypotheses.grounding_context.path_graph) but not written to their own table.
CORR_EDGES_V2 = os.environ.get("CORR_EDGES_V2", "false").lower() == "true"
CORR_PATH_EDGES_TABLE = os.environ.get("CORR_PATH_EDGES_TABLE", "netops.corr_path_edges")
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
# #102: bound from the resource plan (CORR_WINDOW_BUFFER, floor 50k = the
# audited constant) so the window scales with the container's memory budget.
WINDOW_BUFFER: Deque[Signal] = deque(
    maxlen=max(50_000, int(os.environ.get("CORR_WINDOW_BUFFER", "50000"))))
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
_path_graph_cache: PathGraphView = PathGraphView()
_path_graph_mtime: float = -1.0
_cloud_dep_cache: PathGraphView = PathGraphView()
_cloud_dep_mtime: float = -1.0
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
        # File gone: keep serving the last-known adjacency (dropping it would
        # collapse grounding mid-incident) — but this view is now FROZEN, and
        # _topology_stale ages it into staleness so nothing scored under it is
        # declared fresh.
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


def cloud_dependency_inventory() -> PathGraphView:
    """The cloud service dependency view (cloud_dependency.py) built from the
    enrichment export at CLOUD_DEPENDENCY_FILE. mtime-cached like seam_inventory();
    absent file = the empty view (no cloud dependency records ⇒ no edges — the
    builder fails closed and fabricates nothing), unreadable file = the last good
    view (never a silently emptied one mid-incident). Tenancy rides each emitted
    object (build_from_records drops tenant-less records), so run_window's
    for_tenant() scoping applies to these edges exactly as to the Go-exported ones."""
    global _cloud_dep_cache, _cloud_dep_mtime
    try:
        mt = os.path.getmtime(CLOUD_DEPENDENCY_FILE)
    except OSError:
        return _cloud_dep_cache
    if mt != _cloud_dep_mtime:
        _cloud_dep_mtime = mt
        try:
            with open(CLOUD_DEPENDENCY_FILE) as f:
                raw = json.load(f)
            _cloud_dep_cache = build_from_records(raw if isinstance(raw, dict) else {})
        except (OSError, ValueError, KeyError, TypeError) as exc:
            log.warning("cloud dependency map unreadable (%s); keeping previous view", exc)
    return _cloud_dep_cache


def path_graph_inventory() -> PathGraphView:
    """The Service Path Graph view for the grounding gate (contract §2): the
    Go-exported inventory MERGED with the cloud service dependency view
    (cloud_dependency_inventory() above) — one graph, so an app's edge devices
    (DNS/WAF/LB/firewall) ground into the app's object. mtime-cached like
    seam_inventory(); absent/unreadable file = the last good view (never a
    silently emptied one mid-incident). Tenant scoping happens in run_window(),
    which calls PathGraphView.for_tenant() before ANY lookup — a path object with
    no tenant_id is reachable by nobody (fail-closed: unlike seams, there are no
    platform-scoped path relationships)."""
    global _path_graph_cache, _path_graph_mtime
    try:
        mt = os.path.getmtime(PATH_GRAPH_FILE)
    except OSError:
        pass
    else:
        if mt != _path_graph_mtime:
            _path_graph_mtime = mt
            try:
                with open(PATH_GRAPH_FILE) as f:
                    raw = json.load(f)
                _path_graph_cache = PathGraphView.from_dict(raw if isinstance(raw, dict) else {})
            except (OSError, ValueError, KeyError, TypeError) as exc:
                log.warning("path graph unreadable (%s); keeping previous view", exc)
    dep = cloud_dependency_inventory()
    if not (dep.endpoints or dep.observations or dep.service_bindings or dep.routes):
        # No cloud dependency records ⇒ the Go view unchanged (an empty merge must
        # not touch the base view's freshness budget).
        return _path_graph_cache
    return merge_path_views(_path_graph_cache, dep)


def cloud_topology_snapshots() -> dict[str, dict]:
    """The cloud inventory topology snapshots for the INVENTORY discovery source,
    read from CLOUD_TOPOLOGY_DIR (deployment/docker/cloud-fixtures/*-topology.json,
    mounted read-only). mtime-cached per file like the other enrichment loaders; an
    unreadable/absent dir yields the last-good snapshots (never a silently emptied one
    mid-incident). Returns {filename: topology_dict}. Tenancy is applied by the CALLER
    (stamped with CLOUD_LOGS_TENANT) — a fixture carries no tenant of its own."""
    if not CLOUD_TOPOLOGY_DIR and not CLOUD_TOPOLOGY_RUNTIME_DIR:
        return {}
    try:
        # Fixture layer first, then the runtime layer: a live-poller snapshot
        # shadows the tracked fixture of the same basename (runtime split).
        present: dict[str, str] = {}
        for d in (CLOUD_TOPOLOGY_DIR, CLOUD_TOPOLOGY_RUNTIME_DIR):
            if not d:
                continue
            for p in glob.glob(os.path.join(d, "*-topology.json")):
                present[os.path.basename(p)] = p
    except OSError as exc:
        log.warning("cloud topology dir unreadable (%s); keeping previous snapshots", exc)
        return _cloud_topo_cache
    # drop snapshots whose file has disappeared (never serve a stale, removed topology).
    for gone in [n for n in _cloud_topo_cache if n not in present]:
        _cloud_topo_cache.pop(gone, None)
        _cloud_topo_mtimes.pop(gone, None)
    for name, path in present.items():
        try:
            mt = os.path.getmtime(path)
        except OSError:
            continue
        if _cloud_topo_mtimes.get(name) == mt:
            continue
        try:
            with open(path, encoding="utf-8") as f:
                raw = json.load(f)
            if isinstance(raw, dict):
                _cloud_topo_cache[name] = raw
                _cloud_topo_mtimes[name] = mt
        except (OSError, ValueError, TypeError) as exc:
            log.warning("cloud topology %s unreadable (%s); keeping previous", name, exc)
    return _cloud_topo_cache


def _flow_discovery_edges(tenant: str) -> tuple[DiscoveredEdge, ...]:
    """FLOW discovery source (precedence 2): this tenant's directed NetFlow per-pair
    volume (_FLOW_DIR[tenant], the C7.3 lane) → directed DiscoveredEdges via the P1
    adapter. STRICTLY this tenant's own map (never the "" global) — a path that seeds
    attribution must never carry another tenant's / untagged flow (§3a default-closed)."""
    vol = _FLOW_DIR.get(tenant, {})
    pairs = [(a, b) for (a, b), nbytes in vol.items() if nbytes > 0]
    if not pairs:
        return ()
    return flow_edges_from_pairs(tenant, pairs, f"netflow:{tenant}")


def _inventory_discovery_edges(tenant: str) -> tuple[DiscoveredEdge, ...]:
    """INVENTORY discovery source (precedence 3): the cloud topology snapshots →
    inventory edges via the P1 adapter. Default-CLOSED and tenant-gated: contributes
    ONLY for the single CLOUD_LOGS_TENANT that owns the demo cloud data (a fixture has
    no tenant of its own, exactly as the cloud-log tailer stamps it), so no other
    tenant's path can ever include a cloud-inventory edge (§3a)."""
    if not CLOUD_TOPOLOGY_DIR or not CLOUD_LOGS_TENANT or tenant != CLOUD_LOGS_TENANT:
        return ()
    out: list[DiscoveredEdge] = []
    for name, topo in sorted(cloud_topology_snapshots().items()):
        out.extend(inventory_edges_from_topology(tenant, topo, f"cloud-topo:{name}"))
    return tuple(out)


def _dns_heads_from_window(tenant: str, window) -> dict[str, DnsHead]:
    """DNS discovery source: the tenant's cloud_dns_log signals in THIS window → path
    HEADs (the resolved frontend the app depends on). entity_id is the resolved NAME;
    a failed resolution carries no answer, so resolved_address stays empty (honest —
    never a fabricated address). Keyed by resolved_address when known else query_name,
    so a scope whose endpoint is that frontend can attach its head. Tenant-filtered."""
    heads: dict[str, DnsHead] = {}
    for s in window:
        if s.tenant_id != tenant or s.kind != "cloud_dns_log":
            continue
        name = str(s.entity_id or "").strip()
        if not name:
            continue
        attrs = s.attrs if isinstance(s.attrs, dict) else {}
        resolved = str(attrs.get("resolved_address") or attrs.get("answer") or "").strip()
        key = resolved or name
        heads.setdefault(key, DnsHead(
            tenant_id=tenant, query_name=name, resolved_address=resolved,
            evidence_ref=f"dns:{name}"))
    return heads


def _edge_discovery_scopes(edges: tuple[DiscoveredEdge, ...], limit: int
                           ) -> list[tuple[str, str]]:
    """Derive candidate (src→dst) scopes from a directed edge graph: each path SOURCE
    (a node with out-edges but no in-edge) to each path SINK (in-edge, no out-edge).
    This scopes discovery to the AFFECTED src→dst path, never the whole VPC. Bounded by
    `limit`. Falls back to any-out→any-in when the graph is a cycle with no clean end."""
    has_in: set[str] = set()
    has_out: set[str] = set()
    for e in edges:
        a, b = e.upstream.address, e.downstream.address
        if not a or not b or a == b:
            continue
        has_out.add(a)
        has_in.add(b)
    srcs = sorted(has_out - has_in) or sorted(has_out)
    dsts = sorted(has_in - has_out) or sorted(has_in)
    scopes: list[tuple[str, str]] = []
    for s in srcs:
        for d in dsts:
            if s != d:
                scopes.append((s, d))
                if len(scopes) >= limit:
                    return scopes
    return scopes


def _head_for_scope(heads: dict[str, DnsHead], src: str, dst: str) -> "DnsHead | None":
    """Attach a DNS head to a scope ONLY when the name it resolved points at the scope's
    frontend endpoint (dst, else src) — never force a head onto an unrelated path."""
    for key in (dst, src):
        if key and key in heads:
            return heads[key]
    return None


def discovery_paths_for(tenant: str, view: PathGraphView,
                        window: "list | tuple" = ()) -> tuple[AssembledPath, ...]:
    """Build this tenant's P1 typed causal paths for the on-path attribution pass
    (path-causality RCA P2 / step 4), FUSING all four discovery sources so a cloud
    incident gets a discovered SRC→DST path even WITHOUT a traceroute (cloud hides hops):

      * MEASURED  — the LIVE path observations the engine already loads (traceroute /
        STAMP / transaction runs, exported by the Go API into the Service Path Graph)
        via measured_run_from_observation. Precedence 1 — the spine when present.
      * FLOW      — this tenant's directed NetFlow per-pair volume (_FLOW_DIR) via
        flow_edges_from_pairs. Precedence 2.
      * INVENTORY — the cloud topology snapshots (cloud-fixtures/*-topology.json) via
        inventory_edges_from_topology. Precedence 3 — the cloud-without-traceroute path.
      * DNS       — this window's cloud_dns_log resolutions as the path HEAD (the
        resolved frontend the app depends on).

    All four fold into the SAME DiscoverySources; P1's precedence (measured > flow >
    inventory > route) fuses them. Scoped per (src→dst): measured endpoints ∪ the edge
    graph's source→sink endpoints, so a path is the AFFECTED path, not the whole VPC.

    Tenant-scoped (§3a): every feed is filtered/stamped to THIS tenant before assembly
    (PathAssembler also drops any cross-tenant run/edge/head structurally). Additive +
    honest: a feed with no data contributes nothing; when NONE of the four yield
    anything the result is () — byte-identical to the pre-fusion no-op. Bounded
    (CORR_MAX_DISCOVERY_PATHS scopes; assembler caps hops) and exception-safe — EACH
    feed degrades to empty on failure and the whole build returns () on any error, so
    attribution simply doesn't fire and the engine cycle is never broken (§9/§10)."""
    if not CORR_PATH_ATTRIBUTION:
        return ()
    try:
        # -- feed 1: MEASURED (the live source; groups by observed endpoints) --------
        measured_groups: Dict[tuple[str, str], list] = {}
        try:
            for o in (o for o in view.observations if canon_tenant(o.tenant_id) == canon_tenant(tenant) and o.hops):
                run = measured_run_from_observation(o)
                responding = [h.address for h in run.hops if h.responding]
                if len(responding) < 2:
                    continue  # a single-endpoint run is not a path — nothing to walk
                measured_groups.setdefault((responding[0], responding[-1]), []).append(run)
        except Exception as exc:  # noqa: BLE001 — one feed failing degrades to empty
            log.warning("path-discovery measured feed failed tenant=%s: %s", tenant, exc)
            measured_groups = {}

        # -- feeds 2-4: FLOW / INVENTORY / DNS (each independently exception-safe) ----
        try:
            flow_edges = _flow_discovery_edges(tenant)
        except Exception as exc:  # noqa: BLE001
            log.warning("path-discovery flow feed failed tenant=%s: %s", tenant, exc)
            flow_edges = ()
        try:
            inv_edges = _inventory_discovery_edges(tenant)
        except Exception as exc:  # noqa: BLE001
            log.warning("path-discovery inventory feed failed tenant=%s: %s", tenant, exc)
            inv_edges = ()
        try:
            dns_heads = _dns_heads_from_window(tenant, window)
        except Exception as exc:  # noqa: BLE001
            log.warning("path-discovery dns feed failed tenant=%s: %s", tenant, exc)
            dns_heads = {}

        # Inventory FIRST so its authoritative device role hints (to_kind: lb/nva/…)
        # seed a node's identity before a hint-less flow edge for the same address does
        # (the edge-spine takes the first HopNode seen per address). Source PRECEDENCE
        # for ordering/direction is by rank inside the assembler, unaffected by list order.
        edges = tuple(inv_edges) + tuple(flow_edges)

        # NONE of the four sources yielded anything → () (byte-identical no-op).
        if not measured_groups and not edges and not dns_heads:
            return ()

        # -- SCOPES: measured endpoints ∪ edge-graph source→sink endpoints -----------
        scopes: list[tuple[str, str]] = list(measured_groups.keys())
        if edges:
            for scope in _edge_discovery_scopes(edges, CORR_MAX_DISCOVERY_PATHS):
                if scope not in measured_groups:
                    scopes.append(scope)
        scopes = sorted(dict.fromkeys(scopes))[:CORR_MAX_DISCOVERY_PATHS]

        paths: list[AssembledPath] = []
        for (src, dst) in scopes:
            runs = tuple(measured_groups.get((src, dst), ()))
            bundle = DiscoverySources(
                measured=runs, edges=edges,
                dns_head=_head_for_scope(dns_heads, src, dst))
            paths.append(_PATH_ASSEMBLER.assemble(tenant, src, dst, bundle))
        return tuple(paths)
    except Exception as exc:  # noqa: BLE001 — enrichment must never break the cycle
        log.warning("path-attribution discovery build failed tenant=%s: %s", tenant, exc)
        return ()


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
    # Canonical global-tenant spelling at the SINGLE live window-entry chokepoint
    # (#113): ""-stamped signals become "global" so objects, write-amp buckets and
    # every per-tenant join (path discovery above all) agree with the Go side and
    # the path-observation exporter. Replay is untouched — it reconstructs archived
    # signals directly into run_window, never through here, so per-object replay
    # of pre-fix objects stays bit-perfect (#101 contract).
    if sig.tenant_id != canon_tenant(sig.tenant_id):
        sig = dc_replace(sig, tenant_id=canon_tenant(sig.tenant_id))
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
    # #101 write-amp accounting: raw lane pressure per tenant (post-dedup, so a
    # redelivered signal never double-counts).
    _wa_note_raw(sig)


def _prune_buffer(now: datetime) -> None:
    horizon = now.timestamp() - ENGINE_CFG.window_s
    while WINDOW_BUFFER and WINDOW_BUFFER[0].ts.timestamp() < horizon:
        _BUFFERED_IDS.discard(str(WINDOW_BUFFER[0].signal_id))
        WINDOW_BUFFER.popleft()


# Column subset of to_object_row that feeds the HOT current-state projection
# (netops.corr_current, #100 hardening). Deliberately NO wide blobs — the
# projection exists so Command Center list reads never touch hypotheses/
# layer_coverage/app_impact except keyed by a picked page.
CORR_CURRENT_FIELDS = (
    "tenant_id", "correlation_id", "version", "state", "window_start",
    "window_end", "top_hypothesis", "top_confidence", "verdict_tier",
    "evidence_missing", "affected", "signal_count", "node_count",
    "engine_version", "catalog_version", "merged_into",
)


def _current_badges(hypotheses_blob: str) -> dict:
    """Narrow triage-badge columns for corr_current, derived from the SAME
    hypotheses JSON the history row persists — semantically identical to the
    read-time JSONExtracts they replace, computed once per (damped) persist so
    the hot list path never reads the ~5.7KB blob column (#100 completion:
    that read alone was ~1.3 GiB of blob granules per page at storm size)."""
    try:
        ranked = json.loads(hypotheses_blob).get("ranking", {}).get("hypotheses") or [{}]
        verdict = ranked[0].get("verdict") or {}
    except (ValueError, AttributeError, IndexError, TypeError):
        verdict = {}
    return {
        "owner": str(verdict.get("owner") or ""),
        "plane_count": len(verdict.get("modality_coverage") or []),
        "debug_excluded": 1 if verdict.get("excluded_debug_probes") else 0,
        "low_authority": 1 if verdict.get("low_authority_probe_scopes") else 0,
    }


async def _persist_snapshot(snap: ObjectSnapshot, version: int, state: str,
                            window: list[Signal], merged_into: str = "") -> None:
    assert ch is not None
    obj_row = snap.to_object_row(version, state, merged_into)
    await ch_insert("netops.corr_objects", [obj_row],
                    corr_id=snap.correlation_id, version=version, tenant=snap.tenant_id)
    # Dual-write the narrow current-state row (app-level, NOT an MV — row
    # policies break MV inserts). ReplacingMergeTree(created_at) keeps the
    # latest write per (tenant, correlation_id). Projection failure must never
    # block the history write (truth) — but it MUST be counted and alertable
    # (#101): corr_current is what Command Center reads, so a lost dual-write
    # is a stale incident list. It self-heals on the next material persist and
    # is force-repaired by the Go corr_current reconciler.
    global PROJECTION_WRITE_FAILURES
    failure: tuple[str, bool] | None = None  # (error, retryable)
    try:
        current_row = {k: obj_row[k] for k in CORR_CURRENT_FIELDS if k in obj_row}
        current_row.update(_current_badges(obj_row.get("hypotheses", "")))
        current_row["chaos_fixture"] = _chaos_fixture_for(snap)
        if not await ch_insert("netops.corr_current", [current_row]):
            failure = ("clickhouse rejected insert (see preceding error log)", True)
    except Exception as exc:  # noqa: BLE001 — observable, non-fatal (§10)
        # Network/timeout errors are retryable; anything else (serialization,
        # schema shape) will not fix itself by retrying.
        retryable = isinstance(exc, (httpx.TransportError, httpx.TimeoutException))
        failure = (f"{type(exc).__name__}: {exc}", retryable)
    if failure is not None:
        PROJECTION_WRITE_FAILURES += 1
        err, retryable = failure
        log.warning(
            "corr_current projection write FAILED tenant_id=%s corr_id=%s "
            "version_id=%d material_hash=%s retryable=%s error=%s",
            snap.tenant_id, snap.correlation_id, version,
            snap.material_hash(), retryable, err,
        )
    edge_rows = snap.to_edge_rows(version)
    if edge_rows:
        await ch_insert("netops.corr_edges", edge_rows,
                        corr_id=snap.correlation_id, version=version)
        # Contract §5: the typed edge + its evidence block (edge_type, method, rank,
        # evidence_class, evidence_ref, observation_method, confidence, observed_at,
        # data_class). corr_edges' frozen Enum8 grounding_kind cannot express these and
        # grounding_ref is NOT overloaded to smuggle them — they go to their own table
        # once the backend migration lands (CORR_EDGES_V2). Until then they are still
        # emitted: embedded in the snapshot's grounding context (replay-safe) and served
        # from there.
        if CORR_EDGES_V2:
            await ch_insert(CORR_PATH_EDGES_TABLE, snap.to_typed_edge_rows(version))
    ev_rows = snap.to_evidence_rows(version)
    if ev_rows:
        await ch_insert("netops.corr_evidence", ev_rows,
                        corr_id=snap.correlation_id, version=version)
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
        await ch_insert("netops.corr_signals_archive", archive_rows,
                        corr_id=snap.correlation_id, version=version, row_count=len(archive_rows))
    log.info("corr-object %s v%d %s: top=%s tier=%s nodes=%d edges=%d",
             snap.correlation_id[:8], version, state, snap.ranking.top_hypothesis,
             snap.ranking.verdict_tier.value, len(snap.nodes), len(snap.edges))


# Wall-clock of the last time ANY topology enrichment file was readable. A
# DELETED file used to age into freshness instead of staleness: getmtime raised,
# the loaders returned their cache "silently forever", newest stayed -1 and this
# function returned False = NOT stale. So the exporter dying (or the enrichment
# volume unmounting) left the engine grounding causal edges on a frozen topology
# while stamping topology_stale=false on every snapshot it emitted — the one
# state where the declaration is a lie rather than a caveat.
_TOPO_LAST_SEEN_WALL: float | None = None
_TOPO_ABSENT_LOG_LAST = -1e9


def _topology_stale(now: datetime) -> bool:
    """§8: the topology/seam view is STALE when the Go exporter has stopped
    refreshing it (newest of seams.json / topology_links.json older than
    CORR_TOPO_STALE_S). Grounding then resolves against the last-known view with
    w_topo capped, and every snapshot scored under it is declared.

    A file that DISAPPEARS ages exactly like a frozen one: staleness is measured
    from the last moment the view was known-good, so a deleted export can never
    read as fresh. Files that were never present get the same single staleness
    grace period from process start — after it, the cached (empty) view the
    loaders keep serving is honestly declared stale.
    """
    global _TOPO_LAST_SEEN_WALL
    newest = -1.0
    for path in (SEAM_ENRICHMENT_FILE, TOPO_LINKS_FILE):
        try:
            newest = max(newest, os.path.getmtime(path))
        except OSError:
            continue
    wall = now.timestamp()
    if newest >= 0:
        _TOPO_LAST_SEEN_WALL = wall
        return (wall - newest) > CORR_TOPO_STALE_S
    if _TOPO_LAST_SEEN_WALL is None:
        _TOPO_LAST_SEEN_WALL = wall
    stale = (wall - _TOPO_LAST_SEEN_WALL) > CORR_TOPO_STALE_S
    if stale:
        global _TOPO_ABSENT_LOG_LAST
        mono = time.monotonic()
        if (mono - _TOPO_ABSENT_LOG_LAST) >= CORR_TOPO_STALE_S:
            _TOPO_ABSENT_LOG_LAST = mono
            log.warning("topology enrichment files ABSENT for %.0fs (%s, %s) — "
                        "grounding on the last-known view, declared stale",
                        wall - _TOPO_LAST_SEEN_WALL, SEAM_ENRICHMENT_FILE, TOPO_LINKS_FILE)
    return stale


async def engine_cycle() -> None:
    """One evaluation: prune window, partition by tenant, run the pure core,
    persist version increments, close quiesced objects."""
    global LAST_GAP_HINTS, VERSIONS_PERSISTED, VERSIONS_DAMPED
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

    gap_hints = 0
    adj_by_tenant = topology_links_by_tenant()  # L2/L3 links for the adjacency rung (G1)
    evaluated: list[tuple[str, list[Signal], list[ObjectSnapshot]]] = []
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
        pgv = path_graph_inventory()
        # Path-causality RCA P2: the tenant's typed causal paths for the on-path
        # attribution enrichment, fusing measured + flow + inventory + DNS discovery
        # (window carries this tenant's cloud_dns_log heads). Empty ⇒ no-op, objects
        # byte-identical to pre-P2.
        discovery = discovery_paths_for(tenant, pgv, window)
        try:
            snapshots = run_window(window, CATALOG, seams, ENGINE_CFG, adjacency=adjacency,
                                   topology_stale=topo_stale, storm_mode=storm, directed=directed,
                                   paths=pgv, discovery=discovery)
        except ValueError as exc:
            log.error("engine window rejected: %s", exc)
            continue
        evaluated.append((tenant, window, snapshots))

    # #111 churn fix — know every id that MATERIALIZED this cycle before deciding
    # whether an unknown id is a genuinely new incident or an ongoing one re-keyed
    # by windowing (correlation_id derives from the earliest node + onset, so when
    # an incident's first signal ages out of the sliding window the same condition
    # returns under a new id every sweep). Pre-fix that minted a new object and
    # tombstoned the old one into it (create-then-merge: ~13/min of state='merged'
    # tombstones, ~20M archive rows/day on one sustained signature). Now the new
    # snapshot ADOPTS the open object's identity (find_continuation: same
    # entity-overlap + window-overlap criterion as find_merges, tenant-guarded)
    # and versions it — one object with version bumps, no tombstone. Only an open
    # object whose own id did NOT materialize may be adopted, and at most once per
    # cycle — two live components can never collapse into one identity.
    materialized = {s.correlation_id for _, _, snaps in evaluated for s in snaps}
    seen_this_cycle: set[str] = set()
    for tenant, window, snapshots in evaluated:
        for snap in snapshots:
            gap_hints += snap.gap_hints
            reg = OPEN_OBJECTS.get(snap.correlation_id)
            if reg is None:
                cont = find_continuation(snap, [
                    r["snapshot"] for c, r in OPEN_OBJECTS.items()
                    if c not in materialized and c not in seen_this_cycle
                ])
                if cont:
                    snap = dc_replace(snap, correlation_id=cont)
                    reg = OPEN_OBJECTS[cont]
                    log.info("corr-object %s continued under re-keyed window (identity adopted, no tombstone)",
                             cont[:8])
            seen_this_cycle.add(snap.correlation_id)
            chash = snap.content_hash()
            if reg is None:
                OPEN_OBJECTS[snap.correlation_id] = {
                    "version": 1, "hash": chash, "material": snap.material_hash(),
                    "last_seen": now, "last_persist": now, "snapshot": snap,
                    "opened_at": now,  # #101: max_incident_age in the write-amp rollup
                }
                await _persist_snapshot(snap, 1, "open", window)
                VERSIONS_PERSISTED += 1
                _wa_note_outcome(tenant, "persisted")
            elif reg["hash"] != chash:
                # #100 damping: content moved (it always does while an incident
                # persists — instance ids rotate through the window), but only a
                # MATERIAL move, an elapsed heartbeat, or damping-off warrants a
                # persisted version. The in-memory registry still tracks the
                # freshest snapshot so merge/close always persist current truth.
                mhash = snap.material_hash()
                elapsed = (now - reg.get("last_persist", now)).total_seconds()
                if (mhash != reg.get("material") or CORR_VERSION_HEARTBEAT_S <= 0
                        or elapsed >= CORR_VERSION_HEARTBEAT_S):
                    reg["version"] += 1
                    reg["last_persist"] = now
                    await _persist_snapshot(snap, reg["version"], "open", window)
                    VERSIONS_PERSISTED += 1
                    _wa_note_outcome(tenant, "persisted")
                else:
                    VERSIONS_DAMPED += 1
                    _wa_note_outcome(tenant, "damped")
                reg["hash"] = chash
                reg["material"] = mhash
                reg["last_seen"] = now
                reg["snapshot"] = snap
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
        VERSIONS_PERSISTED += 1
        _wa_note_outcome(reg["snapshot"].tenant_id, "persisted")
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
            VERSIONS_PERSISTED += 1
            _wa_note_outcome(reg["snapshot"].tenant_id, "persisted")
            await _persist_snapshot(reg["snapshot"], reg["version"], "closed", [])
            del OPEN_OBJECTS[cid]
    LAST_GAP_HINTS = gap_hints
    # #101: flush the per-tenant write-amplification window (no-op until
    # CORR_WA_FLUSH_S has elapsed; resets even when the insert fails).
    await _flush_tenant_write_amp(now)


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
    extra_attrs: dict | None = None,
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
            extra_attrs=extra_attrs,
        )
        row = sig.to_ch_row()
    except DeadLetter as exc:
        DEADLETTER_COUNT += 1
        keep_deadletter_payload("provenance", ev, exc)
        log.warning("dead-letter (provenance): %s", exc)
        return False
    await ch_insert("netops.corr_signals", [row], lane="metrics", kind=row.get("kind", ""))
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
    s = SERIES.get(key)
    if s is None:
        s = Series()
        SERIES[key] = s
        while len(SERIES) > SERIES_MAX:
            SERIES.popitem(last=False)
    else:
        SERIES.move_to_end(key)
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

    async def insert(self, table: str, rows: Iterable[dict]) -> bool:
        """True on success. An HTTP-level failure is logged AND reported to the
        caller (#101: the corr_current projection write must be able to count
        its own failures — before this, a 4xx/5xx insert was log-only and
        indistinguishable from success at the call site)."""
        body = "\n".join(json.dumps(r) for r in rows)
        if not body:
            return True
        params = {"query": f"INSERT INTO {table} FORMAT JSONEachRow"}
        r = await self.client.post(
            self.base, params=params, content=body, auth=self.auth,
            headers={"Content-Type": "application/x-ndjson"},
        )
        if r.status_code >= 300:
            log.error("clickhouse insert failed: %s %s", r.status_code, r.text)
            return False
        return True

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

# Per-table count of ClickHouse inserts that did NOT land. `CH.insert` returns
# False on a 4xx/5xx, and 19 of the 20 call sites used to discard that boolean:
# a schema drift affecting only netops.corr_signals_archive would keep live RCA
# looking perfect (the signal still enters WINDOW_BUFFER, which happens AFTER
# the insert) while the replay source silently grew holes — so "replay this
# incident" months later answers differently than the incident did at the time,
# with no counter having moved. Every write now goes through ch_insert(), which
# cannot forget to check.
CH_INSERT_FAILURES: Dict[str, int] = {}
_CH_FAIL_LOG_LAST: Dict[str, float] = {}
CH_FAIL_LOG_EVERY_S = float(os.environ.get("CORR_CH_FAIL_LOG_EVERY_S", "30"))


def _note_ch_failure(table: str, reason: str, ctx: dict) -> None:
    """Count + log one lost ClickHouse write. Logging is rate-limited per table
    (a ClickHouse outage fails every write; 10k identical lines bury the one
    that explains it) — the COUNTER is always exact."""
    CH_INSERT_FAILURES[table] = CH_INSERT_FAILURES.get(table, 0) + 1
    now = time.monotonic()
    if (now - _CH_FAIL_LOG_LAST.get(table, -1e9)) < CH_FAIL_LOG_EVERY_S:
        return
    _CH_FAIL_LOG_LAST[table] = now
    detail = " ".join(f"{k}={v}" for k, v in ctx.items() if v not in (None, ""))
    log.warning("clickhouse write LOST table=%s reason=%s lost_total=%d %s",
                table, reason, CH_INSERT_FAILURES[table], detail)


async def ch_insert(table: str, rows, **ctx) -> bool:
    """`ch.insert` with the failure actually surfaced (log + counter).

    Exceptions are counted and RE-RAISED, deliberately: a transport failure is
    the caller's problem (the consumer quarantines the event so the payload
    survives), while a rejected insert is reported here and returned as False.
    """
    assert ch is not None
    try:
        ok = await ch.insert(table, rows)
    except Exception as exc:  # noqa: BLE001 — counted, then re-raised
        _note_ch_failure(table, type(exc).__name__, ctx)
        raise
    # `is False` exactly: CH.insert's contract is a bool, and a test double that
    # returns None must not be miscounted as a lost write.
    if ok is False:
        _note_ch_failure(table, "rejected", ctx)
    return ok


# ---------------------------------------------------------------------------
# Kafka consumer loop.
# ---------------------------------------------------------------------------


async def _scan_cloud_logs() -> int:
    """Tail every *.alb/*.vpc file in CLOUD_LOGS_DIR from its last byte offset,
    parse new lines, stamp the configured tenant, and feed the cloud lane. Returns
    the number of signals fed. Offset-tracked so a re-scan never re-ingests a line;
    a truncated/rotated file (size < offset) restarts from 0."""
    fed = 0
    for path in sorted(glob.glob(os.path.join(CLOUD_LOGS_DIR, "*"))):
        if not path.endswith((".alb", ".vpc", ".waf", ".dns")):
            continue
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        off = _cloud_log_offsets.get(path, 0)
        if size < off:
            off = 0
        if size == off:
            continue
        try:
            with open(path) as f:
                f.seek(off)
                data = f.read()
                _cloud_log_offsets[path] = f.tell()
        except OSError as exc:
            log.warning("cloud-log read failed %s: %s", path, exc)
            continue
        fname = os.path.basename(path)
        accept_recs: list[dict] = []
        waf_recs: list[dict] = []
        dns_recs: list[dict] = []
        for line in data.splitlines():
            if fname.endswith(".vpc"):
                rec = parse_vpc_flow_log(line)
                if rec is None:
                    continue
                if str(rec.get("action") or "").upper() == "ACCEPT":
                    accept_recs.append(rec)  # volume lane: aggregated below
                    continue
                ev = vpc_flow_signal(rec)
            elif fname.endswith(".waf"):
                rec = parse_aws_waf_log(line)
                if rec is not None:
                    waf_recs.append(rec)  # aggregated below, never per-request
                continue
            elif fname.endswith(".dns"):
                rec = parse_r53_dns_log(line)
                if rec is not None:
                    dns_recs.append(rec)  # aggregated below, errors only
                continue
            else:
                ev = cloud_log_event(fname, line)
            if ev is None:
                continue
            ev["tenant_id"] = CLOUD_LOGS_TENANT
            await handle_cloud(ev)
            fed += 1
        # Batch rollups — one signal per aggregation key per scan, never a
        # per-record firehose (audit P1-6 discipline, applied to every lane):
        # ACCEPT flows → per-ENI volume + top-K (src,dst) pairs (#9 talks_to
        # edges); WAF BLOCKs → per (ACL, rule); DNS errors → per (name, rcode).
        for ev in (vpc_accept_rollup(accept_recs)
                   + vpc_pair_rollup(accept_recs, CLOUD_FLOW_PAIR_TOP_K)
                   + waf_block_rollup(waf_recs)
                   + dns_error_rollup(dns_recs)):
            ev["tenant_id"] = CLOUD_LOGS_TENANT
            await handle_cloud(ev)
            fed += 1
    return fed


async def cloud_log_tailer() -> None:
    """Supervised P3B file source (§10 — never a silent task death). Disabled unless
    CLOUD_LOGS_DIR and CLOUD_LOGS_TENANT are both set (default-closed isolation)."""
    if not CLOUD_LOGS_DIR:
        return
    if not CLOUD_LOGS_TENANT:
        log.warning("CLOUD_LOGS_DIR set but CLOUD_LOGS_TENANT empty — cloud-log ingestion DISABLED (default-closed)")
        return
    log.info("cloud-log tailer watching %s (tenant=%s, every %.0fs)", CLOUD_LOGS_DIR, CLOUD_LOGS_TENANT, CLOUD_LOGS_REFRESH_S)
    while True:
        try:
            n = await _scan_cloud_logs()
            if n:
                log.info("cloud-log tailer fed %d signal(s)", n)
        except asyncio.CancelledError:
            raise
        except Exception:                                  # noqa: BLE001
            log.exception("cloud-log scan failed; retrying")
        await asyncio.sleep(max(CLOUD_LOGS_REFRESH_S, 5.0))


# Bounds for the consumer supervisor (env-tunable; tests use tiny values).
# stop() and start() are awaited against a BROKER — when the broker is mid
# crash-loop either call can hang forever, and an unbounded await turns the
# "restarting in 1s" promise into a silent permanent wedge (live incident
# 2026-07-14 19:18Z: handler raised, finally awaited consumer.stop(), stop
# hung on the churning coordinator, engine consumed NOTHING for 5.5h while
# the process looked healthy).
CONSUMER_STOP_TIMEOUT_S = float(os.environ.get("CONSUMER_STOP_TIMEOUT_S", "30"))
CONSUMER_START_TIMEOUT_S = float(os.environ.get("CONSUMER_START_TIMEOUT_S", "90"))


async def _stop_bounded(consumer) -> None:
    """Stop a consumer without letting a hung broker wedge the supervisor.
    On timeout the old consumer is ABANDONED (its group member times out
    broker-side); a fresh consumer replaces it. Never raises."""
    try:
        await asyncio.wait_for(consumer.stop(), timeout=CONSUMER_STOP_TIMEOUT_S)
    except asyncio.CancelledError:
        raise
    except Exception:                                      # noqa: BLE001
        log.exception("consumer stop failed/timed out — abandoning old consumer")


# ── poison-event quarantine (the per-EVENT half of the supervisor) ───────────
#
# The supervisor below survives a poison BATCH, but until an unexpected
# exception in one handler (a TypeError on an unforeseen field shape, a
# ClickHouse transport error) tore down the consumer for ALL ten topics: the
# batch in flight was lost, the offending payload was never recorded, and the
# only evidence was a stack trace. A single malformed producer could therefore
# stop every evidence lane in the engine.
#
# Now one event's failure costs exactly that event: it is counted per topic,
# logged (rate-limited), and its PAYLOAD is preserved so the defect can be
# reproduced — in a bounded in-memory ring always, and appended to a
# dead-letter NDJSON file when CORR_DLQ_DIR is configured.
CORR_QUARANTINE_MAX = int(os.environ.get("CORR_QUARANTINE_MAX", "200"))
CORR_QUARANTINE_PAYLOAD_CHARS = int(os.environ.get("CORR_QUARANTINE_PAYLOAD_CHARS", "4000"))
CORR_DLQ_DIR = os.environ.get("CORR_DLQ_DIR", "")
CORR_DLQ_MAX_BYTES = int(os.environ.get("CORR_DLQ_MAX_BYTES", str(32 * 1024 * 1024)))
QUARANTINE: Deque[dict] = deque(maxlen=CORR_QUARANTINE_MAX)
HANDLER_FAILURES: Dict[str, int] = {}   # topic -> events lost to a handler error
QUARANTINE_WRITE_FAILURES = 0
_QUARANTINE_LOG_LAST: Dict[str, float] = {}
QUARANTINE_LOG_EVERY_S = float(os.environ.get("CORR_QUARANTINE_LOG_EVERY_S", "30"))
# Consecutive handler failures that mean "the dependency is down", not "one
# poison event" — the consumer then restarts through the supervisor's backoff
# instead of quarantining the whole stream at full consume rate.
CORR_QUARANTINE_BURST_MAX = int(os.environ.get("CORR_QUARANTINE_BURST_MAX", "100"))


def _dlq_append(record: dict) -> None:
    """Append one quarantined event to the on-disk dead-letter file. Bounded by
    CORR_DLQ_MAX_BYTES so a poison producer can never fill the volume; a write
    failure is counted, never raised (quarantine must not become the new
    failure)."""
    global QUARANTINE_WRITE_FAILURES
    if not CORR_DLQ_DIR:
        return
    path = os.path.join(CORR_DLQ_DIR, "corr-deadletter.ndjson")
    try:
        os.makedirs(CORR_DLQ_DIR, exist_ok=True)
        try:
            if os.path.getsize(path) >= CORR_DLQ_MAX_BYTES:
                return
        except OSError:
            pass
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except (OSError, TypeError, ValueError):
        QUARANTINE_WRITE_FAILURES += 1


def _quarantine_record(topic: str, event: object, exc: BaseException) -> dict:
    """Build + store one quarantine record (ring + optional on-disk NDJSON)."""
    try:
        payload = json.dumps(event, default=str)[:CORR_QUARANTINE_PAYLOAD_CHARS]
    except (TypeError, ValueError):
        payload = repr(event)[:CORR_QUARANTINE_PAYLOAD_CHARS]
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "topic": topic,
        "error": f"{type(exc).__name__}: {exc}"[:500],
        "payload": payload,
    }
    QUARANTINE.append(record)
    _dlq_append(record)
    return record


def keep_deadletter_payload(lane: str, event: object, exc: BaseException) -> None:
    """Preserve a dead-lettered payload for inspection.

    DeadLetter is caught at 8 sites; each counted it and logged the exception
    MESSAGE, then dropped the event — so the record that provoked it could never
    be looked at, and "why did this device's traps stop becoming signals" was
    unanswerable. Counting stays with DEADLETTER_COUNT at the call site; this
    only keeps the evidence.
    """
    _quarantine_record(f"deadletter:{lane}", event, exc)


def quarantine_event(topic: str, event: object, exc: BaseException) -> None:
    """Record one event whose handler raised: count it, keep the payload, log."""
    HANDLER_FAILURES[topic] = HANDLER_FAILURES.get(topic, 0) + 1
    _quarantine_record(topic, event, exc)
    now = time.monotonic()
    if (now - _QUARANTINE_LOG_LAST.get(topic, -1e9)) >= QUARANTINE_LOG_EVERY_S:
        _QUARANTINE_LOG_LAST[topic] = now
        log.exception("event QUARANTINED topic=%s lost_total=%d (payload kept, "
                      "consumer continues)", topic, HANDLER_FAILURES[topic],
                      exc_info=exc)


async def consume() -> None:
    """Supervised consumer: a poison batch / codec error / broker hiccup is
    logged and retried with backoff, NEVER a silent task death (§10 — the
    pre-build-⑥ consumer died unobserved on a snappy-compressed batch and
    starved the whole engine; this loop is the guarantee that can't recur).
    Every broker-facing await is BOUNDED so the guarantee holds even when the
    broker itself is wedged (see CONSUMER_*_TIMEOUT_S above)."""
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
            await asyncio.wait_for(consumer.start(), timeout=CONSUMER_START_TIMEOUT_S)
            log.info("consuming topics=%s bootstrap=%s", TOPICS, KAFKA_BOOTSTRAP)
            backoff = 1.0
            consecutive_failures = 0
            async for msg in consumer:
                # Per-EVENT isolation: one bad record must cost one record, not
                # the whole ten-topic consumer (see quarantine_event above).
                try:
                    await handle(msg.topic, msg.value)
                    consecutive_failures = 0
                except asyncio.CancelledError:
                    raise
                except Exception as exc:                   # noqa: BLE001
                    quarantine_event(msg.topic, msg.value, exc)
                    consecutive_failures += 1
                    # A RUN of failures is not a poison event, it is a broken
                    # dependency (ClickHouse down). Tolerating those at full
                    # consume rate would quarantine the entire stream; hand it
                    # back to the supervisor so its backoff applies pressure.
                    if consecutive_failures >= CORR_QUARANTINE_BURST_MAX:
                        raise
        except asyncio.CancelledError:
            await _stop_bounded(consumer)
            raise
        except Exception:                                  # noqa: BLE001
            log.exception("consumer failed; restarting in %.0fs", backoff)
        await _stop_bounded(consumer)
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
    elif topic == "netops.app.identities.v1":
        await handle_app_identity(event)
    elif topic == "netops.controller_events":
        await handle_controller_event(event)
    elif topic == "netops.app.edge":
        await handle_app_edge(event)
    elif topic == "netops.verification":
        await handle_verification(event)


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
    if family == "cloud_resource":
        # Provider-reported health/utilization for a cloud instance (CloudWatch /
        # Azure Monitor). The resource id is carried in `index`; tokens include it
        # AND the app-host private IPs so a cloud-metric anomaly co-grounds with
        # the probes and app signals that name the same host (cloud RCA needs an
        # INDEPENDENT provider observer to reach confirmed).
        rid = str(ev.get("index") or "")
        tokens = tuple(t for t in (device, rid, *(str(ev.get("private_ip") or "").split(","))) if t)
        return device, EntityType.DEVICE, "cloud_resource_anomaly", tokens
    return None


async def handle_metric(ev: dict) -> None:
    """Canonical MetricEvent (netops.metrics) → device_telemetry signal.

    Wire contract with collectors/metric_events.go: device, metric, value,
    signal_family, if_name/peer/index, collection_path, ts, vendor. Legacy
    Telegraf-shaped events (hostname/name/first-numeric) are still tolerated for
    back-compat but carry no canonical identity."""
    global METRICS_RECEIVED, METRICS_ACCEPTED, METRICS_DROPPED
    global METRICS_DROPPED_NO_VALUE, METRICS_DROPPED_NO_IDENTITY, METRICS_DROPPED_STALE_TS
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
        METRICS_DROPPED_NO_VALUE += 1
        return
    value = float(raw_value)

    ident = metric_identity(ev)
    if ident is None:
        # No canonical identity → cannot ground a signal. Drop, don't guess.
        METRICS_DROPPED += 1
        METRICS_DROPPED_NO_IDENTITY += 1
        return
    entity_id, entity_type, kind_prefix, tokens = ident

    # Timestamp validation (Layer-1F): trust the event clock only within skew.
    now = datetime.now(timezone.utc)
    event_ts = parse_event_ts(ev.get("ts")) or now
    age = (now - event_ts).total_seconds()
    if age < -METRIC_FUTURE_SKEW_S or age > METRIC_MAX_AGE_S:
        METRICS_DROPPED += 1
        METRICS_DROPPED_STALE_TS += 1
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
# Cap on distinct syslog hostnames tracked for burst detection. The key comes
# from the device — it is attacker-controllable — so it needs a hard bound, not
# just per-key pruning.
SYSLOG_BUCKET_MAX = int(os.environ.get("CORR_MAX_SYSLOG_HOSTS", "50000"))
_SYSLOG_SWEEP_LAST = 0.0
SYSLOG_SWEEP_EVERY_S = 30.0


def _sweep_syslog_buckets(now: float) -> None:
    """Drop hosts whose window has emptied; hard-cap the key set as a backstop."""
    global _SYSLOG_SWEEP_LAST
    if (now - _SYSLOG_SWEEP_LAST) < SYSLOG_SWEEP_EVERY_S and len(SYSLOG_BUCKET) < SYSLOG_BUCKET_MAX:
        return
    _SYSLOG_SWEEP_LAST = now
    cutoff = now - SYSLOG_WINDOW
    for host in [h for h, b in SYSLOG_BUCKET.items() if not b or b[-1][0] < cutoff]:
        SYSLOG_BUCKET.pop(host, None)
    if len(SYSLOG_BUCKET) > SYSLOG_BUCKET_MAX:
        # Still over: evict the least-recently-active hosts.
        for host, _ in sorted(SYSLOG_BUCKET.items(),
                              key=lambda kv: kv[1][-1][0] if kv[1] else 0.0,
                              )[:len(SYSLOG_BUCKET) - SYSLOG_BUCKET_MAX]:
            SYSLOG_BUCKET.pop(host, None)
        log.warning("syslog burst tracker at cap (%d hosts) — evicting oldest; "
                    "check for spoofed/rotating syslog hostnames", SYSLOG_BUCKET_MAX)


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
        "opensearch,victoriametrics,prometheus,kafka,redpanda,vector,loki,"
        "promtail,correlation,prober",
    ).split(",") if t.strip()
}
_SERVICE_DEP_TARGETS = {
    t.strip().lower() for t in os.getenv("CORR_SERVICE_DEP_TARGETS", "").split(",") if t.strip()
}


# Signal purposes that are NOT production traffic (§11): their evidence must
# never confirm production customer impact — forced to LAB_TEST intent, which
# derives DEBUG_ONLY authority (excluded from verdicts and marked internal).
_NON_PRODUCTION_PURPOSES = frozenset({
    "validation", "lab", "fault_injection", "debug", "demo", "staging",
})


def classify_probe(ev: dict, sig: Signal) -> None:
    """Enrich an active_probe signal IN PLACE with its derived authority/scope +
    fate fingerprint. Registry fields (`probe_intent`/`vantage_type` on the event)
    are authoritative; otherwise infer and fail closed to UNKNOWN→LOW."""
    # Lineage + environment (§2/§11) — stamped on EVERY probe-derived signal so
    # rows from one execution are joinable and validation traffic is marked.
    if ev.get("execution_id"):
        sig.attrs["execution_id"] = str(ev["execution_id"])
    purpose = str(ev.get("signal_purpose") or "production").strip().lower() or "production"
    sig.attrs["signal_purpose"] = purpose
    sig.attrs["environment"] = (
        str(ev.get("environment") or "").strip().lower()
        or ("prod" if purpose == "production" else purpose)
    )
    intent = str(ev.get("probe_intent") or "")
    vantage = str(ev.get("vantage_type") or "")
    src = "registry"
    if purpose in _NON_PRODUCTION_PURPOSES:
        # A declared non-production purpose overrides everything, including a
        # declared customer-path intent: validation/lab/fault-injection traffic
        # is DEBUG_ONLY evidence, full stop (§11).
        pi, vt, src = ProbeIntent.LAB_TEST, VantageType.LOCAL_CONTAINER, "declared-purpose"
    elif intent and vantage:
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
    global DEADLETTER_COUNT, PROBES_RECEIVED
    PROBES_RECEIVED += 1
    if not CORR_SIGNALS_ENABLED or ch is None:
        return
    host = str(ev.get("target") or "")
    tenant = str(ev.get("tenant_id") or "") or tenant_for(host)
    now = datetime.now(timezone.utc)
    try:
        sigs = probe_signals(ev, DETECTOR, tenant, now)
    except DeadLetter as exc:
        DEADLETTER_COUNT += 1
        keep_deadletter_payload("probe", ev, exc)
        log.warning("dead-letter (probe): %s", exc)
        return
    for sig in sigs:
        classify_probe(ev, sig)
        await ch_insert("netops.corr_signals", [sig.to_ch_row()], lane="probes")
        buffer_signal(sig)
        log.info("probe signal %s: %s sev=%s value=%.1f scope=%s auth=%s",
                 sig.kind, sig.entity_id, sig.severity.value, sig.value,
                 sig.attrs.get("probe_scope"), sig.attrs.get("probe_authority"))

    # Semantic application-experience lane (external Digital-Experience, NOT APM):
    # an HTTP/TCP/ICMP synthetic FAILURE also emits a semantic app-experience
    # signal (synthetic_http_fail / synthetic_tls_fail / …) the sig.ent.app.*
    # templates match. Additive — the generic probe signals above are unchanged.
    # Classified through the SAME fail-closed path as the generic lane: both
    # rows carry the event's execution_id/purpose, and a validation canary can
    # never arrive as a trusted customer-path witness (epic §2/§11).
    app_sig = synthetic_app_signal(ev, tenant, now)
    if app_sig is not None:
        classify_probe(ev, app_sig)
        await ch_insert("netops.corr_signals", [app_sig.to_ch_row()], lane="probes")
        buffer_signal(app_sig)
        log.info("synthetic app-experience signal %s: %s reason=%s app=%s",
                 app_sig.kind, app_sig.entity_id, app_sig.attrs.get("reason"),
                 app_sig.attrs.get("app_name"))


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
        keep_deadletter_payload("trap", ev, exc)
        log.warning("dead-letter (trap): %s", exc)
        return
    if sig is None:
        TRAPS_DROPPED += 1   # unclassified — no RCA signal, kept searchable
        return
    await ch_insert("netops.corr_signals", [sig.to_ch_row()], lane="snmptrap")
    TRAPS_NORMALIZED += 1
    buffer_signal(sig)
    log.info("trap signal %s: %s %s", sig.kind, sig.entity_id, sig.attrs.get("state", ""))


async def handle_controller_event(ev: dict) -> None:
    """Normalized controller_event (netops.controller_events, the Go nms poll
    runtime #95) → management-plane signal on the SAME spine. Vendor-neutral:
    the producer already normalized kinds, so Meraki == Versa == vManage here.
    A controller is ONE modality (Source.CONTROLLER + MANAGEMENT_PLANE): the
    independence gate caps controller-alone pictures at suspected — confirmation
    always needs corroborating direct telemetry (the 3-tier evidence hierarchy)."""
    global CONTROLLER_EVENTS_RECEIVED, CONTROLLER_EVENTS_SIGNALS, CONTROLLER_EVENTS_DROPPED
    CONTROLLER_EVENTS_RECEIVED += 1
    if not CORR_SIGNALS_ENABLED or ch is None:
        return
    sig = controller_event_to_signal(ev, datetime.now(timezone.utc))
    if sig is None:
        CONTROLLER_EVENTS_DROPPED += 1  # no tenant/kind identity — default-closed
        return
    await ch_insert("netops.corr_signals", [sig.to_ch_row()], lane="controller_events")
    CONTROLLER_EVENTS_SIGNALS += 1
    buffer_signal(sig)
    log.info("controller signal %s: %s", sig.kind, sig.entity_id)


async def handle_verification(ev: dict) -> None:
    """Active-verification check results (netops.verification, the Go verify
    engine — RCA spec item 8) → active_verification-modality signals on the
    SAME spine. A failing check corroborates (attrs.corroborates_kinds feeds
    scoring's clause matching); a healthy battery REFUTES
    (attrs.refutes_kinds → scoring's contradiction path). Because
    active_verification is its own modality class, the independence gate can
    count a device answer as a second source — while the device-as-observer
    identity blocks it from corroborating the same device's passive telemetry.
    Fail-closed: an untenanted, unbindable or skipped result is dropped."""
    global VERIFICATION_RECEIVED, VERIFICATION_SIGNALS, VERIFICATION_DROPPED
    VERIFICATION_RECEIVED += 1
    if not CORR_SIGNALS_ENABLED or ch is None:
        return
    sig = verification_signal_from_event(ev, datetime.now(timezone.utc))
    if sig is None:
        VERIFICATION_DROPPED += 1  # no tenant/device identity or skipped — default-closed
        return
    await ch_insert("netops.corr_signals", [sig.to_ch_row()], lane="verification")
    VERIFICATION_SIGNALS += 1
    buffer_signal(sig)
    log.info("verification signal %s %s: %s", sig.kind, sig.attrs.get("check", ""), sig.entity_id)


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
        keep_deadletter_payload("cloud", ev, exc)
        log.warning("dead-letter (cloud): %s", exc)
        return
    if sig.kind == "clock_skew":
        # META finding (S5): recorded for operators, never engine-buffered (it
        # must not lend a modality plane to a fault) and cooldown-guarded here
        # too — defense in depth against a chatty poller.
        global CLOCK_SKEW_SIGNALS
        if _clock_skew_due(tenant, sig.entity_id):
            await ch_insert("netops.corr_signals", [sig.to_ch_row()], lane="cloud")
            CLOCK_SKEW_SIGNALS += 1
            log.info("clock-skew signal (cloud lane): %s skew=%.0fs",
                     sig.entity_id, float(sig.value))
        return
    await ch_insert("netops.corr_signals", [sig.to_ch_row()], lane="cloud")
    CLOUD_SIGNALS += 1
    buffer_signal(sig)
    log.info("cloud signal %s: %s sev=%s acct=%s region=%s",
             sig.kind, sig.entity_id, sig.severity.value,
             sig.attrs.get("account", ""), sig.attrs.get("region", ""))


async def handle_app_identity(ev: dict) -> None:
    """Fused application-identity events (netops.app.identities.v1) → canonical
    enrichment signals on the SAME spine (#81 P5). Identity is ENRICHMENT, not a
    fault (AD-5): an INFO signal that attaches to objects the engine ALREADY formed
    from real faults, naming the app they affect — it can never seed an object or
    self-confirm a verdict (one platform vantage). Additive lane: the existing
    engine grounds it with no identity-specific code path.

    Tenancy is EXPLICIT — an identity event carries its own tenant_id (there is no
    device to infer it from); an untenanted event is DROPPED, never guessed
    (default-closed isolation, §3a). A malformed event dead-letters (counted)."""
    global DEADLETTER_COUNT, APP_ID_RECEIVED, APP_ID_SIGNALS, APP_ID_DROPPED
    APP_ID_RECEIVED += 1
    if not CORR_SIGNALS_ENABLED or ch is None:
        return
    tenant = str(ev.get("tenant_id") or "")
    if not tenant:
        APP_ID_DROPPED += 1
        log.warning("app-identity event dropped: no tenant_id (app=%s)", ev.get("app"))
        return
    try:
        sig = app_identity_from_event(ev, tenant, datetime.now(timezone.utc))
    except DeadLetter as exc:
        DEADLETTER_COUNT += 1
        APP_ID_DROPPED += 1
        keep_deadletter_payload("app_identity", ev, exc)
        log.warning("dead-letter (app-identity): %s", exc)
        return
    await ch_insert("netops.corr_signals", [sig.to_ch_row()], lane="app_identity")
    APP_ID_SIGNALS += 1
    buffer_signal(sig)
    # #98 Phase 4 — feed the tenant-scoped dst_ip→app index the flow lane joins
    # against (attribution level 2). TTL'd + bounded in the index itself.
    _APPID_INDEX.observe(tenant, str(ev.get("dst_ip") or ""), sig.entity_id,
                         str(sig.attrs.get("band", "")), sig.ts)
    log.info("app-identity signal %s: app=%s band=%s state=%s",
             sig.kind, sig.entity_id,
             sig.attrs.get("band", ""), sig.attrs.get("state", ""))


async def handle_app_edge(ev: dict) -> None:
    """LB / proxy / ingress telemetry (netops.app.edge, #98 P5) → one canonical
    app-edge signal (lb_5xx / lb_target_unhealthy / app_error_rate_high /
    app_latency_high / lb_4xx_high) via the vendor-neutral contract
    (lb_normalize.py, docs/lb-proxy-ingress-telemetry-contract.md).

    Tenancy is EXPLICIT and default-closed, same policy as app identity: an
    app-edge event carries its own tenant_id (there is no device to infer it
    from); an untenanted event is DROPPED, never guessed (§3a). A healthy /
    unclassifiable / ungroundable event emits nothing (anti-noise)."""
    global APP_EDGE_RECEIVED, APP_EDGE_SIGNALS, APP_EDGE_DROPPED
    APP_EDGE_RECEIVED += 1
    if not CORR_SIGNALS_ENABLED or ch is None:
        return
    tenant = str(ev.get("tenant_id") or "")
    if not tenant:
        APP_EDGE_DROPPED += 1
        log.warning("app-edge event dropped: no tenant_id (app=%s host=%s)",
                    ev.get("app_name"), ev.get("host"))
        return
    sig = normalize_lb_event(ev, tenant, datetime.now(timezone.utc))
    if sig is None:
        APP_EDGE_DROPPED += 1
        return
    await ch_insert("netops.corr_signals", [sig.to_ch_row()], lane="app_edge")
    APP_EDGE_SIGNALS += 1
    buffer_signal(sig)
    log.info("app-edge signal %s: %s reason=%s lb=%s",
             sig.kind, sig.entity_id, sig.attrs.get("reason"),
             sig.observer.observer_id)


async def handle_syslog(ev: dict) -> None:
    # Control-plane extraction first (#67 build ⑦): adjacency / link-state
    # events become control_plane signals on the spine regardless of burst
    # behavior — one BGP-down is evidence even when nothing else is on fire.
    global DEADLETTER_COUNT, SYSLOG_RECEIVED, SYSLOG_SIGNALS
    # Intake is counted BEFORE any filtering: `syslog_received` must mean
    # "arrived from the bus", so a flat-line means the lane died, not that the
    # traffic happened to be unclassifiable.
    SYSLOG_RECEIVED += 1
    if CORR_SIGNALS_ENABLED and ch is not None:
        cp_tenant = str(ev.get("tenant_id") or "") or tenant_for(str(ev.get("hostname") or ""))
        try:
            cp_sig = syslog_control_signal(ev, cp_tenant, datetime.now(timezone.utc))
        except DeadLetter as exc:
            DEADLETTER_COUNT += 1
            keep_deadletter_payload("syslog", ev, exc)
            log.warning("dead-letter (syslog): %s", exc)
            cp_sig = None
        if cp_sig is not None:
            await ch_insert("netops.corr_signals", [cp_sig.to_ch_row()], lane="syslog")
            SYSLOG_SIGNALS += 1
            buffer_signal(cp_sig)
            log.info("control-plane signal %s: %s %s",
                     cp_sig.kind, cp_sig.entity_id, cp_sig.attrs.get("state", ""))
        # Port Intelligence physical-layer event (#94 P3b): transceiver/optics/
        # DOM/FEC syslog → sig.ent.spdc evidence kinds. Independent of the
        # control-plane classifier (a line can be one or the other, rarely both).
        try:
            pe_sig = port_event_signal(ev, cp_tenant, datetime.now(timezone.utc))
        except DeadLetter as exc:
            DEADLETTER_COUNT += 1
            keep_deadletter_payload("port_event", ev, exc)
            log.warning("dead-letter (port-event): %s", exc)
            pe_sig = None
        if pe_sig is not None:
            await ch_insert("netops.corr_signals", [pe_sig.to_ch_row()], lane="syslog")
            SYSLOG_SIGNALS += 1
            buffer_signal(pe_sig)
            log.info("port-event signal %s: %s", pe_sig.kind, pe_sig.entity_id)
        # Clock-skew meta-finding (log-time standard S5/R5): Vector stamps
        # clock_skew_s on the event when the origin timestamp disagrees with the
        # receive clock beyond tolerance; here it becomes a per-device signal.
        # META evidence: persisted for operators (events feed / evidence store)
        # but NEVER buffer_signal()ed — a wrong clock must not lend an extra
        # modality plane to a real fault. Cooldown-guarded per (tenant, device)
        # so a misconfigured device logging at volume yields one finding per
        # window, not a firehose.
        try:
            skew_sig = clock_skew_signal(ev, cp_tenant, datetime.now(timezone.utc))
        except DeadLetter as exc:
            DEADLETTER_COUNT += 1
            keep_deadletter_payload("clock_skew", ev, exc)
            log.warning("dead-letter (clock-skew): %s", exc)
            skew_sig = None
        if skew_sig is not None and _clock_skew_due(cp_tenant, skew_sig.entity_id):
            global CLOCK_SKEW_SIGNALS
            await ch_insert("netops.corr_signals", [skew_sig.to_ch_row()], lane="syslog")
            CLOCK_SKEW_SIGNALS += 1
            SYSLOG_SIGNALS += 1
            log.info("clock-skew signal: %s skew=%.0fs", skew_sig.entity_id,
                     float(skew_sig.value))

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
    # The per-host LISTS were pruned but the KEY SET never was — and the key is
    # the device-supplied, spoofable syslog hostname, so a single misbehaving or
    # hostile sender could grow this map without limit. Sweep empty buckets, and
    # hard-cap the key set as the backstop.
    _sweep_syslog_buckets(now)
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
    global FLOWS_RECEIVED, FLOWS_DROPPED
    if not (CORR_SIGNALS_ENABLED and FLOW_CORRELATION_ENABLED) or ch is None:
        return
    sample = flow_sample(ev)
    if sample is None:
        # Unattributable/unmeasurable record. `flows_received` counts ACCEPTED
        # flows (it is incremented after the parse), so without this counter a
        # goflow2 field-name change that fails 100% of parses reads exactly like
        # a quiet network. Logged rate-limited: flows are a firehose.
        FLOWS_DROPPED += 1
        _log_flow_drop(ev)
        return
    FLOWS_RECEIVED += 1
    sampler, entity, bytes_est = sample
    tenant = str(ev.get("tenant_id") or "") or tenant_for(sampler)
    agg = _FLOW_AGG.setdefault((tenant, entity), {"bytes": 0.0, "sampler": sampler})
    agg["bytes"] += bytes_est
    # #98 Phase 4 — SECOND grounding: when a confirming attribution source names
    # the application this flow serves, also accumulate a per-app volume series.
    # No attribution → nothing here; the flow stays infrastructure-grounded.
    att = resolve_flow_app(ev, tenant, _APPID_INDEX, datetime.now(timezone.utc))
    if att is not None and att.confirming:
        aagg = _FLOW_APP_AGG.setdefault(
            (tenant, att.app),
            {"bytes": 0.0, "sampler": sampler, "source": att.source,
             "confidence": att.confidence})
        aagg["bytes"] += bytes_est
    # C7.3: directed per-pair volume. Resolve src/dst → devices (best-effort; abstains
    # when an endpoint is unknown) and accumulate a directed byte total → the oracle's
    # NetFlow direction source.
    global FLOW_DIRECTION_PAIRS
    dsample = flow_direction_sample(ev, cached_entity_resolver_for(tenant))
    if dsample is not None:
        sd, dd, dbytes = dsample
        dirmap = _FLOW_DIR.setdefault(tenant, {})
        if (sd, dd) not in dirmap:
            # Accumulated CONTINUOUSLY (never reset) and keyed by resolved
            # device pair: bounded in a stable fleet, unbounded under entity
            # churn. At the cap the smallest-volume pairs go first — they are
            # the ones the dominance ratio never depends on.
            if len(dirmap) >= FLOW_DIR_MAX_PAIRS:
                for pair, _ in sorted(dirmap.items(), key=lambda kv: kv[1])[:FLOW_DIR_MAX_PAIRS // 4]:
                    dirmap.pop(pair, None)
            FLOW_DIRECTION_PAIRS += 1
        dirmap[(sd, dd)] = dirmap.get((sd, dd), 0.0) + dbytes


async def _flush_flow_aggregator(now: datetime) -> None:
    """Feed each accumulated per-interface byte total through CUSUM as ONE
    passive_flow sample this cycle, then reset. The detection interval is the engine
    cycle interval — regular sampling, exactly like a metric poll — so the existing
    episode machinery baselines and fires flow_volume_anomaly episodes."""
    global PASSIVE_FLOW_SIGNALS
    if not _FLOW_AGG and not _FLOW_APP_AGG:
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
    # #98 Phase 4 — the app-grounded series (same canonical kind, app entity).
    # Tokens mirror the synthetic lane's grounding vocabulary (bare slug +
    # app:<slug>) so an app-attributed flow anomaly co-locates with the
    # synthetic app-experience signal on ONE application-impact object;
    # attribution provenance rides the signal (attribution_source/confidence).
    app_snapshot = dict(_FLOW_APP_AGG)
    _FLOW_APP_AGG.clear()
    for (tenant, app), a in sorted(app_snapshot.items()):
        emitted = await feed_episode_detector(
            tenant, app, "flow_bytes_rate", a["bytes"] / interval, now,
            observer_id=a["sampler"], collection_path="flow_export",
            entity_type=EntityType.APP, kind_prefix="flow_volume_anomaly",
            entity_tokens=(app, f"app:{app}", a["sampler"]),
            source=Source.FLOW, modality=ModalityClass.PASSIVE_FLOW,
            observer_type=ObserverType.FLOW_EXPORTER,
            extra_attrs={"attribution_source": a["source"],
                         "attribution_confidence": a["confidence"]},
        )
        if emitted:
            PASSIVE_FLOW_SIGNALS += 1


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
    await ch_insert("netops.findings", [row], kind=row["kind"], device=device)
    log.info("finding: %s %s %s", row["severity"], row["kind"], row["summary"])


# ---------------------------------------------------------------------------
# HTTP API
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global ch
    ch = CH(CLICKHOUSE_URL, CLICKHOUSE_USER, CLICKHOUSE_PASS)
    tasks = [
        asyncio.create_task(consume()),
        asyncio.create_task(engine_loop()),
        asyncio.create_task(cloud_log_tailer()),  # #81 P3B file source (opt-in)
    ]
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


@app.get("/deadletters")
async def deadletters(limit: int = 50) -> dict:
    """The quarantined events (newest first) WITH their payloads — the point of
    the quarantine is that a poison event stays reproducible instead of costing
    a stack trace and a lost record. Internal surface (the Go API fronts it with
    authz), bounded by CORR_QUARANTINE_MAX."""
    n = max(1, min(int(limit), CORR_QUARANTINE_MAX))
    return {
        "count": len(QUARANTINE),
        "failures_by_topic": dict(sorted(HANDLER_FAILURES.items())),
        "write_failures": QUARANTINE_WRITE_FAILURES,
        "events": list(QUARANTINE)[-n:][::-1],
    }


@app.get("/metrics")
async def metrics_exposition():
    """Prometheus text exposition of the intake/drop counters (#99 R6) — the
    same numbers /healthz reports, scrapeable by VictoriaMetrics so silent
    ingestion failures (received flat-lined, dropped rising, dead-letters)
    become alerts instead of archaeology."""
    from fastapi.responses import PlainTextResponse
    h = await health()
    lines = [
        "# HELP corr_ingest_events Correlation intake counters by lane (monotonic since process start).",
        "# TYPE corr_ingest_events counter",
    ]
    for key, val in h["ingest"].items():
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            lines.append(f'corr_ingest_events{{counter="{key}"}} {val}')
    eng = h["engine_v2"]
    lines += [
        "# TYPE corr_deadletters counter",
        f"corr_deadletters {eng['deadletter_count']}",
        "# TYPE corr_window_signals gauge",
        f"corr_window_signals {eng['window_signals']}",
        "# TYPE corr_open_objects gauge",
        f"corr_open_objects {eng['open_objects']}",
        # #100 damping: persisted vs suppressed object versions. A damped:persisted
        # ratio collapsing to 0 under a storm means the material gate stopped working.
        "# TYPE corr_versions counter",
        f'corr_versions{{outcome="persisted"}} {eng["versions_persisted"]}',
        f'corr_versions{{outcome="damped"}} {eng["versions_damped"]}',
        # #101: lost corr_current dual-writes = stale Command Center. Alerted
        # by CorrCurrentProjectionFailing; repaired by the Go reconciler.
        "# HELP corr_current_projection_write_failures_total corr_current projection writes lost (hot-read staleness risk).",
        "# TYPE corr_current_projection_write_failures_total counter",
        f"corr_current_projection_write_failures_total {PROJECTION_WRITE_FAILURES}",
        # F-38: any lost ClickHouse write, by table. corr_signals_archive
        # rising = the replay source is growing holes while live RCA looks fine.
        "# HELP corr_ch_insert_failures_total ClickHouse inserts that did not land, by table.",
        "# TYPE corr_ch_insert_failures_total counter",
    ]
    for table, n in sorted(CH_INSERT_FAILURES.items()):
        lines.append(f'corr_ch_insert_failures_total{{table="{table}"}} {n}')
    lines += [
        # F-40: events lost to a handler exception. Non-zero means a producer is
        # emitting a shape the engine cannot process — the payloads are in
        # /deadletters (and CORR_DLQ_DIR when configured).
        "# HELP corr_handler_failures_total Events quarantined after a handler raised, by topic.",
        "# TYPE corr_handler_failures_total counter",
    ]
    for topic, n in sorted(HANDLER_FAILURES.items()):
        lines.append(f'corr_handler_failures_total{{topic="{topic}"}} {n}')
    lines += [
        "# TYPE corr_quarantined_events gauge",
        f"corr_quarantined_events {len(QUARANTINE)}",
    ]
    # #101 tenant write-amp, BOUNDED cardinality: only the top-K noisiest
    # tenants of the last flushed window get series (K=CORR_WA_TOPK); the full
    # per-tenant history lives in netops.corr_tenant_write_amp (SQL, 30d TTL).
    if TENANT_WA_LAST:
        lines += [
            "# HELP corr_tenant_writes_window Last write-amp window counts, top-K noisiest tenants only.",
            "# TYPE corr_tenant_writes_window gauge",
        ]
        for row in TENANT_WA_LAST:
            t = row["tenant_id"] or "platform"
            for outcome in ("raw_seen", "persisted", "damped"):
                lines.append(
                    f'corr_tenant_writes_window{{tenant_id="{t}",outcome="{outcome}"}} {row[outcome]}')
    return PlainTextResponse("\n".join(lines) + "\n")


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
            "versions_persisted": VERSIONS_PERSISTED,
            "versions_damped": VERSIONS_DAMPED,
            # #101: projection health + intentional-storm registry + top-K
            # write-amp of the last flushed window (bounded; full per-tenant
            # truth in netops.corr_tenant_write_amp).
            "projection_write_failures": PROJECTION_WRITE_FAILURES,
            "chaos_fixtures": sorted(CHAOS_FIXTURES.values()),
            "tenant_write_amp_topk": TENANT_WA_LAST,
            "window_signals": len(WINDOW_BUFFER),
            "seam_inventory": len(seam_inventory()),
            "topology_gap_hints": LAST_GAP_HINTS,
            # C7.1 EntityResolver coverage (global slice) — proves the IP/ifIndex→entity
            # bridge is populated; the directed-topology sources resolve through it.
            "entity_resolver": entity_resolver_for("").coverage(),
            "probe_paths": len(probe_paths()),          # C7.4 measured paths available
            "routing_direction_pairs": len(routing_direction()),  # C7.5 computed fwd pairs
        },
        # Durability: writes and events that did NOT land. All-zero is the only
        # healthy state; anything else is data the platform silently does not
        # have (F-38 ClickHouse writes, F-40 quarantined events).
        "durability": {
            "ch_insert_failures": dict(sorted(CH_INSERT_FAILURES.items())),
            "handler_failures": dict(sorted(HANDLER_FAILURES.items())),
            "quarantined_events": len(QUARANTINE),
            "quarantine_write_failures": QUARANTINE_WRITE_FAILURES,
            "topology_stale": _topology_stale(datetime.now(timezone.utc)),
        },
        # Metric/trap lane observability — proves netops.metrics is fed and where
        # events are accepted vs dropped (the lane was historically empty).
        "ingest": {
            "probes_received": PROBES_RECEIVED,
            "syslog_received": SYSLOG_RECEIVED,
            "syslog_signals": SYSLOG_SIGNALS,
            "metrics_received": METRICS_RECEIVED,
            "metrics_accepted": METRICS_ACCEPTED,
            "metrics_dropped": METRICS_DROPPED,
            # F-44: the SAME total, split by cause — "which device/producer is
            # losing data, and why" is not answerable from the total alone.
            "metrics_dropped_no_value": METRICS_DROPPED_NO_VALUE,
            "metrics_dropped_no_identity": METRICS_DROPPED_NO_IDENTITY,
            "metrics_dropped_stale_ts": METRICS_DROPPED_STALE_TS,
            # Event timestamps that fell back to ingest time (producers.py).
            "event_ts_invalid": ts_invalid_count(),
            "device_telemetry_signals": DEVICE_TELEMETRY_SIGNALS,
            "traps_received": TRAPS_RECEIVED,
            "traps_normalized": TRAPS_NORMALIZED,
            "traps_recanonicalized": TRAPS_RECANON,  # C8: device recovered via EntityResolver
            "traps_dropped": TRAPS_DROPPED,
            "flows_received": FLOWS_RECEIVED,
            "flows_dropped": FLOWS_DROPPED,
            "passive_flow_signals": PASSIVE_FLOW_SIGNALS,
            "flow_entities_tracked": len(_FLOW_AGG),
            # C7.3 NetFlow direction: distinct directed device-pairs observed.
            "flow_direction_pairs": FLOW_DIRECTION_PAIRS,
            # #81 P3G cloud lane: proves netops.cloud is consumed + where events are lost.
            "cloud_received": CLOUD_RECEIVED,
            "cloud_signals": CLOUD_SIGNALS,
            "cloud_dropped": CLOUD_DROPPED,
            # #81 P5 fusion identity lane: proves netops.app.identities.v1 is consumed.
            "app_identity_received": APP_ID_RECEIVED,
            "app_identity_signals": APP_ID_SIGNALS,
            "app_identity_dropped": APP_ID_DROPPED,
            "app_edge_received": APP_EDGE_RECEIVED,
            "app_edge_signals": APP_EDGE_SIGNALS,
            "app_edge_dropped": APP_EDGE_DROPPED,
            # #95 NMS controller lane: proves netops.controller_events is consumed.
            "controller_events_received": CONTROLLER_EVENTS_RECEIVED,
            "controller_events_signals": CONTROLLER_EVENTS_SIGNALS,
            "controller_events_dropped": CONTROLLER_EVENTS_DROPPED,
            # RCA spec item 8: proves netops.verification is consumed.
            "verification_received": VERIFICATION_RECEIVED,
            "verification_signals": VERIFICATION_SIGNALS,
            "verification_dropped": VERIFICATION_DROPPED,
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
    # RFC 3339 UTC on the wire (log-time standard S3/R1): zone-less
    # toString(DateTime64) strings parse as browser-local in JS consumers.
    sql = f"""
      SELECT concat(replaceOne(toString(ts, 'UTC'), ' ', 'T'), 'Z') AS ts,
             id, kind, severity, score, device,
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
