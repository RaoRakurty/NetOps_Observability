"""Correlation service — the impure shell around the pure engine core.

FastAPI + aiokafka. engine.py owns determinism (pure ``run_window``, replayable
forever); this module owns everything that touches the world:

  * Consume the 12 ``TOPICS`` lanes (syslog / flows / metrics / probes /
    snmptrap / cloud / app identities / controller events / app edge /
    verification / wireless sessions + events) under a supervised consumer —
    offsets commit only after the ClickHouse flush succeeds, so a crash
    replays instead of losing signals.
  * Normalize every event into canonical Signals (producers + the cloud /
    app-identity / wireless intakes), tenant-scoped end to end — a signal
    never crosses its tenant.
  * Assemble per-tenant windows and run engine v3 in the default thread-pool
    executor: storm-window CPU must never starve the consumer heartbeat or
    /healthz (inputs are snapshotted tuples, so purity survives the offload).
  * Persist snapshots + signals through CHBatcher (bounded, size/time-flushed
    batches), with verdict / attribution fields flattened for the UI.
  * Serve the read API: /findings, /correlations (incl. /{id}/replay, which
    re-runs the stored snapshot byte-identically), /metrics, /healthz, and
    POST /analyze.

The dividing line is load-bearing: anything deterministic belongs in
engine.py; anything with IO, clocks, or retries belongs here.
"""

from __future__ import annotations

import asyncio
import contextlib
import csv
import functools
import glob
import hashlib
import json
import logging
import os
import time
import uuid
from collections import Counter, OrderedDict, deque
from collections.abc import Awaitable, Callable, Iterable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from dataclasses import replace as dc_replace
from datetime import datetime, timezone

import httpx
from aiokafka import AIOKafkaConsumer, TopicPartition
from aiokafka.abc import ConsumerRebalanceListener
from aiokafka.coordinator.assignors.range import RangePartitionAssignor
from aiokafka.partitioner import murmur2
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

import diagnostics
import signals
from app_producers import app_identity_from_event
from catalog import builtin_catalog
from cloud_dependency import build_from_records, merge_path_views
from cloud_log_parsers import (
    cloud_log_event,
    dns_error_rollup,
    parse_aws_waf_log,
    parse_r53_dns_log,
    parse_vpc_flow_log,
    vpc_accept_rollup,
    vpc_flow_signal,
    vpc_pair_rollup,
    waf_block_rollup,
)
from cloud_producers import cloud_signal_from_event
from controller_events import controller_event_to_signal
from directed_topology import DirectedTopology
from engine import (
    EngineConfig,
    ObjectSnapshot,
    SeamView,
    TopologyAdjacency,
    find_continuation,
    find_merges,
    run_window,
)
from entity_resolver import EntityResolver
from episodes import EpisodeDetector
from flow_app_attribution import AppIdentityIndex, resolve_flow_app
from flow_direction import flow_direction_sample, netflow_direction_source
from lb_normalize import normalize_lb_event
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
from path_direction import resolve_path_order, traceroute_direction_source
from path_graph import PathGraphView
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
from routing_direction import forwarding_pairs, routing_direction_source
from series_budget import derive_max_series
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
from synthetic_normalize import synthetic_app_signal
from tls_ident import PeerIdentityMiddleware
from verification_producer import verification_signal_from_event
from wireless_onboarding import (
    assemble_episode as assemble_wireless_episode,
)
from wireless_onboarding import (
    client_identity as wo_client_identity,
)
from wireless_onboarding import (
    episode_signal as wireless_episode_signal,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LOG_LEVEL        = os.environ.get("LOG_LEVEL", "info").upper()
KAFKA_BOOTSTRAP  = os.environ.get("KAFKA_BOOTSTRAP", "kafka:9092")


def kafka_security_kwargs(env=os.environ) -> dict:
    """mTLS to the bus (SEC-006.2): when the three cert paths are set, the
    consumer dials the broker's authenticated listener presenting the
    correlation SVID; unset, the plaintext baseline is bit-for-bit unchanged.
    A PARTIAL config refuses to start rather than silently falling back to
    plaintext — a downgrade that looks exactly like "the bus is quiet"."""
    ca = env.get("KAFKA_SSL_CA", "")
    cert = env.get("KAFKA_SSL_CERT", "")
    key = env.get("KAFKA_SSL_KEY", "")
    if not (ca or cert or key):
        return {}
    if not (ca and cert and key):
        raise RuntimeError(
            "KAFKA_SSL_CA, KAFKA_SSL_CERT and KAFKA_SSL_KEY must be set together "
            f"(got ca={bool(ca)} cert={bool(cert)} key={bool(key)}) — refusing a "
            "partial TLS config instead of silently downgrading to plaintext")
    import ssl as _ssl
    ctx = _ssl.create_default_context(purpose=_ssl.Purpose.SERVER_AUTH, cafile=ca)
    ctx.load_cert_chain(cert, key)
    return {"security_protocol": "SSL", "ssl_context": ctx}


# Built once at import: a broken TLS config fails the BOOT, loudly, not the
# Nth reconnect attempt at 3am.
KAFKA_SECURITY = kafka_security_kwargs()
CLICKHOUSE_URL   = os.environ.get("CLICKHOUSE_URL", "http://clickhouse:8123")
CLICKHOUSE_USER  = os.environ.get("CLICKHOUSE_USER", "netops")
CLICKHOUSE_PASS  = os.environ.get("CLICKHOUSE_PASSWORD", "")

TOPICS = ["netops.syslog", "netops.flows", "netops.metrics", "netops.probes", "netops.snmptrap", "netops.cloud", "netops.app.identities.v1", "netops.controller_events", "netops.app.edge", "netops.verification",
          # #128 Q7: DEDICATED wireless topics — session records and onboarding
          # observations must not starve SD-WAN/fabric controller events on a
          # shared partition set (wireless is the highest-volume producer).
          "netops.wireless_sessions", "netops.wireless_events"]

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
_tenant_map: dict[str, str] = {}
_tenant_mtime: float = -1.0
# How often the device->tenant registry file may be re-stat'ed (tracker 156).
# The exporter rewrites it every 60s; 1s keeps pickup effectively immediate
# while taking the syscall off the per-event path.
TENANT_STAT_EVERY_S = float(os.environ.get("CORR_TENANT_STAT_EVERY_S", "1.0"))
_tenant_stat_at: float = -1e9


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


def _tenant_registry() -> dict[str, str]:
    """The TRUSTED identity→tenant registry (device_tenant.csv, written by the Go
    API from the device inventory — src/backend/telemetry_enrichment.go).

    This file is the ONLY authority on which tenant owns a piece of telemetry.
    It is produced by the platform from its own inventory, one row per distinct
    device NAME and per distinct management ADDRESS, and an identity that maps
    to more than one tenant is OMITTED by the exporter (fail-safe) — so a hit
    here is unambiguous by construction.

    Cheap: re-reads the CSV only when its mtime changes."""
    global _tenant_map, _tenant_mtime, _tenant_stat_at
    # Tracker 156: this ran os.path.getmtime on EVERY event — one syscall per
    # syslog line, 40,000 in a 40,000-event profile. The writer refreshes the
    # CSV every 60s, so restatting more often than TENANT_STAT_EVERY_S buys
    # nothing. The mtime comparison below is unchanged; only how often we ask
    # the filesystem is.
    nowm = time.monotonic()
    # Only throttle once a map has actually been loaded: a first call, or a
    # caller that reset _tenant_mtime to force a reload, must still stat
    # immediately. Otherwise the throttle would delay the FIRST registry read,
    # which is exactly when events are most likely to be refused as
    # unattributable (tracker 159's registry-propagation edge).
    loaded = isinstance(_tenant_mtime, (int, float)) and _tenant_mtime >= 0
    if loaded and nowm - _tenant_stat_at < TENANT_STAT_EVERY_S:
        return _tenant_map
    _tenant_stat_at = nowm
    try:
        mt = os.path.getmtime(TENANT_ENRICHMENT_FILE)
    except OSError:
        return _tenant_map
    if mt != _tenant_mtime:
        _tenant_mtime = mt  # retry on the next mtime change (writer refreshes every 60s)
        fresh: dict[str, str] = {}
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
    return _tenant_map


def tenant_lookup(identity: str) -> str | None:
    """Registry lookup for one observed identity.

    Returns the registry's tenant for `identity` (which may legitimately be ""
    = platform-owned), or **None when the registry does not know the identity
    at all**. That distinction is the whole point: `tenant_for` collapses both
    cases to "global", which makes it a FALLBACK-FOR-ABSENCE and useless as a
    CHECK-ON-PRESENCE (TENANT-HIGH-3). `verified_tenant` needs to tell "the
    registry says platform" apart from "the registry has never heard of this"."""
    if not identity:
        return None
    return _tenant_registry().get(identity)


def tenant_for(device: str) -> str:
    """Resolve a device name/id to its canonical tenant id ("global" = the
    platform-global tenant — see canon_tenant). Cheap: re-reads the CSV only
    when its mtime changes.

    NOTE: this answers "what does the registry say about this device", NOT "is
    the tenant this event claims legitimate". Anything that consumes a
    SELF-DECLARED tenant_id off the bus must go through `verified_tenant`."""
    if not device:
        return canon_tenant("")
    return canon_tenant(tenant_lookup(device) or "")

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("correlation")


# ---------------------------------------------------------------------------
# TENANT CLAIM VERIFICATION (TENANT-HIGH-3/4 — CLAUDE.md §3a, default-closed)
#
# THE DEFECT THIS FIXES: tenant identity used to be ASSERTED by the sender and
# never VERIFIED by anyone. Every lane did
#
#     tenant = str(ev.get("tenant_id") or "") or tenant_for(<device>)
#
# i.e. the device→tenant registry was consulted ONLY when the payload carried
# no tenant. A payload that DID carry one — including one written by anything
# that can reach the bus, or (before this change) one re-derived from the
# attacker-controlled `devname=` field inside a FortiGate log BODY — was taken
# verbatim and persisted into that tenant's corr_signals. An empty tenant was
# dropped (good); a FORGED non-empty tenant was honoured (the hole).
#
# THE TRUST MODEL NOW:
#   • TRUSTED: device_tenant.csv, written by the Go API from its own inventory.
#     Nothing on the wire can change it.
#   • UNTRUSTED: every field of every bus event, `tenant_id` included. It is a
#     CLAIM, and a claim is only ever accepted when it REPRODUCES what the
#     registry says for an identity the event itself carries (syslog hostname,
#     flow sampler_address, metric/trap device, probe target, wireless
#     observer). The value we persist is always the REGISTRY's, never the
#     claim's — a verified claim and the registry agree, so there is nothing to
#     choose between.
#   • On disagreement we take NEITHER value: the event is refused, counted,
#     logged with a `SECURITY:` prefix and quarantined through the existing
#     durable dead-letter path. Same shape as the reference implementation in
#     src/backend/ticketing_worker.go:96-103.
#
# `registry_anchored=True` marks the lanes whose tenant is stamped by Vector
# SOLELY from this same registry (syslog, flows) — for those, a non-empty claim
# the registry cannot reproduce is by definition not something the pipeline
# produced, so an UNKNOWN identity is refused too (requirement (c): an
# unresolvable tenant fails closed). The remaining lanes carry tenants that
# genuinely have no device to resolve from (cloud accounts, app identities);
# there the registry can only ever CONTRADICT a claim, so it is used for
# exactly that and an unknown identity leaves the authenticated producer's
# claim standing.
#
# What this does NOT fix, stated plainly: an attacker who can reach the
# unauthenticated syslog port AND knows a victim's real device hostname still
# lands in that tenant's lane, because the registry genuinely maps that
# hostname to that tenant. Closing that needs transport authentication
# (RFC5425 TLS / per-source ACLs), not an app-layer check — see
# deployment/docker/syslog-ng/syslog-ng.conf.
# ---------------------------------------------------------------------------

TENANT_CLAIMS_VERIFIED = 0            # non-empty claims that matched the registry
TENANT_CLAIMS_REFUSED = 0             # events refused because the claim did not
TENANT_REFUSALS: dict[str, int] = {}  # "lane:reason" -> count
_TENANT_REFUSE_LOG_LAST: dict[str, float] = {}
# A hostile or misconfigured producer can refuse at full consume rate; the
# COUNTERS stay exact, the log line is rate-limited per (lane, reason).
TENANT_REFUSE_LOG_EVERY_S = float(os.environ.get("CORR_TENANT_REFUSE_LOG_EVERY_S", "30"))


class TenantClaimRefused(DeadLetter):
    """An event's SELF-DECLARED tenant_id could not be verified against the
    trusted device→tenant registry.

    A DeadLetter subclass on purpose: every lane already routes DeadLetter into
    the durable quarantine (keep_deadletter_payload → CORR_DLQ_DIR), so a
    refused event keeps its payload for forensics instead of vanishing. It is
    NEVER downgraded to "use the registry value anyway" — the two sources
    disagree about who owns the data, and guessing is the defect.

    EXCEPTION (F-11, INV-F11-10): the `identity_unattributable` class keeps NO
    payload — the ROUTER seals that very event under the quarantine key, and a
    plaintext copy here (ring + NDJSON) would be the durable confidentiality
    downgrade the owner invariant forbids. _quarantine_record keys on the
    `reason` attribute below to store metadata + identity hash only."""

    # Structured refusal facts, stamped by _tenant_refusal. Class defaults keep
    # older pickled/hand-built instances harmless.
    lane: str = ""
    reason: str = ""
    identity: str = ""


def _tenant_refusal(lane: str, reason: str, identity: str,
                    claimed: str, resolved: str) -> TenantClaimRefused:
    """Count + (rate-limited) log one refusal and build the exception to raise."""
    global TENANT_CLAIMS_REFUSED
    TENANT_CLAIMS_REFUSED += 1
    key = f"{lane}:{reason}"
    TENANT_REFUSALS[key] = TENANT_REFUSALS.get(key, 0) + 1
    now = time.monotonic()
    if (now - _TENANT_REFUSE_LOG_LAST.get(key, -1e9)) >= TENANT_REFUSE_LOG_EVERY_S:
        _TENANT_REFUSE_LOG_LAST[key] = now
        log.warning(
            "SECURITY: tenant claim refused — event quarantined, NOT persisted "
            "lane=%s reason=%s identity=%s claimed_tenant=%s registry_tenant=%s "
            "refused_total=%d",
            lane, reason, identity or "-", claimed or "-", resolved or "-",
            TENANT_REFUSALS[key])
    exc = TenantClaimRefused(
        f"tenant claim refused ({reason}): lane={lane} identity={identity or '-'} "
        f"claimed={claimed or '-'} registry={resolved or '-'}")
    exc.lane, exc.reason, exc.identity = lane, reason, identity
    return exc


def verified_tenant(claimed: str, identity: str, lane: str, *,
                    registry_anchored: bool = False) -> str:
    """Return the tenant this event may be persisted under, or raise.

    claimed  — the event's self-declared tenant_id (UNTRUSTED).
    identity — the observed device identity the event carries (syslog hostname,
               flow sampler_address, metric/trap device, probe target …).
    lane     — counter/log label.

    Contract:
      • no claim            → the registry decides; an identity the registry
                              does not know is the PLATFORM tenant ("global",
                              which the strict ClickHouse row policy keeps
                              platform-only), never another tenant's and never
                              a permissive wildcard.
      • claim == registry   → accepted (the registry's value is returned).
      • claim != registry   → REFUSED (raises), both lane kinds.
      • registry has no such identity:
          registry_anchored → REFUSED (the claim is unverifiable and this lane's
                              tenants only ever come from the registry).
          otherwise         → the authenticated producer's claim stands; the
                              registry had nothing to say about it.
    """
    global TENANT_CLAIMS_VERIFIED
    claim = str(claimed or "").strip()
    resolved = tenant_lookup(identity)
    if not claim:
        # F-11 (INV-F11-10): on a registry-ANCHORED lane an identity the
        # registry has never heard of is TENANT_UNATTRIBUTABLE — it must not
        # be processed as the platform tenant (that path reaches RCA and the
        # global tenant's ticketing/notification destinations). It joins the
        # same durable quarantine the contradicted-claim path uses. A registry
        # hit that maps a KNOWN platform device to "" still becomes "global":
        # platform self-monitoring is load-bearing and unchanged.
        if registry_anchored and resolved is None:
            raise _tenant_refusal(lane, "identity_unattributable", identity, "", "")
        return canon_tenant(resolved or "")
    if resolved is not None:
        if canon_tenant(resolved) == canon_tenant(claim):
            TENANT_CLAIMS_VERIFIED += 1
            return canon_tenant(resolved)
        raise _tenant_refusal(lane, "claim_mismatch", identity,
                              canon_tenant(claim), canon_tenant(resolved))
    if registry_anchored:
        raise _tenant_refusal(lane, "identity_unknown", identity,
                              canon_tenant(claim), "")
    return canon_tenant(claim)


# ---------------------------------------------------------------------------
# In-memory state for anomaly detection.
#
# Per-(device, metric) rolling window of recent samples. We keep a fixed
# window size so memory stays bounded; once the window has 20 samples
# we start scoring new arrivals against its mean + stddev.
# ---------------------------------------------------------------------------

WINDOW_SIZE = 200
Z_THRESHOLD = 3.0

# O(1) rolling-stats drift guard (perf defect #4): mean/stddev are maintained as
# shifted running sums (sum, sum-of-squares around a pivot) instead of a full
# O(window) pass per query — ~6 full 200-deque passes per metric sample saturated
# a core near 2-5k samples/s. Floating-point drift from incremental subtraction
# is bounded by an EXACT recompute every this-many pushes (amortized O(window/N)
# ≪ 1 op/sample) plus a clamp-and-recompute whenever variance goes negative.
STATS_RECOMPUTE_EVERY = 1024


@dataclass
class Series:
    values: deque[float] = field(default_factory=lambda: deque(maxlen=WINDOW_SIZE))
    # Shifted running aggregates: _sum/_sumsq accumulate (v - _shift) so a large
    # baseline mean with a small variance does not cancel catastrophically. The
    # shift re-pivots to the current mean at every exact recompute.
    _sum: float = 0.0
    _sumsq: float = 0.0
    _shift: float = 0.0
    _pushes: int = 0

    def _recompute(self) -> None:
        """Exact O(window) rebuild of the aggregates — the float-drift guard."""
        n = len(self.values)
        self._shift = (sum(self.values) / n) if n else 0.0
        self._sum = sum(v - self._shift for v in self.values)
        self._sumsq = sum((v - self._shift) ** 2 for v in self.values)

    def mean(self) -> float:
        n = len(self.values)
        return (self._shift + self._sum / n) if n else 0.0

    def stddev(self) -> float:
        n = len(self.values)
        if n < 2:
            return 0.0
        var = (self._sumsq - self._sum * self._sum / n) / (n - 1)
        if var < 0.0:
            # Cancellation artifact — rebuild exactly, then re-derive.
            self._recompute()
            var = max(0.0, (self._sumsq - self._sum * self._sum / n) / (n - 1))
        return var ** 0.5

    def push(self, v: float) -> None:
        if not self.values:
            # Pivot on the first sample: a 1e9-baseline series must not
            # accumulate (v − 0)² terms before the first periodic re-pivot.
            self._shift, self._sum, self._sumsq = v, 0.0, 0.0
        elif len(self.values) == self.values.maxlen:
            old = self.values[0] - self._shift
            self._sum -= old
            self._sumsq -= old * old
        self.values.append(v)
        d = v - self._shift
        self._sum += d
        self._sumsq += d * d
        self._pushes += 1
        if self._pushes % STATS_RECOMPUTE_EVERY == 0:
            self._recompute()


# Legacy z-score series, bounded + LRU. Unbounded before: keyed by
# (device, metric) with no eviction, so cardinality churn (ephemeral cloud
# resource ids arriving as `device`) grew it until the container hit its memory
# limit. Dropping the least-recently-scored series only costs it its warm-up.
# The cap is DERIVED from the container memory budget (series_budget.py): the
# old flat 200k default measured ~2.9 GiB at cap across this store + the
# episode detector's — the 768 MiB container OOM'd long before the cap engaged.
# CORR_MAX_SERIES still overrides verbatim.
# M29b: keyed by (tenant, entity, metric) — two tenants can legitimately own
# the same device name + metric (overlapping RFC1918 inventories), and a
# tenant-blind key averaged their baselines into one series: cross-tenant
# value leakage into the z-score AND wrong anomaly math for both.
SERIES: OrderedDict[tuple[str, str, str], Series] = OrderedDict()
SERIES_MAX = derive_max_series()
# M29a: LRU evictions were silent (§10) — a cardinality storm quietly ate every
# warm baseline and the only symptom was findings going quiet. Counted here,
# exposed on /healthz + /metrics, WARNed rate-limited below.
SERIES_EVICTED = 0
_SERIES_EVICT_LOG_LAST = -1e9
SERIES_EVICT_LOG_EVERY_S = 60.0

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
WIRELESS_RECEIVED = 0           # #128: wireless session/event records received
WIRELESS_SIGNALS = 0            # #128: onboarding-failure signals emitted
WIRELESS_DROPPED = 0            # #128: dropped — no tenant/identity (default-closed)
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
_CLOCK_SKEW_LAST: dict[tuple, float] = {}
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


def _chaos_fixture_for(snap: ObjectSnapshot) -> str:
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
TENANT_WA: dict[str, dict] = {}   # tenant -> raw/persisted/damped + kind/entity Counters
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
    ages: dict[str, float] = {}
    for reg in OPEN_OBJECTS.values():
        t = reg["snapshot"].tenant_id
        age = (now - reg.get("opened_at", now)).total_seconds()
        ages[t] = max(ages.get(t, 0.0), age)
    open_counts: dict[str, int] = {}
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
_FLOW_AGG: dict[tuple, dict] = {}   # (tenant, entity_id) -> {bytes, sampler}
# #98 Phase 4 — per-application flow volume, populated ONLY for records with a
# confirming attribution (explicit / appid-fusion / operator prefix map). The
# interface aggregation above is untouched: one flow can feed BOTH groundings.
_FLOW_APP_AGG: dict[tuple, dict] = {}   # (tenant, app_slug) -> {bytes, sampler, source, confidence}
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
_FLOW_DIR: dict[str, dict[tuple, float]] = {}
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
WINDOW_BUFFER: deque[Signal] = deque(
    maxlen=max(50_000, int(os.environ.get("CORR_WINDOW_BUFFER", "50000"))))
# Kafka delivery is at-least-once (auto-commit ~5s): a consumer restart
# re-delivers recent messages, and a duplicated signal_id in the window
# inflates snapshots and churns versions (found by basic testing — stored
# signal_count 14 vs 10 unique). The buffer therefore dedupes by signal id;
# the set is pruned alongside the buffer so memory stays bounded.
_BUFFERED_IDS: set[str] = set()
# The SAME ids, in window order, so eviction never recomputes one.
#
# TRACKER 156 (2026-08-20). `_prune_buffer` and the maxlen-eviction branch of
# `buffer_signal` both did `str(WINDOW_BUFFER[0].signal_id)` — a uuid5, i.e. a
# SHA-1 — for EVERY signal they evicted, inline on the event loop. buffer_signal
# had already computed that exact id at insert time to key the dedup set, so the
# work was pure recomputation, and it is unbounded: a 50,000-signal window aging
# out in one prune is 50,000 SHA-1s with no await in between. Captured live on
# 2026-08-20 as the top frame of a 30,989 ms stall — past the 30 s Kafka session
# timeout — while the container had ~800 MB of FREE memory, so it is a stall
# source entirely independent of memory pressure.
#
# Holding a second reference to a string that already lives in _BUFFERED_IDS
# costs a pointer per entry, not a string: ~400 KB at the 50k floor.
_BUFFERED_ID_ORDER: deque[str] = deque(
    maxlen=max(50_000, int(os.environ.get("CORR_WINDOW_BUFFER", "50000"))))
# Times the id deque had to be rebuilt because it drifted from the window.
# Should be 0 in production; non-zero means something mutated one without the
# other, which the self-heal makes SLOW and VISIBLE rather than WRONG.
WINDOW_ID_ORDER_RESYNCS = 0

# Housekeeping observability (tracker 156 architecture review, 2026-08-20).
# The 30,989 ms prune stall was findable ONLY because a bespoke forensic build
# captured stacks; the service itself exposed nothing about its own maintenance
# work. These are the minimum that make a prune regression visible in
# production: how often it runs, how much it evicts, and how long it holds the
# loop. Deliberately low-cardinality — no per-tenant labels.
PRUNE_CALLS = 0             # prune invocations (monotonic)
PRUNE_EVICTED = 0           # signals evicted by age (monotonic)
PRUNE_SECONDS_LAST = 0.0    # duration of the most recent prune (gauge)
PRUNE_SECONDS_MAX = 0.0     # worst prune this process has done (gauge)

# H14: event timestamps entering the LIVE window are bounded (see
# buffer_signal). Clamped-future / stale-past counts, exposed on /healthz —
# a device with a broken clock must be visible, never a silent re-stamp (§10).
EVENT_TS_FUTURE_CLAMPED = 0
EVENT_TS_PAST_STALE = 0
_TS_BOUND_LOG_LAST = -1e9      # rate-limits the WARN (one broken clock ≠ log storm)
TS_BOUND_LOG_EVERY_S = 60.0

# Open-object registry: correlation_id → persistence state. CH stays append-
# only; this is the engine's working memory (PG corr_active wiring follows
# with the ops lifecycle build).
OPEN_OBJECTS: dict[str, dict] = {}
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
            for section, by_tenant in grouped.items():
                for row in raw.get(section) or []:
                    by_tenant.setdefault(str(row.get("tenant_id") or ""), []).append(row)
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


def _head_for_scope(heads: dict[str, DnsHead], src: str, dst: str) -> DnsHead | None:
    """Attach a DNS head to a scope ONLY when the name it resolved points at the scope's
    frontend endpoint (dst, else src) — never force a head onto an unrelated path."""
    for key in (dst, src):
        if key and key in heads:
            return heads[key]
    return None


def discovery_paths_for(tenant: str, view: PathGraphView,
                        window: list | tuple = ()) -> tuple[AssembledPath, ...]:
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
        measured_groups: dict[tuple[str, str], list] = {}
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
    # H14: bound the DEVICE-supplied event timestamp at the same chokepoint.
    # _prune_buffer pops from the LEFT of this arrival-ordered deque while
    # ts < horizon — so ONE far-future head signal (a device clock years ahead)
    # stopped pruning for EVERY tenant until restart. The metric lane already
    # bounds its clock (handle_metric, METRIC_FUTURE_SKEW_S/METRIC_MAX_AGE_S);
    # the syslog/trap/probe lanes trusted the device verbatim. A future ts past
    # the same skew is clamped to arrival time (the honest estimate — the event
    # DID just arrive; the device clock is the thing that's broken), preserving
    # the signal's stored identity so window dedup, the archive slice and
    # replay keep comparing the id the corr_signals row was written under. A
    # ts too far in the PAST is deliberately NOT re-stamped — fabricating
    # freshness would corrupt cause/effect order, and the arrival-ordered deque
    # ages a stale head out on the very next prune — but it is counted, so a
    # device stuck in the past is visible instead of silently never
    # correlating. Both counts surface on /healthz + /metrics.
    global EVENT_TS_FUTURE_CLAMPED, EVENT_TS_PAST_STALE, _TS_BOUND_LOG_LAST
    arrival = datetime.now(timezone.utc)
    age_s = (arrival - sig.ts).total_seconds()
    if age_s < -METRIC_FUTURE_SKEW_S or age_s > METRIC_MAX_AGE_S:
        mono = time.monotonic()
        if (mono - _TS_BOUND_LOG_LAST) >= TS_BOUND_LOG_EVERY_S:
            _TS_BOUND_LOG_LAST = mono
            log.warning(
                "event ts out of bounds (age=%.0fs, %s) tenant=%s entity=%s kind=%s — "
                "future is clamped to arrival, past ages out of the window",
                age_s, "future" if age_s < 0 else "past",
                sig.tenant_id, sig.entity_id, sig.kind)
        if age_s < 0:
            EVENT_TS_FUTURE_CLAMPED += 1
            sig = dc_replace(sig, ts=arrival, stored_signal_id=str(sig.signal_id))
        else:
            EVENT_TS_PAST_STALE += 1
    sid = str(sig.signal_id)
    if sid in _BUFFERED_IDS:
        return  # at-least-once redelivery — the window already holds it
    # The deque is maxlen-bounded (§9): once full, append() silently evicts the
    # OLDEST signal. Drop that signal's id from the dedup set in lockstep — else the
    # set leaks unboundedly under a flood AND a later redelivery of an evicted signal
    # would be wrongly deduped (dropped) because its stale id lingers in the set.
    _sync_buffered_id_order()
    if len(WINDOW_BUFFER) == WINDOW_BUFFER.maxlen:
        # The window is FULL and about to drop its oldest signal to make room.
        # Not data loss — the signal is already in corr_signals — but it IS a
        # silent narrowing of the correlation horizon, which the 2026-08-20
        # review flagged as the one place state is shed with no counter. Now it
        # is countable, so "RCA got thinner under storm" is a visible fact.
        global WINDOW_OVERFLOW_DROPPED
        WINDOW_OVERFLOW_DROPPED += 1
        _BUFFERED_IDS.discard(_BUFFERED_ID_ORDER[0])
    _BUFFERED_IDS.add(sid)
    # Appended in lockstep, and both deques carry the SAME maxlen, so a full
    # deque drops its head from both at once and the two stay aligned.
    WINDOW_BUFFER.append(sig)
    _BUFFERED_ID_ORDER.append(sid)
    # #101 write-amp accounting: raw lane pressure per tenant (post-dedup, so a
    # redelivered signal never double-counts).
    _wa_note_raw(sig)


def _sync_buffered_id_order() -> None:
    """Rebuild the id deque if it has drifted from the window.

    Drift is impossible on the production paths — both deques are appended and
    popped together in this module — but a test that clears one and not the
    other, or a future edit that touches only one, must degrade to
    CORRECT-and-slow rather than to silently wrong. The rebuild is the old
    expensive behaviour, done once and counted, instead of the old expensive
    behaviour done forever and unnoticed.
    """
    global WINDOW_ID_ORDER_RESYNCS
    if len(_BUFFERED_ID_ORDER) == len(WINDOW_BUFFER):
        return
    WINDOW_ID_ORDER_RESYNCS += 1
    _BUFFERED_ID_ORDER.clear()
    _BUFFERED_ID_ORDER.extend(str(sig.signal_id) for sig in WINDOW_BUFFER)


# Maximum signals evicted between yields. The ARCHITECTURAL INVARIANT this
# serves (2026-08-20 review): no maintenance operation may perform unbounded
# synchronous work on the correlation event loop.
#
# The prune still completes fully in one call — partial pruning would leave
# expired signals in the window that `by_tenant` then feeds to run_window,
# silently changing RCA semantics. What is bounded is the CONTIGUOUS block: the
# work is the same, the loop gets it back every chunk. This is the same shape as
# Flink's incremental state cleanup — bound the slice, not the job.
#
# 5,000 measured at ~6 ms per chunk (60.3 ms for a full 50k eviction), so a
# worst-case full-window prune yields ten times and never holds the loop for
# more than single-digit milliseconds.
CORR_PRUNE_CHUNK = int(os.environ.get("CORR_PRUNE_CHUNK", "5000"))
PRUNE_YIELDS = 0            # loop hand-backs during pruning (monotonic)
# Signals dropped because the window was FULL, not because they aged out. The
# name ends in _DROPPED so the counter-exposure contract discovers it
# automatically and fails if it is ever left off /healthz.
WINDOW_OVERFLOW_DROPPED = 0


async def _prune_buffer(now: datetime) -> None:
    global PRUNE_CALLS, PRUNE_EVICTED, PRUNE_SECONDS_LAST, PRUNE_SECONDS_MAX
    global PRUNE_YIELDS
    horizon = now.timestamp() - ENGINE_CFG.window_s
    _sync_buffered_id_order()
    evicted = 0
    worst_block = 0.0
    while True:
        block_started = time.monotonic()
        chunk = 0
        while (WINDOW_BUFFER and WINDOW_BUFFER[0].ts.timestamp() < horizon
               and chunk < CORR_PRUNE_CHUNK):
            # The id was computed once, at insert. Popping it is O(1);
            # recomputing it was a SHA-1 per evicted signal (tracker 156).
            _BUFFERED_IDS.discard(_BUFFERED_ID_ORDER.popleft())
            WINDOW_BUFFER.popleft()
            chunk += 1
        worst_block = max(worst_block, time.monotonic() - block_started)
        evicted += chunk
        if chunk < CORR_PRUNE_CHUNK:
            break          # nothing left to expire
        PRUNE_YIELDS += 1
        await asyncio.sleep(0)   # hand the loop back: heartbeat, fetch, commit
    PRUNE_CALLS += 1
    PRUNE_EVICTED += evicted
    # The gauge reports the worst CONTIGUOUS block, not total elapsed — blocking
    # is what threatens Kafka membership, and total elapsed across yields does
    # not.
    PRUNE_SECONDS_LAST = worst_block
    PRUNE_SECONDS_MAX = max(PRUNE_SECONDS_MAX, worst_block)


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


# ── Stage [8] archive sizing (perf defect #3: archive amplification) ─────────
# Every persisted version used to archive the ENTIRE tenant window (50k floor)
# — N spray-minted objects per cycle × full window = ~1M rows/30s at N=20, each
# batch serialized as one multi-MB NDJSON string on the event loop. The slice is
# now BOUNDED and NODE-COMPLETE (see _archive_slice) and re-archiving an
# UNCHANGED slice for the same object is skipped (readers — replay._select_slice
# and the Go timeline query — already fall back to the newest archived_version
# ≤ the requested one, exactly as close-versions have always relied on).
CORR_ARCHIVE_CHUNK_ROWS = int(os.environ.get("CORR_ARCHIVE_CHUNK_ROWS", "10000"))


# ── P1 regression (1000-device scale, 2026-08-17): bound event-loop blocking ──
#
# MEASURED ROOT CAUSE. The mini-ladder's 1000-device fleet emits one uniform
# signature, so the whole access layer folds into a FEW ENORMOUS objects —
# live evidence from netops-correlation-2:
#
#   03:34:47Z  corr-object 859c45d9 v4 open: ... nodes=750 edges=48375
#
# Object COUNT stayed small (5–15 per cycle, verified in netops.corr_objects),
# but every per-object step is a SINGLE MONOLITHIC synchronous call whose cost
# scales with the graph, measured on the real 750-node/48,375-edge shape:
#
#   content_hash()          1.60s     to_object_row()        0.66s
#   material_hash()         0.13s     to_typed_edge_rows()   0.40s
#   to_evidence_rows()      0.31s     to_edge_rows()         0.16s
#   CH.insert body build    0.68s     batcher token hash     0.93s
#   → ~7.5s of UNINTERRUPTIBLE loop time per object per cycle
#   → 10–15 objects = 75–110s frozen, which is exactly the 84s / 193s / 421s
#     stalls in the container log
#
# Consequence: aiokafka's BACKGROUND heartbeat task cannot run, so the broker
# expires the session (30s) → "Heartbeat session expired" → UnknownMemberIdError
# → the commit fails (CommitFailedError, poll gap past max_poll_interval) → the
# batch replays → repeat. Cooperative `await asyncio.sleep(0)` yields (the
# earlier P1 fix) CANNOT help here: no single one of these calls is
# interruptible, so there is no point at which a yield could run.
#
# THE FIX, bounded BY DESIGN rather than by tuning: every size-unbounded
# pure-CPU step goes through `_offload` below. Measured on the same object:
# inline froze the loop for 2.40s; via the executor the worst loop latency was
# 0.39s — the loop (and the heartbeat) keeps running no matter how large the
# object gets, because the blocking call no longer owns the loop thread.
# Threshold: payloads below CORR_OFFLOAD_MIN_ELEMENTS keep today's exact inline
# path (a thread hand-off costs more than the work), and 2000 elements measures
# at ~0.1s — 30x under the 3s heartbeat interval, so the inline branch is
# provably bounded too.
CORR_OFFLOAD_MIN_ELEMENTS = int(os.environ.get("CORR_OFFLOAD_MIN_ELEMENTS", "2000"))


async def _offload(fn, /, *args, **kwargs):
    """Run a size-unbounded PURE-CPU call off the event loop.

    The default thread-pool executor: the call still holds the GIL, but it no
    longer owns the LOOP THREAD, so the loop's own tasks — critically
    aiokafka's heartbeat and fetch coroutines — are scheduled at the
    interpreter's switch interval instead of waiting out the whole call.
    Only for PURE functions (no shared mutable state, no IO): everything
    routed here is a serializer/hasher over an immutable snapshot.
    """
    return await asyncio.get_running_loop().run_in_executor(
        None, functools.partial(fn, *args, **kwargs))


def _snap_elements(snap: ObjectSnapshot) -> int:
    """Graph size driving every per-object serialization cost above."""
    return len(snap.nodes) + len(snap.edges)


async def _snap_call(snap: ObjectSnapshot, fn, /, *args, **kwargs):
    """One per-object pure call, offloaded only when the object is big enough
    for the sync cost to threaten the heartbeat (see CORR_OFFLOAD_MIN_ELEMENTS)."""
    if _snap_elements(snap) >= CORR_OFFLOAD_MIN_ELEMENTS:
        return await _offload(fn, *args, **kwargs)
    return fn(*args, **kwargs)


ARCHIVE_ROWS_WRITTEN = 0     # archive rows actually inserted (monotonic)
ARCHIVE_SLICES_DAMPED = 0    # re-persists whose slice membership was unchanged
_ARCHIVE_SLICE_HASH: dict[str, str] = {}  # cid → last successfully archived slice id-hash


@dataclass(frozen=True)
class _WindowIndex:
    """The window grouping every object version of one cycle shares.

    TRACKER 156. `_archive_slice` used to rebuild this per OBJECT: it walked the
    whole tenant window, bucketed every signal by node key, and recomputed each
    bucket's min/max ts — so the work was O(objects x window) and, as the tracker
    put it, "sized by the whole 50k-floor WINDOW rather than by the object". The
    grouping depends only on the window, so it is built ONCE per cycle here and
    the per-object step is reduced to the overlap test that actually varies.

    `nodes` is pre-sorted by key so `keep` is assembled in the same order the
    per-object build produced; the final sort is unchanged. Slices therefore stay
    byte-identical — pinned by test_replay_archive_slice.py.
    """
    nodes: tuple[tuple[str, list[Signal], object, object], ...]
    loose: tuple[tuple[Signal, str], ...]
    # id(signal) -> str(signal_id), and id(signal) -> position in the window's
    # canonical (ts, signal_id) order. Both are computed ONCE per cycle here
    # instead of once per object: stringifying a UUID and re-sorting the slice
    # were 1.08M calls and 120 full sorts in one profiled cycle. Keying by id()
    # is safe because the window list holds a strong reference to every signal
    # for the whole life of the index, and the index dies with the cycle.
    sid: dict[int, str]
    ordinal: dict[int, int]


_WINDOW_INDEX_CACHE: dict[int, tuple[int, _WindowIndex]] = {}

# Per-CYCLE archive row cache, keyed by signal id (tracker 156). The archive
# converts the same window signal to a row once per OPEN OBJECT — 360,000
# to_ch_row calls in one profiled cycle, each re-running json.dumps over attrs.
# Caching on the Signal itself was measured and rejected: a Signal lives in
# WINDOW_BUFFER, so a memo there is retained for the whole window lifetime and
# costs RSS, which is the resource correlation actually runs out of. This cache
# is cleared at the top of every engine_cycle, so it is transient by
# construction — it exists only while the cycle that populated it is running.
_CYCLE_ROW_CACHE: dict[int, dict] = {}


def _sid_of(window: list[Signal], sig: Signal) -> str:
    """This cycle's cached str(signal_id), falling back to computing it."""
    got = _window_index(window).sid.get(id(sig))
    return got if got is not None else sig.signal_id_str


def _archive_row(sig: Signal, corr_id: str, version: int) -> dict:
    """One archive row, reusing this cycle's base row for `sig` if we built one.

    Always returns a FRESH dict (and a fresh entity_tokens list), because the
    caller stamps archived_for/archived_version onto it and every object needs
    its own stamps.
    """
    key = id(sig)
    base = _CYCLE_ROW_CACHE.get(key)
    if base is None:
        base = sig.to_ch_row()
        _CYCLE_ROW_CACHE[key] = base
    row = dict(base)
    row["entity_tokens"] = list(base["entity_tokens"])
    row["archived_for"] = corr_id
    row["archived_version"] = version
    return row


def _window_index(window: list[Signal]) -> _WindowIndex:
    """Build (or reuse) the per-cycle index for `window`.

    Keyed by id() AND length: engine_cycle hands the same list object to every
    object version of one tenant within a cycle, and the list is rebuilt each
    cycle. The length guard means a recycled id() cannot serve a stale index for
    a different window; the cache is cleared per cycle regardless (see
    engine_cycle) so this is belt-and-braces, not the correctness argument.
    """
    key = id(window)
    hit = _WINDOW_INDEX_CACHE.get(key)
    if hit is not None and hit[0] == len(window):
        return hit[1]
    sid = {id(s): s.signal_id_str for s in window}
    ordinal = {id(s): i for i, s in enumerate(
        sorted(window, key=lambda s: (s.ts, sid[id(s)])))}
    by_node: dict[str, list[Signal]] = {}
    loose: list[tuple[Signal, str]] = []
    for s in window:
        if s.kind.endswith("_clear") or s.source is Source.APP_IDENTITY:
            loose.append((s, sid[id(s)]))
            continue
        by_node.setdefault(f"{s.entity_type.value}:{s.entity_id}:{s.kind}", []).append(s)
    nodes = []
    for k in sorted(by_node):
        sigs = by_node[k]
        nodes.append((k, sigs, min(s.ts for s in sigs), max(s.ts for s in sigs)))
    idx = _WindowIndex(nodes=tuple(nodes), loose=tuple(loose), sid=sid, ordinal=ordinal)
    _WINDOW_INDEX_CACHE[key] = (len(window), idx)
    return idx


def _archive_slice(snap: ObjectSnapshot, window: list[Signal]) -> list[Signal]:
    """The BOUNDED, replay-exact archive slice for one object version.

    Contents:
      * every signal of every evidence NODE (same (entity_type, entity_id, kind)
        grouping as engine.build_nodes) whose activity interval [first ts, last
        ts] overlaps the object's [window_start, window_end] — nodes are never
        CLIPPED, so each included node is byte-identical to its live twin;
      * every non-node signal (kind *_clear, source=app_identity — both excluded
        from build_nodes) inside the object's bounds, plus the identity signals
        this object actually matched (snap.identity_signals), so the Inspector
        timeline and the app-impact enrichment reproduce.

    Replay exactness argument (pinned by test_replay_archive_slice.py):
    edge admission is PAIR-LOCAL (resolve_grounding reads only the two nodes +
    the embedded seams/adjacency/paths context), so restricting the window to a
    node-complete subset that contains the whole component reproduces the SAME
    component — every component node overlaps [window_start, window_end] by
    construction (those bounds ARE the component's min/max ts), included nodes
    carry all their signals (identical tokens/onset/intervals ⇒ identical pair
    verdicts), and an excluded node could only have joined through an edge the
    live run would also have admitted — contradiction with it not being in the
    component. Ranking/verdict/confidence are component-local. What legitimately
    differs on replay: the window-global gap-hint COUNT (not diffed, not part of
    the stored row set) — the trade for not re-writing the full tenant window
    per object version.
    """
    idx = _window_index(window)
    ws, we = snap.window_start, snap.window_end
    matched_identities = {s.signal_id_str for s in snap.identity_signals}
    order = idx.ordinal
    keep: list[Signal] = []
    for s, sid in idx.loose:
        if (ws <= s.ts <= we) or sid in matched_identities:
            keep.append(s)
    for _key, sigs, lo, hi in idx.nodes:
        if lo <= we and ws <= hi:
            keep.extend(sigs)
    # Same order as sorting by (ts, signal_id) — the ordinal IS that order,
    # computed once per cycle rather than once per object.
    keep.sort(key=lambda s: order[id(s)])
    return keep


async def _persist_snapshot(snap: ObjectSnapshot, version: int, state: str,
                            window: list[Signal], merged_into: str = "") -> None:
    assert ch is not None
    # P1 (1000-device scale): every serializer below is offloaded for a large
    # graph — see _offload. On the live 48,375-edge object these four calls plus
    # the token hash were ~3.2s of frozen loop; the heartbeat task died in them.
    obj_row = await _snap_call(snap, snap.to_object_row, version, state, merged_into)
    # H13: these engine-cycle writes run OUTSIDE any consumer message, so they
    # must not draw tokens from the consumer's Kafka coordinate (a redelivery
    # resets that seq, colliding a NEW object version's token with a spent one
    # → ClickHouse silently drops the new version). The object version itself
    # is the idempotency key: a retry of the SAME (cid, version, state,
    # content) dedups, any new version/state/content mints a fresh token. The
    # content-hash suffix guards the restart edge where OPEN_OBJECTS resets
    # and version numbering restarts at 1 with different content.
    tok = (f"obj:{snap.correlation_id}:v{version}:{state}:"
           f"{(await _snap_call(snap, snap.content_hash))[:16]}")
    await ch_insert("netops.corr_objects", [obj_row],
                    dedup_token=f"{tok}:objects",
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
        if not await ch_insert("netops.corr_current", [current_row],
                               dedup_token=f"{tok}:current"):
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
            await _snap_call(snap, snap.material_hash), retryable, err,
        )
    edge_rows = await _snap_call(snap, snap.to_edge_rows, version)
    if edge_rows:
        await ch_insert("netops.corr_edges", edge_rows,
                        dedup_token=f"{tok}:edges",
                        corr_id=snap.correlation_id, version=version)
        # Contract §5: the typed edge + its evidence block (edge_type, method, rank,
        # evidence_class, evidence_ref, observation_method, confidence, observed_at,
        # data_class). corr_edges' frozen Enum8 grounding_kind cannot express these and
        # grounding_ref is NOT overloaded to smuggle them — they go to their own table
        # once the backend migration lands (CORR_EDGES_V2). Until then they are still
        # emitted: embedded in the snapshot's grounding context (replay-safe) and served
        # from there.
        if CORR_EDGES_V2:
            await ch_insert(CORR_PATH_EDGES_TABLE,
                            await _snap_call(snap, snap.to_typed_edge_rows, version))
    ev_rows = await _snap_call(snap, snap.to_evidence_rows, version)
    if ev_rows:
        await ch_insert("netops.corr_evidence", ev_rows,
                        dedup_token=f"{tok}:evidence",
                        corr_id=snap.correlation_id, version=version)
    # Stage [8] archive: a BOUNDED, node-complete slice of the tenant window
    # (see _archive_slice — replay-exact for THIS object, no longer the whole
    # 50k-floor tenant window per object version). Slices stay version-scoped:
    # replay re-runs exactly the window slice THIS version was computed from.
    global ARCHIVE_ROWS_WRITTEN, ARCHIVE_SLICES_DAMPED
    slice_sigs = _archive_slice(snap, window)
    if slice_sigs:
        slice_hash = hashlib.sha256(
            "|".join(_sid_of(window, s) for s in slice_sigs).encode()).hexdigest()[:16]
        if _ARCHIVE_SLICE_HASH.get(snap.correlation_id) == slice_hash:
            # Same membership as the last archived version of this object —
            # skip the re-write. Readers (replay._select_slice, the Go timeline
            # archived_version fallback) resolve to the newest slice ≤ version.
            ARCHIVE_SLICES_DAMPED += 1
        else:
            # Chunked, and BUILT per chunk (tracker 156). Chunking only the
            # INSERT still materialised the whole slice as row dicts first, so
            # peak transient memory was slice_size x ~1 KB — tens of MB per
            # object version, per cycle, in the container that runs closest to
            # its cgroup cap. Building inside the loop bounds that peak to
            # CORR_ARCHIVE_CHUNK_ROWS rows regardless of slice size, while the
            # insert bodies and the loop yields are unchanged. All chunks must
            # land before the slice hash is recorded — a partial slice must be
            # retried whole on the next persist.
            all_ok = True
            for start in range(0, len(slice_sigs), CORR_ARCHIVE_CHUNK_ROWS):
                chunk = [_archive_row(sig, snap.correlation_id, version)
                         for sig in slice_sigs[start:start + CORR_ARCHIVE_CHUNK_ROWS]]
                ok = await ch_insert(
                    "netops.corr_signals_archive", chunk,
                    corr_id=snap.correlation_id, version=version, row_count=len(chunk))
                if ok is False:
                    all_ok = False
                else:
                    ARCHIVE_ROWS_WRITTEN += len(chunk)
            if all_ok:
                _ARCHIVE_SLICE_HASH[snap.correlation_id] = slice_hash
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
    """One evaluation, with the per-cycle caches guaranteed to die with it.

    Tracker 156: `_WINDOW_INDEX_CACHE` and `_CYCLE_ROW_CACHE` make one cycle's
    repeated work cheap, and both are scoped to THIS cycle. They are cleared on
    the way IN (so no early return or exception can leave a previous cycle's
    window retained) and again on the way OUT (so nothing is held while the
    engine is idle between cycles — holding a 50k-row base-row cache between
    cycles would trade the on-loop win for exactly the RSS this tracker exists
    to reduce).
    """
    _WINDOW_INDEX_CACHE.clear()
    _CYCLE_ROW_CACHE.clear()
    try:
        await _engine_cycle_inner()
    finally:
        _WINDOW_INDEX_CACHE.clear()
        _CYCLE_ROW_CACHE.clear()


async def _engine_cycle_inner() -> None:
    """One evaluation: prune window, partition by tenant, run the pure core,
    persist version increments, close quiesced objects."""
    global LAST_GAP_HINTS, VERSIONS_PERSISTED, VERSIONS_DAMPED
    if ch is None:
        return
    now = datetime.now(timezone.utc)
    await _prune_buffer(now)
    # C6: flush this cycle's accumulated flow volume → passive_flow episodes BEFORE
    # partitioning, so the new flow signals join the same window they were measured in.
    await _flush_flow_aggregator(now)
    # §8 degradation, declared on every snapshot scored under it (never silent):
    topo_stale = _topology_stale(now)
    storm = len(WINDOW_BUFFER) >= STORM_BUFFER_FRACTION * (WINDOW_BUFFER.maxlen or 1)
    if topo_stale or storm:
        log.warning("engine degradation: topology_stale=%s storm_mode=%s (buffer=%d/%s)",
                    topo_stale, storm, len(WINDOW_BUFFER), WINDOW_BUFFER.maxlen)
    by_tenant: dict[str, list[Signal]] = {}
    for s in WINDOW_BUFFER:
        by_tenant.setdefault(s.tenant_id, []).append(s)
    # P1 max-poll thrash: the prune + partition pass above is pure sync over a
    # buffer that can hold 50k signals in a storm — hand the loop back to the
    # consumer/heartbeat tasks before the per-tenant work starts.
    await asyncio.sleep(0)

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
            # Perf defect #1c: run_window is pure CPU work (seconds-to-minutes on a
            # storm window) and used to run SYNCHRONOUSLY on the loop hosting the
            # Kafka consumer and /healthz — a broad fault blocked heartbeats until
            # the group rebalanced the consumer out and the healthcheck flapped.
            # It now runs in the default thread-pool executor. The ENGINE stays
            # pure/deterministic (no IO/clock/randomness inside run_window); the
            # executor is strictly a main.py call-site concern, and the inputs are
            # snapshotted (tuple) so concurrent buffer appends can never leak in.
            snapshots = await asyncio.get_running_loop().run_in_executor(
                None,
                functools.partial(
                    run_window, tuple(window), CATALOG, seams, ENGINE_CFG,
                    adjacency=adjacency, topology_stale=topo_stale, storm_mode=storm,
                    directed=directed, paths=pgv, discovery=discovery))
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
    # Per-cycle continuation index (tracker 162): open objects bucketed by
    # tenant, built ONCE, with a shared entity-set cache. `materialized` is
    # fixed for the cycle so it is filtered here; `seen_this_cycle` grows as we
    # go, so it is passed through as an exclusion instead.
    cont_index: dict[str, list] = {}
    for _cid, _reg in OPEN_OBJECTS.items():
        if _cid in materialized:
            continue
        _snap = _reg["snapshot"]
        cont_index.setdefault(_snap.tenant_id, []).append(_snap)
    cont_entities: dict[str, frozenset] = {}
    for tenant, window, snapshots in evaluated:
        # P1 max-poll thrash: a damped-heavy cycle walks every snapshot with
        # no awaits (content_hash is sync CPU) — yield per tenant so the
        # consumer's poll cadence survives a storm cycle.
        await asyncio.sleep(0)
        for snap in snapshots:
            gap_hints += snap.gap_hints
            reg = OPEN_OBJECTS.get(snap.correlation_id)
            if reg is None:
                # TRACKER 162. This used to rebuild the whole candidate list
                # inside the loop — O(open_objects) per snapshot, so
                # O(snapshots x open_objects) of pure list-building per cycle,
                # on the event loop, before find_continuation even started
                # recomputing every candidate's entity set.
                #
                # The tenant bucket is an EXACT index, not a heuristic: the very
                # first thing find_continuation does is skip any candidate whose
                # tenant differs (§3a, default-closed), so a cross-tenant object
                # could never have won. Excluding it earlier removes work the
                # contract already forbade using.
                cont = find_continuation(
                    snap, cont_index.get(snap.tenant_id, ()),
                    exclude=seen_this_cycle, entity_cache=cont_entities)
                if cont:
                    snap = dc_replace(snap, correlation_id=cont)
                    reg = OPEN_OBJECTS[cont]
                    log.info("corr-object %s continued under re-keyed window (identity adopted, no tombstone)",
                             cont[:8])
            seen_this_cycle.add(snap.correlation_id)
            # P1 (1000-device scale): content_hash on the live 48,375-edge
            # object is a 1.6s uninterruptible json.dumps+sha256 — offloaded.
            chash = await _snap_call(snap, snap.content_hash)
            if reg is None:
                OPEN_OBJECTS[snap.correlation_id] = {
                    "version": 1, "hash": chash,
                    "material": await _snap_call(snap, snap.material_hash),
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
                mhash = await _snap_call(snap, snap.material_hash)
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
        _ARCHIVE_SLICE_HASH.pop(merged_cid, None)

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
            _ARCHIVE_SLICE_HASH.pop(cid, None)
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
        except Exception:
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
    await batch_signal(row)  # batched: lane=metrics (perf defect #2)
    if modality is ModalityClass.DEVICE_TELEMETRY:
        DEVICE_TELEMETRY_SIGNALS += 1
    # Build ⑥: every spine signal also feeds the engine's evidence window.
    buffer_signal(sig)
    log.info("episode %s: %s/%s peak=%.1fσ ±%.0fs", ev.phase, ev.key[1],
             ev.key[2], ev.peak_deviation, ev.onset_uncertainty_s)
    return True  # an episode signal was emitted this sample


def score(tenant: str, device: str, metric: str, value: float) -> float | None:
    """Return a |z-score| if the value is anomalous, else None. Keyed by the
    VERIFIED tenant (M29b) so same-named devices in different tenants never
    share a baseline."""
    global SERIES_EVICTED, _SERIES_EVICT_LOG_LAST
    key = (tenant, device, metric)
    s = SERIES.get(key)
    if s is None:
        s = Series()
        SERIES[key] = s
        while len(SERIES) > SERIES_MAX:
            SERIES.popitem(last=False)
            # M29a: eviction is legitimate LRU behaviour but never silent —
            # sustained evictions mean cardinality churn is eating warm
            # baselines and the z-score lane is quietly degrading.
            SERIES_EVICTED += 1
            mono = time.monotonic()
            if (mono - _SERIES_EVICT_LOG_LAST) >= SERIES_EVICT_LOG_EVERY_S:
                _SERIES_EVICT_LOG_LAST = mono
                log.warning("z-score series LRU eviction (cap=%d, evicted_total=%d) — "
                            "cardinality churn is recycling baselines", SERIES_MAX, SERIES_EVICTED)
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

# Inserts that legitimately span more than one tenant, by table. A rollup that
# summarises EVERY tenant's window in one batch (corr_tenant_write_amp) cannot
# be written at a single tenant's scope; anything else showing up here means a
# lane started smuggling mixed-tenant batches and wants investigating.
CH_CROSS_TENANT_INSERTS: dict[str, int] = {}


def _ndjson_body(rows: list[dict]) -> str:
    """The ClickHouse JSONEachRow body for `rows`. Split out so the large-batch
    case can run through `_offload` (P1: a 48k-row body is 0.68s of otherwise
    uninterruptible event-loop time). PURE — safe in a worker thread."""
    return "\n".join(json.dumps(r) for r in rows)


def _batch_token(rows: list[dict]) -> str:
    """Content-hash dedup token for a retained batch (see CHBatcher._insert_batch).
    Split out for the same reason as _ndjson_body — measured 0.93s at 48k rows."""
    return "batch:" + hashlib.sha256(
        "\n".join(json.dumps(r, sort_keys=True, default=str)
                  for r in rows).encode()).hexdigest()[:32]


def insert_scope(rows: list[dict]) -> str:
    """The `tenant_scope` custom setting one INSERT is issued under.

    Derived from the ROWS, never from a caller-supplied default — mirroring
    src/backend/chhttp's rule that Scope is REQUIRED because every default is
    wrong ("__all__" defeats isolation, "__none__" silently returns nothing).

    HONEST SCOPE NOTE: ClickHouse row policies are `FOR SELECT` only, so this
    setting does NOT reject a mis-tenanted INSERT on its own. What it does buy:
    (a) the insert is executed in the row's OWN tenant context, so any policy
    re-evaluated during the write (a materialized view selecting from a
    policy-protected table — the exact failure that forced flows_hourly to be
    dropped, see src/backend/clickhouse_policies.go:16-19) sees the row's scope
    instead of an unset setting or a wildcard; (b) a cross-tenant batch has to
    announce itself and is counted. The control that actually stops a forged
    tenant reaching a row is `verified_tenant` at intake.
    """
    scopes = {str(r.get("tenant_id", "")) for r in rows if "tenant_id" in r}
    if len(scopes) == 1 and len(rows) == len([r for r in rows if "tenant_id" in r]):
        return scopes.pop()
    # Mixed tenants (the per-tenant write-amp rollup) or a table with no tenant
    # column: the only honest scope is the explicit cross-tenant one. Counted
    # per table so it can never grow quietly.
    return "__all__"


@dataclass(frozen=True)
class InsertOutcome:
    """What actually happened to one ClickHouse insert (tracker 160).

    `committed` is the only thing most callers need. The rest exists so the
    batcher can tell a TRANSIENT failure (retry it) from a PERMANENT one
    (quarantine immediately — retrying a schema error just delays the same
    loss while the backlog grows), and so the dead-letter record can say WHY
    rather than being an unclassifiable blob.
    """
    committed: bool
    kind: str = ""            # committed | rejected | transport | empty
    status: int = 0
    ch_code: int = 0
    query_id: str = ""
    error: str = ""
    rows: int = 0
    nbytes: int = 0

    def as_evidence(self) -> dict:
        return {"kind": self.kind, "status": self.status, "ch_code": self.ch_code,
                "query_id": self.query_id, "error": self.error,
                "rows": self.rows, "bytes": self.nbytes}


# ClickHouse exception codes worth retrying: the server was momentarily unable,
# not permanently unwilling. Deliberately a SMALL allowlist — anything not named
# here is treated as permanent and quarantined at once, because retrying a
# schema or parse error cannot succeed and only delays the loss.
#   241 MEMORY_LIMIT_EXCEEDED        — the one observed live on 2026-08-19
#   202 TOO_MANY_SIMULTANEOUS_QUERIES
#   203 NO_FREE_CONNECTION
#   209 SOCKET_TIMEOUT / 210 NETWORK_ERROR
#   252 TOO_MANY_PARTS               — merge backlog; drains on its own
#   159 TIMEOUT_EXCEEDED
#   173 CANNOT_ALLOCATE_MEMORY
CH_RETRYABLE_CODES = frozenset({241, 202, 203, 209, 210, 252, 159, 173})

CORR_CH_RETRY_ATTEMPTS = int(os.environ.get("CORR_CH_RETRY_ATTEMPTS", "4"))
CORR_CH_RETRY_BASE_S = float(os.environ.get("CORR_CH_RETRY_BASE_S", "0.5"))
CORR_CH_RETRY_MAX_S = float(os.environ.get("CORR_CH_RETRY_MAX_S", "8.0"))
CH_RETRIES_ATTEMPTED = 0
CH_RETRIES_RECOVERED = 0
CH_RETRIES_EXHAUSTED = 0


async def _insert_with_outcome(table: str, rows: list, token: str) -> InsertOutcome:
    """`ch.insert_detailed` when the sink offers it, else a bool-only fallback.

    A sink that can only answer true/false (every test double, and any future
    alternative implementation) yields an outcome with no ClickHouse code, which
    `ch_retryable` treats as PERMANENT. That is the safe default: we retry only
    when something told us the failure was transient, never on an unexplained
    one.
    """
    assert ch is not None
    detailed = getattr(ch, "insert_detailed", None)
    if detailed is not None:
        return await detailed(table, rows, dedup_token=token)
    ok = await ch.insert(table, rows, dedup_token=token)
    if ok is False:
        return InsertOutcome(committed=False, kind="rejected", rows=len(rows))
    return InsertOutcome(committed=True, kind="committed", rows=len(rows))


def ch_retryable(outcome: InsertOutcome) -> bool:
    """Transport failures and a named set of server-busy codes are retryable."""
    if outcome.committed:
        return False
    if outcome.kind == "transport":
        return True
    return outcome.ch_code in CH_RETRYABLE_CODES


def ch_retry_delay(attempt: int, rnd=None) -> float:
    """Exponential backoff with full jitter, capped. attempt is 1-based.

    Full jitter (uniform in [0, backoff]) rather than fixed backoff: every
    correlation replica retries the same rejected batch shape at the same
    moment otherwise, which is how a memory-limit rejection turns into a
    synchronised retry storm against the server that just said it was short of
    memory.
    """
    import random as _random
    backoff = min(CORR_CH_RETRY_BASE_S * (2 ** (attempt - 1)), CORR_CH_RETRY_MAX_S)
    return (rnd or _random.random)() * backoff


class CH:
    def __init__(self, base_url: str, user: str, password: str) -> None:
        self.base = base_url.rstrip("/")
        self.auth = (user, password)
        # SEC-009: when CLICKHOUSE_URL is https, verify against the mesh CA
        # (CORRELATION_CA_FILE) — never the system pool, never verify=False.
        # Plain http keeps the default (verify is irrelevant there), so the
        # fresh-install baseline is byte-identical.
        verify = os.environ.get("CORRELATION_CA_FILE") or True
        self.client = httpx.AsyncClient(timeout=10.0, verify=verify)

    async def insert(self, table: str, rows: Iterable[dict],
                     dedup_token: str = "") -> bool:
        """True on a POSITIVELY COMMITTED insert, False otherwise.

        Thin bool wrapper over `insert_detailed` so the 20 call sites that only
        care whether it landed are unchanged. Anything that must DECIDE what to
        do about a failure — retry or quarantine — needs the outcome, because
        "false" cannot distinguish a transient memory-limit rejection from a
        schema error that will fail identically forever (tracker 160).
        """
        return (await self.insert_detailed(table, rows, dedup_token)).committed

    async def insert_detailed(self, table: str, rows: Iterable[dict],
                              dedup_token: str = "") -> InsertOutcome:
        """The insert, with the verdict DETAIL the caller needs to act on.

        Ports the wire-level correctness the Go chhttp package proved against the
        pinned ClickHouse 24.8.14.39 (see src/backend/chhttp). A status check
        alone is NOT sufficient, for reasons measured there:

          - ClickHouse can return HTTP 200 with the DB::Exception in the BODY
            (wait_end_of_query=0, failure after the first buffer flush). A
            status-only check calls that success and drops the write. We send
            wait_end_of_query=1, inspect X-ClickHouse-Exception-Code, and
            backstop with a body-tail scan.
          - The error body may quote the offending ROW, which for this platform
            is customer telemetry. It must NEVER reach the log (constraint:
            no PII in logs). We log status + exception code + query id, never
            r.text.

        dedup_token (Phase 3): when set, sent as insert_deduplication_token so a
        retried insert of the SAME block is dropped by ClickHouse rather than
        duplicated. The RCA-critical tables are plain MergeTree (no content
        dedup), so this is what makes a retry-after-Unknown safe on them. The
        table's non_replicated_deduplication_window (init.sql) bounds the memory
        of tokens; immediate retries are always inside it.
        """
        rows = list(rows)
        nbytes = 0
        # P1 (1000-device scale): a 48,375-edge insert serializes a 22.5 MiB
        # NDJSON body in ONE synchronous comprehension — measured 0.68s of
        # frozen event loop, inside which aiokafka's heartbeat cannot run.
        # Offloaded above the threshold; small inserts keep the inline path.
        if len(rows) >= CORR_OFFLOAD_MIN_ELEMENTS:
            body = await _offload(_ndjson_body, rows)
        else:
            body = _ndjson_body(rows)
        nbytes = len(body.encode()) if isinstance(body, str) else len(body)
        if not body:
            return InsertOutcome(committed=True, kind="empty", rows=0, nbytes=0)
        # #20 Phase 2 / TENANT-HIGH-4: state the tenant this batch is written on
        # behalf of instead of leaving the setting unset (or wildcarding it on
        # the read side and hoping). See insert_scope().
        scope = insert_scope(rows)
        if scope == "__all__":
            CH_CROSS_TENANT_INSERTS[table] = CH_CROSS_TENANT_INSERTS.get(table, 0) + 1
        params = {
            "tenant_scope": scope,
            "query": f"INSERT INTO {table} FORMAT JSONEachRow",
            # Server-side buffering so a post-flush failure arrives as a real
            # error status + header rather than a 200 with the exception buried.
            "wait_end_of_query": "1",
            # Insert tolerance (F-56): an unknown field is dropped, not fatal to
            # the batch. Row errors are NOT tolerated (see the Go note) — a bad
            # row must fail loudly, never be silently discarded.
            "input_format_skip_unknown_fields": "1",
            "date_time_input_format": "best_effort",
        }
        if dedup_token:
            params["insert_deduplication_token"] = dedup_token
        try:
            r = await self.client.post(
                self.base, params=params, content=body, auth=self.auth,
                headers={"Content-Type": "application/x-ndjson"},
            )
        except httpx.HTTPError as exc:
            # Transport failure before any verdict: the caller must treat this as
            # NOT committed and quarantine the payload. Type name only — never
            # the exception detail, which can echo the request body.
            log.error("clickhouse insert transport failure table=%s err=%s",
                      table, type(exc).__name__)
            return InsertOutcome(committed=False, kind="transport",
                                 error=type(exc).__name__,
                                 rows=len(rows), nbytes=nbytes)
        code = r.headers.get("X-ClickHouse-Exception-Code")
        qid = r.headers.get("X-ClickHouse-Query-Id", "")
        # A 200 can still be a failure: the exception header, or the exception
        # marker in the body tail (the measured wait_end_of_query race backstop).
        embedded = ("DB::Exception" in r.text[-4096:]) if r.status_code < 300 else False
        if r.status_code >= 300 or code or embedded:
            # r.text deliberately absent — it can contain customer rows.
            log.error("clickhouse insert failed table=%s status=%s ch_code=%s query_id=%s",
                      table, r.status_code, code or "-", qid or "-")
            return InsertOutcome(committed=False, kind="rejected",
                                 status=r.status_code,
                                 ch_code=int(code) if (code or "").lstrip("-").isdigit() else 0,
                                 query_id=qid, rows=len(rows), nbytes=nbytes)
        return InsertOutcome(committed=True, kind="committed", status=r.status_code,
                             query_id=qid, rows=len(rows), nbytes=nbytes)

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
CH_INSERT_FAILURES: dict[str, int] = {}
_CH_FAIL_LOG_LAST: dict[str, float] = {}
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


# RCA-critical tables: a rejected write here corrupts causality, so it must
# never advance the Kafka offset silently. These raise CHInsertRejected on a
# rejected insert, which the consumer's per-event handler turns into a durable
# quarantine — closing the gap where the ~19 callers that ignored the bool let a
# rejected write look like success. Reconstructable/best-effort tables keep the
# bool contract (their source of truth is replayable).
CH_CRITICAL_TABLES = frozenset({
    "netops.corr_signals",
    "netops.corr_objects",
    "netops.corr_current",
    "netops.corr_edges",
    "netops.corr_evidence",
})


class CHInsertRejected(Exception):
    """A ClickHouse insert to an RCA-critical table was positively rejected.

    Raised (not returned) so it enters the consumer's quarantine path: the
    payload is preserved durably and the offset is NOT advanced past it. This is
    the constraint — never acknowledge a source message for a write that neither
    committed nor was durably kept.
    """


# ── Phase 3 idempotency: per-message dedup coordinate ──────────────────────
#
# The RCA-critical tables are plain MergeTree (no content dedup), so a retry of
# an insert after an UNKNOWN outcome would DUPLICATE causal rows. ClickHouse
# insert_deduplication_token drops a re-inserted block carrying a token it has
# seen within the table's non_replicated_deduplication_window (set in init.sql).
#
# The token must be STABLE across a retry/redelivery of the same message and
# UNIQUE per logical insert. The consumer processes messages sequentially
# (`async for msg: await handle(...)`), so a module-level coordinate set before
# each handle() is safe without contextvars — there is no interleaving. The
# per-message sequence disambiguates multiple inserts (same or different tables)
# from one message; a deterministic handler re-runs them in the same order on
# redelivery, so the tokens match and ClickHouse dedups.
_dedup_coord = ""      # "topic:partition:offset" for the message in flight
_dedup_seq = 0         # monotonic per-message insert counter


def set_dedup_coord(topic: str, partition: int, offset: int) -> None:
    """Called by the consumer before handle(); establishes this message's token base."""
    global _dedup_coord, _dedup_seq
    _dedup_coord = f"{topic}:{partition}:{offset}"
    _dedup_seq = 0


def _next_dedup_token(table: str) -> str:
    """Stable, unique token for the next insert of this message. Empty when there
    is no coordinate (e.g. a non-consumer write path), leaving dedup off."""
    global _dedup_seq
    if not _dedup_coord:
        return ""
    tok = f"{_dedup_coord}:{table}:{_dedup_seq}"
    _dedup_seq += 1
    return tok


async def ch_insert(table: str, rows, *, dedup_token: str | None = None, **ctx) -> bool:
    """`ch.insert` with the failure actually surfaced (log + counter).

    Transport exceptions are counted and RE-RAISED (the consumer quarantines the
    event). A REJECTED insert (HTTP 4xx/5xx or an embedded exception) is counted
    here, and for an RCA-critical table it is RAISED as CHInsertRejected so it
    too reaches the durable quarantine — a rejected causal write that silently
    returned False was the F-38 hole on the Python side.

    Phase 3: critical-table inserts carry an insert_deduplication_token derived
    from the Kafka coordinate, so a retry/redelivery cannot duplicate the row.
    H13: a caller that is NOT driven by a consumer message (the engine cycle's
    _persist_snapshot) passes its own naturally-idempotent dedup_token instead —
    borrowing the consumer coordinate meant a redelivery reset the per-message
    seq and a NEW object version minted during replay reused an already-seen
    token, which ClickHouse then silently dropped.
    """
    assert ch is not None
    if dedup_token is not None:
        token = dedup_token
    else:
        token = _next_dedup_token(table) if table in CH_CRITICAL_TABLES else ""
    try:
        ok = await ch.insert(table, rows, dedup_token=token)
    except Exception as exc:  # blanket on purpose: counted, then re-raised
        _note_ch_failure(table, type(exc).__name__, ctx)
        raise
    # `is False` exactly: CH.insert's contract is a bool, and a test double that
    # returns None must not be miscounted as a lost write.
    if ok is False:
        _note_ch_failure(table, "rejected", ctx)
        if table in CH_CRITICAL_TABLES:
            raise CHInsertRejected(f"{table} rejected the insert")
    return ok


# ---------------------------------------------------------------------------
# Consume-loop ClickHouse batching (perf defect #2).
#
# Every consumed event used to await 1–3 SINGLE-ROW corr_signals inserts with
# wait_end_of_query=1 — a full ClickHouse round-trip per row in the sequential
# consume loop capped ALL topics at a few hundred events/s and exploded
# MergeTree parts (TOO_MANY_PARTS → valid signals quarantined). Rows now
# accumulate per table and flush as ONE insert when a batch reaches
# CORR_BATCH_MAX_ROWS, ages past CORR_BATCH_MAX_S (background flusher), the
# total buffered rows hit CORR_BATCH_QUEUE_MAX (bounded queue — the sequential
# consume loop awaits the flush, which IS the backpressure), on shutdown, and —
# the at-least-once anchor — ALWAYS before a Kafka offset commit (_commit
# flushes first; a failed flush aborts the commit, so the supervisor replays
# from the last committed offset and no acknowledged row can be lost).
#
# Failure semantics mirror the per-row path at batch granularity:
#   * transport failure (outcome UNKNOWN): counted, rows RETAINED for retry,
#     re-raised — the current event is quarantined (payload kept) and a run of
#     failures hands the stream back to the supervisor's backoff, exactly as
#     single-row transport failures did.
#   * positive rejection: counted, every row of the batch preserved in the
#     durable dead-letter file (never acknowledge a write that neither
#     committed nor was durably kept), batch dropped, consumption continues.
# The dedup token is a content hash of the batch, so a retry of an UNCHANGED
# retained batch after an unknown outcome dedups instead of duplicating.
# ---------------------------------------------------------------------------

CORR_BATCH_MAX_ROWS = int(os.environ.get("CORR_BATCH_MAX_ROWS", "500"))
CORR_BATCH_MAX_S = float(os.environ.get("CORR_BATCH_MAX_S", "2.0"))
CORR_BATCH_QUEUE_MAX = int(os.environ.get("CORR_BATCH_QUEUE_MAX", "5000"))
BATCH_FLUSHES = 0            # committed batch inserts (monotonic)
BATCH_ROWS_FLUSHED = 0       # rows landed through the batcher (monotonic)
BATCH_ROWS_QUARANTINED = 0   # rows a rejected batch preserved in the DLQ
BATCH_ROWS_REPLAY_DEDUPED = 0  # redelivered rows dropped by the commit guard
# P1 thrash fix: identities of rows that FLUSHED but whose Kafka offsets have
# not yet committed. A member ejection between flush and commit redelivers the
# messages; their handlers re-add the same rows to a FRESH batch whose
# content-hash token differs from the one that landed — so ClickHouse could
# not dedup and corr_signals (plain MergeTree) got duplicate causal rows. The
# guard makes the replayed add a no-op within this process (the dominant
# thrash case: the supervisor rebuilds the CONSUMER, not the process). Bounded
# per §9; a successful offset commit clears it (nothing left to replay).
CORR_BATCH_COMMIT_GUARD_MAX = int(os.environ.get("CORR_BATCH_COMMIT_GUARD_MAX", "100000"))


class _TableBatch:
    __slots__ = ("first_mono", "ids", "rows")

    def __init__(self) -> None:
        self.rows: list[dict] = []
        # H12: per-row identities of everything pending for this table. A flush
        # transport failure RETAINS the rows for retry, then escapes to the
        # supervisor → consumer restart → Kafka redelivers the uncommitted
        # messages → their handlers re-add the SAME rows to the still-retained
        # batch, and the next flush landed both copies (the doubled membership
        # also changed the content-hash token, so ClickHouse could not dedup).
        # Keying pending rows by their stable identity (signal_id — Kafka
        # redelivery regenerates the same deterministic id) makes the replayed
        # add a no-op: membership is unchanged, so the retry token stays the
        # one the failed attempt used and server-side dedup still covers the
        # attempt-actually-landed case.
        self.ids: set[str] = set()
        self.first_mono = time.monotonic()


class CHBatcher:
    """Bounded per-table row accumulator for the consume-loop write path."""

    def __init__(self) -> None:
        self._batches: dict[str, _TableBatch] = {}
        # H12: a batch whose insert TRANSPORT-failed (outcome unknown) is parked
        # here and retried with its membership — and therefore its content-hash
        # token — UNCHANGED. Merging it back into the live batch (the old
        # front-merge) let rows added while the insert was in flight (the engine
        # task runs concurrently) change the token, so a first attempt that had
        # actually landed server-side was re-inserted under a fresh token and
        # duplicated. At most one parked batch per table: flush retries it
        # before touching the live batch, and only a successful retry frees the
        # slot for a newly-failed live batch.
        self._retry: dict[str, _TableBatch] = {}
        # Flushed-but-uncommitted row identities per table (see
        # CORR_BATCH_COMMIT_GUARD_MAX above). OrderedDict as a bounded
        # insertion-ordered set: oldest identities evict first.
        self._flushed_uncommitted: dict[str, OrderedDict] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def _row_identity(row: dict) -> str:
        """Stable per-row identity for replay dedup (H12): the deterministic
        signal_id when present, else the row content itself — identical
        replayed content collapses either way, distinct rows never do."""
        rid = row.get("signal_id")
        if rid:
            return str(rid)
        return hashlib.sha256(
            json.dumps(row, sort_keys=True, default=str).encode()).hexdigest()

    def pending(self) -> int:
        return (sum(len(b.rows) for b in self._batches.values())
                + sum(len(b.rows) for b in self._retry.values()))

    def drop_pending(self) -> int:
        """Discard buffered rows WITHOUT writing them. Test-hermeticity hook
        (conftest resets the batcher between tests so one test's unflushed rows
        can never surface in another test's fake ClickHouse) — production code
        never drops; it flushes."""
        n = self.pending()
        self._batches.clear()
        self._retry.clear()
        self._flushed_uncommitted.clear()
        return n

    def note_committed(self) -> None:
        """The Kafka offsets covering every flushed row have COMMITTED — no
        redelivery of them is possible, so the replay guard can forget them.
        Called by the consumer after each successful offset commit."""
        self._flushed_uncommitted.clear()

    def due(self, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        if self._retry:
            return True  # a parked batch is always due — its rows are only aging
        return any(len(b.rows) >= CORR_BATCH_MAX_ROWS
                   or (now - b.first_mono) >= CORR_BATCH_MAX_S
                   for b in self._batches.values())

    async def add(self, table: str, row: dict) -> None:
        global BATCH_ROWS_REPLAY_DEDUPED
        b = self._batches.get(table)
        if b is None:
            b = self._batches[table] = _TableBatch()
        rid = self._row_identity(row)
        parked = self._retry.get(table)
        if rid in b.ids or (parked is not None and rid in parked.ids):
            return  # H12: redelivered row already pending — replay, not new data
        if rid in self._flushed_uncommitted.get(table, ()):
            # Post-flush redelivery (member ejected between flush and commit):
            # the row already LANDED; re-adding it would re-insert it under a
            # different batch token and duplicate it (plain MergeTree).
            BATCH_ROWS_REPLAY_DEDUPED += 1
            return
        b.ids.add(rid)
        b.rows.append(row)
        if len(b.rows) >= CORR_BATCH_MAX_ROWS or self.pending() >= CORR_BATCH_QUEUE_MAX:
            await self.flush()

    async def flush(self) -> None:
        """Flush every pending table batch — a parked retry batch first, and
        SEPARATELY from the live one, so its content-hash token is byte-stable
        across the retry (H12). Raises on a transport failure (rows retained);
        a positive rejection quarantines the rows durably."""
        async with self._lock:
            if ch is None:
                return  # startup/shutdown edge: nothing to write to yet; rows stay
            for table in sorted(set(self._batches) | set(self._retry)):
                parked = self._retry.pop(table, None)
                if parked is not None and parked.rows:
                    try:
                        await self._insert_batch(table, parked)
                    except Exception:  # re-park UNCHANGED → same token next try
                        self._retry[table] = parked
                        raise
                b = self._batches.pop(table, None)
                if b is None or not b.rows:
                    continue
                try:
                    await self._insert_batch(table, b)
                except Exception:
                    # Park with membership (and token) frozen. Rows added while
                    # this insert was in flight live in the fresh live batch
                    # add() creates and flush on a later pass — NEVER merged
                    # into the batch being retried (that changed the token).
                    self._retry[table] = b
                    raise

    async def _insert_batch(self, table: str, b: _TableBatch) -> None:
        """One batch → one insert. Counts every outcome; raises on transport
        failure (the caller decides where the retained batch lives)."""
        global BATCH_FLUSHES, BATCH_ROWS_FLUSHED, BATCH_ROWS_QUARANTINED
        assert ch is not None
        # Content-hash token: a retry of the SAME retained batch after an
        # unknown outcome dedups server-side instead of duplicating.
        # P1: offloaded for a large batch (0.93s at 48k rows) — byte-identical
        # token either way, so server-side dedup across a retry is unchanged.
        if len(b.rows) >= CORR_OFFLOAD_MIN_ELEMENTS:
            token = await _offload(_batch_token, b.rows)
        else:
            token = _batch_token(b.rows)
        global CH_RETRIES_ATTEMPTED, CH_RETRIES_RECOVERED, CH_RETRIES_EXHAUSTED
        # TRACKER 160 — the delivery contract for one batch:
        #   committed  -> offsets may advance
        #   retryable  -> bounded retries with exponential backoff + full jitter,
        #                 re-sent under the SAME content-hash token so a retry
        #                 after an unknown outcome dedups server-side instead of
        #                 duplicating
        #   permanent, or retries exhausted
        #              -> every row durably spooled to the dead-letter file WITH
        #                 the reason, ClickHouse code and query id, and only then
        #                 may offsets advance
        #
        # Before this, a positively-rejected batch was quarantined and the method
        # RETURNED, so flush() succeeded and the consumer committed. There was no
        # retry of any kind, and CH.insert folded transport failures into the
        # same `False`, so a momentary ClickHouse blip permanently removed rows
        # from corr_signals. Code 241 (MEMORY_LIMIT_EXCEEDED) — the one measured
        # live on 2026-08-19 — is exactly the transient case that should have
        # been retried.
        outcome = None
        for attempt in range(1, CORR_CH_RETRY_ATTEMPTS + 1):
            try:
                outcome = await _insert_with_outcome(table, b.rows, token)
            except Exception as exc:  # counted, retained by the caller, re-raised
                _note_ch_failure(table, type(exc).__name__,
                                 {"batched_rows": len(b.rows)})
                raise
            if outcome.committed:
                if attempt > 1:
                    CH_RETRIES_RECOVERED += 1
                    log.warning(
                        "clickhouse insert RECOVERED table=%s attempt=%d rows=%d",
                        table, attempt, len(b.rows))
                break
            if attempt >= CORR_CH_RETRY_ATTEMPTS or not ch_retryable(outcome):
                break
            CH_RETRIES_ATTEMPTED += 1
            delay = ch_retry_delay(attempt)
            log.warning("clickhouse insert retry table=%s attempt=%d/%d "
                        "ch_code=%s kind=%s rows=%d backoff=%.2fs",
                        table, attempt, CORR_CH_RETRY_ATTEMPTS,
                        outcome.ch_code or "-", outcome.kind, len(b.rows), delay)
            await asyncio.sleep(delay)
        if outcome is not None and not outcome.committed:
            if ch_retryable(outcome):
                CH_RETRIES_EXHAUSTED += 1
            _note_ch_failure(table, "rejected", {"batched_rows": len(b.rows),
                                                 **outcome.as_evidence()})
            self._quarantine_rows(table, b.rows, outcome)
            BATCH_ROWS_QUARANTINED += len(b.rows)
            return
        BATCH_FLUSHES += 1
        BATCH_ROWS_FLUSHED += len(b.rows)
        # Remember what landed until its offsets commit (replay guard, §9-bounded).
        guard = self._flushed_uncommitted.setdefault(table, OrderedDict())
        for rid in b.ids:
            guard[rid] = None
        while len(guard) > CORR_BATCH_COMMIT_GUARD_MAX:
            guard.popitem(last=False)

    @staticmethod
    def _quarantine_rows(table: str, rows: list[dict],
                         outcome: InsertOutcome | None = None) -> None:
        """Durably preserve every row of a rejected batch: one DLQ record per
        row (replayable), ONE ring summary (the 200-slot ring must not be wiped
        by a single 500-row batch).

        Each record now carries a `reason` and the ClickHouse verdict (tracker
        160). Without a reason these records were unclassifiable: the mini-ladder
        accounting gate could only lump them in with benign tenant refusals, so
        95 genuinely lost signals read as background noise. `payload_truncated`
        is stated explicitly rather than left to be discovered — a silently
        truncated payload is not replayable, and a record that claims
        recoverability it does not have is worse than one that admits the gap.
        """
        ts = datetime.now(timezone.utc).isoformat()
        ev = outcome.as_evidence() if outcome is not None else {}
        reason = ("ch_insert_rejected" if (outcome is None or outcome.kind == "rejected")
                  else f"ch_insert_{outcome.kind}")
        for r in rows:
            full = json.dumps(r, default=str)
            payload = full[:CORR_QUARANTINE_PAYLOAD_CHARS]
            _dlq_append({
                "ts": ts,
                "topic": f"chbatch:{table}",
                "reason": reason,
                "table": table,
                "ch": ev,
                "retries_exhausted": bool(outcome is not None and ch_retryable(outcome)),
                "payload_truncated": len(full) > CORR_QUARANTINE_PAYLOAD_CHARS,
                "error": "clickhouse rejected the batched insert",
                "payload": payload,
            })
        QUARANTINE.append({
            "ts": ts,
            "topic": f"chbatch:{table}",
            "error": f"clickhouse rejected a batched insert — {len(rows)} rows "
                     f"preserved in the durable dead-letter file",
            "payload": "",
        })


SIGNAL_BATCH = CHBatcher()


async def batch_signal(row: dict) -> None:
    """Enqueue one corr_signals row on the consume-loop batcher (see CHBatcher)."""
    await SIGNAL_BATCH.add("netops.corr_signals", row)


# ── event-loop stall watchdog (P1: make the NEXT blocker self-reporting) ─────
#
# The 2026-08-17 regression cost hours of forensics because the platform could
# not say "the event loop was frozen for 84s" — it had to be inferred from gaps
# between log lines. aiokafka's heartbeat starving is invisible until the broker
# ejects the member, by which point the cause is gone. This task samples the
# loop's own scheduling delay: it sleeps a known interval and measures the
# overshoot, which IS the time the loop was blocked by something else. Any
# sample over the threshold is logged (with the size of the stall) and counted,
# and the counters are on /healthz + /metrics per the GA counter-exposure
# contract, so a stall becomes an alertable fact instead of an archaeology
# exercise. Cost: one timer wakeup every CORR_LOOP_LAG_SAMPLE_S.
CORR_LOOP_LAG_SAMPLE_S = float(os.environ.get("CORR_LOOP_LAG_SAMPLE_S", "0.5"))
# Default 1s: 3x under aiokafka's heartbeat_interval_ms (3s) so a stall is
# reported well before it can threaten the session (30s).
CORR_LOOP_LAG_WARN_MS = float(os.environ.get("CORR_LOOP_LAG_WARN_MS", "1000"))
LOOP_LAG_STALLS = 0        # samples whose lag exceeded the warn threshold
LOOP_LAG_MAX_MS = 0.0      # worst lag seen this process (gauge)
LOOP_LAG_LAST_MS = 0.0     # most recent sample (gauge)


async def loop_lag_watchdog() -> None:
    """Measure and report event-loop scheduling delay (see comment above)."""
    global LOOP_LAG_STALLS, LOOP_LAG_MAX_MS, LOOP_LAG_LAST_MS
    while True:
        t0 = time.monotonic()
        await asyncio.sleep(CORR_LOOP_LAG_SAMPLE_S)
        lag_ms = (time.monotonic() - t0 - CORR_LOOP_LAG_SAMPLE_S) * 1000.0
        if lag_ms < 0:
            lag_ms = 0.0
        LOOP_LAG_LAST_MS = lag_ms
        LOOP_LAG_MAX_MS = max(LOOP_LAG_MAX_MS, lag_ms)
        # Diagnostic heartbeat (no-op unless CORR_DIAG_MEMORY). The stall
        # detector runs on a plain thread and watches this value: a task cannot
        # observe the stall that is stopping it from being scheduled.
        diagnostics.heartbeat()
        if lag_ms >= CORR_LOOP_LAG_WARN_MS:
            LOOP_LAG_STALLS += 1
            log.warning(
                "event loop STALLED %.0fms (threshold %.0fms, stalls=%d, "
                "worst=%.0fms) — something synchronous is blocking the loop; "
                "aiokafka's heartbeat cannot run inside a stall and the broker "
                "expires the session at %dms",
                lag_ms, CORR_LOOP_LAG_WARN_MS, LOOP_LAG_STALLS,
                LOOP_LAG_MAX_MS, CORR_SESSION_TIMEOUT_MS)


def diag_app_state() -> dict:
    """The application-side half of a memory snapshot: what correlation is
    actually holding, so retained bytes can be attributed to a structure rather
    than guessed at."""
    return {
        "open_objects": len(OPEN_OBJECTS),
        "window_signals": len(WINDOW_BUFFER),
        "window_maxlen": WINDOW_BUFFER.maxlen,
        "buffered_ids": len(_BUFFERED_IDS),
        "pending_batch_rows": SIGNAL_BATCH.pending(),
        "archive_slice_hashes": len(_ARCHIVE_SLICE_HASH),
        "series": len(SERIES),
        "quarantine_ring": len(QUARANTINE),
        "flow_agg": len(_FLOW_AGG),
        "syslog_buckets": len(SYSLOG_BUCKET),
        "observer_cache": len(signals._OBSERVER_CACHE),
        "cycle_row_cache": len(_CYCLE_ROW_CACHE),
        "asyncio_tasks": len(asyncio.all_tasks()),
        "consumer_state": consumer_state(),
        "assigned_partitions": sum(len(v) for v in CONSUMER_ASSIGNMENT.values()),
        "loop_lag_last_ms": round(LOOP_LAG_LAST_MS, 1),
        "loop_lag_max_ms": round(LOOP_LAG_MAX_MS, 1),
        "loop_lag_stalls": LOOP_LAG_STALLS,
    }


async def diag_snapshot_loop() -> None:
    """Periodic synchronized snapshots, plus threshold-triggered ones as RSS
    climbs toward the cgroup cap — the interesting samples are the crossings,
    not the round-numbered intervals.

    Only scheduled when diagnostics are enabled.
    """
    every = float(os.environ.get("CORR_DIAG_SNAPSHOT_EVERY_S", "30"))
    crossed: set[int] = set()
    cap = _cgroup_mem_max()
    await asyncio.to_thread(diagnostics.snapshot, "pre-load-baseline",
                            diag_app_state(), True)
    while True:
        await asyncio.sleep(every)
        state = diag_app_state()
        label, heavy = "periodic", False
        if cap:
            rss = diagnostics._proc_memory().get("rss_bytes", 0)
            pct = int(rss * 100 / cap) if cap else 0
            for mark in (85, 90, 95, 99):
                if pct >= mark and mark not in crossed:
                    crossed.add(mark)
                    label, heavy = f"rss-crossed-{mark}pct", True
                    break
            state["rss_pct_of_cap"] = pct
            state["cgroup_max_bytes"] = cap
        # OFF THE LOOP, always. Even the light path touches /proc and the GC;
        # the heavy path walks every tracemalloc traceback and was measured at
        # 39-96s, which is what made the profiler itself the stall in the first
        # forensic run. Heavy analysis is reserved for threshold crossings.
        await asyncio.to_thread(diagnostics.snapshot, label, state, heavy)


def _cgroup_mem_max() -> int:
    """The container's memory ceiling, or 0 when it cannot be read."""
    for path in ("/sys/fs/cgroup/memory.max",
                 "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        try:
            with open(path) as fh:
                raw = fh.read().strip()
            return 0 if raw == "max" else int(raw)
        except (OSError, ValueError):
            continue
    return 0


async def batch_flush_loop() -> None:
    """Bounds batch latency to ≤ CORR_BATCH_MAX_S when the bus goes quiet —
    the consume loop only flushes on traffic/commit, and a trailing burst must
    not sit buffered until the next event arrives."""
    while True:
        await asyncio.sleep(max(CORR_BATCH_MAX_S / 2, 0.25))
        try:
            if SIGNAL_BATCH.due():
                await SIGNAL_BATCH.flush()
        except Exception as exc:  # noqa: BLE001 — supervisor loop must survive any flush error
            # Rows are retained; the next tick (or the pre-commit flush) retries.
            log.debug("batch flush tick failed; retrying next tick: %s", exc)
            continue


# ---------------------------------------------------------------------------
# Kafka consumer loop.
# ---------------------------------------------------------------------------


def _read_from_offset(path: str, off: int) -> tuple[str, int]:
    """Blocking read of everything after `off`; runs via asyncio.to_thread so a
    slow/large log file never stalls the event loop (ASYNC230)."""
    with open(path) as f:
        f.seek(off)
        return f.read(), f.tell()


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
            data, new_off = await asyncio.to_thread(_read_from_offset, path, off)
            _cloud_log_offsets[path] = new_off
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
    skipped_logged = False
    while True:
        try:
            # Scale P0: the tailer is a SINGLETON side-input (files, not the
            # bus). With --scale correlation=N every replica sees the same
            # files, so only the replica that owns CLOUD_LOGS_TENANT's
            # partition may feed them — the same instance whose engine holds
            # that tenant's state. owns_tenant() fails open before the first
            # rebalance (single-replica / broker-less dev behavior unchanged).
            if not owns_tenant(CLOUD_LOGS_TENANT):
                if not skipped_logged:
                    skipped_logged = True
                    log.info("cloud-log tailer idle: tenant %s owned by another "
                             "replica (co-partitioned scale-out)", CLOUD_LOGS_TENANT)
                await asyncio.sleep(max(CLOUD_LOGS_REFRESH_S, 5.0))
                continue
            skipped_logged = False
            n = await _scan_cloud_logs()
            if n:
                log.info("cloud-log tailer fed %d signal(s)", n)
        except asyncio.CancelledError:
            raise
        except Exception:
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
# Tracker #126: manual-commit batching. Replay-after-crash is bounded to at
# most N already-HANDLED messages (dedup tokens absorb the redelivery); an
# unhandled offset is never committed.
CORR_COMMIT_EVERY_N = int(os.environ.get("CORR_COMMIT_EVERY_N", "100"))
CORR_COMMIT_EVERY_S = float(os.environ.get("CORR_COMMIT_EVERY_S", "5"))

# ── Group-membership tuning (P1 max-poll rebalance thrash, 2026-08-16) ──────
#
# The G2 mini-ladder measured the failure live: a 24k-event backlog put the
# consumer in a session-expiry rebalance loop (78x UnknownMemberIdError, 9x
# CommitFailedError, drain collapsed 1k/s -> ~40/s, lag never drained). The
# container logs show 17-second event-loop stalls (19:15:34,257 -> 19:15:51,342
# with ZERO lines between) — longer than aiokafka's 10s session_timeout_ms
# default, so the broker ejected the member, the next commit raised
# CommitFailedError, the uncommitted batch replayed, and the loop repeated.
#
# The stalls themselves are fixed structurally (run_window in an executor,
# batched CH writes, the explicit yield cadence below). These values make the
# session contract honest on top of that fix, with the arithmetic:
#
#   * session_timeout 30s / heartbeat 3s: worst measured event-loop latency
#     with the engine chewing a storm window in the executor is ~0.2s (GIL
#     convoy, gil_probe 2026-08-16), so 30s tolerates a >100x regression plus
#     GC/CPU-throttle pauses. 3s = session/10 (Kafka's recommended <= 1/3).
#   * max_poll_interval 300s (explicit, was implicit default): the worst
#     legitimate gap between polls is one loop iteration = handle() with up to
#     ~5 direct CH inserts x 10s httpx timeout (wireless lane) + a commit
#     (flush <= 10s/table + 30s commit bound) ~= 90s << 300s. A gap beyond
#     that is a real wedge and SHOULD trigger leave + supervisor restart.
#   * rebalance_timeout 60s: the revoke hook flushes + commits before
#     partitions move (see _AssignmentLogger); its bound is one batch flush
#     (<= 10s) + one commit (<= 30s), so 60s covers it with margin.
CORR_SESSION_TIMEOUT_MS = int(os.environ.get("CORR_SESSION_TIMEOUT_MS", "30000"))
CORR_HEARTBEAT_INTERVAL_MS = int(os.environ.get("CORR_HEARTBEAT_INTERVAL_MS", "3000"))
CORR_MAX_POLL_INTERVAL_MS = int(os.environ.get("CORR_MAX_POLL_INTERVAL_MS", "300000"))
CORR_REBALANCE_TIMEOUT_MS = int(os.environ.get("CORR_REBALANCE_TIMEOUT_MS", "60000"))
# Budget for the revoke-time flush AND, separately, the revoke-time commit.
# The revoke callback runs INSIDE the rejoin: time spent there is time the group
# is not re-forming, so it must be a small fraction of rebalance_timeout (60s),
# not equal to it. 5s each => worst added rejoin latency ~10s (and a 2x backstop
# in on_partitions_revoked), i.e. <= 1/6 of the rebalance timeout. Exceeding the
# flush budget SKIPS the commit rather than extending the callback — F-38 is
# preserved by not committing, never by waiting longer.
CORR_REVOKE_BUDGET_S = float(os.environ.get("CORR_REVOKE_BUDGET_S", "5"))
# Cooperative poll cadence: aiokafka's fetcher returns already-buffered records
# WITHOUT yielding to the event loop (fetcher.next_record's fast path), and a
# handler whose awaits all complete synchronously (CH batcher below its flush
# thresholds) never yields either — so under a backlog the consume task could
# monopolize the loop between commit-triggered flushes and starve the heartbeat
# task. Force a loop yield every N messages: N=20 x <=10ms/event worst-case
# sync handler CPU = <=200ms between yields << heartbeat 3s << session 30s.
CORR_CONSUME_YIELD_EVERY_N = int(os.environ.get("CORR_CONSUME_YIELD_EVERY_N", "20"))


async def _stop_bounded(consumer) -> None:
    """Stop a consumer without letting a hung broker wedge the supervisor.
    On timeout the old consumer is ABANDONED (its group member times out
    broker-side); a fresh consumer replaces it. Never raises."""
    try:
        await asyncio.wait_for(consumer.stop(), timeout=CONSUMER_STOP_TIMEOUT_S)
    except asyncio.CancelledError:
        raise
    except Exception:
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
QUARANTINE: deque[dict] = deque(maxlen=CORR_QUARANTINE_MAX)
HANDLER_FAILURES: dict[str, int] = {}   # topic -> events lost to a handler error
QUARANTINE_WRITE_FAILURES = 0
QUARANTINE_ROTATIONS = 0
_DLQ_UNSET_WARNED = False
_QUARANTINE_LOG_LAST: dict[str, float] = {}
QUARANTINE_LOG_EVERY_S = float(os.environ.get("CORR_QUARANTINE_LOG_EVERY_S", "30"))
# Consecutive handler failures that mean "the dependency is down", not "one
# poison event" — the consumer then restarts through the supervisor's backoff
# instead of quarantining the whole stream at full consume rate.
CORR_QUARANTINE_BURST_MAX = int(os.environ.get("CORR_QUARANTINE_BURST_MAX", "100"))


def dlq_startup_check() -> None:
    """Fail fast at BOOT when CORR_DLQ_DIR is configured but not writable.

    The runtime write path (`_dlq_append`) deliberately never raises — the
    quarantine must not kill the consumer over one bad write. But that policy
    made a *permanently* unwritable DLQ invisible: the 2026-08 scale test lost
    238k dead-lettered payloads because the bind-mount source was owned by the
    wrong uid (root-created), every append failed, and the service kept
    starting and advancing offsets anyway. Durability that is configured but
    cannot work is a misconfiguration, and misconfigurations refuse to boot
    (same posture as the partial-TLS check above): probe the exact runtime
    write path once at startup and raise with the precise remedy.

    Unset CORR_DLQ_DIR is untouched — memory-only quarantine remains a legal
    (warned-about) posture; see `_dlq_append`.
    """
    if not CORR_DLQ_DIR:
        return
    path = os.path.join(CORR_DLQ_DIR, "corr-deadletter.ndjson")
    try:
        os.makedirs(CORR_DLQ_DIR, exist_ok=True)
        # Open the real dead-letter file for append — the exact operation
        # every quarantined payload needs — and fsync so a lying filesystem
        # (full/read-only remount) fails here, not at the first drop.
        with open(path, "a", encoding="utf-8") as f:
            f.flush()
            os.fsync(f.fileno())
    except OSError as exc:
        raise RuntimeError(
            f"CORR_DLQ_DIR={CORR_DLQ_DIR!r} is configured but NOT writable by "
            f"this process (uid={os.getuid()} gid={os.getgid()}): "
            f"{type(exc).__name__}: {exc}. Refusing to start: every "
            "dead-lettered payload would be silently lost while offsets "
            "advance. Fix the ownership of the HOST directory bind-mounted at "
            f"{CORR_DLQ_DIR} (compose default: data/correlation/deadletter) "
            f"and restart:\n"
            f"    sudo chown -R {os.getuid()}:{os.getgid()} "
            "data/correlation/deadletter\n"
            "or rerun scripts/install.py, which repairs data/ ownership."
        ) from exc
    log.info("CORR_DLQ_DIR=%s verified writable at startup", CORR_DLQ_DIR)


# DLQ WRITE PATH — measured during the 2026-08-17 P1 investigation and
# DELIBERATELY LEFT SYNCHRONOUS. On the live volume the per-record syscall
# pattern (makedirs + getsize + open/append/close) costs p50 102us / p99 429us
# / max 7.1ms, i.e. a ~7.5k records/s ceiling; at the ladder's 1784/s
# mass-refusal rate that is ~18% of the event loop, with multi-ms hitches. It
# is real, but it is O(1) PER RECORD — bounded independently of backlog, fleet
# size and object size — so it cannot produce the 30-400s stalls that caused
# the rebalance loop (those were the per-object graph serializations above).
#
# Batching it behind an off-loop flush was prototyped and rejected for now: it
# trades the immediate-durability property that seven durability tests and the
# 238k-lost-payload incident (dlq_startup_check) are built on for a saving that
# is not on the critical path. If corr_loop_lag_stalls_total ever implicates
# this path, the loop-lag watchdog will say so with a number, and THEN it is
# worth its own change. See docs/scale-correlation.md.
def _dlq_append(record: dict) -> None:
    """Append one quarantined event to the on-disk dead-letter file.

    Bounded by CORR_DLQ_MAX_BYTES so a poison producer can never fill the volume.
    At the cap the file ROTATES (one .1 kept) rather than silently dropping — the
    previous version just `return`ed with no counter, which is the accept-and-
    ignore defect (F-38) reappearing inside the safety net that exists to catch
    it. A dropped dead-letter is a lost payload with nothing to say so.

    A write failure is counted (QUARANTINE_WRITE_FAILURES, a scraped metric),
    never raised: quarantine must not itself become the failure that kills the
    consumer.
    """
    global QUARANTINE_WRITE_FAILURES, QUARANTINE_ROTATIONS
    if not CORR_DLQ_DIR:
        # Memory-only quarantine (ring buffer) is NOT durable across a restart.
        # In a deployment that means an RCA-critical payload can be lost when the
        # offset has already auto-committed. Surface it once so the operational
        # posture is visible rather than assumed. See the compose default.
        global _DLQ_UNSET_WARNED
        if not _DLQ_UNSET_WARNED:
            _DLQ_UNSET_WARNED = True
            log.warning("CORR_DLQ_DIR unset — quarantine is in-memory only and "
                        "does NOT survive a restart; set it to a durable volume")
        return
    path = os.path.join(CORR_DLQ_DIR, "corr-deadletter.ndjson")
    try:
        os.makedirs(CORR_DLQ_DIR, exist_ok=True)
        try:
            if os.path.getsize(path) >= CORR_DLQ_MAX_BYTES:
                # Rotate: keep exactly one prior generation. Retains the most
                # recent 2×CAP of evidence instead of freezing at CAP and
                # dropping everything after — silently.
                os.replace(path, path + ".1")
                QUARANTINE_ROTATIONS += 1
                log.warning("dead-letter file hit %d bytes — rotated to .1 "
                            "(rotations=%d)", CORR_DLQ_MAX_BYTES, QUARANTINE_ROTATIONS)
        except OSError:
            pass
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except (OSError, TypeError, ValueError) as exc:
        QUARANTINE_WRITE_FAILURES += 1
        log.error("dead-letter write failed (total=%d): %s",
                  QUARANTINE_WRITE_FAILURES, type(exc).__name__)


def _quarantine_record(topic: str, event: object, exc: BaseException) -> dict:
    """Build + store one quarantine record (ring + optional on-disk NDJSON)."""
    if isinstance(exc, TenantClaimRefused) and exc.reason == "identity_unattributable":
        # F-11 (INV-F11-10): a registry-MISS event is sealed by the ROUTER's
        # quarantine stage. Keeping its body here — in the /deadletters ring
        # AND the durable corr-deadletter.ndjson — would be a second, PLAINTEXT
        # durable copy of what the router just encrypted: the exact
        # confidentiality downgrade the owner invariant forbids. Store metadata
        # plus the identity's sha256 only (the SAME digest the router envelope
        # carries as identity_sha, so an operator can join the two records and
        # feed /api/quarantine/reattribute). Never the event body, and never
        # the plaintext identity (D2: hostname deliberately not kept). Every
        # other dead-letter class keeps its payload for forensics, unchanged.
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "topic": topic,
            "lane": exc.lane,
            "reason": exc.reason,
            "identity_sha": hashlib.sha256(
                exc.identity.encode("utf-8", "replace")).hexdigest(),
            "error": "TenantClaimRefused: identity_unattributable "
                     "(payload withheld — the router's sealed quarantine holds it; F-11)",
        }
        QUARANTINE.append(record)
        _dlq_append(record)
        return record
    if isinstance(event, (bytes, bytearray)):
        # Raw wire bytes — a payload that failed to DECODE. Keep them as text
        # (errors="replace": a mangled byte becomes U+FFFD, nothing is dropped)
        # rather than a b'...' repr, so the poison record stays greppable and
        # can be replayed from the dead-letter file.
        payload = bytes(event).decode("utf-8", "replace")[:CORR_QUARANTINE_PAYLOAD_CHARS]
    else:
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


# ── horizontal scale: tenant-keyed co-partitioning (scale P0) ────────────────
#
# THE CONTRACT: every producer onto the 12 consumed topics keys each record by
# the tenant the engine will attribute it to (fallback "global"), using the
# Java-compatible murmur2 partitioner (Vector sinks: librdkafka
# `murmur2_random`; cloud-ingest: kafka-python's default murmur2; flows are
# re-keyed by vector-router — goflow2 itself cannot key by tenant). With every
# topic created at the SAME partition count (kafka-init `BUS_PARTITIONS`) and
# the RANGE assignor below, instance k of `docker compose up --scale
# correlation=N` owns partition k of EVERY topic — a complete, disjoint slice
# of tenants with worker-local state (Kafka-Streams-style co-partitioned
# tasks). The engine core is tenant-partitioned (run_window refuses a
# mixed-tenant window), so N slices produce the union a single instance would,
# below the capacity caps (WINDOW_BUFFER / series LRU budgets are per-process
# — see docs/scale-correlation.md).
#
# aiokafka's DEFAULT assignor is RoundRobin, which spreads TopicPartitions
# round-robin over members — partition k of topic A and partition k of topic B
# can land on DIFFERENT members, silently breaking tenant stickiness. Range
# assigns each topic's partition list contiguously over the same sorted member
# list, so equal partition counts ⇒ member i owns partition set i of every
# topic. Pinned here and by test_scale_copartition.py.

CONSUMER_ASSIGNMENT: dict[str, list[int]] = {}   # topic -> owned partitions (last rebalance)
CONSUMER_PARTITION_TOTALS: dict[str, int] = {}   # topic -> total partitions (broker metadata)
CONSUMER_REBALANCES = 0                          # monotonic; /healthz + logs
CONSUMER_REVOKE_COMMITS = 0                      # revoke-hook flush+commit landed
CONSUMER_REVOKE_COMMIT_FAILURES = 0              # revoke-hook could not commit (replay-safe)
# Rebalances that assigned this instance ZERO partitions. Distinct from "no
# rebalance yet": a member that JOINED and got nothing is a misconfiguration
# (more replicas than BUS_PARTITIONS — the range assignor leaves the surplus
# empty) and contributes no throughput forever. Before this counter both states
# serialized to `{}` on /healthz and the idle replica looked healthy.
CONSUMER_ZERO_ASSIGNMENTS = 0
# Has an assignment callback ever run? The state machine below must NOT infer
# this from `CONSUMER_REBALANCES > 0` — that is racy (the counter is bumped
# inside the callback) and cannot express the cold-window state at all.
CONSUMER_ASSIGNMENT_SEEN = False
# "topic:partition" -> monotonic clock when THIS replica first acquired it.
# Retained partitions keep their original timestamp across a rebalance; released
# ones are dropped. Feeds the cold-window state (see consumer_state).
CONSUMER_PARTITION_ACQUIRED_AT: dict[str, float] = {}
# Revokes where the pre-hand-off flush did NOT finish inside its budget, so the
# hook returned WITHOUT committing (F-38: an uncommitted offset is replayed and
# dedup absorbs it). Rising = rebalances are landing on a slow ClickHouse.
CONSUMER_REVOKE_SKIPPED = 0


def tenant_partition(tenant: str, num_partitions: int) -> int:
    """The partition a tenant's records land on — mirrors every producer's
    keying (Java murmur2 on the UTF-8 tenant key, positive-masked, mod N).
    The single source of truth for 'which instance owns tenant T'."""
    key = (tenant or "global").encode("utf-8")
    return (murmur2(key) & 0x7FFFFFFF) % max(1, int(num_partitions))


class _AssignmentLogger(ConsumerRebalanceListener):
    """Records + logs partition ownership at every rebalance, and verifies the
    co-partitioning invariant: with the range assignor and equal partition
    counts, this member's partition SET must be identical across all 12
    topics. A mismatch means the topics' partition counts diverged (e.g. a
    failed `kafka-topics --alter` after raising BUS_PARTITIONS) — tenants
    would be split across instances, so it is an ERROR, not a debug line."""

    def __init__(self, consumer: AIOKafkaConsumer) -> None:
        self._consumer = consumer
        # P1 thrash fix: consume() installs its flush-then-commit closure here
        # so work that is already durably persisted is acknowledged BEFORE the
        # partitions move to another member (aiokafka keeps the member's
        # heartbeat alive during this callback precisely so it can commit).
        # None until consume() wires it — a bare listener stays log-only.
        self.revoke_hook: Callable[[], Awaitable[None]] | None = None

    async def on_partitions_revoked(self, revoked) -> None:
        log.info("rebalance: %d partition(s) revoked", len(revoked))
        if self.revoke_hook is None or not revoked:
            return
        global CONSUMER_REVOKE_COMMITS, CONSUMER_REVOKE_COMMIT_FAILURES
        try:
            # TIGHTLY bounded (§9) — this callback runs INSIDE the rejoin, so
            # every second spent here is a second the group is not re-forming.
            # The first version capped the whole hook at rebalance_timeout (60s),
            # which let one slow ClickHouse flush add up to a full rebalance
            # timeout of latency PER REVOKE and risked turning the thrash loop
            # self-sustaining (starve -> revoke -> 60s of flush -> re-revoke).
            # Live counters from the thrash window support that reading:
            # correlation-1 logged 20 rebalances against 17 hook runs, 6 of them
            # FAILED (i.e. hit the old bound). The budget is now
            # 2x CORR_REVOKE_BUDGET_S as a pure backstop; the hook bounds its
            # own flush and commit individually (see _revoke_commit).
            await asyncio.wait_for(
                self.revoke_hook(), timeout=2 * CORR_REVOKE_BUDGET_S)
            CONSUMER_REVOKE_COMMITS += 1
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — a raise here would kill the rejoin
            # Replay-safe by design: an uncommitted offset is redelivered and
            # the dedup machinery (per-message tokens + the batcher's commit
            # guard) absorbs it. Counted + logged, never silent (§10).
            CONSUMER_REVOKE_COMMIT_FAILURES += 1
            log.warning("revoke-time flush/commit failed (replay-safe, dedup "
                        "absorbs the redelivery): %s", type(exc).__name__)

    async def on_partitions_assigned(self, assigned) -> None:
        global CONSUMER_REBALANCES
        CONSUMER_REBALANCES += 1
        owned: dict[str, list[int]] = {t: [] for t in TOPICS}
        for tp in assigned:
            owned.setdefault(tp.topic, []).append(tp.partition)
        for parts in owned.values():
            parts.sort()
        CONSUMER_ASSIGNMENT.clear()
        CONSUMER_ASSIGNMENT.update(owned)
        # Cold-window bookkeeping (see consumer_state): RETAINED partitions keep
        # their original acquisition time, NEWLY acquired ones start their window
        # now, released ones are forgotten. Recorded here — never inferred from
        # the rebalance counter, which cannot express "cold".
        global CONSUMER_ASSIGNMENT_SEEN
        CONSUMER_ASSIGNMENT_SEEN = True
        now_mono = time.monotonic()
        held = {f"{t}:{p}" for t, parts in owned.items() for p in parts}
        for key in list(CONSUMER_PARTITION_ACQUIRED_AT):
            if key not in held:
                del CONSUMER_PARTITION_ACQUIRED_AT[key]
        for key in held:
            CONSUMER_PARTITION_ACQUIRED_AT.setdefault(key, now_mono)
        for topic in TOPICS:
            total = self._consumer.partitions_for_topic(topic)
            if total:
                CONSUMER_PARTITION_TOTALS[topic] = len(total)
        log.info("rebalance #%d: assignment=%s totals=%s", CONSUMER_REBALANCES,
                 {t: p for t, p in owned.items() if p}, dict(CONSUMER_PARTITION_TOTALS))
        if not assigned:
            # Joined the group and got NOTHING. Silent-failure class: this
            # replica will never consume, but every health signal looks normal.
            # Name the cause AND the remedy — the range assignor gives the
            # surplus replicas beyond BUS_PARTITIONS an empty set by design.
            global CONSUMER_ZERO_ASSIGNMENTS
            CONSUMER_ZERO_ASSIGNMENTS += 1
            log.warning(
                "rebalance #%d assigned 0 partitions — THIS REPLICA IS IDLE and "
                "will consume nothing (zero_assignments=%d). Instances beyond "
                "BUS_PARTITIONS are idle by design with the range assignor: "
                "raise BUS_PARTITIONS (and re-run kafka-init) or reduce the "
                "replica count. Partition totals seen: %s",
                CONSUMER_REBALANCES, CONSUMER_ZERO_ASSIGNMENTS,
                dict(CONSUMER_PARTITION_TOTALS))
        distinct = {tuple(p) for p in owned.values()}
        if len(distinct) > 1:
            log.error("CO-PARTITIONING BROKEN: this member owns different "
                      "partition sets per topic (%s) — topic partition counts "
                      "have diverged; re-run kafka-init with BUS_PARTITIONS "
                      "and check `kafka-topics --describe`",
                      {t: p for t, p in owned.items()})


def consumer_state(now_mono: float | None = None) -> str:
    """This replica's consumer state — FOUR distinguishable values, not two.

      "pending"      no assignment callback has run yet. Says nothing about
                     health; single-replica/broker-less dev sits here briefly.
      "idle"         joined the group and holds ZERO partitions. A
                     MISCONFIGURATION: with the range assignor the replicas
                     beyond BUS_PARTITIONS get an empty set and consume nothing
                     forever. Before this state existed it serialized to `{}`,
                     byte-identical to "pending", and looked healthy.
      "cold_window"  holds partitions, but at least one was acquired less than
                     one engine window ago, so its tenants' sliding window has
                     not had time to refill. RCA output for those tenants is
                     temporarily DEGRADED (thin window) rather than wrong.
      "active"       holds partitions, all held for at least one engine window.

    HONEST LIMITATION (tracker 155). "cold_window" is a TIME-BASED PROXY, not a
    measurement of carried-over state. `OPEN_OBJECTS` and `WINDOW_BUFFER` are
    per-process with NO rehydration path, so a partition acquired at a rebalance
    necessarily starts with none of its tenants' in-flight correlation state —
    that state is stranded in whichever replica held the partition before. This
    field therefore reports "the window has not had time to refill yet"; it does
    NOT and cannot report the deeper loss tracker 155 covers (merges and
    continuations whose open objects lived in the other replica's memory are
    gone, and no elapsed time repairs them). Do not read "active" as "no state
    was lost at the last rebalance".
    """
    if not CONSUMER_ASSIGNMENT_SEEN:
        return "pending"
    if not any(CONSUMER_ASSIGNMENT.values()):
        return "idle"
    now_mono = time.monotonic() if now_mono is None else now_mono
    if any((now_mono - t) < ENGINE_CFG.window_s
           for t in CONSUMER_PARTITION_ACQUIRED_AT.values()):
        return "cold_window"
    return "active"


def cold_partitions(now_mono: float | None = None) -> list[str]:
    """The owned partitions still inside their first engine window (see
    consumer_state). Named explicitly so an operator can see WHICH tenants'
    RCA is thin, not just that some are."""
    now_mono = time.monotonic() if now_mono is None else now_mono
    return sorted(k for k, t in CONSUMER_PARTITION_ACQUIRED_AT.items()
                  if (now_mono - t) < ENGINE_CFG.window_s)


def owns_tenant(tenant: str, *, topic: str = "netops.cloud") -> bool:
    """Does THIS instance own `tenant`'s partition of `topic`?

    Used to elect exactly one replica for singleton side-inputs (the cloud-log
    tailer). Fail-OPEN before the first rebalance (no assignment recorded yet
    — single-replica/offline behavior unchanged); fail-closed once an
    assignment exists and excludes the tenant's partition."""
    total = CONSUMER_PARTITION_TOTALS.get(topic)
    if not total or not CONSUMER_ASSIGNMENT:
        return True
    return tenant_partition(tenant, total) in CONSUMER_ASSIGNMENT.get(topic, [])


def build_consumer() -> AIOKafkaConsumer:
    """Construct (but do not start) the co-partitioned group consumer.

    A factory so tests can pin the wiring: range assignor (co-partitioning),
    manual commit, no deserializer, subscription with the rebalance listener."""
    consumer = AIOKafkaConsumer(
        bootstrap_servers=KAFKA_BOOTSTRAP,
        group_id="netops-correlation",
        auto_offset_reset="latest",
        # Co-partitioning: see the scale-P0 comment above. Round-robin (the
        # aiokafka default) breaks tenant stickiness across topics.
        partition_assignment_strategy=(RangePartitionAssignor,),
        # P1 max-poll thrash: explicit group-membership contract — the
        # arithmetic behind these values lives at CORR_SESSION_TIMEOUT_MS.
        session_timeout_ms=CORR_SESSION_TIMEOUT_MS,
        heartbeat_interval_ms=CORR_HEARTBEAT_INTERVAL_MS,
        max_poll_interval_ms=CORR_MAX_POLL_INTERVAL_MS,
        rebalance_timeout_ms=CORR_REBALANCE_TIMEOUT_MS,
        # SEC-006.2: {} on the plaintext baseline; SSL + the correlation
        # SVID when the KAFKA_SSL_* env is present (kafka_security_kwargs).
        **KAFKA_SECURITY,
        # NO value_deserializer, deliberately. aiokafka runs the deserializer
        # inside its fetcher (_consumer_record) BEFORE it advances
        # next_fetch_offset — so a malformed payload raised OUTSIDE the
        # per-event try below, escaped to the supervisor, and (with manual
        # commit) the offset never moved: the restart re-read the same poison
        # bytes forever and every one of the topics starved, with no counter
        # moving to say so. Decoding moved INSIDE the per-event try, where
        # the existing quarantine path preserves the payload and the offset
        # advances past it. Keep the raw bytes here.
        # Tracker #126 (write-integrity criterion 8): offsets advance ONLY
        # after the handler returned — never on a timer that runs ahead of
        # the outcome. Auto-commit could commit an offset whose handler then
        # crashed BEFORE the durable-DLQ append, losing the event silently.
        # A quarantined event counts as handled (its payload is preserved);
        # redelivery after a crash is safe because every critical insert
        # carries the Phase-3 dedup token (set_dedup_coord below).
        enable_auto_commit=False,
    )
    # Topics via subscribe() (not the constructor) so the rebalance listener
    # sees every assignment — the ownership log/check above.
    listener = _AssignmentLogger(consumer)
    consumer.subscribe(topics=list(TOPICS), listener=listener)
    # Same-module wiring point for consume()'s revoke hook (the closure over
    # the commit ledger cannot exist before the consumer does).
    consumer._corr_listener = listener  # our own consumer instance, same module
    return consumer


async def consume() -> None:
    """Supervised consumer: a poison batch / codec error / broker hiccup is
    logged and retried with backoff, NEVER a silent task death (§10 — the
    pre-build-⑥ consumer died unobserved on a snappy-compressed batch and
    starved the whole engine; this loop is the guarantee that can't recur).
    Every broker-facing await is BOUNDED so the guarantee holds even when the
    broker itself is wedged (see CONSUMER_*_TIMEOUT_S above)."""
    backoff = 1.0
    while True:
        consumer = build_consumer()
        # Batched manual commit: per-message commits would round-trip the broker
        # on every event. Committing every N/T bounds replay after a crash to at
        # most N already-handled messages — which dedup absorbs.
        uncommitted = 0
        last_commit = time.monotonic()
        # F-38 ledger: next-commit offset per partition, advanced ONLY after a
        # message was handled (or durably quarantined — that counts as handled).
        # The revoke hook commits exactly this dict, so a rebalance that fires
        # MID-handle can never acknowledge the in-flight message.
        handled_offsets: dict[TopicPartition, int] = {}
        since_yield = 0

        async def _commit(force: bool = False, consumer: AIOKafkaConsumer = consumer) -> None:
            # `consumer` bound at definition time (B023): the enclosing while-loop
            # rebinds it each supervision round, and this closure must always
            # commit on the consumer of ITS round, never a later one.
            nonlocal uncommitted, last_commit
            if uncommitted == 0:
                return
            if not force and uncommitted < CORR_COMMIT_EVERY_N \
                    and (time.monotonic() - last_commit) < CORR_COMMIT_EVERY_S:
                return
            # At-least-once anchor for the batched writes: never acknowledge an
            # offset whose corr_signals rows are still buffered. A flush failure
            # (transport/unknown) raises HERE, the commit is skipped, and the
            # supervisor replays from the last committed offset; a positive
            # rejection preserved the rows durably inside flush(), which counts
            # as handled — exactly the per-row discipline, at batch granularity.
            await SIGNAL_BATCH.flush()
            await asyncio.wait_for(consumer.commit(), timeout=CONSUMER_STOP_TIMEOUT_S)
            # Every flushed row's offset is now committed — the batcher's
            # replay guard has nothing left to absorb (P1 thrash fix).
            SIGNAL_BATCH.note_committed()
            uncommitted = 0
            last_commit = time.monotonic()

        async def _revoke_commit(consumer: AIOKafkaConsumer = consumer,
                                 handled_offsets: dict = handled_offsets) -> None:
            # Rebalance listener hook (P1 max-poll thrash): before this
            # member's partitions move, land what is already safely persisted
            # so the successor (or this member's own rejoin) does not replay
            # the whole uncommitted batch. Flush FIRST (never acknowledge an
            # offset whose rows are still buffered — the F-38 anchor), then
            # commit ONLY the handled ledger: the in-flight message's offset
            # is not in it, so a revoke mid-handle cannot advance past
            # unpersisted work. The batcher's replay guard is deliberately
            # NOT cleared here — the hook's flush may include rows of the
            # in-flight message, whose offset stays uncommitted.
            nonlocal uncommitted, last_commit
            global CONSUMER_REVOKE_SKIPPED
            # Each leg gets its OWN small budget (CORR_REVOKE_BUDGET_S): this
            # runs inside the rejoin, so a slow ClickHouse must cost the group a
            # few seconds, never a full rebalance timeout. If the flush does not
            # finish in budget we SKIP the commit and return — F-38 holds
            # because nothing is acknowledged, and the redelivery is absorbed by
            # the per-message dedup tokens plus the batcher's commit guard.
            try:
                await asyncio.wait_for(SIGNAL_BATCH.flush(),
                                       timeout=CORR_REVOKE_BUDGET_S)
            except asyncio.TimeoutError:
                CONSUMER_REVOKE_SKIPPED += 1
                log.warning(
                    "revoke-time flush exceeded %.0fs — NOT committing (offsets "
                    "stay unacknowledged; the successor replays and dedup "
                    "absorbs it). skipped_total=%d",
                    CORR_REVOKE_BUDGET_S, CONSUMER_REVOKE_SKIPPED)
                return
            if handled_offsets:
                await asyncio.wait_for(
                    consumer.commit(dict(handled_offsets)),
                    timeout=CORR_REVOKE_BUDGET_S)
                uncommitted = 0
                last_commit = time.monotonic()

        listener = getattr(consumer, "_corr_listener", None)
        if listener is not None:
            listener.revoke_hook = _revoke_commit

        try:
            await asyncio.wait_for(consumer.start(), timeout=CONSUMER_START_TIMEOUT_S)
            log.info("consuming topics=%s bootstrap=%s (manual commit, N=%d/T=%.0fs)",
                     TOPICS, KAFKA_BOOTSTRAP, CORR_COMMIT_EVERY_N, CORR_COMMIT_EVERY_S)
            backoff = 1.0
            consecutive_failures = 0
            async for msg in consumer:
                # Per-EVENT isolation: one bad record must cost one record, not
                # the whole ten-topic consumer (see quarantine_event above).
                event = None
                try:
                    # Phase 3: establish this message's dedup coordinate so every
                    # critical-table insert it drives carries a stable token — a
                    # retry/redelivery of THIS offset dedups instead of duplicating.
                    set_dedup_coord(msg.topic, msg.partition, msg.offset)
                    # Decode HERE, not in the consumer: a JSONDecodeError or
                    # UnicodeDecodeError is then just another one-event failure.
                    # Empty/tombstone values stay None (handle() no-ops on falsy).
                    event = json.loads(msg.value.decode("utf-8")) if msg.value else None
                    await handle(msg.topic, event)
                    consecutive_failures = 0
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    # `event` is still None when the DECODE itself failed —
                    # quarantine the RAW bytes then, so the poison payload that
                    # has to be reproduced is the one that gets kept.
                    quarantine_event(msg.topic, msg.value if event is None else event, exc)
                    consecutive_failures += 1
                    # A RUN of failures is not a poison event, it is a broken
                    # dependency (ClickHouse down). Tolerating those at full
                    # consume rate would quarantine the entire stream; hand it
                    # back to the supervisor so its backoff applies pressure.
                    # The quarantined message itself IS handled (payload kept)
                    # — commit through it so restart resumes AFTER it instead
                    # of replaying the poison forever.
                    if consecutive_failures >= CORR_QUARANTINE_BURST_MAX:
                        handled_offsets[TopicPartition(msg.topic, msg.partition)] = msg.offset + 1
                        uncommitted += 1
                        await _commit(force=True)
                        raise
                # Handled (or quarantined — payload durably kept): the ledger
                # may now advance past this message.
                handled_offsets[TopicPartition(msg.topic, msg.partition)] = msg.offset + 1
                uncommitted += 1
                await _commit()
                # Cooperative poll cadence (P1 max-poll thrash): aiokafka's
                # buffered fast path and an all-sync handler never yield, so
                # under a backlog this task could monopolize the event loop
                # between commit-triggered flushes and starve the heartbeat
                # task into a session-timeout ejection. Hand the loop back
                # every CORR_CONSUME_YIELD_EVERY_N messages (arithmetic at the
                # constant).
                since_yield += 1
                if since_yield >= CORR_CONSUME_YIELD_EVERY_N:
                    since_yield = 0
                    await asyncio.sleep(0)
        except asyncio.CancelledError:
            with contextlib.suppress(Exception):
                await _commit(force=True)  # clean shutdown: nothing replays
            await _stop_bounded(consumer)
            raise
        except Exception:
            log.exception("consumer failed; restarting in %.0fs", backoff)
            # NO commit here beyond what _commit already advanced: an offset
            # whose handler did not return stays unacknowledged, by design.
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
    elif topic == "netops.wireless_sessions":
        await handle_wireless_session(event)
    elif topic == "netops.wireless_events":
        await handle_wireless_event(event)


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

    # The claim is checked against the registry entry for the device the sample
    # names. Not registry-anchored: a canonical MetricEvent can legitimately
    # describe an entity the exporter has no inventory row for (a fresh device,
    # a cloud resource), so the registry is used to CONTRADICT a claim, never to
    # require one. A contradiction is refused + quarantined, never averaged.
    try:
        tenant = verified_tenant(str(ev.get("tenant_id") or ""),
                                 str(ev.get("device") or ""), "metrics")
    except TenantClaimRefused as exc:
        METRICS_DROPPED += 1
        keep_deadletter_payload("metrics", ev, exc)
        return
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
    # shared metric name, and on the VERIFIED tenant (M29b) so same-named
    # entities in different tenants never share a baseline. Superseded by the
    # episode detector above; kept until the findings surface retires.
    z = score(tenant, entity_id, metric, value)
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
        # M29b: the finding carries the tenant this event was VERIFIED under,
        # not a second registry lookup that can disagree with it.
        tenant_id=tenant,
    )


# Severity weights for syslog correlation. A burst of high-severity
# events from one device within a short window is itself a finding.
# BOTH spellings are keyed: the RFC 3164 short keywords (Cisco et al.) AND the
# long-form levels vendors like FortiOS emit (Vector's syslog_normalized passes
# kv.level through verbatim — 'critical'/'error'/'emergency'). Before the
# long forms were added, 50 FortiGate level=critical lines in 60s scored weight
# 0 and the burst finding silently never fired while identical Cisco 'crit'
# traffic did (vendor blind spot, journal PRI-0/F-severity finding). 'panic' and
# 'emerg' parity mirrors the aggregator's severity reconcile map.
SEVERITY_WEIGHT = {
    "emerg": 8, "panic": 8, "emergency": 8,
    "alert": 7,
    "crit": 6, "critical": 6,
    "err": 5, "error": 5,
    "warning": 3, "warn": 3,
    "notice": 2,
    "info": 1, "information": 1, "informational": 1,
    "debug": 0,
}
# Keyed by (tenant, hostname) — NOT hostname alone. Two tenants can each own a
# device named "core-sw1" (or hit the "unknown" fallback); a shared bucket let
# tenant A's log volume fire a burst finding stamped with tenant B (§3a
# cross-tenant leak), and made burst output depend on which tenants share an
# instance (scale P0 tenant-slice equivalence).
SYSLOG_BUCKET: dict[tuple[str, str], list[tuple[float, int]]] = {}
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
    # Most probe targets are external hosts the registry has never heard of, so
    # this lane is not registry-anchored — but when the target IS an inventory
    # device, a probe claiming a DIFFERENT tenant than that device's owner is a
    # cross-tenant write and is refused.
    try:
        tenant = verified_tenant(str(ev.get("tenant_id") or ""), host, "probes")
    except TenantClaimRefused as exc:
        DEADLETTER_COUNT += 1
        keep_deadletter_payload("probe", ev, exc)
        return
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
        await batch_signal(sig.to_ch_row())  # batched: lane=probes
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
        await batch_signal(app_sig.to_ch_row())  # batched: lane=probes
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
    # F-11 (D1/D4, INV-F11-10): registry-ANCHORED like syslog and flows — the
    # aggregator stamps the trap tenant SOLELY from the device→tenant registry,
    # and the router's generated quarantine stage seals snmptrap misses. A
    # no-claim trap whose identity the registry never heard of is therefore
    # TENANT_UNATTRIBUTABLE and joins the durable quarantine; it must NOT
    # process as 'global' into corr_signals/RCA/ticketing while the router
    # seals the same event. The old NAT-ambiguity concern is answered by D1:
    # ambiguous identities are deliberately OMITTED from the registry, so they
    # are misses that must quarantine (recoverable), not process. The identity
    # mirrors the router's quarantine stage: device, falling back to the
    # transport source address — the two tiers must agree on what is
    # attributable, or a router-restored trap would be re-refused here.
    try:
        tenant = verified_tenant(str(ev.get("tenant_id") or ""),
                                 device or str(ev.get("host") or ""),
                                 "snmptrap", registry_anchored=True)
    except TenantClaimRefused as exc:
        DEADLETTER_COUNT += 1
        TRAPS_DROPPED += 1
        keep_deadletter_payload("trap", ev, exc)
        return
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
    await batch_signal(sig.to_ch_row())  # batched: lane=snmptrap
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
    await batch_signal(sig.to_ch_row())  # batched: lane=controller_events
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
    await batch_signal(sig.to_ch_row())  # batched: lane=verification
    VERIFICATION_SIGNALS += 1
    buffer_signal(sig)
    log.info("verification signal %s %s: %s", sig.kind, sig.attrs.get("check", ""), sig.entity_id)


async def handle_wireless_session(ev: dict) -> None:
    """Wireless client-session record (netops.wireless_sessions, #128 Phase 4)
    → netops.wireless_sessions CH row (+ MLO link rows). PURELY the per-client
    event tier: session records are troubleshooting data and NEVER become
    engine signals (the §20 volume rule — onboarding FAILURES are the signal
    lane, handle_wireless_event). Tenancy explicit, default-closed. A non-MLO
    client is an MLO client with one link (report §10): a session with no
    links list still writes one implicit link row so every query works
    against wireless_mlo_links from day one."""
    global WIRELESS_RECEIVED, WIRELESS_DROPPED
    WIRELESS_RECEIVED += 1
    if ch is None:
        return
    tenant = str(ev.get("tenant_id") or "")
    session_id = str(ev.get("session_id") or "")
    client_mac = str(ev.get("client_mac") or "")
    bssid = str(ev.get("bssid") or "")
    if not tenant or not session_id or not client_mac or not bssid:
        WIRELESS_DROPPED += 1
        log.warning("wireless session dropped: missing identity (tenant=%r session=%r)",
                    tenant, session_id)
        return
    # The claim is cross-checked against the registry entry for the OBSERVER
    # (controller / AP) that reported the session. Wireless client data is
    # per-tenant PII, so a session claiming a tenant the reporting observer does
    # not belong to is refused, not stored.
    try:
        tenant = verified_tenant(tenant, str(ev.get("observer_id") or ""), "wireless")
    except TenantClaimRefused as exc:
        WIRELESS_DROPPED += 1
        keep_deadletter_payload("wireless", ev, exc)
        return
    cid, confidence, method = wo_client_identity(
        tenant, client_mac,
        eap_cn=str(ev.get("eap_cn") or ""), username=str(ev.get("username") or ""),
        dhcp_client_id=str(ev.get("dhcp_client_id") or ""), session_seed=session_id)
    links = ev.get("links") or []
    row = {
        "tenant_id": tenant, "session_id": session_id,
        "client_mac": client_mac.lower(),
        "mld_mac": str(ev.get("mld_mac") or client_mac).lower(),
        "client_id": cid, "identity_confidence": confidence, "identity_method": method,
        "bssid": bssid.lower(), "ap_ref": str(ev.get("ap_ref") or ""),
        "radio_ref": str(ev.get("radio_ref") or ""),
        "wlan_ref": str(ev.get("wlan_ref") or ""),
        "ssid_name": str(ev.get("ssid_name") or ""),
        "username": str(ev.get("username") or ""),
        "ip_v4": str(ev.get("ip_v4") or ""), "ip_v6": str(ev.get("ip_v6") or ""),
        "is_mlo": bool(ev.get("is_mlo") or len(links) > 1),
        "link_count": max(1, len(links)),
        "assoc_start": int(ev.get("assoc_start_ms") or 0),
        "assoc_end": int(ev["assoc_end_ms"]) if ev.get("assoc_end_ms") else None,
        "end_reason": str(ev.get("end_reason") or ""),
        "observer_id": str(ev.get("observer_id") or ""),
        "collection_path": str(ev.get("collection_path") or "via_controller"),
        "data_class": str(ev.get("data_class") or "live"),
    }
    await ch_insert("netops.wireless_sessions", [row], lane="wireless")
    link_rows = []
    for i, ln in enumerate(links if links else [{}]):
        link_rows.append({
            "tenant_id": tenant,
            "link_id": f"{session_id}|{i}",
            "session_ref": session_id, "link_index": i,
            "band": str(ln.get("band") or ""),
            "radio_ref": str(ln.get("radio_ref") or ev.get("radio_ref") or ""),
            "bssid_ref": str(ln.get("bssid") or bssid).lower(),
            "link_state": str(ln.get("link_state") or "active"),
            "rssi_dbm": float(ln.get("rssi_dbm") or 0),
            "snr_db": float(ln.get("snr_db") or 0),
            "mcs": int(ln.get("mcs") or 0), "nss": int(ln.get("nss") or 0),
            "channel": int(ln.get("channel") or 0),
            "channel_width_mhz": int(ln.get("channel_width_mhz") or 0),
            "valid_from": int(ev.get("assoc_start_ms") or 0),
            "data_class": str(ev.get("data_class") or "live"),
        })
    await ch_insert("netops.wireless_mlo_links", link_rows, lane="wireless")


async def handle_wireless_event(ev: dict) -> None:
    """Wireless onboarding/roam observations (netops.wireless_events, #128
    Phase 4). `type=onboarding` events assemble an applicability-aware episode
    (wireless_onboarding.py): the EPISODE always lands in ClickHouse; only a
    terminal failure/degraded emits ONE engine signal at the terminal phase's
    kind (§20 — successes never enter the window). `type=roam` events write
    the deduped roam row (both APs may report one roam; the deterministic
    roam_id collapses them)."""
    global WIRELESS_RECEIVED, WIRELESS_SIGNALS, WIRELESS_DROPPED
    WIRELESS_RECEIVED += 1
    if ch is None:
        return
    tenant = str(ev.get("tenant_id") or "")
    if not tenant:
        WIRELESS_DROPPED += 1
        return
    # Same observer cross-check as handle_wireless_session.
    try:
        tenant = verified_tenant(tenant, str(ev.get("observer_id") or ""), "wireless")
    except TenantClaimRefused as exc:
        WIRELESS_DROPPED += 1
        keep_deadletter_payload("wireless", ev, exc)
        return
    etype = str(ev.get("type") or "")
    if etype == "onboarding":
        client_mac = str(ev.get("client_mac") or "")
        bssid = str(ev.get("bssid") or "")
        start_ms = int(ev.get("attempt_start_ms") or 0)
        if not client_mac or not bssid or not start_ms:
            WIRELESS_DROPPED += 1
            return
        ep = assemble_wireless_episode(
            tenant, client_mac, bssid, str(ev.get("ap_ref") or ""),
            dict(ev.get("wlan") or {}), dict(ev.get("observations") or {}),
            datetime.fromtimestamp(start_ms / 1000, tz=timezone.utc),
            str(ev.get("observer_id") or ""),
            wlan_ref=str(ev.get("wlan_ref") or ""),
            data_class=str(ev.get("data_class") or "live"))
        await ch_insert("netops.wireless_onboarding_episodes", [ep.to_ch_row()],
                        lane="wireless")
        sig = wireless_episode_signal(ep)
        if sig is not None and CORR_SIGNALS_ENABLED:
            await batch_signal(sig.to_ch_row())  # batched: lane=wireless
            WIRELESS_SIGNALS += 1
            buffer_signal(sig)
            log.info("wireless onboarding signal %s: %s", sig.kind, sig.entity_id)
    elif etype == "roam":
        client_mac = str(ev.get("client_mac") or "").lower()
        to_bssid = str(ev.get("to_bssid") or "").lower()
        ts_ms = int(ev.get("ts_ms") or 0)
        if not client_mac or not to_bssid or not ts_ms:
            WIRELESS_DROPPED += 1
            return
        # Deterministic roam id: both the old and new AP may report this roam;
        # bucketing ts to the report-uncertainty window collapses the pair.
        bucket = ts_ms // 5000
        roam_id = f"{client_mac}|{to_bssid}|{bucket}"
        await ch_insert("netops.wireless_roams", [{
            "tenant_id": tenant, "roam_id": roam_id, "client_mac": client_mac,
            "session_ref": str(ev.get("session_ref") or ""),
            "from_bssid": str(ev.get("from_bssid") or "").lower(),
            "to_bssid": to_bssid,
            "from_ap_ref": str(ev.get("from_ap_ref") or ""),
            "to_ap_ref": str(ev.get("to_ap_ref") or ""),
            "roam_type": str(ev.get("roam_type") or "unknown"),
            "duration_ms": int(ev.get("duration_ms") or 0),
            "ts": ts_ms,
            "observer_id": str(ev.get("observer_id") or ""),
            "collection_path": str(ev.get("collection_path") or "via_controller"),
            "data_class": str(ev.get("data_class") or "live"),
        }], lane="wireless")
    else:
        WIRELESS_DROPPED += 1


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
    # NOT run through verified_tenant (unlike syslog/flows/metrics/traps/probes/
    # wireless), and deliberately so: a cloud account, an app identity and an LB
    # host have NO device identity in device_tenant.csv to check a claim against,
    # and inventing one would mean matching a raw IP — which collides across
    # tenants in overlapping RFC1918 space and would refuse legitimate data. The
    # controls that DO apply here are the authenticated bus producer (F-08
    # ingest auth) and the default-closed empty-tenant drop below. Same for
    # handle_app_identity and handle_app_edge. If the registry ever grows cloud
    # resource identities, these three lanes get the same gate.
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
            await batch_signal(sig.to_ch_row())  # batched: lane=cloud
            CLOCK_SKEW_SIGNALS += 1
            log.info("clock-skew signal (cloud lane): %s skew=%.0fs",
                     sig.entity_id, float(sig.value))
        return
    await batch_signal(sig.to_ch_row())  # batched: lane=cloud
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
    await batch_signal(sig.to_ch_row())  # batched: lane=app_identity
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
    await batch_signal(sig.to_ch_row())  # batched: lane=app_edge
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
    # TENANT-HIGH-3: syslog reaches this process from an UNAUTHENTICATED UDP/TCP
    # 514 listener via syslog-ng → Vector, and Vector derives .tenant_id purely
    # from the device→tenant registry keyed on .hostname. So a tenant_id here is
    # only legitimate if it REPRODUCES the registry's answer for the hostname
    # this very event carries. Anything else — a made-up hostname with a real
    # tenant, a real hostname with someone else's tenant — is refused and
    # quarantined BEFORE any lane can persist it. Registry-anchored, so an
    # unknown hostname with a non-empty claim fails closed too.
    try:
        cp_tenant = verified_tenant(str(ev.get("tenant_id") or ""),
                                    str(ev.get("hostname") or ""),
                                    "syslog", registry_anchored=True)
    except TenantClaimRefused as exc:
        DEADLETTER_COUNT += 1
        keep_deadletter_payload("syslog", ev, exc)
        return
    if CORR_SIGNALS_ENABLED and ch is not None:
        # One clock read per event (tracker 156): datetime.now was called five
        # times per syslog line, and both producers want the SAME receive time
        # anyway — two reads could straddle a second boundary and stamp two
        # signals from one line with different receive clocks.
        recv_now = datetime.now(timezone.utc)
        try:
            cp_sig = syslog_control_signal(ev, cp_tenant, recv_now)
        except DeadLetter as exc:
            DEADLETTER_COUNT += 1
            keep_deadletter_payload("syslog", ev, exc)
            log.warning("dead-letter (syslog): %s", exc)
            cp_sig = None
        if cp_sig is not None:
            await batch_signal(cp_sig.to_ch_row())  # batched: lane=syslog
            SYSLOG_SIGNALS += 1
            buffer_signal(cp_sig)
            # DEBUG, not INFO (tracker 156). This fired once per accepted
            # signal — two lines per syslog event, ~4,000 lines/s at the GA
            # burst rate — and every one was formatted, written to stdout, and
            # then shipped through Vector into OpenSearch. The rate it was
            # reporting is already exposed as SYSLOG_SIGNALS / corr metrics, so
            # nothing observable is lost; the per-signal detail is still there
            # at debug level when someone is actually chasing one event.
            log.debug("control-plane signal %s: %s %s",
                      cp_sig.kind, cp_sig.entity_id, cp_sig.attrs.get("state", ""))
        # Port Intelligence physical-layer event (#94 P3b): transceiver/optics/
        # DOM/FEC syslog → sig.ent.spdc evidence kinds. Independent of the
        # control-plane classifier (a line can be one or the other, rarely both).
        try:
            pe_sig = port_event_signal(ev, cp_tenant, recv_now)
        except DeadLetter as exc:
            DEADLETTER_COUNT += 1
            keep_deadletter_payload("port_event", ev, exc)
            log.warning("dead-letter (port-event): %s", exc)
            pe_sig = None
        if pe_sig is not None:
            await batch_signal(pe_sig.to_ch_row())  # batched: lane=syslog
            SYSLOG_SIGNALS += 1
            buffer_signal(pe_sig)
            log.debug("port-event signal %s: %s", pe_sig.kind, pe_sig.entity_id)
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
            await batch_signal(skew_sig.to_ch_row())  # batched: lane=syslog
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
    # Tenant-scoped bucket key: cp_tenant is the VERIFIED tenant from the top
    # of this handler (a refused claim returned before reaching here), so two
    # tenants sharing a hostname can never pool weight into one finding — and
    # a finding's burst math is identical whether the tenant's slice runs
    # alone or alongside every other tenant (scale P0 equivalence).
    bkey = (cp_tenant, host)
    bucket = SYSLOG_BUCKET.setdefault(bkey, [])
    bucket.append((now, weight))
    # Drop expired entries.
    cutoff = now - SYSLOG_WINDOW
    SYSLOG_BUCKET[bkey] = [(t, w) for t, w in bucket if t >= cutoff]
    # The per-host LISTS were pruned but the KEY SET never was — and the key is
    # the device-supplied, spoofable syslog hostname, so a single misbehaving or
    # hostile sender could grow this map without limit. Sweep empty buckets, and
    # hard-cap the key set as the backstop.
    _sweep_syslog_buckets(now)
    total = sum(w for _, w in SYSLOG_BUCKET[bkey])
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
            tenant_id=cp_tenant,
        )
        SYSLOG_BUCKET[bkey] = []   # reset so we don't spam


async def handle_flow(ev: dict) -> None:
    """Accumulate per-(tenant, exporting-interface) flow VOLUME (C6). Cheap by
    design — flows are a firehose, so we aggregate O(1) here and never emit a signal
    per flow; _flush_flow_aggregator turns each per-interface total into one CUSUM
    sample per engine cycle. This is the passive_flow modality lane — the 4th
    independent witness class for the verdict gate (DDoS / top-talker-shift /
    port-scan SIGNATURES are future catalog growth on top of this volume series)."""
    global DEADLETTER_COUNT, FLOWS_RECEIVED, FLOWS_DROPPED
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
    # TENANT-HIGH-4: flows arrive from goflow2 on an unauthenticated collector
    # port and their tenancy is keyed on sampler_address — harder to forge than
    # a hostname, but still unauthenticated, and nothing stops a bus writer from
    # attaching a tenant_id of its choosing. Registry-anchored: the claim must
    # reproduce the registry's answer for THIS exporter, or the flow is refused.
    try:
        tenant = verified_tenant(str(ev.get("tenant_id") or ""), sampler,
                                 "flows", registry_anchored=True)
    except TenantClaimRefused as exc:
        DEADLETTER_COUNT += 1
        FLOWS_DROPPED += 1
        keep_deadletter_payload("flows", ev, exc)
        return
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
        # M29b: a caller that VERIFIED the event's tenant (handle_metric via
        # verified_tenant) stamps it; only tenant-less callers fall back to the
        # registry lookup (#20: same tenant discriminator as flows/logs).
        "tenant_id":   kwargs.get("tenant_id") or tenant_for(device),
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
    # Boot gate: a configured-but-unwritable dead-letter dir refuses startup
    # (raising here aborts uvicorn's lifespan startup → non-zero exit → the
    # container restarts loudly instead of silently losing evidence).
    dlq_startup_check()
    # Opt-in forensics (CORR_DIAG_MEMORY). Dormant by default: returns before
    # starting tracemalloc, creating a thread, or touching the filesystem.
    diagnostics.start()
    ch = CH(CLICKHOUSE_URL, CLICKHOUSE_USER, CLICKHOUSE_PASS)
    tasks = [
        asyncio.create_task(consume()),
        asyncio.create_task(engine_loop()),
        asyncio.create_task(cloud_log_tailer()),  # #81 P3B file source (opt-in)
        asyncio.create_task(batch_flush_loop()),  # ≤2s latency bound for batched writes
        asyncio.create_task(loop_lag_watchdog()),  # P1: names the next blocker itself
    ]
    if diagnostics.enabled():
        tasks.append(asyncio.create_task(diag_snapshot_loop()))
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
        # Shutdown flush: rows still buffered (e.g. engine-cycle episode signals
        # with no Kafka offset to hold them) must not die with the process. A
        # failure here was already counted by _note_ch_failure inside flush.
        with contextlib.suppress(Exception):
            await SIGNAL_BATCH.flush()
        await ch.close()


app = FastAPI(title="netops-correlation", version="0.1.0", lifespan=lifespan)

# APP-001: workload-identity authorization for the mTLS deployment. Dormant on
# the plaintext baseline (no CORR_TLS_ALLOWED_URIS -> enforcement off); under
# tls_serve.py the handshake has already limited callers to mesh-CA client
# certificates, and this narrows them to named SPIFFE identities — the Go api
# in full, the metric scraper and the container's own healthcheck on
# /metrics + /healthz only. Registered LAST so it runs FIRST (outermost) —
# only this add_middleware call's position matters for ordering; the import
# lives at the top of the file (E402).
app.add_middleware(PeerIdentityMiddleware)


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
        # M29a: z-score series budget — evictions must be alertable, not silent.
        "# HELP corr_zscore_series_evicted_total Legacy z-score baselines evicted by the LRU cap.",
        "# TYPE corr_zscore_series_evicted_total counter",
        f"corr_zscore_series_evicted_total {eng['series_evicted']}",
        "# TYPE corr_zscore_series gauge",
        f'corr_zscore_series{{k="len"}} {eng["series_len"]}',
        f'corr_zscore_series{{k="max"}} {eng["series_max"]}',
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
        # Perf defect #2/#3: batched write path + bounded archive slices.
        "# HELP corr_signal_batch Batched corr_signals write-path events.",
        "# TYPE corr_signal_batch counter",
        f'corr_signal_batch{{event="flushes"}} {BATCH_FLUSHES}',
        f'corr_signal_batch{{event="rows_flushed"}} {BATCH_ROWS_FLUSHED}',
        f'corr_signal_batch{{event="rows_quarantined"}} {BATCH_ROWS_QUARANTINED}',
        f'corr_signal_batch{{event="rows_replay_deduped"}} {BATCH_ROWS_REPLAY_DEDUPED}',
        # P1 max-poll thrash: revoke-hook flush+commit outcomes. "failed" is
        # replay-safe (dedup absorbs) but rising = rebalances are landing on a
        # broken flush path.
        "# HELP corr_consumer_revoke_commits_total Rebalance revoke-hook flush+commit outcomes.",
        "# TYPE corr_consumer_revoke_commits_total counter",
        f'corr_consumer_revoke_commits_total{{outcome="ok"}} {CONSUMER_REVOKE_COMMITS}',
        f'corr_consumer_revoke_commits_total{{outcome="failed"}} {CONSUMER_REVOKE_COMMIT_FAILURES}',
        f'corr_consumer_revoke_commits_total{{outcome="skipped"}} {CONSUMER_REVOKE_SKIPPED}',
        # An IDLE replica (joined the group, assigned nothing — more replicas
        # than BUS_PARTITIONS) consumes forever at zero rate while looking
        # healthy. owned_partitions==0 with rebalances>0 is that state; alert on
        # it rather than discovering it from a lag graph that never drains.
        "# HELP corr_consumer_owned_partitions Partitions assigned to THIS replica.",
        "# TYPE corr_consumer_owned_partitions gauge",
        f"corr_consumer_owned_partitions {sum(len(p) for p in CONSUMER_ASSIGNMENT.values())}",
        "# HELP corr_consumer_zero_assignments_total Rebalances that assigned this replica no partitions.",
        "# TYPE corr_consumer_zero_assignments_total counter",
        f"corr_consumer_zero_assignments_total {CONSUMER_ZERO_ASSIGNMENTS}",
        # Four-state gauge (1 = the replica is in that state). cold_window =
        # holds partitions acquired less than one engine window ago, so their
        # tenants' RCA is thin — degraded, not wrong. See consumer_state() for
        # the honest limitation (tracker 155).
        "# HELP corr_consumer_state Consumer state: pending|idle|cold_window|active.",
        "# TYPE corr_consumer_state gauge",
        *(f'corr_consumer_state{{state="{s}"}} {1 if consumer_state() == s else 0}'
          for s in ("pending", "idle", "cold_window", "active")),
        "# TYPE corr_consumer_cold_partitions gauge",
        f"corr_consumer_cold_partitions {len(cold_partitions())}",
        "# TYPE corr_signal_batch_pending gauge",
        f"corr_signal_batch_pending {SIGNAL_BATCH.pending()}",
        # P1: event-loop stall watchdog. corr_loop_lag_stalls_total rising means
        # something synchronous is blocking the loop — the exact condition that
        # starves aiokafka's heartbeat into a rebalance loop.
        "# HELP corr_loop_lag_stalls_total Loop-lag samples over the warn threshold.",
        "# TYPE corr_loop_lag_stalls_total counter",
        f"corr_loop_lag_stalls_total {LOOP_LAG_STALLS}",
        "# TYPE corr_loop_lag_max_ms gauge",
        f"corr_loop_lag_max_ms {LOOP_LAG_MAX_MS:.1f}",
        "# TYPE corr_loop_lag_ms gauge",
        f"corr_loop_lag_ms {LOOP_LAG_LAST_MS:.1f}",
        "# TYPE corr_archive_rows_written counter",
        f"corr_archive_rows_written {ARCHIVE_ROWS_WRITTEN}",
        "# TYPE corr_archive_slices_damped counter",
        f"corr_archive_slices_damped {ARCHIVE_SLICES_DAMPED}",
        # Housekeeping: the window-prune path. The 2026-08-20 review found the
        # service exposed NOTHING about its own maintenance work, so a 30,989 ms
        # prune stall was only findable with a bespoke forensic build. Low
        # cardinality on purpose — counts and durations, no per-tenant labels.
        "# HELP corr_prune_calls_total Window-prune invocations.",
        "# TYPE corr_prune_calls_total counter",
        f"corr_prune_calls_total {PRUNE_CALLS}",
        "# HELP corr_prune_evicted_total Signals evicted from the window by age.",
        "# TYPE corr_prune_evicted_total counter",
        f"corr_prune_evicted_total {PRUNE_EVICTED}",
        "# HELP corr_prune_seconds_last Duration of the most recent prune.",
        "# TYPE corr_prune_seconds_last gauge",
        f"corr_prune_seconds_last {PRUNE_SECONDS_LAST:.6f}",
        # The alertable one: a prune is synchronous, so this IS event-loop
        # blocking time. Rising toward the session timeout means membership is
        # at risk.
        "# HELP corr_prune_seconds_max Worst prune duration this process (loop-blocking).",
        "# TYPE corr_prune_seconds_max gauge",
        f"corr_prune_seconds_max {PRUNE_SECONDS_MAX:.6f}",
        # Non-zero means the window and its id index drifted and had to be
        # rebuilt — correct but slow, and it should never happen in production.
        "# HELP corr_window_id_order_resyncs_total Window/id-index drift rebuilds.",
        "# TYPE corr_window_id_order_resyncs_total counter",
        f"corr_window_id_order_resyncs_total {WINDOW_ID_ORDER_RESYNCS}",
        "# HELP corr_prune_yields_total Loop hand-backs during pruning (chunk boundaries).",
        "# TYPE corr_prune_yields_total counter",
        f"corr_prune_yields_total {PRUNE_YIELDS}",
        # Rising means the evidence window is FULL and shedding its oldest
        # signals to make room — RCA is getting thinner, which used to be
        # invisible.
        "# HELP corr_window_overflow_dropped_total Signals dropped because the window was full.",
        "# TYPE corr_window_overflow_dropped_total counter",
        f"corr_window_overflow_dropped_total {WINDOW_OVERFLOW_DROPPED}",
    ]
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
        # TENANT-HIGH-3/4: a forged/contradicted tenant claim must be an ALERT,
        # not a log line nobody reads. Bounded cardinality: lane:reason pairs.
        "# HELP corr_tenant_claims_total Self-declared tenant_ids checked against the device registry.",
        "# TYPE corr_tenant_claims_total counter",
        f'corr_tenant_claims_total{{outcome="verified"}} {TENANT_CLAIMS_VERIFIED}',
        f'corr_tenant_claims_total{{outcome="refused"}} {TENANT_CLAIMS_REFUSED}',
        "# HELP corr_tenant_claims_refused_total Refused tenant claims by lane and reason.",
        "# TYPE corr_tenant_claims_refused_total counter",
    ]
    for key, n in sorted(TENANT_REFUSALS.items()):
        lane, _, reason = key.partition(":")
        lines.append(f'corr_tenant_claims_refused_total{{lane="{lane}",reason="{reason}"}} {n}')
    lines += [
        "# HELP corr_cross_tenant_inserts_total Inserts issued at tenant_scope=__all__, by table.",
        "# TYPE corr_cross_tenant_inserts_total counter",
    ]
    for table, n in sorted(CH_CROSS_TENANT_INSERTS.items()):
        lines.append(f'corr_cross_tenant_inserts_total{{table="{table}"}} {n}')
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
        # Scale P0: per-instance partition ownership (co-partitioned tenant
        # slices). PER-INSTANCE diagnostics by design — with --scale
        # correlation=N, Docker DNS round-robins correlation:8000, so this
        # names WHICH slice answered; rebalances counts group churn.
        "consumer": {
            "assignment": {t: p for t, p in CONSUMER_ASSIGNMENT.items() if p},
            "partition_totals": dict(CONSUMER_PARTITION_TOTALS),
            "rebalances": CONSUMER_REBALANCES,
            # The `assignment` map above is filtered for readability, which made
            # "no rebalance yet" and "rebalanced and got NOTHING" both render as
            # {} — the second is a misconfiguration (replicas beyond
            # BUS_PARTITIONS are idle by design) that looked healthy forever.
            # These three fields state it explicitly instead.
            "owned_partition_count": sum(
                len(p) for p in CONSUMER_ASSIGNMENT.values()),
            # FOUR states — pending | idle | cold_window | active. See
            # consumer_state() for what each means and, importantly, for the
            # honest limitation of "cold_window" (tracker 155: there is no
            # rehydration path, so "active" does NOT mean no state was lost).
            "state": consumer_state(),
            "cold_partitions": cold_partitions(),
            "zero_assignments": CONSUMER_ZERO_ASSIGNMENTS,
            # P1 max-poll thrash: revoke-hook outcomes. "failures" rising =
            # rebalances landing on a broken flush path (replay-safe, but
            # every one of them re-processes the uncommitted batch).
            "revoke_commits": CONSUMER_REVOKE_COMMITS,
            "revoke_commit_failures": CONSUMER_REVOKE_COMMIT_FAILURES,
            # Revokes that returned WITHOUT committing because the pre-hand-off
            # flush exceeded CORR_REVOKE_BUDGET_S. Replay-safe, but rising means
            # rebalances are landing on a slow ClickHouse.
            "revoke_skipped": CONSUMER_REVOKE_SKIPPED,
        },
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
            # Housekeeping visibility (tracker 156 review): a prune that starts
            # holding the loop must be observable from /healthz, not only from a
            # forensic build.
            "prune_calls": PRUNE_CALLS,
            "prune_evicted": PRUNE_EVICTED,
            "prune_seconds_last": round(PRUNE_SECONDS_LAST, 4),
            "prune_seconds_max": round(PRUNE_SECONDS_MAX, 4),
            "window_id_order_resyncs": WINDOW_ID_ORDER_RESYNCS,
            "prune_yields": PRUNE_YIELDS,
            "window_overflow_dropped": WINDOW_OVERFLOW_DROPPED,
            # M29a: legacy z-score series budget — evicted rising means
            # cardinality churn is recycling warm baselines (never silent).
            "series_len": len(SERIES),
            "series_max": SERIES_MAX,
            "series_evicted": SERIES_EVICTED,
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
        # TENANT-HIGH-3/4: tenant claims checked against the trusted device→
        # tenant registry. `refused` non-zero means something on the bus is
        # asserting a tenant the registry contradicts — the payloads are in
        # /deadletters. `cross_tenant_inserts` should only ever name
        # netops.corr_tenant_write_amp (the per-tenant rollup).
        "tenant_verification": {
            "claims_verified": TENANT_CLAIMS_VERIFIED,
            "claims_refused": TENANT_CLAIMS_REFUSED,
            "refusals": dict(sorted(TENANT_REFUSALS.items())),
            # _tenant_registry(), not the raw global: the map loads lazily on
            # the first lookup, so an idle replica (no events on its partitions
            # yet) would report 0 for a perfectly healthy registry file. The
            # refresh is a single stat() unless the file changed. Proven live
            # 2026-08-16: a 2-replica deployment's idle member reported
            # registry_identities=0 and failed the mini-ladder propagation gate
            # while the CSV held 201 rows.
            "registry_identities": len(_tenant_registry()),
            "cross_tenant_inserts": dict(sorted(CH_CROSS_TENANT_INSERTS.items())),
        },
        "durability": {
            "ch_insert_failures": dict(sorted(CH_INSERT_FAILURES.items())),
            "handler_failures": dict(sorted(HANDLER_FAILURES.items())),
            "quarantined_events": len(QUARANTINE),
            "quarantine_write_failures": QUARANTINE_WRITE_FAILURES,
            # GA counter-exposure contract (test_ga_failure_accounting): every
            # module-level failure/drop counter MUST surface here. A rotation
            # is a capped-DLQ eviction of the oldest .1 file — old payloads
            # aging out is a (bounded, intended) loss and must be visible.
            "quarantine_rotations": QUARANTINE_ROTATIONS,
            # P1: the loop-lag watchdog. stalls>0 means the event loop was
            # blocked long enough to threaten the group heartbeat.
            "loop_lag_stalls": LOOP_LAG_STALLS,
            "loop_lag_max_ms": round(LOOP_LAG_MAX_MS, 1),
            "loop_lag_ms": round(LOOP_LAG_LAST_MS, 1),
            "topology_stale": _topology_stale(datetime.now(timezone.utc)),
            # Perf defect #2: the batched corr_signals write path. pending>0 is
            # normal (≤2s of traffic); rows_quarantined>0 means a rejected batch
            # parked rows in the durable DLQ.
            "signal_batch_pending": SIGNAL_BATCH.pending(),
            "signal_batch_flushes": BATCH_FLUSHES,
            "signal_batch_rows_flushed": BATCH_ROWS_FLUSHED,
            "signal_batch_rows_quarantined": BATCH_ROWS_QUARANTINED,
            # Perf defect #3: bounded archive slices — damped = re-persists whose
            # slice membership had not moved (no re-write; readers fall back).
            "archive_rows_written": ARCHIVE_ROWS_WRITTEN,
            "archive_slices_damped": ARCHIVE_SLICES_DAMPED,
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
            # H14: device event clocks out of bounds at the window chokepoint —
            # future clamped to arrival (a far-future head froze pruning for
            # every tenant), past counted and left to age out (see buffer_signal).
            "event_ts_future_clamped": EVENT_TS_FUTURE_CLAMPED,
            "event_ts_past_stale": EVENT_TS_PAST_STALE,
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
            # #128 wireless lane — was the one ingest lane with counters but no
            # exposure (found by the GA counter-exposure contract test): a
            # default-closed drop nobody can see is a silent loss.
            "wireless_received": WIRELESS_RECEIVED,
            "wireless_signals": WIRELESS_SIGNALS,
            "wireless_dropped": WIRELESS_DROPPED,
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
    # Severities are simple enum words (warning/critical/info/...). Restrict
    # to letters so the value cannot carry SQL metacharacters — quote-
    # stripping alone is unsafe because ch.query sends raw SQL and ClickHouse
    # honors backslash escapes. An out-of-shape value is ignored (no filter).
    if severity and severity.isalpha():
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
