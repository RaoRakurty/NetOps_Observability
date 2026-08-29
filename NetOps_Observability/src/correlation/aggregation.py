"""P3 Aggregation Plane — step 1: the pure, deterministic state machine.

Authority: `docs/design/AGGREGATION_PLANE_P3_2026-08-29.md` §3/§5/§7 and the
owner memo `/var/tmp/Correlix-Bottleneck-Modified.md` §16–§19, §21–§25. Sizing:
`docs/scale/P3_AGGREGATION_OPPORTUNITY_2026-08-29.md` (step 0) and the measured
ladder in the design's §6b.

WHAT THIS MODULE IS
    A content-addressed aggregation state, one entry per `AggKey`, that turns a
    stream of raw promoted `Signal`s into a stream of **state deltas**. A
    repeated observation that does not move the causal state updates the state
    (count / last / distinct sets / offset range / samples) and emits NOTHING;
    every observation that carries causal information (memo §17) is forwarded
    SYNCHRONOUSLY, annotated with the state it collapsed.

WHAT THIS MODULE IS NOT
    It has no clock, no RNG, no IO, no environment reads on the hot path and no
    knowledge of the engine. `observe()` is a pure function of (the plane's
    state, the signal); the plane's state is a pure function of the observations
    it has been given. Runtime load can change WHEN a delta is produced, never
    WHICH deltas exist (memo §21) — nothing here reads wall time, queue depth or
    CPU.

────────────────────────────────────────────────────────────────────────────
THE KEY (final, chosen by the step-0 + §6b measurements)

    AggKey = (tenant_id, entity_id, kind, severity, bucket)
    bucket = floor(event_time_epoch_seconds / CORR_AGG_BUCKET_S)   # 60 s

    This is EXACTLY the harness's K3 (`scripts/enterprise_outage_chain.py`
    `measure_stream`: `K2 + int(t // AGG_BUCKET_S_K3)`, with
    `K2 = (tenant, entity_id, kind, severity)`), so the plan-time projection and
    the engine-side counters partition the stream the same way and their numbers
    are comparable. `severity` IS the severity band: `Signal.severity` is already
    the 4-value banded enum (info/warn/high/crit), and for the control-plane
    producers it is a pure function of the parsed state — no second banding is
    invented here.

    The ONE deliberate difference from plan time: the harness buckets on
    `t`, seconds from the stream start; the engine buckets on ABSOLUTE epoch
    seconds, because absolute event time is the only content-derived origin a
    live process has. Same width, an origin that may differ by up to one bucket;
    identical partitions when the stream starts on a minute boundary (which the
    bench arranges, so its two columns are exactly comparable).

    TOPOLOGY EPOCH IS NOT IN THE KEY — verified, not assumed: `grep -rn
    topology_epoch src/correlation` finds nothing, no producer stamps one on a
    Signal or into `attrs`, so there is no content-derived epoch to read. A
    phantom always-empty component would cost a tuple slot per event and buy
    nothing. When a topology epoch lands on the Signal it is added here and
    `AGG_POLICY_VERSION` is bumped — which is the memo-§21 "aggregation-policy
    version" that makes the change visible in replay.

────────────────────────────────────────────────────────────────────────────
THE ORDERING RULE (exact — memo §21, "evaluated in event-time order")

    Classification of the ORDERED classes (STATE_TRANSITION / RECOVERY /
    CONTRADICTION — the three that read the identity's previous state) is a
    function of the event-time-ordered observation prefix. The plane never
    buffers and never delays a delta (memo §17 forbids "storm detected → wait"),
    so ordering is imposed by REFUSING to classify out of order rather than by
    holding events back:

    Let `ordered(sig) = (event_ts_ms, signal_id_str)` — a TOTAL order, so two
    observations sharing an event millisecond still order deterministically.
    BOTH the AggKey and the identity keep a `frontier` = the greatest `ordered`
    admitted to that level so far. The AggKey's frontier can only see lateness
    INSIDE one 60 s bucket; the identity's is the one that spans buckets and
    severity bands, and it is the frontier the transition classifier reads.

    * IN ORDER  — `ordered(sig) >= frontier` at BOTH levels: classified normally
      against the state, both frontiers advance, and the ordered fields
      (`IdentState.state`, `IdentState.transitions`) are updated. This is 100 %
      of a per-identity event-time-monotone stream, which is what a
      single-partition, single-threaded consumer of one device's syslog is.
    * LATE, within `lateness_s` — behind either frontier by at most the declared
      lateness: the observation is merged into the COMMUTATIVE accumulators
      (count, first/last ts, severity distribution, distinct sources / vantages
      / modalities, offset range, samples) so no evidence and no accounting is
      lost; it is classified against ORDER-FREE facts only (it can be FIRST /
      NEW_VANTAGE / NEW_MODALITY / CONTRADICTION / COUNT_THRESHOLD, never
      STATE_TRANSITION or RECOVERY, and it never rewrites the identity's
      state); and it is ALWAYS FORWARDED — the plane never suppresses an
      observation it could not order. One that would otherwise have been a
      REPEAT is counted in `late_forwarded`.
    * BEYOND lateness — behind a frontier by more than `lateness_s`: identical
      treatment, and counted separately as `beyond_lateness` so an operator sees
      a source whose clock or delivery has fallen outside the declared
      allowance (§10).

    WHAT THIS GUARANTEES (and what it does not — stated honestly):
      1. FINAL STATE is order-independent under ANY reordering of one stream:
         every accumulator is commutative (including the "first" facts, which
         `merge` moves when an earlier observation turns up), and the identity's
         `state`/`last_ts` are the values of the globally greatest `ordered`
         observation, which is always admitted IN ORDER whenever it arrives.
         The one ORDERED field, `IdentState.transitions`, records the chain the
         plane actually walked and is therefore reordering-sensitive; that is
         the documented limit.
      2. The DELTA SEQUENCE is identical under any reordering that preserves
         per-IDENTITY event-time order — i.e. arbitrary interleaving ACROSS
         identities, which is the reordering a partitioned bus actually
         produces (one entity's events live in one partition and arrive in
         order; different entities interleave freely). Per-identity order
         implies per-key order, because the AggKey refines the identity.
      3. Under out-of-order arrival WITHIN one identity, the forwarded set is a
         SUPERSET of the canonical (event-time-ordered) one: losslessness is
         preserved in the safe direction, and the excess is bounded by
         `late_forwarded`, a counter — never silent (§10).

────────────────────────────────────────────────────────────────────────────
BOUNDS (§9 — bounded, backpressure over loss, eviction never silent)

    Per TENANT (never a shared pool — §3a: a noisy tenant may not evict a quiet
    tenant's aggregation state, and a key from tenant A can never be read or
    written by tenant B because the tenant is the first component of the key AND
    the store is a per-tenant object):
      * keys are held in per-BUCKET maps. The bucket is part of the key and the
        retention horizon is a small multiple of it, so the live bucket count is
        `horizon / bucket ≈ 9` — "evict oldest by event time" is therefore an
        exact O(#buckets) choice, not an approximation.
      * event-time EXPIRY: buckets whose upper edge is older than
        `tenant watermark - horizon_s` are dropped whole (reason `expired`).
        The watermark is the tenant's greatest observed event time — stream
        time, exactly like the window's retention clock; no wall clock.
      * SIZE CAP `max_keys` (CORR_AGG_MAX_KEYS, default 200,000): over the cap,
        the oldest bucket's oldest entry is evicted (reason `capacity`).
      * the per-identity map (see below) has the same cap and its own sweep
        (reasons `ident_expired` / `ident_capacity`).
    The tenant map itself is bounded by `max_tenants` (default 512, reason
    `tenant_capacity`). Every eviction is counted by reason; nothing is dropped
    silently, and NOTHING here can lose a raw event — the raw row is persisted
    upstream of this module (see main.handle_syslog) and Kafka still holds it.

    WHY A SECOND, IDENTITY-LEVEL MAP. Severity is in the AggKey and severity is
    a pure function of state for the control-plane producers, so "up" and "down"
    NEVER share an AggKey: a within-key state comparison could not detect a
    single transition and `state_transitions_total` would be a permanent zero.
    Transitions and recoveries are therefore tracked on the K1 identity
    `(tenant, entity_id, kind)` — which is precisely how `measure_stream`
    classifies them (`last_state[a]`, `a = (tenant, entity_id, kind)`), so the
    engine-side counters mean the same thing as the plan-time ones.

────────────────────────────────────────────────────────────────────────────
TENANCY (§3a). The tenant is the first component of every key and the store is
one object per tenant. There is no unscoped "list all", no cross-tenant read
path, and no shared accumulator: an observation from tenant A cannot create,
read, mutate or evict any state of tenant B. `test_aggregation_p3.py` pins it.
"""

from __future__ import annotations

import bisect
import os
from collections import OrderedDict
from collections.abc import Iterable
from datetime import datetime, timezone
from enum import Enum
from typing import NamedTuple

from signals import Signal

# ── policy constants ────────────────────────────────────────────────────────
#
# The aggregation-policy version (memo §21). It identifies the KEY and the
# CLASSIFIER; any change to either must bump it, because a replay of archived
# deltas is only meaningful against the policy that produced them.
AGG_POLICY_VERSION = "p3.k3.v1"

# The event-time bucket width. 60 s == the harness's AGG_BUCKET_S_K3, and the
# §6b ladder was measured with it.
CORR_AGG_BUCKET_S = max(1, int(os.environ.get("CORR_AGG_BUCKET_S", "60")))
# Per-tenant ceiling on live aggregation keys AND on live identities.
CORR_AGG_MAX_KEYS = max(1, int(os.environ.get("CORR_AGG_MAX_KEYS", "200000")))
# Ceiling on the tenant map itself, so the plane is bounded in both dimensions.
CORR_AGG_MAX_TENANTS = max(1, int(os.environ.get("CORR_AGG_MAX_TENANTS", "512")))
# Representative raw signal ids kept per key (memo §16 "representative anomalous
# events" / the losslessness back-reference when no Kafka coordinate is known).
CORR_AGG_SAMPLES = max(1, int(os.environ.get("CORR_AGG_SAMPLES", "8")))
# Distinct Kafka partitions whose offset range one key will track. A key is one
# (entity, kind, severity, minute) — its events come from one or two partitions
# in any sane partitioning; the bound exists so a pathological one cannot grow.
_MAX_OFFSET_PARTITIONS = 8
# Bound on the recorded transition chain per identity (the chain is evidence,
# not a log).
_MAX_TRANSITIONS = 8
# How many expired identities one observation may sweep. Bounded work per event
# (§9): the hard cap is the backstop, this is the incremental collector.
_IDENT_SWEEP_MAX = 16

# Content-derived count thresholds (memo §17: "count crossing a content-derived
# threshold (e.g. 1 → 10 → 100), not 'every N seconds'"). 1 is the FIRST delta
# itself; these are the crossings after it. Powers of ten, so the number of
# COUNT_THRESHOLD deltas for a key of N observations is log10(N) — bounded by
# construction and independent of rate, load or wall time.
COUNT_THRESHOLDS: frozenset[int] = frozenset({10, 100, 1000, 10_000, 100_000,
                                              1_000_000})

# States that mean "the thing came back". MIRRORS
# `scripts/enterprise_outage_chain.RECOVERY_STATES` — the harness and the engine
# must classify a recovery identically or the plan-time and engine-side recovery
# counts are not the same metric. `test_aggregation_p3.py` pins the two sets
# equal whenever the harness module is importable.
RECOVERY_STATES: frozenset[str] = frozenset({"up", "forwarding", "learning",
                                             "full"})
# States that carry no health claim at all. Everything else is unhealthy.
_UNKNOWN_STATES: frozenset[str] = frozenset({"", "unknown", "none", "n/a"})

_HEALTH_UP = "healthy"
_HEALTH_DOWN = "unhealthy"
_HEALTH_NONE = ""


class DeltaClass(str, Enum):
    """The memo-§17 causal classes, plus REPEAT for "changes nothing".

    Ordered by causal significance in `delta_class` — the FIRST match wins, so a
    signal that is both a recovery and a new vantage is reported as the recovery
    (memo §18: "use causal significance, not raw event rate"). Every class
    except REPEAT is forwarded to the engine SYNCHRONOUSLY.
    """

    FIRST = "first"
    STATE_TRANSITION = "state_transition"
    RECOVERY = "recovery"
    CONTRADICTION = "contradiction"
    NEW_VANTAGE = "new_vantage"
    NEW_MODALITY = "new_modality"
    COUNT_THRESHOLD = "count_threshold"
    REPEAT = "repeat"


FORWARDED_CLASSES: frozenset[DeltaClass] = frozenset(
    c for c in DeltaClass if c is not DeltaClass.REPEAT)

# The CLOSED eviction-reason label set (§10: an operator must be able to tell a
# resource ceiling from ordinary event-time expiry without inferring it). Every
# reason is exported on every scrape, zero included, so the series set is stable.
AGG_EVICT_REASONS: tuple[str, ...] = (
    "expired",          # the key's bucket aged past the retention horizon
    "capacity",         # the per-tenant key cap forced out the oldest bucket
    "ident_expired",    # an identity aged past the horizon
    "ident_capacity",   # the per-tenant identity cap
    "tenant_capacity",  # the tenant map cap dropped a whole tenant's state
)


class AggKey(NamedTuple):
    """`(tenant_id, entity_id, kind, severity, bucket)` — content-derived only.

    A NamedTuple: hashable, immutable, comparable, and its fields are readable
    at every call site that has to reason about the key (the eviction code
    indexes it positionally on the hot path, which is the same tuple access).
    """

    tenant_id: str
    entity_id: str
    kind: str
    severity: str
    bucket: int

    @classmethod
    def of(cls, sig: Signal, bucket_s: int = CORR_AGG_BUCKET_S, *,
           severity: str | None = None, epoch_s: int | None = None) -> AggKey:
        """The key of one Signal. Pure: event time, canonical fields only.

        `sig.tenant_id` is used VERBATIM — the canonical global-tenant spelling
        ("" -> "global") is applied downstream at `main.buffer_signal`, the
        single window-entry chokepoint. Two spellings of one tenant therefore
        aggregate separately here, which can only aggregate LESS; it can never
        merge two tenants, and that is the direction §3a requires an ambiguity
        to fail in.

        `severity` and `epoch_s` are the caller's already-read copies of
        `sig.severity.value` and `int(sig.ts.timestamp())` — `Enum.value` is a
        descriptor lookup and `timestamp()` is not free, and the ingest path has
        both in hand. Omit them and they are read here: this stays THE single
        place the key is derived, which is what keeps the hot path and every
        offline re-derivation (tests, bench, replay) provably identical.
        """
        return cls(sig.tenant_id, sig.entity_id, sig.kind,
                   sig.severity.value if severity is None else severity,
                   (int(sig.ts.timestamp()) if epoch_s is None else epoch_s)
                   // bucket_s)

    def token(self) -> str:
        """The key as it is stamped onto a forwarded signal (`agg_key`) and into
        an archive slice: stable, readable, and parseable back to the tuple."""
        return (f"{self.tenant_id}|{self.entity_id}|{self.kind}|"
                f"{self.severity}|{self.bucket}")


def ident_key(sig: Signal) -> tuple[str, str]:
    """The K1 identity WITHIN a tenant — `(entity_id, kind)`. The tenant is the
    store, so it is not repeated in the key (see `_TenantAgg`)."""
    return (sig.entity_id, sig.kind)


def parsed_state(sig: Signal) -> str:
    """The parsed state value the producers stamp (`attrs["state"]`: up / down /
    forwarding / blocking / full / …), lowercased; "" when the signal carries
    none. This is the SAME field `measure_stream` reads as `Observation.state`.
    """
    attrs = sig.attrs
    if not isinstance(attrs, dict):
        return ""
    v = attrs.get("state")
    return v.strip().lower() if isinstance(v, str) else ""


def health_of(state: str) -> str:
    """`healthy` / `unhealthy` / "" (no claim) for a parsed state value."""
    if state in _UNKNOWN_STATES:
        return _HEALTH_NONE
    return _HEALTH_UP if state in RECOVERY_STATES else _HEALTH_DOWN


def _ordered(sig: Signal) -> tuple[int, str]:
    """The TOTAL event-time order used by every frontier comparison. The signal
    id breaks a same-millisecond tie deterministically and is itself
    content-derived (uuid5 over source|native_id|event-ts)."""
    return (int(sig.ts.timestamp() * 1000), sig.signal_id_str)


def _iso(ts_ms: int) -> str:
    return datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc).isoformat()


class IdentState:
    """Per-identity (K1) ORDERED state: what this entity/kind was last observed
    to be. The only reason it exists is that severity — a pure function of state
    — is inside the AggKey, so a transition never stays inside one key."""

    __slots__ = ("frontier", "health", "last_ts_ms", "observer", "state",
                 "transitions")

    def __init__(self, frontier: tuple[int, str], state: str, health: str,
                 observer: str) -> None:
        self.frontier = frontier
        self.state = state
        self.health = health
        # WHO reported the current state. It is what separates "the witness
        # itself says it changed" (a transition) from "a DIFFERENT witness
        # disagrees" (a contradiction) — see `delta_class`.
        self.observer = observer
        self.last_ts_ms = frontier[0]
        self.transitions: tuple[tuple[str, str], ...] = ()

    def note_transition(self, prev: str, new: str) -> None:
        chain = self.transitions + ((prev, new),)
        self.transitions = chain[-_MAX_TRANSITIONS:]


class AggState:
    """The compact per-key state of memo §16.

    Every field except `transitions` (which lives on `IdentState`, not here) is
    COMMUTATIVE — merging an observation is order-independent — which is what
    makes the final state a pure function of the SET of observations.
    """

    __slots__ = ("contradiction", "count", "first_health", "first_iso",
                 "first_observer", "first_order", "first_ts_ms", "forwarded",
                 "frontier", "key", "last_ts_ms", "modalities", "offsets",
                 "recovery", "samples", "sev_dist", "sources", "states",
                 "suppressed", "vantages")

    def __init__(self, key: AggKey, sig: Signal, order: tuple[int, str],
                 state: str) -> None:
        self.key = key
        self.first_ts_ms = order[0]
        # Rendered lazily on the first delta and reused: `first_ts` moves at
        # most once per key (only a late arrival can move it), while a busy key
        # emits many deltas, so re-rendering it per delta was pure repeat work.
        self.first_iso = ""
        self.last_ts_ms = order[0]
        self.frontier = order
        self.count = 0
        self.sev_dist: dict[str, int] = {}
        self.sources: set[str] = set()
        self.vantages: set[str] = set()
        self.modalities: set[str] = set()
        self.states: dict[str, int] = {}
        self.recovery = False
        self.contradiction = False
        # The "first" facts are those of the EVENT-TIME-earliest observation,
        # not of whichever one happened to arrive first — `merge` moves them
        # when an earlier observation turns up, so they are commutative like
        # every other accumulator here.
        self.first_order = order
        self.first_health = health_of(state)
        self.first_observer = sig.observer.observer_id
        # partition -> (min offset, max offset). Empty when the caller supplies
        # no Kafka coordinate (see AggPlane.observe).
        self.offsets: dict[int, tuple[int, int]] = {}
        # The N smallest (ts_ms, signal_id) — a content-derived, commutative
        # choice, so two orderings of one stream keep the same samples.
        self.samples: list[tuple[int, str]] = []
        self.forwarded = 0
        self.suppressed = 0

    # ── merge (commutative) ─────────────────────────────────────────────────
    def merge(self, order: tuple[int, str], in_order: bool,
              coord: tuple[int, int] | None, samples_max: int, *,
              sev: str, state: str, observer: str, modality: str,
              source: str) -> None:
        """The enum values and the parsed state are read ONCE by the caller and
        passed in: `Enum.value` is a descriptor lookup and `attrs["state"]` a
        dict probe, and both were being repeated four times per observation on
        a path that runs at ingest rate."""
        self.count += 1
        if order < self.first_order:
            self.first_order = order
            self.first_health = health_of(state)
            self.first_observer = observer
        if order[0] < self.first_ts_ms:
            self.first_ts_ms = order[0]
            self.first_iso = ""
        if order[0] > self.last_ts_ms:             # noqa: PLR1730 - is not free
            self.last_ts_ms = order[0]
        if in_order:
            self.frontier = order
        self.sev_dist[sev] = self.sev_dist.get(sev, 0) + 1
        self.sources.add(source)
        self.vantages.add(observer)
        self.modalities.add(modality)
        self.states[state] = self.states.get(state, 0) + 1
        if state and state in RECOVERY_STATES:
            self.recovery = True
        if coord is not None:
            part, off = coord
            cur = self.offsets.get(part)
            if cur is None:
                if len(self.offsets) < _MAX_OFFSET_PARTITIONS:
                    self.offsets[part] = (off, off)
            elif off < cur[0]:
                self.offsets[part] = (off, cur[1])
            elif off > cur[1]:
                self.offsets[part] = (cur[0], off)
        if len(self.samples) < samples_max:
            bisect.insort(self.samples, order)
        elif order < self.samples[-1]:
            bisect.insort(self.samples, order)
            self.samples.pop()

    # ── projection ──────────────────────────────────────────────────────────
    def offset_range(self) -> list[str]:
        """`["3:63059833-63970676", …]` — the raw Kafka coordinate range this
        key collapsed, per partition. Empty when no coordinate was supplied."""
        return [f"{p}:{lo}-{hi}" for p, (lo, hi) in sorted(self.offsets.items())]

    def sample_ids(self) -> list[str]:
        return [sid for _ts, sid in self.samples]


def delta_class(prev_state: AggState | None, sig: Signal, *,
                ident: IdentState | None = None, state: str | None = None,
                observer: str = "", modality: str = "") -> DeltaClass:
    """Classify one observation. PURE — reads state, mutates nothing.

    Priority order is causal significance (memo §18), first match wins:

      1. STATE_TRANSITION / RECOVERY / CONTRADICTION — the identity's parsed
         state moved. Evaluated against `ident`, the K1 identity's ORDERED
         state; the caller passes `ident=None` when the observation could not be
         ordered (see the ordering rule at the top of this file), which is what
         stops a late arrival from inventing a transition that never happened.
         A move INTO a recovery state is RECOVERY and any other move is
         STATE_TRANSITION — identical to `measure_stream`'s split — but ONLY
         when the report comes from the SAME witness that set the current state.
         A move reported by a DIFFERENT observer is not the entity changing, it
         is two witnesses disagreeing about it: memo §17's "contradictory
         healthy observation" / §18's "contradictory evidence", classified
         CONTRADICTION. Both are forwarded synchronously, and the state-move
         COUNTERS (`state_transitions` / `recoveries`) count the move either
         way, so they mean exactly what `measure_stream` means by them.
      2. FIRST — no state for this AggKey: the first observation of this
         (tenant, entity, kind, severity, minute). This is the class the K3
         reduction is counted in, and it is the memo's "first occurrence" at the
         plane's identity granularity.
      3. CONTRADICTION (key-level fallback) — a DIFFERENT observer reports a
         health that disagrees with the health of the key's event-time-first
         observation. This covers the cases rule 1 cannot see: an identity whose
         ordered state is not yet established, or one whose state was evicted.
      4. NEW_VANTAGE — an observer_id this key has not been seen from.
      5. NEW_MODALITY — a telemetry modality this key has not been seen in.
      6. COUNT_THRESHOLD — the count crosses 10 / 100 / 1000 / … (content
         derived; NEVER a timer, NEVER a rate).
      7. REPEAT — changes nothing. Suppressed: the state absorbs it.

    `state` / `observer` / `modality` are the caller's already-read copies of
    `attrs["state"]`, `observer.observer_id` and `modality_class.value`; omit
    them and they are read here, so the function stays callable with just
    `(prev_state, sig)`.
    """
    if state is None:
        state = parsed_state(sig)
    if not observer:
        observer = sig.observer.observer_id
    if ident is not None and state and ident.state and state != ident.state:
        if observer != ident.observer:
            return DeltaClass.CONTRADICTION
        return (DeltaClass.RECOVERY if state in RECOVERY_STATES
                else DeltaClass.STATE_TRANSITION)
    if prev_state is None:
        return DeltaClass.FIRST
    health = health_of(state)
    if (health and prev_state.first_health and health != prev_state.first_health
            and observer != prev_state.first_observer):
        return DeltaClass.CONTRADICTION
    if observer not in prev_state.vantages:
        return DeltaClass.NEW_VANTAGE
    if (modality or sig.modality_class.value) not in prev_state.modalities:
        return DeltaClass.NEW_MODALITY
    if (prev_state.count + 1) in COUNT_THRESHOLDS:
        return DeltaClass.COUNT_THRESHOLD
    return DeltaClass.REPEAT


class _TenantAgg:
    """One tenant's aggregation state. §3a: the ONLY container that holds keys,
    and it is reachable only through `AggPlane._tenants[tenant]`."""

    __slots__ = ("buckets", "idents", "keys", "watermark_ms", "wm_bucket")

    def __init__(self) -> None:
        # bucket -> OrderedDict[(entity_id, kind, severity)] -> AggState.
        # Bucket count is bounded by horizon/bucket_s (~9 at the shipped
        # constants), so "the oldest bucket" is an O(#buckets) exact answer.
        self.buckets: dict[int, OrderedDict[tuple[str, str, str], AggState]] = {}
        self.idents: OrderedDict[tuple[str, str], IdentState] = OrderedDict()
        self.watermark_ms = 0
        # The bucket the watermark is in. Expiry can only remove WHOLE buckets,
        # so it can only have anything to do when this changes — sweeping on
        # every event was pure per-event tax with an identical outcome.
        self.wm_bucket = -1
        self.keys = 0


class AggPlane:
    """The aggregation plane. One instance per process; state is per tenant.

    `horizon_s` and `lateness_s` are INJECTED (never read from `main` — that
    would be a circular import and, worse, hidden coupling): the caller passes
    `main.RETENTION_REQUIRED_S` and `main.CORR_PERMITTED_LATENESS_S`, so the
    plane expires state on exactly the window's own horizon and tolerates
    exactly the window's own declared lateness.
    """

    __slots__ = ("_tenants", "beyond_lateness", "bucket_s", "contradictions",
                 "count_thresholds", "evicted", "forwarded",
                 "forwarded_by_class", "horizon_ms", "late_forwarded",
                 "lateness_ms", "max_keys", "max_tenants", "observed",
                 "recoveries", "samples_max", "state_transitions",
                 "suppressed", "tenants_seen")

    def __init__(self, *, horizon_s: float, lateness_s: float,
                 bucket_s: int = CORR_AGG_BUCKET_S,
                 max_keys: int = CORR_AGG_MAX_KEYS,
                 max_tenants: int = CORR_AGG_MAX_TENANTS,
                 samples_max: int = CORR_AGG_SAMPLES) -> None:
        self._tenants: OrderedDict[str, _TenantAgg] = OrderedDict()
        self.bucket_s = max(1, int(bucket_s))
        self.horizon_ms = max(0, int(horizon_s * 1000.0))
        self.lateness_ms = max(0, int(lateness_s * 1000.0))
        self.max_keys = max(1, int(max_keys))
        self.max_tenants = max(1, int(max_tenants))
        self.samples_max = max(1, int(samples_max))
        # ── counters (§10: every one of these is exported; none is derived on
        # the hot path — ratios are computed at scrape time).
        self.observed = 0
        self.suppressed = 0
        self.forwarded = 0
        self.forwarded_by_class: dict[str, int] = {}
        self.evicted: dict[str, int] = {}
        self.state_transitions = 0
        self.recoveries = 0
        self.contradictions = 0
        self.count_thresholds = 0
        self.late_forwarded = 0
        self.beyond_lateness = 0
        self.tenants_seen = 0

    # ── the hot path ────────────────────────────────────────────────────────
    def observe(self, sig: Signal,
                coord: tuple[int, int] | None = None) -> Signal | None:
        """Absorb one promoted Signal; return the Signal to forward, or None.

        `coord` is the OPTIONAL raw Kafka coordinate `(partition, offset)` of
        the message this signal was parsed from — memo §16's "raw Kafka offset
        range". It is not on the `Signal` (checked: the dataclass has no offset
        field and no producer stamps one into `attrs`), so the ingest wiring
        supplies it from the consumer's own dedup coordinate. When it is absent
        the bounded sample-id list is the back-reference instead.

        The returned Signal is the SAME object, with the aggregation fields
        stamped into `attrs`. Stamping in place is deliberate and safe: the raw
        `corr_signals` row was already built and batched upstream of this call
        (`to_ch_row()` serialises `attrs` to a JSON string at that moment), so
        the persisted RAW row never carries these fields and the accounting gate
        is untouched.
        """
        self.observed += 1
        # Read once, use everywhere below (see `merge` and `AggKey.of`).
        sev = sig.severity.value
        observer = sig.observer.observer_id
        modality = sig.modality_class.value
        state = parsed_state(sig)
        ts_ms = int(sig.ts.timestamp() * 1000)
        order = (ts_ms, sig.signal_id_str)
        key = AggKey.of(sig, self.bucket_s, severity=sev,
                        epoch_s=ts_ms // 1000)

        tenants = self._tenants
        tenant = tenants.get(key[0])
        if tenant is None:
            tenant = _TenantAgg()
            tenants[key[0]] = tenant
            self.tenants_seen += 1
            if len(tenants) > self.max_tenants:
                self._evict_tenant()
        else:
            tenants.move_to_end(key[0])

        # Stream clock: the tenant's own greatest event time. No wall clock.
        if ts_ms > tenant.watermark_ms:
            tenant.watermark_ms = ts_ms
            wm_bucket = key[4]
            if wm_bucket != tenant.wm_bucket:
                tenant.wm_bucket = wm_bucket
                self._expire(tenant)

        bkey = (key[1], key[2], key[3])
        slot = tenant.buckets.get(key[4])
        prev = slot.get(bkey) if slot is not None else None

        # ── ordering (see the module docstring's ordering rule) ─────────────
        #
        # BOTH frontiers are consulted. The AggKey contains the event-time
        # bucket, so a key frontier can only see lateness INSIDE one bucket; the
        # identity frontier is the one that spans buckets and severity bands,
        # and it is the frontier the transition classifier actually reads. The
        # displacement reported against the declared lateness is the larger of
        # the two violations, so a late arrival is never under-reported.
        ik = (key[1], key[2])
        ident = tenant.idents.get(ik)
        in_order = prev is None or order >= prev.frontier
        ident_in_order = ident is None or order >= ident.frontier
        if not (in_order and ident_in_order):
            lag = 0
            if prev is not None and order < prev.frontier:
                lag = prev.frontier[0] - order[0]
            if ident is not None and order < ident.frontier:
                lag = max(lag, ident.frontier[0] - order[0])
            if lag > self.lateness_ms:
                self.beyond_lateness += 1

        cls = delta_class(prev, sig, ident=ident if ident_in_order else None,
                          state=state, observer=observer, modality=modality)

        # ── merge (commutative; happens for EVERY observation, ordered or not,
        # so Σ agg_count over a key is exactly the raw count of that key) ─────
        if prev is None:
            prev = AggState(key, sig, order, state)
            if slot is None:
                slot = OrderedDict()
                tenant.buckets[key[4]] = slot
            slot[bkey] = prev
            tenant.keys += 1
            if tenant.keys > self.max_keys:
                self._evict_key(tenant)
        prev.merge(order, in_order, coord, self.samples_max, sev=sev,
                   state=state, observer=observer, modality=modality,
                   source=sig.source.value)

        # ── ordered identity state ──────────────────────────────────────────
        #
        # The state-move counters are incremented on the MOVE, not on the class
        # it was labelled with: a move reported by a different witness is
        # labelled CONTRADICTION but is still a transition, and
        # `state_transitions` / `recoveries` must keep meaning exactly what
        # `measure_stream` means by them or the plan-time and engine-side
        # numbers stop being the same metric.
        moved = (ident is not None and ident_in_order and state
                 and ident.state and state != ident.state)
        if moved:
            self.state_transitions += 1
            if state in RECOVERY_STATES:
                self.recoveries += 1
        if ident is None:
            tenant.idents[ik] = IdentState(order, state, health_of(state),
                                           observer)
            if len(tenant.idents) > self.max_keys:
                tenant.idents.popitem(last=False)
                self._count_evict("ident_capacity")
        else:
            tenant.idents.move_to_end(ik)
            if ident_in_order:
                if state and ident.state and state != ident.state:
                    ident.note_transition(ident.state, state)
                if state:
                    ident.state = state
                    ident.health = health_of(state)
                    ident.observer = observer
                ident.frontier = order
                ident.last_ts_ms = order[0]

        if cls is DeltaClass.CONTRADICTION:
            self.contradictions += 1
            prev.contradiction = True
        elif cls is DeltaClass.COUNT_THRESHOLD:
            self.count_thresholds += 1

        # ── forward or suppress ─────────────────────────────────────────────
        ordered_ok = in_order and ident_in_order
        if cls is DeltaClass.REPEAT and ordered_ok:
            prev.suppressed += 1
            self.suppressed += 1
            return None
        if cls is DeltaClass.REPEAT:
            # Never suppress an observation the plane could not order (the
            # ordering rule's point 3: losslessness in the safe direction).
            self.late_forwarded += 1
        prev.forwarded += 1
        self.forwarded += 1
        name = cls.value
        self.forwarded_by_class[name] = self.forwarded_by_class.get(name, 0) + 1
        return self._annotate(sig, key, prev, cls)

    # ── annotation ──────────────────────────────────────────────────────────
    def _annotate(self, sig: Signal, key: AggKey, state: AggState,
                  cls: DeltaClass) -> Signal:
        """Stamp the delta's aggregation fields (design §3, "the delta signal").

        The values are the state AT EMISSION — a delta carries what it collapsed
        up to the moment it left, which is what makes the sequence of deltas a
        faithful, replayable description of the raw stream.
        """
        attrs = sig.attrs
        if not isinstance(attrs, dict):          # defensive: never guess
            return sig
        attrs["agg_key"] = key.token()
        attrs["agg_policy"] = AGG_POLICY_VERSION
        attrs["agg_class"] = cls.value
        attrs["agg_count"] = state.count
        if not state.first_iso:
            state.first_iso = _iso(state.first_ts_ms)
        attrs["agg_first_ts"] = state.first_iso
        attrs["agg_last_ts"] = (state.first_iso
                                if state.last_ts_ms == state.first_ts_ms
                                else _iso(state.last_ts_ms))
        attrs["agg_distinct_sources"] = len(state.sources)
        attrs["agg_distinct_vantages"] = len(state.vantages)
        attrs["agg_distinct_modalities"] = len(state.modalities)
        if state.count > 1:
            attrs["agg_samples"] = state.sample_ids()
        if state.offsets:
            attrs["agg_offset_range"] = state.offset_range()
        return sig

    # ── bounds ──────────────────────────────────────────────────────────────
    def _count_evict(self, reason: str) -> None:
        self.evicted[reason] = self.evicted.get(reason, 0) + 1

    def _expire(self, tenant: _TenantAgg) -> None:
        """Event-time expiry against the tenant's own stream watermark."""
        if not self.horizon_ms:
            return
        cutoff = tenant.watermark_ms - self.horizon_ms
        if cutoff <= 0:
            return
        bucket_ms = self.bucket_s * 1000
        dead = [b for b in tenant.buckets if (b + 1) * bucket_ms <= cutoff]
        for b in dead:
            slot = tenant.buckets.pop(b)
            tenant.keys -= len(slot)
            for _ in range(len(slot)):
                self._count_evict("expired")
        # Identities age on the same horizon. Bounded per call: the OrderedDict
        # front is the least-recently-touched identity, which is the oldest by
        # event time for any stream whose per-identity arrivals are ordered; the
        # size cap is the hard backstop for the streams where it is not.
        idents = tenant.idents
        for _ in range(_IDENT_SWEEP_MAX):
            if not idents:
                return
            ik, ist = next(iter(idents.items()))
            if ist.last_ts_ms >= cutoff:
                return
            idents.pop(ik)
            self._count_evict("ident_expired")

    def _evict_key(self, tenant: _TenantAgg) -> None:
        """Over the size cap: drop the OLDEST-by-event-time key. The bucket IS
        event time, so the oldest bucket's first-inserted entry is the oldest
        key, exactly (not approximately)."""
        while tenant.keys > self.max_keys and tenant.buckets:
            oldest = min(tenant.buckets)
            slot = tenant.buckets[oldest]
            if not slot:
                del tenant.buckets[oldest]
                continue
            slot.popitem(last=False)
            tenant.keys -= 1
            self._count_evict("capacity")
            if not slot:
                del tenant.buckets[oldest]

    def _evict_tenant(self) -> None:
        """Over the tenant cap: drop the least-recently-observed tenant WHOLE.
        Counted per key so the loss is measured, not merely noted."""
        while len(self._tenants) > self.max_tenants:
            _name, victim = self._tenants.popitem(last=False)
            for _ in range(victim.keys):
                self._count_evict("tenant_capacity")

    # ── observability (§10) ─────────────────────────────────────────────────
    def key_count(self) -> int:
        return sum(t.keys for t in self._tenants.values())

    def ident_count(self) -> int:
        return sum(len(t.idents) for t in self._tenants.values())

    def evicted_total(self) -> int:
        return sum(self.evicted.values())

    def stats(self) -> dict:
        """Everything an operator needs to answer "is the plane collapsing the
        right things, and is it bounded?" — counters and the ratios derived
        from them HERE (scrape time), never on the hot path."""
        obs = self.observed or 1
        return {
            "policy": AGG_POLICY_VERSION,
            "bucket_s": self.bucket_s,
            "horizon_s": round(self.horizon_ms / 1000.0, 3),
            "lateness_s": round(self.lateness_ms / 1000.0, 3),
            "max_keys": self.max_keys,
            "max_tenants": self.max_tenants,
            "observed": self.observed,
            "forwarded": self.forwarded,
            "suppressed": self.suppressed,
            "forwarded_by_class": dict(self.forwarded_by_class),
            "state_transitions": self.state_transitions,
            "recoveries": self.recoveries,
            "contradictions": self.contradictions,
            "count_thresholds": self.count_thresholds,
            "late_forwarded": self.late_forwarded,
            "beyond_lateness": self.beyond_lateness,
            "keys": self.key_count(),
            "idents": self.ident_count(),
            "tenants": len(self._tenants),
            "tenants_seen": self.tenants_seen,
            "evicted": dict(self.evicted),
            "evicted_total": self.evicted_total(),
            # THE two ratios the §6b ladder is read on: what share of promoted
            # signals the engine never has to see, and the raw→engine collapse.
            "suppressed_ratio": round(self.suppressed / obs, 6),
            "forward_ratio": round(self.forwarded / obs, 6),
        }

    # ── test / bench affordances (never used by the ingest path) ────────────
    def state_of(self, key: AggKey) -> AggState | None:
        """The state of one key, or None. Tenant-scoped by construction: the
        tenant is `key[0]` and no other tenant's store is consulted."""
        tenant = self._tenants.get(key[0])
        if tenant is None:
            return None
        slot = tenant.buckets.get(key[4])
        return slot.get((key[1], key[2], key[3])) if slot else None

    def keys_of(self, tenant_id: str) -> list[AggKey]:
        """Every live key OF ONE TENANT. There is deliberately no "list all"
        across tenants (§3a) — a caller must name the tenant it is entitled to.
        """
        tenant = self._tenants.get(tenant_id)
        if tenant is None:
            return []
        return [AggKey(tenant_id, e, k, s, b)
                for b, slot in sorted(tenant.buckets.items())
                for (e, k, s) in slot]

    def raw_count(self, tenant_id: str) -> int:
        """Σ agg_count over every live key of one tenant — the losslessness
        ledger: it must equal the number of observations absorbed for that
        tenant, minus whatever eviction removed (which is counted)."""
        tenant = self._tenants.get(tenant_id)
        if tenant is None:
            return 0
        return sum(st.count for slot in tenant.buckets.values()
                   for st in slot.values())

    def reset(self) -> None:
        """Drop all state and counters. Tests and benches only."""
        self._tenants.clear()
        self.observed = self.suppressed = self.forwarded = 0
        self.forwarded_by_class = {}
        self.evicted = {}
        self.state_transitions = self.recoveries = 0
        self.contradictions = self.count_thresholds = 0
        self.late_forwarded = self.beyond_lateness = 0
        self.tenants_seen = 0


def observe_all(plane: AggPlane, sigs: Iterable[Signal]) -> list[Signal]:
    """Feed a stream through a plane and collect what it forwards. Bench/test
    helper; the ingest path calls `observe` one signal at a time."""
    out: list[Signal] = []
    for s in sigs:
        got = plane.observe(s)
        if got is not None:
            out.append(got)
    return out
