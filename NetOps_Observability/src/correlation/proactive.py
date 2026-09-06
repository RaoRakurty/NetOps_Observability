"""Proactive checks — the A4 heartbeat plane (Project 4 C, IRIS model §3.4).

NetClaw flags a handful of conditions *without being asked*: an OSPF adjacency
that is not FULL, an IS-IS adjacency that is not UP, a BGP peer parked in
IDLE/ACTIVE, CPU or memory pinned high, a config change in the window, a CVE
match, an SoT mismatch. `docs/design/PROACTIVE_CHECKS_AUDIT_2026-09-02.md` maps
that list onto what this engine already emits. Most of it was already covered;
what was NOT is the thing this module adds:

    THE ENGINE FLAGS TRANSITIONS. IT DID NOT FLAG A STATE THAT STAYS BAD.

Every existing control-plane kind is a *change*: `bgp_adjacency_change`,
`ospf_adjacency_change`, `isis_adjacency_change`. Every existing metric kind is
a *deviation*: `device_resource_anomaly` is a CUSUM episode against the box's
own baseline. Both are blind to the steady state an operator opens a case
about — a peer that has been ACTIVE for twenty minutes emits ONE adjacency line
and then nothing, and a device that has run at 97 % CPU all week has a baseline
of 97 % and therefore no deviation at all. A heartbeat check asks a different
question: *is it still bad, and has it been bad long enough to matter?*

WHAT THIS MODULE IS
-------------------
A small, PURE, deterministic dwell-timer plane. No IO, no ClickHouse, no
asyncio: `ProactiveMonitor` takes observations and returns events, and
`main.py` owns every side effect. Three inputs, one shape:

  * `observe_metric()`  — a canonical MetricEvent sample already admitted by
    `handle_metric` (BGP session state, CPU %, memory %).
  * `observe_signal()`  — a control-plane Signal already built by the syslog /
    trap producers (`*_adjacency_change`, carrying `attrs.state`).
  * `sweep()`           — the wall/stream clock advancing. REQUIRED: a syslog
    adjacency-down line is a single event, so nothing else would ever ask
    "is it still down?".

FLAP vs PERSISTENT — the whole point
------------------------------------
A watch opens when the state goes bad and CLOSES when it goes good. It fires
only when the bad state has been continuously held for `dwell_s`. A flap
(down → up inside the dwell) therefore fires NOTHING and is left to the
existing `*-adjacency-flap` signatures, which are the right explanation for
it. Persistence and flapping are different faults with different first steps,
and this module deliberately owns only the first.

SHADOW BY DEFAULT — the A8/A9b contract, restated
-------------------------------------------------
Every check ships `shadow=True`. A shadow check is evaluated exactly like a
live one, its firings are counted in `SHADOW_HITS[check_id]`, and then it
returns NOTHING. That is the same contract `producers._run` gives a shadow
parser rule (A8), and it is here for the same reason A9b needed it: a new
condition must earn its promotion by being measured against real production
traffic before it is allowed to produce evidence.

It is also what keeps the V1 reference qualification honest. A check that
emits nothing cannot open an object, cannot join a window, cannot move
`FIXTURE_GOLDEN`, and cannot re-classify one line of the V1 noise pool — so
the golden/digest pins in `test_bounded_object_paging.py` and
`tests/test_storm_scenario_profile.py` are byte-identical with this module
present and absent. `test_proactive_checks_a4.py` asserts exactly that.

PROMOTION (per check, one at a time — see `PROMOTION` below)
------------------------------------------------------------
1. Run the check shadow on real traffic and read
   `corr_proactive_shadow_hits_total{check_id}` — a firing rate that tracks
   real incidents, not the background.
2. Register the kind: `producers.EMITTED_KINDS`, `confirmability.KIND_MODALITY`,
   `layers.CAUSAL_LAYER`.
3. Install the check's signature from `PROACTIVE_TEMPLATES` into
   `catalog.BUILTIN_TEMPLATES` (they are authored here, validated by the
   test, and deliberately NOT installed — installing one moves
   `catalog_version` and therefore `FIXTURE_GOLDEN`).
4. Re-freeze `FIXTURE_GOLDEN` with the A9b-style proof: the V1 object is
   byte-identical modulo the `catalog_version` stamp.
5. Flip `shadow=False` on that one check and rerun the qualification.
"""

from __future__ import annotations

import os
from collections import OrderedDict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta

from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

# ── the BGP4-MIB / OSPF-MIB / ISIS-MIB state contracts ───────────────────────
# The canonical numeric enums the whole stack agrees on. gnmic maps every
# vendor spelling onto them (deployment/docker/gnmic/gnmic-correlation.yaml
# `canon-bgp-enums` / `canon-isis-enums`) and telemetry-catalog/normalization.yaml
# declares them as the specs of record, so a threshold written here is the same
# threshold the SNMP lane, the gNMI lane and the alert templates use. Named
# constants rather than bare integers: `< 6` in isolation is unreadable and
# invites someone to "fix" it.
BGP_STATE_ESTABLISHED = 6      # bgpPeerState established(6); 1..5 are not
OSPF_NBR_STATE_FULL = 8        # ospfNbrState full(8); 1..7 are not
ISIS_ADJ_STATE_UP = 3          # isisISAdjState up(3); 1/2/4 are not

#: Sustained-utilisation floors, percent. Deliberately ABOVE the value a busy
#: box touches at peak — a heartbeat check that fires on a control-plane spike
#: is noise, and noise is what got the config-change rule held at shadow. The
#: dwell does the rest of the discrimination.
CPU_HIGH_PCT = float(os.environ.get("CORR_PROACTIVE_CPU_PCT", "90"))
MEM_HIGH_PCT = float(os.environ.get("CORR_PROACTIVE_MEM_PCT", "90"))

#: Default dwell before a bad state is "persistent", seconds. Five minutes is
#: the operator's own threshold: it outlasts a reload, an IGP dead-timer
#: expiry + re-adjacency, and a BGP idle-hold retry, so what remains is a
#: session/adjacency that is not coming back on its own.
DEFAULT_DWELL_S = float(os.environ.get("CORR_PROACTIVE_DWELL_S", "300"))

#: Bound on distinct watches held in memory (§9: all queues bounded). A watch
#: key contains a device id and a peer address, both of which come off the
#: wire, so this is an attacker-facing cardinality and needs a hard cap, not
#: just per-key expiry. LRU by last observation, exactly like `main.SERIES`.
MAX_WATCHES = max(1, int(os.environ.get("CORR_PROACTIVE_MAX_WATCHES", "100000")))

#: A watch whose entity has said nothing for this long is dropped on the next
#: sweep. A device that is decommissioned, re-addressed or simply stops being
#: polled must not hold an open watch forever — and must not fire one either,
#: because "we stopped hearing about it" is not evidence that it is still bad.
#: Deliberately larger than the dwell, so silence never PREVENTS a fire that
#: the dwell had already earned.
STALE_AFTER_S = float(os.environ.get("CORR_PROACTIVE_STALE_S", "3600"))


# ── the check table ──────────────────────────────────────────────────────────

#: How a check reads an observation. Three comparisons cover the whole
#: heartbeat list, and keeping them as a WORD rather than a callable field
#: means the check table stays printable, comparable and diffable — a callable
#: on a frozen dataclass breaks equality and turns the table into addresses.
#:   "below"        — bad while value < threshold   (BGP state < established)
#:   "at_or_above"  — bad while value >= threshold  (CPU/memory floors)
#:   "negative"     — bad while value < 0           (the encoded adjacency lane)
BadWhen = str


@dataclass(frozen=True)
class ProactiveCheck:
    """One heartbeat condition, as DATA.

    `kind` is the signal kind the check WOULD emit once promoted; while
    `shadow` is True it is a declaration, not a producer output — which is why
    it is deliberately absent from `producers.EMITTED_KINDS` (nothing emits
    it, so the coverage gate must not be told that something does).
    """

    check_id: str
    kind: str
    #: What the check watches: a canonical metric name, or the signal kind
    #: whose `attrs.state` it tracks.
    trigger: str
    #: "metric" | "adjacency" — which `observe_*` entry point feeds it.
    lane: str
    entity_type: EntityType
    modality: ModalityClass
    source: Source
    severity: Severity
    bad_when: BadWhen
    threshold: float = 0.0
    dwell_s: float = DEFAULT_DWELL_S
    #: A8/A9b: evaluated + counted, emits NOTHING. Flip per check, one at a
    #: time, following `PROMOTION`.
    shadow: bool = True
    #: The operator-facing sentence, in the catalog's own voice. Carried on
    #: the check (not only on the template) so the shadow firing is readable
    #: in a log line before any signature exists to render it.
    operator_phrase: str = ""

    def __post_init__(self) -> None:
        if self.bad_when not in ("below", "at_or_above", "negative"):
            raise ValueError(f"{self.check_id}: unknown bad_when {self.bad_when!r}")

    def bad(self, value: float) -> bool:
        """Is this observation the condition the check watches for? Total by
        construction — every `bad_when` is validated at construction, so there
        is no silent 'no branch matched, assume healthy' path."""
        if self.bad_when == "below":
            return value < self.threshold
        if self.bad_when == "at_or_above":
            return value >= self.threshold
        return value < 0.0


#: The heartbeat list, in the order the audit doc states it.
#:
#: OSPF and IS-IS carry TWO lanes each, on purpose (tracker 222).
#:
#:  * the ADJACENCY-CHANGE SIGNAL (`lane="adjacency"`), which works on
#:    syslog-only and trap-only estates and needs no polled series at all; and
#:  * the POLLED SERIES (`lane="metric"`, `device_ospf_nbr_state` /
#:    `device_isis_adj_state`), admitted onto the correlation bus as the `igp`
#:    family by tracker 222 — `rcaMetricFamilies` in
#:    src/backend/collectors/metric_events.go and its pinned mirror, the gnmic
#:    shaper's `corr-rca-shape` allowlist, changed together.
#:
#: The metric lane closes the signal lane's one weakness: it answers "is it
#: STILL bad?" from the current sample instead of depending on receiving the
#: recovery line. It is gated on PRESENCE by construction — `observe_metric` is
#: only ever called with a sample that arrived, so on an estate that polls
#: neither series the metric checks simply never open a watch, and on an estate
#: that polls them the signal lane keeps working unchanged.
#:
#: Both lanes stay `shadow` until the ownership question in `PROMOTION` is
#: settled: they emit the same `kind` on different entities (`device` vs
#: `device:neighbour`), so promoting both without a dedup rule would count one
#: stuck adjacency twice.
CHECKS: tuple[ProactiveCheck, ...] = (
    ProactiveCheck(
        check_id="proactive.bgp.not_established",
        kind="bgp_session_not_established",
        trigger="device_bgp_peer_state",
        lane="metric",
        entity_type=EntityType.DEVICE,
        modality=ModalityClass.DEVICE_TELEMETRY,
        source=Source.METRIC,
        severity=Severity.HIGH,
        bad_when="below",
        threshold=float(BGP_STATE_ESTABLISHED),
        operator_phrase=(
            "This BGP peer has stayed below ESTABLISHED for the whole window — "
            "it is not flapping, it is not coming up. Check whether the peer is "
            "reachable at all (IDLE/CONNECT) or being refused (ACTIVE): a stuck "
            "session is a configuration, policy or underlay problem, not a "
            "transient one."),
    ),
    ProactiveCheck(
        check_id="proactive.bgp.adjacency_down_persisting",
        kind="bgp_session_not_established",
        trigger="bgp_adjacency_change",
        lane="adjacency",
        entity_type=EntityType.DEVICE,
        modality=ModalityClass.CONTROL_PLANE,
        source=Source.SYSLOG,
        severity=Severity.HIGH,
        bad_when="negative",
        operator_phrase=(
            "This BGP peer went down and has not come back — the session has "
            "been down for the whole window with no re-establish. Treat it as a "
            "standing outage of that peering, not a flap."),
    ),
    ProactiveCheck(
        check_id="proactive.ospf.adjacency_not_full",
        kind="ospf_adjacency_not_full",
        trigger="ospf_adjacency_change",
        lane="adjacency",
        entity_type=EntityType.DEVICE,
        modality=ModalityClass.CONTROL_PLANE,
        source=Source.SYSLOG,
        severity=Severity.HIGH,
        bad_when="negative",
        operator_phrase=(
            "This OSPF adjacency has stayed out of FULL for the whole window — "
            "it dropped and did not re-form. An adjacency stuck short of FULL is "
            "usually MTU, area/auth mismatch or a one-way link, not a bounce; "
            "check ip mtu and the area/authentication config on both ends."),
    ),
    ProactiveCheck(
        check_id="proactive.isis.adjacency_not_up",
        kind="isis_adjacency_not_up",
        trigger="isis_adjacency_change",
        lane="adjacency",
        entity_type=EntityType.DEVICE,
        modality=ModalityClass.CONTROL_PLANE,
        source=Source.SYSLOG,
        severity=Severity.HIGH,
        bad_when="negative",
        operator_phrase=(
            "This IS-IS adjacency has stayed out of UP for the whole window — it "
            "dropped and did not re-form. On a fabric that is a lost path, not a "
            "flap: check the level (L1/L2), the MTU and the area on both ends "
            "before looking further."),
    ),
    ProactiveCheck(
        check_id="proactive.ospf.nbr_state_not_full",
        kind="ospf_adjacency_not_full",
        trigger="device_ospf_nbr_state",
        lane="metric",
        entity_type=EntityType.DEVICE,
        modality=ModalityClass.DEVICE_TELEMETRY,
        source=Source.METRIC,
        severity=Severity.HIGH,
        bad_when="below",
        threshold=float(OSPF_NBR_STATE_FULL),
        operator_phrase=(
            "This OSPF neighbour has POLLED below FULL for the whole window — "
            "the current state says so, not a log line we may have missed. An "
            "adjacency stuck short of FULL is usually MTU, area/auth mismatch "
            "or a one-way link; check ip mtu and the area/authentication "
            "config on both ends."),
    ),
    ProactiveCheck(
        check_id="proactive.isis.adj_state_not_up",
        kind="isis_adjacency_not_up",
        trigger="device_isis_adj_state",
        lane="metric",
        entity_type=EntityType.DEVICE,
        modality=ModalityClass.DEVICE_TELEMETRY,
        source=Source.METRIC,
        severity=Severity.HIGH,
        bad_when="below",
        threshold=float(ISIS_ADJ_STATE_UP),
        operator_phrase=(
            "This IS-IS adjacency has POLLED below UP for the whole window — "
            "the current state says so, not a log line we may have missed. On "
            "a fabric that is a lost path, not a flap: check the level "
            "(L1/L2), the MTU and the area on both ends before looking "
            "further."),
    ),
    ProactiveCheck(
        check_id="proactive.device.cpu_sustained_high",
        kind="device_resource_saturation",
        trigger="device_cpu_percent",
        lane="metric",
        entity_type=EntityType.DEVICE,
        modality=ModalityClass.DEVICE_TELEMETRY,
        source=Source.METRIC,
        severity=Severity.WARN,
        bad_when="at_or_above",
        threshold=CPU_HIGH_PCT,
        operator_phrase=(
            "This device has held CPU above the saturation floor for the whole "
            "window. Sustained is the point: a box that is always this busy has "
            "no deviation to detect, and control-plane work (adjacency "
            "keepalives, SNMP, the CLI you are about to open) is already "
            "competing for it."),
    ),
    ProactiveCheck(
        check_id="proactive.device.mem_sustained_high",
        kind="device_resource_saturation",
        trigger="device_mem_percent",
        lane="metric",
        entity_type=EntityType.DEVICE,
        modality=ModalityClass.DEVICE_TELEMETRY,
        source=Source.METRIC,
        severity=Severity.WARN,
        bad_when="at_or_above",
        threshold=MEM_HIGH_PCT,
        operator_phrase=(
            "This device has held memory above the saturation floor for the "
            "whole window. Check what is growing (route/MAC tables, a leaking "
            "process) before it starts refusing allocations — a box that runs "
            "out of memory drops adjacencies rather than reporting the cause."),
    ),
)

#: Adjacency `attrs.state` is a WORD, not a number — the producers normalize
#: every vendor spelling onto {down, up, unknown} (parser_rules.py, the
#: `state` scan/case blocks). Encode it so one dwell-timer serves both lanes:
#: bad states are negative, good states positive, `unknown` is NEITHER and is
#: dropped by the caller rather than guessed at.
ADJ_STATE_VALUE: Mapping[str, float] = {"down": -1.0, "up": 1.0}

CHECKS_BY_TRIGGER: Mapping[str, tuple[ProactiveCheck, ...]] = {
    trig: tuple(c for c in CHECKS if c.trigger == trig)
    for trig in {c.trigger for c in CHECKS}
}
CHECK_BY_ID: Mapping[str, ProactiveCheck] = {c.check_id: c for c in CHECKS}

#: The kinds these checks would emit once promoted. NOT registered in
#: `producers.EMITTED_KINDS` while every check is shadow — see ProactiveCheck.
SHADOW_KINDS: frozenset[str] = frozenset(c.kind for c in CHECKS)

#: A8-shaped counters. Pre-seeded at zero so the /metrics series exists before
#: the first firing (a label set that appears only on failure is a label set
#: nobody has a dashboard for). Bounded by construction: the key space is the
#: fixed check table.
SHADOW_HITS: dict[str, int] = {c.check_id: 0 for c in CHECKS if c.shadow}
LIVE_HITS: dict[str, int] = {c.check_id: 0 for c in CHECKS}


# ── events ───────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ProactiveEvent:
    """A check firing. `phase` mirrors `EpisodeEvent`: 'onset' when the dwell
    is first satisfied, 'clear' when the state returns to good after a fire."""

    phase: str                 # 'onset' | 'clear'
    check_id: str
    kind: str
    tenant_id: str
    entity_id: str
    entity_tokens: tuple[str, ...]
    #: When the bad state STARTED — not when the dwell expired, and never the
    #: firing time. Same rule as `EpisodeEvent.onset_ts`: an alert time is a
    #: systematic lie about causal order, and RCA is built on that order.
    onset_ts: datetime
    #: How long the state had been continuously bad at firing time.
    held_s: float
    value: float
    observer_id: str
    metric_name: str
    peer: str = ""
    clear_ts: datetime | None = None

    def native_id(self) -> str:
        """Content-bearing and idempotent under redelivery (tracker 198): the
        identity is the (check, entity, onset), so a re-observed firing of the
        same held state is the same event, not a second one."""
        onset_ms = int(self.onset_ts.timestamp() * 1000)
        return (f"{self.tenant_id}|{self.entity_id}|{self.check_id}|"
                f"{self.phase}|{onset_ms}")


# ── the dwell-timer plane ────────────────────────────────────────────────────

@dataclass
class _Watch:
    """Per (tenant, entity, check) state. NO HISTORY: a dwell timer needs the
    start of the current bad run and whether it has already fired — keeping
    samples would make an unbounded store out of a bounded one. Everything
    else here is the last observation, carried so a firing can describe itself
    without a second lookup."""

    since: datetime | None = None   # start of the current continuous bad run
    fired: bool = False             # onset already emitted for this run
    last_ts: datetime | None = None  # last observation (staleness + clear ts)
    last_value: float = 0.0
    observer_id: str = ""
    tokens: tuple[str, ...] = ()
    peer: str = ""
    #: The entity the firing REPORTS. Distinct from the watch key, which is
    #: (device|peer) for the adjacency lane so one peer coming up cannot clear
    #: another's outage. Held on the watch because `sweep()` fires from the key
    #: alone and would otherwise report the composite as the entity id.
    entity_id: str = ""
    #: When a SWEEP first saw this run open — the anti-skew gate. See
    #: `ProactiveMonitor.sweep`.
    armed_at: datetime | None = None
    #: Accepted-observation counter, and the value the last sweep read. Their
    #: difference is "has anything happened since I last looked" — the ONLY
    #: honest way to measure silence, because `last_ts` is the DEVICE's clock
    #: and a box an hour behind would look permanently silent under it.
    obs: int = 0
    obs_at_sweep: int = -1
    #: Sweep-clock time since which this watch has been silent.
    idle_since: datetime | None = None


class ProactiveMonitor:
    """Bounded, deterministic dwell timers over the checks in `CHECKS`.

    Pure in the sense that matters: given the same ordered observations it
    yields the same events. It holds state (that is the whole job) but performs
    no IO and reads no clock of its own — every method takes the timestamp from
    the caller, so replay and tests drive it with stream time, not wall time.
    """

    def __init__(self, *, max_watches: int = MAX_WATCHES,
                 stale_after_s: float = STALE_AFTER_S) -> None:
        self._watches: OrderedDict[tuple[str, str, str], _Watch] = OrderedDict()
        self._max = max(1, int(max_watches))
        self._stale = timedelta(seconds=max(1.0, float(stale_after_s)))
        self.evicted = 0

    # -- introspection ------------------------------------------------------
    def __len__(self) -> int:
        return len(self._watches)

    def open_watches(self) -> int:
        """Watches currently holding a bad state (a gauge worth graphing: it
        is the size of the 'something is still wrong' set)."""
        return sum(1 for w in self._watches.values() if w.since is not None)

    def reset(self) -> None:
        """Test hook + the restart contract: dwell state is in-memory and
        deliberately not persisted. A restart does not fabricate a dwell it
        did not observe; it starts timing again from the next observation."""
        self._watches.clear()
        self.evicted = 0

    # -- observation --------------------------------------------------------
    def observe_metric(
        self, *, tenant: str, entity_id: str, metric: str, value: float,
        ts: datetime, observer_id: str, tokens: tuple[str, ...] = (),
        peer: str = "",
    ) -> tuple[ProactiveEvent, ...]:
        """A canonical metric sample. Returns the events the caller may act on
        — EMPTY for every shadow check, whose firing is counted and dropped."""
        checks = CHECKS_BY_TRIGGER.get(metric)
        if not checks:
            return ()
        return self._advance(checks, tenant, entity_id, value, ts,
                             observer_id, tokens, peer, metric)

    def observe_signal(
        self, *, tenant: str, entity_id: str, kind: str, state: str,
        ts: datetime, observer_id: str, tokens: tuple[str, ...] = (),
        peer: str = "",
    ) -> tuple[ProactiveEvent, ...]:
        """A control-plane adjacency Signal. `state` is the producer's own
        normalized word; anything outside {down, up} is DROPPED — 'unknown'
        means the grammar could not read the state, and a dwell timer must
        never treat "we could not tell" as "it is fine" (which would clear a
        real outage) or as "it is broken" (which would invent one)."""
        checks = CHECKS_BY_TRIGGER.get(kind)
        if not checks:
            return ()
        value = ADJ_STATE_VALUE.get(state.strip().lower())
        if value is None:
            return ()
        # An adjacency is per (device, peer): one peer dropping must not clear
        # the watch on another. The peer is already a grounding token on the
        # signal, so it is identity here too.
        key_entity = f"{entity_id}|{peer}" if peer else entity_id
        return self._advance(checks, tenant, key_entity, value, ts,
                             observer_id, tokens, peer, kind,
                             report_entity=entity_id)

    def sweep(self, now: datetime) -> tuple[ProactiveEvent, ...]:
        """Advance every open watch to `now` and fire the ones whose dwell has
        expired without another observation.

        This is not an optimisation — it is the only reason the syslog-driven
        checks work at all. A device logs "adjacency down" ONCE; without a
        sweep nothing would ever ask whether it is still down, and the check
        would silently only ever fire for the polled lanes.

        O(watches) per call, on the engine loop's cadence, not the ingest hot
        path — bounded by `CORR_PROACTIVE_MAX_WATCHES` and by the staleness
        expiry that runs in the same pass, which is what keeps the set the
        size of the estate rather than the size of its history.

        THE ANTI-SKEW GATE — the reason this method reads two clocks. `now` is
        the sweep's; `since` and `last_ts` are the DEVICE's (a syslog/trap
        timestamp). Both of the naive readings are wrong on a box with a bad
        NTP config:

          * a device an hour BEHIND opens a run stamped an hour ago, so a naive
            `now - since` would fire on the first sweep and invent a
            five-minute outage out of a clock error;
          * the same device would also look permanently SILENT under a naive
            `now - last_ts`, so its watch would be expired as stale before it
            could ever fire.

        So neither duration is measured on the device's clock. A firing must
        have survived the dwell from `armed_at` (the first sweep that saw the
        run open), and silence is measured by whether the observation COUNTER
        moved between sweeps, not by comparing timestamps from two clocks. The
        reported `held_s` is that conservative, actually-observed span; the
        reported onset stays the device's own claim, which is what an operator
        needs to line this up against the rest of the timeline. The polled lane
        needs none of this: `_advance` ignores out-of-order samples, so a
        backwards clock jump cannot inflate a dwell there.

        A watch that expires while `fired` is set emits no `clear` — the state
        is unknown, not resolved, and manufacturing a recovery for a device
        that went silent would be exactly the lie this gate exists to prevent.
        A later transition simply opens a new watch.
        """
        out: list[ProactiveEvent] = []
        stale: list[tuple[str, str, str]] = []
        for key, w in self._watches.items():
            if w.obs != w.obs_at_sweep:       # activity since the last sweep
                w.obs_at_sweep = w.obs
                w.idle_since = now
            elif w.idle_since is not None and (now - w.idle_since) > self._stale:
                stale.append(key)
                continue
            if w.since is None or w.fired:
                continue
            if w.armed_at is None:
                w.armed_at = now      # first sighting — the dwell starts here
                continue
            check = CHECK_BY_ID[key[2]]
            held = min((now - w.since).total_seconds(),
                       (now - w.armed_at).total_seconds())
            if held < check.dwell_s:
                continue
            w.fired = True
            ev = self._event("onset", check, key, w, held, now)
            if ev is not None:
                out.append(ev)
        for key in stale:
            self._watches.pop(key, None)
        return tuple(out)

    # -- internals ----------------------------------------------------------
    def _advance(
        self, checks: Iterable[ProactiveCheck], tenant: str, entity_id: str,
        value: float, ts: datetime, observer_id: str,
        tokens: tuple[str, ...], peer: str, metric: str,
        report_entity: str | None = None,
    ) -> tuple[ProactiveEvent, ...]:
        out: list[ProactiveEvent] = []
        for check in checks:
            key = (tenant, entity_id, check.check_id)
            w = self._watches.get(key)
            if w is None:
                w = _Watch()
                self._watches[key] = w
                while len(self._watches) > self._max:
                    self._watches.popitem(last=False)
                    self.evicted += 1
            else:
                self._watches.move_to_end(key)
            # Out-of-order sample: the dwell is a wall of STREAM time, and
            # rewinding it would let a late sample shorten or reopen a run
            # that already closed. Ignore it — visible as a no-op, never as a
            # silent state change.
            if w.last_ts is not None and ts < w.last_ts:
                continue
            w.last_ts = ts
            w.obs += 1
            w.last_value = value
            w.observer_id = observer_id or w.observer_id
            w.tokens = tokens or w.tokens
            w.peer = peer or w.peer
            w.entity_id = report_entity or entity_id
            if not check.bad(value):
                if w.fired:
                    ev = self._event("clear", check, key, w, 0.0, ts,
                                     report_entity=report_entity)
                    if ev is not None:
                        out.append(ev)
                w.since = None
                w.fired = False
                w.armed_at = None
                continue
            if w.since is None:
                w.since = ts
                w.armed_at = None
            if w.fired:
                continue
            held = (ts - w.since).total_seconds()
            if held < check.dwell_s:
                continue
            w.fired = True
            ev = self._event("onset", check, key, w, held, ts,
                             report_entity=report_entity)
            if ev is not None:
                out.append(ev)
        return tuple(out)

    def _event(self, phase: str, check: ProactiveCheck,
               key: tuple[str, str, str], w: _Watch, held: float,
               now: datetime, report_entity: str | None = None,
               ) -> ProactiveEvent | None:
        """Build the event — then apply the SHADOW GATE.

        A8, restated for this plane: a shadow check is counted here and
        returns None, so a caller cannot accidentally emit one. The gate is in
        the constructor rather than at the call sites on purpose — there is
        exactly one place to audit, and adding a new call site cannot open a
        hole in it.
        """
        tenant, _entity_key, check_id = key
        if check.shadow:
            SHADOW_HITS[check_id] = SHADOW_HITS.get(check_id, 0) + 1
            return None
        LIVE_HITS[check_id] = LIVE_HITS.get(check_id, 0) + 1
        onset = w.since if w.since is not None else now
        return ProactiveEvent(
            phase=phase,
            check_id=check_id,
            kind=check.kind,
            tenant_id=tenant,
            entity_id=report_entity or w.entity_id or _entity_key,
            entity_tokens=w.tokens,
            onset_ts=onset,
            held_s=round(held, 3),
            value=w.last_value,
            observer_id=w.observer_id,
            metric_name=check.trigger,
            peer=w.peer,
            clear_ts=now if phase == "clear" else None,
        )


def proactive_signal(ev: ProactiveEvent) -> Signal:
    """ProactiveEvent → canonical Signal row.

    Only ever reached for a PROMOTED (non-shadow) check — the monitor returns
    no event for a shadow one — but it ships now, and is tested now against a
    deliberately-promoted check, so that promotion really is the one-line flip
    the module docstring promises rather than "flip the flag, then write the
    emission path under time pressure".

    Two properties it must have, both inherited from the A9b symptom:
      * IDENTITY is content-bearing and idempotent under redelivery — the
        native_id is (tenant, entity, check, phase, onset), so re-observing the
        same held state is the same signal.
      * GROUNDING is the DEVICE (and the peer, when there is one). Never the
        metric name, never the check id: a token that is not one entity welds
        unrelated incidents into one object (#99 R2).
    """
    check = CHECK_BY_ID[ev.check_id]
    attrs = {
        "check_id": ev.check_id,
        "phase": ev.phase,
        "held_s": ev.held_s,
        "dwell_s": check.dwell_s,
        "bad_when": check.bad_when,
        "threshold": check.threshold,
        "operator_phrase": check.operator_phrase,
    }
    if ev.peer:
        attrs["peer"] = ev.peer
    if ev.clear_ts is not None:
        attrs["clear_ts"] = ev.clear_ts.isoformat()
    return Signal(
        tenant_id=ev.tenant_id,
        ts=ev.onset_ts if ev.phase == "onset" else (ev.clear_ts or ev.onset_ts),
        source=check.source,
        kind=check.kind if ev.phase == "onset" else f"{check.kind}_clear",
        observer=Observer(
            observer_id=ev.observer_id,
            observer_type=ObserverType.DEVICE,
            collection_path="proactive_check",
            clock_quality="unknown",
        ),
        modality_class=check.modality,
        entity_type=check.entity_type,
        entity_id=ev.entity_id,
        severity=check.severity,
        native_id=ev.native_id(),
        entity_tokens=ev.entity_tokens,
        metric_name=ev.metric_name,
        value=ev.value,
        attrs=attrs,
    )


def proactive_stats() -> dict:
    """Counters + the check table, for /metrics and /healthz.

    Shaped like `producers.parser_stats()`: metadata (what each check IS) next
    to the counters, so the shadow rate can be read against the check that
    produced it without a second lookup.
    """
    return {
        "checks": len(CHECKS),
        "checks_meta": [
            {"check_id": c.check_id, "kind": c.kind, "lane": c.lane,
             "trigger": c.trigger, "dwell_s": c.dwell_s, "shadow": bool(c.shadow)}
            for c in CHECKS
        ],
        "shadow_hits": dict(SHADOW_HITS),
        "live_hits": dict(LIVE_HITS),
    }


def reset_counters() -> None:
    """Test hook — the counters are module-level by design (same as
    `producers.SHADOW_HITS`), so a suite that asserts on them must be able to
    zero them."""
    for k in SHADOW_HITS:
        SHADOW_HITS[k] = 0
    for k in LIVE_HITS:
        LIVE_HITS[k] = 0


# ── the signatures, authored and NOT installed ───────────────────────────────
# Template dicts in exactly the `catalog.BUILTIN_TEMPLATES` shape. They are
# authored here, schema-validated by `test_proactive_checks_a4.py` (built into
# a real `Catalog` alongside the built-ins), and deliberately left OUT of the
# built-in list: installing one moves `catalog_version`, which
# `Snapshot.content_hash()` pins, which moves `FIXTURE_GOLDEN`. Step 3 of
# PROMOTION installs the one template belonging to the check being promoted.
#
# Wording follows the catalog's own voice: `operator_phrase` states what the
# engine believes and why, `first_steps` are what a network engineer does next,
# and neither claims more certainty than single-plane evidence supports.
PROACTIVE_TEMPLATES: tuple[dict, ...] = (
    {
        "id": "sig.ent.wan-edge.bgp-session-stuck",
        "title": "BGP session stuck below ESTABLISHED",
        "domain": "ent.wan-edge",
        "requires": [
            {"kind": "bgp_session_not_established", "entity_type": "device"},
            # Corroboration, never required: the peering interface, the box's
            # own pressure, or reachability loss to what the peer carried.
            {"kind": "link_state_change|device_resource_saturation|probe_loss",
             "optional": True},
            # "What changed?" — a config or policy push on the same device in
            # the window. Single-plane by construction (the box talking about
            # itself), so it raises coverage and never supplies the second
            # modality a confirmation needs.
            {"kind": "device_config_change", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # A session that is stuck AND flapping is a flap — the flap
            # signature explains the churn, and this one would double-count it.
            {"absent": {"kind": "bgp_adjacency_change"}, "within_s": 300,
             "else_prefer": "sig.ent.wan-edge.bgp-peer-flap"},
        ],
        "direction_expect": "control-plane -> route -> service",
        "operator_phrase": (
            "This BGP peer has stayed below ESTABLISHED for the whole window — "
            "it is not flapping, it is not coming up. IDLE/CONNECT points at "
            "reachability to the peer address; ACTIVE points at the peer "
            "refusing or never answering the open."),
        "verdict": {
            "owner": "netops", "layer": "L3 (routing)",
            "first_steps": [
                "Read the session state and the last error on the peer (IDLE/CONNECT = we cannot reach it; ACTIVE = it is not answering our OPEN)",
                "Verify the peering address is reachable and the update-source/TTL/MD5 still match on both sides",
                "Check for a policy or ACL change on either end inside the window, then escalate to the peer owner if the local side is clean",
            ],
        },
    },
    {
        "id": "sig.ent.access.ospf-adjacency-stuck",
        "title": "OSPF adjacency stuck short of FULL",
        "domain": "ent.access",
        "requires": [
            {"kind": "ospf_adjacency_not_full", "entity_type": "device"},
            {"kind": "if_metric_anomaly|device_resource_saturation|link_state_change",
             "optional": True},
            {"kind": "device_config_change", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            {"absent": {"kind": "link_state_change"}, "within_s": 300,
             "else_prefer": "sig.ent.access.local-link-fault"},
        ],
        "direction_expect": "control-plane -> route -> service",
        "operator_phrase": (
            "This OSPF adjacency dropped and has not re-formed for the whole "
            "window. An adjacency that stays short of FULL is usually MTU, an "
            "area/authentication mismatch or a one-way link — not a bounce."),
        "verdict": {
            "owner": "netops", "layer": "L3 (IGP)",
            "first_steps": [
                "Read the neighbor state on both ends — EXSTART/EXCHANGE means MTU, INIT means our hellos are not being heard back",
                "Compare ip mtu, area id, network type, hello/dead timers and authentication on both interfaces",
                "Check the interface for one-way loss (errors on one side only) before assuming a protocol misconfiguration",
            ],
        },
    },
    {
        "id": "sig.ent.fabric.isis-adjacency-stuck",
        "title": "IS-IS adjacency stuck out of UP (fabric IGP)",
        "domain": "ent.fabric",
        "requires": [
            {"kind": "isis_adjacency_not_up", "entity_type": "device"},
            {"kind": "if_metric_anomaly|device_resource_saturation|lldp_neighbor_change|link_state_change",
             "optional": True},
            {"kind": "device_config_change", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            {"absent": {"kind": "link_state_change"}, "within_s": 300,
             "else_prefer": "sig.ent.access.local-link-fault"},
        ],
        "direction_expect": "control-plane -> route -> service",
        "operator_phrase": (
            "This IS-IS adjacency dropped and has not re-formed for the whole "
            "window. On a fabric that is a lost path, not a flap — the spine "
            "keeps forwarding, so the loss shows up as reduced capacity rather "
            "than an outage."),
        "verdict": {
            "owner": "netops", "layer": "L2/L3 (IS-IS fabric IGP)",
            "first_steps": [
                "Identify the neighbor system-id and the level (L1/L2) that did not come back",
                "Compare MTU, level, area and authentication on both interfaces — an IS-IS adjacency that stays in INIT is almost always one of those",
                "Confirm the remaining fabric paths still carry the load before scheduling the fix",
            ],
        },
    },
    {
        "id": "sig.ent.device.resource-saturation",
        "title": "Device resource saturation (sustained CPU/memory)",
        "domain": "ent.access",
        "requires": [
            {"kind": "device_resource_saturation", "entity_type": "device"},
            # What saturation DOES: it starves the control plane. Any of these
            # on the same device turns a standing property into a story.
            {"kind": "bgp_adjacency_change|ospf_adjacency_change|isis_adjacency_change|probe_loss",
             "optional": True},
            {"kind": "device_config_change", "optional": True},
            # A reload inside the window RE-READS the whole finding: a box that
            # is busy because it just came up is converging, not short of
            # capacity. `device_restart` is INTENTIONAL_BLIND (coverage.py) —
            # emitted, searchable, required by no signature — so naming it as
            # an OPTIONAL clause is the first reasoning use it has had, and the
            # honest one: it changes what the operator should conclude without
            # pretending to be a competing root cause of its own.
            {"kind": "device_restart", "optional": True},
        ],
        "required_modalities": ["device_telemetry"],
        # No discriminator. The look-alike ("it just reloaded") has no competing
        # template to prefer, and pointing `else_prefer` at an unrelated
        # signature to satisfy the schema would be worse than saying nothing —
        # it would make the engine argue for a cause nobody proposed.
        "direction_expect": "device -> control-plane -> service",
        "operator_phrase": (
            "This device has held CPU or memory above the saturation floor for "
            "the whole window. Sustained is the point — a box that is always "
            "this busy shows no deviation to detect, while adjacency "
            "keepalives, SNMP and your own CLI session compete for what is "
            "left."),
        "verdict": {
            "owner": "netops", "layer": "device (platform)",
            "first_steps": [
                "Check first whether the device reloaded inside the window — a box that just came up is converging, not short of capacity",
                "Identify the top process/queue on the box and whether it is control-plane punt, a scan, or a leaking process",
                "Check whether adjacencies or probes on this device degraded inside the same window — saturation is only a cause once something else moved",
                "If it is punt-driven, find the traffic being punted (CoPP counters, ACL logging) rather than raising the threshold",
            ],
        },
    },
)

#: Promotion order and the one-line justification for each. Read with
#: `PROMOTION` in the module docstring.
PROMOTION: Mapping[str, str] = {
    "proactive.bgp.not_established":
        "Polled lane, numeric contract (bgpPeerState), no noise-pool overlap — "
        "the first candidate. Promote when the shadow rate tracks real stuck "
        "peers rather than devices whose poller is intermittently silent.",
    "proactive.bgp.adjacency_down_persisting":
        "Syslog-driven, so it depends on the sweep AND on receiving the "
        "recovery line. Promote only after the metric check above is live and "
        "the two have been compared on the same estate — if they disagree, the "
        "recovery line is being lost and the check would fabricate outages. "
        "NOTE: it emits the SAME kind as the metric check but on a different "
        "entity (device vs device:peer), so promoting both without a dedup rule "
        "double-counts one stuck peer as two pieces of evidence — decide which "
        "lane owns the kind before either goes live on a gNMI/SNMP estate.",
    "proactive.ospf.adjacency_not_full":
        "Same dependency as the BGP adjacency check: it needs the sweep AND the "
        "recovery line. Superseded as the PREFERRED route by "
        "proactive.ospf.nbr_state_not_full below, now that the metric path "
        "exists (tracker 222); keep it as the lane that still works on a "
        "syslog-only estate.",
    "proactive.ospf.nbr_state_not_full":
        "The metric path the audit doc named as preferred, unblocked by tracker "
        "222 (`igp` is now an RCA family in BOTH producers). Polled, numeric "
        "contract (ospfNbrState), and it does not depend on receiving the "
        "recovery line. Promote FIRST of the OSPF pair, and only together with "
        "a dedup rule: it emits the same kind as "
        "proactive.ospf.adjacency_not_full on a different entity "
        "(device:neighbour vs device), so promoting both un-deduped counts one "
        "stuck adjacency twice.",
    "proactive.isis.adjacency_not_up":
        "As above, the syslog lane. On a fabric the stakes are "
        "different from the access edge: a lost adjacency is reduced "
        "capacity rather than an outage, so this check must be promoted "
        "with a severity that does not page for a spine link the fabric "
        "already routed around.",
    "proactive.isis.adj_state_not_up":
        "The IS-IS metric path (device_isis_adj_state, gNMI-owned), unblocked by "
        "tracker 222. Same dedup precondition as the OSPF pair, and the same "
        "fabric severity caveat: on a spine the fabric already routed around, a "
        "lost adjacency is reduced capacity, not an outage.",
    "proactive.device.cpu_sustained_high":
        "Needs a per-platform floor before promotion: 90 % is normal for some "
        "control-plane-heavy platforms and alarming for others, and one global "
        "constant would make this the noisiest check in the set.",
    "proactive.device.mem_sustained_high":
        "As above; memory is the more portable of the two, because a device at "
        "90 % memory is close to refusing allocations on every platform.",
}
