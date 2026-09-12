# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""A4 — the proactive heartbeat plane (`proactive.py`).

The gap this closes, stated once: THE ENGINE FLAGGED TRANSITIONS AND NOT
STATES. `bgp_adjacency_change` fires when a session drops and then never again;
`device_resource_anomaly` is a CUSUM episode against the box's OWN baseline, so
a router that has run at 97 % CPU for a week has 97 % as normal and deviates by
nothing. NetClaw's heartbeat list asks the other question — *is it still bad,
and has it been bad long enough to matter* — and until now nothing in this
engine did.

WHAT THIS FILE PINS, in the order that matters:

  1. THE DISCRIMINATOR — persistent fires, flapping does NOT. This is the whole
     value of the plane: a flap already has a signature that explains it, and a
     check that fired on both would be a second, noisier copy of that
     signature. Positive, negative and flap streams for every check.
  2. THE SHADOW CONTRACT — every check ships shadow, a shadow firing is
     COUNTED and returns NOTHING, and no call site can bypass that (the gate is
     in the event constructor, not at the call sites).
  3. THE V1 GOLDENS DO NOT MOVE — `FIXTURE_GOLDEN` and the built-in catalog
     version are byte-identical with this module present. That is a
     CONSEQUENCE of 2 and of leaving `PROACTIVE_TEMPLATES` uninstalled, and it
     is asserted rather than argued.
  4. PROMOTION IS ONE LINE — a deliberately-promoted check emits a real,
     well-formed Signal through the same builder production would use, and the
     authored signature loads into a real Catalog beside the built-ins. Neither
     is exercised in production while the flags are off, so both are exercised
     here.
  5. IT IS BOUNDED AND TENANT-SCOPED — the watch store is LRU-capped, stale
     watches expire, out-of-order samples cannot rewind a dwell, and two
     tenants that own a same-named device never share a timer (§3a).
"""
from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta, timezone

import pytest

import coverage
import proactive as P
from catalog import BUILTIN_TEMPLATES, builtin_catalog, load_catalog
from coverage import classify_kind
from producers import EMITTED_KINDS
from signals import DeadLetter, ModalityClass, Severity, Source

T0 = datetime(2026, 9, 2, 12, 0, 0, tzinfo=timezone.utc)
DWELL = P.DEFAULT_DWELL_S


@pytest.fixture(autouse=True)
def _clean_counters():
    """The counters are module-level by design (same as
    `producers.SHADOW_HITS`), so every test starts from zero."""
    P.reset_counters()
    yield
    P.reset_counters()


def _at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def _promoted(check_id: str) -> P.ProactiveCheck:
    """The same check with `shadow=False` — what promotion produces."""
    return dataclasses.replace(P.CHECK_BY_ID[check_id], shadow=False)


@pytest.fixture
def promote(monkeypatch):
    """Promote ONE check for the duration of a test.

    The monitor reads the check table through `CHECK_BY_ID` /
    `CHECKS_BY_TRIGGER`, so promotion in production is exactly this: the same
    row with one flag flipped. Patching both maps (rather than reaching into
    the monitor) keeps the test on the real code path.
    """
    def _do(check_id: str) -> P.ProactiveCheck:
        live = _promoted(check_id)
        by_id = {**P.CHECK_BY_ID, check_id: live}
        by_trigger = {
            trig: tuple(by_id[c.check_id] for c in checks)
            for trig, checks in P.CHECKS_BY_TRIGGER.items()
        }
        monkeypatch.setattr(P, "CHECK_BY_ID", by_id)
        monkeypatch.setattr(P, "CHECKS_BY_TRIGGER", by_trigger)
        return live
    return _do


# ── 1. the discriminator: persistent fires, flapping does not ───────────────

def test_bgp_stuck_below_established_fires_once_the_dwell_is_held(promote):
    """A peer parked in ACTIVE. The engine's existing evidence for this is ONE
    adjacency line at t=0 and then silence; the poller keeps saying 3."""
    promote("proactive.bgp.not_established")
    mon = P.ProactiveMonitor()
    fired = []
    for t in range(0, int(DWELL) + 61, 60):
        fired += list(mon.observe_metric(
            tenant="t1", entity_id="wan-r1:198.51.100.7",
            metric="device_bgp_peer_state", value=3.0, ts=_at(t),
            observer_id="wan-r1", tokens=("wan-r1", "198.51.100.7"),
            peer="198.51.100.7"))
    assert [e.phase for e in fired] == ["onset"], (
        "a session held below ESTABLISHED past the dwell must fire EXACTLY "
        "once — a re-fire on every subsequent poll would turn one stuck peer "
        "into a signal storm")
    ev = fired[0]
    assert ev.kind == "bgp_session_not_established"
    # The onset is when the bad state STARTED, not when the dwell expired.
    # Alert-firing time is a systematic lie about causal order, which is the
    # one thing RCA cannot tolerate.
    assert ev.onset_ts == T0
    assert ev.held_s >= DWELL
    assert ev.peer == "198.51.100.7"


def test_bgp_established_never_fires(promote):
    """The negative. A healthy peer polls established(6) forever."""
    promote("proactive.bgp.not_established")
    mon = P.ProactiveMonitor()
    fired = []
    for t in range(0, 3600, 60):
        fired += list(mon.observe_metric(
            tenant="t1", entity_id="wan-r1:198.51.100.7",
            metric="device_bgp_peer_state", value=6.0, ts=_at(t),
            observer_id="wan-r1", peer="198.51.100.7"))
    assert fired == []
    assert mon.open_watches() == 0


def test_bgp_flap_does_not_fire_but_a_persistent_run_after_it_does(promote):
    """THE DISCRIMINATOR.

    Three flaps, each shorter than the dwell, then one run that holds. Only
    the run fires. A check that fired on the flaps would be a second, noisier
    copy of `sig.ent.wan-edge.bgp-peer-flap`, which already explains them and
    has different first steps.
    """
    promote("proactive.bgp.not_established")
    mon = P.ProactiveMonitor()
    fired = []

    def poll(t, value):
        fired.extend(mon.observe_metric(
            tenant="t1", entity_id="wan-r1:198.51.100.7",
            metric="device_bgp_peer_state", value=value, ts=_at(t),
            observer_id="wan-r1", peer="198.51.100.7"))

    t = 0
    for _ in range(3):                     # down for 120s, up for 120s, x3
        for _ in range(2):
            poll(t, 3.0)
            t += 60
        for _ in range(2):
            poll(t, 6.0)
            t += 60
    assert fired == [], "a flap is not a persistent state and must not fire"

    start = t
    while t <= start + DWELL:              # now it stays down
        poll(t, 1.0)
        t += 60
    assert [e.phase for e in fired] == ["onset"]
    assert fired[0].onset_ts == _at(start), (
        "the onset must be the start of the run that HELD, not of the first "
        "flap — a dwell that survived a recovery would date the fault wrong")


def test_recovery_after_a_fire_emits_a_clear(promote):
    promote("proactive.bgp.not_established")
    mon = P.ProactiveMonitor()
    fired = []
    for t in range(0, int(DWELL) + 61, 60):
        fired += list(mon.observe_metric(
            tenant="t1", entity_id="wan-r1:198.51.100.7",
            metric="device_bgp_peer_state", value=3.0, ts=_at(t),
            observer_id="wan-r1", peer="198.51.100.7"))
    fired += list(mon.observe_metric(
        tenant="t1", entity_id="wan-r1:198.51.100.7",
        metric="device_bgp_peer_state", value=6.0, ts=_at(DWELL + 120),
        observer_id="wan-r1", peer="198.51.100.7"))
    assert [e.phase for e in fired] == ["onset", "clear"]
    assert fired[1].clear_ts == _at(DWELL + 120)
    # ...and the watch is armed again, not permanently spent.
    assert mon.open_watches() == 0


@pytest.mark.parametrize("check_id,kind,signal_kind", [
    ("proactive.ospf.adjacency_not_full", "ospf_adjacency_not_full",
     "ospf_adjacency_change"),
    ("proactive.isis.adjacency_not_up", "isis_adjacency_not_up",
     "isis_adjacency_change"),
    ("proactive.bgp.adjacency_down_persisting", "bgp_session_not_established",
     "bgp_adjacency_change"),
])
def test_adjacency_down_needs_the_sweep_to_fire(promote, check_id, kind,
                                                signal_kind):
    """The syslog/trap lane. A device logs "adjacency down" ONCE and then says
    nothing, so the dwell can only expire on the sweep — without it these
    checks would silently work for the polled lanes only."""
    promote(check_id)
    mon = P.ProactiveMonitor()
    assert mon.observe_signal(
        tenant="t1", entity_id="leaf-3", kind=signal_kind, state="down",
        ts=T0, observer_id="leaf-3", tokens=("leaf-3", "0000.0000.0009"),
        peer="0000.0000.0009") == ()
    # The FIRST sweep only arms the anti-skew gate (see `sweep`): a firing must
    # survive the dwell on the sweep's own clock, not only on the device's.
    assert mon.sweep(_at(10)) == ()
    assert mon.sweep(_at(DWELL - 1)) == (), "the dwell is not up yet"
    out = mon.sweep(_at(DWELL + 11))
    assert [e.kind for e in out] == [kind]
    assert out[0].onset_ts == T0, (
        "the reported onset is the DEVICE's claim — the gate decides whether "
        "to believe the duration, not what to call the start")
    assert out[0].entity_id == "leaf-3", (
        "the reported entity is the DEVICE; the peer is identity for the "
        "watch key and an attribute on the signal, never part of the entity id")
    # Idempotent: a second sweep does not re-fire the same held state.
    assert mon.sweep(_at(DWELL + 900)) == ()


@pytest.mark.parametrize("check_id,signal_kind", [
    ("proactive.ospf.adjacency_not_full", "ospf_adjacency_change"),
    ("proactive.isis.adjacency_not_up", "isis_adjacency_change"),
    ("proactive.bgp.adjacency_down_persisting", "bgp_adjacency_change"),
])
def test_adjacency_that_reforms_inside_the_dwell_never_fires(promote, check_id,
                                                             signal_kind):
    """The flap, on the signal lane. down → up inside the dwell, twice."""
    promote(check_id)
    mon = P.ProactiveMonitor()
    out = []
    for base in (0, 600):
        out += list(mon.observe_signal(
            tenant="t1", entity_id="leaf-3", kind=signal_kind, state="down",
            ts=_at(base), observer_id="leaf-3", peer="p1"))
        out += list(mon.sweep(_at(base + 60)))
        out += list(mon.observe_signal(
            tenant="t1", entity_id="leaf-3", kind=signal_kind, state="up",
            ts=_at(base + 120), observer_id="leaf-3", peer="p1"))
        out += list(mon.sweep(_at(base + 180)))
    assert out == []
    assert mon.open_watches() == 0


def test_an_unreadable_adjacency_state_is_dropped_not_guessed(promote):
    """`state: unknown` is what the producers emit when the vendor grammar
    could not read the transition. Treating it as UP would clear a real
    outage; treating it as DOWN would invent one. It is neither."""
    promote("proactive.ospf.adjacency_not_full")
    mon = P.ProactiveMonitor()
    assert mon.observe_signal(
        tenant="t1", entity_id="leaf-3", kind="ospf_adjacency_change",
        state="unknown", ts=T0, observer_id="leaf-3", peer="p1") == ()
    assert len(mon) == 0, "an unreadable state must not even open a watch"
    assert mon.sweep(_at(DWELL * 2)) == ()


def test_one_peer_dropping_does_not_clear_another_on_the_same_device(promote):
    """Adjacency identity is (device, peer). A shared watch would let peer B
    coming up clear peer A's standing outage."""
    promote("proactive.ospf.adjacency_not_full")
    mon = P.ProactiveMonitor()
    for peer in ("10.0.0.1", "10.0.0.2"):
        mon.observe_signal(tenant="t1", entity_id="leaf-3",
                           kind="ospf_adjacency_change", state="down",
                           ts=T0, observer_id="leaf-3", peer=peer)
    mon.observe_signal(tenant="t1", entity_id="leaf-3",
                       kind="ospf_adjacency_change", state="up",
                       ts=_at(30), observer_id="leaf-3", peer="10.0.0.2")
    assert mon.sweep(_at(60)) == ()          # arms the gate
    out = mon.sweep(_at(DWELL + 61))
    assert [e.peer for e in out] == ["10.0.0.1"]


@pytest.mark.parametrize("check_id,metric,floor", [
    ("proactive.device.cpu_sustained_high", "device_cpu_percent", P.CPU_HIGH_PCT),
    ("proactive.device.mem_sustained_high", "device_mem_percent", P.MEM_HIGH_PCT),
])
def test_sustained_resource_pressure_fires_and_a_spike_does_not(promote,
                                                                check_id,
                                                                metric, floor):
    """CPU/memory: the case the CUSUM episode detector structurally cannot
    reach. A single spike is a deviation and already has a producer; a WEEK at
    97 % is not a deviation at all, and is what a heartbeat check is for."""
    promote(check_id)
    mon = P.ProactiveMonitor()

    def poll(t, value):
        return list(mon.observe_metric(
            tenant="t1", entity_id="core-1", metric=metric, value=value,
            ts=_at(t), observer_id="core-1", tokens=("core-1",)))

    # A spike well past the floor, but short.
    out = poll(0, floor + 9) + poll(60, floor + 9) + poll(120, 40.0)
    assert out == [], "a spike is a deviation, not saturation"

    # Now hold it.
    fired = []
    t = 180
    while t <= 180 + DWELL:
        fired += poll(t, floor + 5)
        t += 60
    assert [e.phase for e in fired] == ["onset"]
    assert fired[0].kind == "device_resource_saturation"
    assert fired[0].metric_name == metric
    assert fired[0].value >= floor
    # Just BELOW the floor never fires, however long it is held.
    mon2 = P.ProactiveMonitor()
    quiet = []
    t = 0
    while t <= DWELL * 3:
        quiet += list(mon2.observe_metric(
            tenant="t1", entity_id="core-2", metric=metric,
            value=floor - 0.5, ts=_at(t), observer_id="core-2"))
        t += 60
    assert quiet == []


@pytest.mark.parametrize("check_id,kind,metric,good,bad", [
    ("proactive.ospf.nbr_state_not_full", "ospf_adjacency_not_full",
     "device_ospf_nbr_state", float(P.OSPF_NBR_STATE_FULL),
     float(P.OSPF_NBR_STATE_FULL) - 1.0),
    ("proactive.isis.adj_state_not_up", "isis_adjacency_not_up",
     "device_isis_adj_state", float(P.ISIS_ADJ_STATE_UP),
     float(P.ISIS_ADJ_STATE_UP) - 1.0),
])
def test_igp_metric_lane_fires_from_the_polled_state_without_a_recovery_line(
        promote, check_id, kind, metric, good, bad):
    """Tracker 222: the metric path the signal lane could not have.

    The point of the polled lane is that it answers "is it STILL bad?" from the
    CURRENT sample. So the fire must come from the samples themselves — no
    sweep is called anywhere in this test — and the healthy value must close
    the watch even though no recovery LINE was ever received."""
    promote(check_id)
    mon = P.ProactiveMonitor()

    def poll(t, value):
        return list(mon.observe_metric(
            tenant="t1", entity_id="spine1:0000.0000.0001", metric=metric,
            value=value, ts=_at(t), observer_id="spine1",
            tokens=("spine1",)))

    fired, t = [], 0
    while t <= DWELL:
        fired += poll(t, bad)
        t += 60
    assert [e.phase for e in fired] == ["onset"], \
        "the polled lane must fire on its own samples, with no sweep"
    assert fired[0].kind == kind
    assert fired[0].metric_name == metric
    assert fired[0].entity_id == "spine1:0000.0000.0001", (
        "the metric lane's entity is (device, neighbour) — the identity "
        "metric_identity builds for the `igp` family")

    # Healthy again: the watch closes off the SERIES, not off a recovery line.
    clear = poll(t + 60, good)
    assert [e.phase for e in clear] == ["clear"]
    assert mon.open_watches() == 0


@pytest.mark.parametrize("metric", ["device_ospf_nbr_state",
                                    "device_isis_adj_state"])
def test_igp_metric_lane_is_gated_on_the_series_actually_arriving(metric):
    """The presence gate, stated as a test. On an estate that does not poll the
    IGP adjacency series `observe_metric` is never called with it, so the check
    holds no state and cannot fire — the signal lane stays the only lane, which
    is exactly the pre-222 behaviour."""
    mon = P.ProactiveMonitor()
    assert metric in P.CHECKS_BY_TRIGGER, \
        "the metric-path check must be registered on its canonical metric name"
    assert len(mon) == 0 and mon.open_watches() == 0


def test_an_unwatched_metric_costs_one_dict_lookup_and_opens_no_watch():
    """The hot-path guarantee. handle_metric calls this for EVERY admitted
    sample, so a metric the plane does not watch must not allocate state."""
    mon = P.ProactiveMonitor()
    assert mon.observe_metric(
        tenant="t1", entity_id="core-1:Gi0/1", metric="device_if_in_octets",
        value=1e9, ts=T0, observer_id="core-1") == ()
    assert len(mon) == 0


# ── 2. the shadow contract ──────────────────────────────────────────────────

def test_every_check_ships_shadow():
    """The A8/A9b default. If this ever fails, a check was promoted — which is
    legitimate, and must be a DELIBERATE change that also does steps 2-5 of
    `proactive.PROMOTION` (register the kind, install the signature, re-freeze
    the golden), not a flag someone flipped while debugging."""
    live = [c.check_id for c in P.CHECKS if not c.shadow]
    assert live == [], (
        f"{live} are no longer shadow — promotion must also register the kind "
        f"in producers.EMITTED_KINDS, install the signature from "
        f"PROACTIVE_TEMPLATES, and re-freeze FIXTURE_GOLDEN")


def test_a_shadow_firing_is_counted_and_emits_nothing():
    """The contract in one test: the check FIRES (it is evaluated exactly like
    a live one and its hit is recorded) and yields no event, so no caller can
    turn it into a signal."""
    mon = P.ProactiveMonitor()
    out = []
    for t in range(0, int(DWELL) + 61, 60):
        out += list(mon.observe_metric(
            tenant="t1", entity_id="wan-r1:198.51.100.7",
            metric="device_bgp_peer_state", value=1.0, ts=_at(t),
            observer_id="wan-r1", peer="198.51.100.7"))
    assert out == []
    assert P.SHADOW_HITS["proactive.bgp.not_established"] == 1
    assert P.LIVE_HITS["proactive.bgp.not_established"] == 0
    # ...and the shadow hit is disjoint from the live counter, so the two
    # series can be read against each other on /metrics.
    assert sum(P.LIVE_HITS.values()) == 0


def test_the_shadow_gate_is_in_one_place():
    """Structural, not behavioural: every event any lane produces is built by
    `ProactiveMonitor._event`, so there is exactly ONE gate to audit and a new
    call site cannot open a hole in it."""
    src = P.ProactiveMonitor._event.__doc__ or ""
    assert "SHADOW GATE" in src
    assert P.ProactiveMonitor._advance.__code__.co_names.count("_event") >= 1
    assert "_event" in P.ProactiveMonitor.sweep.__code__.co_names


def test_shadow_kinds_are_not_declared_as_emitted():
    """A kind nothing emits must NOT be in `producers.EMITTED_KINDS`.

    The coverage gate reads that set as "the engine produces this", and a
    shadow check produces nothing. Declaring it early would make the kind an
    orphan producer forever and hide a real orphan behind it.
    """
    assert P.SHADOW_KINDS.isdisjoint(EMITTED_KINDS)


def test_every_check_has_a_recorded_promotion_condition():
    """A shadow check with no stated promotion condition is a check that will
    sit at shadow forever — the failure mode the tracker's own 263 KB of
    never-removed rows is a monument to."""
    assert set(P.PROMOTION) == {c.check_id for c in P.CHECKS}
    for check_id, why in P.PROMOTION.items():
        assert len(why.strip()) > 40, f"{check_id}: promotion condition is a stub"


# ── 3. the V1 goldens do not move ───────────────────────────────────────────

def test_the_builtin_catalog_is_untouched():
    """`Snapshot.content_hash()` pins `catalog_version`, so installing one of
    these templates moves `FIXTURE_GOLDEN`. They are authored and deliberately
    NOT installed; step 3 of PROMOTION installs the one being promoted, with
    the A9b-style byte-identity proof."""
    builtin_ids = {t["id"] for t in BUILTIN_TEMPLATES}
    proactive_ids = {t["id"] for t in P.PROACTIVE_TEMPLATES}
    assert builtin_ids.isdisjoint(proactive_ids)
    assert P.SHADOW_KINDS.isdisjoint(
        k for t in builtin_catalog().templates for c in t.requires
        for k in c.kinds())


def test_the_v1_replay_golden_is_byte_identical():
    """THE PIN. Imported from its owner rather than restated, so this test
    cannot pass against a stale copy of the number."""
    from test_bounded_object_paging import FIXTURE_GOLDEN, _fixture_snapshot
    assert _fixture_snapshot().content_hash() == FIXTURE_GOLDEN, (
        "the A4 plane moved the V1 replay golden — it must not: every check "
        "is shadow (emits nothing) and no template was installed")


def test_the_module_cannot_reclassify_a_v1_noise_line():
    """The tracker-220 hazard, checked structurally: this plane adds no parser
    rule and no syslog grammar, so it cannot change what any line classifies
    as. It only reads signals the parser ALREADY produced."""
    import parser_rules
    from producers import RULES
    # The rev this file pins is "the parser as the A4 plane found it, plus every
    # deliberate parser change since" — it is re-pinned only by the change that
    # moves it, never by an A4 edit. 2026-09-06-218: the linkDown/linkUp
    # ifAdminStatus/ifOperStatus enrichment (tracker 218), which adds no syslog
    # grammar and cannot reclassify a V1 noise line.
    assert parser_rules.PARSER_REV == "2026-09-06-218", (
        "the parser revision moved — an A4 change must not touch the parser")
    assert not any(r.rule_id.startswith("proactive") for r in RULES)


# ── 4. promotion is one line ────────────────────────────────────────────────

def test_a_promoted_check_builds_a_well_formed_signal(promote):
    """The emission path production would take, exercised now so promotion is
    the flag flip the docstring promises."""
    live = promote("proactive.bgp.not_established")
    mon = P.ProactiveMonitor()
    fired = []
    for t in range(0, int(DWELL) + 61, 60):
        fired += list(mon.observe_metric(
            tenant="t1", entity_id="wan-r1:198.51.100.7",
            metric="device_bgp_peer_state", value=2.0, ts=_at(t),
            observer_id="wan-r1", tokens=("wan-r1", "198.51.100.7"),
            peer="198.51.100.7"))
    sig = P.proactive_signal(fired[0])
    assert sig.kind == "bgp_session_not_established"
    assert sig.tenant_id == "t1"
    assert sig.entity_id == "wan-r1:198.51.100.7"
    assert sig.source is Source.METRIC
    assert sig.modality_class is ModalityClass.DEVICE_TELEMETRY
    assert sig.severity is Severity.HIGH
    assert sig.observer.collection_path == "proactive_check"
    assert sig.attrs["check_id"] == live.check_id
    assert sig.attrs["held_s"] >= DWELL
    assert sig.attrs["operator_phrase"].startswith("This BGP peer")
    assert sig.entity_tokens == ("wan-r1", "198.51.100.7")
    # Identity is content-bearing and idempotent under redelivery (tracker
    # 198): the same held state rebuilt is the same signal.
    assert P.proactive_signal(fired[0]).signal_id == sig.signal_id
    # ...and it round-trips onto the wire.
    row = sig.to_ch_row()
    assert row["kind"] == "bgp_session_not_established"


def test_a_promoted_signal_grounds_on_the_device_never_on_the_check(promote):
    """#99 R2: a grounding token that is not ONE entity welds unrelated
    incidents into one object. The check id and the metric name are labels,
    not co-location keys."""
    promote("proactive.device.cpu_sustained_high")
    mon = P.ProactiveMonitor()
    fired = []
    t = 0
    while t <= DWELL:
        fired += list(mon.observe_metric(
            tenant="t1", entity_id="core-1", metric="device_cpu_percent",
            value=99.0, ts=_at(t), observer_id="core-1", tokens=("core-1",)))
        t += 60
    sig = P.proactive_signal(fired[0])
    assert sig.entity_tokens == ("core-1",)
    assert "proactive.device.cpu_sustained_high" not in sig.entity_tokens
    assert "device_cpu_percent" not in sig.entity_tokens


def test_a_tenant_wide_token_dead_letters(promote):
    """The guard is at the Signal model, and this plane must not be able to
    smuggle past it."""
    promote("proactive.device.cpu_sustained_high")
    mon = P.ProactiveMonitor()
    fired = []
    t = 0
    while t <= DWELL:
        fired += list(mon.observe_metric(
            tenant="t1", entity_id="core-1", metric="device_cpu_percent",
            value=99.0, ts=_at(t), observer_id="core-1",
            tokens=("tenant:acme",)))
        t += 60
    with pytest.raises(DeadLetter):
        P.proactive_signal(fired[0])


def test_the_authored_signatures_load_beside_the_builtins():
    """Schema validation + the catalog's own lints (unique ids, resolvable
    `else_prefer`, no self-preference) against a REAL Catalog. A template that
    would not load is not a signature — it is a comment."""
    merged = load_catalog(list(BUILTIN_TEMPLATES) + list(P.PROACTIVE_TEMPLATES))
    ids = {t.id for t in merged.templates}
    for t in P.PROACTIVE_TEMPLATES:
        assert t["id"] in ids
    by_id = {t.id: t for t in merged.templates}
    for t in P.PROACTIVE_TEMPLATES:
        tpl = by_id[t["id"]]
        assert tpl.operator_phrase.strip(), f"{tpl.id}: no operator phrase"
        assert tpl.verdict.first_steps, f"{tpl.id}: no first steps"
        # The phrase is what an operator READS. It must say what the engine
        # believes, not name a check id or a metric.
        assert "proactive." not in tpl.operator_phrase
        assert len(tpl.operator_phrase) > 80


def test_every_shadow_kind_has_a_signature_waiting_for_it():
    """A promoted kind with no consumer is a dead template in the other
    direction — evidence nothing reasons over. Each check's kind is required
    by at least one authored signature."""
    required = {k for t in P.PROACTIVE_TEMPLATES
                for c in t["requires"] for k in c["kind"].split("|")}
    assert P.SHADOW_KINDS <= required


def test_promotion_closes_the_coverage_gap(monkeypatch):
    """The two halves of promotion are steps 2 and 3 and they must land
    TOGETHER: registering the kind without the signature makes an orphan
    producer, and installing the signature without the kind makes a dead
    template. With both, every new kind classifies fully_connected."""
    merged = load_catalog(list(BUILTIN_TEMPLATES) + list(P.PROACTIVE_TEMPLATES))
    # Before: signature installed, kind unregistered → dead template.
    assert classify_kind("bgp_session_not_established", merged) == "dead_template"
    monkeypatch.setattr(coverage, "EMITTED_KINDS",
                        coverage.EMITTED_KINDS | P.SHADOW_KINDS)
    for kind in sorted(P.SHADOW_KINDS):
        assert classify_kind(kind, merged) == "fully_connected", kind


# ── 5. bounded, tenant-scoped, order-safe ───────────────────────────────────

def test_two_tenants_never_share_a_dwell_timer():
    """§3a. Two tenants can each own a device called `core-1`; a shared watch
    would let one tenant's recovery clear the other's outage, and would stamp
    a firing with the wrong tenant."""
    mon = P.ProactiveMonitor()
    for tenant in ("t1", "t2"):
        mon.observe_metric(tenant=tenant, entity_id="core-1",
                           metric="device_cpu_percent", value=99.0, ts=T0,
                           observer_id="core-1")
    assert len(mon) == 2
    # t2 recovers; t1's watch is untouched.
    mon.observe_metric(tenant="t2", entity_id="core-1",
                       metric="device_cpu_percent", value=10.0, ts=_at(60),
                       observer_id="core-1")
    assert mon.open_watches() == 1
    keys = [k for k in mon._watches if mon._watches[k].since is not None]
    assert [k[0] for k in keys] == ["t1"]


def test_the_watch_store_is_lru_bounded():
    """§9: the key carries a device id and a peer address, both off the wire.
    An unbounded store here is an OOM with an attacker-controlled trigger."""
    mon = P.ProactiveMonitor(max_watches=50)
    for i in range(500):
        mon.observe_metric(tenant="t1", entity_id=f"dev-{i}",
                           metric="device_cpu_percent", value=99.0, ts=T0,
                           observer_id=f"dev-{i}")
    assert len(mon) == 50
    assert mon.evicted == 450, "evictions are COUNTED, never silent"


def test_a_stale_watch_expires_instead_of_firing(promote):
    """A device that stops being polled must not fire. "We stopped hearing
    about it" is not evidence that it is still bad — it is evidence that we
    stopped looking.

    Silence is counted in SWEEPS, not in device timestamps (see `sweep`): the
    first sweep records the activity it can see, and the watch expires on a
    later sweep that saw none.
    """
    promote("proactive.device.cpu_sustained_high")
    mon = P.ProactiveMonitor(stale_after_s=600)
    mon.observe_metric(tenant="t1", entity_id="core-1",
                       metric="device_cpu_percent", value=99.0, ts=T0,
                       observer_id="core-1")
    assert mon.sweep(T0) == ()               # sees the observation, arms
    assert len(mon) == 1
    assert mon.sweep(_at(1200)) == (), (
        "the dwell WOULD be satisfied, but the device has been silent for "
        "twice the staleness bound — a fire here would report a state nobody "
        "has observed for twenty minutes")
    assert len(mon) == 0


def test_a_stale_sweep_never_prevents_a_fire_already_earned(promote):
    """The staleness bound must be strictly larger than the dwell, or a real
    persistent fault would expire before it could fire."""
    promote("proactive.device.cpu_sustained_high")
    assert P.STALE_AFTER_S > P.DEFAULT_DWELL_S
    mon = P.ProactiveMonitor()
    mon.observe_metric(tenant="t1", entity_id="core-1",
                       metric="device_cpu_percent", value=99.0, ts=T0,
                       observer_id="core-1")
    assert mon.sweep(_at(10)) == ()          # arms the gate
    out = mon.sweep(_at(DWELL + 11))
    assert [e.check_id for e in out] == ["proactive.device.cpu_sustained_high"]


def test_an_out_of_order_sample_cannot_rewind_a_dwell(promote):
    """Stream time only moves forward here. A late sample that reopened or
    shortened a closed run would make the plane non-deterministic under
    replay."""
    promote("proactive.device.cpu_sustained_high")
    mon = P.ProactiveMonitor()
    fired = []
    t = 0
    while t <= DWELL:
        fired += list(mon.observe_metric(
            tenant="t1", entity_id="core-1", metric="device_cpu_percent",
            value=99.0, ts=_at(t), observer_id="core-1"))
        t += 60
    assert len(fired) == 1
    # A healthy sample stamped BEFORE the fire arrives late: ignored.
    assert mon.observe_metric(
        tenant="t1", entity_id="core-1", metric="device_cpu_percent",
        value=5.0, ts=_at(30), observer_id="core-1") == ()
    assert mon.open_watches() == 1


def test_reset_does_not_fabricate_a_dwell_it_did_not_observe():
    """The restart contract. Dwell state is in-memory on purpose: a process
    that came up thirty seconds ago has not WITNESSED five minutes of anything,
    and persisting the timer would let it claim it had."""
    mon = P.ProactiveMonitor()
    mon.observe_metric(tenant="t1", entity_id="core-1",
                       metric="device_cpu_percent", value=99.0, ts=T0,
                       observer_id="core-1")
    mon.reset()
    assert len(mon) == 0
    assert mon.sweep(_at(DWELL * 10)) == ()


def test_a_device_with_a_backwards_clock_cannot_fabricate_a_dwell(promote):
    """THE ANTI-SKEW GATE.

    A device running an hour behind logs "adjacency down" stamped an hour ago.
    A naive `now - since` fires on the first sweep and invents a five-minute
    outage out of a bad NTP config — so the sweep also requires the run to have
    survived the dwell on ITS OWN clock, from the first sweep that saw it.
    """
    promote("proactive.ospf.adjacency_not_full")
    mon = P.ProactiveMonitor()
    skewed = T0 - timedelta(hours=1)
    mon.observe_signal(tenant="t1", entity_id="leaf-9",
                       kind="ospf_adjacency_change", state="down",
                       ts=skewed, observer_id="leaf-9", peer="10.0.0.9")
    assert mon.sweep(T0) == (), "the first sweep arms; it must not fire"
    assert mon.sweep(_at(60)) == (), (
        "one minute of OBSERVED persistence is not five, whatever the device's "
        "clock claims")
    out = mon.sweep(_at(DWELL + 1))
    assert [e.check_id for e in out] == ["proactive.ospf.adjacency_not_full"]
    # The reported duration is the OBSERVED one, not the device's hour.
    assert out[0].held_s == pytest.approx(DWELL + 1, abs=2)
    # ...while the onset stays the device's own claim, which is what an
    # operator needs to line this up against the rest of the timeline.
    assert out[0].onset_ts == skewed


def test_a_run_that_recovers_re_arms_the_skew_gate(promote):
    """A closed run must not leave the gate armed, or the NEXT run would fire
    on the strength of the previous one's sighting."""
    promote("proactive.ospf.adjacency_not_full")
    mon = P.ProactiveMonitor()
    mon.observe_signal(tenant="t1", entity_id="leaf-9",
                       kind="ospf_adjacency_change", state="down",
                       ts=T0, observer_id="leaf-9", peer="p")
    assert mon.sweep(_at(10)) == ()
    mon.observe_signal(tenant="t1", entity_id="leaf-9",
                       kind="ospf_adjacency_change", state="up",
                       ts=_at(20), observer_id="leaf-9", peer="p")
    mon.observe_signal(tenant="t1", entity_id="leaf-9",
                       kind="ospf_adjacency_change", state="down",
                       ts=_at(30), observer_id="leaf-9", peer="p")
    assert mon.sweep(_at(40)) == (), "the new run arms from scratch"
    assert mon.sweep(_at(30 + DWELL)) == (), (
        "the new run has been observed for less than the dwell — the previous "
        "run's sighting must not count towards it")
    out = mon.sweep(_at(45 + DWELL))
    assert [e.check_id for e in out] == ["proactive.ospf.adjacency_not_full"]
    assert out[0].onset_ts == _at(30)


def test_stats_expose_the_table_next_to_the_counters():
    stats = P.proactive_stats()
    assert stats["checks"] == len(P.CHECKS)
    assert {m["check_id"] for m in stats["checks_meta"]} == set(P.CHECK_BY_ID)
    assert all(m["shadow"] for m in stats["checks_meta"])
    assert set(stats["shadow_hits"]) == {c.check_id for c in P.CHECKS if c.shadow}
