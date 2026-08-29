"""The `t-storm-2.5k` scenario profile (tracker 183, 2026-08-29).

THE GAP THIS CLOSES. The ratified `t-nominal-2.5k` workload pins every device's
state for life — `_syslog_event` picks `state = "down" if seq % 2 == 0 else
"up"` while `_burst_lanes` picks `dev_i = ln["seq"] % 2500`, and 2,500 is even,
so a device's parity never changes. Measured on the real run
(`docs/scale/P3_AGGREGATION_OPPORTUNITY_2026-08-29.md` §4, two independent
sources agreeing to ±1 event): 900,001 raw events, 44,280 promoted signals,
**0 state transitions, 0 recoveries**, one source and one vantage per identity,
no identity repeating inside 120 s, and no ground-truth cause label anywhere.
Nothing in owner-memo §17/§18 — recovery, contradiction, corroboration,
independent vantage, blast-radius expansion — can be exercised against it, and
`scale-rca-latency.py` has to say in its own docstring that T4 correctness
"CANNOT be scored from persisted data".

What these tests hold:
  * the storm profile keeps t-nominal-2.5k's THROUGHPUT to the event (the same
    90 × 10,000 chunk plan) — completion/TTUR stay comparable — while
    t-nominal-2.5k itself is left carrying no scenario at all;
  * the scenario is a PURE FUNCTION of (profile, seed, device list): same seed
    ⇒ same digest, same incidents, same event stream, byte for byte on the wire
    once the wall-clock timestamp is set aside; a different seed ⇒ different;
  * the injected fleet still sums to the plan, with scenario + background
    accounted separately;
  * every dynamic the profile exists for is PRESENT and non-zero;
  * every scenario line classifies through the REAL correlation classifier to
    the kind, entity and state the ground truth claims;
  * ground-truth.json carries the documented schema;
  * background noise never shares a cause entity with an incident — device
    pools are disjoint, and the fault interface / peer ranges sit outside
    anything the background mix can emit.

Run:  python3 -m pytest tests/test_storm_scenario_profile.py -v
"""

from __future__ import annotations

import argparse
import importlib.util
import itertools
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src" / "correlation"))

import producers  # path set above


def _load_harness():
    path = ROOT / "scripts" / "scale-miniladder.py"
    spec = importlib.util.spec_from_file_location("scale_miniladder_storm", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    before = os.environ.get("PATH", "")
    sys.modules["scale_miniladder_storm"] = mod
    spec.loader.exec_module(mod)
    assert os.environ.get("PATH", "") == before
    return mod


ml = _load_harness()

PROFILE = "t-storm-2.5k"
DEVICES = 2500
WINDOW_S = 900


def _devices(n: int = DEVICES) -> list[str]:
    return [f"mlx-storm-{i:05d}" for i in range(n)]


def _scenario(seed: int = ml.SCENARIO_SEED_DEFAULT, devices: int = DEVICES,
              window_s: int = WINDOW_S):
    return ml.StormScenario(ml.STORM_SCENARIO_2K5, _devices(devices), seed=seed,
                            window_s=window_s, chunk_secs=ml.BURST_CHUNK_SECS,
                            profile=PROFILE, runid="testrun")


@pytest.fixture(scope="module")
def scen():
    return _scenario()


# ── the throughput floor is untouched ───────────────────────────────────────

def test_storm_carries_the_same_ratified_throughput_as_t_nominal():
    """Same lanes, same window ⇒ the SAME chunk plan, event for event. The
    profile changes the composition of the stream, never its volume — the
    entire reason completion/TTUR numbers stay comparable across the two."""
    storm = ml.WORKLOAD_PROFILES[PROFILE]
    nominal = ml.WORKLOAD_PROFILES["t-nominal-2.5k"]
    assert storm["lanes"] == nominal["lanes"] == [("fleet", 1.0, "production",
                                                   1000.0)]
    assert storm["burst_minutes"] == nominal["burst_minutes"] == 15
    assert storm["workload_class"] == "T_STORM_2K5"
    assert storm["scenario"] == "storm-2.5k"


def test_t_nominal_is_left_alone():
    """The A/B baseline (memo §23 replays the EXACT 2.5K storm): no T-nominal
    profile may grow a scenario, or every recorded 2.5K number changes meaning."""
    for name in ("t-nominal", "t-p95", "t-nominal-2.5k", "s1-2.5k", "s4-chatter",
                 "soak-72h", "legacy"):
        assert "scenario" not in ml.WORKLOAD_PROFILES[name], (
            f"profile {name!r} grew a scenario — it is no longer the workload "
            f"its recorded numbers were measured on")


def test_only_scenario_profiles_build_a_scenario():
    for name, prof in ml.WORKLOAD_PROFILES.items():
        h = _harness(Path("."), None, None, profile=name, minutes=1)
        built = h._build_scenario()
        if prof.get("scenario"):
            assert built is not None and built.spec["name"] == prof["scenario"]
        else:
            assert built is None, f"{name!r} built a scenario it never declared"


# ── determinism: a pure function of (profile, seed, device list) ────────────

def test_same_seed_plans_a_byte_identical_scenario():
    a, b = _scenario(), _scenario()
    assert a.digest() == b.digest()
    assert a.incidents == b.incidents
    assert a.events == b.events
    assert a.noise_pool == b.noise_pool
    assert a.template_counts == b.template_counts
    assert (json.dumps(a.ground_truth(900_000), sort_keys=True) ==
            json.dumps(b.ground_truth(900_000), sort_keys=True))


def test_a_different_seed_plans_a_different_scenario():
    a, b = _scenario(), _scenario(seed=ml.SCENARIO_SEED_DEFAULT + 1)
    assert a.digest() != b.digest()
    assert len(a.incidents) == len(b.incidents)      # same SHAPE, new draw


def test_the_plan_does_not_depend_on_the_run_id_or_the_clock(scen):
    other = ml.StormScenario(ml.STORM_SCENARIO_2K5, _devices(),
                             seed=ml.SCENARIO_SEED_DEFAULT, window_s=WINDOW_S,
                             chunk_secs=ml.BURST_CHUNK_SECS, profile=PROFILE,
                             runid="a-completely-different-run")
    assert other.digest() == scen.digest()


def test_seeding_never_touches_the_global_random_stream():
    """`_rng` must build its OWN Random. A `random.seed()` inside the planner
    would make every other seeded thing in the process reproducible-by-accident
    and this scenario dependent on call order."""
    import random
    random.seed(1234)
    before = [random.random() for _ in range(3)]
    random.seed(1234)
    _scenario(devices=500)
    after = [random.random() for _ in range(3)]
    assert before == after


# ── the dynamics the profile exists for ─────────────────────────────────────

def test_every_dynamic_is_present(scen):
    """Each of these is measured as ZERO on t-nominal-2.5k. A profile that
    leaves any of them at zero has not fixed the gap it was built for."""
    d = scen.dynamics()
    assert d["incidents"] > 0
    assert d["state_transitions"] > 0, "still a state-pinned stream"
    assert d["recoveries"] > 0, "no recovery transitions — memo §17's P0 class"
    assert d["repeats_within_60s"] > 0, "no repeated confirmation (memo §18)"
    assert d["identities_repeating_within_60s"] > 0
    assert d["multi_vantage_incidents"] > 0, "no corroboration structure"
    assert d["max_vantages_on_one_cause"] >= 2
    assert d["contradictions"] > 0, "no contradictory healthy observations"
    assert d["blast_radius_expansions"] > 0, "blast radius never expands"
    assert d["incidents_with_recovery"] > 0
    assert d["flap_cycles_total"] > d["incidents"], "no multi-cycle flapping"
    assert d["scenario_devices"] > 0 and d["noise_devices"] > 0


def test_no_scenario_device_is_left_silent_at_the_ratified_window(scen):
    """A scenario device with no event is a guaranteed accounting FAIL forty
    minutes later — `corr_signals covers N/M burst devices` — because the
    background pool never speaks for it. Every template's onset window must
    stay bounded well inside the 900 s window."""
    assert scen.silent_devices() == []
    assert scen.dynamics()["silent_scenario_devices"] == 0


def test_a_window_too_short_for_the_scenario_is_reported_not_hidden(
        tmp_path, monkeypatch, capsys):
    """16.1: the harness may still run, but it must SAY that per-device
    coverage is about to come up short, and by how much."""
    short = _scenario(window_s=120)
    assert short.silent_devices(), "pick a shorter window for this pin"
    _ok, _ev, _notes, _stack = _run_burst(tmp_path, monkeypatch, minutes=2)
    cap = capsys.readouterr()          # ONE read: it consumes the buffers
    out = cap.out + cap.err
    assert "scenario device(s) got NO event" in out, out[-500:]
    assert "mis-sized for this window" in out


def test_all_cause_kinds_are_instantiated(scen):
    kinds = {i["cause_kind"] for i in scen.incidents}
    assert kinds == {"upstream_link_failure", "local_link_fault",
                     "bgp_peer_flap", "ospf_adjacency_flap",
                     "enterprise_outage"}
    for tpl, counts in scen.template_counts.items():
        assert counts["instances_built"] == counts["instances_planned"], (
            f"{tpl} was truncated by the device budget at the RATIFIED size")
        assert counts["truncated_by_device_budget"] is False


def test_flap_recovery_cycles_really_cycle(scen):
    """down → up → down on ONE identity, three times over: the class the
    ratified nominal workload contains exactly zero of."""
    ospf = [i for i in scen.incidents
            if i["cause_kind"] == "ospf_adjacency_flap"]
    assert ospf
    assert all(i["flap_cycles"] == 3 for i in ospf)
    dev = ospf[0]["cause_entity"]["device"]
    states = [e.state for e in scen.events
              if e.device == dev and e.symptom == "ospf_adjacency_change"]
    assert states.count("up") >= 2 and states.count("down") >= 3
    # the sequence must actually alternate at least twice
    changes = sum(1 for a, b in itertools.pairwise(states) if a != b)
    assert changes >= 4, f"adjacency never really flapped: {states}"


def test_repeats_land_inside_the_60s_window(scen):
    """Memo §18's 'repeated confirmation' only counts inside 60 s. Every event
    tagged `repeat` must sit within SCENARIO_REPEAT_MAX_OFFSET_S of an ANCHOR
    on the same identity (onset / expansion / flap), and the bound must leave
    room for the 10 s chunk clock to quantize injection — a repeat planned at
    +40 s can be emitted a chunk later than one planned at +0 s and must STILL
    be inside the window it is counted in."""
    assert (ml.SCENARIO_REPEAT_MAX_OFFSET_S + 3.0 + ml.BURST_CHUNK_SECS
            < ml.SCENARIO_REPEAT_WINDOW_S), (
        "a repeat could be emitted outside the 60 s window it is counted in")
    anchors: dict = {}
    for e in scen.events:
        if e.role in ("onset", "expansion", "flap"):
            anchors.setdefault((e.entity, e.symptom), []).append(e.t)
    repeats = [e for e in scen.events if e.role == "repeat"]
    assert repeats
    bound = ml.SCENARIO_REPEAT_MAX_OFFSET_S + 3.0
    for e in repeats:
        near = [t for t in anchors.get((e.entity, e.symptom), [])
                if 0.0 <= e.t - t <= bound]
        assert near, (
            f"repeat {e.symptom} on {e.entity} at t={e.t} has no anchor within "
            f"{bound}s — it would not count as a repeated confirmation")


def test_repeat_offsets_are_bounded_by_construction(scen):
    tpl = {"repeats": (1, 6)}
    for i in range(200):
        offs = ml.StormScenario._repeat_offsets(scen, tpl, scen._rng(f"o{i}"))
        assert offs == sorted(offs)
        assert offs[-1] <= 3.0 + ml.SCENARIO_REPEAT_MAX_OFFSET_S


def test_multi_vantage_incidents_are_multi_DEVICE_on_one_cause(scen):
    """Syslog stamps the observer as the emitting device, so two vantages on one
    entity_id is not expressible. What must be present is several INDEPENDENT
    devices reporting the same cause — a shared peer address in the engine's
    entity_tokens."""
    multi = [i for i in scen.incidents if len(i["vantages"]) >= 2]
    assert multi
    inc = next(i for i in multi if i["cause_kind"] == "bgp_peer_flap")
    peer = inc["cause_entity"]["peer"]
    observers = {e.device for e in scen.events
                 if e.incident_id == inc["incident_id"] and peer in e.message}
    assert len(observers) >= 2
    assert observers <= set(inc["vantages"])


def test_contradictions_are_healthy_observations_during_an_open_fault(scen):
    contra = [e for e in scen.events if e.role == "contradiction"]
    assert contra
    by_inc = {i["incident_id"]: i for i in scen.incidents}
    for e in contra:
        inc = by_inc[e.incident_id]
        assert e.state == "up", "a contradiction must be a HEALTHY observation"
        assert e.t > inc["onset_ts"]
        if inc["recovery_ts"] is not None:
            assert e.t < inc["recovery_ts"], (
                "an 'up' after recovery is not a contradiction, it is the truth")


def test_blast_radius_expands_in_waves(scen):
    ups = [i for i in scen.incidents
           if i["cause_kind"] == "upstream_link_failure"]
    assert ups
    for inc in ups:
        waves = inc["blast_radius_waves"]
        assert len(waves) >= 2, "no expansion — the whole radius arrived at once"
        assert [w["at"] for w in waves] == sorted(w["at"] for w in waves)
        seen: set = set()
        for w in waves:
            assert not (set(w["devices"]) & seen), "a wave re-listed a device"
            seen |= set(w["devices"])
        assert seen | {inc["cause_entity"]["device"]} == set(inc["blast_radius"])


# ── the lines are what the ground truth says they are ───────────────────────

def test_scenario_lines_classify_as_planned(scen):
    """Against the REAL classifier, not a copy of it: every planned line must
    promote, and to the kind / entity_id / state the ground truth claims. A
    scenario whose lines the engine reads differently is ground truth that
    lies."""
    now = datetime.now(timezone.utc)
    unpromotable = 0
    for i, e in enumerate(scen.events):
        ev = json.loads(_line(e, i))
        sig = producers.syslog_control_signal(ev, "t1", now)
        if not e.symptom:
            # A line the ground truth declares UNPROMOTABLE must really not
            # promote. The dangerous direction is the other one: a symptom
            # marked invisible that quietly does classify would inflate every
            # promoted-signal number with events no scorer is counting.
            assert sig is None, (
                f"{e.etype!r} is declared not_promoted but classified as "
                f"{sig.kind!r}: {ev}")
            unpromotable += 1
            continue
        assert sig is not None, f"scenario line never promotes: {ev}"
        assert sig.kind == e.symptom, f"{sig.kind} != {e.symptom}: {ev}"
        assert sig.entity_id == e.entity, f"{sig.entity_id} != {e.entity}"
        if e.state:
            assert sig.attrs.get("state") == e.state, ev
    assert unpromotable > 0, (
        "no unpromotable lines at all — the enterprise chain is supposed to "
        "emit the vendor-standard BGP churn messages the engine cannot see")


def test_the_incident_marker_cannot_change_the_parse(scen):
    """The `[mlx seq N inc I0001]` marker is a trace aid. It must carry no
    interface token, no IP and no state word, or it would silently re-key the
    signal it was meant to annotate."""
    now = datetime.now(timezone.utc)
    for e in scen.events[:400]:
        bare = json.loads(_line(e, 7, marker=False))
        with_marker = json.loads(_line(e, 7, marker=True))
        a = producers.syslog_control_signal(bare, "t1", now)
        b = producers.syslog_control_signal(with_marker, "t1", now)
        assert a is not None and b is not None
        assert (a.kind, a.entity_id, a.severity, a.entity_tokens) == \
               (b.kind, b.entity_id, b.severity, b.entity_tokens)
        # `text` is the raw line and necessarily differs; everything the engine
        # DERIVES from it (state, interface, peer, tag) must not.
        assert {k: v for k, v in a.attrs.items() if k != "text"} == \
               {k: v for k, v in b.attrs.items() if k != "text"}


def _line(e, seq: int, marker: bool = True) -> str:
    msg = e.message + (f" [mlx seq {seq} inc {e.incident_id}]" if marker else "")
    return json.dumps({
        "hostname": e.device, "appname": e.appname, "message": msg,
        "severity": e.severity,
        "timestamp": datetime.now(timezone.utc)
                     .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"})


# ── noise never shares a cause entity with an incident ──────────────────────

def test_noise_pool_is_disjoint_from_every_scenario_device(scen):
    scenario_devices = {e.device for e in scen.events}
    assert scenario_devices
    assert not (scenario_devices & set(scen.noise_pool))
    for inc in scen.incidents:
        assert not (set(inc["blast_radius"]) & set(scen.noise_pool))
        assert inc["cause_entity"]["device"] not in set(scen.noise_pool)
    assert len(scenario_devices) + len(scen.noise_pool) == DEVICES


def test_background_lines_never_carry_a_cause_entity(scen):
    """The disjointness clause, checked on GENERATED background rather than
    argued from the pools: no cause token appears in a background line, and no
    background signal shares an identity with a scenario signal."""
    causes = scen.cause_entities()
    assert causes
    gen = _generator()
    pool = scen.noise_pool
    now = datetime.now(timezone.utc)
    scenario_ids = {(e.entity, e.symptom) for e in scen.events}
    noise_ids: set = set()
    for seq in range(60_000):
        dev_i = seq % len(pool)
        line = gen._syslog_event(pool[dev_i], seq, mix_name="production",
                                 mix_seq=dev_i + 31 * (seq // len(pool)))
        for token in causes:
            assert token not in line, f"background line carries cause {token}"
        sig = producers.syslog_control_signal(json.loads(line), "t1", now)
        if sig is not None:
            noise_ids.add((sig.entity_id, sig.kind))
            assert not (set(sig.entity_tokens) & causes)
    assert noise_ids, "the background produced no signals at all"
    assert not (noise_ids & scenario_ids)


def test_fault_names_sit_outside_every_range_the_background_can_emit(scen):
    """Belt and braces on the pool disjointness: interfaces 48..95 and peer host
    octets 200+ are unreachable for the background mix (`if_n = seq % 48`, host
    octets {1,2,9,50}), so the two populations could not collide even if the
    pools were ever allowed to overlap."""
    for inc in scen.incidents:
        ifname = inc["cause_entity"].get("interface")
        if ifname:
            n = int(ifname.rsplit("/", 1)[1])
            assert ml.SCENARIO_IF_BASE <= n < ml.SCENARIO_IF_BASE + ml.SCENARIO_IF_SPAN
        peer = inc["cause_entity"].get("peer")
        if peer:
            assert int(peer.rsplit(".", 1)[1]) >= ml.SCENARIO_PEER_HOST_BASE
    for e in scen.events:
        for octet in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", e.message):
            assert int(octet.rsplit(".", 1)[1]) >= ml.SCENARIO_PEER_HOST_BASE


def test_cause_entities_are_unique_across_incidents(scen):
    """A shared cause address between two incidents would weld them into one —
    a FALSE MERGE the scorer could never distinguish from an engine defect."""
    ids = [i["cause_entity"]["entity_id"] for i in scen.incidents]
    assert len(ids) == len(set(ids))
    peers = [i["cause_entity"]["peer"] for i in scen.incidents
             if i["cause_entity"].get("peer")]
    assert len(peers) == len(set(peers))


# ── ground truth on disk ────────────────────────────────────────────────────

def test_ground_truth_schema(scen):
    gt = scen.ground_truth(planned_total=900_000)
    assert gt["schema"] == ml.GROUND_TRUTH_SCHEMA == "correlix.scale.ground-truth/1"
    for key in ("profile", "scenario", "seed", "runid", "window_s", "chunk_secs",
                "planned_total_events", "digest", "devices", "templates",
                "counts", "incidents", "contract", "description"):
        assert key in gt, f"ground truth lost {key!r}"
    assert gt["seed"] == ml.SCENARIO_SEED_DEFAULT
    assert gt["window_s"] == WINDOW_S and gt["chunk_secs"] == ml.BURST_CHUNK_SECS
    assert gt["planned_total_events"] == 900_000
    assert len(gt["digest"]) == 64
    assert gt["devices"] == {"total": DEVICES,
                             "scenario": DEVICES - len(scen.noise_pool),
                             "noise_pool": len(scen.noise_pool),
                             "budget_share": ml.SCENARIO_DEVICE_BUDGET}
    assert 0 < gt["counts"]["scenario_event_share_of_plan"] < 0.05, (
        "the scenario has stopped being a structural change to a nominal "
        "stream and become a different workload")
    for inc in gt["incidents"]:
        for key in ("incident_id", "cause_kind", "cause_entity", "onset_ts",
                    "recovery_ts", "blast_radius", "blast_radius_waves",
                    "vantages", "contradictions", "symptom_kinds",
                    "expected_owner_class", "expected_seam_class",
                    "flap_cycles"):
            assert key in inc, f"{inc.get('incident_id')} lost {key!r}"
        ce = inc["cause_entity"]
        assert ce["entity_type"] in ("interface", "device", "peer")
        assert ce["entity_id"]
        assert 0 <= inc["onset_ts"] < WINDOW_S
        assert inc["recovery_ts"] is None or inc["recovery_ts"] > inc["onset_ts"]
        assert inc["blast_radius"] and inc["vantages"]
        assert json.dumps(inc)          # the whole record must be serializable


def test_ground_truth_is_written_into_the_run_dir(tmp_path, monkeypatch):
    ok, ev, _notes, _stack = _run_burst(tmp_path, monkeypatch, minutes=2)
    assert ok
    path = tmp_path / ml.GROUND_TRUTH_FILE
    assert path.exists(), "no ground truth — T4 correctness stays unscoreable"
    gt = json.loads(path.read_text(encoding="utf-8"))
    assert gt["schema"] == ml.GROUND_TRUTH_SCHEMA
    assert gt["digest"] == ev["scenario"]["digest"] == ev["ground_truth"]["digest"]
    assert gt["runid"] == "testrun"
    assert ev["ground_truth"]["path"] == str(path)


# ── the burst: composition changes, the fleet contract does not ─────────────

class FakeClock:
    def __init__(self) -> None:
        self.t = 0.0

    def monotonic(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        assert seconds > 0
        self.t += seconds


class FakeStack:
    def __init__(self, clock: FakeClock, chunk_cost_s: float = 6.0) -> None:
        self.clock = clock
        self.chunk_cost_s = chunk_cost_s
        self.batches: list[list[str]] = []

    def produce(self, topic, lines, key=None):
        self.batches.append(list(lines))
        self.clock.t += self.chunk_cost_s
        return True, ""

    @property
    def lines(self) -> list[str]:
        return [ln for b in self.batches for ln in b]


def _generator(profile: str = PROFILE):
    cls = ml.Harness
    g = cls.__new__(cls)
    g.args = argparse.Namespace(event_mix="production", profile=profile)
    g._mix = cls._mix_table(cls.EVENT_MIX_REALISTIC)
    g._tables = cls._composed_tables()
    return g


def _harness(tmp_path, clock, stack, profile=PROFILE, minutes=15,
             devices=DEVICES, seed=ml.SCENARIO_SEED_DEFAULT,
             cheap_background=True):
    cls = ml.Harness
    h = cls.__new__(cls)
    h.args = argparse.Namespace(
        burst_minutes=minutes, eps=1000, profile=profile, event_mix="single",
        producer_key="none", burst_window_factor=ml.BURST_WINDOW_MAX_FACTOR,
        scenario_seed=seed)
    h.profile = ml.WORKLOAD_PROFILES[profile]
    h._mix = cls._mix_table(cls.EVENT_MIX_REALISTIC)
    h._tables = cls._composed_tables()
    h.created_ids = _devices(devices)
    h.producer_key = None
    h.injected_total = 0
    h.produce_failures = []
    h.phases = []
    h.burst_seconds = 0.0
    h.run_dir = str(tmp_path)
    h.stack = stack
    h.runid = "testrun"
    h.scenario = None
    if cheap_background:
        # The scenario lines stay REAL (they are what is under test); the
        # background payload shape is pinned by test_workload_profiles.py, so
        # keep these runs about composition and accounting.
        h._syslog_event = lambda dev, seq, mix_name=None, mix_seq=None: (
            f"bg|{dev}|{seq}|{mix_seq}")
    return h


def _run_burst(tmp_path, monkeypatch, minutes=15, devices=DEVICES,
               seed=ml.SCENARIO_SEED_DEFAULT, profile=PROFILE):
    os.makedirs(tmp_path, exist_ok=True)
    clock = FakeClock()
    stack = FakeStack(clock)
    h = _harness(tmp_path, clock, stack, profile=profile, minutes=minutes,
                 devices=devices, seed=seed)
    monkeypatch.setattr(ml, "time", clock)
    ok = h._burst_lanes({})
    entry = h.phases[-1]
    return ok, entry["evidence"], entry["notes"], stack


def test_the_ratified_fleet_is_injected_whole(tmp_path, monkeypatch):
    ok, ev, notes, stack = _run_burst(tmp_path, monkeypatch)
    assert ok, notes
    assert ev["fleet_planned"] == ev["fleet_injected"] == 900_000
    assert ev["fleet_shortfall"] == 0
    assert ev["workload_class"] == "T_STORM_2K5"
    assert len(stack.lines) == 900_000
    sc = ev["scenario"]
    assert sc["injected"] == sc["planned"] > 0
    assert sc["shortfall"] == 0
    assert sc["planned"] + sc["background_injected"] == 900_000
    # the two halves are distinguishable on the wire
    scenario_lines = [ln for ln in stack.lines if " inc I" in ln]
    assert len(scenario_lines) == sc["planned"]


def test_scenario_events_land_in_the_chunk_their_plan_time_falls_in(
        tmp_path, monkeypatch):
    ok, _ev, notes, stack = _run_burst(tmp_path, monkeypatch, minutes=3)
    assert ok, notes
    scen = ml.StormScenario(ml.STORM_SCENARIO_2K5, _devices(), seed=ml.SCENARIO_SEED_DEFAULT,
                            window_s=180, chunk_secs=ml.BURST_CHUNK_SECS,
                            profile=PROFILE, runid="testrun")
    for i, batch in enumerate(stack.batches):
        got = sum(1 for ln in batch if " inc I" in ln)
        assert got == len(scen.buckets[i]), f"chunk {i}: {got} != plan"
        assert len(batch) == 10_000, "the ratified quota changed"


def test_two_runs_of_one_seed_emit_the_identical_stream(tmp_path, monkeypatch):
    """Byte-identical apart from the wall-clock `timestamp` field, which every
    line in this harness has always carried (`_syslog_event` stamps `now()`)."""
    a = _run_burst(tmp_path / "a", monkeypatch, minutes=3)[3]
    b = _run_burst(tmp_path / "b", monkeypatch, minutes=3)[3]
    strip = re.compile(r',\s*"timestamp":\s*"[^"]*"')
    la = [strip.sub("", ln) for ln in a.lines]
    lb = [strip.sub("", ln) for ln in b.lines]
    scenario_lines = [ln for ln in la if " inc I" in ln]
    assert scenario_lines, "no scenario lines in the stream at all"
    assert not any("timestamp" in ln for ln in scenario_lines), (
        "the timestamp was not actually stripped — this comparison would be "
        "vacuous the moment two runs happened to share a millisecond")
    assert la == lb


def test_a_different_seed_emits_a_different_stream(tmp_path, monkeypatch):
    a = _run_burst(tmp_path / "a", monkeypatch, minutes=3)[3]
    b = _run_burst(tmp_path / "b", monkeypatch, minutes=3,
                   seed=ml.SCENARIO_SEED_DEFAULT + 1)[3]
    strip = re.compile(r',\s*"timestamp":\s*"[^"]*"')
    assert [strip.sub("", x) for x in a.lines] != [strip.sub("", x) for x in b.lines]


def test_background_is_drawn_only_from_the_noise_pool(tmp_path, monkeypatch):
    ok, _ev, notes, stack = _run_burst(tmp_path, monkeypatch, minutes=3)
    assert ok, notes
    scen = ml.StormScenario(ml.STORM_SCENARIO_2K5, _devices(), seed=ml.SCENARIO_SEED_DEFAULT,
                            window_s=180, chunk_secs=ml.BURST_CHUNK_SECS,
                            profile=PROFILE, runid="testrun")
    noise = set(scen.noise_pool)
    seen = {ln.split("|")[1] for ln in stack.lines if ln.startswith("bg|")}
    assert seen and seen <= noise, (
        f"{len(seen - noise)} background devices are scenario devices — a "
        f"background line could carry an incident's cause entity")


def test_every_device_still_receives_events(tmp_path, monkeypatch):
    """Accounting FAILS the run when corr_signals does not cover every burst
    device (`entities != len(created_ids)`), so no device may be silent: the
    scenario devices get incident lines, everyone else gets background."""
    ok, _ev, notes, stack = _run_burst(tmp_path, monkeypatch)
    assert ok, notes
    scen = _scenario()
    bg = {ln.split("|")[1] for ln in stack.lines if ln.startswith("bg|")}
    sc_devices = {e.device for e in scen.events}
    assert bg | sc_devices == set(_devices())


def test_an_oversized_scenario_fails_the_burst_before_injecting(
        tmp_path, monkeypatch):
    """A scenario that plans more events than a chunk's ratified quota would
    force the loop either to overshoot the fleet or to silently drop planned
    ground-truth events. It must refuse, loudly, having produced nothing."""
    clock = FakeClock()
    stack = FakeStack(clock)
    h = _harness(tmp_path, clock, stack, minutes=15)
    monkeypatch.setattr(ml, "time", clock)
    real = h._build_scenario

    def bloated():
        scen = real()
        scen.buckets[0] = scen.events * 200         # >> the 10,000 quota
        return scen

    h._build_scenario = bloated
    ok = h._burst_lanes({})
    notes = h.phases[-1]["notes"]
    assert not ok
    assert "more events than the ratified chunk quota" in notes
    assert stack.batches == [], "it injected before refusing"


def test_a_scenario_on_a_multi_lane_profile_is_refused(tmp_path, monkeypatch):
    """A scenario owns the whole fleet's composition; splitting it across lanes
    would make 'which pool is background' ambiguous."""
    clock = FakeClock()
    stack = FakeStack(clock)
    h = _harness(tmp_path, clock, stack, minutes=15)
    h.profile = dict(ml.WORKLOAD_PROFILES[PROFILE])
    h.profile["lanes"] = [("storm", 0.5, "storm", 500.0),
                          ("bg", 0.5, "production", 500.0)]
    monkeypatch.setattr(ml, "time", clock)
    assert not h._burst_lanes({})
    assert "cannot be split across" in h.phases[-1]["notes"]


GREEDY_SPEC = {
    "name": "greedy", "description": "",
    "templates": ({"cause_kind": "local_link_fault",
                   "instances_per_1k_devices": 1000.0,
                   "devices_per_instance": 1,
                   "onset_window": (10.0, 60.0),
                   "recovery_after_s": None, "repeats": (1, 1),
                   "reassert_every_s": 0.0,
                   "expected_owner_class": "x", "expected_seam_class": "y"},),
}


@pytest.mark.parametrize("n", [10, 100, 999, 2500])
def test_the_device_budget_always_leaves_a_background_pool(n):
    """The disjointness clause rests on a non-empty noise pool, and the budget
    is what guarantees one even for a scenario that asks for every device."""
    assert ml.SCENARIO_DEVICE_BUDGET < 1.0
    scen = ml.StormScenario(GREEDY_SPEC, _devices(n), seed=1, window_s=120,
                            chunk_secs=10)
    assert scen.noise_pool
    assert len(scen.noise_pool) >= n - int(n * ml.SCENARIO_DEVICE_BUDGET)


def test_a_scenario_that_claims_every_device_is_refused(monkeypatch):
    """No background pool left ⇒ the chunk plan could not be filled from a
    disjoint pool, so disjointness would silently stop being true. Unreachable
    at the ratified budget, which is exactly why the guard is pinned: widening
    the budget to 1.0 must FAIL, not quietly mix incident devices into the
    background."""
    monkeypatch.setattr(ml, "SCENARIO_DEVICE_BUDGET", 1.0)
    with pytest.raises(ValueError, match="no background pool"):
        ml.StormScenario(GREEDY_SPEC, _devices(10), seed=1, window_s=120,
                         chunk_secs=10)


def test_an_unknown_template_is_a_defect_not_a_skip():
    with pytest.raises(ValueError, match="no builder"):
        ml.StormScenario(
            {"name": "bogus", "description": "",
             "templates": ({"cause_kind": "meteor_strike",
                            "instances_per_1k_devices": 1.0,
                            "devices_per_instance": 1,
                            "onset_window": (10.0, 60.0),
                            "recovery_after_s": None, "repeats": (1, 1),
                            "reassert_every_s": 0.0,
                            "expected_owner_class": "x",
                            "expected_seam_class": "y"},)},
            _devices(100), seed=1, window_s=120, chunk_secs=10)


# ── CLI surface ─────────────────────────────────────────────────────────────

def test_profile_and_seed_are_selectable_from_the_command_line():
    args = ml.parse_args(["--profile", PROFILE])
    assert args.profile == PROFILE
    assert args.scenario_seed == ml.SCENARIO_SEED_DEFAULT
    args = ml.parse_args(["--profile", PROFILE, "--scenario-seed", "7"])
    assert args.scenario_seed == 7


def test_the_ratified_seed_is_pinned():
    """Changing the default seed silently changes the workload every t-storm
    number was measured on. It is a ratified constant, like the rates."""
    assert ml.SCENARIO_SEED_DEFAULT == 20260829


# ── the enterprise outage chain (2026-08-29) ────────────────────────────────
#
# One causally ordered chain per SITE — uplink down → OSPF adjacency loss → a
# second core port flapping → eBGP session flap → route churn + update burst →
# STP reconvergence and MAC re-homing → recovery, or a hard outage. The
# vocabulary and the phase bands live in `scripts/enterprise_outage_chain.py`
# and are SHARED with the network digital twin's `_tpl_enterprise_outage`, so
# these tests pin the SHARED definition, not a mini-ladder-local copy of it.

import enterprise_outage_chain as chain  # ROOT/scripts is on sys.path

CHAIN_PHASES = ("uplink_down", "ospf_neighbor_down", "ospf_interface_flap",
                "bgp_session_flap", "route_churn", "access_layer")


def _enterprise(scen) -> list[dict]:
    return [i for i in scen.incidents if i["cause_kind"] == "enterprise_outage"]


def test_the_chain_vocabulary_comes_from_the_shared_module(scen):
    """Every enterprise line must be one the SHARED module built. Two harnesses
    quietly emitting different messages for one symptom is the whole failure
    this module exists to prevent, so the mnemonic set is pinned to it."""
    shared = {row.exemplar[0] for row in chain.CHAIN_SIGNATURES
              if row.exemplar is not None}
    emitted = {e.appname for e in scen.events if e.etype}
    assert emitted, "the enterprise template emitted nothing"
    assert emitted <= shared, (
        f"mnemonic(s) {sorted(emitted - shared)} are not in the shared chain "
        f"vocabulary — the two harnesses have started to drift")
    for e in scen.events:
        if e.etype:
            assert e.etype in chain.CHAIN_BY_TYPE, e.etype


def test_the_enterprise_template_builds_fifteen_full_sites(scen):
    """6 sites per 1,000 devices ⇒ 15 at the ratified 2,500, each a full
    40-device site (2 core/dist + 38 access). A site truncated by the device
    budget would ship ground truth for a blast radius the stream never had."""
    counts = scen.template_counts["enterprise_outage"]
    assert counts["instances_planned"] == counts["instances_built"] == 15
    assert counts["devices_per_instance"] == 40
    assert counts["truncated_by_device_budget"] is False
    incs = _enterprise(scen)
    assert len(incs) == 15
    for inc in incs:
        assert len(inc["blast_radius"]) == 40
        assert inc["site"]["access_devices"] == 38
        assert inc["cause_entity"]["entity_type"] == "interface"
        assert inc["cause_entity"]["device"] == inc["site"]["core"]


def test_every_phase_of_the_chain_fires_in_causal_order(scen):
    """Offsets are seeded AND jittered ±20 %, so ordering can never be an
    accident of the draw: each phase is clamped after the phase that causes
    it. If a future edit removes a clamp, some seed makes this red."""
    incs = _enterprise(scen)
    assert incs
    for inc in incs:
        tl = {ph["phase"]: ph for ph in inc["timeline"]}
        assert set(CHAIN_PHASES) <= set(tl), (
            f"{inc['incident_id']}: missing phase(s) "
            f"{sorted(set(CHAIN_PHASES) - set(tl))}")
        ats = [tl[p]["at"] for p in CHAIN_PHASES]
        assert ats == sorted(ats), (
            f"{inc['incident_id']}: phases fired out of causal order: "
            f"{list(zip(CHAIN_PHASES, ats))}")
        assert tl["uplink_down"]["at"] == inc["onset_ts"]
        # every phase offset is measured from the cause, not from the run
        for name in CHAIN_PHASES:
            assert tl[name]["offset_s"] == round(
                tl[name]["at"] - inc["onset_ts"], 1)


def test_the_chain_really_flaps_and_really_churns(scen):
    for inc in _enterprise(scen):
        tl = {ph["phase"]: ph for ph in inc["timeline"]}
        cycles = tl["ospf_interface_flap"]["cycles"]
        assert chain.FLAP_CYCLE_RANGE[0] <= len(cycles) <= chain.FLAP_CYCLE_RANGE[1]
        for cyc in cycles:
            assert cyc["up_at"] > cyc["down_at"], "a flap that never came back"
        downs = [c["down_at"] for c in cycles]
        assert downs == sorted(downs)
        bgp = tl["bgp_session_flap"]["transitions"]
        assert [x["state"] for x in bgp] == ["down", "up", "down"], (
            "the transit session must flap Down → Up → Down, not just drop")
        assert [x["at"] for x in bgp] == sorted(x["at"] for x in bgp)
        churn = tl["route_churn"]
        lo, hi = chain.CHURN_EPS_RANGE
        assert lo <= churn["rate_eps"] <= hi
        assert churn["events"] > 0 and churn["update_burst_events"] >= 3
        acc = tl["access_layer"]
        assert acc["tcn_devices"] == 38, (
            "a TCN floods the WHOLE STP domain — every switch in the site logs "
            "it, which is also what keeps every site device audible")
        assert 1 <= acc["stp_port_devices"] <= 38
        assert 1 <= acc["mac_move_devices"] <= 38


def test_recovery_follows_every_fault_of_its_own_incident(scen):
    """A recovery that lands before a fault it is supposed to end is ground
    truth that contradicts its own stream. The builder clamps recovery to at
    least 5 s after the incident's LAST fault event; this checks the events."""
    by_inc: dict = {}
    for e in scen.events:
        by_inc.setdefault(e.incident_id, []).append(e)
    recovered = hard = 0
    for inc in _enterprise(scen):
        evs = by_inc[inc["incident_id"]]
        rec_ts = inc["recovery_ts"]
        if rec_ts is None:
            hard += 1
            assert not [e for e in evs if e.role == "recovery"], (
                "a hard outage emitted recovery events")
            continue
        recovered += 1
        faults = [e.t for e in evs if e.role != "recovery"]
        assert max(faults) < rec_ts, (
            f"{inc['incident_id']}: a fault at t={max(faults)} lands at or "
            f"after recovery_ts={rec_ts}")
        recs = [e for e in evs if e.role == "recovery"]
        assert recs, "a recovered incident with no recovery events"
        assert min(e.t for e in recs) >= rec_ts
        # …and the recovery really restores the cause identity
        cause_entity = inc["cause_entity"]["entity_id"]
        ups = [e for e in recs if e.entity == cause_entity and e.state == "up"]
        assert ups, f"{inc['incident_id']}: the cause interface never came up"
    assert recovered and hard, (
        "the ratified plan must contain BOTH recovered sites and hard outages "
        "— a scenario where everything recovers is as unrealistic as one where "
        "nothing does")


def test_the_access_layer_repeats_and_re_homes_inside_the_window(scen):
    """The site symptoms must show repeated confirmation on ONE identity and
    real MAC movement — the classes t-nominal-2.5k contains zero of."""
    d = scen.dynamics()
    assert d["chain_events_by_type"]["stp_topology_change"] > 0
    assert d["chain_events_by_type"]["stp_port_block"] > 0
    assert d["chain_events_by_type"]["mac_move"] > 0
    assert d["chain_events_by_type"]["ospf_neighbor_down"] > 0
    assert d["chain_events_by_type"]["bgp_session_up"] > 0
    macs = {e.message.split("Host ")[1].split(" ")[0]
            for e in scen.events if e.etype == "mac_move"}
    total = sum(1 for e in scen.events if e.etype == "mac_move")
    # A MAC is a GLOBAL entity token: reuse across sites would weld them into
    # one false object. Every distinct (site, device) gets its own address.
    per_identity = {(e.device, e.message.split("Host ")[1].split(" ")[0])
                    for e in scen.events if e.etype == "mac_move"}
    assert len(macs) == len(per_identity), (
        "a MAC address is shared between two devices — that welds their "
        "incidents together through entity_tokens")
    assert total > len(macs), "no MAC move was ever re-reported"


# ── parser coverage: what the engine could actually SEE ─────────────────────

def _classify(appname: str, message: str, severity: str):
    now = datetime.now(timezone.utc)
    return producers.syslog_control_signal({
        "hostname": "cov-dev-1", "appname": appname, "message": message,
        "severity": severity,
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
    }, "t1", now)


def _check_coverage(rows) -> None:
    """Assert every row of a coverage table against the REAL producer.

    Factored out so the mutant test below can run the IDENTICAL check on a
    corrupted table and prove the assertions have teeth.
    """
    for row in rows:
        if row.exemplar is None:               # composite: check its parts
            assert row.components, f"{row.event_type}: composite with no parts"
            for part in row.components:
                assert part in chain.CHAIN_BY_TYPE, part
            assert row.coverage == (
                chain.PROMOTED
                if all(chain.CHAIN_BY_TYPE[c].coverage == chain.PROMOTED
                       for c in row.components) else chain.NOT_PROMOTED)
            continue
        sig = _classify(*row.exemplar)
        if row.coverage == chain.NOT_PROMOTED:
            assert sig is None, (
                f"{row.event_type}: declared not_promoted but the classifier "
                f"yields {sig.kind!r} — the backlog item has been CLOSED and "
                f"this table is now lying about it")
            continue
        assert sig is not None, (
            f"{row.event_type}: declared promoted but the classifier drops "
            f"{row.exemplar[1]!r}")
        assert sig.kind == row.kind, f"{row.event_type}: {sig.kind} != {row.kind}"
        assert (sig.attrs.get("state") or "") == row.state, (
            f"{row.event_type}: state {sig.attrs.get('state')!r} != "
            f"{row.state!r}")
        ifname = (chain.SAMPLE_IF if chain.SAMPLE_IF in row.exemplar[1]
                  else chain.SAMPLE_IF_B)
        assert sig.entity_id == chain.entity_of(
            row.event_type, "cov-dev-1", ifname), (
            f"{row.event_type}: entity {sig.entity_id!r} is not the "
            f"{row.entity_shape!r} shape the table claims")


def test_the_parser_coverage_table_is_pinned_against_the_real_parser():
    """Every requested outage symptom → the message the chain emits → what
    `producers.syslog_control_signal` ACTUALLY does with it. A table that
    drifts from the parser is ground truth that lies about what the engine was
    given, so it is checked against the producer itself, never restated."""
    _check_coverage(chain.CHAIN_SIGNATURES)
    cov = chain.parser_coverage()
    assert set(cov) == {r.event_type for r in chain.CHAIN_SIGNATURES}
    assert set(cov.values()) <= {chain.PROMOTED, chain.NOT_PROMOTED}
    # the symptoms this engine cannot see — a product backlog item each
    assert set(chain.not_promoted_types()) == {
        "bgp_route_churn", "bgp_router_update_burst"}, (
        "the not-promoted list changed — that is either an engine improvement "
        "worth recording or a regression; either way it is not silent")


def test_a_mutant_message_for_a_promoted_type_is_caught():
    """Proof the check above has teeth: replace one PROMOTED row's message with
    an unrecognized mnemonic and the very same checker must go red. Without
    this, a coverage table that silently stopped matching the parser would
    still pass."""
    mutated = []
    seen = False
    for row in chain.CHAIN_SIGNATURES:
        if (not seen and row.coverage == chain.PROMOTED
                and row.exemplar is not None):
            seen = True
            mutated.append(row._replace(
                exemplar=("WIDGET-6-NOTHING",
                          "%WIDGET-6-NOTHING: nothing to see here", "info")))
            continue
        mutated.append(row)
    assert seen, "no promoted row to mutate — the table is empty?"
    with pytest.raises(AssertionError, match="declared promoted"):
        _check_coverage(mutated)


def test_a_mutant_that_makes_an_invisible_symptom_classify_is_caught():
    """The other direction: a `not_promoted` row whose message DOES classify
    would silently add signals no scorer counts."""
    mutated = [row._replace(exemplar=chain.link(chain.SAMPLE_IF, "down"))
               if row.coverage == chain.NOT_PROMOTED else row
               for row in chain.CHAIN_SIGNATURES]
    with pytest.raises(AssertionError, match="declared not_promoted"):
        _check_coverage(mutated)


def test_ground_truth_carries_the_coverage_table_and_the_backlog(scen):
    gt = scen.ground_truth(planned_total=900_000)
    assert gt["parser_coverage"] == chain.parser_coverage()
    assert gt["not_promoted"] == list(chain.not_promoted_types())
    detail = gt["parser_coverage_detail"]
    for etype, verdict in gt["parser_coverage"].items():
        assert detail[etype]["coverage"] == verdict
        assert detail[etype]["note"] or verdict == chain.PROMOTED
    assert [p["phase"] for p in gt["phase_timeline"]] == list(
        chain.PHASE_ORDER)
    assert gt["counts"]["unpromotable_events"] > 0
    assert (gt["counts"]["promoted_events"]
            + gt["counts"]["unpromotable_events"]
            == gt["counts"]["scenario_events"])


def test_unpromotable_lines_never_count_as_engine_visible_dynamics(scen):
    """A dropped line contributes no signal, so it may not appear as an
    identity, a transition or a repeat — counting it would report dynamics the
    engine cannot possibly observe."""
    d = scen.dynamics()
    entities = {(e.entity, e.symptom) for e in scen.events if e.symptom}
    assert d["identities"] == len(entities)
    assert all(e.entity == "" for e in scen.events if not e.symptom), (
        "an unpromotable line claims an entity_id the engine never creates")


# ── the ratified throughput bound ───────────────────────────────────────────

def test_the_scenario_stays_inside_the_ratified_two_percent(scen):
    """The storm profile is a STRUCTURAL change to a nominal stream, not a
    different workload: past ~2 % of the raw fleet its completion/TTUR numbers
    stop being comparable with t-nominal-2.5k and the A/B is dishonest."""
    d = scen.dynamics()
    share = d["scenario_events"] / 900_000
    assert share <= 0.02, (
        f"the scenario is {share:.3%} of the ratified 900,000-event fleet — "
        f"over the 2 % bound; trim the route-churn budget "
        f"(chain.CHURN_MAX_EVENTS_SCALE), not the causal structure")
    assert share > 0.005, "the scenario has become too small to measure"


def test_the_chain_never_overruns_a_chunk_quota(scen):
    """`_burst_lanes` REFUSES a scenario that plans more events into a 10 s
    chunk than the ratified quota. The route-churn phase is the only one dense
    enough to get near it, so the margin is pinned here rather than discovered
    in a run."""
    quota = 10_000
    worst = max(len(b) for b in scen.buckets)
    assert worst < quota, f"chunk plans {worst} events of a {quota} quota"
    assert worst < quota // 2, (
        f"worst chunk is {worst}/{quota} — the churn phase has grown close "
        f"enough to the quota that a seed change could fail the burst")


def test_no_site_device_is_left_silent(scen):
    """Every one of a site's 40 devices must speak, or accounting fails the run
    forty minutes later on per-device corr_signals coverage. The TCN flood is
    what guarantees it for the access layer."""
    spoke = {e.device for e in scen.events}
    for inc in _enterprise(scen):
        missing = sorted(set(inc["blast_radius"]) - spoke)
        assert not missing, (
            f"{inc['incident_id']}: {len(missing)} site device(s) emitted "
            f"nothing at all (e.g. {missing[:3]})")


def test_no_site_cause_entity_is_shared_with_the_noise_pool(scen):
    """Restated for the site template specifically: a background line carrying
    a site's cause token would make its blast radius unfalsifiable."""
    noise = set(scen.noise_pool)
    for inc in _enterprise(scen):
        assert not (set(inc["blast_radius"]) & noise)
        assert inc["cause_entity"]["device"] not in noise
        assert inc["site"]["distribution"] not in noise
    # peers are unique across ALL incidents, sites included
    peers = [i["cause_entity"]["peer"] for i in scen.incidents
             if i["cause_entity"].get("peer")]
    assert len(peers) == len(set(peers))


# ── the twin-scorable projection of the same ground truth ───────────────────

def test_twin_records_carry_the_shape_the_twin_scorer_reads(scen):
    """`scripts/lab/twin/scorer.py` scores a mini-ladder run unchanged — that
    is the point of writing the same incidents in its record shape. These are
    the exact keys `score_story` dereferences."""
    recs = scen.twin_records()
    assert len(recs) == len(scen.incidents)
    ids = {r["story_id"] for r in recs}
    assert ids == {i["incident_id"] for i in scen.incidents}
    for rec in recs:
        for key in ("story_id", "template", "affected", "entities",
                    "extra_entities", "expect", "labels"):
            assert key in rec, f"twin record lost {key!r}"
        assert isinstance(rec["affected"].get("devices"), list)
        assert rec["entities"] == rec["affected"]["devices"]
        rca = rec["expect"]["rca"]
        assert rca["verdict_tier_at_least"] in ("suspected", "confirmed")
        # affected_includes is prefixed with state["prefix"] by the scorer, and
        # the mini-ladder writes prefix "" — so the name must be the full id
        assert rca["affected_includes"][0] in rec["entities"]
        assert json.dumps(rec)                    # must be serializable
    state = scen.twin_state()
    assert state["prefix"] == "", (
        "mini-ladder device ids are already fully qualified; a non-empty "
        "prefix would make every scorer lookup miss")
    assert state["runid"] == "testrun"
    assert state["device_tenants"] == {}


def test_twin_records_carry_the_labels_the_miniladder_schema_has_no_room_for(
        scen):
    by_id = {r["story_id"]: r for r in scen.twin_records()}
    for inc in _enterprise(scen):
        lab = by_id[inc["incident_id"]]["labels"]
        assert lab["cause_entity"] == inc["cause_entity"]
        assert lab["onset_offset_s"] == inc["onset_ts"]
        assert lab["recovery_offset_s"] == inc["recovery_ts"]
        assert lab["blast_radius"] == inc["blast_radius"]
        assert lab["parser_coverage"] == chain.parser_coverage()
        assert [p["phase"] for p in lab["timeline"]][:len(CHAIN_PHASES)] == \
            list(CHAIN_PHASES)


def test_the_run_dir_gets_both_ground_truths(tmp_path, monkeypatch):
    """`ground-truth.json` stays the mini-ladder's own contract; the same
    incidents also land in the twin's `ground_truth.jsonl` + `state.json`, so
    `twin.py score --runid <id> --run-root data/miniladder` needs no second
    scorer and no schema migration."""
    ok, ev, notes, _stack = _run_burst(tmp_path, monkeypatch, minutes=2)
    assert ok, notes
    jl = tmp_path / ml.TWIN_GROUND_TRUTH_FILE
    st = tmp_path / ml.TWIN_STATE_FILE
    assert (tmp_path / ml.GROUND_TRUTH_FILE).exists()
    assert jl.exists() and st.exists()
    recs = [json.loads(ln) for ln in jl.read_text(encoding="utf-8").splitlines()
            if ln.strip()]
    assert recs and len(recs) == ev["ground_truth"]["twin_records"]
    assert all("story_id" in r and "expect" in r for r in recs)
    state = json.loads(st.read_text(encoding="utf-8"))
    assert state["prefix"] == "" and state["runid"] == "testrun"
    assert ev["ground_truth"]["not_promoted"] == list(
        chain.not_promoted_types())
    assert "twin.py score" in ev["ground_truth"]["twin_score_cmd"]
