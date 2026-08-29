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


def test_all_four_cause_kinds_are_instantiated(scen):
    kinds = {i["cause_kind"] for i in scen.incidents}
    assert kinds == {"upstream_link_failure", "local_link_fault",
                     "bgp_peer_flap", "ospf_adjacency_flap"}
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
    for i, e in enumerate(scen.events):
        ev = json.loads(_line(e, i))
        sig = producers.syslog_control_signal(ev, "t1", now)
        assert sig is not None, f"scenario line never promotes: {ev}"
        assert sig.kind == e.symptom, f"{sig.kind} != {e.symptom}: {ev}"
        assert sig.entity_id == e.entity, f"{sig.entity_id} != {e.entity}"
        if e.state:
            assert sig.attrs.get("state") == e.state, ev


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
