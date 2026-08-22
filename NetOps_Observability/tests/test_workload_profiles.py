"""Ratified workload profiles in the G2 mini-ladder (gate spec §5/§6).

Pins, against the REAL correlation classifier where promotion is claimed:
  * production mix promotion ≈ the ratified 5 % plan; storm mix ≈ 30 %;
    noise arms NEVER classify (each one individually)
  * the decorrelation property — with a noise-bearing mix, EVERY device in a
    lane pool still emits classifying events (the latent seq%N vs seq%L
    correlation would starve fixed devices forever)
  * profile overrides: T/S profiles set eps/duration/mix; legacy touches
    nothing; --devices never overridden
  * lane math: S1 pools and rates compose to the ratified ~4,000 raw fleet;
    the S2 ramp is 40→3,640 over 3,600 s then holds; planned totals integrate
    the schedule

Run:  python3 -m pytest tests/test_workload_profiles.py -v
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
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
    spec = importlib.util.spec_from_file_location("scale_miniladder_prof", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    before = os.environ.get("PATH", "")
    sys.modules["scale_miniladder_prof"] = mod
    spec.loader.exec_module(mod)
    assert os.environ.get("PATH", "") == before
    return mod


ml = _load_harness()


def _gen(profile="legacy", event_mix="realistic", devices=1000):
    cls = ml.Harness
    inst = cls.__new__(cls)
    inst.args = argparse.Namespace(event_mix=event_mix, profile=profile)
    inst._mix = cls._mix_table(cls.EVENT_MIX_REALISTIC)
    inst._tables = cls._composed_tables()
    inst.profile = ml.WORKLOAD_PROFILES[profile]
    inst.created_ids = [f"mlx-prof-{i:05d}" for i in range(devices)]
    return inst


def _classifies(gen, device, seq, mix_name, mix_seq):
    ev = json.loads(gen._syslog_event(device, seq, mix_name=mix_name, mix_seq=mix_seq))
    return producers.syslog_control_signal(ev, "t1", datetime.now(timezone.utc)) is not None


# ── promotion fractions, against the real classifier ─────────────────────────

def test_production_mix_promotion_is_the_ratified_plan():
    gen = _gen()
    n = 4000
    promoted = sum(_classifies(gen, "mlx-prof-00001", i, "production", i)
                   for i in range(n))
    assert promoted / n == pytest.approx(0.05, abs=0.005), (
        f"production promotion {promoted/n:.3f} != ratified ~5 %")


def test_storm_mix_promotion_is_the_ratified_storm_share():
    gen = _gen()
    n = 3000
    promoted = sum(_classifies(gen, "mlx-prof-00001", i, "storm", i)
                   for i in range(n))
    assert promoted / n == pytest.approx(1 / 3, abs=0.02), (
        f"storm promotion {promoted/n:.3f} != ratified ~30 %")


def test_every_noise_arm_never_classifies():
    """Arm-by-arm, not in aggregate: one classifying noise arm silently
    shifts the promotion ratio for every profile that dilutes with it."""
    now = datetime.now(timezone.utc)
    for weight, appname, template, sev in ml.Harness.EVENT_MIX_NOISE:
        msg = template.format(oct2=7, oct3=11)
        ev = {"hostname": "mlx-prof-00001", "appname": appname,
              "message": msg + " [mlx seq 1]", "severity": sev,
              "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"}
        sig = producers.syslog_control_signal(ev, "t1", now)
        assert sig is None, f"noise arm {appname!r} classified as {sig and sig.kind}"


# ── decorrelation: no device may be starved of classifying events ────────────

@pytest.mark.parametrize("pool_size", [100, 900, 995, 1000])
def test_every_device_in_a_lane_emits_classifying_events(pool_size):
    """The latent modulus-correlation defect: device = seq % P and mix =
    seq % L share factors, so without decorrelation some devices NEVER
    classify. The lane loop uses mix_seq = dev_i + 31·round (31 coprime to
    every table length), so each device cycles the whole table and reaches
    the classifying block within ~len(table)/31 ≈ 65 rounds. Verified for
    the real pool sizes (S1 storm=100, bg=900; S4 bg=995; 1K single-lane)
    at an 80-round budget — well under any real run's rounds (T-nominal:
    ~360; S4: ~1,400)."""
    gen = _gen()
    rounds = 80
    hits = [0] * pool_size
    for seq in range(pool_size * rounds):
        dev_i = seq % pool_size
        mix_seq = dev_i + 31 * (seq // pool_size)
        if _classifies(gen, f"mlx-prof-{dev_i:05d}", seq, "production", mix_seq):
            hits[dev_i] += 1
    starved = [i for i, h in enumerate(hits) if h == 0]
    assert not starved, (
        f"{len(starved)} devices emitted ZERO classifying events over "
        f"{rounds} rounds — the modulus correlation is back")


def test_mutation_correlated_index_starves_devices():
    """The defect this design step exists for, at the REAL shape: 1,000
    devices against the 2,000-slot production table. With raw seq for both
    picks, device j only ever sees table indices {j, j+1000} — outside the
    classifying block [0,100) for 90 % of devices, FOREVER, at any budget.
    If this stops failing after a table reshape, re-derive whether
    decorrelation is still required."""
    gen = _gen()
    pool_size = 1000
    rounds = 20
    hits = [0] * pool_size
    for seq in range(pool_size * rounds):
        if _classifies(gen, f"mlx-prof-{seq % pool_size:05d}", seq,
                       "production", seq):          # CORRELATED index
            hits[seq % pool_size] += 1
    starved = [i for i, h in enumerate(hits) if h == 0]
    assert len(starved) >= 800, (
        f"only {len(starved)} devices starved — correlated indexing no longer "
        f"demonstrates the defect")


# ── profile overrides and lane math ──────────────────────────────────────────

def test_profiles_are_closed_and_legacy_is_default():
    assert ml.parse_args([]).profile == "legacy"
    with pytest.raises(SystemExit):
        ml.parse_args(["--profile", "s9"])


@pytest.mark.parametrize("profile,eps,minutes,mix", [
    ("t-nominal", 400, 15, "production"),
    ("t-p95", 800, 15, "production"),
    ("s3-stress", 2000, 5, "single"),
])
def test_single_lane_profiles_override_args(profile, eps, minutes, mix):
    prof = ml.WORKLOAD_PROFILES[profile]
    assert (prof["eps"], prof["burst_minutes"], prof["event_mix"]) == (eps, minutes, mix)


def test_s1_composes_to_the_ratified_fleet_rate():
    lanes = ml.WORKLOAD_PROFILES["s1"]["lanes"]
    total = sum(rate for _n, _s, _m, rate in lanes)
    assert total == pytest.approx(4000.0), "S1 fleet raw != ratified 4,000 EPS"
    (storm, bg) = lanes
    assert storm[1] == pytest.approx(0.10), "S1 blast radius != ratified 10 %"
    assert storm[2] == "storm" and bg[2] == "production"
    assert ml.WORKLOAD_PROFILES["s1"]["burst_minutes"] == 15
    assert ml.WORKLOAD_PROFILES["s1-long"]["burst_minutes"] == 60


def test_s2_ramp_schedule():
    """1× → 10× over 60 min, then hold (gate spec §5)."""
    rate = ml.WORKLOAD_PROFILES["s2-ramp"]["lanes"][0][3]
    assert callable(rate)
    assert rate(0) == pytest.approx(40.0)
    assert rate(1800) == pytest.approx(40.0 + 1800.0)
    assert rate(3600) == pytest.approx(3640.0)
    assert rate(4200) == pytest.approx(3640.0), "the hold must be flat"


def test_lane_pools_partition_all_devices():
    gen = _gen(profile="s1")
    lanes = gen._lane_states()
    sizes = [len(ln["pool"]) for ln in lanes]
    assert sizes == [100, 900]
    assert sum(sizes) == 1000
    assert len({d for ln in lanes for d in ln["pool"]}) == 1000, "pool overlap"


def test_s4_chatter_pool_and_rate_match_the_chronic_class():
    gen = _gen(profile="s4-chatter")
    lanes = gen._lane_states()
    chatter = lanes[0]
    assert chatter["name"] == "chatter" and len(chatter["pool"]) == 5
    per_dev_hr = (chatter["rate"] / len(chatter["pool"])) * 3600
    assert per_dev_hr == pytest.approx(252, rel=0.05), (
        f"chatter {per_dev_hr:.0f}/hr/device != the measured ~250/hr class")


def test_planned_total_integrates_the_ramp():
    gen = _gen(profile="s2-ramp")
    gen.args.burst_minutes = 75
    got = gen._planned_total()
    # storm lane: ∫(40 + t)dt over 3600 + 3640×900 ; background 360×4500
    storm = sum(40.0 + min(1.0, t / 3600.0) * 3600.0 for t in range(4500))
    want = int(storm + 360.0 * 4500)
    assert got == want


def test_planned_total_flat_profiles_match_eps_times_duration():
    gen = _gen(profile="t-nominal")
    gen.args.eps, gen.args.burst_minutes = 400, 15
    assert gen._planned_total() == 400 * 900


# ── the canary must prove the pipe, never the mix ────────────────────────────

def test_canary_always_classifies_under_every_profile():
    """Run 08221806kefm's failure, pinned: the canary at fixed seq 999,999
    under the production mix landed on a NOISE slot (999,999 % 2000 = 1999)
    and could never produce a corr_signal — a false pipeline-broken verdict.
    The canary is now mix-independent and must classify under EVERY profile."""
    now = datetime.now(timezone.utc)
    for profile in ml.WORKLOAD_PROFILES:
        gen = _gen(profile=profile,
                   event_mix=ml.WORKLOAD_PROFILES[profile].get("event_mix", "single"))
        ev = json.loads(gen._canary_event())
        sig = producers.syslog_control_signal(ev, "t1", now)
        assert sig is not None, f"canary does not classify under profile {profile!r}"
        assert sig.kind == "link_state_change"
        assert "[mlx seq 999999]" in ev["message"], "canary lost its trace marker"


def test_mutation_run_mix_canary_is_noise_at_the_fixed_seq():
    """The regression direction: build the canary with the RUN mix (the old
    code) under t-nominal and it must NOT classify — proving the mix-pinned
    canary is load-bearing, not decorative."""
    gen = _gen(profile="t-nominal", event_mix="production")
    ev = json.loads(gen._syslog_event(gen.created_ids[0], 999_999))  # old behaviour
    sig = producers.syslog_control_signal(ev, "t1", datetime.now(timezone.utc))
    assert sig is None, (
        "seq 999,999 now classifies under the production mix — if the table "
        "reshaped, this mutation pin needs a new fixed-seq noise witness")
