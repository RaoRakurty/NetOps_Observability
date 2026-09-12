# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

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
    ("t-nominal", 400.0, 15, "production"),
    ("t-p95", 800.0, 15, "production"),
    ("s3-stress", 2000.0, 5, "single"),
])
def test_single_lane_profiles_carry_the_ratified_rates(profile, eps, minutes, mix):
    prof = ml.WORKLOAD_PROFILES[profile]
    assert prof["burst_minutes"] == minutes
    lanes = prof["lanes"]
    assert len(lanes) == 1 and lanes[0][1] == 1.0
    assert lanes[0][2] == mix and lanes[0][3] == eps


def test_every_non_legacy_profile_routes_through_the_lanes_path():
    """THE 100/1000 regression pin (second T-nominal run): the legacy loop's
    correlated modulus starves 90 % of devices under a noise-bearing mix, so
    NO profile may route through it — every profile except 'legacy' must
    define lanes, and legacy must never carry a noise-bearing mix key."""
    for name, prof in ml.WORKLOAD_PROFILES.items():
        if name == "legacy":
            assert "lanes" not in prof
            assert prof.get("event_mix") not in ("production", "storm")
            continue
        assert prof.get("lanes"), (
            f"profile {name!r} has no lanes — it would take the legacy "
            f"correlated-modulus loop")


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


def test_soak_profile_matches_the_launch_decision():
    """72h soak (owner go, 2026-08-22): 100 raw eps background (0.1/device,
    inside the measured production band) + the chronic-chatter lane, 4,320
    minutes, promotion-realistic. Rate is a DISK-sized decision — changing it
    changes the claim on every soak artifact, so it is pinned."""
    prof = ml.WORKLOAD_PROFILES["soak-72h"]
    assert prof["burst_minutes"] == 4320
    chatter, bg = prof["lanes"]
    assert bg == ("background", 0.995, "production", 100.0)
    assert chatter == ("chatter", 0.005, "single", 0.35)
    assert prof["workload_class"] == "SOAK_72H_100EPS"


def test_2k5_rung_profiles_match_the_ratified_ladder():
    """Pre-staged 2.5K rung (run after the 1K rung closes): nominal 0.4
    eps/device x 2,500 = 1,000 raw; S1 composes to 10,000 raw at 10 % radius
    (storm 9,100 + background 900) — the ladder's 10x aggregate."""
    tn = ml.WORKLOAD_PROFILES["t-nominal-2.5k"]
    assert tn["lanes"] == [("fleet", 1.0, "production", 1000.0)]
    s1 = ml.WORKLOAD_PROFILES["s1-2.5k"]
    (storm, bg) = s1["lanes"]
    assert storm[1] == 0.10 and storm[2] == "storm"
    assert storm[3] + bg[3] == pytest.approx(10_000.0)
    assert (storm[3] + bg[3]) / (2500 * 0.4) == pytest.approx(10.0),         "S1-2.5K aggregate is not the ratified 10x nominal"


# ══════════════════════════════════════════════════════════════════════════
# THE HOST-CEILING LADDER (5K / 10K rungs, 2026-08-30)
#
# `docs/projects/01-SCALE-TESTING.md` §ladder hunts the largest fleet this box
# carries to a graded verdict. The rungs vary SCALE and nothing else, so what
# these tests hold is everything that must NOT move while it does:
#
#   * the per-device rate — the ratified 0.4 eps/device the whole T-family
#     runs at, so a completion/TTUR difference between rungs is about the box
#     and not about the load per device;
#   * the 15-minute window, which is where the ratified 2,700 s drain and
#     completion caps come from (`--drain-factor` 3.0 x 900 s). An INCOMPLETE
#     at the cap is the MEASURED finding for that rung, never a reason to
#     widen it;
#   * the onboard budget, which is the ONE thing that must scale with the
#     fleet — and does, from the harness's own measured create rates;
#   * every profile that predates the ladder, byte for byte: the recorded 1K
#     and 2.5K numbers are about those exact workloads.
# ══════════════════════════════════════════════════════════════════════════

# (profile, devices it is run with, raw eps, workload class, scenario)
HOST_CEILING_RUNGS = (
    ("t-nominal-5k", 5000, 2000.0, "T_NOMINAL_5K", None),
    ("t-storm-5k", 5000, 2000.0, "T_STORM_5K", "storm-5k"),
    ("t-nominal-10k", 10000, 4000.0, "T_NOMINAL_10K", None),
    ("t-storm-10k", 10000, 4000.0, "T_STORM_10K", "storm-10k"),
)
RATIFIED_EPS_PER_DEVICE = 0.4


@pytest.mark.parametrize("name,devices,eps,klass,scenario", HOST_CEILING_RUNGS)
def test_host_ceiling_rungs_are_registered_at_the_ratified_per_device_rate(
        name, devices, eps, klass, scenario):
    """The registry entry itself. `--devices` is never overridden by a
    profile, so the rate is written into the LANE and the rung has to be run
    with the matching count — the pairing is pinned here because nothing at
    run time can check it."""
    assert name in ml.WORKLOAD_PROFILES, f"{name!r} is not registered"
    prof = ml.WORKLOAD_PROFILES[name]
    assert prof["workload_class"] == klass
    assert prof["burst_minutes"] == 15
    assert prof["lanes"] == [("fleet", 1.0, "production", eps)]
    assert eps / devices == pytest.approx(RATIFIED_EPS_PER_DEVICE), (
        f"{name}: {eps}/{devices} = {eps / devices} eps/device, not the "
        f"ratified {RATIFIED_EPS_PER_DEVICE}")
    assert prof.get("scenario") == scenario
    if scenario:
        assert scenario in ml.SCENARIO_SPECS


@pytest.mark.parametrize("name,devices,eps,_k,_s", HOST_CEILING_RUNGS)
def test_a_host_ceiling_rung_plans_eps_times_the_window(name, devices, eps,
                                                        _k, _s):
    """The chunk plan a rung actually injects: rate x 900 s, integrated the
    same way every other lane profile's is."""
    gen = _gen(profile=name, devices=devices)
    gen.args.eps, gen.args.burst_minutes = int(eps), 15
    assert gen._planned_total() == int(eps) * 900
    lanes = gen._lane_states()
    assert [len(ln["pool"]) for ln in lanes] == [devices], (
        "the fleet lane must carry every device — a rung that splits the "
        "fleet is not the T-family workload")


def test_the_host_ceiling_rungs_keep_the_ratified_2700s_budgets():
    """`drain()` and `correlation_completion()` both budget
    `--drain-factor x burst_seconds`. Keeping the window at 15 min is what
    keeps both caps at the ratified 2,700 s across the whole ladder — so an
    INCOMPLETE at the cap compares directly with the 2.5K rung's."""
    args = ml.parse_args([])
    assert args.drain_factor == 3.0, (
        "the drain factor moved — every recorded 2,700 s budget is now a "
        "different number")
    for name, _devices, _eps, _k, _s in HOST_CEILING_RUNGS:
        burst_s = ml.WORKLOAD_PROFILES[name]["burst_minutes"] * 60
        assert burst_s == 900
        assert max(args.drain_factor * burst_s, 120.0) == 2700.0


# ── the onboard budget: the one thing that DOES scale with the fleet ────────

@pytest.mark.parametrize("devices,want_s", [(1000, 366.7), (2500, 466.7),
                                            (5000, 633.3), (10000, 966.7)])
def test_the_onboard_budget_scales_with_the_fleet(devices, want_s):
    got = ml.onboard_budget_s(devices)
    assert got == pytest.approx(
        ml.ONBOARD_BUDGET_BASE_S + devices / ml.ONBOARD_RATE_FLOOR_PER_S)
    assert got == pytest.approx(want_s, abs=0.5)


def test_the_onboard_budget_is_per_device_not_a_constant():
    """A constant budget silently stops covering the fleet exactly when the
    fleet gets big enough to need it. Doubling the devices must add the
    devices' own time at the measured floor rate."""
    step = ml.onboard_budget_s(10000) - ml.onboard_budget_s(5000)
    assert step == pytest.approx(5000 / ml.ONBOARD_RATE_FLOOR_PER_S)
    budgets = [ml.onboard_budget_s(n) for n in (0, 1000, 2500, 5000, 10000)]
    assert budgets == sorted(budgets) and len(set(budgets)) == len(budgets)


def test_the_onboard_budget_covers_the_runs_it_was_derived_from():
    """The measurements in the harness header, held against the budget:
    2,500 devices took 79.68 s wall (report 20260828T014955Z, 31.4/s) and the
    tombstone-laden store managed 15.4/s (tracker 175). A budget that does not
    cover the SLOW case would fire on every healthy run and mean nothing."""
    assert ml.onboard_budget_s(2500) > 79.68
    for n in (1000, 2500, 5000, 10000):
        assert ml.onboard_budget_s(n) > n / 15.4, (
            f"the {n}-device budget does not cover the measured 15.4/s "
            f"tombstone-laden rate the floor was derived from")
    assert ml.ONBOARD_RATE_FLOOR_PER_S <= ml.ONBOARD_RATE_PLAN_PER_S


def test_the_onboard_budget_is_reported_and_never_a_verdict():
    """§16.1: the overrun must be VISIBLE (evidence + warning), and it must
    not decide the phase — a slow create is what the linearity gate judges,
    and abandoning a half-built fleet would destroy the run's evidence."""
    src = (ROOT / "scripts" / "scale-miniladder.py").read_text(encoding="utf-8")
    body = src.split("    def onboard(self) -> bool:", 1)[1].split(
        "\n    # -- phase 3", 1)[0]
    assert '"budget_s": round(budget_s, 0)' in body
    assert '"over_budget": total_wall > budget_s' in body
    assert "if total_wall > budget_s:" in body and "warn(" in body
    guard = body.split("if total_wall > budget_s:", 1)[1].split(
        "if self.absorbed", 1)[0]
    assert "return" not in guard, (
        "the onboard budget overrun grew a return — it became a verdict")


# ── everything that predates the ladder is byte-unchanged ───────────────────

# The 15 profiles as they stood at commit 2a4c66e5, canonicalised (rate
# callables render as "<callable>" because a lambda's repr carries its
# address). VERIFIED both ways: this digest was computed from
# `git show 2a4c66e5:scripts/scale-miniladder.py` and from the working tree
# after the 5K/10K rungs were added, and the two agreed — which is the claim
# the pin makes. A rung ADDED to the registry does not move it; a rate,
# window, mix, lane split or class CHANGED on any of these does, and that
# would re-base every 1K/2.5K number already recorded against them.
PRE_LADDER_PROFILES = (
    "legacy", "s1", "s1-2.5k", "s1-long", "s2-ramp", "s3-stress", "s4-chatter",
    "soak-72h", "t-nominal", "t-nominal-2.5k", "t-p95", "t-storm-10-2.5k",
    "t-storm-2.5k", "t-storm-25-2.5k", "t-storm-50-2.5k",
)
PRE_LADDER_PROFILE_DIGEST = (
    "5c634edce461d95d42991ec59ac9ef9cc8948827d3b7425d38c52609e60a5082")


def _canonical_profile(prof: dict) -> dict:
    out: dict = {}
    for key, value in sorted(prof.items()):
        if key == "lanes":
            out[key] = [[n, share, mix,
                         ("<callable>" if callable(rate) else rate)]
                        for n, share, mix, rate in value]
        else:
            out[key] = value
    return out


def test_every_profile_that_predates_the_host_ceiling_ladder_is_unchanged():
    import hashlib
    assert set(PRE_LADDER_PROFILES) <= set(ml.WORKLOAD_PROFILES), (
        "a pre-ladder profile was REMOVED — its recorded runs lost their "
        "workload definition")
    blob = json.dumps(
        {n: _canonical_profile(ml.WORKLOAD_PROFILES[n])
         for n in sorted(PRE_LADDER_PROFILES)},
        sort_keys=True, separators=(",", ":"))
    assert hashlib.sha256(blob.encode()).hexdigest() == \
        PRE_LADDER_PROFILE_DIGEST, (
            "a profile that predates the host-ceiling ladder changed — every "
            "number recorded against it is now about a different workload")


def test_the_pin_would_catch_a_moved_rate():
    """THE MUTANT: the digest is only worth having if a one-rate change turns
    it red."""
    import hashlib
    mutated = {n: _canonical_profile(ml.WORKLOAD_PROFILES[n])
               for n in sorted(PRE_LADDER_PROFILES)}
    mutated["t-nominal-2.5k"]["lanes"][0][3] = 1001.0
    blob = json.dumps(mutated, sort_keys=True, separators=(",", ":"))
    assert hashlib.sha256(blob.encode()).hexdigest() != \
        PRE_LADDER_PROFILE_DIGEST


# ── the dry run must print the plan the burst would inject (16.3) ───────────

def test_the_chunk_plan_has_one_definition():
    """`lane_chunk_plan` is what the burst plans from AND what --dry-run
    prints; two integrations of the same profile could disagree, and the one
    the operator reads is the one that would be wrong."""
    for name in ("t-nominal-2.5k", "t-storm-5k", "t-storm-10k", "s2-ramp"):
        prof = ml.WORKLOAD_PROFILES[name]
        gen = _gen(profile=name, devices=100)
        gen.args.burst_minutes = prof["burst_minutes"]
        gen.args.eps = 2000
        duration = prof["burst_minutes"] * 60
        assert gen._lane_schedule() == ml.lane_chunk_plan(prof["lanes"],
                                                          duration)


@pytest.mark.parametrize("profile,devices,planned", [
    ("t-nominal-2.5k", 2500, 900_000),
    ("t-storm-5k", 5000, 1_800_000),
    ("t-nominal-10k", 10000, 3_600_000),
    ("t-storm-10k", 10000, 3_600_000),
])
def test_the_dry_run_prints_the_plan_the_burst_would_inject(
        profile, devices, planned, capsys, monkeypatch):
    """THE DEFECT: --dry-run printed `--eps`, which NO lane profile reads, so
    a 10K rung's operator was told 2,000/s while the run would inject 4,000/s.
    §16.3 says a dry run states exactly what would happen."""
    monkeypatch.setenv("PATH", os.environ.get("PATH", ""))   # main() rewrites it
    assert ml.main(["--dry-run", "--devices", str(devices),
                    "--profile", profile]) == 0
    out = capsys.readouterr().out
    assert f"then {planned} syslog events" in out
    eps = ml.WORKLOAD_PROFILES[profile]["lanes"][0][3]
    assert f"@ {eps:.0f}/s across 1 lane(s)" in out
    gen = _gen(profile=profile, devices=devices)
    gen.args.burst_minutes, gen.args.eps = 15, 2000
    assert gen._planned_total() == planned, (
        "the printed plan and the burst's plan disagree")


def test_the_dry_run_still_reports_eps_for_the_legacy_profile(capsys,
                                                              monkeypatch):
    """`legacy` is the one profile that genuinely runs off --eps; its dry-run
    line must not start quoting a lane rate it does not have."""
    monkeypatch.setenv("PATH", os.environ.get("PATH", ""))
    assert ml.main(["--dry-run", "--devices", "1000", "--profile", "legacy",
                    "--eps", "1234", "--burst-minutes", "5"]) == 0
    out = capsys.readouterr().out
    assert "then 370200 syslog events @ 1234/s" in out
    assert "lane(s)" not in out.split("phase 3 burst")[1].split("\n")[0]


def test_the_dry_run_prints_an_onboard_budget_that_tracks_the_fleet(
        capsys, monkeypatch):
    monkeypatch.setenv("PATH", os.environ.get("PATH", ""))
    assert ml.main(["--dry-run", "--devices", "10000",
                    "--profile", "t-storm-10k"]) == 0
    out = capsys.readouterr().out
    assert f"budget {ml.onboard_budget_s(10000):.0f}s (informational)" in out
