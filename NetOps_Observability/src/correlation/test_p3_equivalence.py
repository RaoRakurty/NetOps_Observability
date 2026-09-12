# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""P3 step 3 — representation + equivalence (design §5, memo §24/§25).

Two halves, and the second is worthless without the first:

  A. REPRESENTATION. An object built from DELTA signals must carry its own
     aggregation provenance — policy, delta/key counts, raw coverage, class
     histogram, Kafka offset range — in bytes that survive the archive and
     re-derive on replay; and an object built from raw must be BYTE-IDENTICAL
     to pre-P3 (the `storm_occurrences` precedent: a new representation may not
     churn the objects that do not use it).

  B. EQUIVALENCE. Flag OFF vs flag ON over the SAME stream must agree on every
     property in memo §25. The harness lives in `bench_agg_equivalence` (so the
     bench mode and the gate run exactly the same comparison, never two drifting
     implementations of it); this file runs it over every fixture and,
     critically, MUTATION-TESTS IT — a suite that has never been shown to fail
     is a suite that proves nothing, so three deliberate defects are injected
     and each must be caught by the check that claims to catch it.
"""
from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest

import aggregation
import bench_agg_equivalence as B
import main as M
from aggregation import AGG_POLICY_VERSION, AggPlane, DeltaClass, delta_class
from engine import EngineConfig, aggregation_block, run_window
from golden_wire import GOLDEN_DIR
from replay import StoredObject, check_rederivation, rederive_deltas, replay
from signals import EntityType, Signal
from test_engine import sig

CAT = B.CAT
CFG = EngineConfig()
T0 = B.T0


# ═══════════════════════════════════════════════════════════════════════════
# A. representation
# ═══════════════════════════════════════════════════════════════════════════

def _plain_window():
    """A two-node containment object with NO aggregation annotation."""
    return (sig("device_cpu_high", EntityType.DEVICE, "agg0", offset_s=0.0),
            sig("if_errors", EntityType.INTERFACE, "agg0:Gi0/1", offset_s=20.0))


def _agg_window():
    """The same object, run through a real plane."""
    plane = AggPlane(horizon_s=B.HARNESS_HORIZON_S,
                     lateness_s=B.HARNESS_LATENESS_S)
    out = [plane.observe(s, (3, 1000 + i))
           for i, s in enumerate(B._copy(_plain_window()))]
    return tuple(s for s in out if s is not None), plane


def test_unaggregated_object_embeds_no_aggregation_block():
    """THE byte-identity contract. The block is the ONLY thing P3 adds to
    `hypotheses_blob`, so its absence is exactly "the blob did not move" — and a
    blob that did not move means `content_hash`, the replay pin and the version
    damping detector all keep their pre-P3 values."""
    snap = run_window(_plain_window(), CAT, (), CFG)[0]
    assert snap.agg_provenance() == {}
    ctx = json.loads(snap.hypotheses_blob())["grounding_context"]
    assert "aggregation" not in ctx, (
        "an un-aggregated object grew an aggregation block: every pre-P3 object "
        f"would churn a version on deploy. ctx keys: {sorted(ctx)}")


def test_aggregated_object_embeds_the_block_with_the_policy_pinned():
    window, _plane = _agg_window()
    snap = run_window(window, CAT, (), CFG)[0]
    block = json.loads(snap.hypotheses_blob())["grounding_context"]["aggregation"]
    assert block["policy"] == AGG_POLICY_VERSION, (
        "the policy that produced these deltas is not pinned in the object, so "
        "replay has nothing to compare against")
    assert block["deltas"] == 2
    assert block["keys"] == 2
    assert block["raw_signal_count"] == 2
    assert block["classes"] == {"first": 2}
    assert block["offsets"] == ["3:1000-1001"], (
        "the raw Kafka coordinate range did not reach the object (memo §16)")
    assert block["first_ts"] <= block["last_ts"]


def test_raw_signal_count_is_max_per_key_never_the_sum():
    """The §24 arithmetic, stated as a test rather than as prose.

    `agg_count` is the key's CUMULATIVE count at emission, so a key that emits
    FIRST at 1 and COUNT_THRESHOLD at 10 has covered 10 raw observations, not
    11. Summing would inflate every busy key by its own delta count.
    """
    base = sig("device_cpu_high", EntityType.DEVICE, "agg0")
    deltas = [
        B.dc_replace(base, attrs={"agg_key": "t|agg0|device_cpu_high|high|1",
                                  "agg_policy": AGG_POLICY_VERSION,
                                  "agg_class": "first", "agg_count": 1}),
        B.dc_replace(base, native_id="x2",
                     attrs={"agg_key": "t|agg0|device_cpu_high|high|1",
                            "agg_policy": AGG_POLICY_VERSION,
                            "agg_class": "count_threshold", "agg_count": 10}),
    ]
    block = aggregation_block(deltas)
    assert block["keys"] == 1 and block["deltas"] == 2
    assert block["raw_signal_count"] == 10, (
        f"summed cumulative snapshots instead of taking the max: {block}")


def test_block_is_bounded_by_construction():
    """A storm object may hold ~180k signals; the block may not grow with it.

    Every field is a counter, a min/max, a closed-enum histogram (≤ 8) or an
    explicitly capped list — so a 1,000-key object's block is the same SHAPE as
    a 2-key object's, and the elision is declared."""
    base = sig("device_cpu_high", EntityType.DEVICE, "agg0")
    deltas = [
        B.dc_replace(base, native_id=f"x{i}",
                     attrs={"agg_key": f"t|agg{i}|device_cpu_high|high|1",
                            "agg_policy": AGG_POLICY_VERSION,
                            "agg_class": "first", "agg_count": 1,
                            "agg_offset_range": [f"{i}:0-{i}"]})
        for i in range(1000)]
    block = aggregation_block(deltas)
    assert block["keys"] == 1000
    assert len(block["classes"]) <= len(DeltaClass)
    assert len(block["offsets"]) == 16, "the partition list is not capped"
    assert block["offsets_truncated"] == 1000 - 16, (
        "partitions were dropped without declaring it — a silent elision")


def test_offset_ranges_merge_per_partition():
    base = sig("device_cpu_high", EntityType.DEVICE, "agg0")
    deltas = [
        B.dc_replace(base, native_id=f"x{i}",
                     attrs={"agg_key": "t|agg0|device_cpu_high|high|1",
                            "agg_policy": AGG_POLICY_VERSION,
                            "agg_class": "first", "agg_count": 1,
                            "agg_offset_range": [rng]})
        for i, rng in enumerate(("3:500-600", "3:100-200", "7:9-9"))]
    assert aggregation_block(deltas)["offsets"] == ["3:100-600", "7:9-9"]


@pytest.mark.parametrize("bad", ["", "nope", "3:", "3:a-b", "3-100", 17, None,
                                 ["3:1-2"]])
def test_a_malformed_offset_token_is_skipped_not_raised(bad):
    """Provenance is untrusted input (§3): it round-trips through an archived
    JSON blob. A corrupt token may not be able to fail an object's
    serialization — one bad string must never cost an operator the whole RCA."""
    base = sig("device_cpu_high", EntityType.DEVICE, "agg0")
    d = B.dc_replace(base, attrs={"agg_key": "t|agg0|k|high|1",
                                  "agg_policy": AGG_POLICY_VERSION,
                                  "agg_class": "first", "agg_count": 1,
                                  "agg_offset_range": [bad, "3:1-2"]})
    assert aggregation_block([d])["offsets"] == ["3:1-2"]


def test_partially_aggregated_object_declares_its_remainder():
    window, _ = _agg_window()
    mixed = (*window, sig("if_util_high", EntityType.INTERFACE, "agg0:Gi0/1",
                          offset_s=40.0))
    block = aggregation_block(mixed)
    assert block["deltas"] == 2 and block["unaggregated"] == 1, (
        "a half-aggregated object reports `deltas` as if it were the whole "
        f"signal count: {block}")


def test_archive_row_preserves_every_agg_attr():
    """Requirement (b), tested on the PRODUCTION archive builder.

    `main._archive_row` -> `Signal.from_ch_row` is the exact path a delta takes
    into `corr_signals_archive` and back out again for a replay. Every `agg_*`
    annotation must survive it verbatim; anything that does not is evidence the
    engine reasoned over and the archive cannot reproduce.
    """
    window, _ = _agg_window()
    for s in window:
        row = M._archive_row(s, "00000000-0000-0000-0000-000000000001", 1,
                             cache=False)
        back = Signal.from_ch_row(row)
        for k, v in s.attrs.items():
            if k.startswith("agg_"):
                assert back.attrs.get(k) == v, (
                    f"{k} did not survive the archive round-trip: "
                    f"{v!r} -> {back.attrs.get(k)!r}")


def _repeat_stream(repeats: int):
    """The plain window plus `repeats` re-deliveries of its CPU signal — same
    AggKey (2 s apart, far inside the 60 s bucket), distinct signal ids."""
    plane = AggPlane(horizon_s=B.HARNESS_HORIZON_S,
                     lateness_s=B.HARNESS_LATENESS_S)
    raw = list(B._copy(_plain_window()))
    raw += [B.dc_replace(raw[0], native_id=f"rep{i}",
                         ts=raw[0].ts + timedelta(seconds=2.0 * i))
            for i in range(1, repeats + 1)]
    window = [s for s in (plane.observe(x) for x in B._ordered(raw))
              if s is not None]
    return raw, window, run_window(tuple(window), CAT, (), CFG)[0]


def test_signal_count_counts_deltas_and_raw_coverage_lives_in_the_blob():
    """The §24 decision, pinned so it cannot be silently reversed.

    `corr_objects.signal_count` = forwarded deltas (what the engine reasoned
    over, and what `replay` recomputes and compares). Raw coverage is a
    different number and lives in the BLOCK — not in a new `corr_objects`
    column, which would need a ClickHouse migration for a value only aggregated
    objects have.
    """
    raw, window, snap = _repeat_stream(3)
    row = snap.to_object_row(1)
    assert row["signal_count"] == len(window) < len(raw), (
        "signal_count must be the DELTA count — the population the engine saw")
    assert "raw_signal_count" not in row, (
        "a column was added to corr_objects without a schema migration")
    block = json.loads(row["hypotheses"])["grounding_context"]["aggregation"]
    assert "raw_signal_count" in block


def test_raw_signal_count_is_an_honest_lower_bound_not_a_claim():
    """THE limitation, pinned as a test so it can never be quietly overstated.

    `agg_count` is a snapshot taken WHEN A DELTA IS EMITTED. Repeats that arrive
    after a key's LAST delta are absorbed into plane state and never
    re-announced, so the object cannot see them:

      * 3 repeats -> the key emits only FIRST (count 1); the block reports 1 for
        that key even though 4 raw observations exist. Under, never over.
      * 10 repeats -> the count crosses the 10 threshold, a COUNT_THRESHOLD
        delta is emitted carrying `agg_count=10`, and the block reports 10.

    The block therefore under-reports and never over-reports. The EXACT ledger
    is the plane's own `raw_count()` and `corr_signals` (every raw row, kept),
    and the equivalence suite measures coverage at the KEY level where it is
    exact — see `bench_agg_equivalence.compare`.
    """
    for repeats, expect_key_max in ((3, 1), (10, 10)):
        raw, _window, snap = _repeat_stream(repeats)
        block = snap.agg_provenance()
        assert block["raw_signal_count"] <= len(raw), (
            f"the block OVER-reports raw coverage: {block} over {len(raw)} raw")
        # keys == 2 (the cpu key and the if_errors key); the if_errors key
        # contributes exactly 1, so the cpu key's contribution is the rest.
        assert block["keys"] == 2
        assert block["raw_signal_count"] - 1 == expect_key_max, block
    # the plane's OWN ledger is exact, which is what makes the bound honest
    plane = AggPlane(horizon_s=B.HARNESS_HORIZON_S,
                     lateness_s=B.HARNESS_LATENESS_S)
    raw = list(B._copy(_plain_window()))
    raw += [B.dc_replace(raw[0], native_id=f"rep{i}",
                         ts=raw[0].ts + timedelta(seconds=2.0 * i))
            for i in range(1, 4)]
    for x in B._ordered(raw):
        plane.observe(x)
    assert plane.raw_count("") == len(raw)


def test_affected_is_identical_with_and_without_the_plane():
    """Blast radius is a projection of node IDENTITY, and every AggKey emits at
    least a FIRST delta, so no entity can disappear behind a collapse."""
    off = run_window(_plain_window(), CAT, (), CFG)[0]
    window, _ = _agg_window()
    on = run_window(window, CAT, (), CFG)[0]
    assert {k: sorted(v) for k, v in off.affected().items()} == \
           {k: sorted(v) for k, v in on.affected().items()}


# ═══════════════════════════════════════════════════════════════════════════
# A2. replay of the representation
# ═══════════════════════════════════════════════════════════════════════════

def _store_and_replay(snap, *, mutate_rows=None):
    rows = [M._archive_row(s, snap.correlation_id, 1, cache=False)
            for n in snap.nodes for s in n.signals]
    if mutate_rows is not None:
        rows = [mutate_rows(r) for r in rows]
    window = [Signal.from_ch_row(r) for r in rows]
    stored = StoredObject.from_rows(snap.to_object_row(1), snap.to_edge_rows(1))
    return replay(stored, window)


def test_replay_of_an_aggregated_object_is_clean():
    window, _ = _agg_window()
    snap = run_window(window, CAT, (), CFG)[0]
    report = _store_and_replay(snap)
    assert report.clean, report.differences
    assert report.agg_pin_match
    assert report.to_dict()["agg_policy"] == AGG_POLICY_VERSION


def test_replay_reports_a_policy_pin_mismatch_loudly(monkeypatch):
    """We cannot time-travel an aggregation policy any more than we can
    time-travel code. A stored object whose deltas came from a policy this
    process no longer implements is REPORTED, exactly like an engine pin."""
    import replay as R
    window, _ = _agg_window()
    snap = run_window(window, CAT, (), CFG)[0]
    monkeypatch.setattr(R, "AGG_POLICY_VERSION", "p3.k9.vX")
    report = _store_and_replay(snap)
    assert not report.agg_pin_match
    assert not report.clean
    assert any("aggregation policy pin" in d for d in report.agg_drift)
    assert report.agg_drift and set(report.agg_drift) <= set(report.differences), (
        "an aggregation finding did not reach `differences` — every pre-P3 "
        "reader of a DriftReport would miss it")


def test_replay_catches_annotations_lost_in_the_archive():
    """MUTATION WITNESS for `test_archive_row_preserves_every_agg_attr`.

    Strip the `agg_*` attrs on the way into the archive — the shape a
    `_shrink_attrs` truncation would take — and replay must NAME it, not shrug.
    """
    window, _ = _agg_window()
    snap = run_window(window, CAT, (), CFG)[0]

    def strip(row):
        attrs = json.loads(row["attrs"])
        row = dict(row)
        row["attrs"] = json.dumps(
            {k: v for k, v in attrs.items() if not k.startswith("agg_")},
            separators=(",", ":"), sort_keys=True)
        return row

    report = _store_and_replay(snap, mutate_rows=strip)
    assert not report.clean
    assert any("aggregation block" in d for d in report.agg_drift), report.differences


def test_replay_catches_a_rewritten_agg_count():
    """A subtler corruption than a missing block: the annotations are there but
    one of them moved. Field-level diffing is what makes this nameable."""
    window, _ = _agg_window()
    snap = run_window(window, CAT, (), CFG)[0]

    def bump(row):
        attrs = json.loads(row["attrs"])
        if "agg_count" in attrs:
            attrs["agg_count"] = int(attrs["agg_count"]) + 99
        row = dict(row)
        row["attrs"] = json.dumps(attrs, separators=(",", ":"), sort_keys=True)
        return row

    report = _store_and_replay(snap, mutate_rows=bump)
    assert not report.clean
    assert any("aggregation.raw_signal_count" in d for d in report.agg_drift), \
        report.differences


def test_rederive_deltas_reproduces_the_archived_slice():
    """The OTHER level of replay (design §3): `corr_signals` still holds every
    raw row, so the delta stream itself must be reconstructible from raw."""
    stream = B.stream_chain(sites=2)
    raw = list(B._copy(stream.signals))
    plane = AggPlane(horizon_s=B.HARNESS_HORIZON_S,
                     lateness_s=B.HARNESS_LATENESS_S)
    archived = [s for s in (plane.observe(x) for x in B._ordered(raw))
                if s is not None]
    assert not check_rederivation(archived, B._copy(stream.signals),
                                  horizon_s=B.HARNESS_HORIZON_S,
                                  lateness_s=B.HARNESS_LATENESS_S)
    # determinism: a second re-derivation over the same raw is identical
    a = [s.signal_id_str for s in rederive_deltas(
        B._copy(stream.signals), horizon_s=B.HARNESS_HORIZON_S,
        lateness_s=B.HARNESS_LATENESS_S)]
    b = [s.signal_id_str for s in rederive_deltas(
        B._copy(stream.signals), horizon_s=B.HARNESS_HORIZON_S,
        lateness_s=B.HARNESS_LATENESS_S)]
    assert a == b and a == [s.signal_id_str for s in archived]


def test_rederivation_from_the_wrong_raw_slice_is_reported():
    """MUTATION WITNESS: a re-derivation that silently 'succeeds' against the
    wrong raw slice would make the whole losslessness claim unfalsifiable."""
    stream = B.stream_chain(sites=2)
    raw = B._ordered(B._copy(stream.signals))
    plane = AggPlane(horizon_s=B.HARNESS_HORIZON_S,
                     lateness_s=B.HARNESS_LATENESS_S)
    archived = [s for s in (plane.observe(x) for x in raw) if s is not None]
    findings = check_rederivation(archived, B._copy(stream.signals)[:20],
                                  horizon_s=B.HARNESS_HORIZON_S,
                                  lateness_s=B.HARNESS_LATENESS_S)
    assert findings and "fewer delta" in findings[0]


# ═══════════════════════════════════════════════════════════════════════════
# B. the §25 equivalence suite, over every fixture
# ═══════════════════════════════════════════════════════════════════════════

GOLDEN = sorted(p.name for p in Path(GOLDEN_DIR).glob("*.json"))

SYNTHETIC = {
    "fx166:bounded-cohort": B.stream_166,
    "fx162:continuation-index": B.stream_162,
    "fx168:local-identity-scope": B.stream_168,
    "storm:bench_profile_p2": B.stream_storm,
    "storm:repeats-x3": B.stream_storm_repeats,
    "chain:enterprise-outage": B.stream_chain,
}


def _assert_equivalent(stream):
    v = B.compare(stream)
    assert v.ok, f"{stream.name}: " + "; ".join(v.failures())
    return v


@pytest.mark.parametrize("fixture", GOLDEN)
def test_equivalence_on_the_golden_wire_set(fixture, monkeypatch):
    stream = B.golden_wire_stream(fixture, monkeypatch)
    if stream is None:
        pytest.skip(f"{fixture} produces no signal")
    _assert_equivalent(stream)


@pytest.mark.parametrize("name", sorted(SYNTHETIC))
def test_equivalence_on_the_engine_fixtures(name):
    _assert_equivalent(SYNTHETIC[name]())


def test_the_fixtures_actually_exercise_suppression():
    """A suite whose fixtures collapse nothing proves nothing about collapsing.

    Pinned as a PREMISE, not an outcome: `storm:bench_profile_p2` legitimately
    suppresses 0 % (design §2 — the ratified t-nominal mix pins each device's
    state for life, so K3 has nothing to collapse), which is why the repeat rung
    and the chain fixture exist. If BOTH of those ever stopped collapsing, every
    equivalence check above would still pass and mean nothing.
    """
    for builder, floor in ((B.stream_168, 0.5), (B.stream_chain, 0.25),
                           (B.stream_storm_repeats, 0.15)):
        v = B.compare(builder(), do_replay=False)
        assert float(v.metrics["suppressed_ratio"]) >= floor, (
            f"{v.stream} collapsed {v.metrics['suppressed_ratio']}, "
            f"below the {floor} this fixture exists to exercise")


def test_the_tenancy_probe_is_sharp():
    """The chain fixture's two tenants must genuinely COLLIDE on every AggKey
    component except the tenant — otherwise `tenant_isolation` passing says
    nothing at all."""
    v = B.compare(B.stream_chain(), do_replay=False)
    assert int(v.metrics["colliding_key_suffixes"]) > 0, (
        "the two tenants share no AggKey suffix, so the isolation check is "
        "not testing isolation")


# ═══════════════════════════════════════════════════════════════════════════
# B2. mutation witnesses — the suite must be able to FAIL
# ═══════════════════════════════════════════════════════════════════════════

def test_a_tenant_blind_key_is_caught_by_tenant_isolation(monkeypatch):
    """THE §3a mutant. Drop the tenant from the AggKey and two tenants' states
    merge — a cross-tenant leak at the ingest boundary, upstream of every filter
    the engine has."""
    real_of = aggregation.AggKey.of

    def blind(cls, s, *a, **kw):
        k = real_of(s, *a, **kw)
        return aggregation.AggKey("", k.entity_id, k.kind, k.severity, k.bucket)

    monkeypatch.setattr(aggregation.AggKey, "of", classmethod(blind))
    v = B.compare(B.stream_chain(), do_replay=False)
    ok, detail = v.checks["tenant_isolation"]
    assert not ok, "a tenant-blind AggKey passed the isolation check"
    assert "another tenant's key" in detail


def test_suppressing_a_recovery_is_caught(monkeypatch):
    """THE memo-§17 mutant. Recoveries and state transitions must ALWAYS be
    forwarded synchronously; a plane that absorbs them is the single most
    damaging defect this design can have (an incident that never closes)."""
    def deaf(prev, s, **kw):
        got = delta_class(prev, s, **kw)
        return (DeltaClass.REPEAT
                if got in (DeltaClass.RECOVERY, DeltaClass.STATE_TRANSITION)
                else got)

    monkeypatch.setattr(aggregation, "delta_class", deaf)
    v = B.compare(B.stream_chain(), do_replay=False)
    assert not v.ok, (
        "a plane that swallows recoveries and state transitions passed every "
        f"equivalence check: {v.metrics}")


def test_a_plane_that_suppresses_first_occurrences_is_caught(monkeypatch):
    """The complementary mutant: swallow FIRST and entities vanish from the
    engine entirely — the failure mode `blast_radius` and `raw_coverage` claim
    to detect."""
    def blind_first(prev, s, **kw):
        got = delta_class(prev, s, **kw)
        return DeltaClass.REPEAT if got is DeltaClass.FIRST else got

    monkeypatch.setattr(aggregation, "delta_class", blind_first)
    v = B.compare(B.stream_166(), do_replay=False)
    assert not v.ok, "a plane that drops first occurrences looked equivalent"


# ═══════════════════════════════════════════════════════════════════════════
# housekeeping
# ═══════════════════════════════════════════════════════════════════════════

def test_the_harness_never_shares_attrs_between_the_two_legs():
    """The one way this whole suite could quietly compare a stream with itself.

    `AggPlane.observe` STAMPS its annotation onto the `attrs` dict of the signal
    it is handed. If the two legs shared signal objects, the flag-OFF leg would
    run over pre-annotated evidence and every check would pass for the wrong
    reason.
    """
    stream = B.stream_166()
    B.run_leg(stream, aggregate=True)
    assert not any("agg_key" in s.attrs for s in stream.signals), (
        "the ON leg annotated the stream's own signals in place")
    off = B.run_leg(stream, aggregate=False)
    assert not any("agg_key" in s.attrs for s in off.window)


def test_bench_mode_runs_and_reports(capsys, monkeypatch):
    """`--agg-equivalence` is a deliverable, so it is smoke-tested like one:
    the real entry point, on a real fixture, asserting the §25 table renders and
    that the exit code is the suite's verdict (0 == every property held)."""
    monkeypatch.setattr(
        "sys.argv", ["bench_agg_equivalence.py", "--agg-equivalence",
                     "--fixture", "fx166", "--no-replay"])
    rc = B.main_cli()
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "fixture" in out and "root_caus" in out and AGG_POLICY_VERSION in out
    assert "fx166:bounded-cohort" in out
