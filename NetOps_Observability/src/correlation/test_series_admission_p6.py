# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""P6 PR-C2 — engine stage [2] series admission (flag CORR_SERIES_ADMISSION).

Owner decision 2026-11-07 (NMS_DEVICE_IDENTITY_2026-11-01.md §8): SNMP and a
controller feeding one device keep ONE metric series — the CUSUM key stays
(tenant, entity_id, metric). This file pins what that requires:

  1. one sample per (series, bucket) ACROSS sources — first arrival wins, the
     loser is counted; a source's own samples are always admitted;
  2. same semantics before samples meet — a unit that contradicts the canonical
     table (pinned to the Go producers by parsing their source) is refused and
     counted;
  3. an honest observer — the episode records the sources that fed it; several
     sources make the witness MORE conservative, never less, and one series is
     one witness: with E1 on it never corroborates its own device's controller
     alarm.

Flag OFF must be byte-identical: no source reaches the detector, no attrs key,
no Witness field, no memo-key byte (the golden / replay / p3 / rank_memo suites
run unchanged).
"""
from __future__ import annotations

import asyncio
import itertools
import json
import os
import re
import subprocess  # nosec B404 — runs this interpreter on a fixed argv, no shell
import sys
from dataclasses import replace as dc_replace
from datetime import datetime, timedelta, timezone

import pytest

import main
import rank_memo
import signals
from counter_rate import CUMULATIVE_METRICS, CounterRates
from episodes import MAX_RUN_SOURCES, MAX_SOURCE_LEN, EpisodeDetector, EpisodeEvent
from producers import episode_signal
from series_admission import COUNTER, SERIES_SEMANTICS, unit_contradicts
from signals import (
    ORIGIN_DEVICE_ATTR,
    SERIES_SOURCES_ATTR,
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Source,
    set_origin_observer,
    set_series_admission,
)
from test_verdicts import make_signal
from verdicts import (
    VerdictTier,
    assess,
    authority_of_path,
    conservative_collection_path,
    coverage,
    witness_of,
)

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.join(HERE, "..", "backend")
GO_SNMP = os.path.join(BACKEND, "collectors", "metric_events.go")
GO_VMANAGE = os.path.join(BACKEND, "nms", "vmanage_realtime.go")
GNMIC = os.path.join(HERE, "..", "..", "deployment", "docker", "gnmic", "gnmic-correlation.yaml")

T0 = datetime(2026, 11, 7, 12, 0, 0, tzinfo=timezone.utc)   # a bucket boundary for 60 s
DEVICE = "vedge-20-1e95f00f"
SNMP, CTL, GNMI = "snmp_poll", "via_controller", "gnmi_subscribe"


@pytest.fixture(autouse=True)
def _restore_flags():
    prev = (signals.series_admission_enabled(), signals.series_bucket_s(), signals.origin_observer_enabled())
    yield
    set_series_admission(prev[0], prev[1])
    set_origin_observer(prev[2])


@pytest.fixture
def admission_on():
    set_series_admission(True, 60.0)
    yield


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def warm(det: EpisodeDetector, n: int = 20, *, source: str | None = SNMP, start: float = 0.0) -> float:
    """n baseline samples, one per 60 s bucket (alternating 20/21: mean 20.5,
    σ≈0.51). Returns the next free time."""
    t = start
    for i in range(n):
        kw = {"source": source} if source is not None else {}
        assert det.observe("t", DEVICE, "device_cpu_percent", at(t), 20.0 + (i % 2), **kw) is None
        t += 60.0
    return t


# ── the flag ──────────────────────────────────────────────────────────────────

def test_flag_defaults_off_in_a_clean_process() -> None:
    env = {k: v for k, v in os.environ.items() if k not in ("CORR_SERIES_ADMISSION", "CORR_SERIES_BUCKET_S")}
    out = subprocess.run(  # nosec B603 — fixed argv, this interpreter
        [sys.executable, "-c",
         ("import signals; print(signals.series_admission_enabled(), signals.series_bucket_s(), "
          "signals.series_bucket_env_valid())")],
        cwd=HERE, env=env, capture_output=True, text=True, timeout=60, check=True)
    assert out.stdout.split() == ["False", "60.0", "True"], out.stdout + out.stderr


@pytest.mark.parametrize("raw,expected", [
    (None, (60.0, True)), ("", (60.0, True)), ("30", (30.0, True)), (" 120.5 ", (120.5, True)),
    ("abc", (60.0, False)), ("0", (60.0, False)), ("-5", (60.0, False)), ("nan", (60.0, False)),
    ("inf", (60.0, False)), ("3601", (60.0, False)),
])
def test_bucket_env_is_validated(raw, expected) -> None:
    assert signals._parse_series_bucket(raw) == expected


def test_the_test_hook_refuses_a_bad_bucket() -> None:
    with pytest.raises(ValueError):
        set_series_admission(True, 0.0)


def test_detector_refuses_a_non_positive_bucket() -> None:
    with pytest.raises(ValueError):
        EpisodeDetector().observe("t", DEVICE, "m", at(0), 1.0, source=SNMP, bucket_s=0.0)


# ── 1. one sample per (series, bucket) across sources ─────────────────────────

def test_two_sources_in_one_bucket_admit_one_and_count_one() -> None:
    det = EpisodeDetector()
    det.observe("t", DEVICE, "device_cpu_percent", at(5), 20.0, source=SNMP)
    det.observe("t", DEVICE, "device_cpu_percent", at(35), 99.0, source=CTL)
    st = det._state[("t", DEVICE, "device_cpu_percent")]
    assert det.cross_source_dropped == 1
    assert list(st.values) == [20.0], "the loser must not reach the baseline"
    assert st.last_ts == at(5), "the loser must not move the interval estimate"


def test_the_first_arrival_wins_whichever_source_it_is() -> None:
    det = EpisodeDetector()
    det.observe("t", DEVICE, "device_cpu_percent", at(35), 20.0, source=CTL)
    det.observe("t", DEVICE, "device_cpu_percent", at(5), 21.0, source=SNMP)   # same bucket, later arrival
    assert det.cross_source_dropped == 1
    assert list(det._state[("t", DEVICE, "device_cpu_percent")].values) == [20.0]


def test_a_sources_own_samples_in_one_bucket_are_all_admitted() -> None:
    det = EpisodeDetector()
    for s in (1, 20, 40, 59):          # one source, jittered — never a duplicate
        det.observe("t", DEVICE, "device_cpu_percent", at(s), 20.0 + s, source=SNMP)
    assert det.cross_source_dropped == 0
    assert len(det._state[("t", DEVICE, "device_cpu_percent")].values) == 4


def test_the_bucket_boundary() -> None:
    det = EpisodeDetector()
    det.observe("t", DEVICE, "m", at(59.999), 1.0, source=SNMP)      # bucket 0
    det.observe("t", DEVICE, "m", at(60.0), 2.0, source=CTL)         # bucket 1: a new bucket → admitted
    assert det.cross_source_dropped == 0
    det.observe("t", DEVICE, "m", at(61.0), 3.0, source=SNMP)        # bucket 1 is CTL's now → dropped
    assert det.cross_source_dropped == 1
    det.observe("t", DEVICE, "m", at(120.0), 4.0, source=SNMP)       # bucket 2 → admitted
    assert det.cross_source_dropped == 1
    assert list(det._state[("t", DEVICE, "m")].values) == [1.0, 2.0, 4.0]


def test_a_bucket_width_other_than_60s() -> None:
    det = EpisodeDetector()
    det.observe("t", DEVICE, "m", at(5), 1.0, source=SNMP, bucket_s=300.0)
    det.observe("t", DEVICE, "m", at(200), 2.0, source=CTL, bucket_s=300.0)   # same 300 s bucket
    assert det.cross_source_dropped == 1


def test_a_late_sample_from_another_source_for_an_earlier_bucket_is_dropped() -> None:
    det = EpisodeDetector()
    det.observe("t", DEVICE, "m", at(130), 1.0, source=SNMP)    # bucket 2
    det.observe("t", DEVICE, "m", at(70), 2.0, source=CTL)      # bucket 1, arrives late
    assert det.cross_source_dropped == 1


def test_failover_a_second_source_takes_over_when_the_first_goes_quiet() -> None:
    det = EpisodeDetector()
    det.observe("t", DEVICE, "m", at(5), 1.0, source=SNMP)
    for b in range(1, 5):                                       # SNMP silent, controller continues
        det.observe("t", DEVICE, "m", at(60 * b + 30), 1.0, source=CTL)
    assert det.cross_source_dropped == 0
    assert len(det._state[("t", DEVICE, "m")].values) == 5


def test_series_are_independent_and_tenants_never_share_a_bucket() -> None:
    det = EpisodeDetector()
    det.observe("t", DEVICE, "m", at(5), 1.0, source=SNMP)
    det.observe("u", DEVICE, "m", at(6), 1.0, source=CTL)       # other tenant
    det.observe("t", DEVICE, "m2", at(7), 1.0, source=CTL)      # other metric
    det.observe("t", "other", "m", at(8), 1.0, source=CTL)      # other entity
    assert det.cross_source_dropped == 0


def test_source_none_is_the_legacy_path_and_never_drops() -> None:
    det = EpisodeDetector()
    for i in range(10):
        det.observe("t", DEVICE, "m", at(i), float(i))
    assert det.cross_source_dropped == 0
    assert len(det._state[("t", DEVICE, "m")].values) == 10


def test_off_the_event_stream_is_identical_to_the_legacy_detector() -> None:
    """OFF = source None. The same stream must produce the same events, field
    for field, as a detector that never heard of admission."""
    vals = [20.0 + (i % 2) for i in range(25)] + [30.0] * 6 + [20.5] * 6 + [20.0 + (i % 2) for i in range(10)]
    a, b, ea, eb = EpisodeDetector(), EpisodeDetector(), [], []
    for i, v in enumerate(vals):
        ea.append(a.observe("t", DEVICE, "m", at(60 * i), v))
        eb.append(b.observe("t", DEVICE, "m", at(60 * i), v, "unknown", source=None))
    assert ea == eb
    assert any(e is not None and e.phase == "onset" for e in ea)
    assert all(e is None or e.sources == frozenset() for e in ea)


def test_the_lru_bound_still_holds_and_carries_the_admission_state() -> None:
    det = EpisodeDetector(max_series=3)
    for i in range(10):
        det.observe("t", f"e{i}", "m", at(5), 1.0, source=SNMP)
    assert len(det._state) == 3
    assert det.evicted == 7
    # The state lives in the evicted series: a re-created series starts over and
    # its first sample is admitted whatever the source.
    det.observe("t", "e0", "m", at(6), 1.0, source=CTL)
    assert det.cross_source_dropped == 0


def test_source_strings_are_bounded() -> None:
    det = EpisodeDetector()
    det.observe("t", DEVICE, "m", at(5), 1.0, source="x" * 10_000)
    assert len(det._state[("t", DEVICE, "m")].adm_source) == MAX_SOURCE_LEN


# ── which sources fed the episode ─────────────────────────────────────────────

def _run_to_onset(det: EpisodeDetector, t: float, steps: list[tuple[str, float]]) -> tuple[EpisodeEvent, float]:
    ev = None
    for src, v in steps:
        ev = det.observe("t", DEVICE, "device_cpu_percent", at(t), v, source=src)
        t += 60.0
    assert ev is not None and ev.phase == "onset", ev
    return ev, t


def test_a_single_source_episode_records_that_source() -> None:
    det = EpisodeDetector()
    t = warm(det)
    ev, _ = _run_to_onset(det, t, [(SNMP, 22.0), (SNMP, 22.0)])
    assert ev.sources == frozenset({SNMP})


def test_a_run_fed_by_two_sources_records_both() -> None:
    det = EpisodeDetector()
    t = warm(det)
    ev, _ = _run_to_onset(det, t, [(CTL, 22.0), (SNMP, 22.0)])
    assert ev.sources == frozenset({SNMP, CTL})


def test_baseline_samples_outside_the_run_do_not_count_as_feeding_it() -> None:
    det = EpisodeDetector()
    t = warm(det, source=CTL)                 # a controller-fed baseline …
    ev, _ = _run_to_onset(det, t, [(SNMP, 22.0), (SNMP, 22.0)])
    assert ev.sources == frozenset({SNMP}), "… did not feed the SNMP run that opened the episode"


def test_the_clear_records_the_run_and_the_open_period_then_resets() -> None:
    det = EpisodeDetector()
    t = warm(det)
    _ev, t = _run_to_onset(det, t, [(SNMP, 22.0), (SNMP, 22.0)])
    clear = None
    for src in (GNMI, SNMP, SNMP, SNMP):
        clear = det.observe("t", DEVICE, "device_cpu_percent", at(t), 20.5, source=src) or clear
        t += 60.0
    assert clear is not None and clear.phase == "clear"
    assert clear.sources == frozenset({SNMP, GNMI})
    assert det._state[("t", DEVICE, "device_cpu_percent")].run_sources == ()


def test_recorded_sources_are_bounded() -> None:
    det = EpisodeDetector()
    t = warm(det)
    det.observe("t", DEVICE, "device_cpu_percent", at(t), 22.0, source="p0")
    st = det._state[("t", DEVICE, "device_cpu_percent")]
    for i in range(1, 40):
        EpisodeDetector._note_source(st, f"p{i}")
    assert len(st.run_sources) == MAX_RUN_SOURCES


# ── 2. same semantics before samples meet ─────────────────────────────────────

def _go_block(src: str, start: str) -> str:
    block = src[src.index(start):]
    return block[:block.index("\n}\n")]


def test_the_table_equals_the_go_snmp_allowlist() -> None:
    """Parses `rcaMetricFamilies` (collectors/metric_events.go): name → {family, unit}."""
    with open(GO_SNMP, encoding="utf-8") as fh:
        block = _go_block(fh.read(), "var rcaMetricFamilies")
    pairs = re.findall(r'"(device_[a-z0-9_]+)":\s*\{"([a-z_]+)",\s*"([a-z_]+)"\}', block)
    assert len(pairs) > 15, "parsed too few families — the regex rotted"
    go = {name: (fam, unit) for name, fam, unit in pairs}
    py = {name: (s.family, s.unit) for name, s in SERIES_SEMANTICS.items()}
    assert py == go


def test_the_table_agrees_with_every_unit_vmanage_realtime_stamps() -> None:
    """vManage's realtime lane (nms/vmanage_realtime.go) keeps its OWN family
    map (`canonicalDeviceMetrics`, pinned to the SNMP allowlist only by family)
    and stamps units as literals in each transform. Both are parsed: every
    family must match, and every literal unit must equal the table's."""
    with open(GO_VMANAGE, encoding="utf-8") as fh:
        src = fh.read()
    fams = dict(re.findall(r'"(device_[a-z0-9_]+)":\s*"([a-z_]+)"', _go_block(src, "var canonicalDeviceMetrics")))
    assert len(fams) >= 10, "parsed too few controller families — the regex rotted"
    for name, fam in fams.items():
        assert name in SERIES_SEMANTICS, f"vManage emits {name}, which no RCA family declares"
        assert SERIES_SEMANTICS[name].family == fam, name
    units: dict[str, set[str]] = {}
    for name, unit in re.findall(r'\bm\("(device_[a-z0-9_]+)",[^"\n]*"([a-z_]+)"\)', src):
        units.setdefault(name, set()).add(unit)
    for name, unit in re.findall(r'vmMetric\([^"\n]*"(device_[a-z0-9_]+)",[^"\n]*"([a-z_]+)",', src):
        units.setdefault(name, set()).add(unit)
    assert set(units) == set(fams), f"every controller family must be stamped somewhere: {set(fams) ^ set(units)}"
    for name, seen in units.items():
        assert seen == {SERIES_SEMANTICS[name].unit}, f"{name}: vManage stamps {seen}"


def test_the_table_agrees_with_the_gnmi_shaper() -> None:
    with open(GNMIC, encoding="utf-8") as fh:
        text = fh.read()
    rows = re.findall(r'"(device_[a-z0-9_]+)":\s*\{"f":"([a-z_]+)","u":"([a-z_]+)"\}', text)
    assert len(rows) > 15, "parsed too few gNMI rows — the regex rotted"
    assert {n: (f, u) for n, f, u in rows} == {n: (s.family, s.unit) for n, s in SERIES_SEMANTICS.items()}


def test_counter_semantics_equal_the_counter_rate_set() -> None:
    assert {n for n, s in SERIES_SEMANTICS.items() if s.semantics == COUNTER} == set(CUMULATIVE_METRICS)


@pytest.mark.parametrize("metric,unit,contradicts", [
    ("device_cpu_percent", "percent", False),
    ("device_cpu_percent", " Percent ", False),       # spelling is not semantics
    ("device_cpu_percent", None, False),              # a legacy producer declares nothing
    ("device_cpu_percent", "", False),
    ("device_cpu_percent", "ratio", True),
    ("device_if_in_octets", "bytes", False),
    ("device_if_in_octets", "bps", True),             # a rate where a counter is declared
    ("device_if_speed", "bps", True),
    ("device_cpu_percent", 100, True),                # zero trust: not even text
    ("not_an_rca_family", "anything", False),         # no opinion outside the table
])
def test_unit_contradicts(metric, unit, contradicts) -> None:
    assert unit_contradicts(metric, unit) is contradicts


# ── end to end through handle_metric ──────────────────────────────────────────

class _Rows:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    async def batch(self, row: dict) -> None:
        self.rows.append(row)


@pytest.fixture
def lane(monkeypatch):
    """handle_metric with a fresh detector, a captured spine and no window."""
    sink = _Rows()
    monkeypatch.setattr(main, "DETECTOR", EpisodeDetector())
    monkeypatch.setattr(main, "ch", object())
    monkeypatch.setattr(main, "CORR_SIGNALS_ENABLED", True)
    monkeypatch.setattr(main, "batch_signal", sink.batch)
    monkeypatch.setattr(main, "agg_admit", lambda sig: None)
    monkeypatch.setattr(main, "score", lambda *a, **k: None)
    monkeypatch.setattr(main, "verified_tenant", lambda claim, device, lane_, **k: "t1")
    monkeypatch.setattr(main, "METRICS_SERIES_UNIT_REJECTED", 0)
    return sink


def metric_ev(ts: datetime, value: float, path: str, unit: str | None = "percent",
              metric: str = "device_cpu_percent") -> dict:
    ev = {"metric": metric, "value": value, "device": DEVICE, "signal_family": "device_resource",
          "collection_path": path, "tenant_id": "t1", "ts": ts.isoformat()}
    if unit is not None:
        ev["unit"] = unit
    return ev


def recent(bucket_offset: int, second: float) -> datetime:
    """A time inside the metric lane's age window, on a 60 s bucket grid."""
    now = datetime.now(timezone.utc)
    base = datetime.fromtimestamp((int(now.timestamp()) // 60 - 50) * 60, tz=timezone.utc)
    return base + timedelta(seconds=60 * bucket_offset + second)


def test_on_two_sources_in_one_bucket_reach_the_series_once_and_are_counted(lane, admission_on) -> None:
    asyncio.run(_test_on_two_sources_in_one_bucket_reach_the_series_once_and_are_counted())


async def _test_on_two_sources_in_one_bucket_reach_the_series_once_and_are_counted() -> None:
    await main.handle_metric(metric_ev(recent(0, 5), 20.0, SNMP))
    await main.handle_metric(metric_ev(recent(0, 35), 20.0, CTL))
    assert main.DETECTOR.cross_source_dropped == 1
    health = main._health_payload()["ingest"]
    assert health["series_cross_source_dropped"] == 1
    text = main._metrics_text(main._health_payload())
    assert "corr_series_cross_source_dropped_total 1" in text
    assert 'corr_ingest_events{counter="series_cross_source_dropped"} 1' in text
    assert "corr_series_admission_enabled 1" in text


def test_off_both_sources_reach_the_series(lane) -> None:
    asyncio.run(_test_off_both_sources_reach_the_series())


async def _test_off_both_sources_reach_the_series() -> None:
    await main.handle_metric(metric_ev(recent(0, 5), 20.0, SNMP))
    await main.handle_metric(metric_ev(recent(0, 35), 20.0, CTL))
    assert main.DETECTOR.cross_source_dropped == 0
    assert len(main.DETECTOR._state[("t1", DEVICE, "device_cpu_percent")].values) == 2


def test_on_a_unit_mismatch_is_rejected_and_counted(lane, admission_on) -> None:
    asyncio.run(_test_on_a_unit_mismatch_is_rejected_and_counted())


async def _test_on_a_unit_mismatch_is_rejected_and_counted() -> None:
    await main.handle_metric(metric_ev(recent(0, 5), 0.2, CTL, unit="ratio"))
    assert main.METRICS_SERIES_UNIT_REJECTED == 1
    assert ("t1", DEVICE, "device_cpu_percent") not in main.DETECTOR._state, "never averaged in"
    assert main._health_payload()["ingest"]["series_unit_rejected"] == 1


def test_on_a_unit_mismatch_never_seeds_a_counter_base(lane, admission_on, monkeypatch) -> None:
    monkeypatch.setattr(main, "COUNTER_RATES", CounterRates())
    asyncio.run(_test_on_a_unit_mismatch_never_seeds_a_counter_base())


async def _test_on_a_unit_mismatch_never_seeds_a_counter_base() -> None:
    await main.handle_metric({**metric_ev(recent(0, 5), 1e9, SNMP, unit="bits", metric="device_if_in_octets"),
                              "signal_family": "interface", "if_name": "ge0/0"})
    assert len(main.COUNTER_RATES) == 0
    assert main.METRICS_SERIES_UNIT_REJECTED == 1


def test_off_a_unit_mismatch_is_fed_as_before(lane) -> None:
    asyncio.run(_test_off_a_unit_mismatch_is_fed_as_before())


async def _test_off_a_unit_mismatch_is_fed_as_before() -> None:
    await main.handle_metric(metric_ev(recent(0, 5), 0.2, CTL, unit="ratio"))
    assert main.METRICS_SERIES_UNIT_REJECTED == 0
    assert len(main.DETECTOR._state[("t1", DEVICE, "device_cpu_percent")].values) == 1


async def _drive_two_source_onset(path_order: tuple[str, str]) -> None:
    for i in range(20):
        await main.handle_metric(metric_ev(recent(i, 5), 20.0 + (i % 2), SNMP))
        await main.handle_metric(metric_ev(recent(i, 35), 20.0 + (i % 2), CTL))   # dropped: SNMP owns it
    first, second = path_order
    await main.handle_metric(metric_ev(recent(20, 30), 22.0, first))
    await main.handle_metric(metric_ev(recent(21, 30), 22.0, second))             # this sample trips it


def test_on_the_spine_row_names_every_source_and_the_conservative_path(lane, admission_on) -> None:
    asyncio.run(_test_on_the_spine_row_names_every_source_and_the_conservative_path(lane))


async def _test_on_the_spine_row_names_every_source_and_the_conservative_path(lane: _Rows) -> None:
    """The tripping sample is SNMP's; the run also carried a controller sample.
    The observer path must not be "whichever sample tripped it"."""
    await _drive_two_source_onset((CTL, SNMP))
    onsets = [r for r in lane.rows if r["kind"] == "device_resource_anomaly"]
    assert len(onsets) == 1, lane.rows
    row = onsets[0]
    attrs = row["attrs"] if isinstance(row["attrs"], dict) else json.loads(row["attrs"])
    assert attrs[SERIES_SOURCES_ATTR] == sorted([SNMP, CTL])
    assert row["collection_path"] == CTL
    assert main.DETECTOR.cross_source_dropped == 20


def test_off_the_spine_row_is_the_legacy_row(lane) -> None:
    asyncio.run(_test_off_the_spine_row_is_the_legacy_row(lane))


async def _test_off_the_spine_row_is_the_legacy_row(lane: _Rows) -> None:
    await _drive_two_source_onset((CTL, SNMP))
    rows = [r for r in lane.rows if r["kind"] == "device_resource_anomaly"]
    assert rows, "with interleaved sources the OFF series still opens an episode"
    for row in rows:
        attrs = row["attrs"] if isinstance(row["attrs"], dict) else json.loads(row["attrs"])
        assert SERIES_SOURCES_ATTR not in attrs


# ── 3. the honest observer ────────────────────────────────────────────────────

def _event(sources: frozenset[str] = frozenset()) -> EpisodeEvent:
    return EpisodeEvent(phase="onset", key=("t1", DEVICE, "device_cpu_percent"), onset_ts=T0,
                        onset_uncertainty_s=60.0, value=95.0, baseline=20.0, deviation=9.0,
                        peak_deviation=9.0, integral=500.0, sources=sources)


def _obs(path: str) -> Observer:
    return Observer(observer_id=DEVICE, observer_type=ObserverType.DEVICE, collection_path=path)


def _episode(sources: frozenset[str], path: str = SNMP, origin: str | None = None):
    sig = episode_signal(_event(sources), _obs(path), entity_type=EntityType.DEVICE,
                         kind_prefix="device_resource_anomaly", entity_tokens=(DEVICE,))
    if origin:
        sig = dc_replace(sig, attrs={**sig.attrs, ORIGIN_DEVICE_ATTR: origin})
    return sig


def test_no_sources_means_the_legacy_signal_byte_for_byte() -> None:
    legacy = episode_signal(EpisodeEvent(phase="onset", key=("t1", DEVICE, "device_cpu_percent"), onset_ts=T0,
                                         onset_uncertainty_s=60.0, value=95.0, baseline=20.0, deviation=9.0,
                                         peak_deviation=9.0, integral=500.0),
                            _obs(SNMP), entity_type=EntityType.DEVICE, kind_prefix="device_resource_anomaly",
                            entity_tokens=(DEVICE,))
    assert _episode(frozenset()).to_ch_row() == legacy.to_ch_row()
    assert SERIES_SOURCES_ATTR not in legacy.attrs


def test_a_single_source_is_recorded_and_the_observer_is_untouched() -> None:
    sig = _episode(frozenset({SNMP}))
    assert sig.attrs[SERIES_SOURCES_ATTR] == [SNMP]
    assert sig.observer.collection_path == SNMP


@pytest.mark.parametrize("tripping", [SNMP, CTL, GNMI])
def test_several_sources_name_the_conservative_path_whatever_tripped(tripping) -> None:
    sig = _episode(frozenset({SNMP, CTL, GNMI}), path=tripping)
    assert sig.attrs[SERIES_SOURCES_ATTR] == sorted([SNMP, CTL, GNMI])
    assert sig.observer.collection_path == CTL
    assert sig.signal_id == _episode(frozenset({SNMP, CTL, GNMI}), path=SNMP).signal_id, \
        "identity is content, never the observer"


@pytest.mark.parametrize("paths,expected", [
    ({SNMP, CTL}, CTL),
    ({"direct", SNMP}, SNMP),                         # an unrecognised path is its own bucket: before transport
    ({"direct", "via_aggregator"}, "direct"),
    ({"via_cloud_api", CTL}, "via_cloud_api"),         # two authorities: by name, deterministic
    ({"via_controller:ci-1", SNMP}, "via_controller:ci-1"),
    (set(), "direct"),
])
def test_conservative_collection_path(paths, expected) -> None:
    assert conservative_collection_path(paths) == expected


def test_off_the_witness_and_the_memo_key_ignore_series_sources() -> None:
    multi, single = _episode(frozenset({SNMP, CTL}), path=CTL), _episode(frozenset(), path=CTL)
    assert witness_of(multi).series_authorities == frozenset()
    assert rank_memo.signal_projection(multi)[-1] == rank_memo.signal_projection(single)[-1]


def test_on_the_witness_sits_in_every_sources_bucket(admission_on) -> None:
    w = witness_of(_episode(frozenset({SNMP, CTL, "direct"})))
    assert w.authority == CTL
    assert w.series_authorities == frozenset({CTL, "unknown:snmp_poll"})


def test_on_the_memo_key_carries_the_buckets(admission_on) -> None:
    a = rank_memo.signal_projection(_episode(frozenset({SNMP, CTL})))
    b = rank_memo.signal_projection(_episode(frozenset({CTL})))
    assert a != b


def _pool():
    other_dev_snmp = make_signal("leaf9", ModalityClass.CONTROL_PLANE, source=Source.TRAP,
                                 collection_path=SNMP, kind="link_state_change")
    ctl_alarm = make_signal("vmanage:nmsi-1", ModalityClass.MANAGEMENT_PLANE, source=Source.CONTROLLER,
                            collection_path=CTL, observer_type=ObserverType.CONTROLLER, kind="link_state_change")
    syslog = make_signal("vEdge-20", ModalityClass.CONTROL_PLANE, source=Source.SYSLOG, kind="link_state_change")
    cloud = make_signal("aws:acct", ModalityClass.MANAGEMENT_PLANE, source=Source.CLOUD,
                        collection_path="via_cloud_api", kind="cloud_resource_anomaly")
    return [other_dev_snmp, ctl_alarm, syslog, cloud]


def test_a_single_chosen_path_alone_would_not_be_downgrade_only(admission_on) -> None:
    """Why the witness takes EVERY bucket: naming via_controller alone would lift
    the episode OUT of the shared snmp_poll bucket and make it independent of
    another device's SNMP evidence — an upgrade. The union keeps it dependent."""
    other = witness_of(_pool()[0])
    sources = frozenset({SNMP, CTL})
    as_snmp = witness_of(_episode(frozenset(), path=SNMP))
    as_ctl_only = witness_of(_episode(frozenset(), path=CTL))
    honest = witness_of(_episode(sources))
    assert not as_snmp.independent_of(other)
    assert as_ctl_only.independent_of(other), "the naive single path upgrades"
    assert not honest.independent_of(other) and not other.independent_of(honest)


@pytest.mark.parametrize("sources", [frozenset({SNMP, CTL}), frozenset({SNMP, GNMI}),
                                     frozenset({"direct", CTL}), frozenset({SNMP, CTL, "via_cloud_api"})])
def test_on_multi_source_never_creates_independence(admission_on, sources) -> None:
    """Downgrade-only, for every path the tripping sample could have had."""
    honest = witness_of(_episode(sources))
    for other_sig in _pool():
        other = witness_of(other_sig)
        if honest.independent_of(other) or other.independent_of(honest):
            for p in sources:
                set_series_admission(False)
                legacy = witness_of(_episode(frozenset(), path=p))
                set_series_admission(True, 60.0)
                assert legacy.independent_of(other), f"{sources} vs {other_sig.observer}: upgraded over {p}"


def test_on_the_verdict_never_rises_over_any_tripping_path(admission_on) -> None:
    rank = {VerdictTier.UNDETERMINED: 0, VerdictTier.SUSPECTED: 1, VerdictTier.CONFIRMED: 2}
    sources = frozenset({SNMP, CTL})
    for r in (1, 2):
        for combo in itertools.combinations(_pool(), r):
            on = assess([_episode(sources), *combo]).tier
            for p in sources:
                set_series_admission(False)
                off = assess([_episode(frozenset(), path=p), *combo]).tier
                set_series_admission(True, 60.0)
                assert rank[on] <= rank[off], f"{combo}: {off} → {on} over {p}"


def test_on_fate_groups_show_the_shared_buckets(admission_on) -> None:
    cov = coverage([_episode(frozenset({SNMP, CTL})), _pool()[0], _pool()[1]])
    assert tuple(sorted((DEVICE, "leaf9", "vmanage:nmsi-1"))) in cov.fate_groups


def test_authority_of_path_matches_the_legacy_taxonomy() -> None:
    assert authority_of_path("direct") is None
    assert authority_of_path("") is None
    assert authority_of_path("via_aggregator") is None
    assert authority_of_path("via_controller") == "via_controller"
    assert authority_of_path("Via_Controller:CI-1 ") == "via_controller:ci-1"
    assert authority_of_path("snmp_poll") == "unknown:snmp_poll"


# ── E1: one series is ONE witness ─────────────────────────────────────────────

def _ctl_alarm_about(origin: str):
    return make_signal("vmanage:nmsi-1", ModalityClass.MANAGEMENT_PLANE, source=Source.CONTROLLER,
                       collection_path=CTL, observer_type=ObserverType.CONTROLLER, kind="link_state_change",
                       attrs={ORIGIN_DEVICE_ATTR: origin})


def test_e1_a_multi_source_episode_never_pairs_with_its_own_devices_controller_alarm(admission_on) -> None:
    set_origin_observer(True)
    for sources in (frozenset({SNMP, CTL}), frozenset({SNMP, GNMI}), frozenset({CTL})):
        for path in sources:
            ep = _episode(sources, path=path, origin=DEVICE)
            alarm = _ctl_alarm_about(DEVICE)
            a, b = witness_of(ep), witness_of(alarm)
            assert not a.independent_of(b) and not b.independent_of(a), (sources, path)
            assert coverage([ep, alarm]).independent_pair is None
            assert assess([ep, alarm]).tier is not VerdictTier.CONFIRMED


def test_e1_is_what_stops_a_controller_free_multi_source_episode_corroborating_its_own_syslog(admission_on) -> None:
    """{snmp_poll, gnmi_subscribe} shares no bucket with the device's syslog
    (observer = hostname, direct): only the origin rule makes them one box."""
    ep = _episode(frozenset({SNMP, GNMI}), origin=DEVICE)
    syslog = make_signal("vEdge-20", ModalityClass.CONTROL_PLANE, source=Source.SYSLOG, kind="link_state_change",
                         attrs={ORIGIN_DEVICE_ATTR: DEVICE})
    set_origin_observer(False)
    assert witness_of(ep).independent_of(witness_of(syslog)), "pins the over-count E1 exists to close"
    set_origin_observer(True)
    assert not witness_of(ep).independent_of(witness_of(syslog))
    assert assess([ep, syslog]).tier is not VerdictTier.CONFIRMED


def test_e1_two_different_devices_stay_two_witnesses(admission_on) -> None:
    set_origin_observer(True)
    ep = _episode(frozenset({SNMP, GNMI}), origin=DEVICE)
    syslog = make_signal("cEDGE-40", ModalityClass.CONTROL_PLANE, source=Source.SYSLOG, kind="link_state_change",
                         attrs={ORIGIN_DEVICE_ATTR: "cedge-40-b99e47eb"})
    assert witness_of(ep).independent_of(witness_of(syslog))
