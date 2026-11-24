# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""ENGINE_SEMVER 3.7.0 — volume is context; the interface kind split (owner 2026-11-24).

Stage [1]: an interface episode's kind says WHAT moved — octets are traffic
volume (`if_metric_anomaly`), errors / discards / FCS / oper-admin status are
`if_errors` / `if_discards` / `if_crc` / `if_state_anomaly`, and interface speed is
collected but never scored. Volume episodes are capped at warn.
Stage [5]: a component made only of traffic-volume kinds opens no object — the
evidence stays, and a real fault on the same port folds it in.
"""
from __future__ import annotations

import asyncio
import unittest
from datetime import datetime, timedelta, timezone

import engine as E
import main
from catalog import builtin_catalog
from counter_rate import CounterRates
from engine import EngineConfig, run_window
from episodes import EpisodeEvent
from producers import (
    INTERFACE_METRIC_KINDS,
    UNSCORED_INTERFACE_METRICS,
    VOLUME_KINDS,
    episode_signal,
    interface_metric_kind,
)
from series_admission import SERIES_SEMANTICS
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

T0 = datetime(2026, 11, 24, 10, 0, 0, tzinfo=timezone.utc)
LOCAL = "sig.ent.access.local-link-fault"


# ── stage [1]: the kind split ───────────────────────────────────────────────────

def test_interface_metric_kinds():
    assert interface_metric_kind("device_if_in_octets") == "if_metric_anomaly"
    assert interface_metric_kind("device_if_out_octets") == "if_metric_anomaly"
    assert interface_metric_kind("device_if_in_errors") == "if_errors"
    assert interface_metric_kind("device_if_out_errors") == "if_errors"
    assert interface_metric_kind("device_if_in_discards") == "if_discards"
    assert interface_metric_kind("device_if_out_discards") == "if_discards"
    assert interface_metric_kind("device_if_fcs_errors") == "if_crc"
    assert interface_metric_kind("device_if_oper_status") == "if_state_anomaly"
    assert interface_metric_kind("device_if_admin_status") == "if_state_anomaly"
    assert interface_metric_kind("some_vendor_if_metric") == "if_metric_anomaly"  # legacy


def test_every_interface_family_has_a_kind_or_is_explicitly_unscored():
    iface = {m for m, s in SERIES_SEMANTICS.items() if s.family == "interface"}
    undecided = sorted(iface - set(INTERFACE_METRIC_KINDS) - UNSCORED_INTERFACE_METRICS)
    assert undecided == [], f"map these to a kind or list them unscored: {undecided}"
    assert UNSCORED_INTERFACE_METRICS == {"device_if_speed"}


def _ev(peak: float) -> EpisodeEvent:
    return EpisodeEvent(phase="onset", key=("t1", "cedge-80:Gi1", "m"), onset_ts=T0,
                        onset_uncertainty_s=30.0, value=1.0, baseline=0.0,
                        deviation=peak, peak_deviation=peak, integral=10.0)


def test_volume_episodes_are_capped_at_warn_and_faults_are_not():
    obs = Observer(observer_id="cedge-80", observer_type=ObserverType.DEVICE)
    for kind in sorted(VOLUME_KINDS):
        sig = episode_signal(_ev(40.0), obs, entity_type=EntityType.INTERFACE, kind_prefix=kind)
        assert sig.severity is Severity.WARN, kind
    sig = episode_signal(_ev(40.0), obs, entity_type=EntityType.INTERFACE, kind_prefix="if_errors")
    assert sig.severity is Severity.CRIT


# ── stage [5]: a volume-only component opens nothing ──────────────────────────

def _sig(kind: str, eid: str, *, off: float = 0.0, sev: Severity = Severity.HIGH,
         modality: ModalityClass = ModalityClass.DEVICE_TELEMETRY,
         source: Source = Source.METRIC, observer: str = "cedge-80") -> Signal:
    return Signal(
        tenant_id="t1", ts=T0 + timedelta(seconds=off), source=source, kind=kind,
        observer=Observer(observer_id=observer, observer_type=ObserverType.DEVICE),
        modality_class=modality, entity_type=EntityType.INTERFACE, entity_id=eid,
        severity=sev, native_id=f"t37v|{kind}|{eid}|{off}", entity_tokens=(eid.split(":")[0],))


def test_a_volume_only_component_opens_no_object_even_when_grounded():
    # Two octet episodes on two ports of ONE box ground by containment (an edge),
    # at HIGH severity (pre-cap evidence): still no object, and it is counted.
    ev = [_sig("if_metric_anomaly", "cedge-80:Gi4.200"),
          _sig("if_metric_anomaly", "cedge-80:Gi1", off=5),
          _sig("flow_volume_anomaly", "cedge-80:Gi1", off=8, modality=ModalityClass.PASSIVE_FLOW,
               source=Source.FLOW)]
    before = E.volume_context_singletons_total()
    assert run_window(ev, builtin_catalog(), (), EngineConfig()) == []
    assert E.volume_context_singletons_total() == before + 1


def test_volume_beside_a_real_fault_folds_in_as_context():
    ev = [_sig("link_state_change", "cedge-80:Gi1", modality=ModalityClass.CONTROL_PLANE,
               source=Source.TRAP, observer="cedge-80-trap"),
          _sig("if_metric_anomaly", "cedge-80:Gi1", off=5)]
    snaps = run_window(ev, builtin_catalog(), (), EngineConfig())
    assert len(snaps) == 1
    kinds = sorted(n.kind for n in snaps[0].nodes)
    assert kinds == ["if_metric_anomaly", "link_state_change"]
    local = {h.template_id: h for h in snaps[0].ranking.hypotheses}[LOCAL]
    assert abs(local.confidence_rank - 0.55) < 1e-9          # link + the volume clue
    assert local.verdict_gate.tier.value != "confirmed"       # volume never confirms


def test_metric_lines_name_the_counter():
    lines = E.volume_context_metric_lines()
    assert lines[1] == "# TYPE corr_volume_context_singletons_total counter"
    assert lines[2].startswith("corr_volume_context_singletons_total ")


# ── the metric lane end to end ───────────────────────────────────────────────

class _FakeCH:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    async def insert(self, table: str, rows, dedup_token="") -> None:
        for r in rows:
            self.rows.append({"_table": table, **r})


def _iface(metric: str, value: float, ts: datetime) -> dict:
    return {"observer_type": "device", "modality_class": "device_telemetry",
            "collection_path": "snmp_poll", "device": "leaf1", "if_name": "Ethernet1",
            "index": "1", "signal_family": "interface", "metric": metric,
            "value": value, "ts": ts.isoformat()}


class MetricLaneTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.ch = _FakeCH()
        self._saved = (main.ch, main.CORR_SIGNALS_ENABLED, main.COUNTER_RATES,
                       main.METRICS_NOT_SCORED, main.DETECTOR.observe)
        main.ch = self.ch
        main.CORR_SIGNALS_ENABLED = True
        main.COUNTER_RATES = CounterRates()
        main.DETECTOR.observe = self._fake_observe

    def tearDown(self):
        (main.ch, main.CORR_SIGNALS_ENABLED, main.COUNTER_RATES,
         main.METRICS_NOT_SCORED, main.DETECTOR.observe) = self._saved

    @staticmethod
    def _fake_observe(tenant, entity_id, metric, ts, value, clock_quality="unknown", **_kw):
        return EpisodeEvent(phase="onset", key=(tenant, entity_id, metric), onset_ts=ts,
                            onset_uncertainty_s=30.0, value=value, baseline=0.0,
                            deviation=20.0, peak_deviation=20.0, integral=100.0)

    async def _rows_for(self, metric: str) -> list[dict]:
        now = datetime.now(timezone.utc)
        await main.handle_metric(_iface(metric, 5, now - timedelta(seconds=60)))
        await main.handle_metric(_iface(metric, 125, now))
        await main.SIGNAL_BATCH.flush()
        return [r for r in self.ch.rows if r["_table"] == "netops.corr_signals"]

    async def test_error_counter_episode_is_if_errors_at_its_own_severity(self):
        rows = await self._rows_for("device_if_in_errors")
        assert [(r["kind"], r["severity"]) for r in rows] == [("if_errors", "crit")]

    async def test_octet_episode_is_volume_capped_at_warn(self):
        rows = await self._rows_for("device_if_in_octets")
        assert [(r["kind"], r["severity"]) for r in rows] == [("if_metric_anomaly", "warn")]

    async def test_interface_speed_is_counted_never_scored(self):
        before = main.METRICS_NOT_SCORED
        now = datetime.now(timezone.utc)
        await main.handle_metric(_iface("device_if_speed", 1000, now))
        await main.handle_metric(_iface("device_if_speed", 10, now))
        await main.SIGNAL_BATCH.flush()
        assert main.METRICS_NOT_SCORED == before + 2
        assert [r for r in self.ch.rows if r["_table"] == "netops.corr_signals"] == []


def run(coro):
    return asyncio.run(coro)


# ── golden wire: the lab case from raw MetricEvents ─────────────────────────────

def test_golden_wire_lab_case_never_headlines_a_link_fault(monkeypatch):
    from golden_wire import load_fixture, replay_fixture_through_engine

    name = "traffic_volume_not_a_link_fault_p37.json"
    fx = load_fixture(name)["expect"]
    signals, snaps, ranking = replay_fixture_through_engine(name, monkeypatch)
    assert {s.metric_name: s.kind for s in signals} == fx["kinds"]
    assert all(x.ranking.top_hypothesis != fx["never_top"] for x in snaps)
    assert ranking is not None and ranking.top_hypothesis != fx["never_top"]
    assert fx["never_top"] not in {h.template_id for h in ranking.hypotheses}
