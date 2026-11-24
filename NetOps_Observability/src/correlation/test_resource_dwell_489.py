# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""ENGINE_SEMVER 3.8.0 — tracker 489 (owner 2026-11-24).

Stage [1]: a device's CPU / memory THRESHOLD alarm is fault evidence only once it
has stood 300 s without a clear; a raise cleared inside the dwell is counted and
never buffered (its raw row is in corr_signals); trap + syslog twins are one; the
kill switch restores 3.7.0.
Stage [1]/[5]: a busy-poll platform's CPU signal is `device_cpu_context` — visible,
never a cause on its own; a real fault on the box still opens and folds it in.

Lab shape (7 days, 4 vEdges): 92.2 % of critical raises (4,749 / 5,149) cleared
within 120 s, median 4 s; each raise also arrived as a syslog twin.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

import engine as E
import main
from catalog import BUSY_POLL_PLATFORMS, builtin_catalog
from engine import EngineConfig, run_window
from entity_resolver import identity_resolver_for
from resource_dwell import (
    CPU_CONTEXT_KIND,
    HOLD,
    PASS,
    ResourceDwell,
    is_cpu_signal,
    recast_busy_poll,
    threshold_resource,
)
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
TENANT = "t_lab"
VEDGE_ID = "vedge-100-3efc4148"
VEDGE_NAME = "vEdge-100"
CEDGE_ID = "cedge-40-fdf7b64f"


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def _res(kind: str, *, src: Source = Source.TRAP, sev: Severity = Severity.CRIT,
         eid: str = VEDGE_ID, resource: str = "cpu", off: float = 0.0,
         tenant: str = TENANT, ts: datetime | None = None, n: int = 0) -> Signal:
    when = ts or (T0 + timedelta(seconds=off))
    return Signal(
        tenant_id=tenant, ts=when, source=src, kind=kind,
        observer=Observer(observer_id=eid, observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.DEVICE_TELEMETRY, entity_type=EntityType.DEVICE,
        entity_id=eid, severity=sev, native_id=f"489|{src.value}|{kind}|{eid}|{off}|{n}",
        entity_tokens=(eid,), metric_name="device_resource_threshold",
        attrs={"resource": resource} if resource else {})


RAISE, CLEAR = "device_resource_anomaly", "device_resource_anomaly_clear"


# ── the gate itself ───────────────────────────────────────────────────────────

def test_a_flap_cleared_in_4s_is_suppressed_and_counted():
    clk = Clock()
    g = ResourceDwell(dwell_s=300, clock=clk)
    assert g.admit(_res(RAISE), VEDGE_ID) == HOLD
    clk.t += 4
    assert g.admit(_res(CLEAR, sev=Severity.INFO, off=4), VEDGE_ID) == PASS  # a clear always passes
    clk.t += 400
    assert g.due() == []
    assert g.suppressed == 1 and g.released == 0 and g.pending_count() == 0


def test_a_sustained_raise_is_released_once_at_expiry_with_its_own_identity():
    clk = Clock()
    g = ResourceDwell(dwell_s=300, clock=clk)
    raise_sig = _res(RAISE)
    assert g.admit(raise_sig, VEDGE_ID) == HOLD
    clk.t += 299
    assert g.due() == []
    clk.t += 2
    out = g.due()
    assert out == [raise_sig] and out[0].signal_id == raise_sig.signal_id
    assert g.released == 1 and g.due() == []


def test_trap_and_syslog_twins_are_one_release_at_the_highest_severity():
    clk = Clock()
    g = ResourceDwell(dwell_s=300, clock=clk)
    trap = _res(RAISE, sev=Severity.WARN)
    syslog = _res(RAISE, src=Source.SYSLOG, eid=VEDGE_NAME, sev=Severity.CRIT, off=0.2)
    assert g.admit(trap, VEDGE_ID) == HOLD
    assert g.admit(syslog, VEDGE_ID) == HOLD           # the caller keyed both on the id
    clk.t += 301
    assert g.due() == [syslog]
    assert g.released == 1 and g.folded == 1


def test_a_standing_condition_passes_further_raises_and_a_clear_ends_it():
    clk = Clock()
    g = ResourceDwell(dwell_s=300, clock=clk)
    g.admit(_res(RAISE), VEDGE_ID)
    clk.t += 301
    assert len(g.due()) == 1
    assert g.admit(_res(RAISE, off=400, n=1), VEDGE_ID) == PASS   # already proven
    assert g.passed_standing == 1
    assert g.admit(_res(CLEAR, sev=Severity.INFO, off=500), VEDGE_ID) == PASS
    assert g.suppressed == 0                                      # a clear after the dwell is recovery
    assert g.admit(_res(RAISE, off=600, n=2), VEDGE_ID) == HOLD   # a new crossing waits again


def test_memory_is_gated_too_and_keyed_apart_from_cpu():
    clk = Clock()
    g = ResourceDwell(dwell_s=300, clock=clk)
    assert g.admit(_res(RAISE, resource="memory"), VEDGE_ID) == HOLD
    assert g.admit(_res(RAISE, resource="cpu"), VEDGE_ID) == HOLD
    g.admit(_res(CLEAR, resource="cpu", sev=Severity.INFO), VEDGE_ID)
    clk.t += 301
    out = g.due()
    assert [s.attrs["resource"] for s in out] == ["memory"]


def test_tenants_never_share_a_group():
    clk = Clock()
    g = ResourceDwell(dwell_s=300, clock=clk)
    g.admit(_res(RAISE, tenant="t_a"), VEDGE_ID)
    g.admit(_res(RAISE, tenant="t_b"), VEDGE_ID)
    g.admit(_res(CLEAR, tenant="t_b", sev=Severity.INFO), VEDGE_ID)   # clears only t_b's
    clk.t += 301
    assert [s.tenant_id for s in g.due()] == ["t_a"]


def test_the_kill_switch_passes_everything(monkeypatch):
    monkeypatch.setenv("CORR_RESOURCE_DWELL_S", "0")
    g = ResourceDwell()
    assert not g.enabled
    assert g.admit(_res(RAISE), VEDGE_ID) == PASS
    assert g.pending_count() == 0


def test_not_a_threshold_alarm_is_never_held():
    g = ResourceDwell(dwell_s=300, clock=Clock())
    metric_ep = _res(RAISE, src=Source.METRIC, resource="")          # the CUSUM CPU episode
    assert threshold_resource(metric_ep) is None and g.admit(metric_ep, VEDGE_ID) == PASS
    other = _res("device_alarm", resource="cpu")
    assert threshold_resource(other) is None and g.admit(other, VEDGE_ID) == PASS
    fan = _res(RAISE, resource="fan")
    assert threshold_resource(fan) is None and g.admit(fan, VEDGE_ID) == PASS


def test_the_bound_releases_the_oldest_early_instead_of_dropping_it():
    clk = Clock()
    g = ResourceDwell(dwell_s=300, max_groups=2, clock=clk)
    a, b, c = (_res(RAISE, eid=f"d{i}", n=i) for i in range(3))
    for s in (a, b, c):
        assert g.admit(s, s.entity_id) == HOLD
    assert g.pending_count() == 2 and g.overflow_released == 1
    assert g.due() == [a]                     # released early, never lost
    clk.t += 301
    assert g.due() == [b, c]


def test_metric_lines_and_health():
    g = ResourceDwell(dwell_s=300, clock=Clock())
    lines = g.metric_lines()
    assert "corr_resource_flap_suppressed_total 0" in lines
    assert "corr_resource_dwell_pending 0" in lines
    assert g.health()["dwell_s"] == 300


# ── the lab shape: −92 % ──────────────────────────────────────────────────────

def test_lab_shaped_week_releases_only_the_sustained_raises():
    # 5,149 critical raises: 4,749 (92.2 %) cleared 4 s later, 400 that stood past
    # the dwell; every one also arrived as a syslog twin 200 ms later.
    clk = Clock()
    g = ResourceDwell(dwell_s=300, clock=clk)
    released = 0
    for i in range(5149):
        trap = _res(RAISE, n=i)
        twin = _res(RAISE, src=Source.SYSLOG, eid=VEDGE_NAME, n=i, off=0.2)
        assert g.admit(trap, VEDGE_ID) == HOLD
        assert g.admit(twin, VEDGE_ID) == HOLD
        if i < 4749:
            clk.t += 4
            g.admit(_res(CLEAR, sev=Severity.INFO, n=i, off=4), VEDGE_ID)
            clk.t += 62
        else:
            clk.t += 301
            released += len(g.due())
            g.admit(_res(CLEAR, sev=Severity.INFO, n=i, off=301), VEDGE_ID)
            clk.t += 62
        released += len(g.due())
    assert released == 400                     # crit raises reaching the window: 10,298 → 400
    assert g.suppressed == 2 * 4749            # the trap and its twin, each counted
    assert g.folded == 5149
    assert round(1 - released / (2 * 5149), 3) == 0.961   # vs trap+syslog today


# ── busy-poll CPU is context ─────────────────────────────────────────────────

def test_busy_poll_cpu_is_recast_to_context_at_warn():
    assert "vedge-cloud" in BUSY_POLL_PLATFORMS
    crit = _res(RAISE)
    out = recast_busy_poll(crit, "vedge-cloud", BUSY_POLL_PLATFORMS)
    assert out.kind == CPU_CONTEXT_KIND and out.severity is Severity.WARN
    assert out.signal_id == crit.signal_id          # kind is not part of the identity
    episode = _cpu_episode()
    assert is_cpu_signal(episode)
    assert recast_busy_poll(episode, "VEDGE-CLOUD", BUSY_POLL_PLATFORMS).kind == CPU_CONTEXT_KIND


def _cpu_episode() -> Signal:
    return Signal(
        tenant_id=TENANT, ts=T0, source=Source.METRIC, kind=RAISE,
        observer=Observer(observer_id=VEDGE_ID, observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.DEVICE_TELEMETRY, entity_type=EntityType.DEVICE,
        entity_id=VEDGE_ID, severity=Severity.HIGH, native_id="489|cpu-episode",
        entity_tokens=(VEDGE_ID,), metric_name="device_cpu_percent")


def test_only_cpu_on_a_busy_poll_model_is_recast():
    crit = _res(RAISE)
    assert recast_busy_poll(crit, "vedge-csr-1000v", BUSY_POLL_PLATFORMS) is crit   # cEdge
    assert recast_busy_poll(crit, "", BUSY_POLL_PLATFORMS) is crit                 # unknown model
    mem = _res(RAISE, resource="memory")
    assert recast_busy_poll(mem, "vedge-cloud", BUSY_POLL_PLATFORMS) is mem         # memory stays


def _ctx(eid: str = VEDGE_ID, off: float = 0.0, n: int = 0) -> Signal:
    return recast_busy_poll(_res(RAISE, eid=eid, off=off, n=n), "vedge-cloud", BUSY_POLL_PLATFORMS)


def test_busy_poll_cpu_alone_opens_no_object_and_is_counted():
    ev = [_ctx(), _ctx(off=60, n=1)]
    before = E.cpu_context_singletons_total()
    assert run_window(ev, builtin_catalog(), (), EngineConfig()) == []
    assert E.cpu_context_singletons_total() == before + 1


def test_a_real_fault_on_the_busy_poll_box_opens_and_folds_the_cpu_in():
    link = Signal(
        tenant_id=TENANT, ts=T0 + timedelta(seconds=5), source=Source.TRAP,
        kind="link_state_change",
        observer=Observer(observer_id=VEDGE_ID, observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.CONTROL_PLANE, entity_type=EntityType.INTERFACE,
        entity_id=f"{VEDGE_ID}:ge0/2", severity=Severity.HIGH, native_id="489|link",
        entity_tokens=(VEDGE_ID,))
    snaps = run_window([_ctx(), link], builtin_catalog(), (), EngineConfig())
    assert len(snaps) == 1
    kinds = sorted(n.kind for n in snaps[0].nodes)
    assert kinds == [CPU_CONTEXT_KIND, "link_state_change"]
    top = snaps[0].ranking.hypotheses[0]
    assert CPU_CONTEXT_KIND not in {k for h in snaps[0].ranking.hypotheses for k in h.satisfied}
    assert top.template_id != ""


def test_sustained_cpu_on_an_ordinary_box_still_opens():
    crit = _res(RAISE, eid=CEDGE_ID)
    snaps = run_window([crit], builtin_catalog(), (), EngineConfig())
    assert len(snaps) == 1 and snaps[0].nodes[0].kind == RAISE


def test_no_template_reads_the_context_kind():
    for t in builtin_catalog().templates:
        for clause in t.requires:
            assert CPU_CONTEXT_KIND not in clause.kinds(), t.id


def test_engine_semver_and_counter_lines():
    assert E.ENGINE_SEMVER == "3.8.0"
    lines = E.cpu_context_metric_lines()
    assert lines[1] == "# TYPE corr_cpu_context_singletons_total counter"


# ── the resolver carries the registry model ──────────────────────────────────

def _raw() -> dict:
    return {
        "devices": {TENANT: [
            {"tenant_id": TENANT, "device": VEDGE_ID, "name": VEDGE_NAME, "model": "vedge-cloud"},
            {"tenant_id": TENANT, "device": CEDGE_ID, "name": "cEDGE-40", "model": "vedge-CSR-1000v"},
        ], "t_other": [
            {"tenant_id": "t_other", "device": VEDGE_ID, "model": "something-else"},
        ]},
        "interface_ips": {}, "ifindex": {},
    }


def test_resolver_reads_the_model_per_tenant():
    r = identity_resolver_for(_raw(), TENANT)
    assert r.model_of(VEDGE_ID) == "vedge-cloud"
    assert r.model_of(CEDGE_ID) == "vedge-csr-1000v"
    assert r.model_of("nope") == ""
    assert r.canonical_device(VEDGE_NAME) == VEDGE_ID
    assert identity_resolver_for(_raw(), "t_other").model_of(VEDGE_ID) == "something-else"


# ── wired at the window entry (main.buffer_signal) ───────────────────────────

@pytest.fixture
def wired(monkeypatch):
    clk = Clock()
    monkeypatch.setattr(main, "RESOURCE_DWELL", ResourceDwell(dwell_s=300, clock=clk))
    resolver = identity_resolver_for(_raw(), TENANT)
    monkeypatch.setattr(main, "cached_identity_resolver_for", lambda t: resolver)
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear()
    yield clk
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear()


def _now_res(kind: str, **kw) -> Signal:
    return _res(kind, ts=datetime.now(timezone.utc), **kw)


def test_buffer_signal_holds_a_flap_and_releases_a_sustained_raise(wired):
    clk = wired
    flap = _now_res(RAISE, eid=CEDGE_ID, n=1)
    main.buffer_signal(flap)
    main.buffer_signal(_now_res(CLEAR, eid=CEDGE_ID, sev=Severity.INFO, n=2))
    assert [s.kind for s in main.WINDOW_BUFFER] == [CLEAR]      # the raise never entered
    sustained = _now_res(RAISE, eid=CEDGE_ID, n=3)
    main.buffer_signal(sustained)
    assert main.release_resource_dwell() == 0
    clk.t += 301
    assert main.release_resource_dwell() == 1
    assert main.WINDOW_BUFFER[-1].signal_id == sustained.signal_id
    assert main.WINDOW_BUFFER[-1].kind == RAISE                 # cEdge: not busy-poll


def test_buffer_signal_keys_twins_through_the_resolver_and_recasts_busy_poll(wired):
    clk = wired
    main.buffer_signal(_now_res(RAISE, eid=VEDGE_ID, n=1))
    main.buffer_signal(_now_res(RAISE, src=Source.SYSLOG, eid=VEDGE_NAME, n=2))
    assert main.RESOURCE_DWELL.pending_count() == 1 and main.RESOURCE_DWELL.folded == 1
    clk.t += 301
    assert main.release_resource_dwell() == 1
    out = main.WINDOW_BUFFER[-1]
    assert out.kind == CPU_CONTEXT_KIND and out.severity is Severity.WARN


def test_buffer_signal_with_the_switch_off_is_3_7_0(wired, monkeypatch):
    monkeypatch.setattr(main, "RESOURCE_DWELL", ResourceDwell(dwell_s=0))
    sig = _now_res(RAISE, eid=CEDGE_ID, n=9)
    main.buffer_signal(sig)
    assert list(main.WINDOW_BUFFER) == [sig]
