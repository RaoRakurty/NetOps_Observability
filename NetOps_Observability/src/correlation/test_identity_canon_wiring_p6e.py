# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""P6 PR-E — stage [1] identity canonicalisation WIRED behind CORR_IDENTITY_CANON.

Plan: docs/design/P6_CANONICALISATION_PLAN_2026-11-07.md ("PR-E: wiring"). The
pure rules are pinned in test_canon_identity_p6.py (PR-D); this file pins the
wiring:

  * the flag: default OFF, and REFUSED (stays off, gauge 0, start-up error)
    without E1 (CORR_ORIGIN_OBSERVER) AND series admission (CORR_SERIES_ADMISSION);
  * OFF is byte-identical: canonicalize is never called, nothing is stamped,
    nothing is counted, every window row is the input row;
  * ON, the seams: event lanes in `buffer_signal` AFTER `canon_tenant` and
    BEFORE the E1 origin stamp (never before `agg_admit`); the metric lane's
    series key in `handle_metric` before the counter-rate state, the episode
    detector, the proactive plane and the z-score;
  * ON, per lane: syslog D1/D2/D4, trap, controller D5, proactive, metric —
    `native_id` / `signal_id` never move, attrs["canon"] only on a rewrite;
  * replay is flag-independent (it never comes through buffer_signal);
  * §3a: two tenants with identically named devices never cross; the cached
    resolver is keyed by tenant, never ∪ global, and bounded by the file's tenants;
  * corr_identity_canon_total{lane,axis,outcome} + /healthz ingest totals.
"""
from __future__ import annotations

import ast
import asyncio
import json
import os
import subprocess  # nosec B404 — fixed argv, this interpreter
import sys
from datetime import datetime, timedelta, timezone

import pytest

import canon as C
import main
import producers as P
import signals
from canon import (
    ABSTAIN_AMBIGUOUS,
    ABSTAIN_CONFLICT,
    ABSTAIN_GENERIC,
    ABSTAIN_UNKNOWN,
    CANON_ATTR,
    REWRITTEN,
    UNCHANGED,
    canonicalize_series,
)
from catalog import builtin_catalog
from controller_events import controller_event_to_signal
from engine import build_nodes, run_window
from entity_resolver import identity_resolver_for
from episodes import EpisodeDetector
from proactive import CHECKS, ProactiveEvent, proactive_signal
from replay import StoredObject, replay
from signals import (
    ORIGIN_DEVICE_ATTR,
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
    set_identity_canon,
    set_origin_observer,
    set_series_admission,
)

HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN_PEER = os.path.join(HERE, "..", "backend", "nms", "testdata", "source_parity",
                           "vmanage_20.6.controller_events_peer_in_inventory.json")
TRAPS = os.path.join(HERE, "fixtures", "source_parity", "traps_cedge81_bgp_20261101.jsonl")

TENANT = "t_lab"
OTHER = "t_other"
DEVICE = "cedge-81-11060ae2"
OTHER_DEVICE = "other-81-0000beef"
CEDGE81_MGMT = "192.168.222.106"
PEER = "192.168.200.34"
RFC_BACKWARD = "1.3.6.1.2.1.15.7.2"
INGEST = datetime(2026, 11, 1, 17, 5, tzinfo=timezone.utc)
SNMP, CTL = "snmp_poll", "via_controller"


# ── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _restore_flags():
    prev = (signals.origin_observer_enabled(), signals.series_admission_enabled(),
            signals.series_bucket_s(), signals.identity_canon_requested())
    yield
    set_origin_observer(prev[0])
    set_series_admission(prev[1], prev[2])
    set_identity_canon(prev[3])


@pytest.fixture
def canon_on():
    set_origin_observer(True)
    set_series_admission(True, 60.0)
    set_identity_canon(True)
    assert main.identity_canon_enabled()
    yield


def _rows(tenant: str, device: str, *, name: str = "cEDGE-81", mgmt: str = CEDGE81_MGMT) -> dict:
    return {
        "devices": [{"tenant_id": tenant, "device": device, "name": name, "mgmt_ip": mgmt}],
        "interface_ips": [],
        "ifindex": [
            {"tenant_id": tenant, "device": device, "ifindex": "1", "ifname": "GigabitEthernet1"},
            {"tenant_id": tenant, "device": device, "ifindex": "2", "ifname": "GigabitEthernet2"},
        ],
    }


def _resolver_file(path: str, *, with_other: bool = True, with_global: bool = True) -> None:
    """entity_resolver.json as the Go API writes it: section → rows, tenant_id per
    row. Tenant t_lab owns cEDGE-81; t_other owns a DIFFERENT box with the SAME
    name and the SAME management address; the platform-global slice holds yet
    another box spelled the same — none of them may ever cross."""
    out: dict[str, list] = {"devices": [], "interface_ips": [], "ifindex": []}
    parts = [_rows(TENANT, DEVICE)]
    if with_other:
        parts.append(_rows(OTHER, OTHER_DEVICE))
    if with_global:
        parts.append(_rows("", "global-81"))
    for p in parts:
        for k, v in p.items():
            out[k] += v
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh)


@pytest.fixture
def inventory(tmp_path, monkeypatch):
    """A real entity_resolver.json behind the real mtime caches."""
    path = str(tmp_path / "entity_resolver.json")
    _resolver_file(path)
    monkeypatch.setattr(main, "ENTITY_RESOLVER_FILE", path)
    monkeypatch.setattr(main, "_er_raw", {"devices": {}, "interface_ips": {}, "ifindex": {}})
    monkeypatch.setattr(main, "_er_mtime", -1.0)
    monkeypatch.setattr(main, "_resolver_cache", {})
    monkeypatch.setattr(main, "_resolver_cache_mtime", -1.0)
    monkeypatch.setattr(main, "_identity_resolver_cache", {})
    monkeypatch.setattr(main, "_identity_resolver_cache_mtime", -1.0)
    monkeypatch.setattr(main, "IDENTITY_CANON_COUNTS", {})
    return path


def _window_row(sig: Signal) -> Signal:
    """Push one signal through the live window entry; return what the window holds."""
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_ID_ORDER.clear()
    main._BUFFERED_IDS.clear()
    main.buffer_signal(sig)
    assert len(main.WINDOW_BUFFER) == 1
    return main.WINDOW_BUFFER[-1]


def _syslog(message: str, host: str = CEDGE81_MGMT, tenant: str = TENANT) -> Signal:
    """A syslog line through the PRODUCTION parser. The message is synthetic (no
    recorded cEDGE-81 BGP/link line exists — E7 docstring); the host is the box's
    recorded one, its management address."""
    tag = message.split(":", 1)[0]
    sig = P.syslog_control_signal({"appname": tag, "facility": "local7", "hostname": host,
                                   "message": message, "timestamp": "2026-11-01T17:00:01Z"},
                                  tenant, INGEST)
    assert sig is not None, message
    return sig


BGP_LINE = f"%BGP-5-ADJCHANGE: neighbor {PEER} vpn vrf 200 Down BGP Notification sent"
LINK_LINE = "%LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet1, changed state to down"


def _rfc_trap() -> Signal:
    with open(TRAPS, encoding="utf-8") as fh:
        rec = next(json.loads(ln) for ln in fh if ln.strip() and RFC_BACKWARD in ln)
    sig = P.trap_control_signal({**rec, "device": DEVICE}, TENANT, INGEST)
    assert sig is not None
    return sig


def _controller_peer_in_inventory() -> Signal:
    with open(GOLDEN_PEER, encoding="utf-8") as fh:
        ev = json.load(fh)[0]
    sig = controller_event_to_signal(ev, INGEST)
    assert sig is not None and sig.tenant_id == TENANT
    return sig


def _proactive_bgp(entity: str, peer: str = PEER) -> Signal:
    check = next(c for c in CHECKS if c.check_id == "proactive.bgp.adjacency_down_persisting")
    ev = ProactiveEvent(phase="onset", check_id=check.check_id, kind=check.kind, tenant_id=TENANT,
                        entity_id=entity, entity_tokens=(entity,),
                        onset_ts=datetime(2026, 11, 1, 17, 0, 1, tzinfo=timezone.utc),
                        held_s=300.0, value=0.0, observer_id=entity, metric_name=check.trigger,
                        peer=peer)
    sig = proactive_signal(ev)
    assert sig.source is Source.SYSLOG and sig.observer.collection_path == "proactive_check"
    return sig


def _event_battery() -> list[Signal]:
    return [_syslog(BGP_LINE), _syslog(LINK_LINE), _rfc_trap(), _controller_peer_in_inventory(),
            _proactive_bgp(CEDGE81_MGMT)]


# ── 1. the flag ──────────────────────────────────────────────────────────────

def test_flag_defaults_off_in_a_clean_process() -> None:
    env = {k: v for k, v in os.environ.items() if k != "CORR_IDENTITY_CANON"}
    out = subprocess.run(  # nosec B603 — fixed argv, this interpreter
        [sys.executable, "-c",
         "import signals; print(signals.identity_canon_requested(), signals.identity_canon_enabled())"],
        cwd=HERE, env=env, capture_output=True, text=True, timeout=60, check=True)
    assert out.stdout.split() == ["False", "False"], out.stdout + out.stderr


@pytest.mark.parametrize("e1,series,expected", [
    (False, False, False), (True, False, False), (False, True, False), (True, True, True)])
def test_the_gate_requires_e1_and_series_admission(e1, series, expected) -> None:
    set_identity_canon(True)
    set_origin_observer(e1)
    set_series_admission(series)
    assert signals.identity_canon_requested() is True
    assert signals.identity_canon_enabled() is expected
    assert main.identity_canon_enabled() is expected
    missing = main.identity_canon_missing_prereqs()
    assert ("CORR_ORIGIN_OBSERVER" in missing) is (not e1)
    assert ("CORR_SERIES_ADMISSION" in missing) is (not series)
    text = main._metrics_text(main._health_payload())
    assert f"corr_identity_canon_enabled {1 if expected else 0}" in text


@pytest.mark.parametrize("env,refused", [
    ({"CORR_IDENTITY_CANON": "1"}, True),
    ({"CORR_IDENTITY_CANON": "1", "CORR_ORIGIN_OBSERVER": "1"}, True),
    ({"CORR_IDENTITY_CANON": "1", "CORR_SERIES_ADMISSION": "1"}, True),
    ({"CORR_IDENTITY_CANON": "1", "CORR_ORIGIN_OBSERVER": "1", "CORR_SERIES_ADMISSION": "1"}, False),
])
def test_requested_without_prerequisites_stays_off_and_says_so_at_startup(env, refused) -> None:
    base = {k: v for k, v in os.environ.items()
            if k not in ("CORR_IDENTITY_CANON", "CORR_ORIGIN_OBSERVER", "CORR_SERIES_ADMISSION")}
    out = subprocess.run(  # nosec B603 — fixed argv, this interpreter
        [sys.executable, "-c", "import main; print(main.identity_canon_enabled())"],
        cwd=HERE, env={**base, **env}, capture_output=True, text=True, timeout=180, check=True)
    assert out.stdout.split()[-1] == ("False" if refused else "True"), out.stdout + out.stderr
    assert ("identity canonicalisation stays OFF" in out.stderr) is refused, out.stderr
    assert ("identity canonicalisation ON" in out.stderr) is (not refused), out.stderr


# ── 2. OFF is byte-identical ─────────────────────────────────────────────────

def _forbid_canon(monkeypatch) -> None:
    def boom(*_a, **_k):
        raise AssertionError("canonicalize must never be called with the flag off")
    monkeypatch.setattr(main, "canonicalize_detailed", boom)
    monkeypatch.setattr(main, "canonicalize_series", boom)


@pytest.mark.parametrize("requested", [False, True])
def test_off_canonicalize_is_never_called_and_every_row_is_the_input(requested, inventory,
                                                                    monkeypatch) -> None:
    """OFF — and REQUESTED but refused (no E1 / no series admission) — the window
    row is the input row byte for byte, no canon attr, nothing counted."""
    set_identity_canon(requested)
    assert not main.identity_canon_enabled()
    _forbid_canon(monkeypatch)
    for sig in _event_battery():
        row = _window_row(sig)
        assert row.to_ch_row() == sig.to_ch_row()
        assert row.entity_id == sig.entity_id and CANON_ATTR not in row.attrs
        assert ORIGIN_DEVICE_ATTR not in row.attrs
    assert main.IDENTITY_CANON_COUNTS == {}
    ing = main._health_payload()["ingest"]
    assert all(ing[f"identity_canon_{o}"] == 0 for o in C.OUTCOMES)
    assert "corr_identity_canon_total{" not in main._metrics_text(main._health_payload())


class _Rows:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    async def batch(self, row: dict) -> None:
        self.rows.append(row)


@pytest.fixture
def lane(monkeypatch, inventory):
    sink = _Rows()
    monkeypatch.setattr(main, "DETECTOR", EpisodeDetector())
    monkeypatch.setattr(main, "ch", object())
    monkeypatch.setattr(main, "CORR_SIGNALS_ENABLED", True)
    monkeypatch.setattr(main, "batch_signal", sink.batch)
    monkeypatch.setattr(main, "agg_admit", lambda sig: sig)
    seen: list[tuple] = []
    monkeypatch.setattr(main, "score", lambda tenant, ent, metric, value: seen.append(("z", ent, ())))
    real_observe = main.PROACTIVE.observe_metric

    def observe_metric(**kw):
        seen.append(("proactive", kw["entity_id"], kw["tokens"]))
        return real_observe(**kw)

    monkeypatch.setattr(main.PROACTIVE, "observe_metric", observe_metric)
    monkeypatch.setattr(main, "verified_tenant", lambda claim, device, lane_, **k: claim or "global")
    sink.seen = seen  # type: ignore[attr-defined]
    return sink


def _recent(bucket: int, second: float) -> datetime:
    now = datetime.now(timezone.utc)
    base = datetime.fromtimestamp((int(now.timestamp()) // 60 - 50) * 60, tz=timezone.utc)
    return base + timedelta(seconds=60 * bucket + second)


def metric_ev(ts: datetime, value: float, *, if_name: str = "", index: str = "", path: str = SNMP,
              device: str = DEVICE, tenant: str = TENANT, metric: str = "device_if_oper_status",
              family: str = "interface", **extra) -> dict:
    ev = {"device": device, "metric": metric, "value": value, "signal_family": family,
          "collection_path": path, "ts": ts.isoformat(), "tenant_id": tenant, "unit": "state",
          **extra}
    if if_name:
        ev["if_name"] = if_name
    if index:
        ev["index"] = index
    return ev


def test_off_the_metric_lane_never_canonicalises(lane, monkeypatch) -> None:
    _forbid_canon(monkeypatch)
    asyncio.run(main.handle_metric(metric_ev(_recent(0, 5), 1.0, if_name="Gi1", index="1")))
    assert list(main.DETECTOR._state) == [(TENANT, f"{DEVICE}:Gi1", "device_if_oper_status")]
    assert ("z", f"{DEVICE}:Gi1", ()) in lane.seen
    assert main.IDENTITY_CANON_COUNTS == {}


# ── 3. ON: the event lanes ───────────────────────────────────────────────────

def test_on_syslog_bgp_from_the_management_ip_meets_the_trap_and_controller(canon_on, inventory) -> None:
    syslog, trap, ctl = _syslog(BGP_LINE), _rfc_trap(), _controller_peer_in_inventory()
    rows = [_window_row(s) for s in (syslog, trap, ctl)]
    assert {r.entity_id for r in rows} == {f"{DEVICE}:{PEER}"}
    assert len(build_nodes(tuple(rows))) == 1
    for raw, row in zip((syslog, trap, ctl), rows):
        assert row.native_id == raw.native_id and row.signal_id == raw.signal_id
    assert rows[0].attrs[CANON_ATTR] == {"raw": CEDGE81_MGMT, "basis": "device:ip+peer:ip"}
    assert CANON_ATTR not in rows[1].attrs, "the trap was already canonical: no stamp"
    assert rows[2].attrs[CANON_ATTR] == {"raw": f"{DEVICE}:pe-vpn200-parity",
                                         "basis": "peer:controller_hint"}
    # E1 stamps AFTER canonicalisation, on the same tenant's box.
    assert {r.attrs[ORIGIN_DEVICE_ATTR] for r in rows} == {DEVICE}
    # the input signals were never mutated
    assert CANON_ATTR not in syslog.attrs and syslog.entity_id == CEDGE81_MGMT


def test_on_syslog_interface_spelling_becomes_the_canonical_key(canon_on, inventory) -> None:
    sig = _syslog(LINK_LINE)
    row = _window_row(sig)
    assert row.entity_id == f"{DEVICE}:gi1"
    assert row.attrs[CANON_ATTR] == {"raw": f"{CEDGE81_MGMT}:GigabitEthernet1",
                                     "basis": "device:ip+iface:key"}
    assert row.attrs["interface"] == "GigabitEthernet1", "the display name stays"
    assert row.native_id == sig.native_id and row.signal_id == sig.signal_id


def test_on_proactive_bgp_check_binds_the_session_its_line_binds(canon_on, inventory) -> None:
    line, check = _syslog(BGP_LINE), _proactive_bgp(CEDGE81_MGMT)
    a, b = _window_row(line), _window_row(check)
    assert a.entity_id == b.entity_id == f"{DEVICE}:{PEER}"
    assert b.native_id == check.native_id and b.signal_id == check.signal_id
    assert main.IDENTITY_CANON_COUNTS[("proactive", "signal", REWRITTEN)] == 1
    assert main.IDENTITY_CANON_COUNTS[("syslog", "signal", REWRITTEN)] == 1


def test_on_a_trap_derived_proactive_check_is_kept_not_guessed(canon_on, inventory) -> None:
    sig = _proactive_bgp(f"{DEVICE}:{PEER}")
    row = _window_row(sig)
    assert row.entity_id == sig.entity_id and CANON_ATTR not in row.attrs


def test_on_an_unknown_or_generic_host_keeps_its_spelling(canon_on, inventory) -> None:
    for host, outcome in (("10.99.99.99", ABSTAIN_UNKNOWN), ("router", ABSTAIN_GENERIC)):
        sig = _syslog(BGP_LINE, host=host)
        row = _window_row(sig)
        assert row.entity_id == host and CANON_ATTR not in row.attrs
        assert main.IDENTITY_CANON_COUNTS[("syslog", "signal", outcome)] == 1


def test_on_non_event_lanes_never_reach_canonicalize(canon_on, inventory, monkeypatch) -> None:
    calls: list[str] = []
    real = main.canonicalize_detailed
    monkeypatch.setattr(main, "canonicalize_detailed",
                        lambda s, r: calls.append(s.source.value) or real(s, r))
    probe = Signal(tenant_id=TENANT, ts=INGEST, source=Source.PROBE, kind="probe_loss",
                   observer=Observer(observer_id="agent-1", observer_type=ObserverType.VANTAGE_AGENT),
                   modality_class=ModalityClass.ACTIVE_PROBE, entity_type=EntityType.DEVICE,
                   entity_id="cEDGE-81", severity=Severity.HIGH, native_id="p|1",
                   attrs={"probe_authority": "low"})
    row = _window_row(probe)
    assert row.entity_id == "cEDGE-81" and calls == []
    _window_row(_syslog(BGP_LINE))
    assert calls == ["syslog"]


def test_on_the_seam_order_tenant_then_canon_then_origin(canon_on, inventory, monkeypatch) -> None:
    """The resolver is picked by the CANONICAL tenant ("" → "global"), and E1's
    origin stamp sees the canonical entity — never the reverse."""
    order: list[tuple[str, str]] = []
    real_canon, real_origin = main._canonicalize_event, main._stamp_origin_device
    monkeypatch.setattr(main, "_canonicalize_event",
                        lambda s: order.append(("canon", s.tenant_id)) or real_canon(s))
    monkeypatch.setattr(main, "_stamp_origin_device",
                        lambda s: order.append(("origin", s.entity_id)) or real_origin(s))
    _window_row(_syslog(BGP_LINE, tenant=""))
    assert order == [("canon", "global"), ("origin", "global-81:" + PEER)]


def _call_sites(tree: ast.Module, name: str) -> list[tuple[str, int]]:
    """(enclosing top-level function, line) of every call to `name` in main.py."""
    out: list[tuple[str, int]] = []
    for fn in tree.body:
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(fn):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == name:
                out.append((fn.name, node.lineno))
    return out


def test_the_seams_are_where_the_plan_puts_them() -> None:
    """Event lanes: ONLY buffer_signal canonicalises — after canon_tenant, before
    the E1 origin stamp — and so never before any lane's agg_admit (every lane
    calls agg_admit BEFORE buffer_signal; INVARIANTS §10a). Metric lane: ONLY
    handle_metric canonicalises the series key, before the counter-rate state,
    the episode detector, the proactive plane and the z-score."""
    with open(main.__file__, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    assert [f for f, _ in _call_sites(tree, "canonicalize_detailed")] == ["_canonicalize_event"]
    assert [f for f, _ in _call_sites(tree, "_canonicalize_event")] == ["buffer_signal"]
    assert [f for f, _ in _call_sites(tree, "canonicalize_series")] == ["handle_metric"]
    assert all(f != "agg_admit" for f, _ in _call_sites(tree, "buffer_signal"))

    def line(fn: str, call: str) -> int:
        return min(n for f, n in _call_sites(tree, call) if f == fn)

    canon_at = line("buffer_signal", "_canonicalize_event")
    assert line("buffer_signal", "canon_tenant") < canon_at < line("buffer_signal", "_stamp_origin_device")
    series_at = line("handle_metric", "canonicalize_series")
    assert line("handle_metric", "metric_identity") < line("handle_metric", "verified_tenant") < series_at
    for later in ("feed_episode_detector", "score", "unit_contradicts"):
        assert series_at < line("handle_metric", later), later


def test_agg_admit_sees_the_raw_entity(canon_on, inventory, monkeypatch) -> None:
    """INVARIANTS §10a at runtime: the aggregation plane keys stay the RAW spelling."""
    seen: list[str] = []

    class _Plane:
        def observe(self, sig, _coord):
            seen.append(sig.entity_id)
            return sig

    monkeypatch.setattr(main, "CORR_AGGREGATION_PLANE", True)
    monkeypatch.setattr(main, "AGG_PLANE", _Plane())
    fwd = main.agg_admit(_syslog(BGP_LINE))   # the REAL gate, plane on
    assert fwd is not None
    main.buffer_signal(fwd)
    assert seen == [CEDGE81_MGMT]
    assert main.WINDOW_BUFFER[-1].entity_id == f"{DEVICE}:{PEER}"


def test_on_counter_and_healthz(canon_on, inventory) -> None:
    for sig in _event_battery():
        _window_row(sig)
    counts = main.IDENTITY_CANON_COUNTS
    assert counts[("syslog", "signal", REWRITTEN)] == 2
    assert counts[("syslog", "device", REWRITTEN)] == 2
    assert counts[("syslog", "peer", REWRITTEN)] == 1
    assert counts[("syslog", "iface", REWRITTEN)] == 1
    assert counts[("trap", "signal", UNCHANGED)] == 1
    assert counts[("controller", "signal", REWRITTEN)] == 1
    assert counts[("proactive", "signal", REWRITTEN)] == 1
    for lane_, axis, outcome in counts:
        assert lane_ in main.CANON_LANES and outcome in C.OUTCOMES
        assert axis in C.AXES or axis == "signal"
    ing = main._health_payload()["ingest"]
    assert ing["identity_canon_rewritten"] == 4 and ing["identity_canon_unchanged"] == 1
    text = main._metrics_text(main._health_payload())
    assert 'corr_identity_canon_total{lane="syslog",axis="device",outcome="rewritten"} 2' in text
    assert 'corr_identity_canon_total{lane="trap",axis="signal",outcome="unchanged"} 1' in text
    assert 'corr_ingest_events{counter="identity_canon_rewritten"} 4' in text
    assert "corr_identity_canon_enabled 1" in text


def test_the_counter_never_mints_a_label() -> None:
    saved = dict(main.IDENTITY_CANON_COUNTS)
    try:
        main.IDENTITY_CANON_COUNTS.clear()
        main._count_canon("evil\"lane", "pwn", (("x", "y"), ("device", REWRITTEN)))
        assert set(main.IDENTITY_CANON_COUNTS) == {("other", "signal", "other"),
                                                   ("other", "other", "other"),
                                                   ("other", "device", REWRITTEN)}
    finally:
        main.IDENTITY_CANON_COUNTS.clear()
        main.IDENTITY_CANON_COUNTS.update(saved)


# ── 4. ON: the metric lane ───────────────────────────────────────────────────

def test_on_two_spellings_of_one_port_are_one_series(lane, canon_on) -> None:
    """SNMP polls `GigabitEthernet1` (ifIndex 1); the controller relays `Gi1`;
    a sample with no ifName but the declared ifIndex 1 is the same port."""
    async def run() -> None:
        await main.handle_metric(metric_ev(_recent(0, 5), 1.0, if_name="GigabitEthernet1", index="1"))
        await main.handle_metric(metric_ev(_recent(1, 5), 1.0, if_name="Gi1", path=CTL))
        await main.handle_metric(metric_ev(_recent(2, 5), 1.0, index="1"))
    asyncio.run(run())
    assert list(main.DETECTOR._state) == [(TENANT, f"{DEVICE}:gi1", "device_if_oper_status")]
    assert {e for k, e, _t in lane.seen if k == "z"} == {f"{DEVICE}:gi1"}
    assert {(e, t) for k, e, t in lane.seen if k == "proactive"} == {(f"{DEVICE}:gi1", (DEVICE,))}
    assert main.IDENTITY_CANON_COUNTS[("metric", "iface", REWRITTEN)] == 3


def test_on_the_metric_lane_canonicalises_before_the_counter_rate_state(lane, canon_on, monkeypatch) -> None:
    from counter_rate import CounterRates
    monkeypatch.setattr(main, "COUNTER_RATES", CounterRates())
    asyncio.run(main.handle_metric(metric_ev(_recent(0, 5), 100.0, if_name="GigabitEthernet1",
                                             metric="device_if_in_octets", unit="bytes")))
    asyncio.run(main.handle_metric(metric_ev(_recent(1, 5), 200.0, if_name="Gi1", path=CTL,
                                             metric="device_if_in_octets", unit="bytes")))
    assert [k[1] for k in main.COUNTER_RATES._last] == [f"{DEVICE}:gi1", f"{DEVICE}:gi1"]


def test_on_a_metric_episode_carries_the_canon_stamp_and_the_canonical_key(lane, canon_on) -> None:
    async def run() -> None:
        for i in range(22):
            await main.handle_metric(metric_ev(_recent(i, 5), 20.0 + (i % 2), device="cEDGE-81",
                                               metric="device_cpu_percent", family="device_resource",
                                               unit="percent"))
        for i in range(22, 26):
            await main.handle_metric(metric_ev(_recent(i, 5), 95.0, device="cEDGE-81",
                                               metric="device_cpu_percent", family="device_resource",
                                               unit="percent"))
    asyncio.run(run())
    onsets = [r for r in lane.rows if r["kind"] == "device_resource_anomaly"]
    assert onsets, "the series must open an episode"
    row = onsets[0]
    attrs = row["attrs"] if isinstance(row["attrs"], dict) else json.loads(row["attrs"])
    assert row["entity_id"] == DEVICE
    assert attrs[CANON_ATTR] == {"raw": "cEDGE-81", "basis": "device:name"}
    assert row["observer_id"] == "cEDGE-81", "the observer is the lane's own, never rewritten"


def test_on_a_metric_episode_with_nothing_to_rewrite_is_unstamped(lane, canon_on) -> None:
    async def run() -> None:
        for i in range(22):
            await main.handle_metric(metric_ev(_recent(i, 5), 20.0 + (i % 2),
                                               metric="device_cpu_percent", family="device_resource",
                                               unit="percent"))
        for i in range(22, 26):
            await main.handle_metric(metric_ev(_recent(i, 5), 95.0, metric="device_cpu_percent",
                                               family="device_resource", unit="percent"))
    asyncio.run(run())
    onsets = [r for r in lane.rows if r["kind"] == "device_resource_anomaly"]
    assert onsets
    attrs = onsets[0]["attrs"] if isinstance(onsets[0]["attrs"], dict) else json.loads(onsets[0]["attrs"])
    assert CANON_ATTR not in attrs


# canonicalize_series — the pure metric-lane rule, against the lab inventory.

def _lab():
    raw = {"devices": {TENANT: [
        {"tenant_id": TENANT, "device": DEVICE, "name": "cEDGE-81", "mgmt_ip": CEDGE81_MGMT},
        {"tenant_id": TENANT, "device": "sw-hp", "name": "hp-edge"},
        {"tenant_id": TENANT, "device": "core-a", "name": "core"},
        {"tenant_id": TENANT, "device": "core-b", "name": "core"},
    ]}, "interface_ips": {}, "ifindex": {TENANT: [
        {"tenant_id": TENANT, "device": DEVICE, "ifindex": "1", "ifname": "GigabitEthernet1"},
        {"tenant_id": TENANT, "device": DEVICE, "ifindex": "7", "ifname": "FiveGigabitEthernet1/0/1"},
        {"tenant_id": TENANT, "device": DEVICE, "ifindex": "8", "ifname": "FiftyGigabitEthernet1/0/1"},
        *({"tenant_id": TENANT, "device": "sw-hp", "ifindex": str(i), "ifname": str(i)}
          for i in range(1, 49)),
        {"tenant_id": TENANT, "device": "sw-hp", "ifindex": "100", "ifname": "Trk1"},
    ]}}
    return identity_resolver_for(raw, TENANT)


def _series(ev: dict, resolver=None, tenant: str = TENANT):
    ident = main.metric_identity(ev)
    assert ident is not None
    eid, _etype, _kp, toks = ident
    return canonicalize_series(ev, eid, toks, _lab() if resolver is None else resolver, tenant)


def _mev(**kw) -> dict:
    base = {"device": DEVICE, "signal_family": "interface"}
    return {**base, **kw}


@pytest.mark.parametrize("ev,entity,outcome", [
    (_mev(if_name="GigabitEthernet1", index="1"), f"{DEVICE}:gi1", REWRITTEN),
    (_mev(if_name="Gi1"), f"{DEVICE}:gi1", REWRITTEN),
    (_mev(index="1"), f"{DEVICE}:gi1", REWRITTEN),                 # declared ifIndex
    (_mev(if_name="gi1"), f"{DEVICE}:gi1", UNCHANGED),             # a fixed point
    (_mev(index="42"), f"{DEVICE}:42", ABSTAIN_UNKNOWN),           # unknown ifIndex: kept
    (_mev(if_name="42"), f"{DEVICE}:42", ABSTAIN_UNKNOWN),         # digits, no declared index
    (_mev(if_name="Fi1/0/1"), f"{DEVICE}:Fi1/0/1", ABSTAIN_AMBIGUOUS),  # 5G vs 50G collision
    (_mev(device="sw-hp", if_name="5", index="5"), "sw-hp:5", UNCHANGED),      # ProCurve name
    (_mev(device="sw-hp", if_name="5"), "sw-hp:5", UNCHANGED),
    (_mev(device="sw-hp", if_name="5", index="100"), "sw-hp:5", ABSTAIN_AMBIGUOUS),
    (_mev(if_name="1", index="1"), f"{DEVICE}:1", ABSTAIN_CONFLICT),  # source says "1", inventory Gi1
    (_mev(device="hp-edge", if_name="5", index="5"), "sw-hp:5", REWRITTEN),
    (_mev(device="core", if_name="Gi1"), "core:Gi1", ABSTAIN_AMBIGUOUS),   # never weld two boxes
    (_mev(device="router", if_name="Gi1"), "router:Gi1", ABSTAIN_GENERIC),
    (_mev(device="ctl-only-9", if_name="GigabitEthernet3"), "ctl-only-9:gi3", REWRITTEN),
    (_mev(signal_family="bgp", peer="2001:0db8:0:0::34"), f"{DEVICE}:2001:db8::34", REWRITTEN),
    (_mev(signal_family="bgp", peer=PEER), f"{DEVICE}:{PEER}", UNCHANGED),
    (_mev(signal_family="bgp", peer="pe-1"), f"{DEVICE}:pe-1", ABSTAIN_UNKNOWN),
    (_mev(signal_family="igp", neighbor="0000.0000.0001"), f"{DEVICE}:0000.0000.0001", UNCHANGED),
    (_mev(device="cEDGE-81", signal_family="igp", neighbor="10.0.0.2"), f"{DEVICE}:10.0.0.2", REWRITTEN),
    (_mev(device=CEDGE81_MGMT, signal_family="device_resource"), DEVICE, REWRITTEN),
    (_mev(signal_family="cloud_resource", index="i-1"), DEVICE, UNCHANGED),   # not an inventory box
])
def test_canonicalize_series_rules(ev, entity, outcome) -> None:
    res = _series(ev)
    assert (res.entity_id, res.outcome) == (entity, outcome), res
    if outcome == REWRITTEN:
        assert res.attrs is not None and res.attrs[CANON_ATTR]["raw"] == main.metric_identity(ev)[0]
    else:
        assert res.attrs is None


def test_canonicalize_series_swaps_device_and_peer_tokens() -> None:
    res = _series(_mev(device="cEDGE-81", signal_family="bgp", peer="2001:0db8::0034"))
    assert res.entity_tokens == (DEVICE, "2001:db8::34")
    assert res.basis == "device:name+peer:ip"


def test_canonicalize_series_is_idempotent() -> None:
    for ev in (_mev(if_name="GigabitEthernet1"), _mev(index="1"),
               _mev(device="cEDGE-81", signal_family="bgp", peer="2001:0db8::0034")):
        once = _series(ev)
        dev, _, part = once.entity_id.partition(":")
        again = canonicalize_series({**ev, "device": dev, "if_name": part, "peer": part},
                                    once.entity_id, once.entity_tokens, _lab(), TENANT)
        assert again.entity_id == once.entity_id and again.outcome == UNCHANGED


def test_canonicalize_series_refuses_another_tenants_resolver() -> None:
    res = _series(_mev(if_name="Gi1"), tenant=OTHER)
    assert res.outcome == ABSTAIN_CONFLICT and res.entity_id == f"{DEVICE}:Gi1"
    unscoped = main.entity_resolver_for(TENANT)
    assert unscoped.tenant is None
    assert _series(_mev(if_name="Gi1"), resolver=unscoped).outcome == ABSTAIN_CONFLICT


def test_canonicalize_series_never_raises_on_hostile_input() -> None:
    r = _lab()
    for ev in ({"device": "x" * 5000, "signal_family": "interface", "if_name": "Gi1"},
               {"device": DEVICE, "signal_family": "interface", "if_name": "\x00\x01"},
               {"device": DEVICE, "signal_family": "interface", "if_name": "Gi1", "index": ["1"]},
               {"device": DEVICE, "signal_family": "interface", "if_name": "Gi1", "vendor": 7},
               {"device": DEVICE, "signal_family": "interface", "if_name": "9" * 40},
               {"device": DEVICE, "signal_family": "bgp", "peer": "::ffff:10.0.0.1"}):
        ident = main.metric_identity(ev)
        if ident is None:
            continue
        res = canonicalize_series(ev, ident[0], ident[3], r, TENANT)
        assert res.outcome in C.OUTCOMES
    assert canonicalize_series("not a mapping", "x", (), r, TENANT).outcome == UNCHANGED  # type: ignore[arg-type]


# ── 5. replay is flag-independent ────────────────────────────────────────────

def _persist_and_rehydrate(snap, window):
    obj_row, edge_rows = snap.to_object_row(1), snap.to_edge_rows(1)
    archive = []
    for s in window:
        row = s.to_ch_row()
        row["archived_for"] = snap.correlation_id
        archive.append(row)
    return StoredObject.from_rows(obj_row, edge_rows), [Signal.from_ch_row(r) for r in archive]


def test_replay_of_an_object_built_with_canon_on_is_identical_with_the_flag_off_and_on(
        canon_on, inventory) -> None:
    window = []
    for sig in (_syslog(BGP_LINE), _rfc_trap(), _controller_peer_in_inventory(), _syslog(LINK_LINE)):
        window.append(_window_row(sig))
    assert {s.entity_id for s in window} == {f"{DEVICE}:{PEER}", f"{DEVICE}:gi1"}
    snaps = run_window(window, builtin_catalog(), ())
    assert snaps, "the canonical window must open an object"
    reports = {}
    for flag in (False, True):
        set_identity_canon(flag)
        for snap in snaps:
            stored, archived = _persist_and_rehydrate(snap, window)
            rep = replay(stored, archived)
            assert rep.clean, rep.differences
            reports.setdefault(snap.correlation_id, []).append(json.dumps(rep.to_dict(), sort_keys=True))
            # the archive carries the canonical entity and the stamp: replay reads them back
            assert {s.entity_id for s in archived} == {s.entity_id for s in window}
    for runs in reports.values():
        assert runs[0] == runs[1]


# ── 6. §3a ───────────────────────────────────────────────────────────────────

def test_two_tenants_with_identical_names_and_addresses_never_cross(canon_on, inventory) -> None:
    mine = _window_row(_syslog(BGP_LINE, tenant=TENANT))
    theirs = _window_row(_syslog(BGP_LINE, tenant=OTHER))
    glob = _window_row(_syslog(BGP_LINE, tenant=""))
    assert mine.entity_id == f"{DEVICE}:{PEER}"
    assert theirs.entity_id == f"{OTHER_DEVICE}:{PEER}"
    assert glob.entity_id == f"global-81:{PEER}" and glob.tenant_id == "global"
    for name in ("cEDGE-81", "cedge-81"):
        assert _window_row(_syslog(LINK_LINE, host=name, tenant=OTHER)).entity_id == f"{OTHER_DEVICE}:gi1"


def test_the_cached_resolver_is_keyed_by_tenant_and_never_unions_global(inventory) -> None:
    a = main.cached_identity_resolver_for(TENANT)
    b = main.cached_identity_resolver_for(OTHER)
    g = main.cached_identity_resolver_for("global")
    assert (a.tenant, b.tenant, g.tenant) == (TENANT, OTHER, "")
    assert a.resolve_device("cEDGE-81") == (DEVICE, "ok"), "a global twin must not make it ambiguous"
    assert b.resolve_device("cEDGE-81") == (OTHER_DEVICE, "ok")
    assert g.resolve_device("cEDGE-81") == ("global-81", "ok")
    assert a.resolve_device("global-81") == (None, "unknown")
    assert main.cached_identity_resolver_for("") is g, "'' and 'global' are one principal"
    assert main.cached_identity_resolver_for(TENANT) is a, "memoized"


def test_the_cache_is_bounded_by_the_files_tenants(inventory) -> None:
    for i in range(500):
        r = main.cached_identity_resolver_for(f"t_spoof_{i}")
        assert r.tenant == f"t_spoof_{i}" and r.resolve_device("cEDGE-81") == (None, "unknown")
    main.cached_identity_resolver_for(TENANT)
    assert set(main._identity_resolver_cache) <= {TENANT, OTHER, ""}


def test_the_cache_follows_the_file(inventory) -> None:
    assert main.cached_identity_resolver_for(OTHER).resolve_device("cEDGE-81")[0] == OTHER_DEVICE
    _resolver_file(inventory, with_other=False)
    st = os.stat(inventory)
    os.utime(inventory, (st.st_atime, st.st_mtime + 10))
    assert main.cached_identity_resolver_for(OTHER).resolve_device("cEDGE-81") == (None, "unknown")


def test_a_metric_sample_for_another_tenant_uses_that_tenants_inventory(lane, canon_on) -> None:
    async def run() -> None:
        await main.handle_metric(metric_ev(_recent(0, 5), 1.0, device="cEDGE-81", if_name="Gi1",
                                           tenant=OTHER))
        await main.handle_metric(metric_ev(_recent(0, 6), 1.0, device="cEDGE-81", if_name="Gi1"))
    asyncio.run(run())
    assert set(main.DETECTOR._state) == {(OTHER, f"{OTHER_DEVICE}:gi1", "device_if_oper_status"),
                                         (TENANT, f"{DEVICE}:gi1", "device_if_oper_status")}
