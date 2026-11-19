# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""N-H6 step 4 — the seasonal SHADOW score (seasonal_shadow.py).

The owner's ruling (2026-11-19), made mechanical: "the correlation engine's
truest intention shouldn't be diverted." The shadow may INFORM (counters) and
must never DECIDE. Proven here:

  * decision-neutrality: the episode lane emits byte-identical corr_signals
    rows, window signals, return values and detector state with the shadow OFF
    and with it ON and actively scoring — across a routine weekly peak (the
    seasonal reading says "usual"), a genuine anomaly ("unusual"), no history,
    a counter-rate metric, and a shadow that raises;
  * isolation: nothing the engine decides with imports or reads the shadow
    (static), and a tenant's profile never serves another tenant's same-named
    series; the profile read runs at the tenant's own scope with no tenant text
    in the SQL;
  * parity: the maths reproduces the Go package's fixture exactly
    (src/backend/internal/nlquery/seasonal/testdata/parity.json);
  * bounds and failure: a failed read is counted and retried later, never raised.
"""
from __future__ import annotations

import ast
import asyncio
import json
import math
import os
from datetime import datetime, timedelta, timezone

import pytest

import main
import seasonal_shadow as ss
from episodes import EpisodeDetector

HERE = os.path.dirname(os.path.abspath(__file__))
PARITY = os.path.join(HERE, "..", "backend", "internal", "nlquery", "seasonal", "testdata", "parity.json")

T0 = datetime(2026, 11, 19, 10, 0, 0, tzinfo=timezone.utc)
TENANT = "t_acme"


def _read(*parts: str) -> str:
    with open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


# ── parity with the Go package ────────────────────────────────────────────────
def test_maths_reproduces_the_go_parity_fixture():
    with open(PARITY, encoding="utf-8") as fh:
        fx = json.load(fh)
    now = datetime.strptime(fx["now"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    assert len(fx["cases"]) >= 5, "parity fixture rotted"
    for c in fx["cases"]:
        def refs(items):
            return [ss.Ref(at=now - timedelta(hours=r["offset_hours"]), value=float(r["value"]),
                           present=r["present"], excluded=r["excluded"]) for r in items]
        assert ss.unit_floor(c["unit"]) == pytest.approx(c["floor"], abs=1e-12), c["name"]
        p = ss.fit(now, refs(c["weekly"]), refs(c["daily"]), c["floor"])
        w = c["want"]
        assert (p.tier, p.used, p.considered, p.excluded, p.history_days) == \
            (w["tier"], w["used"], w["considered"], w["excluded"], w["history_days"]), c["name"]
        assert math.isclose(p.centre, w["centre"], abs_tol=1e-9), c["name"]
        assert math.isclose(p.scale, w["scale"], abs_tol=1e-9), c["name"]
        z = p.z(c["x"])
        if w["z"] is None:
            assert z is None, c["name"]
        else:
            assert z is not None and math.isclose(z, w["z"], abs_tol=1e-9), c["name"]


def test_constants_match_the_go_package():
    go = _read(HERE, "..", "backend", "internal", "nlquery", "seasonal", "seasonal.go")
    for name, val in [("MaxWeeks", ss.MAX_WEEKS), ("MaxDays", ss.MAX_DAYS), ("MinWeeks", ss.MIN_WEEKS),
                      ("MinDays", ss.MIN_DAYS), ("MADScale", ss.MAD_SCALE), ("RelFloor", ss.REL_FLOOR),
                      ("AboveZ", ss.ABOVE_Z)]:
        assert f"{name}" in go
        line = next(ln for ln in go.splitlines() if ln.strip().startswith(name) and "=" in ln)
        assert float(line.split("=")[1].split("//")[0].strip()) == float(val), name


def test_metric_map_matches_the_api_rollup_metrics():
    go = _read(HERE, "..", "backend", "path_health_baselines.go")
    for m in ss.METRIC_MAP.values():
        assert f'Name: "{m.series_metric}"' in go, m.series_metric


# ── isolation ─────────────────────────────────────────────────────────────────
DECISION_MODULES = ("engine", "scoring", "verdicts", "catalog", "producers", "signals", "episodes",
                    "replay", "rank_memo", "confirmability", "evidence_plane", "aggregation")


def _imports(path: str) -> set[str]:
    tree = ast.parse(_read(path))
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.add(node.module.split(".")[0])
    return out


def test_no_decision_module_imports_the_shadow_and_the_shadow_imports_none():
    for mod in DECISION_MODULES:
        p = os.path.join(HERE, f"{mod}.py")
        if os.path.exists(p):
            assert "seasonal_shadow" not in _imports(p), f"{mod}.py must never read the shadow"
    assert not (_imports(os.path.join(HERE, "seasonal_shadow.py")) & set(DECISION_MODULES))


def test_main_only_feeds_and_reports_the_shadow():
    """In main.py the shadow is only fed (the hook) and reported (metrics,
    healthz). Any other read of it would be a path from shadow to decision."""
    src = _read(HERE, "main.py")
    uses = [ln.strip() for ln in src.splitlines() if "SEASONAL_SHADOW" in ln and not ln.strip().startswith("#")]
    allowed = ("SEASONAL_SHADOW = SeasonalShadow()", "if SEASONAL_SHADOW.enabled:",
               "need = SEASONAL_SHADOW.observe(", "SEASONAL_SHADOW.errors += 1",
               "if query is None or not SEASONAL_SHADOW.claim(*need):",
               "task = asyncio.get_running_loop().create_task(SEASONAL_SHADOW.refresh(",
               "SEASONAL_SHADOW.release(*need)", "lines += SEASONAL_SHADOW.metrics_lines()",
               '"seasonal_shadow": SEASONAL_SHADOW.health(),')
    for ln in uses:
        assert ln.startswith(allowed), f"unexpected use of the shadow in main.py: {ln}"


def _profile_rows(series: str, key: str, h: datetime, weekly: list[float], daily: list[float]):
    wk, dy = ss.reference_hours(h)
    rows = {}
    for x, v in zip(wk, weekly):
        rows[int(x.timestamp())] = v
    for x, v in zip(dy, daily):
        rows[int(x.timestamp())] = v
    return {(series, key): rows}


def test_a_tenants_profile_never_serves_another_tenants_same_named_series():
    sh = ss.SeasonalShadow(enabled=True)
    h = ss.hour_start(T0)
    sh._store("t_acme", h, _profile_rows("cpu_util_pct", "edge-1", h, [300, 300, 300, 300], []), failed=False)
    sh._store("t_globex", h, {}, failed=False)
    sh.observe("t_acme", "edge-1", "device_cpu_percent", T0, 305.0, onset=True)
    sh.observe("t_globex", "edge-1", "device_cpu_percent", T0, 305.0, onset=True)
    assert sh.onsets[("seasonal_quiet", "A")] == 1      # acme: its own usual peak
    assert sh.onsets[("no_baseline", "C")] == 1         # globex: never acme's rows


def test_the_profile_read_runs_at_the_tenants_own_scope():
    sh = ss.SeasonalShadow(enabled=True)
    seen = []

    async def query(sql, tenant):
        seen.append((sql, tenant))
        return []

    assert sh.claim("t_acme", int(ss.hour_start(T0).timestamp()))
    asyncio.run(sh.refresh("t_acme", int(ss.hour_start(T0).timestamp()), query))
    assert seen and seen[0][1] == "t_acme"
    assert "t_acme" not in seen[0][0] and "tenant" not in seen[0][0].lower()
    assert "netops.series_hourly FINAL" in seen[0][0] and "LIMIT" in seen[0][0]
    # The platform partition and an unrecognised tenant are never read.
    assert not sh.claim("global", 1) and not sh.claim("Bad Tenant!", 1)
    assert sh.reads["skipped"] == 2


def test_a_failed_read_is_counted_and_retried_later_never_raised():
    clock = [1000.0]
    sh = ss.SeasonalShadow(enabled=True, retry_s=300, clock=lambda: clock[0])
    hts = int(ss.hour_start(T0).timestamp())

    async def boom(sql, tenant):
        raise RuntimeError("clickhouse down")

    assert sh.claim(TENANT, hts)
    asyncio.run(sh.refresh(TENANT, hts, boom))
    assert sh.reads["failed"] == 1
    assert sh.observe(TENANT, "edge-1", "device_cpu_percent", T0, 50.0, onset=False) is None  # not yet
    clock[0] += 301
    assert sh.observe(TENANT, "edge-1", "device_cpu_percent", T0, 50.0, onset=False) == (TENANT, hts)


def test_bounds_hold():
    sh = ss.SeasonalShadow(enabled=True, max_tenants=2, max_inflight=1)
    h = ss.hour_start(T0)
    for t in ("t_a", "t_b", "t_c"):
        sh._store(t, h, {}, failed=False)
    assert list(sh._tenants) == ["t_b", "t_c"]
    assert sh.claim("t_a", 1) and not sh.claim("t_b", 1), "the in-flight bound held"
    # An older hour's slow read never replaces a newer profile.
    sh._store("t_c", h - timedelta(hours=1), {("x", "y"): {1: 1.0}}, failed=False)
    assert sh._tenants["t_c"].hour == h and not sh._tenants["t_c"].rows


# ── the owner's rule: decision-neutrality through the real episode lane ──────
class _Sink:
    def __init__(self):
        self.rows: list[str] = []
        self.window: list[str] = []

    async def batch(self, row):
        self.rows.append(json.dumps(row, sort_keys=True, default=str))

    def buffer(self, sig):
        self.window.append(json.dumps(sig.to_ch_row(), sort_keys=True, default=str))


def _series(base: float, peak: float) -> list[tuple[datetime, float]]:
    pts = []
    for i in range(30):                       # baseline: ~base with deterministic wobble
        pts.append((T0 + timedelta(minutes=i), base + (i % 5 - 2)))
    for i in range(30, 40):                   # the peak the detector opens on
        pts.append((T0 + timedelta(minutes=i), peak + (i % 3)))
    for i in range(40, 50):                   # back to normal → the episode clears
        pts.append((T0 + timedelta(minutes=i), base + (i % 5 - 2)))
    return pts


def _run_lane(monkeypatch, shadow: ss.SeasonalShadow, metric: str, entity: str,
              pts, raise_in_shadow: bool = False):
    sink = _Sink()
    monkeypatch.setattr(main, "DETECTOR", EpisodeDetector())
    monkeypatch.setattr(main, "ch", object())
    monkeypatch.setattr(main, "CORR_SIGNALS_ENABLED", True)
    monkeypatch.setattr(main, "batch_signal", sink.batch)
    monkeypatch.setattr(main, "agg_admit", lambda sig: sig)
    monkeypatch.setattr(main, "buffer_signal", sink.buffer)
    monkeypatch.setattr(main, "SEASONAL_SHADOW", shadow)
    if raise_in_shadow:
        def boom(*a, **k):
            raise ValueError("shadow bug")
        monkeypatch.setattr(shadow, "observe", boom)
    returns = []

    async def drive():
        for ts, v in pts:
            returns.append(await main.feed_episode_detector(
                TENANT, entity, metric, v, ts,
                observer_id=entity.split(":")[0], collection_path="snmp_poll",
                entity_type=main.EntityType.DEVICE, kind_prefix="device_resource_anomaly",
                entity_tokens=(entity.split(":")[0],)))
    asyncio.run(drive())
    state = {k: (s.open, s.onset_ts, s.peak, s.frozen_mean, s.frozen_std, list(s.values))
             for k, s in main.DETECTOR._state.items()}
    return sink.rows, sink.window, returns, state


SCENARIOS = [
    # (name, metric, entity, base, peak, profile weekly p50s (None = no rows), expected onset outcome)
    ("routine weekly peak: the seasonal reading says usual", "device_cpu_percent", "edge-1",
     40.0, 85.0, [85.0, 86.0, 84.0, 85.0], ("seasonal_quiet", "A")),
    ("genuine anomaly: unusual for this time of week too", "device_cpu_percent", "edge-1",
     40.0, 85.0, [40.0, 41.0, 39.0, 40.0], ("seasonal_confirms", "A")),
    ("no history: tier C", "device_mem_percent", "edge-2",
     30.0, 90.0, None, ("no_baseline", "C")),
    ("counter rate octets/s mapped to the roll-up's bits/s", "device_if_in_octets", "edge-1:Gi1",
     1.0e5, 9.0e5, [7.2e6, 7.2e6, 7.3e6, 7.1e6], ("seasonal_quiet", "A")),
]


@pytest.mark.parametrize("name,metric,entity,base,peak,weekly,outcome", SCENARIOS)
def test_the_episode_lane_is_identical_with_the_shadow_off_and_on(
        monkeypatch, name, metric, entity, base, peak, weekly, outcome):
    pts = _series(base, peak)
    off = _run_lane(monkeypatch, ss.SeasonalShadow(enabled=False), metric, entity, pts)

    on_shadow = ss.SeasonalShadow(enabled=True)
    h = ss.hour_start(T0)
    m = ss.METRIC_MAP[metric]
    key = ss.entity_key(entity, m.key)
    rows = _profile_rows(m.series_metric, key, h, weekly, []) if weekly else {}
    on_shadow._store(TENANT, h, rows, failed=False)
    on = _run_lane(monkeypatch, on_shadow, metric, entity, pts)

    assert any("onset" in r for r in off[0]), f"{name}: the scenario must open an episode"
    assert off == on, f"{name}: the shadow changed what the episode lane emitted or decided"
    # ...and the shadow DID run and say what it was built to say.
    assert on_shadow.onsets[outcome] >= 1, (name, on_shadow.onsets)
    assert sum(on_shadow.samples[k] for k in ("A", "B", "C")) == len(pts)


def test_a_shadow_that_raises_never_reaches_the_episode_lane(monkeypatch):
    pts = _series(40.0, 85.0)
    off = _run_lane(monkeypatch, ss.SeasonalShadow(enabled=False), "device_cpu_percent", "edge-1", pts)
    broken = ss.SeasonalShadow(enabled=True)
    on = _run_lane(monkeypatch, broken, "device_cpu_percent", "edge-1", pts, raise_in_shadow=True)
    assert off == on
    assert broken.errors == len(pts)


def test_a_profile_fetch_is_started_off_the_hot_path_and_scoped(monkeypatch):
    """With nothing loaded, the first sample schedules ONE background read at
    the tenant's scope; the lane's own output is unaffected."""
    seen = []

    class FakeCH:
        async def query_scoped(self, sql, tenant):
            seen.append(tenant)
            return []

    pts = _series(40.0, 85.0)[:3]
    off = _run_lane(monkeypatch, ss.SeasonalShadow(enabled=False), "device_cpu_percent", "edge-1", pts)
    shadow = ss.SeasonalShadow(enabled=True)
    sink = _Sink()
    monkeypatch.setattr(main, "DETECTOR", EpisodeDetector())
    monkeypatch.setattr(main, "ch", FakeCH())
    monkeypatch.setattr(main, "batch_signal", sink.batch)
    monkeypatch.setattr(main, "agg_admit", lambda sig: sig)
    monkeypatch.setattr(main, "buffer_signal", sink.buffer)
    monkeypatch.setattr(main, "SEASONAL_SHADOW", shadow)

    async def drive():
        out = []
        for ts, v in pts:
            out.append(await main.feed_episode_detector(
                TENANT, "edge-1", "device_cpu_percent", v, ts, observer_id="edge-1",
                collection_path="snmp_poll", entity_type=main.EntityType.DEVICE,
                kind_prefix="device_resource_anomaly", entity_tokens=("edge-1",)))
        await asyncio.gather(*list(main._SHADOW_TASKS))
        return out
    returns = asyncio.run(drive())
    assert returns == off[2] and sink.rows == off[0]
    assert seen == [TENANT], "exactly one scoped read for the tenant's hour"
    assert shadow.reads["ok"] == 1 and shadow.samples["pending"] >= 1


def test_metrics_and_health_expose_the_shadow():
    sh = ss.SeasonalShadow(enabled=True)
    text = "\n".join(sh.metrics_lines())
    for name in ("corr_seasonal_shadow_enabled 1", 'corr_seasonal_shadow_samples_total{tier="A"}',
                 'corr_seasonal_shadow_onsets_total{outcome="seasonal_quiet",tier="A"}',
                 'corr_seasonal_shadow_profile_reads_total{result="failed"}',
                 "corr_seasonal_shadow_errors_total 0"):
        assert name in text, name
    h = sh.health()
    assert h["enabled"] is True and "seasonal_quiet_A" in h["onsets"]
    assert "seasonal_shadow" in main._health_payload()
    assert "corr_seasonal_shadow_enabled" in main._metrics_text()


def test_off_by_default():
    assert ss._flag("CORR_SEASONAL_SHADOW_UNSET_FOR_TEST", "0") is False
    src = _read(HERE, "seasonal_shadow.py")
    assert 'CORR_SEASONAL_SHADOW = _flag("CORR_SEASONAL_SHADOW", "0")' in src
