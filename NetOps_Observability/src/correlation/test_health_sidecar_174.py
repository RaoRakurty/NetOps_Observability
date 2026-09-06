# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 174 — health/metrics must survive a saturated event loop.

THE MEASURED DEFECT (S1 run 082220005r1a): /healthz + /metrics are served by
the loop that the storm starves (worst stall 49.3s), so 4s probes timed out —
Docker health flapped on a HEALTHY process and the completion gate read a
replica as unreadable. In an orchestrator that acts on liveness, that is a
self-inflicted restart mid-storm.

THE CONTRACT PINNED HERE: saturation degrades FRESHNESS, never REACHABILITY.
  * the sidecar answers from a published snapshot with NO asyncio loop
    involved at all (the strongest form of the stalled-loop case);
  * a frozen snapshot AGES — age is stamped on both bodies and the stale flag
    flips past CORR_HEALTH_STALE_AFTER_S, while the response stays HTTP 200
    (the age IS the storm signal, unreachability would destroy it);
  * before the first snapshot the sidecar says 503 "starting", never garbage;
  * the sidecar and the in-app route share ONE builder, so they cannot drift;
  * port <= 0 disables the sidecar entirely.
"""
from __future__ import annotations

import json
import time
import urllib.request

import pytest

import main


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    monkeypatch.setattr(main, "_HEALTH_SNAPSHOT", None)
    monkeypatch.setattr(main, "HEALTH_SNAPSHOTS_BUILT", 0)
    monkeypatch.setattr(main, "CORR_HEALTH_STALE_AFTER_S", 10.0)
    yield


# ── the pure response path ───────────────────────────────────────────────────

def test_before_first_snapshot_is_starting_never_garbage():
    status, _ctype, body = main._sidecar_response("/healthz")
    assert status == 503 and json.loads(body)["status"] == "starting"


def test_healthz_snapshot_carries_age_and_shares_the_builder():
    main._publish_health_snapshot()
    status, _, body = main._sidecar_response("/healthz")
    got = json.loads(body)
    assert status == 200 and got["status"] == "ok"
    assert 0.0 <= got["snapshot_age_s"] < 5.0 and got["snapshot_stale"] is False
    # single-builder: the sidecar body is the route payload + the two stamps
    route = main._health_payload()
    got.pop("snapshot_age_s"); got.pop("snapshot_stale")
    assert set(got) == set(route), "sidecar /healthz drifted from the route"


def test_metrics_snapshot_appends_the_age_gauges():
    main._publish_health_snapshot()
    status, ctype, body = main._sidecar_response("/metrics")
    text = body.decode()
    assert status == 200 and ctype.startswith("text/plain")
    assert text.startswith(main._HEALTH_SNAPSHOT["metrics"][:40])
    assert "corr_health_snapshot_age_s " in text
    assert "corr_health_snapshot_stale 0" in text


def test_stale_snapshot_stays_reachable_and_says_so(monkeypatch):
    """THE invariant: a starving publisher makes the snapshot OLD, never the
    endpoint DEAD — the age is the storm signal."""
    main._publish_health_snapshot()
    main._HEALTH_SNAPSHOT["built_mono"] = time.monotonic() - 60.0
    status, _, body = main._sidecar_response("/healthz")
    got = json.loads(body)
    assert status == 200, "a stale snapshot became unreachable — the defect is back"
    assert got["snapshot_stale"] is True and got["snapshot_age_s"] > 50
    _, _, m = main._sidecar_response("/metrics")
    assert "corr_health_snapshot_stale 1" in m.decode()


def test_unknown_path_is_404():
    main._publish_health_snapshot()
    assert main._sidecar_response("/correlations")[0] == 404


# ── the live thread server, with NO asyncio loop anywhere ────────────────────

def test_sidecar_thread_serves_while_no_loop_exists(monkeypatch):
    """The strongest stalled-loop simulation: no asyncio loop is running AT
    ALL in this process, and the sidecar must still answer both endpoints.
    (A 49s-stalled loop is strictly weaker than a nonexistent one.)"""
    main._publish_health_snapshot()
    monkeypatch.setattr(main, "CORR_HEALTH_SIDECAR_PORT", 0)  # pick ephemeral
    # port 0 disables via _start_health_sidecar; bind ephemeral explicitly:
    monkeypatch.setattr(main, "CORR_HEALTH_SIDECAR_PORT", 18094)
    srv = main._start_health_sidecar()
    assert srv is not None
    try:
        with urllib.request.urlopen("http://127.0.0.1:18094/healthz", timeout=5) as r:
            got = json.loads(r.read())
            assert r.status == 200 and got["status"] == "ok"
            assert "snapshot_age_s" in got
        with urllib.request.urlopen("http://127.0.0.1:18094/metrics", timeout=5) as r:
            assert b"corr_health_snapshot_age_s" in r.read()
    finally:
        srv.shutdown()


def test_disabled_port_starts_nothing(monkeypatch):
    monkeypatch.setattr(main, "CORR_HEALTH_SIDECAR_PORT", 0)
    assert main._start_health_sidecar() is None


def test_publisher_failure_keeps_the_previous_snapshot(monkeypatch):
    """§10: a broken builder must not take the sidecar down with it — the
    previous snapshot keeps serving (and keeps AGING, which is the signal)."""
    main._publish_health_snapshot()
    before = main._HEALTH_SNAPSHOT
    monkeypatch.setattr(main, "_health_payload",
                        lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(RuntimeError):
        main._publish_health_snapshot()
    assert main._HEALTH_SNAPSHOT is before, (
        "a failed rebuild clobbered the last good snapshot")
    assert main._sidecar_response("/healthz")[0] == 200


def test_lifespan_starts_the_sidecar_wiring_pin():
    """The 2026-08-24 first-deploy defect: every sidecar piece existed and the
    snapshot feed task ran, but lifespan never called _start_health_sidecar()
    — nothing listened on :8094 and the new healthcheck failed on refused
    connections. Pin the wiring, not just the parts."""
    import inspect
    src = inspect.getsource(main.lifespan)
    assert "_start_health_sidecar()" in src
    assert "health_snapshot_loop()" in src


# ── tracker 208b (ultra-review #43): one health build per snapshot tick ──────

def test_health_payload_is_built_once_per_snapshot_tick(monkeypatch):
    """The publisher renders TWO bodies from ONE set of numbers.

    `_publish_health_snapshot` builds the /healthz body and the /metrics body,
    and `_metrics_text` used to call `_health_payload()` for itself — so every
    tick walked the whole health surface twice for a value it already had in
    hand. The snapshot loop runs on CORR_HEALTH_SNAPSHOT_S (2 s by default) for
    the life of the process, and it runs ON the main loop precisely because the
    reads must be race-free, which makes wasted work there loop time the storm
    cannot use.

    The count is the assertion: exactly one build per tick, whatever the number
    of bodies rendered from it.
    """
    calls = {"n": 0}
    real = main._health_payload

    def counting():
        calls["n"] += 1
        return real()

    monkeypatch.setattr(main, "_health_payload", counting)
    main._publish_health_snapshot()
    assert calls["n"] == 1, (
        f"_health_payload built {calls['n']} times in ONE snapshot tick — the "
        "publisher and _metrics_text are each building their own again")

    # A second tick is one more build, not two: the memo is per-tick, not cached
    # across ticks (a cached snapshot would freeze the numbers).
    main._publish_health_snapshot()
    assert calls["n"] == 2


def test_snapshot_bodies_are_rendered_from_the_same_health_payload():
    """Handing the payload through is what makes the two bodies consistent.

    Both are rendered from ONE dict now, so a counter that moves between the two
    renders can no longer make /healthz and /metrics in the SAME snapshot
    disagree. Pinned on a field both bodies carry.
    """
    main._publish_health_snapshot()
    snap = main._HEALTH_SNAPSHOT
    assert snap is not None
    health = snap["health"]
    metrics = snap["metrics"]
    assert isinstance(health, dict) and isinstance(metrics, str)
    open_objects = health["engine_v2"]["open_objects"]
    assert f"corr_open_objects {open_objects}" in metrics, (
        "the metrics body was not rendered from the snapshot's own health payload")


def test_metrics_text_still_builds_its_own_payload_when_not_given_one():
    """The /metrics ROUTE passes nothing and must keep working exactly as before
    — the parameter is an optimisation for the publisher, never a requirement."""
    body = main._metrics_text()
    assert body.startswith("# HELP ")
    assert "corr_open_objects " in body
    # And an explicitly passed payload must be the one used, not a fresh read.
    injected = dict(main._health_payload())
    injected["engine_v2"] = dict(injected["engine_v2"])
    injected["engine_v2"]["open_objects"] = 123456
    assert "corr_open_objects 123456" in main._metrics_text(injected)
