"""Tracker 156 v2 — the corpus falsification gate.

THE CLAIM THIS FILE EXISTS TO FALSIFY (and, failing that, to pin): a
component-only archive slice replays CLEAN for EVERY object the engine
produces, across every component shape the engine can build — not just the
one fixture the 2026-08-22 adversarial review happened to test.

Both reviews accepted the pair-locality exactness argument but required this
corpus run as the ship gate (docs/scale/ARCHIVE_REDESIGN_156_2026-08-22.md
§7): if ANY object here drifts when replayed from its component slice, the v2
membership rule is wrong and the change must stop.

Shapes covered: containment components (device+interface), multi-interface
components, singleton objects (no edges), shared-token (rank-7 candidate)
components, objects with matched app-identity signals, objects surrounded by
heavy ambient noise (the exact case whose slice used to be window-sized), and
in/out-of-bounds clears.

Run:  python3 -m pytest test_archive_corpus_replay_156.py -v
"""

from __future__ import annotations

import pytest

import main
from engine import EngineConfig, run_window
from replay import StoredObject, replay
from signals import EntityType, Severity, Source
from test_archive_slice import CAT, _window, sig


def _estate_window(n_devices: int, offset_step: float = 30.0):
    """n containment components: each device contributes a device node plus an
    interface node, close enough in time to form one object per device."""
    window = []
    for d in range(n_devices):
        base = d * offset_step
        window.append(sig("device_cpu_high", EntityType.DEVICE, f"edge-{d}",
                          offset_s=base))
        window.append(sig("if_errors", EntityType.INTERFACE, f"edge-{d}:Gi0/1",
                          offset_s=base + 10))
        window.append(sig("if_errors", EntityType.INTERFACE, f"edge-{d}:Gi0/2",
                          offset_s=base + 20))
    return window


def _singleton_window(n: int):
    """Isolated HIGH-severity signals: singleton objects, zero edges."""
    return [sig("device_cpu_high", EntityType.DEVICE, f"lone-{i}", offset_s=i * 40)
            for i in range(n)]


def _shared_token_window():
    """Two devices joined only by a shared token — a rank-7 candidate edge."""
    return [
        sig("device_cpu_high", EntityType.DEVICE, "tok-a",
            tokens=("svc-shared",), offset_s=0),
        sig("device_cpu_high", EntityType.DEVICE, "tok-b",
            tokens=("svc-shared",), offset_s=30),
    ]


def _identity_window():
    """A component whose object matches an app-identity enrichment signal."""
    return [
        sig("device_cpu_high", EntityType.DEVICE, "id-edge", offset_s=0),
        sig("if_errors", EntityType.INTERFACE, "id-edge:Gi0/1", offset_s=15),
        sig("app_identity", EntityType.APP, "CrmApp", offset_s=200,
            source=Source.APP_IDENTITY, severity=Severity.INFO,
            tokens=("id-edge",)),
        sig("if_errors_clear", EntityType.INTERFACE, "id-edge:Gi0/1", offset_s=5),
        sig("if_errors_clear", EntityType.INTERFACE, "far-dev:Et1", offset_s=900),
    ]


def _noisy_window():
    """One real component drowned in ambient single-signal noise from 30 other
    devices — the shape whose slice was window-sized under the old rule."""
    window = [
        sig("device_cpu_high", EntityType.DEVICE, "victim", offset_s=0),
        sig("if_errors", EntityType.INTERFACE, "victim:Gi0/1", offset_s=10),
    ]
    window += [sig("metric_anomaly", EntityType.DEVICE, f"amb-{i}",
                   offset_s=2 + (i % 20)) for i in range(30)]
    return window


def _grown_dallas():
    window, _ = _window()
    return window + [sig("if_errors", EntityType.INTERFACE, "dallas-edge:Gi0/1",
                         offset_s=15)]


CORPUS = {
    "dallas-fixture": lambda: _window()[0],
    "dallas-grown": _grown_dallas,
    "estate-8": lambda: _estate_window(8),
    "estate-dense": lambda: _estate_window(6, offset_step=5.0),
    "singletons": lambda: _singleton_window(10),
    "shared-token": _shared_token_window,
    "identity-matched": _identity_window,
    "noisy": _noisy_window,
}


@pytest.mark.parametrize("name", sorted(CORPUS))
def test_every_object_replays_clean_from_its_component_slice(name):
    window = CORPUS[name]()
    snapshots = run_window(tuple(window), CAT, (), EngineConfig())
    assert snapshots, f"corpus window {name!r} produced no objects — dead fixture"
    for snap in snapshots:
        slice_sigs = main._archive_slice(snap, window)
        stored = StoredObject.from_rows(snap.to_object_row(1, "open"),
                                        snap.to_edge_rows(1))
        report = replay(stored, slice_sigs)
        assert report.engine_pin_match and report.catalog_pin_match
        assert report.clean, (
            f"corpus window {name!r}, object {snap.correlation_id[:8]} "
            f"({len(snap.nodes)} nodes, {len(snap.edges)} edges): component-"
            f"slice replay DRIFTED: {report.differences} — the v2 membership "
            f"rule is wrong for this shape; STOP and revisit the design's §9")


@pytest.mark.parametrize("name", sorted(CORPUS))
def test_slices_are_component_sized_never_window_sized(name):
    """The write-amplification half of the gate, corpus-wide: each slice's
    non-loose rows are exactly its component's signals — ambient nodes never
    ride along."""
    window = CORPUS[name]()
    for snap in run_window(tuple(window), CAT, (), EngineConfig()):
        slice_ids = {s.signal_id for s in main._archive_slice(snap, window)}
        comp_ids = {s.signal_id for n in snap.nodes for s in n.signals}
        loose_ok = {s.signal_id for s in window
                    if s.kind.endswith("_clear") or s.source is Source.APP_IDENTITY}
        assert comp_ids <= slice_ids, "component not node-complete in its slice"
        assert slice_ids - comp_ids <= loose_ok, (
            "slice contains ambient NODE signals beyond the component")


def test_the_noisy_slice_is_actually_small():
    """The measured defect, in miniature: 30 ambient devices must contribute 0
    rows to the victim object's slice."""
    window = _noisy_window()
    snaps = run_window(tuple(window), CAT, (), EngineConfig())
    victim = next(s for s in snaps if "victim" in s.affected().get("devices", []))
    assert len(main._archive_slice(victim, window)) == 2
