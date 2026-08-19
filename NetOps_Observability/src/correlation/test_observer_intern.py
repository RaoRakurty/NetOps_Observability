"""Tracker 156 — interned Observers must be value-identical and bounded.

A syslog line rebuilt a per-DEVICE Observer on every event: thousands of
identical immutable objects per second, each also retained for as long as its
Signal sits in the evidence window. `observer_of` reuses one per distinct
(device, type, path, ...).

Two things must hold: the interned object must be indistinguishable from a
freshly constructed one (it is handed to the independence gate), and the cache
must be bounded, because observer_id comes from an untrusted device.
"""
from __future__ import annotations

import dataclasses

import pytest
import signals as S


@pytest.fixture(autouse=True)
def _clear():
    S._OBSERVER_CACHE.clear()
    yield
    S._OBSERVER_CACHE.clear()


def test_interned_observer_equals_a_constructed_one():
    a = S.observer_of("leaf1", S.ObserverType.DEVICE,
                      collection_path="direct", clock_quality="unknown")
    b = S.Observer(observer_id="leaf1", observer_type=S.ObserverType.DEVICE,
                   collection_path="direct", clock_quality="unknown")
    assert a == b
    assert dataclasses.asdict(a) == dataclasses.asdict(b)


def test_same_arguments_return_the_same_object():
    a = S.observer_of("leaf1", S.ObserverType.DEVICE)
    b = S.observer_of("leaf1", S.ObserverType.DEVICE)
    assert a is b, "identical observers should be shared, not rebuilt"
    assert len(S._OBSERVER_CACHE) == 1


@pytest.mark.parametrize("kw", [
    {"observer_id": "leaf2"},
    {"observer_type": S.ObserverType.CONTROLLER},
    {"location": "dc1"},
    {"trust_domain": "cloud_tenant"},
    {"collection_path": "via_controller"},
    {"clock_quality": "ptp"},
])
def test_every_field_participates_in_identity(kw):
    """A cache that ignored a field would hand out a WRONG observer."""
    base = {"observer_id": "leaf1", "observer_type": S.ObserverType.DEVICE,
            "location": "", "trust_domain": "", "collection_path": "direct",
            "clock_quality": "unknown"}
    a = S.observer_of(base.pop("observer_id"), base.pop("observer_type"), **base)
    other = {"observer_id": "leaf1", "observer_type": S.ObserverType.DEVICE,
             "location": "", "trust_domain": "", "collection_path": "direct",
             "clock_quality": "unknown"}
    other.update(kw)
    b = S.observer_of(other.pop("observer_id"), other.pop("observer_type"), **other)
    assert a is not b, f"changing {next(iter(kw))} must produce a different observer"
    assert a != b


def test_cache_is_bounded_and_evicts_oldest(monkeypatch):
    monkeypatch.setattr(S, "OBSERVER_CACHE_MAX", 10)
    before = S.OBSERVER_CACHE_EVICTED
    for i in range(50):
        S.observer_of(f"dev{i}", S.ObserverType.DEVICE)
    assert len(S._OBSERVER_CACHE) <= 11, "cache grew past its bound"
    assert S.OBSERVER_CACHE_EVICTED > before, "evictions are not counted"


def test_eviction_still_returns_a_correct_observer(monkeypatch):
    """Overflow degrades to 'build a fresh one', never to a wrong one."""
    monkeypatch.setattr(S, "OBSERVER_CACHE_MAX", 2)
    for i in range(20):
        obs = S.observer_of(f"dev{i}", S.ObserverType.DEVICE)
        assert obs.observer_id == f"dev{i}"
        assert obs == S.Observer(observer_id=f"dev{i}",
                                 observer_type=S.ObserverType.DEVICE)


def test_a_hostile_varying_observer_id_cannot_grow_it_without_bound(monkeypatch):
    monkeypatch.setattr(S, "OBSERVER_CACHE_MAX", 100)
    for i in range(5000):
        S.observer_of(f"attacker-{i}", S.ObserverType.DEVICE)
    assert len(S._OBSERVER_CACHE) <= 101


def test_capping_still_applies_through_the_cache():
    """__post_init__ caps oversized labels; the cached instance is capped too."""
    huge = "x" * 5000
    obs = S.observer_of(huge, S.ObserverType.DEVICE)
    assert len(obs.observer_id) < len(huge)
    assert obs.observer_id == S.Observer(observer_id=huge,
                                         observer_type=S.ObserverType.DEVICE).observer_id


def test_empty_observer_id_still_raises_through_the_cache():
    with pytest.raises(S.DeadLetter):
        S.observer_of("", S.ObserverType.DEVICE)
