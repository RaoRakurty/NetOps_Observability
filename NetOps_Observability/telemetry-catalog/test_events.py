"""Pytest: event/parser catalog — grammar parsing + the correlation invariant.

The fixtures carry an embedded `_expect` (the canonical event the parser must
produce, or null for non-events). This is the event-plane analogue of the metric
conformance harness.
"""
import json
import os

import pytest

from parse_events import EventCatalog, parse_event
from normalize import load_catalog as load_metric_catalog

HERE = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture(scope="module")
def cat():
    return EventCatalog.load()


def _fixtures():
    rows = []
    for line in open(os.path.join(HERE, "fixtures/syslog_events.jsonl")):
        if line.strip():
            rows.append(json.loads(line))
    return rows


@pytest.mark.parametrize("row", _fixtures(), ids=lambda r: r.get("appname", "?"))
def test_syslog_parses_to_expected_canonical_event(row, cat):
    expect = row.get("_expect")
    ev = {k: v for k, v in row.items() if k != "_expect"}
    got = parse_event(ev, cat)
    if expect is None:
        assert got is None, f"non-event should not parse, got {got}"
        return
    assert got is not None, f"expected an event, got None for {ev['appname']}"
    assert got["event_type"] == expect["event_type"]
    assert got["state"] == expect["state"]
    assert got["severity"] == expect["severity"]
    # tracker 184 adds `stp_instance` (the STP instance/VLAN a TCN names) and
    # `mac` (the moving MAC) — checked here so a fixture cannot claim an
    # attribution the grammar does not actually extract.
    for key in ("device", "peer", "ifName", "stp_instance", "mac"):
        if key in expect:
            assert got["labels"].get(key) == expect[key], \
                f"{key}: expected {expect[key]!r}, got {got['labels'].get(key)!r}"


def test_correlation_invariant_join_keys_are_real_identity_keys(cat):
    """Every event family's join_on keys must be canonical identity keys AND must
    be labels the event actually produces — otherwise events can't join metrics."""
    metric_cat = load_metric_catalog()
    # canonical identity keys = the label space the metric plane uses too
    known = set()
    for fam in metric_cat.families.values():
        known.update(fam["labels"])
    for fname, fam in cat.families.items():
        join = fam.get("join_on", [])
        assert join, f"event family '{fname}' declares no join_on (cannot correlate)"
        produced = set(fam.get("labels", {}).keys())
        for k in join:
            assert k in produced, f"{fname}: join_on '{k}' is not a label the parser produces"
            assert k in known, f"{fname}: join_on '{k}' is not a canonical identity key used by metrics"


def test_bgp_event_joins_bgp_metric_on_device_peer(cat):
    """The product-truth anchor: a BGP adjchange event and device_bgp_peer_state
    metric share (device, peer) so they correlate to the same session."""
    ev = {"hostname": "leaf1", "appname": "%BGP-5-ADJCHANGE",
          "message": "peer 10.0.0.1 old state Established new state Idle"}
    got = parse_event(ev, cat)
    assert got["correlates_with"] == "device_bgp_peer_state"
    assert got["join_on"] == ["device", "peer"]
    assert got["labels"]["device"] == "leaf1" and got["labels"]["peer"] == "10.0.0.1"
    # the metric for the same session (from the gNMI fixture) carries the same keys
    # device=leaf1, peer=10.0.0.1 — proven in test_catalog.py — so they join.
