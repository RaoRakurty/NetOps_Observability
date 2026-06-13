"""Pytest: catalog invariants + conformance replay + explicit canonical assertions.

Run:  cd telemetry-catalog && python3 -m pytest -q
"""
import json
import os

import pytest

import catalog
import conformance
from normalize import load_catalog, normalize_event

HERE = os.path.dirname(os.path.abspath(__file__))


def test_catalog_invariants_clean():
    problems = catalog.check()
    assert problems == [], "catalog invariant violations:\n" + "\n".join(problems)


def test_conformance_replay_clean():
    checked, problems = conformance.run()
    assert checked >= 3, f"expected >=3 validated fixtures, got {checked}"
    assert problems == [], "conformance failures:\n" + "\n".join(problems)


# ---- explicit canonical-output assertions (the product-truth anchors) ----

@pytest.fixture(scope="module")
def cat():
    return load_catalog()


def _one(events_file, vendor, cat):
    out = []
    for line in open(os.path.join(HERE, events_file)):
        if line.strip():
            out.extend(normalize_event(json.loads(line), vendor=vendor, cat=cat))
    return out


def test_srl_bgp_established_maps_to_6(cat):
    series = _one("fixtures/nokia_srl_24.10_bgp_native_once.jsonl", "nokia", cat)
    est = [s for s in series if s["labels"].get("peer") == "10.0.0.11"]
    assert est and est[0]["name"] == "device_bgp_peer_state"
    assert est[0]["value"] == 6, "SRL 'established' must map to BGP4-MIB 6"
    assert est[0]["labels"]["vrf"] == "default"
    assert est[0]["labels"]["vendor"] == "nokia"
    assert est[0]["labels"]["transport"] == "gnmi"
    # plumbing tags must be gone
    assert "subscription-name" not in est[0]["labels"]


def test_ceos_bgp_active_maps_to_3(cat):
    series = _one("fixtures/arista_ceos_4.36_bgp_oc_once.jsonl", "arista", cat)
    assert series and series[0]["name"] == "device_bgp_peer_state"
    assert series[0]["value"] == 3, "cEOS 'ACTIVE' must map to BGP4-MIB 3"
    assert series[0]["labels"]["peer"] == "192.168.100.5"
    # protocol_identifier/protocol_name plumbing dropped
    assert "protocol_identifier" not in series[0]["labels"]


def test_ceos_oper_status_up_maps_to_1(cat):
    series = _one("fixtures/arista_ceos_4.36_if_operstatus_oc_once.jsonl", "arista", cat)
    assert series and series[0]["name"] == "device_if_oper_status"
    assert series[0]["value"] == 1, "'UP' must map to ifOperStatus 1"
    assert "ifName" in series[0]["labels"]


def test_srl_memory_is_gauge(cat):
    series = _one("fixtures/nokia_srl_24.10_memory_native_once.jsonl", "nokia", cat)
    mem = [s for s in series if s["name"] == "device_mem_percent"]
    assert mem, "memory/utilization must map to device_mem_percent"
    assert 0 <= mem[0]["value"] <= 100, "must be a 0-100 percent gauge"
    # the free/physical/reserved leaves must NOT produce canonical series (fail-closed)
    assert all(s["name"] == "device_mem_percent" for s in series)


def test_unknown_enum_token_is_dropped_not_emitted(cat):
    ev = {"tags": {"source": "x:6030"},
          "values": {"/interfaces/interface/state/oper-status": "BOGUS_STATE"}}
    assert normalize_event(ev, vendor="arista", cat=cat) == []


def test_unmapped_path_is_dropped(cat):
    ev = {"tags": {"source": "x:6030"}, "values": {"/some/unmapped/path": 5}}
    assert normalize_event(ev, vendor="arista", cat=cat) == []
