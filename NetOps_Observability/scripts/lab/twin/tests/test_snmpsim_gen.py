# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""snmpsim data-file generation: golden-file pin (deterministic .snmprec from
the example topology) + manifest shape the supervisor consumes."""
import json
import os

from conftest import REPO_ROOT
from scenario import load_scenario
from snmpsim_gen import engine_id_hex, generate_agents, snmprec_for_device

EXAMPLE = os.path.join(REPO_ROOT, "docs", "design", "examples",
                       "twin-scenario-example.yaml")
GOLDEN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden",
                      "edge-a1.snmprec")


def _example():
    return load_scenario(EXAMPLE)


def test_snmprec_matches_golden():
    sc = _example()
    dev = next(d for d in sc["devices"] if d["name"] == "edge-a1")
    sites = {s["id"]: str(s.get("name") or s["id"]) for s in sc["sites"]}
    rec = snmprec_for_device(dev, "twx-golden-", sites, int(sc["meta"]["seed"]))
    with open(GOLDEN, encoding="utf-8") as f:
        assert rec == f.read()


def test_snmprec_is_oid_sorted_and_carries_identity():
    sc = _example()
    dev = next(d for d in sc["devices"] if d["name"] == "br-b1")
    rec = snmprec_for_device(dev, "twx-t-", {}, 1)
    oids = [tuple(int(x) for x in line.split("|")[0].split("."))
            for line in rec.strip().splitlines()]
    assert oids == sorted(oids), "snmpsim requires OID-sorted data files"
    assert "1.3.6.1.2.1.1.5.0|4|twx-t-br-b1\n" in rec       # sysName == device
    assert "1.3.6.1.2.1.31.1.1.1.1.1|4|GigabitEthernet0/0\n" in rec  # ifName


def test_generate_agents_manifest(tmp_path):
    sc = _example()
    addrs = {d["name"]: f"198.19.0.{i + 1}"
             for i, d in enumerate(sc["devices"])}
    manifest = generate_agents(sc, "twx-m1-", addrs, str(tmp_path), "gen-1")
    assert manifest["generation"] == "gen-1"
    assert len(manifest["agents"]) == len(sc["devices"])
    with open(tmp_path / "manifest.json", encoding="utf-8") as f:
        assert json.load(f) == manifest
    by_dev = {a["device"]: a for a in manifest["agents"]}
    a1 = by_dev["twx-m1-edge-a1"]                 # v3 device in the example
    assert a1["ip"] == addrs["edge-a1"] and a1["port"] == 161
    assert a1["v3"]["user"] == "twin-sim"
    assert a1["v3"]["auth_proto"] == "SHA" and a1["v3"]["priv_proto"] == "AES"
    assert a1["v3"]["engine_id"] == engine_id_hex("twx-m1-edge-a1")
    core = by_dev["twx-m1-core-a1"]               # v2c device
    assert core["v3"] is None and core["community"] == "twin-public"
    # per-device data dir with the community-named data file
    assert (tmp_path / "twx-m1-core-a1" / "twin-public.snmprec").is_file()
    assert (tmp_path / "twx-m1-edge-a1" / "public.snmprec").is_file()


def test_engine_id_deterministic_and_distinct():
    assert engine_id_hex("a") == engine_id_hex("a")
    assert engine_id_hex("a") != engine_id_hex("b")
    assert len(engine_id_hex("a")) == 26 and engine_id_hex("a").startswith("80")
