# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Pytest: the source-equivalence matrix is computed, honest and ratcheted.

What this file proves (design docs/design/NMS_DEVICE_IDENTITY_2026-11-01.md
§7a/§7b, E0):

  1. CONSISTENT — evidence.yaml validates against what the code supplies right
     now: no undeclared gap, no stale declaration, no undeclared orphan or
     registry-drift kind, every registered connector present.
  2. GUARDED — each of those rules actually fires (the analyser is fed a broken
     model and must refuse it), so a green run is not a green no-op.
  3. DERIVED — the connector kind parser still reads the Go normalizers (a regex
     that silently matched nothing would make every connector look empty).
  4. CURRENT — the checked-in matrix doc is exactly what the generator emits.
  5. RATCHETED — no customer profile's matchable-template count drops below
     source_equivalence_baseline.json.
"""
from __future__ import annotations

import copy
import json
import os

import pytest

import source_equivalence as S


@pytest.fixture(scope="module")
def model() -> dict:
    return S.load_model()


@pytest.fixture(scope="module")
def analysis(model: dict) -> dict:
    return S.analyse(model)


def _broken(model: dict, mutate) -> dict:
    m = copy.deepcopy(model)
    mutate(m)
    return m


def _source(m: dict, sid: str) -> dict:
    return next(s for s in m["sources"] if s["id"] == sid)


# 1. consistent ------------------------------------------------------------------

def test_model_is_consistent_with_the_code(analysis: dict) -> None:
    assert analysis["profiles"], "no profile was scored"


def test_every_cell_is_native_or_a_reasoned_gap(model: dict, analysis: dict) -> None:
    for s in model["sources"]:
        for e in model["evidence_types"]:
            cell = analysis["cells"][s["id"]][e["id"]]
            if cell["status"] == "native":
                assert cell["kinds"], f"{s['id']} × {e['id']}: native without a kind"
            else:
                assert cell["detail"].strip(), f"{s['id']} × {e['id']}: gap without a reason"


# 2. guarded ----------------------------------------------------------------------

def test_an_undeclared_gap_is_refused(model: dict) -> None:
    m = _broken(model, lambda m: _source(m, "vmanage")["gaps"].pop("l2_control"))
    with pytest.raises(S.EquivalenceError, match=r"vmanage × l2_control: not supplied and not declared"):
        S.analyse(m)


def test_a_stale_gap_declaration_is_refused(model: dict) -> None:
    # vManage supplies overlay_tunnel natively; declaring it a gap is stale.
    def mutate(m: dict) -> None:
        _source(m, "vmanage")["gaps"]["overlay_tunnel"] = {"status": "collection_pending", "detail": "x"}
    with pytest.raises(S.EquivalenceError, match=r"vmanage × overlay_tunnel: declared .* but the code now supplies"):
        S.analyse(_broken(model, mutate))


def test_an_undeclared_orphan_kind_is_refused(model: dict) -> None:
    m = _broken(model, lambda m: m["orphan_kinds"].pop("controller_alarm"))
    with pytest.raises(S.EquivalenceError, match=r"controller_alarm"):
        S.analyse(m)


def test_a_healed_orphan_declaration_is_refused(model: dict) -> None:
    def mutate(m: dict) -> None:
        m["orphan_kinds"]["controller_never_emitted"] = {"reason": "r", "fix": "f"}
    with pytest.raises(S.EquivalenceError, match=r"no longer orphaned"):
        S.analyse(_broken(model, mutate))


def test_undeclared_registry_drift_is_refused(model: dict) -> None:
    m = _broken(model, lambda m: m["registry_drift"].pop("pcs_local_fault"))
    with pytest.raises(S.EquivalenceError, match=r"coverage registry calls pending, undeclared: pcs_local_fault"):
        S.analyse(m)


def test_a_missing_connector_is_refused(model: dict) -> None:
    def mutate(m: dict) -> None:
        m["sources"] = [s for s in m["sources"] if s["id"] != "meraki"]
        for p in m["profiles"].values():
            p["sources"] = [x for x in p["sources"] if x != "meraki"]
    with pytest.raises(S.EquivalenceError, match=r"registered connector\(s\) with no source entry: \['meraki'\]"):
        S.analyse(_broken(model, mutate))


def test_an_unknown_engine_kind_is_refused(model: dict) -> None:
    def mutate(m: dict) -> None:
        m["evidence_types"][0]["engine_kinds"].append("no_such_kind_anywhere")
    with pytest.raises(S.EquivalenceError, match=r"engine does not know kind"):
        S.analyse(_broken(model, mutate))


def test_a_gap_without_a_reason_is_refused(model: dict) -> None:
    def mutate(m: dict) -> None:
        _source(m, "flow")["gaps"]["link_state"]["detail"] = "  "
    with pytest.raises(S.EquivalenceError, match=r"a gap needs a `detail`"):
        S.analyse(_broken(model, mutate))


# 3. derived ----------------------------------------------------------------------

def test_every_registered_connector_has_its_normalizer_files() -> None:
    for vendor in S.registered_connectors():
        files = S.CONNECTOR_FILES.get(vendor)
        assert files, f"connector {vendor}: add its normalizer file(s) to CONNECTOR_FILES"
        for f in files:
            assert os.path.exists(os.path.join(S.NMS_DIR, f)), f"{vendor}: {f} not found"


def test_the_go_kind_parser_still_reads_the_normalizers() -> None:
    vm = S.connector_kinds("vmanage")
    for k in ("controller_bfd_down", "controller_tunnel_state", "controller_alarm"):
        assert k in vm, f"vManage normalizer parse lost {k} — the regex no longer matches the Go source"
    # The SD-WAN state table's KEYS are states, never kinds.
    assert "device_health" not in vm
    # E2a: the canonical kind table (nms/vmanage_kinds.go) is read too, and a
    # `StateKind:` value is never mistaken for a kind.
    for k in ("bgp_adjacency_change", "link_state_change", "ospf_adjacency_change", "device_restart"):
        assert k in vm, f"vManage kind table parse lost {k}"
    for state in ("bgp", "ospf", "interface", "control_conn", "omp", "bfd"):
        assert state not in vm, f"state name {state!r} parsed as a kind"
    # E3: the canonical METRIC table yields the episode kinds the engine makes
    # of those samples, as it does for SNMP.
    vm_metrics = S.connector_metric_kinds("vmanage")
    assert {"if_metric_anomaly", "device_resource_anomaly"} <= vm_metrics, vm_metrics


def test_runtime_rule_supply_excludes_grammar_only_rows() -> None:
    assert "pan_threat" not in S.rule_kinds("syslog"), "lane: catalog rows supply nothing at runtime"


# 4. current ----------------------------------------------------------------------

def test_matrix_doc_is_current(model: dict, analysis: dict) -> None:
    with open(S.TARGET, encoding="utf-8") as fh:
        assert fh.read() == S.render(model, analysis), \
            "docs/design/source-equivalence-matrix.md is stale — run python3 source_equivalence.py"


# 5. ratcheted --------------------------------------------------------------------

def test_no_profile_loses_matchable_templates(analysis: dict) -> None:
    with open(S.BASELINE, encoding="utf-8") as fh:
        baseline = json.load(fh)
    now = S.baseline_of(analysis)
    assert set(baseline) == set(now), "profiles changed — re-run with --write-baseline and justify it"
    dropped = {p: (baseline[p], now[p]) for p in now if now[p] < baseline[p]}
    assert not dropped, f"profile(s) lost matchable templates (baseline, now): {dropped}"


def test_doc_claimed_supply_is_marked_apart(model: dict, analysis: dict) -> None:
    """A mapping computed from code but never proven by a recorded payload must
    not read the same as a lab-validated one."""
    doc = S.render(model, analysis)
    meraki = next(s for s in model["sources"] if s["id"] == "meraki")
    assert meraki.get("fidelity") == "doc_claimed"
    assert analysis["cells"]["meraki"]["link_state"]["status"] == "native"
    assert "✅ᵈ" in doc and "doc_claimed" in doc
    vmanage = next(s for s in model["sources"] if s["id"] == "vmanage")
    assert vmanage.get("fidelity") == "lab_validated"
