"""gNMI fidelity-status conformance (Layer 6 D/E — critical test #5).

Enforces the honesty contract for gNMI telemetry claims (catalog:
src/config/gnmi_fidelity.yaml). gNMI metric→correlation is Phase 2 and NOT yet
wired; this guards the SEPARATE claim of "what gNMI we can collect" so it can
never be overstated from vendor docs, and pins the cEOS leaf-BGP degraded case.

Run:  python3 -m pytest tests/test_gnmi_fidelity.py -v
"""
import os

import yaml

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
CATALOG = os.path.join(ROOT, "src", "config", "gnmi_fidelity.yaml")

VALID_STATUS = {"live_validated", "lab_validated", "doc_claimed", "degraded", "failed"}
# Only these two statuses may be surfaced as "supported / validated".
SUPPORTED_STATUS = {"live_validated", "lab_validated"}


def is_supported(status: str) -> bool:
    """The single gate the UI/API/catalog must use to decide whether a gNMI
    capability may be advertised. doc_claimed / degraded / failed are NOT."""
    return status in SUPPORTED_STATUS


def load_rows():
    with open(CATALOG) as fh:
        return yaml.safe_load(fh)["rows"]


def test_every_row_has_a_valid_status():
    for r in load_rows():
        assert r["status"] in VALID_STATUS, f"unknown status {r['status']} in {r}"


def test_doc_claimed_is_not_supported():
    """A doc_claimed row (vendor docs only, no validation here) must NEVER be
    treated as supported — DoD #8."""
    doc_rows = [r for r in load_rows() if r["status"] == "doc_claimed"]
    assert doc_rows, "expected at least one doc_claimed row to guard the rule"
    for r in doc_rows:
        assert not is_supported(r["status"]), f"doc_claimed advertised as supported: {r}"


def test_degraded_is_not_advertised_as_validated():
    for r in load_rows():
        if r["status"] == "degraded":
            assert not is_supported(r["status"]), f"degraded advertised as validated: {r}"


def test_ceos_leaf_bgp_persistent_multitarget_is_degraded():
    """The known cEOS regression: leaf BGP subscribe works standalone but fails in
    the persistent multi-target collector. It must stay pinned 'degraded' so the
    catalog/UI/API cannot claim fully-validated cEOS BGP streaming — DoD #9."""
    rows = load_rows()
    match = [r for r in rows
             if r["vendor"] == "arista" and r["platform"] == "ceos"
             and r["signal_family"] == "bgp_peer_state"
             and r["collector_mode"] == "persistent_multi_target"]
    assert match, "cEOS persistent-multi-target BGP row missing — regression unguarded"
    for r in match:
        assert r["status"] == "degraded", \
            f"cEOS leaf BGP persistent-multi-target must be 'degraded', got {r['status']}"
        assert not is_supported(r["status"])


def test_validated_rows_have_evidence_notes():
    """A row may only be *_validated if it carries a note (evidence pointer) —
    no silent promotion to validated."""
    for r in load_rows():
        if is_supported(r["status"]):
            assert r.get("notes", "").strip(), f"validated row without evidence note: {r}"
