"""Confirmability audit gates (#98 Phase 3). The audit itself lives in
confirmability.py; these tests make its honesty CI-enforced:

  * every emitted kind must be modality-classified (else independence math lies);
  * matchable p0 signatures must be confirmable_now or carry a structured,
    ticketed exception with a target resolution;
  * the audit must agree with the engine on the ground truths we know
    (saas-experience = entity_mismatch until Phase 4 lands).
"""

from catalog import builtin_catalog
from confirmability import (
    APP_GROUNDABLE_KINDS,
    DEMO_CONFIRMABILITY_EXCEPTIONS,
    KIND_MODALITY,
    audit,
    reconciliation,
    write_reports,
)
from producers import EMITTED_KINDS

CAT = builtin_catalog()
ROWS = {r["signature_id"]: r for r in audit(CAT)}


def test_every_emitted_kind_is_modality_classified():
    unmapped = EMITTED_KINDS - frozenset(KIND_MODALITY)
    assert not unmapped, (
        f"emitted kind(s) missing from KIND_MODALITY: {sorted(unmapped)} — the "
        f"confirmability audit cannot do independence math over unclassified kinds; "
        f"add each with the ModalityClass its producer stamps."
    )
    stale = frozenset(KIND_MODALITY) - EMITTED_KINDS
    assert not stale, f"KIND_MODALITY lists unemitted kinds (remove): {sorted(stale)}"


def test_app_groundable_is_a_subset_of_emitted():
    assert APP_GROUNDABLE_KINDS <= EMITTED_KINDS
    # Phase 4 shipped: app-ATTRIBUTED flow anomalies ground on the app entity
    # (flow_app_attribution.py); unattributed flows stay interface-grounded,
    # which test_flow_app_attribution.py asserts separately.
    assert "flow_volume_anomaly" in APP_GROUNDABLE_KINDS


def test_audit_covers_every_enabled_signature():
    assert set(ROWS) == {t.id for t in CAT.enabled_templates()}
    valid_status = {
        "confirmable_now", "suspected_only", "not_matchable",
        "collection_pending", "normalization_pending",
        "entity_mismatch", "modality_mismatch",
    }
    for r in ROWS.values():
        assert r["status"] in valid_status, r
        assert r["max_possible_verdict"] in ("confirmed", "suspected", "not_matchable"), r


def test_known_ground_truths():
    # The #98 app signature: Phase 4 flipped it — app-attributed passive flow
    # reaches the app entity, so active_probe + passive_flow can confirm
    # (proven end-to-end by test_flow_app_attribution.py test D).
    saas = ROWS["sig.ent.app.saas-experience-degraded"]
    assert saas["status"] == "confirmable_now"
    assert saas["max_possible_verdict"] == "confirmed"
    # three independent app-groundable witness classes since Phase 5:
    # synthetics (probe), app-attributed flow, and the LB/app-edge lane.
    assert sorted(saas["app_groundable_classes"]) == [
        "active_probe", "device_telemetry", "passive_flow"]

    # spine-leaf demands device_telemetry whose witnesses (if_errors/if_crc)
    # are a normalization gap → verdict capped at suspected.
    spine = ROWS["sig.ent.fabric.spine-leaf-path-degradation"]
    assert spine["status"] == "modality_mismatch"
    assert spine["max_possible_verdict"] == "suspected"

    # a healthy two-modality signature is confirmable now.
    assert ROWS["sig.ent.middle-mile.dia-egress-corroborated"]["status"] == "confirmable_now"


def test_p0_signatures_are_confirmable():
    # The demo gate: every MATCHABLE p0 signature must reach confirmed today or
    # carry a structured exception. Unmatchable p0s are governed by the
    # coverage ledgers (catalog-leads-ingestion policy), not this gate.
    failures = []
    for r in ROWS.values():
        if r["priority"] != "p0":
            continue
        if r["status"] in ("collection_pending", "normalization_pending", "not_matchable"):
            continue  # unmatchable — gated by coverage.py ledgers
        if r["status"] == "confirmable_now":
            continue
        exc = DEMO_CONFIRMABILITY_EXCEPTIONS.get(r["signature_id"])
        if not exc or not exc.get("reason") or not exc.get("target_resolution"):
            failures.append(
                f"Signature {r['signature_id']} is p0 but cannot reach confirmed "
                f"(status={r['status']}; available classes: "
                f"{', '.join(r['producer_classes_available']) or 'none'}). Add an "
                f"independent corroborator or a structured DEMO_CONFIRMABILITY_EXCEPTIONS "
                f"entry with reason + target_resolution."
            )
    assert not failures, "\n".join(failures)


def test_exceptions_are_not_stale():
    # An exception for a signature that is now confirmable (or gone) must be
    # deleted — exceptions are temporary by construction.
    for sig_id, exc in DEMO_CONFIRMABILITY_EXCEPTIONS.items():
        assert sig_id in ROWS, f"exception for unknown signature {sig_id}"
        assert ROWS[sig_id]["status"] != "confirmable_now", (
            f"{sig_id} is confirmable now — remove its stale exception"
        )
        assert exc.get("owner") and exc.get("date_added"), sig_id


def test_confirmability_ratchet_never_decreases():
    # #99 R4: the confirmable_now count is a one-way ratchet. A catalog or
    # producer change that silently darkens a signature fails here; a change
    # that brightens one must bump confirmability_baseline.json in the same
    # commit (keeping the floor honest).
    import json
    from pathlib import Path
    baseline_path = Path(__file__).parent / "confirmability_baseline.json"
    baseline = json.loads(baseline_path.read_text())["confirmable_now"]
    now = sum(1 for r in ROWS.values() if r["status"] == "confirmable_now")
    assert now >= baseline, (
        f"confirmable_now dropped: {now} < baseline {baseline} — a signature "
        f"that could reach confirmed no longer can. Find the darkened "
        f"signature(s) in the audit (python3 confirmability.py) and fix the "
        f"producer/catalog regression; lowering the baseline requires an "
        f"explicit owner decision."
    )
    if now > baseline:
        import warnings
        warnings.warn(
            f"confirmable_now rose to {now} (baseline {baseline}) — bump "
            f"confirmability_baseline.json to lock in the gain.")


def test_reconciliation_table_is_consistent():
    rows = {r["kind"]: r for r in reconciliation(CAT)}
    # every emitted kind appears, with its coverage classification
    for k in EMITTED_KINDS:
        assert k in rows and rows[k]["emitted"]
    # a fully-connected example both emits and is consumed
    teams_kind = rows["synthetic_http_5xx"]
    assert teams_kind["class"] == "fully_connected"
    assert "sig.ent.app.saas-experience-degraded" in teams_kind["consuming_signatures"]
    # the flow kind is app-groundable since Phase 4 (attribution-gated)
    assert rows["flow_volume_anomaly"]["app_groundable"] is True


def test_write_reports(tmp_path):
    written = write_reports(str(tmp_path))
    assert len(written) == 2
    for p in written:
        assert tmp_path in __import__("pathlib").Path(p).parents or str(tmp_path) in p
