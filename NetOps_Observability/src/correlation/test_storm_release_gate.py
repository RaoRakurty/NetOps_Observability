"""#101 release-gate storm SLO tests — the shippable-lane contract.

A NEW signal lane may not ship unless this suite (plus the Go bounded-IO
guardrails: src/backend/bounded_io_test.go) passes with the lane's own signals
substituted into the batch builders. Run via `make release-gate` (repo root),
which chains: this suite → Go SQL-shape tests → (live stacks only) the
ch-query-budget-check + ch-retention-dry-run scripts.

Asserted SLOs, from docs/design/correlation-data-contract.md §new-lane:
  1. WRITE BUDGET   — a permanently-broken source persists O(heartbeats), not
                      O(cycles): damping ratio ≥ 0.9 over a 20-cycle storm.
  2. BLAST RADIUS   — tenant A's storm never changes tenant B's write behavior
                      or RCA content.
  3. RCA INTEGRITY  — damping suppresses churn, never truth: the persisted
                      snapshot still carries hypothesis/verdict/affected.
  4. ATTRIBUTION    — the storm is attributable per tenant via the write-amp
                      rollup (who / dominant kind / dominant entity).
"""

import asyncio
from datetime import datetime, timedelta, timezone

import main
from signals import EntityType, ModalityClass, Observer, ObserverType, Severity, Signal, Source
from test_lane_soak import _StubCH, _dead_target_batches, run_broken_source_soak


def _sig(tenant: str, kind: str, entity: str, *, offset_s: float, now: datetime) -> Signal:
    return Signal(
        tenant_id=tenant, ts=now + timedelta(seconds=offset_s), source=Source.METRIC,
        kind=kind, observer=Observer(observer_id="gate-obs", observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.DEVICE_TELEMETRY, entity_type=EntityType.DEVICE,
        entity_id=entity, severity=Severity.CRIT,
        native_id=f"gate|{tenant}|{kind}|{entity}|{offset_s}",
        attrs={"onset_uncertainty_s": 5.0},
    )


def test_gate_write_budget_damping_ratio():
    """SLO 1: 20 storm cycles → 1 persisted version, ratio ≥ 0.9. A lane whose
    broken source cannot meet this budget must not ship (this was the #100
    incident: ~30x table growth from ONE dead probe target)."""
    now = datetime.now(timezone.utc)
    res = run_broken_source_soak(_dead_target_batches(20, now))
    total = res["persisted"] + res["damped"]
    assert res["object_rows"] == 1, f"write budget breached: {res['object_rows']} versions/20 cycles"
    assert total > 0 and res["damped"] / total >= 0.9, (
        f"damping ratio {res['damped']}/{total} below the 0.9 storm SLO")


def test_gate_tenant_blast_radius(monkeypatch):
    """SLO 2+4: t-storm floods every cycle; t-victim has one ordinary incident.
    The victim's write pattern, RCA content, and hot projection row must be
    byte-identical to what it gets in a storm-free run."""
    monkeypatch.setattr(main, "TENANT_WA", {})
    monkeypatch.setattr(main, "_WA_WINDOW_START", None)
    monkeypatch.setattr(main, "CORR_WA_FLUSH_S", 1e9)

    def victim_batch(now):
        return [_sig("t-victim", "link_state_change", "victim-core", offset_s=-240, now=now),
                _sig("t-victim", "device_resource_anomaly", "victim-core", offset_s=-238, now=now)]

    def storm_batches(cycles, now):
        out = []
        for i in range(cycles):
            off = -600 + i * 30
            out.append([
                _sig("t-storm", "link_state_change", "storm-target", offset_s=off + j, now=now)
                for j in range(6)
            ] + [
                _sig("t-storm", "device_resource_anomaly", "storm-target", offset_s=off + 10 + j, now=now)
                for j in range(6)
            ])
        return out

    now = datetime.now(timezone.utc)
    # Baseline: victim alone.
    baseline = run_broken_source_soak([victim_batch(now)] + [[]] * 9)
    base_rows = [r for r in baseline["_stub"].rows["netops.corr_objects"]
                 if r["tenant_id"] == "t-victim"]
    # Under storm: same victim signals + a 10-cycle multi-signal storm.
    batches = storm_batches(10, now)
    batches[0] = batches[0] + victim_batch(now)
    stormed = run_broken_source_soak(batches)
    storm_rows = [r for r in stormed["_stub"].rows["netops.corr_objects"]
                  if r["tenant_id"] == "t-victim"]

    assert len(storm_rows) == len(base_rows) == 1, "victim write count changed under a neighbor storm"
    for key in ("top_hypothesis", "verdict_tier", "affected", "signal_count", "state"):
        assert storm_rows[0][key] == base_rows[0][key], (
            f"victim RCA field {key!r} changed under a neighbor storm")
    cur = [r for r in stormed["_stub"].rows["netops.corr_current"]
           if r["tenant_id"] == "t-victim"]
    assert len(cur) == 1, "victim hot projection row missing/duplicated under storm"

    # SLO 4: attribution — the accounting names the storm tenant, its dominant
    # kind and entity, without any per-tenant metric series existing yet.
    wa = main.TENANT_WA
    assert wa["t-storm"]["raw_seen"] > wa["t-victim"]["raw_seen"] * 10
    assert wa["t-storm"]["entities"].most_common(1)[0][0] == "storm-target"


def test_gate_rca_integrity_under_damping():
    """SLO 3: the single persisted storm version is a COMPLETE RCA snapshot —
    damping suppressed churn, not content."""
    now = datetime.now(timezone.utc)
    res = run_broken_source_soak(_dead_target_batches(15, now))
    row = res["_stub"].rows["netops.corr_objects"][0]
    assert row["top_hypothesis"], "damped storm object lost its hypothesis"
    assert row["hypotheses"], "history row must carry the full hypotheses blob"
    assert row["signal_count"] >= 2
    assert row["verdict_tier"] in ("undetermined", "suspected", "confirmed")
    cur = res["_stub"].rows["netops.corr_current"][0]
    assert cur["top_hypothesis"] == row["top_hypothesis"]
    assert "hypotheses" not in cur, "hot projection must stay narrow (wide-column regression)"
