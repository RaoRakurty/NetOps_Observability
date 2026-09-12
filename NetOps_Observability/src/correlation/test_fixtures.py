# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Per-signature replay fixtures — the CI gate on the catalog (research C7).

Every signature ships with scenario fixtures under fixtures/: at least one
where it must fire, and look-alike scenarios where its competitor must win.
A catalog change that breaks a scenario blocks the merge — the catalog is a
falsifiable, CI-tested artifact, not configuration.

Fixture shape (JSON):
{
  "name": "...",
  "signals": [{"kind": ..., "entity_type": ..., "entity_id": ...,
               "observer_id": ..., "observer_type": ..., "modality": ...,
               "deviation": ..., "collection_path": ..., "ts_offset_s": ...}],
  "expect": {"top": "sig...", "tier": "confirmed|suspected|undetermined",
             "min_confidence": 0.0..1.0, "owner": "..."}
}
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from catalog import builtin_catalog
from scoring import rank
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

T0 = datetime(2026, 6, 11, 12, 0, 0, tzinfo=timezone.utc)
FIXTURE_DIR = Path(__file__).parent / "fixtures"

MODALITY_SOURCE = {
    ModalityClass.ACTIVE_PROBE: Source.PROBE,
    ModalityClass.PASSIVE_FLOW: Source.FLOW,
    ModalityClass.CONTROL_PLANE: Source.TOPOLOGY,
    ModalityClass.DEVICE_TELEMETRY: Source.METRIC,
    ModalityClass.MANAGEMENT_PLANE: Source.CONTROLLER,  # NMS controller intelligence
    # T2b evidence-class bus: a rule/benchmark/advisory VERDICT, its own plane
    # (signals.EVIDENCE_CLASSES). Source mirrors the lane exactly as the others do.
    ModalityClass.SECURITY: Source.SECURITY,
}


def signal_from_fixture(spec: dict, idx: int) -> Signal:
    modality = ModalityClass(spec["modality"])
    attrs = dict(spec.get("attrs", {}))
    # Fixtures model REAL incident scenarios, so their probes are real vantages:
    # default active_probe to HIGH authority unless the fixture says otherwise
    # (low/debug fixtures set probe_authority explicitly). Fate inputs pass through.
    if modality is ModalityClass.ACTIVE_PROBE:
        attrs.setdefault("probe_authority", spec.get("probe_authority", "high"))
        for k in ("agent_host", "source_egress", "seam_id", "schedule_id", "probe_scope"):
            if k in spec:
                attrs.setdefault(k, spec[k])
    return Signal(
        tenant_id="t1",
        ts=T0 + timedelta(seconds=float(spec.get("ts_offset_s", idx))),
        source=MODALITY_SOURCE[modality],
        kind=spec["kind"],
        observer=Observer(
            observer_id=spec["observer_id"],
            observer_type=ObserverType(spec.get("observer_type", "device")),
            collection_path=spec.get("collection_path", "direct"),
        ),
        modality_class=modality,
        entity_type=EntityType(spec.get("entity_type", "device")),
        entity_id=spec.get("entity_id", spec["observer_id"]),
        severity=Severity.WARN,
        native_id=f"fixture|{idx}|{spec['kind']}",
        deviation=float(spec.get("deviation", 0.0)),
        attrs=attrs,
    )


def fixture_files() -> list[Path]:
    # Top level only: fixtures/golden_wire/ holds RAW collector-shaped events
    # with their own driver (test_golden_wire.py), not Signal-level fixtures.
    files = sorted(FIXTURE_DIR.glob("*.json"))
    assert files, f"no fixtures under {FIXTURE_DIR} — the catalog CI gate is empty"
    return files


def every_signature_has_a_fixture() -> None:
    covered = set()
    for f in fixture_files():
        data = json.loads(f.read_text())
        covered.add(data["expect"]["top"])
    required = {t.id for t in builtin_catalog().enabled_templates()}
    missing = required - covered
    assert not missing, f"signatures with no positive fixture: {sorted(missing)}"


def test_every_signature_has_a_positive_fixture():
    every_signature_has_a_fixture()


@pytest.mark.parametrize("path", fixture_files(), ids=lambda p: p.stem)
def test_fixture(path: Path):
    data = json.loads(path.read_text())
    signals = [signal_from_fixture(s, i) for i, s in enumerate(data["signals"])]
    res = rank(builtin_catalog(), signals)
    exp = data["expect"]

    assert res.top_hypothesis == exp["top"], (
        f"{data['name']}: expected top {exp['top']}, got {res.top_hypothesis} "
        f"(ranking: {[(h.template_id, round(h.confidence_rank, 3)) for h in res.hypotheses]})"
    )
    assert res.verdict_tier.value == exp["tier"], (
        f"{data['name']}: expected tier {exp['tier']}, got {res.verdict_tier.value} "
        f"(gate reasons: {res.hypotheses[0].verdict_gate.reasons if res.hypotheses else ()})"
    )
    if "min_confidence" in exp and res.hypotheses:
        top = next((h for h in res.hypotheses if h.template_id == res.top_hypothesis), None)
        if top is not None:
            assert top.confidence_rank >= exp["min_confidence"]
    if "owner" in exp:
        top = next(h for h in res.hypotheses if h.template_id == exp["top"])
        assert top.owner == exp["owner"]
