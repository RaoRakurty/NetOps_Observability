# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Signature live-fire drill — prove every ENABLED signature triggers on the
DEPLOYED engine.

Runs inside the running correlation container against the exact artifact that
serves production:

    docker compose exec correlation python drill.py            # all enabled
    docker compose exec correlation python drill.py sig.ent.x  # one signature

For every enabled signature it loads the signature's positive fixture (the
owner-approved evidence bundle), replays it through the live catalog + scorer +
verdict gate, and asserts the signature wins with the expected tier/owner —
then prints the operator phrase the AI would narrate. Nothing is persisted:
this validates matching on the deployed binary without polluting live
incidents.

Honest scope note: the drill proves CATALOG MATCHING (evidence bundle →
signature → tier → voice). In production the bundle must also CORRELATE into
one incident first (grounding: shared seam / topology / entity tokens) — that
half is scenario-dependent and is exercised by the e2e tests and real lab
faults, not by this drill.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

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

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
MODALITY_SOURCE = {
    ModalityClass.ACTIVE_PROBE: Source.PROBE,
    ModalityClass.PASSIVE_FLOW: Source.FLOW,
    ModalityClass.CONTROL_PLANE: Source.TOPOLOGY,
    ModalityClass.DEVICE_TELEMETRY: Source.METRIC,
}


def signal_from_fixture(spec: dict, idx: int) -> Signal:
    modality = ModalityClass(spec["modality"])
    attrs = dict(spec.get("attrs", {}))
    if modality is ModalityClass.ACTIVE_PROBE:
        attrs.setdefault("probe_authority", spec.get("probe_authority", "high"))
        for k in ("agent_host", "source_egress", "seam_id", "schedule_id", "probe_scope"):
            if k in spec:
                attrs.setdefault(k, spec[k])
    return Signal(
        tenant_id="drill",
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
        native_id=f"drill|{idx}|{spec['kind']}",
        deviation=float(spec.get("deviation", 0.0)),
        attrs=attrs,
    )


def main() -> int:
    only = sys.argv[1] if len(sys.argv) > 1 else None
    cat = builtin_catalog()
    enabled = {t.id: t for t in cat.enabled_templates()}
    fixdir = Path(__file__).parent / "fixtures"

    # Index fixtures by the signature they expect to win.
    by_sig: dict[str, list[Path]] = {}
    for f in sorted(fixdir.glob("*.json")):
        data = json.loads(f.read_text())
        top = data.get("expect", {}).get("top")
        if top:
            by_sig.setdefault(top, []).append(f)

    passed, failed, unfixtured = 0, 0, []
    print(f"catalog {cat.version_hash()} — {len(enabled)} enabled signatures\n")
    for sid, tmpl in sorted(enabled.items()):
        if only and only not in sid:
            continue
        paths = by_sig.get(sid)
        if not paths:
            unfixtured.append(sid)
            continue
        for f in paths:
            data = json.loads(f.read_text())
            sigs = [signal_from_fixture(s, i) for i, s in enumerate(data["signals"])]
            res = rank(cat, sigs)
            exp = data["expect"]
            ok = res.top_hypothesis == sid and (
                not exp.get("tier") or res.verdict_tier.value == exp["tier"])
            top = next((h for h in res.hypotheses if h.template_id == sid), None)
            owner_ok = not exp.get("owner") or (top and top.owner == exp["owner"])
            if ok and owner_ok:
                passed += 1
                voice = (top.operator_phrase or "(pre-v1 wording engine)") if top else ""
                label = top.confidence_label() if top else "?"
                print(f"  PASS {sid}  [{res.verdict_tier.value}/{label}]")
                print(f"       voice: {voice[:110]}")
            else:
                failed += 1
                print(f"  FAIL {sid}: top={res.top_hypothesis} tier={res.verdict_tier.value} (fixture {f.name})")

    print(f"\n{passed} fired as expected, {failed} failed"
          + (f", {len(unfixtured)} enabled without a fixture: {unfixtured}" if unfixtured else ""))
    return 1 if failed or unfixtured else 0


if __name__ == "__main__":
    raise SystemExit(main())
