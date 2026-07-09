"""Golden-wire replay (#98 Phase 3) — raw collector-shaped events through the
REAL pipeline: wire JSON → production normalizers → engine → verdict.

Why this exists: the per-signature fixtures (fixtures/*.json, test_fixtures.py)
start from hand-authored Signal objects — they validate the CATALOG, but they
silently assume the raw-event→signal boundary works. That assumption is exactly
where the #98 gap hid (collectors observed the phenomenon; nothing produced the
semantic kind). Golden-wire fixtures start from the bytes a collector actually
puts on the bus and must survive the same functions production runs.

Fixture shape (fixtures/golden_wire/*.json):
{
  "name": "...",
  "env": {"CORR_SAAS_HOST_MAP": "..."},        # optional runtime config (customer app map)
  "tenant": "acme",
  "events": [
     {"lane": "probe", "event": { ...exact ProbeEvent wire JSON (collectors/probe_events.go)... }},
     {"lane": "flow",  "records": [ ...raw goflow2-shaped flow records... ],
      "detected": {"deviation": 4.0}}          # see honesty note below
  ],
  "expect": { ... assertions used by test_golden_wire.py ... }
}

Honesty note on the flow lane: production turns raw flow records into a
flow_volume_anomaly only through the CUSUM episode detector over MANY engine
cycles (main._flush_flow_aggregator) — a single fixture record cannot honestly
"be" an anomaly. The replay therefore runs the REAL parsing/grounding boundary
(producers.flow_sample → the same entity/tenant/token fields _flush uses) and
then constructs the anomaly signal those fields would produce WHEN the detector
fires, marked ``attrs["detection_assumed"]=True``. Detection math itself is
covered by the episode tests; what golden-wire proves is the grounding truth —
today that is entity_type=INTERFACE with NO app token (the Phase 4 gap).
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from catalog import builtin_catalog
from episodes import EpisodeDetector
from engine import run_window
from producers import flow_sample, probe_signals
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
from synthetic_normalize import synthetic_app_signal

GOLDEN_DIR = Path(__file__).parent / "fixtures" / "golden_wire"
T0 = datetime(2026, 7, 9, 9, 0, 0, tzinfo=timezone.utc)


def load_fixture(name: str) -> dict:
    return json.loads((GOLDEN_DIR / name).read_text())


def normalize_probe_event(ev: dict, tenant: str, now: datetime) -> list[Signal]:
    """One raw ProbeEvent (the exact netops.probes wire shape) → the signals
    production emits: the generic lane (probe_signals — probe_loss / RTT
    episodes) PLUS the semantic app-experience lane (synthetic_app_signal).
    Same order, same functions as main.handle_probe."""
    out = probe_signals(ev, EpisodeDetector(), tenant, now)
    app = synthetic_app_signal(ev, tenant, now)
    if app is not None:
        out.append(app)
    return out


def normalize_flow_records(records: list[dict], tenant: str, now: datetime,
                           detected: dict | None) -> list[Signal]:
    """Raw goflow2-shaped records → the per-interface aggregation production
    performs (REAL flow_sample parsing), then the flow_volume_anomaly signal
    those aggregates yield when CUSUM fires (detection_assumed — see module
    docstring). Returns [] when nothing parses or no detection is declared."""
    agg: dict[tuple[str, str], dict] = {}
    for rec in records:
        sample = flow_sample(rec)
        if sample is None:
            continue
        sampler, entity, nbytes = sample
        a = agg.setdefault((tenant, entity), {"bytes": 0.0, "sampler": sampler})
        a["bytes"] += nbytes
    if not agg or not detected:
        return []
    out: list[Signal] = []
    for (ten, entity), a in sorted(agg.items()):
        # Field-for-field what main._flush_flow_aggregator's episode emission
        # grounds on: INTERFACE entity `<sampler>:if<N>`, sampler token only.
        out.append(Signal(
            tenant_id=ten,
            ts=now,
            source=Source.FLOW,
            kind="flow_volume_anomaly",
            observer=Observer(observer_id=a["sampler"],
                              observer_type=ObserverType.FLOW_EXPORTER,
                              collection_path="flow_export"),
            modality_class=ModalityClass.PASSIVE_FLOW,
            entity_type=EntityType.INTERFACE,
            entity_id=entity,
            severity=Severity.WARN,
            native_id=f"golden|flow|{entity}",
            entity_tokens=(a["sampler"],),
            deviation=float(detected.get("deviation", 0.0)),
            attrs={"detection_assumed": True, "flow_bytes": a["bytes"]},
        ))
    return out


def replay_fixture_through_engine(name: str, monkeypatch=None):
    """load fixture → production normalizers → engine. Returns
    (signals, snapshots, ranking). ``env`` entries are applied via monkeypatch
    when provided (test use) else os.environ (restored by caller)."""
    fx = load_fixture(name)
    for k, v in fx.get("env", {}).items():
        if monkeypatch is not None:
            monkeypatch.setenv(k, v)
        else:  # pragma: no cover - non-test convenience
            os.environ[k] = v
    tenant = fx.get("tenant", "acme")
    signals: list[Signal] = []
    for item in fx["events"]:
        lane = item["lane"]
        if lane == "probe":
            signals.extend(normalize_probe_event(item["event"], tenant, T0))
        elif lane == "flow":
            signals.extend(normalize_flow_records(
                item["records"], tenant, T0, item.get("detected")))
        else:
            raise ValueError(f"unknown golden-wire lane {lane!r} in {name}")
    cat = builtin_catalog()
    snaps = run_window(tuple(signals), cat, ())
    ranking = rank(cat, signals) if signals else None
    return signals, snaps, ranking
