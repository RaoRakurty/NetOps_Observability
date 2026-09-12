# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tests for the cloud signal contract — #81 P3G Phase 1.

Proves Cloud App Observability emits canonical Signals into the SAME spine
(source=cloud), additively, with the mandatory observer block and honest
single-plane independence (cloud-only cannot confirm).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cloud_producers import CLOUD_KINDS, cloud_signal, cloud_signal_from_event
from signals import (
    DeadLetter,
    EntityType,
    ModalityClass,
    ObserverType,
    Severity,
    Source,
)

TS = datetime(2026, 6, 25, 12, 0, 0, tzinfo=timezone.utc)


def test_cloud_health_signal_shape():
    s = cloud_signal("acme", TS, "cloud_health", app="billing", account="123", region="us-east-1",
                     severity=Severity.HIGH, metric_name="alb_5xx_pct", value=6.4, baseline=0.2)
    assert s.source is Source.CLOUD
    assert s.entity_type is EntityType.APP and s.entity_id == "billing"
    assert s.modality_class is ModalityClass.DEVICE_TELEMETRY
    assert s.observer.observer_type is ObserverType.CLOUD_API
    assert s.observer.collection_path == "via_cloud_api"
    assert "billing" in s.entity_tokens
    # round-trips through the frozen CH schema
    row = s.to_ch_row()
    assert row["source"] == "cloud" and row["entity_type"] == "app"


def test_resource_and_change_kinds_map_correctly():
    db = cloud_signal("acme", TS, "database_metric", resource_id="billing-db", account="123",
                      region="us-east-1", metric_name="connections_pct", value=98, baseline=40)
    assert db.entity_type is EntityType.CLOUD_RESOURCE and db.entity_id == "billing-db"
    assert db.modality_class is ModalityClass.DEVICE_TELEMETRY

    chg = cloud_signal("acme", TS, "cloud_change", resource_id="billing-svc", account="123", region="us-east-1")
    assert chg.modality_class is ModalityClass.CONTROL_PLANE

    flow = cloud_signal("acme", TS, "cloud_flow_log", app="billing", account="123", region="us-east-1")
    assert flow.modality_class is ModalityClass.PASSIVE_FLOW
    assert flow.observer.observer_type is ObserverType.FLOW_EXPORTER


def test_one_cloud_vantage_per_account_region():
    # all cloud-API kinds from the same account/region share ONE observer_id, so the
    # engine's independence gate treats the cloud plane as a single observer
    # (single-plane cloud cannot confirm — the design's confidence rule).
    a = cloud_signal("acme", TS, "cloud_health", app="billing", account="123", region="us-east-1")
    b = cloud_signal("acme", TS, "cloud_change", resource_id="billing-db", account="123", region="us-east-1")
    assert a.observer.observer_id == b.observer.observer_id
    c = cloud_signal("acme", TS, "cloud_health", app="billing", account="999", region="us-east-1")
    assert a.observer.observer_id != c.observer.observer_id  # different account = different vantage


def test_deterministic_id_and_unknown_kind():
    a = cloud_signal("acme", TS, "cloud_health", app="billing", account="123", region="us-east-1", metric_name="m")
    b = cloud_signal("acme", TS, "cloud_health", app="billing", account="123", region="us-east-1", metric_name="m")
    assert a.signal_id == b.signal_id  # same inputs → same id (replay/idempotent insert)
    with pytest.raises(ValueError):
        cloud_signal("acme", TS, "not_a_cloud_kind", app="x")
    with pytest.raises(ValueError):
        cloud_signal("acme", TS, "cloud_health")  # needs app or resource_id


def test_all_declared_kinds_build():
    for kind in CLOUD_KINDS:
        s = cloud_signal("acme", TS, kind, app="billing", resource_id="billing-db", account="123", region="us-east-1")
        assert s.source is Source.CLOUD
        assert s.to_ch_row()["kind"] == kind


# ── wire adapter (netops.cloud topic → Signal) ───────────────────────────────

def test_from_event_builds_canonical_signal():
    ev = {
        "kind": "cloud_health", "app": "billing", "account": "123", "region": "us-east-1",
        "severity": "critical", "metric_name": "alb_5xx_pct", "value": 6.4, "baseline": 0.2,
        "ts": "2026-06-25T12:00:00Z", "attrs": {"alb": "checkout-alb"},
    }
    s = cloud_signal_from_event(ev, "acme", TS)
    assert s.source is Source.CLOUD and s.kind == "cloud_health"
    assert s.entity_type is EntityType.APP and s.entity_id == "billing"
    assert s.severity is Severity.CRIT             # "critical" alias → CRIT
    assert s.value == 6.4 and s.tenant_id == "acme"
    assert s.attrs.get("alb") == "checkout-alb"    # passthrough attrs preserved


def test_from_event_severity_aliases_and_bad_numbers():
    s = cloud_signal_from_event({"kind": "cloud_metric", "resource_id": "r1", "severity": "warning", "value": "n/a"}, "acme", TS)
    assert s.severity is Severity.WARN             # "warning" → WARN
    assert s.value == 0.0                          # non-numeric coerces to 0, no crash
    s2 = cloud_signal_from_event({"kind": "cloud_metric", "resource_id": "r1"}, "acme", TS)
    assert s2.severity is Severity.WARN            # absent severity defaults to WARN


def test_from_event_uses_ingest_ts_when_absent_or_bad():
    s = cloud_signal_from_event({"kind": "cloud_health", "app": "billing", "ts": "not-a-date"}, "acme", TS)
    assert s.ts == TS                              # malformed event time → honest ingest fallback


def test_from_event_dead_letters_bad_input():
    with pytest.raises(DeadLetter):
        cloud_signal_from_event({"kind": "not_a_cloud_kind", "app": "x"}, "acme", TS)
    with pytest.raises(DeadLetter):
        cloud_signal_from_event({"kind": "cloud_health"}, "acme", TS)   # neither app nor resource_id
