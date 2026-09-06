# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tests for the application-identity signal contract — #81 Fusion Layer P5a.

Proves fused application identity emits canonical Signals into the SAME spine
(source=app_identity), additively, with the mandatory observer block, INFO
severity (identity is enrichment, never a fault), honest single-vantage
independence (identity alone cannot confirm), and strict provenance validation
(a present-but-invalid band/state dead-letters rather than being guessed).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app_producers import (
    APP_IDENTITY_KIND,
    app_identity_from_event,
    app_identity_signal,
)
from signals import (
    DeadLetter,
    EntityType,
    ModalityClass,
    ObserverType,
    Severity,
    Source,
)

TS = datetime(2026, 6, 26, 12, 0, 0, tzinfo=timezone.utc)


def test_identity_signal_shape():
    s = app_identity_signal(
        "acme", TS,
        app="Microsoft Teams", band="authoritative", state="fused",
        provider="Microsoft", evidence_score=92, sources=("ngfw_app_id", "ip_catalog"),
        fusion_version="appfuse-1", dst_ip="13.107.6.152", flow_id="f-1",
    )
    assert s.source is Source.APP_IDENTITY
    assert s.kind == APP_IDENTITY_KIND
    assert s.entity_type is EntityType.APP and s.entity_id == "Microsoft Teams"
    assert s.modality_class is ModalityClass.CONTROL_PLANE
    # Identity is enrichment, never a fault — must be INFO so it can't seed an object.
    assert s.severity is Severity.INFO
    # one platform fusion vantage (independence gate: cannot self-confirm)
    assert s.observer.observer_id == "appid:fusion"
    assert s.observer.observer_type is ObserverType.PLATFORM
    assert s.observer.collection_path == "via_aggregator"
    # provenance carried in attrs, not re-derived
    assert s.attrs["band"] == "authoritative"
    assert s.attrs["state"] == "fused"
    assert s.attrs["evidence_score"] == 92
    assert s.attrs["sources"] == ["ngfw_app_id", "ip_catalog"]
    assert s.attrs["provider"] == "Microsoft"
    # round-trips through the frozen CH schema
    row = s.to_ch_row()
    assert row["source"] == "app_identity"
    assert row["entity_id"] == "Microsoft Teams"


def test_entity_tokens_default_to_app_and_scope():
    s = app_identity_signal("acme", TS, app="checkout", dst_ip="10.5.0.9", flow_id="f-9")
    # the shared tokens are the JOIN that lets a network-fault object name its app
    assert "checkout" in s.entity_tokens
    assert "10.5.0.9" in s.entity_tokens
    assert "f-9" in s.entity_tokens
    assert s.service_id == "checkout"


def test_explicit_entity_tokens_override():
    s = app_identity_signal("acme", TS, app="checkout", dst_ip="10.5.0.9",
                            entity_tokens=("checkout", "site:dallas"))
    assert s.entity_tokens == ("checkout", "site:dallas")


def test_native_id_deterministic_same_scope():
    a = app_identity_signal("acme", TS, app="checkout", flow_id="f-1", fusion_version="appfuse-1")
    b = app_identity_signal("acme", TS, app="checkout", flow_id="f-1", fusion_version="appfuse-1")
    assert a.signal_id == b.signal_id  # same scope ⇒ same deterministic id


def test_native_id_differs_by_scope_and_version():
    base = app_identity_signal("acme", TS, app="checkout", flow_id="f-1", fusion_version="appfuse-1")
    diff_scope = app_identity_signal("acme", TS, app="checkout", flow_id="f-2", fusion_version="appfuse-1")
    diff_ver = app_identity_signal("acme", TS, app="checkout", flow_id="f-1", fusion_version="appfuse-2")
    assert base.signal_id != diff_scope.signal_id
    assert base.signal_id != diff_ver.signal_id


def test_signal_requires_app():
    with pytest.raises(ValueError):
        app_identity_signal("acme", TS, app="")


def test_signal_rejects_invalid_band_state():
    with pytest.raises(ValueError):
        app_identity_signal("acme", TS, app="x", band="bogus")
    with pytest.raises(ValueError):
        app_identity_signal("acme", TS, app="x", state="bogus")


# ── wire adapter ──────────────────────────────────────────────────────────────


def test_from_event_happy_path():
    ev = {
        "tenant_id": "acme", "app": "Zoom", "band": "high", "state": "fused",
        "evidence_score": 80, "sources": ["ngfw_app_id"], "fusion_version": "appfuse-1",
        "dst_ip": "203.0.113.50", "dst_port": 8801, "proto": "udp", "flow_id": "f-7",
        "ts": "2026-06-26T12:00:00Z",
    }
    s = app_identity_from_event(ev, "acme", TS)
    assert s.source is Source.APP_IDENTITY
    assert s.entity_id == "Zoom"
    assert s.attrs["band"] == "high" and s.attrs["state"] == "fused"
    assert s.attrs["dst_port"] == 8801
    assert s.ts == TS  # parsed from the event clock


def test_from_event_canonical_app_fallback():
    s = app_identity_from_event({"canonical_app": "Salesforce"}, "acme", TS)
    assert s.entity_id == "Salesforce"
    # absent band/state → honest defaults, never a guess
    assert s.attrs["band"] == "unresolved"
    assert s.attrs["state"] == "unknown"


def test_from_event_dead_letters_no_app():
    with pytest.raises(DeadLetter):
        app_identity_from_event({"tenant_id": "acme", "band": "high"}, "acme", TS)


def test_from_event_dead_letters_invalid_band():
    with pytest.raises(DeadLetter):
        app_identity_from_event({"app": "x", "band": "totally-made-up"}, "acme", TS)


def test_from_event_dead_letters_invalid_state():
    with pytest.raises(DeadLetter):
        app_identity_from_event({"app": "x", "state": "not-a-state"}, "acme", TS)


def test_from_event_falls_back_to_ingest_ts():
    s = app_identity_from_event({"app": "x"}, "acme", TS)
    assert s.ts == TS  # no event ts → ingest time (honest fallback)


def test_from_event_tolerates_garbage_score():
    s = app_identity_from_event({"app": "x", "evidence_score": "not-a-number"}, "acme", TS)
    assert s.attrs["evidence_score"] == 0
