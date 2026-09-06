# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Seam signal kinds (#105 P0) — contract tests.

Every seam kind the pollers emit must round-trip through the ingestion lane
into a valid Signal with the right modality/entity, carry the provider-native
identity, and use the provider's OWN observation time — correlation runs on
observed_at, never ingest time.
"""
from __future__ import annotations

from datetime import datetime, timezone

from cloud_producers import CLOUD_KINDS, cloud_signal_from_event
from signals import EntityType, ModalityClass

TS = datetime(2026, 7, 14, 22, 0, 0, tzinfo=timezone.utc)

SEAM_KINDS = [
    "cloud_bgp_session_down", "cloud_bgp_session_up", "cloud_bgp_flap",
    "cloud_route_count_drop", "cloud_vpn_tunnel_down", "cloud_vpn_tunnel_up",
    "cloud_vpn_packet_drop", "cloud_physical_link_down", "cloud_link_error",
    "cloud_gateway_blackhole_drop", "cloud_gateway_no_route_drop",
    "cloud_nat_port_exhaustion", "cloud_state_unknown",
]


def test_all_seam_kinds_registered():
    for kind in SEAM_KINDS:
        assert kind in CLOUD_KINDS, f"{kind} missing from the contract"


def test_state_kinds_are_control_plane():
    for kind in ("cloud_bgp_session_down", "cloud_vpn_tunnel_down",
                 "cloud_route_count_drop", "cloud_state_unknown"):
        modality, _, _ = CLOUD_KINDS[kind]
        assert modality is ModalityClass.CONTROL_PLANE, kind


def test_forwarding_drops_are_data_plane_evidence():
    for kind in ("cloud_gateway_blackhole_drop", "cloud_gateway_no_route_drop",
                 "cloud_nat_port_exhaustion", "cloud_vpn_packet_drop"):
        modality, _, _ = CLOUD_KINDS[kind]
        assert modality is ModalityClass.DEVICE_TELEMETRY, kind


def test_seam_signal_roundtrips_with_native_identity():
    ev = {
        "kind": "cloud_bgp_session_down",
        "tenant_id": "acme",
        "resource_id": "dxbgp:dxvif-7:p1",
        "account": "123456789012", "region": "us-west-2",
        "severity": "crit", "metric_name": "cloud_bgp_session_down",
        "value": 1.0, "ts": "2026-07-14T21:58:00Z",  # provider observation, BEFORE ingest
        "attrs": {"provider": "aws", "evidence_class": "state_transition",
                  "vif_id": "dxvif-7", "peer_address": "169.254.0.1",
                  "from_state": "up", "to_state": "down"},
    }
    sig = cloud_signal_from_event(ev, "acme", TS)
    assert sig.kind == "cloud_bgp_session_down"
    assert sig.entity_type is EntityType.CLOUD_RESOURCE
    assert sig.entity_id == "dxbgp:dxvif-7:p1"           # native identity retained
    assert sig.ts.isoformat().startswith("2026-07-14T21:58")  # observed_at wins
    assert sig.attrs["evidence_class"] == "state_transition"
    assert sig.attrs["vif_id"] == "dxvif-7"


def test_blackhole_vs_noroute_never_merge():
    def mk(kind):
        return cloud_signal_from_event({
            "kind": kind, "tenant_id": "acme", "resource_id": "tgw-1",
            "severity": "high", "metric_name": kind, "value": 12.0,
            "ts": "2026-07-14T22:00:00Z",
            "attrs": {"provider": "aws", "evidence_class": "forwarding_drop"},
        }, "acme", TS)
    a, b = mk("cloud_gateway_blackhole_drop"), mk("cloud_gateway_no_route_drop")
    assert a.kind != b.kind and a.native_id != b.native_id
