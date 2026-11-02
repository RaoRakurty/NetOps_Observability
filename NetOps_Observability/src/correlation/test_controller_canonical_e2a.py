# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""E2a — canonical kinds a controller relays bind to the same entity shapes as
the device's own traps and syslog (events.yaml), and stay management-plane.

Plan of record: docs/design/NMS_DEVICE_IDENTITY_2026-11-01.md §7a/§7b.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from controller_events import controller_event_to_signal
from coverage import EMITTED_KINDS
from signals import EntityType, ModalityClass

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)


def ev(kind: str, **kw) -> dict:
    base = {"tenant_id": "t_retail", "integration_id": "nmsi-1", "source_system": "vmanage",
            "normalized_event_type": kind, "severity": "high", "device_id": "10.255.255.40",
            "event_id": f"e-{kind}-{len(kw)}", "event_time": NOW.isoformat()}
    base.update(kw)
    return base


@pytest.mark.parametrize("kind", ["link_state_change", "link_state_change_clear"])
def test_interface_kind_binds_like_the_trap_rule(kind: str) -> None:
    sig = controller_event_to_signal(ev(kind, interface_name="GigabitEthernet2"), NOW)
    assert sig is not None
    assert sig.entity_type is EntityType.INTERFACE
    assert sig.entity_id == "10.255.255.40:GigabitEthernet2", "same '<device>:<ifname>' shape as the trap rule"


def test_interface_kind_without_an_interface_binds_to_the_device() -> None:
    sig = controller_event_to_signal(ev("link_state_change"), NOW)
    assert sig is not None and sig.entity_type is EntityType.DEVICE and sig.entity_id == "10.255.255.40"


@pytest.mark.parametrize("kind", ["bgp_adjacency_change", "bgp_adjacency_change_clear",
                                  "ospf_adjacency_change", "ospf_adjacency_change_clear",
                                  "isis_adjacency_change", "routing_adjacency_change"])
def test_session_kind_binds_to_device_and_peer(kind: str) -> None:
    sig = controller_event_to_signal(ev(kind, peer_id="192.168.200.34"), NOW)
    assert sig is not None
    assert sig.entity_type is EntityType.DEVICE
    assert sig.entity_id == "10.255.255.40:192.168.200.34", "same '<device>:<peer>' shape as the trap rule"


def test_session_kind_without_a_peer_binds_to_the_device() -> None:
    sig = controller_event_to_signal(ev("bgp_adjacency_change"), NOW)
    assert sig is not None and sig.entity_id == "10.255.255.40"


def test_a_fault_and_its_recovery_share_one_entity() -> None:
    fault = controller_event_to_signal(ev("bgp_adjacency_change", peer_id="192.168.200.34"), NOW)
    clear = controller_event_to_signal(ev("bgp_adjacency_change_clear", peer_id="192.168.200.34"), NOW)
    assert fault is not None and clear is not None
    assert (fault.entity_type, fault.entity_id) == (clear.entity_type, clear.entity_id)


@pytest.mark.parametrize("kind", ["link_state_change", "bgp_adjacency_change", "ospf_adjacency_change",
                                  "device_restart", "transceiver_unsupported"])
def test_relayed_canonical_kinds_stay_management_plane(kind: str) -> None:
    """Owner decision carried into T2: a relayed observation names the right
    hypothesis; it does not by itself become control-plane evidence."""
    sig = controller_event_to_signal(ev(kind, interface_name="Gi1", peer_id="1.2.3.4"), NOW)
    assert sig is not None and sig.modality_class is ModalityClass.MANAGEMENT_PLANE


@pytest.mark.parametrize("kind", ["link_state_change", "bgp_adjacency_change", "ospf_adjacency_change",
                                  "device_restart"])
def test_every_relayed_kind_is_one_the_engine_consumes(kind: str) -> None:
    assert kind in EMITTED_KINDS
