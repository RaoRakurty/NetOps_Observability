# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 388(c): the controller relay of an admin shutdown.

vManage's `interface-admin-state-change` device event names an operator's
shutdown by its event name; the connector (nms/vmanage_kinds.go LinkCause) states
it as `correlation_hints.link_cause=admin`. Stage [1] lifts that into the
signal's clause-testable `link_cause` attr, so stage [5] opens no object for a
lone admin link change, the same as the syslog lane's admin-down (tracker 385).
Fail-closed: a cause that is absent, not in the vocabulary, or on a kind that is
not a link change states nothing, and the signal stays a fault."""
from datetime import datetime, timezone

import pytest

from catalog import builtin_catalog
from controller_events import controller_event_to_signal, controller_link_cause
from engine import run_window
from signals import EntityType, clause_attr

INGEST = datetime(2026, 11, 21, 12, 0, 0, tzinfo=timezone.utc)


def _ev(event_type="interface-admin-state-change", kind="link_state_change",
        hints=None, sev="high"):
    return {
        "tenant_id": "t-a", "integration_id": "int-vm", "source_system": "vmanage",
        "vendor": "cisco", "normalized_event_type": kind, "severity": sev,
        "device_id": "10.255.255.81", "device_name": "cEDGE-81",
        "interface_name": "GigabitEthernet2", "event_id": "ev-1",
        "event_time": "2026-11-21T11:59:00Z", "event_type": event_type,
        "message": f"{event_type} if-name=GigabitEthernet2; new-state=down",
        "correlation_hints": hints if hints is not None else
        {"component": "VPN", "system_ip": "10.255.255.81", "link_cause": "admin"},
    }


def test_admin_cause_reaches_the_clause_attr():
    s = controller_event_to_signal(_ev(), INGEST)
    assert s is not None
    assert s.entity_type == EntityType.INTERFACE
    assert s.entity_id == "10.255.255.81:GigabitEthernet2"
    assert clause_attr(s, "link_cause") == "admin"


def test_oper_state_event_states_no_cause():
    hints = {"component": "VPN", "system_ip": "10.255.255.81"}
    s = controller_event_to_signal(_ev("interface-state-change", hints=hints), INGEST)
    assert "link_cause" not in s.attrs
    assert clause_attr(s, "link_cause") == ""


@pytest.mark.parametrize("raw", ["Admin", " admin "])
def test_cause_is_normalised(raw):
    assert controller_link_cause("link_state_change", {"link_cause": raw}) == "admin"


@pytest.mark.parametrize("raw", ["administrative", "shutdown", "", None, 1, ["admin"],
                                 {"v": "admin"}, "admin" * 20])
def test_unknown_or_malformed_cause_states_nothing(raw):
    assert controller_link_cause("link_state_change", {"link_cause": raw}) == ""


@pytest.mark.parametrize("kind", ["controller_bfd_down", "controller_control_connection_loss",
                                  "bgp_adjacency_change", "controller_alarm"])
def test_cause_only_on_link_kinds(kind):
    s = controller_event_to_signal(_ev(kind=kind), INGEST)
    assert s is None or "link_cause" not in s.attrs


def test_clear_keeps_the_cause_but_is_a_clear():
    s = controller_event_to_signal(_ev(kind="link_state_change_clear", sev="info"), INGEST)
    assert s.kind == "link_state_change_clear"
    assert s.attrs["link_cause"] == "admin"


# Stage [5] end to end: the relayed admin shutdown opens nothing; the relayed oper
# down (no stated cause) still opens, as a fault.
def test_relayed_admin_shutdown_opens_no_object():
    s = controller_event_to_signal(_ev(), INGEST)
    assert run_window([s], builtin_catalog(), ()) == []


def test_relayed_oper_down_still_opens():
    hints = {"component": "VPN", "system_ip": "10.255.255.81"}
    s = controller_event_to_signal(_ev("interface-state-change", hints=hints), INGEST)
    assert len(run_window([s], builtin_catalog(), ())) == 1
