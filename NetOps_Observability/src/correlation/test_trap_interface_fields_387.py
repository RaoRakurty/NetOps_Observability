# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 387 PR 13c: the receiver now stamps `interface`, `ifindex` and
`interface_basis` beside the varbinds. Stage [1] is unchanged: `_trap_interface`
still reads the VARBINDS, so these fields can neither rename nor merge an entity
until a follow-on engine change decides to read them (canon D4 already maps a
digits-only interface through the same ifIndex map when CORR_IDENTITY_CANON is
on). These pin that the new fields are inert here, by value.
"""

from __future__ import annotations

from datetime import datetime, timezone

import producers as P

T0 = datetime(2026, 11, 9, 23, 0, 0, tzinfo=timezone.utc)


def _link_down(varbinds: list[dict], **receiver_fields) -> dict:
    ev = {"device": "vedge-20-1e95f00f", "trap_oid": "1.3.6.1.6.3.1.1.5.3", "trap_name": "linkDown",
          "event_type": "link_down", "authenticated": True,
          "timestamp": "2026-11-09T23:00:00.000Z", "varbinds": varbinds}
    ev.update(receiver_fields)
    return ev


IETF_LINK_DOWN = [
    {"oid": "1.3.6.1.2.1.2.2.1.1.4", "name": "ifIndex", "value": "4"},
    {"oid": "1.3.6.1.2.1.2.2.1.7.4", "name": "ifAdminStatus", "value": "up(1)"},
    {"oid": "1.3.6.1.2.1.2.2.1.8.4", "name": "ifOperStatus", "value": "down(2)"},
]


def test_trap_interface_still_reads_the_varbinds() -> None:
    plain = _link_down(IETF_LINK_DOWN)
    named = _link_down(IETF_LINK_DOWN, interface="ge0/3", ifindex="4", interface_basis="ifindex_map",
                       attribution_basis="mgmt_ip")
    assert P._trap_interface(plain) == "4"
    assert P._trap_interface(named) == "4", "the receiver's name must not bypass stage [1] D4"


def test_the_signal_is_byte_identical_with_or_without_the_fields() -> None:
    plain = P.trap_control_signal(_link_down(IETF_LINK_DOWN), "t1", T0)
    named = P.trap_control_signal(
        _link_down(IETF_LINK_DOWN, interface="ge0/3", ifindex="4", interface_basis="ifindex_map",
                   attribution_basis="interface_ip"), "t1", T0)
    assert plain is not None and named is not None
    assert plain.entity_id == named.entity_id == "vedge-20-1e95f00f:4"
    assert plain.kind == named.kind
    assert plain.signal_id == named.signal_id


def test_a_vendor_ifname_varbind_still_binds_by_name() -> None:
    vbs = [{"oid": "1.3.6.1.4.1.41916.100.1.73.0", "name": "viptelaVpnIfName", "value": "ge0/1"}]
    ev = _link_down(vbs, interface="ge0/1", interface_basis="varbind_name")
    assert P._trap_interface(ev) == "ge0/1"
