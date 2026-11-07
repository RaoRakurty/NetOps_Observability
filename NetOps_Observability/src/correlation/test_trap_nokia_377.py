# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""tracker 377 — Nokia TIMETRA-BGP-MIB IPv6 session traps, typed safely.

Decoding TIMETRA-BGP-MIB (the MIB now reaches the trap index) would, on its
own, have made the generic event_type BGP rule take `tBgpPeerNgLastError`'s
VALUE as the peer — its name contains "peer". These tests pin that:

  * tBgpNgEstablished → up, tBgpNgBackwardTransition → down, on
    `device:<canonical IPv6 peer>`, in the RFC 4273 vocabulary;
  * the routing instance in the row index is kept as an attr, never glued into
    the entity id; a malformed index binds the bare device, never a phantom;
  * the event_type rule cannot claim the Nokia subtree any more;
  * the transition collapse (tracker 376) folds a duplicate report as for Cisco;
  * the MIB index itself carries the decoded names (the build assertion's twin).
"""
from __future__ import annotations

import json
import os
import unittest
from datetime import datetime, timezone

import producers as P
from trap_collapse import TransitionCollapser

HERE = os.path.dirname(os.path.abspath(__file__))
INDEX = os.path.join(HERE, "..", "backend", "collectors", "mibs", "index", "oididx.json")
NOW = datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc)
DEVICE = "sr1"
TENANT = "t_lab"
NOTIF = "1.3.6.1.4.1.6527.3.1.3.14.0."
CONN_STATE = "1.3.6.1.4.1.6527.3.1.2.14.4.7.1.59"
LAST_ERROR = "1.3.6.1.4.1.6527.3.1.2.14.4.10.1.11"
V6 = "32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.9"      # 2001:db8::9


def ng_trap(n: int, index: str = f"1.2.16.{V6}", state: str = "idle(1)") -> dict:
    return {"_signal": "snmptrap", "timestamp": NOW.isoformat(), "device": DEVICE,
            "host": "10.0.0.9", "authenticated": False,
            "trap_oid": f"{NOTIF}{n}",
            "trap_name": "tBgpNgEstablished" if n == 7 else "tBgpNgBackwardTransition",
            "event_type": "t_bgp_ng_established" if n == 7 else "t_bgp_ng_backward_transition",
            "severity": "info" if n == 7 else "warning",
            "varbinds": [
                {"oid": f"{LAST_ERROR}.{index}", "name": "tBgpPeerNgLastError", "value": "0x0000"},
                {"oid": f"{CONN_STATE}.{index}", "name": "tBgpPeerNgConnState", "value": state},
            ]}


def classify(ev: dict):
    return P.trap_control_signal(ev, TENANT, NOW)


class NokiaNgRuleTest(unittest.TestCase):
    def test_established_is_up_on_the_canonical_ipv6_peer(self):
        sig = classify(ng_trap(7, state="established(6)"))
        self.assertEqual(sig.kind, "bgp_adjacency_change")
        self.assertEqual(sig.entity_id, f"{DEVICE}:2001:db8::9")
        self.assertEqual(sig.attrs["state"], "up")
        self.assertEqual(sig.severity.value, "warn")
        self.assertEqual(sig.attrs["rule_id"], "trap.bgp.nokia_ng")

    def test_backward_transition_is_down(self):
        sig = classify(ng_trap(8))
        self.assertEqual(sig.entity_id, f"{DEVICE}:2001:db8::9")
        self.assertEqual(sig.attrs["state"], "down")
        self.assertEqual(sig.severity.value, "high")

    def test_the_routing_instance_is_an_attr_not_part_of_the_entity(self):
        a = classify(ng_trap(8, index=f"1.2.16.{V6}"))
        b = classify(ng_trap(8, index=f"5.2.16.{V6}"))
        self.assertEqual(a.attrs["bgp_instance"], "1")
        self.assertEqual(b.attrs["bgp_instance"], "5")
        self.assertEqual(a.entity_id, b.entity_id)

    def test_an_ipv4_row_index_also_resolves(self):
        sig = classify(ng_trap(8, index="1.1.4.10.0.0.9"))
        self.assertEqual(sig.entity_id, f"{DEVICE}:10.0.0.9")

    def test_a_malformed_index_binds_the_device_never_a_phantom(self):
        for bad in ("1.2.16.1.2.3", "x.2.16.1.2", "", "1"):
            sig = classify(ng_trap(8, index=bad) if bad else {**ng_trap(8), "varbinds": []})
            self.assertEqual(sig.entity_id, DEVICE, bad)
            self.assertEqual(sig.attrs["peer"], "", bad)
            self.assertNotIn("0x0000", sig.entity_id)

    def test_the_last_error_value_can_never_become_the_peer(self):
        """The bug this rule exists to prevent: the event_type rule's name scan."""
        for n in (7, 8):
            sig = classify(ng_trap(n))
            self.assertNotEqual(sig.attrs.get("rule_id"), "trap.bgp.adjacency_change.event_type")
            self.assertNotIn("0x", sig.entity_id)

    def test_other_nokia_bgp_notifications_are_not_adjacency(self):
        for n in (1, 2, 3, 6, 9):      # max-prefix, GR status, hold-time …
            sig = classify({**ng_trap(8), "trap_oid": f"{NOTIF}{n}",
                            "trap_name": "tBgpMaxPrefix90", "event_type": "t_bgp_max_prefix90"})
            self.assertTrue(sig is None or sig.kind != "bgp_adjacency_change", n)

    def test_unattributed_trap_emits_nothing(self):
        self.assertIsNone(classify({**ng_trap(8), "device": ""}))

    def test_a_duplicate_report_collapses_like_cisco(self):
        col = TransitionCollapser()
        sigs = [classify(ng_trap(8)), classify(ng_trap(8))]
        kept = [s for s in sigs if col.admit(TENANT, s.entity_id, s.attrs["state"], s.ts)]
        self.assertEqual(len(kept), 1)


class IndexCarriesTheDecodedNamesTest(unittest.TestCase):
    """The MIB index is what turns these OIDs into names at the receiver."""

    def test_the_four_modules_reach_the_index(self):
        with open(INDEX, encoding="utf-8") as fh:
            nodes = json.load(fh)["nodes"]
        want = {
            "1.3.6.1.4.1.6527.3.1.3.14.0.7": ("tBgpNgEstablished", "notification", "info"),
            "1.3.6.1.4.1.6527.3.1.3.14.0.8": ("tBgpNgBackwardTransition", "notification", "warning"),
            CONN_STATE: ("tBgpPeerNgConnState", "column", None),
            "1.0.8802.1.1.2.0.0.1": ("lldpRemTablesChange", "notification", None),
            "1.3.6.1.4.1.9.2.2.1.1.20": ("locIfReason", "column", None),
        }
        for oid, (name, kind, hint) in want.items():
            self.assertIn(oid, nodes, name)
            self.assertEqual((nodes[oid]["name"], nodes[oid]["kind"]), (name, kind))
            self.assertEqual(nodes[oid].get("severity_hint"), hint, name)

    def test_juniper_chassis_identities_are_not_mislabelled_scalars(self):
        with open(INDEX, encoding="utf-8") as fh:
            nodes = json.load(fh)["nodes"]
        self.assertFalse([o for o, n in nodes.items()
                          if n.get("mib") == "JUNIPER-CHASSIS-DEFINES-MIB"])


if __name__ == "__main__":
    unittest.main()
