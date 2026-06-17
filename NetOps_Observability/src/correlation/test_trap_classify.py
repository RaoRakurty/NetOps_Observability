"""Commit 3 — SNMP trap → control_plane normalization tests.

Proves the trap guardrail the architecture requires (Layer 1G + Layer 4D):

  * high-value, well-standardized traps (linkDown/Up, coldStart/warmStart, BGP
    transition) → ONE normalized control_plane signal bound to the same
    interface/peer entity model as metrics & syslog
  * every UNCLASSIFIED trap → None (kept searchable in OpenSearch, NEVER an RCA
    signal) — the anti-noise guardrail
  * handle_snmptrap counts received / normalized / dropped and never crashes
"""
import asyncio
import unittest
from datetime import datetime, timezone

import main
from producers import trap_control_signal
from signals import EntityType, ModalityClass, Source

NOW = datetime.now(timezone.utc)


def trap(**over):
    ev = {
        "_signal": "snmptrap",
        "timestamp": NOW.isoformat(),
        "device": "leaf1",
        "host": "172.40.40.21",
        "snmp_version": "2c",
        "authenticated": False,
        "trap_oid": "1.3.6.1.6.3.1.1.5.3",   # linkDown
        "trap_name": "linkDown",
        "severity": "warning",
        "varbinds": [
            {"oid": "1.3.6.1.2.1.2.2.1.1.7", "value": "7"},               # ifIndex
            {"oid": "1.3.6.1.2.1.31.1.1.1.1.7", "value": "Ethernet7"},    # ifName
        ],
    }
    ev.update(over)
    return ev


class TrapClassifyTest(unittest.TestCase):
    def test_linkdown_to_control_plane_interface(self):
        sig = trap_control_signal(trap(), "", NOW)
        self.assertIsNotNone(sig)
        self.assertEqual(sig.source, Source.TRAP)
        self.assertEqual(sig.modality_class, ModalityClass.CONTROL_PLANE)
        self.assertEqual(sig.kind, "link_state_change")
        self.assertEqual(sig.entity_type, EntityType.INTERFACE)
        # binds to the same identity the interface metrics use (device:ifName)
        self.assertEqual(sig.entity_id, "leaf1:Ethernet7")
        self.assertEqual(sig.attrs["state"], "down")

    def test_linkup_state(self):
        sig = trap_control_signal(
            trap(trap_oid="1.3.6.1.6.3.1.1.5.4", trap_name="linkUp"), "", NOW)
        self.assertEqual(sig.attrs["state"], "up")

    def test_interface_falls_back_to_ifindex(self):
        ev = trap(varbinds=[{"oid": "1.3.6.1.2.1.2.2.1.1.7", "value": "7"}])
        sig = trap_control_signal(ev, "", NOW)
        self.assertEqual(sig.entity_id, "leaf1:7")

    def test_coldstart_to_device_restart(self):
        sig = trap_control_signal(
            trap(trap_oid="1.3.6.1.6.3.1.1.5.1", trap_name="coldStart", varbinds=[]), "", NOW)
        self.assertEqual(sig.kind, "device_restart")
        self.assertEqual(sig.entity_type, EntityType.DEVICE)
        self.assertEqual(sig.entity_id, "leaf1")
        self.assertEqual(sig.attrs["restart"], "cold")

    def test_bgp_backward_transition_to_peer(self):
        ev = trap(trap_oid="1.3.6.1.2.1.15.7.2", trap_name="",
                  varbinds=[{"oid": "1.3.6.1.2.1.15.3.1.7.10.0.0.5", "value": "10.0.0.5"}])
        sig = trap_control_signal(ev, "", NOW)
        self.assertEqual(sig.kind, "bgp_adjacency_change")
        self.assertEqual(sig.entity_id, "leaf1:10.0.0.5")
        self.assertEqual(sig.attrs["state"], "down")

    def test_bgp_established_is_up(self):
        sig = trap_control_signal(
            trap(trap_oid="1.3.6.1.2.1.15.7.1", trap_name="", varbinds=[]), "", NOW)
        self.assertEqual(sig.attrs["state"], "up")

    def test_authenticated_flag_passthrough(self):
        sig = trap_control_signal(trap(authenticated=True), "", NOW)
        self.assertTrue(sig.attrs["authenticated"])

    def test_unknown_trap_creates_no_signal(self):
        # an enterprise-specific / unclassified trap → searchable, no RCA signal
        ev = trap(trap_oid="1.3.6.1.4.1.9.9.999.0.1", trap_name="enterpriseSpecific", varbinds=[])
        self.assertIsNone(trap_control_signal(ev, "", NOW))

    def test_vendor_bgp_trap_classifies_via_event_type(self):
        # Arista BGP trap: non-standard OID the standard checks miss, but the
        # NormalizedEvent envelope (#32) carries event_type → generic classify.
        ev = trap(
            trap_oid="1.3.6.1.4.1.30065.4.1.0.2", trap_name="aristaBgp4V2BackwardTransitionNotification",
            event_type="arista_bgp4_v2_backward_transition",
            varbinds=[{"oid": "1.3.6.1.4.1.30065.4.1.1.2.5", "name": "aristaBgp4V2PeerRemoteAddr", "value": "192.168.100.5"}],
        )
        sig = trap_control_signal(ev, "", NOW)
        self.assertIsNotNone(sig)
        self.assertEqual(sig.kind, "bgp_adjacency_change")
        self.assertEqual(sig.attrs["state"], "down")
        self.assertEqual(sig.entity_id, "leaf1:192.168.100.5")  # peer via resolved varbind name

    def test_missing_device_no_signal(self):
        self.assertIsNone(trap_control_signal(trap(device="", host=""), "", NOW))


class HandleSnmptrapCountersTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.rows = []

        class FakeCH:
            async def insert(_self, table, rows):
                for r in rows:
                    self.rows.append({"_table": table, **r})

        main.ch = FakeCH()
        main.CORR_SIGNALS_ENABLED = True
        main.TRAPS_RECEIVED = main.TRAPS_NORMALIZED = main.TRAPS_DROPPED = 0

    async def test_classified_trap_creates_signal_and_counts(self):
        await main.handle_snmptrap(trap())
        self.assertEqual(main.TRAPS_RECEIVED, 1)
        self.assertEqual(main.TRAPS_NORMALIZED, 1)
        self.assertEqual(main.TRAPS_DROPPED, 0)
        sigs = [r for r in self.rows if r["_table"] == "netops.corr_signals"]
        self.assertEqual(len(sigs), 1)
        self.assertEqual(sigs[0]["modality_class"], "control_plane")

    async def test_unknown_trap_dropped_no_signal(self):
        await main.handle_snmptrap(
            trap(trap_oid="1.3.6.1.4.1.9.9.999.0.1", trap_name="enterpriseSpecific", varbinds=[]))
        self.assertEqual(main.TRAPS_RECEIVED, 1)
        self.assertEqual(main.TRAPS_NORMALIZED, 0)
        self.assertEqual(main.TRAPS_DROPPED, 1)
        self.assertEqual(self.rows, [])


if __name__ == "__main__":
    unittest.main()
