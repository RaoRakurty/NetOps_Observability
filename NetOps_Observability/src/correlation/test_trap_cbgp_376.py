# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""tracker 376 — CISCO-BGP4-MIB traps: classified, and one signal per transition.

Pins, against the RECORDED lab event (cEDGE-81, 2026-11-01) and synthetic
fixtures for every notification of the MIB:

  * each cbgp*/cbgpPeer2* adjacency notification classifies into the SAME
    vocabulary as RFC 4273 (entering established → up, backward → down), so a
    device with only the Cisco family on gives the engine the RFC evidence;
  * forward retry churn that never reaches established, and the prefix-
    threshold notifications, are NOT adjacency signals (behaviour unchanged);
  * the peer comes from the row index — bare octets or RFC 4001 type.len form,
    IPv6 canonicalised — and garbage never becomes an entity id;
  * the trap lane collapses one transition reported by six families into ONE
    signal, while a real flap (alternating states) keeps every leg, and two
    tenants never collapse into each other.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

import main
import producers as P
from rule_model import inet_index_text
from trap_collapse import TransitionCollapser

HERE = os.path.dirname(os.path.abspath(__file__))
TRAPS = os.path.join(HERE, "fixtures", "source_parity", "traps_cedge81_bgp_20261101.jsonl")
DEVICE = "cedge-81-11060ae2"
PEER = "192.168.200.34"
TENANT = "t_lab"
NOW = datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc)

CBGP = "1.3.6.1.4.1.9.9.187.0."
PEER2 = "1.3.6.1.4.1.9.9.187.1.2.5.1."      # cbgpPeer2Entry
PEER1 = "1.3.6.1.4.1.9.9.187.1.2.1.1."      # cbgpPeerEntry
RFC = "1.3.6.1.2.1.15.3.1."                  # bgpPeerEntry


def recorded() -> list[dict]:
    with open(TRAPS, encoding="utf-8") as fh:
        return [{**json.loads(line), "device": DEVICE} for line in fh if line.strip()]


def peer2_trap(n: int, state: str | None, prev: str | None = None,
               index: str = PEER, ts: datetime = NOW) -> dict:
    vbs = [{"oid": "1.3.6.1.2.1.1.3.0", "name": "sysUpTime", "value": "70193062"},
           {"oid": f"{PEER2}17.{index}", "value": "0x0000"}]
    if state is not None:
        vbs.append({"oid": f"{PEER2}3.{index}", "value": state})
    if prev is not None:
        vbs.append({"oid": f"{PEER2}29.{index}", "value": prev})
    return {"_signal": "snmptrap", "timestamp": ts.isoformat(), "device": DEVICE,
            "host": "192.168.200.33", "authenticated": False,
            "trap_oid": f"{CBGP}{n}", "trap_name": "enterpriseSpecific",
            "event_type": "enterprise_specific", "severity": "notice", "varbinds": vbs}


def peer1_trap(n: int, state: str, prev: str | None, ts: datetime = NOW) -> dict:
    vbs = [{"oid": f"{RFC}14.{PEER}", "name": "bgpPeerLastError", "value": "0x0000"},
           {"oid": f"{RFC}2.{PEER}", "name": "bgpPeerState", "value": state}]
    if prev is not None:
        vbs.append({"oid": f"{PEER1}8.{PEER}", "value": prev})
    return {"_signal": "snmptrap", "timestamp": ts.isoformat(), "device": DEVICE,
            "host": "192.168.200.33", "authenticated": False,
            "trap_oid": f"{CBGP}{n}", "trap_name": "enterpriseSpecific",
            "event_type": "enterprise_specific", "severity": "notice", "varbinds": vbs}


def classify(ev: dict):
    return P.trap_control_signal(ev, TENANT, NOW)


class CiscoBgp4RuleTest(unittest.TestCase):
    def assertTransition(self, ev: dict, state: str, peer: str = PEER) -> None:
        sig = classify(ev)
        self.assertIsNotNone(sig, ev["trap_oid"])
        self.assertEqual(sig.kind, "bgp_adjacency_change")
        self.assertEqual(sig.entity_id, f"{DEVICE}:{peer}")
        self.assertEqual(sig.attrs["state"], state)
        self.assertEqual(sig.attrs["peer"], peer)
        self.assertEqual(sig.attrs["rule_id"], "trap.bgp.cisco_bgp4")
        self.assertEqual(sig.severity.value, "warn" if state == "up" else "high")

    def assertNotAdjacency(self, ev: dict) -> None:
        sig = classify(ev)
        self.assertTrue(sig is None or sig.kind != "bgp_adjacency_change",
                        f"{ev['trap_oid']} became {sig and sig.kind}")

    # cbgpFsmStateChange (.0.1) — every FSM move; only the RFC-equivalent ones count.
    def test_fsm_state_change_into_established_is_up(self):
        self.assertTransition(peer1_trap(1, "established(6)", "5"), "up")

    def test_fsm_state_change_backward_is_down(self):
        self.assertTransition(peer1_trap(1, "idle(1)", "6"), "down")

    def test_fsm_state_change_forward_churn_is_not_a_signal(self):
        self.assertNotAdjacency(peer1_trap(1, "active(3)", "1"))
        self.assertNotAdjacency(peer1_trap(1, "connect(2)", "1"))

    def test_fsm_state_change_without_prev_state_only_counts_established(self):
        self.assertTransition(peer1_trap(1, "established(6)", None), "up")
        self.assertNotAdjacency(peer1_trap(1, "idle(1)", None))

    # cbgpBackwardTransition (.0.2)
    def test_backward_transition_is_down(self):
        self.assertTransition(peer1_trap(2, "idle(1)", "6"), "down")

    # cbgpPeer2EstablishedNotification (.0.5) / BackwardTransNotification (.0.6)
    def test_peer2_established_is_up(self):
        self.assertTransition(peer2_trap(5, "6"), "up")

    def test_peer2_backward_notification_is_down_without_prev(self):
        self.assertTransition(peer2_trap(6, "1"), "down")

    # cbgpPeer2FsmStateChange (.0.7) / BackwardTransition (.0.8)
    def test_peer2_fsm_change(self):
        self.assertTransition(peer2_trap(7, "6", "5"), "up")
        self.assertTransition(peer2_trap(7, "1", "6"), "down")
        self.assertTransition(peer2_trap(7, "idle(1)", "openconfirm(5)"), "down")
        self.assertNotAdjacency(peer2_trap(7, "3", "1"))

    def test_peer2_backward_transition_is_down(self):
        self.assertTransition(peer2_trap(8, "1", "3"), "down")

    def test_prefix_threshold_notifications_are_not_adjacency(self):
        for n in (3, 4, 9, 10):
            self.assertNotAdjacency(peer2_trap(n, "6", "6"))

    # WHICH SESSION
    def test_rfc4001_prefixed_ipv4_index(self):
        self.assertTransition(peer2_trap(5, "6", index=f"1.4.{PEER}"), "up")

    def test_ipv6_index_is_canonicalised_both_forms(self):
        octets = "32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1"
        self.assertTransition(peer2_trap(6, "1", index=f"2.16.{octets}"), "down", "2001:db8::1")
        self.assertTransition(peer2_trap(6, "1", index=octets), "down", "2001:db8::1")

    def test_garbage_index_binds_the_device_not_a_phantom(self):
        sig = classify(peer2_trap(6, "1", index="1.4.10.0.1"))  # truncated InetAddress
        self.assertIsNotNone(sig)
        self.assertEqual(sig.entity_id, DEVICE)
        self.assertEqual(sig.attrs["peer"], "")

    def test_unattributed_trap_still_emits_nothing(self):
        self.assertIsNone(classify({**peer2_trap(6, "1"), "device": ""}))

    def test_fsm_attrs_are_omitted_when_the_trap_did_not_carry_them(self):
        sig = classify(peer2_trap(6, "1"))
        self.assertEqual(sig.attrs["fsm_to"], "1")
        self.assertNotIn("fsm_from", sig.attrs)


class InetIndexTextTest(unittest.TestCase):
    def test_forms(self):
        cases = {
            "10.0.0.1": "10.0.0.1",
            "1.4.10.0.0.1": "10.0.0.1",
            "2.16.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1": "2001:db8::1",
            "32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1": "2001:db8::1",
        }
        for raw, want in cases.items():
            self.assertEqual(inet_index_text(raw), want, raw)

    def test_rejects(self):
        for raw in ("", "1.2.3", "1.4.1.2.3", "256.1.1.1", "a.b.c.d", "1..2.3",
                    "3.8.1.2.3.4.0.0.0.1",      # ipv4z: zoned, not an entity
                    "1.2.3.4.5", "1234.1.1.1", "-1.2.3.4"):
            self.assertEqual(inet_index_text(raw), "", raw)


class RecordedEventTest(unittest.TestCase):
    """The lab's real transition: six families, one transition."""

    def test_first_transition_six_reports_one_signal(self):
        col = TransitionCollapser()
        first = [t for t in recorded() if t["timestamp"] < "2026-11-01T17:00:11"]
        self.assertEqual(len(first), 6)
        sigs = [classify(t) for t in first]
        self.assertTrue(all(s is not None for s in sigs), "every family classifies")
        self.assertEqual({(s.entity_id, s.attrs["state"]) for s in sigs},
                         {(f"{DEVICE}:{PEER}", "down")})
        kept = [s for s in sigs if col.admit(TENANT, s.entity_id, s.attrs["state"], s.ts)]
        self.assertEqual(len(kept), 1)
        self.assertEqual(col.collapsed, 5)

    def test_idle_to_active_retry_is_not_a_signal(self):
        later = [t for t in recorded() if t["timestamp"] >= "2026-11-01T17:00:11"]
        self.assertEqual(len(later), 2)
        self.assertTrue(all(classify(t) is None for t in later))

    def test_cisco_only_family_gives_the_rfc_evidence(self):
        evs = recorded()
        rfc = {(s.entity_id, s.attrs["state"]) for s in map(classify, evs)
               if s is not None and s.attrs["rule_id"] == "trap.bgp.adjacency_change"}
        cisco = {(s.entity_id, s.attrs["state"]) for s in map(classify, evs)
                 if s is not None and s.attrs["rule_id"] == "trap.bgp.cisco_bgp4"}
        self.assertTrue(rfc)
        self.assertEqual(rfc, cisco)


class TransitionCollapserTest(unittest.TestCase):
    T0 = NOW

    def at(self, s: float) -> datetime:
        return self.T0 + timedelta(seconds=s)

    def test_same_state_inside_window_collapses(self):
        c = TransitionCollapser(window_s=5)
        self.assertTrue(c.admit("t", "d:p", "down", self.at(0)))
        self.assertFalse(c.admit("t", "d:p", "down", self.at(0.4)))
        self.assertFalse(c.admit("t", "d:p", "down", self.at(-0.2)))  # out-of-order report
        self.assertEqual(c.collapsed, 2)

    def test_a_fast_flap_keeps_every_leg(self):
        c = TransitionCollapser(window_s=5)
        legs = [("down", 0), ("up", 0.5), ("down", 1.0), ("up", 1.5)]
        self.assertEqual([c.admit("t", "d:p", s, self.at(x)) for s, x in legs], [True] * 4)

    def test_same_state_after_window_is_a_new_transition(self):
        c = TransitionCollapser(window_s=5)
        self.assertTrue(c.admit("t", "d:p", "down", self.at(0)))
        self.assertTrue(c.admit("t", "d:p", "down", self.at(30)))

    def test_repeats_do_not_stretch_the_window(self):
        c = TransitionCollapser(window_s=5)
        self.assertTrue(c.admit("t", "d:p", "down", self.at(0)))
        for x in (2, 4):
            self.assertFalse(c.admit("t", "d:p", "down", self.at(x)))
        self.assertTrue(c.admit("t", "d:p", "down", self.at(6)))

    def test_tenants_and_entities_never_collapse_into_each_other(self):
        c = TransitionCollapser(window_s=5)
        self.assertTrue(c.admit("t_a", "d:p", "down", self.at(0)))
        self.assertTrue(c.admit("t_b", "d:p", "down", self.at(0)))
        self.assertTrue(c.admit("t_a", "d:q", "down", self.at(0)))

    def test_stateless_signal_is_always_admitted(self):
        c = TransitionCollapser(window_s=5)
        self.assertTrue(c.admit("t", "d", "", self.at(0)))
        self.assertTrue(c.admit("t", "d", "", self.at(0)))
        self.assertEqual(len(c), 0)

    def test_bounded(self):
        c = TransitionCollapser(window_s=5, max_keys=3)
        for i in range(10):
            c.admit("t", f"d:{i}", "down", self.at(0))
        self.assertEqual(len(c), 3)
        # The evicted oldest entity is admitted again — never wrongly collapsed.
        self.assertTrue(c.admit("t", "d:0", "down", self.at(0.1)))

    def test_rejects_bad_config(self):
        with self.assertRaises(ValueError):
            TransitionCollapser(window_s=0)
        with self.assertRaises(ValueError):
            TransitionCollapser(max_keys=0)


class HandleSnmptrapCollapseTest(unittest.IsolatedAsyncioTestCase):
    """End to end through the trap lane: the recorded six → one corr_signals row."""

    def setUp(self):
        self.rows: list[dict] = []

        class FakeCH:
            async def insert(_self, table, rows, dedup_token=""):
                for r in rows:
                    self.rows.append({"_table": table, **r})

        self._prev = (main.ch, main.CORR_SIGNALS_ENABLED, main.TRAP_TRANSITIONS,
                      main.TENANT_ENRICHMENT_FILE, main._tenant_map, main._tenant_mtime)
        main.ch = FakeCH()
        main.CORR_SIGNALS_ENABLED = True
        main.TRAP_TRANSITIONS = TransitionCollapser()
        main.TRAPS_RECEIVED = main.TRAPS_NORMALIZED = main.TRAPS_DROPPED = main.TRAPS_RECANON = 0
        self._tmp = tempfile.TemporaryDirectory()
        csv_path = os.path.join(self._tmp.name, "device_tenant.csv")
        with open(csv_path, "w", encoding="utf-8") as f:
            f.write(f"identity,tenant_id\n{DEVICE},\n")
        main.TENANT_ENRICHMENT_FILE = csv_path
        main._tenant_map = {}
        main._tenant_mtime = -1.0
        self.addCleanup(self._restore)

    def _restore(self):
        (main.ch, main.CORR_SIGNALS_ENABLED, main.TRAP_TRANSITIONS,
         main.TENANT_ENRICHMENT_FILE, main._tenant_map, main._tenant_mtime) = self._prev
        self._tmp.cleanup()

    async def test_recorded_event_is_one_signal_and_counted(self):
        for t in recorded():
            # Fresh, admissible timestamps with the recorded spacing preserved.
            ts = datetime.fromisoformat(t["timestamp"].replace("Z", "+00:00"))
            shifted = datetime.now(timezone.utc) - timedelta(seconds=30) + (
                ts - datetime(2026, 11, 1, 17, 0, 9, tzinfo=timezone.utc))
            await main.handle_snmptrap({**t, "timestamp": shifted.isoformat()})
        await main.SIGNAL_BATCH.flush()
        sigs = [r for r in self.rows if r["_table"] == "netops.corr_signals"]
        self.assertEqual(len(sigs), 1, sigs)
        self.assertEqual(sigs[0]["entity_id"], f"{DEVICE}:{PEER}")
        self.assertEqual(main.TRAPS_RECEIVED, 8)
        self.assertEqual(main.TRAPS_NORMALIZED, 1)
        self.assertEqual(main.TRAPS_DROPPED, 2)            # the idle→active retry pair
        self.assertEqual(main.TRAP_TRANSITIONS.collapsed, 5)
        self.assertEqual(main._health_payload()["ingest"]["traps_collapsed"], 5)


if __name__ == "__main__":
    unittest.main()
