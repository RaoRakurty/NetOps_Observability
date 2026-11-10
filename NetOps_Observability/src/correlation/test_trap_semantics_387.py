# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""tracker 387, trap semantics — stage [1] normalize of BGP transition traps.

Owner rule (2026-11-10): only an ESTABLISHED session going down is a BGP session
failure. The lab's cEDGE-81 neighbour 192.168.200.34 oscillates idle <-> active
(~90 transitions/h, six notifications each): it never came up, so it withdrew
nothing, and before this change every active -> idle produced a `high`
bgp_adjacency_change down, which opens an object alone (E:104).

Pins, by value:
  * the classifier is the receiver's, row for row (the shared JSON fixture);
  * a never-established or progressing transition builds no down signal, from
    the trap's own states or the receiver's `bgp.transition_class`, and is
    counted;
  * six grouped reports of a real session loss are ONE signal end to end;
  * a forged class outside the vocabulary is ignored, and "unknown" leaves the
    rule's reading as it was (no evidence, no new claim).
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

import main
import producers as P
from trap_collapse import TransitionCollapser

HERE = os.path.dirname(os.path.abspath(__file__))
CLASSES = os.path.join(HERE, "..", "backend", "collectors", "testdata", "bgp_transition_classes.json")
LAB = os.path.join(HERE, "..", "backend", "collectors", "testdata", "traps_lab_20261110.jsonl")
DEVICE = "cedge-81-11060ae2"
PEER = "192.168.200.34"
TENANT = "t_lab"
NOW = datetime(2026, 11, 10, 6, 0, tzinfo=timezone.utc)

CBGP = "1.3.6.1.4.1.9.9.187.0."
PEER2 = "1.3.6.1.4.1.9.9.187.1.2.5.1."
PEER1 = "1.3.6.1.4.1.9.9.187.1.2.1.1."
RFC = "1.3.6.1.2.1.15.3.1."


def lab_group() -> list[dict]:
    """The real active -> idle transition (2026-11-10 04:05:35-38), six reports,
    as the receiver now stamps them: bgp.transition_class never_established."""
    out = []
    with open(LAB, encoding="utf-8") as fh:
        for line in fh:
            rec = json.loads(line)
            if rec["_capture"] != "bgp_transition":
                continue
            states = [v["value"] for v in rec["varbinds"] if v["oid"].startswith((PEER2 + "3.", RFC + "2."))]
            if states != ["1"]:
                continue  # the forward (idle -> active) report that follows
            out.append({**rec, "_signal": "snmptrap", "device": DEVICE, "authenticated": False,
                        "trap_name": "", "event_type": "", "severity": "notice",
                        "attribution_basis": "interface_ip",
                        "bgp": {"peer_address": PEER, "peer_afi": "ipv4", "state": "idle",
                                "prev_state": "active", "transition_class": "never_established",
                                "peer_basis": "index"}})
    return out


def trap(n: int, state: str, prev: str | None, cls: str | None, ts: datetime = NOW,
         rfc: bool = False) -> dict:
    if rfc:
        vbs = [{"oid": f"{RFC}14.{PEER}", "value": "0x0400"}, {"oid": f"{RFC}2.{PEER}", "value": state}]
        oid = "1.3.6.1.2.1.15.7.2"
    else:
        vbs = [{"oid": f"{PEER2}17.{PEER}", "value": "0x0400"}, {"oid": f"{PEER2}3.{PEER}", "value": state}]
        if prev is not None:
            vbs.append({"oid": f"{PEER2}29.{PEER}", "value": prev})
        oid = f"{CBGP}{n}"
    ev = {"_signal": "snmptrap", "timestamp": ts.isoformat(), "device": DEVICE, "host": "192.168.200.33",
          "authenticated": False, "trap_oid": oid, "trap_name": "", "event_type": "",
          "severity": "notice", "attribution_basis": "interface_ip", "varbinds": vbs}
    if cls is not None:
        ev["bgp"] = {"peer_address": PEER, "peer_afi": "ipv4", "state": "idle", "transition_class": cls}
    return ev


class ClassifierParityTest(unittest.TestCase):
    def test_same_table_as_the_receiver(self):
        with open(CLASSES, encoding="utf-8") as fh:
            rows = json.load(fh)["rows"]
        self.assertEqual(len(rows), 42)
        for r in rows:
            self.assertEqual(P.classify_bgp_transition(r["prev"], r["state"]), r["class"], r)
        self.assertEqual({r["class"] for r in rows}, set(P.BGP_TRANSITION_CLASSES))


class StageOneTest(unittest.TestCase):
    def setUp(self):
        P.reset_parser_counters()

    def classify(self, ev):
        return P.trap_control_signal(ev, TENANT, NOW)

    def test_the_lab_flap_is_never_a_session_failure(self):
        evs = lab_group()
        self.assertEqual(len(evs), 6)
        sigs = [self.classify(e) for e in evs]
        self.assertEqual(sigs, [None] * 6)
        self.assertEqual(P.parser_stats()["trap_bgp_not_session_failure"],
                         {"never_established": 6, "progressing": 0})

    def test_the_trap_own_states_decide_first(self):
        # A forged receiver class cannot turn established -> idle into a non-event.
        sig = self.classify(trap(8, "1", "6", "never_established"))
        self.assertIsNotNone(sig)
        self.assertEqual((sig.attrs["state"], sig.severity.value), ("down", "high"))

    def test_the_receiver_class_decides_when_the_trap_has_no_prior(self):
        self.assertIsNone(self.classify(trap(0, "idle(1)", None, "never_established", rfc=True)))
        self.assertIsNone(self.classify(trap(6, "1", None, "progressing")))
        lost = self.classify(trap(6, "1", None, "session_lost"))
        self.assertEqual(lost.attrs["state"], "down")

    def test_no_evidence_keeps_the_rule_reading(self):
        for cls in (None, "unknown", "forged_value"):
            sig = self.classify(trap(0, "idle(1)", None, cls, rfc=True))
            self.assertIsNotNone(sig, cls)
            self.assertEqual(sig.attrs["state"], "down")

    def test_recovery_is_untouched(self):
        sig = self.classify(trap(7, "6", "5", "session_up"))
        self.assertEqual((sig.attrs["state"], sig.severity.value), ("up", "warn"))


class HandleSnmptrapTest(unittest.IsolatedAsyncioTestCase):
    """End to end through the trap lane."""

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
        P.reset_parser_counters()
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

    async def _feed(self, evs):
        base = datetime.now(timezone.utc) - timedelta(seconds=30)
        for i, ev in enumerate(evs):
            await main.handle_snmptrap({**ev, "timestamp": (base + timedelta(milliseconds=100 * i)).isoformat()})
        await main.SIGNAL_BATCH.flush()
        return [r for r in self.rows if r["_table"] == "netops.corr_signals"]

    async def test_six_reports_of_a_session_loss_are_one_signal(self):
        evs = [trap(6, "1", None, "session_lost"), trap(0, "idle(1)", None, "session_lost", rfc=True),
               trap(8, "1", "6", "session_lost"), trap(7, "1", "6", "session_lost"),
               trap(6, "1", None, "session_lost"), trap(8, "1", "6", "session_lost")]
        sigs = await self._feed(evs)
        self.assertEqual(len(sigs), 1, sigs)
        self.assertEqual(sigs[0]["entity_id"], f"{DEVICE}:{PEER}")
        self.assertEqual(main.TRAPS_NORMALIZED, 1)
        self.assertEqual(main.TRAP_TRANSITIONS.collapsed, 5)

    async def test_the_lab_flap_reaches_no_window(self):
        sigs = await self._feed(lab_group())
        self.assertEqual(sigs, [])
        self.assertEqual(main.TRAPS_RECEIVED, 6)
        self.assertEqual(main.TRAPS_DROPPED, 6)
        self.assertIn('corr_trap_bgp_not_session_failure_total{class="never_established"} 6',
                      main._metrics_text())


if __name__ == "__main__":
    unittest.main()
