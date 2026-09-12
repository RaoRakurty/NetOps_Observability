# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Wireless intake lane (#128 Phase 4) — the netops.wireless_sessions /
netops.wireless_events contract through the REAL handlers with a fake CH
(the test_metric_intake pattern):

  · a session record writes the session row + AT LEAST one MLO link row (a
    non-MLO client is an MLO client with one link — §10) and NEVER a signal
  · an onboarding SUCCESS writes the episode row and NO signal (§20 rule)
  · an onboarding FAILURE writes the episode row AND one corr_signals row
  · a roam reported by both APs collapses onto one deterministic roam_id
  · untenanted / identity-less records are dropped and counted, never guessed
"""
import asyncio
import unittest

import main


class FakeCH:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    async def insert(self, table: str, rows, dedup_token="") -> None:
        for r in rows:
            self.rows.append({"_table": table, **r})


def run(coro):
    return asyncio.run(coro)


SESSION_EV = {
    "tenant_id": "t1", "session_id": "sess-1",
    "client_mac": "A8:66:7F:01:02:03", "bssid": "AA:BB:CC:00:00:01",
    "ap_ref": "ap-abc", "ssid_name": "corp",
    "assoc_start_ms": 1753500000000,
    "observer_id": "catalyst_9800:int-1",
}

ONBOARD_FAIL_EV = {
    "tenant_id": "t1", "type": "onboarding",
    "client_mac": "a8:66:7f:01:02:03", "bssid": "aa:bb:cc:00:00:01",
    "ap_ref": "ap-abc", "attempt_start_ms": 1753500000000,
    "observer_id": "catalyst_9800:int-1",
    "wlan": {"wlan_id": "wlan-corp", "auth_method": "dot1x",
             "security_mode": "wpa2_enterprise", "address_policy": "dual"},
    "observations": {
        "discovery": {"outcome": "success"},
        "authentication": {"outcome": "success"},
        "association": {"outcome": "success"},
        "key_exchange": {"outcome": "success"},
        "addressing": {"outcome": "failure", "reason_code": "no_offer"},
    },
}


class WirelessIntakeTest(unittest.TestCase):
    def setUp(self):
        self.ch = FakeCH()
        self._old_ch = main.ch
        main.ch = self.ch
        main.WIRELESS_RECEIVED = main.WIRELESS_SIGNALS = main.WIRELESS_DROPPED = 0

    def tearDown(self):
        main.ch = self._old_ch

    def rows(self, table):
        return [r for r in self.ch.rows if r["_table"] == table]

    def test_session_writes_row_and_implicit_link_never_a_signal(self):
        run(main.handle("netops.wireless_sessions", dict(SESSION_EV)))
        sess = self.rows("netops.wireless_sessions")
        self.assertEqual(len(sess), 1)
        self.assertEqual(sess[0]["client_mac"], "a8:66:7f:01:02:03")
        self.assertEqual(sess[0]["link_count"], 1)
        links = self.rows("netops.wireless_mlo_links")
        self.assertEqual(len(links), 1, "non-MLO session still writes one link row")
        self.assertEqual(links[0]["link_index"], 0)
        self.assertFalse(self.rows("netops.corr_signals"),
                         "session records are data, never engine signals")

    def test_mlo_session_writes_per_link_rows(self):
        ev = dict(SESSION_EV)
        ev["links"] = [
            {"band": "5GHz", "rssi_dbm": -55, "link_state": "active"},
            {"band": "6GHz", "rssi_dbm": -62, "link_state": "active"},
        ]
        run(main.handle("netops.wireless_sessions", ev))
        self.assertTrue(self.rows("netops.wireless_sessions")[0]["is_mlo"])
        links = self.rows("netops.wireless_mlo_links")
        self.assertEqual([ln["band"] for ln in links], ["5GHz", "6GHz"])

    def test_onboarding_success_no_signal(self):
        ev = dict(ONBOARD_FAIL_EV)
        ev["observations"] = {p: {"outcome": "success"} for p in (
            "discovery", "authentication", "association", "key_exchange",
            "addressing", "name_resolution", "first_data")}
        run(main.handle("netops.wireless_events", ev))
        self.assertEqual(len(self.rows("netops.wireless_onboarding_episodes")), 1)
        self.assertFalse(self.rows("netops.corr_signals"))
        self.assertEqual(main.WIRELESS_SIGNALS, 0)

    def test_onboarding_failure_writes_episode_and_one_signal(self):
        run(main.handle("netops.wireless_events", dict(ONBOARD_FAIL_EV)))
        run(main.SIGNAL_BATCH.flush())  # drain the batched write path
        eps = self.rows("netops.wireless_onboarding_episodes")
        self.assertEqual(len(eps), 1)
        self.assertEqual(eps[0]["terminal_phase"], "addressing")
        sigs = self.rows("netops.corr_signals")
        self.assertEqual(len(sigs), 1)
        self.assertEqual(sigs[0]["kind"], "wireless_onboarding_dhcp_failure")
        self.assertEqual(sigs[0]["entity_type"], "wireless_session")
        self.assertEqual(main.WIRELESS_SIGNALS, 1)

    def test_roam_double_report_collapses(self):
        base = {"tenant_id": "t1", "type": "roam",
                "client_mac": "a8:66:7f:01:02:03",
                "from_bssid": "aa:bb:cc:00:00:01", "to_bssid": "aa:bb:cc:00:00:02",
                "ts_ms": 1753500001000}
        run(main.handle("netops.wireless_events", dict(base)))
        # The OTHER AP reports the same roam 800 ms later (same 5 s bucket).
        other = dict(base)
        other["ts_ms"] = 1753500001800
        run(main.handle("netops.wireless_events", other))
        roams = self.rows("netops.wireless_roams")
        self.assertEqual(len(roams), 2)  # both insert; ReplacingMergeTree keys collapse
        self.assertEqual(roams[0]["roam_id"], roams[1]["roam_id"],
                         "both reports must share one deterministic roam_id")

    def test_untenanted_dropped(self):
        ev = dict(SESSION_EV)
        ev.pop("tenant_id")
        run(main.handle("netops.wireless_sessions", ev))
        self.assertFalse(self.ch.rows)
        self.assertEqual(main.WIRELESS_DROPPED, 1)
        ev2 = dict(ONBOARD_FAIL_EV)
        ev2["tenant_id"] = ""
        run(main.handle("netops.wireless_events", ev2))
        self.assertEqual(main.WIRELESS_DROPPED, 2)


if __name__ == "__main__":
    unittest.main()
