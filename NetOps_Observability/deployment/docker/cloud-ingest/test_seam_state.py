# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Unit tests for the pure seam-state core (#105 P1, §11).

The tracker is the shared truth engine for every provider seam lane, so its
semantics are pinned here: first-sight silence, transition dedup, flap
detection, freshness decay to `unknown`, restart round-trips, counter resets,
and expected-context route-drop materiality.

Run: python3 -m pytest test_seam_state.py  (or python3 -m unittest)
"""
import unittest

from seam_state import (SeamStateTracker, counter_delta, material_route_drop,
                        FLAP_COUNT, FLAP_WINDOW_S)

OBS = "2026-07-14T22:00:00Z"


class TestObserve(unittest.TestCase):
    def test_first_sight_is_silent(self):
        # Discovering an already-down seam is inventory, not a witnessed event.
        t = SeamStateTracker()
        self.assertEqual(t.observe("k", "down", OBS, 1000.0), [])
        self.assertEqual(t.current("k"), "down")

    def test_transition_emits_once(self):
        t = SeamStateTracker()
        t.observe("k", "up", OBS, 1000.0)
        evs = t.observe("k", "down", OBS, 1060.0)
        self.assertEqual(len(evs), 1)
        self.assertEqual((evs[0]["from"], evs[0]["to"]), ("up", "down"))
        self.assertEqual(evs[0]["observed_at"], OBS)

    def test_repeated_state_is_deduped(self):
        t = SeamStateTracker()
        t.observe("k", "up", OBS, 1000.0)
        t.observe("k", "down", OBS, 1060.0)
        # the same DOWN re-observed forever must never re-announce
        for i in range(5):
            self.assertEqual(t.observe("k", "down", OBS, 1120.0 + i * 60), [])

    def test_empty_state_maps_to_unknown(self):
        t = SeamStateTracker()
        t.observe("k", "up", OBS, 1000.0)
        evs = t.observe("k", "", OBS, 1060.0)
        self.assertEqual(evs[0]["to"], "unknown")

    def test_flap_marker_at_threshold(self):
        t = SeamStateTracker()
        t.observe("k", "up", OBS, 1000.0)
        now, flaps = 1000.0, []
        for state in ("down", "up", "down"):
            now += 60
            flaps = [e for e in t.observe("k", state, OBS, now) if e.get("flap")]
        self.assertEqual(len(flaps), 1)  # 3rd transition inside 15 min → flap
        self.assertEqual(flaps[0]["transitions_15m"], FLAP_COUNT)

    def test_slow_transitions_never_flap(self):
        t = SeamStateTracker()
        t.observe("k", "up", OBS, 1000.0)
        now = 1000.0
        for state in ("down", "up", "down", "up"):
            now += FLAP_WINDOW_S + 1  # each transition outside the window
            evs = t.observe("k", state, OBS, now)
            self.assertFalse(any(e.get("flap") for e in evs))


class TestExpire(unittest.TestCase):
    def test_stale_state_decays_to_unknown_once(self):
        t = SeamStateTracker()
        t.observe("k", "up", OBS, 1000.0)
        evs = t.expire(freshness_s=360, now=1361.0)
        self.assertEqual([(e["from"], e["to"]) for e in evs], [("up", "unknown")])
        # already-unknown keys stay quiet
        self.assertEqual(t.expire(freshness_s=360, now=2000.0), [])

    def test_fresh_state_survives(self):
        t = SeamStateTracker()
        t.observe("k", "up", OBS, 1000.0)
        self.assertEqual(t.expire(freshness_s=360, now=1300.0), [])
        self.assertEqual(t.current("k"), "up")

    def test_reobservation_resets_freshness(self):
        t = SeamStateTracker()
        t.observe("k", "up", OBS, 1000.0)
        t.observe("k", "up", OBS, 1300.0)  # identical sample refreshes epoch
        self.assertEqual(t.expire(freshness_s=360, now=1400.0), [])


class TestPersistence(unittest.TestCase):
    def test_round_trip_preserves_dedup(self):
        # A poller restart must neither re-announce old transitions nor forget state.
        t = SeamStateTracker()
        t.observe("k", "up", OBS, 1000.0)
        t.observe("k", "down", OBS, 1060.0)
        t2 = SeamStateTracker.from_state(t.to_state())
        self.assertEqual(t2.current("k"), "down")
        self.assertEqual(t2.observe("k", "down", OBS, 1120.0), [])
        self.assertEqual(len(t2.observe("k", "up", OBS, 1180.0)), 1)

    def test_from_state_tolerates_garbage(self):
        t = SeamStateTracker.from_state({"k": "not-a-dict", "j": {"no_state": 1}})
        self.assertEqual(t.current("k"), "unknown")
        self.assertEqual(t.current("j"), "unknown")

    def test_from_state_none(self):
        self.assertEqual(SeamStateTracker.from_state(None).to_state(), {})


class TestCounterDelta(unittest.TestCase):
    def test_first_sample_is_absolute(self):
        self.assertEqual(counter_delta(None, 5.0), 5.0)

    def test_normal_delta(self):
        self.assertEqual(counter_delta(10.0, 14.0), 4.0)

    def test_reset_never_goes_negative(self):
        self.assertEqual(counter_delta(100.0, 3.0), 3.0)


class TestMaterialRouteDrop(unittest.TestCase):
    def test_uses_expected_context_not_fixed_threshold(self):
        self.assertTrue(material_route_drop(1000, 900))   # 10% loss
        self.assertFalse(material_route_drop(1000, 995))  # noise
        self.assertTrue(material_route_drop(3, 2))        # tiny tables: 1 route matters

    def test_zero_after_nonzero_always_material(self):
        self.assertTrue(material_route_drop(1, 0))

    def test_no_baseline_or_growth_is_not_a_drop(self):
        self.assertFalse(material_route_drop(None, 0))
        self.assertFalse(material_route_drop(100, 100))
        self.assertFalse(material_route_drop(100, 150))


if __name__ == "__main__":
    unittest.main()
