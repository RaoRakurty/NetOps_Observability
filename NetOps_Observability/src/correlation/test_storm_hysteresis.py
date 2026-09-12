# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Storm-mode hysteresis (gate spec §7a, 2026-08-22).

ISA-18.2/EEMUA-191 define floods with an entry/exit BAND (>10/10min in,
<5/10min out) because a single threshold flaps the declaration at the
boundary — and `storm_mode` is a per-snapshot honesty stamp that must
describe a state, not the last sample. Enter at CORR_STORM_FRACTION (0.9),
exit only below CORR_STORM_EXIT_FRACTION (0.45).
"""
from __future__ import annotations

import pytest

import main


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.setattr(main, "_STORM_ACTIVE", False)
    monkeypatch.setattr(main, "STORM_BUFFER_FRACTION", 0.9)
    monkeypatch.setattr(main, "STORM_EXIT_FRACTION", 0.45)


def test_enters_at_the_entry_threshold():
    assert main._storm_state(89_999, 100_000) is False
    assert main._storm_state(90_000, 100_000) is True


def test_stays_in_storm_inside_the_band():
    """THE hysteresis: once in, a dip below entry but above exit must NOT
    clear the declaration — that dip is the flapping a band exists to absorb."""
    assert main._storm_state(95_000, 100_000) is True
    assert main._storm_state(60_000, 100_000) is True, "cleared inside the band"
    assert main._storm_state(46_000, 100_000) is True, "cleared just above exit"


def test_exits_below_the_exit_threshold_and_rearms():
    main._storm_state(95_000, 100_000)
    assert main._storm_state(44_000, 100_000) is False
    # re-entry requires the full entry threshold again
    assert main._storm_state(60_000, 100_000) is False, "re-entered below entry"
    assert main._storm_state(91_000, 100_000) is True


def test_mutation_single_threshold_would_flap():
    """The behaviour a threshold-only implementation cannot produce: the same
    boundary sample sequence yields opposite states depending on history."""
    seq = [95_000, 60_000, 44_000, 60_000]
    got = [main._storm_state(n, 100_000) for n in seq]
    assert got == [True, True, False, False], got


def test_zero_maxlen_never_divides_by_zero():
    assert main._storm_state(0, 0) is False
