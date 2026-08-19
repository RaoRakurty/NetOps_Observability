"""Tracker 156 — the port-event pre-filter must never reject a real port event.

`port_event_signal` used to run all of `_PORT_EVENT_RULES` on every syslog line:
12 of the 16.5 regex searches per event, all missing for ordinary traffic. The
pre-filter is the UNION of exactly those rules, so soundness is structural — a
union matches iff some alternative matches. These tests pin that property so it
survives someone adding a rule, reordering the list, or "tidying" the union into
a hand-written keyword check.

The dangerous direction is UNDER-matching: a line the filter rejects never
reaches the chain, so a real optics fault would vanish silently. Over-matching
is harmless (it falls through and matches nothing).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

import producers as P
import pytest

# Vendor-shaped lines, one or more per rule family.
CORPUS = [
    "%PLATFORM-4-XCVR: Unsupported transceiver found in Gi0/1",
    "unqualified SFP detected on Ethernet1/1",
    "Transceiver rx power low alarm on Et1/2 (-14.2 dBm below threshold)",
    "receive optical power below low alarm threshold Ethernet3",
    "Transceiver temperature high alarm on Et1/3 above threshold",
    "temp high warning alarm optics Gi0/4",
    "Tx bias current high alarm threshold exceeded Et1/5",
    "bias high alarm on transceiver port 6",
    "Uncorrectable FEC codeword errors on Ethernet1/7",
    "FEC uncorrectable block errors detected",
    "pre-FEC BER exceeded on Et1/8",
    "fec corrected rate above threshold Ethernet9",
    "%ETH-3-LOCAL_FAULT: local fault detected on Ethernet1/10",
    "remote fault REMOTE_FAULT on Et1/11",
    "deskew failure on lane 2 Ethernet1/12",
    "align marker lost lane 3 Et1/13",
    "hi-ber detected Ethernet1/14",
    "high bit error rate on Et1/15",
    "no light detected on Ethernet1/16",
    "loss of signal LOS on Et1/17",
    "SIGNAL_LOSS on Et1/17",
    "transceiver removed then insert on Et1/18 flap",
    "SFP flap detected Gi0/19",
    "optic flap on Ethernet1/20",
]


def test_the_prefilter_is_derived_from_the_rules_not_hand_written():
    """Every rule's pattern must appear verbatim inside the union."""
    union = P._PORT_EVENT_PREFILTER.pattern
    for pat, kind, _iface, _sev in P._PORT_EVENT_RULES:
        assert f"(?:{pat.pattern})" in union, (
            f"rule {kind!r} is not in the pre-filter union — a message matching "
            "it would be rejected before the chain ever ran")


def test_prefilter_alternative_count_matches_the_rules():
    assert P._PORT_EVENT_PREFILTER.pattern.count("(?:") >= len(P._PORT_EVENT_RULES)


@pytest.mark.parametrize("rule_index", range(len(P._PORT_EVENT_RULES)))
def test_every_rule_implies_the_prefilter(rule_index):
    """Soundness per rule, against corpus text that rule actually matches."""
    pat, kind, _iface, _sev = P._PORT_EVENT_RULES[rule_index]
    hits = [s for s in CORPUS if pat.search(s)]
    assert hits, f"no corpus line exercises rule {kind!r} — the corpus has a hole"
    for s in hits:
        assert P._PORT_EVENT_PREFILTER.search(s), (
            f"pre-filter REJECTS a line that rule {kind!r} matches: {s!r}")


@pytest.mark.parametrize("line", CORPUS)
def test_corpus_lines_all_pass_the_prefilter(line):
    assert P._PORT_EVENT_PREFILTER.search(line), (
        f"pre-filter rejects a vendor port-event line: {line!r}")


def test_union_would_pick_up_a_newly_added_rule():
    """The union is rebuilt FROM the rules, so adding one cannot desync it."""
    extra = re.compile(r"zzz_new_optics_rule_zzz", re.IGNORECASE)
    assert not P._PORT_EVENT_PREFILTER.search("zzz_new_optics_rule_zzz")
    rebuilt = re.compile(
        "|".join(f"(?:{p.pattern})" for p, _k, _i, _s in
                 list(P._PORT_EVENT_RULES) + [(extra, "x", False, None)]),
        re.IGNORECASE)
    assert rebuilt.search("zzz_new_optics_rule_zzz")


# --- the behaviour the pre-filter exists to change -------------------------

def test_ordinary_traffic_short_circuits(monkeypatch):
    """A LINK-3-UPDOWN line must not reach the rule chain at all."""
    touched = []
    real = list(P._PORT_EVENT_RULES)

    class Watch(list):
        def __iter__(self):
            touched.append(1)
            return super().__iter__()

    monkeypatch.setattr(P, "_PORT_EVENT_RULES", Watch(real))
    ev = {"hostname": "leaf1", "appname": "LINK-3-UPDOWN",
          "message": "%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down",
          "severity": "err"}
    assert P.port_event_signal(ev, "acme", datetime.now(timezone.utc)) is None
    assert not touched, "the rule chain ran for a line the pre-filter should reject"


def test_a_real_port_event_still_classifies():
    ev = {"hostname": "leaf1", "appname": "PLATFORM-4-XCVR",
          "message": "Transceiver rx power low alarm on Et1/2 below threshold",
          "severity": "err"}
    sig = P.port_event_signal(ev, "acme", datetime.now(timezone.utc))
    assert sig is not None and sig.kind
