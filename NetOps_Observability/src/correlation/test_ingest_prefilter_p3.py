# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""P3 change B — the syslog ingest PRE-FILTER must never reject a promotable line.

`producers.syslog_promotable` decides "cannot promote" from the raw line before
`syslog_control_signal` and `port_event_signal` run. The dangerous direction is
UNDER-matching: a line the screen rejects never reaches a classifier, so a real
BGP flap or optics fault would vanish silently. Over-matching is harmless — the
line falls through the chain and classifies as nothing.

These tests pin soundness three independent ways:

  1. STRUCTURAL — the screen is DERIVED. Its port-event half is extracted from
     `_PORT_EVENT_RULES` by `regex_screen`; its control-plane half is
     re-derived here from each syslog rule's OWN GUARD TREE, so a new rule
     whose marker nobody registered is RED.

     (Before A3 that walk read `syslog_control_signal`'s Python AST, because the
     guards WERE Python. They are catalog rows now — telemetry-catalog/
     events.yaml — so the walk reads the rows. Same contract, same fail-closed
     rule for an unrecognized shape, one less layer of indirection.)
  2. PROPERTY — >=100k lines from the ratified harness generator mix
     (`scripts/scale-miniladder.py` EVENT_MIX_REALISTIC + EVENT_MIX_NOISE) are
     replayed through both classifiers with and without the screen: the
     promoted SET must be byte-identical.
  3. MUTANT — a screen that drops one promotable kind's marker must turn (1)
     and (2) red. A test that cannot fail proves nothing.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

import pytest

import producers as P
from regex_screen import alternative_screen, pattern_screen, split_alternatives

T0 = datetime(2026, 8, 29, 12, 0, 0, tzinfo=timezone.utc)


# ══ 1. the screen is DERIVED from the classifiers, not hand-written ══════════

def _covered(literal: str) -> bool:
    """Would the live screen pass a line whose only content is `literal`?"""
    lits = P._SYSLOG_SCREEN_LITERALS
    assert lits is not None, "the screen failed to build — it is inert"
    hay = literal.lower()
    return any(lit in hay for lit in lits)


def _guard_covered(node) -> bool:
    """Is this promotion guard implied by the screen?

    An `any` needs EVERY disjunct covered (any one alone can admit a line); an
    `all` needs only ONE conjunct (all must hold, so screening on one is sound).
    An unrecognized shape — and a `not`, and an UNREGISTERED regex — is NOT
    covered: fail closed, so a new guard idiom shows up as a test failure rather
    than as a silent hole.
    """
    if not isinstance(node, dict) or len(node) != 1:
        return False
    op, arg = next(iter(node.items()))
    if op == "any":
        return all(_guard_covered(v) for v in arg)
    if op == "all":
        return any(_guard_covered(v) for v in arg)
    if op == "contains":
        return _covered(str(arg[1]))
    if op == "re":
        # A regex is only allowed to CARRY the coverage of a guard if the rule
        # registered it as its `pattern_src`; anything else the screen has never
        # seen and cannot be relied on (the bake refuses a `pattern_src` that is
        # not a live `re` node of its own guard, so the two directions meet).
        pat = str(arg[1])
        if pat not in P._CP_GUARD_PATTERNS:
            return False
        screen = pattern_screen(pat)
        return bool(screen) and all(_covered(lit) for lit in screen)
    return False


def _severity_guard(node) -> bool:
    """The generic device-alarm net: `sev_num is not None and sev_num <= FLOOR`.
    The screen implements it directly (severity is checked before the literal
    scan), so recognizing it is enough."""
    return isinstance(node, dict) and "severity_floor" in node


def _promotion_guards() -> list:
    """Every syslog-lane rule that can emit a Signal, as (rule_id, guard tree).

    A `shadow` row emits nothing, so the screen owes it nothing — excluded on
    purpose, and that is why adding one cannot silently widen this contract."""
    return [(r.rule_id, r.guard_src) for r in P.RULES
            if r.lane == "syslog" and not r.shadow]


def test_the_table_holds_every_promotion_guard():
    """A canary on the derivation itself: if this stops finding rules, every
    coverage test below becomes vacuously true."""
    guards = _promotion_guards()
    assert len(guards) >= 9, (
        f"only {len(guards)} promotion guards found in the syslog rule table — "
        "the lane split drifted and this proves nothing")
    assert all(g is not None for _rid, g in guards), \
        "a syslog rule carries no guard tree at all"


@pytest.mark.parametrize("idx", range(len(_promotion_guards())))
def test_every_promotion_guard_is_implied_by_the_screen(idx):
    rule_id, guard = _promotion_guards()[idx]
    assert _guard_covered(guard) or _severity_guard(guard), (
        f"rule {rule_id!r} is NOT implied by the ingest screen: {guard}\n"
        "A line matching it would be rejected before the classifier ran. "
        "Register its marker in the rule's `markers:` (telemetry-catalog/"
        "events.yaml) — that is what builds producers._CP_GUARD_MARKERS.")


def test_every_port_event_rule_is_implied_by_the_screen():
    """The port half is derived from the rule table itself — assert it landed."""
    for pat, kind, _iface, _sev in P._PORT_EVENT_RULES:
        screen = pattern_screen(pat.pattern)
        assert screen, f"port-event rule {kind!r} is unscreenable — screen must fail OPEN"
        for lit in screen:
            assert _covered(lit), f"port-event rule {kind!r} literal {lit!r} is missing"


@pytest.mark.parametrize("line", [
    "%PLATFORM-4-XCVR: Unsupported transceiver found in Gi0/1",
    "unqualified SFP detected on Ethernet1/1",
    "Transceiver rx power low alarm on Et1/2 (-14.2 dBm below threshold)",
    "receive optical power below low alarm threshold Ethernet3",
    "Transceiver temperature high alarm on Et1/3 above threshold",
    "temp high warning alarm optics Gi0/4",
    "Tx bias current high alarm threshold exceeded Et1/5",
    "Uncorrectable FEC codeword errors on Ethernet1/7",
    "pre-FEC BER exceeded on Et1/8",
    "%ETH-3-LOCAL_FAULT: local fault detected on Ethernet1/10",
    "remote fault REMOTE_FAULT on Et1/11",
    "deskew failure on lane 2 Ethernet1/12",
    "hi-ber detected Ethernet1/14",
    "no light detected on Ethernet1/16",
    "loss of signal LOS on Et1/17",
    "transceiver removed then insert on Et1/18 flap",
])
def test_real_port_event_lines_survive_the_screen(line):
    """The tracker-156 vendor corpus, at INFO severity so only the literal scan
    can save them — the case where a wrong screen loses an optics fault."""
    ev = {"hostname": "leaf1", "appname": "PLATFORM-6-INFO",
          "message": line, "severity": "info"}
    assert P.syslog_promotable(ev), f"screen rejects a real port-event line: {line!r}"


@pytest.mark.parametrize("line,tag", [
    ("isisAdjacencyChange 1921.6800.1001 to state Down", ""),
    ("%CLNS-5-ADJCHANGE: IS-IS adjacency down", "CLNS-5-ADJCHANGE"),
    ("%BGP-5-ADJCHANGE: neighbor 10.0.0.1 Down", "BGP-5-ADJCHANGE"),
    ("%OSPF-5-ADJCHG: Nbr 10.0.0.2 from FULL to DOWN", "OSPF-5-ADJCHG"),
    ("%LINK-3-UPDOWN: Interface Ethernet1, changed state to down", "LINK-3-UPDOWN"),
    ("%LINEPROTO-5-UPDOWN: Line protocol on Interface Et1, changed state to down",
     "LINEPROTO-5-UPDOWN"),
    ("%LLDP-5-NEIGHBOR: neighbor removed on interface Et1", "LLDP-5-NEIGHBOR"),
    ("remotePeerRemoved on interface ethernet-1/1", ""),
    ("%SPANTREE-6-INTERFACE: Et1 moved to discarding", "SPANTREE-6-INTERFACE"),
    ("%NVE-5-BFD_CC_STATE_CHANGE: BFD CC down for bfd-neighbor 10.1.1.1", "NVE-5-BFD"),
    ("%EVPN-3-BLACKLISTED_DUPLICATE_MAC: mac 0011.2233.4455 vlan 10", "EVPN-3-BLACKLIST"),
    ("host aabb.ccdd.eeff blacklisted in vlan 20", ""),
    ("%HSRP-5-STATECHANGE: Vlan10 Grp 1 state Standby -> Active", "HSRP-5-STATECHANGE"),
    ("%SW_MATM-4-MACFLAP_NOTIF: mac 0011.2233.4455 vlan 5", "SW_MATM-4-MACFLAP_NOTIF"),
    ("host 0011.2233.4455 is flapping between port Gi0/1 and port Gi0/2", ""),
])
def test_real_control_plane_lines_survive_the_screen(line, tag):
    """At INFO severity, so the severity net cannot mask a hole in the markers."""
    ev = {"hostname": "leaf1", "appname": tag, "message": line, "severity": "info"}
    assert P.syslog_promotable(ev), f"screen rejects a real control line: {line!r}"


# ══ 2. property: the promoted set is IDENTICAL over the ratified mix ═════════
#
# The generator is the harness's own (scripts/scale-miniladder.py): one full
# EVENT_MIX_REALISTIC table (100 slots) diluted with 1,900 EVENT_MIX_NOISE slots
# = the `production` mix that profile t-nominal-2.5k runs, measured at ~4.9 %
# promotion. Reproduced here rather than imported so the property does not
# depend on a script outside src/correlation.

EVENT_MIX_REALISTIC = (
    (46, "LINK-3-UPDOWN",
     "%LINK-3-UPDOWN: Interface GigabitEthernet0/{if_n}, changed state to {state}", "err"),
    (18, "BGP-5-ADJCHANGE",
     "%BGP-5-ADJCHANGE: neighbor 10.{oct2}.{oct3}.1 {State} Interface flap", "notice"),
    (12, "OSPF-5-ADJCHG",
     ("%OSPF-5-ADJCHG: Process 1, Nbr 10.{oct2}.{oct3}.2 on "
      "GigabitEthernet0/{if_n} from FULL to {STATE}"), "notice"),
    (9, "LLDP-5-NEIGHBOR",
     "%LLDP-5-NEIGHBOR: neighbor {verb} on interface GigabitEthernet0/{if_n}", "notice"),
    (8, "SPANTREE-6-INTERFACE",
     "%SPANTREE-6-INTERFACE: GigabitEthernet0/{if_n} moved to {stp_state}", "info"),
    (7, "ENVMON-4-FAN_FAILED", "%ENVMON-4-FAN_FAILED: Fan {if_n} failed", "warning"),
)
EVENT_MIX_NOISE = (
    (35, "SYS-5-CONFIG_I",
     "%SYS-5-CONFIG_I: Configured from console by admin on vty0", "info"),
    (25, "SEC_LOGIN-5-LOGIN_SUCCESS",
     ("%SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: ops] [Source: "
      "10.{oct2}.{oct3}.50] at 12:00:00 UTC"), "notice"),
    (20, "SSH-5-SSH2_SESSION",
     ("%SSH-5-SSH2_SESSION: SSH2 Session request from 10.{oct2}.{oct3}.9 "
      "(tty = 0) succeeded"), "notice"),
    (12, "SYS-6-LOGGINGHOST_STARTSTOP",
     "%SYS-6-LOGGINGHOST_STARTSTOP: Logging to host 10.0.0.2 port 514 started", "info"),
    (8, "SNMP-5-COLDSTART",
     "%SNMP-5-COLDSTART: SNMP agent on host reconfigured", "notice"),
)


def _table(mix):
    out = []
    for weight, app, tpl, sev in mix:
        out.extend([(app, tpl, sev)] * weight)
    return tuple(out)


def _production_table():
    realistic = _table(EVENT_MIX_REALISTIC)
    noise = _table(EVENT_MIX_NOISE)
    return realistic + tuple(noise[i % len(noise)] for i in range(1900))


PRODUCTION = _production_table()
N_LINES = 100_000


def _events(n=N_LINES):
    """The harness's `_syslog_event` shape, decorrelated exactly as it is there."""
    for seq in range(n):
        app, tpl, sev = PRODUCTION[(seq * 7 + 1) % len(PRODUCTION)]
        state = "down" if seq % 2 == 0 else "up"
        msg = tpl.format(
            if_n=seq % 48, state=state, State=state.capitalize(), STATE=state.upper(),
            oct2=(seq // 251) % 251, oct3=seq % 251,
            verb="removed" if state == "down" else "added",
            stp_state="discarding" if state == "down" else "forwarding",
        ) + f" [mlx seq {seq}]"
        yield {"hostname": f"mlx-{seq % 2500}", "appname": app, "message": msg,
               "severity": sev,
               "timestamp": (T0 + timedelta(milliseconds=seq)).isoformat()}


def _classify(ev):
    """Both promoting classifiers, as handle_syslog calls them."""
    out = []
    for sig in (P.syslog_control_signal(ev, "t1", T0), P.port_event_signal(ev, "t1", T0)):
        if sig is not None:
            out.append(json.dumps(sig.to_ch_row(), sort_keys=True, default=str))
    return out


@pytest.fixture(scope="module")
def corpus():
    return list(_events())


def test_the_corpus_reproduces_the_ratified_promotion_ratio(corpus):
    promoted = sum(1 for ev in corpus if _classify(ev))
    ratio = promoted / len(corpus)
    assert 0.04 <= ratio <= 0.06, (
        f"promotion ratio {ratio:.3%} is not the ratified ~4.9 % production mix — "
        "the property below would be measuring the wrong workload")


def test_the_prefilter_never_rejects_a_promotable_line(corpus):
    """SOUNDNESS, the direction that would lose a signal."""
    for ev in corpus:
        if _classify(ev) and not P.syslog_promotable(ev):
            pytest.fail(f"screen REJECTED a promotable line: {ev['message']!r}")


def test_the_promoted_set_is_byte_identical_with_and_without_the_screen(corpus):
    """EQUIVALENCE: not just 'nothing lost' but 'the same rows, in the same
    order, with the same bytes'."""
    without = [row for ev in corpus for row in _classify(ev)]
    with_screen = [row for ev in corpus
                   if P.syslog_promotable(ev) for row in _classify(ev)]
    assert with_screen == without


def test_the_screen_rejects_the_bulk_of_the_ratified_noise(corpus):
    """The point of the change. Not a correctness clause — a regression guard on
    the saving, so a marker that silently starts matching everything is visible."""
    rejected = sum(1 for ev in corpus if not P.syslog_promotable(ev))
    assert rejected / len(corpus) > 0.90, (
        f"only {rejected / len(corpus):.1%} of the ratified mix is rejected — "
        "the screen has stopped saving work")


def test_counters_account_for_every_screened_line(corpus):
    P.reset_prefilter_counts()
    try:
        for ev in corpus:
            P.syslog_promotable(ev)
        passed, rejected = P.prefilter_counts()
        assert passed + rejected == len(corpus)
        assert rejected > 0 and passed > 0
    finally:
        P.reset_prefilter_counts()


# ══ 3. MUTANTS — the tests above must be able to fail ════════════════════════

# One (marker, line) pair per gate whose marker is the ONLY reason the screen
# passes that line — verified by construction: the fixture asserts the real
# screen's hit set is exactly {marker}. Drop the marker and the line must be
# rejected, which is the failure mode this change could introduce.
ISOLATING = [
    ("updown", "LINK-3-UPDOWN",
     "%LINK-3-UPDOWN: Interface Ethernet1, changed state to down"),
    ("adjchange", "BGP-5-ADJCHANGE", "%BGP-5-ADJCHANGE: neighbor 10.0.0.1 Down"),
    ("adjchg", "OSPF-5-ADJCHG",
     "%OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 from FULL to DOWN"),
    ("lldp", "LLDP-5-NEIGHBOR",
     "%LLDP-5-NEIGHBOR: neighbor deleted on interface Ethernet1"),
    ("spantree", "SPANTREE-6-INTERFACE",
     "%SPANTREE-6-INTERFACE: Ethernet1 changed to discarding"),
    ("hsrp", "HSRP-5-STATECHANGE", "%HSRP-5-STATECHANGE: Vlan10 Grp 1 state Speak -> Active"),
    ("vrrp", "VRRP-6-STATECHANGE", "%VRRP-6-STATECHANGE: Vlan20 Grp 2 state Backup -> Master"),
    ("isisadjacencychange", "", "isisAdjacencyChange 1921.6800.1001 to state Down"),
    ("evpn", "EVPN-3-MACMOB", "mac 0011.2233.4455 vlan 10 vni 100"),
    ("nve", "NVE-5-BFD_CC", "BFD CC down for bfd-neighbor 10.1.1.1"),
    ("hmm", "HMM-2-DUPHOSTS", "host 0011.2233.4455 seen twice"),
    ("dup_host", "XYZ-2-DUP_HOST", "host 0011.2233.4455 seen twice"),
    ("standby", "STANDBY-6-STATECHANGE", "Vlan10 Grp 1 state Listen -> Active"),
]


@pytest.mark.parametrize("marker,tag,msg", ISOLATING,
                         ids=[m for m, _t, _m in ISOLATING])
def test_dropping_one_marker_loses_that_kind(monkeypatch, marker, tag, msg):
    """MUTANT. Remove one marker from the screen and the line that gate exists
    for must stop passing. Held at INFO severity so the generic device-alarm net
    cannot mask the hole."""
    ev = {"hostname": "leaf1", "appname": tag, "message": msg, "severity": "info"}
    full = P._SYSLOG_SCREEN_LITERALS
    assert _classify(ev), f"bad fixture: {msg!r} does not promote"
    hits = {lit for lit in full if lit in f"{msg} {tag}".lower()}
    assert hits == {marker}, (
        f"fixture for {marker!r} also matches {sorted(hits - {marker})} — the "
        "mutant would not isolate this gate")
    assert P.syslog_promotable(ev)
    monkeypatch.setattr(P, "_SYSLOG_SCREEN_LITERALS",
                        tuple(x for x in full if x != marker))
    assert not P.syslog_promotable(ev), (
        f"dropping {marker!r} changed nothing — this gate's coverage is untested")


@pytest.mark.parametrize("kill", ["updown", "adjchange", "lldp", "spantree"])
def test_dropping_a_marker_breaks_the_structural_coverage_test(monkeypatch, kill):
    """MUTANT on the DERIVATION test: with a marker gone, some rule's guard tree
    must stop being implied by the screen."""
    mutant = tuple(x for x in P._SYSLOG_SCREEN_LITERALS if x != kill)
    assert len(mutant) == len(P._SYSLOG_SCREEN_LITERALS) - 1, f"{kill!r} was not in the screen"
    monkeypatch.setattr(P, "_SYSLOG_SCREEN_LITERALS", mutant)
    guards = _promotion_guards()
    assert not all(_guard_covered(g) or _severity_guard(g) for _rid, g in guards), \
        f"dropping {kill!r} did not break guard coverage — the structural test is vacuous"


def test_an_unscreenable_rule_fails_the_whole_screen_open(monkeypatch, caplog):
    """A pattern the extractor cannot read must DISABLE the screen (everything
    passes), never produce a partial screen that rejects real lines."""
    bad = (re.compile(r"(?=lookahead)"), "unreadable", True, None)
    monkeypatch.setattr(P, "_PORT_EVENT_RULES", [*P._PORT_EVENT_RULES, bad])
    with caplog.at_level("WARNING"):
        assert P._build_syslog_screen() is None
    assert any("pre-filter DISABLED" in r.getMessage() for r in caplog.records)


def test_fail_open_passes_everything(monkeypatch):
    monkeypatch.setattr(P, "_SYSLOG_SCREEN_LITERALS", None)
    assert P.syslog_promotable({"message": "nothing at all", "severity": "debug"})


# ══ the extractor's own soundness ═══════════════════════════════════════════

@pytest.mark.parametrize("pattern,samples", [
    (r"local\s+fault|LOCAL_FAULT", ["a local  fault b", "x LOCAL_FAULT y"]),
    (r"(rx|receive)[^\n]{0,80}power[^\n]{0,80}(low|below)", ["rx optical power is low"]),
    (r"pre[-_ ]?fec\s+ber", ["pre-fec ber", "pre_fec  ber", "prefec ber"]),
    (r"no\s+(light|signal)", ["no light", "no  signal"]),
    (r"(tx\s+)?bias[^\n]{0,80}(high|current)", ["tx bias high", "bias current"]),
    (r"\b(?:is flapping between|mac[\s_-]?move)\b", ["is flapping between", "mac_move"]),
])
def test_extracted_literals_are_present_in_everything_the_pattern_matches(pattern, samples):
    screen = pattern_screen(pattern)
    assert screen, f"{pattern!r} was declared unscreenable"
    rx = re.compile(pattern, re.IGNORECASE)
    for s in samples:
        assert rx.search(s), f"bad fixture: {pattern!r} does not match {s!r}"
        assert any(lit in s.lower() for lit in screen), (
            f"screen {sorted(screen)} misses a string the pattern matches: {s!r}")


@pytest.mark.parametrize("pattern", [
    r"(?=foo)", r"a?b?", r"(?P<x>abc)?",
])
def test_unreadable_or_all_optional_patterns_are_unscreenable(pattern):
    assert pattern_screen(pattern) is None


def test_alternation_split_ignores_bars_inside_groups_and_classes():
    assert split_alternatives(r"a(b|c)d|e[|]f") == [r"a(b|c)d", r"e[|]f"]


def test_an_optional_trailing_character_is_not_treated_as_mandatory():
    """`colou?r` guarantees 'colo', not 'colou' — a screen on 'colou' would
    reject 'color'."""
    screen = alternative_screen("colou?r")
    assert screen is not None
    assert "colo" in screen or "r" in screen
    assert "colou" not in screen


# ══ the ingest lane still behaves exactly as before ═════════════════════════

def test_handle_syslog_still_counts_every_arrival_and_still_bursts(monkeypatch):
    """The pre-filter gates ONLY the two classifiers. `syslog_received`, the
    verified-tenant refusal, the clock-skew meta-finding and the severity-
    weighted burst detector must be untouched — those are what make a rejected
    line as accounted-for as a passed one."""
    import asyncio

    import main

    emitted: list[dict] = []

    async def _emit(**kw):
        emitted.append(kw)

    monkeypatch.setattr(main, "emit", _emit)
    monkeypatch.setattr(main, "CORR_SIGNALS_ENABLED", False)   # classifier lane off
    monkeypatch.setattr(main, "verified_tenant", lambda claim, host, lane, **kw: "t1")
    monkeypatch.setattr(main, "SYSLOG_BUCKET", {})
    monkeypatch.setattr(main, "SYSLOG_THRESHOLD", 4)
    received0 = main.SYSLOG_RECEIVED

    noise = {"hostname": "leaf9", "appname": "SYS-5-CONFIG_I", "severity": "notice",
             "message": "%SYS-5-CONFIG_I: Configured from console by admin on vty0"}
    for _ in range(3):
        asyncio.run(main.handle_syslog(dict(noise)))
    assert main.SYSLOG_RECEIVED == received0 + 3, "every arrival must still be counted"
    assert emitted, "the severity-weighted burst detector must still see rejected lines"
    assert emitted[-1]["kind"] == "correlation"


def test_the_prefilter_flag_off_restores_the_unfiltered_path(monkeypatch):
    """CORR_INGEST_PREFILTER=0 must call the classifiers for every line."""
    import asyncio

    import main

    seen: list[dict] = []

    def _spy(ev, tenant, ts):
        seen.append(ev)

    monkeypatch.setattr(main, "CORR_INGEST_PREFILTER", False)
    monkeypatch.setattr(main, "CORR_SIGNALS_ENABLED", True)
    monkeypatch.setattr(main, "ch", object())
    monkeypatch.setattr(main, "verified_tenant", lambda claim, host, lane, **kw: "t1")
    monkeypatch.setattr(main, "syslog_control_signal", _spy)
    monkeypatch.setattr(main, "port_event_signal", lambda ev, t, ts: None)
    monkeypatch.setattr(main, "clock_skew_signal", lambda ev, t, ts: None)
    noise = {"hostname": "leaf9", "appname": "SYS-5-CONFIG_I", "severity": "notice",
             "message": "%SYS-5-CONFIG_I: Configured from console by admin on vty0"}
    asyncio.run(main.handle_syslog(dict(noise)))
    assert seen, "flag off must not short-circuit the classifier"

    seen.clear()
    monkeypatch.setattr(main, "CORR_INGEST_PREFILTER", True)
    asyncio.run(main.handle_syslog(dict(noise)))
    assert not seen, "flag on must short-circuit a provably-unpromotable line"
