# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Every vendor-pack fixture, through the engine's real classifier (tracker 387).

Tests the VALUE, never the presence: a fixture states the parse it must get and the
signal it must or must not produce, and the rule "only a qualifying critical event
opens an object alone" (owner D3) is enforced for every pack by construction.
"""
from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime, timezone

import bake_rules as B
import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "src", "correlation")))

import producers as P

#: engine.severity_open_floor: a lone node at this rank or above opens an object.
OPENS_ALONE = {"high", "crit"}


def _fixtures() -> list[tuple[str, dict]]:
    return [(p["pack"], fx) for p in B.load_packs() for fx in p["fixtures"]]


def _event(fx: dict) -> dict:
    """The event as the engine receives it: Stage B has already run."""
    raw = {"hostname": fx.get("hostname", "spine1"), "appname": fx.get("appname", "unknown"),
           "severity": fx.get("severity", "notice"), "message": fx["message"],
           "timestamp": "2026-11-09T10:00:00Z"}
    return {**raw, **P._PACKS.parse(raw)}


@pytest.mark.parametrize(("pack", "fx"), _fixtures(),
                         ids=[f"{p}:{f['name']}" for p, f in _fixtures()])
def test_the_fixture_gets_its_parse_and_its_signal(pack, fx):
    ev = _event(fx)
    for key, want in fx["expect"].items():
        assert ev.get(key) == want, f"{key}: {ev.get(key)!r} != {want!r}"
    if not fx["expect"]:
        # An empty `expect` is a claim that no pack has an opinion on this line.
        assert "parser_id" not in ev and "event_category" not in ev
    sig = P.syslog_control_signal(dict(ev), "t1", datetime.now(timezone.utc))
    want = fx["signal"]
    if want is None:
        assert sig is None, f"expected no signal, got {sig and sig.kind}"
        return
    assert sig is not None, "expected a signal, got none"
    assert sig.kind == want["kind"]
    assert sig.severity.value == want["severity"]
    assert (sig.severity.value in OPENS_ALONE) == want.get("opens_alone", False)
    if "rule_id" in want:
        assert sig.attrs["rule_id"] == want["rule_id"]
        assert sig.attrs["fidelity"] == fx["fidelity"]


@pytest.mark.parametrize(("pack", "fx"), _fixtures(),
                         ids=[f"{p}:{f['name']}" for p, f in _fixtures()])
def test_a_signal_the_engine_produces_was_also_admitted(pack, fx):
    """The screen is a necessary condition: never reject what would promote."""
    ev = _event(fx)
    if P.syslog_control_signal(dict(ev), "t1", datetime.now(timezone.utc)) is not None:
        assert P.syslog_promotable(ev)


def test_the_alarm_floor_holds_on_the_real_pack():
    """Only the critical line may pass severity gates, whatever a row would do later."""
    def _ev(sev: str) -> dict:
        return {"hostname": "e", "appname": "SYSMGR", "severity": "notice",
                "message": f"%Viptela-e-SYSMGR-{sev}-XXXX-1: text"}
    assert P.syslog_alarm_num(_ev("2"), "SYSMGR") == 2
    assert P.syslog_alarm_num(_ev("3"), "SYSMGR") is None
    assert P.syslog_alarm_num(_ev("4"), "SYSMGR") is None
    assert P.syslog_severity_num(_ev("3"), "SYSMGR") == 3, "read, not hidden"


def test_only_a_critical_may_open_an_object_alone():
    """D3, over the table: a pack row emitting high or crit must be a critical row."""
    for pack in B.load_packs():
        for row in pack.get("rules") or []:
            sev = row.get("severity") or (row.get("emit") or {}).get("severity")
            if sev == "high":
                pytest.fail(f"{row['rule_id']}: `high` opens an object alone and is not critical")
            if sev == "crit":
                assert "[0-2]" in str(row.get("pattern_src")), (
                    f"{row['rule_id']}: emits crit but its pattern does not require a "
                    "critical severity in the line")


def test_every_grammar_has_a_fixture_it_decides():
    for pack in B.load_packs():
        grammars, _ = B.pack_tables([pack])
        if not grammars:
            continue
        table = P.PackTable(grammars, [])
        seen = set()
        for fx in pack["fixtures"]:
            msg, _ = P._PACKS.strip_envelope(fx["message"])
            app = fx.get("appname", "unknown").lower()
            for g in table.grammars:
                if g.applies(msg, app, "") and g.regex.search(msg):
                    seen.add(g.grammar_id)
                    break
        assert seen == {g.grammar_id for g in table.grammars}


@pytest.mark.parametrize("mutate,needle", [
    (lambda g: g.update(fidelity="doc_claimed", source=""), "must cite"),
    (lambda g: g.update(pattern="(?P<x"), "does not compile"),
    (lambda g: g.update(pattern="x$"), "cannot be compiled into VRL"),
    (lambda g: g.update(pattern="it's"), "cannot be compiled into VRL"),
    (lambda g: g.update(facility="{nope}"), "lacks"),
    (lambda g: g.update(alarm_floor=None), "alarm_floor"),
    (lambda g: g.update(bogus=1), "unknown key"),
])
def test_a_bad_grammar_does_not_bake(mutate, needle):
    g = {"id": "x", "parser_id": "x.v1", "literal": "x", "pattern": "(?P<s>[0-7]) x",
         "severity": {"digit": "s"}, "alarm_floor": 2, "fidelity": "lab_validated"}
    mutate(g)
    with pytest.raises(B.BakeError, match=needle):
        B.pack_tables([{"pack": "p", "vendor": "v", "grammars": [g]}])


def test_a_pack_row_needs_a_fidelity_claim():
    row = {"rule_id": "syslog.x", "lane": "syslog"}
    with pytest.raises(B.BakeError, match="fidelity_status"):
        B._merge_pack_rows([], [{"pack": "p", "rules": [row]}])


def test_pack_rows_sit_ahead_of_the_net_and_behind_every_older_rule():
    _, rows = B.load()
    syslog = [r["rule_id"] for r in rows if r["lane"] == "syslog"]
    assert syslog[-1] == "syslog.generic.device_alarm"
    pack_ids = [r["rule_id"] for p in B.load_packs() for r in p.get("rules") or []]
    if pack_ids:
        first = min(syslog.index(i) for i in pack_ids if i in syslog)
        assert syslog.index("syslog.config.change") < first


def test_a_benign_row_counts_and_stops_the_walk():
    """FTMD-3-ERRO-1000003, the plan's warning: a storm must open nothing, and must be
    visible. It is admitted by the screen so the count is real, and no signal comes out
    even though the line carries an error severity."""
    P.reset_parser_counters()
    raw = {"hostname": "vEdge-1", "appname": "FTMD", "severity": "notice",
           "timestamp": "2026-11-09T10:00:00Z",
           "message": "%Viptela-vEdge-1-FTMD-3-ERRO-1000003: User ifname = ge0/0; "
                      "kernel if_name= ge0_0; encap = 1"}
    for _ in range(1000):
        assert P.syslog_promotable(raw)
        assert P.syslog_control_signal(dict(raw), "t1", datetime.now(timezone.utc)) is None
    hits = P.parser_stats()["known_benign_hits"]
    assert hits["syslog.sdwan.ftmd.interface_dump"] == 1000
    assert P.syslog_severity_num(raw, "FTMD") == 3      # read correctly, not hidden


def test_a_benign_row_needs_its_reason():
    row = dict(next(r for r in B.load()[1] if r["known_benign"]))
    del row["benign_reason"]
    with pytest.raises(B.BakeError, match="benign_reason"):
        B.validate_row(row, {}, set())


def test_a_benign_row_cannot_be_shadow_too():
    """Shadow falls through to the net, benign stops the walk: one row cannot be both."""
    raw = dict(next(r for p in B.load_packs() for r in p.get("rules") or []
                    if r.get("known_benign")))
    raw["shadow"] = True
    with pytest.raises(B.BakeError, match="cannot be shadow"):
        B.validate_row(raw, {}, set())


def test_every_pack_line_is_recorded_in_the_golden_corpus():
    """So a later change that moves a signal's identity is red. Adding a vendor runs the
    recorder; it does not edit a test."""
    proc = subprocess.run([sys.executable, os.path.join(HERE, "record_pack_corpus.py"),
                           "--check"], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr


def _audit(message: str, host: str = "e1", app: str = "confd") -> dict:
    return P._PACKS.parse({"hostname": host, "appname": app, "severity": "notice",
                           "message": message})


def test_the_dedup_key_groups_repeats_and_nothing_else():
    """D2: stable over what changes on every poll (session number, source port), and
    distinct across device, app and event type. It groups at read time; nothing here
    can drop a record, because a parse only adds fields."""
    one = _audit("audit user: u/1 terminated session (reason: normal)")
    two = _audit("audit user: u/2 terminated session (reason: normal)")
    other_host = _audit("audit user: u/1 terminated session (reason: normal)", host="e2")
    other_type = _audit("audit user: u/1 assigned to groups: basic")
    assert one["dedup_key"] == two["dedup_key"] == "e1|confd|audit_session_terminated"
    assert other_host["dedup_key"] != one["dedup_key"]
    assert other_type["dedup_key"] != one["dedup_key"]


def test_audit_rows_cannot_alarm():
    """Non-alarm by construction: no severity reader, so no alarm floor to cross, and no
    typed row that emits (a known_benign row emits nothing: it is how a line a device sends
    at `err` stays off the generic net). Even a device that sends the line at `err` gets
    only what it always did."""
    table = P._PACKS
    audit = [g for g in table.grammars if g.category]
    assert audit
    assert all(not g.reads_severity and g.alarm_floor is None for g in audit)
    rows = [r for p in B.load_packs() for r in p.get("rules") or [] if not r.get("known_benign")]
    audit_literals = {g.literal for g in audit}
    assert not any(lit in str(r.get("pattern_src")) for r in rows for lit in audit_literals)


def test_usernames_stay_in_the_message():
    """D7 is another stream: this one must not redact, and must not add a field that
    copies a username out of the message."""
    line = "audit user: svc-user/1 created new session via snmp from 192.0.2.1:1 with udp"
    parsed = _audit(line)
    assert "message" not in parsed
    assert not any("svc-user" in str(v) for v in parsed.values())


def test_every_wanted_row_says_why():
    for pack in B.load_packs():
        for w in pack.get("wanted") or []:
            assert w["why_absent"].strip() and w["symptom"].strip()
