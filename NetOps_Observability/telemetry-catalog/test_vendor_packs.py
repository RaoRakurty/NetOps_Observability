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

#: The pack table WITH the event model (title, metrics, guidance), as Stage B runs it. The
#: engine's own table (`P._PACKS`, baked into parser_rules.py) carries no presentation.
_FULL = P.PackTable(*B.pack_tables(B.load_packs()))

#: engine.severity_open_floor: a lone node at this rank or above opens an object.
OPENS_ALONE = {"high", "crit"}


def _fixtures() -> list[tuple[str, dict]]:
    return [(p["pack"], fx) for p in B.load_packs() for fx in p["fixtures"]]


def _event(fx: dict) -> dict:
    """The event as the engine receives it: Stage B has already run."""
    raw = {"hostname": fx.get("hostname", "spine1"), "appname": fx.get("appname", "unknown"),
           "severity": fx.get("severity", "notice"), "message": fx["message"],
           "timestamp": "2026-11-09T10:00:00Z"}
    if "msgid" in fx:
        raw["msgid"] = fx["msgid"]
    return _stage_b(raw)


def _stage_b(raw: dict) -> dict:
    """The pack parse plus Stage B's envelope fallback: an RFC 5424 MSGID becomes the
    event_type when no grammar stated one (vector.yaml, after the body parsers)."""
    ev = {**raw, **_FULL.parse(raw)}
    mid = str(raw.get("msgid") or "")
    if mid and mid != "-" and "event_type" not in ev:
        ev["event_type"] = mid.lower()
    return ev


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
    # The meaning a row reads from the line, by value: a session that came up must not
    # arrive as down because only its kind and severity were asserted.
    for key in ("state", "link_cause", "peer", "failure"):
        if key in want:
            assert sig.attrs.get(key) == want[key], f"{key}: {sig.attrs.get(key)!r} != {want[key]!r}"
    if "entity" in want:
        assert sig.entity_id == want["entity"]


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


def _severity_values(spec) -> list[str]:
    """Every severity a row's severity spec can emit."""
    if spec is None:
        return []
    if isinstance(spec, str):
        return [spec]
    out = [str(v) for v in (spec.get("by_state") or {}).values()]
    out += [str(c["value"]) for c in spec.get("case") or ()]
    if "default" in spec:
        out.append(str(spec["default"]))
    return out


def _re_nodes(node) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "re" and isinstance(v, list) and len(v) >= 2 and isinstance(v[0], str):
                out.append((v[0], str(v[1])))
            else:
                out.extend(_re_nodes(v))
    elif isinstance(node, list):
        for v in node:
            out.extend(_re_nodes(v))
    return out


def test_only_a_critical_may_open_an_object_alone():
    """D3, over the table: a pack row never states `high`, and states `crit` only where
    the line itself must state a critical severity, as a plain row whose pattern needs
    one or as a case branch that reads the message for it."""
    for pack in B.load_packs():
        for row in pack.get("rules") or []:
            spec = row.get("severity") or (row.get("emit") or {}).get("severity")
            values = _severity_values(spec)
            if "high" in values:
                pytest.fail(f"{row['rule_id']}: `high` opens an object alone and is not critical")
            if "crit" not in values:
                continue
            if isinstance(spec, str):
                assert "[0-2]" in str(row.get("pattern_src")), (
                    f"{row['rule_id']}: emits crit but its pattern does not require a "
                    "critical severity in the line")
                continue
            for branch in spec.get("case") or ():
                if branch["value"] == "crit":
                    assert any(field == "msg" for field, _ in _re_nodes(branch["when"])), (
                        f"{row['rule_id']}: a crit branch must read the line's own severity")
            assert spec.get("default") != "crit", row["rule_id"]


@pytest.mark.parametrize(("pack", "fx"), _fixtures(),
                         ids=[f"{p}:{f['name']}" for p, f in _fixtures()])
def test_a_pack_row_opens_alone_only_on_a_line_that_states_critical(pack, fx):
    """The same rule, by value: every fixture a PACK row answers at an opening severity
    states emerg, alert or crit itself, in its PRI or in its text."""
    pack_rows = {r["rule_id"] for p in B.load_packs() for r in p.get("rules") or []}
    ev = _event(fx)
    sig = P.syslog_control_signal(dict(ev), "t1", datetime.now(timezone.utc))
    if sig is None or sig.attrs.get("rule_id") not in pack_rows:
        return
    if sig.severity.value in OPENS_ALONE:
        tag = str(ev.get("appname") or "").upper()
        assert (P.syslog_severity_num(ev, tag) or 7) <= 2, fx["name"]


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
                text = g.haystack(msg, fx)
                if g.applies(text, app, "") and g.regex.search(text):
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
    return _FULL.parse({"hostname": host, "appname": app, "severity": "notice",
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
    # A one-character literal (`:`, the SYSMGR process-table row) is a cheap gate, not the
    # line's identity: its `apps` gate is. Those rows are held to the fixture instead,
    # where each one is asserted to emit nothing.
    audit_literals = {g.literal for g in audit if len(g.literal) >= 3}
    assert not any(lit in str(r.get("pattern_src")) for r in rows for lit in audit_literals)
    short = [g for g in audit if len(g.literal) < 3]
    assert all(g.apps for g in short), "a short-literal category row needs an apps gate"


def test_usernames_stay_in_the_message():
    """D7: usernames are retained, never redacted here. The human summary and title (owner,
    live review 2026-11-10) and the typed `audit_user` name the user as the message does,
    on the same record under the same access; the message itself is untouched."""
    line = "audit user: svc-user/1 created new session via snmp from 192.0.2.1:1 with udp"
    parsed = _audit(line)
    assert "message" not in parsed
    assert parsed["summary"] == "SNMP session by svc-user from 192.0.2.1 (poll)"
    # The audit card's typed fields (event model, 2026-11-10) name the user too; the Logs
    # read path enforces RBAC and audit on the whole record. No other field copies it.
    allowed = {"summary", "title", "audit_user", "correlation_key"}
    assert parsed["audit_user"] == "svc-user"
    assert not any("svc-user" in str(v) for k, v in parsed.items() if k not in allowed)


def test_every_typed_grammar_renders_a_human_summary():
    """Owner, live review 2026-11-10: a parsed line with no summary shows raw text. Every
    pack grammar that types an event states a summary, and every fixture it parses
    renders a non-empty one."""
    packs = B.load_packs()
    grammars, envelopes = B.pack_tables(packs)
    missing = [g["id"] for g in grammars if g["event_type"] and not g["summary"]]
    assert not missing, f"grammars with an event type and no summary: {missing}"
    table = P.PackTable(grammars, envelopes)
    for pack in packs:
        for fx in pack["fixtures"]:
            ev = {"hostname": fx.get("hostname", "spine1"), "appname": fx.get("appname", "unknown"),
                  "severity": fx.get("severity", "notice"), "message": fx["message"]}
            if "msgid" in fx:
                ev["msgid"] = fx["msgid"]
            got = table.parse(ev)
            if got.get("event_type"):
                assert str(got.get("summary") or "").strip(), fx["name"]


@pytest.mark.parametrize(("template", "groups", "want"), [
    ("SSH login[ for {user}][ from {src}]", {"user": "u", "src": "h"}, "SSH login for u from h"),
    ("SSH login[ for {user}][ from {src}]", {"user": "u", "src": None}, "SSH login for u"),
    ("SSH login[ for {user}][ from {src}]", {"user": None, "src": None}, "SSH login"),
    ("x[ {a} and {b}]", {"a": "1", "b": None}, "x"),
])
def test_a_missing_field_drops_its_clause_never_invents_text(template, groups, want):
    import re as _re
    names = list(groups)
    pat = "".join(f"(?P<{n}>{v})?" if v else f"(?P<{n}>z)?" for n, v in groups.items())
    m = _re.match(pat, "".join(v or "" for v in groups.values()))
    assert m is not None and names
    import syslog_packs
    assert syslog_packs._render(template, m) == want


def test_every_wanted_row_says_why():
    for pack in B.load_packs():
        for w in pack.get("wanted") or []:
            assert w["why_absent"].strip() and w["symptom"].strip()


def _gen_syslog_packs():
    import importlib.util
    path = os.path.join(HERE, "..", "scripts", "gen-syslog-packs.py")
    spec = importlib.util.spec_from_file_location("gen_syslog_packs_t", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("gid", [g["id"] for g in B.pack_tables(B.load_packs())[0]])
def test_every_grammar_is_load_bearing(gid):
    """Mutation check, permanent: a grammar that stops matching makes generation refuse,
    because some fixture of its pack states the parse it gave. A grammar no fixture
    depends on would pass this mutation, and is dead weight or an untested claim."""
    gen = _gen_syslog_packs()
    packs = B.load_packs()
    grammars, envelopes = B.pack_tables(packs)
    broken = [dict(g, pattern="(?!x)x") if g["id"] == gid else g for g in grammars]
    with pytest.raises(gen.GenerationError):
        gen.decide_fixtures(packs, P.PackTable(broken, envelopes))


WAVE1_PACKS = ("nokia_sros", "cisco_ios", "juniper_junos")


def test_every_wave1_fixture_cites_where_its_line_comes_from():
    """No captures exist for these vendors, so a fixture is only as good as its source."""
    for pack in B.load_packs():
        if pack["pack"] not in WAVE1_PACKS:
            continue
        for fx in pack["fixtures"]:
            assert str(fx.get("source") or "").strip(), f"{pack['pack']}: {fx['name']}"
            assert fx["fidelity"] == "doc_claimed", f"{pack['pack']}: {fx['name']}"
        for row in pack.get("rules") or []:
            assert row["fidelity_status"] == "doc_claimed", row["rule_id"]
        for g in pack.get("grammars") or []:
            assert g["fidelity"] == "doc_claimed" and g.get("source"), g["id"]


@pytest.mark.parametrize("pack_name", WAVE1_PACKS)
def test_every_wave1_rule_has_a_fixture_that_reaches_it(pack_name):
    """A typed row no fixture reaches is a claim nothing tests."""
    pack = next(p for p in B.load_packs() if p["pack"] == pack_name)
    reached = {fx["signal"]["rule_id"] for fx in pack["fixtures"]
               if fx.get("signal") and "rule_id" in fx["signal"]}
    benign = {r["rule_id"] for r in pack.get("rules") or [] if r.get("known_benign")}
    P.reset_parser_counters()
    for fx in pack["fixtures"]:
        P.syslog_control_signal(dict(_event(fx)), "t1", datetime.now(timezone.utc))
    hits = {k for k, v in P.parser_stats()["known_benign_hits"].items() if v}
    rows = {r["rule_id"] for r in pack.get("rules") or []}
    assert rows - reached - (benign & hits) == set()



# ── the rich event model (tracker 387, the trap lane's names) ───────────────────

#: The fault families whose records must carry pack guidance (owner, 2026-11-10).
FAULT_EVENT_TYPES = {
    "cisco_sdwan": {"dns_lookup_failed", "dns_resolution_failed", "control-connection-state-change",
                    "bfd-state-change", "omp-peer-state-change", "omp-state-change",
                    "interface-state-change", "bgp-peer-state-change", "cpu-usage",
                    "sysmgr_200069"},
    "nokia_sros": {"bgp_2020", "bgp_2039", "ospf_2042", "snmp_2004", "chassis_2144",
                   "chassis_2148", "system_2010"},
    "juniper_junos": {"rpd_bgp_neighbor_state_changed", "rpd_ospf_nbrdown",
                      "rpd_isis_adjdown", "snmp_trap_link_down"},
    "cisco_ios": {"updown", "adjchange"},
}


def _parse_fixture(table, fx: dict) -> dict:
    ev = {"hostname": fx.get("hostname", "spine1"), "appname": fx.get("appname", "unknown"),
          "severity": fx.get("severity", "notice"), "message": fx["message"]}
    if "msgid" in fx:
        ev["msgid"] = fx["msgid"]
    return table.parse(ev)


def test_every_typed_grammar_renders_a_title():
    packs = B.load_packs()
    grammars, envelopes = B.pack_tables(packs)
    missing = [g["id"] for g in grammars if g["event_type"] and not (g.get("fields") or {}).get("title")]
    assert not missing, f"grammars with an event type and no title: {missing}"
    table = P.PackTable(grammars, envelopes)
    for pack in packs:
        for fx in pack["fixtures"]:
            got = _parse_fixture(table, fx)
            if got.get("event_type"):
                assert str(got.get("title") or "").strip(), fx["name"]
                assert got["enrichment"]["fields_derived"][0] == "normalized_severity"


def test_the_fault_families_carry_guidance():
    by_pack = {p["pack"]: p for p in B.load_packs()}
    for pack_name, ets in FAULT_EVENT_TYPES.items():
        table = B.guidance_table(by_pack[pack_name])
        missing = sorted(ets - set(table))
        assert not missing, f"{pack_name}: fault families with no guidance: {missing}"
        for et, guide in table.items():
            assert guide["impact"] and guide["next_checks"], (pack_name, et)


def test_guidance_reaches_the_record_only_for_its_event_type():
    """By value, on fixtures: a DNS failure carries it, the matching success does not."""
    packs = B.load_packs()
    table = P.PackTable(*B.pack_tables(packs))
    sdwan = next(p for p in packs if p["pack"] == "cisco_sdwan")
    fx = {f["name"]: f for f in sdwan["fixtures"]}
    failed = _parse_fixture(table, fx["a vBond lookup failure is a below-floor alarm, not a DNS symptom"])
    ok = _parse_fixture(table, fx["a vBond lookup success emits nothing"])
    assert failed["guidance"]["basis"] == "pack_guidance"
    assert failed["enrichment"]["fields_guidance"] == ["guidance"]
    assert "guidance" not in ok and ok["enrichment"]["fields_guidance"] == []


def test_a_missing_optional_group_is_unknown_never_invented():
    """`unknown` lists a declared field the line did not carry."""
    table = P.PackTable(*B.pack_tables(B.load_packs()))
    got = table.parse({"hostname": "vEdge-1", "appname": "confd", "severity": "notice",
                       "message": "audit user: svc-user created new session via snmp"})
    assert got["title"] == "SNMP session on vEdge-1 by svc-user (poll)"
    assert "audit_source" not in got and "session_id" not in got
    assert got["enrichment"]["unknown"] == ["audit_source", "session_id"]


@pytest.mark.parametrize("mutate,needle", [
    (lambda g: g.update(fields={"bogus": "x"}), "is not one of"),
    (lambda g: g.update(fields={"title": "{nope}"}), "lacks"),
    (lambda g: g.update(fields={"title": "a [b"}), "open"),
    (lambda g: g.update(fields={"title": "costs $5"}), "dollar"),
    (lambda g: g.update(metrics={"Bad-Name": "s"}), "snake_case"),
    (lambda g: g.update(metrics={"ok": "nope"}), "lacks"),
])
def test_a_bad_event_model_does_not_bake(mutate, needle):
    g = {"id": "x", "parser_id": "x.v1", "literal": "x", "pattern": "(?P<s>[0-7]) x",
         "event_type": "e", "severity": {"digit": "s"}, "alarm_floor": 2,
         "fidelity": "lab_validated"}
    mutate(g)
    with pytest.raises(B.BakeError, match=needle):
        B.pack_tables([{"pack": "p", "vendor": "v", "grammars": [g]}])


def test_guidance_needs_its_three_parts():
    with pytest.raises(B.BakeError, match="needs event_types"):
        B.guidance_table({"pack": "p", "guidance": [{"event_types": ["x"], "impact": ["i"]}]})
