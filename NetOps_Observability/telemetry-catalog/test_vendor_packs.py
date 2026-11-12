# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Every vendor-pack fixture, through the engine's real classifier (tracker 387).

Tests the VALUE, never the presence: a fixture states the parse it must get and the
signal it must or must not produce, and the rule "only a qualifying critical event
opens an object alone" (owner D3) is enforced for every pack by construction.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from datetime import datetime, timezone

import pytest
import yaml

import bake_rules as B

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
           "severity": fx.get("severity", "notice"), "message": fx["message"]}
    for key in ("msgid", "timestamp"):
        if key in fx:
            raw[key] = fx[key]
    # The parse sees the fixture's own time or none (a time-less fixture claims a row
    # with no stated time); the engine's signal still needs one.
    return {"timestamp": "2026-11-09T10:00:00Z", **_stage_b(raw)}


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
    on the same record under the same access; the message itself is untouched. A NETCONF
    session is a person's (or a controller account's); an SNMP session names no user
    (next test)."""
    line = "audit user: svc-user/1 created new session via netconf from 192.0.2.1:1 with ssh"
    parsed = _audit(line)
    assert "message" not in parsed
    assert parsed["summary"] == "NETCONF session opened by svc-user from 192.0.2.1"
    # The audit card's typed fields (event model, 2026-11-10) name the user too; the Logs
    # read path enforces RBAC and audit on the whole record. No other field copies it.
    allowed = {"summary", "title", "audit_user", "correlation_key"}
    assert parsed["audit_user"] == "svc-user"
    assert not any("svc-user" in str(v) for k, v in parsed.items() if k not in allowed)


#: A fabricated community: the value must reach no field the parse adds.
_COMMUNITY = "fabricated-community-7f3a"


@pytest.mark.parametrize(("user", "tail", "src", "port"), [
    (_COMMUNITY, " from 127.0.0.1:54873 with udp", "127.0.0.1", "54873"),
    (_COMMUNITY, " from 192.0.2.1:59169 with udp", "192.0.2.1", "59169"),
    (_COMMUNITY, "", None, None),
    ("public", " from 127.0.0.1:1 with udp", "127.0.0.1", "1"),
    ("snmpv3-usm-user", " from 127.0.0.1:2 with udp", "127.0.0.1", "2"),
    ("1234", " from 127.0.0.1:3 with udp", "127.0.0.1", "3"),
], ids=["lab-shape", "other-source", "no-source", "public", "v3-user", "numeric"])
def test_an_snmp_session_names_no_user(user, tail, src, port):
    """Found live 2026-11-11: ConfD names a v1/v2c SNMP session by the community the
    request carried, so the user slot of a `via snmp` session is a credential (owner D1).
    The parse reads none of it: not audit_user, title, summary, dedup_key or
    correlation_key. A v3 USM user is not a secret, but the line cannot tell v2c from v3,
    so it is never read either."""
    line = f"audit user: {user}/49119 created new session via snmp{tail}"
    parsed = _audit(line, host="vEdge-20")
    assert parsed["event_type"] == "audit_session_created_snmp"
    assert parsed["event_category"] == "management_audit"
    assert parsed["audit_via"] == "snmp"
    assert parsed["audit_action"] == "session_created"
    assert parsed["session_id"] == "49119"
    assert parsed.get("audit_source") == (f"{src}:{port}" if src else None)
    assert parsed["correlation_key"] == "audit:vEdge-20:snmp:49119"
    assert parsed["dedup_key"] == "vEdge-20|confd|audit_session_created_snmp"
    assert parsed["title"] == ("SNMP session on vEdge-20" + (f" from {src}" if src else "")
                               + " (poll)")
    assert "audit_user" not in parsed and "message" not in parsed
    assert "audit_user" not in parsed["enrichment"]["fields_observed"]
    leaked = {k: v for k, v in parsed.items() if user in repr(v)}
    assert not leaked, f"the session's user slot reached {sorted(leaked)}"


@pytest.mark.parametrize(("line", "event_type", "summary"), [
    ("audit user: fixture-person/49119 assigned to groups: basic",
     "audit_session_groups", "Session of fixture-person given groups basic"),
    ("audit user: fixture-person/49119 terminated session (reason: normal)",
     "audit_session_terminated", "Session of fixture-person closed (normal)"),
    ("audit user: fixture-person/7 created new session via cli from 192.0.2.7:51234 with ssh",
     "audit_session_created_cli", "Session opened via cli by fixture-person from 192.0.2.7"),
])
def test_a_persons_session_lines_keep_the_user(line, event_type, summary):
    """The group and close lines of an SNMP session look exactly like a person's, and no
    stateless parse can tell them apart, so they keep capturing the user (D7). The read
    path masks the platform's configured communities by value (internal/credscrub)."""
    parsed = _audit(line, host="vEdge-20")
    assert parsed["event_type"] == event_type
    assert parsed["audit_user"] == "fixture-person"
    assert parsed["summary"] == summary
    assert "fixture-person" in parsed["title"]


@pytest.mark.parametrize(("community", "tail", "src"), [
    (_COMMUNITY, " 127.0.0.1.198.53", "127.0.0.1"),
    (_COMMUNITY, " 192.0.2.10.0.161", "192.0.2.10"),
    (_COMMUNITY, "", None),
    (_COMMUNITY, " 32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1.198.53", None),
    (_COMMUNITY, " 127.0.0.1.198.53x", None),
    ("fabricated cmty 7f3a", " 127.0.0.1.198.53", "127.0.0.1"),
    ("fabricated 10.9.8.7.6.5 7f3a", "", None),
    ("10.9.8.7.6.5", "", None),
], ids=["lab-shape", "other-port", "no-address", "ipv6-transport", "run-on-word",
        "spaces", "numbers-inside", "numeric-community"])
def test_a_refused_community_reaches_no_parsed_field(community, tail, src):
    """Owner D1: an SNMP community is a credential. ConfD prints the refused one twice, as
    the session's user and after `bad community name:`. The parse is security-relevant
    (its own category, the source when the line's last word is a six-octet transport
    address) and copies the community into no title, summary, typed field or key."""
    line = (f"audit user: {community}/0 SNMP authentication failed: PDU discarded: "
            f"bad community name: {community}{tail}")
    parsed = _audit(line, host="vEdge-1")
    assert parsed["event_type"] == "snmp_auth_failed_community"
    assert parsed["event_category"] == "security_audit"
    assert parsed["audit_action"] == "auth_failed"
    assert parsed.get("audit_source") == src
    assert "audit_user" not in parsed and "session_id" not in parsed
    assert "message" not in parsed  # the parse never rewrites the stored message
    tokens = {community, *community.split()}
    leaked = {k: v for k, v in parsed.items() for t in tokens if t in repr(v)}
    assert not leaked, f"the community reached {sorted(leaked)}"


def test_a_refused_community_never_opens_or_joins_at_the_level_it_is_sent():
    """No rule row: the line states nothing about the network, and the security evidence
    class is fed by the platform evaluator, not by syslog. At the info ConfD sends it at,
    no signal, so the community also never reaches a signal's attrs."""
    line = (f"audit user: {_COMMUNITY}/0 SNMP authentication failed: PDU discarded: "
            f"bad community name: {_COMMUNITY} 127.0.0.1.198.53")
    raw = {"hostname": "vEdge-1", "appname": "confd", "severity": "info", "message": line}
    ev = {"timestamp": "2026-11-10T10:00:00Z", **_stage_b(raw)}
    assert P.syslog_control_signal(dict(ev), "t1", datetime.now(timezone.utc)) is None


def test_the_vbond_success_path_groups_with_its_lookup():
    """The tracker's cache expiry and the resolver's answer carry the lookup lines' own
    correlation key, so one vBond lookup is one group, success and failure alike."""
    lines = [
        ("dnsclient_ares_callback[258]: DNS lookup failed for 0/vbond.example.net via none, "
         "reason: Timeout while contacting DNS servers"),
        "dnsclient_ares_callback[224]: DNS lookup succeeded for 0/vbond.example.net via none",
        ("monitor_req_send_cb[537]: DNS cache expired for 0/vbond.example.net/0 via none, "
         "resolving DNS again"),
        "dnsclient_cache_update[134]: FQDN vbond.example.net (via none) resolved to 192.0.2.3",
    ]
    parsed = [_audit(line, host="vEdge-1", app="VTRACKER") for line in lines]
    assert {p["correlation_key"] for p in parsed} == {"dns:vEdge-1:vbond.example.net"}
    assert [p["event_type"] for p in parsed] == [
        "dns_lookup_failed", "dns_lookup_succeeded", "dns_cache_expired", "dns_resolved"]
    assert parsed[3]["title"] == ("DNS lookup succeeded for vbond.example.net on vEdge-1: "
                                  "resolved to 192.0.2.3")
    refreshed = _audit("dnsclient_cache_update[144]: DNS cache entry for vbond.example.net "
                       "(via none) refreshed", host="vEdge-1", app="VTRACKER")
    assert refreshed["correlation_key"] == "dns:vEdge-1:vbond.example.net"
    assert refreshed["event_type"] == "dns_cache_refreshed"


# ── tracker 387, the final syslog wave (2026-11-11) ─────────────────────────────

def _signal(raw: dict):
    ev = {"timestamp": "2026-11-11T10:00:00Z", **_stage_b(raw)}
    return ev, P.syslog_control_signal(dict(ev), "t1", datetime.now(timezone.utc))


def test_a_default_gateway_pairs_up_and_down_on_one_key_and_only_down_alarms():
    """The tracker's monitor line and the resolver's verdict name one gateway, so its
    loss and its recovery are one timeline per device, VPN and gateway. Only the loss is a
    signal (below the floor, naming the gateway); a recovery has no honest clear."""
    def line(n: int, gw: str, vpn: str, word: str) -> str:
        if n == 0:
            return f"monitor_peer_change_state[291]: Monitor attached to {vpn}/{gw}/0 via ge0_0 is {word}"
        return f"resolv_monitor_state_callback[260]: Default gateway {gw} in VPN {vpn} is now {word}"
    words = [(0, "DOWN"), (1, "unreachable"), (0, "UP"), (1, "reachable")]
    out = [_signal({"hostname": "vEdge-1", "appname": "RESOLVD", "severity": "notice",
                    "message": line(n, "192.0.2.1", "0", w)}) for n, w in words]
    assert {ev["correlation_key"] for ev, _ in out} == {"gateway:vEdge-1:0:192.0.2.1"}
    sigs = [s for _, s in out]
    assert [s is not None for s in sigs] == [True, True, False, False]
    assert [s.attrs["rule_id"] for s in sigs[:2]] == [
        "syslog.sdwan.default_gateway.monitor_down", "syslog.sdwan.default_gateway.unreachable"]
    for s in sigs[:2]:
        assert (s.kind, s.severity.value, s.entity_id) == ("device_alarm", "warn", "vEdge-1")
        assert (s.attrs["failure"], s.attrs["gateway"], s.attrs["vpn"]) == (
            "default_gateway_unreachable", "192.0.2.1", "0")
    assert sigs[0].attrs["interface"] == "ge0_0"
    assert sigs[1].attrs["interface"] == "", "the resolver line names no interface"
    # Another gateway, or the same address in another VPN, is another timeline.
    other_gw = _signal({"hostname": "vEdge-1", "appname": "RESOLVD", "severity": "notice",
                        "message": line(1, "198.51.100.1", "0", "unreachable")})[0]
    other_vpn = _signal({"hostname": "vEdge-1", "appname": "RESOLVD", "severity": "notice",
                         "message": line(1, "192.0.2.1", "10", "unreachable")})[0]
    assert other_gw["correlation_key"] == "gateway:vEdge-1:0:198.51.100.1"
    assert other_vpn["correlation_key"] == "gateway:vEdge-1:10:192.0.2.1"


@pytest.mark.parametrize(("app", "sev", "message", "rule_id"), [
    ("fp-um", "err", "Port 3: Cannot remove default MAC address ", "syslog.sdwan.fp.default_mac"),
    ("kernel", "warning", "hrtimer: interrupt took 4421501 ns", "syslog.standard.kernel_hrtimer_slow"),
    ("OSPF", "warning", "Packet[DD]: Neighbor 192.0.2.7 state is 2-Way, packet discarded.",
     "syslog.standard.ospf_dd_two_way"),
])
def test_each_new_benign_row_counts_its_line_and_stops_the_net(app, sev, message, rule_id):
    """Without its row the line reaches the generic net (err/warning -> warn). With it the
    line is counted, admitted (so the count is real) and emits nothing."""
    P.reset_parser_counters()
    raw = {"hostname": "vEdge-1", "appname": app, "severity": sev, "message": message,
           "timestamp": "2026-11-11T10:00:00Z"}
    ev, sig = _signal(raw)
    assert P.syslog_promotable(ev)
    assert sig is None
    assert P.parser_stats()["known_benign_hits"][rule_id] == 1


def test_the_ios_xe_banner_groups_one_boot_and_a_later_boot_apart():
    """All four banner lines of one boot carry one key: the device and the minute."""
    lines = [
        ("Cisco IOS Software [Amsterdam], Virtual XE Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), "
         "Version 17.3.2, RELEASE SOFTWARE (fc3)"),
        "Technical Support: http://www.cisco.com/techsupport",
        "Copyright (c) 1986-2020 by Cisco Systems, Inc.",
        "Compiled Sat 31-Oct-20 13:16 by mcpre",
    ]

    def parse(line: str, ts: str) -> dict:
        return _FULL.parse({"hostname": "cEdge-1", "appname": "unknown", "severity": "notice",
                            "message": line, "timestamp": ts})
    boot = [parse(line, "2026-11-11T09:00:01Z") for line in lines]
    assert {p["correlation_key"] for p in boot} == {"boot:cEdge-1:2026-11-11T09:00"}
    assert {p["parser_id"] for p in boot} == {"cisco_iosxe.v1"}
    assert {p["event_category"] for p in boot} == {"system_lifecycle"}
    assert boot[0]["title"] == "cEdge-1 booted Cisco IOS XE 17.3.2"
    assert boot[0]["metrics"]["software_version"]["value"] == "17.3.2"
    later = parse(lines[0], "2026-11-11T11:42:07Z")
    assert later["correlation_key"] == "boot:cEdge-1:2026-11-11T11:42"
    # A banner line no IOS sender writes under a process tag is not read from one.
    assert "parser_id" not in _FULL.parse({"hostname": "h", "appname": "otherd",
                                           "severity": "notice", "message": lines[2]})


def test_an_ntp_clock_step_is_a_metric_and_never_a_signal():
    """The step moves every timestamp the box writes, so it is kept as a typed number. It
    is not evidence: the platform measures clock skew itself (clock_skew_signal), and a
    step is the device correcting its clock."""
    ev, sig = _signal({"hostname": "vEdge-1", "appname": "ntpd", "severity": "info",
                       "message": "0.0.0.0 c61c 0c clock_step +28.800702 s"})
    assert ev["metrics"]["clock_step_s"] == {"value": 28.800702, "basis": "observed"}
    assert ev["event_category"] == "time_sync"
    assert sig is None
    # The same line at a worse PRI is still not typed: only the generic net could answer.
    _, sig_warn = _signal({"hostname": "vEdge-1", "appname": "ntpd", "severity": "warning",
                           "message": "0.0.0.0 c61c 0c clock_step +28.800702 s"})
    assert sig_warn is not None and sig_warn.attrs["rule_id"] == "syslog.generic.device_alarm"


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


WAVE1_PACKS = ("nokia_sros", "nokia_srlinux", "cisco_ios", "juniper_junos", "sonic")


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
                    "sysmgr_200069", "gateway_monitor_down", "default_gateway_unreachable"},
    "nokia_sros": {"bgp_2020", "bgp_2039", "ospf_2042", "snmp_2004", "chassis_2144",
                   "chassis_2148", "system_2010"},
    "juniper_junos": {"rpd_bgp_neighbor_state_changed", "rpd_ospf_nbrdown",
                      "rpd_isis_adjdown", "snmp_trap_link_down"},
    "cisco_ios": {"updown", "adjchange"},
    "nokia_srlinux": {"port_down", "subinterface_down"},
    "sonic": {"host_intf_oper_status_down", "port_admin_status_down"},
}


def _parse_fixture(table, fx: dict) -> dict:
    ev = {"hostname": fx.get("hostname", "spine1"), "appname": fx.get("appname", "unknown"),
          "severity": fx.get("severity", "notice"), "message": fx["message"]}
    for key in ("msgid", "timestamp"):
        if key in fx:
            ev[key] = fx[key]
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
    assert got["title"] == "SNMP session on vEdge-1 (poll)"
    assert "audit_source" not in got and "session_id" not in got
    assert got["enrichment"]["unknown"] == ["audit_source", "session_id"]


@pytest.mark.parametrize("mutate,needle", [
    (lambda g: g.update(fields={"bogus": "x"}), "is not one of"),
    (lambda g: g.update(fields={"title": "{nope}"}), "lacks"),
    (lambda g: g.update(fields={"title": "a [b"}), "open"),
    (lambda g: g.update(fields={"title": "costs $5"}), "dollar"),
    (lambda g: g.update(metrics={"Bad-Name": "s"}), "snake_case"),
    (lambda g: g.update(metrics={"ok": "nope"}), "lacks"),
    (lambda g: g.update(metrics={"ok": {"text": "nope"}}), "lacks"),
    (lambda g: g.update(metrics={"ok": {"txt": "s"}}), "takes a group"),
    (lambda g: g.update(summary="{s|nope}"), "does not state"),
    (lambda g: g.update(fields={"title": "{host|names}"}), "record name"),
])
def test_a_bad_event_model_does_not_bake(mutate, needle):
    g = {"id": "x", "parser_id": "x.v1", "literal": "x", "pattern": "(?P<s>[0-7]) x",
         "event_type": "e", "severity": {"digit": "s"}, "alarm_floor": 2,
         "fidelity": "lab_validated"}
    mutate(g)
    with pytest.raises(B.BakeError, match=needle):
        B.pack_tables([{"pack": "p", "vendor": "v", "grammars": [g],
                        "labels": {"names": {"a": "b"}}}])


@pytest.mark.parametrize("labels,needle", [
    ({}, "non-empty"),
    ({"Bad": {"a": "b"}}, "snake_case"),
    ({"t": {}}, "needs entries"),
    ({"t": {"a": 'say "hi"'}}, "plain printable"),
    ({"t": {"a": "back\\slash"}}, "plain printable"),
    ({"t": {"a": "costs $5"}}, "plain printable"),
])
def test_a_bad_label_table_does_not_load(tmp_path, labels, needle):
    pack = {"pack": "p", "vendor": "v", "labels": labels,
            "fixtures": [{"name": "n", "message": "m", "expect": {}, "signal": None,
                          "fidelity": "lab_validated"}]}
    (tmp_path / "p.yaml").write_text(yaml.safe_dump(pack), encoding="utf-8")
    with pytest.raises(B.BakeError, match=needle):
        B.load_packs(str(tmp_path))


def test_an_unquoted_fixture_time_does_not_load(tmp_path):
    (tmp_path / "p.yaml").write_text(
        "pack: p\nvendor: v\nfixtures:\n  - {name: n, message: m, expect: {}, signal: null,"
        " fidelity: lab_validated, timestamp: 2026-11-10T09:34:41Z}\n", encoding="utf-8")
    with pytest.raises(B.BakeError, match="quoted"):
        B.load_packs(str(tmp_path))


# ── the process snapshot (tracker 387, owner feedback 2026-11-10) ──────────────

_SNAPSHOT_ROWS = re.compile(r"^process snapshot row \d+: ")


def _snapshot(table: P.PackTable) -> tuple[dict, list[tuple[dict, dict]], dict]:
    """(header doc, [(fixture, row doc)], cpu-usage doc) of the golden snapshot."""
    sdwan = next(p for p in B.load_packs() if p["pack"] == "cisco_sdwan")
    fx = {f["name"]: f for f in sdwan["fixtures"]}
    header = _parse_fixture(table, fx["a process-table header is the snapshot's representative row"])
    cpu = _parse_fixture(table, fx["a notification takes its identity from the event name"])
    rows = [(f, _parse_fixture(table, f)) for n, f in fx.items() if _SNAPSHOT_ROWS.match(n)]
    return header, rows, cpu


def test_the_golden_snapshot_is_one_dump_with_named_typed_rows():
    labels = next(p for p in B.load_packs() if p["pack"] == "cisco_sdwan")["labels"]["process"]
    header, rows, cpu = _snapshot(_FULL)
    assert len(rows) == 10
    dump = "dump:vEdge-1:2026-11-10T09:34"
    assert header["dump_id"] == cpu["dump_id"] == dump
    assert header["title"] == "Process snapshot on vEdge-1"
    for fx, doc in rows:
        # The columns, read here independently of the grammar.
        _user, _pid, cpu_p, mem_p, vsz, rss, _tty, stat, start, cputime, *cmd = fx["message"].split()
        head = cmd[0] if cmd[0].startswith("[") else cmd[0].rsplit("/", 1)[-1]
        proc = re.match(r"\[?([A-Za-z0-9_.@-]+)", head).group(1)
        name = labels.get(proc, proc)
        assert doc["dump_id"] == dump, fx["name"]
        assert doc["event_category"] == "diagnostic_dump"
        assert doc["summary"] == f"{name} ({proc}) using {cpu_p}% CPU, {mem_p}% memory"
        assert doc["metrics"] == {
            "process": {"value": proc, "basis": "observed"},
            "cpu_percent": {"value": float(cpu_p), "basis": "observed"},
            "mem_percent": {"value": float(mem_p), "basis": "observed"},
            "rss_kb": {"value": float(rss), "basis": "observed"},
            "vsz_kb": {"value": float(vsz), "basis": "observed"},
            "state": {"value": stat, "basis": "observed"},
            "start": {"value": start, "basis": "observed"},
            "cputime": {"value": cputime, "basis": "observed"},
        }, fx["name"]
    owner = next(doc for fx, doc in rows if fx["message"].startswith("root 3180 0.7 5.3"))
    assert owner["summary"] == "data-plane forwarding (FTM) (ftmd) using 0.7% CPU, 5.3% memory"
    assert owner["metrics"]["rss_kb"]["value"] == 47560.0
    unnamed = next(doc for fx, doc in rows if "zebra" in fx["message"])
    assert unnamed["summary"].startswith("zebra (zebra) using ")


def test_a_row_with_no_stated_time_names_no_snapshot():
    """dump_id needs the record's time: without one it is unknown, never a key that
    would group every time-less row of a device into one snapshot."""
    got = _FULL.parse({"hostname": "vEdge-1", "appname": "SYSMGR", "severity": "info",
                       "message": "root 3180 0.7 5.3 513260 47560 ? Sl 09:34 0:08 /usr/sbin/ftmd -f"})
    assert "dump_id" not in got
    assert got["enrichment"]["unknown"] == ["dump_id"]
    zoneless = _FULL.parse({"hostname": "vEdge-1", "appname": "SYSMGR", "severity": "info",
                            "timestamp": "2026-11-10T09:34:41",
                            "message": "root 3180 0.7 5.3 513260 47560 ? Sl 09:34 0:08 /usr/sbin/ftmd -f"})
    assert "dump_id" not in zoneless


def test_the_snapshot_checks_catch_a_broken_label_table_or_window():
    """Mutation check: a dropped label and a shifted time each change what the golden
    test asserts, so neither could slip through it."""
    packs = B.load_packs()
    sdwan = next(p for p in packs if p["pack"] == "cisco_sdwan")
    del sdwan["labels"]["process"]["ftmd"]
    mutated = P.PackTable(*B.pack_tables(packs))
    _header, rows, _cpu = _snapshot(mutated)
    owner = next(doc for fx, doc in rows if fx["message"].startswith("root 3180 0.7 5.3"))
    assert owner["summary"] == "ftmd (ftmd) using 0.7% CPU, 5.3% memory"
    fx = dict(next(f for f, _ in rows if f["message"].startswith("root 3180")))
    fx["timestamp"] = "2026-11-10T09:35:00Z"
    assert _parse_fixture(_FULL, fx)["dump_id"] == "dump:vEdge-1:2026-11-10T09:35"
    fx["timestamp"] = "2026-11-10T10:34:41+01:00"   # the same instant, another zone
    assert _parse_fixture(_FULL, fx)["dump_id"] == "dump:vEdge-1:2026-11-10T09:34"


def test_guidance_needs_its_three_parts():
    with pytest.raises(B.BakeError, match="needs event_types"):
        B.guidance_table({"pack": "p", "guidance": [{"event_types": ["x"], "impact": ["i"]}]})
