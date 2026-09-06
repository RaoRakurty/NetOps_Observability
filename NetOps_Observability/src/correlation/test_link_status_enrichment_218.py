"""Tracker 218 — a linkDown must say WHETHER SOMEONE SHUT THE PORT.

THE DEFECT. `trap.link.state_change` typed every linkDown/linkUp into one
undifferentiated `state: down` / `state: up`. An operator shutting a port for
maintenance and a fibre cut produced byte-identical evidence, so correlation
could not tell a planned change from an outage, and `lowerLayerDown` — "my link
is down because the thing UNDER it is down", i.e. this device is a VICTIM, not
the cause — was indistinguishable from a local failure.

The notification has always carried the answer. RFC 2863, vendored verbatim in
this repo at `src/backend/collectors/mibs/vendored/IF-MIB`:

    linkDown NOTIFICATION-TYPE
        OBJECTS { ifIndex, ifAdminStatus, ifOperStatus }
        ...  "This other state is indicated by the included value of
              ifOperStatus."

Every trap payload in this file is built from that OBJECTS clause and from the
INTEGER enums of the same vendored MIB (`ifAdminStatus ::= { ifEntry 7 }` with
up(1)/down(2)/testing(3); `ifOperStatus ::= { ifEntry 8 }` with
up(1)/down(2)/testing(3)/unknown(4)/dormant(5)/notPresent(6)/lowerLayerDown(7)).
Nothing here is a remembered vendor string: `test_the_ladders_are_the_vendored_
mib_enum_and_nothing_else` re-derives both ladders from
`src/backend/collectors/mibs/index/oididx.json` — the index `make mib-index`
generates from those MIB sources — and fails if the rule and the MIB disagree in
EITHER direction.

WHY THIS WAS DEFERRED, AND WHY THE DEFERRAL WAS WRONG. The A9 trap-coverage
audit (`6e8d66cc`) refused the enrichment on one stated ground: it "changes the
ATTRS and the state of an already-shipping rule, which re-identifies every link
trap already stored". Identity is `uuid5(source|native_id|ts_ms)` — see
`signals.Signal.signal_id` — so attrs reach it only through `native_id`, and
`native_id` here is `{device}|trap_link|{iface}|{state}|{ts_ms}`. The enrichment
therefore re-identifies nothing PROVIDED it never touches `state`, and this one
does not: `state` is still decided by the trap OID alone. The second ground —
"breaks the frozen parity baseline" — held only for an UNCONDITIONAL attr; the
two keys are declared `omit_empty`, so a trap that carries no status varbind
(which is every event in the 1,151-entry golden corpus) emits the attrs dict it
always did.

Both halves are proven below, not asserted:
  1. DISCRIMINATION — admin-down, oper-down-while-admin-up, and lowerLayerDown
     are three different pieces of evidence.
  2. NON-RE-IDENTIFICATION — the same trap with and without the status varbinds
     produces the SAME signal_id, native_id, entity, state and severity.
  3. HONEST ABSENCE — a trap that did not carry the varbind has no such key, so
     "not reported" can never be read as "reported empty".
  4. NO FABRICATION — the enum ladders are the vendored MIB's, both ways.
  5. THE GRAMMAR — `omit_empty` cannot name a key the rule does not emit.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import pytest

import producers as P
from rule_model import RuleError, compile_rule

HERE = os.path.dirname(os.path.abspath(__file__))
MIB_INDEX = os.path.abspath(os.path.join(
    HERE, "..", "backend", "collectors", "mibs", "index", "oididx.json"))

T0 = datetime(2026, 9, 6, 10, 0, 0, tzinfo=timezone.utc)

LINK_DOWN = "1.3.6.1.6.3.1.1.5.3"
LINK_UP = "1.3.6.1.6.3.1.1.5.4"
OID_IF_INDEX = "1.3.6.1.2.1.2.2.1.1"
OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
OID_ADMIN = "1.3.6.1.2.1.2.2.1.7"
OID_OPER = "1.3.6.1.2.1.2.2.1.8"

#: ifIndex of the interface every fixture below is about. The varbind OIDs are
#: the column OID plus this instance suffix, exactly as an agent sends them.
IFX = 7


def vb(col: str, name: str, value) -> dict:
    return {"oid": f"{col}.{IFX}", "name": name, "value": value}


def link_trap(*, oid: str = LINK_DOWN, admin=None, oper=None,
              iface: str = "Ethernet7", name: str = "linkDown") -> dict:
    """A linkDown/linkUp payload in the OBJECTS order RFC 2863 declares.

    `admin`/`oper` are passed through UNRENDERED so a test can hand the decoder
    the bare int, the label, or the `label(int)` form an agent may emit.
    """
    varbinds = [vb(OID_IF_INDEX, "ifIndex", IFX)]
    if admin is not None:
        varbinds.append(vb(OID_ADMIN, "ifAdminStatus", admin))
    if oper is not None:
        varbinds.append(vb(OID_OPER, "ifOperStatus", oper))
    varbinds.append(vb(OID_IF_NAME, "ifName", iface))
    return {"device": "leaf9", "trap_oid": oid, "trap_name": name,
            "event_type": "", "authenticated": True,
            "timestamp": "2026-09-06T10:00:00.000Z", "varbinds": varbinds}


def classify(ev: dict):
    sig = P.trap_control_signal(dict(ev), "t1", T0)
    assert sig is not None, f"the trap did not classify at all: {ev}"
    return sig


@pytest.fixture(autouse=True)
def _clean_counters():
    P.reset_parser_counters()
    yield
    P.reset_parser_counters()


# ══ 1. DISCRIMINATION — the thing the row was opened for ═════════════════════


def test_an_administratively_shut_port_is_distinguishable_from_a_fault():
    """THE POINT OF THE ROW. Two linkDowns on the same port, one because an
    operator shut it and one because the link failed, must not be the same
    evidence. `state` is `down` on both — that is the link's state and it is
    true — and `admin_status` is what separates the planned change from the
    outage."""
    shut = classify(link_trap(admin=2, oper=2))
    fault = classify(link_trap(admin=1, oper=2))

    assert shut.attrs["admin_status"] == "down"
    assert fault.attrs["admin_status"] == "up"
    assert shut.attrs["oper_status"] == fault.attrs["oper_status"] == "down"
    assert shut.attrs["state"] == fault.attrs["state"] == "down"
    # …and they really are two distinguishable pieces of evidence now.
    assert shut.attrs != fault.attrs


def test_lower_layer_down_is_not_read_as_down():
    """`lowerLayerDown(7)` says THIS device is a victim: the interface under it
    failed. The naive decode — substring `down` — collapses it into a plain
    local failure, which is the single most misleading answer this enrichment
    could give, so it is pinned separately."""
    sig = classify(link_trap(admin=1, oper=7))
    assert sig.attrs["oper_status"] == "lowerlayerdown"
    assert sig.attrs["oper_status"] != "down"


@pytest.mark.parametrize("raw", [2, "2", "down", "down(2)", "DOWN(2)",
                                 "INTEGER: down(2)"])
def test_the_decoder_takes_every_rendering_an_agent_sends(raw):
    """An INTEGER enum reaches the receiver as the bare int, the label, or
    `label(int)` depending on whether the agent's MIB was loaded. All three are
    the same fact and must decode to the same word — otherwise the attr is a
    report on the AGENT's MIB loading, not on the interface."""
    assert classify(link_trap(admin=raw)).attrs["admin_status"] == "down"


@pytest.mark.parametrize("raw,want", [
    (1, "up"), (2, "down"), (3, "testing"), (4, "unknown"), (5, "dormant"),
    (6, "notpresent"), (7, "lowerlayerdown"),
])
def test_every_if_oper_status_value_decodes_to_its_own_word(raw, want):
    assert classify(link_trap(admin=1, oper=raw)).attrs["oper_status"] == want


@pytest.mark.parametrize("raw,want", [(1, "up"), (2, "down"), (3, "testing")])
def test_every_if_admin_status_value_decodes_to_its_own_word(raw, want):
    assert classify(link_trap(admin=raw)).attrs["admin_status"] == want


def test_a_value_that_is_not_on_the_ladder_is_unknown_not_a_guess():
    """A varbind that arrived but did not decode is `unknown`. It is NOT dropped
    (the device did report something) and it is NOT mapped to the nearest
    plausible word (that would be a fabricated reading)."""
    sig = classify(link_trap(admin="admin-state-99", oper="weird"))
    assert sig.attrs["admin_status"] == "unknown"
    assert sig.attrs["oper_status"] == "unknown"


def test_a_link_up_carries_the_status_varbinds_too():
    """linkUp declares the same OBJECTS clause. A recovery that comes back with
    ifOperStatus still down is a half-recovery, and the enrichment is what makes
    that visible."""
    sig = classify(link_trap(oid=LINK_UP, name="linkUp", admin=1, oper=1))
    assert sig.attrs["state"] == "up"
    assert (sig.attrs["admin_status"], sig.attrs["oper_status"]) == ("up", "up")


def test_the_vendor_event_type_twin_is_enriched_identically():
    """A vendor trap that the MIB index decodes to a link transition takes the
    `.event_type` rule, not the OID rule. The two must produce ONE vocabulary —
    a device whose trap happens to be enterprise-specific must not lose the
    discrimination."""
    ev = link_trap(admin=2, oper=2, oid="1.3.6.1.4.1.9.9.999.0.1",
                   name="someVendorLinkDown")
    ev["event_type"] = "link_down"
    sig = classify(ev)
    assert sig.attrs["rule_id"] == "trap.link.state_change.event_type"
    assert (sig.attrs["admin_status"], sig.attrs["oper_status"]) == ("down", "down")


def test_the_status_is_read_by_varbind_name_when_the_oid_is_not_the_column():
    """Some receivers hand on a resolved NAME and an instance OID the column
    match does not cover. The name arm is the same fallback the interface
    extraction already uses, so the two agree."""
    ev = {"device": "leaf9", "trap_oid": LINK_DOWN, "trap_name": "linkDown",
          "event_type": "", "authenticated": True,
          "timestamp": "2026-09-06T10:00:00.000Z",
          "varbinds": [{"oid": "1.3.6.1.4.1.9.2.2.1.1.20.7",
                        "name": "ifAdminStatus", "value": "down"},
                       {"oid": "1.3.6.1.4.1.9.2.2.1.1.20.8",
                        "name": "ifOperStatus", "value": "down"},
                       vb(OID_IF_NAME, "ifName", "Ethernet7")]}
    sig = classify(ev)
    assert (sig.attrs["admin_status"], sig.attrs["oper_status"]) == ("down", "down")


# ══ 2. NON-RE-IDENTIFICATION — the deferral's stated objection, refuted ══════


IDENTITY_FIELDS = ("native_id", "entity_id", "entity_type", "severity",
                   "metric_name", "kind")


def _identity(sig) -> tuple:
    return (str(sig.signal_id), sig.native_id, sig.entity_id,
            sig.entity_type.value, sig.severity.value, sig.metric_name,
            sig.kind, sig.attrs["state"], tuple(sig.entity_tokens))


@pytest.mark.parametrize("admin,oper", [(2, 2), (1, 2), (1, 7), (1, 1)])
def test_the_status_varbinds_do_not_re_identify_the_trap(admin, oper):
    """THE REFUTATION. Same device, same interface, same millisecond, same trap
    OID — once bare and once carrying the status varbinds. Every identity field,
    `signal_id` included, must be equal: the enrichment is evidence ABOUT the
    event, never part of what the event IS."""
    bare = classify(link_trap())
    rich = classify(link_trap(admin=admin, oper=oper))
    assert _identity(bare) == _identity(rich)


def test_the_enrichment_is_purely_additive_on_the_attrs_dict():
    """Not just the identity: every attr the rule emitted BEFORE still has the
    value it had. The enrichment may only ADD keys."""
    bare = classify(link_trap())
    rich = classify(link_trap(admin=2, oper=2))
    for key, value in bare.attrs.items():
        assert rich.attrs[key] == value, f"attr {key!r} changed value"
    assert set(rich.attrs) - set(bare.attrs) == {"admin_status", "oper_status"}


def test_no_golden_corpus_event_carries_a_status_varbind():
    """WHY the whole frozen parity baseline stays green with no new skips: the
    corpus this rule was pinned against contains no ifAdminStatus/ifOperStatus
    varbind at all, so every recorded output replays byte-for-byte. If a future
    corpus entry adds one, this test says so BEFORE the parity run turns red for
    a reason nobody can place."""
    path = os.path.join(HERE, "fixtures", "parser_golden_corpus.jsonl")
    with open(path, encoding="utf-8") as fh:
        rows = [json.loads(line) for line in fh if line.strip()]
    assert len(rows) >= 1000
    carrying = [
        r for r in rows
        for v in (r["ev"].get("varbinds") or [])
        if str(v.get("oid") or "").startswith((OID_ADMIN + ".", OID_OPER + ".",
                                               OID_ADMIN, OID_OPER))
    ]
    assert not carrying, (
        f"{len(carrying)} corpus events now carry a link-status varbind — "
        "re-bake their recorded output before trusting the parity run")


# ══ 3. HONEST ABSENCE ════════════════════════════════════════════════════════


def test_a_trap_without_the_varbinds_has_no_status_keys_at_all():
    """"The agent did not send it" and "the agent sent an empty value" are
    different facts. An empty string would make the first look like the second
    everywhere downstream — in the RCA payload, in OpenSearch, in an operator's
    eyes. The key is absent instead."""
    attrs = classify(link_trap()).attrs
    assert "admin_status" not in attrs
    assert "oper_status" not in attrs


def test_one_varbind_present_and_one_absent_emits_exactly_one_key():
    """The two are independent: an agent that sends ifOperStatus but not
    ifAdminStatus must produce the one fact it reported and no placeholder for
    the other."""
    attrs = classify(link_trap(oper=2)).attrs
    assert attrs["oper_status"] == "down"
    assert "admin_status" not in attrs


def test_an_empty_varbind_value_is_an_absent_key_not_an_empty_status():
    """An agent that sends the varbind with an empty value has told us nothing
    decodable and nothing at all — same treatment as not sending it."""
    attrs = classify(link_trap(admin="", oper="")).attrs
    assert "admin_status" not in attrs and "oper_status" not in attrs


def test_omit_empty_touches_nothing_but_the_two_declared_keys():
    """A blanket "drop falsy attrs" would silently delete `authenticated: False`
    — the flag that says a v1/v2c trap is spoofable — which is the exact
    opposite of honest. Only the declared keys may be dropped."""
    sig = classify({**link_trap(admin=2), "authenticated": False})
    assert sig.attrs["authenticated"] is False
    assert "authenticated" in sig.attrs


# ══ 4. NO FABRICATION — the ladders come from the vendored MIB ═══════════════


def _index_enum(oid: str) -> dict[str, str]:
    with open(MIB_INDEX, encoding="utf-8") as fh:
        node = json.load(fh)["nodes"][oid]
    assert node["mib"] == "IF-MIB" and node["kind"] == "column"
    return node["enum"]


@pytest.mark.parametrize("oid,attr", [(OID_ADMIN, "admin_status"),
                                      (OID_OPER, "oper_status")])
def test_the_ladders_are_the_vendored_mib_enum_and_nothing_else(oid, attr):
    """THE ANTI-FABRICATION GATE, both directions.

    FORWARD: every value in the vendored MIB's enum must decode — by its number
    AND by its label — to that label lower-cased, so no defined state is lost.
    REVERSE: the rule must not be able to produce a word the MIB does not
    define, apart from the documented `unknown` sentinel. A label recalled from
    memory (`admin_down`, `not_present`, `lower_layer_down`) fails here."""
    enum = _index_enum(oid)
    produced: set[str] = set()
    for num, label in enum.items():
        for raw in (int(num), num, label, f"{label}({num})"):
            kw = {"admin" if attr == "admin_status" else "oper": raw}
            got = classify(link_trap(**kw)).attrs[attr]
            assert got == label.lower(), (
                f"{oid} {raw!r} decoded to {got!r}, but the vendored IF-MIB "
                f"calls {num} {label!r}")
            produced.add(got)
    assert produced == {v.lower() for v in enum.values()}


@pytest.mark.parametrize("oid,attr", [(OID_ADMIN, "admin_status"),
                                      (OID_OPER, "oper_status")])
def test_the_rule_can_emit_no_word_the_mib_does_not_define(oid, attr):
    """The closed-vocabulary half: whatever a device sends, the attr is either a
    lower-cased MIB label or the `unknown` sentinel."""
    allowed = {v.lower() for v in _index_enum(oid).values()} | {"unknown"}
    for raw in (8, 99, "-1", "shutdown", "admin-down", "notPresent(6)",
                "lowerLayerDown", "up", "\x00", "down down", "7 lowerLayerDown"):
        kw = {"admin" if attr == "admin_status" else "oper": raw}
        got = classify(link_trap(**kw)).attrs[attr]
        assert got in allowed, f"{raw!r} produced the invented word {got!r}"


@pytest.mark.parametrize("attr", ["admin_status", "oper_status"])
def test_a_zero_valued_status_varbind_reads_as_not_reported(attr):
    """0 is not on either ladder — SMI numbers these enums from 1 — and the
    trap reader has always coerced a falsy varbind value to '' (see
    `producers._trap_varbind`). So an agent that sends 0 has reported nothing
    decodable, and the key is absent rather than carrying a fabricated word."""
    kw = {"admin" if attr == "admin_status" else "oper": 0}
    assert attr not in classify(link_trap(**kw)).attrs


def test_both_status_oids_are_the_columns_the_notification_declares():
    """The OIDs are the ones RFC 2863's `OBJECTS { ifIndex, ifAdminStatus,
    ifOperStatus }` names, resolved through the index rather than trusted."""
    with open(MIB_INDEX, encoding="utf-8") as fh:
        nodes = json.load(fh)["nodes"]
    assert nodes[OID_ADMIN]["name"] == "ifAdminStatus"
    assert nodes[OID_OPER]["name"] == "ifOperStatus"
    assert nodes[OID_ADMIN]["index"] == nodes[OID_OPER]["index"] == ["ifIndex"]


# ══ 5. THE GRAMMAR ═══════════════════════════════════════════════════════════


def test_both_link_rules_declare_the_two_keys_as_omit_empty():
    """The declaration IS the additivity guarantee, so it is pinned rather than
    left to a reviewer to notice if it is dropped."""
    for rid in ("trap.link.state_change", "trap.link.state_change.event_type"):
        rule = P.RULES_BY_ID[rid]
        assert rule.emit is not None
        assert rule.emit.omit_empty == ("admin_status", "oper_status"), rid


def test_no_other_rule_drops_an_attr():
    """`omit_empty` is a deliberate, narrow exception. If it spreads, an absent
    key stops meaning "the device did not report it" and starts meaning
    "somebody decided this one was boring"."""
    declaring = {r.rule_id for r in P.RULES
                 if r.emit is not None and r.emit.omit_empty}
    assert declaring == {"trap.link.state_change",
                         "trap.link.state_change.event_type"}


def test_omit_empty_cannot_name_a_key_the_rule_does_not_emit():
    """A row that claims to conditionally drop a field nothing builds is a lie
    that would never fire. It must not compile."""
    row = {
        "rule_id": "t.bad", "lane": "trap", "source": "trap",
        "kind": "link_state_change", "entity_type": "interface",
        "family": None, "vendors": ["standard"], "severity": "warn",
        "guard": {"always": True},
        "extract": {},
        "emit": {"kind": "link_state_change", "metric": "link_state",
                 "modality": "control_plane",
                 "entity": {"type": "device", "id": "{device}"},
                 "native_id": "{device}|x|{ts_ms}",
                 "attrs": {"trap_oid": {"var": "oid"}},
                 "omit_empty": ["admin_status"]},
    }
    with pytest.raises(RuleError, match="omit_empty"):
        compile_rule(row)


def test_the_native_id_template_never_reads_a_status_var():
    """The structural guarantee behind test 2: identity is a template, and
    neither status var may appear in it. Read off the rule table, so a future
    edit to the template is caught here and not by a re-identification incident
    six months of stored evidence later."""
    for rid in ("trap.link.state_change", "trap.link.state_change.event_type"):
        row = P.RULES_BY_ID[rid].emit_src
        assert "admin_status" not in row["native_id"]
        assert "oper_status" not in row["native_id"]
        assert "admin_status" not in row["entity"]["id"]
        assert "oper_status" not in row["entity"]["id"]
        assert row["severity"] == {"by_state": {"down": "high"}, "default": "warn"}
