# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 378 — ONE canonical answer to "who took this link down?".

THE DEFECT. An operator's `shutdown` and a real fault reached the engine as the
same `link_state_change`. Tracker 218 added `admin_status` (RFC 2863
ifAdminStatus) when the trap carries it — but Cisco IOS's default-format link
trap does not carry it. It carries the enterprise varbind `locIfReason`
(OLD-CISCO-INTERFACES-MIB `1.3.6.1.4.1.9.2.2.1.1.20`, a DisplayString), which
decodes BY NAME since tracker 377 and which the rules ignored.

THE FIX (additive evidence only). Both trap link rules emit:
  link_cause   admin | fault | unknown — vendor-neutral, priority-derived
  link_reason  the raw reason text, trimmed and bounded to 64 chars
Both `omit_empty`: a trap that carries neither ifAdminStatus nor a reason
varbind gains NO key, so its attrs dict, native_id and signal_id are exactly
what they always were (the tracker-218 pattern).

THE VOCABULARY IS RECORDED (see the `trap_link_cause` fragment in
telemetry-catalog/events.yaml for the citations):
  - "administratively down" / "up" as locIfReason on linkDown / linkUp — the
    LoriotPro trap-log sample of an IOS agent (`trap_Feb_23_2002.csv`).
  - the failure reasons — Cisco Press, "Performance and Fault Management",
    ch. "Error/Fault Monitoring": "Keepalive failed", "Lost Carrier", "Fatal Tx
    Error", "Late Collision", "Excessive collision", "Open Failure, Lobe",
    "Ring Beaconing", "Duplicate Address", "Wire-fault", "Auto-removal",
    "LAPB down", "EIA signal lost".

MULTI-VENDOR. Juniper, Nokia (SR OS / SR Linux), Arista and SONiC send the RFC
2863 link trap `OBJECTS { ifIndex, ifAdminStatus, ifOperStatus }`; none defines
a reason varbind in its link notification (no reason/cause interface object in
the indexed JUNIPER-*, ARISTA-*, TIMETRA-* modules — pinned below against the
MIB index), so ifAdminStatus is their evidence and is tested per vendor.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone

import pytest

import producers as P

HERE = os.path.dirname(os.path.abspath(__file__))
MIB_INDEX = os.path.abspath(os.path.join(
    HERE, "..", "backend", "collectors", "mibs", "index", "oididx.json"))
GOLDEN = os.path.join(HERE, "fixtures", "parser_golden_corpus.jsonl")

T0 = datetime(2026, 11, 8, 10, 0, 0, tzinfo=timezone.utc)

LINK_DOWN = "1.3.6.1.6.3.1.1.5.3"
LINK_UP = "1.3.6.1.6.3.1.1.5.4"
OID_IF_INDEX = "1.3.6.1.2.1.2.2.1.1"
OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
OID_IF_TYPE = "1.3.6.1.2.1.2.2.1.3"
OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
OID_ADMIN = "1.3.6.1.2.1.2.2.1.7"
OID_OPER = "1.3.6.1.2.1.2.2.1.8"
OID_LOC_IF_REASON = "1.3.6.1.4.1.9.2.2.1.1.20"

NEW_KEYS = {"link_cause", "link_reason"}


def _ev(device: str, varbinds: list[dict], *, oid: str = LINK_DOWN,
        name: str = "linkDown", event_type: str = "") -> dict:
    return {"device": device, "trap_oid": oid, "trap_name": name,
            "event_type": event_type, "authenticated": True,
            "timestamp": "2026-11-08T10:00:00.000Z", "varbinds": varbinds}


def cisco_ios(reason: str | None, *, ifx: int = 3, up: bool = False,
              admin=None) -> dict:
    """The IOS Cisco-format link trap: ifIndex, ifDescr, ifType, locIfReason
    (the varbind set the LoriotPro capture records), optionally with the RFC
    2863 ifAdminStatus an IETF-format trap adds."""
    vbs = [{"oid": f"{OID_IF_INDEX}.{ifx}", "name": "ifIndex", "value": str(ifx)},
           {"oid": f"{OID_IF_DESCR}.{ifx}", "name": "ifDescr",
            "value": "GigabitEthernet0/1"},
           {"oid": f"{OID_IF_TYPE}.{ifx}", "name": "ifType",
            "value": "ethernetCsmacd"}]
    if admin is not None:
        vbs.append({"oid": f"{OID_ADMIN}.{ifx}", "name": "ifAdminStatus",
                    "value": admin})
    if reason is not None:
        vbs.append({"oid": f"{OID_LOC_IF_REASON}.{ifx}", "name": "locIfReason",
                    "value": reason})
    if up:
        return _ev("ios-r1", vbs, oid=LINK_UP, name="linkUp")
    return _ev("ios-r1", vbs)


def rfc2863(device: str, iface: str, admin, oper, *, ifx: int = 545,
            up: bool = False) -> dict:
    """The RFC 2863 link trap Junos, SR OS, SR Linux, EOS and SONiC send."""
    vbs = [{"oid": f"{OID_IF_INDEX}.{ifx}", "name": "ifIndex", "value": str(ifx)},
           {"oid": f"{OID_ADMIN}.{ifx}", "name": "ifAdminStatus", "value": admin},
           {"oid": f"{OID_OPER}.{ifx}", "name": "ifOperStatus", "value": oper},
           {"oid": f"{OID_IF_NAME}.{ifx}", "name": "ifName", "value": iface}]
    if up:
        return _ev(device, vbs, oid=LINK_UP, name="linkUp")
    return _ev(device, vbs)


def classify(ev: dict):
    sig = P.trap_control_signal(dict(ev), "t1", T0)
    assert sig is not None, f"the trap did not classify at all: {ev}"
    assert sig.kind == "link_state_change"
    return sig


@pytest.fixture(autouse=True)
def _clean_counters():
    P.reset_parser_counters()
    yield
    P.reset_parser_counters()


# ══ 1. Cisco locIfReason ═════════════════════════════════════════════════════


def test_cisco_administratively_down_is_admin():
    """The recorded IOS shutdown: linkDown, locIfReason "administratively down",
    and no ifAdminStatus in the varbind list at all."""
    sig = classify(cisco_ios("administratively down"))
    assert sig.attrs["link_cause"] == "admin"
    assert sig.attrs["link_reason"] == "administratively down"
    assert "admin_status" not in sig.attrs       # IOS did not send it


@pytest.mark.parametrize("reason", [
    "Keepalive failed", "Lost Carrier", "Fatal Tx Error", "Late Collision",
    "Excessive collision", "Open Failure, Lobe", "Ring Beaconing",
    "Duplicate Address", "Wire-fault", "Auto-removal", "LAPB down",
    "EIA signal lost",
])
def test_every_documented_cisco_failure_reason_is_fault(reason):
    sig = classify(cisco_ios(reason))
    assert sig.attrs["link_cause"] == "fault"
    assert sig.attrs["link_reason"] == reason


@pytest.mark.parametrize("reason", ["down", "looped", "Remove MAC", "up",
                                    "something new in IOS 99", "0x0001ff"])
def test_a_reason_that_names_no_documented_cause_is_unknown(reason):
    """A bare "down" names the new STATE, not why. "Remove MAC" is a removal
    ordered by the ring manager. Anything undocumented is not guessed: unknown,
    with the raw text kept for the operator."""
    sig = classify(cisco_ios(reason))
    assert sig.attrs["link_cause"] == "unknown"
    assert sig.attrs["link_reason"] == reason


def test_the_reason_matches_case_insensitively():
    assert classify(cisco_ios("Administratively Down")).attrs["link_cause"] == "admin"
    assert classify(cisco_ios("KEEPALIVE FAILED")).attrs["link_cause"] == "fault"


def test_admin_text_must_be_the_whole_reason():
    """`administratively down` is matched as the whole (trimmed) reason, so a
    longer string that merely contains the words is not read as a shutdown."""
    sig = classify(cisco_ios("peer administratively down, local carrier lost"))
    assert sig.attrs["link_cause"] == "unknown"


def test_a_link_up_never_claims_a_cause():
    """The recorded linkUp carries locIfReason "up". A recovery names no fault
    and no shutdown — evidence present, so `unknown`, never admin/fault."""
    sig = classify(cisco_ios("up", up=True))
    assert sig.attrs["state"] == "up"
    assert sig.attrs["link_cause"] == "unknown"
    assert sig.attrs["link_reason"] == "up"
    # …even when the text would be a failure reason on a down transition.
    assert classify(cisco_ios("Keepalive failed", up=True)).attrs["link_cause"] == "unknown"


def test_the_reason_is_found_by_name_when_the_oid_is_not_the_column():
    ev = cisco_ios(None)
    ev["varbinds"].append({"oid": "1.3.6.1.4.1.9.99.99.3", "name": "locIfReason",
                           "value": "Lost Carrier"})
    assert classify(ev).attrs["link_cause"] == "fault"


def test_the_reason_is_trimmed_and_bounded():
    """Untrusted device text: first line only, surrounding whitespace dropped,
    at most 64 characters."""
    sig = classify(cisco_ios("  Lost Carrier  \r\nInjected: second line"))
    assert sig.attrs["link_reason"] == "Lost Carrier"
    assert sig.attrs["link_cause"] == "fault"
    long = classify(cisco_ios("x" * 500)).attrs["link_reason"]
    assert long == "x" * 64


@pytest.mark.parametrize("blank", ["", "   ", "\r\n"])
def test_a_blank_reason_is_no_reason(blank):
    attrs = classify(cisco_ios(blank)).attrs
    assert NEW_KEYS.isdisjoint(attrs)


# ══ 2. ifAdminStatus precedence (RFC 2863, every vendor) ═════════════════════


@pytest.mark.parametrize("admin", [2, "2", "down", "down(2)"])
def test_admin_status_down_wins_over_a_fault_reason(admin):
    """Priority 1: the standard object. A shut port whose reason text says
    "Keepalive failed" is still an operator's shutdown."""
    sig = classify(cisco_ios("Keepalive failed", admin=admin))
    assert sig.attrs["admin_status"] == "down"
    assert sig.attrs["link_cause"] == "admin"


def test_admin_status_up_contradicting_the_admin_text_is_unknown():
    """The agent says the port is admin-UP while its reason text says
    administratively down. The cause is not guessed."""
    sig = classify(cisco_ios("administratively down", admin="up(1)"))
    assert sig.attrs["link_cause"] == "unknown"


def test_admin_status_up_with_a_fault_reason_is_fault():
    assert classify(cisco_ios("Lost Carrier", admin=1)).attrs["link_cause"] == "fault"


@pytest.mark.parametrize("vendor,device,iface", [
    ("juniper", "mx1", "xe-0/0/0"),       # Junos mib2d
    ("nokia_sros", "sr1", "1/1/1"),
    ("nokia_srl", "srl1", "ethernet-1/1"),
    ("arista", "eos1", "Ethernet1"),
    ("sonic", "sonic1", "Ethernet0"),
])
def test_rfc2863_vendors_admin_and_not_admin(vendor, device, iface):
    """Every non-Cisco vendor's evidence is ifAdminStatus. Shut → admin. Down
    while admin-up states no reason (it may be a far-end shutdown) → unknown,
    never a fabricated `fault`. Recovery → unknown."""
    shut = classify(rfc2863(device, iface, "down(2)", "down(2)"))
    assert shut.attrs["link_cause"] == "admin", vendor
    assert "link_reason" not in shut.attrs, vendor

    oper = classify(rfc2863(device, iface, "up(1)", "down(2)"))
    assert oper.attrs["link_cause"] == "unknown", vendor
    assert "link_reason" not in oper.attrs, vendor

    rec = classify(rfc2863(device, iface, 1, 1, up=True))
    assert rec.attrs["link_cause"] == "unknown", vendor


def test_admin_status_testing_is_unknown():
    assert classify(rfc2863("eos1", "Ethernet1", 3, 2)).attrs["link_cause"] == "unknown"


def test_the_vendor_event_type_twin_derives_the_same_cause():
    """A vendor trap decoded to a link transition takes the `.event_type` rule;
    the two rules must speak one vocabulary."""
    ev = cisco_ios("administratively down")
    ev.update(trap_oid="1.3.6.1.4.1.9.9.999.0.1", trap_name="someVendorLinkDown",
              event_type="link_down")
    sig = classify(ev)
    assert sig.attrs["rule_id"] == "trap.link.state_change.event_type"
    assert sig.attrs["link_cause"] == "admin"
    assert sig.attrs["link_reason"] == "administratively down"


# ══ 3. ADDITIVE — no re-identification, byte-identical when absent ═══════════


def _identity(sig) -> tuple:
    return (str(sig.signal_id), sig.native_id, sig.entity_id,
            sig.entity_type.value, sig.severity.value, sig.metric_name,
            sig.kind, sig.attrs["state"], tuple(sig.entity_tokens))


@pytest.mark.parametrize("reason", ["administratively down", "Keepalive failed",
                                    "down"])
def test_the_cause_never_re_identifies_the_trap(reason):
    bare = classify(cisco_ios(None))
    rich = classify(cisco_ios(reason))
    assert _identity(bare) == _identity(rich)
    for key, value in bare.attrs.items():
        assert rich.attrs[key] == value, key
    assert set(rich.attrs) - set(bare.attrs) == NEW_KEYS


def test_an_absent_reason_and_absent_status_add_no_key():
    """The byte-identical half: what every stored link trap looked like."""
    for ev in (cisco_ios(None),
               _ev("x", [{"oid": f"{OID_IF_INDEX}.1", "name": "ifIndex",
                          "value": "1"}])):
        attrs = classify(ev).attrs
        assert NEW_KEYS.isdisjoint(attrs)


def test_status_without_reason_adds_only_the_cause():
    attrs = classify(rfc2863("eos1", "Ethernet1", 2, 2)).attrs
    assert attrs["link_cause"] == "admin"
    assert "link_reason" not in attrs


def test_both_link_rules_declare_the_new_keys_omit_empty_and_keep_identity():
    for rid in ("trap.link.state_change", "trap.link.state_change.event_type"):
        rule = P.RULES_BY_ID[rid]
        assert rule.emit is not None
        assert rule.emit.omit_empty == ("admin_status", "oper_status",
                                        "link_cause", "link_reason"), rid
        row = rule.emit_src
        for key in ("link_cause", "link_reason", "reason"):
            assert key not in row["native_id"], rid
            assert key not in row["entity"]["id"], rid
        assert row["severity"] == {"by_state": {"down": "high"}, "default": "warn"}


def _golden() -> list[dict]:
    with open(GOLDEN, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _carries_reason(row: dict) -> bool:
    return any(str(v.get("oid") or "").startswith(OID_LOC_IF_REASON + ".")
               or "locifreason" in str(v.get("name") or "").lower()
               for v in (row["ev"].get("varbinds") or []))


def test_only_the_378_corpus_entries_carry_a_reason_varbind():
    """Why every PRE-378 corpus entry replays byte-for-byte: none carries a
    locIfReason varbind, so none gains a key. The entries that do are the ones
    this change added, each declared baseline-absent (the frozen code emits the
    same signal without the two keys)."""
    rows = _golden()
    assert len(rows) >= 1000
    carrying = [r for r in rows if _carries_reason(r)]
    assert carrying, "the 378 corpus entries are gone"
    for r in carrying:
        assert r["origin"] == "378-link-cause", r["ev"]
        assert r["baseline"] == "absent" and "tracker 378" in r["baseline_reason"]


def test_no_pre_378_corpus_output_carries_the_new_keys():
    for row in _golden():
        if row.get("origin") == "378-link-cause":
            continue
        # Tracker 388: vendor-pack syslog lines that state their own cause.
        if str(row.get("origin") or "").startswith("pack:"):
            continue
        for out in row["out"].values():
            if out and "attrs" in out:
                assert NEW_KEYS.isdisjoint(out["attrs"]), row["ev"]


def test_the_378_corpus_entries_record_every_cause():
    """The recorded outputs cover admin, fault and unknown; the W1b replay then
    checks them byte-for-byte on every run."""
    causes = sorted(
        r["out"]["trap_control_signal"]["attrs"]["link_cause"]
        for r in _golden() if r.get("origin") == "378-link-cause")
    assert causes == ["admin", "fault", "fault", "unknown", "unknown"]


# ══ 4. closed vocabulary + MIB facts ═════════════════════════════════════════


@pytest.mark.parametrize("reason", ["administratively down", "Lost Carrier",
                                    "down", "\x00", "admin", "fault", "%s" * 40])
@pytest.mark.parametrize("admin", [None, 1, 2, 3, "garbage"])
def test_link_cause_is_a_closed_vocabulary(reason, admin):
    attrs = classify(cisco_ios(reason, admin=admin)).attrs
    assert attrs.get("link_cause", "unknown") in {"admin", "fault", "unknown"}


def test_loc_if_reason_is_the_indexed_old_cisco_column():
    with open(MIB_INDEX, encoding="utf-8") as fh:
        node = json.load(fh)["nodes"][OID_LOC_IF_REASON]
    assert (node["name"], node["mib"], node["kind"]) == (
        "locIfReason", "OLD-CISCO-INTERFACES-MIB", "column")


def test_no_indexed_juniper_nokia_arista_module_defines_an_interface_reason():
    """The multi-vendor claim, pinned: if a future MIB fetch brings a vendor
    interface reason/cause object into the index, this fails and the rule must
    learn it (only locIfReason is wired today)."""
    with open(MIB_INDEX, encoding="utf-8") as fh:
        nodes = json.load(fh)["nodes"]
    found = sorted(
        (o, n["name"]) for o, n in nodes.items()
        if re.match(r"(JUNIPER|BGP4-V2-MIB-JUNIPER|ARISTA|TIMETRA)", str(n.get("mib")))
        and re.search(r"(reason|cause)", str(n.get("name")), re.IGNORECASE)
        # camelCase-anchored, so `tmnxChassisNotifyCardFailureReason` (a card,
        # matched by the "if" inside "Notify") is not read as an interface
        and re.search(r"(^if|If[A-Z]|[Pp]ort|[Ll]ink|[Ii]ntf)", str(n.get("name"))))
    assert found == [], found
