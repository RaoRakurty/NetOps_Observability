# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Stage [1] once real PRI reaches the engine (tracker 387 PR 10, owner D3).

syslog-ng used to reset PRI to 13 for every vendor, so the generic net was silent by
accident. These pin what real PRI may and may not do, without docker, on the documents
the edge now delivers. tests/test_syslog_edge_framing.py proves the edge delivers them.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

import producers as P
from catalog import builtin_catalog
from engine import run_window

NOW = datetime(2026, 11, 9, 10, 0, tzinfo=timezone.utc)
TS = "2026-11-09T09:59:00.000Z"
WORDS = ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")


def _ev(message: str, severity: str = "notice", appname: str = "otherd", hostname: str = "r1",
        **extra: str) -> dict:
    return {"hostname": hostname, "appname": appname, "severity": severity, "message": message,
            "timestamp": TS, **extra}


def _signal(ev: dict):
    return P.syslog_control_signal(dict(ev), "t1", NOW)


def _objects(*events: dict) -> int:
    sigs = [s for s in (_signal(ev) for ev in events) if s]
    sigs.sort(key=lambda s: (s.ts, s.signal_id))
    return len(run_window(tuple(sigs), builtin_catalog(), ()))


# ── the generic net, for a vendor with no pack ───────────────────────────────────

@pytest.mark.parametrize("word,severity,opens", [
    ("emerg", "crit", 1), ("alert", "crit", 1), ("crit", "crit", 1),
    ("err", "warn", 0), ("warning", "warn", 0),
    ("notice", None, 0), ("info", None, 0), ("debug", None, 0),
])
def test_only_a_critical_line_opens_alone(word: str, severity: str | None, opens: int) -> None:
    ev = _ev("a line no rule and no pack knows", word)
    sig = _signal(ev)
    assert (sig.severity.value if sig else None) == severity
    assert _objects(ev) == opens


def test_an_err_line_still_reaches_the_engine_and_joins_a_component() -> None:
    """Below the floor is not dropped (owner rule 1): a real line on the same device as
    an opening signal shares its component."""
    err = _ev("a line no rule knows", "err")
    crit = _ev("another line no rule knows", "crit")
    assert _signal(err).kind == "device_alarm"
    assert _objects(err, crit) == 1


def test_the_trap_net_is_not_touched() -> None:
    """Traps were never suppressed, so nothing changed there."""
    sig = P.trap_control_signal(
        {"device": "r1", "trap_oid": "1.3.6.1.4.1.99999.1", "trap_name": "fooFailed",
         "severity": "err", "timestamp": TS}, "t1", NOW)
    assert (sig.kind, sig.severity.value) == ("device_alarm", "high")


# ── where a line's own severity is read ──────────────────────────────────────────

def test_a_mnemonic_at_the_start_of_the_message_is_read() -> None:
    sig = _signal(_ev("%FOO-3-BAR: no rule knows this", "notice", appname="Rib"))
    assert sig is not None and sig.attrs["severity"] == 3
    assert sig.severity.value == "warn"


def test_a_critical_mnemonic_in_the_message_opens_as_it_did_from_the_tag() -> None:
    ev = _ev("%PLATFORM-2-PS_FAIL: power supply failed", "notice", appname="Rib")
    assert _signal(ev).severity.value == "crit"
    assert _objects(ev) == 1


def test_text_later_in_a_line_sets_no_severity() -> None:
    """A sender writes its own message; it cannot talk its way to critical."""
    assert _signal(_ev("user typed %FOO-1-BAR into a field")) is None
    assert not P.syslog_promotable(_ev("user typed %FOO-1-BAR into a field"))


def test_the_old_tag_shape_still_reads() -> None:
    """A frame already on the bus at upgrade, and every harness, carries it there."""
    sig = _signal(_ev("no rule knows this", "notice", appname="%FOO-3-BAR"))
    assert sig is not None and sig.attrs["severity"] == 3


# ── the SSH banner probe ─────────────────────────────────────────────────────────

BANNER = "error: kex_exchange_identification: Connection closed by remote host"


def test_the_banner_probe_is_counted_and_emits_nothing() -> None:
    before = P.KNOWN_BENIGN_HITS.get("syslog.standard.sshd_banner_probe", 0)
    assert _signal(_ev(BANNER, "err", appname="sshd")) is None
    assert P.KNOWN_BENIGN_HITS["syslog.standard.sshd_banner_probe"] == before + 1


def test_another_sshd_error_is_not_the_banner_probe() -> None:
    sig = _signal(_ev("error: Too many authentication failures", "err", appname="sshd"))
    assert (sig.kind, sig.severity.value) == ("device_alarm", "warn")


# ── link state, in both directions (tracker 385, stage [5]) ─────────────────────

LINK_DOWN = "Interface Gi1, changed state to down"
PROTO_DOWN = "Line protocol on Interface Gi1, changed state to down"
ADMIN_DOWN = "Interface Gi1, changed state to administratively down"


def _ios(mnemonic: str, text: str, severity: str) -> dict:
    """An IOS line as the edge delivers it: no process tag, the body grammar's fields."""
    facility, _digit, event = mnemonic.split("-")
    return _ev(f"%{mnemonic}: {text}", severity, appname="unknown", facility=facility,
               event_type=event.lower())


def test_an_ios_link_fault_opens() -> None:
    assert _objects(_ios("LINK-3-UPDOWN", LINK_DOWN, "err"),
                    _ios("LINEPROTO-5-UPDOWN", PROTO_DOWN, "notice")) == 1


def test_an_ios_shutdown_does_not_open() -> None:
    assert _objects(_ios("LINK-5-CHANGED", ADMIN_DOWN, "notice"),
                    _ios("LINEPROTO-5-UPDOWN", PROTO_DOWN, "notice")) == 0


def test_an_ios_shutdown_line_is_a_change_that_cannot_open() -> None:
    """Tracker 388: the line that says `administratively down` is the change half
    (link_cause=admin), below the open floor, on the same node as the protocol line."""
    sig = _signal(_ios("LINK-5-CHANGED", ADMIN_DOWN, "notice"))
    assert (sig.kind, sig.severity.value, sig.attrs["link_cause"]) == (
        "link_state_change", "warn", "admin")
    assert sig.entity_id == "r1:Gi1"


def test_the_protocol_line_still_joins_a_fault() -> None:
    sig = _signal(_ios("LINEPROTO-5-UPDOWN", PROTO_DOWN, "notice"))
    assert (sig.kind, sig.severity.value) == ("link_state_change", "warn")
    assert sig.entity_id == "r1:Gi1"


def test_a_tagged_protocol_line_is_the_fault_as_it_was() -> None:
    """EOS logs `Ebra: %LINEPROTO-5-UPDOWN` and nothing else for a link fault."""
    ev = _ev(f"%LINEPROTO-5-UPDOWN: {PROTO_DOWN}", "notice", appname="Ebra",
             facility="LINEPROTO", event_type="updown")
    assert _signal(ev).severity.value == "high"
    assert _objects(ev) == 1


def test_the_old_tag_shape_of_the_protocol_line_is_unmoved() -> None:
    sig = _signal(_ev(PROTO_DOWN, "notice", appname="%LINEPROTO-5-UPDOWN"))
    assert sig.severity.value == "high"


ADMIN_TRAP = {
    "device": "r1", "trap_oid": "1.3.6.1.6.3.1.1.5.3", "trap_name": "linkDown", "timestamp": TS,
    "varbinds": [{"oid": "1.3.6.1.2.1.31.1.1.1.1.1", "value": "Gi1"},
                 {"oid": "1.3.6.1.2.1.2.2.1.7.1", "name": "ifAdminStatus", "value": "2"},
                 {"oid": "1.3.6.1.2.1.2.2.1.8.1", "name": "ifOperStatus", "value": "2"}],
}


def _objects_with_trap(*events: dict) -> int:
    trap = P.trap_control_signal(dict(ADMIN_TRAP), "t1", NOW)
    assert (trap.attrs.get("link_cause"), trap.severity.value) == ("admin", "high")
    sigs = [trap] + [s for s in (_signal(ev) for ev in events) if s]
    sigs.sort(key=lambda s: (s.ts, s.signal_id))
    return len(run_window(tuple(sigs), builtin_catalog(), ()))


def test_a_shutdown_trap_alone_opens_nothing() -> None:
    assert _objects_with_trap() == 0


def test_the_protocol_line_does_not_defeat_the_admin_exemption() -> None:
    """The reason the IOS protocol line is warn. `_admin_change_only` fails closed on any
    opening-severity signal with no cause, and this line carries none: at high it would
    reopen every shutdown the trap had correctly exempted."""
    assert _objects_with_trap(_ios("LINK-5-CHANGED", ADMIN_DOWN, "notice"),
                              _ios("LINEPROTO-5-UPDOWN", PROTO_DOWN, "notice")) == 0


def test_a_real_fault_beside_the_admin_trap_opens() -> None:
    """Fail-closed in the other direction: the fault line has no admin cause."""
    assert _objects_with_trap(_ios("LINK-3-UPDOWN", LINK_DOWN, "err")) == 1


def test_a_tagged_protocol_line_beside_the_admin_trap_opens() -> None:
    """EOS's line is its fault line, so it cannot be exempted on the trap's word. This is
    the one shutdown shape that still opens: tracker 388."""
    ev = _ev(f"%LINEPROTO-5-UPDOWN: {PROTO_DOWN}", "notice", appname="Ebra",
             facility="LINEPROTO", event_type="updown")
    assert _objects_with_trap(ev) == 1


@pytest.mark.parametrize("word", WORDS)
def test_pri_cannot_move_a_typed_link_row(word: str) -> None:
    """The rows state severity by state and shape. Real PRI cannot widen or narrow what
    stage [5] opens on them, nor what `_admin_change_only` sees as opening."""
    assert _signal(_ios("LINK-3-UPDOWN", LINK_DOWN, word)).severity.value == "high"
    assert _signal(_ios("LINK-3-UPDOWN", "Interface Gi1, changed state to up", word)).severity.value == "warn"
    assert _signal(_ios("LINEPROTO-5-UPDOWN", PROTO_DOWN, word)).severity.value == "warn"


# ── the prefilter's fields ───────────────────────────────────────────────────────

def test_a_pri_facility_in_the_facility_field_would_defeat_the_screen() -> None:
    """Why the aggregator moves it to syslog_facility: `local` is a screen literal."""
    plain = _ev("an ordinary line", "info")
    assert not P.syslog_promotable(plain)
    assert P.syslog_promotable({**plain, "facility": "local7"})
    assert "local" in P._SYSLOG_SCREEN_LITERALS
