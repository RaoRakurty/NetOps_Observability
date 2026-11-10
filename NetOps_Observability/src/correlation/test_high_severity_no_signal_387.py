# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""The count of high-severity lines that reached nothing (tracker 387 PR 14).

Stage [1] telemetry. Owner D3 keeps a line below a grammar's alarm floor away from the
generic net, on purpose. What must stay visible is the line nobody decided about: it
stated err or worse, no typed row emitted it, and no known_benign row dismissed it.

These run the real handler, because the answer depends on both paths: a pack's literal
usually lets its lines past the screen, so counting rejections alone would read zero
on exactly the lines this is for. The verdict is not touched: `test_ingest_prefilter_p3`
owns that, and the count is asserted here to change nothing it reads.

What it reads today: zero on Cisco SD-WAN, and that is a true answer. Its `below_floor`
rows take the withheld lines at `warn`, so they join a component without opening one,
and its known_benign row dismisses the one repeater. The count watches for the pack
that ships without such a row, so the tests that need that line remove the row's signal.
"""
from __future__ import annotations

import asyncio

import pytest

import main
import producers as P


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch):
    async def _sink(*_a, **_kw):
        return None
    for name in ("emit", "batch_signal", "_emit_proactive"):
        monkeypatch.setattr(main, name, _sink)
    monkeypatch.setattr(main, "buffer_signal", lambda *_a, **_kw: None)
    monkeypatch.setattr(main, "CORR_SIGNALS_ENABLED", True)
    monkeypatch.setattr(main, "ch", object())
    monkeypatch.setattr(main, "verified_tenant", lambda claim, host, lane, **kw: "t1")
    monkeypatch.setattr(main, "SYSLOG_BUCKET", {})
    P.reset_prefilter_counts()
    yield
    P.reset_prefilter_counts()


def _line(message: str, appname: str = "ZZZD", severity: str = "notice") -> dict:
    return {"hostname": "e1", "appname": appname, "severity": severity, "message": message,
            "timestamp": "2026-11-09T10:00:00Z"}


def _handle(ev: dict) -> None:
    asyncio.run(main.handle_syslog(dict(ev)))


def test_a_withheld_high_severity_line_with_no_rule_is_counted(monkeypatch):
    """The line this exists for. It passes the screen on the pack's literal, the generic
    net abstains (alarm floor), and no row emitted it: stored, and read by nobody."""
    monkeypatch.setattr(main, "syslog_control_signal", lambda *_a, **_kw: None)
    ev = _line("%Viptela-vEdge-1-ZZZD-3-ERRO-1000999: plain words")
    assert P.syslog_promotable(dict(ev)) is True, "premise: the literal lets it past the screen"
    P.reset_prefilter_counts()
    _handle(ev)
    assert P.high_severity_no_signal() == {"screen": 0, "classifier": 1}


def test_a_withheld_line_a_below_floor_row_took_is_not_counted():
    """It reached the engine at warn: it can join a component, it cannot open an object."""
    ev = _line("%Viptela-vEdge-1-ZZZD-3-ERRO-1000999: plain words")
    assert P.syslog_alarm_num(dict(ev), "ZZZD") is None, "premise: the alarm floor withheld it"
    _handle(ev)
    assert sum(P.high_severity_no_signal().values()) == 0


def test_a_lower_severity_withheld_line_is_not_a_question(monkeypatch):
    monkeypatch.setattr(main, "syslog_control_signal", lambda *_a, **_kw: None)
    _handle(_line("%Viptela-vEdge-1-ZZZD-5-NTCE-1000998: plain words"))
    assert sum(P.high_severity_no_signal().values()) == 0


def test_a_line_the_alarm_floor_admits_is_not_counted(monkeypatch):
    """Critical clears the floor, so the generic net or a typed row has it. Even with
    the rule removed it is not this count's question: the floor did not withhold it."""
    monkeypatch.setattr(main, "syslog_control_signal", lambda *_a, **_kw: None)
    _handle(_line("%Viptela-vEdge-1-ZZZD-2-CRIT-1000997: plain words"))
    assert sum(P.high_severity_no_signal().values()) == 0


def test_a_dismissed_line_is_a_decision_not_a_question():
    """FTMD-3-ERRO-1000003 has a known_benign row: reading it as unanswered would make
    the alert fire on the one repeater we have already decided about."""
    before = P.known_benign_total()
    _handle(_line("%Viptela-vEdge-1-FTMD-3-ERRO-1000003: User ifname = ge0/0; kernel if_name= ge0_0; encap = 1",
                  appname="FTMD"))
    assert P.known_benign_total() == before + 1, "premise: the row dismissed the line"
    assert sum(P.high_severity_no_signal().values()) == 0


def test_a_line_a_typed_rule_took_is_not_counted():
    _handle(_line("%Viptela-vEdge-1-SYSMGR-4-WARN-200070: System cpu usage is above 75%",
                  appname="SYSMGR"))
    assert sum(P.high_severity_no_signal().values()) == 0


def test_ordinary_lines_count_nothing_and_pay_nothing():
    calls: list = []
    real = P.syslog_severity_num
    P.syslog_severity_num = lambda *a: calls.append(a) or real(*a)  # the second read
    try:
        for _ in range(3):
            _handle(_line("an ordinary line, nothing to see"))
    finally:
        P.syslog_severity_num = real
    assert sum(P.high_severity_no_signal().values()) == 0
    assert not calls, "an ordinary notice must not pay for a second severity read"


def test_a_line_with_no_severity_at_all_counts_nothing():
    _handle(_line("nothing here at all", severity=""))
    assert sum(P.high_severity_no_signal().values()) == 0


def test_the_screen_path_counts_a_withheld_line_it_rejected(monkeypatch):
    """A pack with a severity grammar and no rule literal: the screen rejects the line
    itself, and the same question must still be counted."""
    monkeypatch.setattr(P, "_SYSLOG_SCREEN_LITERALS", ("no such literal anywhere",))
    ev = _line("%Viptela-vEdge-1-ZZZD-3-ERRO-1000999: plain words")
    assert P.syslog_promotable(dict(ev)) is False
    assert P.high_severity_no_signal() == {"screen": 1, "classifier": 0}


def test_counting_never_changes_what_the_screen_answers():
    ev = _line("%Viptela-vEdge-1-ZZZD-3-ERRO-1000999: plain words")
    first = P.syslog_promotable(dict(ev))
    P.reset_prefilter_counts()
    second = P.syslog_promotable(dict(ev))
    assert first == second


def test_the_count_reaches_metrics_and_health(monkeypatch):
    monkeypatch.setattr(main, "syslog_control_signal", lambda *_a, **_kw: None)
    _handle(_line("%Viptela-vEdge-1-ZZZD-3-ERRO-1000999: plain words"))
    text = main._metrics_text()
    assert 'corr_syslog_high_severity_no_signal_total{path="classifier"} 1' in text
    assert 'corr_syslog_high_severity_no_signal_total{path="screen"} 0' in text
