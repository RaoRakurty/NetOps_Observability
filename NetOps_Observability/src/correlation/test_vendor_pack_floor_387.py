# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Owner D3 and rule 1, on the real engine (tracker 387).

"Ingestion is not incident creation." A vendor-pack line reaches stage [5] at the
severity its row states, and the singleton rule decides from there: only a qualifying
critical may open an object alone, and a below-floor signal can still join a component
when something else grounds it. A storm of the repeating line must open nothing.
Lines are scrubbed lab shapes, run through the classifier rather than hand-built, so
this fails if a row's severity or the alarm floor moves.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from catalog import builtin_catalog
from engine import EngineConfig, run_window
from producers import RULES, syslog_control_signal, syslog_promotable

T0 = datetime(2026, 11, 9, 10, 0, 0, tzinfo=timezone.utc)
CPU_CRIT = "%Viptela-vEdge-1-SYSMGR-2-CRIT-200069: System cpu usage is above 90% (critically high)"
CPU_WARN = "%Viptela-vEdge-1-SYSMGR-4-WARN-200070: System cpu usage is above 75%"
CPU_BELOW = "%Viptela-vEdge-1-SYSMGR-5-NTCE-200072: System cpu usage is below 75%"
DNS_FAIL = ("dnsclient_ares_callback[258]: DNS lookup failed for 0/vbond.example.net via "
            "none, reason: Timeout while contacting DNS servers")
FTMD = ("%Viptela-vEdge-1-FTMD-3-ERRO-1000003: User ifname = ge0/0; "
        "kernel if_name= ge0_0; encap = 1")
UNKNOWN_ERROR = "%Viptela-vEdge-1-OMPD-3-ERRO-400002: an unknown error line"


def _sig(message: str, app: str, *, offset_s: int = 0, host: str = "vEdge-1"):
    ts = T0 + timedelta(seconds=offset_s)
    ev = {"hostname": host, "appname": app, "severity": "notice", "message": message,
          "timestamp": ts.isoformat()}
    assert syslog_promotable(ev)
    return syslog_control_signal(ev, "t1", ts)


def _objects(signals):
    return run_window(signals, builtin_catalog(), (), EngineConfig())


def test_a_critical_cpu_line_opens_an_object_alone():
    assert len(_objects([_sig(CPU_CRIT, "SYSMGR")])) == 1


def test_a_warning_cpu_line_does_not():
    assert _objects([_sig(CPU_WARN, "SYSMGR")]) == []


def test_a_dns_failure_does_not():
    assert _objects([_sig(DNS_FAIL, "VTRACKER")]) == []


def test_an_unknown_error_line_does_not():
    sig = _sig(UNKNOWN_ERROR, "OMPD")
    assert (sig.kind, sig.severity.value) == ("device_alarm", "warn")
    assert _objects([sig]) == []


def test_a_clear_is_not_a_node():
    assert _objects([_sig(CPU_BELOW, "SYSMGR")]) == []


def test_a_storm_of_the_repeating_line_opens_nothing():
    """Every ~20 s per vEdge for a day, on three vEdges: no signal at all."""
    signals = [
        _sig(FTMD, "FTMD", offset_s=i * 20, host=f"vEdge-{d}")
        for d in (1, 2, 3) for i in range(4320)
    ]
    assert not any(signals)


def test_a_below_floor_signal_joins_a_component_it_is_grounded_to():
    """Rule 1: the warning cannot start an object, but it is evidence once one exists."""
    crit = _sig(CPU_CRIT, "SYSMGR")
    dns = _sig(DNS_FAIL, "VTRACKER", offset_s=5)
    snaps = _objects([crit, dns])
    assert len(snaps) == 1
    assert {n.kind for n in snaps[0].nodes} == {"device_resource_anomaly", "device_alarm"}


def _dns_template_ids() -> set[str]:
    return {t.id for t in builtin_catalog().templates
            if any("dns" in part for clause in t.requires for part in clause.kind.split("|"))}


def test_a_vbond_dns_line_can_never_produce_a_dns_template_top_hypothesis():
    """A device failing to resolve its own orchestrator says nothing about the internet's
    DNS. `sig.ent.internet.dns-impairment` needs one kind and names the ISP as owner, so
    feeding it these lines would blame the ISP in any component on that device, with no
    independent evidence. Run through the real ranker, with the lines as the only other
    evidence beside a critical line that opens the object, across every shape of the
    failure, and alone in numbers."""
    dns_ids = _dns_template_ids()
    assert "sig.ent.internet.dns-impairment" in dns_ids, "the guard lost its subject"
    dns_lines = [
        (DNS_FAIL, "VTRACKER"),
        (DNS_FAIL, "VDAEMON"),
        ("monitor_dns_callback[170]: DNS resolution failed for vbond.example.net via ", "VTRACKER"),
    ]
    windows = [
        [_sig(CPU_CRIT, "SYSMGR"), *[_sig(m, a, offset_s=5 + i) for i, (m, a) in enumerate(dns_lines)]],
        [_sig(CPU_CRIT, "SYSMGR"), *[_sig(DNS_FAIL, "VTRACKER", offset_s=i) for i in range(1, 200)]],
    ]
    for signals in windows:
        snaps = _objects(signals)
        assert len(snaps) == 1
        ranking = snaps[0].ranking
        assert ranking.top_hypothesis not in dns_ids
        for hyp in ranking.hypotheses:
            cited = " ".join(hyp.satisfied)
            assert "dns_" not in cited, f"{hyp.template_id} cites DNS evidence: {cited}"
            if hyp.template_id in dns_ids:
                assert hyp.confidence_rank < 0.3, f"{hyp.template_id} scored {hyp.confidence_rank}"


def test_no_pack_row_feeds_a_kind_a_dns_template_needs():
    """Structural, so a later row cannot reintroduce it: every kind a template names under a
    `dns` clause is out of reach for a pack line that talks about DNS."""
    dns_kinds = {part for t in builtin_catalog().templates for clause in t.requires
                 for part in clause.kind.split("|") if "dns" in part}
    assert "dns_failure_rate" in dns_kinds
    for rule in RULES:
        if rule.lane == "syslog" and "sdwan" in rule.rule_id:
            assert rule.kind not in dns_kinds, rule.rule_id


def test_dns_success_lines_emit_nothing_and_stay_out_of_the_screen():
    for msg in ("dnsclient_ares_callback[224]: DNS lookup succeeded for 0/vbond.example.net via none",
                "monitor_dns_callback[190]: DNS resolution successful for vbond.example.net via "):
        ev = {"hostname": "vEdge-1", "appname": "VTRACKER", "severity": "notice", "message": msg,
              "timestamp": T0.isoformat()}
        assert syslog_control_signal(dict(ev), "t1", T0) is None
        assert not syslog_promotable(ev)
