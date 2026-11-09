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
from producers import syslog_control_signal, syslog_promotable

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
    assert {n.kind for n in snaps[0].nodes} == {"device_resource_anomaly", "dns_failure_rate"}
