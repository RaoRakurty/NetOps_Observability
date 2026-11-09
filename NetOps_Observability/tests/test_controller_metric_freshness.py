# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Controller statistics arrive 30-60 minutes late; nothing may assume otherwise.

vManage publishes approute/interface/QoS/system statistics in closed 10-minute
buckets behind a settle watermark (nms/vmanage_metrics.go), so a sample is
stamped 30-60 minutes in the past when it lands. An instant query (5-minute
lookback) or an alert rule on `controller_metric_*` without a lookback sees
NOTHING and reads as "no data" (tracker 357, lab 2026-10-18).

Readers today: the device page's controller panel
(pages/device/ControllerOverview.tsx), which uses last_over_time(...[3h]).
This test keeps every alert rule and that panel honest.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "src" / "config"
PANEL = ROOT / "src" / "frontend" / "src" / "pages" / "device" / "ControllerOverview.tsx"

_DURATION = re.compile(r"\[(\d+)([smhdw])\]")
_UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def _rule_exprs():
    for f in sorted(CONFIG.glob("rules*.yaml")):
        for m in re.finditer(r"^\s*expr:\s*(.+(?:\n\s{6,}.+)*)", f.read_text(), re.M):
            yield f.name, m.group(1)


def test_no_alert_rule_reads_controller_metrics_without_an_hour_of_lookback():
    offenders = []
    for name, expr in _rule_exprs():
        if "controller_metric_" not in expr:
            continue
        windows = [int(n) * _UNIT[u] for n, u in _DURATION.findall(expr)]
        if "last_over_time" not in expr or not windows or max(windows) < 3600:
            offenders.append(f"{name}: {expr.strip()[:120]}")
    assert not offenders, (
        "an alert rule reads controller_metric_* without last_over_time over >= 1h; "
        "the samples land 30-60 minutes late, so it would never fire: " + "; ".join(offenders))


def test_the_device_panel_reads_controller_metrics_with_a_lookback():
    src = PANEL.read_text()
    m = re.search(r'const LOOKBACK = "(\d+)([smhdw])"', src)
    assert m, "ControllerOverview no longer declares its LOOKBACK"
    assert int(m.group(1)) * _UNIT[m.group(2)] >= 3600, "the controller panel's lookback is under an hour"
    # Every KPI (an instant read) goes through last(), i.e. last_over_time(...[LOOKBACK]).
    stats = re.findall(r"<MetricStat[^>]*query=\{`([^`]*)`\}", src)
    assert stats, "no MetricStat found — the test is not looking at the panel"
    bare = [q for q in stats if "controller_metric_" in q and "last(" not in q]
    assert not bare, f"instant reads without the lookback: {bare}"
