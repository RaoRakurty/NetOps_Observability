# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix
"""The real syslog edge, then the engine's real stage [5] (tracker 387, plan PR 10).

These four cases send frames through the shipped syslog-ng + Vector edge and count
the objects the engine opens from what arrives. They live in the correlation suite
because stage [5] imports `catalog`, which needs pydantic; the ingest-contracts job
installs only pyyaml and pytest, on purpose. The edge harness itself stays in
`tests/` and is shared, so both suites drive the same edge.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import catalog
import engine
import producers as P

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
import syslog_edge_harness as H

SYSLOG_NG = ROOT / "deployment" / "docker" / "syslog-ng"
VECTOR_YAML = ROOT / "deployment" / "docker" / "vector" / "vector.yaml"
FIVE_HOURS = timedelta(hours=5)
_SKIP = ("docker is unavailable, so the edge-to-stage-[5] cases DID NOT RUN against the "
         "shipped syslog-ng config. Run them before shipping.")


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=30,
                              check=False).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


@pytest.fixture(scope="module")
def edge() -> Iterator[H.Edge]:
    if not _docker_available():
        pytest.skip(_SKIP)
    with H.running_edge(SYSLOG_NG, VECTOR_YAML,
                        registry=[("vEdge-1", "lab"), ("router1", "lab")]) as running:
        yield running


def _objects_opened(docs: list[dict], now: datetime, stamp: str | None) -> tuple[int, int]:
    """Stage [5] over what the edge delivered: (signals, objects)."""
    sigs = []
    for d in docs:
        doc = dict(d) if stamp is None else {**d, "timestamp": stamp}
        sig = P.syslog_control_signal(doc, "t1", now)
        if sig:
            sigs.append(sig)
    sigs.sort(key=lambda s: (s.ts, s.signal_id))
    return len(sigs), len(engine.run_window(tuple(sigs), catalog.builtin_catalog(), ()))


_FIXED_NOW = datetime(2026, 11, 9, 10, 0, tzinfo=timezone.utc)
_FIXED_STAMP = "2026-11-09T09:59:00Z"

IOS_FAULT = (b"<187>25170: Nov  9 09:00:01.123: %LINK-3-UPDOWN: Interface Gi1, changed state to down",
             b"<189>25171: Nov  9 09:00:02.123: %LINEPROTO-5-UPDOWN: Line protocol on Interface Gi1, changed state to down")
IOS_SHUTDOWN = (b"<189>25172: Nov  9 09:00:01.123: %LINK-5-CHANGED: Interface Gi1, changed state to administratively down",
                b"<189>25173: Nov  9 09:00:02.123: %LINEPROTO-5-UPDOWN: Line protocol on Interface Gi1, changed state to down")


def test_a_real_ios_link_fault_opens_one_object(edge: H.Edge) -> None:
    docs = [edge.send(f) for f in IOS_FAULT]
    assert _objects_opened(docs, _FIXED_NOW, _FIXED_STAMP)[1] == 1


def test_an_ios_shutdown_opens_nothing(edge: H.Edge) -> None:
    """Both of its lines, as the box logs them, through stage [5]."""
    docs = [edge.send(f) for f in IOS_SHUTDOWN]
    assert _objects_opened(docs, _FIXED_NOW, _FIXED_STAMP)[1] == 0


def test_an_eos_link_fault_still_opens(edge: H.Edge) -> None:
    doc = edge.send(b"<149>Nov  9 09:00:01 edge01 Ebra: %LINEPROTO-5-UPDOWN: Line protocol on "
                    b"Interface Ethernet1, changed state to down")
    assert _objects_opened([doc], _FIXED_NOW, _FIXED_STAMP)[1] == 1


def _bsd(at: datetime) -> str:
    return f"{at.strftime('%b')} {at.day:2d} {at.strftime('%H:%M:%S')}"


def _iso(at: datetime) -> str:
    return at.strftime("%Y-%m-%dT%H:%M:%S.") + f"{at.microsecond // 1000:03d}Z"


def test_a_device_five_hours_behind_still_correlates_with_a_frame_on_time(edge: H.Edge) -> None:
    """THE REGRESSION. Each line can open an object alone, so two objects means they never
    met: the gap between them was five hours. One object means they correlated."""
    now = datetime.now(timezone.utc)
    behind = edge.send(f"<187>{_bsd(now - FIVE_HOURS)} r5 %LINK-3-UPDOWN: Interface Gi1, "
                       f"changed state to down".encode())
    on_time = edge.send(f"<186>1 {_iso(now)} r5 chassisd 1 - - a critical line no rule knows".encode())
    assert behind["hostname"] == on_time["hostname"] == "r5"
    assert _objects_opened([behind, on_time], datetime.now(timezone.utc), None) == (2, 1)
