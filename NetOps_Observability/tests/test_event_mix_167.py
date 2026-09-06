# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 167 — the mini-ladder's workload must be able to TEST the signal-kind
template index, not just flatter it.

BACKGROUND. Tracker 167 gave the correlation catalog a signal-kind index so an
RCA object scores only the templates its kinds can match, instead of all 100.
Offline it measured **22 candidate templates per object of 100** and the tracker
is PASS offline. Its own evidence doc records the caveat that matters here
(`docs/scale/TEMPLATE_APPLICABILITY_167.md`, "Honest caveat on generality"): the
qualification workload is SINGLE-KIND (`link_state_change`), which is the
friendliest possible case for a kind index. 22 % is a property of that workload,
not of the platform, and 167's LIVE selectivity was therefore never validated —
the harness could not emit a workload capable of validating it.

`--event-mix realistic` is that workload. These tests pin the two properties it
has to have to be worth anything:

  * it really does produce MULTIPLE DISTINCT KINDS — asserted by running the
    generator's output through the engine's REAL classifier
    (`producers.syslog_control_signal`), never against a re-typed expectation;
  * it loses NOTHING. The generic device-alarm branch has a severity floor and
    ignores notice/info, so a plausible-looking `%SYS-5-CONFIG_I` at info
    severity yields NO signal at all. The first draft of the mix did exactly
    that: 28 of 400 events silently produced nothing and the "six-kind" mix was
    a five-kind mix. This test is why that was caught.

And the property the DEFAULT has to have:

  * `single` must stay byte-identical to the pre-change generator. Every
    capacity number in tracker 166's evidence trail was measured on it;
    changing the workload under the baseline would invalidate the comparison
    rather than extend it.

Run:  python3 -m pytest tests/test_event_mix_167.py -v
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src" / "correlation"))

import producers  # path set above


def _load_harness():
    """Import the hyphen-named harness by path, asserting the import stays
    side-effect-free (see test_scale_miniladder_group_parse for why PATH)."""
    path = ROOT / "scripts" / "scale-miniladder.py"
    spec = importlib.util.spec_from_file_location("scale_miniladder_mix", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    before = os.environ.get("PATH", "")
    sys.modules["scale_miniladder_mix"] = mod
    spec.loader.exec_module(mod)
    assert os.environ.get("PATH", "") == before
    return mod


ml = _load_harness()


def _ladder_class():
    for value in vars(ml).values():
        if isinstance(value, type) and hasattr(value, "_syslog_event"):
            return value
    raise AssertionError("no harness class exposing _syslog_event")


def _generator(mix: str):
    """A harness instance with ONLY what _syslog_event reads — no stack, no
    network, no run directory."""
    cls = _ladder_class()
    inst = cls.__new__(cls)
    inst.args = argparse.Namespace(event_mix=mix, profile="legacy")
    inst._mix = cls._mix_table(cls.EVENT_MIX_REALISTIC)
    inst._tables = cls._composed_tables()
    inst.profile = ml.WORKLOAD_PROFILES["legacy"]
    return inst


DEVICE = "mlx-t167abcd-00042"
SAMPLE = 1200


def _classify(mix: str, n: int = SAMPLE):
    """Run n generated events through the real engine classifier."""
    gen = _generator(mix)
    now = datetime.now(timezone.utc)
    kinds: dict[str, int] = {}
    scopes: set[str] = set()
    dropped: list[str] = []
    for seq in range(n):
        ev = json.loads(gen._syslog_event(DEVICE, seq))
        sig = producers.syslog_control_signal(ev, "t1", now)
        if sig is None:
            dropped.append(ev["appname"])
            continue
        kinds[sig.kind] = kinds.get(sig.kind, 0) + 1
        scopes.add(sig.entity_type.value)
    return kinds, scopes, dropped


# ── the realistic mix is actually multi-kind ─────────────────────────────────

def test_realistic_mix_yields_at_least_six_distinct_kinds():
    """The whole point. Asserted through the engine's own classifier, so a
    mnemonic that LOOKS like it should classify but does not cannot pass."""
    kinds, _scopes, _dropped = _classify("realistic")
    assert len(kinds) >= 6, f"only {len(kinds)} distinct kinds: {sorted(kinds)}"


def test_realistic_mix_spans_more_than_one_entity_scope():
    """Device-scoped and interface-scoped signals exercise different grounding
    paths; a mix confined to one scope would still be a soft test."""
    _kinds, scopes, _dropped = _classify("realistic")
    assert {"device", "interface"} <= scopes, f"scopes covered: {sorted(scopes)}"


def test_realistic_mix_drops_nothing():
    """THE regression this file exists for. Every injected event must become a
    signal: the generic device-alarm net has a severity floor, so an
    info-severity unrecognized mnemonic produces NOTHING — which both weakens
    the mix and makes the harness's injected-vs-persisted accounting harder to
    reason about. Caught live at 28/400 on the first draft."""
    _kinds, _scopes, dropped = _classify("realistic")
    assert not dropped, (
        f"{len(dropped)}/{SAMPLE} events produced no signal at all "
        f"(mnemonics: {sorted(set(dropped))}) — raise their severity above the "
        f"device-alarm floor or classify them explicitly")


def test_the_device_alarm_safety_net_is_exercised():
    """One arm of the mix is deliberately an UNRECOGNIZED mnemonic, so the
    generic fallback every unknown vendor log lands on is under test too."""
    kinds, _scopes, _dropped = _classify("realistic")
    assert kinds.get("device_alarm", 0) > 0, (
        "no event reached the generic device-alarm branch — the mix stopped "
        "covering the fallback path")


def test_every_declared_arm_of_the_mix_actually_appears():
    """A weight of zero, or an arm shadowed by an earlier classifier branch,
    would silently shrink the mix. Every declared arm must show up."""
    cls = _ladder_class()
    declared = {row[1] for row in cls.EVENT_MIX_REALISTIC}
    gen = _generator("realistic")
    seen = {json.loads(gen._syslog_event(DEVICE, seq))["appname"]
            for seq in range(SAMPLE)}
    assert declared == seen, f"declared but never emitted: {declared - seen}"


# ── determinism: accounting depends on it ────────────────────────────────────

def test_the_mix_is_deterministic_in_the_sequence_number():
    """No RNG. The harness's balance equation (injected == persisted + DLQ +
    counted loss) and run-to-run comparability both rest on this."""
    a, b = _generator("realistic"), _generator("realistic")
    for seq in (0, 1, 7, 99, 1000):
        ea = json.loads(a._syslog_event(DEVICE, seq))
        eb = json.loads(b._syslog_event(DEVICE, seq))
        ea.pop("timestamp"), eb.pop("timestamp")
        assert ea == eb, f"seq {seq} not reproducible"


def test_the_sequence_number_is_carried_for_traceability():
    """Every event keeps its `[mlx seq N]` marker in both modes — it is how a
    single event is traced end to end through the pipeline."""
    for mix in ("single", "realistic"):
        gen = _generator(mix)
        for seq in (0, 3, 250):
            ev = json.loads(gen._syslog_event(DEVICE, seq))
            assert f"[mlx seq {seq}]" in ev["message"], (mix, seq)


# ── the default must not have moved ──────────────────────────────────────────

def test_single_is_the_default():
    """Protecting the baseline: 166's whole evidence trail was measured on the
    single-kind workload."""
    assert ml.parse_args([]).event_mix == "single"


def test_the_mix_choices_are_closed():
    """An unknown --event-mix must be refused, not silently fall through to the
    realistic branch (`_syslog_event` treats anything != 'single' as the mix)."""
    with pytest.raises(SystemExit):
        ml.parse_args(["--event-mix", "chaos"])


def test_single_mode_is_still_one_mnemonic_and_one_kind():
    kinds, _scopes, dropped = _classify("single")
    assert not dropped
    assert set(kinds) == {"link_state_change"}, sorted(kinds)


def test_single_mode_payload_is_unchanged_shape():
    """The exact pre-change payload: LINK-3-UPDOWN, err severity, the
    GigabitEthernet0/<seq%48> interface walk and the alternating state."""
    gen = _generator("single")
    ev = json.loads(gen._syslog_event(DEVICE, 4))
    assert ev["appname"] == "LINK-3-UPDOWN"
    assert ev["severity"] == "err"
    assert ev["hostname"] == DEVICE
    assert ev["message"] == (
        "%LINK-3-UPDOWN: Interface GigabitEthernet0/4, "
        "changed state to down [mlx seq 4]")
    ev_odd = json.loads(gen._syslog_event(DEVICE, 5))
    assert "changed state to up" in ev_odd["message"]
