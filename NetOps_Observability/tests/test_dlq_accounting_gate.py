"""Tracker 159 — the accounting gate judges DLQ reasons, not a raw count.

The mini-ladder failed `accounting` every night on a non-empty DLQ. But the DLQ
was 100% `identity_unattributable` / TenantClaimRefused — the §3a zero-trust
tenant check refusing events it cannot attribute, counting them, and sealing the
payload (F-11). That is the system working, and the lab carries a standing
~7,530/hour background of it. A gate that can never pass is not a gate, and it
meant the one channel where a NEW loss would show up was permanently red.

The fix must NOT be "ignore the DLQ". These tests pin the three ways it still
fails: an unreadable DLQ, any unexpected reason at a single line, and expected
reasons above their envelope.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os

import pytest

SPEC = importlib.util.spec_from_file_location(
    "scale_miniladder",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "scripts", "scale-miniladder.py"))
ml = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ml)


class FakeStack:
    def __init__(self, out="", rc=0, cid="cc"):
        self._out, self._rc, self._cid = out, rc, cid

    def cid(self, _svc):
        return self._cid


def _reasons(monkeypatch, out, rc=0, cid="cc"):
    """Drive Stack.dlq_run_reasons against a canned `docker exec` result."""
    monkeypatch.setattr(ml, "run", lambda *a, **k: (rc, out, ""))
    stack = object.__new__(ml.Stack)
    stack.cid = lambda _svc: cid
    return ml.Stack.dlq_run_reasons(stack, "RUNID")


def test_expected_reason_is_recognised(monkeypatch):
    """Records carry the runid here (the chbatch shape); refusals are covered
    by the identity-sha tests below, since they carry no runid at all."""
    out = "\n".join(
        '{"reason": "identity_unattributable", "lane": "syslog", "rid": "RUNID"}'
        for _ in range(5))
    assert _reasons(monkeypatch, out) == {"identity_unattributable": 5}


def test_reasons_are_counted_per_kind(monkeypatch):
    out = ('{"reason": "identity_unattributable", "rid": "RUNID"}\n'
           '{"reason": "schema_violation", "rid": "RUNID"}\n'
           '{"reason": "identity_unattributable", "rid": "RUNID"}\n')
    assert _reasons(monkeypatch, out) == {
        "identity_unattributable": 2, "schema_violation": 1}


def test_unparseable_lines_are_surfaced_not_dropped(monkeypatch):
    """A line we cannot read is its own reason — never silently skipped."""
    got = _reasons(
        monkeypatch,
        'not json at all but RUNID is in it\n'
        '{"reason": "identity_unattributable", "rid": "RUNID"}\n')
    assert got["(unparseable DLQ line)"] == 1
    assert got["identity_unattributable"] == 1


def test_a_failed_read_returns_empty_so_the_caller_can_fail(monkeypatch):
    """Unknown is not clean — the gate turns {} into a FAIL when lines exist."""
    assert _reasons(monkeypatch, "", rc=1) == {}


def test_no_correlation_container_returns_empty(monkeypatch):
    assert _reasons(monkeypatch, "", cid="") == {}


# --- the policy constants --------------------------------------------------

def test_identity_unattributable_is_the_only_expected_reason():
    """Widening this set is a deliberate act, not a drive-by."""
    assert ml.DLQ_EXPECTED_REASONS == frozenset({"identity_unattributable"})


def test_the_envelope_is_bounded_and_small():
    assert 0 < ml.DLQ_EXPECTED_MAX_FRACTION <= 0.02, (
        "the expected-reason envelope must stay tight enough to fail a real "
        "attribution regression")


def test_the_envelope_admits_the_observed_worst_run_but_not_a_regression():
    """786 of 600,001 was the worst observed run (0.13%)."""
    injected = 600_001
    envelope = int(injected * ml.DLQ_EXPECTED_MAX_FRACTION)
    assert envelope >= 786, "the gate would fail a run we know is healthy"
    assert envelope < 786 * 10, "a 10x attribution regression must still fail"


@pytest.mark.parametrize("reason", [
    "schema_violation", "handler_exception", "poison_payload", "",
])
def test_any_other_reason_is_unexpected(reason):
    assert reason not in ml.DLQ_EXPECTED_REASONS


# --- identity-aware attribution (2026-08-19) --------------------------------
#
# THE HOLE THIS CLOSES. `dlq_run_reasons` grepped the dead-letter file for the
# runid. A tenant-refusal record deliberately withholds the payload and the
# plaintext hostname (F-11 / INV-F11-10) and keeps only
# `identity_sha` = sha256(identity) — so a run's own refusals contain the runid
# NOWHERE and matched nothing. Measured on ladder 08191832j027: 133,349 refused
# events belonging to that run's devices, and the gate reported 95.


def _refusal(identity: str) -> str:
    return json.dumps({
        "ts": "2026-08-19T19:01:00Z", "topic": "deadletter:syslog",
        "lane": "syslog", "reason": "identity_unattributable",
        "identity_sha": hashlib.sha256(identity.encode()).hexdigest(),
        "error": "TenantClaimRefused: identity_unattributable (payload withheld)",
    })


def _shas(names):
    return {hashlib.sha256(n.encode()).hexdigest(): i for i, n in enumerate(names)}


def test_refusals_are_invisible_without_identity_shas(monkeypatch):
    """The defect, pinned: no runid in the record, so a grep sees nothing."""
    mine = [f"mlx-RUNID-{i:05d}" for i in range(3)]
    out = "\n".join(_refusal(n) for n in mine)
    got = _reasons(monkeypatch, out)          # no shas passed
    assert got == {}, "a runid grep cannot see refusals — that was the hole"


def test_refusals_are_counted_when_identity_shas_are_supplied(monkeypatch):
    mine = [f"mlx-RUNID-{i:05d}" for i in range(3)]
    out = "\n".join(_refusal(n) for n in mine)
    monkeypatch.setattr(ml, "run", lambda *a, **k: (0, out, ""))
    stack = object.__new__(ml.Stack)
    stack.cid = lambda _svc: "cc"
    got = ml.Stack.dlq_run_reasons(stack, "RUNID", _shas(mine))
    assert got == {"identity_unattributable": 3}


def test_another_runs_refusals_are_not_charged_to_us(monkeypatch):
    """Attribution must be OURS only — the DLQ is shared across runs."""
    mine = [f"mlx-RUNID-{i:05d}" for i in range(2)]
    theirs = [f"mlx-OTHER-{i:05d}" for i in range(5)]
    out = "\n".join(_refusal(n) for n in mine + theirs)
    monkeypatch.setattr(ml, "run", lambda *a, **k: (0, out, ""))
    stack = object.__new__(ml.Stack)
    stack.cid = lambda _svc: "cc"
    got = ml.Stack.dlq_run_reasons(stack, "RUNID", _shas(mine))
    assert got == {"identity_unattributable": 2}, (
        "a neighbouring run's refusals were charged to this run")


def test_runid_matching_still_works_alongside_shas(monkeypatch):
    """The chbatch records DO carry the runid in their payload."""
    rec = json.dumps({"ts": "t", "topic": "chbatch:netops.corr_signals",
                      "error": "clickhouse rejected the batched insert",
                      "payload": '{"entity_id": "mlx-RUNID-00007:Gi0/1"}'})
    monkeypatch.setattr(ml, "run", lambda *a, **k: (0, rec, ""))
    stack = object.__new__(ml.Stack)
    stack.cid = lambda _svc: "cc"
    got = ml.Stack.dlq_run_reasons(stack, "RUNID", {})
    assert got == {"(no reason field)": 1}


def test_unparseable_line_is_only_ours_if_it_names_the_run(monkeypatch):
    out = "garbage-with-RUNID-in-it\nunrelated-garbage\n"
    monkeypatch.setattr(ml, "run", lambda *a, **k: (0, out, ""))
    stack = object.__new__(ml.Stack)
    stack.cid = lambda _svc: "cc"
    got = ml.Stack.dlq_run_reasons(stack, "RUNID", {})
    assert got == {"(unparseable DLQ line)": 1}
