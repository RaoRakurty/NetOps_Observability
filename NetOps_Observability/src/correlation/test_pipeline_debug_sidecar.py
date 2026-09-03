"""Pipeline debugger — the correlation container's bounded debug endpoints.

docs/design/PIPELINE_DEBUGGER_2026-09-04.md §2 (stage 3, the bus) and §4 (the
runtime log level). Go has no Kafka client by design (CLAUDE.md §6), so the API
cannot look at the bus itself; this container already speaks aiokafka, so the
peek lives here and the API proxies it.

WHAT IS PINNED HERE, and why each line is a defect that would otherwise ship:

  * DEFAULT-CLOSED. With CORR_DEBUG_TOKEN unset the routes answer 503 and say
    so — they are never open "because the port is internal" (§3: no implicit
    trust between services).
  * The bearer check is constant-time and the empty token authorizes nothing.
  * Every untrusted field is validated against a CLOSED grammar and every
    numeric field is CLAMPED — a caller cannot ask for an unbounded scan.
  * A broker fault is a 502 that NAMES the fault, never an empty record list.
    "we could not look" rendered as "it was not there" is the exact inversion
    the whole feature exists to prevent.
  * The peek consumer carries NO group id, so it can neither join the engine's
    consumer group nor move its offsets.
  * The log level auto-reverts from a timer armed IN THIS PROCESS, so a dead
    caller cannot leave the service at debug.

Run:  python3 -m pytest src/correlation/test_pipeline_debug_sidecar.py -v
"""
from __future__ import annotations

import inspect
import json
import logging

import pytest

import main


MARKER = "01j9abcdefghjkmnpqrstvwxyz"


@pytest.fixture(autouse=True)
def _token(monkeypatch):
    monkeypatch.setattr(main, "CORR_DEBUG_TOKEN", "unit-test-token")
    monkeypatch.setattr(main, "DEBUG_LEVEL_REVERT_TIMER", None)
    yield
    if main.DEBUG_LEVEL_REVERT_TIMER is not None:
        main.DEBUG_LEVEL_REVERT_TIMER.cancel()


def auth(tok: str = "unit-test-token") -> str:
    return "Bearer " + tok


def peek_body(**over) -> bytes:
    body = {"topic": "netops.syslog", "marker": MARKER}
    body.update(over)
    return json.dumps(body).encode()


# ── default-closed ──────────────────────────────────────────────────────────

def test_unconfigured_deployment_refuses_and_explains(monkeypatch):
    monkeypatch.setattr(main, "CORR_DEBUG_TOKEN", "")
    status, _, body = main._sidecar_debug_response("/debug/kafka-peek", peek_body(), auth())
    assert status == 503
    assert "CORR_DEBUG_TOKEN" in json.loads(body)["detail"]


def test_unconfigured_token_authorizes_nothing(monkeypatch):
    """The empty string is not a password: an unset token must not be matchable
    by sending an empty bearer."""
    monkeypatch.setattr(main, "CORR_DEBUG_TOKEN", "")
    assert main._debug_authorized("Bearer ") is False
    assert main._debug_authorized("Bearer") is False
    assert main._debug_authorized(None) is False


@pytest.mark.parametrize("header", [None, "", "Basic x", "Bearer wrong", "unit-test-token"])
def test_bad_or_missing_credentials_are_401(header):
    status, _, _ = main._sidecar_debug_response("/debug/kafka-peek", peek_body(), header)
    assert status == 401


def test_correct_bearer_is_accepted_case_insensitively():
    seen = {}

    def runner(params):
        seen.update(params)
        return {"records": [], "scanned": 0, "elapsed_s": 0.0, "truncated": False}

    status, _, _ = main._sidecar_debug_response(
        "/debug/kafka-peek", peek_body(), "bearer unit-test-token", peek_runner=runner)
    assert status == 200 and seen["marker"] == MARKER


# ── closed grammars + clamping ──────────────────────────────────────────────

@pytest.mark.parametrize("bad", [
    {"topic": "netops.syslog; DROP", "marker": MARKER},
    {"topic": "", "marker": MARKER},
    {"topic": "netops.syslog", "marker": "short"},
    {"topic": "netops.syslog", "marker": MARKER.upper() + "X"},
    {"topic": "netops.syslog", "marker": "01j9abcdefghjkmnpqrstvwxy!"},
])
def test_closed_grammars_refuse_bad_input(bad):
    status, _, body = main._sidecar_debug_response(
        "/debug/kafka-peek", json.dumps(bad).encode(), auth())
    assert status == 400, body


def test_marker_is_case_normalised_not_rejected():
    p = main._debug_peek_params(json.dumps(
        {"topic": "netops.syslog", "marker": MARKER.upper()}).encode())
    assert p["marker"] == MARKER


def test_numeric_fields_are_clamped_not_trusted():
    p = main._debug_peek_params(peek_body(
        max_seconds=9999, max_records=10_000, lookback_seconds=10**9))
    assert p["max_seconds"] == main.CORR_DEBUG_PEEK_MAX_S
    assert p["max_records"] == main.CORR_DEBUG_MAX_RECORDS
    assert p["lookback_seconds"] == main.CORR_DEBUG_MAX_LOOKBACK_S


def test_oversized_body_is_refused_before_parsing():
    with pytest.raises(ValueError):
        main._debug_peek_params(b"x" * (main.CORR_DEBUG_MAX_BODY + 1))


def test_non_json_body_is_a_400_not_a_traceback():
    status, _, body = main._sidecar_debug_response("/debug/kafka-peek", b"{oops", auth())
    assert status == 400 and "not JSON" in json.loads(body)["detail"]


def test_unknown_path_is_404():
    status, _, _ = main._sidecar_debug_response("/debug/anything", b"{}", auth())
    assert status == 404


# ── honest failure ──────────────────────────────────────────────────────────

def test_broker_failure_is_a_502_that_names_it_not_an_empty_result():
    """THE inversion this feature exists to prevent: a failed look must never
    render as 'the marker was not on the bus'."""
    def boom(_params):
        raise RuntimeError("kafka unreachable")

    before = main.DEBUG_PEEK_ERRORS
    status, _, body = main._sidecar_debug_response(
        "/debug/kafka-peek", peek_body(), auth(), peek_runner=boom)
    assert status == 502
    detail = json.loads(body)["detail"]
    assert "kafka unreachable" in detail and "RuntimeError" in detail
    assert main.DEBUG_PEEK_ERRORS == before + 1


def test_matching_records_are_returned_verbatim():
    def runner(_p):
        return {"records": [{"topic": "netops.syslog", "partition": 2,
                             "offset": 41, "timestamp_ms": 1700,
                             "excerpt": "cx_debug=" + MARKER}],
                "scanned": 12, "elapsed_s": 0.4, "truncated": False}

    status, ctype, body = main._sidecar_debug_response(
        "/debug/kafka-peek", peek_body(), auth(), peek_runner=runner)
    got = json.loads(body)
    assert status == 200 and ctype == "application/json"
    assert got["records"][0]["offset"] == 41 and got["scanned"] == 12


# ── the peek cannot perturb the engine ──────────────────────────────────────

def test_peek_consumer_is_group_less_and_never_commits():
    """A debug read must not be able to join netops-correlation, trigger a
    rebalance, or move a committed offset."""
    src = inspect.getsource(main._debug_kafka_peek)
    # Scan the CODE, not the docstring that explains the rule.
    doc = main._debug_kafka_peek.__doc__ or ""
    src = src.replace(doc, "")
    assert "group_id" not in src, "the peek consumer must not carry a group id"
    assert "enable_auto_commit=False" in src
    assert "commit(" not in src
    assert "seek_to_beginning" not in src, "a peek must never replay a topic from the start"
    assert "offsets_for_times" in src, "the peek must seek by a bounded lookback time"


# ── log level + auto-revert ─────────────────────────────────────────────────

@pytest.mark.parametrize("bad", [{"level": "trace"}, {"level": ""}, {"level": "warn"}])
def test_level_grammar_is_closed(bad):
    status, _, _ = main._sidecar_debug_response(
        "/debug/loglevel", json.dumps(bad).encode(), auth())
    assert status == 400


def test_level_window_is_capped_at_thirty_minutes():
    assert main._debug_level_params(
        json.dumps({"level": "debug", "for_seconds": 99999}).encode())["for_seconds"] == 1800.0


def test_raising_to_debug_arms_an_auto_revert_in_this_process():
    status, _, body = main._sidecar_debug_response(
        "/debug/loglevel", json.dumps({"level": "debug", "for_seconds": 60}).encode(), auth())
    got = json.loads(body)
    assert status == 200 and got["applied"] is True and got["level"] == "debug"
    assert got["revert_at_unix"] is not None
    assert main.DEBUG_LEVEL_REVERT_TIMER is not None, "no auto-revert armed — a dead caller would leave the service at debug"
    assert logging.getLogger().level == logging.DEBUG
    # explicit revert cancels the pending timer and drops the level
    main._sidecar_debug_response(
        "/debug/loglevel", json.dumps({"level": "info"}).encode(), auth())
    assert main.DEBUG_LEVEL_REVERT_TIMER is None
    assert logging.getLogger().level == logging.INFO


def test_second_raise_replaces_rather_than_stacks_the_timer():
    main._sidecar_debug_response(
        "/debug/loglevel", json.dumps({"level": "debug", "for_seconds": 60}).encode(), auth())
    first = main.DEBUG_LEVEL_REVERT_TIMER
    main._sidecar_debug_response(
        "/debug/loglevel", json.dumps({"level": "debug", "for_seconds": 90}).encode(), auth())
    assert main.DEBUG_LEVEL_REVERT_TIMER is not first
    assert not first.is_alive() or first.finished.is_set()
    main._sidecar_debug_response(
        "/debug/loglevel", json.dumps({"level": "info"}).encode(), auth())


# ── the GET surface is unchanged ────────────────────────────────────────────

def test_get_sidecar_still_serves_only_health_and_metrics():
    main._publish_health_snapshot()
    assert main._sidecar_response("/healthz")[0] == 200
    status, _, _ = main._sidecar_response("/debug/kafka-peek")
    assert status == 404, "the debug routes must not be reachable by GET"
