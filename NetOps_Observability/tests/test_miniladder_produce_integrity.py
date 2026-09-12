# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""The injector delivers every record, or it says so (2026-08-29).

THE DEFECT THIS PINS. Run `p2-s04b-08290858` failed accounting with

    [FAIL] accounting — 901 events UNEXPLAINED (injected 870001, persisted
           869100, counted losses 1.0) — silent drop

and the finger pointed at the platform. It was not the platform. Measured
after the fact:

  * `netops.syslog` gained exactly 869,100 harness records — the same number
    OpenSearch held (kafka end-offset delta minus the aggregator's organic
    produce, stable to the record across four different measurement windows);
  * Vector's source received them all and its OpenSearch sink sent them all;
  * every one of the 901 missing events fell in ONE 10,000-event produce
    chunk (seq 790000–799999 → 9,099 indexed), the chunk whose produce call
    took 22.73 s.

So a single `kafka-console-producer.sh` invocation dropped 901 of its 10,000
records and exited 0. It is an ASYNCHRONOUS producer: a record that cannot be
delivered reaches an `ErrorLoggingCallback`, which LOGS it and leaves the exit
code alone. Its shipped defaults make that routine under load —
`--request-timeout-ms` is 1500 and `--message-send-max-retries` is 3, while
the broker was so saturated that its own 2 s internal heartbeats to itself
were timing out for the whole burst. `Stack.produce` read only `rc`, threw the
stderr away, and reported success (`return True, ""`) — the §16.1
accept-and-ignore defect, in the one place the whole balance equation trusts.

What these tests hold:
  * a logged send failure under exit 0 FAILS the produce, naming how many
    records and quoting the log line (mutant: judge by rc alone ⇒ red);
  * the hardened producer settings are actually passed, as the DEDICATED
    flags — ConsoleProducer writes its own option defaults into the producer
    properties, so `--producer-property request.timeout.ms=…` is not
    guaranteed to survive them;
  * retries are made safe by idempotent produce (a duplicate is as dishonest
    as a loss: it inflates the same balance);
  * the tool bound outlives `delivery.timeout.ms`, so a batch still
    legitimately retrying is never killed by `docker exec`;
  * a failure reason is NEVER empty (the `--cleanup-only` lesson: "purge
    failed: " with no reason at all);
  * unrecognised stderr is a failure, not a shrug.

Run:  python3 -m pytest tests/test_miniladder_produce_integrity.py -v
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))


def _load_harness():
    path = ROOT / "scripts" / "scale-miniladder.py"
    spec = importlib.util.spec_from_file_location("scale_miniladder_produce", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    before = os.environ.get("PATH", "")
    sys.modules["scale_miniladder_produce"] = mod
    spec.loader.exec_module(mod)
    # The harness pins a cron-safe PATH for its own subprocesses; importing it
    # for the parsers must not repoint the test session's PATH (that once made
    # every shellcheck suite fail with "No such file or directory").
    assert os.environ.get("PATH", "") == before
    return mod


ml = _load_harness()

# The console producer's two real loss shapes, copied from the tool's own
# ErrorLoggingCallback / producer exception text rather than paraphrased.
SEND_ERROR_LINE = (
    "[2026-08-29 09:12:14,880] ERROR Error when sending message to topic "
    "netops.syslog with key: 6 bytes, value: 214 bytes with error: "
    "(org.apache.kafka.clients.producer.internals.ErrorLoggingCallback)")
EXPIRY_LINE = (
    "org.apache.kafka.common.errors.TimeoutException: Expiring 84 record(s) "
    "for netops.syslog-3:1503 ms has passed since batch creation")


class FakeStack:
    """A `Stack` with only `produce` real; `kafka_tool` is the seam under test.

    Built with `__new__` so no container, broker or env file is touched — the
    method's whole contract is "what do you conclude from (rc, stderr)".
    """

    def __init__(self, rc: int = 0, err: str = "") -> None:
        self.rc = rc
        self.err = err
        self.calls: list[dict] = []

    def kafka_tool(self, tool, args, input_text=None, timeout=0,
                   config_flag="--command-config"):
        self.calls.append({"tool": tool, "args": list(args),
                           "input_text": input_text, "timeout": timeout,
                           "config_flag": config_flag})
        return self.rc, "", self.err


def _stack(rc: int = 0, err: str = "") -> object:
    s = ml.Stack.__new__(ml.Stack)
    fake = FakeStack(rc, err)
    s.kafka_tool = fake.kafka_tool          # type: ignore[method-assign]
    s._probe = fake                          # test handle, not harness state
    return s


def _lines(n: int = 10) -> list[str]:
    return [f'{{"hostname": "mlx-t-{i:05d}", "message": "x"}}' for i in range(n)]


# --------------------------------------------------------------------------
# 1. THE DEFECT: exit 0 with logged send failures is a LOSS, not a success.
# --------------------------------------------------------------------------

def test_logged_send_failure_under_exit_zero_fails_the_produce():
    """Pre-fix this returned (True, "") and 901 records vanished from the
    balance equation with the platform blamed for it."""
    s = _stack(rc=0, err="\n".join([SEND_ERROR_LINE] * 3))
    ok, reason = s.produce("netops.syslog", _lines(10000))
    assert ok is False
    assert "3" in reason and "10000" in reason          # rows, not "a failure"
    assert "netops.syslog" in reason
    assert "Error when sending message" in reason        # the evidence itself


def test_batch_expiry_exception_is_a_send_failure():
    """The exact shape a 1.5 s ack deadline produces under a loaded broker."""
    s = _stack(rc=0, err=EXPIRY_LINE)
    ok, reason = s.produce("netops.syslog", _lines())
    assert ok is False
    assert "Expiring 84 record(s)" in reason


def test_clean_run_still_succeeds():
    s = _stack(rc=0, err="")
    assert s.produce("netops.syslog", _lines()) == (True, "")


def test_whitespace_only_stderr_is_still_clean():
    s = _stack(rc=0, err="   \n \n")
    assert s.produce("netops.syslog", _lines()) == (True, "")


def test_unrecognised_error_stderr_fails_unknown_is_not_clean():
    s = _stack(rc=0, err="[2026-08-29 09:12:14,880] ERROR something new here")
    ok, reason = s.produce("netops.syslog", _lines())
    assert ok is False
    assert "unrecognised stderr" in reason
    assert "something new here" in reason


def test_benign_stderr_warns_but_does_not_fail(capsys):
    """No error/exception marker: not a known loss shape, so it must not fail
    the run — but it must not be swallowed either (16.1)."""
    s = _stack(rc=0, err="Note: some harmless chatter")
    ok, reason = s.produce("netops.syslog", _lines())
    assert (ok, reason) == (True, "")
    assert "harmless chatter" in capsys.readouterr().err


# --------------------------------------------------------------------------
# 2. A non-zero exit still fails — and NEVER with an empty reason.
# --------------------------------------------------------------------------

def test_nonzero_exit_reports_code_and_stderr():
    s = _stack(rc=1, err="Connection to node -1 could not be established")
    ok, reason = s.produce("netops.syslog", _lines())
    assert ok is False
    assert "exit 1" in reason
    assert "could not be established" in reason


def test_nonzero_exit_with_no_output_still_states_the_exit_code():
    """The `--cleanup-only` lesson: a reason of "" diagnoses nothing."""
    s = _stack(rc=124, err="")
    ok, reason = s.produce("netops.syslog", _lines())
    assert ok is False
    assert reason.strip()
    assert "124" in reason and "[no output]" in reason


# --------------------------------------------------------------------------
# 3. The hardened producer settings actually reach the tool.
# --------------------------------------------------------------------------

def _args_of(s) -> list[str]:
    return s._probe.calls[0]["args"]


def _flag(args: list[str], name: str) -> str:
    return args[args.index(name) + 1]


def _props(args: list[str]) -> dict:
    out = {}
    for i, a in enumerate(args):
        if a == "--producer-property":
            k, _, v = args[i + 1].partition("=")
            out[k] = v
    return out


def test_ack_deadline_is_not_the_tools_1500ms_default():
    s = _stack()
    s.produce("netops.syslog", _lines())
    got = int(_flag(_args_of(s), "--request-timeout-ms"))
    assert got != 1500, "the 1.5 s default is what expired 901 records"
    assert got >= 30000


def test_retries_are_not_the_tools_3_default_and_are_time_bounded():
    s = _stack()
    s.produce("netops.syslog", _lines())
    args = _args_of(s)
    assert int(_flag(args, "--message-send-max-retries")) > 3
    # Unbounded retries are only safe because delivery.timeout.ms bounds them
    # in TIME (§9: every IO bounded).
    delivery = int(_props(args)["delivery.timeout.ms"])
    assert 0 < delivery <= 600000
    assert delivery > int(_flag(args, "--request-timeout-ms"))


def test_retries_cannot_duplicate_a_record():
    """A duplicate inflates the same balance equation a loss deflates."""
    props = _props(_args_of(_produced()))
    assert props["enable.idempotence"] == "true"
    # Idempotence is only ACCEPTED with acks=all and in-flight <= 5.
    assert int(props["max.in.flight.requests.per.connection"]) <= 5


def test_acks_are_all():
    s = _produced()
    assert _flag(_args_of(s), "--request-required-acks") == "-1"


def test_buffer_full_blocks_rather_than_drops():
    assert int(_props(_args_of(_produced()))["max.block.ms"]) > 0


def test_settings_use_dedicated_flags_not_producer_property():
    """ConsoleProducer writes its own option defaults into the producer
    properties, so these three must be the dedicated flags or the defaults win
    silently — the exact way a 1500 ms deadline survives being 'configured'."""
    props = _props(_args_of(_produced()))
    for k in ("request.timeout.ms", "retries", "acks"):
        assert k not in props
    args = _args_of(_produced())
    for f in ("--request-timeout-ms", "--message-send-max-retries",
              "--request-required-acks"):
        assert f in args


def _produced(lines: int = 10):
    s = _stack()
    s.produce("netops.syslog", _lines(lines))
    return s


# --------------------------------------------------------------------------
# 4. The tool bound must not kill a batch that is still legitimately retrying.
# --------------------------------------------------------------------------

def test_tool_timeout_outlives_the_delivery_deadline():
    s = _produced()
    call = s._probe.calls[0]
    delivery_s = int(_props(call["args"])["delivery.timeout.ms"]) / 1000.0
    assert call["timeout"] > delivery_s, (
        "docker exec would kill a record still inside its delivery deadline — "
        "trading a silent drop for a needless loud one")


def test_tool_timeout_still_scales_with_payload():
    small = _produced(10)._probe.calls[0]["timeout"]
    huge = _produced(10_000_000)._probe.calls[0]["timeout"]
    assert huge > small


def test_producer_config_flag_is_the_console_producer_spelling():
    assert _produced()._probe.calls[0]["config_flag"] == "--producer.config"


# --------------------------------------------------------------------------
# 5. Keying is unchanged by the hardening (the 2026-08-22 tenant-key finding).
# --------------------------------------------------------------------------

def test_key_is_rejected_when_it_would_corrupt_the_separator():
    s = _stack()
    ok, reason = s.produce("netops.syslog", _lines(), key="a\tb")
    assert ok is False and "tab" in reason
    assert s._probe.calls == [], "nothing may be produced on a bad key"


def test_keyed_payload_shape_and_flags():
    s = _stack()
    s.produce("netops.syslog", ['{"a": 1}', '{"b": 2}'], key="global")
    call = s._probe.calls[0]
    assert call["input_text"] == 'global\t{"a": 1}\nglobal\t{"b": 2}\n'
    assert "parse.key=true" in call["args"]
    assert "key.separator=\t" in call["args"]


def test_unkeyed_payload_is_the_legacy_shape():
    s = _stack()
    s.produce("netops.syslog", ['{"a": 1}'], key=None)
    call = s._probe.calls[0]
    assert call["input_text"] == '{"a": 1}\n'
    assert "parse.key=true" not in call["args"]


def test_topic_is_passed_through():
    s = _produced()
    assert _flag(_args_of(s), "--topic") == "netops.syslog"


# --------------------------------------------------------------------------
# 6. Mutants: each asserts the detector is not accidentally trivial.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("line", [SEND_ERROR_LINE, EXPIRY_LINE])
def test_send_error_pattern_matches_both_real_shapes(line):
    assert ml.PRODUCER_SEND_ERROR_RE.search(line)


@pytest.mark.parametrize("line", [
    "Produced 10000 records",
    "[2026-08-29 09:12:14,880] INFO Instantiated an idempotent producer.",
    "",
])
def test_send_error_pattern_does_not_match_ordinary_output(line):
    assert not ml.PRODUCER_SEND_ERROR_RE.search(line)


def test_one_failure_line_among_many_clean_ones_is_still_a_failure():
    """A detector that required the FIRST line to be the error, or that
    counted whole-stderr matches rather than lines, would pass this wrongly."""
    noise = ["[..] INFO ok"] * 50
    s = _stack(rc=0, err="\n".join(noise[:25] + [SEND_ERROR_LINE] + noise[25:]))
    ok, reason = s.produce("netops.syslog", _lines())
    assert ok is False
    assert " 1 send failure(s)" in reason
