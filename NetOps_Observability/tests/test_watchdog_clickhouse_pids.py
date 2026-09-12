# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Watchdog fault-domain separation (2026-08-15 ClickHouse/cgroup incident).

The incident: the ClickHouse container's cgroup task charge reached its ceiling
(19046/19046) while only ~739 threads actually existed. Nothing could fork in
that cgroup, so `docker exec` failed — and because the watchdog probed the
DATABASE by exec'ing into it, it spent 12 hours reporting

    telemetry: ClickHouse did not answer the corr_signals freshness query
    (store unreachable or query rejected)

about a ClickHouse that answered every query put to it. A container-runtime
fault wore a database fault's clothes.

Two structural fixes are pinned here:

  * check_clickhouse_health probes ClickHouse over its REAL authenticated TLS
    endpoint from a DIFFERENT container's cgroup, so ClickHouse's own task
    ceiling can no longer blind the probe, and every failure mode gets its own
    name (UNREACHABLE / TLS / AUTH / QUERY / DATA_STALE / RUNTIME_EXEC).
  * check_pid_capacity reads HOST cgroup state (never exec) and names task
    saturation directly, including the leak signature — charged tasks far above
    observed live threads.

Both are executed for real with a fake `docker` on PATH and fake cgroup files,
following the fake-binary pattern established in test_watchdog_ship.py.
"""

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WATCHDOG = ROOT / "scripts" / "stack-watchdog.sh"

# The secret the fake .env carries; AT-8 asserts it never escapes into output.
FAKE_PW = "s3cr3t-must-never-appear"


def _extract(start_re: str) -> str:
    """Pull a self-contained block out of the watchdog for standalone execution."""
    out = subprocess.run(
        ["sed", "-n", f"/{start_re}/,/^}}/p", str(WATCHDOG)],
        check=True, capture_output=True, text=True,
    ).stdout
    assert out.strip(), f"block {start_re!r} not found in stack-watchdog.sh"
    return out


def _fake_docker(bindir: Path) -> Path:
    """A `docker` that is scriptable per-scenario through env vars.

    FAKE_EXEC_FAIL_SVC : exec into this service id fails like a broken runtime
    FAKE_PING_RC       : curl /ping exit code (0 = Ok.)
    FAKE_PING_ERR      : stderr text emitted when FAKE_PING_RC != 0
    FAKE_QUERY_BODY    : body returned for the authenticated query
    FAKE_NO_PROBE      : the probe container does not exist
    """
    p = bindir / "docker"
    p.write_text(
        "#!/bin/sh\n"
        'case "$1" in\n'
        "  ps)\n"
        # Return an id named after the requested compose service so exec can
        # tell which container it is being asked to enter.
        '    svc=$(printf "%s\\n" "$@" | sed -n "s/.*service=//p" | head -1)\n'
        '    if [ "$svc" = "$FAKE_NO_PROBE" ]; then exit 0; fi\n'
        '    echo "cid-$svc"\n'
        "    ;;\n"
        "  inspect)\n"
        '    echo "cid-inspected"\n'
        "    ;;\n"
        "  exec)\n"
        "    shift\n"
        '    [ "$1" = "-i" ] && shift\n'
        '    target="$1"\n'
        '    if [ -n "${FAKE_EXEC_FAIL_SVC:-}" ] && [ "$target" = "cid-$FAKE_EXEC_FAIL_SVC" ]; then\n'
        '      echo "OCI runtime exec failed: unable to start container process: procReady not received" >&2\n'
        "      exit 126\n"
        "    fi\n"
        # Distinguish the /ping call from the --config query call.
        '    case "$*" in\n'
        "      *ping*)\n"
        '        if [ "${FAKE_PING_RC:-0}" -ne 0 ]; then\n'
        '          printf "%s\\n" "${FAKE_PING_ERR:-error}" >&2\n'
        '          exit "${FAKE_PING_RC}"\n'
        "        fi\n"
        '        echo "Ok."\n'
        "        ;;\n"
        "      *--config*)\n"
        # Drain stdin so the config (with the password) is consumed, never echoed.
        "        cat >/dev/null\n"
        # %b: the built-in default carries a literal \n that must become a real
        # newline (M25 rejects a body that is not one clean integer line).
        '        printf "%b" "${FAKE_QUERY_BODY:-10\\nHTTP:200}"\n'
        "        ;;\n"
        "    esac\n"
        "    ;;\n"
        "esac\n"
    )
    p.chmod(0o755)
    return p


def _run_ch(tmp_path, **env_over):
    """Execute check_clickhouse_health standalone; return (proc, problems)."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    _fake_docker(bindir)
    envfile = tmp_path / "stack.env"
    envfile.write_text(f"CLICKHOUSE_USER=netops\nCLICKHOUSE_PASSWORD={FAKE_PW}\n")

    body = _extract("^CH_PROBE_FROM=")
    script = (
        f'SCRIPT_DIR="{tmp_path}"\nPROJECT=netops\n'
        f'CH_ENV_FILE="{envfile}"\n'
        # M25: docker rides the watchdog's bounded dkr wrapper.
        'dkr() { docker "$@"; }\n'
        + body
        + '\nproblems=()\ncheck_clickhouse_health "${STALE_MIN:-20}"\n'
        'printf "%s\\n" "${problems[@]:-}"\n'
    )
    env = os.environ.copy()
    env["PATH"] = f"{bindir}:{env['PATH']}"
    env.update({k: str(v) for k, v in env_over.items()})
    r = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
    problems = [ln for ln in r.stdout.splitlines() if ln.strip()]
    return r, problems


def _run_pids(tmp_path, current, maximum, live_threads=None, events="max 0"):
    """Execute check_pid_capacity against a fake cgroup tree."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    _fake_docker(bindir)
    cg = tmp_path / "cg" / "system.slice" / "docker-cid-inspected.scope"
    cg.mkdir(parents=True, exist_ok=True)
    (cg / "pids.current").write_text(f"{current}\n")
    (cg / "pids.max").write_text(f"{maximum}\n")
    (cg / "pids.events").write_text(f"{events}\n")
    # cgroup.procs holds this test process when we want a *low* live-thread
    # count relative to the charge (the leak signature).
    (cg / "cgroup.procs").write_text(f"{os.getpid()}\n" if live_threads else "")

    script = (
        'dkr() { docker "$@"; }\n'
        + _extract("^check_pid_capacity() {")
        + '\nproblems=()\ncheck_pid_capacity clickhouse cid-x\n'
        'printf "%s\\n" "${problems[@]:-}"\n'
    )
    env = os.environ.copy()
    env["PATH"] = f"{bindir}:{env['PATH']}"
    env["PID_CGROUP_ROOT"] = str(tmp_path / "cg")
    r = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
    return r, [ln for ln in r.stdout.splitlines() if ln.strip()]


# ---------------------------------------------------------------------------
# AT-1 — the incident itself: exec into ClickHouse is dead, ClickHouse is fine
# ---------------------------------------------------------------------------

def test_at1_clickhouse_exec_dead_but_database_healthy(tmp_path):
    # The probe never enters ClickHouse's cgroup, so a broken exec THERE is
    # invisible to it: the database reads healthy, because it is.
    r, problems = _run_ch(tmp_path, FAKE_EXEC_FAIL_SVC="clickhouse")
    assert r.returncode == 0, r.stderr
    assert problems == [], f"a dead ClickHouse exec must not raise anything: {problems}"


def test_at1b_probe_vantage_exec_failure_never_blames_the_database(tmp_path):
    # If the VANTAGE container's exec breaks, we lose observability — say so,
    # and say explicitly that it implies nothing about ClickHouse.
    r, problems = _run_ch(tmp_path, FAKE_EXEC_FAIL_SVC="vector-router")
    joined = " ".join(problems)
    assert "CONTAINER_RUNTIME_EXEC_FAILURE" in joined, problems
    assert "NOTHING about the database" in joined
    for forbidden in ("CLICKHOUSE_UNREACHABLE", "CLICKHOUSE_QUERY_FAILURE"):
        assert forbidden not in joined, f"transport fault misreported as {forbidden}"


# ---------------------------------------------------------------------------
# AT-2 / AT-3 — genuine database faults still surface, correctly named
# ---------------------------------------------------------------------------

def test_at2_clickhouse_really_unreachable(tmp_path):
    r, problems = _run_ch(tmp_path, FAKE_PING_RC=7, FAKE_PING_ERR="Connection refused")
    joined = " ".join(problems)
    assert "CLICKHOUSE_UNREACHABLE" in joined, problems
    assert "CONTAINER_RUNTIME_EXEC_FAILURE" not in joined


def test_at2b_tls_failure_is_its_own_class(tmp_path):
    r, problems = _run_ch(
        tmp_path, FAKE_PING_RC=60,
        FAKE_PING_ERR="SSL certificate problem: unable to get local issuer certificate")
    joined = " ".join(problems)
    assert "CLICKHOUSE_TLS_FAILURE" in joined, problems
    assert "CLICKHOUSE_UNREACHABLE" not in joined


def test_at3_data_stale_is_not_unreachable(tmp_path):
    # Reachable, query answered, but the newest signal is 40 minutes old.
    r, problems = _run_ch(tmp_path, FAKE_QUERY_BODY="2400\nHTTP:200", STALE_MIN=20)
    joined = " ".join(problems)
    assert "CLICKHOUSE_DATA_STALE" in joined, problems
    assert "40m old" in joined
    assert "UNREACHABLE" not in joined and "QUERY_FAILURE" not in joined


def test_auth_failure_is_not_an_outage(tmp_path):
    r, problems = _run_ch(tmp_path, FAKE_QUERY_BODY="Authentication failed\nHTTP:516")
    joined = " ".join(problems)
    assert "CLICKHOUSE_AUTH_FAILURE" in joined, problems
    assert "REACHABLE" in joined


def test_fresh_data_reports_nothing(tmp_path):
    r, problems = _run_ch(tmp_path, FAKE_QUERY_BODY="10\nHTTP:200")
    assert problems == [], problems


def test_missing_probe_container_is_unknown_not_healthy(tmp_path):
    r, problems = _run_ch(tmp_path, FAKE_NO_PROBE="vector-router")
    joined = " ".join(problems)
    assert "CANNOT PROBE" in joined and "UNKNOWN, not healthy" in joined, problems


# ---------------------------------------------------------------------------
# AT-4 / AT-5 / AT-6 — pid capacity thresholds
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("cur,mx,expected", [
    (6000, 10000, None),                      # 60% — below warning
    (7000, 10000, "PID_CAPACITY_WARNING"),    # AT-4
    (8600, 10000, "PID_CAPACITY_HIGH"),
    (9600, 10000, "PID_CAPACITY_CRITICAL"),   # AT-5
    (10000, 10000, "PID_LIMIT_REACHED"),      # AT-6
])
def test_pid_capacity_thresholds(tmp_path, cur, mx, expected):
    r, problems = _run_pids(tmp_path, cur, mx)
    joined = " ".join(problems)
    if expected is None:
        assert not any("PID_" in p for p in problems), problems
    else:
        assert expected in joined, problems


def test_at6_ceiling_message_names_the_consequence(tmp_path):
    _, problems = _run_pids(tmp_path, 19046, 19046)
    joined = " ".join(problems)
    assert "PID_LIMIT_REACHED" in joined
    # The operator must learn that forking is what breaks, and that the service
    # itself may be fine — the two facts missing during the real incident.
    assert "CANNOT create new processes or threads" in joined
    assert "answers normally" in joined


def test_uncapped_pids_max_is_not_arithmetic(tmp_path):
    # pids.max is the literal string "max" when uncapped — must not divide by it.
    r, problems = _run_pids(tmp_path, 500, "max")
    assert r.returncode == 0, r.stderr
    assert problems == [], problems


def test_leak_signature_reports_observation_not_diagnosis(tmp_path):
    # The incident shape: charge far above live threads.
    _, problems = _run_pids(tmp_path, 19046, 19046, live_threads=True, events="max 8123")
    joined = " ".join(problems)
    assert "PID_LEAK_SUSPECTED" in joined, problems
    assert "pids.events:max=8123" in joined
    # Must NOT assert a runc/kernel bug we have not proven.
    assert "observation, not a diagnosis" in joined
    for unproven in ("runc bug", "kernel bug"):
        assert unproven not in joined.lower()


# ---------------------------------------------------------------------------
# M25 — the freshness "age" is only ever mined from a CLEAN HTTP-200 reply.
#
# ClickHouse error bodies are FULL of digits (error codes, byte counts, server
# versions). The pre-fix parse ran tr -dc '0-9-' over the whole body before
# looking at the HTTP status, so an UNKNOWN_TABLE / READONLY / memory-limit
# exception became a plausible concatenated "age" that silently passed — or
# fired DATA_STALE about — the staleness compare. HTTP != 200 must be a named
# CLICKHOUSE_QUERY_FAILURE before any number is extracted, and even a 200 body
# must match ^-?[0-9]{1,12}$ to be treated as an age.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("body", [
    pytest.param(
        "Code: 60. DB::Exception: Table netops.corr_signals does not exist. "
        "(UNKNOWN_TABLE) (version 24.8.1.2026 (official build))\nHTTP:404",
        id="unknown-table-404"),
    pytest.param(
        "Code: 242. DB::Exception: Table is in readonly mode "
        "(TABLE_IS_READ_ONLY) (version 24.8.1.2026)\nHTTP:503",
        id="readonly-503"),
    pytest.param(
        "Code: 241. DB::Exception: Memory limit (total) exceeded: would use "
        "9.32 GiB (attempt to allocate chunk of 4194304 bytes), maximum: 9.31 "
        "GiB (MEMORY_LIMIT_EXCEEDED)\nHTTP:500",
        id="memory-limit-500"),
])
def test_m25_error_bodies_are_query_failure_not_bogus_age(tmp_path, body):
    r, problems = _run_ch(tmp_path, FAKE_QUERY_BODY=body, STALE_MIN=20)
    joined = " ".join(problems)
    assert "CLICKHOUSE_QUERY_FAILURE" in joined, (
        f"an error body must be a named QUERY_FAILURE, got: {problems}")
    assert "CLICKHOUSE_DATA_STALE" not in joined, (
        "digits mined out of an error body must never drive the staleness "
        f"compare: {problems}")


def test_m25_clean_number_with_non200_is_query_failure(tmp_path):
    # A parsable number under a failing HTTP status is still not an age.
    r, problems = _run_ch(tmp_path, FAKE_QUERY_BODY="86400\nHTTP:500", STALE_MIN=20)
    joined = " ".join(problems)
    assert "CLICKHOUSE_QUERY_FAILURE" in joined, problems
    assert "CLICKHOUSE_DATA_STALE" not in joined, problems


def test_m25_http200_garbage_body_is_query_failure(tmp_path):
    r, problems = _run_ch(
        tmp_path, FAKE_QUERY_BODY="warning: 123 partial 456\nHTTP:200", STALE_MIN=20)
    joined = " ".join(problems)
    assert "CLICKHOUSE_QUERY_FAILURE" in joined, (
        f"a 200 body that is not one integer must not be arithmetic'd: {problems}")
    assert "CLICKHOUSE_DATA_STALE" not in joined, problems


def test_m25_negative_age_clock_skew_is_not_stale(tmp_path):
    # Negative by clock skew: a valid integer, and not stale.
    r, problems = _run_ch(tmp_path, FAKE_QUERY_BODY="-42\nHTTP:200", STALE_MIN=20)
    assert problems == [], problems


# ---------------------------------------------------------------------------
# AT-8 — the credential never escapes
# ---------------------------------------------------------------------------

def test_at8_password_never_appears_in_output(tmp_path):
    for over in ({"FAKE_QUERY_BODY": "10\nHTTP:200"},
                 {"FAKE_QUERY_BODY": "Authentication failed\nHTTP:516"},
                 {"FAKE_PING_RC": 7, "FAKE_PING_ERR": "Connection refused"},
                 {"FAKE_EXEC_FAIL_SVC": "vector-router"}):
        r, problems = _run_ch(tmp_path, **over)
        blob = r.stdout + r.stderr + " ".join(problems)
        assert FAKE_PW not in blob, f"credential leaked with {over}"


def test_password_is_not_passed_on_a_command_line(tmp_path):
    # Structural: the query call must hand curl a --config on stdin. A password
    # in argv would be visible in `ps` on the host and inside the container.
    body = _extract("^CH_PROBE_FROM=")
    assert "--config -" in body, "the authenticated query must read its config from stdin"
    assert "-u " not in body and "--user " not in body, \
        "credentials must not ride the command line"
