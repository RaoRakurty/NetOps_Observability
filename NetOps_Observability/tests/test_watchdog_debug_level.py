# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Watchdog DEBUG_LEVEL_STUCK problem class (pipeline debugger W2(d), 2026-09-04).

`correlix-debug logs` raises a module's runtime log level to debug for a bounded
window. Three reverts are supposed to bring it back down — the CLI at the end of
the window, the CLI on Ctrl-C, and the timer the module arms inside its own
process (src/backend/internal/pipedebug/levelswitch.go). All three live INSIDE
the stack. The watchdog block pinned here is the fourth and the only EXTERNAL
one: the layer that still works when the api is itself the thing that is wedged,
which is precisely the case where the in-process timer did not fire. A module
left at debug fills the disk, costs ingest throughput and writes tenant payloads
into logs that ship in support bundles — an incident of its own.

The metric contract it reads (all four ALWAYS exported, including when 0):

    netops_debug_level_active{module="…"}            0|1
    netops_debug_level_revert_at_seconds{module="…"} unix seconds, 0 = none armed
    netops_debug_parse_marker_active                 0|1
    netops_debug_parse_marker_revert_at_seconds      unix seconds, 0 = none armed

What is asserted here, and why each one is a defect class rather than a nicety:

  * past the window -> DEBUG_LEVEL_STUCK, NAMING the module(s);
  * revert_at == 0 (no auto-revert armed at all) -> the MORE serious wording,
    never a nonsense 55-year duration — `time() - 0` is unix-now;
  * VictoriaMetrics renders large values with %g, so that unix-now arrives as
    "1.78e+09"; `${v%%.*}` on it yields "1", which a naive shape check passes
    and then compares as ONE SECOND, i.e. reports the worst case as healthy.
    Pinned explicitly (test_exponential_…);
  * revert_at in the future, and level 0 -> silence;
  * the series ABSENT -> a quiet named gap in the log, never a pass and never a
    page ("always exported even when 0" is what makes absence mean "this api
    cannot be checked at all");
  * a failed query -> SKIPPED, a malformed value -> UNKNOWN. Never healthy;
  * DEBUG_LEVEL_CHECK=0 -> the block does not run at all (no query issued).

Everything runs the FULL script with `docker` and `curl` faked on PATH, so the
assertions are over what the watchdog actually emits, not over its source.
"""

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WATCHDOG = ROOT / "scripts" / "stack-watchdog.sh"

# The encoded constants the block sends. Kept here (not imported) so a silent
# rewrite of a query is a test failure rather than a test that follows it.
Q_LEVEL_ACTIVE = "query=max%28netops_debug_level_active%29"
Q_LEVEL_MODULES = "query=netops_debug_level_active%20%3D%3D%201"
Q_LEVEL_PAST = (
    "query=max%28netops_debug_level_active%20%2A%20%28time%28%29%20-%20"
    "netops_debug_level_revert_at_seconds%29%29"
)
Q_MARKER_ACTIVE = "query=max%28netops_debug_parse_marker_active%29"
Q_MARKER_PAST = (
    "query=max%28netops_debug_parse_marker_active%20%2A%20%28time%28%29%20-%20"
    "netops_debug_parse_marker_revert_at_seconds%29%29"
)


FAKE_DOCKER = r'''#!/bin/sh
# A healthy fake stack whose VictoriaMetrics answers are scripted per query.
#
#   FAKE_NO_VICTORIA=1        no victoria container in the project
#   FAKE_VM_FAIL=1            every debug query fails like a wedged exec
#   FAKE_LEVEL_ACTIVE=<v>     max(netops_debug_level_active)          ("" = no series)
#   FAKE_LEVEL_PAST=<v>       max(active * (time() - revert_at))      ("" = no series)
#   FAKE_MODULES="api ..."    labels the `== 1` naming query returns
#   FAKE_MODULES_BAD=1        the naming query answers an unusable body
#   FAKE_PM_ACTIVE=<v>        max(netops_debug_parse_marker_active)
#   FAKE_PM_PAST=<v>          max(marker * (time() - revert_at))
#   VM_QUERY_LOG=<path>       every exec'd command line is appended here
vm_vector() {   # $1 = sample value; empty -> a successful EMPTY result
  if [ -z "$1" ]; then
    printf '{"status":"success","data":{"resultType":"vector","result":[]}}'
  else
    printf '{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1756900000,"%s"]}]}}' "$1"
  fi
}
vm_modules() { # $* = module names
  if [ -z "$*" ]; then
    printf '{"status":"success","data":{"resultType":"vector","result":[]}}'
    return
  fi
  out='{"status":"success","data":{"resultType":"vector","result":['
  sep=""
  for m in $*; do
    out="$out$sep{\"metric\":{\"__name__\":\"netops_debug_level_active\",\"module\":\"$m\"},\"value\":[1756900000,\"1\"]}"
    sep=","
  done
  printf '%s]}}' "$out"
}
case "$1" in
  ps)
    svc=$(printf '%s\n' "$@" | sed -n 's/.*service=//p' | head -1)
    [ -n "$svc" ] || exit 0
    if [ -n "${FAKE_NO_VICTORIA:-}" ] && [ "$svc" = "victoria" ]; then exit 0; fi
    echo "cid-$svc"
    ;;
  inspect)
    case "$2$3" in
      *StartedAt*)    echo "" ;;
      *RestartCount*) echo "0 false 0" ;;
      *State.Status*) echo "running" ;;
      *State.Health*) echo "healthy" ;;
      *)              echo "" ;;
    esac
    ;;
  exec)
    shift
    [ "$1" = "-i" ] && shift
    shift   # container id
    [ -n "${VM_QUERY_LOG:-}" ] && printf '%s\n' "$*" >> "$VM_QUERY_LOG"
    case "$*" in
      *netops_debug_*)
        if [ -n "${FAKE_VM_FAIL:-}" ]; then
          echo "wget: server returned error: HTTP/1.1 503 Service Unavailable" >&2
          exit 8
        fi
        case "$*" in
          *"netops_debug_level_active%20%3D%3D%201"*)
            if [ -n "${FAKE_MODULES_BAD:-}" ]; then
              printf 'upstream connect error'
            else
              vm_modules ${FAKE_MODULES:-}
            fi ;;
          *"netops_debug_level_revert_at_seconds%29%29"*) vm_vector "${FAKE_LEVEL_PAST-}" ;;
          *"max%28netops_debug_level_active%29"*)         vm_vector "${FAKE_LEVEL_ACTIVE-}" ;;
          *"netops_debug_parse_marker_revert_at_seconds%29%29"*) vm_vector "${FAKE_PM_PAST-}" ;;
          *"max%28netops_debug_parse_marker_active%29"*)  vm_vector "${FAKE_PM_ACTIVE-}" ;;
          *) printf 'unexpected debug query' ;;
        esac ;;
      *"/proc/net/snmp"*)
        printf 'Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors\n'
        printf 'Udp: 100 0 0 50 0 0\n' ;;
      *ALERTS*) echo '{}' ;;
      *wget*)   echo '{"status":"success","data":{"result":[{"value":[1756900000,"5"]}]}}' ;;
      *--config*)
        cfg=$(cat)
        case "$cfg" in
          *corr_signals*) printf '10\nHTTP:200' ;;
          *_count*)          echo '{"count":42}' ;;
          *nodes/stats*)     echo '{"indices":{"indexing":{"doc_status":{"4xx":0}}}}' ;;
          *_cluster/health*) echo '{"status":"green"}' ;;
          *_cat/snapshots*)  printf '[{"id":"s1","status":"SUCCESS","end_epoch":"%s"}]' "$(date +%s)" ;;
        esac ;;
      *ping*) echo "Ok." ;;
      *) exit 1 ;;
    esac
    ;;
esac
exit 0
'''

FAKE_CURL = r'''#!/bin/sh
printf 'CURL %s\n' "$*" >> "$CURL_LOG"
case "$*" in
  */admin/version*) printf '{"version":"0.1.0","sha":"cafebabe"}\nHTTP:200' ;;
  *http_code*)      printf '200' ;;
esac
exit 0
'''


def _write_exec(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _layout(tmp_path: Path):
    """A packaged-style install: the script, its env file, and fake tools."""
    etc = tmp_path / "etc"
    etc.mkdir()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    _write_exec(bindir / "docker", FAKE_DOCKER)
    _write_exec(bindir / "curl", FAKE_CURL)

    stack_env = tmp_path / "stack.env"
    stack_env.write_text("CLICKHOUSE_USER=netops\nCLICKHOUSE_PASSWORD=fake-ch-pw\n")

    # Same sanctioned seam the other watchdog suites use: prepend the fake
    # bindir to the script's OWN explicit PATH export (§16.2).
    content = WATCHDOG.read_text()
    assert 'export PATH="' in content, "stack-watchdog.sh lost its explicit PATH export"
    (etc / "stack-watchdog.sh").write_text(
        content.replace('export PATH="', f'export PATH="{bindir}:', 1))
    (etc / "stack-watchdog.sh").chmod(0o755)

    (etc / "stack-watchdog.env").write_text(
        "COMPOSE_PROJECT='netops'\n"
        "APP_URL='http://localhost:8000/'\n"
        "NTFY_TOPIC='correlix-test-topic'\n"
        f"CH_ENV_FILE='{stack_env}'\n"
        "DISK_WARN_PCT='101'\n"
        # The two sibling probes that share the victoria container lookup are
        # OFF here on purpose. It keeps the assertions about this block alone —
        # and it pins the guard extension: the lookup that populates eng_cid
        # must fire for DEBUG_LEVEL_CHECK too, or every test below would report
        # "no running victoria container" instead of reading the gauges.
        "ENGINE_CONSUMER_CHECK='0'\n"
        "SNAPSHOT_RESTORABLE_CHECK='0'\n"
    )
    return etc


def _run(tmp_path: Path, etc: Path, name: str, **knobs):
    env = os.environ.copy()
    env.update({
        "WATCHDOG_ENV": str(etc / "stack-watchdog.env"),
        "CURL_LOG": str(tmp_path / f"curl.{name}.log"),
        "VM_QUERY_LOG": str(tmp_path / f"vmq.{name}.log"),
    })
    env.update({k: str(v) for k, v in knobs.items()})
    r = subprocess.run(["bash", str(etc / "stack-watchdog.sh")],
                       env=env, capture_output=True, text=True, timeout=300)
    assert r.returncode in (0, 1), f"unexpected exit {r.returncode}:\n{r.stderr}"
    queries = (tmp_path / f"vmq.{name}.log").read_text() \
        if (tmp_path / f"vmq.{name}.log").exists() else ""
    pushes = (tmp_path / f"curl.{name}.log").read_text() \
        if (tmp_path / f"curl.{name}.log").exists() else ""
    return r, queries, pushes


NOW = 1788000000   # a plausible unix-now; only its ORDER of magnitude matters


# ---------------------------------------------------------------------------
# It fires — and names the module
# ---------------------------------------------------------------------------

def test_level_past_its_window_fires_and_names_the_module(tmp_path):
    etc = _layout(tmp_path)
    r, queries, _ = _run(tmp_path, etc, "past",
                         FAKE_LEVEL_ACTIVE="1", FAKE_LEVEL_PAST="900",
                         FAKE_MODULES="correlation")
    assert "DEBUG_LEVEL_STUCK" in r.stderr, r.stderr
    assert "PAST the auto-revert window" in r.stderr, r.stderr
    assert "correlation" in r.stderr, (
        f"the stuck module must be NAMED, not merely counted:\n{r.stderr}")
    assert "15m past" in r.stderr, f"the overrun must be quantified:\n{r.stderr}"
    # The remedies, all three, plus the runbook.
    assert 'PUT /api/debug/loglevel' in r.stderr and '"level":"info"' in r.stderr
    assert "correlix-debug logs" in r.stderr
    assert "in-process timer" in r.stderr
    assert "docs/runbooks/pipeline-debug.md" in r.stderr
    assert Q_LEVEL_MODULES in queries, (
        f"the naming query must actually be issued:\n{queries}")
    # The shared victoria lookup is guarded by the three checks that need it;
    # this run has the other two OFF, so a query landing at all proves
    # DEBUG_LEVEL_CHECK was added to that guard.
    assert Q_LEVEL_ACTIVE in queries, queries
    assert "no running victoria container" not in r.stderr, r.stderr


def test_several_stuck_modules_are_all_named(tmp_path):
    etc = _layout(tmp_path)
    r, _, _ = _run(tmp_path, etc, "multi",
                   FAKE_LEVEL_ACTIVE="1", FAKE_LEVEL_PAST="1800",
                   FAKE_MODULES="api correlation")
    assert "DEBUG_LEVEL_STUCK" in r.stderr
    assert "api" in r.stderr and "correlation" in r.stderr, r.stderr


def test_within_the_grace_does_not_fire(tmp_path):
    """The armed deadline has passed by less than the grace: the scrape, the
    revert timer and this one-minute cron all have to fit inside it."""
    etc = _layout(tmp_path)
    r, _, _ = _run(tmp_path, etc, "grace",
                   FAKE_LEVEL_ACTIVE="1", FAKE_LEVEL_PAST="120",
                   FAKE_MODULES="api")
    assert "DEBUG_LEVEL_STUCK" not in r.stderr, r.stderr


def test_grace_is_configurable(tmp_path):
    etc = _layout(tmp_path)
    r, _, _ = _run(tmp_path, etc, "grace-cfg", DEBUG_LEVEL_STUCK_GRACE_SEC="60",
                   FAKE_LEVEL_ACTIVE="1", FAKE_LEVEL_PAST="120",
                   FAKE_MODULES="api")
    assert "DEBUG_LEVEL_STUCK" in r.stderr, r.stderr


def test_a_nonsense_grace_is_refused_not_defaulted(tmp_path):
    """A typo'd grace must not silently become 'compare against garbage'."""
    etc = _layout(tmp_path)
    r, _, _ = _run(tmp_path, etc, "grace-bad", DEBUG_LEVEL_STUCK_GRACE_SEC="5m",
                   FAKE_LEVEL_ACTIVE="1", FAKE_LEVEL_PAST="900",
                   FAKE_MODULES="api")
    assert "debug-level probe SKIPPED" in r.stderr, r.stderr
    assert "DEBUG_LEVEL_STUCK_GRACE_SEC" in r.stderr, r.stderr
    assert "UNKNOWN, not healthy" in r.stderr, r.stderr


# ---------------------------------------------------------------------------
# revert_at == 0 — the MORE serious condition, not a 55-year duration
# ---------------------------------------------------------------------------

def test_no_auto_revert_armed_is_reported_as_such(tmp_path):
    """`time() - 0` is unix-now. That is not "stuck for 55 years", it is "this
    raise will never expire on its own" — the worse of the two states."""
    etc = _layout(tmp_path)
    r, _, _ = _run(tmp_path, etc, "norevert",
                   FAKE_LEVEL_ACTIVE="1", FAKE_LEVEL_PAST=str(NOW),
                   FAKE_MODULES="api")
    assert "DEBUG_LEVEL_STUCK" in r.stderr, r.stderr
    assert "NO auto-revert armed" in r.stderr, r.stderr
    assert "api" in r.stderr
    assert "PAST the auto-revert window" not in r.stderr, (
        "the unset revert time must not be reported as an overrun duration")
    # 1788000000 / 60 = 29800000 minutes. Reporting that would be the defect.
    assert not re.search(r"\b\d{5,}m past\b", r.stderr), (
        f"a 55-year 'duration' leaked into the message:\n{r.stderr}")


def test_exponential_sample_value_is_normalised_not_truncated_to_one(tmp_path):
    """VictoriaMetrics renders large values with %g, so unix-now arrives as
    "1.788e+09". `${v%%.*}` yields "1" — which passes a naive ^[0-9]+$ check and
    then compares as ONE SECOND, reporting the WORST state (no revert armed at
    all) as comfortably inside its window. §16.1's swallow, in numeric form."""
    etc = _layout(tmp_path)
    r, _, _ = _run(tmp_path, etc, "expo",
                   FAKE_LEVEL_ACTIVE="1", FAKE_LEVEL_PAST="1.788e+09",
                   FAKE_MODULES="api")
    assert "DEBUG_LEVEL_STUCK" in r.stderr, (
        f"an exponential sample value was read as ~1 second:\n{r.stderr}")
    assert "NO auto-revert armed" in r.stderr, r.stderr


def test_a_future_revert_time_does_not_fire(tmp_path):
    """A raise INSIDE its window is the normal case for the whole feature; it
    must be silent or `correlix-debug logs` pages every time it is used."""
    etc = _layout(tmp_path)
    r, _, pushes = _run(tmp_path, etc, "future",
                        FAKE_LEVEL_ACTIVE="1", FAKE_LEVEL_PAST="-240",
                        FAKE_MODULES="api")
    assert "DEBUG_LEVEL_STUCK" not in r.stderr, r.stderr
    assert "NetOps advisory" not in pushes, f"no push for a healthy raise: {pushes}"


def test_level_inactive_fires_nothing_and_asks_no_further_questions(tmp_path):
    etc = _layout(tmp_path)
    r, queries, _ = _run(tmp_path, etc, "inactive",
                         FAKE_LEVEL_ACTIVE="0", FAKE_PM_ACTIVE="0")
    assert "DEBUG_LEVEL_STUCK" not in r.stderr, r.stderr
    assert "debug-level probe SKIPPED" not in r.stderr, r.stderr
    assert Q_LEVEL_ACTIVE in queries, "the gauge must still be read every run"
    assert Q_LEVEL_MODULES not in queries, (
        "nothing is raised — the naming query is wasted work:\n" + queries)
    assert Q_LEVEL_PAST not in queries, queries


# ---------------------------------------------------------------------------
# Absence is not health
# ---------------------------------------------------------------------------

def test_absent_series_is_a_quiet_named_gap_never_a_pass(tmp_path):
    """The gauges are exported even when they read 0, so ABSENCE means this api
    predates the debug routes or is not scraped — i.e. a stuck level would not
    be detected here at all. Say so once, quietly; never page, never pass."""
    etc = _layout(tmp_path)
    r, _, pushes = _run(tmp_path, etc, "absent",
                        FAKE_LEVEL_ACTIVE="", FAKE_PM_ACTIVE="")
    assert "DEBUG_LEVEL_STUCK" not in r.stderr, "an unmeasurable state is not an outage"
    assert "debug-level probe SKIPPED" not in r.stderr, "absence is not a probe failure"
    assert "netops_debug_level_active is absent" in r.stderr, (
        f"the gap must be NAMED in the log:\n{r.stderr}")
    assert "netops_debug_parse_marker_active is absent" in r.stderr, r.stderr
    assert "would go undetected on this deployment" in r.stderr, (
        "the log line must say what is NOT being checked, not merely that a "
        f"series is missing:\n{r.stderr}")
    assert "NetOps advisory" not in pushes and "NetOps stack DOWN" not in pushes, (
        f"a missing series must not page:\n{pushes}")


def test_active_but_no_revert_series_is_stuck_not_silent(tmp_path):
    """The level gauge says raised and the revert gauge is absent: nothing
    proves the level ever comes back down. That is the stuck class, not a
    quiet 'not checked' — the raise itself was measured."""
    etc = _layout(tmp_path)
    r, _, _ = _run(tmp_path, etc, "no-revert-series",
                   FAKE_LEVEL_ACTIVE="1", FAKE_LEVEL_PAST="", FAKE_MODULES="vector")
    assert "DEBUG_LEVEL_STUCK" in r.stderr, r.stderr
    assert "NO revert timestamp is exported" in r.stderr, r.stderr
    assert "vector" in r.stderr


# ---------------------------------------------------------------------------
# A probe that cannot run is never a pass
# ---------------------------------------------------------------------------

def test_failed_victoria_query_is_skipped_never_healthy(tmp_path):
    etc = _layout(tmp_path)
    r, _, _ = _run(tmp_path, etc, "vmfail", FAKE_VM_FAIL=1)
    assert "debug-level probe SKIPPED" in r.stderr, r.stderr
    assert "parse-marker probe SKIPPED" in r.stderr, r.stderr
    assert "victoria query failed" in r.stderr, r.stderr
    assert r.returncode == 1, "a probe that could not run must fail the run"


def test_non_numeric_value_is_unknown_never_healthy(tmp_path):
    etc = _layout(tmp_path)
    r, _, _ = _run(tmp_path, etc, "nan", FAKE_LEVEL_ACTIVE="1.2.3",
                   FAKE_PM_ACTIVE="1.2.3")
    assert "debug-level probe SKIPPED" in r.stderr, r.stderr
    assert "parse-marker probe SKIPPED" in r.stderr, r.stderr
    assert "UNKNOWN, not as healthy" in r.stderr, r.stderr
    assert "1.2.3" in r.stderr, "the offending value must be quoted back"


def test_non_numeric_window_value_is_unknown_never_healthy(tmp_path):
    etc = _layout(tmp_path)
    r, _, _ = _run(tmp_path, etc, "nan-window", FAKE_LEVEL_ACTIVE="1",
                   FAKE_LEVEL_PAST="1.2.3", FAKE_MODULES="api")
    assert "debug-level probe SKIPPED" in r.stderr, r.stderr
    assert "UNKNOWN, not as healthy" in r.stderr, r.stderr
    assert "DEBUG_LEVEL_STUCK" not in r.stderr, (
        "an unreadable window is UNKNOWN — it must not be asserted as stuck "
        "either")


def test_unnamed_modules_still_report_the_raise(tmp_path):
    """The naming query failing must not turn a real stuck level into silence:
    the raise was measured, only the label was not."""
    etc = _layout(tmp_path)
    r, _, _ = _run(tmp_path, etc, "noname", FAKE_LEVEL_ACTIVE="1",
                   FAKE_LEVEL_PAST="900", FAKE_MODULES_BAD=1)
    assert "DEBUG_LEVEL_STUCK" in r.stderr, r.stderr
    assert "names UNAVAILABLE" in r.stderr, r.stderr
    assert "module-label query returned no usable body" in r.stderr, r.stderr


def test_missing_victoria_container_is_a_named_skip(tmp_path):
    etc = _layout(tmp_path)
    r, _, _ = _run(tmp_path, etc, "novm", FAKE_NO_VICTORIA=1)
    assert "debug-level probe SKIPPED: no running victoria container" in r.stderr, r.stderr
    assert "whether a module was left at debug" in r.stderr, r.stderr


# ---------------------------------------------------------------------------
# The parser decision-trace marker (no module label, same class, own wording)
# ---------------------------------------------------------------------------

def test_parse_marker_past_its_window_fires(tmp_path):
    etc = _layout(tmp_path)
    r, _, _ = _run(tmp_path, etc, "pm-past", FAKE_LEVEL_ACTIVE="0",
                   FAKE_PM_ACTIVE="1", FAKE_PM_PAST="600")
    assert "DEBUG_LEVEL_STUCK" in r.stderr, r.stderr
    assert "parser decision-trace marker filter is still ON PAST" in r.stderr, r.stderr
    assert "10m past" in r.stderr, r.stderr
    assert "docs/runbooks/pipeline-debug.md" in r.stderr


def test_parse_marker_with_no_auto_revert_armed_fires_with_its_own_wording(tmp_path):
    etc = _layout(tmp_path)
    r, _, _ = _run(tmp_path, etc, "pm-norevert", FAKE_LEVEL_ACTIVE="0",
                   FAKE_PM_ACTIVE="1", FAKE_PM_PAST=str(NOW))
    assert "DEBUG_LEVEL_STUCK" in r.stderr, r.stderr
    assert "marker filter is ON with NO auto-revert armed" in r.stderr, r.stderr
    assert not re.search(r"\b\d{5,}m past\b", r.stderr), r.stderr


def test_parse_marker_within_its_window_is_silent(tmp_path):
    etc = _layout(tmp_path)
    r, _, queries = _run(tmp_path, etc, "pm-ok", FAKE_LEVEL_ACTIVE="0",
                         FAKE_PM_ACTIVE="1", FAKE_PM_PAST="-30")
    assert "DEBUG_LEVEL_STUCK" not in r.stderr, r.stderr


def test_parse_marker_inactive_asks_no_further_questions(tmp_path):
    etc = _layout(tmp_path)
    r, queries, _ = _run(tmp_path, etc, "pm-off", FAKE_LEVEL_ACTIVE="0",
                         FAKE_PM_ACTIVE="0")
    assert Q_MARKER_ACTIVE in queries, queries
    assert Q_MARKER_PAST not in queries, queries


def test_level_and_marker_are_reported_independently(tmp_path):
    """One shared class, two distinct findings: the remedy differs, so folding
    them into one message would send the operator to the wrong control."""
    etc = _layout(tmp_path)
    r, _, _ = _run(tmp_path, etc, "both", FAKE_LEVEL_ACTIVE="1",
                   FAKE_LEVEL_PAST="900", FAKE_MODULES="api",
                   FAKE_PM_ACTIVE="1", FAKE_PM_PAST="900")
    assert "module(s) still at debug PAST the auto-revert window" in r.stderr, r.stderr
    assert "parser decision-trace marker filter is still ON PAST" in r.stderr, r.stderr


# ---------------------------------------------------------------------------
# The gate knob, and the transition machine
# ---------------------------------------------------------------------------

def test_debug_level_check_zero_skips_the_whole_block(tmp_path):
    etc = _layout(tmp_path)
    r, queries, _ = _run(tmp_path, etc, "off", DEBUG_LEVEL_CHECK=0,
                         FAKE_LEVEL_ACTIVE="1", FAKE_LEVEL_PAST="900",
                         FAKE_MODULES="api", FAKE_PM_ACTIVE="1",
                         FAKE_PM_PAST=str(NOW))
    assert "DEBUG_LEVEL_STUCK" not in r.stderr, r.stderr
    assert "debug-level probe" not in r.stderr, r.stderr
    assert "netops_debug_" not in queries, (
        f"DEBUG_LEVEL_CHECK=0 must issue no query at all:\n{queries}")


def test_it_is_its_own_advisory_problem_class(tmp_path):
    """Own class (so it cannot be swallowed by, or swallow, another standing
    problem) and ADVISORY, not critical: a stuck debug level is an incident of
    its own but it is not the stack being down."""
    etc = _layout(tmp_path)
    r, _, pushes = _run(tmp_path, etc, "class", FAKE_LEVEL_ACTIVE="1",
                        FAKE_LEVEL_PAST="900", FAKE_MODULES="api")
    state = (etc / ".stack-watchdog.state").read_text()
    keys = [k for k in state.splitlines() if "DEBUG_LEVEL_STUCK" in k]
    assert len(keys) == 1, f"expected exactly one DEBUG_LEVEL_STUCK class:\n{state}"
    assert keys[0].startswith("A "), (
        f"a stuck debug level is advisory, not a stack-down page: {keys[0]}")
    assert "NetOps advisory" in pushes, f"a NEW advisory pushes once:\n{pushes}"
    assert "NetOps stack DOWN" not in pushes


def test_the_four_stuck_messages_are_four_distinct_classes(tmp_path):
    """problem_key hashes the first 160 characters with digits stripped, so two
    findings whose wording only differs later would collide into one class and
    the second would never push. Each state key is collected from a real run."""
    scenarios = {
        "level-past": dict(FAKE_LEVEL_ACTIVE="1", FAKE_LEVEL_PAST="900",
                           FAKE_MODULES="api"),
        "level-norevert": dict(FAKE_LEVEL_ACTIVE="1", FAKE_LEVEL_PAST=str(NOW),
                               FAKE_MODULES="api"),
        "level-noseries": dict(FAKE_LEVEL_ACTIVE="1", FAKE_LEVEL_PAST="",
                               FAKE_MODULES="api"),
        "marker-past": dict(FAKE_LEVEL_ACTIVE="0", FAKE_PM_ACTIVE="1",
                            FAKE_PM_PAST="900"),
        "marker-norevert": dict(FAKE_LEVEL_ACTIVE="0", FAKE_PM_ACTIVE="1",
                                FAKE_PM_PAST=str(NOW)),
        "marker-noseries": dict(FAKE_LEVEL_ACTIVE="0", FAKE_PM_ACTIVE="1",
                                FAKE_PM_PAST=""),
    }
    seen: dict[str, str] = {}
    for name, knobs in scenarios.items():
        sub = tmp_path / name
        sub.mkdir()
        etc = _layout(sub)
        r, _, _ = _run(sub, etc, name, **knobs)
        assert "DEBUG_LEVEL_STUCK" in r.stderr, f"{name}: {r.stderr}"
        keys = [k for k in (etc / ".stack-watchdog.state").read_text().splitlines()
                if "DEBUG_LEVEL_STUCK" in k]
        assert len(keys) == 1, f"{name}: {keys}"
        assert keys[0] not in seen, (
            f"{name} collides with {seen[keys[0]]} on problem class {keys[0]!r} "
            "— the second finding would never push")
        seen[keys[0]] = name


def test_a_sustained_stuck_level_pushes_once(tmp_path):
    etc = _layout(tmp_path)
    knobs = dict(FAKE_LEVEL_ACTIVE="1", FAKE_LEVEL_PAST="900", FAKE_MODULES="api")
    _, _, p1 = _run(tmp_path, etc, "sustain1", **knobs)
    assert "NetOps advisory" in p1
    # The overrun grows every minute; digits are stripped from the class key, so
    # the class must NOT change and the push must not repeat.
    knobs["FAKE_LEVEL_PAST"] = "960"
    _, _, p2 = _run(tmp_path, etc, "sustain2", **knobs)
    assert "NetOps advisory" not in p2, (
        f"a growing overrun must not mint a new class every minute:\n{p2}")
    # Reverted: the class clears and the stack recovers.
    r3, _, p3 = _run(tmp_path, etc, "sustain3", FAKE_LEVEL_ACTIVE="0")
    assert r3.returncode == 0, r3.stderr
    assert "RECOVERED" in p3, p3


# ---------------------------------------------------------------------------
# hygiene floor (the same bar the sibling suites hold)
# ---------------------------------------------------------------------------

def test_watchdog_parses():
    r = subprocess.run(["bash", "-n", str(WATCHDOG)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck not installed")
def test_watchdog_shellcheck_clean():
    r = subprocess.run(["shellcheck", "-x", str(WATCHDOG)],
                       capture_output=True, text=True)
    assert r.returncode == 0, f"shellcheck stack-watchdog.sh:\n{r.stdout}{r.stderr}"


def test_debug_queries_are_pre_encoded_constants_with_readable_promql():
    """The victoria image has wget only and does not resolve "localhost", and
    encoding PromQL braces/quotes in bash at runtime is a bug farm: the queries
    are constants, and each carries its readable form in the comment above it."""
    import urllib.parse

    lines = WATCHDOG.read_text().splitlines()
    for encoded in (Q_LEVEL_ACTIVE, Q_LEVEL_MODULES, Q_LEVEL_PAST,
                    Q_MARKER_ACTIVE, Q_MARKER_PAST):
        raw = encoded.split("=", 1)[1]
        idx = next((i for i, l in enumerate(lines) if raw in l), None)
        assert idx is not None, f"query constant missing from the watchdog: {raw}"
        readable = urllib.parse.unquote(raw)
        comments = [lines[j].strip().lstrip("#").strip()
                    for j in range(max(0, idx - 4), idx)]
        assert readable in comments, (
            f"the readable PromQL for {raw!r} ({readable!r}) is not in the "
            f"comment above it; found: {comments}")
