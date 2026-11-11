# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Watchdog PLATFORM_ALERTS_UNROUTED problem class (review 2026-11-11).

Since 2026-11-11 the destinations of the stack's own alerts are set in the web
console (Platform -> Platform alerts). With none set — or with the saved
settings unreadable since the api started — the api's receiver keeps getting
the vmalert heartbeat (so AlertDeliveryBroken stays quiet) while every page is
counted not_configured: pages reach nobody while every layer reads green, the
2026-09-02 shape. The in-stack PlatformAlertsReachNobody rule travels the very
route it reports on, so this external block is the one that can actually reach
a person, over the watchdog's own ntfy topic.

Asserted, each a defect class:
  * routed nowhere for the whole 10-minute window -> CRITICAL class, naming the
    cause (nothing configured vs. settings unreadable);
  * routed nowhere but the gauge is younger than the grace -> quiet (a fresh
    install gets ten minutes), never a page;
  * routed -> silence; receiver disabled or absent -> silence (the heartbeat
    block owns that report);
  * the routing gauge ABSENT -> a quiet named gap in the log, never a pass;
  * a failed query -> SKIPPED, a malformed value -> UNKNOWN. Never healthy;
  * PLATFORM_ALERT_ROUTE_CHECK=0 -> no query issued at all;
  * end to end: the class is pushed at URGENT priority over the watchdog's ntfy.

The block-level tests lift the block and stub eng_query per query (the same
technique as the client-cert block tests); the end-to-end test runs the FULL
script with docker and curl faked on PATH. Nothing here reaches a real ntfy
topic — curl is a fake that only logs its arguments. `--test` is never run.
"""

import os
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WATCHDOG = ROOT / "scripts" / "stack-watchdog.sh"

# The encoded queries, kept here (not imported) so a silent rewrite of a query
# is a test failure rather than a test that follows it.
Q_ENABLED = "max%28netops_alert_webhook_enabled%29"
Q_ROUTED = "max%28netops_platform_alert_page_routed%29"
Q_WINDOW = ("max%28max_over_time%28netops_platform_alert_page_routed%5B10m%5D%29%29"
            "%20unless%20on%28%29%20absent%28netops_platform_alert_page_routed%20offset%2010m%29")
Q_EVER = "max%28netops_platform_alert_store_ever_read%29"


def _block() -> str:
    src = WATCHDOG.read_text(encoding="utf-8")
    start = src.index('if [ "${PLATFORM_ALERT_ROUTE_CHECK:-1}" = "1" ] && [ -n "${eng_cid:-}" ]; then')
    end = src.index("# CLIENT-CERTIFICATE EXPIRY", start)
    return src[start:src.rindex("\nfi\n", start, end) + 4]


def _stub(answers: dict, fail: str = "") -> str:
    """An eng_query that answers per encoded query; `fail` names a query that errors."""
    lines = ['eng_query() {', '  eng_err=""; eng_val=""', '  echo "$1" >> "$QLOG"', '  case "$1" in']
    if fail:
        lines.append(f'    "{fail}") eng_err="victoria query failed (rc=8)"; return 1 ;;')
    for q, v in answers.items():
        lines.append(f'    "{q}") eng_val="{v}" ;;')
    lines += ['    *) eng_val="" ;;', '  esac', '  return 0', '}']
    return "\n".join(lines)


def _run_block(tmp_path: Path, answers: dict, fail: str = "", **env: str):
    qlog = tmp_path / "q.log"
    script = ("problems=()\neng_cid=victoria\n"
              "logerr() { printf 'LOG %s\\n' \"$*\" >&2; }\n"
              + _stub(answers, fail) + "\n" + _block()
              + '\nprintf "%s\\n" "${problems[@]}"\n')
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30,
                       env={"PATH": "/usr/bin:/bin", "QLOG": str(qlog), **env})
    assert r.returncode == 0, r.stderr
    queries = qlog.read_text() if qlog.exists() else ""
    return [ln for ln in r.stdout.splitlines() if ln], r.stderr, queries


def test_routed_nowhere_for_the_whole_window_is_the_critical_class(tmp_path):
    probs, _, queries = _run_block(tmp_path, {Q_ENABLED: "1", Q_ROUTED: "0", Q_WINDOW: "0", Q_EVER: "1"})
    assert len(probs) == 1 and probs[0].startswith("PLATFORM_ALERTS_UNROUTED"), probs
    assert "no channel receives pages" in probs[0] and "Platform alerts" in probs[0], probs
    assert "docs/runbooks/engine-not-consuming.md" in probs[0]
    # The problem text must be free of run-varying digits in its hashed prefix.
    assert not any(c.isdigit() for c in probs[0][:160]), probs[0]
    for q in (Q_ENABLED, Q_ROUTED, Q_WINDOW, Q_EVER):
        assert q in queries, f"query not issued: {q}\n{queries}"


def test_unreadable_settings_name_postgres_and_the_vault(tmp_path):
    probs, _, _ = _run_block(tmp_path, {Q_ENABLED: "1", Q_ROUTED: "0", Q_WINDOW: "0", Q_EVER: "0"})
    assert len(probs) == 1 and probs[0].startswith("PLATFORM_ALERTS_UNROUTED"), probs
    assert "could not be read" in probs[0] and "vault" in probs[0], probs


def test_a_fresh_install_gets_the_grace(tmp_path):
    # Routed nowhere NOW, but the series did not exist ten minutes ago: the
    # windowed query answers empty. Quiet, logged, never a page.
    probs, log, _ = _run_block(tmp_path, {Q_ENABLED: "1", Q_ROUTED: "0", Q_WINDOW: ""})
    assert probs == [], probs
    assert "younger than the 10-minute grace" in log, log


def test_a_route_configured_inside_the_window_does_not_page(tmp_path):
    # It was routed at some point in the last ten minutes (max_over_time = 1).
    probs, _, _ = _run_block(tmp_path, {Q_ENABLED: "1", Q_ROUTED: "0", Q_WINDOW: "1"})
    assert probs == [], probs


def test_routed_is_silent_and_skips_the_window_query(tmp_path):
    probs, _, queries = _run_block(tmp_path, {Q_ENABLED: "1", Q_ROUTED: "1"})
    assert probs == [], probs
    assert Q_WINDOW not in queries


def test_receiver_disabled_or_absent_is_left_to_the_heartbeat_block(tmp_path):
    for enabled in ("0", ""):
        probs, _, queries = _run_block(tmp_path, {Q_ENABLED: enabled, Q_ROUTED: "0", Q_WINDOW: "0"})
        assert probs == [], (enabled, probs)
        assert Q_ROUTED not in queries.replace(Q_ENABLED, ""), queries


def test_absent_routing_gauge_is_a_named_gap_never_a_pass(tmp_path):
    probs, log, _ = _run_block(tmp_path, {Q_ENABLED: "1", Q_ROUTED: ""})
    assert probs == [], probs
    assert "UNPROVEN" in log and "netops_platform_alert_page_routed is absent" in log, log


def test_failed_or_garbage_query_is_never_healthy(tmp_path):
    for fail in (Q_ENABLED, Q_ROUTED, Q_WINDOW):
        probs, _, _ = _run_block(tmp_path, {Q_ENABLED: "1", Q_ROUTED: "0", Q_WINDOW: "0"}, fail=fail)
        assert any("SKIPPED" in p for p in probs), (fail, probs)
    probs, _, _ = _run_block(tmp_path, {Q_ENABLED: "1", Q_ROUTED: "NaN"})
    assert any("UNKNOWN" in p for p in probs), probs
    probs, _, _ = _run_block(tmp_path, {Q_ENABLED: "1", Q_ROUTED: "0", Q_WINDOW: "abc"})
    assert any("UNKNOWN" in p for p in probs), probs


def test_the_check_can_be_disabled(tmp_path):
    probs, _, queries = _run_block(tmp_path, {Q_ENABLED: "1", Q_ROUTED: "0", Q_WINDOW: "0"},
                                   PLATFORM_ALERT_ROUTE_CHECK="0")
    assert probs == [] and queries == "", (probs, queries)


def test_the_class_is_critical():
    src = WATCHDOG.read_text(encoding="utf-8")
    start = src.index("problem_is_critical() {")
    assert "*PLATFORM_ALERTS_UNROUTED*" in src[start:start + 800], (
        "PLATFORM_ALERTS_UNROUTED must be a CRITICAL class: pages reaching nobody is a page")


def test_env_example_documents_the_knob():
    ex = (ROOT / "scripts" / "stack-watchdog.env.example").read_text(encoding="utf-8")
    assert "#PLATFORM_ALERT_ROUTE_CHECK=1" in ex


# ---------------------------------------------------------------------------
# End to end: the full script, docker + curl faked, VictoriaMetrics scripted.
# ---------------------------------------------------------------------------

FAKE_DOCKER = r'''#!/bin/sh
vm_vector() {
  if [ -z "$1" ]; then
    printf '{"status":"success","data":{"resultType":"vector","result":[]}}'
  else
    printf '{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1756900000,"%s"]}]}}' "$1"
  fi
}
case "$1" in
  ps)
    svc=$(printf '%s\n' "$@" | sed -n 's/.*service=//p' | head -1)
    [ -n "$svc" ] || exit 0
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
    shift
    case "$*" in
      *"netops_platform_alert_page_routed%5B10m%5D"*) vm_vector "${FAKE_WINDOW-0}" ;;
      *"max%28netops_platform_alert_page_routed%29"*) vm_vector "${FAKE_ROUTED-0}" ;;
      *"max%28netops_platform_alert_store_ever_read%29"*) vm_vector "1" ;;
      *"max%28netops_alert_webhook_enabled%29"*) vm_vector "1" ;;
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


def _layout(tmp_path: Path) -> Path:
    etc = tmp_path / "etc"
    etc.mkdir()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    _write_exec(bindir / "docker", FAKE_DOCKER)
    _write_exec(bindir / "curl", FAKE_CURL)
    stack_env = tmp_path / "stack.env"
    stack_env.write_text("CLICKHOUSE_USER=netops\nCLICKHOUSE_PASSWORD=fake-ch-pw\n")
    content = WATCHDOG.read_text()
    assert 'export PATH="' in content, "stack-watchdog.sh lost its explicit PATH export"
    (etc / "stack-watchdog.sh").write_text(content.replace('export PATH="', f'export PATH="{bindir}:', 1))
    (etc / "stack-watchdog.sh").chmod(0o755)
    (etc / "stack-watchdog.env").write_text(
        "COMPOSE_PROJECT='netops'\n"
        "APP_URL='http://localhost:8000/'\n"
        "NTFY_TOPIC='correlix-test-topic'\n"
        f"CH_ENV_FILE='{stack_env}'\n"
        "DISK_WARN_PCT='101'\n"
        # Only this block reads VictoriaMetrics in these runs.
        "ENGINE_CONSUMER_CHECK='0'\n"
        "SNAPSHOT_RESTORABLE_CHECK='0'\n"
        "CLIENT_CERT_CHECK='0'\n"
        "DEBUG_LEVEL_CHECK='0'\n"
    )
    return etc


def _run_full(tmp_path: Path, etc: Path, name: str, **knobs):
    env = os.environ.copy()
    env.update({"WATCHDOG_ENV": str(etc / "stack-watchdog.env"),
                "CURL_LOG": str(tmp_path / f"curl.{name}.log")})
    env.update({k: str(v) for k, v in knobs.items()})
    r = subprocess.run(["bash", str(etc / "stack-watchdog.sh")], env=env,
                       capture_output=True, text=True, timeout=300)
    assert r.returncode in (0, 1), f"unexpected exit {r.returncode}:\n{r.stderr}"
    log = tmp_path / f"curl.{name}.log"
    return r, (log.read_text() if log.exists() else "")


def test_end_to_end_pushes_the_class_at_urgent_priority(tmp_path):
    etc = _layout(tmp_path)
    r, pushes = _run_full(tmp_path, etc, "unrouted", FAKE_ROUTED="0", FAKE_WINDOW="0")
    assert "PLATFORM_ALERTS_UNROUTED" in r.stderr + pushes, (r.stderr, pushes)
    # One fake-curl invocation per "CURL " record; a push body spans lines.
    calls = [c for c in ("\n" + pushes).split("\nCURL ") if "correlix-test-topic" in c]
    ours = [c for c in calls if "PLATFORM_ALERTS_UNROUTED" in c]
    assert ours, pushes
    assert any("Priority: urgent" in c for c in ours), ours


def test_end_to_end_routed_is_quiet(tmp_path):
    etc = _layout(tmp_path)
    r, pushes = _run_full(tmp_path, etc, "routed", FAKE_ROUTED="1", FAKE_WINDOW="1")
    assert "PLATFORM_ALERTS_UNROUTED" not in r.stderr + pushes
