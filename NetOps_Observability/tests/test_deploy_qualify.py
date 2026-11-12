# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Static guards for scripts/deploy-qualify.sh — the post-deploy gate.

WHY THIS EXISTS. On 2026-09-03 the gate appeared to HANG a real deploy at
"running B2 (kafka-init topics)"; it was killed after ~15 minutes. Three
separate defects combined, and each one is pinned below because each is the
kind that comes back:

  1. **The bound did not bind.** `timeout N cmd` sends SIGTERM only. The
     `docker compose` CLI traps SIGTERM to run its own graceful shutdown, so a
     600s "timeout" never fired. `timeout -k` escalates to SIGKILL.
  2. **`docker compose run` leaks.** It creates a SECOND, differently-named
     container (`<project>-<service>-run-<hash>`) which KEEPS RUNNING when the
     CLI is killed. One was found alive on the box afterwards.
  3. **The check was the run.** kafka-init starts a JVM twice per topic over 20
     topics (~5s each on this stack = 200s+ minimum) to discover that every
     topic already existed. The gate now READS the topic list first and re-runs
     the one-shot only when something is missing.

Plus the anti-drift guard that makes (3) safe: the script keeps its own copy of
the canonical topic list, and a topic added to compose but missed here would
make B2 report a green "all topics present" while a lane is unbootstrapped.

These are STATIC checks over the committed files — no docker, no running stack
— in the spirit of tests/test_watchdog_transitions.py.

Run:  python3 -m pytest tests/test_deploy_qualify.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "deploy-qualify.sh"
COMPOSE = ROOT / "deployment" / "docker" / "docker-compose.yml"
COMPOSE_TLS = ROOT / "deployment" / "docker" / "compose.tls.yml"

TOPIC_RE = re.compile(r"\bnetops\.[A-Za-z0-9_.]+")


def _compose_yaml(text: str) -> dict:
    """Compose merge tags (!override, !reset) are not plain YAML."""

    class _Loader(yaml.SafeLoader):
        pass

    def _passthrough(loader, node):
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        if isinstance(node, yaml.MappingNode):
            return loader.construct_mapping(node)
        return loader.construct_scalar(node)

    _Loader.add_constructor("!override", _passthrough)
    _Loader.add_constructor("!reset", _passthrough)
    return yaml.load(text, Loader=_Loader)


def _script() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def _script_topics() -> set[str]:
    m = re.search(r"^CANONICAL_TOPICS=\(\n(.*?)^\)$", _script(), re.S | re.M)
    assert m, "CANONICAL_TOPICS array not found in deploy-qualify.sh"
    return set(TOPIC_RE.findall(m.group(1)))


def _entrypoint_topics(path: Path) -> set[str]:
    svc = _compose_yaml(path.read_text(encoding="utf-8"))["services"]["kafka-init"]
    ep = svc.get("entrypoint")
    assert ep, f"{path.name}: kafka-init has no entrypoint"
    body = " ".join(str(x) for x in ep) if isinstance(ep, list) else str(ep)
    # The `for t in <topics>; do` list is the authority.
    m = re.search(r"for\s+t\s+in\s+(.*?);\s*do", body, re.S)
    assert m, f"{path.name}: could not find kafka-init's topic loop"
    return set(TOPIC_RE.findall(m.group(1)))


def test_script_topic_list_matches_compose() -> None:
    """The gate's copy of the canonical topics must equal kafka-init's.

    A topic in compose but missing here => B2 reports "all topics present"
    while that lane was never created, and producers to it fail loud at
    runtime instead (broker auto-create is OFF by design).
    """
    script = _script_topics()
    base = _entrypoint_topics(COMPOSE)
    assert script == base, (
        "deploy-qualify.sh CANONICAL_TOPICS has drifted from kafka-init's "
        f"entrypoint list.\n  only in script: {sorted(script - base)}\n"
        f"  only in compose: {sorted(base - script)}")


def test_tls_override_restates_the_same_topics() -> None:
    """compose.tls.yml REPLACES the entrypoint, so it restates the list."""
    base, tls = _entrypoint_topics(COMPOSE), _entrypoint_topics(COMPOSE_TLS)
    assert base == tls, (
        "the TLS kafka-init entrypoint creates a different topic set than the "
        f"base one.\n  only in base: {sorted(base - tls)}\n"
        f"  only in tls: {sorted(tls - base)}")


def test_timeout_escalates_to_sigkill() -> None:
    """Defect 1: a bound that only SIGTERMs is advisory, not binding."""
    m = re.search(r"^\s*bound\(\)\s*\{\s*timeout([^;}]*)", _script(), re.M)
    assert m, "bound() no longer wraps `timeout` — re-check how calls are bounded"
    assert "-k" in m.group(1), (
        "bound() calls `timeout` without -k. The docker compose CLI traps "
        "SIGTERM, so the bound will not fire — this is exactly the 2026-09-03 "
        f"hang. Got: timeout{m.group(1)!r}")


def test_oneshots_do_not_use_compose_run() -> None:
    """Defect 2: `compose run` orphans a container when the CLI is killed."""
    code = re.sub(r"^\s*#.*$", "", _script(), flags=re.M)   # strip comments
    # Only real INVOCATIONS count. Diagnostic strings legitimately mention the
    # banned construct (the orphan sweep names what it is cleaning up), so skip
    # lines that merely print text.
    offenders = []
    for ln in code.splitlines():
        stripped = ln.strip()
        if re.match(r"(warn|say|record|printf|echo)\b", stripped):
            continue
        if re.search(r"\brun\s+--rm\b", stripped) or re.search(
                r"(^|[|&;(]|\$\()\s*(docker\s+compose|dc)\b[^\"']*\brun\b", stripped):
            offenders.append(stripped)
    assert not offenders, (
        "a one-shot is invoked with `docker compose run`, which creates a "
        "second container that survives the CLI being killed (orphan found on "
        f"the box 2026-09-03). Use `up -d --no-deps --force-recreate` + "
        f"`docker wait`. Offending line(s): {offenders}")


def test_b2_verifies_the_topic_list_not_just_the_exit_code() -> None:
    """Defect 3's safety net: the verdict must come from observed state."""
    code = _script()
    assert "kafka_missing_topics" in code, (
        "B2 no longer reads the topic list — 'the bootstrap exited 0' is the "
        "same unfounded confidence as 'docker compose up exited 0', which is "
        "the premise this whole gate exists to reject.")
    assert "--list" in code, "no kafka-topics --list call remains in the script"


def test_a_global_deadline_exists_and_is_enforced() -> None:
    """The whole script must be bounded, not merely each call inside it."""
    code = _script()
    for token in ("GLOBAL_DEADLINE", "remaining()", "clamp()", "have_time()"):
        assert token in code, f"global-deadline machinery missing: {token}"
    assert "deadline_skip" in code, (
        "running out of time must record a REQUIRED skip (exit 2), never fall "
        "through as a pass")


def test_orphan_sweep_is_loud() -> None:
    """A silent cleanup would erase the evidence that a run was killed."""
    m = re.search(r"kafka_sweep_orphans\(\)\s*\{(.*?)\n\}", _script(), re.S)
    assert m, "kafka_sweep_orphans() not found"
    assert "warn " in m.group(1), (
        "the orphan sweep removes containers without saying so — §16.1: a "
        "degraded/abnormal condition must be reported, not tidied away")


def test_b1_is_check_first_like_b2() -> None:
    """B1 must not re-apply an idempotent matrix just to discover it is applied.

    Lowering the phase bound to 240s exposed this: apply-acls.sh issues 13
    `kafka-acls.sh --add` calls plus two read-backs, each a JVM start against
    the mTLS listener (~5-6s measured), so an unconditional re-apply blew the
    bound and reported FAIL on a stack whose matrix was already correct and
    verified. Same lesson as B2: read the state, and treat applying as the
    REMEDY rather than as the check.
    """
    code = _script()
    assert "kafka_acl_applied" in code, (
        "B1 no longer reads the ACL store before re-applying the matrix")
    # It must judge by the applier's own criteria, not a weaker proxy.
    m = re.search(r"kafka_acl_applied\(\)\s*\{(.*?)\n\}", code, re.S)
    assert m, "kafka_acl_applied() body not found"
    body = m.group(1)
    assert "KAFKA_ACL_FLOOR" in body and "vector-router" in body, (
        "the 'already applied?' read must assert BOTH the entry-count floor and "
        "the load-bearing vector-router grant — a high count with no router "
        "grant is a PARTIAL matrix, which is an auth-dead bus (2026-08-16).")


def test_each_bootstrap_bound_is_clamped_to_the_global_budget() -> None:
    """A phase may be given less time than it asks for; never more."""
    code = _script()
    for want in ('clamp "$ACL_TIMEOUT"', 'clamp "$BOOTSTRAP_TIMEOUT"',
                 'clamp "$DOCKER_TIMEOUT"'):
        assert want in code, (
            f"a bound is used unclamped ({want} missing) — the sum of the "
            "phases could then outrun the global deadline")


# ---------------------------------------------------------------------------
# Q6's bootstrap-aware window floor (fresh-install acceptance, DEFECT-10).
#
# Q6 greps a fixed wall-clock window for bootstrap-class Kafka errors. An
# installer CANNOT apply the SEC-007 ACL matrix before the broker it runs
# inside exists, so TLS phases A and B necessarily run against an empty ACL
# store and the consumers necessarily log GroupAuthorizationFailed /
# TopicAuthorizationFailedError until the matrix lands — then join their groups
# and stay quiet. On 10.70.245.123 the gate therefore reported NOT QUALIFIED
# about a stack that was working, and PASSED on a re-run once the window had
# rolled past. The floor fixes that WITHOUT weakening the steady-state check.
# ---------------------------------------------------------------------------

def _q6_block() -> str:
    src = _script()
    start = src.index("# --- Q6: no bootstrap-class Kafka errors")
    end = src.index("# --- Q7:", start)
    return src[start:end]


def test_q6_window_is_floored_at_the_acl_application_not_replaced_by_it() -> None:
    """Steady state must be untouched: the floor may only ever RAISE the start
    of the window, never lower it, or a long-idle appliance would be graded on
    hours of logs instead of twenty minutes."""
    block = _q6_block()
    assert "acl_applied_epoch" in block, "Q6 does not consult the ACL marker"
    # The comparison that makes it a max(): the floor is used only when it is
    # later than the ordinary window start.
    assert re.search(r'\[ "\$q6_floor" -gt \$\(\( q6_now - q6_window_s \)\)',
                     block), (
        "the floor must be applied only when it is NEWER than (now - window); "
        "anything else changes steady-state behaviour")


def test_q6_never_passes_on_an_empty_window() -> None:
    """A floor set to 'five seconds ago' would make Q6 a rubber stamp. It has
    to wait until it has a real slice of post-matrix logs to judge."""
    block = _q6_block()
    assert "Q6_MIN_OBSERVE" in block and "sleep" in block, (
        "Q6 must wait for at least Q6_MIN_OBSERVE seconds of post-matrix logs "
        "before a PASS can mean anything")
    assert 'clamp "$q6_wait"' in block, (
        "that wait must be clamped to the global deadline like every other "
        "bound in this script")


def test_a_clamped_wait_downgrades_the_verdict_instead_of_passing() -> None:
    """The wait for post-matrix logs is clamped to the global budget, so it can
    end early — and a `--since` timestamp in the future returns no lines at
    all, which would read as a clean PASS on a window nobody looked at. That is
    the rubber stamp this whole gate exists to refuse: it becomes a required
    SKIP (exit 2, INCOMPLETE), exactly as the exit-code table promises."""
    block = _q6_block()
    assert "Q6_SHORT" in block
    assert re.search(r'if \[ -n "\$Q6_SHORT" \]; then\n\s*record SKIP REQUIRED "Q6', block), (
        "a too-short post-matrix window must record SKIP REQUIRED, not PASS")
    # The clock is re-read AFTER the sleep, or the shortfall is invisible.
    sleep_at = block.index('sleep "$q6_wait_bound"')
    assert block.index('q6_observed=$(( q6_now - q6_floor ))') > sleep_at


def test_q6_reports_the_floor_and_what_it_excluded() -> None:
    """A window that silently narrows itself is a gate nobody can audit."""
    block = _q6_block()
    assert "Q6_FLOOR_NOTE" in block
    assert "pre-matrix line(s) in the wider" in block, (
        "Q6 must say HOW MANY lines the floor excluded, not merely that a "
        "floor was applied")
    assert "not install bootstrap noise" in block, (
        "a FAIL under a raised floor must state that the hits are post-matrix")


def test_q6_degrades_to_the_old_behaviour_when_the_marker_is_absent() -> None:
    """No marker (an upgrade, an externally managed broker, a deleted file) =
    exactly the check that shipped before. Absence must never be an error."""
    block = _q6_block()
    assert 'Q6_SINCE="$LOG_WINDOW"' in block, (
        "the default must remain the plain fixed window")
    assert 'elif [ -n "$q6_acl_at" ]' in block, (
        "the floor branch must be conditional on the marker existing")


def test_the_marker_is_stamped_by_b1_when_it_applies_the_matrix() -> None:
    """deploy-qualify.sh can be the thing that applies the matrix (B1 on a
    stack whose install did not). It then owns the same fact install.py owns
    and must record it, or its own Q6 will grade its own bootstrap."""
    src = _script()
    b1 = src[src.index("# ---- B1: the Kafka ACL matrix"):
             src.index("# ---- B2: canonical topic pre-creation")]
    assert "stamp_acl_marker" in b1
    assert b1.index("stamp_acl_marker") < b1.index(
        'record PASS REQUIRED "B1 kafka ACL matrix" \\\n        "applied and verified'), \
        "stamp before the PASS is recorded, so a stamp failure is visible"


def test_the_marker_path_matches_the_one_install_py_writes() -> None:
    """Two scripts, one file. A rename in either is a silent regression to the
    failing-by-construction behaviour."""
    installer = (ROOT / "scripts" / "install.py").read_text(encoding="utf-8")
    m = re.search(r'^KAFKA_ACL_MARKER = "([^"]+)"$', installer, re.MULTILINE)
    assert m, "install.py no longer defines KAFKA_ACL_MARKER"
    name = m.group(1)
    assert f'ACL_MARKER_FILE="${{DQ_ACL_MARKER:-$REPO_ROOT/data/{name}}}"' in _script(), (
        f"deploy-qualify.sh must read the same file install.py writes ({name})")


def test_q6_knobs_are_documented_in_usage() -> None:
    """§16: a knob that only exists in the source is a knob nobody can use."""
    usage = _script()[:_script().index("# --------", _script().index("EOF\n}"))]
    for knob in ("DQ_ACL_MARKER", "DQ_ACL_SETTLE", "DQ_Q6_MIN_OBSERVE"):
        assert knob in usage, f"{knob} is not documented in --help"


# ---------------------------------------------------------------------------
# H-3.8-14 — B3 recorded NO verdict on success
#
# `run_oneshot` records a ledger row on FAILURE only, and B3 had no follow-up
# `record`. A SUCCESSFUL opensearch-init bootstrap therefore produced nothing:
# a passing B3 was indistinguishable from a B3 that never ran, and the summary
# counted it among the steps with "no failures". This script exists precisely
# because `docker compose up` exiting 0 is not evidence of anything; a step
# that proves nothing on success is the same defect one level up.
# ---------------------------------------------------------------------------

def _b3_block() -> str:
    src = _script()
    start = src.index("# ---- B3: OpenSearch ISM retention + snapshot policy")
    end = src.index("# ---- B4:", start)
    return src[start:end]


ISM_LOG_OK = """\
ism: waiting for OpenSearch at http://opensearch:9200 ...
ism: security-auditlog replica template installed.
ism: installing retention policy (delete after 14d) ...
ism: policy written.
ism: retention policy applied — netops-* indices delete after 14d.
ism: quarantine retention applied — netops-quarantine-* deletes after 30d.
ism: snapshot repository ready.
ism: snapshot policy netops-daily installed (daily 01:30 UTC, keep 14, enabled=true).
ism: coverage check —
  ism: 9/9 netops indices managed
"""

ISM_LOG_HALF = """\
ism: waiting for OpenSearch at http://opensearch:9200 ...
ism: installing retention policy (delete after 14d) ...
ism: WARNING policy PUT did not take:
"""

ISM_LOG_WARN = ISM_LOG_OK + "ism: ERROR snapshot repository NOT registered: {}\n"


def _run_b3(oneshot_rc: int, ism_log: str) -> list[str]:
    """Execute the REAL B3 block with its collaborators stubbed.

    `record`, `run_oneshot`, `dkr`, `have_time` and `oneline` are replaced so
    the block runs offline; everything the block itself does — including which
    verdicts it records — is the shipped code.
    """
    import os
    import subprocess
    stub = (
        "set -euo pipefail\n"
        'OPENSEARCH_CID="cid-opensearch"\n'
        'PROJECT="netops"\n'
        'ONESHOT_CID=""\n'
        'have_time() { return 0; }\n'
        'deadline_skip() { printf "SKIP\\tREQUIRED\\t%s\\n" "$1"; }\n'
        'record() { printf "%s\\t%s\\t%s\\t%s\\n" "$1" "$2" "$3" "$4"; }\n'
        'oneline() { printf "%s" "$1" | tr "\\n" " " | cut -c1-"${2:-220}"; }\n'
        'run_oneshot() { ONESHOT_CID="cid-oneshot"; return "$ONESHOT_RC"; }\n'
        'dkr() { if [ "$1" = "logs" ]; then printf "%s" "$ISM_LOG"; return 0; fi; return 0; }\n'
    )
    r = subprocess.run(["bash", "-c", stub + _b3_block()],
                       capture_output=True, text=True, timeout=30, check=False,
                       env={**os.environ, "ONESHOT_RC": str(oneshot_rc),
                            "ISM_LOG": ism_log})
    assert r.returncode == 0, f"B3 block aborted: {r.stderr}"
    return [ln for ln in (r.stdout + r.stderr).splitlines() if "\t" in ln]


def test_b3_records_a_verdict_when_the_bootstrap_succeeds() -> None:
    """The regression. A successful ISM bootstrap must leave a PASS row."""
    rows = _run_b3(0, ISM_LOG_OK)
    assert rows, (
        "a SUCCESSFUL opensearch-init bootstrap recorded no verdict at all — "
        "a passing B3 is indistinguishable from one that never ran")
    verdict, cls, label, detail = rows[0].split("\t", 3)
    assert verdict == "PASS" and cls == "REQUIRED", rows
    assert label.startswith("B3"), rows
    assert "retention" in detail and "exit code" in detail, (
        "the verdict must say what it verified, and that it was not the exit "
        f"code: {detail}")


def test_b3_fails_when_the_bootstrap_exits_zero_halfway_through() -> None:
    """Exit 0 is not the verdict: apply-ism.sh stopping after the first PUT
    leaves indices with no retention policy, which is the disk-fill path."""
    rows = _run_b3(0, ISM_LOG_HALF)
    assert rows, "no verdict recorded"
    verdict, cls, _label, detail = rows[0].split("\t", 3)
    assert verdict == "FAIL" and cls == "REQUIRED", rows
    assert "quarantine retention applied" in detail and "coverage check" in detail, (
        f"the FAIL must name the steps that never reported: {detail}")


def test_b3_fails_when_the_log_cannot_be_read() -> None:
    """§16.1: an unreadable check is not a passed check."""
    rows = _run_b3(0, "")
    verdict, cls, _label, detail = rows[0].split("\t", 3)
    assert verdict == "FAIL" and cls == "REQUIRED", rows
    assert "could not be read" in detail, detail


def test_b3_downgrades_to_advisory_when_apply_ism_reported_a_problem() -> None:
    """Every step completed, but the bootstrap named a problem of its own (no
    snapshot repository). Retention IS applied, so this is not a required
    failure — but it must not vanish into a bare PASS either."""
    rows = _run_b3(0, ISM_LOG_WARN)
    verdict, cls, _label, detail = rows[0].split("\t", 3)
    assert verdict == "ADVISORY" and cls == "ADVISORY", rows
    assert "snapshot repository NOT registered" in detail, detail


def test_b3_leaves_the_failure_verdict_to_run_oneshot() -> None:
    """When the one-shot itself fails, run_oneshot has already recorded the
    FAIL; B3 must not double-report."""
    assert _run_b3(1, "") == [], (
        "B3 recorded a second row for a failure run_oneshot already recorded")


def test_b3_reads_the_one_shot_container_it_actually_started() -> None:
    """The verdict has to come from THIS run's output. run_oneshot publishes
    the container id for exactly that reason."""
    src = _script()
    assert "ONESHOT_CID" in src
    m = re.search(r"run_oneshot\(\)\s*\{(.*?)\n\}", src, re.S)
    assert m and 'ONESHOT_CID="$cid"' in m.group(1), (
        "run_oneshot no longer publishes the container id it started")
    assert 'ONESHOT_CID=""' in m.group(1), (
        "it must be cleared on entry, or a later step could judge an earlier "
        "one-shot's log")


# --- behavioural: run the real helpers out of the real script ---------------

def _source_helpers(extra: str = "") -> str:
    """Run a snippet with deploy-qualify.sh's Q6 helpers in scope.

    The helpers are extracted from the shipped file rather than restated, so a
    change to them is a change to what is tested.
    """
    src = _script()
    start = src.index("stamp_acl_marker() {")
    end = src.index("# Is the ACL matrix already applied?")
    return "set -euo pipefail\n" + src[start:end] + "\n" + extra


def _run_bash(body: str, env: dict | None = None) -> str:
    import os
    import subprocess
    res = subprocess.run(["bash", "-c", body], capture_output=True, text=True,
                         env={**os.environ, **(env or {})}, timeout=30,
                         check=False)
    assert res.returncode == 0, f"bash failed: {res.stderr}"
    return res.stdout


def _parse_ratio(lane: str, total: str, stuck: str) -> str:
    src = _script()
    start = src.index("parse_ratio_detail() {")
    end = src.index('if [ "$METRICS_OK" -eq 0 ]; then\n  record SKIP ADVISORY "Q10')
    helpers = ("set -euo pipefail\n"
               "num_gt() { awk -v a=\"$1\" -v b=\"$2\" 'BEGIN { exit !(a + 0 >  b + 0) }'; }\n"
               + src[start:end])
    return _run_bash(helpers + f'\nparse_ratio_detail "{lane}" "{total}" "{stuck}"')


def test_q10_reads_the_value_of_the_status_per_lane() -> None:
    out = _parse_ratio("syslog", "1000", "30")
    assert out.startswith("syslog: 97.0% parsed of 1000 records")
    assert "understood" not in out


def test_q10_calls_a_stuck_lane_what_it_is() -> None:
    out = _parse_ratio("syslog", "119000", "119000")
    assert "0.0% parsed of 119000" in out and "almost nothing" in out
    assert "almost nothing" in _parse_ratio("snmptrap", "1000", "990")
    assert "almost nothing" not in _parse_ratio("snmptrap", "1000", "989")


def test_q10_no_records_is_not_a_percentage() -> None:
    out = _parse_ratio("snmptrap", "0", "0")
    assert "no records" in out and "%" not in out


def test_q10_is_advisory_and_absent_is_not_healthy() -> None:
    src = _script()
    block = src[src.index("# --- Q10 (ADVISORY)"):src.index("# FINAL BLOCK")]
    assert "record FAIL" not in block, "parse coverage must never fail a deploy"
    assert "record PASS" not in block, "a reading is reported, not passed"
    assert "UNKNOWN, not healthy" in block
    assert "Q10" in src[:src.index("EOF\n}")], "Q10 is not documented in --help"


def test_q10_treats_only_an_empty_result_as_no_unparsed_lines() -> None:
    """A transport failure read as zero would report a lane as fully parsed."""
    src = _script()
    block = src[src.index("# --- Q10 (ADVISORY)"):src.index("# FINAL BLOCK")]
    assert "*'empty result set'*) q10_stuck=0" in block
    assert "2>/dev/null" not in block, "the reason must be read, not discarded (§16.1)"
    # The match must keep tracking the message vm_scalar really prints.
    assert "empty result set" in src[src.index("vm_scalar() {"):src.index("vm_labels() {")]


def test_duration_seconds_understands_dockers_since_syntax() -> None:
    out = _run_bash(_source_helpers(
        'for d in 20m 2h 90s 1h30m 10m30s abc 3d ""; do '
        'printf "%s=[%s]\\n" "$d" "$(duration_seconds "$d")"; done'))
    assert "20m=[1200]" in out and "2h=[7200]" in out and "90s=[90]" in out
    assert "1h30m=[5400]" in out and "10m30s=[630]" in out
    # Anything it does not fully understand yields nothing, so the caller keeps
    # the literal string and the pre-existing behaviour instead of guessing.
    assert "abc=[]" in out and "3d=[]" in out


def test_marker_round_trip_and_malformed_markers_read_as_unknown(tmp_path) -> None:
    marker = tmp_path / "data" / ".kafka-acls-applied"
    body = _source_helpers(
        'stamp_acl_marker\n'
        'printf "roundtrip=[%s]\\n" "$(acl_applied_epoch)"\n'
        'printf "garbage\\n" > "$ACL_MARKER_FILE"\n'
        'printf "malformed=[%s]\\n" "$(acl_applied_epoch)"\n'
        'printf "applied_epoch=not-a-number\\n" > "$ACL_MARKER_FILE"\n'
        'printf "nonnumeric=[%s]\\n" "$(acl_applied_epoch)"\n'
        'rm -f "$ACL_MARKER_FILE"\n'
        'printf "absent=[%s]\\n" "$(acl_applied_epoch)"\n')
    out = _run_bash(body, env={
        "ACL_MARKER_FILE": str(marker), "LOG_WINDOW": "20m"})
    assert re.search(r"roundtrip=\[\d{10}\]", out), out
    assert "malformed=[]" in out and "nonnumeric=[]" in out and "absent=[]" in out


# ---------------------------------------------------------------------------
# Tracker 353 — Q2c: prove CONSUMPTION, not membership.
#
# 2026-10-17: netops-router-applogs read nothing for over an hour (lag 22,643,
# KafkaConsumerStalled) while its group member stayed joined, so "Q2 router
# consumers joined" PASSED during the stall. Vector 0.40's kafka source loses
# its per-partition consumer task across a rebalance (upstream
# vectordotdev/vector#22006, open; reported still present on 0.54/0.55) and the
# member keeps heartbeating. Q2c judges every (group, topic, partition) from
# the broker's committed and end offsets instead. These tests run the SHIPPED
# functions and the SHIPPED block, extracted from the script, not a restatement.
# ---------------------------------------------------------------------------

def _q2c_block() -> str:
    src = _script()
    start = src.index("# --- Q2c: every consumer group is CONSUMING")
    end = src.index("# --- Q3:", start)
    return src[start:end]


def _q2c_judge(rows: list[tuple], final: int = 0, minobs: int = 120,
               grace: int = 60, tol: int = 100) -> dict[tuple, tuple[str, str]]:
    """Run the real q2c_judge over (epoch, group, topic, partition, C, E) rows."""
    import subprocess
    block = _q2c_block()
    fn = block[block.index("q2c_judge() {"):block.index("q2c_numeric_ok=1")]
    data = "\n".join("\t".join(str(x) for x in r) for r in rows) + "\n"
    res = subprocess.run(
        ["bash", "-c", "set -euo pipefail\n" + fn +
         f"\nq2c_judge {minobs} {grace} {tol} {final}"],
        input=data, capture_output=True, text=True, timeout=30, check=False)
    assert res.returncode == 0, res.stderr
    out = {}
    for ln in res.stdout.splitlines():
        g, t, p, verdict, detail = ln.split("\t", 4)
        out[(g, t, p)] = (verdict, detail)
    return out


def _series(group: str, topic: str, part: str, t0: int, step: int,
            committed: list[int], end: list[int]) -> list[tuple]:
    return [(t0 + i * step, group, topic, part, c, e)
            for i, (c, e) in enumerate(zip(committed, end))]


APP = ("netops-router-applogs", "netops.applogs", "0")


def test_q2c_the_2026_10_17_wedge_is_a_failure() -> None:
    """Records keep arriving, the committed offset never moves, the member is
    joined: the exact shape Q2 passed. It must be STALLED."""
    rows = _series(*APP, 1000, 10, [5000] * 19, [5000 + 40 * i for i in range(19)])
    verdict, detail = _q2c_judge(rows)[APP]
    assert verdict == "STALLED", detail
    assert "committed offset stayed at 5000" in detail and "lag now 720" in detail


def test_q2c_a_moving_consumer_passes() -> None:
    rows = _series(*APP, 1000, 10, [5000 + 30 * i for i in range(4)],
                   [5040 + 30 * i for i in range(4)])
    assert _q2c_judge(rows)[APP][0] == "CONSUMING"


def test_q2c_one_wedged_partition_cannot_hide_behind_a_moving_sibling() -> None:
    """Nothing is summed: Vector's bug is per PARTITION task."""
    p1 = ("netops-router-applogs", "netops.applogs", "1")
    rows = (_series(*APP, 1000, 10, [100 + 9 * i for i in range(19)],
                    [110 + 9 * i for i in range(19)])
            + _series(*p1, 1000, 10, [700] * 19, [700 + 5 * i for i in range(19)]))
    out = _q2c_judge(rows)
    assert out[APP][0] == "CONSUMING"
    assert out[p1][0] == "STALLED", out[p1]


def test_q2c_an_idle_lane_is_not_a_failure() -> None:
    """No input + no backlog is a quiet lane — but only after MIN_OBSERVE."""
    rows = _series(*APP, 1000, 10, [800] * 13, [800] * 13)
    assert _q2c_judge(rows)[APP][0] == "IDLE"
    assert _q2c_judge(rows[:6])[APP][0] == "PENDING", (
        "60 s of quiet is not yet proof of an idle lane")


def test_q2c_idle_tolerates_a_small_uncommitted_tail() -> None:
    """correlation commits every 100 records or 5 s, on the NEXT record, so a
    quiet lane can rest with a few uncommitted offsets."""
    rows = _series(*APP, 1000, 10, [800] * 13, [899] * 13)
    assert _q2c_judge(rows, tol=100)[APP][0] == "IDLE"


def test_q2c_a_consumer_sitting_on_a_backlog_is_frozen() -> None:
    """Input stopped, but 22k records are unread and nothing commits: the
    wedge after its producer went quiet. Not idle."""
    rows = _series(*APP, 1000, 10, [1000] * 13, [23643] * 13)
    verdict, detail = _q2c_judge(rows)[APP]
    assert verdict == "FROZEN", detail
    assert "22643 records still unread" in detail


def test_q2c_records_inside_the_grace_period_are_not_a_stall() -> None:
    """A record that lands in the last seconds has not had time to be
    committed (5 s cadence + a 30 s scrape). Before the end it keeps the poll
    open; at the end it is judged on the quiet part of the window."""
    end = [800] * 16 + [805, 805, 805]       # arrives 30 s before the last sample
    rows = _series(*APP, 1000, 10, [800] * 19, end)
    assert _q2c_judge(rows, final=0)[APP][0] == "PENDING"
    verdict, detail = _q2c_judge(rows, final=1)[APP]
    assert verdict == "IDLE", detail
    assert "too recent" in detail


def test_q2c_a_rewound_group_is_rebaselined_not_read_as_progress() -> None:
    """A committed offset moving BACKWARDS (group reset) must neither count as
    consumption nor carry the old baseline."""
    rows = _series(*APP, 1000, 10, [900] * 5 + [100] * 14, [900] * 19)
    verdict, detail = _q2c_judge(rows)[APP]
    assert verdict == "FROZEN", detail       # 800 unread after the reset
    rows_ok = _series(*APP, 1000, 10, [900] * 5 + [100] * 14, [100] * 19)
    assert _q2c_judge(rows_ok)[APP][0] == "IDLE"


def test_q2c_a_partition_that_never_committed_while_data_arrives_is_stalled() -> None:
    rows = _series(*APP, 1000, 10, [-1] * 19, [10 * i for i in range(19)])
    verdict, detail = _q2c_judge(rows)[APP]
    assert verdict == "STALLED" and "never committed" in detail, detail


def _vm_rows_fn() -> str:
    block = _q2c_block()
    return block[block.index("vm_rows() {"):block.index("# One observation:")]


def test_q2c_vm_rows_parses_a_real_victoriametrics_body() -> None:
    body = ('{"status":"success","data":{"resultType":"vector","result":['
            '{"metric":{"__name__":"kafka_consumergroup_current_offset",'
            '"consumergroup":"netops-router-applogs","instance":"kafka-exporter:9308",'
            '"job":"kafka","partition":"0","topic":"netops.applogs"},'
            '"value":[1731400000,"5000"]},'
            '{"metric":{"consumergroup":"netops-correlation","partition":"11",'
            '"topic":"netops.syslog"},"value":[1731400000,"1.2e+06"]},'
            '{"metric":{"consumergroup":"no-partition-label","topic":"x"},'
            '"value":[1731400000,"7"]}]},"stats":{"seriesFetched":"3"}}')
    out = _run_bash(
        "set -euo pipefail\n"
        'oneline() { printf "%s" "$1"; }\n'
        'vm_body() { printf "%s" "$BODY"; }\n' + _vm_rows_fn() +
        "\nvm_rows q consumergroup topic partition\n", env={"BODY": body})
    assert out.splitlines() == [
        "netops-router-applogs\tnetops.applogs\t0\t5000",
        "netops-correlation\tnetops.syslog\t11\t1.2e+06",
    ], out


def test_q2c_vm_rows_refuses_a_non_success_body() -> None:
    import subprocess
    res = subprocess.run(
        ["bash", "-c", "set -euo pipefail\n"
         'oneline() { printf "%s" "$1"; }\n'
         "vm_body() { printf '{\"status\":\"error\",\"error\":\"bad\"}'; }\n"
         + _vm_rows_fn() + "\nvm_rows q topic partition\n"],
        capture_output=True, text=True, timeout=30, check=False)
    assert res.returncode != 0 and "non-success" in res.stderr, res


# --- the whole Q2c block, end to end, on a fake clock -----------------------

_Q2C_HARNESS = r'''
set -euo pipefail
METRICS_OK=1; EXPORTER_CID=exp; C_SKIP=''; C_OFF=''
POLL_INTERVAL=10
T0=1000000
echo "$T0" > "$CLK"
date() { if [ "${1:-}" = "+%s" ]; then cat "$CLK"; else command date "$@"; fi; }
sleep() { echo $(( $(cat "$CLK") + $1 )) > "$CLK"; }
DEADLINE=$(( T0 + 300 )); GLOBAL_DEADLINE=$(( T0 + 900 ))
have_time() { return 0; }
deadline_skip() { printf 'SKIP\tREQUIRED\t%s\tdeadline\n' "$1"; }
record() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4"; }
warn() { printf 'WARN %s\n' "$*" >&2; }
oneline() { printf '%s' "$1" | tr '\n' ' ' | cut -c1-"${2:-220}"; }
is_num() { grep -qE '^[+-]?([0-9]+\.?[0-9]*|\.[0-9]+)([eE][+-]?[0-9]+)?$' <<<"$1"; }
num_gt() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a + 0 > b + 0) }'; }
vm_scalar() { printf '%s' "${FRESH_AGE:-5}"; }
# Offsets are a function of elapsed fake time t, per SCENARIO.
vm_body() {
  local t c1 e1 c2 e2
  t=$(( $(cat "$CLK") - T0 ))
  case "$SCENARIO" in
    wedge)   c1=5000;                e1=$(( 5000 + 4 * t )); c2=$(( 900 + t )); e2=$(( 903 + t )) ;;
    healthy) c1=$(( 5000 + 4 * t )); e1=$(( 5010 + 4 * t )); c2=$(( 900 + t )); e2=$(( 903 + t )) ;;
    idle)    c1=5000;                e1=5000;                c2=900;            e2=900 ;;
  esac
  case "$1" in
    *consumergroup_current_offset*)
      printf '{"status":"success","data":{"result":[{"metric":{"consumergroup":"netops-router-applogs","partition":"0","topic":"netops.applogs"},"value":[1,"%s"]},{"metric":{"consumergroup":"netops-correlation","partition":"0","topic":"netops.syslog"},"value":[1,"%s"]}]}}' "$c1" "$c2" ;;
    *topic_partition_current_offset*)
      printf '{"status":"success","data":{"result":[{"metric":{"partition":"0","topic":"netops.applogs"},"value":[1,"%s"]},{"metric":{"partition":"0","topic":"netops.syslog"},"value":[1,"%s"]}]}}' "$e1" "$e2" ;;
  esac
}
'''


def _run_q2c(scenario: str, tmp_path, extra: str = "", **env) -> list[list[str]]:
    import subprocess
    res = subprocess.run(
        ["bash", "-c", _Q2C_HARNESS + extra + _q2c_block()],
        capture_output=True, text=True, timeout=60, check=False,
        env={"PATH": "/usr/bin:/bin", "SCENARIO": scenario,
             "CLK": str(tmp_path / "clock"), **env})
    assert res.returncode == 0, f"Q2c block aborted: {res.stderr}"
    rows = [ln.split("\t") for ln in res.stdout.splitlines()
            if ln.startswith(("PASS\t", "FAIL\t", "SKIP\t"))]
    assert len(rows) == 1, f"Q2c must record exactly one verdict: {res.stdout}"
    return rows


def _elapsed(tmp_path) -> int:
    return int((tmp_path / "clock").read_text()) - 1000000


def test_q2c_block_fails_the_wedge_and_names_the_lane(tmp_path) -> None:
    (verdict, cls, label, detail), = _run_q2c("wedge", tmp_path)
    assert (verdict, cls) == ("FAIL", "REQUIRED"), detail
    assert label.startswith("Q2c")
    assert "STALLED netops-router-applogs[0] netops.applogs" in detail, detail
    assert "STALLED netops-correlation" not in detail, (
        "the moving correlation group must not be blamed")
    assert "vectordotdev/vector#22006" in detail


def test_q2c_block_passes_moving_consumers_early(tmp_path) -> None:
    (verdict, _cls, _label, detail), = _run_q2c("healthy", tmp_path)
    assert verdict == "PASS", detail
    assert "2 partition(s) consuming" in detail, detail
    assert _elapsed(tmp_path) < 60, "two moving groups must not wait out the window"


def test_q2c_block_passes_a_quiet_stack_only_after_watching_it(tmp_path) -> None:
    (verdict, _cls, _label, detail), = _run_q2c("idle", tmp_path)
    assert verdict == "PASS" and "2 idle" in detail, detail
    assert _elapsed(tmp_path) >= 120, "idle is only proven after DQ_Q2_MIN_OBSERVE"


def test_q2c_block_stale_exporter_is_a_skip_not_a_pass(tmp_path) -> None:
    """Frozen numbers from a dead exporter would read as idle lanes."""
    (verdict, cls, _label, detail), = _run_q2c("idle", tmp_path, FRESH_AGE="900")
    assert (verdict, cls) == ("SKIP", "REQUIRED"), detail
    assert "not current" in detail


def test_q2c_block_extends_a_spent_window_to_min_observe(tmp_path) -> None:
    """Earlier checks may have used up the shared window; Q2c still watches
    for MIN_OBSERVE (inside the global deadline) instead of judging nothing."""
    (verdict, cls, _label, detail), = _run_q2c("wedge", tmp_path, extra="DEADLINE=$T0\n")
    assert (verdict, cls) == ("FAIL", "REQUIRED"), detail
    assert _elapsed(tmp_path) >= 120


def test_q2c_block_never_overruns_the_global_deadline(tmp_path) -> None:
    """…but the extension is bounded: with no global budget left the partitions
    stay unjudged and that is a required SKIP, never a PASS."""
    (verdict, cls, _label, detail), = _run_q2c(
        "idle", tmp_path, extra="DEADLINE=$T0; GLOBAL_DEADLINE=$(( T0 + 40 ))\n")
    assert (verdict, cls) == ("SKIP", "REQUIRED"), detail
    assert "Not evaluated is not passed" in detail
    assert _elapsed(tmp_path) <= 40


def test_q2c_is_documented_and_reads_the_broker_not_vector() -> None:
    usage = _script()[:_script().index("EOF\n}")]
    assert "Q2c" in usage
    for knob in ("DQ_Q2_MIN_OBSERVE", "DQ_Q2_COMMIT_GRACE",
                 "DQ_Q2_IDLE_LAG_MAX", "DQ_Q2_MAX_STALENESS"):
        assert knob in usage, f"{knob} is not documented in --help"
    block = _q2c_block()
    # Vector's own lag gauge is wrong after the very glitch we are detecting
    # (upstream vectordotdev/vector#21134); the broker's offsets are the truth.
    assert "vector_kafka_consumer_lag" not in block
    assert "kafka_consumergroup_current_offset" in block
    assert "kafka_topic_partition_current_offset" in block
