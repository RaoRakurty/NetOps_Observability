"""Watchdog ship contract (owner decision 2026-08-13).

The external stack watchdog is promoted into customer bundles with phone
(ntfy) + email + webhook notification support, installed as a root cron by
scripts/install-watchdog.sh (invoked by the setup GUI via sudo, fixed argv).

Asserted here:
  * bundle guard: LAB_PATHS no longer excludes stack-watchdog, .gitattributes
    ships the three watchdog files, and none of them contains a LAB_MARKERS
    pattern (the de-lab guarantee, tested against the regex make-installer.sh
    actually greps with — not a copy of it);
  * install-watchdog.sh rejects every invalid-argument class and, in
    --print-only mode, emits the exact root-owned file contents while writing
    nothing;
  * the publish path (executed with a fake `curl` on PATH, not just grepped):
    Email: header iff WATCHDOG_EMAIL, Authorization: Bearer iff NTFY_TOKEN,
    email-without-topic refused loudly, webhook POSTs bounded (-m) valid JSON
    with an optional bearer token;
  * the kernel UDP-drop sentinel (executed with a fake `docker` on PATH feeding
    canned /proc/net/snmp): named-column parsing, run-over-run delta math incl.
    counter reset (restart makes the counter go BACKWARD — never a huge-delta
    alarm), transition-only alerting (drops-started / drops-stopped, not one
    per minute), graceful "not measurable" degradation, bounded docker exec;
  * both scripts stay `bash -n` and shellcheck clean.
"""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
WATCHDOG = SCRIPTS / "stack-watchdog.sh"
INSTALLER = SCRIPTS / "install-watchdog.sh"
MAKE_INSTALLER = SCRIPTS / "make-installer.sh"
ENV_EXAMPLE = SCRIPTS / "stack-watchdog.env.example"

SHIPPED_WATCHDOG_FILES = [WATCHDOG, ENV_EXAMPLE, INSTALLER]


def _guard_var(name: str) -> str:
    """Extract a guard regex exactly as make-installer.sh defines it."""
    m = re.search(rf"^{name}='([^']+)'", MAKE_INSTALLER.read_text(), re.M)
    assert m, f"{name} definition not found in make-installer.sh"
    return m.group(1)


# ---------------------------------------------------------------------------
# Bundle guard contract
# ---------------------------------------------------------------------------

def test_lab_paths_no_longer_excludes_watchdog():
    lab_paths = _guard_var("LAB_PATHS")
    assert "stack-watchdog" not in lab_paths, (
        "scripts/stack-watchdog must ship in the customer bundle "
        f"(LAB_PATHS still excludes it: {lab_paths})"
    )


def test_gitattributes_ships_watchdog_files():
    """git archive is the bundle source of truth: the three watchdog files
    must NOT be export-ignored (and the bundle builder itself must be — its
    LAB_MARKERS literals would self-trip the content scan)."""
    paths = [
        "scripts/stack-watchdog.sh",
        "scripts/stack-watchdog.env.example",
        "scripts/install-watchdog.sh",
        "scripts/make-installer.sh",
    ]
    out = subprocess.run(
        ["git", "check-attr", "export-ignore", "--", *paths],
        cwd=ROOT, check=True, capture_output=True, text=True,
    ).stdout
    attrs = dict(
        (line.split(": export-ignore: ")[0], line.split(": export-ignore: ")[1])
        for line in out.strip().splitlines()
    )
    for p in paths[:3]:
        assert attrs[p] == "unspecified", f"{p} is export-ignored — it would not ship"
    assert attrs["scripts/make-installer.sh"] == "set", (
        "make-installer.sh must be export-ignored: it contains the LAB_MARKERS "
        "literals and would self-trip the lab-leak content scan"
    )


def test_shipped_watchdog_files_carry_no_lab_markers():
    """De-lab guarantee, using the very regex the bundle build greps with."""
    markers = _guard_var("LAB_MARKERS")
    for f in SHIPPED_WATCHDOG_FILES:
        hit = re.search(markers, f.read_text())
        assert hit is None, f"lab marker {hit.group(0)!r} in shipped file {f.name}"


# ---------------------------------------------------------------------------
# install-watchdog.sh argument validation (all via --print-only: no root, no
# writes — validation runs in full before the mode branches)
# ---------------------------------------------------------------------------

def run_installer(*args):
    return subprocess.run(
        ["bash", str(INSTALLER), "--print-only", *args],
        capture_output=True, text=True,
    )


VALID = {
    "app": "https://netops.example.com:8000/",
    "topic": "correlix-alerts_x7Kq93Lm",
    "email": "noc@example.com",
    "hc": "https://hc.example.com/ping/0a1b2c3d-1111-2222-3333-444455556666",
    "ntfy_server": "https://ntfy.corp.example.com",
    "ntfy_token": "test-token-00000000",
    "webhook": "https://hooks.example.com/services/T000/B000/XXXXYYYYZZZZ",
    "webhook_token": "test-hook-00000000",
}


@pytest.mark.parametrize(
    "argv,expect",
    [
        pytest.param([], "--app-url is required", id="missing-app-url"),
        pytest.param(["--app-url", "ftp://x.example/"], "--app-url", id="app-url-scheme"),
        pytest.param(["--app-url", "https://bad host/"], "--app-url", id="app-url-space"),
        pytest.param(["--app-url", "https://x.example/" + "a" * 200], "--app-url", id="app-url-too-long"),
        pytest.param(["--app-url", VALID["app"], "--topic", "bad topic!"], "--topic", id="topic-charset"),
        pytest.param(["--app-url", VALID["app"], "--topic", "x" * 65], "--topic", id="topic-too-long"),
        pytest.param(["--app-url", VALID["app"], "--topic", VALID["topic"], "--email", "not-an-email"], "--email", id="email-shape"),
        pytest.param(["--app-url", VALID["app"], "--topic", VALID["topic"], "--email", "a" * 250 + "@example.com"], "--email", id="email-too-long"),
        pytest.param(["--app-url", VALID["app"], "--email", VALID["email"]], "--email requires --topic", id="email-without-topic"),
        pytest.param(["--app-url", VALID["app"], "--hc-url", "http://hc.example.com/ping/abc"], "--hc-url", id="hc-url-not-https"),
        pytest.param(["--app-url", VALID["app"], "--hc-url", "https://hc.example.com/ping/../etc"], "--hc-url", id="hc-url-charset"),
        pytest.param(["--app-url", VALID["app"], "--hc-url", "https://hc.example.com/" + "a" * 200], "--hc-url", id="hc-url-too-long"),
        pytest.param(["--app-url", VALID["app"], "--topic", VALID["topic"], "--ntfy-server", "ftp://n.example"], "--ntfy-server", id="ntfy-server-scheme"),
        pytest.param(["--app-url", VALID["app"], "--topic", VALID["topic"], "--ntfy-server", "https://n.example/sub/path"], "--ntfy-server", id="ntfy-server-path"),
        pytest.param(["--app-url", VALID["app"], "--topic", VALID["topic"], "--ntfy-token", "short"], "--ntfy-token", id="ntfy-token-too-short"),
        pytest.param(["--app-url", VALID["app"], "--topic", VALID["topic"], "--ntfy-token", "has space aaaa"], "--ntfy-token", id="ntfy-token-charset"),
        pytest.param(["--app-url", VALID["app"], "--webhook-url", "http://hooks.example.com/x"], "--webhook-url", id="webhook-url-not-https"),
        pytest.param(["--app-url", VALID["app"], "--webhook-url", "https://hooks.example.com/x<y"], "--webhook-url", id="webhook-url-charset"),
        pytest.param(["--app-url", VALID["app"], "--webhook-url", VALID["webhook"], "--webhook-token", "short"], "--webhook-token", id="webhook-token-too-short"),
        pytest.param(["--app-url", VALID["app"]], "at least one notification channel", id="no-channel"),
        pytest.param(["--app-url", VALID["app"], "--topic", VALID["topic"], "--script", "/nonexistent/watchdog.sh"], "not found", id="script-missing"),
        pytest.param(["--app-url", VALID["app"], "--topic"], "--topic requires a value", id="flag-missing-value"),
        pytest.param(["--app-url", VALID["app"], "--topic", VALID["topic"], "--bogus"], "unknown argument", id="unknown-flag"),
    ],
)
def test_installer_rejects_invalid_args(argv, expect):
    r = run_installer(*argv)
    assert r.returncode == 2, f"expected rejection, got rc={r.returncode}\nstdout={r.stdout}\nstderr={r.stderr}"
    assert "ERROR" in r.stderr and expect in r.stderr, f"unexpected error text: {r.stderr}"


def test_installer_print_only_emits_contract_and_writes_nothing():
    r = run_installer(
        "--app-url", VALID["app"],
        "--topic", VALID["topic"],
        "--email", VALID["email"],
        "--hc-url", VALID["hc"],
        "--ntfy-server", VALID["ntfy_server"] + "/",  # trailing slash is normalized
        "--ntfy-token", VALID["ntfy_token"],
        "--webhook-url", VALID["webhook"],
        "--webhook-token", VALID["webhook_token"],
    )
    assert r.returncode == 0, r.stderr
    out = r.stdout
    # Env file: every key present, values single-quoted (the file is sourced).
    for line in [
        f"APP_URL='{VALID['app']}'",
        f"NTFY_TOPIC='{VALID['topic']}'",
        f"NTFY_SERVER='{VALID['ntfy_server']}'",
        f"NTFY_TOKEN='{VALID['ntfy_token']}'",
        f"WATCHDOG_EMAIL='{VALID['email']}'",
        f"HC_PING_URL='{VALID['hc']}'",
        f"WATCHDOG_WEBHOOK_URL='{VALID['webhook']}'",
        f"WATCHDOG_WEBHOOK_TOKEN='{VALID['webhook_token']}'",
    ]:
        assert line in out, f"missing env line: {line}\n{out}"
    # Customer base service set: sso ships in base (keycloak), add-on packs
    # (grafana/osd/self-monitoring) must NOT be demanded on a base install.
    svc = re.search(r"^WATCHDOG_SERVICES='([^']+)'", out, re.M)
    assert svc, out
    services = svc.group(1).split()
    assert "keycloak" in services and "api" in services and "kafka" in services
    assert "grafana" not in services and "opensearch-dashboards" not in services
    # Cron: minute cadence, root, explicit env file, bounded log, sane PATH.
    assert re.search(
        r"^\* \* \* \* \* root WATCHDOG_ENV=/etc/correlix/stack-watchdog\.env "
        r"/etc/correlix/stack-watchdog\.sh >>/var/log/correlix-watchdog\.log 2>&1$",
        out, re.M,
    ), out
    assert re.search(r"^PATH=\S*/usr/bin\S*$", out, re.M), "cron PATH= line missing"
    # Log growth is bounded.
    assert "/etc/logrotate.d/correlix-watchdog" in out and "size 5M" in out
    assert "nothing written" in out


def test_installer_uninstall_print_only():
    r = subprocess.run(
        ["bash", str(INSTALLER), "--uninstall", "--print-only"],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    for f in ("/etc/cron.d/correlix-watchdog", "/etc/correlix/stack-watchdog.env",
              "/etc/logrotate.d/correlix-watchdog"):
        assert f in r.stdout


# ---------------------------------------------------------------------------
# Publish path: execute the real functions with a fake curl on PATH
# ---------------------------------------------------------------------------

def _extract_notify_functions() -> str:
    return subprocess.run(
        ["sed", "-n",
         "-e", "/^push() {/,/^}/p",
         "-e", "/^json_str() {/,/^}/p",
         "-e", "/^notify_webhook() {/,/^}/p",
         str(WATCHDOG)],
        check=True, capture_output=True, text=True,
    ).stdout


def _run_notify(tmp_path, extra_env, call):
    """Run a snippet against the extracted notify functions with curl faked."""
    funcs = _extract_notify_functions()
    assert "push()" in funcs and "notify_webhook()" in funcs and "json_str()" in funcs
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    argsfile = tmp_path / "curl-args.txt"
    fake = bindir / "curl"
    fake.write_text('#!/bin/sh\nprintf \'%s\\n\' "$@" > "$CURL_ARGS_FILE"\nexit 0\n')
    fake.chmod(0o755)
    env = os.environ.copy()
    env["PATH"] = f"{bindir}:{env['PATH']}"
    env["CURL_ARGS_FILE"] = str(argsfile)
    env.update(extra_env)
    r = subprocess.run(["bash", "-c", funcs + "\n" + call],
                       env=env, capture_output=True, text=True)
    args = argsfile.read_text().splitlines() if argsfile.exists() else None
    return r, args


def _assert_bounded(args):
    assert "-m" in args, "curl call is unbounded (no -m)"
    assert args[args.index("-m") + 1] == "10"


def test_push_sends_email_and_bearer_headers(tmp_path):
    r, args = _run_notify(tmp_path, {
        "NTFY_TOPIC": "t0pic_x",
        "NTFY_SERVER": "https://ntfy.corp.example.com",
        "NTFY_TOKEN": VALID["ntfy_token"],
        "WATCHDOG_EMAIL": "noc@example.com",
    }, 'push "Title" "tag" "urgent" "body text"')
    assert r.returncode == 0, r.stderr
    assert args is not None, "curl was never invoked"
    assert "Email: noc@example.com" in args
    assert f"Authorization: Bearer {VALID['ntfy_token']}" in args
    assert "https://ntfy.corp.example.com/t0pic_x" in args
    _assert_bounded(args)


def test_push_without_email_or_token_omits_headers(tmp_path):
    r, args = _run_notify(tmp_path, {
        "NTFY_TOPIC": "t0pic_x",
        "NTFY_SERVER": "https://ntfy.example",
        "NTFY_TOKEN": "",
        "WATCHDOG_EMAIL": "",
    }, 'push "Title" "tag" "default" "body"')
    assert r.returncode == 0, r.stderr
    assert args is not None
    assert not any(a.startswith("Email:") for a in args)
    assert not any(a.startswith("Authorization:") for a in args)


def test_push_email_without_topic_refused_loudly(tmp_path):
    r, args = _run_notify(tmp_path, {
        "NTFY_TOPIC": "",
        "NTFY_SERVER": "https://ntfy.example",
        "WATCHDOG_EMAIL": "noc@example.com",
    }, 'push "Title" "tag" "default" "body"')
    assert r.returncode == 0, r.stderr
    assert args is None, "must not publish without a topic"
    assert "requires a topic" in r.stderr, "silent skip: §16.1 violation"


def test_webhook_posts_bounded_valid_json_with_bearer(tmp_path):
    detail = 'api: down\nnginx: state="exited" \\ backslash'
    r, args = _run_notify(tmp_path, {
        "WATCHDOG_WEBHOOK_URL": VALID["webhook"],
        "WATCHDOG_WEBHOOK_TOKEN": VALID["webhook_token"],
    }, f'notify_webhook "down" {json.dumps(detail)}')
    assert r.returncode == 0, r.stderr
    assert args is not None, "curl was never invoked"
    _assert_bounded(args)
    assert "Content-Type: application/json" in args
    assert f"Authorization: Bearer {VALID['webhook_token']}" in args
    assert VALID["webhook"] in args
    payload = json.loads(args[args.index("-d") + 1])
    assert set(payload) == {"text", "host", "status", "detail", "ts"}
    # "text" is load-bearing: Slack/Teams incoming webhooks reject
    # bodies without it (ultra-review find, 2026-08-14).
    assert payload["text"].startswith("Correlix watchdog:")
    assert payload["status"] == "down"
    assert 'nginx: state="exited"' in payload["detail"]


def test_webhook_skipped_when_unconfigured(tmp_path):
    r, args = _run_notify(tmp_path, {"WATCHDOG_WEBHOOK_URL": ""},
                          'notify_webhook "down" "detail"')
    assert r.returncode == 0, r.stderr
    assert args is None, "webhook must not fire without WATCHDOG_WEBHOOK_URL"


def test_webhook_fires_on_both_transitions():
    """The state machine, not just the function: the new-critical branch must
    notify the webhook alongside the urgent ntfy push, and the full-recovery
    branch must notify "up" (H16: per-problem-class machine)."""
    text = WATCHDOG.read_text()
    down = re.search(
        r'if \[ \$\{#new_crit\[@\]\} -gt 0 \]; then\n(.*?)\nelif ', text, re.S)
    assert down and 'notify_webhook "down"' in down.group(1)
    up = re.search(r'if \[ "\$prev_had_any" = 1 \]; then\n(.*?)\n  fi', text, re.S)
    assert up and 'notify_webhook "up"' in up.group(1)


# ---------------------------------------------------------------------------
# Kernel UDP-drop sentinel: execute check_syslog_udp_drops with a fake docker
# on PATH feeding canned /proc/net/snmp content
# ---------------------------------------------------------------------------

# Real-world header shape (column POSITIONS vary across kernels; the check must
# resolve RcvbufErrors / InErrors by NAME, which the swapped-order test pins).
SNMP_UDP_HEADER = ("Udp: InDatagrams NoPorts InErrors OutDatagrams "
                   "RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors")


def _snmp_content(in_errors, rcvbuf_errors):
    return (
        "Ip: Forwarding DefaultTTL\n"
        "Ip: 1 64\n"
        f"{SNMP_UDP_HEADER}\n"
        f"Udp: 51234 0 {in_errors} 4321 {rcvbuf_errors} 0 0 0 0\n"
        "UdpLite: InDatagrams NoPorts InErrors\n"
        "UdpLite: 0 0 0\n"
    )


def _extract_udp_check() -> str:
    return subprocess.run(
        ["sed", "-n", "/^check_syslog_udp_drops() {/,/^}/p", str(WATCHDOG)],
        check=True, capture_output=True, text=True,
    ).stdout


def _run_udp_check(tmp_path, snmp_content, state_before=None,
                   no_container=False, exec_fail=False):
    """Execute the extracted check with docker faked and push/webhook recorded.

    Returns (proc, pushes, webhooks, state_after) where pushes/webhooks are the
    recorded call lines and state_after is the state file content (or None).
    """
    funcs = _extract_udp_check()
    assert "check_syslog_udp_drops()" in funcs, \
        "check_syslog_udp_drops() not found in stack-watchdog.sh"
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    snmp_file = tmp_path / "proc-net-snmp"
    snmp_file.write_text(snmp_content)
    fake_docker = bindir / "docker"
    # ps → one container id (or none); exec → the canned /proc/net/snmp.
    fake_docker.write_text(
        "#!/bin/sh\n"
        'case "$1" in\n'
        "  ps)\n"
        '    [ -n "${FAKE_NO_CONTAINER:-}" ] && exit 0\n'
        "    echo deadbeefcafe\n"
        "    ;;\n"
        "  exec)\n"
        '    if [ -n "${FAKE_EXEC_FAIL:-}" ]; then\n'
        '      echo "OCI runtime exec failed: container not running" >&2\n'
        "      exit 1\n"
        "    fi\n"
        '    cat "$FAKE_SNMP_FILE"\n'
        "    ;;\n"
        "esac\n"
    )
    fake_docker.chmod(0o755)
    state = tmp_path / "udp.state"
    if state_before is not None:
        state.write_text(state_before)
    push_log = tmp_path / "push.log"
    webhook_log = tmp_path / "webhook.log"
    stubs = (
        'push() { printf \'%s|%s|%s|%s\\n\' "$1" "$2" "$3" "$4" >> "$PUSH_LOG"; }\n'
        'notify_webhook() { printf \'%s|%s\\n\' "$1" "$2" >> "$WEBHOOK_LOG"; }\n'
        # M25: the watchdog routes docker through its bounded dkr wrapper;
        # standalone extraction needs the same seam.
        'dkr() { docker "$@"; }\n'
        f'PROJECT=netops\nUDP_STATE="{state}"\n'
    )
    env = os.environ.copy()
    env["PATH"] = f"{bindir}:{env['PATH']}"
    env["FAKE_SNMP_FILE"] = str(snmp_file)
    env["PUSH_LOG"] = str(push_log)
    env["WEBHOOK_LOG"] = str(webhook_log)
    if no_container:
        env["FAKE_NO_CONTAINER"] = "1"
    if exec_fail:
        env["FAKE_EXEC_FAIL"] = "1"
    r = subprocess.run(
        ["bash", "-c", stubs + funcs + "\ncheck_syslog_udp_drops\n"],
        env=env, capture_output=True, text=True,
    )
    pushes = push_log.read_text().splitlines() if push_log.exists() else []
    webhooks = webhook_log.read_text().splitlines() if webhook_log.exists() else []
    state_after = state.read_text() if state.exists() else None
    return r, pushes, webhooks, state_after


def test_udp_check_first_run_baselines_without_alert(tmp_path):
    r, pushes, webhooks, state = _run_udp_check(tmp_path, _snmp_content(7, 5))
    assert r.returncode == 0, r.stderr
    assert pushes == [] and webhooks == [], "first run must only baseline, never alert"
    assert state is not None and state.split() == ["5", "7", "clean"], state


def test_udp_check_zero_delta_stays_quiet(tmp_path):
    r, pushes, webhooks, state = _run_udp_check(
        tmp_path, _snmp_content(7, 5), state_before="5 7 clean\n")
    assert r.returncode == 0, r.stderr
    assert pushes == [] and webhooks == []
    assert state.split() == ["5", "7", "clean"]


def test_udp_check_nonzero_delta_alerts_once_with_exact_deltas(tmp_path):
    r, pushes, webhooks, state = _run_udp_check(
        tmp_path, _snmp_content(12, 9), state_before="5 7 clean\n")
    assert r.returncode == 0, r.stderr
    assert len(pushes) == 1, f"exactly one drops-started push expected: {pushes}"
    body = pushes[0]
    assert "RcvbufErrors +4" in body and "InErrors +5" in body, \
        f"push must carry the exact deltas: {body}"
    assert len(webhooks) == 1, "webhook channel must also carry the transition"
    assert state.split() == ["9", "12", "dropping"]


def test_udp_check_sustained_drops_do_not_realert(tmp_path):
    r, pushes, webhooks, state = _run_udp_check(
        tmp_path, _snmp_content(20, 15), state_before="9 12 dropping\n")
    assert r.returncode == 0, r.stderr
    assert pushes == [] and webhooks == [], \
        "transition-only: sustained drops must not push once per minute"
    assert state.split() == ["15", "20", "dropping"]


def test_udp_check_recovery_alerts_when_drops_stop(tmp_path):
    r, pushes, webhooks, state = _run_udp_check(
        tmp_path, _snmp_content(20, 15), state_before="15 20 dropping\n")
    assert r.returncode == 0, r.stderr
    assert len(pushes) == 1 and "STOPPED" in pushes[0].upper(), \
        f"drops-stopped transition must push once: {pushes}"
    assert len(webhooks) == 1
    assert state.split() == ["15", "20", "clean"]


def test_udp_check_counter_reset_never_alerts_as_huge_delta(tmp_path):
    # Container restart resets the netns counters to ~0: the value goes
    # BACKWARD. An unsigned delta would read as ~2^32 drops; the check must
    # re-baseline silently instead.
    r, pushes, webhooks, state = _run_udp_check(
        tmp_path, _snmp_content(4, 3), state_before="5000 6000 clean\n")
    assert r.returncode == 0, r.stderr
    assert pushes == [] and webhooks == [], f"counter reset must not alert: {pushes}"
    assert state.split() == ["3", "4", "clean"]


def test_udp_check_counter_reset_while_dropping_keeps_state(tmp_path):
    # Reset mid-incident: the delta is unknowable, so neither a started nor a
    # stopped transition may fire; the drop-state carries over unchanged.
    r, pushes, webhooks, state = _run_udp_check(
        tmp_path, _snmp_content(4, 3), state_before="5000 6000 dropping\n")
    assert r.returncode == 0, r.stderr
    assert pushes == [] and webhooks == []
    assert state.split() == ["3", "4", "dropping"]


def test_udp_check_container_absent_is_not_measurable(tmp_path):
    r, pushes, webhooks, state = _run_udp_check(
        tmp_path, _snmp_content(7, 5), no_container=True)
    assert r.returncode == 0, "absent container must degrade, not fail the run"
    assert "not measurable" in r.stderr, f"§16.1: degradation must be named: {r.stderr}"
    assert pushes == [] and webhooks == [], "absent container must never false-alarm"
    assert state is None, "no measurement, no baseline write"


def test_udp_check_exec_failure_is_not_measurable(tmp_path):
    r, pushes, webhooks, state = _run_udp_check(
        tmp_path, _snmp_content(7, 5), state_before="5 7 clean\n", exec_fail=True)
    assert r.returncode == 0
    assert "not measurable" in r.stderr, r.stderr
    assert pushes == [] and webhooks == []
    assert state == "5 7 clean\n", "a failed read must not touch the baseline"


def test_udp_check_unparsable_snmp_is_not_measurable(tmp_path):
    r, pushes, webhooks, state = _run_udp_check(
        tmp_path, "Ip: Forwarding\nIp: 1\nTcp: ActiveOpens\nTcp: 3\n")
    assert r.returncode == 0
    assert "not measurable" in r.stderr, r.stderr
    assert pushes == [] and webhooks == []
    assert state is None


def test_udp_check_resolves_counters_by_column_name(tmp_path):
    # A kernel with a different column layout: positional parsing would read
    # the wrong counters; name resolution must still find the right two.
    content = (
        "Udp: RcvbufErrors InErrors InDatagrams NoPorts\n"
        "Udp: 7 9 100 0\n"
    )
    r, pushes, _, state = _run_udp_check(
        tmp_path, content, state_before="5 7 clean\n")
    assert r.returncode == 0, r.stderr
    assert len(pushes) == 1
    assert "RcvbufErrors +2" in pushes[0] and "InErrors +2" in pushes[0], pushes[0]
    assert state.split() == ["7", "9", "dropping"]


def test_udp_check_docker_exec_is_bounded():
    funcs = _extract_udp_check()
    assert re.search(r"timeout\s+10\s+docker exec", funcs), \
        "§16.3: docker exec must run under a hard timeout"
    assert re.search(r"command -v timeout", funcs), \
        "§16.2: probe for `timeout` and degrade to 'not measurable' when absent " \
        "— never fall back to an unbounded docker exec"


def test_udp_check_runs_in_main_flow():
    """The function must actually be invoked by the watchdog run, and its state
    file must ride the same overridable state-file mechanism as the others."""
    text = WATCHDOG.read_text()
    assert re.search(r"^check_syslog_udp_drops$", text, re.M), \
        "check_syslog_udp_drops is defined but never called"
    assert 'UDP_STATE="${WATCHDOG_UDPDROPS:-$SCRIPT_DIR/.stack-watchdog.udpdrops}"' in text


# ---------------------------------------------------------------------------
# Config-location + hygiene contracts
# ---------------------------------------------------------------------------

def test_watchdog_reads_etc_correlix_config():
    text = WATCHDOG.read_text()
    assert "/etc/correlix/stack-watchdog.env" in text
    # Existing lab behavior unchanged: the sibling env file still wins.
    assert 'ENV_FILE="$SCRIPT_DIR/stack-watchdog.env"' in text


def test_scripts_are_bash_clean():
    for script in (WATCHDOG, INSTALLER):
        r = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
        assert r.returncode == 0, f"bash -n {script.name}: {r.stderr}"


# ---------------------------------------------------------------------------
# pre-push hook: advisory checks may never hang a push
# ---------------------------------------------------------------------------

PRE_PUSH = SCRIPTS / "git-hooks" / "pre-push"


def test_pre_push_bundle_staleness_is_bounded_and_advisory():
    """(fix 2026-08-14) The hook's bundle-staleness step is ADVISORY (§16.5
    warn-only by design), but it shells into `ls dist/` + `git rev-list` with
    no bound — a wedged mount or pathological history hung `git push`
    indefinitely, which converts a warn-only convenience into a workflow
    outage. §16.3: every external call bounded. Pin:
      (a) the staleness invocation runs under a hard 10s `timeout` (with a
          kill escalation so a TERM-ignoring child still dies);
      (b) expiry (124 TERM / 137 KILL) is detected DISTINCTLY and warned
          loudly — "freshness unknown" must not read as "bundle stale";
      (c) the hook still ends `exit 0`: the advisory tail never blocks;
      (d) a host without `timeout` skips the check with a warning rather
          than reintroducing the unbounded call (§16.2: assume nothing)."""
    text = PRE_PUSH.read_text()
    # (a) bounded, with kill escalation, still --quiet hook mode
    assert re.search(
        r"timeout\s+--kill-after=\S+\s+10\s+bash\s+\S*bundle-staleness\.sh\"?\s+--quiet",
        text), (
        "pre-push: bundle-staleness.sh must run under `timeout --kill-after=… 10` "
        "— an advisory hook may never hang the push")
    # (b) timeout exit codes handled as their own loud outcome
    assert "124" in text and "137" in text, (
        "pre-push: timeout expiry (124/137) must be distinguished from a "
        "stale bundle — unknown is not stale")
    assert "TIMED OUT" in text, "pre-push: expiry warning must be loud and explicit"
    # (c) advisory to the end
    assert text.rstrip().endswith("exit 0"), (
        "pre-push must end `exit 0` — the staleness tail is warn-only")
    # (d) no unbounded fallback path
    assert re.search(r"command -v timeout", text), (
        "pre-push: probe for `timeout` and SKIP (with a warning) when absent "
        "— never fall back to the unbounded call")
    # floor: the hook itself parses
    r = subprocess.run(["bash", "-n", str(PRE_PUSH)], capture_output=True, text=True)
    assert r.returncode == 0, f"bash -n pre-push: {r.stderr}"


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck not installed")
def test_scripts_are_shellcheck_clean():
    for script in (WATCHDOG, INSTALLER):
        r = subprocess.run(["shellcheck", str(script)], capture_output=True, text=True)
        assert r.returncode == 0, f"shellcheck {script.name}:\n{r.stdout}{r.stderr}"
