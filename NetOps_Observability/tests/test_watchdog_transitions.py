"""Watchdog per-problem-class state machine + packaged-layout contract
(H16/H17/M25/M27, 2026-08-15).

The defect chain these pin:

  * H16(a) — the old watchdog kept ONE up/down flag. Any standing advisory
    problem (config drift, a stale backup, one misdetected probe) parked the
    flag at "down", and a service dying LATER arrived into "already down": no
    transition, no push, ever. Now state is a SET of active problem classes —
    a NEW critical key pushes regardless of what was already standing.
  * H16(b)/(c) + M27 — the packaged watchdog runs from /etc/correlix, where
    the repo-relative defaults (CH_ENV_FILE, the #150 backup-intent trio)
    resolve into /etc/... and silently miss, and the hard-coded
    https://clickhouse:8443 probe URL made every plaintext install report a
    permanent CLICKHOUSE_TLS_FAILURE. install-watchdog.sh now writes the real
    bundle paths into the env it generates, and the probe URL is detected
    from the stack .env's COMPOSE_FILE.
  * H17 — the OpenSearch probes were plain http://localhost:9200 and every
    consumer guarded its result with [ -n ], so a TLS install (https + auth)
    silently disabled ingest-stall/doc-reject/cluster-status/backup-freshness.
    Blindness is now the NAMED problem OPENSEARCH_UNVERIFIABLE.
  * M25 — overlapping cron runs on a wedged dockerd now yield on a flock.

Everything here runs the FULL script (no function extraction) from a COPIED
/etc/correlix-style layout, against the env file install-watchdog.sh itself
generates, with docker and curl faked on PATH.
"""

import fcntl
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
WATCHDOG = SCRIPTS / "stack-watchdog.sh"
INSTALLER = SCRIPTS / "install-watchdog.sh"

STACK_ENV_PLAIN = (
    "CLICKHOUSE_USER=netops\n"
    "CLICKHOUSE_PASSWORD=fake-ch-pw\n"
    "COMPOSE_PROFILES=embedded-bus,prober\n"
)
STACK_ENV_TLS = STACK_ENV_PLAIN + (
    "COMPOSE_FILE=docker-compose.yml:compose.tls.yml\n"
    "OS_API_PASSWORD=fake-os-api-pw\n"
    "OS_AGGREGATOR_PASSWORD=fake-os-mon-pw\n"
)

FAKE_DOCKER = r'''#!/bin/sh
# Scripted healthy stack. Env knobs break specific pieces:
#   FAKE_DOWN_SVC   this compose service has no container (critical problem)
#   FAKE_SNAP_OLD   newest OpenSearch snapshot is ~111h old (advisory problem)
#   FAKE_OS_EMPTY   every OpenSearch fetch returns nothing (H17 blindness)
#   OS_CFG_LOG      append each curl --config stdin here (probe forensics)
case "$1" in
  ps)
    svc=$(printf '%s\n' "$@" | sed -n 's/.*service=//p' | head -1)
    [ -n "$svc" ] || exit 0
    if [ -n "${FAKE_DOWN_SVC:-}" ] && [ "$svc" = "$FAKE_DOWN_SVC" ]; then exit 0; fi
    echo "cid-$svc"
    ;;
  inspect)
    fmt="$3"
    case "$2" in -f) fmt="$3";; *) fmt="$2";; esac
    case "$fmt" in
      *StartedAt*)     echo "${FAKE_API_STARTED:-}" ;;
      *RestartCount*)  echo "0 false 0" ;;
      *State.Status*)  echo "running" ;;
      *State.Health*)  echo "healthy" ;;
      *Mounts*)        echo "" ;;
      *.Id*)           echo "fullid" ;;
      *)               echo "" ;;
    esac
    ;;
  exec)
    shift
    [ "$1" = "-i" ] && shift
    shift   # container id
    case "$*" in
      *"/proc/net/snmp"*)
        printf 'Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors\n'
        printf 'Udp: 100 0 0 50 0 0\n' ;;
      *ALERTS*) echo '{}' ;;
      *wget*)   echo '{"status":"success","data":{"result":[{"value":[1723710000,"5"]}]}}' ;;
      *--config*)
        cfg=$(cat)
        [ -n "${OS_CFG_LOG:-}" ] && printf '%s\n----\n' "$cfg" >> "$OS_CFG_LOG"
        case "$cfg" in
          *corr_signals*) printf '10\nHTTP:200' ;;
          *)
            [ -n "${FAKE_OS_EMPTY:-}" ] && exit 0
            case "$cfg" in
              *_count*)          echo '{"count":42}' ;;
              *nodes/stats*)     echo '{"indices":{"indexing":{"doc_status":{"4xx":0}}}}' ;;
              *_cluster/health*) echo '{"status":"green"}' ;;
              *_cat/snapshots*)
                if [ -n "${FAKE_SNAP_OLD:-}" ]; then ep=$(( $(date +%s) - 400000 )); else ep=$(date +%s); fi
                printf '[{"id":"s1","status":"SUCCESS","end_epoch":"%s"}]' "$ep" ;;
            esac ;;
        esac ;;
      *ping*)   echo "Ok." ;;
      *"test -f"*) exit 1 ;;
      *) exit 1 ;;
    esac
    ;;
esac
exit 0
'''

FAKE_CURL = r'''#!/bin/sh
# Models the two HOST-side probes the watchdog makes through nginx :8000.
#   FAKE_API_DOWN   /admin/version refuses the connection (api process dead)
#   FAKE_API_5XX    nginx answers 502 (api container up, not serving)
#   FAKE_API_EMPTY  a 200 with an EMPTY body (not a serving api either)
printf 'CURL %s\n' "$*" >> "$CURL_LOG"
case "$*" in
  */admin/version*)
    if [ -n "${FAKE_API_DOWN:-}" ]; then
      echo "curl: (7) Failed to connect to localhost port 8000: Connection refused" >&2
      printf '\nHTTP:000'
      exit 7
    fi
    if [ -n "${FAKE_API_5XX:-}" ]; then
      printf '<html>502 Bad Gateway</html>\nHTTP:502'
      exit 0
    fi
    if [ -n "${FAKE_API_EMPTY:-}" ]; then
      printf '\nHTTP:200'
      exit 0
    fi
    printf '{"version":"0.1.0-scaffold","sha":"cafebabe","identified":true}\nHTTP:200'
    ;;
  *http_code*) printf '200' ;;
esac
exit 0
'''


def _write_exec(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _sandboxed_copy(src: Path, dest: Path, bindir: Path) -> None:
    """Copy the watchdog with the fake-tool bindir prepended to its OWN
    explicit-PATH export (the sanctioned test seam — see test_backup_ship)."""
    content = src.read_text()
    assert 'export PATH="' in content, f"{src.name} lost its explicit PATH export"
    dest.write_text(content.replace('export PATH="', f'export PATH="{bindir}:', 1))
    dest.chmod(0o755)


def _installed_layout(tmp_path: Path, stack_env: str = STACK_ENV_PLAIN,
                      intent: str | None = None):
    """Build a bundle tree + the /etc/correlix-style install from it, using the
    env file install-watchdog.sh ITSELF generates (--print-only), so the test
    breaks if the installer stops writing the paths the packaged layout needs."""
    bundle = tmp_path / "opt" / "correlix"
    (bundle / "scripts").mkdir(parents=True)
    (bundle / "deployment" / "docker").mkdir(parents=True)
    (bundle / "data" / "api").mkdir(parents=True)
    (bundle / "deployment" / "docker" / ".env").write_text(stack_env)
    shutil.copy(WATCHDOG, bundle / "scripts" / "stack-watchdog.sh")
    (bundle / "scripts" / "stack-watchdog.sh").chmod(0o755)
    applier_calls = tmp_path / "applier.calls"
    _write_exec(bundle / "scripts" / "apply-backup-config.sh",
                f'#!/bin/sh\necho run >> "{applier_calls}"\n'
                'echo "apply-backup-config: done."\nexit 0\n')
    if intent is not None:
        (bundle / "data" / "api" / "system_backup.json").write_text(intent)

    r = subprocess.run(
        ["bash", str(INSTALLER), "--print-only",
         "--app-url", "http://localhost:8000/",
         "--topic", "correlix-test-topic",
         "--script", str(bundle / "scripts" / "stack-watchdog.sh")],
        capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    m = re.search(r"== /etc/correlix/stack-watchdog\.env [^=]*==\n(.*?)\n\n== ",
                  r.stdout, re.S)
    assert m, f"installer --print-only did not emit the env file:\n{r.stdout}"
    env_text = m.group(1)

    etc = tmp_path / "etc" / "correlix"
    etc.mkdir(parents=True)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    _write_exec(bindir / "docker", FAKE_DOCKER)
    _write_exec(bindir / "curl", FAKE_CURL)
    _sandboxed_copy(WATCHDOG, etc / "stack-watchdog.sh", bindir)
    # The generated stamp path is /etc/correlix (root-owned on a real host);
    # this test's only rewrite is pointing THAT at its own etc dir.
    env_text = env_text.replace("/etc/correlix/.backup-config.applied",
                                str(etc / ".backup-config.applied"))
    (etc / "stack-watchdog.env").write_text(env_text)
    return bundle, etc, bindir, env_text, applier_calls


def _run(tmp_path: Path, etc: Path, run_name: str, **knobs):
    curl_log = tmp_path / f"curl.{run_name}.log"
    env = os.environ.copy()
    env.update({
        "WATCHDOG_ENV": str(etc / "stack-watchdog.env"),
        "CURL_LOG": str(curl_log),
        # keep the real host's disk usage out of the verdict
        "DISK_WARN_PCT": "101",
    })
    env.update({k: str(v) for k, v in knobs.items()})
    r = subprocess.run(["bash", str(etc / "stack-watchdog.sh")],
                       env=env, capture_output=True, text=True, timeout=300)
    pushes = curl_log.read_text() if curl_log.exists() else ""
    return r, pushes


# ---------------------------------------------------------------------------
# H16(b) — the installer writes the packaged-layout paths
# ---------------------------------------------------------------------------

def test_h16b_installer_env_carries_bundle_paths(tmp_path):
    bundle, etc, bindir, env_text, _ = _installed_layout(tmp_path)
    assert f"CH_ENV_FILE='{bundle}/deployment/docker/.env'" in env_text, env_text
    assert f"BACKUP_INTENT_FILE='{bundle}/data/api/system_backup.json'" in env_text
    assert f"BACKUP_APPLY_SCRIPT='{bundle}/scripts/apply-backup-config.sh'" in env_text
    assert "BACKUP_APPLY_STAMP=" in env_text
    assert "COMPOSE_PROJECT='netops'" in env_text


# ---------------------------------------------------------------------------
# H16 — full-script runs from the packaged layout
# ---------------------------------------------------------------------------

def test_h16_healthy_stack_from_etc_layout_reports_zero_problems(tmp_path):
    """The shipped-layout regression: with the installer-generated env, a
    healthy fake stack must produce NO problems — no phantom
    CLICKHOUSE_TLS_FAILURE from the old hard-coded https URL, no 'freshness
    UNCHECKED' from a /etc-relative CH_ENV_FILE."""
    _, etc, _, _, _ = _installed_layout(tmp_path)
    r, pushes = _run(tmp_path, etc, "healthy")
    assert r.returncode == 0, (
        f"healthy stack must exit 0; stderr:\n{r.stderr}\nstdout:\n{r.stdout}")
    assert "DOWN ->" not in r.stderr, r.stderr
    assert "NetOps stack DOWN" not in pushes
    state = (etc / ".stack-watchdog.state").read_text()
    assert state.strip() == "", f"healthy run must persist an empty problem set: {state!r}"


def test_h16_standing_advisory_does_not_mask_new_critical(tmp_path):
    """THE H16 regression. Old behavior: run 2's advisory parks the single flag
    at 'down'; run 3's dead service is then 'already down' — no push, ever."""
    _, etc, _, _, _ = _installed_layout(tmp_path)

    r1, p1 = _run(tmp_path, etc, "r1")
    assert r1.returncode == 0, r1.stderr

    # Run 2: a STANDING advisory problem appears (stale OpenSearch backup).
    r2, p2 = _run(tmp_path, etc, "r2", FAKE_SNAP_OLD=1)
    assert r2.returncode == 1, r2.stderr
    assert "backup STALE" in r2.stderr
    assert "NetOps advisory" in p2, f"a NEW advisory must push once: {p2}"
    assert "NetOps stack DOWN" not in p2, "an advisory is not an outage"

    # Run 3: the advisory still stands AND a service dies. The outage push
    # MUST fire despite the pre-existing problem.
    r3, p3 = _run(tmp_path, etc, "r3", FAKE_SNAP_OLD=1, FAKE_DOWN_SVC="api")
    assert r3.returncode == 1
    assert "NetOps stack DOWN" in p3, (
        "a NEW critical (api down) arriving on top of a standing advisory "
        f"must push — the exact defect H16 fixes. pushes:\n{p3}\nstderr:\n{r3.stderr}")
    assert "api: not running" in p3

    # Run 4: nothing new — sustained problems never re-push.
    r4, p4 = _run(tmp_path, etc, "r4", FAKE_SNAP_OLD=1, FAKE_DOWN_SVC="api")
    assert r4.returncode == 1
    assert "NetOps stack DOWN" not in p4, f"no transition, no push: {p4}"
    assert "NetOps advisory" not in p4

    # Run 5: everything heals — one recovery push.
    r5, p5 = _run(tmp_path, etc, "r5")
    assert r5.returncode == 0, r5.stderr
    assert "RECOVERED" in p5, f"full recovery must push once: {p5}"


def test_h16_critical_clear_with_standing_advisory_pushes_all_clear(tmp_path):
    _, etc, _, _, _ = _installed_layout(tmp_path)
    _run(tmp_path, etc, "seed", FAKE_SNAP_OLD=1, FAKE_DOWN_SVC="api")
    r, p = _run(tmp_path, etc, "heal-critical", FAKE_SNAP_OLD=1)
    assert r.returncode == 1, "the advisory still stands"
    assert "criticals CLEARED" in p, (
        f"criticals clearing while advisories remain must be announced: {p}")


# ---------------------------------------------------------------------------
# H17 — OpenSearch blindness is named, and TLS probes carry CA + credentials
# ---------------------------------------------------------------------------

def test_h17_unparsable_opensearch_reply_is_named_not_silent(tmp_path):
    _, etc, _, _, _ = _installed_layout(tmp_path, stack_env=STACK_ENV_TLS)
    r, _ = _run(tmp_path, etc, "os-blind", FAKE_OS_EMPTY=1)
    assert r.returncode == 1, (
        f"a blind search tier must fail the run, not pass silently: {r.stderr}")
    assert "OPENSEARCH_UNVERIFIABLE" in r.stderr, (
        "no parsable OpenSearch reply must be a NAMED problem "
        f"(the pre-fix [ -n ] guards silenced it): {r.stderr}")
    for probe in ("ingest-stall", "doc-rejects", "cluster-status", "backup-freshness"):
        assert probe in r.stderr, f"blindness must name the blinded probe {probe}: {r.stderr}"


def test_h17_tls_install_probes_with_https_auth_and_cacert(tmp_path):
    _, etc, _, _, _ = _installed_layout(tmp_path, stack_env=STACK_ENV_TLS)
    cfg_log = tmp_path / "os-cfg.log"
    r, _ = _run(tmp_path, etc, "tls-probe", OS_CFG_LOG=cfg_log)
    assert r.returncode == 0, r.stderr
    cfg = cfg_log.read_text()
    assert 'url = "https://opensearch:9200' in cfg, (
        "OS probes must go https to the SAN name on TLS installs:\n" + cfg)
    assert 'url = "https://localhost:9200' not in cfg, (
        "the OpenSearch wire cert carries DNS:opensearch + a SPIFFE URI and NO "
        "localhost, so a localhost probe fails hostname verification (curl 60, "
        f"http 000) and blinds the whole search tier:\n{cfg}")
    assert 'user = "svc_api:fake-os-api-pw"' in cfg, "count/health/snapshots ride svc_api"
    assert 'user = "svc_aggregator:fake-os-mon-pw"' in cfg, "nodes/stats rides svc_aggregator"
    assert "cacert" in cfg, "TLS probes must VERIFY the CA, never ride -k"
    # H16(c): the ClickHouse URL is detected from COMPOSE_FILE, not assumed.
    assert 'url = "https://clickhouse:8443/' in cfg, f"TLS variant must probe CH on 8443:\n{cfg}"


def test_h16c_plaintext_install_probes_clickhouse_on_8123(tmp_path):
    _, etc, _, _, _ = _installed_layout(tmp_path, stack_env=STACK_ENV_PLAIN)
    cfg_log = tmp_path / "ch-cfg.log"
    r, _ = _run(tmp_path, etc, "plain-probe", OS_CFG_LOG=cfg_log)
    assert r.returncode == 0, r.stderr
    cfg = cfg_log.read_text()
    assert 'url = "http://clickhouse:8123/' in cfg, (
        "plaintext installs must probe CH over http:8123 — the old https:8443 "
        f"default was a permanent false CLICKHOUSE_TLS_FAILURE:\n{cfg}")
    assert "CLICKHOUSE_TLS_FAILURE" not in r.stderr


def test_os_probe_url_host_is_never_localhost_on_tls_and_never_insecure():
    """Static guard for the 2026-09-03 blindness: the watchdog probed
    https://localhost:9200 from inside the opensearch container, but the issued
    cert's SANs are `DNS:opensearch` + the SPIFFE URI ONLY. curl exited 60 with
    http 000 on every run, so ingest-stall / doc-rejects / cluster-status /
    backup-freshness were permanently BLIND on exactly the TLS installs that
    carry customer data — reported as the useless guess "TLS/auth mismatch?".

    Pinned here rather than in a run-test because the tempting "fix" (-k) makes
    the symptom disappear while converting a real MITM or a misissued cert into
    a silent pass — the §16.1 defect class this repo exists to kill.
    """
    text = WATCHDOG.read_text()

    tls_urls = re.findall(r'OS_PROBE_URL="(https://[^"]+)"', text)
    assert tls_urls, "the TLS OpenSearch probe URL assignment disappeared"
    for url in tls_urls:
        host = url.split("://", 1)[1].split(":")[0].split("/")[0]
        assert host == "opensearch", (
            f"OS_PROBE_URL {url!r} uses host {host!r}; the OpenSearch cert's "
            "SAN set is DNS:opensearch + a SPIFFE URI, so any other name fails "
            "hostname verification (curl 60 / http 000)")

    # The plaintext default must survive: the probe must not become TLS-only.
    assert 'OS_PROBE_URL="http://' in text, \
        "plaintext installs still need a plain http OpenSearch probe"

    # No insecure escape hatch anywhere in the watchdog, in ANY of its three
    # spellings: the `-k`/`--insecure` flags and the `insecure` curl --config
    # directive (the probes are built as config files, so the directive is the
    # form that would actually be reached for).
    for ln in text.splitlines():
        if ln.strip().startswith("#"):
            continue
        assert "insecure" not in ln, (
            "-k/--insecure/`insecure` must never appear in a probe — it turns a "
            "real MITM or a misissued cert into a silent pass (§16.1): "
            f"{ln.strip()}")
        assert not re.search(r'curl\b[^|;#]*(^|\s)-[A-Za-z]*k(\s|$)', ln), \
            f"curl -k must never appear in a probe: {ln.strip()}"


def test_os_blind_run_names_the_evidenced_cause_not_a_guess():
    """A BLIND run must self-test and report WHICH failure it is, from curl's
    own exit code + http status — not the old "(TLS/auth mismatch? probe
    fault?)" guess. All four branches must exist and be evidence-keyed."""
    text = WATCHDOG.read_text()
    assert "os_probe_diag" in text, "the blind-run self-test is gone"
    code = "\n".join(ln for ln in text.splitlines()
                     if not ln.strip().startswith("#"))
    assert "TLS/auth mismatch?" not in code, \
        "the guess must stay replaced by a measured cause"
    for token in ("TLS_HOSTNAME", "TLS_CA", "AUTH", "UNREACHABLE", "UNCLASSIFIED"):
        assert f'os_diag_class="{token}"' in text, \
            f"os_probe_diag lost its {token} branch"
    # The $? trap: the exit code must be captured on its own line, never read
    # after an `if ! out=$(...)` (where it is the *if*'s status, always 0).
    assert re.search(r'^\s*os_diag_rc=\$\?', text, re.M), \
        "curl's exit code must be captured explicitly on its own line"
    assert not re.search(r'if\s*!\s*out=\$\(.*\)\s*;?\s*then', text)
    # problem_key hashes the first 160 chars with digits stripped. The self-test
    # CLASS and the raw codes may ride the problem text (a change of cause SHOULD
    # mint a new class); the run-varying curl message must NOT, or every minute
    # of a standing outage would re-push. Same discipline as API_UNRESPONSIVE.
    blind = next(ln for ln in text.splitlines()
                 if "OPENSEARCH_UNVERIFIABLE (self-test:" in ln)
    assert "os_diag_detail" not in blind, \
        "run-varying self-test detail must go to the log, not the problem text"
    assert "os_diag_class" in blind and "os_diag_rc" in blind
    head = blind.split("no parsable reply", 1)[0]
    assert "os_diag_class" in head, \
        "the cause class must land inside problem_key's 160-char window"


# ---------------------------------------------------------------------------
# M25 — overlap guard
# ---------------------------------------------------------------------------

def test_m25_flock_makes_overlapping_run_yield(tmp_path):
    _, etc, _, _, _ = _installed_layout(tmp_path)
    lock_path = etc / ".stack-watchdog.state.lock"
    lock_path.touch()
    with open(lock_path, "w") as holder:
        fcntl.flock(holder, fcntl.LOCK_EX)
        r, pushes = _run(tmp_path, etc, "overlap")
        assert r.returncode == 0, r.stderr
        assert "skipping this minute" in r.stderr, (
            f"an overlapping run must yield LOUDLY, not stack up: {r.stderr}")
        assert pushes == "", "a yielded run must not probe or push"
        assert not (etc / ".stack-watchdog.state").exists(), \
            "a yielded run must not touch the state machine"


def test_m25_docker_calls_are_bounded():
    text = WATCHDOG.read_text()
    assert re.search(r'dkr\(\)\s*\{ timeout "\$\{WATCHDOG_DOCKER_TIMEOUT:-20\}" docker "\$@"; \}', text), \
        "M25: the dkr wrapper must bound docker calls with timeout"
    # No stray unbounded docker INVOCATIONS (command position: line start,
    # $( capture, or a pipe) outside the wrapper definitions and the
    # already-bounded `timeout N docker exec` call sites. Problem-message
    # strings that merely mention docker are not invocations.
    bare = [
        ln for ln in text.splitlines()
        if re.search(r"(^\s*|\$\(\s*|\|\s*|!\s*)docker\s+(ps|inspect|logs|exec|builder)", ln)
        and "timeout" not in ln and "dkr" not in ln and not ln.strip().startswith("#")
    ]
    assert bare == [], f"unbounded docker calls remain: {bare}"


# ---------------------------------------------------------------------------
# M27 — the installer-written intent paths actually close the #150 loop
# ---------------------------------------------------------------------------

def test_m27_packaged_intent_is_applied_via_installer_paths(tmp_path):
    _, etc, _, _, applier_calls = _installed_layout(
        tmp_path, intent='{"schedule_enabled": true}')
    r1, _ = _run(tmp_path, etc, "intent1")
    assert r1.returncode == 0, r1.stderr
    assert applier_calls.exists() and applier_calls.read_text().count("run") == 1, (
        "the packaged intent must reach the applier through the "
        "installer-written BACKUP_* paths (pre-fix: defaults under /etc "
        "meant it was silently never applied)")
    assert (etc / ".backup-config.applied").exists(), "a successful apply must stamp"
    r2, _ = _run(tmp_path, etc, "intent2")
    assert r2.returncode == 0, r2.stderr
    assert applier_calls.read_text().count("run") == 1, \
        "unchanged intent must not re-apply (stamp discipline)"


# ---------------------------------------------------------------------------
# Tracker 194 — api liveness through nginx, with a cold-boot grace
#
# The blind spot this pins: APP_URL (:8000/) is proxied to the FRONTEND, so the
# SPA answers 200 with the api dead; nginx declares no /healthz location, so
# that path falls through to the SPA too; the api container declares no
# healthcheck, so the container loop reads "running"; and the one api-touching
# check (build_drift_check) emits BUILD UNVERIFIABLE, which problem_is_critical
# does not match — advisory only. A two-minute api outage on 2026-08-31 was
# therefore invisible: no urgent page, and the dead-man's switch kept pinging
# "healthy" throughout.
# ---------------------------------------------------------------------------

HC_URL = "https://hc.example.test/ping-token"


def _with_hc(etc):
    """Give the layout a healthchecks.io dead-man URL so the ping/withhold
    behaviour is observable in the curl log."""
    envf = etc / "stack-watchdog.env"
    envf.write_text(envf.read_text() + f"\nHC_PING_URL='{HC_URL}'\n")


def _api_state(etc):
    return etc / ".stack-watchdog.api"


def _seed_api_state(etc, first_fail_ago_s: int, escalated: int) -> None:
    import time
    _api_state(etc).write_text(f"{int(time.time()) - first_fail_ago_s} {escalated}\n")


def test_t194_healthy_api_is_probed_and_pings_the_dead_man(tmp_path):
    """The probe runs in the normal flow, hits /admin/version through :8000,
    and a healthy api leaves the dead-man's ping intact."""
    _, etc, _, _, _ = _installed_layout(tmp_path)
    _with_hc(etc)
    r, curl_log = _run(tmp_path, etc, "api-ok")
    assert r.returncode == 0, f"{r.stderr}\n{r.stdout}"
    assert "/admin/version" in curl_log, (
        f"the api liveness probe must actually run every cron minute:\n{curl_log}")
    assert HC_URL in curl_log, "a healthy stack must still ping the dead-man's switch"
    assert not _api_state(etc).exists(), \
        "a passing probe must leave no api-failure state behind"


def test_t194_first_failing_minutes_are_graced_but_withhold_the_heartbeat(tmp_path):
    """Cold boot: ~2.5 min of fault-in must NOT page (every redeploy would),
    but the dead-man's switch must stop reading 'healthy' immediately — that is
    the whole point of a dead-man's switch."""
    _, etc, _, _, _ = _installed_layout(tmp_path)
    _with_hc(etc)
    r, curl_log = _run(tmp_path, etc, "api-grace", FAKE_API_DOWN=1)
    assert r.returncode == 0, f"a graced cold boot is not yet an outage:\n{r.stderr}"
    assert "cold-boot grace" in r.stderr, r.stderr
    assert "NetOps stack DOWN" not in curl_log, "no page inside the grace window"
    assert "NetOps advisory" not in curl_log, \
        "the grace must add NO push noise — every deploy would fire one"
    assert HC_URL not in curl_log, (
        "REQUIREMENT 3: a non-serving api must STOP the healthy dead-man ping, "
        f"grace or not:\n{curl_log}")
    assert _api_state(etc).exists(), "the first failure must anchor the grace clock"
    assert _api_state(etc).read_text().split()[1] == "0", "not escalated yet"


def test_t194_sustained_api_outage_escalates_to_a_critical_page(tmp_path):
    """Past the grace the failure is CRITICAL: it rides the existing up<->down
    transition machine (urgent push + /fail), and a sustained outage pushes
    exactly ONCE."""
    _, etc, _, _, _ = _installed_layout(tmp_path)
    _with_hc(etc)
    _seed_api_state(etc, first_fail_ago_s=200, escalated=0)

    r, curl_log = _run(tmp_path, etc, "api-crit", FAKE_API_DOWN=1)
    assert r.returncode == 1, f"an api outage must fail the run:\n{r.stderr}"
    assert "API_UNRESPONSIVE" in r.stderr, r.stderr
    assert "NetOps stack DOWN" in curl_log, (
        "an api outage must page URGENTLY like any other critical — the "
        f"pre-fix BUILD UNVERIFIABLE string was advisory only:\n{curl_log}")
    assert f"{HC_URL}/fail" in curl_log, "a down api must hit the dead-man /fail leg"
    assert f"{HC_URL} -o" not in curl_log, \
        "the healthy ping must not also be sent while the api is down"
    assert _api_state(etc).read_text().split()[1] == "1", "escalation must be recorded"

    # Sustained: no transition, no second page.
    r2, curl2 = _run(tmp_path, etc, "api-crit-2", FAKE_API_DOWN=1)
    assert r2.returncode == 1
    assert "NetOps stack DOWN" not in curl2, (
        "a sustained outage must not re-push every minute — the problem key "
        f"must be stable across runs (no digits in its first 160 chars):\n{curl2}")

    # Recovery: one all-clear, and the api state is cleared.
    r3, curl3 = _run(tmp_path, etc, "api-recover")
    assert r3.returncode == 0, r3.stderr
    assert "RECOVERED" in curl3, f"recovery must be announced once:\n{curl3}"
    assert "api liveness RESTORED" in r3.stderr, r3.stderr
    assert not _api_state(etc).exists()


def test_t194_escalation_is_sticky_across_a_container_restart(tmp_path):
    """A crash-looping api must not win a fresh 150 s grace every restart —
    once escalated the verdict holds until a probe actually SUCCEEDS."""
    import datetime
    _, etc, _, _, _ = _installed_layout(tmp_path)
    _seed_api_state(etc, first_fail_ago_s=200, escalated=1)
    just_now = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.000000000Z")
    r, _ = _run(tmp_path, etc, "api-sticky", FAKE_API_DOWN=1,
                FAKE_API_STARTED=just_now)
    assert r.returncode == 1, r.stderr
    assert "API_UNRESPONSIVE" in r.stderr, (
        "a restart mid-outage must not re-open the grace once escalated: "
        f"{r.stderr}")


def test_t194_a_restart_mid_outage_re_opens_the_boot_budget_once(tmp_path):
    """The grace anchor is the LATER of first-failure and container start, so a
    container that has only just started is still inside its cold-boot budget
    even though the failure itself is older."""
    import datetime
    _, etc, _, _, _ = _installed_layout(tmp_path)
    _seed_api_state(etc, first_fail_ago_s=300, escalated=0)
    just_now = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.000000000Z")
    r, curl_log = _run(tmp_path, etc, "api-restart-grace", FAKE_API_DOWN=1,
                       FAKE_API_STARTED=just_now)
    assert r.returncode == 0, f"a just-restarted api is still booting:\n{r.stderr}"
    assert "cold-boot grace" in r.stderr, r.stderr
    assert "NetOps stack DOWN" not in curl_log


def test_t194_hard_ceiling_beats_a_restart_loop(tmp_path):
    """The grace can never suppress forever: past API_BOOT_GRACE_MAX_SEC the
    failure escalates however recently the container started."""
    import datetime
    _, etc, _, _, _ = _installed_layout(tmp_path)
    _seed_api_state(etc, first_fail_ago_s=700, escalated=0)
    just_now = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.000000000Z")
    r, _ = _run(tmp_path, etc, "api-ceiling", FAKE_API_DOWN=1,
                FAKE_API_STARTED=just_now)
    assert r.returncode == 1, r.stderr
    assert "API_UNRESPONSIVE" in r.stderr, r.stderr


def test_t194_a_502_and_an_empty_200_both_count_as_not_serving(tmp_path):
    """nginx answering 502, and a 200 with an empty body, are both 'the api is
    not serving' — the probe requires 200 AND a body."""
    for knob, name in (({"FAKE_API_5XX": 1}, "502"), ({"FAKE_API_EMPTY": 1}, "empty")):
        sub = tmp_path / name
        sub.mkdir()
        _, etc, _, _, _ = _installed_layout(sub)
        _seed_api_state(etc, first_fail_ago_s=200, escalated=0)
        r, curl_log = _run(sub, etc, f"api-{name}", **knob)
        assert r.returncode == 1, f"{name}: {r.stderr}"
        assert "API_UNRESPONSIVE" in r.stderr, f"{name}: {r.stderr}"
        assert "NetOps stack DOWN" in curl_log, f"{name}: {curl_log}"


def test_t194_test_mode_exercises_the_api_probe(tmp_path):
    """--test must exercise the probe it arms, not only the push channels."""
    _, etc, bindir, _, _ = _installed_layout(tmp_path)
    env = os.environ.copy()
    env.update({"WATCHDOG_ENV": str(etc / "stack-watchdog.env"),
                "CURL_LOG": str(tmp_path / "curl.test.log")})
    ok = subprocess.run(["bash", str(etc / "stack-watchdog.sh"), "--test"],
                        env=env, capture_output=True, text=True, timeout=120)
    assert ok.returncode == 0, f"{ok.stdout}\n{ok.stderr}"
    assert "api liveness probe OK" in ok.stdout, ok.stdout
    assert "/admin/version" in ok.stdout, ok.stdout

    env["FAKE_API_DOWN"] = "1"
    env["CURL_LOG"] = str(tmp_path / "curl.test2.log")
    bad = subprocess.run(["bash", str(etc / "stack-watchdog.sh"), "--test"],
                         env=env, capture_output=True, text=True, timeout=120)
    assert bad.returncode == 1, (
        "--test must FAIL loudly when the probe it arms cannot reach the api "
        f"(§16.1): rc={bad.returncode}\n{bad.stdout}\n{bad.stderr}")
    assert "api liveness probe FAILED" in bad.stderr, bad.stderr
    assert "CRITICAL" in bad.stderr, "say what a sustained failure would do"


def test_t194_api_liveness_is_wired_into_the_main_flow_and_classified():
    """Contract pins, so the probe cannot be quietly downgraded again."""
    text = WATCHDOG.read_text()
    assert re.search(r"^check_api_liveness$", text, re.M), \
        "check_api_liveness is defined but never called"
    assert 'API_PROBE_URL="${API_PROBE_URL:-${APP_URL%/}/admin/version}"' in text, \
        "the api probe must target /admin/version — the one route only the api answers"
    assert 'API_STATE="${WATCHDOG_API_STATE:-$SCRIPT_DIR/.stack-watchdog.api}"' in text, \
        "the grace state must ride the same overridable state-file mechanism"
    crit = re.search(r"problem_is_critical\(\) \{(.*?)\n\}", text, re.S)
    assert crit and "API_UNRESPONSIVE" in crit.group(1), (
        "API_UNRESPONSIVE must be CRITICAL — an advisory api outage is exactly "
        "the tracker-194 defect")
    # The pre-existing advisory stays advisory (requirement 5: no new noise).
    assert "BUILD UNVERIFIABLE" in text and "BUILD UNVERIFIABLE" not in crit.group(1)


# ---------------------------------------------------------------------------
# hygiene floor
# ---------------------------------------------------------------------------

def test_watchdog_parses():
    r = subprocess.run(["bash", "-n", str(WATCHDOG)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck not installed")
def test_watchdog_shellcheck_clean():
    r = subprocess.run(["shellcheck", "-x", str(WATCHDOG)], capture_output=True, text=True)
    assert r.returncode == 0, f"shellcheck stack-watchdog.sh:\n{r.stdout}{r.stderr}"
