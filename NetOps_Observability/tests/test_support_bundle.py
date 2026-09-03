"""scripts/support-bundle.sh — the pilot diagnostic bundle (Project 2, G6).

What a support bundle must guarantee, and what this suite pins:

  * COMPLETE — every collector is accounted for in the MANIFEST, and the
    MANIFEST's sha256 matches the packed file byte-for-byte.
  * REDACTED — a canary secret planted in the resolved compose config, in a
    URL userinfo credential, and in a CONTAINER LOG LINE (where no key name
    hints at it) never reaches the archive. `.env` ships as key names only.
  * NEVER SILENTLY PARTIAL (§16.1) — a failing collector yields exit 2, the
    bundle is still written, and the failure is NAMED in the MANIFEST.
  * READ-ONLY against a live stack — the Kafka collector may only `--describe`.
  * shellcheck/bash -n clean (§16.3 merge bar).

Everything runs against fakes: a scripted `docker` and `curl` on PATH, a
throwaway install tree, a temp output dir. No stack, no daemon, no network.

Run:  python3 -m pytest tests/test_support_bundle.py -v
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
SUPPORT = SCRIPTS / "support-bundle.sh"
INSTALL_SH = SCRIPTS / "install-correlix.sh"

# Canary values. Each one probes a DIFFERENT redaction path:
CANARY_ENV_PW = "canary-pg-password-4f2a9c"      # .env value, echoed in a log line
CANARY_ENV_JWT = "canary-jwt-secret-b71e3d"      # .env value, in compose config
CANARY_CONFIG_ONLY = "canary-config-only-9ab4c1"  # only in compose config (key-pattern)
KEEP_ME = "keep-me-visible-marker"                # non-secret key: must SURVIVE

STACK_ENV = f"""\
# Correlix stack environment (fake)
BASE_PORT=8000
COMPOSE_PROJECT_NAME=netops
COMPOSE_PROFILES=embedded-bus,prober
CLICKHOUSE_USER=netops
CLICKHOUSE_PASSWORD={CANARY_ENV_PW}
JWT_SECRET={CANARY_ENV_JWT}
ADMIN_USERNAME=admin
CORRELIX_EDITION={KEEP_ME}
"""

FAKE_DOCKER = r'''#!/bin/sh
# Scripted stack. Knobs:
#   FAKE_STATS_FAIL   `docker stats` fails (collector failure -> exit 2)
#   FAKE_NO_KAFKA     no kafka container (collector failure)
#   KAFKA_ARGV_LOG    append every kafka-consumer-groups.sh argv here
[ -n "${DOCKER_ARGV_LOG:-}" ] && printf '%s\n' "$*" >> "$DOCKER_ARGV_LOG"
case "$1" in
  compose)
    shift
    case "$1" in
      ps)
        echo "NAME                 IMAGE            STATUS"
        echo "netops-api-1         correlix/api     Up 3 hours (healthy)"
        echo "netops-clickhouse-1  clickhouse       Up 3 hours (healthy)"
        ;;
      config)
        cat <<'YAML'
services:
  api:
    image: correlix/api
    environment:
      JWT_SECRET: __CANARY_ENV_JWT__
      SOME_APP_KEY: __CANARY_CONFIG_ONLY__
      DATABASE_URL: postgres://netops:__CANARY_ENV_PW__@postgres:5432/netops
      CORRELIX_EDITION: __KEEP_ME__
  clickhouse:
    image: clickhouse/clickhouse-server
    environment:
      - CLICKHOUSE_PASSWORD=__CANARY_ENV_PW__
      - CLICKHOUSE_USER=netops
YAML
        ;;
      *) echo "fake compose: unhandled $1" >&2; exit 1 ;;
    esac
    ;;
  stats)
    if [ -n "${FAKE_STATS_FAIL:-}" ]; then
      echo "Cannot connect to the Docker daemon at unix:///var/run/docker.sock." >&2
      exit 3
    fi
    echo "CONTAINER      CPU %   MEM USAGE / LIMIT"
    echo "netops-api-1   2.10%   310MiB / 4GiB"
    ;;
  ps)
    case "$*" in
      *service=kafka*)
        [ -n "${FAKE_NO_KAFKA:-}" ] && exit 0
        echo "cid-kafka" ;;
      *service=opensearch*)    echo "cid-opensearch" ;;
      *service=vector-router*) echo "cid-vector-router" ;;
      *"{{.Names}}"*)
        echo "netops-api-1"
        echo "netops-clickhouse-1" ;;
      *) exit 0 ;;
    esac
    ;;
  exec)
    shift
    [ "$1" = "-i" ] && shift
    shift   # container id
    case "$*" in
      *kafka-consumer-groups.sh*)
        [ -n "${KAFKA_ARGV_LOG:-}" ] && printf '%s\n' "$*" >> "$KAFKA_ARGV_LOG"
        echo "GROUP              TOPIC        PARTITION  CURRENT-OFFSET  LOG-END-OFFSET  LAG"
        echo "netops-correlation netops.flows 0          128374          128390          16"
        ;;
      *vmalert*)
        echo '{"status":"success","data":{"alerts":[]}}' ;;
      *ALERTS*)
        echo '{"status":"success","data":{"result":[]}}' ;;
      *--config*)
        cfg=$(cat)
        case "$cfg" in
          *system.parts*)
            printf 'database\ttable\trows\tsize\tparts\n'
            printf 'netops\tcorr_signals\t1200\t4.10 MiB\t3\n'
            printf 'HTTP:200\n' ;;
          *corr_signals*)
            printf 'tbl\trows\ncorr_current\t42\ncorr_signals\t1200\n'
            printf 'HTTP:200\n' ;;
          *_cluster/health*)
            echo '{"cluster_name":"netops","status":"green"}' ;;
          *_cat/indices*)
            printf 'health index                 store.size\n'
            printf 'green  netops-applogs-000001 10485760\n' ;;
          *) echo "fake docker exec curl: unhandled config" >&2; exit 22 ;;
        esac ;;
      *) echo "fake docker exec: unhandled $*" >&2; exit 1 ;;
    esac
    ;;
  logs)
    # The log line carries a REAL .env secret with no key name near it — only
    # the literal-value redaction pass can catch this one.
    echo "2026-09-02T00:00:01Z api connecting to postgres with __CANARY_ENV_PW__"
    echo "2026-09-02T00:00:02Z api ready (__KEEP_ME__)"
    ;;
  *) echo "fake docker: unhandled $1" >&2; exit 1 ;;
esac
exit 0
'''

FAKE_CURL = r'''#!/bin/sh
# Host-side probes through nginx. The script always hands the request on a
# curl config via STDIN (credentials must never ride argv).
cfg=$(cat)
url=$(printf '%s' "$cfg" | sed -n 's/^url = "\(.*\)"$/\1/p' | head -1)
[ -n "${CURL_LOG:-}" ] && printf '%s\n%s\n----\n' "$*" "$cfg" >> "$CURL_LOG"
case "$url" in
  */admin/version)
    printf '{"version":"0.1.0","sha":"cafebabe"}\nHTTP:200\n' ;;
  */api/health)
    printf '{"error":"unauthorized"}\nHTTP:401\n' ;;
  */api/health/score*)
    printf '{"error":"unauthorized"}\nHTTP:401\n' ;;
  *)
    echo "fake curl: unhandled url $url" >&2; exit 7 ;;
esac
exit 0
'''


def _write_exec(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _sandboxed_copy(src: Path, dest: Path, bindir: Path) -> None:
    """Copy the script with the fake-tool bindir prepended to its OWN explicit
    PATH export — the sanctioned test seam (see tests/test_watchdog_transitions)."""
    content = src.read_text()
    assert 'export PATH="' in content, f"{src.name} lost its explicit PATH export"
    dest.write_text(content.replace('export PATH="', f'export PATH="{bindir}:', 1))
    dest.chmod(0o755)


@pytest.fixture
def sandbox(tmp_path: Path):
    """A throwaway install tree + fake docker/curl, ready to run."""
    root = tmp_path / "opt" / "correlix"
    (root / "scripts").mkdir(parents=True)
    (root / "deployment" / "docker").mkdir(parents=True)
    (root / "deployment" / "docker" / "docker-compose.yml").write_text("services: {}\n")
    (root / "deployment" / "docker" / ".env").write_text(STACK_ENV)

    bindir = tmp_path / "bin"
    bindir.mkdir()
    docker = (FAKE_DOCKER
              .replace("__CANARY_ENV_JWT__", CANARY_ENV_JWT)
              .replace("__CANARY_CONFIG_ONLY__", CANARY_CONFIG_ONLY)
              .replace("__CANARY_ENV_PW__", CANARY_ENV_PW)
              .replace("__KEEP_ME__", KEEP_ME))
    _write_exec(bindir / "docker", docker)
    _write_exec(bindir / "curl", FAKE_CURL)
    _sandboxed_copy(SUPPORT, root / "scripts" / "support-bundle.sh", bindir)

    out = tmp_path / "out"
    out.mkdir()
    return {"root": root, "bindir": bindir, "out": out,
            "script": root / "scripts" / "support-bundle.sh", "tmp": tmp_path}


def run_bundle(sandbox, *args, **knobs) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.update({"WATCHDOG_LOG_FILE": str(sandbox["tmp"] / "no-such-watchdog.log"),
                "DOCKER_ARGV_LOG": str(sandbox["tmp"] / "docker.argv"),
                "KAFKA_ARGV_LOG": str(sandbox["tmp"] / "kafka.argv"),
                "CURL_LOG": str(sandbox["tmp"] / "curl.log")})
    env.update({k: str(v) for k, v in knobs.items()})
    return subprocess.run(["bash", str(sandbox["script"]),
                           "--out", str(sandbox["out"]), *args],
                          capture_output=True, text=True, timeout=300,
                          env=env, check=False)


def archive_of(sandbox) -> Path:
    archives = sorted(sandbox["out"].glob("correlix-support-*.tar.zst"))
    assert len(archives) == 1, f"expected exactly one archive, got {archives}"
    return archives[0]


def extract(sandbox, tmp_path: Path) -> Path:
    """Unpack the archive; return the bundle directory."""
    arc = archive_of(sandbox)
    tar_path = tmp_path / "bundle.tar"
    subprocess.run(["zstd", "-d", "-q", "-f", str(arc), "-o", str(tar_path)],
                   check=True, timeout=120)
    dest = tmp_path / "unpacked"
    dest.mkdir()
    with tarfile.open(tar_path) as tf:
        tf.extractall(dest)          # our own archive, written above
    dirs = [d for d in dest.iterdir() if d.is_dir()]
    assert len(dirs) == 1
    return dirs[0]


def manifest_rows(bundle: Path) -> list[tuple[str, str, str]]:
    """(status, relative path, note) triples from the MANIFEST STATUS block."""
    text = (bundle / "MANIFEST").read_text()
    block = text.split("STATUS", 1)[1].split("SHA256", 1)[0]
    rows = []
    for line in block.splitlines():
        parts = line.strip().split("\t")
        if len(parts) >= 2 and parts[0] in ("ok", "skip", "note", "FAILED"):
            rows.append((parts[0], parts[1], parts[2] if len(parts) > 2 else ""))
    return rows


# ── happy path: shape, completeness, manifest integrity ──────────────────────

def test_bundle_is_written_and_names_itself_by_host_and_utc_stamp(sandbox):
    r = run_bundle(sandbox)
    assert r.returncode == 0, r.stderr
    arc = archive_of(sandbox)
    assert re.match(r"^correlix-support-[A-Za-z0-9._-]+-\d{8}T\d{6}Z\.tar\.zst$",
                    arc.name), arc.name
    # The archive can hold operational detail: never world-readable.
    assert stat.S_IMODE(arc.stat().st_mode) == 0o600


def test_every_expected_collector_is_present(sandbox, tmp_path):
    assert run_bundle(sandbox).returncode == 0
    bundle = extract(sandbox, tmp_path)
    expected = [
        "MANIFEST",
        "compose/ps.txt", "compose/config.redacted.yml", "compose/env-keys.txt",
        "docker/stats.txt",
        "host/df.txt", "host/free.txt", "host/uname.txt", "host/nproc.txt",
        "api/admin-version.json", "api/health.json", "api/health-score.json",
        "bus/kafka-consumer-lag.txt",
        "store/clickhouse-parts.tsv", "store/clickhouse-corr-rows.tsv",
        "store/opensearch-cluster-health.json", "store/opensearch-indices.txt",
        "alerts/vmalert-alerts.json",
        "watchdog/watchdog-log.txt",
        "logs/netops-api-1.log", "logs/netops-clickhouse-1.log",
    ]
    for rel in expected:
        assert (bundle / rel).is_file(), f"missing collector output: {rel}"


def test_manifest_sha256_covers_and_matches_every_packed_file(sandbox, tmp_path):
    assert run_bundle(sandbox).returncode == 0
    bundle = extract(sandbox, tmp_path)
    text = (bundle / "MANIFEST").read_text()
    listed = {}
    for line in text.split("SHA256", 1)[1].splitlines():
        m = re.match(r"^([0-9a-f]{64})  (.+)$", line.strip())
        if m:
            listed[m.group(2)] = m.group(1)
    on_disk = {str(p.relative_to(bundle)) for p in bundle.rglob("*") if p.is_file()}
    on_disk.discard("MANIFEST")
    assert set(listed) == on_disk, "MANIFEST sha256 block does not cover every file"
    for rel, digest in listed.items():
        actual = hashlib.sha256((bundle / rel).read_bytes()).hexdigest()
        assert actual == digest, f"{rel}: MANIFEST digest does not match content"


def test_manifest_header_states_counts_exit_code_and_redaction(sandbox, tmp_path):
    assert run_bundle(sandbox).returncode == 0
    text = (extract(sandbox, tmp_path) / "MANIFEST").read_text()
    assert re.search(r"collectors:\s+\d+ ok, \d+ skipped, 0 FAILED", text)
    assert re.search(r"exit_code:\s+0", text)
    assert "REDACTION" in text and "KEY NAMES ONLY" in text


def test_every_collector_has_a_status_row(sandbox, tmp_path):
    assert run_bundle(sandbox).returncode == 0
    bundle = extract(sandbox, tmp_path)
    rows = {rel for _, rel, _ in manifest_rows(bundle)}
    for rel in ("compose/ps.txt", "compose/config.redacted.yml",
                "compose/env-keys.txt", "docker/stats.txt", "host/df.txt",
                "api/admin-version.json", "bus/kafka-consumer-lag.txt",
                "store/clickhouse-parts.tsv", "alerts/vmalert-alerts.json",
                "logs/netops-api-1.log"):
        assert rel in rows, f"{rel} produced no MANIFEST status row"


# ── redaction ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("canary", [CANARY_ENV_PW, CANARY_ENV_JWT, CANARY_CONFIG_ONLY])
def test_no_canary_secret_survives_anywhere_in_the_bundle(sandbox, tmp_path, canary):
    assert run_bundle(sandbox).returncode == 0
    bundle = extract(sandbox, tmp_path)
    hits = [str(p.relative_to(bundle)) for p in bundle.rglob("*")
            if p.is_file() and canary in p.read_text(errors="replace")]
    assert hits == [], f"secret {canary!r} leaked into: {hits}"


def test_redaction_keeps_non_secret_content(sandbox, tmp_path):
    """Over-redaction that eats the diagnostic value is its own failure mode."""
    assert run_bundle(sandbox).returncode == 0
    bundle = extract(sandbox, tmp_path)
    body = "\n".join(p.read_text(errors="replace") for p in bundle.rglob("*")
                     if p.is_file())
    assert KEEP_ME in body
    assert "***REDACTED***" in body
    assert "corr_signals" in (bundle / "store/clickhouse-parts.tsv").read_text()


def test_url_userinfo_credentials_are_redacted(sandbox, tmp_path):
    assert run_bundle(sandbox).returncode == 0
    cfg = (extract(sandbox, tmp_path) / "compose/config.redacted.yml").read_text()
    assert "postgres://netops:***REDACTED***@postgres" in cfg


def test_env_ships_key_names_only_never_a_value(sandbox, tmp_path):
    assert run_bundle(sandbox).returncode == 0
    keys = (extract(sandbox, tmp_path) / "compose/env-keys.txt").read_text()
    assert "CLICKHOUSE_PASSWORD" in keys and "JWT_SECRET" in keys
    assert "=" not in keys.split("\n", 1)[1]      # header comment aside: no k=v
    assert CANARY_ENV_PW not in keys and KEEP_ME not in keys


def test_a_secret_in_a_log_line_is_redacted_by_literal_value(sandbox, tmp_path):
    """No key name hints at it — only the .env literal-value pass can catch it."""
    assert run_bundle(sandbox).returncode == 0
    log = (extract(sandbox, tmp_path) / "logs/netops-api-1.log").read_text()
    assert "connecting to postgres with ***REDACTED***" in log


# ── failure handling (§16.1) ─────────────────────────────────────────────────

def test_failing_collector_exits_2_and_is_named_in_the_manifest(sandbox, tmp_path):
    r = run_bundle(sandbox, FAKE_STATS_FAIL="1")
    assert r.returncode == 2, r.stdout + r.stderr
    assert "FAILED" in r.stderr                       # loud on stderr too
    bundle = extract(sandbox, tmp_path)               # bundle STILL written
    rows = {rel: (status, note) for status, rel, note in manifest_rows(bundle)}
    status, note = rows["docker/stats.txt"]
    assert status == "FAILED"
    assert "exit 3" in note and "Cannot connect to the Docker daemon" in note
    assert re.search(r"collectors:\s+\d+ ok, \d+ skipped, 1 FAILED",
                     (bundle / "MANIFEST").read_text())
    assert re.search(r"exit_code:\s+2", (bundle / "MANIFEST").read_text())
    # The output file itself carries the failure — never an empty, silent file.
    assert "COLLECTOR FAILED" in (bundle / "docker/stats.txt").read_text()


def test_missing_kafka_container_is_a_named_failure_not_silence(sandbox, tmp_path):
    r = run_bundle(sandbox, FAKE_NO_KAFKA="1")
    assert r.returncode == 2
    bundle = extract(sandbox, tmp_path)
    rows = {rel: (status, note) for status, rel, note in manifest_rows(bundle)}
    status, note = rows["bus/kafka-consumer-lag.txt"]
    assert status == "FAILED" and "no running kafka container" in note


def test_absent_watchdog_log_is_a_skip_not_a_failure(sandbox, tmp_path):
    r = run_bundle(sandbox)
    assert r.returncode == 0
    rows = {rel: (status, note)
            for status, rel, note in manifest_rows(extract(sandbox, tmp_path))}
    status, note = rows["watchdog/watchdog-log.txt"]
    assert status == "skip" and "no readable watchdog log" in note


def test_watchdog_log_tail_is_collected_when_present(sandbox, tmp_path):
    log = sandbox["tmp"] / "watchdog.log"
    log.write_text("".join(f"line {i}\n" for i in range(500)))
    r = run_bundle(sandbox, WATCHDOG_LOG_FILE=str(log))
    assert r.returncode == 0
    tail = (extract(sandbox, tmp_path) / "watchdog/watchdog-log.txt").read_text()
    assert tail.splitlines() == [f"line {i}" for i in range(300, 500)]  # last 200


# ── flags ────────────────────────────────────────────────────────────────────

def test_no_logs_skips_container_logs_and_records_the_skip(sandbox, tmp_path):
    r = run_bundle(sandbox, "--no-logs")
    assert r.returncode == 0, r.stderr
    bundle = extract(sandbox, tmp_path)
    assert list(bundle.glob("logs/*.log")) == []
    assert (bundle / "logs/README.txt").is_file()
    rows = {rel: (status, note) for status, rel, note in manifest_rows(bundle)}
    assert rows["logs/"][0] == "skip" and "--no-logs" in rows["logs/"][1]
    assert "skipped (--no-logs)" in (bundle / "MANIFEST").read_text()
    # Nothing else was dropped along with the logs.
    assert (bundle / "compose/ps.txt").is_file()


def test_since_is_passed_through_to_docker_logs(sandbox):
    assert run_bundle(sandbox, "--since", "30m").returncode == 0
    argv = (sandbox["tmp"] / "docker.argv").read_text()
    assert "logs --since 30m --tail 20000 netops-api-1" in argv


def test_invalid_since_fails_at_the_boundary_before_any_collection(sandbox):
    r = run_bundle(sandbox, "--since", "yesterday")
    assert r.returncode == 1
    assert "--since" in r.stderr
    assert list(sandbox["out"].iterdir()) == []      # nothing was produced


def test_unknown_flag_is_a_hard_error(sandbox):
    r = run_bundle(sandbox, "--wat")
    assert r.returncode == 1 and "unknown option" in r.stderr
    assert list(sandbox["out"].iterdir()) == []


def test_help_exits_zero_and_writes_no_bundle(sandbox):
    r = run_bundle(sandbox, "--help")
    assert r.returncode == 0
    assert "--no-logs" in r.stdout and "--since" in r.stdout
    assert list(sandbox["out"].iterdir()) == []


# ── safety properties ────────────────────────────────────────────────────────

def test_kafka_collector_is_read_only(sandbox):
    assert run_bundle(sandbox).returncode == 0
    argv = (sandbox["tmp"] / "kafka.argv").read_text()
    assert "--describe" in argv and "--group netops-correlation" in argv
    for forbidden in ("--reset-offsets", "--delete", "--execute", "--to-earliest"):
        assert forbidden not in argv, f"support bundle must never {forbidden}"


def test_credentials_never_ride_argv(sandbox):
    """Every credentialed call hands its config on STDIN (watchdog doctrine)."""
    assert run_bundle(sandbox).returncode == 0
    argv = (sandbox["tmp"] / "docker.argv").read_text()
    assert CANARY_ENV_PW not in argv
    assert "--config" in argv                       # the stdin-config path ran


def test_authenticated_endpoint_401_is_a_note_not_a_failure(sandbox, tmp_path):
    r = run_bundle(sandbox)
    assert r.returncode == 0
    rows = manifest_rows(extract(sandbox, tmp_path))
    notes = [n for s, rel, n in rows if s == "note" and rel == "api/health.json"]
    assert notes and "HTTP 401" in notes[0] and "SUPPORT_API_TOKEN" in notes[0]
    # The collector itself still succeeded — a 401 is a posture fact, not a gap.
    assert any(s == "ok" and rel == "api/health.json" for s, rel, _ in rows)


def test_support_api_token_is_never_written_into_the_bundle(sandbox, tmp_path):
    token = "canary-support-token-77c3ea"
    r = run_bundle(sandbox, SUPPORT_API_TOKEN=token)
    assert r.returncode == 0
    bundle = extract(sandbox, tmp_path)
    hits = [str(p.relative_to(bundle)) for p in bundle.rglob("*")
            if p.is_file() and token in p.read_text(errors="replace")]
    assert hits == [], f"SUPPORT_API_TOKEN leaked into: {hits}"


def test_running_twice_produces_two_independent_bundles(sandbox):
    """Idempotent (§16.3): a second run never corrupts or clobbers the first."""
    assert run_bundle(sandbox).returncode == 0
    first = archive_of(sandbox)
    keep = first.parent / "first.tar.zst"
    first.rename(keep)
    assert run_bundle(sandbox).returncode == 0
    assert archive_of(sandbox).stat().st_size > 0 and keep.stat().st_size > 0


def test_staging_directory_is_cleaned_up(sandbox):
    before = set(Path("/tmp").glob("correlix-support.*"))
    assert run_bundle(sandbox).returncode == 0
    assert set(Path("/tmp").glob("correlix-support.*")) == before


# ── install-correlix.sh support-bundle subcommand ────────────────────────────

def test_wrapper_dispatches_the_support_bundle_subcommand(tmp_path, sandbox):
    """`install-correlix.sh support-bundle` runs the script with our flags."""
    root = sandbox["root"]
    shutil.copy(INSTALL_SH, root / "scripts" / "install-correlix.sh")
    # Record the argv the wrapper hands the collector instead of collecting.
    calls = tmp_path / "sb.calls"
    _write_exec(root / "scripts" / "support-bundle.sh",
                f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{calls}"\nexit 0\n')
    r = subprocess.run(["bash", str(root / "scripts" / "install-correlix.sh"),
                        "support-bundle", "--out", str(tmp_path), "--no-logs",
                        "--since", "2h"],
                       capture_output=True, text=True, timeout=120, check=False,
                       env={"PATH": os.environ["PATH"], "HOME": str(tmp_path)})
    assert r.returncode == 0, r.stdout + r.stderr
    argv = calls.read_text()
    assert "--out" in argv and str(tmp_path) in argv
    assert "--no-logs" in argv and "--since 2h" in argv


def test_wrapper_propagates_the_partial_bundle_exit_code(tmp_path, sandbox):
    root = sandbox["root"]
    shutil.copy(INSTALL_SH, root / "scripts" / "install-correlix.sh")
    _write_exec(root / "scripts" / "support-bundle.sh",
                '#!/bin/sh\necho "Support bundle: /tmp/x.tar.zst"\nexit 2\n')
    r = subprocess.run(["bash", str(root / "scripts" / "install-correlix.sh"),
                        "support-bundle"],
                       capture_output=True, text=True, timeout=120, check=False,
                       env={"PATH": os.environ["PATH"], "HOME": str(tmp_path)})
    assert r.returncode == 2, r.stdout + r.stderr
    assert "partial" in (r.stdout + r.stderr).lower()


def test_wrapper_help_and_dispatch_list_mention_support_bundle():
    src = INSTALL_SH.read_text()
    assert "support-bundle" in src.split("case \"$1\" in", 1)[1][:400], \
        "support-bundle must be an accepted subcommand"
    assert "./install-correlix.sh support-bundle" in src, \
        "support-bundle must be documented in the header/--help text"


# ── §16.3 merge bar ──────────────────────────────────────────────────────────

def test_bash_syntax_is_clean():
    r = subprocess.run(["bash", "-n", str(SUPPORT)], capture_output=True,
                       text=True, check=False)
    assert r.returncode == 0, r.stderr


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck not installed")
def test_shellcheck_is_clean():
    # The script carries ONE file-level `# shellcheck disable=SC2317` directly
    # under its shebang (a file-level directive placed after the first command
    # applies to that command only): collectors, dcompose and cleanup are
    # invoked indirectly (collector table, timeout wrappers, the EXIT trap) and
    # the CI runner's shellcheck reports each as unreachable, one per run.
    r = subprocess.run(["shellcheck", str(SUPPORT)], capture_output=True,
                       text=True, check=False)
    assert r.returncode == 0, r.stdout + r.stderr


def test_script_obeys_the_shell_hygiene_rules():
    src = SUPPORT.read_text()
    assert "set -euo pipefail" in src
    assert 'export PATH="/usr/local/bin:/usr/bin:/bin' in src   # §16.2 cron-safe
    # §16.1: no blanket error swallowing.
    assert ">/dev/null 2>&1 || true" not in src
