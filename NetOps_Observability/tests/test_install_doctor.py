# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""`install-correlix.sh doctor` and the preflight host checks (FMEA 2026-09-15).

docs/design/INSTALLER_SELF_HEALING_FMEA_2026-09-15.md §4.6 (doctor), §3.12
(H1 slow disk, H7 inodes, H9 rootless Docker, H10 image disk), rows 10 and 15.

doctor — READ-ONLY, bounded, redacted. It reports the host profile, the
install lock holder, the wizard's job file, every compose container's state +
RestartCount + OOMKilled + health + the log-signature verdict on its last 200
log lines, disk vs the OpenSearch 85/90/95 % watermarks, .env completeness by
KEY NAME only, and the install journal. Exit 0 healthy · 1 actionable
problems · 2 could not assess. Pinned here:
  * the .123 end state (keycloak restart-looping on a missing database, api
    never started) is exit 1 with the db-missing verdict and its bootstrap;
  * docker unreachable is exit 2, and the rest of the report still prints;
  * sentinel secrets from a fixture .env NEVER appear in text or JSON output,
    even when a container log echoes one without a credential-looking word;
  * nothing is written: the tree is byte-identical afterwards and only the
    read-only docker verbs (info, ps, inspect, logs) are ever called.

preflight — rootless Docker and a Compose older than the `!override` minimum
FAIL with a remedy; inode headroom fails below 5 %; the image disk projection
counts the unpacked size (MANIFEST when it says, otherwise the labelled 6.2x
estimate) and fails only when even the compressed archives cannot fit; the
host profile runs, prints its plain-language verdict, and never fails the
install.

Shell tests run the REAL install-correlix.sh with docker/df faked on PATH;
the harness proves the fake docker is the one that answered.

Run:  python3 -m pytest tests/test_install_doctor.py -v
"""

from __future__ import annotations

import hashlib
import json
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
SCRIPT = SCRIPTS / "install-correlix.sh"
sys.path.insert(0, str(SCRIPTS))

import host_profile as hp
import install_doctor as doc

SENTINELS = {
    "DB_PASSWORD": "Sentinel-DB-9f8e7d6c5b",
    "JWT_SECRET": "Sentinel-JWT-a1b2c3d4e5",
    "KAFKA_CLUSTER_ID": "Sentinel-KCID-q9w8e7r6",
    "ADMIN_INITIAL_PASSWORD": "Sentinel-Admin-z1x2c3v4",
}
NOW = datetime(2026, 9, 15, 3, 45, 0, tzinfo=timezone.utc).timestamp()

COMPOSE = """name: netops
services:
  postgres:
    environment:
      POSTGRES_PASSWORD: ${DB_PASSWORD:?DB_PASSWORD required}
  api:
    environment:
      JWT_SECRET: ${JWT_SECRET:?JWT_SECRET required (install.py generates it)}
      OPTIONAL: ${NOT_REQUIRED:-x}
  kafka:
    environment:
      CLUSTER_ID: "${KAFKA_CLUSTER_ID:?}"
"""
COMPOSE_TLS = """services:
  api:
    environment:
      TLS_THING: ${TLS_ONLY_KEY:?needed under TLS}
"""


# ── python-level harness ────────────────────────────────────────────────────

def make_tree(tmp_path: Path, *, env: dict[str, str] | None = None, tls: bool = False) -> Path:
    root = tmp_path / "NetOps_Observability"
    dc = root / "deployment" / "docker"
    dc.mkdir(parents=True)
    (root / "scripts").mkdir()
    (root / "data").mkdir()
    (dc / "docker-compose.yml").write_text(COMPOSE)
    if tls:
        (dc / "compose.tls.yml").write_text(COMPOSE_TLS)
    values = dict(SENTINELS) if env is None else env
    if values is not None:
        body = "".join(f"{k}={v}\n" for k, v in values.items())
        (dc / ".env").write_text("# generated\nADMIN_USERNAME=admin\n" + body)
    return root


def container(cid: str, service: str, *, status: str = "running", restarts: int = 0,
              oom: bool = False, exit_code: int = 0, started: str = "2026-09-15T02:00:00.123456789Z",
              health: str = "healthy") -> dict:
    return {"id": cid, "name": f"/netops-{service}-1", "service": service, "status": status,
            "restarts": restarts, "oom": oom, "exit": exit_code, "started": started,
            "health": health}


class FakeDocker:
    READ_ONLY = frozenset({"info", "ps", "inspect", "logs"})

    def __init__(self, containers: list[dict] | None = None, logs: dict[str, str] | None = None,
                 *, info_rc: int = 0, root: str = "/var/lib/docker") -> None:
        self.containers = containers or []
        self.logs = logs or {}
        self.info_rc = info_rc
        self.root = root
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], timeout: int) -> tuple[int, str, str]:
        self.calls.append(list(argv))
        assert argv[0] == "docker"
        assert argv[1] in self.READ_ONLY, f"doctor issued a non read-only docker verb: {argv}"
        assert 0 < timeout <= 60
        if argv[1] == "info":
            if self.info_rc:
                return self.info_rc, "", ("Cannot connect to the Docker daemon at "
                                          "unix:///var/run/docker.sock. Is the docker daemon running?")
            return 0, f"29.1.3|{self.root}\n", ""
        if argv[1] == "ps":
            assert "label=com.docker.compose.project=netops" in argv
            return 0, "".join(c["id"] + "\n" for c in self.containers), ""
        if argv[1] == "inspect":
            ids = set(argv[4:])
            return 0, "".join(json.dumps(c) + "\n" for c in self.containers if c["id"] in ids), ""
        return 0, self.logs.get(argv[-1], ""), ""


def fake_readers(io: str | None = None) -> hp.HostReaders:
    files = {"/proc/pressure/io": io}

    def read_text(path: str) -> str:
        v = files.get(path)
        if v is None:
            raise FileNotFoundError(2, "No such file", path)
        return v

    return hp.HostReaders(read_text=read_text, cpu_count=lambda: 4)


def denv(root: Path, docker: FakeDocker, **kw) -> doc.DoctorEnv:
    base = {
        "root": root, "bundle_dir": root.parent, "runner": docker, "readers": fake_readers(),
        "disk_usage": lambda p: (100 * 2**30, 40 * 2**30, 60 * 2**30),
        "device_of": lambda p: 1, "pid_alive": lambda pid: False, "proc_cmdline": lambda pid: "",
        "proc_start": lambda pid: "", "clock": lambda: 0.0, "wall": lambda: NOW, "deadline_s": 120.0}
    base.update(kw)
    return doc.DoctorEnv(**base)


def healthy_stack() -> FakeDocker:
    return FakeDocker([
        container("c1", "postgres"),
        container("c2", "api", health="none"),
        container("c3", "kafka-init", status="exited", exit_code=0, health="none"),
    ], {"c1": "LOG:  database system is ready to accept connections\n"})


def by_id(report: doc.Report, check_id: str) -> doc.Check:
    return next(c for c in report.checks if c.id == check_id)


def all_output(report: doc.Report) -> str:
    return report.render_text() + "\n" + json.dumps(report.to_dict())


def tree_snapshot(root: Path) -> dict[str, tuple[int, int, str]]:
    out = {}
    for p in sorted(root.rglob("*")):
        st = p.lstat()
        digest = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else ""
        out[str(p.relative_to(root))] = (st.st_mode, st.st_mtime_ns, digest)
    return out


# ── verdicts and exit codes ─────────────────────────────────────────────────

def test_healthy_stack_exits_0(tmp_path):
    root = make_tree(tmp_path)
    r = doc.run_doctor(denv(root, healthy_stack()))
    assert r.exit_code == 0, r.render_text()
    assert by_id(r, "container:kafka-init").status == "ok"


def test_the_123_end_state_is_actionable_with_the_db_missing_bootstrap(tmp_path):
    root = make_tree(tmp_path)
    docker = FakeDocker([
        container("c1", "postgres"),
        container("c2", "keycloak", restarts=106, started="2026-09-15T03:44:43.000000001Z",
                  health="none"),
        container("c3", "api", status="created", health="none"),
    ], {
        "c2": ("2026-09-15 03:44:50,1 ERROR [org.hibernate.engine.jdbc.spi.SqlExceptionHelper] "
               "FATAL: database \"keycloak\" does not exist\n") * 5,
    })
    r = doc.run_doctor(denv(root, docker))
    assert r.exit_code == 1
    kc = by_id(r, "container:keycloak")
    assert kc.status == "problem"
    assert "106" in kc.summary
    assert kc.details["verdict"]["class"] == "db-missing"
    assert kc.details["verdict"]["action"] == "bootstrap:keycloak-db"
    assert "database" in kc.remedy.lower()
    api = by_id(r, "container:api")
    assert api.status == "problem" and "never started" in api.summary


def test_recovering_postgres_is_named_with_its_wait_verdict(tmp_path):
    root = make_tree(tmp_path)
    docker = FakeDocker([container("c1", "postgres", health="unhealthy")], {
        "c1": ("LOG:  database system was interrupted; last known up at 03:03:57\n"
               "LOG:  syncing data directory (fsync), elapsed time: 90.02 s\n")})
    r = doc.run_doctor(denv(root, docker))
    pg = by_id(r, "container:postgres")
    assert pg.status == "problem"
    assert pg.details["verdict"]["class"] == "recovering"
    assert pg.details["verdict"]["action"] == "wait"
    assert "unhealthy" in pg.summary


def test_oom_killed_is_classified_from_state_even_without_a_log_line(tmp_path):
    root = make_tree(tmp_path)
    docker = FakeDocker([container("c1", "opensearch", status="exited", exit_code=137, oom=True)])
    r = doc.run_doctor(denv(root, docker))
    c = by_id(r, "container:opensearch")
    assert c.status == "problem"
    assert c.details["verdict"]["class"] == "oom-killed"
    assert "memory" in c.remedy.lower()


def test_failed_one_shot_and_old_restarts(tmp_path):
    root = make_tree(tmp_path)
    docker = FakeDocker([
        container("c1", "opensearch-init", status="exited", exit_code=1, health="none"),
        container("c2", "vector-router", restarts=4, started="2026-09-10T00:00:00Z", health="none"),
    ])
    r = doc.run_doctor(denv(root, docker))
    assert by_id(r, "container:opensearch-init").status == "problem"
    old = by_id(r, "container:vector-router")
    assert old.status == "ok", "restarts days ago are history, not a loop"
    assert "4" in old.summary


def test_historical_fatal_log_on_a_healthy_container_is_not_a_problem(tmp_path):
    root = make_tree(tmp_path)
    docker = FakeDocker([container("c1", "syslog-ng", health="none")],
                        {"c1": "Bind for 0.0.0.0:514 failed: port is already allocated\n"})
    r = doc.run_doctor(denv(root, docker))
    c = by_id(r, "container:syslog-ng")
    assert c.status == "ok"
    assert c.details["verdict"]["class"] == "port-conflict"
    assert r.exit_code == 0


def test_docker_unreachable_is_exit_2_and_the_rest_still_reports(tmp_path):
    root = make_tree(tmp_path, env={k: v for k, v in SENTINELS.items() if k != "JWT_SECRET"})
    r = doc.run_doctor(denv(root, FakeDocker(info_rc=1)))
    assert r.exit_code == 2
    d = by_id(r, "docker")
    assert d.status == "unknown" and "docker" in d.summary.lower()
    assert by_id(r, "env-completeness").status == "problem"
    assert "could not assess" in r.render_text().lower()


def test_installed_but_no_containers_is_a_problem_and_not_installed_is_fine(tmp_path):
    root = make_tree(tmp_path)
    assert doc.run_doctor(denv(root, FakeDocker([]))).exit_code == 1
    bare = make_tree(tmp_path / "bare", env=None)
    (bare / "deployment" / "docker" / ".env").unlink(missing_ok=True)
    r = doc.run_doctor(denv(bare, FakeDocker([])))
    assert r.exit_code == 0
    assert "not installed" in by_id(r, "containers").summary.lower()


def test_time_budget_leaves_containers_unassessed_and_exits_2(tmp_path):
    root = make_tree(tmp_path)
    ticks = iter([0.0, 0.0, 0.0] + [500.0] * 50)
    docker = FakeDocker([container(f"c{i}", f"svc{i}") for i in range(3)])
    r = doc.run_doctor(denv(root, docker, clock=lambda: next(ticks), deadline_s=100.0))
    unassessed = [c for c in r.checks if c.id.startswith("container:") and c.status == "unknown"]
    assert unassessed
    assert r.exit_code == 2


# ── secrets never leave ─────────────────────────────────────────────────────

def test_sentinel_secrets_never_appear_in_any_output(tmp_path):
    root = make_tree(tmp_path)
    docker = FakeDocker([
        container("c1", "api", status="restarting", restarts=9,
                  started="2026-09-15T03:44:59Z", health="none"),
        container("c2", "correlation", health="unhealthy"),
    ], {
        "c1": (f"connecting as netops with {SENTINELS['DB_PASSWORD']}\n"
               f"password={SENTINELS['JWT_SECRET']}\n"
               f"cluster {SENTINELS['KAFKA_CLUSTER_ID']} port is already allocated\n"),
        "c2": (f"TopicAuthorizationFailedError topic={SENTINELS['ADMIN_INITIAL_PASSWORD']}\n"),
    })
    r = doc.run_doctor(denv(root, docker))
    out = all_output(r)
    for name, value in SENTINELS.items():
        assert value not in out, f"{name}'s value leaked"
    assert r.exit_code == 1


def test_env_completeness_names_missing_and_empty_keys_only(tmp_path):
    env = dict(SENTINELS)
    env.pop("JWT_SECRET")
    env["KAFKA_CLUSTER_ID"] = ""
    root = make_tree(tmp_path, env=env, tls=True)
    r = doc.run_doctor(denv(root, healthy_stack()))
    c = by_id(r, "env-completeness")
    assert c.status == "problem"
    assert c.details["missing"] == ["JWT_SECRET", "KAFKA_CLUSTER_ID", "TLS_ONLY_KEY"]
    assert "NOT_REQUIRED" not in json.dumps(c.details)
    assert SENTINELS["DB_PASSWORD"] not in all_output(r)


def test_required_keys_parser():
    keys = doc.required_env_keys_from_text(COMPOSE + COMPOSE_TLS)
    assert keys == {"DB_PASSWORD", "JWT_SECRET", "KAFKA_CLUSTER_ID", "TLS_ONLY_KEY"}


def test_required_keys_of_the_real_compose_files_are_all_generated():
    """Every `${VAR:?}` in the shipped compose files is read by the doctor."""
    keys = doc.required_env_keys(ROOT / "deployment" / "docker")
    assert {"DB_PASSWORD", "JWT_SECRET", "KAFKA_CLUSTER_ID"} <= keys


def test_scrub_replaces_env_values_longest_first():
    s = doc.scrub("a Sentinel-DB-9f8e7d6c5b-and-more b", ["Sentinel-DB", "Sentinel-DB-9f8e7d6c5b-and-more"])
    assert "Sentinel" not in s


# ── lock, wizard job, watermarks, journal, host profile ─────────────────────

def _write_lock(root: Path, pid: int) -> None:
    (root / "deployment" / "docker" / ".install.lock").write_text(
        f"pid={pid}\ncommand=install\nstarted_utc=2026-09-15T02:51:00Z\n")


def test_lock_states(tmp_path):
    root = make_tree(tmp_path)
    r = doc.run_doctor(denv(root, healthy_stack()))
    assert by_id(r, "install-lock").status == "ok"
    _write_lock(root, 4242)
    running = doc.run_doctor(denv(root, healthy_stack(), pid_alive=lambda p: p == 4242,
                                  proc_cmdline=lambda p: "bash ./install-correlix.sh install"))
    lk = by_id(running, "install-lock")
    assert lk.status == "ok" and "4242" in lk.summary and "running" in lk.summary
    stale = doc.run_doctor(denv(root, healthy_stack()))
    lk = by_id(stale, "install-lock")
    assert lk.status == "warn" and "did not finish" in lk.summary
    reused = doc.run_doctor(denv(root, healthy_stack(), pid_alive=lambda p: True,
                                 proc_cmdline=lambda p: "/usr/sbin/cron -f"))
    assert by_id(reused, "install-lock").status == "warn"


def _job(root: Path, **fields) -> None:
    base = {"version": 1, "pid": 5151, "started_utc": "2026-09-15T02:51:00Z",
            "argv0": "./install-correlix.sh", "argv1": "install", "log": "x.log",
            "detached": True, "profile": {"tls": True}}
    base.update(fields)
    (root.parent / "correlix-setup-install.job.json").write_text(json.dumps(base))


def test_wizard_job_states(tmp_path):
    root = make_tree(tmp_path)
    assert by_id(doc.run_doctor(denv(root, healthy_stack())), "wizard-job").status == "ok"
    _job(root, proc_start="777")
    live = doc.run_doctor(denv(root, healthy_stack(), pid_alive=lambda p: True,
                               proc_start=lambda p: "777"))
    assert by_id(live, "wizard-job").status == "ok"
    assert "running" in by_id(live, "wizard-job").summary
    reused = doc.run_doctor(denv(root, healthy_stack(), pid_alive=lambda p: True,
                                 proc_start=lambda p: "999"))
    assert by_id(reused, "wizard-job").status == "warn"
    _job(root)
    dead = doc.run_doctor(denv(root, healthy_stack()))
    assert by_id(dead, "wizard-job").status == "warn"
    assert "without recording a result" in by_id(dead, "wizard-job").summary
    _job(root, outcome="fail", ended_utc="2026-09-15T03:13:02Z", exit_code=1)
    failed = by_id(doc.run_doctor(denv(root, healthy_stack())), "wizard-job")
    assert failed.status == "warn" and "03:13:02" in failed.summary
    _job(root, outcome="ok", ended_utc="2026-09-15T03:13:02Z", exit_code=0)
    assert by_id(doc.run_doctor(denv(root, healthy_stack())), "wizard-job").status == "ok"
    (root.parent / "correlix-setup-install.job.json").write_text("{not json")
    assert by_id(doc.run_doctor(denv(root, healthy_stack())), "wizard-job").status == "warn"
    (root.parent / "correlix-setup-install.job.json").write_text("x" * (doc.MAX_JOB_BYTES + 5))
    assert by_id(doc.run_doctor(denv(root, healthy_stack())), "wizard-job").status == "warn"


def test_wizard_profile_contents_are_never_printed(tmp_path):
    root = make_tree(tmp_path)
    _job(root, outcome="ok", profile={"admin_email": "owner@example.test", "tls": True})
    r = doc.run_doctor(denv(root, healthy_stack()))
    assert "owner@example.test" not in all_output(r)


@pytest.mark.parametrize("used_pct,status,word", [
    (50, "ok", ""), (86, "warn", "85"), (91, "problem", "90"), (96, "problem", "95"),
])
def test_disk_watermarks(tmp_path, used_pct, status, word):
    root = make_tree(tmp_path)
    total = 100 * 2**30
    used = total * used_pct // 100
    r = doc.run_doctor(denv(root, healthy_stack(), disk_usage=lambda p: (total, used, total - used)))
    c = by_id(r, "disk-watermarks")
    assert c.status == status
    assert word in c.summary


def test_disk_watermarks_measure_docker_root_separately_when_on_another_filesystem(tmp_path):
    root = make_tree(tmp_path)
    seen: list[str] = []

    def usage(p: Path) -> tuple[int, int, int]:
        seen.append(str(p))
        return (100, 10, 90)

    r = doc.run_doctor(denv(root, healthy_stack(), disk_usage=usage,
                            device_of=lambda p: 2 if str(p).startswith("/var/lib/docker") else 1))
    assert any(s.startswith("/var/lib/docker") for s in seen)
    assert len(by_id(r, "disk-watermarks").details["filesystems"]) == 2


def test_journal(tmp_path):
    root = make_tree(tmp_path)
    assert by_id(doc.run_doctor(denv(root, healthy_stack())), "install-journal").status == "ok"
    (root / "data" / "install-timing.json").write_text(json.dumps({
        "version": 1, "generated_utc": "2026-09-15T03:13:02Z", "status": "fail", "total_s": 1306.8,
        "stages": [{"id": "bundle", "title": "b", "status": "ok", "elapsed_s": 382.0},
                   {"id": "up-b", "title": "phase B", "status": "fail", "elapsed_s": 235.1}]}))
    j = by_id(doc.run_doctor(denv(root, healthy_stack())), "install-journal")
    assert j.status == "warn" and "up-b" in j.summary
    assert [s["id"] for s in j.details["stages"]] == ["bundle", "up-b"]
    (root / "data" / "install-timing.json").write_text("[]")
    assert by_id(doc.run_doctor(denv(root, healthy_stack())), "install-journal").status == "warn"


def test_host_profile_check(tmp_path):
    root = make_tree(tmp_path)
    missing = by_id(doc.run_doctor(denv(root, healthy_stack())), "host-profile")
    assert missing.status == "warn" and "preflight" in missing.summary.lower()
    (root / "data" / ".host-profile.json").write_text(json.dumps(
        {"class": "very-slow", "budget_factor": 3, "verdict": "WARNING: this host is much slower"}))
    io = "some avg10=1 avg60=30.00 avg300=1 total=1\nfull avg10=1 avg60=22.00 avg300=1 total=1\n"
    c = by_id(doc.run_doctor(denv(root, healthy_stack(), readers=fake_readers(io))), "host-profile")
    assert c.status == "warn" and "much slower" in c.summary
    assert c.details["live_io_full_avg60"] == 22.0
    (root / "data" / ".host-profile.json").write_text(json.dumps({"class": "fast", "budget_factor": 1,
                                                                  "verdict": "fast"}))
    assert by_id(doc.run_doctor(denv(root, healthy_stack())), "host-profile").status == "ok"


# ── read-only, bounded ──────────────────────────────────────────────────────

def test_doctor_never_writes_and_only_reads_docker(tmp_path):
    root = make_tree(tmp_path, tls=True)
    _write_lock(root, 1)
    _job(root, outcome="fail")
    (root / "data" / "install-timing.json").write_text('{"status":"ok","stages":[]}')
    before = tree_snapshot(tmp_path)
    docker = healthy_stack()
    doc.run_doctor(denv(root, docker))
    assert tree_snapshot(tmp_path) == before
    assert {c[1] for c in docker.calls} <= FakeDocker.READ_ONLY
    logs_calls = [c for c in docker.calls if c[1] == "logs"]
    assert logs_calls and all(c[2:4] == ["--tail", "200"] for c in logs_calls)


def test_doctor_source_never_mutates():
    src = (SCRIPTS / "install_doctor.py").read_text()
    for banned in ('"rm"', '"stop"', '"restart"', '"up"', '"down"', '"prune"', "write_text(",
                   "os.replace", "os.unlink", "shutil.", "mkdir(", '"exec"', "flock"):
        assert banned not in src, f"doctor must be read-only: found {banned}"


def test_json_shape(tmp_path):
    root = make_tree(tmp_path)
    d = doc.run_doctor(denv(root, healthy_stack())).to_dict()
    assert d["version"] == 1 and d["exit_code"] == 0
    assert {"id", "title", "status", "summary", "remedy", "details"} <= set(d["checks"][0])
    assert {c["status"] for c in d["checks"]} <= {"ok", "warn", "problem", "unknown"}


def test_main_json_and_text(tmp_path, capsys):
    root = make_tree(tmp_path)
    rc = doc.main(["--root", str(root), "--bundle-dir", str(tmp_path), "--json"],
                  env=denv(root, healthy_stack()))
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["exit_code"] == 0
    rc = doc.main(["--root", str(root), "--bundle-dir", str(tmp_path)], env=denv(root, healthy_stack()))
    assert rc == 0
    assert "Result:" in capsys.readouterr().out


# ── shell: install-correlix.sh doctor ───────────────────────────────────────

_PATH_LINE = 'export PATH="/usr/local/bin:/usr/bin:/bin:${PATH:-}"'


def _fakes_win(src: str) -> str:
    assert src.count(_PATH_LINE) == 1, "install-correlix.sh PATH line changed — update the harness"
    return src.replace(_PATH_LINE, 'export PATH="${PATH:?test harness sets PATH}"')


def _write_exec(path: Path, body: str) -> None:
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


FAKE_DOCKER = r"""#!/bin/bash
printf '%s\n' "$*" >> "$DOCKER_LOG"
case "$1" in
  info)
    if [ -n "${FAKE_DOCKER_INFO_FAIL:-}" ]; then
      echo "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?" >&2
      exit 1
    fi
    case "$*" in
      *SecurityOptions*) printf '%s\n' "${FAKE_SECOPTS:-[\"name=seccomp,profile=builtin\"]}" ;;
      *DockerRootDir*" "*|*"ServerVersion"*) printf '99.9.9-fake|%s\n' "${FAKE_DOCKER_ROOT:-/var/lib/docker}" ;;
      *DockerRootDir*) printf '%s\n' "${FAKE_DOCKER_ROOT:-/var/lib/docker}" ;;
      *) echo "fake docker info" ;;
    esac ;;
  compose)
    [ "$2" = version ] && { printf '%s\n' "${FAKE_COMPOSE_VERSION:-2.40.3}"; exit 0; }
    echo "fake compose: unexpected $*" >&2; exit 64 ;;
  ps) [ -n "${FAKE_PS:-}" ] && cat "$FAKE_PS" ;;
  inspect) [ -n "${FAKE_INSPECT:-}" ] && cat "$FAKE_INSPECT" ;;
  logs) [ -n "${FAKE_LOGS_DIR:-}" ] && [ -f "$FAKE_LOGS_DIR/${*: -1}" ] && cat "$FAKE_LOGS_DIR/${*: -1}" ;;
  *) echo "fake docker: refusing $*" >&2; exit 64 ;;
esac
exit 0
"""

FAKE_DF = r"""#!/bin/bash
printf 'df %s\n' "$*" >> "$DOCKER_LOG"
[ -n "${FAKE_DF_FAIL:-}" ] && { echo "df: cannot read table of mounted file systems" >&2; exit 1; }
case "$*" in
  *-Pi*) printf 'Filesystem Inodes IUsed IFree IUse%% Mounted on\n%s\n' "${FAKE_DF_I:-/dev/vda 1000 100 900 10% /}" ;;
  *-PB1*) printf 'Filesystem 1-blocks Used Available Capacity Mounted on\n%s\n' "${FAKE_DF_B:-/dev/vda 107374182400 10737418240 96636764160 10% /}" ;;
  *) printf 'Filesystem 1G-blocks Used Available Use%% Mounted on\n/dev/vda 100G 10G 90G 10%% /\n' ;;
esac
"""


def _bin(tmp_path: Path) -> Path:
    b = tmp_path / "bin"
    b.mkdir(exist_ok=True)
    _write_exec(b / "docker", FAKE_DOCKER)
    _write_exec(b / "df", FAKE_DF)
    return b


def _shell_env(tmp_path: Path, bindir: Path, **extra: str) -> dict:
    env = {"PATH": f"{bindir}:/usr/local/bin:/usr/bin:/bin", "HOME": str(tmp_path),
           "DOCKER_LOG": str(tmp_path / "docker.log"), "LANG": "C.UTF-8"}
    env.update(extra)
    return env


def _assert_fake_docker_wins(env: dict, bindir: Path) -> None:
    r = subprocess.run(["bash", "-c", "command -v docker; command -v df"], env=env,
                       capture_output=True, text=True, timeout=10, check=False)
    assert r.stdout.split() == [str(bindir / "docker"), str(bindir / "df")], \
        "a test could reach the host's real docker/df — refusing to run"


def _shell_tree(tmp_path: Path, *, with_doctor: bool = True) -> Path:
    root = make_tree(tmp_path)
    dst = root / "scripts" / "install-correlix.sh"
    dst.write_text(_fakes_win(SCRIPT.read_text(encoding="utf-8")))
    dst.chmod(0o755)
    if with_doctor:
        for name in ("install_doctor.py", "install_signatures.py", "host_profile.py"):
            shutil.copy(SCRIPTS / name, root / "scripts" / name)
    return root


def _stack_fixture(tmp_path: Path) -> dict[str, str]:
    ps = tmp_path / "ps.txt"
    ps.write_text("k1\na1\n")
    ins = tmp_path / "inspect.txt"
    ins.write_text(json.dumps(container("k1", "keycloak", restarts=50,
                                        started=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                        health="none")) + "\n"
                   + json.dumps(container("a1", "api", health="none")) + "\n")
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "k1").write_text('FATAL: database "keycloak" does not exist\n'
                             f"jdbc user netops secret {SENTINELS['DB_PASSWORD']}\n"
                             f"echo {SENTINELS['JWT_SECRET']}\n")
    return {"FAKE_PS": str(ps), "FAKE_INSPECT": str(ins), "FAKE_LOGS_DIR": str(logs)}


def _run(root: Path, args: list[str], env: dict, timeout: int = 120):
    return subprocess.run(["bash", str(root / "scripts" / "install-correlix.sh"), *args],
                          capture_output=True, text=True, timeout=timeout, env=env,
                          stdin=subprocess.DEVNULL, check=False)


def test_shell_doctor_json_reports_problems_and_leaks_nothing(tmp_path):
    root = _shell_tree(tmp_path)
    bindir = _bin(tmp_path)
    env = _shell_env(tmp_path, bindir, **_stack_fixture(tmp_path))
    _assert_fake_docker_wins(env, bindir)
    before = tree_snapshot(root)
    r = _run(root, ["doctor", "--json"], env)
    assert r.returncode == 1, r.stdout + r.stderr
    d = json.loads(r.stdout)
    kc = next(c for c in d["checks"] if c["id"] == "container:keycloak")
    assert kc["details"]["verdict"]["class"] == "db-missing"
    docker_check = next(c for c in d["checks"] if c["id"] == "docker")
    assert "99.9.9-fake" in docker_check["summary"], "the fake docker must be the one answering"
    for value in SENTINELS.values():
        assert value not in r.stdout and value not in r.stderr
    assert tree_snapshot(root) == before, "doctor wrote into the install tree"
    verbs = {ln.split()[0] for ln in (tmp_path / "docker.log").read_text().splitlines()}
    assert verbs <= {"info", "ps", "inspect", "logs", "df"}


def test_shell_doctor_text_and_exit_2_when_docker_is_down(tmp_path):
    root = _shell_tree(tmp_path)
    bindir = _bin(tmp_path)
    env = _shell_env(tmp_path, bindir, FAKE_DOCKER_INFO_FAIL="1")
    _assert_fake_docker_wins(env, bindir)
    r = _run(root, ["doctor"], env)
    assert r.returncode == 2, r.stdout + r.stderr
    assert "could not assess" in r.stdout.lower()
    for value in SENTINELS.values():
        assert value not in r.stdout + r.stderr


def test_shell_doctor_without_the_module_exits_2_with_a_reason(tmp_path):
    root = _shell_tree(tmp_path, with_doctor=False)
    bindir = _bin(tmp_path)
    env = _shell_env(tmp_path, bindir)
    r = _run(root, ["doctor"], env)
    assert r.returncode == 2
    assert "install_doctor.py" in r.stdout + r.stderr


def test_shell_json_flag_is_doctor_only(tmp_path):
    root = _shell_tree(tmp_path)
    bindir = _bin(tmp_path)
    r = _run(root, ["status", "--json"], _shell_env(tmp_path, bindir))
    assert r.returncode != 0
    assert "--json" in r.stdout + r.stderr


def test_shell_help_lists_doctor(tmp_path):
    root = _shell_tree(tmp_path)
    bindir = _bin(tmp_path)
    r = _run(root, ["--help"], _shell_env(tmp_path, bindir))
    assert r.returncode == 0
    assert "doctor [--json]" in r.stdout
    assert "support-bundle" in r.stdout
    assert "Advanced" not in r.stdout


# ── shell: preflight host checks ────────────────────────────────────────────

def _script_without_dispatch(src: str) -> str:
    cut = src.rindex('\ncase "$CMD" in\n')
    return src[:cut] + "\n"


def _harness(tmp_path: Path, root: Path, tail: str, env: dict, timeout: int = 120):
    h = root / "scripts" / "harness.sh"
    h.write_text(_script_without_dispatch(_fakes_win(SCRIPT.read_text(encoding="utf-8"))) + tail)
    return subprocess.run(["bash", str(h)], capture_output=True, text=True, timeout=timeout,
                          env=env, stdin=subprocess.DEVNULL, check=False)


def _preflight_body() -> str:
    src = SCRIPT.read_text(encoding="utf-8")
    return src[src.index("\npreflight() {"):src.index("\n# Release-signature check")]


def test_preflight_wires_every_new_host_check():
    body = _preflight_body()
    for fn in ("check_rootless_docker", "check_compose_version", "check_image_disk_projection",
               "check_inode_headroom", "run_host_profile"):
        assert fn in body, f"{fn} is not called from preflight()"
    src = SCRIPT.read_text(encoding="utf-8")
    install = src[src.index("\ncmd_install() {"):src.index("\n# The image `purge_data_dir`")]
    assert install.index("verify_bundle") < install.index("run_host_profile"), \
        "a first-run bundle must be profiled once its source tree is unpacked"


@pytest.mark.parametrize("secopts,rc,word", [
    ('["name=apparmor","name=seccomp,profile=builtin","name=cgroupns"]', 0, "rootful"),
    ('["name=seccomp,profile=builtin","name=rootless","name=cgroupns"]', 1, "rootless"),
])
def test_preflight_rootless_docker(tmp_path, secopts, rc, word):
    root = _shell_tree(tmp_path)
    bindir = _bin(tmp_path)
    env = _shell_env(tmp_path, bindir, FAKE_SECOPTS=secopts)
    _assert_fake_docker_wins(env, bindir)
    r = _harness(tmp_path, root, "check_rootless_docker\n", env)
    assert r.returncode == rc, r.stdout + r.stderr
    assert word in r.stdout
    if rc:
        assert "prepare-host" in r.stdout


def test_preflight_rootless_probe_failure_warns_not_fails(tmp_path):
    root = _shell_tree(tmp_path)
    bindir = _bin(tmp_path)
    env = _shell_env(tmp_path, bindir, FAKE_DOCKER_INFO_FAIL="1")
    r = _harness(tmp_path, root, "check_rootless_docker\n", env)
    assert r.returncode == 0
    assert "not checked" in r.stdout


@pytest.mark.parametrize("version,rc,word", [
    ("2.40.3", 0, "2.40.3"), ("v2.24.4", 0, "2.24.4"), ("2.24.4-desktop.1", 0, "2.24.4"),
    ("2.24.3", 1, "too old"), ("v2.20.2", 1, "too old"), ("1.29.2", 1, "too old"),
    ("garbage", 0, "not checked"),
])
def test_preflight_compose_minimum_version(tmp_path, version, rc, word):
    root = _shell_tree(tmp_path)
    bindir = _bin(tmp_path)
    env = _shell_env(tmp_path, bindir, FAKE_COMPOSE_VERSION=version)
    _assert_fake_docker_wins(env, bindir)
    r = _harness(tmp_path, root, "check_compose_version\n", env)
    assert r.returncode == rc, r.stdout + r.stderr
    assert word in r.stdout


@pytest.mark.parametrize("df_line,rc,word", [
    ("/dev/vda 1000 970 30 97% /", 1, "inodes"),
    ("/dev/vda 1000 920 80 92% /", 0, "only 8 %"),
    ("/dev/vda 1000 100 900 10% /", 0, "90 % inodes free"),
    ("/dev/vda 0 0 0 - /", 0, "no fixed inode limit"),
])
def test_preflight_inode_headroom(tmp_path, df_line, rc, word):
    root = _shell_tree(tmp_path)
    bindir = _bin(tmp_path)
    env = _shell_env(tmp_path, bindir, FAKE_DF_I=df_line)
    _assert_fake_docker_wins(env, bindir)
    r = _harness(tmp_path, root, f'check_inode_headroom "data directory" "{root}/data/not-yet"\n', env)
    assert r.returncode == rc, r.stdout + r.stderr
    assert word in r.stdout
    assert f"df -Pi -- {root}/data" in (tmp_path / "docker.log").read_text(), \
        "the nearest existing directory is the one measured"


def test_preflight_inode_probe_failure_warns(tmp_path):
    root = _shell_tree(tmp_path)
    bindir = _bin(tmp_path)
    env = _shell_env(tmp_path, bindir, FAKE_DF_FAIL="1")
    r = _harness(tmp_path, root, f'check_inode_headroom "data directory" "{root}/data"\n', env)
    assert r.returncode == 0
    assert "not checked" in r.stdout


def _bundle(tmp_path: Path, files: dict[str, int], manifest_extra: str = "") -> Path:
    b = tmp_path / "bundle"
    b.mkdir()
    for name, size in files.items():
        with open(b / name, "wb") as f:
            f.truncate(size)
    (b / "MANIFEST").write_text("product:  Correlix\nimages:\n  - x\n" + manifest_extra)
    return b


GB = 2**30


@pytest.mark.parametrize("files,avail,rc,word", [
    ({"correlix-images-core-v1.tar.zst": 2 * GB}, 50 * GB, 0, "ESTIMATE"),
    ({"correlix-images-core-v1.tar.zst": 2 * GB}, 10 * GB, 0, "may not fit"),
    ({"correlix-images-core-v1.tar.zst": 2 * GB}, 1 * GB, 1, "cannot fit"),
    ({"correlix-images-core-v1.tar.zst.part00": GB, "correlix-images-core-v1.tar.zst.part01": GB,
      "correlix-addon-sso-v1.tar.zst": GB // 2}, 50 * GB, 0, "15.5 GB"),
    ({"correlix-images-core-v1.tar.zst": 2 * GB, "correlix-images-core-v1.tar.zst.part00": GB,
      "correlix-images-core-v1.tar.zst.part01": GB}, 50 * GB, 0, "12.4 GB"),
])
def test_preflight_image_disk_projection(tmp_path, files, avail, rc, word):
    root = _shell_tree(tmp_path)
    bundle = _bundle(tmp_path, files)
    bindir = _bin(tmp_path)
    total = 100 * GB
    env = _shell_env(tmp_path, bindir, FAKE_DF_B=f"/dev/vda {total} {total - avail} {avail} 50% /")
    _assert_fake_docker_wins(env, bindir)
    tail = f'MODE=bundle; BUNDLE_DIR="{bundle}"\ncheck_image_disk_projection "{tmp_path}"\n'
    r = _harness(tmp_path, root, tail, env)
    assert r.returncode == rc, r.stdout + r.stderr
    assert word in r.stdout


def test_preflight_projection_prefers_manifest_unpacked_size(tmp_path):
    root = _shell_tree(tmp_path)
    bundle = _bundle(tmp_path, {"correlix-images-core-v1.tar.zst": 2 * GB},
                     manifest_extra=f"images_unpacked_bytes: {7 * GB}\n")
    bindir = _bin(tmp_path)
    env = _shell_env(tmp_path, bindir)
    r = _harness(tmp_path, root, f'MODE=bundle; BUNDLE_DIR="{bundle}"\ncheck_image_disk_projection "{tmp_path}"\n', env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "7.0 GB" in r.stdout and "MANIFEST" in r.stdout and "ESTIMATE" not in r.stdout


def test_preflight_projection_projected_fill_above_80_percent_warns(tmp_path):
    root = _shell_tree(tmp_path)
    bundle = _bundle(tmp_path, {"correlix-images-core-v1.tar.zst": 2 * GB})
    bindir = _bin(tmp_path)
    total = 100 * GB
    env = _shell_env(tmp_path, bindir, FAKE_DF_B=f"/dev/vda {total} {70 * GB} {30 * GB} 70% /")
    r = _harness(tmp_path, root, f'MODE=bundle; BUNDLE_DIR="{bundle}"\ncheck_image_disk_projection "{tmp_path}"\n', env)
    assert r.returncode == 0
    assert "82 %" in r.stdout


def test_preflight_projection_source_mode_says_why_it_skips(tmp_path):
    root = _shell_tree(tmp_path)
    bindir = _bin(tmp_path)
    r = _harness(tmp_path, root, f'check_image_disk_projection "{tmp_path}"\n', _shell_env(tmp_path, bindir))
    assert r.returncode == 0
    assert "no image bundle" in r.stdout


FAKE_PROFILER = """import sys
print({line!r})
print("note: data: something informational")
sys.exit({rc})
"""


@pytest.mark.parametrize("line,rc,prefix,word", [
    ("fast\t1\tThis host is fast (p99 0.4 ms). Standard time budgets apply.", 0, "✔", "host speed"),
    ("slow\t2\tThis host is slow (p99 20 ms).", 0, "!", "slow"),
    ("very-slow\t3\tWARNING: this host is much slower than recommended (p99 60 ms).", 0, "!", "WARNING"),
    ("unknown\t-\tCould not measure this host's speed (Permission denied).", 2, "!", "could not be measured"),
    ("slow\t2\tThis host is slow.", 3, "!", "not saved"),
])
def test_preflight_host_profile_verdict_is_printed_and_never_fatal(tmp_path, line, rc, prefix, word):
    root = _shell_tree(tmp_path, with_doctor=False)
    extra = "not saved: cannot write" if rc == 3 else ""
    body = FAKE_PROFILER.format(line=line, rc=rc)
    if extra:
        body = body.replace('print("note', f'print({extra!r})\nprint("note')
    (root / "scripts" / "host_profile.py").write_text(body)
    bindir = _bin(tmp_path)
    r = _harness(tmp_path, root, 'run_host_profile "/var/lib/docker"\necho "AFTER=$?"\n',
                 _shell_env(tmp_path, bindir))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "AFTER=0" in r.stdout
    assert word in r.stdout
    assert any(ln.startswith(prefix) for ln in r.stdout.splitlines() if word in ln or "host speed" in ln)


def test_preflight_host_profile_before_unpack_says_when(tmp_path):
    root = _shell_tree(tmp_path, with_doctor=False)
    bindir = _bin(tmp_path)
    r = _harness(tmp_path, root, 'run_host_profile "/var/lib/docker"\n', _shell_env(tmp_path, bindir))
    assert r.returncode == 0
    assert "after the bundle is unpacked" in r.stdout


def test_preflight_host_profile_real_module_writes_the_contract_file(tmp_path):
    root = _shell_tree(tmp_path)
    shutil.rmtree(root / "data")
    dock = tmp_path / "dockerroot"
    dock.mkdir()
    bindir = _bin(tmp_path)
    r = _harness(tmp_path, root, f'run_host_profile "{dock}"\n', _shell_env(tmp_path, bindir), timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    saved = json.loads((root / "data" / ".host-profile.json").read_text())
    assert saved["class"] in hp.CLASSES
    assert saved["budget_factor"] == hp.BUDGET_FACTOR[saved["class"]]
    assert [p.name for p in (root / "data").iterdir()] == [".host-profile.json"]
    assert list(dock.iterdir()) == []
