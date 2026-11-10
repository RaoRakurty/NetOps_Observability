# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""deploy.sh / update.sh must not leave a service running an OLD mounted config.

`docker compose up -d` recreates a container only when its image or compose
definition changed. vector-aggregator ran 7 h on the old VRL after a deploy,
syslog-ng kept its old conf, and vmalert only picks up changed alert rules after
a manual restart — seen three times on the lab. A customer running update.sh
would silently keep old parsing and alert rules (scripts/CLAUDE.md §16.1).

The fix fingerprints every service's read-only bind mounts under deployment/ and
src/config/ (scripts/mounted_config.py), records them after each successful run,
and force-recreates a changed service compose left running.

Two layers here:
  * unit tests of scripts/mounted_config.py — the selection rule, determinism,
    the plan and the state record;
  * the REAL deploy.sh and update.sh run inside a throwaway repo copy against a
    stateful fake `docker` (containers get new ids when recreated), so the live
    stack is never touched.

Run:  python3 -m pytest tests/test_deploy_mounted_config.py -v
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
MC_PY = SCRIPTS / "mounted_config.py"
MC_SH = SCRIPTS / "lib" / "mounted-config.sh"


def _load_mc():
    spec = importlib.util.spec_from_file_location("mounted_config", MC_PY)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


mc = _load_mc()


# ── a minimal install tree + the compose config that would describe it ──────


def _tree(root: Path) -> None:
    (root / "deployment" / "docker" / "vector" / "generated").mkdir(parents=True)
    (root / "deployment" / "docker" / "vector" / "vector.yaml").write_text("sources: {}\n")
    (root / "deployment" / "docker" / "vector" / "generated" / "pack.vrl").write_text(".a = 1\n")
    (root / "deployment" / "docker" / "syslog-ng").mkdir(parents=True)
    (root / "deployment" / "docker" / "syslog-ng" / "netops.conf").write_text("source s {};\n")
    (root / "deployment" / "docker" / "nginx" / "certs").mkdir(parents=True)
    (root / "deployment" / "docker" / "nginx" / "certs" / "key.pem").write_text("KEY-A\n")
    (root / "deployment" / "docker" / "nginx" / "nginx.conf").write_text("events {}\n")
    (root / "src" / "config").mkdir(parents=True)
    (root / "src" / "config" / "rules.yaml").write_text("groups: []\n")
    (root / "data" / "vector-aggregator").mkdir(parents=True)
    (root / "data" / "vector-aggregator" / "checkpoint").write_text("1\n")
    (root / "data" / "api" / "enrichment").mkdir(parents=True)
    (root / "data" / "api" / "enrichment" / "table.csv").write_text("a,b\n")


def _bind(root: Path, rel: str, target: str, ro: bool = True) -> dict:
    m = {"type": "bind", "source": str(root / rel), "target": target, "bind": {}}
    if ro:
        m["read_only"] = True
    return m


def _config(root: Path) -> dict:
    return {"name": "netops", "services": {
        "vector-aggregator": {"image": "vector", "volumes": [
            _bind(root, "deployment/docker/vector", "/etc/vector/conf"),
            _bind(root, "data/vector-aggregator", "/var/lib/vector", ro=False),
            _bind(root, "data/api/enrichment", "/etc/vector/enrichment"),
            {"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock",
             "read_only": True},
        ]},
        "syslog-ng": {"image": "syslog-ng", "volumes": [
            _bind(root, "deployment/docker/syslog-ng", "/etc/syslog-ng/conf.d")]},
        "vmalert": {"image": "vmalert", "volumes": [
            _bind(root, "src/config", "/etc/vmalert/config")]},
        "nginx": {"image": "nginx", "volumes": [
            _bind(root, "deployment/docker/nginx/nginx.conf", "/etc/nginx/nginx.conf"),
            _bind(root, "deployment/docker/nginx/certs", "/etc/nginx/certs")]},
        "api": {"image": "api", "volumes": [
            _bind(root, "src/config", "/config"),
            _bind(root, "data/api", "/data", ro=False)]},
        "postgres": {"image": "postgres", "volumes": [
            _bind(root, "data/postgres", "/var/lib/postgresql/data", ro=False),
            {"type": "volume", "source": "pgsock", "target": "/run/postgresql"}]},
    }}


# ── unit: the selection rule and determinism ────────────────────────────────


def test_fingerprint_is_stable_and_independent_of_the_install_path(tmp_path):
    a, b = tmp_path / "a", tmp_path / "elsewhere" / "b"
    _tree(a)
    _tree(b)
    fa1 = mc.fingerprints(_config(a), a)
    fa2 = mc.fingerprints(_config(a), a)
    assert fa1 == fa2
    assert fa1 == mc.fingerprints(_config(b), b), "the hash must not depend on where the install lives"
    assert set(fa1) == {"vector-aggregator", "syslog-ng", "vmalert", "nginx", "api"}
    assert "postgres" not in fa1, "a service with only data mounts has nothing to track"


def test_a_changed_mounted_file_marks_only_its_service(tmp_path):
    _tree(tmp_path)
    before = mc.fingerprints(_config(tmp_path), tmp_path)
    (tmp_path / "deployment/docker/vector/generated/pack.vrl").write_text(".a = 2\n")
    after = mc.fingerprints(_config(tmp_path), tmp_path)
    assert {s for s in before if before[s] != after[s]} == {"vector-aggregator"}


def test_shared_mount_marks_every_service_that_reads_it(tmp_path):
    _tree(tmp_path)
    before = mc.fingerprints(_config(tmp_path), tmp_path)
    (tmp_path / "src/config/rules.yaml").write_text("groups: [x]\n")
    after = mc.fingerprints(_config(tmp_path), tmp_path)
    assert {s for s in before if before[s] != after[s]} == {"vmalert", "api"}


@pytest.mark.parametrize("rel", [
    "data/vector-aggregator/checkpoint",        # writable bind: service state
    "data/api/enrichment/table.csv",            # read-only, but data/ is runtime-written
    "deployment/docker/nginx/certs/key.pem",    # key material: own reload path, never read
])
def test_writable_data_and_key_material_mounts_are_ignored(tmp_path, rel):
    _tree(tmp_path)
    before = mc.fingerprints(_config(tmp_path), tmp_path)
    (tmp_path / rel).write_text("changed at runtime\n")
    assert mc.fingerprints(_config(tmp_path), tmp_path) == before


def test_new_removed_and_renamed_files_count(tmp_path):
    _tree(tmp_path)
    fp = lambda: mc.fingerprints(_config(tmp_path), tmp_path)["syslog-ng"]
    base = fp()
    extra = tmp_path / "deployment/docker/syslog-ng/extra.conf"
    extra.write_text("x\n")
    added = fp()
    assert added != base
    extra.rename(extra.with_name("renamed.conf"))
    assert fp() not in (base, added)
    extra.with_name("renamed.conf").unlink()
    assert fp() == base


def test_symlinks_are_recorded_not_followed(tmp_path):
    _tree(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("one\n")
    (tmp_path / "deployment/docker/syslog-ng/link.conf").symlink_to(outside)
    fp1 = mc.fingerprints(_config(tmp_path), tmp_path)["syslog-ng"]
    outside.write_text("two\n")  # outside the tree: not ours, not read
    assert mc.fingerprints(_config(tmp_path), tmp_path)["syslog-ng"] == fp1


def test_a_missing_source_is_a_state_not_an_error(tmp_path):
    _tree(tmp_path)
    shutil.rmtree(tmp_path / "deployment/docker/syslog-ng")
    gone = mc.fingerprints(_config(tmp_path), tmp_path)["syslog-ng"]
    (tmp_path / "deployment/docker/syslog-ng").mkdir()
    assert mc.fingerprints(_config(tmp_path), tmp_path)["syslog-ng"] != gone


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode-000 file")
def test_an_unreadable_config_file_is_fatal_not_skipped(tmp_path):
    _tree(tmp_path)
    f = tmp_path / "deployment/docker/syslog-ng/netops.conf"
    f.chmod(0)
    try:
        r = subprocess.run(["python3", str(MC_PY), "fingerprint", "--root", str(tmp_path)],
                           input=json.dumps(_config(tmp_path)), capture_output=True, text=True,
                           timeout=60, check=False)
    finally:
        f.chmod(0o644)
    assert r.returncode == 2
    assert "cannot read mounted config file" in r.stderr and "netops.conf" in r.stderr


def test_garbage_compose_config_is_fatal():
    r = subprocess.run(["python3", str(MC_PY), "fingerprint", "--root", "/"],
                       input="not json", capture_output=True, text=True, timeout=60, check=False)
    assert r.returncode == 2 and "not valid JSON" in r.stderr


# ── unit: snapshots, plan, state ─────────────────────────────────────────────


def test_parse_ps_accepts_both_compose_formats_and_only_running():
    rows = [{"Service": "a", "ID": "1", "State": "running"},
            {"Service": "b", "ID": "2", "State": "exited"},
            {"Service": "c", "ID": "4", "State": "running"},
            {"Service": "c", "ID": "3", "State": "running"}]
    want = {"a": "1", "c": "3,4"}
    assert mc.parse_ps(json.dumps(rows)) == want
    assert mc.parse_ps("\n".join(json.dumps(r) for r in rows)) == want
    assert mc.parse_ps("") == {}
    with pytest.raises(mc.InputError):
        mc.parse_ps('{"Service": "a"}')


FP = {"vec": "f-new", "sys": "s-same", "vma": "v-new", "gone": "g-new", "fresh": "n-1"}
STATE = {"vec": "f-old", "sys": "s-same", "vma": "v-old", "gone": "g-old"}
BEFORE = {"vec": "c1", "sys": "c2", "vma": "c3", "fresh": "c9"}


def test_plan_first_run_restarts_nothing():
    assert mc.plan_lines(None, "", FP, BEFORE, BEFORE, None) == ["first-run"]


def test_plan_classifies_every_case():
    after = {"vec": "c1", "sys": "c2", "vma": "c3-new", "fresh": "c9"}
    lines = mc.plan_lines(STATE, "", FP, BEFORE, after, None)
    assert lines == ["baseline fresh", "not-running gone", "restart vec", "recreated vma"]


def test_plan_named_scope_turns_other_changes_into_warnings():
    lines = mc.plan_lines(STATE, "", FP, BEFORE, BEFORE, ["api", "vma"])
    assert "restart vma" in lines and "stale vec" in lines
    assert not any(ln.startswith("restart vec") for ln in lines)


def test_plan_with_an_unusable_state_treats_everything_as_changed():
    lines = mc.plan_lines(None, "bad json", FP, BEFORE, BEFORE, None)
    assert lines[0] == "state-unreadable bad json"
    assert {"restart vec", "restart sys", "restart vma", "restart fresh"} <= set(lines)


def test_merged_state_keeps_the_old_fingerprint_of_a_service_left_stale():
    after = {"vec": "c1", "sys": "c2", "vma": "c3-new", "fresh": "c9"}
    new = mc.merged_state(STATE, FP, BEFORE, after)
    assert new["vec"] == "f-old", "an unapplied change must keep warning on the next run"
    assert new["vma"] == "v-new" and new["fresh"] == "n-1" and new["sys"] == "s-same"
    assert new["gone"] == "g-old", "a stopped service's record is left untouched"


def test_state_write_is_atomic_and_private(tmp_path):
    path = tmp_path / "data" / ".deploy" / "config-fingerprints.json"
    mc.write_state(path, {"a": "1"})
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert [p.name for p in path.parent.iterdir()] == [path.name], "a temp file was left behind"
    assert mc.load_state(path) == ({"a": "1"}, "")
    path.write_text("{oops")
    state, problem = mc.load_state(path)
    assert state is None and "not valid JSON" in problem
    path.write_text('{"version": 99, "services": {}}')
    assert mc.load_state(path)[0] is None
    assert mc.load_state(tmp_path / "absent.json") == (None, "")


# ── the real scripts against a stateful fake docker ──────────────────────────

FAKE_DOCKER = r'''#!/usr/bin/env python3
"""Stateful stand-in for docker: services get a new container id when recreated."""
import json, os, sys
state_dir = os.environ["FAKE_DOCKER_STATE"]
cpath = os.path.join(state_dir, "containers.json")
containers = json.load(open(cpath)) if os.path.exists(cpath) else {}
args = sys.argv[1:]
with open(os.path.join(state_dir, "calls.log"), "a") as fh:
    fh.write(os.getcwd() + "|" + " ".join(args) + "\n")

def save():
    json.dump(containers, open(cpath, "w"))

def recreate(svc):
    n = int(open(os.path.join(state_dir, "seq")).read()) if os.path.exists(os.path.join(state_dir, "seq")) else 100
    open(os.path.join(state_dir, "seq"), "w").write(str(n + 1))
    containers[svc] = f"{svc}-{n}"

if args[:1] != ["compose"]:
    if args[:1] == ["inspect"]:
        print("sha256:0000000000000000000000old")
    sys.exit(0)
sub = args[1:]
if sub[:1] == ["config"]:
    if "--format" in sub:
        sys.stdout.write(open(os.environ["FAKE_COMPOSE_CONFIG"]).read())
    else:
        print("services: {}")
elif sub[:1] == ["ps"]:
    if "--format" in sub:
        for svc, cid in sorted(containers.items()):
            print(json.dumps({"Service": svc, "ID": cid, "State": "running"}))
    elif "-q" in sub:
        svc = sub[-1]
        if svc in containers:
            print(containers[svc])
    else:
        for svc, cid in sorted(containers.items()):
            print(svc, cid, "running")
elif sub[:1] == ["up"]:
    names, skip = [], False
    for a in sub[1:]:
        if skip:
            skip = False
        elif a == "--wait-timeout":
            skip = True
        elif not a.startswith("-"):
            names.append(a)
    if "--force-recreate" in sub:
        if os.environ.get("FAKE_FORCE_FAIL") == "1":
            print("container is unhealthy", file=sys.stderr)
            sys.exit(1)
        for s in names:
            recreate(s)
    else:
        for s in [x for x in os.environ.get("FAKE_UP_RECREATES", "").split(",") if x]:
            recreate(s)
        for s in names:
            if s not in containers:
                recreate(s)
    save()
sys.exit(0)
'''

INSTALL_STUB = '''"""Stand-in for scripts/install.py: update.sh only calls these four."""
def validate_scaffold(root): pass
def migrate_env_credentials(path): pass
def render_service_secrets(root): pass
def prepare_tls_custody(root): pass
'''

RUNNING = {"vector-aggregator": "va-1", "syslog-ng": "sy-1", "vmalert": "vm-1",
           "nginx": "ng-1", "api": "api-1", "postgres": "pg-1"}


class Rig:
    def __init__(self, tmp_path: Path):
        self.tmp = tmp_path
        self.repo = tmp_path / "repo"
        _tree(self.repo)
        (self.repo / "scripts" / "lib").mkdir(parents=True)
        for src, dst in ((SCRIPTS / "deploy.sh", "scripts/deploy.sh"),
                         (SCRIPTS / "update.sh", "scripts/update.sh"),
                         (MC_PY, "scripts/mounted_config.py"),
                         (MC_SH, "scripts/lib/mounted-config.sh")):
            shutil.copy(src, self.repo / dst)
        (self.repo / "scripts" / "install.py").write_text(INSTALL_STUB)
        (self.repo / "deployment" / "docker" / "docker-compose.yml").write_text("services: {}\n")
        self.state_dir = tmp_path / "docker-state"
        self.state_dir.mkdir()
        (self.state_dir / "containers.json").write_text(json.dumps(RUNNING))
        self.config = tmp_path / "compose-config.json"
        self.config.write_text(json.dumps(_config(self.repo)))
        self.bindir = tmp_path / "bin"
        self.bindir.mkdir()
        for name, body in (("docker", FAKE_DOCKER), ("curl", "#!/usr/bin/env bash\nexit 0\n"),
                           ("sleep", "#!/usr/bin/env bash\nexit 0\n")):
            (self.bindir / name).write_text(body)
            (self.bindir / name).chmod(0o755)
        self.fp_file = self.repo / "data" / ".deploy" / "config-fingerprints.json"

    def run(self, script: str, *args: str, **env_extra: str) -> subprocess.CompletedProcess:
        log = self.state_dir / "calls.log"
        if log.exists():
            log.unlink()
        env = {**os.environ, "PATH": f"{self.bindir}:{os.environ['PATH']}",
               "FAKE_DOCKER_STATE": str(self.state_dir), "FAKE_COMPOSE_CONFIG": str(self.config),
               "TMPDIR": str(self.tmp), **env_extra}
        env.pop("CORRELIX_DEPLOY_STATE_DIR", None)
        return subprocess.run(["bash", str(self.repo / "scripts" / script), *args], env=env,
                              capture_output=True, text=True, timeout=120, cwd=self.tmp, check=False)

    def deploy(self, *args: str, **env: str) -> subprocess.CompletedProcess:
        return self.run("deploy.sh", *args, **env)

    def update(self, **env: str) -> subprocess.CompletedProcess:
        (self.repo / "deployment" / "docker" / ".env").write_text("COMPOSE_FILE=docker-compose.yml\n")
        return self.run("update.sh", "--yes", "--no-backup", "--no-build", **env)

    def force_recreated(self) -> list[str]:
        log = self.state_dir / "calls.log"
        lines = log.read_text().splitlines() if log.exists() else []
        out = []
        for ln in lines:
            cwd, args = ln.split("|", 1)
            if "--force-recreate" in args:
                assert Path(cwd).resolve() == (self.repo / "deployment" / "docker").resolve()
                assert " -f " not in f" {args} ", "an explicit -f drops the COMPOSE_FILE overlays"
                assert "--no-deps" in args and "--no-build" in args and "--wait" in args, args
                out.append(args)
        return out

    def recorded(self) -> dict:
        return json.loads(self.fp_file.read_text())["services"]

    def edit(self, rel: str, text: str) -> None:
        (self.repo / rel).write_text(text)


def _out(r: subprocess.CompletedProcess) -> str:
    return r.stdout + r.stderr


@pytest.fixture
def rig(tmp_path):
    return Rig(tmp_path)


def test_deploy_first_run_records_a_baseline_and_recreates_nothing(rig):
    r = rig.deploy("api")
    assert r.returncode == 0, _out(r)
    assert "recording a baseline" in r.stdout
    assert rig.force_recreated() == []
    assert set(rig.recorded()) == {"vector-aggregator", "syslog-ng", "vmalert", "nginx", "api"}
    assert stat.S_IMODE(rig.fp_file.stat().st_mode) == 0o600
    assert not list(rig.tmp.glob("correlix-mounted-config.*")), "the work dir was not cleaned up"


def test_deploy_recreates_a_named_service_whose_mounted_config_changed(rig):
    assert rig.deploy("api").returncode == 0
    old = rig.recorded()
    rig.edit("deployment/docker/vector/generated/pack.vrl", ".a = 2\n")
    r = rig.deploy("vector-aggregator")  # compose sees no image change: leaves it running
    assert r.returncode == 0, _out(r)
    calls = rig.force_recreated()
    assert len(calls) == 1 and calls[0].endswith(" vector-aggregator"), calls
    assert "recreated because their mounted config changed: vector-aggregator" in r.stdout
    new = rig.recorded()
    assert new["vector-aggregator"] != old["vector-aggregator"]
    assert {k: v for k, v in new.items() if k != "vector-aggregator"} == \
           {k: v for k, v in old.items() if k != "vector-aggregator"}


def test_deploy_named_mode_warns_by_name_about_other_changed_services(rig):
    assert rig.deploy("api").returncode == 0
    old = rig.recorded()
    rig.edit("deployment/docker/syslog-ng/netops.conf", "source s2 {};\n")
    r = rig.deploy("api")
    assert r.returncode == 0, _out(r)
    assert rig.force_recreated() == [], "an unnamed service was recreated without the flag"
    assert r.stdout.count("syslog-ng — they are STILL RUNNING THE OLD CONFIG") == 2, \
        "the warning must name the service, and repeat after the success line"
    assert "--reload-changed-config" in r.stdout
    assert rig.recorded()["syslog-ng"] == old["syslog-ng"], "an unapplied change must keep warning"
    # ... and it does warn again next time, until applied with the flag.
    r2 = rig.deploy("api")
    assert "syslog-ng — they are STILL RUNNING THE OLD CONFIG" in r2.stdout
    r3 = rig.deploy("--reload-changed-config", "api")
    assert r3.returncode == 0, _out(r3)
    calls = rig.force_recreated()
    assert len(calls) == 1 and calls[0].endswith(" syslog-ng"), calls
    assert "recreated because their mounted config changed: syslog-ng" in r3.stdout
    assert rig.recorded()["syslog-ng"] != old["syslog-ng"]
    assert "STILL RUNNING THE OLD CONFIG" not in rig.deploy("api").stdout


def test_a_service_compose_already_recreated_is_not_recreated_twice(rig):
    assert rig.deploy("api").returncode == 0
    rig.edit("src/config/rules.yaml", "groups: [new]\n")  # api AND vmalert mount it
    r = rig.deploy("api", FAKE_UP_RECREATES="api")  # new api image: compose recreates it
    assert r.returncode == 0, _out(r)
    assert rig.force_recreated() == []
    assert "mounted config changed for api — already recreated" in r.stdout
    assert "vmalert — they are STILL RUNNING THE OLD CONFIG" in r.stdout


def test_a_writable_or_data_mount_change_restarts_nothing(rig):
    assert rig.deploy("api").returncode == 0
    rig.edit("data/vector-aggregator/checkpoint", "2\n")
    rig.edit("data/api/enrichment/table.csv", "c,d\n")
    r = rig.deploy("--reload-changed-config", "api")
    assert r.returncode == 0, _out(r)
    assert rig.force_recreated() == []
    assert "STILL RUNNING THE OLD CONFIG" not in r.stdout


def test_deploy_reload_failure_is_loud_non_zero_and_records_nothing(rig):
    assert rig.deploy("api").returncode == 0
    old = rig.fp_file.read_text()
    rig.edit("deployment/docker/vector/vector.yaml", "sources: {x: 1}\n")
    r = rig.deploy("--reload-changed-config", "api", FAKE_FORCE_FAIL="1")
    assert r.returncode == 2, _out(r)
    assert "MOUNTED CONFIG COULD NOT BE APPLIED to: vector-aggregator" in r.stderr
    assert "NOT rolled back" in r.stdout and "vector-aggregator" in r.stdout
    assert rig.fp_file.read_text() == old, "a failed run must not advance the record"


def test_deploy_aborts_untouched_when_the_config_cannot_be_fingerprinted(rig):
    rig.config.write_text("not json")
    r = rig.deploy("api")
    assert r.returncode == 1
    assert "cannot fingerprint the mounted config" in r.stderr and "UNTOUCHED" in r.stderr
    log = (rig.state_dir / "calls.log").read_text()
    assert "compose up" not in log and "compose build" not in log


def test_deploy_rejects_an_unknown_flag(rig):
    r = rig.deploy("--reload-changed-confg", "api")
    assert r.returncode == 2 and "unknown flag" in r.stderr
    assert not (rig.state_dir / "calls.log").exists(), "docker ran despite a bad flag"


def test_update_first_run_then_recreates_every_changed_service(rig):
    r = rig.update()
    assert r.returncode == 0, _out(r)
    assert "recording a baseline" in r.stdout
    assert rig.force_recreated() == []
    old = rig.recorded()
    rig.edit("deployment/docker/syslog-ng/netops.conf", "source s3 {};\n")
    rig.edit("src/config/rules.yaml", "groups: [new]\n")
    r = rig.update(FAKE_UP_RECREATES="api")
    assert r.returncode == 0, _out(r)
    calls = rig.force_recreated()
    assert len(calls) == 1, calls
    assert calls[0].split()[-2:] == ["syslog-ng", "vmalert"], calls
    assert "recreated because their mounted config changed: syslog-ng vmalert" in r.stdout
    assert "already recreated above" in r.stdout  # api, by the image change
    new = rig.recorded()
    for s in ("syslog-ng", "vmalert", "api"):
        assert new[s] != old[s]
    assert new["vector-aggregator"] == old["vector-aggregator"]


def test_update_with_the_stack_stopped_needs_no_extra_recreate(rig):
    assert rig.update().returncode == 0
    rig.edit("deployment/docker/syslog-ng/netops.conf", "source s4 {};\n")
    (rig.state_dir / "containers.json").write_text("{}")  # systemctl stop netops
    r = rig.update(FAKE_UP_RECREATES=",".join(RUNNING))
    assert r.returncode == 0, _out(r)
    assert rig.force_recreated() == []


def test_update_reload_failure_fails_loud_and_records_nothing(rig):
    assert rig.update().returncode == 0
    old = rig.fp_file.read_text()
    rig.edit("deployment/docker/vector/vector.yaml", "sources: {y: 1}\n")
    r = rig.update(FAKE_FORCE_FAIL="1")
    assert r.returncode != 0
    assert "MOUNTED CONFIG COULD NOT BE APPLIED" in r.stderr and "vector-aggregator" in r.stderr
    assert "Upgrade complete" not in r.stdout
    assert rig.fp_file.read_text() == old


def test_update_with_a_corrupt_record_recreates_every_tracked_service(rig):
    assert rig.update().returncode == 0
    rig.fp_file.write_text("{corrupt")
    r = rig.update()
    assert r.returncode == 0, _out(r)
    assert "fingerprint record is unusable" in r.stderr
    calls = rig.force_recreated()
    assert len(calls) == 1
    assert set(calls[0].split()) >= {"vector-aggregator", "syslog-ng", "vmalert", "nginx", "api"}


# ── hygiene ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("script", ["deploy.sh", "update.sh", "lib/mounted-config.sh"])
def test_touched_scripts_parse_and_are_shellcheck_clean(script):
    path = SCRIPTS / script
    assert subprocess.run(["bash", "-n", str(path)], capture_output=True, timeout=30, check=False).returncode == 0
    if shutil.which("shellcheck") is None:
        pytest.skip("shellcheck not installed")
    r = subprocess.run(["shellcheck", "-x", script], cwd=SCRIPTS, capture_output=True, text=True,
                       timeout=60, check=False)
    assert r.returncode == 0, r.stdout + r.stderr


def test_both_paths_share_one_implementation():
    for script in ("deploy.sh", "update.sh"):
        src = (SCRIPTS / script).read_text()
        assert ". \"$ROOT/scripts/lib/mounted-config.sh\"" in src, script
        for fn in ("mc_begin", "mc_plan", "mc_recreate", "mc_commit"):
            assert fn in src, f"{script} does not call {fn}"
    # The snapshot must precede the recreate in both paths, or "compose already
    # recreated it" cannot be told apart from "compose left it running".
    dep = (SCRIPTS / "deploy.sh").read_text()
    assert dep.index("if ! mc_begin") < dep.index('dc up -d --no-deps "${SERVICES[@]}"') \
        < dep.index("mc_plan ") < dep.index("wait_health 30") < dep.index("if ! mc_commit")
    upd = (SCRIPTS / "update.sh").read_text()
    assert upd.index("if ! mc_begin") < upd.index("&& docker compose up -d --remove-orphans)") \
        < upd.index("mc_plan ||") < upd.index("mc_commit ||")
