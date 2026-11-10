# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Service-key custody (docs/design/OPENSEARCH_ACCESS_2026-11-09.md, PR B).

Until 2026-11-09 every TLS install minted every service key 0644, readable by
any local user, although only a few readers could not read a 0600 key. These
tests pin the replacement against ONE reader table,
deployment/docker/tls-key-readers.json:

  * compose: every "group" reader carries group_add of CORRELIX_GID, and nothing
    else does; no service but the api mounts the whole of data/tls; every reader's
    effective identity is the one the table says;
  * the installer: TLS_ENV_VALUES carries no mode with "other" bits and matches
    compose.tls.yml; --verify-custody passes a correct rendered tree and names
    each violation in a wrong one; the upgrade prepares and never tightens; the
    rollback widens;
  * the upgrade scripts: update.sh prepares before `compose up`, deploy.sh
    recreates the readers before the api.

The Go tests pin the mint against the same table. The docker bring-up and CI's
install-boot leg are the proof that the readers really read their keys.

Run:  python3 -m pytest tests/test_tls_key_custody.py -v
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
COMPOSE_DIR = ROOT / "deployment" / "docker"
TABLE = json.loads((COMPOSE_DIR / "tls-key-readers.json").read_text())
sys.path.insert(0, str(ROOT / "scripts"))

import install

GROUP_ADD = ["${CORRELIX_GID:-65532}"]


class _Loader(yaml.SafeLoader):
    """compose.tls.yml uses compose's `!override` tag; read it as a plain node."""


_Loader.add_constructor("!override", lambda loader, node: (
    loader.construct_sequence(node) if isinstance(node, yaml.SequenceNode)
    else loader.construct_mapping(node)))


def _services(name: str) -> dict:
    return yaml.load((COMPOSE_DIR / name).read_text(), Loader=_Loader)["services"]


BASE = _services("docker-compose.yml")
TLS = _services("compose.tls.yml")


def _merged(svc: str) -> dict:
    out = dict(BASE.get(svc, {}))
    out.update(TLS.get(svc, {}))
    return out


def _group_readers() -> set[str]:
    return {r for row in TABLE["keys"] if row["how"] == "group" for r in row["readers"]}


# ── the reader table itself ──────────────────────────────────────────────────

def test_every_mode_in_the_table_is_closed_to_others():
    for row in TABLE["keys"] + TABLE["staged"]:
        assert int(row["mode"], 8) & 0o007 == 0, row["path"]
    for rel, mode in TABLE["dirs"].items():
        assert int(mode, 8) & 0o007 == 0, rel


def test_group_rows_are_0640_and_only_group_rows_are():
    for row in TABLE["keys"]:
        want = "0640" if row["how"] == "group" else "0600"
        assert row["mode"] == want, row["path"]


def test_the_group_readers_are_the_ones_verified():
    """Effective identity checked on the pinned images (2026-11-09). A change here
    is a change to who can read a private key: it needs the same verification."""
    assert _group_readers() == {"nginx", "opensearch", "kafka", "kafka-init", "redis",
                                "correlation", "prober", "cloud-ingest"}


# ── compose shape ────────────────────────────────────────────────────────────

def test_every_group_reader_has_group_add_in_the_tls_variant():
    for svc in _group_readers():
        assert TLS[svc].get("group_add") == GROUP_ADD, (
            f"{svc} reads a 0640 key owned by the api's gid; without group_add it "
            f"cannot read it, and the service goes down at its next start")


def test_nothing_else_has_group_add():
    """group_add hands the api's gid, and with it every group-readable key it can
    reach, to a container: only the readers that need it."""
    for name, services in (("docker-compose.yml", BASE), ("compose.tls.yml", TLS)):
        for svc, spec in services.items():
            if spec.get("group_add"):
                assert name == "compose.tls.yml" and svc in _group_readers(), (name, svc)


def test_the_plaintext_file_has_no_group_add_at_all():
    assert not any(s.get("group_add") for s in BASE.values())


def test_redis_runs_as_valkey_with_its_group():
    """The image's root path drops groups (`setpriv --clear-groups`)."""
    assert TLS["redis"]["user"] == "999:1000"


def test_no_service_but_the_api_mounts_the_whole_tree():
    for name, services in (("docker-compose.yml", BASE), ("compose.tls.yml", TLS)):
        for svc, spec in services.items():
            for v in spec.get("volumes") or []:
                source = v.split(":", 1)[0] if isinstance(v, str) else v.get("source", "")
                if source.rstrip("/") in ("../../data/tls", "../../data"):
                    assert svc == "api", f"{name}: {svc} mounts {source}"


def test_readers_mount_only_their_own_key_directory():
    """A reader holding CORRELIX_GID that could see another reader's directory
    could read that key too. Map each mounted key directory to its readers."""
    by_dir = {str(Path(row["path"]).parent): set(row["readers"]) for row in TABLE["keys"]}
    for svc in set(BASE) | set(TLS):
        for v in _merged(svc).get("volumes") or []:
            if not isinstance(v, str):
                continue
            m = re.match(r"\.\./\.\./data/tls/([^:]+):", v)
            if not m or m.group(1).endswith(".pem"):
                continue
            rel = m.group(1).rstrip("/")
            if by_dir.get(rel):
                assert svc in by_dir[rel], f"{svc} mounts {rel}, read by {by_dir[rel]}"


def test_the_upgrade_ordering_list_in_deploy_sh_matches_the_table():
    text = (ROOT / "scripts" / "deploy.sh").read_text()
    m = re.search(r"^CUSTODY_READERS=\(([^)]*)\)", text, re.MULTILINE)
    assert m, "deploy.sh lost its reader list"
    listed = set(m.group(1).split())
    # kafka-init is a one-shot; it runs fresh at its next start.
    assert listed == _group_readers() - {"kafka-init"}


# ── installer values ─────────────────────────────────────────────────────────

def test_tls_env_values_carry_no_other_bits_and_match_compose():
    api_env = TLS["api"]["environment"]
    for key in ("TLS_SERVICE_KEY_MODE", "TLS_NGINX_KEY_MODE"):
        mode = install.TLS_ENV_VALUES[key]
        assert int(mode, 8) & 0o007 == 0, key
        assert api_env[key] == mode, f"{key}: .env (phase A) and compose.tls.yml (phase B) differ"
    assert api_env["TLS_MINT_ROOT"] == install.TLS_ENV_VALUES["TLS_MINT_ROOT"] == "/data/tls"


def test_phase_a_passes_the_mint_root_through():
    env = BASE["api"]["environment"]
    assert env["TLS_MINT_ROOT"] == "${TLS_MINT_ROOT:-}"


def test_dir_modes_come_from_the_table():
    modes = install.tls_custody_dir_modes()
    assert modes["tls"] == modes["tls/services"] == modes["tls/admin"] == 0o700
    assert modes["tls/nginx"] == 0o750
    assert modes["tls/services/opensearch"] == 0o750
    assert modes["tls/services/vmauth"] == 0o700
    assert modes["tls/services/gotenberg-staged"] == 0o711


# ── --verify-custody against a rendered tree ─────────────────────────────────

ME = (os.getuid(), os.getgid())


def _render(tmp: Path) -> Path:
    """A tree shaped like the api's mint with the installer's settings."""
    data = tmp / "data"
    tls = data / "tls"
    for row in TABLE["keys"]:
        f = tls / row["path"]
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("test-only\n")
        f.chmod(int(row["mode"], 8))
        f.with_suffix(".crt").write_text("public\n")
        f.with_suffix(".crt").chmod(0o644)
    (tls / "ca.pem").write_text("public\n")
    (tls / "ca.pem").chmod(0o644)
    for row in TABLE["staged"]:
        f = tls / row["path"]
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("test-only\n")
        f.chmod(int(row["mode"], 8))
    for rel, mode in install.tls_custody_dir_modes().items():
        (data / rel).chmod(mode)
    return data


def _verify(data: Path) -> list[str]:
    return install.verify_tls_custody(data, *ME)


def test_a_correct_tree_passes(tmp_path):
    assert _verify(_render(tmp_path)) == []


@pytest.mark.parametrize("rel", [row["path"] for row in TABLE["keys"]])
def test_every_key_at_0644_is_named(tmp_path, rel):
    data = _render(tmp_path)
    (data / "tls" / rel).chmod(0o644)
    problems = _verify(data)
    assert any(f"data/tls/{rel} is 0644" in p for p in problems), problems


def test_a_group_key_at_0600_is_named_too(tmp_path):
    """Too tight is a failure as well: the reader cannot read it."""
    data = _render(tmp_path)
    (data / "tls/services/kafka/kafka.key").chmod(0o600)
    assert any("kafka.key is 0600, want 0640" in p for p in _verify(data))


@pytest.mark.parametrize("rel", ["tls", "tls/services", "tls/admin", "tls/nginx"])
def test_a_widened_directory_is_named(tmp_path, rel):
    data = _render(tmp_path)
    (data / rel).chmod(0o755)
    assert any(p.startswith(f"data/{rel} is 0755") for p in _verify(data))


def test_an_unlisted_key_is_named(tmp_path):
    data = _render(tmp_path)
    stray = data / "tls" / "services" / "opensearch" / "copy.key"
    stray.write_text("x")
    stray.chmod(0o600)
    assert any("copy.key is a key the reader table does not list" in p for p in _verify(data))


def test_an_undeclared_open_directory_is_named(tmp_path):
    data = _render(tmp_path)
    d = data / "tls" / "scratch"
    d.mkdir()
    d.chmod(0o755)
    assert any("data/tls/scratch is 0755" in p for p in _verify(data))


def test_wrong_owner_is_named(tmp_path):
    data = _render(tmp_path)
    problems = install.verify_tls_custody(data, ME[0] + 1, ME[1])
    assert any("want the api's" in p for p in problems)


def test_an_in_flight_temp_key_is_tolerated_unless_open(tmp_path):
    data = _render(tmp_path)
    tmp = data / "tls" / "api.key.123.tmp"
    tmp.write_text("x")
    tmp.chmod(0o600)
    assert _verify(data) == []
    tmp.chmod(0o644)
    assert any("temp key file open to others" in p for p in _verify(data))


def test_no_tree_no_problems(tmp_path):
    """Plaintext install: data/tls is empty or absent."""
    assert install.verify_tls_custody(tmp_path / "data", *ME) == []


def test_the_output_never_carries_key_bytes(tmp_path):
    data = _render(tmp_path)
    (data / "tls" / "admin" / "admin.key").chmod(0o644)
    assert all("test-only" not in p for p in _verify(data))


# ── secrets half ─────────────────────────────────────────────────────────────

def _secret_env(**over: str) -> dict[str, str]:
    """Every key the renderer reads, plus the postgres backend so pgpass is written."""
    keys = ([x.env_key for x in install.SERVICE_SECRETS]
            + [d.env_key for d in install.DERIVED_SECRETS]
            + sorted(install.VMAUTH_TEMPLATE_KEYS))
    env = {k: f"pw-{k.lower().replace('_', '-')}" for k in keys}
    env.update(CORRELIX_UID=str(ME[0]), CORRELIX_GID=str(ME[1]), STORE_BACKEND="postgres",
               APP_DB_PASSWORD="pw-app-db")
    env.update(over)
    return env


def _render_secrets(tmp: Path, env: dict[str, str]) -> Path:
    """The REAL renderer, so the verifier is judged against what the installer
    writes. A non-root test cannot chown: the chown step is recorded, not run."""
    cfg = tmp / "src" / "config"
    cfg.mkdir(parents=True)
    cfg.joinpath("vmauth.yml").write_text((ROOT / "src" / "config" / "vmauth.yml").read_text())
    install.render_service_secrets(tmp, env, chown_paths=lambda *a: None)
    return tmp / "data"


def test_the_verifier_lists_every_file_the_renderer_writes(tmp_path):
    env = _secret_env()
    data = _render_secrets(tmp_path, env)
    base = data / install.SECRETS_SUBDIR
    written = {f.relative_to(base).as_posix() for f in base.rglob("*") if f.is_file()}
    assert written, "the renderer wrote nothing"
    assert written <= set(install.secret_file_owners(env)), written - set(install.secret_file_owners(env))
    # 384's additions are covered: the security job's six files, the dashboards
    # config and the app-state role's pgpass.
    assert {f"opensearch/security-init/{k}" for k in install._OS_IDENTITY_KEYS} <= written
    assert "opensearch/dashboards/opensearch_dashboards.secret.yml" in written
    assert f"{install.APP_DB_SECRET_REL}/{install.APP_DB_SECRET_FILE}" in written


def test_secret_files_against_their_owners(tmp_path):
    """Owners differ per reader (root, curl, the image's 1000, CORRELIX_UID). A
    non-root test cannot chown, so the check must name EXACTLY the files whose
    owner differs from the test's uid, and nothing about modes or directories."""
    env = _secret_env()
    data = _render_secrets(tmp_path, env)
    problems = install.verify_secret_custody(data, env)
    base = data / install.SECRETS_SUBDIR
    written = {f.relative_to(base).as_posix() for f in base.rglob("*") if f.is_file()}
    expect_wrong = {rel for rel, owner in install.secret_file_owners(env).items()
                    if rel in written and owner != ME}
    named = {re.search(r"data/secrets/(\S+) is owned", p).group(1) for p in problems}
    assert named == expect_wrong
    assert all("is owned by" in p for p in problems), problems


def test_the_security_job_files_belong_to_the_api_uid():
    """It runs as CORRELIX_UID (it must read the 0600 admin key), so 0400 files
    owned by the image's 1000 would be unreadable to it on any other host."""
    env = {"CORRELIX_UID": "1234", "CORRELIX_GID": "1234"}
    owners = install.secret_file_owners(env)
    for k in install._OS_IDENTITY_KEYS:
        assert owners[f"opensearch/security-init/{k}"] == (1234, 1234), k
    assert owners["opensearch/dashboards/opensearch_dashboards.secret.yml"] == (1000, 1000)


def test_a_widened_secret_is_named(tmp_path):
    env = _secret_env()
    data = _render_secrets(tmp_path, env)
    f = data / "secrets" / "opensearch" / "security-init" / "OS_API_PASSWORD"
    f.chmod(0o444)
    assert any("opensearch/security-init/OS_API_PASSWORD is 0444, want 0400" in p
               for p in install.verify_secret_custody(data, env))


def test_a_listable_identity_dir_is_named(tmp_path):
    env = _secret_env()
    data = _render_secrets(tmp_path, env)
    (data / "secrets" / "opensearch").chmod(0o755)
    assert any("data/secrets/opensearch is 0755, want 0700" in p
               for p in install.verify_secret_custody(data, env))


def test_an_unrendered_secret_file_is_named(tmp_path):
    env = _secret_env()
    data = _render_secrets(tmp_path, env)
    stray = data / "secrets" / "opensearch" / "api" / "copy"
    stray.write_text("x")
    stray.chmod(0o400)
    assert any("opensearch/api/copy is not a file the installer renders" in p
               for p in install.verify_secret_custody(data, env))


# ── upgrade and rollback helpers ─────────────────────────────────────────────

def _tls_env(tmp: Path, extra: str = "") -> Path:
    env = tmp / "deployment" / "docker" / ".env"
    env.parent.mkdir(parents=True)
    env.write_text(f"CORRELIX_UID={ME[0]}\nCORRELIX_GID={ME[1]}\nTLS_INTERNAL_CA=true\n"
                   f"TLS_SERVICE_KEY_MODE=0644\nTLS_NGINX_KEY_MODE=0644\n{extra}")
    env.chmod(0o600)
    return env


def test_prepare_rewrites_a_stale_0644_and_tightens_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(install, "chown_tree", lambda *a: None)
    env = _tls_env(tmp_path)
    old = tmp_path / "data" / "tls" / "services" / "kafka" / "kafka.key"
    old.parent.mkdir(parents=True)
    old.write_text("x")
    old.chmod(0o644)
    (tmp_path / "data" / "tls").chmod(0o775)

    assert install.prepare_tls_custody(tmp_path) is True

    got = install._parse_env(env)
    assert got["TLS_SERVICE_KEY_MODE"] == "0640"
    assert got["TLS_NGINX_KEY_MODE"] == "0640"
    assert got["TLS_MINT_ROOT"] == "/data/tls"
    # The api tightens, after the readers carry group_add. Not this step.
    assert stat.S_IMODE(old.stat().st_mode) == 0o644
    assert stat.S_IMODE((tmp_path / "data" / "tls").stat().st_mode) == 0o775
    for rel in ("tls/admin", "tls/nginx", "tls/victoria"):
        assert (tmp_path / "data" / rel).is_dir()


def test_prepare_is_a_no_op_on_plaintext(tmp_path):
    env = tmp_path / "deployment" / "docker" / ".env"
    env.parent.mkdir(parents=True)
    env.write_text("CORRELIX_UID=1\n")
    before = env.read_text()
    assert install.prepare_tls_custody(tmp_path) is False
    assert env.read_text() == before


def test_rollback_widens_for_the_previous_release(tmp_path):
    data = _render(tmp_path)
    assert install.relax_custody_for_rollback(data) == []
    for row in TABLE["keys"]:
        assert stat.S_IMODE((data / "tls" / row["path"]).stat().st_mode) == 0o644, row["path"]
    assert stat.S_IMODE((data / "tls").stat().st_mode) == 0o755
    staged = data / "tls" / TABLE["staged"][0]["path"]
    assert stat.S_IMODE(staged.stat().st_mode) == 0o400, "the staged copy is its reader's"


def test_update_sh_prepares_before_compose_up():
    text = (ROOT / "scripts" / "update.sh").read_text()
    prep = text.index("mod.prepare_tls_custody(")
    up = text.index('(cd "$COMPOSE_DIR" && docker compose up -d --remove-orphans)')
    assert prep < up


def test_deploy_sh_converges_readers_before_recreating_the_api():
    text = (ROOT / "scripts" / "deploy.sh").read_text()
    assert text.index("mod.prepare_tls_custody(") < text.index('\ncustody_converge\n')
    assert text.index('\ncustody_converge\n') < text.index('dc up -d --no-deps "${SERVICES[@]}"')


def test_the_upgrade_rollback_widens_before_starting_the_previous_version():
    text = (ROOT / "scripts" / "install-correlix.sh").read_text()
    body = text[text.index("upgrade_rollback() {"):]
    assert body.index("--custody-rollback") < body.index("starting the previous version again")


def test_the_watchdog_runs_the_custody_check():
    wd = (ROOT / "scripts" / "stack-watchdog.sh").read_text()
    assert "--verify-custody" in wd and "KEY_CUSTODY" in wd
    iw = (ROOT / "scripts" / "install-watchdog.sh").read_text()
    assert "CUSTODY_INSTALL_PY='$BUNDLE_SCRIPTS_DIR/install.py'" in iw


# ── the installer never tightens under running readers ───────────────────────

def _fake_root(tmp: Path) -> Path:
    compose_dir = tmp / "deployment" / "docker"
    compose_dir.mkdir(parents=True)
    (compose_dir / ".env").write_text(f"CORRELIX_UID={ME[0]}\nCORRELIX_GID={ME[1]}\n")
    for name in ("docker-compose.yml", "compose.tls.yml"):
        (compose_dir / name).write_text((COMPOSE_DIR / name).read_text())
    router = compose_dir / "vector-router"
    router.mkdir()
    (router / "processors-default.yaml").write_text("transforms: {}\n")
    return tmp


def _ensure(tmp: Path, monkeypatch) -> None:
    monkeypatch.setattr(install, "chown_tree", lambda *a: None)
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.delenv("SUDO_GID", raising=False)
    install.ensure_data_dirs(tmp)


def test_a_fresh_install_gets_every_custody_dir_mode(tmp_path, monkeypatch):
    root = _fake_root(tmp_path)
    _ensure(root, monkeypatch)
    for rel, mode in install.tls_custody_dir_modes().items():
        d = root / "data" / rel
        if d.exists():
            assert stat.S_IMODE(d.stat().st_mode) == mode, rel
    assert stat.S_IMODE((root / "data/tls").stat().st_mode) == 0o700


def test_an_upgrade_tightens_only_the_admin_dir(tmp_path, monkeypatch):
    """A minted tree from before custody: the running readers have no group_add
    yet, so only the api, after the recreate, may tighten their directories."""
    root = _fake_root(tmp_path)
    kafka = root / "data/tls/services/kafka"
    kafka.mkdir(parents=True)
    (kafka / "kafka.key").write_text("x")
    for d in (root / "data/tls", root / "data/tls/services", kafka):
        d.chmod(0o775)
    admin = root / "data/tls/admin"
    admin.mkdir()
    admin.chmod(0o755)

    _ensure(root, monkeypatch)

    assert stat.S_IMODE(admin.stat().st_mode) == 0o700
    for d in (root / "data/tls", root / "data/tls/services", kafka):
        assert stat.S_IMODE(d.stat().st_mode) == 0o775, d


# ── deploy.sh's ordering, executed against a fake docker ─────────────────────

FAKE_DOCKER = r'''#!/bin/sh
echo "$*" >> "$DOCKER_LOG"
case "$*" in
  # The mounted-config reload (tests/test_deploy_mounted_config.py): no running
  # containers, no config mounts — nothing to recreate, no extra --wait call.
  *"compose ps --format json"*) ;;
  *"compose config --format json"*) echo '{"services": {}}' ;;
  *"compose config"*) [ "${FAKE_CONFIG_RC:-0}" = 0 ] || { echo "boom: bad compose" >&2; exit 3; }
                      echo "services:"; [ -n "${FAKE_TLS:-}" ] && echo "    group_add:"; exit 0 ;;
  *"compose ps -q kafka"*) echo cid-kafka ;;
  *"compose ps -q redis"*) echo cid-redis ;;
  *"compose ps -q api"*) echo cid-api ;;
  *"compose ps -q"*) exit 1 ;;
  *"inspect -f {{json .HostConfig.GroupAdd}} cid-kafka"*) echo "${KAFKA_GA:-null}" ;;
  *"inspect -f {{json .HostConfig.GroupAdd}} cid-redis"*) echo '["1234"]' ;;
  *"inspect"*) echo sha256:old ;;
esac
exit 0
'''


def _deploy(tmp: Path, **env) -> tuple[int, list[str], str]:
    bindir = tmp / "bin"
    bindir.mkdir()
    (bindir / "docker").write_text(FAKE_DOCKER)
    (bindir / "docker").chmod(0o755)
    (bindir / "curl").write_text("#!/bin/sh\nexit 0\n")
    (bindir / "curl").chmod(0o755)
    log = tmp / "docker.log"
    log.touch()
    run_env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", DOCKER_LOG=str(log),
                   CORRELIX_DEPLOY_STATE_DIR=str(tmp / "deploy-state"), **env)
    r = subprocess.run(["bash", str(ROOT / "scripts" / "deploy.sh"), "api"], env=run_env,
                       capture_output=True, text=True, timeout=120, check=False)
    return r.returncode, log.read_text().splitlines(), r.stdout + r.stderr


@pytest.mark.skipif((COMPOSE_DIR / ".env").exists(), reason="an installed tree: deploy.sh would render its secrets")
def test_deploy_recreates_a_stale_reader_before_the_api(tmp_path):
    rc, calls, out = _deploy(tmp_path, FAKE_TLS="1")
    assert rc == 0, out
    readers = next(i for i, c in enumerate(calls) if "--wait" in c and " up " in f" {c} ")
    api = next(i for i, c in enumerate(calls) if c.endswith("up -d --no-deps api"))
    assert readers < api, calls
    assert calls[readers].split()[-1] == "kafka", "only the reader without group_add"


@pytest.mark.skipif((COMPOSE_DIR / ".env").exists(), reason="an installed tree")
def test_deploy_leaves_converged_readers_alone(tmp_path):
    rc, calls, out = _deploy(tmp_path, FAKE_TLS="1", KAFKA_GA='["1234"]')
    assert rc == 0, out
    assert not any("--wait" in c for c in calls), calls


@pytest.mark.skipif((COMPOSE_DIR / ".env").exists(), reason="an installed tree")
def test_deploy_does_nothing_extra_on_plaintext(tmp_path):
    rc, calls, out = _deploy(tmp_path)
    assert rc == 0, out
    assert not any("--wait" in c for c in calls), calls


@pytest.mark.skipif((COMPOSE_DIR / ".env").exists(), reason="an installed tree")
def test_deploy_refuses_when_it_cannot_tell(tmp_path):
    rc, calls, out = _deploy(tmp_path, FAKE_CONFIG_RC="1")
    assert rc == 1
    assert "cannot render the compose config" in out and "boom: bad compose" in out
    assert not any(c.endswith("up -d --no-deps api") for c in calls), "the api must not be touched"


# ── gotenberg's staged copies survive the installer's recursive chown ────────

def test_staged_uid_matches_the_init_job():
    text = (COMPOSE_DIR / "compose.tls.yml").read_text()
    uid = install.GOTENBERG_STAGED_UID
    assert f"chown {uid}:{uid} /staged/gotenberg.crt /staged/gotenberg.key /staged/ca.pem" in text
    assert install.GOTENBERG_STAGED_REL == "tls/services/gotenberg-staged"
    assert f"../../data/{install.GOTENBERG_STAGED_REL}:/staged" in text


def test_ensure_data_dirs_hands_the_staged_copies_back_after_the_chown(tmp_path, monkeypatch):
    root = _fake_root(tmp_path)
    staged = root / "data" / install.GOTENBERG_STAGED_REL
    staged.mkdir(parents=True)
    for n in ("gotenberg.crt", "gotenberg.key", "ca.pem"):
        (staged / n).write_text("x")
    events: list[tuple] = []
    monkeypatch.setattr(install, "chown_tree", lambda d, u, g, name: events.append(("tree", name)))
    monkeypatch.setattr(install, "_chown_secret_paths",
                        lambda base, rels, u, g: events.append(("files", base, tuple(rels), u, g)))
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.delenv("SUDO_GID", raising=False)

    install.ensure_data_dirs(root)

    restore = [e for e in events if e[0] == "files"]
    assert restore == [("files", staged, ("ca.pem", "gotenberg.crt", "gotenberg.key"), 1001, 1001)]
    tree_calls = [i for i, e in enumerate(events) if e[0] == "tree" and e[1].startswith("data/tls")]
    assert tree_calls and max(tree_calls) < events.index(restore[0]), (
        "the restore must come after every chown of data/tls, or that chown undoes it")


def test_no_staged_dir_no_chown(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(install, "_chown_secret_paths", lambda *a: called.append(a))
    install.restore_staged_owner(tmp_path / "absent")
    (tmp_path / "empty").mkdir()
    install.restore_staged_owner(tmp_path / "empty")
    assert called == []


def test_a_failed_restore_fails_the_install(tmp_path, monkeypatch, capsys):
    staged = tmp_path / "staged"
    staged.mkdir()
    (staged / "gotenberg.key").write_text("x")

    def deny(path, uid, gid, follow_symlinks=True):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(install.os, "chown", deny)
    monkeypatch.setattr(install, "_docker_chown_paths", lambda *a: (False, "daemon down"))
    with pytest.raises(SystemExit):
        install.restore_staged_owner(staged)
    assert "daemon down" in capsys.readouterr().err


@pytest.mark.skipif(os.geteuid() == 0, reason="root enters any directory")
def test_kafka_wrapper_names_the_missing_group_not_the_mint(tmp_path):
    """Without group_add the key directory cannot be entered, and every file in it
    looks absent. The wrapper must say which, not send the operator to the mint."""
    src = tmp_path / "certs-src"
    src.mkdir()
    for n in ("kafka.crt", "kafka.key", "ca.pem"):
        (src / n).write_text("x")
    src.chmod(0o600)
    try:
        r = subprocess.run(["sh", str(COMPOSE_DIR / "kafka" / "tls-entrypoint.sh")],
                           env={"PATH": os.environ["PATH"], "KAFKA_TLS_SRC": str(src)},
                           capture_output=True, text=True, timeout=30, check=False)
    finally:
        src.chmod(0o700)
    assert r.returncode == 78
    assert "cannot enter" in r.stderr and "group_add" in r.stderr
    assert "has not minted" not in r.stderr
