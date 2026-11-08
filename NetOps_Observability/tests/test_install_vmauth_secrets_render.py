# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""install.py render_service_secrets (tracker 367 layer 1).

Every service credential reaches its client as a read-only bind-mounted FILE
rendered from .env. Pinned here:
  * one file per client identity + vmauth's auth.yml, with the .env values;
  * modes: data/secrets 0700, group dirs 0700, identity dirs 0711, files 0400;
  * ownership requested for the consumer uid (root / curl_user / CORRELIX_UID),
    batched per owner, never for the installer's own uid;
  * auth.yml has no percent-brace token left and parses to the right users;
  * idempotent (a re-run converges to identical content and no temp files);
  * atomic (an ENOSPC part-way leaves the previous set intact, no temp file);
  * refusals name the KEY, never the value; the legacy-URL warning prints the
    key name only.

No docker: the chown step is injected, and any docker call fails the test.
Run:  python3 -m pytest tests/test_install_vmauth_secrets_render.py -v
"""
from __future__ import annotations

import errno
import os
import re
import shutil
import stat
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import install  # noqa: E402

KEYS = [s.env_key for s in install.SERVICE_SECRETS] + sorted(install.VMAUTH_TEMPLATE_KEYS)


@pytest.fixture(autouse=True)
def no_docker(monkeypatch):
    def guard(real):
        def call(argv, *args, **kwargs):
            if isinstance(argv, (list, tuple)) and argv and str(argv[0]) == "docker":
                raise AssertionError(f"docker reached from a unit test: {list(argv)[:4]}")
            return real(argv, *args, **kwargs)
        return call
    monkeypatch.setattr(install.subprocess, "run", guard(install.subprocess.run))
    monkeypatch.setattr(install.subprocess, "Popen", guard(install.subprocess.Popen))


@pytest.fixture
def tree(tmp_path):
    cfg = tmp_path / "src" / "config"
    cfg.mkdir(parents=True)
    shutil.copy2(ROOT / "src" / "config" / "vmauth.yml", cfg / "vmauth.yml")
    return tmp_path


def make_env(**over: str) -> dict[str, str]:
    env = {k: f"pw-{k.lower().replace('_', '-')}" for k in set(KEYS)}
    env["CORRELIX_UID"] = str(os.getuid())
    env["CORRELIX_GID"] = str(os.getgid())
    env.update(over)
    return env


class ChownRecorder:
    """Stands in for _chown_secret_paths: records (uid, gid, rels) and checks
    each named file exists and is still a temp (chown happens BEFORE rename)."""

    def __init__(self) -> None:
        self.calls: list[tuple[int, int, list[str]]] = []

    def __call__(self, base: Path, rels: list[str], uid: int, gid: int) -> None:
        for r in rels:
            assert (base / r).is_file(), r
            assert Path(r).name.endswith(".tmp"), f"chown must target the staged temp, got {r}"
        self.calls.append((uid, gid, sorted(rels)))


def mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


def render(tree: Path, env: dict, rec: ChownRecorder | None = None) -> list[Path]:
    return install.render_service_secrets(tree, env, chown_paths=rec or ChownRecorder())


def test_renders_every_identity_with_its_value(tree):
    env = make_env()
    paths = render(tree, env)
    base = tree / "data" / "secrets"
    for s in install.SERVICE_SECRETS:
        f = base / s.rel / "password"
        assert f in paths
        assert f.read_text() == env[s.env_key], s.rel   # no trailing newline
    assert (base / "vmauth" / "vmauth" / "auth.yml") in paths


def test_modes(tree):
    render(tree, make_env())
    base = tree / "data" / "secrets"
    assert mode(base) == 0o700
    for group in ("vmauth", "opensearch"):
        assert mode(base / group) == 0o700
    for s in install.SERVICE_SECRETS:
        assert mode(base / s.rel) == 0o711, s.rel
        assert mode(base / s.rel / "password") == 0o400, s.rel
    assert mode(base / "vmauth" / "vmauth" / "auth.yml") == 0o400


def test_ownership_is_requested_for_the_consumer_uid_batched(tree):
    rec = ChownRecorder()
    render(tree, make_env(), rec)
    owners = {(uid, gid): rels for uid, gid, rels in rec.calls}
    # api + grafana are user-mapped to CORRELIX_UID == the installer here: no
    # chown at all. Root-run consumers and curl_user get exactly one batch each.
    assert set(owners) == {(0, 0), (100, 101)}, rec.calls
    root_dirs = sorted(Path(r).parent.as_posix() for r in owners[(0, 0)])
    assert root_dirs == ["vmauth/gnmic", "vmauth/prober", "vmauth/vector", "vmauth/vmalert", "vmauth/vmauth"]
    assert [Path(r).parent.as_posix() for r in owners[(100, 101)]] == ["opensearch/bootstrap"]


def test_api_and_grafana_follow_correlix_uid(tree):
    rec = ChownRecorder()
    render(tree, make_env(CORRELIX_UID="4242", CORRELIX_GID="4343"), rec)
    owners = {(uid, gid): [Path(r).parent.as_posix() for r in rels] for uid, gid, rels in rec.calls}
    assert sorted(owners[(4242, 4343)]) == ["opensearch/api", "vmauth/api", "vmauth/grafana"]


def test_compose_defaults_when_correlix_uid_unset(tree):
    env = make_env()
    del env["CORRELIX_UID"], env["CORRELIX_GID"]
    rec = ChownRecorder()
    render(tree, env, rec)
    owners = {(uid, gid): [Path(r).parent.as_posix() for r in rels] for uid, gid, rels in rec.calls}
    assert sorted(owners[(65532, 65532)]) == ["opensearch/api", "vmauth/api"]
    assert owners[(472, 472)] == ["vmauth/grafana"]


def test_auth_yml_is_fully_rendered(tree):
    env = make_env()
    render(tree, env)
    text = (tree / "data" / "secrets" / "vmauth" / "vmauth" / "auth.yml").read_text()
    assert "%{" not in text
    users = {u["username"]: u["password"] for u in yaml.safe_load(text)["users"]}
    assert users == {
        "svc-api": env["VMAUTH_API_PASSWORD"],
        "svc-gnmic": env["VMAUTH_GNMIC_PASSWORD"],
        "svc-vector": env["VMAUTH_VECTOR_PASSWORD"],
        "svc-prober": env["VMAUTH_PROBER_PASSWORD"],
        "svc-vmalert": env["VMAUTH_VMALERT_PASSWORD"],
        "svc-grafana": env["VMAUTH_GRAFANA_PASSWORD"],
    }
    # The tracked template is untouched (helm still expands its tokens).
    assert "%{VMAUTH_API_PASSWORD}" in (tree / "src" / "config" / "vmauth.yml").read_text()


def test_idempotent_and_leaves_no_temp_files(tree):
    env = make_env()
    render(tree, env)
    base = tree / "data" / "secrets"
    first = {p: p.read_bytes() for p in base.rglob("*") if p.is_file()}
    render(tree, env)
    second = {p: p.read_bytes() for p in base.rglob("*") if p.is_file()}
    assert first == second
    assert not [p for p in base.rglob("*.tmp")]
    assert not [p for p in base.rglob(".*") if p.is_file()]


def test_rotation_rerender_replaces_values(tree):
    render(tree, make_env())
    env2 = make_env(VMAUTH_API_PASSWORD="rotated-api-value")
    render(tree, env2)
    assert (tree / "data/secrets/vmauth/api/password").read_text() == "rotated-api-value"
    assert "rotated-api-value" in (tree / "data/secrets/vmauth/vmauth/auth.yml").read_text()


def test_enospc_midway_keeps_the_previous_set(tree, monkeypatch):
    env = make_env()
    render(tree, env)
    base = tree / "data" / "secrets"
    before = {p: p.read_bytes() for p in base.rglob("*") if p.is_file()}

    calls = {"n": 0}
    real = install._raw_write

    def flaky(fd, data):
        calls["n"] += 1
        if calls["n"] == 4:   # part-way through the plan
            raise OSError(errno.ENOSPC, "No space left on device")
        return real(fd, data)

    monkeypatch.setattr(install, "_raw_write", flaky)
    with pytest.raises(OSError):
        render(tree, make_env(VMAUTH_API_PASSWORD="never-lands", OS_API_PASSWORD="never-either"))
    after = {p: p.read_bytes() for p in base.rglob("*") if p.is_file()}
    assert after == before, "a failed render must leave every previous file intact"


def test_failed_chown_leaves_the_previous_set(tree):
    render(tree, make_env())
    base = tree / "data" / "secrets"
    before = {p: p.read_bytes() for p in base.rglob("*") if p.is_file()}

    def boom(base_, rels, uid, gid):
        raise SystemExit(1)   # what fail() does

    with pytest.raises(SystemExit):
        install.render_service_secrets(tree, make_env(VMAUTH_API_PASSWORD="nope"), chown_paths=boom)
    after = {p: p.read_bytes() for p in base.rglob("*") if p.is_file()}
    assert after == before


@pytest.mark.parametrize("key,value,why", [
    ("VMAUTH_API_PASSWORD", "", "empty"),
    ("OS_API_PASSWORD", "x" * 1025, "longer than"),
    ("OS_BOOTSTRAP_PASSWORD", "a\nb", "printable"),
    ("VMAUTH_GNMIC_PASSWORD", 'has"quote', "vmauth"),
    ("VMAUTH_VMALERT_PASSWORD", "pct%{X}", "vmauth"),
])
def test_refuses_unusable_values_naming_only_the_key(tree, capsys, key, value, why):
    with pytest.raises(SystemExit):
        render(tree, make_env(**{key: value}))
    err = capsys.readouterr().err
    assert key in err and why in err
    if value:
        assert value not in err, "a refusal must never echo the value"
    assert not (tree / "data" / "secrets" / "vmauth" / "vmauth" / "auth.yml").exists()


def test_os_passwords_may_use_the_full_printable_alphabet(tree):
    # OS_* values only ever land in a file read by Go / curl: no quoting hazard.
    render(tree, make_env(OS_API_PASSWORD='a%b"c\\d'))
    assert (tree / "data/secrets/opensearch/api/password").read_text() == 'a%b"c\\d'


def test_legacy_url_warning_prints_the_key_not_the_value(tree, capsys):
    secret = "URLSECRET-77"
    env = make_env(VICTORIA_URL=f"https://svc-api:{secret}@vmauth:8427",
                   METRICS_URL="https://vmauth:8427",
                   DATABASE_URL=f"postgres://netops_app:{secret}@postgres:5432/netops")
    render(tree, env)
    out = capsys.readouterr()
    text = out.out + out.err
    assert "VICTORIA_URL" in out.err and "userinfo" in out.err
    assert "METRICS_URL" not in text
    assert "DATABASE_URL" in out.out and "deferred" in out.out   # info, not warn
    assert secret not in text
    assert install.url_credential_keys(env) == ["DATABASE_URL", "VICTORIA_URL"]


def test_never_prints_any_secret_value(tree, capsys):
    env = make_env()
    render(tree, env)
    out = capsys.readouterr()
    for k in KEYS:
        assert env[k] not in out.out + out.err


def test_repairs_a_tree_docker_created_as_another_owner(tree, monkeypatch):
    base = tree / "data" / "secrets"
    (base / "vmauth" / "api").mkdir(parents=True)
    seen = []
    real_stat = Path.stat
    me = (os.geteuid(), os.getegid())

    def fake_stat(self, *a, **kw):
        st = real_stat(self, *a, **kw)
        if self == base / "vmauth" / "api" and not seen:
            class S:
                st_uid, st_gid, st_mode = 0, 0, st.st_mode
            return S()
        return st

    monkeypatch.setattr(Path, "stat", fake_stat)
    monkeypatch.setattr(install, "chown_tree",
                        lambda d, uid, gid, name: seen.append((d, uid, gid)))
    install._ensure_secret_dirs(base, [base / "vmauth" / "api"])
    assert seen == [(base, me[0], me[1])]


def test_vmauth_template_tokens_are_all_known_keys():
    text = (ROOT / "src" / "config" / "vmauth.yml").read_text()
    tokens = set(re.findall(r'"%\{([A-Za-z0-9_]+)\}"', text))
    assert tokens == set(install.VMAUTH_TEMPLATE_KEYS)
    assert text.count("%{") == len(re.findall(r'"%\{[A-Za-z0-9_]+\}"', text)), \
        "every percent-brace token must be a quoted credential value"


def test_secret_keys_are_generated_secrets():
    gen = install.generate_secrets()
    for k in KEYS:
        assert k in gen, f"{k} is rendered but never generated"


# ── tracker 367 layer 3: the rotation overlap (two blocks per identity) ──────

def _auth_yml(tree: Path) -> str:
    return (tree / "data" / "secrets" / "vmauth" / "vmauth" / "auth.yml").read_text()


def test_every_template_block_carries_name_and_cred_label():
    """The renderer derives the previous block from name + metric_labels; the
    helm copy must stay byte-identical (it is the same file for the chart)."""
    for rel in ("src/config/vmauth.yml", "deployment/helm/correlix/files/config/vmauth.yml"):
        users = yaml.safe_load((ROOT / rel).read_text())["users"]
        assert len(users) == 6, rel
        for u in users:
            assert u["name"] == u["username"], (rel, u["username"])
            assert u["metric_labels"] == {"cred": "current"}, (rel, u["username"])
    assert (ROOT / "src/config/vmauth.yml").read_text() == \
        (ROOT / "deployment/helm/correlix/files/config/vmauth.yml").read_text()


def test_no_previous_key_renders_one_block_per_identity(tree):
    render(tree, make_env())
    users = yaml.safe_load(_auth_yml(tree))["users"]
    assert len(users) == 6
    assert {u["metric_labels"]["cred"] for u in users} == {"current"}
    assert "ROTATION IN PROGRESS" not in _auth_yml(tree)


def test_previous_key_renders_a_second_block_for_that_identity_only(tree):
    env = make_env(VMAUTH_GNMIC_PASSWORD="new-gnmic-value",
                   VMAUTH_GNMIC_PASSWORD_PREVIOUS="old-gnmic-value")
    render(tree, env)
    text = _auth_yml(tree)
    assert "%{" not in text
    users = yaml.safe_load(text)["users"]
    assert len(users) == 7
    gn = [u for u in users if u["username"] == "svc-gnmic"]
    assert [(u["name"], u["password"], u["metric_labels"]["cred"]) for u in gn] == [
        ("svc-gnmic", "new-gnmic-value", "current"),
        ("svc-gnmic-previous", "old-gnmic-value", "previous")]
    # identical routes: the old credential reaches exactly what the new one does
    assert gn[0]["url_map"] == gn[1]["url_map"]
    assert len({u["name"] for u in users}) == 7, "every vmauth `name` is unique"
    # the client file carries the CURRENT value, never the previous one
    assert (tree / "data/secrets/vmauth/gnmic/password").read_text() == "new-gnmic-value"


def test_two_block_render_is_idempotent(tree):
    env = make_env(VMAUTH_API_PASSWORD="n" * 24, VMAUTH_API_PASSWORD_PREVIOUS="o" * 24,
                   VMAUTH_VECTOR_PASSWORD="m" * 24, VMAUTH_VECTOR_PASSWORD_PREVIOUS="p" * 24)
    render(tree, env)
    first = _auth_yml(tree)
    render(tree, env)
    assert _auth_yml(tree) == first
    names = [u["name"] for u in yaml.safe_load(first)["users"]]
    assert names.count("svc-api-previous") == 1 and names.count("svc-vector-previous") == 1


def test_vmauth_only_render_leaves_client_files_alone(tree):
    render(tree, make_env())
    client = tree / "data/secrets/vmauth/api/password"
    before = client.read_bytes()
    env = make_env(VMAUTH_API_PASSWORD="brand-new-value",
                   VMAUTH_API_PASSWORD_PREVIOUS=before.decode())
    paths = install.render_service_secrets(tree, env, chown_paths=ChownRecorder(), vmauth_only=True)
    assert paths == [tree / "data/secrets/vmauth/vmauth/auth.yml"]
    assert client.read_bytes() == before, "a client must not see the new value before vmauth does"
    assert "brand-new-value" in _auth_yml(tree)


@pytest.mark.parametrize("extra, fragment, secret", [
    ({"VMAUTH_API_PASSWORD_PREVIOUS": "pw-vmauth-api-password"}, "equals VMAUTH_API_PASSWORD", None),
    ({"VMAUTH_BOGUS_PASSWORD_PREVIOUS": "bogus-value-1234"}, "not a vmauth credential", "bogus-value-1234"),
    ({"VMAUTH_API_PASSWORD_PREVIOUS": 'quo"te-value-1234'}, "VMAUTH_API_PASSWORD_PREVIOUS", 'quo"te-value-1234'),
])
def test_unusable_previous_values_are_refused_by_name(tree, capsys, extra, fragment, secret):
    with pytest.raises(SystemExit):
        render(tree, make_env(**extra))
    err = capsys.readouterr().err
    assert fragment in err
    if secret:
        assert secret not in err, "a refusal must never echo the value"
    assert not (tree / "data" / "secrets" / "vmauth" / "vmauth" / "auth.yml").exists()


def test_a_block_without_name_and_label_cannot_be_overlapped(tree, capsys):
    tpl = tree / "src" / "config" / "vmauth.yml"
    tpl.write_text(tpl.read_text().replace('    name: "svc-api"\n', "", 1))
    with pytest.raises(SystemExit):
        render(tree, make_env(VMAUTH_API_PASSWORD_PREVIOUS="old-api-value"))
    assert "must carry" in capsys.readouterr().err
