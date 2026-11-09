# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 367 layer 1: no service credential in a URL or a container's env.

Before this, the TLS variant handed every client its password as URL userinfo
(`https://svc-api:${VMAUTH_API_PASSWORD}@vmauth:8427`) and vmauth held all six
VMAUTH_*_PASSWORD values in its environment — all readable with
`docker inspect`, and printed by anything that printed the URL (gnmic echoed
its whole output config at every start; the api logged 734 push failures with
the password in them).

Static guards over what is COMMITTED (no docker needed):
  * no compose file puts a credential inside a URL (`scheme://user:${…}@`,
    or a literal `user:pass@`);
  * no compose service declares a VMAUTH_*_PASSWORD or OS_*_PASSWORD
    environment value for vmauth or a converted client;
  * every converted client reads a FILE: the api/prober *_AUTH_PASSWORD_FILE
    env, grafana's file provider, gnmic's authentication block, Vector's
    SECRET[...] reference, opensearch-init's header-file path;
  * the mounted secret paths line up with what install.py renders.

Run:  python3 -m pytest tests/test_no_credential_in_url.py -v
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
COMPOSE_DIR = ROOT / "deployment" / "docker"
sys.path.insert(0, str(ROOT / "scripts"))

import install  # noqa: E402


class _ComposeLoader(yaml.SafeLoader):
    """SafeLoader that tolerates compose's !override / !reset merge tags."""


def _passthrough(loader, node):
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return loader.construct_scalar(node)


_ComposeLoader.add_constructor("!override", _passthrough)
_ComposeLoader.add_constructor("!reset", _passthrough)

COMPOSE_FILES = sorted(p for p in COMPOSE_DIR.glob("*.yml")
                       if p.name.startswith(("docker-compose", "compose.")))


def load(path: Path) -> dict:
    return yaml.load(path.read_text(), Loader=_ComposeLoader) or {}


def services(name: str) -> dict:
    return load(COMPOSE_DIR / name).get("services") or {}


def env_of(svc: dict) -> dict:
    env = svc.get("environment") or {}
    if isinstance(env, list):
        out = {}
        for item in env:
            k, _, v = str(item).partition("=")
            out[k] = v
        return out
    return {k: ("" if v is None else str(v)) for k, v in env.items()}


# `scheme://anything:anything@` where the password part is non-empty — a
# credential in a URL, interpolated or literal. A bare `token@` cannot be told
# from an email-ish string, so the password form is what is pinned; the
# `${VAR}@` form (a token as userinfo) is pinned separately.
CRED_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://[^\s/@\"']*:[^\s/@\"']+@")
VAR_USERINFO = re.compile(r"://\$\{[A-Za-z0-9_]+[^}]*\}@")


@pytest.mark.parametrize("path", COMPOSE_FILES, ids=lambda p: p.name)
def test_no_compose_value_carries_a_credential_in_a_url(path: Path) -> None:
    hits = []
    for svc_name, svc in (load(path).get("services") or {}).items():
        for key, value in env_of(svc).items():
            if CRED_URL.search(value) or VAR_USERINFO.search(value):
                hits.append(f"{svc_name}.{key}")
        for field in ("command", "entrypoint"):
            raw = svc.get(field) or []
            for arg in ([raw] if isinstance(raw, str) else raw):
                if CRED_URL.search(str(arg)) or VAR_USERINFO.search(str(arg)):
                    hits.append(f"{svc_name}.{field}")
    assert not hits, (
        f"{path.name}: credential inside a URL at {hits} — use the file-backed "
        "form (*_AUTH_USER + *_AUTH_PASSWORD_FILE, data/secrets) instead "
        "(tracker 367 layer 1)")


SERVICE_PASSWORD_ENV = re.compile(r"^(VMAUTH_[A-Z]+_PASSWORD|OS_[A-Z]+_PASSWORD)$")
# Services whose credential moved to a file. OS_* values that still reach
# OTHER consumers via env (opensearch-dashboards' own OSD settings, the
# vector-router / aggregator OpenSearch sinks) are out of this row's scope
# and are not listed here.
CONVERTED = ("vmauth", "api", "prober", "grafana", "gnmic", "vector-aggregator",
             "opensearch-init", "correlation")


@pytest.mark.parametrize("path", COMPOSE_FILES, ids=lambda p: p.name)
def test_converted_services_hold_no_password_env(path: Path) -> None:
    hits = []
    for svc_name, svc in (load(path).get("services") or {}).items():
        if svc_name not in CONVERTED:
            continue
        for key, value in env_of(svc).items():
            if SERVICE_PASSWORD_ENV.match(key):
                hits.append(f"{svc_name}.{key}")
            if re.search(r"\$\{(VMAUTH_[A-Z]+_PASSWORD|OS_(API|BOOTSTRAP|CORRELATION)_PASSWORD)\b", value):
                hits.append(f"{svc_name}.{key} (interpolates a service password)")
    assert not hits, f"{path.name}: service password still in a container env: {hits}"


def test_vmauth_reads_the_rendered_config_and_rechecks_it() -> None:
    svc = services("docker-compose.yml")["vmauth"]
    cmd = svc["command"]
    assert "-auth.config=/etc/vmauth/secret/auth.yml" in cmd
    assert any(a.startswith("-configCheckInterval=") for a in cmd), \
        "vmauth must re-read its config so a rotation needs no restart"
    assert "environment" not in svc or not env_of(svc), "vmauth must have no credential env"
    assert "../../data/secrets/vmauth/vmauth:/etc/vmauth/secret:ro" in svc["volumes"]
    assert install.VMAUTH_RENDERED_REL.as_posix() == "vmauth/vmauth/auth.yml"


def _mounts(svc: dict) -> list[str]:
    return [str(v) for v in svc.get("volumes") or []]


def _secret_mount(identity_rel: str) -> str:
    return f"../../data/secrets/{identity_rel}:/run/secrets/{identity_rel}:ro"


def test_tls_clients_read_their_credential_from_a_mounted_file() -> None:
    tls = services("compose.tls.yml")

    api = env_of(tls["api"])
    for k in ("VICTORIA_URL", "METRICS_URL", "OPENSEARCH_URL"):
        assert "@" not in api[k], f"api {k} still carries userinfo"
    assert api["VICTORIA_AUTH_USER"] == "svc-api"
    assert api["VICTORIA_AUTH_PASSWORD_FILE"] == "/run/secrets/vmauth/api/password"
    assert api["OPENSEARCH_AUTH_USER"] == "svc_api"
    assert api["OPENSEARCH_AUTH_PASSWORD_FILE"] == "/run/secrets/opensearch/api/password"
    assert _secret_mount("vmauth/api") in _mounts(tls["api"])
    assert _secret_mount("opensearch/api") in _mounts(tls["api"])

    prober = env_of(tls["prober"])
    assert prober["VICTORIA_AUTH_USER"] == "svc-prober"
    assert prober["VICTORIA_AUTH_PASSWORD_FILE"] == "/run/secrets/vmauth/prober/password"
    assert _secret_mount("vmauth/prober") in _mounts(tls["prober"])

    assert "OPENSEARCH_URL" not in env_of(tls["correlation"]), \
        "correlation's OPENSEARCH_URL was dead (no Python reads it) and carried a password"

    init = env_of(tls["opensearch-init"])
    assert init["OPENSEARCH_AUTH_USER"] == "svc_bootstrap"
    assert init["OPENSEARCH_AUTH_PASSWORD_FILE"] == "/run/secrets/opensearch/bootstrap/password"
    assert _secret_mount("opensearch/bootstrap") in _mounts(tls["opensearch-init"])
    assert "/tmp" in (tls["opensearch-init"].get("tmpfs") or []), \
        "the auth header file must live on a tmpfs, not the container's writable layer"

    assert _secret_mount("vmauth/grafana") in _mounts(tls["grafana"])

    agg = env_of(tls["vector-aggregator"])
    assert agg["VMAUTH_VECTOR_PASSWORD_REF"] == "SECRET[vmauth.vector]"
    assert _secret_mount("vmauth/vector") in _mounts(tls["vector-aggregator"])

    gnmic = tls["gnmic"]
    assert "@" not in env_of(gnmic)["VICTORIA_WRITE_URL"]
    ep = gnmic["entrypoint"]
    assert ep[:2] == ["/bin/sh", "/app/conf/cx-secret-env.sh"] and "--" in ep \
        and ep[ep.index("--") + 1] == "/app/gnmic", ep
    assert "GNMIC_VMAUTH_PASSWORD=/run/secrets/vmauth/gnmic/password" in ep
    assert _secret_mount("vmauth/gnmic") in _mounts(gnmic)


def test_every_mounted_secret_is_one_install_renders() -> None:
    rendered = {s.rel for s in install.SERVICE_SECRETS}
    mounted = set()
    for path in COMPOSE_FILES:
        mounted |= set(re.findall(r"\.\./\.\./data/secrets/([a-z]+/[a-z-]+):", path.read_text()))
    mounted.discard("vmauth/vmauth")
    assert mounted <= rendered, f"mounted but never rendered: {sorted(mounted - rendered)}"
    assert rendered <= mounted, f"rendered but mounted by nobody: {sorted(rendered - mounted)}"


def test_grafana_reads_the_password_through_its_file_provider() -> None:
    src = (COMPOSE_DIR / "grafana" / "datasources-mtls.yaml").read_text()
    pw_lines = [ln.strip() for ln in src.splitlines() if "basicAuthPassword" in ln]
    assert pw_lines == ["basicAuthPassword: $__file{/run/secrets/vmauth/grafana/password}"] * 2
    assert "$VMAUTH_GRAFANA_PASSWORD" not in src


@pytest.mark.parametrize("rel", ["grafana/provisioning/datasources/datasources.yaml",
                                 "grafana/datasources-mtls.yaml"])
def test_grafana_reads_the_clickhouse_password_from_a_file(rel: str) -> None:
    """Tracker 384: both datasource variants, because either one is what runs."""
    src = (COMPOSE_DIR / rel).read_text()
    assert "password: $__file{/run/secrets/clickhouse/grafana/password}" in src
    assert "GRAFANA_CH_PASSWORD" not in src


def test_grafana_holds_no_password_in_its_environment() -> None:
    svc = services("docker-compose.yml")["grafana"]
    env = env_of(svc)
    assert "GRAFANA_CH_PASSWORD" not in env
    assert "GF_SECURITY_ADMIN_PASSWORD" not in env
    assert env["GF_SECURITY_ADMIN_PASSWORD__FILE"] == "/run/secrets/grafana/admin/password"
    assert _secret_mount("clickhouse/grafana") in _mounts(svc)
    assert _secret_mount("grafana/admin") in _mounts(svc)


@pytest.mark.parametrize("name", ["gnmic.yaml", "gnmic-correlation.yaml"])
def test_gnmic_authenticates_in_its_output_not_its_url(name: str) -> None:
    cfg = yaml.safe_load((COMPOSE_DIR / "gnmic" / name).read_text())
    writes = {k: v for k, v in cfg["outputs"].items() if v["type"] == "prometheus_write"}
    assert writes, "no prometheus_write output found"
    for out_name, out in writes.items():
        assert out["url"] == "${VICTORIA_WRITE_URL}", out_name
        assert out.get("authentication") == {
            "username": "svc-gnmic", "password": "${GNMIC_VMAUTH_PASSWORD}"}, out_name


def test_vector_sink_resolves_the_password_through_the_secret_backend() -> None:
    cfg = yaml.safe_load((COMPOSE_DIR / "vector" / "vector.yaml").read_text())
    backend = cfg["secret"]["vmauth"]
    assert backend["type"] == "exec"
    assert backend["command"] == ["/bin/sh", "/etc/vector/conf/cx-secret-exec.sh", "/run/secrets/vmauth"]
    auth = cfg["sinks"]["victoria_cloud_metrics"]["auth"]
    assert auth["password"] == "${VMAUTH_VECTOR_PASSWORD_REF:-unused-on-plaintext-victoria}"
    assert "VMAUTH_VECTOR_PASSWORD}" not in (COMPOSE_DIR / "vector" / "vector.yaml").read_text()


@pytest.mark.parametrize("rel", ["vector/vector.yaml", "vector-router/vector.yaml"])
def test_vector_configs_hold_no_literal_secret_reference(rel: str) -> None:
    """Vector collects secret references from the RAW file text — comments
    included. A complete backend.key reference anywhere in the file makes the
    backend run on EVERY boot, so the plaintext baseline (no secret mounted)
    refuses its config. Caught by preflight on 2026-11-07; pinned here so it
    is caught without docker. The reference must arrive through env only."""
    text = (COMPOSE_DIR / rel).read_text()
    hits = re.findall(r"SECRET\[\w+\.[\w.\-]+\]", text)
    assert not hits, f"{rel}: literal secret reference(s) {hits} — Vector would resolve them at boot"


def test_opensearch_init_sends_the_credential_from_a_header_file() -> None:
    src = (COMPOSE_DIR / "opensearch" / "apply-ism.sh").read_text()
    assert 'curl() { command curl -H "@$CX_AUTH_HEADER" "$@"; }' in src
    assert "umask 077" in src and "trap cx_auth_cleanup EXIT" in src
    # The value must never be on a curl argv (-u user:pw is visible in ps).
    assert not re.search(r"curl[^\n]*\s-u\s", src), "a curl -u argv would expose the password in ps"
