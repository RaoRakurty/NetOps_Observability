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
# Services whose credential moved to a file (tracker 367 layer 1, tracker 384).
CONVERTED = ("vmauth", "api", "prober", "grafana", "gnmic", "vector-aggregator",
             "vector-router", "opensearch-dashboards", "opensearch-security-init",
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
            if re.search(r"\$\{(VMAUTH_[A-Z]+_PASSWORD|OS_[A-Z]+_PASSWORD)\b", value):
                hits.append(f"{svc_name}.{key} (interpolates a service password)")
    assert not hits, f"{path.name}: service password still in a container env: {hits}"


# ── The ratchet (tracker 384) ───────────────────────────────────────────────
#
# Every credential a compose service still declares in its environment, named one
# by one. A credential that is NOT here fails the build; so does an entry nothing
# uses any more, so this list can only shrink. docs/runbooks/secret-rotation.md §11
# says why each remains.
ENV_CREDENTIALS_REMAINING: dict[str, set[str]] = {
    "postgres": {"POSTGRES_PASSWORD"},
    "redis": {"REDISCLI_AUTH"},
    "keycloak": {"KC_BOOTSTRAP_ADMIN_PASSWORD", "KEYCLOAK_ADMIN_PASSWORD", "KC_DB_PASSWORD"},
    "gnmic": {"SRL_GNMI_PASS", "EOS_GNMI_PASS"},    # device logins, not service credentials
    "vector-aggregator": {"INGEST_TOKEN_TRAPS", "INGEST_TOKEN_PROBES", "INGEST_TOKEN_METRICS",
                          "INGEST_TOKEN_BUS"},
    "vector-router": {"CLICKHOUSE_PASSWORD", "INGEST_TOKEN"},
    "clickhouse": {"CLICKHOUSE_PASSWORD"},
    "correlation": {"CLICKHOUSE_PASSWORD", "CORR_DEBUG_TOKEN"},
    "api": {"REDIS_PASSWORD", "INGEST_TOKEN", "INGEST_TOKEN_TRAPS", "INGEST_TOKEN_PROBES",
            "INGEST_TOKEN_METRICS", "INGEST_TOKEN_BUS", "VMALERT_WEBHOOK_TOKEN",
            "CLICKHOUSE_PASSWORD", "NTFY_ALERT_TOKEN", "PLATFORM_ALERTS_NTFY_TOKEN",
            "CORR_DEBUG_TOKEN", "NETBOX_TOKEN", "UNIFI_PASSWORD", "PAGERDUTY_KEY", "SMTP_PASS",
            "TWILIO_AUTH_TOKEN", "AWS_SECRET_ACCESS_KEY", "SERVICENOW_PASSWORD", "JIRA_API_TOKEN",
            "CONFIG_BACKUP_SSH_PASSWORD", "CONFIG_BACKUP_SSH_KEY", "PCAP_SSH_PASSWORD",
            "PCAP_SSH_KEY", "PROTOCOL_DIAG_SSH_PASSWORD", "PROTOCOL_DIAG_SSH_KEY",
            "OIDC_CLIENT_SECRET", "KEYCLOAK_ADMIN_PASSWORD", "COPILOT_API_KEY", "JWT_SECRET",
            "ENCRYPTION_KEY", "ADMIN_INITIAL_PASSWORD", "ADMIN_RESET_PASSWORD",
            "REPORT_LINK_SECRET"},
    "prober": {"INGEST_TOKEN_PROBES", "REDIS_PASSWORD"},
    "mock-servicenow": {"MOCK_SNOW_PASSWORD", "MOCK_SNOW_TOKEN"},   # test double
    "mock-nms": {"MOCK_NMS_PASSWORD"},                              # test double
    "cloud-ingest": {"INGEST_TOKEN_METRICS"},
    "netbox-postgres": {"POSTGRES_PASSWORD"},
    "netbox": {"DB_PASSWORD", "REDIS_PASSWORD", "SECRET_KEY", "SUPERUSER_PASSWORD",
               "SUPERUSER_API_TOKEN"},
}
# Interpolated variables whose name ends like a credential's but which are not one.
NOT_A_CREDENTIAL = {"STORE_PG_ALLOW_RLS_BYPASS", "JIRA_PROJECT_KEY"}
INTERPOLATED_CREDENTIAL = re.compile(
    r"\$\{([A-Z0-9_]*(?:PASSWORD|PASS|TOKEN|SECRET|_KEY)|INGEST_TOKEN_[A-Z]+)\b")


def _declared_credentials() -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for path in COMPOSE_FILES:
        for svc_name, svc in (load(path).get("services") or {}).items():
            for key, value in env_of(svc).items():
                names = set(INTERPOLATED_CREDENTIAL.findall(value)) - NOT_A_CREDENTIAL
                if names:
                    found.setdefault(svc_name, set()).add(key)
    return found


def test_no_new_credential_in_a_container_environment() -> None:
    found = _declared_credentials()
    new = {s: sorted(keys - ENV_CREDENTIALS_REMAINING.get(s, set()))
           for s, keys in found.items() if keys - ENV_CREDENTIALS_REMAINING.get(s, set())}
    assert not new, (
        f"credential(s) in a container's environment: {new}. Read it from a file rendered "
        "under data/secrets instead (scripts/install.py SERVICE_SECRETS, tracker 384). "
        "`docker inspect` shows a declared environment, including on an exited container.")


def test_the_remaining_credentials_list_only_shrinks() -> None:
    found = _declared_credentials()
    stale = {s: sorted(keys - found.get(s, set()))
             for s, keys in ENV_CREDENTIALS_REMAINING.items() if keys - found.get(s, set())}
    assert not stale, f"no longer in the compose files, so remove them from the list: {stale}"


def test_no_credential_on_a_container_argv_beyond_the_known_one() -> None:
    """A flag value is readable in `ps` by anything on the host."""
    hits = set()
    for path in COMPOSE_FILES:
        for svc_name, svc in (load(path).get("services") or {}).items():
            for field in ("command", "entrypoint"):
                raw = svc.get(field) or []
                for arg in ([raw] if isinstance(raw, str) else raw):
                    for name in INTERPOLATED_CREDENTIAL.findall(str(arg)):
                        hits.add((svc_name, name))
    assert hits == {("redis", "REDIS_PASSWORD")}, hits   # valkey --requirepass: see §11


# Where a shell-level credential could reach `ps`. Each scan looks for the flag
# followed by a variable or a command substitution, so a documented literal such
# as `--user 0:0` or `-u "$(id -u)"` on docker is not what this is about.
SCRIPT_ROOTS = (ROOT / "scripts", COMPOSE_DIR)
CURL_USER_FLAG = re.compile(r"\bcurl\b[^\n|;]*\s(?:-u|--user)\s")
PASSWORD_FLAG = re.compile(r"--password[ =][\"'$]")
HASH_P_FLAG = re.compile(r"hash\.sh\"?\s+-p\b")
# Known and not moved. Remove an entry when it is fixed; never add one.
CURL_USER_ALLOWED = {"validate-rca-ticketing-e2e.sh"}    # the mock ServiceNow's test login
PASSWORD_FLAG_ALLOWED = {
    "backup-drill.sh", "restore-drill.sh",   # a scratch server's literal, or a shell variable
    "secret_rotation.py",                    # clickhouse-client: tracker 394
    "migrate-tenant-partition.sh",           # clickhouse-client, one-off migration: tracker 394
    "run.py", "iam_audit.py",                # operator's own login to an audit tool, on its CLI
}


def _operational_scripts() -> list[Path]:
    out: list[Path] = []
    for root in SCRIPT_ROOTS:
        for p in sorted(root.rglob("*")):
            if p.suffix in (".sh", ".py") and p.is_file():
                out.append(p)
    return out


def _code(p: Path) -> str:
    """The script without its comment lines: explaining a leak is not one."""
    return "\n".join(ln for ln in p.read_text(errors="replace").splitlines()
                     if not ln.lstrip().startswith("#"))


def test_no_script_passes_a_credential_on_a_curl_argv() -> None:
    hits = [p.relative_to(ROOT).as_posix() for p in _operational_scripts()
            if p.name not in CURL_USER_ALLOWED and CURL_USER_FLAG.search(_code(p))]
    assert not hits, (f"curl -u puts the password in `ps`: {hits}. Send a config on stdin "
                      "(`curl --config -`), as scripts/overlap_rotation.py does.")


def test_no_script_passes_a_credential_on_a_password_flag() -> None:
    hits = [p.relative_to(ROOT).as_posix() for p in _operational_scripts()
            if p.name not in PASSWORD_FLAG_ALLOWED and PASSWORD_FLAG.search(_code(p))]
    assert not hits, f"a --password flag puts the value in `ps`: {hits}"


def test_no_script_hashes_a_password_from_its_argv() -> None:
    hits = [p.relative_to(ROOT).as_posix() for p in _operational_scripts()
            if HASH_P_FLAG.search(_code(p))]
    assert not hits, f"hash.sh -p puts the value on a java argv; use -env: {hits}"


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


def test_api_reads_the_postgres_password_from_a_mounted_file() -> None:
    """Tracker 384. DATABASE_URL names the role and the driver's own PGPASSFILE
    names the file; the superuser's password is not in the api at all."""
    svc = services("docker-compose.yml")["api"]
    env = env_of(svc)
    assert env["PGPASSFILE"] == f"/run/secrets/{install.APP_DB_SECRET_REL}/{install.APP_DB_SECRET_FILE}"
    assert _secret_mount(install.APP_DB_SECRET_REL) in _mounts(svc)
    assert "DB_PASSWORD" not in env, "the Postgres superuser password: nothing in the api reads it"
    assert env["DATABASE_URL"] == "${DATABASE_URL:-}", "the value comes from .env, which migrates"


def test_every_mounted_secret_is_one_install_renders() -> None:
    rendered = ({s.rel for s in install.SERVICE_SECRETS} | {d.rel for d in install.DERIVED_SECRETS}
                | {install.APP_DB_SECRET_REL})
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


def test_vector_opensearch_passwords_are_references_to_mounted_files() -> None:
    """Tracker 384. The variable keeps its name, because a running container
    must still agree with a newer vector.yaml during a partial deploy, so what
    is pinned is that its VALUE is a reference and never a password."""
    tls = services("compose.tls.yml")
    router, agg = tls["vector-router"], tls["vector-aggregator"]
    assert env_of(router)["OPENSEARCH_PASSWORD"] == "SECRET[opensearch.router]"
    assert env_of(agg)["OPENSEARCH_STATS_PASSWORD"] == "SECRET[opensearch.aggregator]"
    assert _secret_mount("opensearch/router") in _mounts(router)
    assert _secret_mount("opensearch/aggregator") in _mounts(agg)

    # The reference only resolves if a backend of that name exists and its root
    # is where the identity directory is mounted.
    router_cfg = yaml.safe_load((COMPOSE_DIR / "vector-router" / "vector.yaml").read_text())
    assert router_cfg["secret"]["opensearch"]["command"] == [
        "/bin/sh", "/etc/vector/shared/cx-secret-exec.sh", "/run/secrets/opensearch"]
    agg_cfg = yaml.safe_load((COMPOSE_DIR / "vector" / "vector.yaml").read_text())
    assert agg_cfg["secret"]["opensearch"]["command"] == [
        "/bin/sh", "/etc/vector/conf/cx-secret-exec.sh", "/run/secrets/opensearch"]
    # The router has the script through its ./vector mount.
    assert "./vector:/etc/vector/shared:ro" in _mounts(services("docker-compose.yml")["vector-router"])


def test_dashboards_reads_its_password_from_a_second_config_file() -> None:
    """Tracker 384. The image's entrypoint turns OPENSEARCH_PASSWORD into
    `--opensearch.password=<value>` on argv, so the env form is a ps leak too."""
    svc = services("compose.tls.yml")["opensearch-dashboards"]
    assert "OPENSEARCH_PASSWORD" not in env_of(svc)
    secret_cfg = "/run/secrets/opensearch/dashboards/opensearch_dashboards.secret.yml"
    assert svc["command"][0] == "opensearch-dashboards"
    assert svc["command"][-2:] == ["--config", secret_cfg]
    # Naming a --config replaces the default, so the image's own must come first.
    assert svc["command"][1:3] == [
        "--config", "/usr/share/opensearch-dashboards/config/opensearch_dashboards.yml"]
    assert _secret_mount("opensearch/dashboards") in _mounts(svc)
    d = next(d for d in install.DERIVED_SECRETS if d.rel == "opensearch/dashboards")
    assert f"/run/secrets/{d.rel}/{d.file}" == secret_cfg


def test_security_init_reads_every_identity_from_files_and_hashes_off_argv() -> None:
    """Tracker 384. An exited one-shot keeps its environment, so `docker inspect`
    on it used to show all six passwords."""
    svc = services("docker-compose.yml")["opensearch-security-init"]
    env = env_of(svc)
    assert not [k for k in env if SERVICE_PASSWORD_ENV.match(k)]
    assert env["OS_SECRET_DIR"] == "/run/secrets/opensearch/security-init"
    assert _secret_mount("opensearch/security-init") in _mounts(svc)
    src = (COMPOSE_DIR / "opensearch" / "security" / "apply-security.sh").read_text()
    assert 'hash.sh" -env "$1"' in src
    assert not re.search(r'hash\.sh"?\s+-p\b', src), "-p puts the password on the java argv"
    wanted = set(re.findall(r"\bOS_[A-Z]+_PASSWORD\b", src))
    assert wanted == set(install._OS_IDENTITY_KEYS), "script and renderer disagree on the identities"


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
