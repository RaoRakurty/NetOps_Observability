# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""The vmalert -> api alert-DELIVERY contract, across both compose variants.

WHY THIS EXISTS. Before 2026-09-02 vmalert ran with `-notifier.blackhole`:
rules were evaluated correctly and delivered NOWHERE. Thirteen alerts were
firing, some since 2026-08-27, and not one had ever reached a human — which is
how a correlation-engine outage lasted three hours with a `CorrProbeLaneFlatlined`
sitting in the ALERTS series the whole time.

The delivery path is easy to re-break silently, in three distinct ways, and
each is pinned below:

  1. **The blackhole comes back.** `compose.tls.yml` REPLACES the whole
     `command:` list (compose semantics), so a flag added only to the base file
     is silently absent on a TLS install. That is not hypothetical — the second
     `-rule=` flag has a comment in the file warning about exactly this.
  2. **mTLS refuses the POST.** With `TLS_CERT_FILE` set the api's :8080 is
     HTTPS with RequireClientCert and authorizes by SPIFFE URI SAN. A valid,
     CA-signed cert that is not on `TLS_CLIENT_ALLOWED_URIS` is rejected with a
     TLS `bad certificate` alert — verified live on 2026-09-02: the
     vector-router SVID got HTTP 200 and the vmalert SVID got `bad certificate`
     from the same api, differing only by that allowlist.
  3. **The identity stops being minted.** The cert only exists because
     `internal/workloadid` registers vmalert as a client workload. Drop that
     row and the mount below becomes an empty directory — at which point vmalert
     presents nothing and delivery fails at the handshake.

Deliberately NOT asserted: that delivery WORKS end to end. That needs a running
stack and is `scripts/deploy-qualify.sh`'s job (and the AlertingHeartbeat /
AlertDeliveryBroken rules'). This file is the static half — it fails in the
cheap lane the moment the wiring drifts.

Run:  python3 -m pytest tests/test_vmalert_delivery_contract.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deployment" / "docker" / "docker-compose.yml"
COMPOSE_TLS = ROOT / "deployment" / "docker" / "compose.tls.yml"
WORKLOADID = ROOT / "src" / "backend" / "internal" / "workloadid" / "workloadid.go"

VMALERT_SPIFFE = "spiffe://netops/ns/default/sa/vmalert"
# vmalert appends /api/v2/alerts to the -notifier.url base itself, so the base
# it is given is the route prefix main.go registers.
RECEIVER_BASE = "/api/internal/vmalert"


def _compose_yaml(text: str) -> dict:
    """Parse a compose file that may carry compose's merge tags (!override,
    !reset) — yaml.safe_load rejects unknown tags. Same loader shape as
    tests/test_compose_agg_overlay.py and tests/test_assurance_contracts.py.
    """

    class _ComposeLoader(yaml.SafeLoader):
        pass

    def _passthrough(loader, node):
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        if isinstance(node, yaml.MappingNode):
            return loader.construct_mapping(node)
        return loader.construct_scalar(node)

    _ComposeLoader.add_constructor("!override", _passthrough)
    _ComposeLoader.add_constructor("!reset", _passthrough)
    return yaml.load(text, Loader=_ComposeLoader)


def _svc(path: Path, name: str) -> dict:
    return (_compose_yaml(path.read_text(encoding="utf-8")) or {})["services"][name]


def _vmalert_command(path: Path) -> list[str]:
    cmd = _svc(path, "vmalert")["command"]
    assert isinstance(cmd, list), f"{path.name}: vmalert command must be a list"
    return [str(c) for c in cmd]


def _notifier_flag(cmd: list[str]) -> str:
    hits = [c for c in cmd if "notifier.url" in c or "notifier.blackhole" in c]
    assert len(hits) == 1, f"expected exactly one notifier flag, got {hits}"
    return hits[0]


# ── 1. The blackhole must not be the default in EITHER file ─────────────────

def test_neither_compose_file_defaults_to_blackhole() -> None:
    for path in (COMPOSE, COMPOSE_TLS):
        flag = _notifier_flag(_vmalert_command(path))
        default = flag.split(":-", 1)[1].rstrip("}") if ":-" in flag else flag
        assert "blackhole" not in default, (
            f"{path.name}: vmalert's notifier DEFAULT is the blackhole again — "
            "rules evaluate and alerts are delivered nowhere. Blackhole is only "
            "ever the explicit opt-out (VMALERT_NOTIFIER_FLAG=-notifier.blackhole)."
        )
        assert RECEIVER_BASE in default, (
            f"{path.name}: notifier default does not point at the api receiver "
            f"({RECEIVER_BASE}); got {default!r}"
        )


def test_blackhole_remains_a_documented_opt_out() -> None:
    """Turning delivery off must stay possible and must stay written down."""
    src = COMPOSE.read_text(encoding="utf-8")
    assert "VMALERT_NOTIFIER_FLAG=-notifier.blackhole" in src, (
        "the explicit opt-out must remain documented in docker-compose.yml — "
        "an operator who cannot turn delivery off cleanly will comment out the "
        "service instead, and lose rule evaluation with it."
    )


def _secrets_of(path: Path, name: str) -> list[str]:
    """The secret NAMES a service mounts (compose accepts short or long form)."""
    out = []
    for item in _svc(path, name).get("secrets") or []:
        out.append(item if isinstance(item, str) else str(item.get("source")))
    return out


def _top_level_secrets(path: Path) -> dict:
    return (_compose_yaml(path.read_text(encoding="utf-8")) or {}).get("secrets") or {}


def test_both_variants_keep_the_shared_secret() -> None:
    """The app-layer credential must survive on BOTH paths.

    mTLS authenticates the connection; the token authenticates the request.
    Dropping the token because 'mTLS already authenticates' collapses two
    independent controls into one.

    Since D-16 (QA 2026-09-03) the token is no longer in the url userinfo — it
    is read from a mounted secret file — so the assertion is that the
    basicAuth pair is present and wired, not that the argv carries the value.
    """
    for path in (COMPOSE, COMPOSE_TLS):
        cmd = _vmalert_command(path)
        user = [c for c in cmd if c.startswith("-notifier.basicAuth.username=")]
        pwf = [c for c in cmd if c.startswith("-notifier.basicAuth.passwordFile=")]
        assert len(user) == 1 and len(pwf) == 1, (
            f"{path.name}: vmalert no longer presents an app-layer credential to the "
            f"receiver (username={user}, passwordFile={pwf}). mTLS alone is ONE control, "
            "and VMALERT_WEBHOOK_TOKEN unset makes the api refuse the route outright."
        )
        target = pwf[0].split("=", 1)[1]
        mounted = {
            (item if isinstance(item, str) else str(item.get("source")))
            for item in (_svc(path, "vmalert").get("secrets") or [])
        }
        assert target == "/run/secrets/vmalert_notifier_password", (
            f"{path.name}: unexpected passwordFile path {target!r}"
        )
        assert "vmalert_notifier_password" in mounted, (
            f"{path.name}: -notifier.basicAuth.passwordFile points at {target}, but the "
            f"vmalert service mounts no such secret (mounts: {sorted(mounted)}) — the file "
            "would not exist and vmalert would present nothing."
        )


# ── D-16: no credential may appear in the container's argv ──────────────────
#
# `docker inspect netops-vmalert-1` reports Config.Cmd verbatim, and reading it
# needs only membership of the `docker` group — not access to .env. Anything
# interpolated into a flag is therefore disclosed. Measured on the live stack
# on 2026-09-03: -datasource.url, -remoteWrite.url and -notifier.url all
# carried inline `user:password@host` credentials.

_CREDENTIAL_VARS = (
    "VMALERT_WEBHOOK_TOKEN",
    "VMAUTH_VMALERT_PASSWORD",
)


def test_no_credential_is_interpolated_into_vmalert_argv() -> None:
    for path in (COMPOSE, COMPOSE_TLS):
        for flag in _vmalert_command(path):
            for var in _CREDENTIAL_VARS:
                assert "${" + var not in flag, (
                    f"{path.name}: {var} is interpolated into vmalert's command line "
                    f"({flag!r}). `docker inspect` discloses it to the whole docker group "
                    "(D-16). Pass it with -*.basicAuth.passwordFile from a compose secret."
                )


def test_no_url_userinfo_in_vmalert_argv() -> None:
    """The shape, not just the variable name: `scheme://user:pw@host` in argv."""
    userinfo = re.compile(r"=\w+://[^/\s]*:[^/\s@]*@")
    for path in (COMPOSE, COMPOSE_TLS):
        for flag in _vmalert_command(path):
            assert not userinfo.search(flag), (
                f"{path.name}: {flag!r} carries URL userinfo. Credentials in argv are "
                "readable with `docker inspect` (D-16)."
            )


def test_every_password_file_is_backed_by_a_declared_secret() -> None:
    """A passwordFile that no secret mounts is a vmalert that starts and then
    presents nothing — delivery fails at the first POST with no obvious cause."""
    for path, extra in ((COMPOSE, None), (COMPOSE_TLS, COMPOSE)):
        cmd = _vmalert_command(path)
        wanted = {c.split("=", 1)[1] for c in cmd if ".basicAuth.passwordFile=" in c}
        assert wanted, f"{path.name}: vmalert declares no passwordFile at all"
        mounted = {
            (item if isinstance(item, str) else str(item.get("source")))
            for item in (_svc(path, "vmalert").get("secrets") or [])
        }
        declared = dict(_top_level_secrets(path))
        if extra is not None:
            declared.update(_top_level_secrets(extra))
        for target in sorted(wanted):
            assert target.startswith("/run/secrets/"), (
                f"{path.name}: {target} is not a compose secret mount point"
            )
            name = target[len("/run/secrets/"):]
            assert name in mounted, (
                f"{path.name}: passwordFile {target} has no matching entry in the "
                f"service's secrets list ({sorted(mounted)})"
            )
            assert name in declared, (
                f"{path.name}: secret {name!r} is mounted but never declared at the "
                f"top level (declared: {sorted(declared)})"
            )
            src = declared[name]
            assert isinstance(src, dict) and src.get("environment"), (
                f"{path.name}: secret {name!r} must be sourced from an environment "
                f"variable so nothing new has to be written to disk at install time; "
                f"got {src!r}"
            )


# ── 2. mTLS wiring on the TLS variant ───────────────────────────────────────

def test_tls_variant_speaks_https_to_the_receiver() -> None:
    flag = _notifier_flag(_vmalert_command(COMPOSE_TLS))
    default = flag.split(":-", 1)[1].rstrip("}")
    assert default.startswith("-notifier.url=https://"), (
        "compose.tls.yml: the api's :8080 is HTTPS with RequireClientCert when "
        f"TLS_CERT_FILE is set — a plaintext POST is refused. Got {default!r}"
    )


def test_tls_variant_presents_a_client_svid() -> None:
    """The three -notifier.tls* flags must be present and must point at the mount."""
    cmd = _vmalert_command(COMPOSE_TLS)
    flags = {
        "-notifier.tlsCAFile": None,
        "-notifier.tlsCertFile": None,
        "-notifier.tlsKeyFile": None,
    }
    for c in cmd:
        for name in flags:
            if c.startswith(name + "="):
                flags[name] = c.split("=", 1)[1]
    missing = sorted(k for k, v in flags.items() if not v)
    assert not missing, (
        f"compose.tls.yml: vmalert presents no client certificate ({missing}). "
        "The api authorizes by SPIFFE URI SAN; with no cert the handshake fails "
        "with 'certificate required' and every alert is dropped at the TLS layer."
    )

    mounts = _svc(COMPOSE_TLS, "vmalert")["volumes"]
    joined = " ".join(str(m) for m in mounts)
    assert "data/tls/services/vmalert" in joined, (
        "compose.tls.yml: vmalert's SVID directory is not mounted, so the "
        f"-notifier.tls*File paths resolve to nothing. Mounts: {mounts}"
    )
    # Every cert/key path the flags name must live under a mounted container dir.
    container_dirs = [str(m).split(":")[1] for m in mounts if str(m).count(":") >= 2]
    for name in ("-notifier.tlsCertFile", "-notifier.tlsKeyFile", "-notifier.tlsCAFile"):
        path = flags[name]
        assert any(path == d or path.startswith(d.rstrip("/") + "/") for d in container_dirs), (
            f"compose.tls.yml: {name}={path} is not covered by any mount "
            f"({container_dirs}) — the file will not exist in the container."
        )


def test_api_allowlists_the_vmalert_principal() -> None:
    """TLS-layer admission. Verified live: without this row a valid, CA-signed
    vmalert SVID is rejected with `bad certificate` while vector-router's is
    accepted by the same listener."""
    uris = str(_svc(COMPOSE_TLS, "api")["environment"]["TLS_CLIENT_ALLOWED_URIS"])
    allowed = [u.strip() for u in uris.split(",") if u.strip()]
    assert VMALERT_SPIFFE in allowed, (
        "compose.tls.yml: the api does not admit "
        f"{VMALERT_SPIFFE} — every delivered alert is refused at the TLS "
        f"handshake on a TLS install. Allowlist is: {allowed}"
    )


# ── 3. The identity must actually be minted ─────────────────────────────────

def test_vmalert_is_a_registered_client_workload() -> None:
    """No registry row, no minted cert, no mount contents, no delivery."""
    src = WORKLOADID.read_text(encoding="utf-8")
    row = re.search(r'\{\s*Service:\s*"vmalert"\s*,([^}]*)\}', src)
    assert row, (
        "internal/workloadid no longer registers a 'vmalert' workload — "
        "data/tls/services/vmalert would stop being minted and rotated, and the "
        "compose.tls.yml mount would silently become an empty directory."
    )
    assert "Client: true" in row.group(1), (
        "the vmalert workload must be a CLIENT identity (it initiates the "
        f"connection to the api). Got: {row.group(1).strip()}"
    )
