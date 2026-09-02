"""Deployment plumbing for the flag-gated api/correlation modules.

A module can be perfectly implemented and still be UNDEPLOYABLE: the flag the
code reads is not passed through compose, the sealed-blob directory is not a
mount (so Docker auto-creates the bind source as ROOT and the api — user-mapped,
cap_drop:ALL — can never write into it), or the installer never creates it with
the right owner. Every one of those failures is silent at `docker compose up`
and only shows up as a crash-loop, an EACCES, or a feature that says it is on
and produces nothing.

These are STATIC contract guards over the committed files (no docker, no
running stack), in the spirit of tests/test_security_lane.py:

  * every env var the Go/Python code READS is passed through on the service
    that reads it, with a compose default that MATCHES the code default —
    a compose default that drifts from the code default is a config lie;
  * `CORR_EVIDENCE_TOPICS` stays a BARE pass-through: for that one variable
    unset ("every registered evidence class") and empty ("subscribe to none")
    are different contracts, so `${VAR:-}` would silently unsubscribe every
    evidence class;
  * the sealed config-blob directory is a real bind mount whose container path
    is exactly what `CONFIG_BACKUP_DIR` names;
  * the installer and fix-permissions.sh both own that directory (api uid,
    mode 0700);
  * the `.env` template and update.sh's reconciliation list agree with the
    compose defaults, so a fresh install and an upgraded install behave
    identically.

The last test is the CLASS guard for the packet-capture module (internal/pcap
landed while this plumbing was being written and is not yet wired into
main.go): it reads the package's OWN `Env… = "…"` constants and fails if any of
them is not passed through on the api — so the module cannot arrive half-
deployed, and a renamed constant is caught rather than silently unplumbed.

Run:  python3 -m pytest tests/test_compose_new_modules.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deployment" / "docker" / "docker-compose.yml"
INSTALL_PY = ROOT / "scripts" / "install.py"
FIX_PERMS = ROOT / "scripts" / "fix-permissions.sh"
UPDATE_SH = ROOT / "scripts" / "update.sh"
PCAP_PKG = ROOT / "src" / "backend" / "internal" / "pcap"

# The sealed device-configuration blob store: container path (configstore
# DefaultDir) → the bind-mount source under data/ that must back it.
CONFIG_BLOB_CONTAINER_DIR = "/data/config-backups"
CONFIG_BLOB_HOST_DIR = "../../data/config-backups"


def compose() -> dict:
    with COMPOSE.open() as fh:
        return yaml.safe_load(fh)


def service_env(name: str) -> dict:
    env = compose()["services"][name]["environment"]
    assert isinstance(env, dict), f"{name}: expected mapping-form environment"
    return env


# ── api: env passthrough, defaults pinned to the CODE defaults ───────────────
#
# Each expected value is `${VAR:-<default>}` where <default> is the constant the
# Go code falls back to when the variable is unset:
#   seclane.DefaultScanInterval = 15m   DefaultMaxFindings   = 5000
#   configstore.DefaultInterval = 24h   DefaultKeepVersions  = 30  SSH port 22
#   parsercov.DefaultMaxLines   = 200000
API_ENV_DEFAULTS = {
    "FEATURE_SECURITY_LANE": "${FEATURE_SECURITY_LANE:-false}",
    "SECURITY_SCAN_INTERVAL": "${SECURITY_SCAN_INTERVAL:-15m}",
    "SECURITY_MAX_FINDINGS_PER_TENANT": "${SECURITY_MAX_FINDINGS_PER_TENANT:-5000}",
    "FEATURE_CONFIG_BACKUP": "${FEATURE_CONFIG_BACKUP:-false}",
    "CONFIG_BACKUP_INTERVAL": "${CONFIG_BACKUP_INTERVAL:-24h}",
    "CONFIG_BACKUP_KEEP_VERSIONS": "${CONFIG_BACKUP_KEEP_VERSIONS:-30}",
    "CONFIG_BACKUP_SSH_USER": "${CONFIG_BACKUP_SSH_USER:-}",
    "CONFIG_BACKUP_SSH_PASSWORD": "${CONFIG_BACKUP_SSH_PASSWORD:-}",
    "CONFIG_BACKUP_SSH_KEY": "${CONFIG_BACKUP_SSH_KEY:-}",
    "CONFIG_BACKUP_SSH_PORT": "${CONFIG_BACKUP_SSH_PORT:-22}",
    "PARSERCOV_MAX_LINES": "${PARSERCOV_MAX_LINES:-200000}",
    "CORRELATION_REPLICA_URLS": "${CORRELATION_REPLICA_URLS:-}",
    # pcap.DefaultKeep = 20; the duration/size ceilings are HARD CAPS in code
    # and deliberately have no env knob at all.
    "FEATURE_PACKET_CAPTURE": "${FEATURE_PACKET_CAPTURE:-false}",
    "PCAP_KEEP": "${PCAP_KEEP:-20}",
    "PCAP_SSH_USER": "${PCAP_SSH_USER:-}",
    "PCAP_SSH_PASSWORD": "${PCAP_SSH_PASSWORD:-}",
    "PCAP_SSH_KEY": "${PCAP_SSH_KEY:-}",
    "PCAP_SSH_PORT": "${PCAP_SSH_PORT:-22}",
    # protocoldiag: the LIVE collect transport is dormant by default (the
    # collect endpoint 503s); the credential falls back to the config-backup
    # read-only account when PROTOCOL_DIAG_SSH_* is entirely unset.
    "FEATURE_PROTOCOL_DIAG_COLLECT": "${FEATURE_PROTOCOL_DIAG_COLLECT:-false}",
    "PROTOCOL_DIAG_SSH_USER": "${PROTOCOL_DIAG_SSH_USER:-}",
    "PROTOCOL_DIAG_SSH_PASSWORD": "${PROTOCOL_DIAG_SSH_PASSWORD:-}",
    "PROTOCOL_DIAG_SSH_KEY": "${PROTOCOL_DIAG_SSH_KEY:-}",
    "PROTOCOL_DIAG_SSH_PORT": "${PROTOCOL_DIAG_SSH_PORT:-22}",
}


@pytest.mark.parametrize("var,expected", sorted(API_ENV_DEFAULTS.items()))
def test_api_passes_module_env_with_code_matching_default(var: str, expected: str):
    env = service_env("api")
    assert var in env, (
        f"{var} is read by the api but never passed through docker-compose.yml — "
        f"the module is undeployable through the supported install path.")
    assert str(env[var]) == expected, (
        f"{var}: compose default {env[var]!r} does not match the code default "
        f"({expected!r}). A compose default that drifts from the code default "
        f"is a lie told to whoever reads either one.")


def test_config_backup_dir_is_pinned_to_the_mounted_path():
    """CONFIG_BACKUP_DIR is deliberately NOT operator-overridable: it must name
    the container path of the bind mount, or the sealed blobs land on the
    container filesystem and die with it."""
    env = service_env("api")
    assert env["CONFIG_BACKUP_DIR"] == CONFIG_BLOB_CONTAINER_DIR
    assert "$" not in str(env["CONFIG_BACKUP_DIR"]), (
        "CONFIG_BACKUP_DIR must not be interpolated — an override would point "
        "the sealed store at an unmounted path inside the container.")


def test_sealed_blob_dir_is_a_bind_mount_on_the_api():
    vols = compose()["services"]["api"]["volumes"]
    assert f"{CONFIG_BLOB_HOST_DIR}:{CONFIG_BLOB_CONTAINER_DIR}" in vols, (
        "the sealed config-blob dir must be a bind mount; without it Docker "
        "creates nothing (or auto-creates a ROOT-owned source) and the "
        "unprivileged api cannot persist a captured configuration.")


def test_pcap_keep_default_matches_the_package_constant():
    """Read pcap.DefaultKeep out of the package so a change on either side
    fails here instead of drifting."""
    doc = (PCAP_PKG / "doc.go").read_text()
    m = re.search(r"DefaultKeep\s*=\s*(\d+)", doc)
    assert m, "could not find pcap.DefaultKeep"
    assert service_env("api")["PCAP_KEEP"] == "${PCAP_KEEP:-%s}" % m.group(1)


def test_pcap_blob_dir_is_pinned_and_mounted():
    env = service_env("api")
    assert env["PCAP_DIR"] == "/data/pcap"
    assert "$" not in str(env["PCAP_DIR"])
    # The metadata register lives in the api's own /data bind (alongside
    # ssh_known_hosts.json), not in the blob dir the retention sweep walks.
    assert str(env["PCAP_METADATA_FILE"]).startswith("/data/")
    assert "../../data/pcap:/data/pcap" in compose()["services"]["api"]["volumes"]


def test_installer_owns_the_pcap_blob_dir_0700():
    src = INSTALL_PY.read_text()
    assert '"pcap": (api_uid, api_gid),' in src
    assert '"pcap": 0o700' in src
    assert "[pcap]=\"0700\"" in FIX_PERMS.read_text()


def test_security_deadletter_spool_stays_inside_the_api_data_mount():
    """The dead-letter spool is the last stop before evidence is LOST, so its
    path must be under a mounted, writable tree — /data is the api's bind."""
    env = service_env("api")
    assert str(env["SECURITY_DEADLETTER_FILE"]).startswith("/data/")


# ── correlation: the three lane switches ────────────────────────────────────

def test_correlation_lane_switches_default_to_current_behaviour():
    env = service_env("correlation")
    # main.py: os.environ.get("CORR_SYSLOG_TOPIC", "netops.syslog")
    assert env["CORR_SYSLOG_TOPIC"] == "${CORR_SYSLOG_TOPIC:-netops.syslog}"
    # signals.py: os.environ.get("CORR_FIDELITY_WEIGHTING", "0")
    assert env["CORR_FIDELITY_WEIGHTING"] == "${CORR_FIDELITY_WEIGHTING:-0}"


def test_evidence_topics_is_a_bare_passthrough_not_an_empty_default():
    """`unset` and `""` are DIFFERENT contracts for CORR_EVIDENCE_TOPICS
    (evidence_topics_from_env: None → every registered class, "" → none).
    A `${CORR_EVIDENCE_TOPICS:-}` default would turn "operator said nothing"
    into "subscribe to no evidence class" — the whole T2b lane silently gone
    with every healthcheck still green."""
    env = service_env("correlation")
    assert "CORR_EVIDENCE_TOPICS" in env
    assert env["CORR_EVIDENCE_TOPICS"] is None, (
        "CORR_EVIDENCE_TOPICS must stay a bare pass-through (`KEY:` with no "
        f"value), got {env['CORR_EVIDENCE_TOPICS']!r}. Compose resolves it from "
        ".env/the environment and OMITS it entirely when unset, which is the "
        "only way to preserve unset != empty.")


def test_correlation_defaults_match_the_python_source():
    """Read the defaults out of the service's own source so this test fails if
    either side moves."""
    main_py = (ROOT / "src" / "correlation" / "main.py").read_text()
    m = re.search(r'CORR_SYSLOG_TOPIC\s*=\s*os\.environ\.get\(\s*"CORR_SYSLOG_TOPIC"\s*,\s*"([^"]+)"',
                  main_py)
    assert m, "could not find the CORR_SYSLOG_TOPIC default in correlation/main.py"
    assert service_env("correlation")["CORR_SYSLOG_TOPIC"] == \
        "${CORR_SYSLOG_TOPIC:-%s}" % m.group(1)

    signals_py = (ROOT / "src" / "correlation" / "signals.py").read_text()
    m2 = re.search(r'"CORR_FIDELITY_WEIGHTING"\s*,\s*"([^"]+)"', signals_py)
    assert m2, "could not find the CORR_FIDELITY_WEIGHTING default in signals.py"
    assert service_env("correlation")["CORR_FIDELITY_WEIGHTING"] == \
        "${CORR_FIDELITY_WEIGHTING:-%s}" % m2.group(1)


# ── installer / fix-permissions / .env template ─────────────────────────────

def test_installer_owns_the_sealed_blob_dir_with_a_private_mode():
    src = INSTALL_PY.read_text()
    assert '"config-backups": (api_uid, api_gid),' in src, (
        "ensure_data_dirs must create data/config-backups owned by the api's "
        "RUNTIME uid — Docker would otherwise auto-create the bind source as "
        "root and every capture would fail with EACCES.")
    assert '"config-backups": 0o700' in src, (
        "the sealed-blob directory listing (device ids, capture times) is not "
        "for every local user to read — it must be created 0700.")


def test_fix_permissions_mirrors_the_api_owned_dirs():
    src = FIX_PERMS.read_text()
    assert "config-backups" in src and "0700" in src, (
        "fix-permissions.sh is the repair path for ownership drift; a dir the "
        "installer creates but it cannot repair is a one-way door.")
    assert "CORRELIX_UID" in src, (
        "the api runs user-mapped as CORRELIX_UID — a hardcoded uid here "
        "re-creates the sudo-install breakage chown_tree exists to prevent.")


def test_env_template_ships_the_flags_commented_out():
    """Default OFF means ABSENT-or-commented, never `=true`."""
    src = INSTALL_PY.read_text()
    for flag in ("FEATURE_SECURITY_LANE", "FEATURE_CONFIG_BACKUP",
                 "FEATURE_PROTOCOL_DIAG_COLLECT"):
        assert f"#{flag}=true" in src, f"{flag} must ship commented out in .env"
        assert f"\n{flag}=true" not in src, f"{flag} must not ship enabled"
    # The one variable whose EMPTY value is a real (and different) setting must
    # not be written as a bare key in the template.
    assert "\nCORR_EVIDENCE_TOPICS=" not in src


def test_update_reconciliation_enumerates_the_new_keys():
    src = UPDATE_SH.read_text()
    for key in ("FEATURE_SECURITY_LANE", "SECURITY_SCAN_INTERVAL",
                "SECURITY_MAX_FINDINGS_PER_TENANT", "FEATURE_CONFIG_BACKUP",
                "CONFIG_BACKUP_INTERVAL", "CONFIG_BACKUP_KEEP_VERSIONS",
                "CONFIG_BACKUP_SSH_USER", "CONFIG_BACKUP_SSH_PORT",
                "PARSERCOV_MAX_LINES", "CORRELATION_REPLICA_URLS",
                "CORR_SYSLOG_TOPIC", "CORR_FIDELITY_WEIGHTING"):
        assert f'"{key}":' in src, (
            f"{key} is missing from update.sh's EXPECTED list — an upgraded "
            f"install would never learn the knob exists.")
    assert '"CORR_EVIDENCE_TOPICS":' not in src, (
        "CORR_EVIDENCE_TOPICS must NOT be reconciled: appending it with an "
        "empty default would unsubscribe every evidence class on the next "
        "restart (unset != empty).")


def test_update_reconciliation_defaults_match_compose():
    """A reconciled key must materialize the SAME value compose already
    defaults to, or a fresh install and an upgraded install diverge."""
    src = UPDATE_SH.read_text()
    env = service_env("api")
    for var, expected in API_ENV_DEFAULTS.items():
        default = expected.split(":-", 1)[1].rstrip("}")
        m = re.search(rf'"{var}":\s*"([^"]*)"', src)
        if m is None:
            continue                      # covered by the enumeration test
        assert m.group(1) == default, (
            f"{var}: update.sh would append {m.group(1)!r} but compose defaults "
            f"to {default!r} — an upgrade would change behaviour silently.")
        assert str(env[var]) == expected


# ── TODO guard: packet capture (module not in the tree yet) ─────────────────

def _go_env_consts(pkg: Path) -> dict[str, str]:
    """Every `EnvX = "SOME_VAR"` const in a package's non-test sources."""
    out: dict[str, str] = {}
    pat = re.compile(r'\b(Env[A-Za-z0-9]*)\s*=\s*"([A-Z][A-Z0-9_]+)"')
    for go in sorted(pkg.glob("*.go")):
        if go.name.endswith("_test.go"):
            continue
        for name, val in pat.findall(go.read_text()):
            out[name] = val
    return out


def test_packet_capture_module_lands_with_its_compose_plumbing():
    """Every `Env… = "…"` constant internal/pcap declares must be passed through
    on the api, and any directory-shaped one must be backed by a bind mount
    (mirror CONFIG_BACKUP_DIR / data/config-backups above).

    The package is not yet wired into main.go, so this guard — not a reading of
    the integrator — is what keeps the deployment surface honest as the wiring
    lands. It skips only if the package is removed again."""
    if not PCAP_PKG.is_dir():
        pytest.skip("src/backend/internal/pcap not present yet — TODO guard armed")
    consts = _go_env_consts(PCAP_PKG)
    assert consts, (
        "internal/pcap exists but declares no Env* constant: put the env "
        "contract in the package (the seclane/configstore precedent) so there "
        "is exactly one spelling of each name.")
    env = service_env("api")
    missing = sorted(v for v in consts.values() if v not in env)
    assert not missing, (
        f"internal/pcap reads {missing} but docker-compose.yml never passes "
        f"them to the api — the module cannot be enabled through the supported "
        f"install path. Add the passthrough with the package's own default, "
        f"and for any blob/spool directory add the bind mount plus the "
        f"install.py/fix-permissions.sh owner entry.")
    for name, var in consts.items():
        if "DIR" not in var:
            continue
        path = str(env[var])
        vols = " ".join(compose()["services"]["api"]["volumes"])
        assert path.lstrip("$").strip("{}") and path in vols, (
            f"{var} ({name}) names a directory that is not a bind mount — "
            f"captures would be written to the container filesystem and lost "
            f"on the next recreate.")
