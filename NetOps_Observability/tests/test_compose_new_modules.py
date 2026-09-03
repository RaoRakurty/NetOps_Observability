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
ALERTWEBHOOK_PKG = ROOT / "src" / "backend" / "internal" / "alertwebhook"
BGPWATCH_PKG = ROOT / "src" / "backend" / "internal" / "bgpwatch"
BGPDEPTH_PKG = ROOT / "src" / "backend" / "internal" / "bgpdepth"

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
    # vmalert alert delivery: alertwebhook.DefaultCooldown = 30m. The TOKEN is
    # deliberately NOT in this table — it is a secret with no code default (see
    # test_vmalert_webhook_token_is_passed_through_and_fail_closed).
    "VMALERT_WEBHOOK_COOLDOWN": "${VMALERT_WEBHOOK_COOLDOWN:-30m}",
    # Platform self-health alerts → the host-monitoring push topic
    # (alertwebhook hostroute.go). EMPTY is a real setting, not a placeholder:
    # the code then falls back to WATCHDOG_NTFY_TOPIC for the topic and to
    # NTFY_ALERT_SERVER / NTFY_ALERT_TOKEN for the transport.
    "PLATFORM_ALERTS_NTFY_TOPIC": "${PLATFORM_ALERTS_NTFY_TOPIC:-}",
    "PLATFORM_ALERTS_NTFY_SERVER": "${PLATFORM_ALERTS_NTFY_SERVER:-}",
    "PLATFORM_ALERTS_NTFY_TOKEN": "${PLATFORM_ALERTS_NTFY_TOKEN:-}",
    # Alert-noise + rate-limit control (alertwebhook digest.go / pushbudget.go).
    # These DO carry a value, unlike the topic knobs above: they are policy with
    # a code default, not a destination. The defaults must stay byte-identical
    # to the Go constants — see
    # test_platform_alert_noise_defaults_match_the_go_constants.
    "PLATFORM_ALERTS_WARNING_DIGEST_INTERVAL": "${PLATFORM_ALERTS_WARNING_DIGEST_INTERVAL:-30m}",
    "PLATFORM_ALERTS_PUSH_BUDGET": "${PLATFORM_ALERTS_PUSH_BUDGET:-30}",
    "PLATFORM_ALERTS_PUSH_BUDGET_PAGE_RESERVE": "${PLATFORM_ALERTS_PUSH_BUDGET_PAGE_RESERVE:-10}",
    # BGP depth + alerting (internal/bgpdepth, internal/bgpwatch). All three
    # are dormant-by-default flags whose Go default is FALSE. They were absent
    # from compose entirely until 2026-09-03 — only a COMMENT mentioned them —
    # so no .env value could enable any of them and the whole watchlist
    # evaluator was unreachable through the supported install path.
    "FEATURE_BGP_LIVE_FEED": "${FEATURE_BGP_LIVE_FEED:-false}",
    "FEATURE_BGP_ALERTS": "${FEATURE_BGP_ALERTS:-false}",
    "FEATURE_BGP_BOGON_FEED": "${FEATURE_BGP_BOGON_FEED:-false}",
    # bgpdepth.DefaultFeedLookback = 6h — the FIRST poll's window. It is an
    # operator knob rather than a code constant because the upstream archive's
    # publishing lag is a property of the internet on the day, not of our
    # build: when the lag exceeds the window the feed buffers nothing at all,
    # with no error anywhere (measured 3 h 15 m on 2026-09-03).
    "BGP_FEED_LOOKBACK": "${BGP_FEED_LOOKBACK:-6h}",
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


# ── vmalert alert delivery (internal/alertwebhook) ──────────────────────────
#
# vmalert ran with `-notifier.blackhole`: every rule evaluated, nothing ever
# delivered. These guard the DELIVERY plumbing specifically, because it is the
# one class of defect the stack cannot report about itself.

ALERTWEBHOOK_PKG = ROOT / "src" / "backend" / "internal" / "alertwebhook"


def test_vmalert_webhook_token_is_passed_through_and_fail_closed():
    """The shared secret must reach the api, and its compose default must be
    EMPTY — empty is the fail-closed state (the api refuses to register the
    receiver rather than serving an unauthenticated alert fan-out). It is
    kept out of API_ENV_DEFAULTS because it has no code default to match:
    install.py mints it and update.sh backfills it."""
    env = service_env("api")
    assert env["VMALERT_WEBHOOK_TOKEN"] == "${VMALERT_WEBHOOK_TOKEN:-}", (
        "VMALERT_WEBHOOK_TOKEN must be a defaulted pass-through on the api; "
        f"got {env.get('VMALERT_WEBHOOK_TOKEN')!r}")


def test_vmalert_cooldown_default_matches_the_package_constant():
    """Read alertwebhook.DefaultCooldown out of the package so a change on
    either side fails here instead of drifting."""
    src = (ALERTWEBHOOK_PKG / "alertwebhook.go").read_text()
    m = re.search(r"DefaultCooldown\s*=\s*(\d+)\s*\*\s*time\.Minute", src)
    assert m, "could not find alertwebhook.DefaultCooldown"
    assert service_env("api")["VMALERT_WEBHOOK_COOLDOWN"] == \
        "${VMALERT_WEBHOOK_COOLDOWN:-%sm}" % m.group(1)


def test_vmalert_notifier_default_is_delivery_not_blackhole():
    """The default must POST to the api's receiver. `-notifier.blackhole` stays
    supported as an EXPLICIT opt-out via VMALERT_NOTIFIER_FLAG, but it must
    never be what an operator gets by doing nothing."""
    cmd = compose()["services"]["vmalert"]["command"]
    flags = [c for c in cmd if "VMALERT_NOTIFIER_FLAG" in str(c)]
    assert len(flags) == 1, f"expected exactly one notifier slot, got {flags}"
    flag = str(flags[0])
    assert ":--notifier.blackhole}" not in flag, (
        "the vmalert notifier default is blackhole again — rules evaluate and "
        "nothing is ever delivered to a human, which is the defect this "
        "plumbing exists to close.")
    # vmalert appends /api/v2/alerts itself: -notifier.url is a BASE url.
    # Since D-16 (2026-09-03) the shared secret is NOT in the url — it is read
    # from a mounted compose secret, because argv is disclosed by
    # `docker inspect` to anyone in the docker group.
    assert "-notifier.url=http://api:8080/api/internal/vmalert}" in flag, (
        f"unexpected notifier default {flag!r}")
    assert "${VMALERT_WEBHOOK_TOKEN}" not in flag, (
        "the shared secret is interpolated into vmalert's argv again (D-16) — "
        "pass it with -notifier.basicAuth.passwordFile from the compose secret.")
    assert "-notifier.basicAuth.passwordFile=/run/secrets/vmalert_notifier_password" in cmd, (
        "the notifier presents no app-layer credential at all — the api's "
        "receiver would answer 401 for every alert.")


def test_tls_variant_restates_the_notifier_flag():
    """compose.tls.yml REPLACES vmalert's whole command list, so a base-file
    flag that is not restated there is silently gone on a TLS install.

    NOT a verbatim comparison. The two variants intentionally differ in ONE
    way: the base file posts over http, and the TLS variant must use https
    because the api's :8080 is HTTPS with RequireClientCert once TLS_CERT_FILE
    is set (a plaintext POST is refused at the handshake — verified live
    2026-09-02). What must hold on BOTH is the invariant this test exists for:
    the flag is present, its default is not the blackhole, and it points at the
    receiver. The mTLS specifics are pinned in
    tests/test_vmalert_delivery_contract.py.
    """
    tls_src = (ROOT / "deployment" / "docker" / "compose.tls.yml").read_text()
    base = compose()["services"]["vmalert"]["command"]
    base_notifier = [str(c) for c in base if "VMALERT_NOTIFIER_FLAG" in str(c)][0]
    # compose.tls.yml carries compose's own `!override` tag, which yaml.safe_load
    # cannot construct — match as TEXT rather than parsing the document.
    tls_notifier = [
        ln.strip() for ln in tls_src.splitlines() if "VMALERT_NOTIFIER_FLAG" in ln
    ]
    assert tls_notifier, (
        "the TLS variant does not restate the notifier flag at all — a TLS "
        "install would fall back to the image default and deliver nothing.")
    flag = tls_notifier[0]
    assert "blackhole" not in flag.split(":-", 1)[-1], (
        "the TLS variant defaults to the blackhole — alerts evaluated, "
        "delivered nowhere, on the very install the customer runs.")
    # Same receiver path on both variants; only the scheme may differ. The
    # shared secret is deliberately NOT in either url since D-16 — it rides
    # -notifier.basicAuth.passwordFile, asserted just below.
    assert "/api/internal/vmalert" in flag, f"TLS notifier flag lost the receiver path: {flag}"
    assert "/api/internal/vmalert" in base_notifier, "base notifier flag lost the receiver path"
    for src, label in ((tls_src, "compose.tls.yml"), (COMPOSE.read_text(), "docker-compose.yml")):
        assert "-notifier.basicAuth.passwordFile=/run/secrets/vmalert_notifier_password" in src, (
            f"{label}: the notifier presents no app-layer credential — mTLS alone is "
            "one control, and the api refuses an unauthenticated POST.")
        assert "${VMALERT_WEBHOOK_TOKEN}@" not in src, (
            f"{label}: the shared secret is back in a url userinfo (D-16) — "
            "`docker inspect` discloses it to the whole docker group.")
    assert "https://" in flag, (
        "compose.tls.yml must post over https — the api requires a client cert "
        f"on that listener. Got: {flag}")


def test_webhook_route_is_registered_and_jwt_exempt():
    """The three halves that must move together: the receiver package exists,
    main.go registers the subtree with the literal the route-isolation ledger
    greps for, and withAuth has the matching JWT escape."""
    assert (ALERTWEBHOOK_PKG / "alertwebhook.go").is_file()
    main_go = (ROOT / "src" / "backend" / "main.go").read_text()
    assert 'mux.HandleFunc("/api/internal/vmalert/"' in main_go, (
        "the webhook subtree is not registered in main.go — vmalert would POST "
        "into a 404 and alerts would go nowhere again.")
    auth_go = (ROOT / "src" / "backend" / "auth.go").read_text()
    assert 'strings.HasPrefix(r.URL.Path, "/api/internal/vmalert/")' in auth_go, (
        "withAuth has no escape for the webhook subtree — vmalert holds no JWT, "
        "so every alert POST would be rejected before reaching the handler.")


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
                 "FEATURE_PROTOCOL_DIAG_COLLECT", "FEATURE_BGP_LIVE_FEED",
                 "FEATURE_BGP_ALERTS", "FEATURE_BGP_BOGON_FEED"):
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
                "CORR_SYSLOG_TOPIC", "CORR_FIDELITY_WEIGHTING",
                "VMALERT_WEBHOOK_TOKEN", "VMALERT_WEBHOOK_COOLDOWN",
                "PLATFORM_ALERTS_NTFY_TOPIC", "PLATFORM_ALERTS_NTFY_SERVER",
                "PLATFORM_ALERTS_NTFY_TOKEN",
                "PLATFORM_ALERTS_WARNING_DIGEST_INTERVAL",
                "PLATFORM_ALERTS_PUSH_BUDGET",
                "PLATFORM_ALERTS_PUSH_BUDGET_PAGE_RESERVE", "FEATURE_BGP_LIVE_FEED",
                "FEATURE_BGP_ALERTS", "FEATURE_BGP_BOGON_FEED", "BGP_FEED_LOOKBACK"):
        assert f'"{key}":' in src, (
            f"{key} is missing from update.sh's EXPECTED list — an upgraded "
            f"install would never learn the knob exists.")
    # The secret is the one key that must NOT be reconciled to the compose
    # default: compose defaults it to EMPTY (fail-closed), and materializing an
    # empty value would leave an upgraded install delivering nothing forever.
    # update.sh mints a URL-safe token instead (it rides URL userinfo).
    assert '"VMALERT_WEBHOOK_TOKEN":         "__URLSAFE__",' in src, (
        "VMALERT_WEBHOOK_TOKEN must be reconciled as a GENERATED url-safe "
        "secret, not as the empty compose default — empty means the api never "
        "registers the receiver and the upgrade silently keeps delivering "
        "nothing.")
    assert "urlsafe_alphabet" in src and '"-_"' in src, (
        "the __URLSAFE__ generator is gone; a token containing @ # % would "
        "break the notifier URL's userinfo and every alert POST with it.")
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


def test_alert_webhook_env_contract_is_fully_plumbed_to_the_api():
    """Every `Env… = "…"` constant internal/alertwebhook declares must be
    passed through on the api.

    The package owns TWO routes: the vmalert receiver itself and the
    host-monitoring push route platform self-health alerts go out on. Both are
    env-wired, and an unplumbed variable there is invisible — the stack keeps
    running and simply never tells anyone it is broken, which is the exact
    defect the module exists to end.
    """
    consts = _go_env_consts(ALERTWEBHOOK_PKG)
    assert consts, "internal/alertwebhook declares no Env* constant"
    env = service_env("api")
    missing = sorted(v for v in consts.values() if v not in env)
    assert not missing, (
        f"internal/alertwebhook reads {missing} but docker-compose.yml never "
        f"passes them to the api — the route cannot be configured through the "
        f"supported install path.")
    # The host route's topic defaults to the watchdog's own topic IN CODE, so
    # compose must not invent a different default for either key.
    for var in ("PLATFORM_ALERTS_NTFY_TOPIC", "WATCHDOG_NTFY_TOPIC"):
        assert str(env[var]) == "${%s:-}" % var, (
            f"{var}: compose must pass the value through empty-by-default; the "
            f"topic fallback chain lives in the code, not in the YAML.")


def test_platform_alert_noise_defaults_match_the_go_constants():
    """The digest window and the push budget are POLICY with a code default, so
    compose and the Go package must agree to the byte.

    They exist because ntfy.sh answered 429 to this route on 2026-09-03 while
    chronic warnings each spent a push. A compose default that drifts from the
    code default would mean the stack behaves one way on a fresh install and
    another way in the tests that prove the behaviour."""
    src = "\n".join((ALERTWEBHOOK_PKG / f).read_text()
                     for f in ("hostroute.go", "pushbudget.go"))
    consts = {
        "PLATFORM_ALERTS_WARNING_DIGEST_INTERVAL":
            (r"DefaultWarningDigestInterval\s*=\s*(\d+)\s*\*\s*time\.Minute", "30m", "30"),
        "PLATFORM_ALERTS_PUSH_BUDGET":
            (r"DefaultPushBudget\s*=\s*(\d+)", "30", "30"),
        "PLATFORM_ALERTS_PUSH_BUDGET_PAGE_RESERVE":
            (r"DefaultPageReserve\s*=\s*(\d+)", "10", "10"),
    }
    env = service_env("api")
    for var, (pattern, compose_default, go_value) in consts.items():
        m = re.search(pattern, src)
        assert m, f"the Go default behind {var} is gone from hostroute.go"
        assert m.group(1) == go_value, (
            f"{var}: the Go default moved to {m.group(1)} — update "
            f"docker-compose.yml, scripts/install.py and scripts/update.sh with it.")
        assert str(env[var]) == "${%s:-%s}" % (var, compose_default), (
            f"{var}: compose default must be {compose_default}, the code's own.")


def test_env_template_ships_the_alert_noise_knobs_commented_with_the_code_default():
    """Discoverable but inert: an operator must be able to FIND the digest
    window and the page reserve in .env, and a shipped uncommented value would
    silently freeze them at install time instead of following the code."""
    src = INSTALL_PY.read_text()
    for var, default in (("PLATFORM_ALERTS_WARNING_DIGEST_INTERVAL", "30m"),
                         ("PLATFORM_ALERTS_PUSH_BUDGET", "30"),
                         ("PLATFORM_ALERTS_PUSH_BUDGET_PAGE_RESERVE", "10")):
        assert f"#{var}={default}" in src, (
            f"{var} must ship commented, with the code default, in the .env template")
        assert f"\n{var}=" not in src, f"{var} must not ship with an active value"


def test_env_template_ships_the_platform_alert_topic_commented_out():
    """Empty/absent = 'use the watchdog topic'. Shipping it SET would silently
    split platform alerts onto a topic nobody is subscribed to."""
    src = INSTALL_PY.read_text()
    for var in ("PLATFORM_ALERTS_NTFY_TOPIC", "PLATFORM_ALERTS_NTFY_SERVER",
                "PLATFORM_ALERTS_NTFY_TOKEN"):
        assert f"#{var}=" in src, f"{var} must be discoverable (commented) in the .env template"
        assert f"\n{var}=" not in src, f"{var} must not ship with a value"


def test_bgp_feature_flags_are_fully_plumbed_to_the_api():
    """Every FEATURE_* flag internal/bgpwatch and internal/bgpdepth declare as
    their own `Env… = "…"` constant must be passed through on the api.

    This is the guard for the defect found live on 2026-09-03: docker-compose.yml
    carried a COMMENT naming FEATURE_BGP_LIVE_FEED / FEATURE_BGP_ALERTS /
    FEATURE_BGP_BOGON_FEED and no passthrough for any of them, so the operator
    could set them in .env, `docker compose up` would report success, and the
    live feed, the watchlist evaluator and the bogon overlay would all stay
    dormant with nothing anywhere saying why.

    Scope is deliberately the FEATURE_* flags: the tuning knobs these packages
    also declare (BGP_ALERT_INTERVAL, BGP_ALERT_COOLDOWN, BGP_BOGON_FEED_URL,
    BGP_ASPA_PROVIDER_URL, BGP_EVIDENCE_TOPIC) and their store paths
    (BGP_ALERT_CONFIG_FILE, BGP_WATCHLIST_FILE, whose code defaults live under
    the api's /data volume) have working code defaults, so an unplumbed one
    degrades to the documented default rather than to a feature that lies about
    being on. A FLAG cannot degrade — unplumbed, it can only ever be off.
    """
    consts: dict[str, str] = {}
    for pkg in (BGPWATCH_PKG, BGPDEPTH_PKG):
        assert pkg.is_dir(), f"{pkg} is missing"
        found = _go_env_consts(pkg)
        assert found, (
            f"{pkg.name} declares no Env* constant: put the env contract in the "
            f"package (the pcap/alertwebhook precedent) so there is exactly one "
            f"spelling of each name.")
        for name, var in found.items():
            consts[f"{pkg.name}.{name}"] = var
    flags = sorted({v for v in consts.values() if v.startswith("FEATURE_")})
    assert flags, "neither BGP package declares a FEATURE_* flag any more"
    env = service_env("api")
    missing = [v for v in flags if v not in env]
    assert not missing, (
        f"internal/bgpwatch + internal/bgpdepth gate themselves on {missing} but "
        f"docker-compose.yml never passes them to the api — the feature cannot "
        f"be enabled through the supported install path, and the stack reports "
        f"success while doing nothing.")
    for var in flags:
        assert str(env[var]) == "${%s:-false}" % var, (
            f"{var}: compose default {env[var]!r} must be "
            f"${{{var}:-false}} — these flags are dormant-by-default in code, "
            f"and a compose default that turns one on (or spells the fallback "
            f"differently) is a config lie.")
