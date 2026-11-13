#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

#
# update.sh — safe in-place upgrade for an existing NetOps Observability
# deployment.
#
# Run AFTER you've pulled / scp'd the new source code into the project
# directory. Preserves your data/ directory and your .env secrets;
# rebuilds container images for the services whose source code changed
# (api, frontend, correlation); applies any new one-time bootstraps.
#
# Usage:
#   cd /opt/netops/NetOps_Observability
#   git pull                                # or rsync the new tree in
#   sudo systemctl stop netops 2>/dev/null  # if you installed the unit
#   bash scripts/update.sh
#   sudo systemctl start netops 2>/dev/null # if you stopped it above
#
# Flags:
#   --no-backup       skip the pre-upgrade tarball (faster, riskier)
#   --no-build        skip docker compose build (use existing images)
#   --yes             skip the confirmation prompt
#
# Mounted config (2026-11-10): `docker compose up -d` recreates a container only
# when its image or compose definition changed, so a service whose only change is
# a bind-mounted config file (vector VRL, syslog-ng conf, vmalert alert rules)
# would keep running the OLD config after an upgrade — silently. After the
# recreate step this script therefore recreates EVERY running service whose
# mounted config changed and that compose left running, waits until each is
# running/healthy, and fails loud if one does not come up. There is no opt-out
# and no scoping on this customer path: an upgrade must leave nothing on old
# config. The fingerprints of the last successful upgrade/deploy live in
# data/.deploy/config-fingerprints.json; the first run without that record
# recreates nothing extra and records a baseline (scripts/mounted_config.py
# holds the rule for which mounts count).

set -euo pipefail

NO_BACKUP=0
NO_BUILD=0
YES=0
for arg in "$@"; do
    case "$arg" in
        --no-backup) NO_BACKUP=1 ;;
        --no-build)  NO_BUILD=1 ;;
        --yes|-y)    YES=1 ;;
        --help|-h)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_DIR="$ROOT/deployment/docker"
ENV_FILE="$COMPOSE_DIR/.env"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/netops}"

cd "$ROOT"

# ---- preflight --------------------------------------------------------------

step() { echo; echo "=== $* ==="; }
info() { echo "[info ] $*"; }
ok()   { echo "[ ok  ] $*"; }
warn() { echo "[warn ] $*" >&2; }
fail() { echo "[fail ] $*" >&2; exit 1; }

[[ -f "$COMPOSE_DIR/docker-compose.yml" ]] || fail "docker-compose.yml not found at $COMPOSE_DIR. Are you in the right directory?"
[[ -f "$ENV_FILE" ]] || fail ".env not found at $ENV_FILE. This script is for UPGRADES; for a first-time install run scripts/install.py."

# SC1091: a plain `shellcheck update.sh` (no -x) cannot follow the helper; it is
# checked on its own, and `shellcheck -x` follows it through source-path.
# shellcheck source-path=SCRIPTDIR source=lib/mounted-config.sh disable=SC1091
. "$ROOT/scripts/lib/mounted-config.sh" || fail "cannot load $ROOT/scripts/lib/mounted-config.sh — the new tree is incomplete"
mc_init "$ROOT" "$COMPOSE_DIR"
trap mc_cleanup EXIT

command -v docker >/dev/null || fail "docker missing — install with scripts/bootstrap-ubuntu.sh"
docker compose version >/dev/null 2>&1 || fail "docker compose v2 plugin missing"
command -v python3 >/dev/null || fail "python3 missing"

cat <<EOF

NetOps Observability — in-place upgrade
=======================================
This script will:
EOF
[[ $NO_BACKUP -eq 0 ]] && echo "  1) Snapshot data/ + .env  →  $BACKUP_DIR/"
echo "  2) Validate the new scaffold (scripts/install.py validator)"
echo "  3) Add the variables this release introduced to $ENV_FILE"
echo "     (install.py --migrate-env: backs it up first, never changes a set value)"
echo "     then render the service credential files under data/secrets from it"
[[ $NO_BUILD -eq 0 ]]  && echo "  4) docker compose pull   (refresh pinned images)"
[[ $NO_BUILD -eq 0 ]]  && echo "  5) docker compose build  (rebuild api / frontend / correlation)"
echo "  6) docker compose up -d --remove-orphans   (recreate containers)"
echo "     then recreate any running service whose mounted config changed"
echo "  7) Run bootstrap-opensearch.sh   (apply new index templates if any)"
echo

if [[ $YES -ne 1 ]]; then
    read -r -p "Proceed? [y/N] " ans
    case "${ans:-}" in
        y|Y|yes|YES) ;;
        *) echo "aborted."; exit 1 ;;
    esac
fi

# ---- 1: validate scaffold (no .env / docker required) ----------------------

step "validating scaffold"
python3 - <<'PY'
import importlib.util, pathlib, sys
spec = importlib.util.spec_from_file_location("install", "scripts/install.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.validate_scaffold(pathlib.Path(".").resolve())
PY

# ---- 2: reconcile .env  ---  MUST happen before any `docker compose`
# invocation, because compose parses docker-compose.yml at startup and
# fails with "variable XYZ required" if .env is missing keys the YAML
# references via ${...:?required}. Existing values are never touched.
#
# 2a (2026-11-11): the installer's OWN migration. `install.py --migrate-env`
# runs write_env's existing-.env branch, the code a re-run of the installer
# runs, so an upgraded install gains every key a newer release introduced
# (CX_PLATFORM_ADDRESSES, the per-lane ingest tokens, STORE_BACKEND, ...) with
# no manual step. Before 2026-11-11 this script carried its own partial copy of
# that list and those keys never arrived. It takes the install lock, refuses a
# truncated .env instead of minting store credentials into it, backs .env up
# (0600) before writing, prints key names only, and exits non-zero on any
# error, which aborts the upgrade here with the containers untouched (set -e).

step "adding the .env keys this release introduced (install.py --migrate-env)"
python3 scripts/install.py --migrate-env

# 2a': discoverability knobs. Every value is BYTE-IDENTICAL to the default
# docker-compose.yml interpolates, so materializing a key changes nothing: it
# only makes the knob visible in .env after an upgrade. This table holds ONLY
# such knobs. Every key install.py's migration or secret generator owns is
# appended (or minted) by 2a, and tests/test_compose_new_modules.py fails if a
# key appears in both places.

step "adding the discoverable configuration knobs"
python3 - <<'PY'
"""Append the knobs below that the live .env lacks. Never touches an existing
value; writes through install.py's atomic owner-only writer; prints names only."""
import datetime, importlib.util, pathlib, sys

spec = importlib.util.spec_from_file_location("install", "scripts/install.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

env_path = pathlib.Path("deployment/docker/.env")
body = env_path.read_text(encoding="utf-8")
existing = mod._parse_env_text(body)

KNOBS = {
    "ADMIN_USERNAME":            "admin",
    "CLICKHOUSE_USER":           "netops",
    # copilot (new in the AI Copilot landing)
    "FEATURE_COPILOT":           "true",   # Iris on (evidence-only); model answers are the add-on + Features switch
    "COPILOT_PROVIDER":          "anthropic",
    "COPILOT_API_KEY":           "",
    "COPILOT_MODEL":             "claude-sonnet-4-5",
    "CORRELATION_LOG_LEVEL":     "info",
    # ingestion ports (new in the ingestion-tier landing)
    "SYSLOG_PORT":               "5514",
    "NETFLOW_PORT":              "2055",
    "IPFIX_PORT":                "4739",
    "SFLOW_PORT":                "6343",
    "GRAFANA_URL":               "http://grafana:3000",
    # expanded notifier (new in the alert-channels landing)
    "SMTP_USER":                 "",
    "SMTP_PASS":                 "",
    "SMTP_TO":                   "",
    "FEATURE_TWILIO_NOTIFICATIONS": "false",
    "TWILIO_ACCOUNT_SID":        "",
    "TWILIO_AUTH_TOKEN":         "",
    "TWILIO_FROM_NUMBER":        "",
    "TWILIO_TO_NUMBERS":         "",
    "FEATURE_SNS_NOTIFICATIONS": "false",
    "AWS_ACCESS_KEY_ID":         "",
    "AWS_SECRET_ACCESS_KEY":     "",
    "AWS_REGION":                "",
    "SNS_PHONE_NUMBERS":         "",
    "SNS_TOPIC_ARN":             "",
    # optional modules (Project 3).
    # DELIBERATELY ABSENT: CORR_EVIDENCE_TOPICS. For that one variable "unset"
    # and "empty" are different contracts (unset = every registered evidence
    # class; empty = subscribe to none), so appending it with an empty default
    # would silently unsubscribe every evidence class on the next restart.
    "FEATURE_SECURITY_LANE":         "false",
    "SECURITY_SCAN_INTERVAL":        "15m",
    "SECURITY_MAX_FINDINGS_PER_TENANT": "5000",
    "FEATURE_CONFIG_BACKUP":         "false",
    "CONFIG_BACKUP_INTERVAL":        "24h",
    "CONFIG_BACKUP_KEEP_VERSIONS":   "30",
    "CONFIG_BACKUP_SSH_USER":        "",
    "CONFIG_BACKUP_SSH_PASSWORD":    "",
    "CONFIG_BACKUP_SSH_KEY":         "",
    "CONFIG_BACKUP_SSH_PORT":        "22",
    "FEATURE_PACKET_CAPTURE":        "false",
    "PCAP_KEEP":                     "20",
    "PCAP_SSH_USER":                 "",
    "PCAP_SSH_PASSWORD":             "",
    "PCAP_SSH_KEY":                  "",
    "PCAP_SSH_PORT":                 "22",
    "FEATURE_PROTOCOL_DIAG_COLLECT": "false",
    "PROTOCOL_DIAG_SSH_USER":        "",
    "PROTOCOL_DIAG_SSH_PASSWORD":    "",
    "PROTOCOL_DIAG_SSH_KEY":         "",
    "PROTOCOL_DIAG_SSH_PORT":        "22",
    # BMP receiver (the live BGP feed). BMP_PORT is the HOST port the compose
    # ports: mapping publishes; BMP_LISTEN is the in-container bind.
    "FEATURE_BMP":                   "false",
    "BMP_LISTEN":                    ":11019",
    "BMP_PORT":                      "11019",
    # BGP depth/alerting flags: the three passthroughs were missing from
    # compose entirely until 2026-09-03, so no .env value could turn any of
    # them on.
    "FEATURE_BGP_LIVE_FEED":         "false",
    "FEATURE_BGP_ALERTS":            "false",
    "FEATURE_BGP_BOGON_FEED":        "false",
    # Byte-identical to the docker-compose default and to
    # bgpdepth.DefaultFeedLookback.
    "BGP_FEED_LOOKBACK":             "6h",
    "PARSERCOV_MAX_LINES":           "200000",
    "CORRELATION_REPLICA_URLS":      "",
    "CORR_SYSLOG_TOPIC":             "netops.syslog",
    "CORR_FIDELITY_WEIGHTING":       "0",
    # Platform self-health alert DESTINATIONS are no longer env (owner decision
    # 2026-11-11): they are set in the web console, Platform -> Platform alerts.
    # PLATFORM_ALERTS_NTFY_TOPIC/_SERVER/_TOKEN are therefore NOT materialized;
    # RETIRED below reports a leftover value instead of silently keeping it.
    # Alert-noise + rate-limit control (2026-09-03). Byte-identical to
    # alertwebhook's DefaultWarningDigestInterval / DefaultPushBudget /
    # DefaultPageReserve.
    "PLATFORM_ALERTS_WARNING_DIGEST_INTERVAL":  "30m",
    "PLATFORM_ALERTS_PUSH_BUDGET":              "30",
    "PLATFORM_ALERTS_PUSH_BUDGET_PAGE_RESERVE": "10",
}

missing = [k for k in KNOBS if k not in existing]

# Retired keys: still in an upgraded .env, read by nothing. Named (values are
# never printed — a topic or token is a credential) so the operator knows the
# setting moved, instead of believing it still routes platform alerts. Not
# fatal and not edited away: removing lines from an operator's .env is theirs
# to do.
RETIRED = {
    "PLATFORM_ALERTS_NTFY_TOPIC":  "Platform -> Platform alerts in the web console",
    "PLATFORM_ALERTS_NTFY_SERVER": "Platform -> Platform alerts in the web console",
    "PLATFORM_ALERTS_NTFY_TOKEN":  "Platform -> Platform alerts in the web console",
}
for k, where in RETIRED.items():
    if existing.get(k, "").strip():
        print(f"  NOTICE: {k} is set in .env but is no longer read — configure it in {where}, then remove the line.")
if not missing:
    print("  no new knobs to add: .env is already current.")
    sys.exit(0)

mod.write_env_text(
    env_path,
    body.rstrip("\n") + "\n\n# ---- added by update.sh on "
    + datetime.datetime.now().isoformat() + " ----\n"
    + "".join(f"{k}={KNOBS[k]}\n" for k in missing),
    what="add the discoverable configuration knobs")
print(f"  added {len(missing)} knob(s): {', '.join(missing)}")
PY

# ---- 2b: render the service credential files ---------------------------------
#
# Tracker 367 layer 1: every client reads its service password from a mounted
# file under data/secrets, rendered from .env. It MUST run before `compose up`
# (a container started without its file refuses to start or fails every
# authenticated call) and after the reconcile (it needs the complete .env).
# The SAME renderer install.py uses — one definition of names, owners and
# modes. A failure aborts the upgrade (set -e): the containers are untouched.
#
# Tracker 384: first move any credential still in an old-form .env (a password
# in DATABASE_URL) to its file-backed key. Idempotent; no manual step.
#
# prepare_tls_custody (2026-11-09): brings a stale TLS_SERVICE_KEY_MODE=0644 in
# .env in line and pre-creates new bind sources. It tightens nothing. The one
# `compose up` below recreates every reader with group_add; the api tightens the
# key modes only when it boots, and a reader that restarts either side of that
# can read its key.

step "rendering service credential files"
python3 - <<'PY'
import importlib.util, pathlib
spec = importlib.util.spec_from_file_location("install", "scripts/install.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
root = pathlib.Path(".").resolve()
mod.migrate_env_credentials(root / "deployment" / "docker" / ".env")
mod.render_service_secrets(root)
mod.prepare_tls_custody(root)
PY

# ---- 3: backup --------------------------------------------------------------
#
# Now safe to run — .env is complete, so docker compose can parse the
# YAML. backup.sh internally skips logical dumps (postgres / clickhouse)
# when those containers aren't currently running, so a pre-first-success
# upgrade still gets a meaningful data-dir snapshot.

if [[ $NO_BACKUP -eq 0 ]]; then
    step "backing up before upgrade"
    mkdir -p "$BACKUP_DIR"
    STAMP="$(date +%F-%H%M%S)"
    OUT="$BACKUP_DIR/pre-upgrade-${STAMP}.tar.zst"
    if [[ -x "$ROOT/scripts/backup.sh" ]]; then
        "$ROOT/scripts/backup.sh" "$OUT"
    else
        warn "backup.sh missing — falling back to a raw tar of data/ and .env"
        tar -C "$ROOT" -cf - data deployment/docker/.env | zstd -T0 -19 -o "$OUT"
        ok "wrote $OUT"
    fi
fi

# ---- 4 + 5: pull + build ----------------------------------------------------

if [[ $NO_BUILD -eq 0 ]]; then
    step "pulling pinned images"
    (cd "$COMPOSE_DIR" && docker compose pull) || warn "pull had errors (proceeding anyway)"

    step "building local images (api / frontend / correlation)"
    (cd "$COMPOSE_DIR" && docker compose build --pull)
fi

# ---- 6: up -d ---------------------------------------------------------------

# Snapshot the running containers and fingerprint the mounted config BEFORE the
# recreate, so step 6b can tell which services compose left on their old config.
# A failure here aborts with the containers untouched.
step "fingerprinting mounted config"
if ! mc_begin; then
    fail "$MC_ERROR — containers left untouched."
fi

step "recreating containers"
(cd "$COMPOSE_DIR" && docker compose up -d --remove-orphans)

# ---- 6b: recreate services whose mounted config changed ----------------------
# See the header. Every changed service is in scope on this path (no names).

step "recreating services whose mounted config changed"
# shellcheck disable=SC2119 # no service names = every service is in scope
mc_plan || fail "$MC_ERROR — the upgrade cannot vouch that every service runs its new config. Re-run update.sh."
if [[ $MC_FIRST_RUN -eq 1 ]]; then
    info "no fingerprint record yet ($MC_STATE_FILE) — recording a baseline; nothing is recreated for config on this first run"
fi
if [[ -n "$MC_STATE_PROBLEM" ]]; then
    warn "the fingerprint record is unusable ($MC_STATE_PROBLEM) — treating EVERY service with mounted config as changed"
fi
if [[ ${#MC_BASELINE[@]} -gt 0 ]]; then
    info "first fingerprint recorded for ${MC_BASELINE[*]} (not recreated)"
fi
if [[ ${#MC_RECREATED[@]} -gt 0 ]]; then
    info "mounted config changed for ${MC_RECREATED[*]} — already recreated above"
fi
if [[ ${#MC_NOT_RUNNING[@]} -gt 0 ]]; then
    info "mounted config changed for ${MC_NOT_RUNNING[*]} — not running; its next start reads the new config"
fi
if [[ ${#MC_STALE[@]} -gt 0 ]]; then
    # Unreachable without --named; kept so a planner change can never be silent.
    fail "planner left ${MC_STALE[*]} out of scope on the update path — refusing to finish with them on old config"
fi
if [[ ${#MC_RESTART[@]} -gt 0 ]]; then
    warn "recreating ${MC_RESTART[*]} — their MOUNTED CONFIG changed and compose left them running on the old one"
    if ! mc_recreate "${MC_RESTART[@]}"; then
        fail "MOUNTED CONFIG COULD NOT BE APPLIED: $MC_ERROR. ${MC_RESTART[*]} may be down or crash-looping on the new config. Inspect: (cd $COMPOSE_DIR && docker compose ps && docker compose logs --tail 100 ${MC_RESTART[*]}). To go back, use the Rollback steps printed by a successful run: docker compose down, scripts/restore.sh ${BACKUP_DIR}/<backup>, docker compose up -d."
    fi
    ok "recreated because their mounted config changed: ${MC_RESTART[*]}"
else
    ok "no running service is left on an old mounted config"
fi
mc_commit || fail "every service is up on its new config, but $MC_ERROR. The next upgrade compares against the previous record and may recreate config-changed services again."
info "$MC_COMMIT_MSG"

# ---- 7: bootstrap opensearch ------------------------------------------------

if [[ -x "$ROOT/scripts/bootstrap-opensearch.sh" ]]; then
    step "applying OpenSearch index templates"
    # ONE owner (2026-09-03): bootstrap-opensearch.sh detects the variant from
    # COMPOSE_FILE, waits for an AUTHENTICATED /_cluster/health, and applies
    # every template in index-templates.json. The readiness loop and the
    # `OPENSEARCH_URL=http://localhost:9200` override that used to live here
    # were both plaintext-only, so on a TLS install this step probed a port
    # that does not exist and then failed all nine templates — the exact
    # blindness the script now owns and reports.
    bash "$ROOT/scripts/bootstrap-opensearch.sh" \
        || warn "template apply failed; see the APPLIED/FAILED lines above and re-run scripts/bootstrap-opensearch.sh"
fi

# ---- 8: reclaim superseded images --------------------------------------------
# Every upgrade loads new image versions and the old ones stay on disk forever —
# the ONE real docker-debris growth vector on an appliance (nothing builds
# there). Dangling-only prune: the running stack's images are referenced and
# untouchable; only layers no tag points at any more are removed.

step "removing superseded image layers"
docker image prune -f >/dev/null 2>&1 || warn "image prune failed (non-fatal)"

# ---- done -------------------------------------------------------------------

step "status"
(cd "$COMPOSE_DIR" && docker compose ps)

cat <<EOF

==============================================================
  Upgrade complete.

  Health:    curl -fs http://localhost:8000/admin/health | jq
  Logs:      cd $COMPOSE_DIR && docker compose logs -f
  Rollback:  cd $COMPOSE_DIR && docker compose down
             python3 scripts/install.py --custody-rollback   # before going back past 2026-11-09
             bash scripts/restore.sh ${BACKUP_DIR}/<the-backup-you-want>
             cd $COMPOSE_DIR && docker compose up -d
==============================================================
EOF
