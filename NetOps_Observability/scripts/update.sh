#!/usr/bin/env bash
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
echo "  3) Reconcile $ENV_FILE with any new variables introduced upstream"
[[ $NO_BUILD -eq 0 ]]  && echo "  4) docker compose pull   (refresh pinned images)"
[[ $NO_BUILD -eq 0 ]]  && echo "  5) docker compose build  (rebuild api / frontend / correlation)"
echo "  6) docker compose up -d --remove-orphans   (recreate containers)"
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
# references via ${...:?required}. Reconciliation appends missing keys
# with safe defaults; existing values are never touched.

step "reconciling .env with current installer template"
python3 - <<'PY'
"""Append any vars in the installer's current template that are missing
from the live .env, with safe defaults. Does NOT touch existing values.
Secrets that need to be cryptographically random get one generated."""
import os, pathlib, re, secrets, string, sys

env_path = pathlib.Path("deployment/docker/.env")
existing = {}
with env_path.open() as f:
    body = f.read()
for line in body.splitlines():
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    k, _, v = line.partition("=")
    existing[k.strip()] = v.strip()

# Keys we expect in the current template. Update this list when adding new
# config; the canonical source is scripts/install.py's write_env() body.
EXPECTED = {
    # auth bootstrap (new in the auth landing)
    "ADMIN_USERNAME":            "admin",
    "ADMIN_INITIAL_PASSWORD":    "__RANDOM__",
    # clickhouse (new in the OLAP landing)
    "CLICKHOUSE_USER":           "netops",
    "CLICKHOUSE_PASSWORD":       "__RANDOM__",
    # copilot (new in the AI Copilot landing)
    "FEATURE_COPILOT":           "false",
    "COPILOT_PROVIDER":          "anthropic",
    "COPILOT_API_KEY":           "",
    "COPILOT_MODEL":             "claude-sonnet-4-5",
    "CORRELATION_LOG_LEVEL":     "info",
    # ingestion ports (new in the ingestion-tier landing)
    "SYSLOG_PORT":               "5514",
    "NETFLOW_PORT":              "2055",
    "IPFIX_PORT":                "4739",
    "SFLOW_PORT":                "6343",
    # event bus (Redpanda→Apache Kafka swap, #97)
    "BROKER_URLS":               "kafka:9092",
    "KAFKA_CLUSTER_ID":          "__KAFKA_UUID__",
    "COMPOSE_PROFILES":          "embedded-bus,prober,osd",
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
}

alphabet = string.ascii_letters + string.digits + "!@#%^&*-_=+"
def randpw(n=24): return "".join(secrets.choice(alphabet) for _ in range(n))

def kafka_uuid():
    # kafka-storage random-uuid format: 22-char base64url uuid, no padding.
    import base64, uuid
    return base64.urlsafe_b64encode(uuid.uuid4().bytes).decode().rstrip("=")

missing = []
for k, default in EXPECTED.items():
    if k in existing:
        continue
    if default == "__RANDOM__":
        v = randpw(20)
    elif default == "__KAFKA_UUID__":
        v = kafka_uuid()
    else:
        v = default
    missing.append((k, v))

if not missing:
    print("  no new variables to add — .env is already current.")
    sys.exit(0)

# Append a clearly labelled block.
with env_path.open("a") as f:
    f.write("\n# ---- added by update.sh on " + __import__("datetime").datetime.now().isoformat() + " ----\n")
    for k, v in missing:
        f.write(f"{k}={v}\n")

env_path.chmod(0o600)
print(f"  added {len(missing)} new variable(s):")
for k, v in missing:
    redacted = v if "PASSWORD" not in k and "TOKEN" not in k and "KEY" not in k else f"<{len(v)} chars>"
    print(f"    {k}={redacted}")
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

step "recreating containers"
(cd "$COMPOSE_DIR" && docker compose up -d --remove-orphans)

# ---- 7: bootstrap opensearch ------------------------------------------------

if [[ -x "$ROOT/scripts/bootstrap-opensearch.sh" ]]; then
    step "applying OpenSearch index templates"
    # Run via docker exec since OpenSearch isn't on the host network.
    (cd "$COMPOSE_DIR" && docker compose exec -T opensearch bash -lc '
        for i in $(seq 1 30); do
            curl -sf http://localhost:9200/_cluster/health >/dev/null && break
            sleep 2
        done
    ') || warn "OpenSearch not ready in time; re-run scripts/bootstrap-opensearch.sh later."
    OPENSEARCH_URL=http://localhost:9200 bash "$ROOT/scripts/bootstrap-opensearch.sh" \
        || warn "template apply failed; check manually."
fi

# ---- done -------------------------------------------------------------------

step "status"
(cd "$COMPOSE_DIR" && docker compose ps)

cat <<EOF

==============================================================
  Upgrade complete.

  Health:    curl -fs http://localhost:8000/admin/health | jq
  Logs:      cd $COMPOSE_DIR && docker compose logs -f
  Rollback:  cd $COMPOSE_DIR && docker compose down
             bash scripts/restore.sh ${BACKUP_DIR}/<the-backup-you-want>
             cd $COMPOSE_DIR && docker compose up -d
==============================================================
EOF
