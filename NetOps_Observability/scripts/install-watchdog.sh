#!/usr/bin/env bash
#
# Correlix watchdog installer (runs as root; the setup GUI invokes it via sudo
# with a fixed argv). Installs the external stack watchdog as a system cron:
#
#   /etc/correlix/stack-watchdog.env   channel + probe config (root:root 0600)
#   /etc/cron.d/correlix-watchdog      every-minute cron entry (root:root 0644)
#   /etc/logrotate.d/correlix-watchdog bounds /var/log/correlix-watchdog.log
#
# Usage:
#   install-watchdog.sh --app-url URL [--topic TOPIC] [--email ADDR]
#                       [--hc-url URL] [--ntfy-server URL] [--ntfy-token TOKEN]
#                       [--webhook-url URL] [--webhook-token TOKEN]
#                       [--app-cacert PATH] [--script PATH]
#                       [--print-only] [--uninstall]
#
#   --app-url       dashboard URL the watchdog probes (http(s)://host[:port][/path])
#   --topic         ntfy topic for phone push (also carries --email fan-out)
#   --email         deliver each alert to this address too (ntfy Email: header;
#                   REQUIRES --topic — ntfy can only publish to a topic)
#   --hc-url        healthchecks.io ping URL (dead-man's switch; pings carry no
#                   content — its own channels are the zero-secret email path)
#   --ntfy-server   self-hosted ntfy server (default https://ntfy.sh)
#   --ntfy-token    bearer token for an authenticated ntfy server
#   --webhook-url   generic https webhook POSTed a JSON status on transitions
#   --webhook-token bearer token for the webhook
#   --app-cacert    PEM CA file for a self-signed https --app-url
#   --script        path to stack-watchdog.sh (default: sibling of this script)
#   --print-only    validate argv and print the three files; write NOTHING
#                   (no root needed — used by tests and for review)
#   --uninstall     remove the cron entry, config and logrotate rule
#
# At least one notification channel (--topic / --email / --hc-url /
# --webhook-url) is required. Re-running is idempotent: both files are simply
# overwritten with the new settings.
#
# SECURITY: on public ntfy.sh the topic name is the only secret (obscurity, not
# access control) — insist on a high-entropy topic, or better a self-hosted
# authenticated ntfy / the webhook / healthchecks channels. The env file is
# root-owned 0600 because topic, tokens and ping URL are credentials.

set -euo pipefail
export PATH="/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

ENV_FILE="/etc/correlix/stack-watchdog.env"
# Root-owned COPY of the watchdog script: cron must never execute a file the
# unprivileged bundle owner can edit (user->root escalation), and deleting the
# extracted bundle dir must not silently kill monitoring (ultra-review finds,
# 2026-08-14). The source path is validated, then copied here at install.
INSTALLED_SCRIPT="/etc/correlix/stack-watchdog.sh"
CRON_FILE="/etc/cron.d/correlix-watchdog"
LOGROTATE_FILE="/etc/logrotate.d/correlix-watchdog"
LOG_FILE="/var/log/correlix-watchdog.log"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Customer base service set = long-running services of the base compose
# profiles (embedded-bus + prober + sso), i.e. what `install-correlix.sh`
# starts on every install — one-shot init containers (kafka-init,
# opensearch-init) excluded. Keep in sync with BASE_PROFILES in
# make-installer.sh; add-on services (osd, self-monitoring) are appended by
# the operator in $ENV_FILE when those packs are enabled.
CUSTOMER_SERVICES="api clickhouse correlation frontend gnmic goflow2 kafka \
keycloak nginx opensearch postgres prober redis syslog-ng vector-aggregator \
vector-router victoria vmalert"

die() { echo "install-watchdog: ERROR: $*" >&2; exit 2; }
# Usage = this file's own header block (single source of truth): print every
# leading comment line after the shebang, stop at the first non-comment line.
usage() { awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "${BASH_SOURCE[0]}"; }

APP_URL="" TOPIC="" EMAIL="" HC_URL=""
NTFY_SERVER="" NTFY_TOKEN="" WEBHOOK_URL="" WEBHOOK_TOKEN="" APP_CACERT=""
WATCHDOG_SCRIPT="$SCRIPT_DIR/stack-watchdog.sh"
PRINT_ONLY=0 UNINSTALL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --app-url)       [ $# -ge 2 ] || die "--app-url requires a value";       APP_URL="$2";         shift 2 ;;
    --topic)         [ $# -ge 2 ] || die "--topic requires a value";         TOPIC="$2";           shift 2 ;;
    --email)         [ $# -ge 2 ] || die "--email requires a value";         EMAIL="$2";           shift 2 ;;
    --hc-url)        [ $# -ge 2 ] || die "--hc-url requires a value";        HC_URL="$2";          shift 2 ;;
    --ntfy-server)   [ $# -ge 2 ] || die "--ntfy-server requires a value";   NTFY_SERVER="$2";     shift 2 ;;
    --ntfy-token)    [ $# -ge 2 ] || die "--ntfy-token requires a value";    NTFY_TOKEN="$2";      shift 2 ;;
    --webhook-url)   [ $# -ge 2 ] || die "--webhook-url requires a value";   WEBHOOK_URL="$2";     shift 2 ;;
    --webhook-token) [ $# -ge 2 ] || die "--webhook-token requires a value"; WEBHOOK_TOKEN="$2";   shift 2 ;;
    --app-cacert)    [ $# -ge 2 ] || die "--app-cacert requires a value";    APP_CACERT="$2";      shift 2 ;;
    --script)        [ $# -ge 2 ] || die "--script requires a value";        WATCHDOG_SCRIPT="$2"; shift 2 ;;
    --print-only)    PRINT_ONLY=1; shift ;;
    --uninstall)     UNINSTALL=1;  shift ;;
    -h|--help)       usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

require_root() {
  [ "$(id -u)" -eq 0 ] || die "must run as root (sudo) — use --print-only to preview without writing"
}

# ---------------------------------------------------------------------------
# Uninstall: remove everything we install; idempotent (absent files are fine).
# ---------------------------------------------------------------------------
if [ "$UNINSTALL" = 1 ]; then
  if [ "$PRINT_ONLY" = 1 ]; then
    echo "print-only: would remove $CRON_FILE, $ENV_FILE, $LOGROTATE_FILE, $INSTALLED_SCRIPT"
    exit 0
  fi
  require_root
  removed=0
  for f in "$CRON_FILE" "$ENV_FILE" "$LOGROTATE_FILE" "$INSTALLED_SCRIPT"; do
    if [ -e "$f" ]; then
      rm -f "$f"
      echo "removed $f"
      removed=1
    fi
  done
  # Optional tidy-up (safe to skip): /etc/correlix may hold other Correlix
  # config, and rmdir refuses non-empty dirs by design — that refusal is the
  # expected outcome, not an error to surface.
  rmdir /etc/correlix 2>/dev/null || true
  [ "$removed" = 1 ] || echo "nothing to remove (watchdog was not installed)"
  exit 0
fi

# ---------------------------------------------------------------------------
# Strict validation. The GUI passes a fixed argv, but this script is the
# security boundary: everything it writes lands in root-parsed files
# (/etc/cron.d, a sourced env file), so every value is allowlist-validated.
# ---------------------------------------------------------------------------
[ -n "$APP_URL" ] || die "--app-url is required"
if ! { [ "${#APP_URL}" -le 200 ] && [[ "$APP_URL" =~ ^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._/-]*)?$ ]]; }; then
  die "--app-url must be http(s)://host[:port][/path], <=200 chars (got: $APP_URL)"
fi

if [ -n "$TOPIC" ]; then
  [[ "$TOPIC" =~ ^[A-Za-z0-9_-]{1,64}$ ]] \
    || die "--topic must match ^[A-Za-z0-9_-]{1,64}\$"
fi

if [ -n "$EMAIL" ]; then
  if ! { [ "${#EMAIL}" -le 254 ] && [[ "$EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; }; then
    die "--email is not a valid address (RFC-lite check, <=254 chars)"
  fi
  [ -n "$TOPIC" ] || die "--email requires --topic: ntfy can only publish to a topic, and email delivery rides the topic publish"
fi

if [ -n "$HC_URL" ]; then
  if ! { [ "${#HC_URL}" -le 200 ] && [[ "$HC_URL" =~ ^https://[A-Za-z0-9.-]+/[A-Za-z0-9/_-]+$ ]]; }; then
    die "--hc-url must be https://host/path ([A-Za-z0-9/_-] path, <=200 chars)"
  fi
fi

if [ -n "$NTFY_SERVER" ]; then
  NTFY_SERVER="${NTFY_SERVER%/}"
  if ! { [ "${#NTFY_SERVER}" -le 200 ] && [[ "$NTFY_SERVER" =~ ^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]]; }; then
    die "--ntfy-server must be http(s)://host[:port], <=200 chars"
  fi
fi

if [ -n "$NTFY_TOKEN" ]; then
  [[ "$NTFY_TOKEN" =~ ^[A-Za-z0-9._~+/=-]{8,256}$ ]] \
    || die "--ntfy-token must match ^[A-Za-z0-9._~+/=-]{8,256}\$"
fi

if [ -n "$WEBHOOK_URL" ]; then
  # Same shape as --hc-url plus the chars real incoming-webhook URLs use
  # (Teams embeds '@', some relays use '?='). https only: a bearer token must
  # never ride plaintext.
  if ! { [ "${#WEBHOOK_URL}" -le 512 ] && [[ "$WEBHOOK_URL" =~ ^https://[A-Za-z0-9.-]+/[A-Za-z0-9/_.@%=\&?~-]+$ ]]; }; then
    die "--webhook-url must be https://host/path, <=512 chars"
  fi
fi

if [ -n "$WEBHOOK_TOKEN" ]; then
  [[ "$WEBHOOK_TOKEN" =~ ^[A-Za-z0-9._~+/=-]{8,256}$ ]] \
    || die "--webhook-token must match ^[A-Za-z0-9._~+/=-]{8,256}\$"
fi

if [ -n "$APP_CACERT" ]; then
  [[ "$APP_CACERT" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "--app-cacert must be an absolute path without spaces"
  [ -f "$APP_CACERT" ] || die "--app-cacert file not found: $APP_CACERT"
  [ -r "$APP_CACERT" ] || die "--app-cacert file not readable: $APP_CACERT"
fi

[ -n "$TOPIC" ] || [ -n "$EMAIL" ] || [ -n "$HC_URL" ] || [ -n "$WEBHOOK_URL" ] \
  || die "at least one notification channel is required: --topic, --email, --hc-url or --webhook-url"

[ -f "$WATCHDOG_SCRIPT" ] || die "watchdog script not found: $WATCHDOG_SCRIPT"
[ -x "$WATCHDOG_SCRIPT" ] || die "watchdog script not executable: $WATCHDOG_SCRIPT"
# Resolve to an absolute path — the cron line must not depend on a cwd — and
# refuse characters that would corrupt the root-parsed cron entry.
WATCHDOG_SCRIPT="$(cd "$(dirname "$WATCHDOG_SCRIPT")" && pwd)/$(basename "$WATCHDOG_SCRIPT")"
[[ "$WATCHDOG_SCRIPT" =~ ^/[A-Za-z0-9._/-]+$ ]] \
  || die "watchdog script path may only contain [A-Za-z0-9._/-] (cron-safe): $WATCHDOG_SCRIPT"

# H16(b)/M27 (2026-08-15): the packaged watchdog runs from /etc/correlix, so
# every default in stack-watchdog.sh that assumes "I live in the repo's
# scripts/ dir" resolves under /etc and silently misses the bundle:
#   * CH_ENV_FILE -> /etc/deployment/docker/.env (never exists), so the
#     ClickHouse/OpenSearch checks lose their credentials AND the TLS-variant
#     detection, leaving a permanent false problem on plaintext installs;
#   * the #150 backup-intent trio -> /etc/data/... , so GUI-stored backup
#     settings were NEVER applied on packaged hosts.
# Derive the real bundle paths from the validated SOURCE script location and
# write them into the env file explicitly. The stamp lives in /etc/correlix
# (root-owned, survives bundle re-extraction). Both derived paths inherit the
# cron-safe charset validated above, which excludes the single quote the env
# values are wrapped in.
BUNDLE_SCRIPTS_DIR="$(dirname "$WATCHDOG_SCRIPT")"
BUNDLE_ROOT="$(cd "$BUNDLE_SCRIPTS_DIR/.." && pwd)"

# ---------------------------------------------------------------------------
# File contents. Env values are single-quoted: the watchdog SOURCES this file,
# and every charset above excludes the single quote, so no value can escape.
# ---------------------------------------------------------------------------
env_content() {
  cat <<EOF
# Correlix stack-watchdog configuration — written by install-watchdog.sh.
# Re-running install-watchdog.sh OVERWRITES this file; --uninstall removes it.
# Root-owned 0600: topic, tokens and ping URL are credentials. Every knob is
# documented in NetOps_Observability/scripts/stack-watchdog.env.example
# (note: a public-ntfy topic without a token is obscurity, not access control).
APP_URL='$APP_URL'
APP_CACERT='$APP_CACERT'
NTFY_TOPIC='$TOPIC'
NTFY_SERVER='${NTFY_SERVER:-https://ntfy.sh}'
NTFY_TOKEN='$NTFY_TOKEN'
WATCHDOG_EMAIL='$EMAIL'
HC_PING_URL='$HC_URL'
WATCHDOG_WEBHOOK_URL='$WEBHOOK_URL'
WATCHDOG_WEBHOOK_TOKEN='$WEBHOOK_TOKEN'
WATCHDOG_SERVICES='$CUSTOMER_SERVICES'
COMPOSE_PROJECT='netops'
CH_ENV_FILE='$BUNDLE_ROOT/deployment/docker/.env'
BACKUP_INTENT_FILE='$BUNDLE_ROOT/data/api/system_backup.json'
BACKUP_APPLY_SCRIPT='$BUNDLE_SCRIPTS_DIR/apply-backup-config.sh'
BACKUP_APPLY_STAMP='/etc/correlix/.backup-config.applied'
EOF
}

cron_content() {
  cat <<EOF
# Correlix stack watchdog — external dead-man's-switch monitor, every minute.
# Managed by install-watchdog.sh (re-run to change settings, --uninstall to
# remove; manual edits are overwritten). Log growth is bounded by
# $LOGROTATE_FILE.
SHELL=/bin/sh
PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
* * * * * root WATCHDOG_ENV=$ENV_FILE $INSTALLED_SCRIPT >>$LOG_FILE 2>&1
EOF
}

logrotate_content() {
  cat <<EOF
# Managed by install-watchdog.sh (Correlix) — bounds the watchdog cron log.
# copytruncate because cron appends with >> (no daemon to signal).
$LOG_FILE {
  size 5M
  rotate 4
  compress
  missingok
  notifempty
  copytruncate
}
EOF
}

if [ "$PRINT_ONLY" = 1 ]; then
  echo "== $ENV_FILE (root:root 0600) =="
  env_content
  echo
  echo "== $CRON_FILE (root:root 0644) =="
  cron_content
  echo
  echo "== $LOGROTATE_FILE (root:root 0644) =="
  logrotate_content
  echo
  echo "print-only: nothing written."
  exit 0
fi

require_root
umask 077
install -d -m 0755 -o root -g root /etc/correlix

# Atomic installs: write a temp file, set ownership/mode, then rename into
# place — a half-written config or cron entry must never be live. The cron
# temp name carries a leading dot so Debian/vixie cron ignores it pre-rename
# (cron.d skips names outside [A-Za-z0-9_-]).
tmp="$(mktemp /etc/correlix/.stack-watchdog.env.XXXXXX)"
env_content > "$tmp"
chown root:root "$tmp"
chmod 0600 "$tmp"
mv -f "$tmp" "$ENV_FILE"

tmp="$(mktemp /etc/correlix/.stack-watchdog.sh.XXXXXX)"
cp "$WATCHDOG_SCRIPT" "$tmp"
chown root:root "$tmp"
chmod 0755 "$tmp"
mv -f "$tmp" "$INSTALLED_SCRIPT"

tmp="$(mktemp /etc/cron.d/.correlix-watchdog.XXXXXX)"
cron_content > "$tmp"
chown root:root "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$CRON_FILE"

tmp="$(mktemp /etc/logrotate.d/.correlix-watchdog.XXXXXX)"
logrotate_content > "$tmp"
chown root:root "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$LOGROTATE_FILE"

echo "installed: $ENV_FILE (0600), $INSTALLED_SCRIPT (root 0755), $CRON_FILE, $LOGROTATE_FILE"
echo "watchdog:  $INSTALLED_SCRIPT runs every minute; log: $LOG_FILE"
echo "verify:    sudo WATCHDOG_ENV=$ENV_FILE $INSTALLED_SCRIPT --test"
