#!/usr/bin/env bash
#
# bootstrap-opensearch.sh — THE single owner of OpenSearch index-template
# application. It applies every template declared in
# deployment/docker/opensearch/index-templates.json to the running cluster.
#
# OWNERSHIP SPLIT (do not re-implement either half elsewhere):
#   * this script                        → deployment/docker/opensearch/index-templates.json
#                                          (the netops-* LOG-LANE field contract)
#   * deployment/docker/opensearch/apply-ism.sh (the `opensearch-init` one-shot)
#                                        → ISM retention policies, the snapshot
#                                          repository + SM policy, replica
#                                          posture, and the settings-only
#                                          `security-auditlog` template, which
#                                          is deliberately NOT in
#                                          index-templates.json.
#   scripts/install.py and scripts/update.sh both CALL this script; neither
#   PUTs a template itself any more (they used to, and the copies drifted).
#
# OpenSearch in the default docker-compose isn't port-mapped to the host, so we
# run curl from INSIDE the opensearch container (via `docker compose exec`).
#
# TLS INSTALLS (SEC-008). When deployment/docker/.env's COMPOSE_FILE includes
# compose.tls.yml the cluster serves **https on 9200 with the security plugin
# on**, so the old unconditional `http://localhost:9200` got an empty/refused
# reply for EVERY template — the script printed "was NOT applied" nine times and
# an upgraded stack ran with zero declared mappings (observed on the lab,
# 2026-09-03: netops-secfindings among them). On TLS we therefore speak
# https://opensearch:9200:
#   * the host name MUST be `opensearch` — the issued SAN set is `DNS:opensearch`
#     plus a SPIFFE URI and nothing else, so `localhost` fails hostname
#     verification (curl 60). The fix is the correct NAME, never `-k`: riding
#     insecure here would turn a real MITM or a misissued cert into a silent
#     pass, which is the §16.1 defect class itself.
#   * authentication reuses install.py's template step exactly: the
#     `svc_bootstrap` credential from .env, which maps to the `netops_bootstrap`
#     role holding `cluster_manage_index_templates`. It is expanded from the
#     CONTAINER's own environment inside `sh -c` — never argv (argv is
#     world-readable in /proc) and never a log line (§8). The admin client
#     certificate (data/tls/admin/*) is deliberately NOT used: it is not mounted
#     into the opensearch container, it is `all_access`, and the SEC-008.1 role
#     model says every client identity is scoped to what it actually touches.
#
# Override by setting OPENSEARCH_URL to a host-reachable endpoint and we'll use
# that instead — useful if you've exposed 9200 or run OpenSearch outside
# compose. A *plaintext* OPENSEARCH_URL is refused on a TLS install rather than
# silently producing the blind run this fix exists to kill.
#
# Idempotent: re-running is safe (PUT _index_template just overwrites).
#
# USAGE
#   scripts/bootstrap-opensearch.sh            apply every declared template
#   scripts/bootstrap-opensearch.sh --verify   READ-ONLY audit; writes nothing.
#       Answers the two questions an upgraded stack gets wrong:
#         (a) is every index pattern vector-router SINKS TO covered by
#             svc_router's `netops_writer` role? (an uncovered lane 403s on
#             `indices:admin/create` and Vector DROPS the batch — the
#             2026-09-03 netops-secfindings defect); and
#         (b) does each declared template actually EXIST in the live cluster?
#       scripts/deploy-qualify.sh's B4 calls exactly this, so the gate and the
#       bootstrap can never disagree about what a healthy lane looks like.

set -euo pipefail

VERIFY=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --verify) VERIFY=1 ;;
        -h|--help)
            sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *)
            echo "FATAL: unknown argument '$1' (try --help)" >&2
            exit 2 ;;
    esac
    shift
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_DIR="$ROOT/deployment/docker"
TEMPLATES="$COMPOSE_DIR/opensearch/index-templates.json"
ENV_FILE="${OS_ENV_FILE:-$COMPOSE_DIR/.env}"

# §16.2: cron/systemd give us `/usr/bin:/bin` only, and this script needs
# docker + python3 by name. The standard directories are APPENDED, not
# prepended: an inherited PATH that deliberately points at a particular docker
# (an operator's wrapper, a test harness's stub) must still win, while a cron
# run with a minimal PATH still finds the tools.
PATH="${PATH:+$PATH:}/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH

for tool in docker python3 curl; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "FATAL: required tool '$tool' is not on PATH ($PATH)" >&2
        exit 1
    }
done

if [[ ! -f "$TEMPLATES" ]]; then
  echo "FATAL: missing $TEMPLATES" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Transport selection: TLS install? host curl? container curl?
# ---------------------------------------------------------------------------
# Detected exactly the way scripts/stack-watchdog.sh detects it — install.py
# appends compose.tls.yml to COMPOSE_FILE when TLS is enabled, and that line in
# the stack's own .env is the only on-disk statement of which variant is
# running. Assuming plaintext is what made this script blind.
TLS=0
if [[ -r "$ENV_FILE" ]] && grep -q '^COMPOSE_FILE=.*compose\.tls\.yml' "$ENV_FILE"; then
    TLS=1
fi

# In-container path: compose.tls.yml mounts data/tls/services/opensearch at
# /usr/share/opensearch/config/tls, and ca.pem lives there.
OS_TLS_URL="${OS_TLS_URL:-https://opensearch:9200}"
OS_TLS_CACERT="${OS_TLS_CACERT:-/usr/share/opensearch/config/tls/ca.pem}"
OS_BOOTSTRAP_PASSWORD="${OS_BOOTSTRAP_PASSWORD:-}"

USE_HOST=0
if [[ -n "${OPENSEARCH_URL:-}" ]]; then
    if [[ $TLS -eq 1 && "$OPENSEARCH_URL" == http://* ]]; then
        # Loud, not silent: this is precisely the combination that produced a
        # 100%-failed run that still looked like it "tried".
        echo "WARNING: OPENSEARCH_URL=$OPENSEARCH_URL is plaintext but this stack runs the TLS variant" >&2
        echo "         (COMPOSE_FILE in $ENV_FILE includes compose.tls.yml)." >&2
        echo "         Ignoring it and using $OS_TLS_URL from inside the container." >&2
    elif curl -sf --max-time 5 "${OPENSEARCH_URL}/_cluster/health" >/dev/null 2>&1; then
        USE_HOST=1
        echo "Using OPENSEARCH_URL=$OPENSEARCH_URL"
    else
        echo "OPENSEARCH_URL set but unreachable from host — falling back to docker exec"
    fi
fi

if [[ $USE_HOST -eq 1 ]]; then
    OS_BASE="$OPENSEARCH_URL"
    MODE="host curl → $OS_BASE"
elif [[ $TLS -eq 1 ]]; then
    OS_BASE="$OS_TLS_URL"
    MODE="docker exec opensearch → $OS_BASE (TLS, CA-verified, svc_bootstrap)"
    OS_BOOTSTRAP_PASSWORD="$(sed -n 's/^OS_BOOTSTRAP_PASSWORD=//p' "$ENV_FILE" | head -1)"
    if [[ -z "$OS_BOOTSTRAP_PASSWORD" ]]; then
        echo "FATAL: this is a TLS install but OS_BOOTSTRAP_PASSWORD is not set in $ENV_FILE." >&2
        echo "       Every template PUT would 401 and the cluster would run with no declared" >&2
        echo "       mappings. Re-run scripts/install.py (it seeds the SEC-008 credentials)." >&2
        exit 1
    fi
    export OS_BOOTSTRAP_PASSWORD
else
    OS_BASE="http://localhost:9200"
    MODE="docker exec opensearch → $OS_BASE (plaintext)"
fi
echo "Transport: $MODE"

# os_curl <curl-args...> — one curl against the cluster. A request body, when
# there is one, arrives on THIS function's stdin (callers pass `-d @-`), which
# keeps template bodies off argv too.
os_curl() {
    if [[ $USE_HOST -eq 1 ]]; then
        curl "$@"
    elif [[ $TLS -eq 1 ]]; then
        # `sh -c 'script' <arg0> <args...>`: the CA path lands in $0 and the
        # curl arguments in "$@", while the password is expanded inside the
        # container from its own environment. Nothing sensitive is on argv.
        docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T \
            --env OS_BOOTSTRAP_PASSWORD opensearch \
            sh -c 'exec curl --cacert "$0" -u "svc_bootstrap:$OS_BOOTSTRAP_PASSWORD" "$@"' \
            "$OS_TLS_CACERT" "$@"
    else
        docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T opensearch curl "$@"
    fi
}

# §8: nothing derived from a response may carry the credential into a log line.
redact() {
    if [[ -n "$OS_BOOTSTRAP_PASSWORD" ]]; then
        printf '%s' "${1//"$OS_BOOTSTRAP_PASSWORD"/***}"
    else
        printf '%s' "$1"
    fi
}

# ---------------------------------------------------------------------------
# Wait for the cluster to answer — AUTHENTICATED on TLS, which proves both the
# listener and the seeded security config (opensearch-security-init) are up.
# This used to fall through silently after 60s and then fail every template
# with a confusing body; a cluster we cannot reach is a hard stop (§16.1).
# ---------------------------------------------------------------------------
# Bounded by construction (§9): attempts x sleep, both overridable so a test
# harness need not burn the full production wait.
READY_ATTEMPTS="${OS_READY_ATTEMPTS:-30}"
READY_SLEEP="${OS_READY_SLEEP:-2}"
echo "Waiting for OpenSearch to respond..."
READY=0
for _ in $(seq 1 "$READY_ATTEMPTS"); do
    if os_curl -sf --max-time 5 "$OS_BASE/_cluster/health" >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep "$READY_SLEEP"
done
if [[ $READY -ne 1 ]]; then
    echo "FATAL: OpenSearch did not answer an authenticated $OS_BASE/_cluster/health within $((READY_ATTEMPTS * READY_SLEEP))s." >&2
    if [[ $TLS -eq 1 ]]; then
        echo "       TLS install: check that the opensearch container is running, that" >&2
        echo "       opensearch-security-init has been applied, and that OS_BOOTSTRAP_PASSWORD" >&2
        echo "       in $ENV_FILE matches the seeded svc_bootstrap credential." >&2
    fi
    echo "       NO templates were applied." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# --verify: READ-ONLY audit. Writes nothing to the cluster.
# ---------------------------------------------------------------------------
if [[ $VERIFY -eq 1 ]]; then
    echo "VERIFY (read-only): router sink lanes vs svc_router's role, and template presence"
    VERIFY_FAIL=0

    # (a) Role coverage. STATIC — the committed vector.yaml and roles.yml are
    # the contract; a lane the router sinks to that netops_writer does not name
    # is write-dead the moment the security plugin is on. Stdlib-only parsing
    # on purpose: PyYAML is not guaranteed on an appliance host, and this must
    # run there.
    LANES=$(python3 - \
        "$COMPOSE_DIR/vector-router/vector.yaml" \
        "$COMPOSE_DIR/vector/vector.yaml" \
        "$COMPOSE_DIR/opensearch/security/roles.yml" <<'PY'
import re, sys

router_p, agg_p, roles_p = sys.argv[1:4]
router = open(router_p).read()
agg = open(agg_p).read()
roles = open(roles_p).read()

# The sinks: block only — a transform may mention an index name in a comment.
sinks = router.split("\nsinks:\n", 1)
if len(sinks) != 2:
    sys.exit("could not locate the sinks: block in %s" % router_p)
sinks = re.split(r"\n(?=\S)", sinks[1])[0]

# `.log_index_base = "applogs" | "platformlogs"` is set by the AGGREGATOR; the
# router only defaults it. Both files are read so a new base cannot appear in
# one and be missed here.
bases = set(re.findall(r'\.log_index_base\s*=\s*"([a-z0-9_]+)"', agg + router))

patterns = set()
for raw in re.findall(r'^\s*index:\s*"([^"]+)"', sinks, re.M):
    if not raw.startswith("netops-"):
        sys.exit("router sink index %r does not start with netops-" % raw)
    seg = raw.split("-")[1]
    m = re.fullmatch(r"\{\{\s*([a-z_]+)\s*\}\}", seg)
    if m is None:
        patterns.add("netops-%s-*" % seg)
    elif m.group(1) == "log_index_base":
        if not bases:
            sys.exit("index %r is templated on log_index_base but no base value was found" % raw)
        for b in bases:
            patterns.add("netops-%s-*" % b)
    else:
        sys.exit("unhandled index template variable %r in %r" % (m.group(1), raw))

# netops_writer's index_patterns list, without PyYAML.
block = re.search(r"\nnetops_writer:\n(.*?)(?=\n[A-Za-z_][A-Za-z0-9_]*:\n)", roles, re.S)
if not block:
    sys.exit("netops_writer role not found in %s" % roles_p)
ip = re.search(r"\n    - index_patterns:\n(.*?)\n      allowed_actions:", block.group(1), re.S)
if not ip:
    sys.exit("netops_writer has no index_patterns block")
allowed = set(re.findall(r'^\s*-\s*"([^"]+)"', ip.group(1), re.M))

for p in sorted(patterns):
    print(("COVERED  " if p in allowed else "UNCOVERED") + " " + p)
PY
    ) || {
        echo "FATAL: could not derive the router's sink lanes — refusing to report a verdict" >&2
        exit 1
    }
    printf '%s\n' "$LANES" | sed 's/^/  role: /'
    if printf '%s\n' "$LANES" | grep -q '^UNCOVERED'; then
        echo "!! at least one router sink lane is NOT writable by svc_router (netops_writer)." >&2
        echo "   Every bulk write to it 403s on indices:admin/create and Vector DROPS the batch." >&2
        echo "   Add the pattern to deployment/docker/opensearch/security/roles.yml and re-apply" >&2
        echo "   the opensearch-security-init one-shot." >&2
        VERIFY_FAIL=1
    fi

    # (b) Template presence in the LIVE cluster.
    for name in $(python3 -c "
import json
print(' '.join(k for k in json.load(open('$TEMPLATES'))['templates']))
"); do
        set +e
        resp=$(os_curl -s --max-time 15 "$OS_BASE/_index_template/$name" 2>&1)
        rc=$?
        set -e
        resp="$(redact "$resp")"
        if [[ $rc -eq 0 && "$resp" == *"\"name\":\"$name\""* ]]; then
            echo "  template: PRESENT $name"
        else
            echo "  template: MISSING $name — $(printf '%s' "$resp" | tr '\n' ' ' | cut -c1-160)" >&2
            VERIFY_FAIL=1
        fi
    done

    if [[ $VERIFY_FAIL -ne 0 ]]; then
        echo "VERIFY FAILED — see the lines above." >&2
        exit 1
    fi
    echo "VERIFY OK — every router sink lane is writable and every template is installed."
    exit 0
fi

# Apply each template.
#
# F-06/F-15/F-53 (2026-07-21): this list used to be HARD-CODED to the three
# original lanes, so adding a template to index-templates.json silently did
# nothing — which is how snmptrap and cloudlogs ended up 100% dynamically
# mapped (and snmptrap permanently yellow) while a template file sat in the
# repo looking authoritative. Enumerate the file instead: the JSON is the
# single source of truth for which lanes have a declared schema.
TEMPLATE_NAMES=$(python3 -c "
import json
print(' '.join(k for k in json.load(open('$TEMPLATES'))['templates']))
")
echo "Templates declared in index-templates.json: $TEMPLATE_NAMES"

APPLIED=()
FAILED_NAMES=()

for name in $TEMPLATE_NAMES; do
    # Strip _-prefixed documentation keys: OpenSearch's _index_template parser
    # rejects unknown fields outright (400 x_content_parse_exception), and the
    # old `curl -sf` swallowed that into an empty response — a template could
    # fail to apply while the script printed nothing and exited 0.
    # Strip _-prefixed docs keys AND resolve the ${OPENSEARCH_REPLICAS}
    # placeholder (F-07). The replica count is a per-install posture, not a
    # constant: 0 on the single-node appliance (a replica can never be assigned
    # there — that is F-53's permanently-yellow cluster), >= 1 on a real
    # cluster, where 0 replicas plus no snapshot repository (F-59) means one
    # corrupt shard is unrecoverable loss. It is substituted as an INT, because
    # a quoted "0" is accepted by OpenSearch but then compares unequal to the
    # int in every settings diff an operator will later run.
    body=$(OPENSEARCH_REPLICAS="${OPENSEARCH_REPLICAS:-0}" python3 -c "
import json, os, sys

replicas = os.environ['OPENSEARCH_REPLICAS']
try:
    replicas = int(replicas)
except ValueError:
    sys.exit('OPENSEARCH_REPLICAS must be an integer, got %r' % replicas)

d = json.load(open('$TEMPLATES'))
t = {k: v for k, v in d['templates']['$name'].items() if not k.startswith('_')}


def resolve(node):
    if isinstance(node, dict):
        return {k: resolve(v) for k, v in node.items()}
    if isinstance(node, list):
        return [resolve(v) for v in node]
    if node == '\${OPENSEARCH_REPLICAS}':
        return replicas
    if isinstance(node, str) and '\${' in node:
        # Fail loudly on an unresolved placeholder rather than PUTting the
        # literal string: OpenSearch would accept some of them as settings
        # values and the template would be quietly wrong.
        sys.exit('unresolved placeholder in template: %r' % node)
    return node


print(json.dumps(resolve(t)))
")
    echo "→ Applying template: $name"

    # `set +e` around the call, not `|| true`: we WANT curl's exit status and
    # its body, and a command substitution under `set -e` would abort the run
    # before we could report which template failed.
    set +e
    resp=$(printf '%s' "$body" | os_curl -s --max-time 30 -X PUT \
        "$OS_BASE/_index_template/$name" \
        -H 'Content-Type: application/json' -d @- 2>&1)
    rc=$?
    set -e
    resp="$(redact "$resp")"
    [[ $rc -ne 0 ]] && resp="$resp (curl/exec exit=$rc)"

    # Try to pretty-print as JSON; fall back to raw on parse error.
    echo "$resp" | python3 -m json.tool 2>/dev/null || echo "$resp"
    case "$resp" in
      *'"acknowledged":true'*|*'"acknowledged": true'*)
        APPLIED+=("$name") ;;
      *)
        echo "!! template $name was NOT applied — see the response above" >&2
        FAILED_NAMES+=("$name") ;;
    esac
    echo
done

# Name what actually landed. "Done." on its own has hidden a fully-failed run.
echo "APPLIED  (${#APPLIED[@]}): ${APPLIED[*]:-<none>}"
echo "FAILED   (${#FAILED_NAMES[@]}): ${FAILED_NAMES[*]:-<none>}"

if [[ ${#FAILED_NAMES[@]} -ne 0 ]]; then
  echo "One or more templates FAILED to apply." >&2
  exit 1
fi
echo "Done."
