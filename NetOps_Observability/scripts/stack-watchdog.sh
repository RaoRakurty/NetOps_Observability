#!/usr/bin/env bash
#
# NetOps stack watchdog.
#
# Runs from cron once a minute. Verifies every compose service is running
# (and healthy, where a healthcheck exists) and that the dashboard answers
# on :8000. Then:
#
#   * Healthy   -> pings the healthchecks.io heartbeat URL. If this host or
#                  its network dies, the pings stop and healthchecks.io
#                  (off-host) alerts you — the dead-man's-switch.
#   * Down      -> hits the healthchecks.io /fail endpoint AND pushes an
#                  ntfy.sh notification to your phone naming the dead service.
#
# Alerts fire only on a state TRANSITION (up->down, down->up), so a sustained
# outage produces one push, not one per minute.
#
# Config (NTFY_TOPIC, HC_PING_URL, ...) lives in stack-watchdog.env next to
# this script — see stack-watchdog.env.example. No secrets are baked in here.

set -uo pipefail
export PATH="/usr/local/bin:/usr/bin:/bin:${PATH:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${WATCHDOG_ENV:-$SCRIPT_DIR/stack-watchdog.env}"
STATE_FILE="${WATCHDOG_STATE:-$SCRIPT_DIR/.stack-watchdog.state}"

# shellcheck disable=SC1090
[ -f "$ENV_FILE" ] && { set -a; . "$ENV_FILE"; set +a; }

PROJECT="${COMPOSE_PROJECT:-netops}"
APP_URL="${APP_URL:-http://localhost:8000/}"
NTFY_SERVER="${NTFY_SERVER:-https://ntfy.sh}"

# NOTE: telegraf is intentionally absent — it was retired (legacy compose
# profile, not started by default; Go collector owns SNMP). Re-adding it here
# would false-alarm every minute. gnmic is the gNMI collector if profiled in.
# vmalert is in this list on purpose (F-16): it is the stack's ONLY standing
# metric-alerting engine, so if it dies every metric-based alert silently stops
# and nothing else would notice. cadvisor/node-exporter/grafana/kafka-exporter
# stay out — they belong to the optional self-monitoring profile.
EXPECTED_SERVICES="api clickhouse correlation frontend goflow2 grafana kafka \
nginx opensearch opensearch-dashboards postgres prober redis \
syslog-ng vector-aggregator vector-router victoria vmalert"

push() {  # title, tags, priority, body
  [ -n "${NTFY_TOPIC:-}" ] || return 0
  curl -fsS -m 10 \
    -H "Title: $1" -H "Tags: $2" -H "Priority: $3" \
    -d "$4" "$NTFY_SERVER/$NTFY_TOPIC" -o /dev/null \
    || echo "watchdog: ntfy push failed" >&2
}

# --test sends one push so you can confirm your phone is subscribed, then exits.
if [ "${1:-}" = "--test" ]; then
  push "NetOps watchdog test" "test_tube" "default" \
    "Test alert from $(hostname) at $(date -Is). If you see this, alerting works."
  echo "Sent test push to topic '${NTFY_TOPIC:-<unset>}' on $NTFY_SERVER"
  exit 0
fi

problems=()

for svc in $EXPECTED_SERVICES; do
  cid=$(docker ps -q \
    --filter "label=com.docker.compose.project=$PROJECT" \
    --filter "label=com.docker.compose.service=$svc" 2>/dev/null)
  if [ -z "$cid" ]; then
    problems+=("$svc: not running")
    continue
  fi
  state=$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null)
  if [ "$state" != "running" ]; then
    problems+=("$svc: state=$state")
    continue
  fi
  health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$cid" 2>/dev/null)
  if [ -n "$health" ] && [ "$health" != "healthy" ]; then
    problems+=("$svc: health=$health")
  fi
done

# Container OOM / restart detection (#102 signoff): cadvisor's per-container
# metrics are dark under docker's containerd image store, so the in-platform
# ContainerOOMKilled alert cannot fire — THIS is the container-OOM sentinel.
# Any OOM-kill under restart:unless-stopped shows up as a RestartCount bump;
# OOMKilled=true is captured directly for containers sitting dead. One push
# per new event (count-delta keyed), distinct from the up/down state machine.
RESTART_STATE="${WATCHDOG_RESTARTS:-$SCRIPT_DIR/.stack-watchdog.restarts}"
touch "$RESTART_STATE" 2>/dev/null || true
oom_events=()
new_restart_state=""
for svc in $EXPECTED_SERVICES; do
  cid=$(docker ps -aq \
    --filter "label=com.docker.compose.project=$PROJECT" \
    --filter "label=com.docker.compose.service=$svc" 2>/dev/null | head -1)
  [ -n "$cid" ] || continue
  read -r rcount oomed exitcode <<<"$(docker inspect -f '{{.RestartCount}} {{.State.OOMKilled}} {{.State.ExitCode}}' "$cid" 2>/dev/null)"
  [ -n "${rcount:-}" ] || continue
  prev=$(awk -v s="$svc" '$1==s{print $2}' "$RESTART_STATE" 2>/dev/null)
  new_restart_state+="$svc ${rcount}"$'\n'
  if [ -n "$prev" ] && [ "$rcount" -gt "$prev" ] 2>/dev/null; then
    if [ "$oomed" = "true" ] || [ "${exitcode:-0}" = "137" ]; then
      oom_events+=("$svc: OOM-KILLED by its cgroup limit (restarts $prev->$rcount) — compare its resource-plan limit vs usage, then --replan")
    else
      oom_events+=("$svc: restarted (${prev}->${rcount}, exit ${exitcode:-?}) — check 'docker logs' / dmesg for OOM")
    fi
  elif [ "$oomed" = "true" ] && [ -z "$prev" ]; then
    oom_events+=("$svc: sitting OOM-killed (exit ${exitcode:-?})")
  fi
done
printf '%s' "$new_restart_state" > "$RESTART_STATE" 2>/dev/null || true
if [ "${#oom_events[@]}" -gt 0 ]; then
  push "🔥 NetOps container OOM/restart on $(hostname)" "fire" "high" \
    "$(printf '%s\n' "${oom_events[@]}")"
fi

# End-to-end probe: the dashboard must answer through nginx.
code=$(curl -s -o /dev/null -w '%{http_code}' -m 10 "$APP_URL" 2>/dev/null)
case "$code" in
  200|301|302|401) ;;                               # served (401 = auth on / is fine)
  *) problems+=("dashboard $APP_URL: HTTP ${code:-no-response}") ;;
esac

# Disk watermark — the cause of the silent log-ingest outage: OpenSearch sets
# EVERY index read-only at its 95% flood stage, and ingestion stops with no
# error. Warn well before that; auto-prune reclaimable Docker build cache (the
# usual filler on a dev/build host) when it crosses the higher mark.
disk_pct=$(df --output=pcent / 2>/dev/null | tail -1 | tr -dc '0-9')
if [ -n "$disk_pct" ] && [ "$disk_pct" -ge "${DISK_WARN_PCT:-85}" ]; then
  if [ "$disk_pct" -ge "${DISK_PRUNE_PCT:-90}" ]; then
    docker builder prune -f >/dev/null 2>&1 || true
    disk_pct=$(df --output=pcent / 2>/dev/null | tail -1 | tr -dc '0-9')
  fi
  [ "$disk_pct" -ge "${DISK_WARN_PCT:-85}" ] &&
    problems+=("disk ${disk_pct}% (warn ${DISK_WARN_PCT:-85}%; OpenSearch flood-stage read-only at 95%)")
fi

# Docker-hygiene cron health (#100 contributing noise): the weekly prune cron
# silently failed for days (lost exec bit → 'Permission denied' in its log) and
# the resulting debris drove the disk warning DURING the incident, muddying
# diagnosis. Fail loudly instead: the hygiene log must exist, be fresher than
# ~8 days (weekly cron + slack), and its last run must not be an error.
hyg_log="$(dirname "${BASH_SOURCE[0]}")/docker-hygiene.log"
if [ -f "$hyg_log" ]; then
  hyg_age_days=$(( ($(date +%s) - $(stat -c %Y "$hyg_log" 2>/dev/null || echo 0)) / 86400 ))
  if [ "$hyg_age_days" -gt "${HYGIENE_MAX_AGE_DAYS:-8}" ]; then
    problems+=("docker-hygiene cron stale: log ${hyg_age_days}d old (weekly cron dead? check crontab + exec bit)")
  elif tail -3 "$hyg_log" 2>/dev/null | grep -qiE 'permission denied|not found|cannot'; then
    problems+=("docker-hygiene cron failing: $(tail -1 "$hyg_log" | cut -c1-80)")
  fi
fi

# host-hygiene (10-min threshold sweeper + OpenSearch block healer) must be
# alive for the same reason: a dead hygiene cron is invisible until the next
# disk-full outage. Quiet runs append nothing, so track a heartbeat marker the
# script's cron line touches — the log alone can legitimately stay silent.
hh_beat="$(dirname "${BASH_SOURCE[0]}")/.host-hygiene.heartbeat"
if [ -f "$hh_beat" ]; then
  hh_age_min=$(( ($(date +%s) - $(stat -c %Y "$hh_beat" 2>/dev/null || echo 0)) / 60 ))
  [ "$hh_age_min" -gt "${HOST_HYGIENE_MAX_AGE_MIN:-45}" ] &&
    problems+=("host-hygiene cron stale: heartbeat ${hh_age_min}m old (10-min cron dead? disk-full protection is OFF)")
fi

# Ingestion liveness — a pipeline that stops silently is invisible until someone
# looks at an empty dashboard. Container logs (applogs) flow continuously, so
# zero docs in the recent window means the log bus stalled (disk block, dead
# Vector/Kafka consumer). Counts via the opensearch container (not host-exposed).
os_cid=$(docker ps -q --filter "label=com.docker.compose.project=$PROJECT" \
  --filter "label=com.docker.compose.service=opensearch" 2>/dev/null)
if [ -n "$os_cid" ]; then
  stale_min="${INGEST_STALE_MIN:-15}"

  os_count() {  # $1 = gte, $2 = lt  -> doc count in that window
    docker exec "$os_cid" curl -s -m 5 \
      "http://localhost:9200/netops-applogs-*/_count" -H 'Content-Type: application/json' \
      -d "{\"query\":{\"range\":{\"timestamp\":{\"gte\":\"$1\",\"lt\":\"$2\"}}}}" 2>/dev/null |
      grep -oE '"count":[0-9]+' | grep -oE '[0-9]+'
  }

  cnt=$(os_count "now-${stale_min}m" "now")
  if [ -n "$cnt" ] && [ "$cnt" -eq 0 ]; then
    problems+=("log ingest stalled: 0 applogs in last ${stale_min}m (Vector/disk/consumer?)")
  fi

  # ---------------------------------------------------------------------------
  # F-19: PARTIAL loss. The check above is `== 0`, which only ever sees a TOTAL
  # stall. Through the entire measured 2026-07-21 incident the count was
  # ~14,000/h and this watchdog reported GREEN while ~4,390 documents/day were
  # being destroyed. A zero-test cannot tell "ingesting correctly" apart from
  # "ingesting with a 5% hole", and the hole is the failure mode that actually
  # happens.
  #
  # Compare the recent window against the 4 windows before it (its own trailing
  # baseline — no external state file, no cold-start problem). Only judge when
  # the baseline is meaningful: on a genuinely idle stack the ratio is noise,
  # and an alert nobody trusts is worse than no alert.
  # ---------------------------------------------------------------------------
  base_win=$(( stale_min * 4 ))
  base_cnt=$(os_count "now-$(( base_win + stale_min ))m" "now-${stale_min}m")
  if [ -n "${cnt:-}" ] && [ -n "${base_cnt:-}" ] && [ "$base_cnt" -gt 0 ]; then
    base_rate=$(( base_cnt / 4 ))                      # per stale_min window
    min_base="${INGEST_MIN_BASELINE:-200}"
    pct="${INGEST_DEGRADE_PCT:-50}"                    # fire under N% of baseline
    if [ "$base_rate" -ge "$min_base" ] && [ "$cnt" -lt $(( base_rate * pct / 100 )) ]; then
      problems+=("log ingest DEGRADED: ${cnt} applogs in ${stale_min}m vs baseline ${base_rate} (<${pct}%) — partial loss, not a stall")
    fi
  fi

  # ---------------------------------------------------------------------------
  # F-17: per-document rejection. OpenSearch's obvious counter LIES here —
  # `index_failed` read 0 while 1,127 documents were being discarded, because
  # bulk rejections are PER ITEM and index_failed only counts whole-request
  # failures. doc_status.4xx is the counter that moves. Tracked as a delta
  # against the previous run so a standing historical total does not alarm
  # forever; a reset (OpenSearch restart) yields a negative delta and is
  # ignored.
  # ---------------------------------------------------------------------------
  REJ_STATE="${WATCHDOG_REJECTS:-$SCRIPT_DIR/.stack-watchdog.rejects}"
  rej_now=$(docker exec "$os_cid" curl -s -m 5 \
    "http://localhost:9200/_nodes/stats/indices/indexing" 2>/dev/null |
    tr ',' '\n' | grep -oE '"4xx"[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+$' | head -1)
  if [ -n "${rej_now:-}" ]; then
    rej_prev=$(cat "$REJ_STATE" 2>/dev/null || echo "")
    if [ -n "$rej_prev" ] && [ "$rej_now" -gt "$rej_prev" ]; then
      problems+=("OpenSearch REJECTED $(( rej_now - rej_prev )) documents since last check — permanent loss (mapping/field-limit; index_failed will read ~0, ignore it)")
    fi
    echo "$rej_now" > "$REJ_STATE" 2>/dev/null || true
  fi

  # Cluster status. This only became a usable signal on 2026-07-21: previously
  # 35 shards were permanently unassignable (no index template on the snmptrap
  # lane + unmanaged ISM history indices, both defaulting to 1 replica on a
  # SINGLE-node cluster), so the cluster was always yellow and yellow meant
  # nothing. Replicas are pinned to 0 now, so a departure from green is real.
  os_status=$(docker exec "$os_cid" curl -s -m 5 "http://localhost:9200/_cluster/health" 2>/dev/null |
    grep -oE '"status"[[:space:]]*:[[:space:]]*"[a-z]+"' | grep -oE '(green|yellow|red)' | head -1)
  case "${os_status:-}" in
    yellow|red) problems+=("OpenSearch cluster is ${os_status} (was pinned green on 2026-07-21 — check for a lane with no index template, i.e. replicas>0)") ;;
  esac

  # ---------------------------------------------------------------------------
  # F-59: BACKUP FRESHNESS — checked here, out of band, on purpose.
  #
  # The 2026-07-21 audit found `GET _snapshot` = {}: no snapshot repository had
  # ever been registered, so nothing had ever backed up a search index. The
  # repository and the daily SM policy exist now (opensearch/apply-ism.sh), but
  # a policy that silently stops running returns the system to exactly the same
  # state — with the added problem that everyone now believes backups exist.
  #
  # This check deliberately does NOT live in rules.yaml. The metrics path runs
  # inside the stack; an alarm about the stack's last line of defence must not
  # share fate with it. Same reasoning that keeps this whole watchdog external.
  #
  # A PARTIAL snapshot is treated as a failure: it means shards were missed, so
  # a restore from it is incomplete — the most dangerous state of the three,
  # because it looks like success in `_cat/snapshots`.
  # ---------------------------------------------------------------------------
  snap_max_age_h="${SNAPSHOT_MAX_AGE_H:-36}"
  if [ "$snap_max_age_h" -gt 0 ]; then
    snap_json=$(docker exec "$os_cid" curl -s -m 10 \
      "http://localhost:9200/_cat/snapshots/netops-fs?h=id,status,end_epoch&format=json" 2>/dev/null)
    case "${snap_json:-}" in
      *repository_missing*|*RepositoryMissingException*)
        problems+=("NO OPENSEARCH BACKUPS: snapshot repository 'netops-fs' is not registered — every search index is unrecoverable if data/ is lost (run docker compose up opensearch-init)") ;;
      "["*)
        # Newest end_epoch across all snapshots; empty list => no snapshot yet.
        snap_last=$(printf '%s' "$snap_json" |
          grep -oE '"end_epoch"[[:space:]]*:[[:space:]]*"?[0-9]+' |
          grep -oE '[0-9]+$' | sort -n | tail -1)
        if [ -z "${snap_last:-}" ]; then
          problems+=("NO OPENSEARCH BACKUPS: repository 'netops-fs' exists but contains ZERO snapshots — the daily policy has never completed")
        else
          snap_age_h=$(( ($(date +%s) - snap_last) / 3600 ))
          [ "$snap_age_h" -gt "$snap_max_age_h" ] &&
            problems+=("OpenSearch backup STALE: newest snapshot is ${snap_age_h}h old (>${snap_max_age_h}h) — the daily snapshot policy has stopped")
        fi
        if printf '%s' "$snap_json" | grep -q '"PARTIAL"'; then
          problems+=("OpenSearch snapshot is PARTIAL — some shards were NOT captured; a restore from it would be incomplete")
        fi
        ;;
    esac
  fi
fi

# -----------------------------------------------------------------------------
# F-51: CONFIG-DRIFT probe.
#
# A single-file bind mount resolves to an INODE. Any editor that writes-then-
# renames (vim, VS Code, sed -i, python atomic writes) produces a NEW inode and
# the mount stays pinned to the OLD one forever — so `docker compose restart`
# re-runs the container against a stale file and the operator sees a fix that
# was never deployed. That is not hypothetical: on 2026-07-21 vector-router ran
# for hours on a config the repo had already replaced (host inode 268641 vs
# container 291584), and nothing anywhere reported it.
#
# The structural fix is directory mounts (done in docker-compose.yml), but the
# failure is invisible and WILL recur the next time someone adds a file mount.
# So verify the claim rather than trusting it: hash the repo file and the
# in-container file and compare. Config drift is the only thing this can report,
# and it reports it before the next incident instead of during it.
# -----------------------------------------------------------------------------
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
drift_check() {  # $1 = compose service, $2 = repo-relative path, $3 = in-container path
  local cid host_sum cont_sum
  cid=$(docker ps -q --filter "label=com.docker.compose.project=$PROJECT" \
                     --filter "label=com.docker.compose.service=$1" 2>/dev/null | head -1)
  [ -n "$cid" ] || return 0
  [ -f "$REPO_ROOT/$2" ] || return 0
  host_sum=$(sha256sum "$REPO_ROOT/$2" 2>/dev/null | cut -d' ' -f1)
  # Hash on the HOST from a streamed `cat`, rather than running sha256sum
  # inside the container. Half these images have no sha256sum (vector, the
  # syslog-ng image), and a missing TOOL produced an empty result that the
  # first version of this check read as "fine" — a drift probe that silently
  # cannot detect drift is precisely the class of defect it exists to catch.
  cont_sum=$(docker exec "$cid" cat "$3" 2>/dev/null | sha256sum 2>/dev/null | cut -d' ' -f1)
  # A MISSING file is not "unknown", it is a broken mount: the service is
  # running on the image's built-in default while the repo believes it is
  # configured. Report it.
  if ! docker exec "$cid" test -f "$3" 2>/dev/null; then
    problems+=("CONFIG MISSING: $1 has no $3 in the container — the bind mount for $2 is not in effect. Fix: docker compose up -d --force-recreate $1")
    return 0
  fi
  # e3b0c442... is the sha256 of empty input, i.e. `cat` produced nothing.
  if [ -z "$cont_sum" ] || [ "$cont_sum" = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ]; then
    problems+=("CONFIG UNVERIFIABLE: could not read $3 from $1 — the drift probe is blind for this service, fix the probe rather than ignoring it")
    return 0
  fi
  if [ "$host_sum" != "$cont_sum" ]; then
    problems+=("CONFIG DRIFT: $1 is running a different $2 than the repo — the container never picked up the edit (stale inode / not recreated). Fix: docker compose up -d --force-recreate $1")
  fi
}
drift_check vector-aggregator deployment/docker/vector/vector.yaml        /etc/vector/conf/vector.yaml
drift_check vector-router     deployment/docker/vector-router/vector.yaml /etc/vector/conf/vector.yaml
drift_check victoria          src/config/vmscrape.yml                     /etc/victoria/config/vmscrape.yml

# ---- BUILD drift: is the deployed BINARY the committed source? -------------
#
# drift_check above covers BIND-MOUNTED config, which updates the instant a
# container restarts. It cannot see the other half: code BAKED INTO AN IMAGE,
# which only changes on `docker compose build`.
#
# That asymmetry is what made F-08 invisible (2026-07-22). The feature's code and
# config were both correct and both committed, but the api image was never
# rebuilt, so it sat built-but-undeployed for weeks while looking complete.
# `docker compose up -d` recreates a container from whatever image already
# exists — it does not rebuild — so "restart the service" silently redeployed old
# code. prober was running a 38-hour-old binary and had been restarted repeatedly
# without ever gaining the fix it needed. Nothing objected, because nothing could
# answer "which commit is actually running?".
#
# Now the binary answers, at /admin/version, and this compares it to HEAD.
build_drift_check() { # $1 service, $2 url
  local running head_sha body
  head_sha=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null)
  [ -n "$head_sha" ] || return 0   # not a git checkout (e.g. an offline bundle)
  body=$(curl -fsS -m 10 "$2" 2>/dev/null) || {
    problems+=("BUILD UNVERIFIABLE: $1 did not answer $2 — the provenance probe is blind, fix the probe rather than ignoring it")
    return 0
  }
  running=$(printf '%s' "$body" | sed -n 's/.*"sha"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  # An UNIDENTIFIED build is a failure, not a pass: a binary that cannot name its
  # revision is exactly the situation this check exists to end.
  if [ -z "$running" ] || [ "$running" = "unknown" ]; then
    problems+=("BUILD UNIDENTIFIED: $1 reports no git SHA — it was built without GIT_SHA. Rebuild with: GIT_SHA=\$(git rev-parse HEAD) docker compose build $1")
    return 0
  fi
  if [ "$running" != "$head_sha" ]; then
    problems+=("BUILD DRIFT: $1 is running ${running:0:8} but HEAD is ${head_sha:0:8} — the deployed image predates the source. Fix: GIT_SHA=\$(git rev-parse HEAD) BUILD_TIME=\$(date -u +%FT%TZ) docker compose build $1 && docker compose up -d $1")
  fi
}
build_drift_check api "${APP_URL%/}/admin/version"
drift_check vmalert           src/config/rules.yaml                       /etc/vmalert/config/rules.yaml
drift_check syslog-ng         deployment/docker/syslog-ng/syslog-ng.conf  /etc/syslog-ng/conf.d/syslog-ng.conf
drift_check nginx             deployment/docker/nginx/default.conf        /etc/nginx/conf.d/default.conf
drift_check nginx             deployment/docker/nginx/nginx.conf          /etc/nginx/nginx.conf

# -----------------------------------------------------------------------------
# F-16: surface what the alerting engine is actually firing.
#
# vmalert evaluates rules.yaml and writes the firing state back into
# VictoriaMetrics as ALERTS series, but nothing DELIVERS them — the stack ships
# no Alertmanager. This watchdog already owns an independent notification path
# (ntfy, deliberately not one of the stack's own notifiers, because a stack
# cannot report its own death), so it is the right place to turn a firing
# critical into a phone push.
#
# Only `critical` severity, and only alerts that have cleared their `for:`
# window, so this cannot become the noise that gets the watchdog muted.
# -----------------------------------------------------------------------------
if [ "${WATCHDOG_REPORT_ALERTS:-1}" = "1" ]; then
  vm_cid=$(docker ps -q --filter "label=com.docker.compose.project=$PROJECT" \
                        --filter "label=com.docker.compose.service=opensearch" 2>/dev/null | head -1)
  if [ -n "$vm_cid" ]; then
    firing=$(docker exec "$vm_cid" curl -s -m 5 -G "http://victoria:8428/api/v1/query" \
      --data-urlencode 'query=ALERTS{alertstate="firing",severity="critical"}' 2>/dev/null |
      grep -oE '"alertname":"[^"]+"' | cut -d'"' -f4 | sort -u | tr '\n' ' ')
    [ -n "${firing// /}" ] && problems+=("vmalert CRITICAL firing: ${firing}")
  fi
fi

prev=$(cat "$STATE_FILE" 2>/dev/null || echo up)
nsvc=$(echo "$EXPECTED_SERVICES" | wc -w | tr -d ' ')

if [ ${#problems[@]} -eq 0 ]; then
  [ -n "${HC_PING_URL:-}" ] && curl -fsS -m 10 "$HC_PING_URL" -o /dev/null
  if [ "$prev" = "down" ]; then
    push "✅ NetOps stack RECOVERED on $(hostname)" "white_check_mark" "default" \
      "All $nsvc services healthy again at $(date -Is)."
  fi
  echo up > "$STATE_FILE"
  exit 0
fi

msg=$(printf '%s\n' "${problems[@]}")
[ -n "${HC_PING_URL:-}" ] && curl -fsS -m 10 --data-raw "$msg" "${HC_PING_URL%/}/fail" -o /dev/null
if [ "$prev" = "up" ]; then
  push "🚨 NetOps stack DOWN on $(hostname)" "rotating_light" "urgent" "$msg"
fi
echo down > "$STATE_FILE"
echo "watchdog: DOWN -> $msg" >&2
exit 1
