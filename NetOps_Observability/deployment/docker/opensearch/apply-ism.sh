#!/bin/sh
# apply-ism.sh — install an OpenSearch ISM (Index State Management) retention
# policy that deletes the netops time-series indices once they age past the
# retention window. Without this, daily log/flow indices grow until they fill
# the disk and trip OpenSearch's flood watermark (read-only) — the #1 thing that
# ends a multi-day run. Run once by the opensearch-init container after the
# cluster is healthy. Idempotent (PUT replaces; add is best-effort).
set -eu

OS="${OPENSEARCH_URL:-http://opensearch:9200}"
DAYS="${OPENSEARCH_LOG_RETENTION_DAYS:-14}"
REPLICAS="${OPENSEARCH_REPLICAS:-0}"
SNAP_KEEP="${OPENSEARCH_SNAPSHOT_KEEP:-14}"
# F-53 (2026-07-21): this list covered 3 of the 6 log lanes. netops-snmptrap-*
# and netops-cloudlogs-* matched NO ism_template, so `_ism/explain` reported
# policy None and those indices were NEVER DELETED — unbounded growth on the
# lane with the widest, most vendor-controlled schema, on a filesystem that has
# already hit NOT_ENOUGH_SPACE once (F-55). Dead-letter is included too: it is
# tiny by construction but "tiny by construction" is exactly the assumption that
# stops being true during the incident you wrote it for.
PATTERNS='["netops-applogs-*","netops-platformlogs-*","netops-syslog-*","netops-flows-*","netops-snmptrap-*","netops-cloudlogs-*","netops-deadletter-*"]'
ADD_PATTERNS='netops-applogs-*,netops-platformlogs-*,netops-syslog-*,netops-flows-*,netops-snmptrap-*,netops-cloudlogs-*,netops-deadletter-*'

echo "ism: waiting for OpenSearch at $OS ..."
until curl -sf "$OS/_cluster/health" >/dev/null 2>&1; do sleep 5; done

# ---------------------------------------------------------------------------
# F-54: single-node shard hygiene, applied BEFORE the retention policy so the
# history indices this very plugin creates are born with 0 replicas.
#
# The cluster ran permanently YELLOW with 35 UNASSIGNED shards — 33 of them the
# ISM plugin's OWN audit-history indices (.opendistro-ism-managed-index-history-*),
# which roll daily, default to 1 replica, and are managed by no policy. On a
# single-node cluster a replica can never be assigned, so every one of those
# indices is born yellow. Yellow then stops meaning anything, and the real
# yellow (F-53's snmptrap) hid inside the noise for weeks.
#
# These are DYNAMIC cluster settings — no restart, no data movement. Note the
# setting is rollover_RETENTION_period (default 30d, which is why 33 daily
# history indices had accumulated); `retention_period` is not a real setting and
# a typo here 400s the WHOLE request, so keep this list verified against
# GET _cluster/settings?include_defaults=true.
#
# F-07 (2026-07-22): the replica count is now a POSTURE (OPENSEARCH_REPLICAS),
# not a hardcoded 0. This block used to force 0 unconditionally, which meant an
# operator who set replicas > 1 in the index templates got them silently reset
# on every boot — the template said one thing and the running cluster another.
# The plugin's OWN history indices stay at 0 regardless: they are disposable
# audit trails, and they are what created the 33 permanently-unassigned shards.
echo "ism: pinning ISM history shard settings (replicas 0, 7d retention) ..."
curl -s -X PUT "$OS/_cluster/settings" -H 'Content-Type: application/json' -d '{
  "persistent": {
    "plugins.index_state_management.history.number_of_replicas": "0",
    "plugins.index_state_management.history.number_of_shards": "1",
    "plugins.index_state_management.history.rollover_check_period": "12h",
    "plugins.index_state_management.history.rollover_retention_period": "7d"
  }
}' | grep -q '"acknowledged":true' || echo "ism: WARNING cluster-settings PUT was rejected"

# Guard the posture against the cluster it is applied to: asking a single-node
# cluster for replicas is how F-53 happened (an UNASSIGNED replica that can
# never be assigned, a permanently yellow cluster, and "yellow" destroyed as an
# alarm signal). Refuse the impossible value LOUDLY instead of half-applying it.
DATA_NODES=$(curl -s "$OS/_cluster/health" 2>/dev/null |
  sed -n 's/.*"number_of_data_nodes"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' | head -1)
DATA_NODES="${DATA_NODES:-1}"
if [ "$REPLICAS" -gt 0 ] && [ "$REPLICAS" -ge "$DATA_NODES" ]; then
  echo "ism: WARNING OPENSEARCH_REPLICAS=$REPLICAS but the cluster has $DATA_NODES data node(s)." >&2
  echo "ism:         Every replica would sit UNASSIGNED and pin the cluster YELLOW forever." >&2
  echo "ism:         Clamping to $((DATA_NODES - 1)). Fix OPENSEARCH_REPLICAS or add nodes." >&2
  REPLICAS=$((DATA_NODES - 1))
fi

# Apply the posture to the indices that ALREADY exist. Template changes only
# affect indices created afterwards, so without this an operator who raises
# OPENSEARCH_REPLICAS sees nothing change for a full retention window and
# reasonably concludes the setting works. Idempotent; a no-match is fine.
echo "ism: applying number_of_replicas=$REPLICAS to existing netops-* indices ..."
curl -sf -X PUT "$OS/netops-*/_settings" \
  -H 'Content-Type: application/json' \
  -d "{\"index\":{\"number_of_replicas\":$REPLICAS}}" >/dev/null 2>&1 ||
  echo "ism: (no netops-* indices yet — nothing to re-settle)"

# The plugin-owned system indices (alerting-alert-history, alerting-alerts,
# ism-config, job-scheduler-lock) all default to 1 replica and are all
# permanently yellow on a single-node cluster for the same reason. They hold no
# customer data, so they are pinned to 0 independently of the posture above.
for pat in '.opendistro-*' '.opensearch-*'; do
  curl -sf -X PUT "$OS/$pat/_settings?expand_wildcards=all" \
    -H 'Content-Type: application/json' \
    -d '{"index":{"number_of_replicas":0}}' >/dev/null 2>&1 || true
done

echo "ism: installing retention policy (delete after ${DAYS}d) ..."

# The header comment used to claim "Idempotent (PUT replaces)". It is not:
# once the policy exists, a bare PUT returns 409 version_conflict and the
# policy is left at its OLD definition. That is how the ism_template patterns
# could stay stuck at 3 lanes while this file said 6 — the classic "the fix is
# in the repo but not in the system" shape (cf. F-51). An UPDATE requires the
# current seq_no/primary_term, so read them first and pass them through.
SEQ=$(curl -s "$OS/_plugins/_ism/policies/netops-retention" 2>/dev/null |
      sed -n 's/.*"_seq_no"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' | head -1)
PTERM=$(curl -s "$OS/_plugins/_ism/policies/netops-retention" 2>/dev/null |
      sed -n 's/.*"_primary_term"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' | head -1)
if [ -n "${SEQ:-}" ] && [ -n "${PTERM:-}" ]; then
  PUT_URL="$OS/_plugins/_ism/policies/netops-retention?if_seq_no=${SEQ}&if_primary_term=${PTERM}"
  echo "ism: policy exists (seq_no=$SEQ) — updating in place"
else
  PUT_URL="$OS/_plugins/_ism/policies/netops-retention"
fi

POLICY_RESP=$(curl -s -X PUT "$PUT_URL" \
  -H 'Content-Type: application/json' -d @- <<JSON
{
  "policy": {
    "description": "Delete netops time-series indices after ${DAYS} days.",
    "default_state": "hot",
    "states": [
      { "name": "hot", "actions": [],
        "transitions": [ { "state_name": "delete", "conditions": { "min_index_age": "${DAYS}d" } } ] },
      { "name": "delete", "actions": [ { "delete": {} } ], "transitions": [] }
    ],
    "ism_template": [ { "index_patterns": ${PATTERNS}, "priority": 1 } ]
  }
}
JSON
)
case "$POLICY_RESP" in
  *'"_id":"netops-retention"'*) echo "ism: policy written." ;;
  *) echo "ism: WARNING policy PUT did not take: $POLICY_RESP" >&2 ;;
esac

# Attach to any already-existing matching indices (new ones auto-adopt via the
# ism_template above). Best-effort — a no-match is fine on a fresh stack.
curl -s -X POST "$OS/_plugins/_ism/add/$ADD_PATTERNS" \
  -H 'Content-Type: application/json' -d '{"policy_id":"netops-retention"}' >/dev/null 2>&1 || true

echo "ism: retention policy applied — netops-* indices delete after ${DAYS}d."

# ---------------------------------------------------------------------------
# F-59 — SNAPSHOTS. `GET _snapshot` returned `{}` on the live stack: no
# repository was registered, so there was NO backup of any search index, ever.
# Together with F-07's zero replicas that is no redundancy at either layer —
# a single corrupt shard, or a lost data/ directory, is permanent loss of every
# log, trap and flow the platform has ever indexed.
#
# rsync-ing data/opensearch while the cluster is running (what backup.sh did)
# produces a TORN copy: Lucene segment files are being written underneath it.
# A snapshot is the only consistent backup OpenSearch has, and it is
# incremental, so a daily one costs roughly the day's new segments.
#
# The repository is `fs` at path.repo (declared on the opensearch service in
# docker-compose.yml — a repo cannot be registered without it). Its directory
# lives OUTSIDE data/opensearch on purpose: a backup stored inside the thing it
# backs up is not a backup. Ship data/opensearch-snapshots off-host to finish
# the job — see docs/runbooks/backup-restore.md.
# ---------------------------------------------------------------------------
if [ "${SNAP_KEEP:-14}" -gt 0 ]; then
  echo "ism: registering snapshot repository netops-fs ..."
  REPO_RESP=$(curl -s -X PUT "$OS/_snapshot/netops-fs" \
    -H 'Content-Type: application/json' \
    -d '{"type":"fs","settings":{"location":"/usr/share/opensearch/snapshots","compress":true}}')
  case "$REPO_RESP" in
    *'"acknowledged":true'*) echo "ism: snapshot repository ready." ;;
    *)
      # Do NOT swallow this. A stack that believes it has backups and does not
      # is strictly worse than one that knows it has none.
      echo "ism: ERROR snapshot repository NOT registered: $REPO_RESP" >&2
      echo "ism:       -> there is currently NO backup of the search tier." >&2
      echo "ism:       Check that path.repo is set on the opensearch service and" >&2
      echo "ism:       that data/opensearch-snapshots is writable by the container." >&2
      ;;
  esac

  # Snapshot Management policy: one snapshot a day, keep SNAP_KEEP of them.
  # PUT is create-only (409 if it exists) like the ISM policy above, so read
  # the seq_no first and update in place — the same trap that let the ism
  # patterns stay stuck at three lanes while this file claimed six.
  SM_SEQ=$(curl -s "$OS/_plugins/_sm/policies/netops-daily" 2>/dev/null |
        sed -n 's/.*"_seq_no"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' | head -1)
  SM_TERM=$(curl -s "$OS/_plugins/_sm/policies/netops-daily" 2>/dev/null |
        sed -n 's/.*"_primary_term"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' | head -1)
  if [ -n "${SM_SEQ:-}" ] && [ -n "${SM_TERM:-}" ]; then
    SM_URL="$OS/_plugins/_sm/policies/netops-daily?if_seq_no=${SM_SEQ}&if_primary_term=${SM_TERM}"
  else
    SM_URL="$OS/_plugins/_sm/policies/netops-daily"
  fi
  SM_RESP=$(curl -s -X PUT "$SM_URL" -H 'Content-Type: application/json' -d @- <<JSON
{
  "description": "Daily snapshot of netops-* to the netops-fs repository (F-59).",
  "creation": {
    "schedule": { "cron": { "expression": "30 1 * * *", "timezone": "UTC" } },
    "time_limit": "2h"
  },
  "deletion": {
    "schedule": { "cron": { "expression": "0 3 * * *", "timezone": "UTC" } },
    "condition": { "max_count": ${SNAP_KEEP} }
  },
  "snapshot_config": {
    "repository": "netops-fs",
    "indices": "netops-*",
    "ignore_unavailable": true,
    "include_global_state": false
  }
}
JSON
)
  case "$SM_RESP" in
    *'"netops-daily"'*) echo "ism: snapshot policy netops-daily installed (daily 01:30 UTC, keep ${SNAP_KEEP})." ;;
    *) echo "ism: WARNING snapshot policy NOT installed: $SM_RESP" >&2 ;;
  esac
else
  echo "ism: OPENSEARCH_SNAPSHOT_KEEP=0 — snapshots DISABLED. The search tier has no backup." >&2
fi

# Report coverage instead of asserting it. A lane with policy "null" here is a
# lane that will grow forever; print it so the boot log carries the evidence.
echo "ism: coverage check —"
curl -s "$OS/_plugins/_ism/explain/netops-*" 2>/dev/null | python3 -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
missing=[k for k,v in d.items() if isinstance(v,dict) and not v.get("index.plugins.index_state_management.policy_id")]
for k in sorted(missing): print("  ism: NO POLICY ->",k)
print("  ism: %d/%d netops indices managed" % (len([k for k,v in d.items() if isinstance(v,dict)])-len(missing),
                                               len([k for k,v in d.items() if isinstance(v,dict)])))
' 2>/dev/null || true
