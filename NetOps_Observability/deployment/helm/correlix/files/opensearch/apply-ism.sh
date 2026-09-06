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
# netops-secfindings-*: the P3-L1 security findings lane (per-tenant, daily,
# same shape as every lane above). It rides the SHARED netops-retention policy
# and therefore the same OPENSEARCH_LOG_RETENTION_DAYS window on purpose — a
# lane with no ism_template is a lane that grows forever (F-53), and findings
# volume is bounded (a scan emits per-device, not per-packet), so it needs no
# window of its own. Give it a dedicated policy the day compliance-trend
# retention has to outlive telemetry retention, not before.
# security-auditlog-*: the security plugin's own audit trail (SEC-008.1) rolls
# a DAILY index like every lane above and is managed by no other policy —
# without retention it is unbounded growth on the disk-fill path (F-53 class).
PATTERNS='["netops-applogs-*","netops-platformlogs-*","netops-syslog-*","netops-flows-*","netops-snmptrap-*","netops-cloudlogs-*","netops-secfindings-*","netops-deadletter-*","security-auditlog-*"]'
ADD_PATTERNS='netops-applogs-*,netops-platformlogs-*,netops-syslog-*,netops-flows-*,netops-snmptrap-*,netops-cloudlogs-*,netops-secfindings-*,netops-deadletter-*,security-auditlog-*'

# §8: OPENSEARCH_URL carries the bootstrap credential as URL userinfo on a
# secured cluster — strip it before logging (this line used to echo the
# password into the container log on every init run; found 2026-08-05).
OS_REDACTED=$(printf '%s' "$OS" | sed 's#//[^@/]*@#//<redacted>@#')
echo "ism: waiting for OpenSearch at $OS_REDACTED ..."
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

# security-auditlog-* joined the born-yellow class with SEC-008.1: the
# security plugin's audit index rolls daily, matched no template, and pinned
# the cluster yellow the day after the cutover (2026-08-05). Unlike the
# dot-prefixed plugin bookkeeping above it is durable security EVIDENCE, so it
# follows the F-07 replica POSTURE (like the netops lanes), not a hardcoded 0.
# Existing indices first (same shape as the netops-* re-settle above):
curl -sf -X PUT "$OS/security-auditlog-*/_settings" \
  -H 'Content-Type: application/json' \
  -d "{\"index\":{\"number_of_replicas\":$REPLICAS}}" >/dev/null 2>&1 ||
  echo "ism: (no security-auditlog-* indices yet — nothing to re-settle)"

# ...and tomorrow's audit index is born from NO template (it is deliberately
# kept out of index-templates.json — that file declares the LOG-LANE field
# contract, which the plugin's own document shape must not be forced into). A
# settings-only template pins the replica posture at creation so the pin above
# doesn't have to win a daily race against the roll. Checked, not swallowed:
# if this PUT fails, every day re-yellows the cluster and yellow stops meaning
# anything (F-54).
TPL_RESP=$(curl -s -X PUT "$OS/_index_template/security-auditlog" \
  -H 'Content-Type: application/json' -d @- <<JSON
{
  "index_patterns": ["security-auditlog-*"],
  "priority": 10,
  "template": { "settings": { "number_of_shards": 1, "number_of_replicas": ${REPLICAS} } }
}
JSON
)
case "$TPL_RESP" in
  *'"acknowledged":true'*) echo "ism: security-auditlog replica template installed." ;;
  *) echo "ism: WARNING security-auditlog template PUT did not take: $TPL_RESP" >&2 ;;
esac

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
# F-11 seal-or-quarantine: the quarantine index gets its OWN bounded window
# (INV-F11-09 — unattributable payloads must never be retained indefinitely),
# separate from the telemetry window because re-attribution may legitimately
# need longer than the log-retention default. Same seq_no dance as above —
# a bare PUT on an existing policy 409s and silently keeps the OLD window.
QDAYS="${QUARANTINE_RETENTION_DAYS:-30}"
echo "ism: installing quarantine retention policy (delete after ${QDAYS}d) ..."
QSEQ=$(curl -s "$OS/_plugins/_ism/policies/netops-quarantine-retention" 2>/dev/null |
      sed -n 's/.*"_seq_no"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' | head -1)
QPTERM=$(curl -s "$OS/_plugins/_ism/policies/netops-quarantine-retention" 2>/dev/null |
      sed -n 's/.*"_primary_term"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' | head -1)
if [ -n "${QSEQ:-}" ] && [ -n "${QPTERM:-}" ]; then
  QPUT_URL="$OS/_plugins/_ism/policies/netops-quarantine-retention?if_seq_no=${QSEQ}&if_primary_term=${QPTERM}"
  echo "ism: quarantine policy exists (seq_no=$QSEQ) — updating in place"
else
  QPUT_URL="$OS/_plugins/_ism/policies/netops-quarantine-retention"
fi
QPOLICY_RESP=$(curl -s -X PUT "$QPUT_URL" \
  -H 'Content-Type: application/json' -d @- <<JSON
{
  "policy": {
    "description": "F-11: delete unattributed quarantine envelopes after ${QDAYS} days (bounded retention, INV-F11-09).",
    "default_state": "hot",
    "states": [
      { "name": "hot", "actions": [],
        "transitions": [ { "state_name": "delete", "conditions": { "min_index_age": "${QDAYS}d" } } ] },
      { "name": "delete", "actions": [ { "delete": {} } ], "transitions": [] }
    ],
    "ism_template": [ { "index_patterns": ["netops-quarantine-*"], "priority": 5 } ]
  }
}
JSON
)
case "$QPOLICY_RESP" in
  *'"_id":"netops-quarantine-retention"'*) echo "ism: quarantine policy written." ;;
  *) echo "ism: WARNING quarantine policy PUT did not take: $QPOLICY_RESP" >&2 ;;
esac
curl -s -X POST "$OS/_plugins/_ism/add/netops-quarantine-*" \
  -H 'Content-Type: application/json' -d '{"policy_id":"netops-quarantine-retention"}' >/dev/null 2>&1 || true
echo "ism: quarantine retention applied — netops-quarantine-* deletes after ${QDAYS}d."

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
  REPO_LOCATION="/usr/share/opensearch/snapshots"

  # -------------------------------------------------------------------------
  # SINGLE-WRITER GUARD (2026-09-03).
  #
  # Two repository NAMES pointing at ONE filesystem location is the documented
  # OpenSearch corruption hazard: each repository believes it owns the blob
  # tree, each runs its own retention/delete pass, and each writes its own
  # root index-N generation. Two deleters over one tree means one of them
  # removes segment blobs the other's index still references — the repository
  # then reads as "registered and healthy" while every restore fails with
  # NoSuchFileException out of BlobStoreRepository.buildBlobStoreIndexShardSnapshots.
  # That is exactly the failure shape that made netops-fs silently
  # unrestorable for seven days (2026-08-26 → 2026-09-03); a second registered
  # writer would reproduce it without anyone deleting anything by hand.
  #
  # So: look BEFORE registering. If some other name already claims this
  # location, refuse to register netops-fs and say why. Refusing is loud but
  # NON-FATAL to the rest of the bootstrap — retention/ISM must still be
  # applied, and an operator who sees "no backup" is strictly better off than
  # one who has two writers quietly eating each other's blobs.
  # -------------------------------------------------------------------------
  REPO_GUARD_OK=1
  ALL_REPOS=$(curl -s -m 10 "$OS/_snapshot/_all" 2>/dev/null)
  if [ -z "${ALL_REPOS:-}" ]; then
    # §16.1: an unreadable guard is NOT a passed guard — name it. We still
    # register, because refusing on an unproven conflict would leave a fresh
    # stack with no backup at all; the operator gets the ambiguity in the log.
    echo "ism: WARNING could not read GET _snapshot/_all — the single-writer check did NOT run." >&2
    echo "ism:         Registering netops-fs anyway. If another repository name already points at" >&2
    echo "ism:         $REPO_LOCATION, the two will corrupt each other's blob tree." >&2
  else
    # No jq/python in this image (curlimages/curl): split the flat object into
    # one line per repository, keep the ones whose location is ours, drop our
    # own name. `}},"` is the entry boundary in OpenSearch's compact reply.
    REPO_CONFLICT=$(printf '%s' "$ALL_REPOS" |
      sed -e 's/^{//' -e 's/}},"/}}\
"/g' |
      grep -E "\"location\"[[:space:]]*:[[:space:]]*\"$REPO_LOCATION\"" |
      sed -n 's/^"\([^"]*\)".*/\1/p' |
      grep -v '^netops-fs$' | tr '\n' ' ')
    if [ -n "${REPO_CONFLICT% }" ]; then
      REPO_GUARD_OK=0
      echo "ism: REFUSING to register netops-fs — repository name(s) [ ${REPO_CONFLICT}] already point at" >&2
      echo "ism:         $REPO_LOCATION. Two repository names over ONE filesystem path is the" >&2
      echo "ism:         documented OpenSearch corruption hazard: two independent deleters over one" >&2
      echo "ism:         blob tree, which ends in snapshots that list shards whose blobs are gone" >&2
      echo "ism:         (restore fails with NoSuchFileException) while the repo still reads healthy." >&2
      echo "ism:         Remove the duplicate registration (DELETE _snapshot/<name>) or give it its" >&2
      echo "ism:         own location, then re-run this bootstrap. Until then the search tier's" >&2
      echo "ism:         backup registration is UNCHANGED and this stack may have NO usable backup." >&2
    fi
  fi

  if [ "$REPO_GUARD_OK" = 1 ]; then
  echo "ism: registering snapshot repository netops-fs ..."
  REPO_RESP=$(curl -s -X PUT "$OS/_snapshot/netops-fs" \
    -H 'Content-Type: application/json' \
    -d "{\"type\":\"fs\",\"settings\":{\"location\":\"$REPO_LOCATION\",\"compress\":true}}")
  # WHERE THE "DO NOT DELETE" NOTICE LIVES, and why it is not written here.
  # The 2026-08-26 incident had no code root cause: a human ran
  # `rm -rf data/opensearch-snapshots/indices` from a shell to free disk. A
  # notice beside the repository is the only control that addresses that, and
  # SNAPSHOTS-DO-NOT-DELETE-README.txt (this directory, versioned) is its text.
  # It is PLACED by scripts/install.py, not by this script, for a hard reason:
  # opensearch-init mounts only ./opensearch:/opensearch-init:ro and has NO
  # mount of the snapshot repository, so it cannot write anywhere the operator
  # would see — and giving the bootstrap a writable mount of the blob tree
  # would add a new way to damage the blob tree. The installer owns the data/
  # layout on the host and can place the file as a SIBLING of the repository
  # directory, which also keeps a stray file out of the blob tree itself
  # (where `_cleanup` may remove it and a future reader may misread it).
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
  fi

  # -------------------------------------------------------------------------
  # SECOND REPOSITORY, OFF THIS DISK (S4, 2026-09-04 — tracker 225a).
  #
  # netops-fs is a filesystem repository on the SAME disk as data/. That is the
  # failure domain docs/audit/BACKUP-FAILURE-DOMAIN.md names, and 2026-08-27 is
  # that domain firing: one `rm -rf` in the wrong directory took every restore
  # point with it. A second `fs` repository on a SEPARATELY MOUNTED path (an NFS
  # export, a second block device, an object-store gateway mount) gives the
  # search tier restore points that survive losing this filesystem.
  #
  # OPTIONAL BY DESIGN, and the shipped default is off. Where the second mount
  # lives is a deployment decision this bootstrap cannot make, and a stack that
  # refused to come up without one would be wrong. Configure BOTH:
  #
  #   OPENSEARCH_SNAPSHOT_REPO2            repository name, e.g. netops-fs-offhost
  #   OPENSEARCH_SNAPSHOT_REPO2_LOCATION   path INSIDE the opensearch container,
  #                                        which must be listed in path.repo and
  #                                        backed by a different device
  #
  # deployment/docker/docker-compose.snapshot-repo2.yml is the ready-made
  # overlay that adds the mount, extends path.repo and passes both names to this
  # bootstrap. See docs/runbooks/storage-and-volume-operations.md.
  #
  # The SAME single-writer guard applies, for the same reason: two repository
  # names over one location is the documented corruption hazard. Here it is
  # cheap to enforce exactly — a second repository pointed at the FIRST one's
  # location is not off-host DR, it is the corruption hazard wearing a new name.
  # -------------------------------------------------------------------------
  REPO2_NAME="${OPENSEARCH_SNAPSHOT_REPO2:-}"
  REPO2_LOCATION="${OPENSEARCH_SNAPSHOT_REPO2_LOCATION:-}"
  if [ -n "$REPO2_NAME" ] && [ -z "$REPO2_LOCATION" ]; then
    echo "ism: WARNING OPENSEARCH_SNAPSHOT_REPO2=$REPO2_NAME is set but" >&2
    echo "ism:         OPENSEARCH_SNAPSHOT_REPO2_LOCATION is not — a repository cannot be" >&2
    echo "ism:         registered without a location. The second repository was NOT created," >&2
    echo "ism:         so every restore point still shares one disk." >&2
  elif [ -n "$REPO2_NAME" ] && [ "$REPO2_LOCATION" = "$REPO_LOCATION" ]; then
    echo "ism: REFUSING to register $REPO2_NAME — its location is the SAME path netops-fs" >&2
    echo "ism:         uses ($REPO_LOCATION). Two repository names over one blob tree is the" >&2
    echo "ism:         documented OpenSearch corruption hazard, and it is not off-host DR:" >&2
    echo "ism:         point OPENSEARCH_SNAPSHOT_REPO2_LOCATION at a SEPARATELY MOUNTED path." >&2
  elif [ -n "$REPO2_NAME" ]; then
    echo "ism: registering second snapshot repository $REPO2_NAME at $REPO2_LOCATION ..."
    REPO2_RESP=$(curl -s -m 30 -X PUT "$OS/_snapshot/$REPO2_NAME" \
      -H 'Content-Type: application/json' \
      -d "{\"type\":\"fs\",\"settings\":{\"location\":\"$REPO2_LOCATION\",\"compress\":true}}")
    case "$REPO2_RESP" in
      *'"acknowledged":true'*)
        echo "ism: second snapshot repository $REPO2_NAME ready."
        echo "ism:       NOTE: registration is not a copy. Nothing writes to it automatically —"
        echo "ism:       take a snapshot into it (POST _snapshot/$REPO2_NAME/<name>) or add an SM"
        echo "ism:       policy of its own, or it will protect nothing."
        ;;
      *)
        # §16.1: a configured-but-unregistered second repository is worse than
        # none, because the Data Protection page would be reporting an intent
        # somebody reads as a copy. Say it plainly.
        echo "ism: ERROR second snapshot repository $REPO2_NAME NOT registered: $REPO2_RESP" >&2
        echo "ism:       -> the off-host repository does NOT exist; every restore point still" >&2
        echo "ism:       shares the primary data's disk. Check that $REPO2_LOCATION is listed" >&2
        echo "ism:       in path.repo on the opensearch service and is writable by the container." >&2
        ;;
    esac
  fi

  # Snapshot Management policy: one snapshot a day, keep SNAP_KEEP of them.
  # PUT is create-only (409 if it exists) like the ISM policy above, so read
  # the seq_no first and update in place — the same trap that let the ism
  # patterns stay stuck at three lanes while this file claimed six.
  # ONE read, three facts (_seq_no, _primary_term and — new, 2026-09-03 — the
  # live `enabled` flag). It used to be two separate GETs; a third would have
  # been a third chance for the two halves to disagree mid-flight.
  SM_GET=$(curl -s -m 10 "$OS/_plugins/_sm/policies/netops-daily" 2>/dev/null)
  SM_SEQ=$(printf '%s' "$SM_GET" |
        sed -n 's/.*"_seq_no"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' | head -1)
  SM_TERM=$(printf '%s' "$SM_GET" |
        sed -n 's/.*"_primary_term"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' | head -1)
  # `"enabled"` with the closing quote — never matches `"enabled_time"`.
  SM_ENABLED=$(printf '%s' "$SM_GET" |
        sed -n 's/.*"enabled"[[:space:]]*:[[:space:]]*\(true\|false\).*/\1/p' | head -1)
  # Snapshot Management differs from ISM here: CREATE is POST, UPDATE is PUT with
  # seq_no/primary_term. ISM accepts PUT for both, so the sibling code above uses
  # PUT throughout — but SM rejects a seq_no-less PUT as "must be provided when
  # updating" even for a policy that does not exist (404 on GET). This was the
  # bug that left netops-daily uninstalled: the else branch below PUT-created it
  # and SM 400'd every time. Method + URL now branch together.
  #
  # PRESERVE THE OPERATOR'S INTENT (2026-09-03). The body below carried no
  # `enabled` field, and OpenSearch defaults a missing `enabled` to TRUE. So an
  # operator who deliberately stopped the schedule from the GUI (or via
  # _sm/policies/netops-daily/_stop) had it silently RE-ENABLED by the next
  # `docker compose up` — proven live at 11:47Z on 2026-09-03 by setting
  # enabled=false, replaying this PUT verbatim, and reading enabled=true back.
  # That is why "snapshots were disabled in the GUI" and snapshots kept running.
  #
  # The rule now: an UPDATE never changes the flag, only a CREATE sets it. The
  # authoritative copy of the flag is the one IN OPENSEARCH (read above); the
  # api additionally records the human context of a deliberate stop in
  # data/api/system_backup.json (snapshot_schedule_disabled_at/_by/_reason).
  SM_SKIP=0
  if [ -n "${SM_SEQ:-}" ] && [ -n "${SM_TERM:-}" ]; then
    SM_METHOD=PUT
    SM_URL="$OS/_plugins/_sm/policies/netops-daily?if_seq_no=${SM_SEQ}&if_primary_term=${SM_TERM}"
    case "${SM_ENABLED:-}" in
      true) : ;;
      false)
        echo "ism: NOTE snapshot schedule netops-daily is DISABLED by operator intent — leaving it disabled." >&2
        echo "ism:      CONSEQUENCE: no new restore points are being created. Every hour it stays off is an" >&2
        echo "ism:      hour of indexed logs, traps and flows with no backup. Re-enable from Settings →" >&2
        echo "ism:      Data Protection, or POST $OS_REDACTED/_plugins/_sm/policies/netops-daily/_start" >&2
        ;;
      *)
        # §16.1: the policy EXISTS (we parsed its seq_no from the same body) but
        # its enabled flag did not parse. Writing the body without the flag
        # would default it to true and could re-enable a deliberately stopped
        # schedule — the exact defect this block fixes. Preserve by NOT writing.
        SM_SKIP=1
        echo "ism: ERROR snapshot policy netops-daily exists but its 'enabled' flag could not be read." >&2
        echo "ism:       REFUSING to update it: a write without the flag defaults to enabled=true and" >&2
        echo "ism:       would clobber a deliberate operator stop. The policy is left EXACTLY as it is," >&2
        echo "ism:       which also means any change to OPENSEARCH_SNAPSHOT_KEEP or the schedule in this" >&2
        echo "ism:       file has NOT been applied. Inspect: GET _plugins/_sm/policies/netops-daily" >&2
        ;;
    esac
  else
    # Absent (the GET 404s): this is a CREATE, and enabled=true is the product
    # default. This is the ONLY branch allowed to turn the schedule on.
    SM_METHOD=POST
    SM_URL="$OS/_plugins/_sm/policies/netops-daily"
    SM_ENABLED=true
  fi
  if [ "$SM_SKIP" = 1 ]; then
    SM_RESP='(skipped: enabled flag unreadable — see the ERROR above)'
  else
  SM_RESP=$(curl -s -X "$SM_METHOD" "$SM_URL" -H 'Content-Type: application/json' -d @- <<JSON
{
  "description": "Daily snapshot of netops-* to the netops-fs repository (F-59).",
  "enabled": ${SM_ENABLED},
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
  fi
  case "$SM_RESP" in
    *'"netops-daily"'*)
      echo "ism: snapshot policy netops-daily installed (daily 01:30 UTC, keep ${SNAP_KEEP}, enabled=${SM_ENABLED})." ;;
    '(skipped'*) : ;;   # already reported as an ERROR above; do not double-report
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
