"""Cloud control-plane / flow-log poller (lab-site service, not a product default).

Two lanes into the existing pipelines, no new product code paths:
  1. VPC flow logs: CloudWatch Logs FilterLogEvents -> append raw v2 lines to
     CLOUD_LOGS_OUT/aws-vpc-flow.vpc. The correlation service's cloud-log tailer
     (CLOUD_LOGS_DIR) parses them; REJECT lines become cloud_flow_log signals.
  2. CloudTrail management events -> netops.cloud kind=cloud_change events
     (control-plane evidence class for the cloud/IPsec RCA signatures).

Checkpointed; every loop is idempotent. Sleeps POLL_S between cycles.
"""
import json
import os
import time

import boto3
from kafka import KafkaProducer

import azure
import azure_logs
import azure_topology
import broker_client
import cloud_events
import cloud_tag
import cloudmetrics
import discover
import gcp
import seam_aws
import source_status
import trail_state

REGION = os.environ.get("AWS_REGION", "us-west-2")
LOG_GROUP = os.environ.get("FLOW_LOG_GROUP", "")  # CloudWatch lane (needs delivery role)
FLOW_S3_BUCKET = os.environ.get("FLOW_S3_BUCKET", "")  # S3 lane (no IAM role needed)
FLOW_S3_PREFIX = os.environ.get("FLOW_S3_PREFIX", "")
# Log-fidelity lanes (ALB access / WAF / Route 53 Resolver query logs): each is
# an S3 prefix, empty = lane off. LOGS_S3_BUCKET falls back to FLOW_S3_BUCKET
# so a single fidelity bucket serves every lane.
LOGS_S3_BUCKET = os.environ.get("LOGS_S3_BUCKET", "")
ALB_S3_PREFIX = os.environ.get("ALB_S3_PREFIX", "")
WAF_S3_PREFIX = os.environ.get("WAF_S3_PREFIX", "")
DNS_S3_PREFIX = os.environ.get("DNS_S3_PREFIX", "")
# Extra S3 log source-sets beyond the primary env config above. Real AWS log
# delivery is per-log-type (WAF logs MUST live in an aws-waf-logs-* bucket; flow
# and ALB access logs commonly land in their own buckets) and often spans
# multiple accounts — so a single LOGS_S3_BUCKET + prefixes can't express it.
# S3_LOG_SOURCES is a JSON array; each entry names its OWN per-lane buckets:
#   [{"name":"prod-acct","flow_bucket":"...","alb_bucket":"...",
#     "waf_bucket":"aws-waf-logs-...","dns_bucket":"...","prefix":""}]
# Any bucket omitted = that lane off for that source. Empty/unset = today's
# single-source behavior, unchanged. Extra sources use the SAME creds/region as
# the primary poller (same-account or a bucket policy that grants this principal);
# cross-account role assumption is the next increment.
S3_LOG_SOURCES_RAW = os.environ.get("S3_LOG_SOURCES", "").strip()
_extra_s3_sources_cache = None


def extra_s3_sources() -> list:
    """Parsed S3_LOG_SOURCES (see above), memoized. A malformed value is logged
    once and ignored — a bad source override must never take the poller down."""
    global _extra_s3_sources_cache
    if _extra_s3_sources_cache is not None:
        return _extra_s3_sources_cache
    out = []
    if S3_LOG_SOURCES_RAW:
        try:
            arr = json.loads(S3_LOG_SOURCES_RAW)
            for i, s in enumerate(arr if isinstance(arr, list) else []):
                if isinstance(s, dict) and any(
                    s.get(k) for k in ("flow_bucket", "alb_bucket", "waf_bucket", "dns_bucket")
                ):
                    s = dict(s)
                    s["_name"] = s.get("name") or f"src{i + 1}"
                    out.append(s)
        except Exception as e:  # noqa: BLE001 — never crash the poller on config
            jlog("S3_LOG_SOURCES parse error — ignoring", error=str(e))
    _extra_s3_sources_cache = out
    return out
OUT_DIR = os.environ.get("CLOUD_LOGS_OUT", "/out")
# Live inventory/topology snapshots go to the RUNTIME dir — a gitignored data/
# mount, never the git-tracked cloud-fixtures (the 2026-07 hygiene split:
# static fixtures stay tracked, live poller output lives under data/).
# CLOUD_RUNTIME_OUT is the knob; legacy CLOUD_FIXTURES_OUT still honored.
RUNTIME_OUT = (os.environ.get("CLOUD_RUNTIME_OUT")
               or os.environ.get("CLOUD_FIXTURES_OUT", "/fixtures"))
BROKERS = os.environ.get("BROKER_URLS", "kafka:9092")
TENANT = os.environ.get("CLOUD_TENANT", "global")
# Unified Cloud Logs: raw cloud log lines are tagged (cloud_family/cloud_provider/
# resource_id) and produced to this topic for vector-router → netops-cloudlogs-*
# so they are searchable as RAW logs, not just correlation signals. Bounded per
# scan so a flow/access-log firehose can never flood OpenSearch (the 2026-06-10
# outage class). 0 = unbounded (not recommended); default keeps a lane's per-scan
# raw-line emission capped.
CLOUDLOGS_TOPIC = os.environ.get("CLOUDLOGS_TOPIC", "netops.cloudlogs")
CLOUDLOGS_RAW = os.environ.get("CLOUDLOGS_RAW", "on").lower() != "off"
CLOUDLOGS_MAX_PER_SCAN = int(os.environ.get("CLOUDLOGS_MAX_PER_SCAN", "5000"))
ACCOUNT = os.environ.get("CLOUD_ACCOUNT", "945714973156")
# Cost-tier policy (owner direction 2026-07-14): lanes that are FREE or
# near-free (inventory describes, audit/change events, health events, S3/
# storage-delivered logs) always run. Lanes whose READS the provider METERS
# are an explicit customer choice: AWS GetMetricData ($0.01/1k values) and
# GCP Monitoring reads ($0.50/M series past the free tier). Azure metric
# reads are not billed — no toggle needed. Off = the matrix shows the lane
# honestly disabled, never silently missing.
AWS_METERED_METRICS = os.environ.get("AWS_METERED_METRICS", "on").lower() != "off"
# Hybrid-seam lanes (#105 P1): describe-API/REST state is FREE and always on
# unless explicitly disabled; the metered drop counters inside each lane honor
# the per-provider metered toggles above.
CLOUD_SEAM_TELEMETRY = os.environ.get("CLOUD_SEAM_TELEMETRY", "on").lower() != "off"
SEAM_EVERY_S = int(os.environ.get("SEAM_EVERY_S", "120"))
GCP_METERED_METRICS = os.environ.get("GCP_METERED_METRICS", "on").lower() != "off"
# GCP log-fidelity lanes (#105 parity: vpc_flows / firewall / LB+Armor / DNS).
# Per-lane opt-in gates live in gcp.py (GCP_VPC_FLOW_LOGS etc.); this is the
# shared cadence. entries:list reads are free but the project quota is
# 60 req/min — 120s keeps 4 lanes × ≤5 pages comfortably inside it.
GCP_LOG_LANES_EVERY_S = int(os.environ.get("GCP_LOG_LANES_EVERY_S", "120"))
POLL_S = int(os.environ.get("POLL_S", "60"))
DISCOVER_EVERY_S = int(os.environ.get("DISCOVER_EVERY_S", "300"))
# ── Per-tenant ingestion (Wave 1 #2) ────────────────────────────────────────
# When the broker is configured (BROKER_API_URL + BROKER_API_KEY[_FILE]), the
# poller ALSO iterates the platform's enabled connectors each cycle, obtains a
# short-lived credential per connector from the backend identity broker, polls
# that connector's cloud with it, and everything it emits is owned by THAT
# connector's tenant (stamped server-side on the inventory write; carried on
# bus events from the server-provided connector list, never from local env).
# The ambient-credential lanes above keep running unchanged either way.
CONNECTOR_EVERY_S = int(os.environ.get("CONNECTOR_EVERY_S", "300"))
CONNECTOR_MAX_PER_CYCLE = int(os.environ.get("CONNECTOR_MAX_PER_CYCLE", "25"))
# Total wall-clock budget for one connector pass — bounds the whole cycle even
# if a provider API crawls; connectors past the budget wait for the next pass.
CONNECTOR_CYCLE_BUDGET_S = int(os.environ.get("CONNECTOR_CYCLE_BUDGET_S", "240"))
# CloudWatch metric lane (Service View counters + CUSUM evidence). CloudWatch's
# free basic resolution is 5 min, so polling faster only re-reads the same point.
METRICS_EVERY_S = int(os.environ.get("CW_METRICS_EVERY_S", "300"))
# Azure platform metrics are 1-minute and FREE (richer than CloudWatch's 5-min
# free tier), so the Azure lane polls faster.
AZ_METRICS_EVERY_S = int(os.environ.get("AZ_METRICS_EVERY_S", "60"))
AZ_HEALTH_EVERY_S = int(os.environ.get("AZ_HEALTH_EVERY_S", "120"))
# Azure storage-delivered log lanes (#105 build order #2: VNet flow logs + the
# AppGW/FD/WAF/DNS fidelity families). Gated inside azure_logs (storage account
# env unset = every lane off — honest absence, mirroring the AWS S3 lanes).
AZ_LOGS_EVERY_S = int(os.environ.get("AZ_LOGS_EVERY_S", "60"))
STATE_PATH = os.path.join(OUT_DIR, ".poller-state.json")
# The flow-log sink is APPENDED to forever today. At real flow volume that fills
# the disk and takes the poller (and the correlation tailer) down with it
# (audit 2026-07-13, P0-4). Roll it when it crosses the cap; the tailer reads
# from the head, so a roll is safe and bounded.
FLOW_FILE_MAX_MB = int(os.environ.get("FLOW_FILE_MAX_MB", "256"))


def _roll_if_large(path: str) -> None:
    try:
        if os.path.getsize(path) < FLOW_FILE_MAX_MB * 1024 * 1024:
            return
    except OSError:
        return
    prev = path + ".1"
    try:
        if os.path.exists(prev):
            os.remove(prev)
        os.replace(path, prev)
        jlog("flow log rolled", path=path, cap_mb=FLOW_FILE_MAX_MB)
    except OSError as exc:
        jlog("flow log roll failed", error=str(exc)[:120])

# Interesting = network/security/compute mutations (cloud_change evidence).
TRAIL_PREFIXES = ("Modify", "Create", "Delete", "Revoke", "Authorize", "Stop",
                  "Start", "Terminate", "Reboot", "Replace", "Attach", "Detach",
                  "Disassociate", "Associate", "Put", "Update")
# Agent/telemetry chatter that matches a prefix but carries no fault meaning —
# SSM heartbeats alone would drown the control-plane lane (observed 2026-07-12).
TRAIL_EXCLUDE = {"UpdateInstanceInformation", "PutInventory", "UpdateInstanceAssociationStatus",
                 "PutMetricData", "CreateLogStream", "PutLogEvents"}


def load_state() -> dict:
    try:
        with open(STATE_PATH) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(st: dict) -> None:
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f)
    os.replace(tmp, STATE_PATH)


def jlog(msg: str, **kw):
    print(json.dumps({"ts": time.time(), "service": "cloud-ingest", "msg": msg, **kw}),
          flush=True)


def _now_iso() -> str:
    import datetime as _dt
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def emit_cloud_log(producer, out_name: str, line: str, sent_so_far: int) -> int:
    """Tag one raw cloud log line and produce it to the cloudlogs topic. Returns 1
    when emitted, 0 otherwise. Bounded per scan (CLOUDLOGS_MAX_PER_SCAN) so raw
    access/flow log volume can never flood OpenSearch. Never raises — a tagging
    hiccup must not take the poll lane (or its file append) down."""
    if not CLOUDLOGS_RAW or producer is None:
        return 0
    if CLOUDLOGS_MAX_PER_SCAN and sent_so_far >= CLOUDLOGS_MAX_PER_SCAN:
        return 0
    try:
        doc = cloud_tag.cloud_log_doc(
            out_name, line, TENANT, account=ACCOUNT, region=REGION, timestamp=_now_iso())
        if doc is None:
            return 0
        producer.send(CLOUDLOGS_TOPIC, doc)
        return 1
    except Exception:  # noqa: BLE001 — tagging is best-effort, never fatal
        return 0


def poll_flow_logs(logs, st: dict, producer=None) -> None:
    start = int(st.get("flow_ts", (time.time() - 300) * 1000))
    kwargs = {"logGroupName": LOG_GROUP, "startTime": start + 1}
    written = 0
    tagged = 0
    newest = start
    try:
        while True:
            resp = logs.filter_log_events(**kwargs)
            events = resp.get("events", [])
            if events:
                _roll_if_large(os.path.join(OUT_DIR, "aws-vpc-flow.vpc"))
                with open(os.path.join(OUT_DIR, "aws-vpc-flow.vpc"), "a") as f:
                    for e in events:
                        line = e["message"].rstrip("\n")
                        f.write(line + "\n")
                        tagged += emit_cloud_log(producer, "aws-vpc-flow.vpc", line, tagged)
                        newest = max(newest, e["timestamp"])
                        written += 1
            token = resp.get("nextToken")
            if not token:
                break
            kwargs["nextToken"] = token
    except logs.exceptions.ResourceNotFoundException:
        jlog("flow log group missing (not enabled yet?)", group=LOG_GROUP)
        return
    # Checkpoint advances on EVERY successful poll (all events are written, so
    # `newest` covers everything seen); an empty window anchors on the lagged
    # now instead of pinning `flow_ts` and re-scanning an ever-growing range
    # (same defect class as trail_ts — see trail_state.py). Millisecond lane.
    st["flow_ts"] = int(trail_state.advance_checkpoint_any(
        start, newest, written > 0, (time.time() - trail_state.DELIVERY_LAG_S) * 1000))
    if written:
        jlog("flow events appended", count=written)


def _poll_s3_lane(s3, st: dict, bucket: str, prefix: str, state_key: str,
                  out_name: str, skip_prefixes: tuple = (), producer=None) -> int:
    """One S3 log lane: fetch .gz objects under `prefix` newer than the
    checkpoint, decompress, append raw lines to OUT_DIR/out_name for the
    correlation tailer (which owns parsing/rollup), AND tag+emit each raw line to
    the cloudlogs topic so it is searchable as a raw log (unified Cloud Logs).
    Shared by VPC flow, ALB access, WAF and Resolver query logs — same checkpoint
    discipline (P0-3), same rotation guard (P0-4)."""
    import gzip
    last_key = st.get(state_key, "")
    kwargs = {"Bucket": bucket, "MaxKeys": 200}
    if prefix:
        kwargs["Prefix"] = prefix
    if last_key:
        kwargs["StartAfter"] = last_key
    written = 0
    tagged = 0
    resp = s3.list_objects_v2(**kwargs)
    out_path = os.path.join(OUT_DIR, out_name)
    for obj in resp.get("Contents", []):
        key = obj["Key"]
        if not (key.endswith(".log.gz") or key.endswith(".gz")):
            last_key = max(last_key, key)
            continue
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        text = gzip.decompress(body).decode()
        _roll_if_large(out_path)
        with open(out_path, "a") as f:
            for line in text.splitlines():
                if not line.strip() or line.startswith(skip_prefixes or ("\x00",)):
                    continue
                f.write(line + "\n")
                written += 1
                tagged += emit_cloud_log(producer, out_name, line, tagged)
        last_key = max(last_key, key)
    if last_key:
        st[state_key] = last_key
    return written


def poll_flow_logs_s3(s3, st: dict, producer=None) -> None:
    """VPC flow logs delivered to S3 (header line stripped). Primary source
    (FLOW_S3_BUCKET) plus any extra sources from S3_LOG_SOURCES — extra sources
    keep their own checkpoints (suffixed state key) so the primary is untouched.
    Each source runs through _lane so an IAM denial / missing bucket becomes a
    structured flow_logs status record, isolated per source."""
    if FLOW_S3_BUCKET:
        n = _lane("flow_logs", _poll_s3_lane, s3, st, FLOW_S3_BUCKET, FLOW_S3_PREFIX,
                  "flow_s3_key", "aws-vpc-flow.vpc", skip_prefixes=("version ",),
                  producer=producer)
        if n:
            jlog("flow records appended from s3", count=n)
    for src in extra_s3_sources():
        bucket = src.get("flow_bucket")
        if not bucket:
            continue
        n = _lane("flow_logs", _poll_s3_lane, s3, st, bucket,
                  src.get("flow_prefix", src.get("prefix", "")),
                  f"flow_s3_key::{src['_name']}", "aws-vpc-flow.vpc",
                  skip_prefixes=("version ",), producer=producer,
                  account=src["_name"])
        if n:
            jlog("flow records appended from s3", source=src["_name"], count=n)


# The Ingestion Status source each fidelity sink feeds — used to attribute a
# lane's permission/misconfiguration failure to the RIGHT matrix chip.
S3_LANE_SOURCE = {
    "aws-alb-access.alb": "lb_logs",
    "aws-waf.waf": "firewall_logs",
    "aws-r53-resolver.dns": "dns_logs",
}


def poll_fidelity_logs_s3(s3, st: dict, producer=None) -> None:
    """The log-fidelity lanes (ALB access / WAF / Resolver query logs), each an
    opt-in S3 prefix. Absent prefix = lane off — nothing is guessed. Each lane
    runs through _lane so an IAM denial surfaces on ITS source chip and never
    blocks the sibling lanes."""
    lanes = [
        (ALB_S3_PREFIX, "alb_s3_key", "aws-alb-access.alb"),
        (WAF_S3_PREFIX, "waf_s3_key", "aws-waf.waf"),
        (DNS_S3_PREFIX, "dns_s3_key", "aws-r53-resolver.dns"),
    ]
    for prefix, state_key, out_name in lanes:
        if not prefix:
            continue
        n = _lane(S3_LANE_SOURCE[out_name], _poll_s3_lane, s3, st,
                  LOGS_S3_BUCKET or FLOW_S3_BUCKET, prefix, state_key,
                  out_name, producer=producer)
        if n:
            jlog("fidelity records appended from s3", lane=out_name, count=n)
    # Extra sources name their OWN per-lane buckets (root prefix by default) —
    # the production-realistic separate-bucket-per-log-type layout.
    for src in extra_s3_sources():
        for bkey, pkey, state_key, out_name in (
            ("alb_bucket", "alb_prefix", "alb_s3_key", "aws-alb-access.alb"),
            ("waf_bucket", "waf_prefix", "waf_s3_key", "aws-waf.waf"),
            ("dns_bucket", "dns_prefix", "dns_s3_key", "aws-r53-resolver.dns"),
        ):
            bucket = src.get(bkey)
            if not bucket:
                continue
            n = _lane(S3_LANE_SOURCE[out_name], _poll_s3_lane, s3, st, bucket,
                      src.get(pkey, src.get("prefix", "")),
                      f"{state_key}::{src['_name']}", out_name, producer=producer,
                      account=src["_name"])
            if n:
                jlog("fidelity records appended from s3", lane=out_name, source=src["_name"], count=n)


def poll_cloudtrail(ct, producer, st: dict, tenant: str = None, account: str = None,
                    region: str = None, connector_id: str = "") -> None:
    """CloudTrail management events → netops.cloud cloud_change evidence.

    Defaults keep today's ambient single-tenant behavior. Per-tenant ingestion
    (Wave 1 #2) passes a connector-scoped `ct` client, the CONNECTOR's tenant/
    account/region (all sourced from the broker's connector list — server truth,
    never local env) and a per-connector state dict so checkpoints never mix.
    """
    tenant = TENANT if tenant is None else tenant
    account = ACCOUNT if account is None else account
    region = REGION if region is None else region
    import datetime
    start = st.get("trail_ts", time.time() - 900)
    start_dt = datetime.datetime.fromtimestamp(start + 0.001, datetime.timezone.utc)
    newest = start
    sent = 0
    # Paginate to EXHAUSTION before advancing the checkpoint. lookup_events
    # returns newest-first; reading only the first 50 and then moving trail_ts
    # past the rest silently DROPS every older event in the window — precisely
    # during a deploy or Terraform apply, i.e. exactly when the change that
    # caused the incident is in that window (audit 2026-07-13, P0-3).
    events = []
    token = None
    for _ in range(20):  # bounded: 20 pages x 50 = 1000 events/cycle ceiling
        kw = {"StartTime": start_dt, "MaxResults": 50}
        if token:
            kw["NextToken"] = token
        resp = ct.lookup_events(**kw)
        events.extend(resp.get("Events", []))
        token = resp.get("NextToken")
        if not token:
            break
    else:
        jlog("cloudtrail page ceiling hit — window truncated", pages=20)

    for e in events:
        # The checkpoint anchors on everything SEEN, matched or excluded —
        # advancing only over matched events pinned trail_ts during quiet
        # periods and re-read 20 pages of SSM chatter every cycle (trail_state).
        newest = max(newest, e["EventTime"].timestamp())
        name = e.get("EventName", "")
        if not name.startswith(TRAIL_PREFIXES) or name in TRAIL_EXCLUDE:
            continue
        detail = json.loads(e.get("CloudTrailEvent", "{}"))
        resources = e.get("Resources") or []
        rid = resources[0]["ResourceName"] if resources else name
        actor = (detail.get("userIdentity") or {}).get("arn", "")
        event_source = detail.get("eventSource", "")
        attrs = {
            "event_source": event_source,
            "actor": actor,
            "request_id": detail.get("requestID", ""),
        }
        if connector_id:
            attrs["connector_id"] = connector_id
        producer.send("netops.cloud", cloud_events.change_event(
            provider="aws", tenant=tenant, resource_id=rid, account=account,
            region=region, severity="medium", metric_name=name,
            ts=e["EventTime"].isoformat(),
            attrs=attrs))
        # Unified Cloud Logs: also emit the change as a tagged RAW log line so the
        # Change lane shows the record itself, not only its correlation rollup.
        if CLOUDLOGS_RAW:
            chg = cloud_tag.change_log_doc(
                tenant, resource_id=rid, event_name=name, provider="aws",
                account=account, region=region, actor=actor,
                event_source=event_source, timestamp=e["EventTime"].isoformat())
            if chg is not None:
                producer.send(CLOUDLOGS_TOPIC, chg)
        sent += 1
    if sent:
        producer.flush(10)
        jlog("cloudtrail changes produced", count=sent)
    st["trail_ts"] = trail_state.advance_checkpoint(start, newest, bool(events), time.time())


def _iso_minutes_ago(minutes: int) -> str:
    import datetime as _dt
    t = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(minutes=minutes)
    return t.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _lane(source_type: str, fn, *args, account: str = "", region: str = "", **kw):
    """Run one ambient AWS lane with structured error surfacing (Wave 2 #4).
    A permission/misconfiguration failure becomes a source-status record the
    Ingestion Status page can render ("IAM denied flow logs since Tuesday")
    instead of only a log line; success clears the record. Errors that do NOT
    classify re-raise into the existing cycle handling, unchanged."""
    acct = account or ACCOUNT
    reg = region or REGION
    try:
        out = fn(*args, **kw)
    except Exception as exc:
        status = source_status.note("aws", source_type, exc,
                                    tenant=TENANT, account=acct, region=reg)
        if status is None:
            raise
        jlog("lane " + status, lane=source_type, error=str(exc)[:200])
        return None
    source_status.clear("aws", source_type, tenant=TENANT, account=acct, region=reg)
    return out


# ── Per-tenant ingestion: connector lanes (Wave 1 #2) ────────────────────────
# One lane per provider. Each lane receives the SERVER-provided connector row
# (id / tenant / provider / scopes) and the broker-minted short-lived credential,
# polls with exactly that credential, and delivers inventory back through the
# broker API — where the backend stamps the tenant from the connector row.
# Credentials live only in local variables; they are never persisted or logged.


def _connector_scope(conn: dict) -> tuple[str, str]:
    """(account_ref, region) from the connector's declared scopes — the same
    precedence the backend's own live trust check uses."""
    account, region = "", ""
    for sc in conn.get("scopes") or []:
        if sc.get("type") == "region" and not region:
            region = sc.get("ref", "")
            continue
        if not account:
            account = sc.get("ref", "")
            if sc.get("regions") and not region:
                region = sc["regions"][0]
    return account, region


def _scoped_inventory_doc(mod, scope_attr: str, scope_ref: str, tok: str, out_name: str) -> dict:
    """Run mod.write_inventory(tok, dir) against a connector's scope and return
    the inventory doc. The module's scope global (azure.SUBSCRIPTION /
    gcp.PROJECT) is substituted for the duration of the call and ALWAYS
    restored — the poller is single-threaded, and this keeps credential/scope
    injection out of those modules while another workstream extends them.
    Writes to a private temp dir (never the shared fixtures dir: connector
    inventory is delivered per-tenant via the broker API, not via files)."""
    import tempfile
    old = getattr(mod, scope_attr)
    if scope_ref:
        setattr(mod, scope_attr, scope_ref)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            mod.write_inventory(tok, tmp)
            with open(os.path.join(tmp, out_name), encoding="utf-8") as f:
                return json.load(f)
    finally:
        setattr(mod, scope_attr, old)


def poll_connector_aws(conn: dict, creds: dict, producer, cst: dict) -> dict:
    """AWS connector lane: STS-credentialed discovery → inventory via broker →
    CloudTrail change evidence stamped with the CONNECTOR's tenant."""
    _, region = _connector_scope(conn)
    region = region or REGION
    session = boto3.Session(
        aws_access_key_id=creds.get("aws_access_key_id", ""),
        aws_secret_access_key=creds.get("aws_secret_access_key", ""),
        aws_session_token=creds.get("aws_session_token", ""),
        region_name=region)
    inventory, _topology = discover.discover_aws(
        session.client("ec2"), session=session, region=region)
    broker_client.put_inventory(conn["id"], inventory)
    if producer is not None:
        # Change evidence in its OWN status scope (Wave 2 #4): inventory can be
        # healthy while CloudTrail reads are IAM-denied — that must surface as
        # "permission denied: change_audit", not fail the whole lane.
        acct = inventory.get("account_id", "")
        try:
            poll_cloudtrail(session.client("cloudtrail"), producer, cst,
                            tenant=conn["tenant"], account=acct,
                            region=region, connector_id=conn["id"])
            source_status.clear("aws", "change_audit", tenant=conn["tenant"],
                                account=acct, region=region)
        except Exception as exc:
            status = source_status.note("aws", "change_audit", exc,
                                        tenant=conn["tenant"], account=acct,
                                        region=region, connector_id=conn["id"])
            if status is None:
                raise
            jlog("connector change_audit " + status, connector=conn["id"],
                 error=str(exc)[:200])
    return {"resources": len(inventory.get("resources", []))}


def poll_connector_azure(conn: dict, creds: dict, producer, cst: dict) -> dict:
    """Azure connector lane: broker-minted ARM token → subscription-scoped
    inventory delivered via the broker API."""
    account, _ = _connector_scope(conn)
    doc = _scoped_inventory_doc(azure, "SUBSCRIPTION", account, creds.get("token", ""), "azure.json")
    broker_client.put_inventory(conn["id"], doc)
    return {"resources": len(doc.get("resources", []))}


def poll_connector_gcp(conn: dict, creds: dict, producer, cst: dict) -> dict:
    """GCP connector lane: broker-minted access token → project-scoped
    inventory delivered via the broker API."""
    account, _ = _connector_scope(conn)
    doc = _scoped_inventory_doc(gcp, "PROJECT", account, creds.get("token", ""), "gcp.json")
    broker_client.put_inventory(conn["id"], doc)
    return {"resources": len(doc.get("resources", []))}


CONNECTOR_LANES = {
    "aws": poll_connector_aws,
    "azure": poll_connector_azure,
    "gcp": poll_connector_gcp,
}


def connector_cycle(producer, st: dict) -> dict:
    """One per-connector pass: list enabled connectors → per connector, fetch a
    short-lived credential and run its provider lane. FAILURE ISOLATION: each
    connector runs in its own try/except — one connector failing never touches
    the others (or the ambient lanes). Bounded: connector count capped per
    cycle, total wall clock capped by CONNECTOR_CYCLE_BUDGET_S."""
    started = time.time()
    try:
        conns = broker_client.list_connectors()
    except Exception as exc:  # noqa: BLE001 — broker outage must not kill the poller
        jlog("connector list failed", error=str(exc)[:200])
        return {"connectors": 0, "failed": 0, "skipped": 0}
    if len(conns) > CONNECTOR_MAX_PER_CYCLE:
        jlog("connector list truncated", total=len(conns), cap=CONNECTOR_MAX_PER_CYCLE)
        conns = conns[:CONNECTOR_MAX_PER_CYCLE]
    ok = failed = skipped = 0
    for conn in conns:
        cid = str(conn.get("id", ""))
        provider = str(conn.get("provider", ""))
        if time.time() - started > CONNECTOR_CYCLE_BUDGET_S:
            skipped += 1
            continue
        lane = CONNECTOR_LANES.get(provider)
        if lane is None or not cid or not conn.get("tenant"):
            jlog("connector skipped", connector=cid, provider=provider)
            skipped += 1
            continue
        cst = st.setdefault("connectors", {}).setdefault(cid, {})
        acct, reg = _connector_scope(conn)
        try:
            creds = broker_client.credentials(cid)  # short-lived; memory only
            counts = lane(conn, creds, producer, cst) or {}
            ok += 1
            source_status.clear(provider, "inventory", tenant=conn["tenant"],
                                account=acct, region=reg)
            jlog("connector polled", connector=cid, provider=provider,
                 tenant=conn["tenant"], **counts)
        except Exception as exc:  # noqa: BLE001 — per-connector isolation
            failed += 1
            # A 403/401-class provider failure becomes a structured record on
            # the CONNECTOR's tenant (Wave 2 #4) — the Ingestion page shows
            # "IAM denied X since <time>" instead of a silent 0-forever.
            status = source_status.note(provider, "inventory", exc,
                                        tenant=conn["tenant"], account=acct,
                                        region=reg, connector_id=cid)
            jlog("connector poll error", connector=cid, provider=provider,
                 classified=status or "", error=str(exc)[:200])
    if skipped:
        jlog("connector cycle budget hit", skipped=skipped, budget_s=CONNECTOR_CYCLE_BUDGET_S)
    return {"connectors": ok, "failed": failed, "skipped": skipped}


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    session = boto3.Session(region_name=REGION)
    logs = session.client("logs")
    ct = session.client("cloudtrail")
    s3 = session.client("s3")
    cw = session.client("cloudwatch")
    producer = KafkaProducer(
        bootstrap_servers=BROKERS.split(","),
        value_serializer=lambda v: json.dumps(v).encode(),
        acks="all", linger_ms=100, retries=5)
    jlog("cloud-ingest started", group=LOG_GROUP, brokers=BROKERS, tenant=TENANT)
    # Which ingestion mode(s) this process runs (Wave 1 #2). Ambient = today's
    # single-credential lanes (always on, unchanged); connectors = per-tenant
    # polling driven by the platform's connector store via the token broker.
    connector_mode = broker_client.configured()
    jlog("ingestion modes", ambient=True, connectors=connector_mode)
    last_connectors = 0.0
    st = load_state()
    last_discover = 0.0
    last_metrics = 0.0
    last_az_metrics = 0.0
    last_az_health = 0.0
    last_az_inventory = 0.0
    inventory: list[dict] = []
    az_vms: list[dict] = []
    az_ready = azure.configured()
    jlog("azure lane", configured=az_ready)
    jlog("azure storage-log lanes", configured=az_ready and azure_logs.configured(),
         lanes=sorted(azure_logs.lanes()) if az_ready else [])
    last_az_logs = 0.0
    gcp_ready = gcp.configured()
    jlog("gcp lane", configured=gcp_ready)
    last_gcp_inventory = 0.0
    last_gcp_metrics = 0.0
    last_seam = 0.0
    last_gcp_seam = 0.0
    last_gcp_logs = 0.0
    last_az_seam = 0.0
    while True:
        try:
            # Cloud inventory + in-cloud egress topology, discovered from the live
            # APIs. Route tables are the authoritative statement of which edge a
            # subnet leaves by (IGW / NAT / IPsec NVA) — we read it, never assume it.
            if time.time() - last_discover >= DISCOVER_EVERY_S:
                res, edges = discover.run()
                last_discover = time.time()
                inventory = discover.instances_snapshot()
                jlog("cloud discovery", resources=res, route_edges=edges)

            # CloudWatch → canonical metric lane: live values for the Service View
            # counters AND anomaly evidence via the correlation CUSUM detector.
            if AWS_METERED_METRICS and inventory and time.time() - last_metrics >= METRICS_EVERY_S:
                n = cloudmetrics.poll(cw, inventory)
                last_metrics = time.time()
                jlog("cloud metrics", events=n, instances=len(inventory))
            if LOG_GROUP:
                _lane("flow_logs", poll_flow_logs, logs, st, producer)
            poll_flow_logs_s3(s3, st, producer)      # primary (guarded within) + extra sources
            poll_fidelity_logs_s3(s3, st, producer)  # opt-in prefixes/buckets; no-op when unset
            _lane("change_audit", poll_cloudtrail, ct, producer, st)
            # Seam lane in its OWN guard: a seam hiccup must never block the
            # flow/cloudtrail lanes' save_state below (P1-11, seen live on the
            # Azure side 2026-07-15).
            if CLOUD_SEAM_TELEMETRY and time.time() - last_seam >= SEAM_EVERY_S:
                try:
                    st["seam_every_s"] = SEAM_EVERY_S
                    counts = seam_aws.run(session, producer, TENANT, st, AWS_METERED_METRICS)
                    jlog("aws seams", **counts)
                except Exception as exc:  # noqa: BLE001 - lane isolation
                    jlog("aws seam error", error=str(exc)[:200])
                last_seam = time.time()
            save_state(st)
        except Exception as exc:  # noqa: BLE001 - poller must survive transient API errors
            jlog("poll cycle error", error=str(exc)[:200])

        # ── GCP (provider-parity program #105) ─────────────────────────────
        # Same separate-failure-domain rule as Azure (audit P1-11): a GCP
        # hiccup must never roll back the AWS/Azure checkpoints.
        if gcp_ready:
            try:
                gtok = gcp.token()
                now = time.time()
                if now - last_gcp_inventory >= DISCOVER_EVERY_S:
                    ninv = gcp.write_inventory(gtok, RUNTIME_OUT)
                    last_gcp_inventory = now
                    source_status.clear("gcp", "inventory", tenant=TENANT,
                                        account=gcp.PROJECT)
                    jlog("gcp inventory", resources=ninv)
                if GCP_METERED_METRICS and now - last_gcp_metrics >= METRICS_EVERY_S:
                    g_insts = gcp.list_instances(gtok)
                    n = gcp.poll_metrics(gtok, g_insts)
                    last_gcp_metrics = now
                    jlog("gcp metrics", events=n, instances=len(g_insts),
                         running=sum(1 for i in g_insts if i.get("power_state") == "running"))
                since = st.get("gcp_audit_ts") or _iso_minutes_ago(15)
                nc, newest, seen = gcp.poll_audit_log(
                    gtok, producer, TENANT, since, st.get("gcp_audit_seen") or [])
                if newest != since or seen != (st.get("gcp_audit_seen") or []):
                    st["gcp_audit_ts"] = newest
                    st["gcp_audit_seen"] = seen
                    save_state(st)
                if nc:
                    jlog("gcp control plane", changes=nc)
                if CLOUD_SEAM_TELEMETRY and now - last_gcp_seam >= SEAM_EVERY_S:
                    try:
                        ns = gcp.poll_router_seams(
                            gtok, producer, TENANT, st, now, _iso_minutes_ago(0))
                        save_state(st)
                        if ns:
                            jlog("gcp seams", signals=ns)
                    except Exception as exc:  # noqa: BLE001 - lane isolation
                        jlog("gcp seam error", error=str(exc)[:200])
                    last_gcp_seam = now
                # Log-fidelity lanes (flow/firewall/LB+Armor/DNS): opt-in gates
                # live in gcp.py; poll_log_lanes has per-lane isolation inside,
                # and this outer guard keeps a lane-table bug from touching the
                # audit/seam checkpoints above (P1-11 discipline).
                if now - last_gcp_logs >= GCP_LOG_LANES_EVERY_S:
                    try:
                        nl = gcp.poll_log_lanes(
                            gtok, producer, TENANT, st, _iso_minutes_ago(15))
                        save_state(st)
                        if nl:
                            jlog("gcp log lanes", signals=nl)
                    except Exception as exc:  # noqa: BLE001 - lane isolation
                        jlog("gcp log lanes error", error=str(exc)[:200])
                    last_gcp_logs = now
            except Exception as exc:  # noqa: BLE001 - lane isolation
                # A denied token mint / API read is a structured, renderable
                # state ("permission denied since <t>"), not only a log line.
                source_status.note("gcp", "inventory", exc, tenant=TENANT,
                                   account=gcp.PROJECT)
                jlog("gcp cycle error", error=str(exc)[:200])

        # ── AZURE ───────────────────────────────────────────────────────────
        # A separate failure domain on purpose: an Azure hiccup must never roll
        # back the AWS checkpoints (audit P1-11 — the four AWS lanes shared one
        # try/except and one save_state).
        if az_ready:
            try:
                tok = azure.token()
                now = time.time()
                # Live inventory on the discover cadence — azure.json is poller-
                # written like aws.json, never a rotting hand-written fixture
                # (audit D-P0-4 / P1-3: ARM-id keyed, power_state carried).
                if now - last_az_inventory >= DISCOVER_EVERY_S:
                    ninv = azure.write_inventory(tok, RUNTIME_OUT)
                    source_status.clear("azure", "inventory", tenant=TENANT,
                                        account=azure.SUBSCRIPTION)
                    # In-cloud NETWORK topology (VNet→subnet→route-table→gateway),
                    # the Azure twin of discover.py's AWS route-table map. Same
                    # discover cadence, own guard so a topology hiccup can't block
                    # the inventory write above.
                    try:
                        ntopo = azure_topology.write_topology(tok, RUNTIME_OUT)
                    except Exception as exc:  # noqa: BLE001 - lane isolation
                        ntopo = -1
                        jlog("azure topology error", error=str(exc)[:200])
                    last_az_inventory = now
                    jlog("azure inventory", resources=ninv, topology_edges=ntopo)
                if now - last_az_metrics >= AZ_METRICS_EVERY_S:
                    az_vms = azure.list_vms(tok)
                    n = azure.poll_metrics(tok, az_vms)
                    last_az_metrics = now
                    jlog("azure metrics", events=n, vms=len(az_vms),
                         running=sum(1 for v in az_vms if v.get("power_state") == "running"))
                if CLOUD_SEAM_TELEMETRY and now - last_az_seam >= SEAM_EVERY_S:
                    try:
                        ns = azure.poll_seams(
                            tok, producer, TENANT, st, now, _iso_minutes_ago(0))
                        save_state(st)
                        if ns:
                            jlog("azure seams", signals=ns)
                    except Exception as exc:  # noqa: BLE001 - lane isolation
                        jlog("azure seam error", error=str(exc)[:200])
                    last_az_seam = now
                # Storage-delivered log lanes (VNet flow / LB access / WAF /
                # DNS → bounded rollups on netops.cloud). Own guard: a storage
                # hiccup must never block metrics/health/activity (P1-11);
                # azure_logs.run additionally isolates each container inside.
                if azure_logs.configured() and now - last_az_logs >= AZ_LOGS_EVERY_S:
                    try:
                        stok = azure.token(scope=azure_logs.STORAGE_SCOPE)
                        counts = azure_logs.run(stok, producer, TENANT, st)
                        save_state(st)
                        if any(counts.values()):
                            jlog("azure log lanes", **counts)
                    except Exception as exc:  # noqa: BLE001 - lane isolation
                        jlog("azure logs error", error=str(exc)[:200])
                    last_az_logs = now
                if now - last_az_health >= AZ_HEALTH_EVERY_S:
                    h = azure.poll_resource_health(tok, producer, TENANT)
                    since = st.get("azure_activity_ts") or _iso_minutes_ago(15)
                    c, newest = azure.poll_activity_log(tok, producer, TENANT, since)
                    st["azure_activity_ts"] = newest
                    last_az_health = now
                    if h or c:
                        jlog("azure control plane", health=h, changes=c)
                    save_state(st)
            except Exception as exc:  # noqa: BLE001
                source_status.note("azure", "inventory", exc, tenant=TENANT,
                                   account=azure.SUBSCRIPTION)
                jlog("azure cycle error", error=str(exc)[:200])

        # ── CONNECTORS (per-tenant ingestion, Wave 1 #2) ────────────────────
        # Its own failure domain, like Azure/GCP: a broker or provider hiccup
        # must never roll back the ambient lanes' checkpoints above.
        if connector_mode and time.time() - last_connectors >= CONNECTOR_EVERY_S:
            try:
                counts = connector_cycle(producer, st)
                save_state(st)
                jlog("connector cycle", **counts)
            except Exception as exc:  # noqa: BLE001 — lane isolation
                jlog("connector cycle error", error=str(exc)[:200])
            last_connectors = time.time()

        # Structured error reporting (Wave 2 #4): ship the CURRENT permission/
        # misconfiguration set to the platform once per loop. Best-effort and
        # bounded inside; a report failure never touches the lanes above.
        source_status.flush()

        time.sleep(POLL_S)


if __name__ == "__main__":
    main()
