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
import cloudmetrics
import discover
import gcp

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
OUT_DIR = os.environ.get("CLOUD_LOGS_OUT", "/out")
BROKERS = os.environ.get("BROKER_URLS", "kafka:9092")
TENANT = os.environ.get("CLOUD_TENANT", "global")
ACCOUNT = os.environ.get("CLOUD_ACCOUNT", "945714973156")
POLL_S = int(os.environ.get("POLL_S", "60"))
DISCOVER_EVERY_S = int(os.environ.get("DISCOVER_EVERY_S", "300"))
# CloudWatch metric lane (Service View counters + CUSUM evidence). CloudWatch's
# free basic resolution is 5 min, so polling faster only re-reads the same point.
METRICS_EVERY_S = int(os.environ.get("CW_METRICS_EVERY_S", "300"))
# Azure platform metrics are 1-minute and FREE (richer than CloudWatch's 5-min
# free tier), so the Azure lane polls faster.
AZ_METRICS_EVERY_S = int(os.environ.get("AZ_METRICS_EVERY_S", "60"))
AZ_HEALTH_EVERY_S = int(os.environ.get("AZ_HEALTH_EVERY_S", "120"))
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


def poll_flow_logs(logs, st: dict) -> None:
    start = int(st.get("flow_ts", (time.time() - 300) * 1000))
    kwargs = {"logGroupName": LOG_GROUP, "startTime": start + 1}
    written = 0
    newest = start
    try:
        while True:
            resp = logs.filter_log_events(**kwargs)
            events = resp.get("events", [])
            if events:
                _roll_if_large(os.path.join(OUT_DIR, "aws-vpc-flow.vpc"))
                with open(os.path.join(OUT_DIR, "aws-vpc-flow.vpc"), "a") as f:
                    for e in events:
                        f.write(e["message"].rstrip("\n") + "\n")
                        newest = max(newest, e["timestamp"])
                        written += 1
            token = resp.get("nextToken")
            if not token:
                break
            kwargs["nextToken"] = token
    except logs.exceptions.ResourceNotFoundException:
        jlog("flow log group missing (not enabled yet?)", group=LOG_GROUP)
        return
    if written:
        st["flow_ts"] = newest
        jlog("flow events appended", count=written)


def _poll_s3_lane(s3, st: dict, bucket: str, prefix: str, state_key: str,
                  out_name: str, skip_prefixes: tuple = ()) -> int:
    """One S3 log lane: fetch .gz objects under `prefix` newer than the
    checkpoint, decompress, append raw lines to OUT_DIR/out_name for the
    correlation tailer (which owns parsing/rollup). Shared by VPC flow, ALB
    access, WAF and Resolver query logs — same checkpoint discipline (P0-3),
    same rotation guard (P0-4)."""
    import gzip
    last_key = st.get(state_key, "")
    kwargs = {"Bucket": bucket, "MaxKeys": 200}
    if prefix:
        kwargs["Prefix"] = prefix
    if last_key:
        kwargs["StartAfter"] = last_key
    written = 0
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
        last_key = max(last_key, key)
    if last_key:
        st[state_key] = last_key
    return written


def poll_flow_logs_s3(s3, st: dict) -> None:
    """VPC flow logs delivered to S3 (header line stripped)."""
    n = _poll_s3_lane(s3, st, FLOW_S3_BUCKET, FLOW_S3_PREFIX, "flow_s3_key",
                      "aws-vpc-flow.vpc", skip_prefixes=("version ",))
    if n:
        jlog("flow records appended from s3", count=n)


def poll_fidelity_logs_s3(s3, st: dict) -> None:
    """The log-fidelity lanes (ALB access / WAF / Resolver query logs), each an
    opt-in S3 prefix. Absent prefix = lane off — nothing is guessed."""
    lanes = [
        (ALB_S3_PREFIX, "alb_s3_key", "aws-alb-access.alb"),
        (WAF_S3_PREFIX, "waf_s3_key", "aws-waf.waf"),
        (DNS_S3_PREFIX, "dns_s3_key", "aws-r53-resolver.dns"),
    ]
    for prefix, state_key, out_name in lanes:
        if not prefix:
            continue
        n = _poll_s3_lane(s3, st, LOGS_S3_BUCKET or FLOW_S3_BUCKET, prefix, state_key, out_name)
        if n:
            jlog("fidelity records appended from s3", lane=out_name, count=n)


def poll_cloudtrail(ct, producer, st: dict) -> None:
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
        name = e.get("EventName", "")
        if not name.startswith(TRAIL_PREFIXES) or name in TRAIL_EXCLUDE:
            continue
        ts = e["EventTime"].timestamp()
        newest = max(newest, ts)
        detail = json.loads(e.get("CloudTrailEvent", "{}"))
        resources = e.get("Resources") or []
        rid = resources[0]["ResourceName"] if resources else name
        producer.send("netops.cloud", {
            "kind": "cloud_change",
            "tenant_id": TENANT,
            "resource_id": rid,
            "account": ACCOUNT,
            "region": REGION,
            "severity": "medium",
            "metric_name": name,
            "ts": e["EventTime"].isoformat(),
            "attrs": {
                "provider": "aws",
                "event_source": detail.get("eventSource", ""),
                "actor": (detail.get("userIdentity") or {}).get("arn", ""),
                "request_id": detail.get("requestID", ""),
            },
        })
        sent += 1
    if sent:
        producer.flush(10)
        st["trail_ts"] = newest
        jlog("cloudtrail changes produced", count=sent)


def _iso_minutes_ago(minutes: int) -> str:
    import datetime as _dt
    t = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(minutes=minutes)
    return t.replace(microsecond=0).isoformat().replace("+00:00", "Z")


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
    gcp_ready = gcp.configured()
    jlog("gcp lane", configured=gcp_ready)
    last_gcp_inventory = 0.0
    last_gcp_metrics = 0.0
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
            if inventory and time.time() - last_metrics >= METRICS_EVERY_S:
                n = cloudmetrics.poll(cw, inventory)
                last_metrics = time.time()
                jlog("cloud metrics", events=n, instances=len(inventory))
            if LOG_GROUP:
                poll_flow_logs(logs, st)
            if FLOW_S3_BUCKET:
                poll_flow_logs_s3(s3, st)
            poll_fidelity_logs_s3(s3, st)  # opt-in prefixes; no-op when unset
            poll_cloudtrail(ct, producer, st)
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
                    ninv = gcp.write_inventory(gtok, os.environ.get("CLOUD_FIXTURES_OUT", "/fixtures"))
                    last_gcp_inventory = now
                    jlog("gcp inventory", resources=ninv)
                if now - last_gcp_metrics >= METRICS_EVERY_S:
                    g_insts = gcp.list_instances(gtok)
                    n = gcp.poll_metrics(gtok, g_insts)
                    last_gcp_metrics = now
                    jlog("gcp metrics", events=n, instances=len(g_insts),
                         running=sum(1 for i in g_insts if i.get("power_state") == "running"))
                since = st.get("gcp_audit_ts") or _iso_minutes_ago(15)
                nc, newest = gcp.poll_audit_log(gtok, producer, TENANT, since)
                if newest != since:
                    st["gcp_audit_ts"] = newest
                    save_state(st)
                if nc:
                    jlog("gcp control plane", changes=nc)
            except Exception as exc:  # noqa: BLE001 - lane isolation
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
                    ninv = azure.write_inventory(tok, os.environ.get("CLOUD_FIXTURES_OUT", "/fixtures"))
                    last_az_inventory = now
                    jlog("azure inventory", resources=ninv)
                if now - last_az_metrics >= AZ_METRICS_EVERY_S:
                    az_vms = azure.list_vms(tok)
                    n = azure.poll_metrics(tok, az_vms)
                    last_az_metrics = now
                    jlog("azure metrics", events=n, vms=len(az_vms),
                         running=sum(1 for v in az_vms if v.get("power_state") == "running"))
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
                jlog("azure cycle error", error=str(exc)[:200])

        time.sleep(POLL_S)


if __name__ == "__main__":
    main()
