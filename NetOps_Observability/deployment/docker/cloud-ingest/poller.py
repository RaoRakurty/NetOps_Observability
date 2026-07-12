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

REGION = os.environ.get("AWS_REGION", "us-west-2")
LOG_GROUP = os.environ.get("FLOW_LOG_GROUP", "")  # CloudWatch lane (needs delivery role)
FLOW_S3_BUCKET = os.environ.get("FLOW_S3_BUCKET", "")  # S3 lane (no IAM role needed)
OUT_DIR = os.environ.get("CLOUD_LOGS_OUT", "/out")
BROKERS = os.environ.get("BROKER_URLS", "kafka:9092")
TENANT = os.environ.get("CLOUD_TENANT", "global")
ACCOUNT = os.environ.get("CLOUD_ACCOUNT", "945714973156")
POLL_S = int(os.environ.get("POLL_S", "60"))
STATE_PATH = os.path.join(OUT_DIR, ".poller-state.json")

# Interesting = network/security/compute mutations (cloud_change evidence).
TRAIL_PREFIXES = ("Modify", "Create", "Delete", "Revoke", "Authorize", "Stop",
                  "Start", "Terminate", "Reboot", "Replace", "Attach", "Detach",
                  "Disassociate", "Associate", "Put", "Update")


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


def poll_flow_logs_s3(s3, st: dict) -> None:
    """VPC flow logs delivered to S3: fetch objects newer than the checkpoint key,
    strip the header line, append raw v2 records for the correlation tailer."""
    import gzip
    last_key = st.get("flow_s3_key", "")
    kwargs = {"Bucket": FLOW_S3_BUCKET, "MaxKeys": 200}
    if last_key:
        kwargs["StartAfter"] = last_key
    written = 0
    resp = s3.list_objects_v2(**kwargs)
    for obj in resp.get("Contents", []):
        key = obj["Key"]
        if not key.endswith(".log.gz"):
            last_key = max(last_key, key)
            continue
        body = s3.get_object(Bucket=FLOW_S3_BUCKET, Key=key)["Body"].read()
        text = gzip.decompress(body).decode()
        with open(os.path.join(OUT_DIR, "aws-vpc-flow.vpc"), "a") as f:
            for line in text.splitlines():
                if line.startswith("version ") or not line.strip():
                    continue
                f.write(line + "\n")
                written += 1
        last_key = max(last_key, key)
    if last_key:
        st["flow_s3_key"] = last_key
    if written:
        jlog("flow records appended from s3", count=written)


def poll_cloudtrail(ct, producer, st: dict) -> None:
    import datetime
    start = st.get("trail_ts", time.time() - 900)
    start_dt = datetime.datetime.fromtimestamp(start + 0.001, datetime.timezone.utc)
    newest = start
    sent = 0
    resp = ct.lookup_events(StartTime=start_dt, MaxResults=50)
    for e in resp.get("Events", []):
        name = e.get("EventName", "")
        if not name.startswith(TRAIL_PREFIXES):
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


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    session = boto3.Session(region_name=REGION)
    logs = session.client("logs")
    ct = session.client("cloudtrail")
    s3 = session.client("s3")
    producer = KafkaProducer(
        bootstrap_servers=BROKERS.split(","),
        value_serializer=lambda v: json.dumps(v).encode(),
        acks="all", linger_ms=100, retries=5)
    jlog("cloud-ingest started", group=LOG_GROUP, brokers=BROKERS, tenant=TENANT)
    st = load_state()
    while True:
        try:
            if LOG_GROUP:
                poll_flow_logs(logs, st)
            if FLOW_S3_BUCKET:
                poll_flow_logs_s3(s3, st)
            poll_cloudtrail(ct, producer, st)
            save_state(st)
        except Exception as exc:  # noqa: BLE001 - poller must survive transient API errors
            jlog("poll cycle error", error=str(exc)[:200])
        time.sleep(POLL_S)


if __name__ == "__main__":
    main()
