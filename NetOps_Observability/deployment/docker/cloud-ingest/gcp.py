"""GCP → the platform's canonical lanes (provider-parity program, tracker #105).

Mirrors azure.py's architecture 1:1 so every downstream consumer stays
provider-blind:

  inventory  Compute API      → gcp.json fixture (poller-written, live — the
                                same contract discover.py/write_inventory keep
                                for AWS/Azure: stable id keys + power_state)
  metrics    Cloud Monitoring → MetricEvent → Vector :8690 → netops.metrics
                                (the SAME canonical cloud_* series)
  changes    Audit Logs       → cloud_change → netops.cloud

Identity: resource_id is the instance's full resource PATH
(projects/<p>/zones/<z>/instances/<name>) — globally unique, matches the
metric label we emit, and is what the console deep-link builder consumes.
Names collide across projects/zones the same way they do across clouds; the
path never does (same rule as Azure ARM ids, audit P1-3).

HONEST GAP (parity matrix): GCP has no StatusCheckFailed-equivalent platform
metric; the provider-verdict lane stays absent rather than fabricated. The
lifecycle truth (power_state) still carries stopped≠broken, and uptime-based
liveness is a later refinement.

Auth: service account via google-auth (the official minimal library — the SA
OAuth flow needs RS256 signing that stdlib cannot do; same dependency posture
as boto3 in this container). Roles: roles/compute.viewer +
roles/monitoring.viewer + roles/logging.viewer (see CREDENTIALS.md).
Cost: $0 — inventory, platform metrics and admin-activity audit logs are free.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import urllib.parse
import urllib.request

import cloud_events
import trail_state

PROJECT = os.environ.get("GCP_PROJECT", "")
CREDS_PATH = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")
METRICS_SINK = os.environ.get("METRIC_EVENT_SINK_URL", "http://vector-aggregator:8690/")

# canonical series (identical names to the AWS/Azure lanes — provider-blind):
# (monitoring metric type, canonical name, unit, is_rate_fraction)
GCP_METRICS = [
    ("compute.googleapis.com/instance/cpu/utilization", "cloud_cpu_util", "percent", True),
    ("compute.googleapis.com/instance/network/received_bytes_count", "cloud_net_in_bytes", "bytes", False),
    ("compute.googleapis.com/instance/network/sent_bytes_count", "cloud_net_out_bytes", "bytes", False),
]

# audit-log methods that are telemetry chatter, never a change a NOC acts on.
# SUFFIX match — a bare ".get" substring also killed legitimate method names
# that merely contain it (telemetry-audit finding, 2026-07-14).
CHANGE_EXCLUDE_SUFFIXES = (".get", ".list", ".aggregatedList", ".getIamPolicy")


def configured() -> bool:
    return bool(PROJECT and CREDS_PATH and os.path.exists(CREDS_PATH))


_creds = None


def token() -> str:
    """Access token from the configured credential — EITHER a service-account
    key (RS256 JWT exchange) OR an authorized-user credential (refresh-token
    flow). google.auth.load_credentials_from_file transparently handles both,
    so a consumer GCP account that is blocked from creating SA keys (org policy
    iam.disableServiceAccountKeyCreation with no organization to override it)
    can still feed the poller via `gcloud auth application-default login`.
    Cached + auto-refreshed."""
    global _creds
    import google.auth  # deferred: lane may be off
    from google.auth.transport.requests import Request
    if _creds is None:
        _creds, _ = google.auth.load_credentials_from_file(
            CREDS_PATH, scopes=["https://www.googleapis.com/auth/cloud-platform"])
    if not _creds.valid:
        _creds.refresh(Request())
    return _creds.token


def _gcp_headers(tok: str) -> dict:
    """Common request headers. X-Goog-User-Project attributes quota/billing to
    our project — REQUIRED when the credential is an authorized-user login (no
    resource project of its own), harmless for a service-account key."""
    return {"Authorization": f"Bearer {tok}", "X-Goog-User-Project": PROJECT}


def _get_json(url: str, tok: str) -> dict:
    req = urllib.request.Request(url, headers=_gcp_headers(tok))
    with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310
        return json.loads(resp.read().decode())


def _post_ndjson(events: list[dict]) -> None:
    if not events:
        return
    body = "\n".join(json.dumps(e) for e in events).encode()
    req = urllib.request.Request(METRICS_SINK, data=body,
                                 headers={"Content-Type": "application/x-ndjson"})
    urllib.request.urlopen(req, timeout=10).read()  # noqa: S310


APP_TAG_KEYS = ("app_id", "app", "application", "app_name", "app-name", "service", "workload")


def list_instances(tok: str) -> list[dict]:
    """All instances across zones (aggregated list, paged)."""
    out: list[dict] = []
    url = (f"https://compute.googleapis.com/compute/v1/projects/{PROJECT}"
           f"/aggregated/instances?returnPartialSuccess=true")
    while url:
        res = _get_json(url, tok)
        for scope, wrap in (res.get("items") or {}).items():
            for inst in wrap.get("instances") or []:
                zone = scope.split("/")[-1]
                nics = inst.get("networkInterfaces") or []
                private = [n.get("networkIP") for n in nics if n.get("networkIP")]
                public = [ac.get("natIP") for n in nics
                          for ac in (n.get("accessConfigs") or []) if ac.get("natIP")]
                out.append({
                    "resource_id": f"projects/{PROJECT}/zones/{zone}/instances/{inst.get('name', '')}",
                    "name": inst.get("name", ""),
                    "numeric_id": str(inst.get("id", "")),
                    "zone": zone,
                    "region": zone.rsplit("-", 1)[0],
                    # RUNNING | STOPPING | TERMINATED … → lifecycle truth,
                    # lower-cased into the shared power_state vocabulary.
                    "power_state": str(inst.get("status", "")).lower(),
                    "machine_type": str(inst.get("machineType", "")).rsplit("/", 1)[-1],
                    "private_ips": private,
                    "public_ips": public,
                    "tags": inst.get("labels") or {},  # GCP labels = the tag surface
                })
        token_next = res.get("nextPageToken")
        url = (url.split("&pageToken=")[0] + "&pageToken=" + token_next) if token_next else ""
    return out


def write_inventory(tok: str, fixtures_dir: str) -> int:
    """Discover instances and REWRITE gcp.json — the same live-fixture contract
    the AWS (discover.py) and Azure (azure.write_inventory) lanes keep."""
    resources = []
    for inst in sorted(list_instances(tok), key=lambda i: i["resource_id"]):
        tags = inst["tags"]
        resources.append({
            "region": inst["region"],
            "zone": inst["zone"],
            "resource_id": inst["resource_id"],
            "resource_arn_or_uri": inst["resource_id"],
            "resource_type": "compute:instance",
            "resource_name": inst["name"],
            "power_state": inst["power_state"],
            "instance_type": inst["machine_type"],
            "private_ips": inst["private_ips"],
            "public_ips": inst["public_ips"],
            "network_interface_ids": [],
            "tags": tags,
            "owner": tags.get("owner", ""),
            "env": tags.get("environment", tags.get("env", "")),
            "source": "cloud_api",
            "confidence": "confirmed" if any(k in tags for k in APP_TAG_KEYS) else "strong",
        })
    # Live-poller provenance stamp — same contract as discover.py/azure.py
    # (pinned by cloud/provider_test.go); drives the UI's honest data-mode badge.
    inventory = {
        "provider": "gcp", "account_id": PROJECT,
        "collection": {"mode": "live_poller",
                       "collected_at": dt.datetime.now(dt.timezone.utc).isoformat()},
        "resources": resources,
    }
    os.makedirs(fixtures_dir, exist_ok=True)
    path = os.path.join(fixtures_dir, "gcp.json")
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(inventory, f, indent=2)
    os.replace(tmp, path)
    return len(resources)


def poll_metrics(tok: str, instances: list[dict]) -> int:
    """Cloud Monitoring → the canonical metric lane. Window ends one full minute
    in the past — the newest point is still filling (the same in-flight-bucket
    rule the AWS lane learned the hard way, audit P0-2)."""
    running = {i["numeric_id"]: i for i in instances if i["power_state"] == "running"}
    if not running:
        return 0
    end = dt.datetime.now(dt.timezone.utc).replace(microsecond=0) - dt.timedelta(minutes=1)
    start = end - dt.timedelta(minutes=5)
    events: list[dict] = []
    for mtype, canon, unit, is_fraction in GCP_METRICS:
        q = urllib.parse.urlencode({
            "filter": f'metric.type="{mtype}" AND resource.type="gce_instance"',
            "interval.startTime": start.isoformat().replace("+00:00", "Z"),
            "interval.endTime": end.isoformat().replace("+00:00", "Z"),
        })
        url = f"https://monitoring.googleapis.com/v3/projects/{PROJECT}/timeSeries?{q}"
        while url:
            res = _get_json(url, tok)
            for ts in res.get("timeSeries") or []:
                inst_id = (ts.get("resource", {}).get("labels", {}) or {}).get("instance_id", "")
                inst = running.get(inst_id)
                if not inst:
                    continue  # stopped/unknown instances emit nothing (stopped ≠ broken)
                points = ts.get("points") or []
                if not points:
                    continue
                latest = points[0]
                val = latest.get("value", {})
                v = float(val.get("doubleValue", val.get("int64Value", 0)) or 0)
                if is_fraction:
                    v *= 100.0  # fraction → percent (canonical form)
                # MetricEvent contract via the shared builder (cloud_events.py)
                # so AWS/Azure/GCP are provably one shape. This lane was never
                # live-tested (cred-gated) and had drifted: it emitted "name"
                # instead of "metric" and omitted vendor/signal_family/
                # collection_path, so the sink dropped the metric name and no GCP
                # series ever formed. Fixed 2026-07-15 on the first live GCP VM;
                # the shared builder makes that drift a ValueError, not a silent
                # drop.
                events.append(cloud_events.metric_event(
                    vendor="gcp", device=inst["name"], index=inst["resource_id"],
                    metric=canon, value=v, unit=unit,
                    ts=latest.get("interval", {}).get("endTime", "")))
            token_next = res.get("nextPageToken")
            url = (url.split("&pageToken=")[0] + "&pageToken=" + token_next) if token_next else ""
    _post_ndjson(events)
    return len(events)


def _overlap_since(since: str, seconds: int = 120) -> str:
    """Cursor minus a trailing overlap window. Cloud Logging entries can arrive
    LATE (receiveTimestamp > timestamp); a bare newest-timestamp cursor silently
    drops them forever — the same checkpoint bug class CloudTrail P0-3 fixed.
    The overlap re-reads the tail; insertId dedup keeps re-reads idempotent."""
    try:
        t = dt.datetime.fromisoformat(since.replace("Z", "+00:00"))
        return (t - dt.timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")
    except ValueError:
        return since


def poll_audit_log(tok: str, producer, tenant: str, since: str,
                   seen_ids: list | None = None) -> tuple[int, str, list]:
    """Admin-activity audit log → cloud_change (the CloudTrail/Activity Log
    equivalent). Checkpointed on the newest timestamp seen, with a trailing
    overlap + insertId dedup so late-arriving entries are neither dropped nor
    double-emitted. `seen_ids` is the caller-persisted dedup window."""
    seen = set(seen_ids or [])
    body = json.dumps({
        "resourceNames": [f"projects/{PROJECT}"],
        "filter": (f'logName="projects/{PROJECT}/logs/cloudaudit.googleapis.com%2Factivity" '
                   f'AND timestamp>"{_overlap_since(since)}"'),
        "orderBy": "timestamp asc",
        "pageSize": 200,
    }).encode()
    req = urllib.request.Request(
        "https://logging.googleapis.com/v2/entries:list", data=body,
        headers={**_gcp_headers(token()), "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310
        res = json.loads(resp.read().decode())
    n, newest = 0, since
    saw = False
    new_seen: list = []
    for e in res.get("entries") or []:
        # Checkpoint anchors on everything SEEN — matched, excluded or deduped.
        # Advancing only past matched entries pinned `since` through windows of
        # excluded-method churn (the trail_ts defect class; see trail_state.py).
        # The insertId overlap dedup makes advancing over skipped entries safe.
        saw = True
        newest = max(newest, str(e.get("timestamp", "")))
        insert_id = str(e.get("insertId", ""))
        if insert_id:
            new_seen.append(insert_id)
            if insert_id in seen:
                continue  # overlap re-read: already emitted
        proto = e.get("protoPayload", {}) or {}
        method = str(proto.get("methodName", ""))
        if not method or method.endswith(CHANGE_EXCLUDE_SUFFIXES):
            continue
        ts = str(e.get("timestamp", ""))
        producer.send("netops.cloud", {
            "kind": "cloud_change",
            "tenant_id": tenant,
            "resource_id": str(proto.get("resourceName", "")),
            "region": "",
            "severity": "info",
            "metric_name": method,
            "ts": ts,
            "attrs": {
                "provider": "gcp",
                "account": PROJECT,
                "event_name": method,
                "actor": str((proto.get("authenticationInfo") or {}).get("principalEmail", "")),
                "event_source": "gcp_audit_log",
                "request_id": str(e.get("insertId", "")),
            },
        })
        n += 1
    # A cleanly-fetched EMPTY window still advances (delivery-lagged now) so
    # quiet periods stay one page wide instead of growing without bound.
    if not saw:
        lagged = (dt.datetime.now(dt.timezone.utc)
                  - dt.timedelta(seconds=trail_state.DELIVERY_LAG_S))
        newest = trail_state.advance_checkpoint_any(
            since, newest, False,
            lagged.replace(microsecond=0).isoformat().replace("+00:00", "Z"))
    # trim the dedup window to the entries the next overlap can re-read
    return n, newest, new_seen[-500:]


# ── hybrid-seam lane (#105 P1): Cloud Router BGP/BFD via FREE REST ───────────
# getRouterStatus returns live per-peer BGP state (status UP/DOWN, session
# state, numLearnedRoutes) with zero Monitoring-API metering — the strongest
# free seam-state source of any provider. Transitions ride the shared
# SeamStateTracker; route-count collapse uses material_route_drop (expected-
# count context, never a fixed threshold).

from seam_state import SeamStateTracker, material_route_drop  # noqa: E402


def list_routers(tok: str) -> list[dict]:
    out: list[dict] = []
    url = (f"https://compute.googleapis.com/compute/v1/projects/{PROJECT}"
           f"/aggregated/routers?returnPartialSuccess=true")
    while url:
        res = _get_json(url, tok)
        for scope, wrap in (res.get("items") or {}).items():
            for r in wrap.get("routers") or []:
                region = scope.split("/")[-1]
                out.append({"name": r.get("name", ""), "region": region,
                            "id": f"projects/{PROJECT}/regions/{region}/routers/{r.get('name', '')}"})
        nxt = res.get("nextPageToken")
        url = (url.split("&pageToken=")[0] + "&pageToken=" + nxt) if nxt else ""
    return out


def poll_router_seams(tok: str, producer, tenant: str, st: dict, now: float,
                      observed_at: str) -> int:
    """Per-peer BGP state + learned-route counts for every Cloud Router.
    Emits transition + route-drop signals; persists tracker/counts via st."""
    tracker = SeamStateTracker.from_state(st.get("gcp_seam_tracker"))
    route_prev: dict = st.get("gcp_route_counts") or {}
    route_new: dict = {}
    n = 0
    for router in list_routers(tok):
        try:
            res = _get_json(
                f"https://compute.googleapis.com/compute/v1/{router['id']}/getRouterStatus", tok)
        except Exception:  # noqa: BLE001 - one router's failure never kills the rest
            continue
        for peer in (res.get("result") or {}).get("bgpPeerStatus") or []:
            key = f"gcprouter:{router['id']}:{peer.get('name', '')}"
            status = str(peer.get("status", "")).lower()  # UP | DOWN | UNKNOWN
            learned = int(peer.get("numLearnedRoutes", 0) or 0)
            for tr in tracker.observe(key, status or "unknown", observed_at, now):
                to = tr["to"]
                kind = ("cloud_bgp_session_down" if to == "down"
                        else "cloud_bgp_session_up" if to == "up"
                        else "cloud_state_unknown")
                if tr.get("flap"):
                    kind = "cloud_bgp_flap"
                producer.send("netops.cloud", {
                    "kind": kind, "tenant_id": tenant,
                    "resource_id": key, "region": router["region"],
                    "severity": "crit" if to == "down" else "info",
                    "metric_name": kind, "value": 1.0, "ts": observed_at,
                    "attrs": {"provider": "gcp", "evidence_class": "state_transition",
                              "router": router["id"], "peer": peer.get("name", ""),
                              "peer_address": peer.get("peerIpAddress", ""),
                              "session_state": peer.get("state", ""),
                              "from_state": tr.get("from", ""), "to_state": to},
                })
                n += 1
            route_new[key] = learned
            if material_route_drop(route_prev.get(key), learned):
                producer.send("netops.cloud", {
                    "kind": "cloud_route_count_drop", "tenant_id": tenant,
                    "resource_id": key, "region": router["region"],
                    "severity": "high", "metric_name": "learned_routes",
                    "value": float(learned), "ts": observed_at,
                    "attrs": {"provider": "gcp", "evidence_class": "route_change",
                              "router": router["id"], "peer": peer.get("name", ""),
                              "previous": str(route_prev.get(key, "")),
                              "bgp_state": tracker.current(key)},
                })
                n += 1
    for tr in tracker.expire(freshness_s=3 * 300, now=now):
        producer.send("netops.cloud", {
            "kind": "cloud_state_unknown", "tenant_id": tenant,
            "resource_id": tr["key"], "region": "",
            "severity": "warn", "metric_name": "cloud_state_unknown",
            "value": 1.0, "ts": tr["observed_at"],
            "attrs": {"provider": "gcp", "evidence_class": "state",
                      "from_state": tr["from"], "stale_after_s": str(tr["stale_after_s"])},
        })
        n += 1
    st["gcp_seam_tracker"] = tracker.to_state()
    st["gcp_route_counts"] = route_new
    return n
