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
import gcp_components
import gcp_log_lanes
import trail_state

PROJECT = os.environ.get("GCP_PROJECT", "")
CREDS_PATH = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")
METRICS_SINK = os.environ.get("METRIC_EVENT_SINK_URL", "http://vector-aggregator:8690/")

# ── log-fidelity lane gates (#105 parity: flow/firewall/LB+Armor/DNS) ────────
# Each lane is an explicit OPT-IN ("on"), mirroring the AWS S3-prefix gates:
# these log families only exist when the customer enabled them in GCP (flow
# logs per subnet, Firewall Rules Logging per rule, LB logging per backend
# service, a DNS logging policy), so an unset gate = lane honestly OFF — the
# matrix shows it disabled, the poller never guesses. entries:list reads are
# free, but the 60 req/min project quota is real: one bounded read per enabled
# lane per cadence, never per-instance.
GCP_VPC_FLOW_LOGS = os.environ.get("GCP_VPC_FLOW_LOGS", "").lower() == "on"
GCP_FIREWALL_LOGS = os.environ.get("GCP_FIREWALL_LOGS", "").lower() == "on"
GCP_LB_LOGS = os.environ.get("GCP_LB_LOGS", "").lower() == "on"
GCP_DNS_LOGS = os.environ.get("GCP_DNS_LOGS", "").lower() == "on"

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


def _post_json_api(url: str, body: dict, tok: str) -> dict:
    """Authenticated JSON POST (backendServices.getHealth is a POST read)."""
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(),
        headers={**_gcp_headers(tok), "Content-Type": "application/json"})
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
                # Network context (cloud-network-overview P0): the VPC network
                # is the segregation axis — carried on instances too.
                networks = [gcp_components.rel_path(n["network"])
                            for n in nics if n.get("network")]
                subnets = [gcp_components.rel_path(n["subnetwork"])
                           for n in nics if n.get("subnetwork")]
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
                    "vpc_id": networks[0] if networks else "",
                    "subnet_ids": subnets,
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
            "vpc_id": inst.get("vpc_id", ""),
            "subnet_ids": inst.get("subnet_ids", []),
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
    # Network components as first-class resources (P0): forwarding rules /
    # backend services (+health) / Cloud Armor / firewall rule-sets / DNS /
    # routers+NAT + the seam endpoints (VPN GW/tunnels/peerings). Per-family
    # isolation inside collect() — a degraded family is logged, the instance
    # inventory and the rest of the components still land.
    comp_rows, comp_errors = gcp_components.collect(
        lambda url: _get_json(url, tok),
        lambda url, body: _post_json_api(url, body, tok), PROJECT)
    resources.extend(comp_rows)
    if comp_errors:
        _lane_log("gcp component families degraded", errors=comp_errors)

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


_LOG_PAGE_SIZE = 200
_LOG_MAX_PAGES = 5  # bounded read per lane per cycle (1000-entry ceiling)


def list_log_entries(tok: str, log_filter: str, since: str,
                     seen_ids: list | None = None,
                     page_size: int = _LOG_PAGE_SIZE,
                     max_pages: int = _LOG_MAX_PAGES) -> tuple[list[dict], str, list]:
    """Cloud Logging entries:list with the checkpoint discipline poll_audit_log
    established, shared by every log lane (audit / vpc_flows / firewall / LB /
    dns_queries): trailing 120s overlap (late-arriving entries are re-read, not
    dropped — receiveTimestamp > timestamp is normal), insertId dedup (re-reads
    are idempotent), checkpoint anchored on everything SEEN (matched, excluded
    or deduped — the trail_ts defect class, see trail_state.py), and a cleanly
    fetched EMPTY window still advances (delivery-lagged now) so quiet periods
    stay one page wide instead of growing without bound.

    Bounded: page_size × max_pages entries per call — a burst past the ceiling
    is picked up next cycle from the advanced checkpoint, never buffered
    unboundedly. Returns (new entries — deduped, oldest→newest —, the next
    checkpoint, the next dedup window)."""
    seen = set(seen_ids or [])
    body = {
        "resourceNames": [f"projects/{PROJECT}"],
        "filter": f'{log_filter} AND timestamp>"{_overlap_since(since)}"',
        "orderBy": "timestamp asc",
        "pageSize": page_size,
    }
    newest, saw = since, False
    fresh: list[dict] = []
    new_seen: list = []
    for _ in range(max_pages):
        req = urllib.request.Request(
            "https://logging.googleapis.com/v2/entries:list",
            data=json.dumps(body).encode(),
            headers={**_gcp_headers(tok), "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310
            res = json.loads(resp.read().decode())
        for e in res.get("entries") or []:
            saw = True
            newest = max(newest, str(e.get("timestamp", "")))
            insert_id = str(e.get("insertId", ""))
            if insert_id:
                new_seen.append(insert_id)
                if insert_id in seen:
                    continue  # overlap re-read: already emitted
            fresh.append(e)
        page_token = res.get("nextPageToken")
        if not page_token:
            break
        body["pageToken"] = page_token
    if not saw:
        lagged = (dt.datetime.now(dt.timezone.utc)
                  - dt.timedelta(seconds=trail_state.DELIVERY_LAG_S))
        newest = trail_state.advance_checkpoint_any(
            since, newest, False,
            lagged.replace(microsecond=0).isoformat().replace("+00:00", "Z"))
    # trim the dedup window to what the next overlap could possibly re-read
    return fresh, newest, new_seen[-(page_size * max_pages):]


def poll_audit_log(tok: str, producer, tenant: str, since: str,
                   seen_ids: list | None = None) -> tuple[int, str, list]:
    """Admin-activity audit log → cloud_change (the CloudTrail/Activity Log
    equivalent). Checkpoint/overlap/dedup live in list_log_entries (shared with
    the log-fidelity lanes); this lane owns only the method filter + mapping."""
    entries, newest, new_seen = list_log_entries(
        tok, f'logName="projects/{PROJECT}/logs/cloudaudit.googleapis.com%2Factivity"',
        since, seen_ids)
    n = 0
    for e in entries:
        proto = e.get("protoPayload", {}) or {}
        method = str(proto.get("methodName", ""))
        if not method or method.endswith(CHANGE_EXCLUDE_SUFFIXES):
            continue
        ts = str(e.get("timestamp", ""))
        producer.send("netops.cloud", cloud_events.change_event(
            provider="gcp", tenant=tenant,
            resource_id=str(proto.get("resourceName", "")),
            region="", severity="info", metric_name=method, ts=ts, account=PROJECT,
            attrs={
                "event_name": method,
                "actor": str((proto.get("authenticationInfo") or {}).get("principalEmail", "")),
                "event_source": "gcp_audit_log",
                "request_id": str(e.get("insertId", "")),
            }))
        n += 1
    return n, newest, new_seen


# ── log-fidelity lanes (#105 parity): flow / firewall / LB+Armor / DNS ───────
# One shared reader (list_log_entries), one pure-rollup module (gcp_log_lanes),
# one lane table. Each lane: fetch its log id since its own checkpoint, run the
# bounded rollup(s), stamp the tenant, produce to netops.cloud — the SAME kinds
# the AWS tailer lanes emit, so every downstream consumer stays provider-blind.
# The LB fetch feeds TWO rollups (5xx + Cloud Armor): Armor has no log of its
# own — it rides the LB request log, so one read closes two matrix rows.

def _lane_log(msg: str, **kw) -> None:
    import time as _time
    print(json.dumps({"ts": _time.time(), "service": "cloud-ingest",
                      "msg": msg, **kw}), flush=True)


# Peer-pair volume bound (#9 service dependency map) — shared knob name across
# the AWS/Azure/GCP flow lanes.
FLOW_PAIR_TOP_K = int(os.environ.get("CLOUD_FLOW_PAIR_TOP_K", "20"))


def flow_pair_rollup(entries: list[dict], project: str) -> list[dict]:
    """Named lane adapter: the pure pair rollup with the env-tuned top-K bound
    (lane functions share the (entries, project) signature; __name__ feeds the
    truncation log line)."""
    return gcp_log_lanes.flow_pair_rollup(entries, project, top_k=FLOW_PAIR_TOP_K)


def _log_lanes() -> list[tuple]:
    """(state_key, filter, rollup functions) per ENABLED lane. Computed per call
    so tests can flip the module gates."""
    lanes: list[tuple] = []
    if GCP_VPC_FLOW_LOGS:
        lanes.append(("gcp_flow",
                      f'logName="projects/{PROJECT}/logs/compute.googleapis.com%2Fvpc_flows"',
                      (gcp_log_lanes.flow_volume_rollup, flow_pair_rollup)))
    if GCP_FIREWALL_LOGS:
        lanes.append(("gcp_fw",
                      f'logName="projects/{PROJECT}/logs/compute.googleapis.com%2Ffirewall"',
                      (gcp_log_lanes.firewall_reject_rollup,)))
    if GCP_LB_LOGS:
        lanes.append(("gcp_lb",
                      f'logName="projects/{PROJECT}/logs/requests" '
                      f'AND resource.type="http_load_balancer"',
                      (gcp_log_lanes.lb_5xx_rollup, gcp_log_lanes.armor_block_rollup)))
    if GCP_DNS_LOGS:
        lanes.append(("gcp_dns",
                      f'logName="projects/{PROJECT}/logs/dns.googleapis.com%2Fdns_queries"',
                      (gcp_log_lanes.dns_error_rollup,)))
    return lanes


def poll_log_lanes(tok: str, producer, tenant: str, st: dict, since_default: str) -> int:
    """Run every enabled log-fidelity lane once. Per-lane try/except: one bad
    lane (a missing log, a quota trip) must never block the others or roll back
    their checkpoints. Returns the number of rollup signals produced."""
    n = 0
    for state_key, log_filter, rollups in _log_lanes():
        try:
            since = st.get(f"{state_key}_ts") or since_default
            entries, newest, new_seen = list_log_entries(
                tok, log_filter, since, st.get(f"{state_key}_seen") or [])
            for rollup in rollups:
                events = rollup(entries, PROJECT)
                for ev in events:
                    ev["tenant_id"] = tenant
                    producer.send("netops.cloud", ev)
                    n += 1
                if events and events[0]["attrs"].get("rollup_truncated"):
                    _lane_log("gcp log lane rollup truncated", lane=state_key,
                              rollup=rollup.__name__,
                              dropped=events[0]["attrs"]["rollup_truncated"])
            st[f"{state_key}_ts"] = newest
            st[f"{state_key}_seen"] = new_seen
        except Exception as exc:  # noqa: BLE001 - lane isolation
            _lane_log("gcp log lane error", lane=state_key, error=str(exc)[:200])
    return n


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
