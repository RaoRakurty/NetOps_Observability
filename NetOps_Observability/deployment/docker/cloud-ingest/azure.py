"""Azure → the platform's canonical lanes (Service View counters + RCA evidence).

Deliberately stdlib-only (`urllib`). The Azure ARM/Monitor APIs are plain REST
and client-credentials auth is one form POST — pulling in azure-mgmt-monitor
(msrest + azure-core + azure-identity) to wrap two GETs would add a large
dependency tree and a container rebuild for nothing.

Three lanes, mirroring the AWS side exactly:

  metrics   Azure Monitor  → MetricEvent → Vector :8690 → netops.metrics
                             → VictoriaMetrics (Service View counters)
                             + CUSUM (anomalies become RCA evidence)
  health    Resource Health→ cloud_resource_health → netops.cloud
  changes   Activity Log   → cloud_change          → netops.cloud

THE KEY INVERSION: Azure's `VmAvailabilityMetric` reports 1 = available, while
AWS's `StatusCheckFailed` reports 1 = failed. We publish the AWS-shaped canonical
metric (`cloud_status_check_failed = 1 - availability`), so every consumer —
cloud_enrich.go, the health rollup, the signatures — works on Azure with ZERO
changes. One arithmetic operation is the whole port.

Auth: service principal (AZURE_CLIENT_ID/SECRET/TENANT_ID). Roles: Monitoring
Reader (metrics + activity log) + Reader (inventory + resource health).
Cost: $0 — platform metrics, resource health and the activity log are free.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import ssl
import urllib.parse
import urllib.request

import cloud_events
import service_infer
import trail_state

TENANT_ID = os.environ.get("AZURE_TENANT_ID", "")
CLIENT_ID = os.environ.get("AZURE_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET", "")
SUBSCRIPTION = os.environ.get("AZURE_SUBSCRIPTION_ID", "")
REGION = os.environ.get("AZURE_REGION", "westus2")
METRICS_SINK = os.environ.get("METRIC_EVENT_SINK_URL", "http://vector-aggregator:8690/")
ARM = "https://management.azure.com"

# The lab MITMs egress TLS (Versa). boto3 honours AWS_CA_BUNDLE; urllib needs an
# explicit context. REQUESTS_CA_BUNDLE/SSL_CERT_FILE is the conventional knob;
# fall back to the system store when unset (a normal deployment).
_CA = (os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("SSL_CERT_FILE")
       or os.environ.get("AWS_CA_BUNDLE") or "")
_SSL = ssl.create_default_context(cafile=_CA) if _CA else ssl.create_default_context()

# Azure metric → (canonical platform metric, unit, aggregation, invert?)
# The canonical names are provider-neutral on purpose: AWS and Azure fill the
# same series, so every downstream consumer is provider-blind.
AZ_METRICS = [
    ("Percentage CPU", "cloud_cpu_util", "percent", "Average", False),
    ("Network In Total", "cloud_net_in_bytes", "bytes", "Total", False),
    ("Network Out Total", "cloud_net_out_bytes", "bytes", "Total", False),
    # 1 = available (Azure) → 1 - v = failed (the AWS-shaped canonical form).
    ("VmAvailabilityMetric", "cloud_status_check_failed", "count", "Minimum", True),
    ("Available Memory Bytes", "cloud_mem_avail_bytes", "bytes", "Average", False),
]

# Activity-log noise: a recommendation engine and autoscale bookkeeping are not
# "changes" a NOC should ever see (verified: Microsoft.Advisor dominates the log).
CHANGE_EXCLUDE_PREFIXES = (
    "microsoft.advisor/", "microsoft.insights/autoscalesettings/",
    "microsoft.resourcehealth/", "microsoft.security/",
)


def configured() -> bool:
    return bool(TENANT_ID and CLIENT_ID and CLIENT_SECRET and SUBSCRIPTION)


def _post_json(url: str, data: bytes, headers: dict) -> dict:
    req = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=15, context=_SSL) as r:  # noqa: S310 - fixed ARM/AAD hosts
        return json.loads(r.read() or b"{}")


def _get_json(url: str, token: str) -> dict:
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(req, timeout=20, context=_SSL) as r:  # noqa: S310
        return json.loads(r.read() or b"{}")


def token(scope: str = "https://management.azure.com/.default") -> str:
    """Client-credentials token — one form POST, no SDK required. Default
    audience is ARM; the storage-log lanes pass the STORAGE audience
    (azure_logs.STORAGE_SCOPE) — same SP, different resource (the documented
    auth choice for the blob reader: no second secret, no SharedKey HMAC)."""
    body = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": scope,
    }).encode()
    out = _post_json(
        f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token",
        body, {"Content-Type": "application/x-www-form-urlencoded"})
    return out.get("access_token", "")


def list_vms(tok: str) -> list[dict]:
    """VMs with their POWER STATE. A deallocated VM is not a broken one — the
    lifecycle truth AWS's lane also carries (audit P0-3/P1-2)."""
    url = (f"{ARM}/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Compute"
           f"/virtualMachines?api-version=2023-09-01&statusOnly=true")
    out = []
    for vm in _get_json(url, tok).get("value", []):
        power = ""
        for st in (vm.get("properties", {}).get("instanceView", {}) or {}).get("statuses", []):
            code = str(st.get("code", ""))
            if code.startswith("PowerState/"):
                power = code.split("/", 1)[1]  # running | deallocated | stopped
        out.append({
            "resource_id": vm["id"],          # the ARM id — globally unique (names collide across RGs)
            "name": vm.get("name", ""),
            "location": vm.get("location", ""),
            "power_state": power,
            "tags": vm.get("tags") or {},
        })
    return out


def poll_metrics(tok: str, vms: list[dict]) -> int:
    """Azure Monitor → MetricEvents on the canonical lane."""
    events: list[dict] = []
    end = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    start = end - dt.timedelta(minutes=10)
    span = f"{start.isoformat().replace('+00:00','Z')}/{end.isoformat().replace('+00:00','Z')}"

    for vm in vms:
        # A deallocated VM publishes nothing; polling it would make "stopped"
        # indistinguishable from "broken".
        if vm.get("power_state") not in ("running", ""):
            continue
        for az_name, canon, unit, agg, invert in AZ_METRICS:
            q = urllib.parse.urlencode({
                "api-version": "2018-01-01",
                "metricnames": az_name,
                "aggregation": agg,
                "interval": "PT1M",
                "timespan": span,
            })
            try:
                res = _get_json(f"{ARM}{vm['resource_id']}/providers/Microsoft.Insights/metrics?{q}", tok)
            except Exception:  # noqa: BLE001 - one metric must never kill the cycle
                continue
            for m in res.get("value", []):
                series = m.get("timeseries") or []
                if not series:
                    continue
                pts = [p for p in (series[0].get("data") or [])
                       if p.get(agg.lower()) is not None]
                if not pts:
                    continue  # no datapoint — absent, never zero
                p = pts[-1]
                val = float(p[agg.lower()])
                if invert:
                    val = 1.0 - val  # Azure: 1=available → canonical: 1=failed
                events.append(cloud_events.metric_event(
                    vendor="azure", device=vm["name"], index=vm["resource_id"],
                    metric=canon, value=val, unit=unit, ts=p["timeStamp"]))
    if events:
        body = "\n".join(json.dumps(e) for e in events).encode()
        req = urllib.request.Request(METRICS_SINK, data=body,
                                     headers={"Content-Type": "application/x-ndjson"})
        urllib.request.urlopen(req, timeout=10).read()  # noqa: S310 - internal sink
    return len(events)


def poll_resource_health(tok: str, producer, tenant: str) -> int:
    """Resource Health → cloud_resource_health. The signal an Azure operator
    checks first — and unlike the AWS Health API it needs no support plan.
    `reasonType` (Platform Initiated vs Customer Initiated) is exactly the RCA
    discriminator: 'Azure rebooted your host' vs 'you stopped it'."""
    url = (f"{ARM}/subscriptions/{SUBSCRIPTION}/providers/Microsoft.ResourceHealth"
           f"/availabilityStatuses?api-version=2023-07-01-preview")
    try:
        res = _get_json(url, tok)
    except Exception:  # noqa: BLE001
        return 0
    n = 0
    for st in res.get("value", []):
        props = st.get("properties", {}) or {}
        state = str(props.get("availabilityState", "Unknown"))
        if state == "Available":
            continue  # healthy is the absence of a fault signal (anti-noise)
        rid = str(st.get("id", "")).split("/providers/Microsoft.ResourceHealth")[0]
        sev = {"Unavailable": "crit", "Degraded": "high"}.get(state, "warn")
        producer.send("netops.cloud", cloud_events.health_event(
            provider="azure", tenant=tenant, resource_id=rid, region=REGION,
            severity=sev, state=state, account=SUBSCRIPTION,
            ts=props.get("occuredTime") or dt.datetime.now(dt.timezone.utc).isoformat(),
            attrs={
                "region": REGION,
                # WHOSE fault: the platform's or the customer's.
                "reason": props.get("reasonType", ""),
                "summary": props.get("summary", "")[:300],
            }))
        n += 1
    return n


def _lagged_now_iso() -> str:
    """now - delivery lag, in the same second-resolution Z format the
    checkpoints use (lexicographic max stays consistent)."""
    t = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=trail_state.DELIVERY_LAG_S)
    return t.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def poll_activity_log(tok: str, producer, tenant: str, since: str) -> tuple[int, str]:
    """Activity Log → cloud_change (the CloudTrail equivalent)."""
    flt = urllib.parse.quote(f"eventTimestamp ge '{since}'")
    url = (f"{ARM}/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Insights"
           f"/eventtypes/management/values?api-version=2015-04-01&$filter={flt}")
    newest = since
    n = 0
    saw = False
    clean = True
    while url:
        try:
            res = _get_json(url, tok)
        except Exception:  # noqa: BLE001
            clean = False
            break
        for e in res.get("value", []):
            # The checkpoint anchors on everything SEEN — matched or excluded.
            # Advancing only on matched events pinned `since` through windows
            # of pure bookkeeping churn (the trail_ts defect class; see
            # trail_state.py).
            ts = str(e.get("eventTimestamp", ""))
            saw = True
            if ts > newest:
                newest = ts
            op = str((e.get("operationName") or {}).get("value", "")).lower()
            if not op or op.startswith(CHANGE_EXCLUDE_PREFIXES):
                continue
            if str((e.get("status") or {}).get("value", "")) not in ("Succeeded", "Failed"):
                continue  # 'Started' is bookkeeping, not a completed change
            producer.send("netops.cloud", cloud_events.change_event(
                provider="azure", tenant=tenant,
                resource_id=e.get("resourceId", ""),
                region=e.get("resourceGroupName", "") or REGION,
                severity="medium",
                metric_name=(e.get("operationName") or {}).get("value", ""),
                ts=ts, account=SUBSCRIPTION,
                attrs={
                    "actor": (e.get("caller") or ""),
                    "event_source": (e.get("resourceProviderName") or {}).get("value", ""),
                    "request_id": e.get("correlationId", ""),
                    "status": (e.get("status") or {}).get("value", ""),
                }))
            n += 1
        url = res.get("nextLink") or ""
    # A cleanly-fetched EMPTY window still advances (to the delivery-lagged
    # now) so quiet periods stay one page wide; a failed fetch never advances.
    if clean and not saw:
        newest = trail_state.advance_checkpoint_any(since, newest, False, _lagged_now_iso())
    return n, newest


# ── inventory writer ─────────────────────────────────────────────────────────

# Tag keys that name the workload — the same set the AWS discover lane honours,
# plus app_id (audit P0-1/P0-6: the tag the lab fleet actually carries).
APP_TAG_KEYS = ("app_id", "app", "application", "app_name", "app-name", "service", "workload")


def write_inventory(tok: str, fixtures_dir: str) -> int:
    """Discover VMs + their NIC addresses and REWRITE azure.json — the same live
    loop the AWS lane has (discover.py). Kills the audit's phantom fixture
    (D-P0-4): the hand-written azure.json rotted from the moment it was saved
    (no power_state, name-keyed ids, 33h-stale addresses). resource_id is the
    ARM id — names collide across clouds AND resource groups (audit P1-3), and
    the metric join (VictoriaMetrics resource_id label) is ARM-id keyed.
    Returns the number of resources written."""
    vms = {v["resource_id"].lower(): v for v in list_vms(tok)}

    # VM model list (sizes + NIC refs); one call, paged via nextLink.
    models: dict[str, dict] = {}
    url = (f"{ARM}/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Compute"
           f"/virtualMachines?api-version=2023-09-01")
    while url:
        res = _get_json(url, tok)
        for vm in res.get("value", []):
            models[str(vm.get("id", "")).lower()] = vm
        url = res.get("nextLink") or ""

    # NICs: private IPs + public-IP refs + owning VM; public IPs: ref → address.
    nics: list[dict] = []
    url = (f"{ARM}/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Network"
           f"/networkInterfaces?api-version=2023-09-01")
    while url:
        res = _get_json(url, tok)
        nics.extend(res.get("value", []))
        url = res.get("nextLink") or ""
    pub_by_ref: dict[str, str] = {}
    url = (f"{ARM}/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Network"
           f"/publicIPAddresses?api-version=2023-09-01")
    while url:
        res = _get_json(url, tok)
        for p in res.get("value", []):
            addr = (p.get("properties", {}) or {}).get("ipAddress", "")
            if addr:
                pub_by_ref[str(p.get("id", "")).lower()] = addr
        url = res.get("nextLink") or ""

    nics_by_vm: dict[str, list[dict]] = {}
    for nic in nics:
        owner = str(((nic.get("properties", {}) or {}).get("virtualMachine") or {}).get("id", "")).lower()
        if owner:
            nics_by_vm.setdefault(owner, []).append(nic)

    resources = []
    for arm_id_l, vm in sorted(vms.items()):
        model = models.get(arm_id_l, {})
        props = model.get("properties", {}) or {}
        tags = vm.get("tags") or {}
        private_ips, public_ips, nic_ids, subnet_ids = [], [], [], []
        for nic in nics_by_vm.get(arm_id_l, []):
            nic_ids.append(str(nic.get("id", "")))
            for cfg in (nic.get("properties", {}) or {}).get("ipConfigurations", []):
                cp = cfg.get("properties", {}) or {}
                if cp.get("privateIPAddress"):
                    private_ips.append(cp["privateIPAddress"])
                # Subnet id — the STRUCTURAL signal the service inference uses to
                # corroborate a resource-group name guess (no tag write needed).
                sn = str((cp.get("subnet") or {}).get("id", ""))
                if sn:
                    subnet_ids.append(sn)
                pref = str((cp.get("publicIPAddress") or {}).get("id", "")).lower()
                if pref and pref in pub_by_ref:
                    public_ips.append(pub_by_ref[pref])
        arm_id = str(model.get("id") or vm["resource_id"])
        resources.append({
            "region": vm.get("location") or REGION,
            "resource_id": arm_id,
            "resource_arn_or_uri": arm_id,
            "resource_type": "compute:virtualMachine",
            "resource_name": vm.get("name", ""),
            "power_state": vm.get("power_state", ""),
            "instance_type": ((props.get("hardwareProfile") or {}).get("vmSize", "")),
            "private_ips": private_ips,
            "public_ips": public_ips,
            "network_interface_ids": nic_ids,
            # Tags are OPTIONAL metadata: absent tags never fail discovery, and no
            # key is required. When present they are carried verbatim (below); the
            # workload is attributed by tag if tagged, else by inference.
            "tags": tags,
            "subnet_ids": subnet_ids,
            "owner": tags.get("owner", ""),
            "env": tags.get("environment", tags.get("env", "")),
            "source": "cloud_api",
            "confidence": "confirmed" if any(k in tags for k in APP_TAG_KEYS) else "strong",
        })

    # Built-in service mapping: infer a BusinessService for every tag-less VM from
    # resource-group naming + subnet/hostname structure (service_infer.py). The
    # monitoring SP is READ-ONLY, so this attributes WITHOUT writing a tag. Each
    # inference carries an explicit confidence + basis; a resource with no usable
    # signal is left un-inferred (stays unknown → generic descriptor downstream).
    inferred = service_infer.infer_services(resources)
    for r in resources:
        r.pop("subnet_ids", None)  # transient signal, not part of the stored shape
        hit = inferred.get(r["resource_id"])
        if hit:
            r["inferred_service"] = hit["service"]
            r["inferred_service_confidence"] = hit["confidence"]
            r["inferred_service_basis"] = hit["basis"]

    # Live-poller provenance stamp — same contract as discover.py/gcp.py
    # (pinned by cloud/provider_test.go); drives the UI's honest data-mode badge.
    inventory = {
        "provider": "azure", "account_id": SUBSCRIPTION,
        "collection": {"mode": "live_poller",
                       "collected_at": dt.datetime.now(dt.timezone.utc).isoformat()},
        "resources": resources,
    }
    os.makedirs(fixtures_dir, exist_ok=True)
    path = os.path.join(fixtures_dir, "azure.json")
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(inventory, f, indent=2)
    os.replace(tmp, path)
    return len(resources)


# ── hybrid-seam lane (#105 P1): ER/VPN-GW metrics WITH dimensions ────────────
# The seam truths on Azure are dimension-split, poll-only metrics (BgpPeerStatus
# per BgpPeerAddress; ER BgpAvailability/ArpAvailability per PeeringType) —
# diagnostic-settings export flattens or omits them, so the Metrics REST API
# with $filter is the only honest path. Transitions ride the shared tracker.

from seam_state import SeamStateTracker  # noqa: E402


def list_network_resources(tok: str, rtype: str) -> list[str]:
    """Subscription-wide ids of one Microsoft.Network resource type (paged)."""
    ids: list[str] = []
    # $filter value must be percent-encoded — a raw space in the URL is a
    # control-character error in urllib (live poller failure 2026-07-15).
    flt = urllib.parse.quote(f"resourceType eq '{rtype}'")
    url = (f"{ARM}/subscriptions/{SUBSCRIPTION}/resources"
           f"?$filter={flt}&api-version=2021-04-01")
    while url:
        res = _get_json(url, tok)
        ids.extend(str(r.get("id", "")) for r in res.get("value", []) if r.get("id"))
        url = res.get("nextLink") or ""
    return ids


def _metric_series(tok: str, rid: str, metric: str, agg: str,
                   dim: str | None = None) -> list[dict]:
    """One metric on one resource, per-dimension series preserved. Returns
    [{dim_value, value, ts}] for the latest point of each series."""
    q = f"metricnames={metric}&aggregation={agg}&interval=PT5M&api-version=2023-10-01"
    if dim:
        dim_filter = dim + " eq '*'"
        q += "&$filter=" + urllib.parse.quote(dim_filter)
    try:
        res = _get_json(f"{ARM}{rid}/providers/Microsoft.Insights/metrics?{q}", tok)
    except Exception:  # noqa: BLE001 - one resource never kills the lane
        return []
    out: list[dict] = []
    for val in res.get("value", []):
        for series in val.get("timeseries", []):
            dv = ""
            for mv in series.get("metadatavalues", []) or []:
                dv = str(mv.get("value", ""))
            points = [p for p in series.get("data", []) or [] if p.get(agg.lower()) is not None]
            if not points:
                continue  # absence stays absence
            p = points[-1]
            out.append({"dim_value": dv, "value": float(p[agg.lower()]),
                        "ts": str(p.get("timeStamp", ""))})
    return out


def poll_seams(tok: str, producer, tenant: str, st: dict, now: float,
               observed_at: str) -> int:
    """ER circuits (BgpAvailability/ArpAvailability per PeeringType) + VPN
    gateways (BgpPeerStatus per peer, tunnel packet drops). Emits transitions
    and forwarding-drop signals. Empty subscriptions degrade to zero work."""
    tracker = SeamStateTracker.from_state(st.get("az_seam_tracker"))
    n = 0

    def send(kind: str, rid: str, sev: str, value: float, attrs: dict, ts: str) -> None:
        nonlocal n
        producer.send("netops.cloud", {
            "kind": kind, "tenant_id": tenant, "resource_id": rid, "region": REGION,
            "severity": sev, "metric_name": kind, "value": value,
            "ts": ts or observed_at, "attrs": {"provider": "azure", **attrs},
        })
        n += 1

    for cid in list_network_resources(tok, "Microsoft.Network/expressRouteCircuits"):
        for metric, evidence in (("BgpAvailability", "state"), ("ArpAvailability", "state")):
            for s in _metric_series(tok, cid, metric, "Average", dim="PeeringType"):
                key = f"er:{cid}:{metric}:{s['dim_value']}"
                state = "up" if s["value"] >= 99.0 else ("down" if s["value"] < 95.0 else "degraded")
                for tr in tracker.observe(key, state, s["ts"] or observed_at, now):
                    kind = ("cloud_bgp_session_down" if tr["to"] in ("down", "degraded")
                            and metric == "BgpAvailability"
                            else "cloud_link_error" if metric == "ArpAvailability"
                            and tr["to"] in ("down", "degraded")
                            else "cloud_bgp_session_up" if tr["to"] == "up"
                            else "cloud_state_unknown")
                    send(kind, key, "crit" if tr["to"] == "down" else "warn" if tr["to"] == "degraded" else "info",
                         s["value"],
                         {"evidence_class": "state_transition", "circuit": cid,
                          "peering_type": s["dim_value"], "availability_pct": str(s["value"]),
                          "layer": "l3" if metric == "BgpAvailability" else "l2",
                          "from_state": tr.get("from", ""), "to_state": tr["to"]},
                         s["ts"])

    for gid in list_network_resources(tok, "Microsoft.Network/virtualNetworkGateways"):
        for s in _metric_series(tok, gid, "BgpPeerStatus", "Minimum", dim="BgpPeerAddress"):
            key = f"vpngw:{gid}:{s['dim_value']}"
            state = "up" if s["value"] >= 1.0 else "down"
            for tr in tracker.observe(key, state, s["ts"] or observed_at, now):
                kind = ("cloud_bgp_session_down" if tr["to"] == "down"
                        else "cloud_bgp_session_up" if tr["to"] == "up"
                        else "cloud_state_unknown")
                if tr.get("flap"):
                    kind = "cloud_bgp_flap"
                send(kind, key, "crit" if tr["to"] == "down" else "info", s["value"],
                     {"evidence_class": "state_transition", "gateway": gid,
                      "peer_address": s["dim_value"],
                      "from_state": tr.get("from", ""), "to_state": tr["to"]},
                     s["ts"])
        for metric, direction in (("TunnelEgressPacketDropCount", "egress"),
                                  ("TunnelIngressPacketDropCount", "ingress")):
            for s in _metric_series(tok, gid, metric, "Total", dim="ConnectionName"):
                if s["value"] > 0:
                    send("cloud_vpn_packet_drop", f"vpngw:{gid}:{s['dim_value']}", "high",
                         s["value"],
                         {"evidence_class": "forwarding_drop", "gateway": gid,
                          "connection": s["dim_value"], "direction": direction},
                         s["ts"])

    for tr in tracker.expire(freshness_s=3 * 300, now=now):
        send("cloud_state_unknown", tr["key"], "warn", 1.0,
             {"evidence_class": "state", "from_state": tr["from"],
              "stale_after_s": str(tr["stale_after_s"])}, tr["observed_at"])
    st["az_seam_tracker"] = tracker.to_state()
    return n
