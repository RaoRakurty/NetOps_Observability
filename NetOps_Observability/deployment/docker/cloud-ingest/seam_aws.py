# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""AWS hybrid-seam lane (#105 P1) — the gateway plane, finally measured.

Two cost tiers, per the owner's policy:

FREE (always on, describe APIs — state truth without CloudWatch metering):
  * Site-to-Site VPN: `describe_vpn_connections` → VgwTelemetry = PER-TUNNEL
    Status/StatusMessage keyed by OutsideIpAddress. Structurally immune to the
    fractional-aggregate TunnelState trap: we never read the aggregate metric.
    Each redundant tunnel is its own tracked key (prompt: never aggregate
    redundant members).
  * Direct Connect: `describe_connections` (connectionState, bandwidth) +
    `describe_virtual_interfaces` → per-VIF bgpPeers[].bgpStatus per address
    family. DX BGP state without a single metered read. Absent in accounts
    with no DX — lane degrades to empty, never errors the poll.
  * Transit Gateway: `describe_transit_gateways` + attachments → inventory/
    topology identity for the metered drop counters below.

METERED (CloudWatch GetMetricData, honors AWS_METERED_METRICS=off):
  * AWS/TransitGateway `PacketDropCountBlackhole` vs `PacketDropCountNoRoute`
    — DISTINCT kinds, never merged (an explicit blackhole route and a missing
    route are different faults with different owners).
  * AWS/NATGateway `ErrorPortAllocation` (port exhaustion — the allocation
    FAILURE, not a utilization guess) + `PacketsDropCount`.
  * AWS/DX `ConnectionErrorCount` + `ConnectionLightLevelTx/Rx` (per
    OpticalLaneNumber, dedicated connections only — hosted connections do not
    expose optics; absence is recorded, not faked).

Emissions:
  * state transitions → netops.cloud seam signal kinds (cloud_producers.py)
    with evidence_class + provider-native ids in attrs; `ts` = the provider's
    observation time.
  * drop/optics values → canonical metric series (vector sink) labeled by the
    seam resource id, so VictoriaMetrics carries trends while the bus carries
    events.

All describe calls are paginated; a failure in one family never rolls back
another (each guarded separately — P1-11 discipline).
"""
from __future__ import annotations

import datetime as dt
import json
import os
import time
import urllib.request

from seam_state import SeamStateTracker, counter_delta, material_route_drop

from ingest_auth import INGEST_SSL_CONTEXT, with_ingest_auth  # F-08 / SEC-013.2

METRICS_SINK = os.environ.get("METRIC_EVENT_SINK_URL", "http://vector-aggregator:8690/")
REGION = os.environ.get("AWS_REGION", "us-west-2")

# CW seam metrics polled when metered reads are enabled:
# (namespace, metric, dimension name, canonical series, stat, signal kind or "")
CW_SEAM_METRICS = [
    ("AWS/TransitGateway", "PacketDropCountBlackhole", "TransitGateway",
     "cloud_tgw_blackhole_drops", "Sum", "cloud_gateway_blackhole_drop"),
    ("AWS/TransitGateway", "PacketDropCountNoRoute", "TransitGateway",
     "cloud_tgw_noroute_drops", "Sum", "cloud_gateway_no_route_drop"),
    ("AWS/NATGateway", "ErrorPortAllocation", "NatGatewayId",
     "cloud_nat_port_alloc_errors", "Sum", "cloud_nat_port_exhaustion"),
    ("AWS/NATGateway", "PacketsDropCount", "NatGatewayId",
     "cloud_nat_dropped_packets", "Sum", ""),
    ("AWS/DX", "ConnectionErrorCount", "ConnectionId",
     "cloud_dx_link_errors", "Sum", "cloud_link_error"),
]


def _post_ndjson(events: list[dict]) -> None:
    if not events:
        return
    body = "\n".join(json.dumps(e) for e in events).encode()
    req = urllib.request.Request(METRICS_SINK, data=body,
                                 headers=with_ingest_auth({"Content-Type": "application/x-ndjson"}))
    urllib.request.urlopen(req, timeout=10, context=INGEST_SSL_CONTEXT).read()  # noqa: S310


# ── discovery (free describes; paginated; each family isolated) ──────────────

def discover_seams(session) -> dict:
    """Seam inventory: per-tunnel VPN state, per-VIF DX BGP state, TGW/NAT ids.
    Returns {vpn:[...], dx_connections:[...], dx_vifs:[...], tgws:[...], nats:[...]}.
    Every entry keeps the provider-native id as identity (never names)."""
    ec2 = session.client("ec2", region_name=REGION)
    out: dict = {"vpn": [], "dx_connections": [], "dx_vifs": [], "tgws": [], "nats": []}

    try:
        for v in ec2.describe_vpn_connections().get("VpnConnections", []):
            if v.get("State") in ("deleted", "deleting"):
                continue
            tunnels = []
            for t in v.get("VgwTelemetry", []) or []:
                tunnels.append({
                    "outside_ip": t.get("OutsideIpAddress", ""),
                    "status": str(t.get("Status", "")).lower(),   # UP | DOWN
                    "status_message": t.get("StatusMessage", ""),
                    "accepted_routes": int(t.get("AcceptedRouteCount", 0) or 0),
                })
            out["vpn"].append({
                "vpn_id": v.get("VpnConnectionId", ""),
                "tgw_id": v.get("TransitGatewayId", ""),
                "vgw_id": v.get("VpnGatewayId", ""),
                "cgw_id": v.get("CustomerGatewayId", ""),
                "tunnels": tunnels,
            })
    except Exception as exc:  # noqa: BLE001 - family isolation
        out["vpn_error"] = str(exc)[:160]

    try:
        dx = session.client("directconnect", region_name=REGION)
        for c in dx.describe_connections().get("connections", []):
            out["dx_connections"].append({
                "connection_id": c.get("connectionId", ""),
                "state": str(c.get("connectionState", "")).lower(),
                "bandwidth": c.get("bandwidth", ""),
                # optics only exist on dedicated connections; record the type so
                # absence of light levels is explained, never papered over.
                "hosted": bool(c.get("partnerName")),
            })
        for vif in dx.describe_virtual_interfaces().get("virtualInterfaces", []):
            peers = []
            for p in vif.get("bgpPeers", []) or []:
                peers.append({
                    "peer_id": p.get("bgpPeerId", ""),
                    "address_family": p.get("addressFamily", ""),
                    "bgp_status": str(p.get("bgpStatus", "")).lower(),  # up|down|unknown
                    "peer_address": p.get("amazonAddress", ""),
                })
            out["dx_vifs"].append({
                "vif_id": vif.get("virtualInterfaceId", ""),
                "connection_id": vif.get("connectionId", ""),
                "vif_state": str(vif.get("virtualInterfaceState", "")).lower(),
                "peers": peers,
            })
    except Exception as exc:  # noqa: BLE001
        out["dx_error"] = str(exc)[:160]

    try:
        for t in ec2.get_paginator("describe_transit_gateways").paginate():
            for g in t.get("TransitGateways", []):
                if g.get("State") not in ("available", "modifying", "pending"):
                    continue
                out["tgws"].append({"tgw_id": g.get("TransitGatewayId", "")})
    except Exception as exc:  # noqa: BLE001
        out["tgw_error"] = str(exc)[:160]

    try:
        for page in ec2.get_paginator("describe_nat_gateways").paginate():
            for n in page.get("NatGateways", []):
                if n.get("State") == "available":
                    out["nats"].append({"nat_id": n.get("NatGatewayId", "")})
    except Exception as exc:  # noqa: BLE001
        out["nat_error"] = str(exc)[:160]

    return out


# ── state → transition signals (pure given a tracker) ────────────────────────

def seam_state_events(seams: dict, tracker: SeamStateTracker, now: float,
                      observed_at: str, route_prev: dict | None = None,
                      route_new: dict | None = None) -> list[dict]:
    """Feed the current describe-API state into the tracker; map transitions to
    the canonical seam signal kinds. Pure aside from tracker mutation.
    route_prev/route_new carry per-tunnel AcceptedRouteCount across cycles so a
    material collapse WHILE THE TUNNEL IS UP emits route_change evidence — the
    "session up, advertisements gone" case is route policy, never an outage."""
    events: list[dict] = []
    route_prev = route_prev or {}
    if route_new is None:
        route_new = {}

    def emit(kind: str, resource_id: str, sev: str, attrs: dict, tr: dict) -> None:
        events.append({
            "kind": kind,
            "resource_id": resource_id,
            "account": "",
            "region": REGION,
            "severity": sev,
            "metric_name": kind,
            "value": 1.0,
            "ts": tr.get("observed_at", observed_at),
            "attrs": {"provider": "aws", **attrs,
                      "from_state": tr.get("from", ""), "to_state": tr.get("to", "")},
        })

    for v in seams.get("vpn", []):
        for t in v["tunnels"]:
            key = f"vpn:{v['vpn_id']}:{t['outside_ip']}"
            for tr in tracker.observe(key, "up" if t["status"] == "up" else
                                      ("unknown" if not t["status"] else "down"),
                                      observed_at, now):
                to = tr["to"]
                kind = ("cloud_vpn_tunnel_down" if to == "down"
                        else "cloud_vpn_tunnel_up" if to == "up"
                        else "cloud_state_unknown")
                attrs = {"evidence_class": "state_transition",
                         "vpn_id": v["vpn_id"], "tunnel_ip": t["outside_ip"],
                         "tgw_id": v.get("tgw_id", ""), "vgw_id": v.get("vgw_id", ""),
                         "cgw_id": v.get("cgw_id", ""),
                         "status_message": t.get("status_message", "")}
                if tr.get("flap"):
                    attrs["flap"] = "true"
                    attrs["transitions_15m"] = str(tr.get("transitions_15m", ""))
                emit(kind, key, "crit" if to == "down" else "info", attrs, tr)
            # Route-count collapse while the tunnel is UP (BGP VPNs): route
            # policy / advertisement evidence, deliberately gated on up so a
            # tunnel-down never double-reports as a route fault too.
            rkey = f"vpnroutes:{v['vpn_id']}:{t['outside_ip']}"
            routes = int(t.get("accepted_routes", 0) or 0)
            route_new[rkey] = routes
            if t["status"] == "up" and material_route_drop(route_prev.get(rkey), routes):
                events.append({
                    "kind": "cloud_route_count_drop", "resource_id": rkey,
                    "account": "", "region": REGION, "severity": "high",
                    "metric_name": "accepted_routes", "value": float(routes),
                    "ts": observed_at,
                    "attrs": {"provider": "aws", "evidence_class": "route_change",
                              "vpn_id": v["vpn_id"], "tunnel_ip": t["outside_ip"],
                              "tgw_id": v.get("tgw_id", ""),
                              "previous": str(route_prev.get(rkey, "")),
                              "tunnel_state": "up"},
                })

    for vif in seams.get("dx_vifs", []):
        for p in vif["peers"]:
            key = f"dxbgp:{vif['vif_id']}:{p['peer_id'] or p['address_family']}"
            for tr in tracker.observe(key, p["bgp_status"] or "unknown", observed_at, now):
                to = tr["to"]
                kind = ("cloud_bgp_session_down" if to == "down"
                        else "cloud_bgp_session_up" if to == "up"
                        else "cloud_state_unknown")
                if tr.get("flap"):
                    kind = "cloud_bgp_flap"
                emit(kind, key, "crit" if to == "down" else "info",
                     {"evidence_class": "state_transition",
                      "vif_id": vif["vif_id"], "connection_id": vif.get("connection_id", ""),
                      "address_family": p.get("address_family", ""),
                      "peer_address": p.get("peer_address", "")}, tr)

    for c in seams.get("dx_connections", []):
        key = f"dxconn:{c['connection_id']}"
        state = "up" if c["state"] == "available" else ("down" if c["state"] == "down" else c["state"])
        for tr in tracker.observe(key, state, observed_at, now):
            if tr["to"] == "down":
                emit("cloud_physical_link_down", key, "crit",
                     {"evidence_class": "physical_health",
                      "connection_id": c["connection_id"], "hosted": str(c.get("hosted", False))}, tr)
    return events


# ── metered CW seam metrics (drops / optics / errors) ────────────────────────

def poll_seam_metrics(cw, seams: dict, prev_counters: dict) -> tuple[list[dict], list[dict], dict]:
    """GetMetricData for the seam drop/error counters. Returns
    (metric_events for the sink, fault signals for the bus, new counter state).
    The trailing window ends one period back (in-flight bucket rule, P0-2)."""
    ids = {
        "TransitGateway": [t["tgw_id"] for t in seams.get("tgws", [])],
        "NatGatewayId": [n["nat_id"] for n in seams.get("nats", [])],
        "ConnectionId": [c["connection_id"] for c in seams.get("dx_connections", [])],
    }
    period = 300
    end = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=period)
    start = end - dt.timedelta(seconds=period * 3)
    queries, meta = [], {}
    qn = 0
    for ns, metric, dim, canon, stat, kind in CW_SEAM_METRICS:
        for rid in ids.get(dim, []):
            qid = f"s{qn}"
            qn += 1
            meta[qid] = (rid, canon, kind, metric)
            queries.append({
                "Id": qid,
                "MetricStat": {
                    "Metric": {"Namespace": ns, "MetricName": metric,
                               "Dimensions": [{"Name": dim, "Value": rid}]},
                    "Period": period, "Stat": stat,
                },
            })
    if not queries:
        return [], [], prev_counters

    metric_events: list[dict] = []
    signals: list[dict] = []
    new_counters = dict(prev_counters)
    for i in range(0, len(queries), 500):
        resp = cw.get_metric_data(MetricDataQueries=queries[i:i + 500],
                                  StartTime=start, EndTime=end, ScanBy="TimestampDescending")
        for r in resp.get("MetricDataResults", []):
            rid, canon, kind, metric = meta[r["Id"]]
            if not r.get("Values"):
                continue  # absence is absence — never a zero
            val = float(r["Values"][0])
            ts = r["Timestamps"][0]
            ts_iso = ts.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
            metric_events.append({
                "name": canon, "value": val, "unit": "count", "ts": ts_iso,
                "observer_type": "cloud_provider", "modality_class": "device_telemetry",
                "device": rid, "index": rid,
                "labels": {"provider": "aws", "region": REGION, "metric": metric},
            })
            ckey = f"{canon}:{rid}"
            delta = counter_delta(prev_counters.get(ckey), val) if metric.endswith("Count") else val
            new_counters[ckey] = val
            if kind and val > 0 and delta > 0:
                signals.append({
                    "kind": kind, "resource_id": rid, "account": "", "region": REGION,
                    "severity": "high", "metric_name": metric, "value": val, "ts": ts_iso,
                    "attrs": {"provider": "aws",
                              "evidence_class": ("forwarding_drop" if "Drop" in metric or "PortAllocation" in metric
                                                 else "physical_health"),
                              "period_s": str(period)},
                })
    return metric_events, signals, new_counters


def run(session, producer, tenant: str, st: dict, metered: bool) -> dict:
    """One seam cycle: discover (free) → state transitions (free) → metered
    drop counters (gated). Tracker + counters persist via `st`. Returns counts."""
    now = time.time()
    observed_at = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    seams = discover_seams(session)
    tracker = SeamStateTracker.from_state(st.get("seam_tracker"))
    route_new: dict = {}
    events = seam_state_events(seams, tracker, now, observed_at,
                               st.get("aws_route_counts") or {}, route_new)
    st["aws_route_counts"] = route_new
    # freshness: a state not re-confirmed within 3 cycles is unknown, not "up".
    for tr in tracker.expire(freshness_s=3 * max(int(st.get("seam_every_s", 120)), 60), now=now):
        events.append({
            "kind": "cloud_state_unknown", "resource_id": tr["key"], "account": "",
            "region": REGION, "severity": "warn", "metric_name": "cloud_state_unknown",
            "value": 1.0, "ts": tr["observed_at"],
            "attrs": {"provider": "aws", "evidence_class": "state",
                      "from_state": tr["from"], "stale_after_s": str(tr["stale_after_s"])},
        })
    for ev in events:
        ev["tenant_id"] = tenant
        producer.send("netops.cloud", ev)

    m_events: list[dict] = []
    m_signals: list[dict] = []
    if metered:
        cw = session.client("cloudwatch", region_name=REGION)
        m_events, m_signals, counters = poll_seam_metrics(cw, seams, st.get("seam_counters") or {})
        st["seam_counters"] = counters
        _post_ndjson(m_events)
        for ev in m_signals:
            ev["tenant_id"] = tenant
            producer.send("netops.cloud", ev)

    st["seam_tracker"] = tracker.to_state()
    return {"vpn": len(seams.get("vpn", [])), "dx_vifs": len(seams.get("dx_vifs", [])),
            "tgws": len(seams.get("tgws", [])), "nats": len(seams.get("nats", [])),
            "transitions": len(events), "metric_points": len(m_events),
            "fault_signals": len(m_signals)}
