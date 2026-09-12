# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""GCP log-based parity lanes (#105) — pure rollups over Cloud Logging entries.

Five lanes, one discipline: gcp.list_log_entries (bounded, checkpointed,
insertId-deduped entries:list) fetches a batch; these PURE functions turn the
batch into BOUNDED per-key rollup events on the existing provider-blind
netops.cloud kinds. cloud_log_parsers.py (correlation side) is the AWS twin —
same event shapes, same anti-firehose law (audit P1-6: never one event per
record; a rollup per aggregation key per batch):

  vpc_flows           → cloud_flow_volume  per local instance (ACCEPT volume)
                      → cloud_flow_pair    top-K (src,dst) pairs by bytes (#9
                        service-dependency talks_to edges; peer kept)
  firewall DENIED     → cloud_flow_log     per (rule, disposition) — the REJECT lane
  LB `requests` 5xx   → cloud_lb_log       per (lb, status)
  LB `requests` Armor → cloud_waf_log      per (policy, rule priority) DENY
  dns_queries errors  → cloud_dns_log      per (query name, rcode)

VERIFIED FACT (cloud-telemetry-catalog.md, KEY CORRECTION): GCP VPC flow logs
have NO accept/reject field — denied traffic NEVER appears in vpc_flows. The
REJECT fault lane on GCP is Firewall Rules Logging, which names the matched
rule in-record (better than AWS, where the blocking SG/NACL must be inferred).
Nothing here fabricates a deny out of a flow record.

Cardinality is capped per batch (MAX_ROLLUP_KEYS, top keys by count, stable
order). A capped batch says so on every emitted event (attrs.rollup_truncated
= dropped-key count) — bounded AND observable, never a silent drop (§10).

Pure + offline (stdlib only). No IO, no wall-clock; gcp.py owns fetch, tenancy
and Kafka.
"""
from __future__ import annotations

# At most this many rollup events per lane per batch. The batch itself is
# already bounded (page_size × max_pages in gcp.list_log_entries); this bounds
# the KEY cardinality a hostile/pathological log family could emit.
MAX_ROLLUP_KEYS = 100

# IANA protocol number → name (same map the AWS VPC parser keeps).
_PROTO_NAME = {"1": "icmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp"}

_DNS_ERROR_RCODES = ("NXDOMAIN", "SERVFAIL", "REFUSED")


def _payload(entry: dict) -> dict:
    p = entry.get("jsonPayload")
    return p if isinstance(p, dict) else {}


def _labels(entry: dict) -> dict:
    lab = (entry.get("resource") or {}).get("labels")
    return lab if isinstance(lab, dict) else {}


def _region(entry: dict) -> str:
    lab = _labels(entry)
    return str(lab.get("region") or lab.get("location") or "")


def _cap(agg: dict, count_key: str) -> tuple[list, int]:
    """Top MAX_ROLLUP_KEYS aggregation keys by count (then key, for stable
    output). Returns (kept items, dropped-key count)."""
    items = sorted(agg.items(), key=lambda kv: (-kv[1][count_key], str(kv[0])))
    return items[:MAX_ROLLUP_KEYS], max(0, len(items) - MAX_ROLLUP_KEYS)


def _attrs(base: dict, dropped: int) -> dict:
    if dropped:
        base["rollup_truncated"] = str(dropped)
    return base


def _int(v: object) -> int:
    try:
        return int(str(v))
    except (TypeError, ValueError):
        return 0


# ── VPC flow logs → ACCEPT volume (cloud_flow_volume) ────────────────────────


def _flow_local_entity(p: dict, project: str) -> str:
    """The LOCAL endpoint of one flow record: the reporter-side instance as a
    full resource path (grounds to the gcp.json inventory rows), falling back
    to the reporter-side subnetwork. Empty when neither is present."""
    src_side = str(p.get("reporter") or "").upper() != "DEST"
    inst = p.get("src_instance" if src_side else "dest_instance") or {}
    vm, zone = str(inst.get("vm_name") or ""), str(inst.get("zone") or "")
    if vm and zone:
        proj = str(inst.get("project_id") or project)
        return f"projects/{proj}/zones/{zone}/instances/{vm}"
    vpc = p.get("src_vpc" if src_side else "dest_vpc") or {}
    sub = str(vpc.get("subnetwork_name") or "")
    return f"subnetwork:{sub}" if sub else ""


def flow_volume_rollup(entries: list[dict], project: str) -> list[dict]:
    """VPC flow entries from one batch → AT MOST one cloud_flow_volume signal
    per local instance/subnet (the AWS per-ENI rollup, GCP edition). ALL GCP
    flow records are accepted traffic (no deny records exist — see module
    header); the REJECT lane is firewall_reject_rollup."""
    agg: dict[str, dict] = {}
    for e in entries:
        p = _payload(e)
        entity = _flow_local_entity(p, project)
        if not entity:
            continue
        a = agg.setdefault(entity, {
            "bytes": 0, "packets": 0, "flows": 0, "ts": "",
            "region": _region(e),
            "subnet": str((p.get("src_vpc") or {}).get("subnetwork_name")
                          or (p.get("dest_vpc") or {}).get("subnetwork_name") or ""),
            "vpc": str((p.get("src_vpc") or {}).get("vpc_name")
                       or (p.get("dest_vpc") or {}).get("vpc_name") or ""),
        })
        a["bytes"] += _int(p.get("bytes_sent"))
        a["packets"] += _int(p.get("packets_sent"))
        a["flows"] += 1
        end = str(p.get("end_time") or e.get("timestamp") or "")
        if end > a["ts"]:
            a["ts"] = end
    kept, dropped = _cap(agg, "flows")
    out: list[dict] = []
    for entity, a in kept:
        out.append({
            "kind": "cloud_flow_volume",
            "provider": "gcp",
            "resource_id": entity,
            "account": project,
            "region": a["region"],
            "severity": "info",
            "metric_name": "accepted_flow_bytes",
            "value": float(a["bytes"]),
            "ts": a["ts"],
            "attrs": _attrs({
                "provider": "gcp",
                "flows": str(a["flows"]),
                "packets": str(a["packets"]),
                # GCP flow logs carry accepted traffic ONLY (a format fact).
                "action": "ACCEPT",
                "subnetwork": a["subnet"],
                "vpc": a["vpc"],
            }, dropped),
        })
    return out


def flow_pair_rollup(entries: list[dict], project: str, top_k: int = 20) -> list[dict]:
    """VPC flow entries from one batch → the top-K (src, dst) PAIR volumes
    (cloud-platform-backlog #9): the peer-preserving sibling of
    flow_volume_rollup, which collapses to per-instance totals and loses who
    talks to whom. GCP flow records carry the 5-tuple in
    jsonPayload.connection (src_ip/dest_ip) — real peer data, so the GCP lane
    emits pairs like AWS/Azure. ALL GCP flow records are accepted traffic (no
    deny records exist — module header), so every record qualifies.

    BOUNDED always: one signal per (src, dst) pair per batch, capped at top_k
    pairs by bytes (largest win, deterministic order). Entity is the pair
    itself ("src->dst"); tokens carry the reporter-side instance + both
    addresses for grounding. Pure — gcp.py owns fetch, tenancy and the
    env-tunable top_k."""
    agg: dict[tuple[str, str], dict] = {}
    for e in entries:
        p = _payload(e)
        conn = p.get("connection") or {}
        src = str(conn.get("src_ip") or "")
        dst = str(conn.get("dest_ip") or "")
        if not src or not dst or src == dst:
            continue
        a = agg.setdefault((src, dst), {
            "bytes": 0, "packets": 0, "flows": 0, "ts": "",
            "region": _region(e),
            "entity": _flow_local_entity(p, project),
        })
        a["bytes"] += _int(p.get("bytes_sent"))
        a["packets"] += _int(p.get("packets_sent"))
        a["flows"] += 1
        end = str(p.get("end_time") or e.get("timestamp") or "")
        if end > a["ts"]:
            a["ts"] = end
    kept = sorted(agg.items(), key=lambda kv: (-kv[1]["bytes"], kv[0]))[:max(1, int(top_k))]
    dropped = max(0, len(agg) - len(kept))
    out: list[dict] = []
    for (src, dst), a in kept:
        out.append({
            "kind": "cloud_flow_pair",
            "provider": "gcp",
            "resource_id": f"{src}->{dst}",
            "account": project,
            "region": a["region"],
            "severity": "info",
            "metric_name": "flow_pair_bytes",
            "value": float(a["bytes"]),
            "ts": a["ts"],
            "entity_tokens": [t for t in (a["entity"], src, dst) if t],
            "attrs": _attrs({
                "provider": "gcp",
                "srcaddr": src,
                "dstaddr": dst,
                # GCP flow logs carry accepted traffic ONLY (a format fact).
                "action": "ACCEPT",
                "flows": str(a["flows"]),
                "packets": str(a["packets"]),
                "interface": a["entity"],
            }, dropped),
        })
    return out


# ── Firewall Rules Logging DENIED → the GCP REJECT lane (cloud_flow_log) ─────


def firewall_reject_rollup(entries: list[dict], project: str) -> list[dict]:
    """Firewall-log entries from one batch → AT MOST one cloud_flow_log signal
    per (rule reference, disposition), DENIED only. This IS the GCP REJECT
    lane (drill #3): the record names the matched rule, so the entity is the
    RULE — richer than the AWS per-ENI reject, mapped onto the same fault kind
    (action=REJECT) so the cross-provider signatures fire unchanged. ALLOWED
    records are volume the flow-log lane already carries — ignored (anti-noise,
    the WAF-lane BLOCK-only discipline)."""
    agg: dict[tuple[str, str], dict] = {}
    for e in entries:
        p = _payload(e)
        disposition = str(p.get("disposition") or "").upper()
        if disposition != "DENIED":
            continue
        rd = p.get("rule_details") or {}
        ref = str(rd.get("reference") or "")
        if not ref:
            continue
        conn = p.get("connection") or {}
        a = agg.setdefault((ref, disposition), {
            "count": 0, "ts": "", "region": _region(e),
            "direction": str(rd.get("direction") or ""),
            "priority": str(rd.get("priority") or ""),
            "srcaddr": "", "dstaddr": "", "dstport": "", "protocol": "",
            "instance": "",
        })
        a["count"] += 1
        ts = str(e.get("timestamp") or "")
        if ts > a["ts"]:
            a["ts"] = ts
        if not a["srcaddr"]:
            a["srcaddr"] = str(conn.get("src_ip") or "")
            a["dstaddr"] = str(conn.get("dest_ip") or "")
            a["dstport"] = str(conn.get("dest_port") or "")
            proto = str(conn.get("protocol") or "")
            a["protocol"] = _PROTO_NAME.get(proto, proto)
            a["instance"] = str((p.get("instance") or {}).get("vm_name") or "")
    kept, dropped = _cap(agg, "count")
    out: list[dict] = []
    for (ref, disposition), a in kept:
        # "network:net-1/firewall:deny-ssh" → short rule name for the humans.
        rule = ref.rsplit("firewall:", 1)[-1]
        out.append({
            "kind": "cloud_flow_log",
            "provider": "gcp",
            "resource_id": ref,
            "account": project,
            "region": a["region"],
            "severity": "warn",
            "metric_name": "rejected_flow",
            "value": float(a["count"]),
            "ts": a["ts"],
            "attrs": _attrs({
                "provider": "gcp",
                # Shared cross-provider fault vocabulary + the native term.
                "action": "REJECT",
                "disposition": disposition,
                "rule": rule,
                "direction": a["direction"],
                "priority": a["priority"],
                "srcaddr": a["srcaddr"],
                "dstaddr": a["dstaddr"],
                "dstport": a["dstport"],
                "protocol": a["protocol"],
                "sample_instance": a["instance"],
            }, dropped),
        })
    return out


# ── Cloud Load Balancing request logs → LB-plane 5xx (cloud_lb_log) ──────────


def _lb_name(entry: dict) -> str:
    lab = _labels(entry)
    return str(lab.get("url_map_name") or lab.get("forwarding_rule_name")
               or lab.get("target_proxy_name") or "")


def lb_5xx_rollup(entries: list[dict], project: str) -> list[dict]:
    """LB request-log entries from one batch → AT MOST one cloud_lb_log signal
    per (LB, status). 5xx only (the ALB-lane rule: an LB-plane server error is
    the fault signal; 2xx/3xx/4xx are traffic). statusDetails is the GCP gift —
    it says WHY the LB answered 5xx (failed_to_pick_backend vs
    backend_connection_closed…), i.e. LB-vs-target blame in-record."""
    agg: dict[tuple[str, str], dict] = {}
    for e in entries:
        status = _int((e.get("httpRequest") or {}).get("status"))
        if not 500 <= status <= 599:
            continue
        lb = _lb_name(e)
        if not lb:
            continue
        a = agg.setdefault((lb, str(status)), {
            "count": 0, "ts": "", "region": _region(e),
            "status_details": "", "url": "", "client": "", "backend": "",
        })
        a["count"] += 1
        ts = str(e.get("timestamp") or "")
        if ts > a["ts"]:
            a["ts"] = ts
        if not a["status_details"]:
            hr = e.get("httpRequest") or {}
            a["status_details"] = str(_payload(e).get("statusDetails") or "")
            a["url"] = str(hr.get("requestUrl") or "")[:200]
            a["client"] = str(hr.get("remoteIp") or "")
            a["backend"] = str(_labels(e).get("backend_service_name") or "")
    kept, dropped = _cap(agg, "count")
    out: list[dict] = []
    for (lb, status), a in kept:
        out.append({
            "kind": "cloud_lb_log",
            "provider": "gcp",
            "resource_id": lb,
            "account": project,
            "region": a["region"],
            "severity": "high",
            "metric_name": "lb_5xx",
            "value": float(a["count"]),
            "ts": a["ts"],
            "attrs": _attrs({
                "provider": "gcp",
                "status": status,
                "status_details": a["status_details"],
                "sample_url": a["url"],
                "sample_client": a["client"],
                "backend_service": a["backend"],
            }, dropped),
        })
    return out


# ── Cloud Armor (rides the SAME LB request log) → cloud_waf_log ──────────────


def armor_block_rollup(entries: list[dict], project: str) -> list[dict]:
    """Cloud Armor enforcement out of the SAME request-log batch → AT MOST one
    cloud_waf_log signal per (security policy, matched rule priority), DENY
    outcomes only (the AWS WAF BLOCK-only rule). One fetch closes two matrix
    rows — Armor has no separate log. The policy is the entity (its name is
    the console pivot and the audit-log join key when a rule change caused the
    blocks); the matched rule priority is the `rule` attr."""
    agg: dict[tuple[str, str], dict] = {}
    for e in entries:
        sp = _payload(e).get("enforcedSecurityPolicy")
        if not isinstance(sp, dict):
            continue
        if str(sp.get("outcome") or "").upper() != "DENY":
            continue
        policy = str(sp.get("name") or "")
        if not policy:
            continue
        rule = str(sp.get("priority") or "")
        a = agg.setdefault((policy, rule), {
            "count": 0, "ts": "", "region": _region(e),
            "uri": "", "client": "", "configured_action": "",
        })
        a["count"] += 1
        ts = str(e.get("timestamp") or "")
        if ts > a["ts"]:
            a["ts"] = ts
        if not a["uri"]:
            hr = e.get("httpRequest") or {}
            a["uri"] = str(hr.get("requestUrl") or "")[:200]
            a["client"] = str(hr.get("remoteIp") or "")
            a["configured_action"] = str(sp.get("configuredAction") or "")
    kept, dropped = _cap(agg, "count")
    out: list[dict] = []
    for (policy, rule), a in kept:
        out.append({
            "kind": "cloud_waf_log",
            "provider": "gcp",
            "resource_id": policy,
            "account": project,
            "region": a["region"],
            "severity": "warn",
            "metric_name": "waf_blocked_requests",
            "value": float(a["count"]),
            "ts": a["ts"],
            "attrs": _attrs({
                "provider": "gcp",
                "rule": rule,
                "sample_uri": a["uri"],
                "sample_client": a["client"],
                "action": "BLOCK",
                "configured_action": a["configured_action"],
            }, dropped),
        })
    return out


# ── Cloud DNS query logs → resolution failures (cloud_dns_log) ───────────────


def dns_error_rollup(entries: list[dict], project: str) -> list[dict]:
    """DNS query-log entries from one batch → AT MOST one cloud_dns_log signal
    per (query name, error rcode). NOERROR answers are volume and are ignored
    (the R53 lane's rule). Entity is the NAME being resolved — what an
    investigation joins to a service's symptoms (EntityType.SERVICE routing in
    cloud_producers)."""
    agg: dict[tuple[str, str], dict] = {}
    for e in entries:
        p = _payload(e)
        rcode = str(p.get("responseCode") or "").upper()
        if rcode not in _DNS_ERROR_RCODES:
            continue
        name = str(p.get("queryName") or "").rstrip(".")
        if not name:
            continue
        a = agg.setdefault((name, rcode), {
            "count": 0, "ts": "", "region": _region(e),
            "src": "", "qtype": "", "network": "", "vm": "",
        })
        a["count"] += 1
        ts = str(e.get("timestamp") or "")
        if ts > a["ts"]:
            a["ts"] = ts
        if not a["src"]:
            a["src"] = str(p.get("sourceIP") or "")
            a["qtype"] = str(p.get("queryType") or "")
            a["network"] = str(p.get("sourceNetwork") or "")
            a["vm"] = str(p.get("vmInstanceName") or "")
    kept, dropped = _cap(agg, "count")
    out: list[dict] = []
    for (name, rcode), a in kept:
        out.append({
            "kind": "cloud_dns_log",
            "provider": "gcp",
            "resource_id": name,
            "account": project,
            "region": a["region"],
            "severity": "warn",
            "metric_name": "dns_resolution_failed",
            "value": float(a["count"]),
            "ts": a["ts"],
            "attrs": _attrs({
                "provider": "gcp",
                "rcode": rcode,
                "query_type": a["qtype"],
                "sample_client": a["src"],
                "source_network": a["network"],
                "sample_vm": a["vm"],
            }, dropped),
        })
    return out
