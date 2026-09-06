# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Azure storage-delivered log lanes (#105 build order #2 + log-fidelity families).

Azure's high-volume log families (VNet flow logs, App Gateway / Front Door
access + WAF logs, DNS security-policy query logs) are delivered by diagnostic
settings into a STORAGE ACCOUNT as hourly, append-grown block blobs
(`.../y=/m=/d=/h=/m=00/[macAddress=…/]PT1H.json`). This module is the Azure
sibling of poller.py's `_poll_s3_lane`: an incremental block-blob reader plus
pure per-batch ROLLUP parsers. Storage delivery is the default lane on purpose
(catalog fact #9: storage ≈ $0.25/GB vs Log Analytics ingestion ≈ $2.30/GB).

Lanes (each env-gated, off when unconfigured — honest, never fabricated):

  vnet_flow  container `insights-logs-flownetworkflowevent` (VNet flow logs
             ONLY — NSG flow logs retire 2027-09 and are deliberately not
             parsed) → the SAME canonical kinds the AWS VPC flow lane emits:
               flowState D  → cloud_flow_log   (bounded deny rollup)
               B/C/E bytes  → cloud_flow_volume (per-NIC accept volume rollup)
                            → cloud_flow_pair   (top-K (src,dst) accept pairs,
                              #9 service-dependency talks_to edges)
  lb_access  ApplicationGatewayAccessLog / FrontDoorAccessLog containers
             → cloud_lb_log — LB-plane 5xx rollup (mirror of the ALB lane)
  waf        ApplicationGatewayFirewallLog / FrontDoorWebApplicationFirewallLog
             → cloud_waf_log — per-(policy, rule) BLOCK rollup
  dns        DnsResponse (DNS security policy query logs)
             → cloud_dns_log — per-(query name, rcode) error rollup; the
               entity is the NAME being resolved (mirror of the R53 lane)

All emitted kinds already exist in the correlation contract
(src/correlation/cloud_producers.py CLOUD_KINDS) — the kinds are provider-
neutral by design; `attrs.provider = "azure"` is the parse fact that facets
the ingestion matrix.

P1-6 law: bounded rollups ONLY. Every lane aggregates a scan batch to at most
one signal per key and caps distinct keys (MAX_ROLLUP_KEYS, largest counts
win); a per-record firehose is structurally impossible here.

AUTH CHOICE (documented per #105): the SAME service-principal client-
credentials flow azure.py already uses, with the STORAGE audience
(scope https://storage.azure.com/.default) — `azure.token(scope=STORAGE_SCOPE)`.
The poller already holds SP creds, so no second secret (storage account key /
SAS) is introduced, and the SharedKey HMAC signing protocol never has to be
hand-rolled. Requires the DATA-plane role "Storage Blob Data Reader" on the
storage account (control-plane Reader is NOT sufficient for blob reads) — see
CREDENTIALS.md.

Incremental-read model: diagnostic-settings blobs are block blobs that GROW —
Azure appends new record blocks and rewrites only the closing `]}` block, so
every byte up to the END OF THE LAST RECORD is immutable. The checkpoint is a
per-blob byte offset that only ever advances to the end of the last fully
parsed record (never past it into the mutable tail), so a re-read never drops
or duplicates a record. Every query-string parameter and blob name is
percent-encoded (the ARM $filter raw-space failure class, live 2026-07-15).

stdlib-only (urllib + xml.etree), like every module in this container.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

STORAGE_SCOPE = "https://storage.azure.com/.default"
_XMS_VERSION = "2021-08-06"  # bearer (AAD) auth requires x-ms-version >= 2017-11-09

# ── env gates (empty = lane off; nothing is guessed) ─────────────────────────
# Master gate: the storage account name. Empty = every storage-log lane off.
STORAGE_ACCOUNT = os.environ.get("AZURE_LOGS_STORAGE_ACCOUNT", "")
# VNet flow lane: ON once the storage account is set (setting the account IS
# the opt-in, mirroring FLOW_S3_BUCKET on AWS); container name overridable.
VNET_FLOW_CONTAINER = os.environ.get(
    "AZURE_VNET_FLOW_CONTAINER", "insights-logs-flownetworkflowevent")
# Fidelity lanes: each an explicit comma-separated container list, empty = off
# (mirroring ALB/WAF/DNS_S3_PREFIX on AWS). Canonical diagnostic-settings names:
#   LB : insights-logs-applicationgatewayaccesslog, insights-logs-frontdooraccesslog
#   WAF: insights-logs-applicationgatewayfirewalllog,
#        insights-logs-frontdoorwebapplicationfirewalllog
#   DNS: insights-logs-dnsresponse
LB_CONTAINERS = os.environ.get("AZURE_LB_LOGS_CONTAINERS", "")
WAF_CONTAINERS = os.environ.get("AZURE_WAF_LOGS_CONTAINERS", "")
DNS_CONTAINERS = os.environ.get("AZURE_DNS_LOGS_CONTAINERS", "")
# Only blobs modified inside this window are considered (hourly PT1H blobs stop
# growing after their hour; 180 min covers the current + previous hour with
# delivery lag to spare) — this is what bounds listing work AND offset state.
LOOKBACK_MIN = int(os.environ.get("AZURE_LOGS_LOOKBACK_MIN", "180"))
REGION = os.environ.get("AZURE_REGION", "westus2")
SUBSCRIPTION = os.environ.get("AZURE_SUBSCRIPTION_ID", "")

# Bounded rollup cardinality (P1-6): at most this many distinct keys per lane
# per scan; when exceeded the LARGEST counts win and the drop is reported by
# the caller's log line, never silent.
MAX_ROLLUP_KEYS = 200
# Peer-pair volume bound (#9 service dependency map): at most this many
# (src,dst) ACCEPT pairs per scan cycle, largest bytes win. Shared knob name
# across the AWS/Azure/GCP flow lanes.
PAIR_TOP_K = int(os.environ.get("CLOUD_FLOW_PAIR_TOP_K", "20"))
_LIST_PAGE = 500       # maxresults per list call
_LIST_MAX_PAGES = 8    # listing ceiling per container per cycle (bounded IO)
_READ_MAX_BYTES = 32 * 1024 * 1024  # per-blob per-cycle read ceiling

# Same egress-TLS posture as azure.py (lab MITM → explicit CA bundle knob).
_CA = (os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("SSL_CERT_FILE")
       or os.environ.get("AWS_CA_BUNDLE") or "")
_SSL = ssl.create_default_context(cafile=_CA) if _CA else ssl.create_default_context()

_PROTO_NAME = {"1": "icmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp"}
_DNS_ERROR_RCODES = ("NXDOMAIN", "SERVFAIL", "REFUSED")


def configured() -> bool:
    """The Azure storage-log lanes exist only when a storage account is named."""
    return bool(STORAGE_ACCOUNT)


def lanes() -> dict[str, list[str]]:
    """lane → container list, only for lanes that are actually configured."""
    out: dict[str, list[str]] = {}
    if not configured():
        return out
    if VNET_FLOW_CONTAINER.strip():
        out["vnet_flow"] = [VNET_FLOW_CONTAINER.strip()]
    for lane, raw in (("lb", LB_CONTAINERS), ("waf", WAF_CONTAINERS), ("dns", DNS_CONTAINERS)):
        names = [c.strip() for c in raw.split(",") if c.strip()]
        if names:
            out[lane] = names
    return out


# ── storage REST primitives (bearer auth; every parameter percent-encoded) ───

def _account_url() -> str:
    return f"https://{STORAGE_ACCOUNT}.blob.core.windows.net"


def list_url(container: str, marker: str = "") -> str:
    """Container list-blobs URL. Marker (and any parameter) percent-encoded —
    raw specials in a query string are the exact failure class that broke the
    ARM $filter lane (2026-07-15)."""
    params = {"restype": "container", "comp": "list", "maxresults": str(_LIST_PAGE)}
    if marker:
        params["marker"] = marker
    return f"{_account_url()}/{urllib.parse.quote(container)}?{urllib.parse.urlencode(params)}"


def blob_url(container: str, name: str) -> str:
    """Blob GET URL. Diagnostic blob names carry '=' and '/' path segments —
    quote everything except the path separators."""
    return (f"{_account_url()}/{urllib.parse.quote(container)}/"
            f"{urllib.parse.quote(name, safe='/')}")


def _http_get(url: str, tok: str, extra_headers: dict | None = None) -> tuple[int, bytes]:
    headers = {"Authorization": "Bearer " + tok, "x-ms-version": _XMS_VERSION}
    headers.update(extra_headers or {})
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30, context=_SSL) as r:  # noqa: S310 - fixed storage host
            return r.status, r.read()
    except urllib.error.HTTPError as exc:
        return exc.code, b""


def list_blobs(tok: str, container: str, newer_than: dt.datetime) -> list[dict]:
    """Blobs in `container` modified after `newer_than` → [{name, size, modified}].
    Paged via NextMarker with a hard page ceiling (bounded IO)."""
    out: list[dict] = []
    marker = ""
    for _ in range(_LIST_MAX_PAGES):
        status, body = _http_get(list_url(container, marker), tok)
        if status == 404:  # container not created yet — lane configured but unfed
            return []
        if status >= 300:
            raise RuntimeError(f"list_blobs {container}: HTTP {status}")
        root = ET.fromstring(body)
        for blob in root.iter("Blob"):
            name = (blob.findtext("Name") or "").strip()
            props = blob.find("Properties")
            if not name or props is None:
                continue
            size = int(props.findtext("Content-Length") or "0")
            mod_raw = props.findtext("Last-Modified") or ""
            try:  # RFC 1123: Tue, 15 Jul 2026 09:00:00 GMT
                mod = dt.datetime.strptime(mod_raw, "%a, %d %b %Y %H:%M:%S %Z").replace(
                    tzinfo=dt.timezone.utc)
            except ValueError:
                mod = dt.datetime.now(dt.timezone.utc)
            if mod >= newer_than:
                out.append({"name": name, "size": size, "modified": mod})
        marker = (root.findtext("NextMarker") or "").strip()
        if not marker:
            break
    return out


def read_range(tok: str, container: str, name: str, offset: int) -> bytes:
    """Bytes of a blob from `offset` (bounded). 416 = nothing new → b''."""
    status, body = _http_get(
        blob_url(container, name), tok,
        {"Range": f"bytes={offset}-{offset + _READ_MAX_BYTES - 1}"})
    if status == 416:  # range past EOF — no new committed bytes
        return b""
    if status >= 300:
        raise RuntimeError(f"read_range {container}/{name}: HTTP {status}")
    return body


# ── incremental JSON record extraction ───────────────────────────────────────

_WRAPPER_RE = re.compile(r'\{\s*"records"\s*:\s*\[')


def scan_json_records(chunk: bytes) -> tuple[list[dict], int]:
    """Extract complete JSON record objects from a blob fragment.

    Handles all three shapes diagnostic delivery produces: a whole
    `{"records":[…]}` document (offset-0 read), an appended fragment
    (`,{…},{…}]}`), and JSON-lines. Returns (records, consumed_bytes) where
    consumed_bytes ends at the LAST COMPLETE record — never inside the mutable
    `]}` tail and never past a truncated object, so the caller's offset
    checkpoint is always a byte Azure will not rewrite.
    """
    try:
        text = chunk.decode("utf-8")
    except UnicodeDecodeError as exc:
        text = chunk[:exc.start].decode("utf-8")  # split multibyte at tail
    dec = json.JSONDecoder()
    records: list[dict] = []
    i = 0
    last_end = 0
    n = len(text)
    while i < n:
        if text[i] != "{":
            i += 1
            continue
        m = _WRAPPER_RE.match(text, i)
        if m:  # skip the wrapper prefix; records are scanned individually
            i = m.end()
            continue
        try:
            obj, end = dec.raw_decode(text, i)
        except ValueError:
            break  # truncated tail — re-read from last_end next cycle
        if isinstance(obj, dict):
            records.append(obj)
            last_end = end
        i = end
    # utf-8 strict decode round-trips exactly → prefix re-encode = byte offset.
    return records, len(text[:last_end].encode("utf-8"))


# ── shared rollup helpers ────────────────────────────────────────────────────

def _iso_from_ms(ms: int) -> str:
    if ms <= 0:
        return ""
    return (dt.datetime.fromtimestamp(ms / 1000, tz=dt.timezone.utc)
            .isoformat().replace("+00:00", "Z"))


def _cap(agg: dict, count_key: str = "count") -> list:
    """Bound rollup cardinality: keep the MAX_ROLLUP_KEYS largest keys.
    Deterministic (count desc, then key) — the loudest evidence survives."""
    items = sorted(agg.items(), key=lambda kv: (-kv[1].get(count_key, 0), str(kv[0])))
    return items[:MAX_ROLLUP_KEYS]


def _prop(rec: dict, *names: str) -> str:
    """Tolerant property lookup: record['properties'] then the record itself,
    each name tried verbatim, then PascalCase/camelCase twin. Diagnostic
    categories disagree on casing across services (verified: AppGW camelCase,
    LA-shaped DNS records PascalCase)."""
    props = rec.get("properties") if isinstance(rec.get("properties"), dict) else {}
    for src in (props, rec):
        for name in names:
            for variant in (name, name[:1].upper() + name[1:], name[:1].lower() + name[1:]):
                v = src.get(variant)
                if v is not None and v != "":
                    return str(v)
    return ""


def _category(rec: dict) -> str:
    return str(rec.get("category") or rec.get("Category") or "")


# ── lane 1: VNet flow logs → cloud_flow_log / cloud_flow_volume ──────────────
# Version-4 tuple (13 comma-separated fields):
#   0 ts_ms, 1 src, 2 dst, 3 srcport, 4 dstport, 5 protocol (IANA number),
#   6 direction I/O, 7 flowState B/C/E/D (D = denied), 8 encryption,
#   9 pktsS2D, 10 bytesS2D, 11 pktsD2S, 12 bytesD2S

def _int0(v: str) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def vnet_flow_rollups(records: list[dict]) -> list[dict]:
    """One scan batch of FlowLogFlowEvent records → bounded rollups on the SAME
    kinds the AWS VPC flow lane emits (provider-blind downstream):

      * denied tuples (flowState D) → cloud_flow_log, one per (NIC MAC, rule);
        value = denied-flow count (denied flows carry no bytes — count is the
        honest magnitude; the AWS lane's per-record value is its bytes field).
      * allowed tuples (B/C/E)      → cloud_flow_volume, one per NIC MAC;
        value = total bytes both directions (mirror of vpc_accept_rollup).
      * allowed tuples, peer kept   → cloud_flow_pair, top PAIR_TOP_K (src,dst)
        pairs by bytes per scan (#9 talks_to edges — mirror of vpc_pair_rollup;
        the per-NIC volume rollup deliberately loses who talks to whom).

    Entity is the NIC (macAddress — the blob's own partition key, the ENI
    analog); the target VNet/subnet ARM id rides attrs + entity_tokens for
    grounding. Malformed tuples are skipped, never guessed.
    """
    deny: dict[tuple[str, str], dict] = {}
    accept: dict[str, dict] = {}
    pair: dict[tuple[str, str], dict] = {}
    for rec in records:
        flows_obj = rec.get("flowRecords")
        if not isinstance(flows_obj, dict):
            continue
        mac = str(rec.get("macAddress") or "")
        if not mac:
            continue
        target = str(rec.get("targetResourceID") or "")
        for flow in flows_obj.get("flows") or []:
            acl = str(flow.get("aclID") or "")
            for group in flow.get("flowGroups") or []:
                rule = str(group.get("rule") or "")
                for tup in group.get("flowTuples") or []:
                    f = str(tup).split(",")
                    if len(f) < 9:
                        continue  # not a v4 tuple — skip, never guess
                    ts_ms = _int0(f[0])
                    state = f[7].strip().upper()
                    if state == "D":
                        a = deny.setdefault((mac, rule), {
                            "count": 0, "ts_ms": 0, "src": "", "dst": "",
                            "dstport": "", "proto": "", "acl": acl, "target": target,
                        })
                        a["count"] += 1
                        if ts_ms > a["ts_ms"]:
                            a["ts_ms"] = ts_ms
                        if not a["src"]:
                            a["src"], a["dst"] = f[1], f[2]
                            a["dstport"] = f[4]
                            a["proto"] = _PROTO_NAME.get(f[5], f[5])
                    elif state in ("B", "C", "E"):
                        tup_bytes = (_int0(f[10]) if len(f) > 10 else 0) + (_int0(f[12]) if len(f) > 12 else 0)
                        tup_pkts = (_int0(f[9]) if len(f) > 9 else 0) + (_int0(f[11]) if len(f) > 11 else 0)
                        a = accept.setdefault(mac, {
                            "bytes": 0, "packets": 0, "flows": 0,
                            "ts_ms": 0, "target": target,
                        })
                        a["bytes"] += tup_bytes
                        a["packets"] += tup_pkts
                        a["flows"] += 1
                        if ts_ms > a["ts_ms"]:
                            a["ts_ms"] = ts_ms
                        src, dst = f[1].strip(), f[2].strip()
                        if src and dst and src != dst:
                            p = pair.setdefault((src, dst), {
                                "bytes": 0, "packets": 0, "flows": 0,
                                "ts_ms": 0, "mac": mac, "target": target,
                            })
                            p["bytes"] += tup_bytes
                            p["packets"] += tup_pkts
                            p["flows"] += 1
                            if ts_ms > p["ts_ms"]:
                                p["ts_ms"] = ts_ms
    out: list[dict] = []
    for (mac, rule), a in _cap(deny):
        out.append({
            "kind": "cloud_flow_log",
            "resource_id": mac,
            "account": SUBSCRIPTION,
            "region": REGION,
            "severity": "warn",
            "metric_name": "rejected_flow",
            "value": float(a["count"]),
            "ts": _iso_from_ms(a["ts_ms"]),
            "entity_tokens": [t for t in (mac, a["target"]) if t],
            "attrs": {
                "provider": "azure",
                "action": "REJECT",
                "rule": rule,
                "acl_id": a["acl"],
                "target_resource_id": a["target"],
                "srcaddr": a["src"],
                "dstaddr": a["dst"],
                "dstport": a["dstport"],
                "protocol": a["proto"],
                "flows": str(a["count"]),
            },
        })
    for mac, a in _cap(accept, count_key="flows"):
        if a["flows"] == 0:
            continue
        out.append({
            "kind": "cloud_flow_volume",
            "resource_id": mac,
            "account": SUBSCRIPTION,
            "region": REGION,
            "severity": "info",
            "metric_name": "accepted_flow_bytes",
            "value": float(a["bytes"]),
            "ts": _iso_from_ms(a["ts_ms"]),
            "entity_tokens": [t for t in (mac, a["target"]) if t],
            "attrs": {
                "provider": "azure",
                "action": "ACCEPT",
                "flows": str(a["flows"]),
                "packets": str(a["packets"]),
                "target_resource_id": a["target"],
            },
        })
    kept_pairs = sorted(pair.items(), key=lambda kv: (-kv[1]["bytes"], kv[0]))[:max(1, PAIR_TOP_K)]
    for (src, dst), a in kept_pairs:
        out.append({
            "kind": "cloud_flow_pair",
            "resource_id": f"{src}->{dst}",
            "account": SUBSCRIPTION,
            "region": REGION,
            "severity": "info",
            "metric_name": "flow_pair_bytes",
            "value": float(a["bytes"]),
            "ts": _iso_from_ms(a["ts_ms"]),
            "entity_tokens": [t for t in (a["mac"], a["target"], src, dst) if t],
            "attrs": {
                "provider": "azure",
                "srcaddr": src,
                "dstaddr": dst,
                "action": "ACCEPT",
                "flows": str(a["flows"]),
                "packets": str(a["packets"]),
                "interface": a["mac"],
                "target_resource_id": a["target"],
            },
        })
    return out


# ── lane 2: App Gateway / Front Door access logs → cloud_lb_log ──────────────

_LB_CATEGORIES = ("ApplicationGatewayAccessLog", "FrontDoorAccessLog")


def lb_5xx_rollups(records: list[dict]) -> list[dict]:
    """Access-log records → LB-plane 5xx rollup, one cloud_lb_log per
    (gateway resource, status code) per scan (the ALB lane's evidence class,
    bounded). AppGW `httpStatus` / Front Door `httpStatusCode` is the status
    the LB ANSWERED — the backend's own status rides attrs for the LB-vs-target
    blame split."""
    agg: dict[tuple[str, str], dict] = {}
    for rec in records:
        cat = _category(rec)
        if cat not in _LB_CATEGORIES:
            continue
        code = _prop(rec, "httpStatus", "httpStatusCode")
        if not code.startswith("5"):
            continue  # only LB-plane 5xx is a fault signal
        rid = str(rec.get("resourceId") or rec.get("ResourceId") or "")
        if not rid:
            continue
        a = agg.setdefault((rid, code), {
            "count": 0, "ts": "", "uri": "", "host": "", "backend": "", "cat": cat,
        })
        a["count"] += 1
        ts = str(rec.get("time") or "")
        if ts > a["ts"]:
            a["ts"] = ts
        if not a["uri"]:
            a["uri"] = _prop(rec, "requestUri")[:200]
            a["host"] = _prop(rec, "host", "hostName", "originalHost")
            a["backend"] = _prop(rec, "serverStatus", "httpStatusDetails")
    out: list[dict] = []
    for (rid, code), a in _cap(agg):
        out.append({
            "kind": "cloud_lb_log",
            "resource_id": rid,
            "account": SUBSCRIPTION,
            "region": REGION,
            "severity": "high",
            "metric_name": "lb_5xx",
            "value": float(a["count"]),
            "ts": a["ts"],
            "attrs": {
                "provider": "azure",
                "status_code": code,
                "backend_status": a["backend"],
                "sample_uri": a["uri"],
                "domain": a["host"],
                "category": a["cat"],
                "requests": str(a["count"]),
            },
        })
    return out


# ── lane 3: WAF logs → cloud_waf_log ─────────────────────────────────────────

# category → the action value that means BLOCK (AppGW says "Blocked",
# Front Door says "Block"; Detected/Log/Matched are observe-mode noise).
_WAF_BLOCK_ACTIONS = {
    "ApplicationGatewayFirewallLog": "blocked",
    "FrontDoorWebApplicationFirewallLog": "block",
}


def waf_block_rollups(records: list[dict]) -> list[dict]:
    """WAF records → per-(policy, rule) BLOCK rollup (cloud_waf_log — the "our
    own WAF rule is eating legitimate traffic" evidence class, joining the
    Activity Log rule-change event). Detect/Log-mode matches are ignored."""
    agg: dict[tuple[str, str], dict] = {}
    for rec in records:
        cat = _category(rec)
        block_word = _WAF_BLOCK_ACTIONS.get(cat)
        if not block_word:
            continue
        if _prop(rec, "action").lower() != block_word:
            continue
        policy = (_prop(rec, "policyId", "policy", "policyName")
                  or str(rec.get("resourceId") or rec.get("ResourceId") or ""))
        rule = _prop(rec, "ruleId", "ruleName")
        if not policy:
            continue
        a = agg.setdefault((policy, rule), {
            "count": 0, "ts": "", "uri": "", "client": "", "host": "",
        })
        a["count"] += 1
        ts = str(rec.get("time") or "")
        if ts > a["ts"]:
            a["ts"] = ts
        if not a["uri"]:
            a["uri"] = _prop(rec, "requestUri")[:200]
            a["client"] = _prop(rec, "clientIp", "clientIP")
            a["host"] = _prop(rec, "hostname", "host")
    out: list[dict] = []
    for (policy, rule), a in _cap(agg):
        out.append({
            "kind": "cloud_waf_log",
            "resource_id": policy,
            "account": SUBSCRIPTION,
            "region": REGION,
            "severity": "warn",
            "metric_name": "waf_blocked_requests",
            "value": float(a["count"]),
            "ts": a["ts"],
            "attrs": {
                "provider": "azure",
                "rule": rule,
                "sample_uri": a["uri"],
                "sample_client": a["client"],
                "host": a["host"],
                "action": "BLOCK",
            },
        })
    return out


# ── lane 4: DNS security-policy query logs → cloud_dns_log ───────────────────

def dns_error_rollups(records: list[dict]) -> list[dict]:
    """DnsResponse records → per-(query name, rcode) error rollup
    (cloud_dns_log). Entity is the NAME being resolved (EntityType.SERVICE via
    the kind's contract) — exactly the R53 Resolver lane's shape. NOERROR
    answers are volume and are ignored."""
    agg: dict[tuple[str, str], dict] = {}
    for rec in records:
        cat = _category(rec)
        if cat and cat != "DnsResponse":
            continue
        rcode = _prop(rec, "responseCode").upper()
        if rcode not in _DNS_ERROR_RCODES:
            continue
        name = _prop(rec, "queryName").rstrip(".")
        if not name:
            continue
        a = agg.setdefault((name, rcode), {
            "count": 0, "ts": "", "src": "", "vnet": "", "qtype": "",
        })
        a["count"] += 1
        ts = str(rec.get("time") or "")
        if ts > a["ts"]:
            a["ts"] = ts
        if not a["src"]:
            a["src"] = _prop(rec, "sourceIpAddress")
            a["vnet"] = _prop(rec, "virtualNetworkId")
            a["qtype"] = _prop(rec, "queryType")
    out: list[dict] = []
    for (name, rcode), a in _cap(agg):
        out.append({
            "kind": "cloud_dns_log",
            "resource_id": name,
            "account": SUBSCRIPTION,
            "region": REGION,
            "severity": "warn",
            "metric_name": "dns_resolution_failed",
            "value": float(a["count"]),
            "ts": a["ts"],
            "attrs": {
                "provider": "azure",
                "rcode": rcode,
                "query_type": a["qtype"],
                "sample_client": a["src"],
                "vnet": a["vnet"],
            },
        })
    return out


_LANE_ROLLUPS = {
    "vnet_flow": vnet_flow_rollups,
    "lb": lb_5xx_rollups,
    "waf": waf_block_rollups,
    "dns": dns_error_rollups,
}


# ── cycle driver ──────────────────────────────────────────────────────────────

def poll_container(tok: str, container: str, offsets: dict) -> list[dict]:
    """One container's incremental sweep: list recent blobs, read each from its
    checkpointed offset, extract new records. `offsets` (blob → byte offset) is
    mutated in place and PRUNED to blobs still inside the lookback window, so
    state never grows unboundedly."""
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=LOOKBACK_MIN)
    blobs = list_blobs(tok, container, cutoff)
    live_names = {b["name"] for b in blobs}
    for stale in [k for k in offsets if k not in live_names]:
        del offsets[stale]
    records: list[dict] = []
    for b in blobs:
        off = int(offsets.get(b["name"], 0))
        if b["size"] <= off:
            continue
        chunk = read_range(tok, container, b["name"], off)
        if not chunk:
            continue
        recs, consumed = scan_json_records(chunk)
        if consumed:
            offsets[b["name"]] = off + consumed
        records.extend(recs)
    return records


def run(tok: str, producer, tenant: str, st: dict) -> dict:
    """One storage-log cycle over every configured lane. Per-container guard:
    one bad container/lane must never kill the others (the exact bug class that
    once took the whole Azure cycle down — P1-11). Returns per-lane signal
    counts + blob-read stats for the poller's log line."""
    state: dict = st.setdefault("az_log_blobs", {})
    counts: dict[str, int] = {}
    errors = 0
    for lane, containers in lanes().items():
        rollup = _LANE_ROLLUPS[lane]
        sent = 0
        for container in containers:
            offsets = state.setdefault(container, {})
            try:
                records = poll_container(tok, container, offsets)
                for ev in rollup(records):
                    ev["tenant_id"] = tenant
                    producer.send("netops.cloud", ev)
                    sent += 1
            except Exception as exc:  # noqa: BLE001 - lane isolation
                errors += 1
                print(json.dumps({"service": "cloud-ingest",
                                  "msg": "azure log lane error", "lane": lane,
                                  "container": container,
                                  "error": str(exc)[:200]}), flush=True)
        counts[lane] = sent
    if errors:
        # "error_count", NOT "errors": discover.py/azure.py log "errors" as an
        # OBJECT (per-component error map), and OpenSearch permanently rejects
        # any applog doc whose field shape conflicts with the day-index mapping
        # (object vs scalar — 301 rejected lines/6h measured 2026-08-04). One
        # field name must have ONE shape across every emitter.
        counts["error_count"] = errors
    return counts
