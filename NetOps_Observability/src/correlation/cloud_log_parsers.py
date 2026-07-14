"""Cloud log parsers — #81 P3B (cloud_flow / cloud_lb_access).

Pure, deterministic parsers that turn raw cloud log records into the canonical
`netops.cloud` event contract (the dicts cloud_producers.cloud_signal_from_event
consumes). Two documented AWS formats to start — the highest-signal Layer-1 "seam"
sources from docs/design/cloud-ingestion.md §2:

  * AWS ALB/NLB access logs  → cloud_lb_log   (gateway 5xx — app-edge errors)
  * AWS VPC flow logs        → cloud_flow_log (boundary REJECT / volume)

By design (cloud-ingestion.md): low-volume, boundary-relevant records only become
signals — we do NOT emit a signal per request/flow (that is the firehose the
ingestion-policy engine exists to suppress). The parser parses ONE record; the
`*_signal` mappers decide whether that record is signal-worthy and, if so, emit
the canonical event. Source wiring (a Vector file/S3 source or a Kinesis poller)
feeds these later — the transformation is what P3B owns and is exercised here.

Pure + offline (stdlib only: shlex/re). No IO, no wall-clock. Honest by
construction: a malformed/non-matching line returns None (the caller counts +
drops; provenance is never invented).
"""

from __future__ import annotations

import re
import shlex
from datetime import datetime, timezone

# arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/billing-tg/abc
_ARN_RE = re.compile(r"^arn:aws[^:]*:[^:]*:([^:]*):([^:]*):")


def _arn_region_account(arn: str) -> tuple[str, str]:
    """(region, account) out of an AWS ARN; ('','') when absent/malformed."""
    m = _ARN_RE.match(arn or "")
    return (m.group(1), m.group(2)) if m else ("", "")


def _f(v: str) -> float:
    """ALB numeric field → float; '-' / '' / bad → 0.0 (never raises)."""
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


# ── AWS ALB / NLB access logs ────────────────────────────────────────────────
# Space-separated, quoted fields may contain spaces (shlex handles the quoting).
# Field order is the documented v1 layout; trailing fields (conn-trace-id) are
# optional, so we index defensively and never require the tail.
_ALB_MIN_FIELDS = 25


def parse_alb_access_log(line: str) -> dict | None:
    """One ALB/NLB access-log line → structured record, or None when it is not a
    well-formed access log. Extracts only the fields the cloud_lb_log signal needs."""
    s = (line or "").strip()
    if not s:
        return None
    try:
        f = shlex.split(s)
    except ValueError:
        return None
    if len(f) < _ALB_MIN_FIELDS:
        return None
    region, account = _arn_region_account(f[16])  # target_group_arn
    return {
        "type": f[0],
        "time": f[1],
        "elb": f[2],                     # e.g. app/billing-alb/0a1b2c
        "client": f[3],
        "target": f[4],
        "target_processing_time": _f(f[6]),
        "elb_status_code": f[8],
        "target_status_code": f[9],
        "domain_name": f[18].strip('"'),
        "target_group_arn": f[16],
        "region": region,
        "account": account,
    }


def alb_lb_signal(rec: dict) -> dict | None:
    """Parsed ALB record → a cloud_lb_log event WHEN it is signal-worthy (an ELB-side
    5xx — the load balancer itself failed, distinct from a target 5xx). Returns None
    otherwise. Per cloud-app-status research: LB 5xx ≠ app 5xx; this is the LB plane.
    Entity is the LB resource (resource_id); app attribution is the identity map's job."""
    if not rec:
        return None
    code = str(rec.get("elb_status_code") or "")
    if not code.startswith("5"):
        return None  # only ELB-side 5xx is a fault signal; 2xx/3xx/4xx are not
    elb = str(rec.get("elb") or "")
    if not elb:
        return None
    return {
        "kind": "cloud_lb_log",
        "resource_id": elb,
        "account": rec.get("account", ""),
        "region": rec.get("region", ""),
        "severity": "high",
        "metric_name": "elb_5xx",
        "value": _f(code),
        "ts": rec.get("time", ""),
        "attrs": {
            # ALB access logs are an AWS-only format — the provider is a parse
            # fact, and the ingestion matrix facets by it (audit Azure P0-7).
            "provider": "aws",
            "elb_status_code": code,
            "target_status_code": str(rec.get("target_status_code") or ""),
            "target": str(rec.get("target") or ""),
            "domain": str(rec.get("domain_name") or ""),
        },
    }


# ── AWS VPC flow logs ────────────────────────────────────────────────────────
# Space-separated. The field SET is configurable per flow-log subscription, so the
# parser takes the field list (defaulting to the v2 default layout) and maps by
# NAME — never by blind position — so a custom format still parses correctly.
_VPC_V2_FIELDS = (
    "version account-id interface-id srcaddr dstaddr srcport dstport "
    "protocol packets bytes start end action log-status"
).split()

_PROTO_NAME = {"1": "icmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp"}


def parse_vpc_flow_log(line: str, fields: tuple[str, ...] | list[str] | None = None) -> dict | None:
    """One VPC flow-log record → structured record keyed by field name, or None when
    it does not match the field layout. `fields` overrides the default v2 layout for
    custom flow-log formats (mapped by name, never by blind position)."""
    s = (line or "").strip()
    if not s:
        return None
    cols = list(fields) if fields else _VPC_V2_FIELDS
    parts = s.split()
    if len(parts) != len(cols):
        return None
    rec = dict(zip(cols, parts))
    # NODATA / SKIPDATA records carry no 5-tuple — keep them out (honest: no flow).
    if rec.get("log-status") in ("NODATA", "SKIPDATA"):
        return None
    return rec


def cloud_log_event(fname: str, line: str) -> dict | None:
    """Dispatch one raw cloud-log line to the right parser by file extension
    (.alb → ALB access log, .vpc → VPC flow log), returning a signal-worthy
    netops.cloud event or None. Pure (no IO) — the runtime tailer adds tenancy + IO."""
    if fname.endswith(".alb"):
        alb = parse_alb_access_log(line)
        return alb_lb_signal(alb) if alb is not None else None
    if fname.endswith(".vpc"):
        vpc = parse_vpc_flow_log(line)
        return vpc_flow_signal(vpc) if vpc is not None else None
    return None


def _flow_ts(rec: dict) -> str:
    """RFC3339 event time from the record's own 'end' epoch (when the provider
    closed the aggregation window) — the flow's observation time, not our ingest
    time (audit P1-7: a flow replayed hours later must not look current)."""
    for key in ("end", "start"):
        raw = str(rec.get(key) or "")
        if raw.isdigit():
            return (
                datetime.fromtimestamp(int(raw), tz=timezone.utc)
                .isoformat()
                .replace("+00:00", "Z")
            )
    return ""


def vpc_flow_signal(rec: dict) -> dict | None:
    """Parsed VPC flow record → a cloud_flow_log event WHEN signal-worthy: a REJECT
    (security-group/NACL drop at a boundary — the cloud-side of a reachability fault).
    ACCEPT flows are volume, not per-record faults — vpc_accept_rollup aggregates
    them (audit P1-6). Entity is the ENI resource."""
    if not rec:
        return None
    if str(rec.get("action") or "").upper() != "REJECT":
        return None
    eni = str(rec.get("interface-id") or "")
    if not eni:
        return None
    proto = str(rec.get("protocol") or "")
    return {
        "kind": "cloud_flow_log",
        "resource_id": eni,
        "account": str(rec.get("account-id") or ""),
        "region": "",  # VPC flow logs do not carry region in the record; set by source
        "severity": "warn",
        "metric_name": "rejected_flow",
        "value": _f(str(rec.get("bytes") or "0")),
        "ts": _flow_ts(rec),
        "attrs": {
            # VPC flow logs are an AWS-only format — a parse fact (audit P0-7).
            "provider": "aws",
            "srcaddr": str(rec.get("srcaddr") or ""),
            "dstaddr": str(rec.get("dstaddr") or ""),
            "dstport": str(rec.get("dstport") or ""),
            "protocol": _PROTO_NAME.get(proto, proto),
            "action": "REJECT",
            "packets": str(rec.get("packets") or ""),
        },
    }


def vpc_accept_rollup(records: list[dict]) -> list[dict]:
    """ACCEPT flows from one scan batch → AT MOST one cloud_flow_volume signal per
    ENI (audit P1-6: discarding them made observed traffic structurally invisible).
    Aggregated here — never one event per record — because unsampled per-flow
    emission is exactly the volume that has taken the stack down before. Pure:
    the tailer owns IO and tenancy."""
    agg: dict[str, dict] = {}
    for rec in records:
        if str(rec.get("action") or "").upper() != "ACCEPT":
            continue
        eni = str(rec.get("interface-id") or "")
        if not eni:
            continue
        a = agg.setdefault(eni, {
            "bytes": 0, "packets": 0, "flows": 0,
            "account": str(rec.get("account-id") or ""), "end": "",
        })
        a["bytes"] += int(str(rec.get("bytes") or "0") or 0)
        a["packets"] += int(str(rec.get("packets") or "0") or 0)
        a["flows"] += 1
        end = str(rec.get("end") or "")
        if end.isdigit() and end > a["end"]:
            a["end"] = end
    out: list[dict] = []
    for eni, a in sorted(agg.items()):
        out.append({
            "kind": "cloud_flow_volume",
            "resource_id": eni,
            "account": a["account"],
            "region": "",
            "severity": "info",
            "metric_name": "accepted_flow_bytes",
            "value": float(a["bytes"]),
            "ts": _flow_ts({"end": a["end"]}),
            "attrs": {
                "provider": "aws",
                "flows": str(a["flows"]),
                "packets": str(a["packets"]),
                "action": "ACCEPT",
            },
        })
    return out
