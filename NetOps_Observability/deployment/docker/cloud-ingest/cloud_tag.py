# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Cloud-log family/provider tagging — the ingest half of the unified Cloud Logs
experience.

The poller already appends raw cloud log lines to per-lane files whose name
encodes the source lane (aws-vpc-flow.vpc, aws-alb-access.alb, aws-waf.waf,
aws-r53-resolver.dns). Those raw lines used to reach OpenSearch only as generic
untagged syslog (or not at all) — searchable by nobody as "cloud". This module
turns one raw line into a canonical `netops.cloudlogs` document tagged with:

  * cloud_family   ∈ {waf, lb, dns, flow, change, host, inventory}
  * cloud_provider ∈ {aws, azure, gcp}
  * resource_id    — the device the line is about (ELB for lb, WebACL for waf,
                     query name for dns, ENI for flow, changed resource for change)

vector-router indexes these into netops-cloudlogs-{tenant}-{date}, so
`cloud_family:waf AND cloud_provider:aws AND resource_id:...` become real Lucene
filters in Log Search — the RAW line, not just a correlation signal.

Pure + deterministic (stdlib only: json/shlex). No IO, no wall-clock EXCEPT the
optional ingest-time stamp, which the caller passes in. Honest by construction:
an unrecognized lane/line returns None (the caller counts + drops; a family/
provider is never guessed).
"""
from __future__ import annotations

import datetime as _dt
import json
import shlex

# File extension → log family. MUST match the out_names the poller writes and the
# family ids the Cloud Logs UI lanes filter on.
FAMILY_BY_EXT: dict[str, str] = {
    ".vpc": "flow",
    ".alb": "lb",
    ".waf": "waf",
    ".dns": "dns",
}

_KNOWN_PROVIDERS = ("aws", "azure", "gcp")

# Clock-skew tolerance per family, in SECONDS (log-time standard S5/R5).
# Batch-delivered lanes legitimately lag their event time — ALB access logs
# arrive ~5 min behind, VPC flow logs up to ~10 min (arbitrarily more on
# backfill) — so the tolerance is per-family, sized ~2–3× the documented
# delivery lag. Only |event − ingest| BEYOND the tolerance stamps
# `clock_skew_s` (signed seconds, positive = event time ahead of ingest —
# i.e. a future-stamped record; negative = delivery/backfill lag beyond the
# expected envelope). The stamp is a data-quality flag: the timestamp itself
# is never rewritten (R2), and ingested_at is always kept alongside (R3).
FAMILY_SKEW_TOLERANCE_S: dict[str, float] = {
    "lb":   900.0,   # ALB/NLB access logs: ~5 min S3 delivery → 15 min envelope
    "flow": 1800.0,  # VPC flow logs: up to ~10 min delivery → 30 min envelope
    "waf":  600.0,   # WAF logs: near-real-time Firehose → 10 min envelope
    "dns":  900.0,   # Resolver query logs: batch delivery → 15 min envelope
}
DEFAULT_SKEW_TOLERANCE_S = 300.0  # any other family: the syslog default


def family_for(out_name: str) -> str:
    """Log family for a lane file name (by extension); "" when unrecognized."""
    for ext, fam in FAMILY_BY_EXT.items():
        if out_name.endswith(ext):
            return fam
    return ""


def provider_for(out_name: str) -> str:
    """Cloud provider from the lane file-name prefix (aws-…/azure-…/gcp-…). The
    provider is a PARSE FACT of the source, never inferred from content. Unknown
    prefix → "" (honest: the caller can still search cloud_family)."""
    head = out_name.split("-", 1)[0].lower()
    return head if head in _KNOWN_PROVIDERS else ""


def _resource_id_flow(line: str) -> str:
    """VPC flow log → interface-id (ENI). Default v2 layout is
    `version account-id interface-id …`; extract defensively by position, only
    when the leading `version` token is numeric (so a header/garbage line yields "")."""
    parts = line.split()
    if len(parts) >= 3 and parts[0].isdigit():
        return parts[2]
    return ""


def _resource_id_lb(line: str) -> str:
    """ALB/NLB access log → the ELB id (field index 2), quoting-aware."""
    try:
        f = shlex.split(line)
    except ValueError:
        return ""
    return f[2] if len(f) >= 3 else ""


def _json_field(line: str, key: str) -> str:
    """Value of `key` in a one-line JSON record; "" when not JSON / absent."""
    s = line.strip()
    if not s.startswith("{"):
        return ""
    try:
        rec = json.loads(s)
    except ValueError:
        return ""
    val = rec.get(key)
    return str(val) if val not in (None, "") else ""


def resource_id_for(family: str, line: str) -> str:
    """Best-effort resource id (the device the line is about) for a family. Never
    raises; "" when the line does not carry an id in the expected place."""
    if family == "flow":
        return _resource_id_flow(line)
    if family == "lb":
        return _resource_id_lb(line)
    if family == "waf":
        return _json_field(line, "webaclId")
    if family == "dns":
        return _json_field(line, "query_name").rstrip(".")
    return ""


def _iso_utc(t: _dt.datetime) -> str:
    """Aware datetime → RFC 3339 UTC string ("...Z")."""
    return (t.astimezone(_dt.timezone.utc)
            .isoformat(timespec="milliseconds").replace("+00:00", "Z"))


def _parse_provider_iso(s: str) -> str:
    """Provider ISO-8601 string → RFC 3339 UTC, or "" when unparseable. AWS
    stamps are UTC ("Z" or offset-suffixed); a zone-less string is refused
    rather than guessed (log-time standard: never assume a zone silently)."""
    if not s:
        return ""
    try:
        t = _dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return ""
    if t.tzinfo is None:
        return ""
    return _iso_utc(t)


def _epoch_to_iso(v, ms: bool = False) -> str:
    """Epoch seconds (or millis) → RFC 3339 UTC, "" when not a sane epoch."""
    try:
        n = float(v)
    except (TypeError, ValueError):
        return ""
    if ms:
        n /= 1000.0
    # Sanity bounds: 2000-01-01 .. 2200-01-01 — a field that is not actually
    # an epoch (port, count) must never masquerade as a time.
    if not (946684800 <= n <= 7258118400):
        return ""
    return _iso_utc(_dt.datetime.fromtimestamp(n, tz=_dt.timezone.utc))


def event_ts_for(family: str, line: str) -> str:
    """The record's OWN event time (RFC 3339 UTC) parsed from the raw line, or
    "" when the line does not carry one where the family's format puts it.
    Cloud log objects are batch-delivered minutes after the fact (ALB ~5 min,
    VPC flow up to ~10 min) — stamping ingest time misplaces every record on
    the timeline, so the searchable `timestamp` must be the event time.

      lb   — ALB/NLB access log, field 1 is ISO-8601 UTC (field 0 is the type).
      waf  — WAF JSON, "timestamp" is epoch milliseconds.
      flow — VPC flow log v2 default layout, fields 10/11 are start/end epoch
             seconds; we use `start` (when the flow began).
      dns  — Route 53 resolver query log JSON, "query_timestamp" is ISO-8601.

    Never raises; never guesses a timezone (zone-less provider stamps → "")."""
    if family == "lb":
        try:
            f = shlex.split(line)
        except ValueError:
            return ""
        return _parse_provider_iso(f[1]) if len(f) >= 2 else ""
    if family == "waf":
        return _epoch_to_iso(_json_field(line, "timestamp"), ms=True)
    if family == "flow":
        parts = line.split()
        if len(parts) >= 12 and parts[0].isdigit():
            return _epoch_to_iso(parts[10])
        return ""
    if family == "dns":
        return _parse_provider_iso(_json_field(line, "query_timestamp"))
    return ""


def cloud_log_doc(
    out_name: str,
    line: str,
    tenant: str,
    *,
    account: str = "",
    region: str = "",
    timestamp: str = "",
) -> dict | None:
    """One raw cloud log line → a tagged `netops.cloudlogs` document, or None when
    the line is blank or the lane is unrecognized (family/provider never guessed).

    `tenant` is REQUIRED and stamped as tenant_id — cloud logs are tenant-scoped
    (§3a); the caller resolves it at the source and must never leave it empty.
    `timestamp` is the INGEST-time stamp (RFC3339), supplied by the caller so
    this stays pure. The doc's `timestamp` (what the router indexes and the UI
    sorts/filters on) is the record's OWN event time parsed from the line
    (event_ts_for) — batch-delivered cloud logs arrive minutes late, so ingest
    time would misplace them on the timeline. The ingest stamp is kept as
    `ingested_at` (and is the `timestamp` fallback when the line carries no
    parseable event time), so origin-vs-receive skew stays observable."""
    if not (line and line.strip()):
        return None
    if not tenant:
        return None
    family = family_for(out_name)
    if not family:
        return None
    provider = provider_for(out_name)
    doc: dict = {
        "tenant_id": tenant,
        "cloud_family": family,
        "cloud_provider": provider,
        "resource_id": resource_id_for(family, line),
        "message": line,
        "source_type": "cloud",
        "signal": "cloud",
    }
    if account:
        doc["account"] = account
    if region:
        doc["region"] = region
    event_ts = event_ts_for(family, line)
    if event_ts:
        doc["timestamp"] = event_ts
    elif timestamp:
        doc["timestamp"] = timestamp
    if timestamp:
        doc["ingested_at"] = timestamp
    # Clock-skew flagging (S5/R5): stamp clock_skew_s only when the record's
    # own event time and the ingest stamp disagree beyond the family tolerance
    # (batch delivery lag inside the envelope is legitimate, not a finding).
    skew = clock_skew_s(family, event_ts, timestamp)
    if skew is not None:
        doc["clock_skew_s"] = skew
    return doc


def clock_skew_s(family: str, event_ts: str, ingested_at: str) -> float | None:
    """Signed skew (event − ingest, seconds) when it exceeds the family
    tolerance; None when in-tolerance or either stamp is missing/unparseable.
    Positive = the record claims a FUTURE event time (a wrong source clock);
    negative = delivery/backfill lag beyond the family's expected envelope."""
    if not event_ts or not ingested_at:
        return None
    try:
        ev = _dt.datetime.fromisoformat(event_ts.replace("Z", "+00:00"))
        ing = _dt.datetime.fromisoformat(ingested_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    if ev.tzinfo is None or ing.tzinfo is None:
        return None
    skew = (ev - ing).total_seconds()
    tolerance = FAMILY_SKEW_TOLERANCE_S.get(family, DEFAULT_SKEW_TOLERANCE_S)
    return skew if abs(skew) > tolerance else None


def change_log_doc(
    tenant: str,
    *,
    resource_id: str,
    event_name: str,
    provider: str = "aws",
    account: str = "",
    region: str = "",
    actor: str = "",
    event_source: str = "",
    timestamp: str = "",
) -> dict | None:
    """A control-plane change (CloudTrail/Activity/Audit event) → a tagged
    `netops.cloudlogs` document in the `change` family. Mirrors the cloud_change
    SIGNAL so the Change lane shows the raw change record alongside the rollup.
    None when tenant/resource are missing (never guessed)."""
    if not tenant or not (resource_id or event_name):
        return None
    msg = event_name
    if actor:
        msg = f"{event_name} by {actor}"
    doc: dict = {
        "tenant_id": tenant,
        "cloud_family": "change",
        "cloud_provider": provider,
        "resource_id": resource_id or event_name,
        "message": msg,
        "event_name": event_name,
        "source_type": "cloud",
        "signal": "cloud",
    }
    if actor:
        doc["actor"] = actor
    if event_source:
        doc["event_source"] = event_source
    if account:
        doc["account"] = account
    if region:
        doc["region"] = region
    if timestamp:
        doc["timestamp"] = timestamp
    return doc
