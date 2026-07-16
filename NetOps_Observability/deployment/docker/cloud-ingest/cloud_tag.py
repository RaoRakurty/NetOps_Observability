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
    `timestamp` is the ingest-time stamp the router sorts/filters on (RFC3339);
    the caller supplies it so this stays pure."""
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
    if timestamp:
        doc["timestamp"] = timestamp
    return doc


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
