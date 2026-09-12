# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Shared vocabulary + helpers for the network-component inventory lanes
(cloud-network-overview P0 — design doc §5).

Every provider's component collector (aws_components / azure_components /
gcp_components) emits ONE resource row per component through component_row(),
so the schema — provider-neutral, consumed by src/backend/cloud/model.go — is
enforced in exactly one place:

    region · zone · vpc_id · subnet_ids       WHERE the component lives
    resource_type · resource_id · name        WHAT it is
    status · status_reason                    the provider's REAL signal
    key_metric_name/value/unit                the type's ONE headline number
    attached_vpc_ids · attached_regions       seam endpoints (design §4a)
    attrs                                     provider-native facts (never guesses)

STATUS HONESTY (binding platform rule): a status is only ever derived from a
signal the provider actually returned (target health, tunnel state,
provisioning/operational state). No signal → NOT_MEASURED. Unknown ≠ green;
nothing here may default to healthy.
"""
from __future__ import annotations

import random
import time
import urllib.error

# ── canonical component status vocabulary (mirrored by cloud/kinds.go) ───────
HEALTHY = "healthy"
DEGRADED = "degraded"
DOWN = "down"
NOT_MEASURED = "not_measured"

_VALID_STATUS = {HEALTHY, DEGRADED, DOWN, NOT_MEASURED}

# The same app-tag keys the instance lanes honour (discover.py / azure.py /
# gcp.py) — a tagged LB is confirmed-attributed exactly like a tagged VM.
APP_TAG_KEYS = ("app_id", "app", "application", "app_name", "app-name",
                "service", "workload")

# Bounded reads: per-family row cap and page-loop cap. Inventory, not a dump —
# past the cap the family is truncated (recorded in attrs), never unbounded.
FAMILY_CAP = 500
PAGE_CAP = 20


def component_row(*, region: str, resource_id: str, resource_type: str,
                  resource_name: str = "", arn_or_uri: str = "", zone: str = "",
                  vpc_id: str = "", subnet_ids: list | None = None,
                  status: str = NOT_MEASURED, status_reason: str = "",
                  key_metric: tuple | None = None,
                  attached_vpc_ids: list | None = None,
                  attached_regions: list | None = None,
                  private_ips: list | None = None, public_ips: list | None = None,
                  tags: dict | None = None, attrs: dict | None = None) -> dict:
    """One inventory row for a network component. Enforces the status
    vocabulary (anything unrecognised is demoted to NOT_MEASURED — an invalid
    status must never read as a state we didn't measure) and emits the
    key-metric fields only when a metric was actually obtained (absence stays
    absence, never zero)."""
    if status not in _VALID_STATUS:
        status, status_reason = NOT_MEASURED, status_reason or f"unrecognised provider state '{status}'"
    tags = tags or {}
    row = {
        "region": region,
        "resource_id": resource_id,
        "resource_arn_or_uri": arn_or_uri or resource_id,
        "resource_type": resource_type,
        "resource_name": resource_name or resource_id,
        "status": status,
        "status_reason": status_reason,
        "tags": tags,
        "owner": tags.get("owner", ""),
        "env": tags.get("environment", tags.get("env", "")),
        "source": "cloud_api",
        "confidence": "confirmed" if any(k in tags for k in APP_TAG_KEYS) else "strong",
    }
    if zone:
        row["zone"] = zone
    if vpc_id:
        row["vpc_id"] = vpc_id
    if subnet_ids:
        row["subnet_ids"] = [s for s in subnet_ids if s]
    if key_metric is not None:
        name, value, unit = key_metric
        row["key_metric_name"] = name
        row["key_metric_value"] = float(value)
        row["key_metric_unit"] = unit
    if attached_vpc_ids:
        row["attached_vpc_ids"] = sorted({v for v in attached_vpc_ids if v})
    if attached_regions:
        row["attached_regions"] = sorted({r for r in attached_regions if r})
    if private_ips:
        row["private_ips"] = [ip for ip in private_ips if ip]
    if public_ips:
        row["public_ips"] = [ip for ip in public_ips if ip]
    if attrs:
        row["attrs"] = {k: str(v) for k, v in attrs.items() if v not in ("", None)}
    return row


def retrying(get_json, attempts: int = 3, base_s: float = 0.5,
             sleep=time.sleep):
    """Wrap a REST getter with bounded retry + exponential backoff + jitter
    (CLAUDE.md §9). Retries transient failures only — URLError and HTTP
    429/5xx; a 4xx (auth/permission) is a real answer and re-raises at once."""
    def get(url: str):
        last: Exception | None = None
        for i in range(attempts):
            try:
                return get_json(url)
            except urllib.error.HTTPError as exc:
                if exc.code not in (429, 500, 502, 503, 504):
                    raise
                last = exc
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last = exc
            if i < attempts - 1:
                sleep(base_s * (2 ** i) + random.uniform(0, base_s))  # noqa: S311 - jitter, not crypto
        raise last  # type: ignore[misc]
    return get


def truncate(rows: list, family: str, cap: int = FAMILY_CAP) -> list:
    """Apply the per-family row cap; a truncated family says so on every kept
    row (attrs.inventory_truncated) instead of silently missing resources."""
    if len(rows) <= cap:
        return rows
    kept = rows[:cap]
    for r in kept:
        r.setdefault("attrs", {})["inventory_truncated"] = f"{family}: {len(rows) - cap} over cap"
    return kept
