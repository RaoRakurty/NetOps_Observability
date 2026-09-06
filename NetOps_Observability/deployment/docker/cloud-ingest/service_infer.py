# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Built-in service mapping — infer a BusinessService for a cloud resource that
carries NO app tag, from the RELATIONSHIPS the read-only inventory already sees.

The live problem this fixes: the lab's Azure VMs come back with empty tags ``{}``
and the monitoring service principal is READ-ONLY (Reader + Monitoring Reader),
so it CANNOT write tags. Requiring tags for attribution is therefore wrong. This
module infers a service name WITHOUT write access and WITHOUT mandatory tags,
from three signals the Reader role already exposes:

  1. Resource-group naming convention — resources in one RG usually share a
     service; the RG name usually NAMES it (``rg-payments-prod`` → ``payments``).
  2. Structural association — VMs sharing a SUBNET (or behind one LB) are the
     same tier of the same service. Structure CORROBORATES the name guess.
  3. Hostname convention — ``web01``/``web02`` collapse to a ``web`` role prefix.

Honesty is the contract (CLAUDE.md: never fabricate certainty). Every inference
carries a CONFIDENCE and a human BASIS; where the signal is weak we emit a low
confidence (or none) and let the report fall back to a generic descriptor —
never a forced name. Confidence maps to the Go ladder (cloud/model.go):

    "strong"    naming convention + a corroborating structural signal
    "suspected" a resource-group naming convention alone
    "weak"      only a lone hostname-prefix guess
    "none"      no usable signal — stays unknown (generic descriptor in reports)

A resource that ALREADY has an app tag is never touched here (a tag is
authoritative; inference is the fallback). Pure + stdlib-only: unit-tested with
sample resource graphs, no I/O.
"""
from __future__ import annotations

import re

# App-tag keys that make a resource already-attributed — inference is skipped for
# those (kept in sync with discover.py / azure.py APP_TAG_KEYS and cloud/resolve.go).
_APP_TAG_KEYS = ("app_id", "app", "application", "app_name", "app-name",
                 "service", "workload", "component")

# Confidence rungs, ordered (must mirror cloud/model.go Confidence).
STRONG, SUSPECTED, WEAK, NONE = "strong", "suspected", "weak", "none"

# Resource-group affixes that are pure convention, not the service name.
_RG_PREFIXES = ("rg-", "rg_", "resourcegroup-", "resource-group-")
_RG_SUFFIXES = ("-rg", "_rg")
# Environment/stage tokens that are NOT the service identity — stripped from both
# resource-group and hostname candidates so ``rg-payments-prod`` == ``payments``.
_ENV_TOKENS = frozenset((
    "prod", "production", "dev", "development", "stage", "staging", "test",
    "testing", "qa", "uat", "sandbox", "sbx", "preprod", "nonprod", "int",
    "integration", "canary", "eastus", "westus", "westus2", "eastus2",
    "centralus", "network", "compute", "infra", "shared",
))
# A candidate this generic is no better than "unknown".
_GENERIC = frozenset((
    "default", "vm", "vms", "server", "servers", "host", "hosts", "node",
    "nodes", "app", "apps", "instance", "instances", "main", "core", "",
))
# Trailing instance ordinals: web01, web-2, db_03, node-a.
_INSTANCE_SUFFIX = re.compile(r"[-_]?(?:[0-9]{1,3}|[a-f])$")


def resource_group_of(arm_id: str) -> str:
    """Resource group from an Azure ARM id (case-insensitive segment match).
    Returns "" when the id carries no resourceGroups segment."""
    parts = str(arm_id or "").split("/")
    for i, seg in enumerate(parts[:-1]):
        if seg.lower() == "resourcegroups":
            return parts[i + 1]
    return ""


def _tokens(s: str) -> list[str]:
    return [t for t in re.split(r"[-_./ ]+", str(s or "").lower().strip()) if t]


def _strip_affixes(name: str) -> str:
    """Reduce a resource-group name to its service token(s): drop rg- affixes and
    env/region tokens. ``rg-payments-prod`` → ``payments``; ``net-shared`` → ""."""
    low = str(name or "").lower().strip()
    for p in _RG_PREFIXES:
        if low.startswith(p):
            low = low[len(p):]
            break
    for suf in _RG_SUFFIXES:
        if low.endswith(suf):
            low = low[: -len(suf)]
            break
    keep = [t for t in _tokens(low) if t not in _ENV_TOKENS]
    return "-".join(keep)


def service_name_from_rg(rg: str) -> str:
    """A service name inferred from a resource-group name, or "" when the RG name
    is pure convention/too generic to carry identity."""
    cand = _strip_affixes(rg)
    if cand in _GENERIC or not cand:
        return ""
    return cand


def hostname_role(name: str) -> str:
    """Collapse an instance hostname to its role prefix: ``web01`` → ``web``,
    ``payments-api-2`` → ``payments-api``. "" when nothing but an ordinal."""
    low = str(name or "").lower().strip()
    # strip a single trailing ordinal (not repeatedly — ``db2`` → ``db``, once).
    stripped = _INSTANCE_SUFFIX.sub("", low, count=1)
    role = "-".join(t for t in _tokens(stripped) if t not in _ENV_TOKENS)
    if role in _GENERIC:
        return ""
    return role


def _common_prefix_role(names: list[str]) -> str:
    """The shared role prefix across ≥2 hostnames, or "" if they disagree."""
    roles = {hostname_role(n) for n in names if n}
    roles.discard("")
    if len(roles) == 1:
        return next(iter(roles))
    return ""


def infer_services(resources: list[dict]) -> dict[str, dict]:
    """Infer a BusinessService per resource that lacks an app tag.

    Each resource is a dict with at least ``resource_id`` (ARM path) and
    optionally ``resource_name``, ``subnet_ids`` (list), ``tags`` (dict).
    Returns ``{resource_id: {"service": name, "confidence": rung, "basis": str}}``
    for every resource that got a non-``none`` inference. Resources with an app
    tag, or with no usable signal, are omitted (caller keeps them unknown).
    """
    # Group by resource group; carry only tag-less resources into inference.
    groups: dict[str, list[dict]] = {}
    for r in resources:
        tags = r.get("tags") or {}
        if any(k in tags for k in _APP_TAG_KEYS):
            continue  # already attributed by a tag — never overridden by a guess
        rg = resource_group_of(r.get("resource_id", ""))
        groups.setdefault(rg, []).append(r)

    out: dict[str, dict] = {}
    for rg, members in groups.items():
        rg_name = service_name_from_rg(rg)
        names = [str(m.get("resource_name", "")) for m in members]
        subnets_per: list[set[str]] = [set(m.get("subnet_ids") or []) for m in members]
        shared_subnet: set[str] = set.intersection(*subnets_per) if subnets_per else set()
        cohort_role = _common_prefix_role(names) if len(members) >= 2 else ""

        for m in members:
            rid = m.get("resource_id", "")
            if not rid:
                continue
            role = hostname_role(m.get("resource_name", ""))
            signals: list[str] = []
            name, conf = "", NONE

            if rg_name:
                name = rg_name
                conf = SUSPECTED
                signals.append(f"resource-group name '{rg}'")
                # Structural corroboration promotes the RG guess to strong.
                if len(members) >= 2 and shared_subnet:
                    conf = STRONG
                    sn = sorted(shared_subnet)[0]
                    signals.append(f"{len(members)} resources share subnet '{_short(sn)}'")
                elif len(members) >= 2 and cohort_role:
                    conf = STRONG
                    signals.append(f"{len(members)} resources share name prefix '{cohort_role}'")
            elif len(members) >= 2 and shared_subnet and cohort_role:
                # No RG signal, but structure alone is coherent: a real tier.
                name = cohort_role
                conf = SUSPECTED
                sn = sorted(shared_subnet)[0]
                signals.append(f"{len(members)} resources share subnet '{_short(sn)}' and name prefix '{cohort_role}'")
            elif role:
                # Lone hostname guess — weakest honest signal.
                name = role
                conf = WEAK
                signals.append(f"hostname role '{role}'")

            if name and conf != NONE:
                out[rid] = {"service": name, "confidence": conf,
                            "basis": "; ".join(signals)}
    return out


def _short(arm_or_id: str) -> str:
    """Last path segment of an id, for readable basis strings."""
    return str(arm_or_id or "").rstrip("/").split("/")[-1] or str(arm_or_id or "")
