#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Normalization engine — applies the normalization catalog to a raw gNMI event
and yields canonical single-contract series. Code-owned and unit-tested (this is
the "not buried in gnmic YAML" part): the gnmic processor chain is a derived
runtime applier of the SAME rules expressed here as data.

A raw gnmic event (``--format event``) looks like:
    {"tags": {"source": "1.2.3.4:6030", "interface_name": "Ethernet1", ...},
     "values": {"/interfaces/interface/state/oper-status": "UP"}}

normalize_event(ev, vendor, transport="gnmi") -> list[CanonicalSeries], where
each series is {"name", "labels": {...}, "value": <int|float>}.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))


@dataclass
class Catalog:
    families: dict
    drop_tags: set
    alias_to_canonical: dict  # raw tag name -> canonical entity key
    _match: list = field(default_factory=list)  # (compiled_regex, family_name)

    def family_for_path(self, path: str):
        for rx, fam in self._match:
            if rx.search(path):
                return fam
        return None


def load_catalog(path_norm: str | None = None, path_ident: str | None = None) -> Catalog:
    norm = yaml.safe_load(open(path_norm or os.path.join(HERE, "normalization.yaml")))
    ident = yaml.safe_load(open(path_ident or os.path.join(HERE, "identity.yaml")))
    families = norm["families"]
    drop = set(norm.get("drop_tags", []))
    alias = {}
    for ent in ident["entities"].values():
        ck = ent["canonical_key"]
        alias[ck] = ck
        for a in ent.get("aliases", []) or []:
            alias[a] = ck
    cat = Catalog(families=families, drop_tags=drop, alias_to_canonical=alias)
    for fam_name, fam in families.items():
        for pat in fam.get("match", []) or []:
            cat._match.append((re.compile(pat), fam_name))
    return cat


def _enum_map(fam) -> dict:
    """raw-token (lowercased) -> canonical int-string."""
    out = {}
    for canon, raws in (fam.get("enum") or {}).items():
        for r in raws:
            out[str(r).lower()] = canon
    return out


def normalize_event(ev: dict, vendor: str, transport: str = "gnmi",
                    cat: Catalog | None = None) -> list[dict]:
    """Return the canonical series produced by one raw event (may be 0..N)."""
    cat = cat or load_catalog()
    tags = ev.get("tags", {}) or {}
    source = tags.get("source", "")
    out = []
    for path, raw_val in (ev.get("values", {}) or {}).items():
        fam_name = cat.family_for_path(path)
        if fam_name is None:
            continue  # fail-closed: unmapped paths never reach the canonical namespace
        fam = cat.families[fam_name]

        # value: enum -> IF-MIB/BGP4-MIB int; gauge/counter -> numeric
        if fam["kind"] == "state_enum":
            em = _enum_map(fam)
            mapped = em.get(str(raw_val).strip().lower())
            if mapped is None:
                continue  # unknown enum token — drop rather than emit a bogus value
            value: float = int(mapped)
        else:
            try:
                value = float(raw_val)
            except (TypeError, ValueError):
                continue

        # labels: reconcile raw tag names -> canonical entity keys (source->device,
        # interface_name->ifName, neighbor_*-address->peer, network-instance_name->vrf),
        # drop plumbing tags, then stamp vendor + transport.
        allowed = set(fam["labels"])
        labels: dict[str, str] = {}
        for tname, tval in tags.items():
            if tname in cat.drop_tags:
                continue
            canon = cat.alias_to_canonical.get(tname)
            if canon and canon in allowed:
                labels[canon] = tval
        if "vendor" in allowed:
            labels["vendor"] = vendor
        if "transport" in allowed:
            labels["transport"] = transport

        out.append({"name": fam_name, "labels": labels, "value": value})
    return out
