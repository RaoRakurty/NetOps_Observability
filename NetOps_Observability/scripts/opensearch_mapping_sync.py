#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix
"""Pure helpers for bootstrap-opensearch.sh's current-index mapping sync.

WHY (tracker 387, 2026-11-10): every lane's template is `dynamic: false`, so a
field added to index-templates.json is stored in `_source` but NOT indexed until
the next daily index is created from the new template. After a deploy, syslog
`title` / `correlation_key` were on every new record yet unsearchable and
ungroupable until midnight UTC. The bootstrap now adds the template's NEW fields
to each lane's current index.

Only fields the index does not have yet are sent. An existing field is never
re-typed: OpenSearch refuses a type change on a live index, and a deliberate
type change in the template is legitimate. It takes effect at the next index, so
it is reported, not attempted. That makes every request this sync sends
additive. One that is refused is a real error.

Subcommands (all I/O is stdin/stdout, so the shell owns every network call):
  targets              stdin: GET <patterns>/_settings/index.creation_date
                       stdout: the newest index of each series, one per line
  missing TEMPLATES N  stdin: GET <index>/_mapping (one index)
                       stdout: a PUT _mapping body with only the new fields,
                       or nothing when the index already has them all
                       stderr: one line per field whose type differs
Exit 2 on input that is not what OpenSearch returns (an error body, HTML, an
empty answer): the caller must not mistake "could not read" for "nothing to do".
"""
from __future__ import annotations

import json
import re
import sys
from typing import Any

# A daily (or rollover) suffix: netops-syslog-untagged-2026.11.10 → series
# netops-syslog-untagged. An index without one is its own series.
_SUFFIX = re.compile(r"-(?:\d{4}\.\d{2}\.\d{2}|\d{4}-\d{2}-\d{2}|\d{6})$")


def _die(msg: str) -> None:
    print(f"opensearch_mapping_sync: {msg}", file=sys.stderr)
    sys.exit(2)


def _load(raw: str) -> dict[str, Any]:
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        _die(f"not JSON ({exc.msg}): {raw[:120]!r}")
    if not isinstance(doc, dict):
        _die(f"expected a JSON object, got {type(doc).__name__}")
    if "error" in doc:
        _die(f"OpenSearch returned an error: {json.dumps(doc['error'])[:300]}")
    return doc


def series(index: str) -> str:
    """The series an index belongs to: its name without the date suffix."""
    return _SUFFIX.sub("", index)


def targets(settings: dict[str, Any]) -> list[str]:
    """The newest index (by creation date) of each series, sorted by name."""
    newest: dict[str, tuple[int, str]] = {}
    for idx, body in settings.items():
        if idx.startswith("."):
            continue  # system indices are never a lane's write index
        try:
            created = int(body["settings"]["index"]["creation_date"])
        except (KeyError, TypeError, ValueError):
            _die(f"index {idx!r} has no readable creation_date")
        key = series(idx)
        if key not in newest or (created, idx) > newest[key]:
            newest[key] = (created, idx)
    return sorted(v[1] for v in newest.values())


def missing(want: dict[str, Any], have: dict[str, Any], path: str = "") -> tuple[dict[str, Any], list[str]]:
    """The subset of `want` (template properties) absent from `have` (live
    properties), recursing into object fields. Returns (additions, conflicts):
    a conflict is an existing field whose declared type differs."""
    add: dict[str, Any] = {}
    conflicts: list[str] = []
    for name, spec in want.items():
        full = f"{path}{name}"
        cur = have.get(name)
        if cur is None:
            add[name] = spec
            continue
        if not isinstance(spec, dict) or not isinstance(cur, dict):
            continue
        if "properties" in spec and "properties" in cur:
            sub, sub_conf = missing(spec["properties"], cur["properties"], full + ".")
            if sub:
                add[name] = {"properties": sub}
            conflicts.extend(sub_conf)
            continue
        wt = spec.get("type", "object" if "properties" in spec else None)
        ht = cur.get("type", "object" if "properties" in cur else None)
        if wt != ht:
            conflicts.append(f"{full}: template {wt}, live {ht}")
    return add, conflicts


def template_properties(templates_path: str, name: str) -> dict[str, Any]:
    with open(templates_path, encoding="utf-8") as fh:
        doc = json.load(fh)
    try:
        tpl = doc["templates"][name]
    except KeyError:
        _die(f"template {name!r} is not in {templates_path}")
    props = tpl.get("template", {}).get("mappings", {}).get("properties", {})
    if not isinstance(props, dict):
        _die(f"template {name!r}: mappings.properties is not an object")
    return props


def main(argv: list[str]) -> int:
    if len(argv) >= 1 and argv[0] == "targets":
        for idx in targets(_load(sys.stdin.read())):
            print(idx)
        return 0
    if len(argv) == 3 and argv[0] == "missing":
        want = template_properties(argv[1], argv[2])
        live = _load(sys.stdin.read())
        if len(live) != 1:
            _die(f"expected the mapping of exactly one index, got {len(live)}")
        (body,) = live.values()
        have = (body or {}).get("mappings", {}).get("properties", {}) or {}
        add, conflicts = missing(want, have)
        for c in conflicts:
            print(f"type differs (applies from the next index): {c}", file=sys.stderr)
        if add:
            print(json.dumps({"properties": add}, sort_keys=True))
        return 0
    print(__doc__, file=sys.stderr)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
