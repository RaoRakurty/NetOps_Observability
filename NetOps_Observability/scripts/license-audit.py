#!/usr/bin/env python3
"""license-audit.py — third-party licence inventory + CI gate for Correlix.

WHY THIS EXISTS
---------------
`dist/*/LICENSES.md` was hand-maintained. Hand-maintained licence lists rot:
the 2026-09-03 audit found the bundle notice listed 14 container images and
ZERO of the libraries actually linked into our own artifacts — including
elkjs (EPL-2.0), four OFL-1.1 font families and certifi (MPL-2.0), all three
of which carry real notice obligations. This script makes the inventory
DERIVED, not remembered, and turns "a new dependency arrived with a licence
nobody reviewed" into a build failure.

WHAT IT DOES
------------
  --check    (default) rebuild the inventory from the tree and gate it.
             Exit 0 = clean, 1 = violation, 2 = the audit itself could not run.
  --write    rebuild the inventory and refresh the checked-in facts file
             (scripts/license-data.json) from whatever local metadata is
             available (vendor/, node_modules/, a running pip environment).
  --report   print the full inventory as a Markdown table (stdout).
  --notices  regenerate docs/THIRD_PARTY_LICENSES.md, grouped by the
             distribution unit the component actually ships in.

DISCOVERY SOURCES (all checked in, so --check works offline and in CI)
  Go        src/backend/vendor/modules.txt      + vendor/<mod>/LICENSE text
  npm       */package-lock.json                 + node_modules/*/package.json
  Python    src/correlation/requirements.txt, the cloud-ingest pip line
  images    deployment/docker/*.yml `image:`    + Dockerfile `FROM`
  vendored  in-tree third-party content declared in license-data.json
            (MIB modules, icon path data, brand marks) — existence-checked,
            so deleting or relocating one surfaces here instead of silently
            dropping its attribution.
Anything a source cannot resolve offline is looked up in license-data.json,
which is human-reviewed and checked in. A component resolvable from NO source
is a HARD FAILURE — an unreviewed dependency is exactly what this gate is for.

THE GATE (see CLAUDE.md §6 — zero trust on dependencies)
  PERMISSIVE          pass anywhere.
  NOTICE_REQUIRED     pass, but the component MUST appear in the generated
                      notices file (OFL fonts, CC-BY data).
  REVIEW_REQUIRED     weak/file-level copyleft (MPL-2.0, EPL-2.0, LGPL). Pass
                      ONLY with an explicit, reasoned exception entry.
  SEPARATE_PROCESS    strong copyleft (GPL, AGPL). Pass ONLY with an exception
                      AND usage == "separate-container". Linking one of these
                      into our own binary is never allowed.
  FORBIDDEN           source-available / non-OSS (SSPL, BUSL, Elastic, RSAL,
                      Commons Clause, CC-BY-NC). Always fails, everywhere.

§16.1 applies: this script never swallows an error. A source it cannot parse
is a failure with the reason named, not a silently shorter inventory.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Iterable

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
DATA_FILE = os.path.join(ROOT, "scripts", "license-data.json")
NOTICES_FILE = os.path.join(ROOT, "docs", "THIRD_PARTY_LICENSES.md")

# ── licence classification ───────────────────────────────────────────────────
# SPDX ids we accept with no obligation beyond keeping the notices file honest.
PERMISSIVE = {
    "0BSD", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "BlueOak-1.0.0",
    "CC0-1.0", "ISC", "MIT", "MIT-0", "PSF-2.0", "Python-2.0", "PostgreSQL",
    "Unlicense", "WTFPL", "Zlib", "curl",
}
# Permissive, but redistribution requires shipping the notice/licence text.
NOTICE_REQUIRED = {"OFL-1.1", "CC-BY-4.0", "CC-BY-3.0"}
# File-level / weak copyleft: fine unmodified, obligations on modification.
REVIEW_REQUIRED = {
    "EPL-1.0", "EPL-2.0", "MPL-2.0", "MPL-1.1",
    "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later",
    "CDDL-1.0", "CDDL-1.1",
}
# Strong copyleft: separate process / separate container only.
SEPARATE_PROCESS = {
    "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later",
    "AGPL-3.0-only", "AGPL-3.0-or-later",
}
# Never acceptable in anything we distribute.
FORBIDDEN = {
    "SSPL-1.0", "BUSL-1.1", "BSL-1.1", "Elastic-2.0", "ELv2", "RSAL-2.0",
    "Commons-Clause", "CC-BY-NC-4.0", "CC-BY-NC-SA-4.0", "Proprietary",
    "UNKNOWN", "UNDECLARED",
}

CLASSES = [
    ("PERMISSIVE", PERMISSIVE),
    ("NOTICE_REQUIRED", NOTICE_REQUIRED),
    ("REVIEW_REQUIRED", REVIEW_REQUIRED),
    ("SEPARATE_PROCESS", SEPARATE_PROCESS),
    ("FORBIDDEN", FORBIDDEN),
]

# Normalisation for the free-text licence strings npm/pip metadata emits.
SPDX_ALIASES = {
    "apache license": "Apache-2.0", "apache 2": "Apache-2.0",
    "apache 2.0": "Apache-2.0", "apache-2": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "mit license": "MIT", "the mit license": "MIT", "mit/x11": "MIT",
    "bsd": "BSD-3-Clause", "bsd license": "BSD-3-Clause",
    "new bsd license": "BSD-3-Clause", "bsd-3": "BSD-3-Clause",
    "simplified bsd": "BSD-2-Clause",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0", "mpl 2.0": "MPL-2.0",
    "eclipse public license - v 2.0": "EPL-2.0", "epl 2.0": "EPL-2.0",
    "gpl-2.0": "GPL-2.0-or-later", "gpl-3.0": "GPL-3.0-or-later",
    "gplv2": "GPL-2.0-or-later", "gplv3": "GPL-3.0-or-later",
    "agpl-3.0": "AGPL-3.0-only", "lgpl-2.1": "LGPL-2.1-or-later",
    "python software foundation license": "PSF-2.0", "psf": "PSF-2.0",
    "sil open font license 1.1": "OFL-1.1", "ofl": "OFL-1.1",
    "postgresql license": "PostgreSQL", "the postgresql license": "PostgreSQL",
    "isc license": "ISC", "unlicense": "Unlicense",
}

# Fingerprints for identifying a vendored LICENSE file with no SPDX header.
# Matched against the licence text with all runs of whitespace collapsed to a
# single space, so upstream line wrapping cannot defeat the match.
LICENSE_TEXT_FINGERPRINTS: list[tuple[str, str]] = [
    ("Permission is hereby granted, free of charge", "MIT"),
    ("Licensed under the Apache License, Version 2.0", "Apache-2.0"),
    ("Eclipse Public License - v 2.0", "EPL-2.0"),
    ("Mozilla Public License Version 2.0", "MPL-2.0"),
    ("GNU AFFERO GENERAL PUBLIC LICENSE", "AGPL-3.0-only"),
    ("GNU LESSER GENERAL PUBLIC LICENSE", "LGPL-2.1-or-later"),
    ("GNU GENERAL PUBLIC LICENSE", "GPL-2.0-or-later"),
    ("SIL OPEN FONT LICENSE", "OFL-1.1"),
    ("Permission to use, copy, modify, and/or distribute this software", "ISC"),
]


class AuditError(Exception):
    """The audit could not be performed (missing/unparsable source). Exit 2."""


def read_text(path: str, *, errors: str = "strict") -> str:
    """Read a discovery source. An unreadable one aborts the audit by name —
    never degrades it into a quietly shorter inventory (scripts/CLAUDE.md §16.1)."""
    try:
        with open(path, encoding="utf-8", errors=errors) as fh:
            return fh.read()
    except OSError as exc:
        raise AuditError(f"cannot read {os.path.relpath(path, ROOT)}: {exc}") from exc


def read_json(path: str) -> dict:
    """Read a JSON discovery source (lockfile, facts file)."""
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise AuditError(f"cannot read {os.path.relpath(path, ROOT)}: {exc}") from exc


# ── component model ──────────────────────────────────────────────────────────
class Component:
    __slots__ = (
        "ecosystem",
        "key",
        "license",
        "name",
        "note",
        "source",
        "unit",
        "usage",
        "version",
    )

    def __init__(self, key: str, name: str, version: str, license: str,
                 ecosystem: str, usage: str, unit: str, source: str,
                 note: str = "") -> None:
        self.key = key
        self.name = name
        self.version = version
        self.license = license
        self.ecosystem = ecosystem
        self.usage = usage        # linked | bundled-runtime | separate-container | build-only | data
        self.unit = unit          # distribution unit it ships in
        self.source = source      # where the licence fact came from
        self.note = note

    @property
    def klass(self) -> str:
        return classify(self.license)

    def as_dict(self) -> dict:
        return {
            "name": self.name, "version": self.version, "license": self.license,
            "ecosystem": self.ecosystem, "usage": self.usage, "unit": self.unit,
            "class": self.klass, "source": self.source, "note": self.note,
        }


def classify(lic: str) -> str:
    """Map an SPDX id (possibly a disjunction) to a gate class.

    A disjunction ("MIT OR CC0-1.0", "BSD-3-Clause OR GPL-2.0") is resolved to
    its MOST PERMISSIVE branch: a dual-licensed component may be taken under
    whichever branch we choose, and we always choose the permissive one.
    """
    lic = (lic or "").strip()
    if not lic:
        return "FORBIDDEN"
    branches = [b.strip(" ()") for b in re.split(r"\bOR\b", lic)] if " OR " in lic else [lic.strip("()")]
    best = "FORBIDDEN"
    order = {"PERMISSIVE": 0, "NOTICE_REQUIRED": 1, "REVIEW_REQUIRED": 2,
             "SEPARATE_PROCESS": 3, "FORBIDDEN": 4}
    for b in branches:
        found = "FORBIDDEN"
        for cname, cset in CLASSES:
            if b in cset:
                found = cname
                break
        if order[found] < order[best]:
            best = found
    return best


def normalize_spdx(raw: str | None) -> str:
    """Best-effort free-text → SPDX. Never guesses into a permissive id."""
    if raw is None:
        return "UNKNOWN"
    if isinstance(raw, dict):
        raw = raw.get("type") or ""
    if isinstance(raw, list):
        parts = [p.get("type") if isinstance(p, dict) else str(p) for p in raw]
        raw = " OR ".join(p for p in parts if p)
    raw = str(raw).strip()
    if not raw:
        return "UNKNOWN"
    # Already a known id (or a disjunction of them)?
    known = set().union(*(c[1] for c in CLASSES))
    if raw in known:
        return raw
    if " OR " in raw and all(b.strip(" ()") in known for b in raw.split(" OR ")):
        return raw
    alias = SPDX_ALIASES.get(raw.lower())
    if alias:
        return alias
    # "Apache-2.0 OR BSD-2-Clause" style with odd spacing / SPDX suffixes.
    stripped = raw.replace("-only", "").replace("-or-later", "")
    if stripped in known:
        return stripped
    return raw if raw else "UNKNOWN"


BSD_REDIST = ("Redistribution and use in source and binary forms, with or "
              "without modification, are permitted provided that the following "
              "conditions are")
BSD_3RD_CLAUSE = "may be used to endorse or promote products derived from this software"


def identify_license_text(text: str) -> str:
    """Identify a licence from its text. Whitespace-insensitive: upstream files
    wrap at different columns, and a wrap must not turn a known licence into an
    UNKNOWN that fails the build for no reason."""
    flat = " ".join(text.split())
    for needle, spdx in LICENSE_TEXT_FINGERPRINTS:
        if " ".join(needle.split()) in flat:
            return spdx
    if BSD_REDIST in flat:
        # The 3rd ("no endorsement") clause is what separates BSD-3 from BSD-2.
        return "BSD-3-Clause" if BSD_3RD_CLAUSE in flat else "BSD-2-Clause"
    return "UNKNOWN"


# ── checked-in facts (human-reviewed) ────────────────────────────────────────
def load_data() -> dict:
    if not os.path.isfile(DATA_FILE):
        raise AuditError(
            f"missing {os.path.relpath(DATA_FILE, ROOT)} — run "
            f"`python3 scripts/license-audit.py --write` and review the result")
    return read_json(DATA_FILE)


# ── source 1: Go vendored modules ────────────────────────────────────────────
def collect_go(data: dict) -> list[Component]:
    mods_txt = os.path.join(ROOT, "src", "backend", "vendor", "modules.txt")
    if not os.path.isfile(mods_txt):
        raise AuditError("src/backend/vendor/modules.txt not found — the backend "
                         "must stay vendored (CLAUDE.md §6 offline-buildable gate)")
    lines = read_text(mods_txt).splitlines()

    out: list[Component] = []
    facts = data.get("go", {})
    for line in lines:
        m = re.match(r"^# (\S+) (\S+)$", line)
        if not m:
            continue
        mod, ver = m.group(1), m.group(2)
        vdir = os.path.join(ROOT, "src", "backend", "vendor", mod)
        lic, src = "UNKNOWN", "unresolved"
        for cand in ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"):
            p = os.path.join(vdir, cand)
            if os.path.isfile(p):
                lic = identify_license_text(read_text(p, errors="replace"))
                src = f"vendor/{mod}/{cand}"
                break
        if lic == "UNKNOWN":
            fact = facts.get(mod)
            if fact:
                lic, src = fact["license"], "license-data.json"
        out.append(Component(
            key=f"go:{mod}", name=mod, version=ver, license=lic,
            ecosystem="go", usage="linked", unit="api image (netops-api, netops-prober)",
            source=src,
            note="statically linked into the Go binaries; must be permissive"))
    if not out:
        raise AuditError("modules.txt parsed to zero modules — parser or file is wrong")
    return out


# ── source 2: npm ────────────────────────────────────────────────────────────
def _npm_license(tree_dir: str, key: str, entry: dict, facts: dict) -> tuple[str, str]:
    if entry.get("license"):
        return normalize_spdx(entry["license"]), "package-lock.json"
    pj = os.path.join(tree_dir, key, "package.json")
    if os.path.isfile(pj):
        j = read_json(pj)
        lic = j.get("license") or j.get("licenses")
        if lic:
            return normalize_spdx(lic), "node_modules/package.json"
    name = key.split("node_modules/")[-1]
    fact = facts.get(name)
    if fact:
        return fact["license"], "license-data.json"
    return "UNKNOWN", "unresolved"


def collect_npm(data: dict) -> list[Component]:
    trees = [
        ("src/frontend", "frontend image (netops-frontend) — SPA bundle",
         "frontend build toolchain"),
        ("docs-portal", "frontend image (netops-frontend) — /docs static site",
         "docs-portal build toolchain"),
    ]
    facts = data.get("npm", {})
    out: list[Component] = []
    for tree, runtime_unit, build_unit in trees:
        lock = os.path.join(ROOT, tree, "package-lock.json")
        if not os.path.isfile(lock):
            raise AuditError(f"{tree}/package-lock.json not found — the npm "
                             f"inventory cannot be derived without the lockfile")
        pkgs = read_json(lock).get("packages", {})
        if not pkgs:
            raise AuditError(f"{lock} has no `packages` map (lockfileVersion < 2?)")
        tdir = os.path.join(ROOT, tree)
        for key, entry in pkgs.items():
            if not key:
                continue  # the root project itself
            name = key.split("node_modules/")[-1]
            dev = bool(entry.get("dev"))
            lic, src = _npm_license(tdir, key, entry, facts)
            # docs-portal ships only its BUILT output; its dependency tree is a
            # static-site generator that never reaches the browser. Treat the
            # whole docs tree as build-only except React, which is emitted into
            # the client bundle.
            if tree == "docs-portal":
                shipped = name in ("react", "react-dom", "scheduler", "clsx",
                                   "prism-react-renderer", "@mdx-js/react",
                                   "js-tokens", "loose-envify")
                usage = "bundled-runtime" if shipped else "build-only"
                unit = runtime_unit if shipped else build_unit
            else:
                usage = "build-only" if dev else "bundled-runtime"
                unit = build_unit if dev else runtime_unit
            out.append(Component(
                key=f"npm:{tree}:{name}@{entry.get('version', '?')}",
                name=name, version=str(entry.get("version", "?")), license=lic,
                ecosystem="npm", usage=usage, unit=unit, source=src,
                note="" if usage != "bundled-runtime"
                     else "minified into the served JS/CSS/font assets"))
    return out


# ── source 3: Python ─────────────────────────────────────────────────────────
def collect_python(data: dict) -> list[Component]:
    facts = data.get("python", {})
    out: list[Component] = []

    req = os.path.join(ROOT, "src", "correlation", "requirements.txt")
    if not os.path.isfile(req):
        raise AuditError("src/correlation/requirements.txt not found")
    text = read_text(req)
    pins = re.findall(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\;]+)", text, re.MULTILINE)
    if not pins:
        raise AuditError("no pinned requirements parsed from requirements.txt")
    for name, ver in pins:
        fact = facts.get(name.lower().replace("_", "-"))
        lic = fact["license"] if fact else "UNKNOWN"
        out.append(Component(
            key=f"pypi:{name}", name=name, version=ver, license=lic,
            ecosystem="pypi", usage="bundled-runtime",
            unit="correlation image (netops-correlation)",
            source="license-data.json" if fact else "unresolved",
            note="installed into site-packages in the shipped image"))

    # The cloud-ingest sidecar installs unpinned packages inline in its
    # Dockerfile. They are still distributed, so they are still inventoried.
    ci = os.path.join(ROOT, "deployment", "docker", "cloud-ingest", "Dockerfile")
    if os.path.isfile(ci):
        for line in read_text(ci).splitlines():
            m = re.search(r"pip install[^\n]*?((?:\s+[A-Za-z0-9][\w.-]*(?:==[\w.]+)?)+)\s*$", line)
            if not m:
                continue
            for tok in m.group(1).split():
                if tok.startswith("-"):
                    continue
                name, _, ver = tok.partition("==")
                fact = facts.get(name.lower().replace("_", "-"))
                out.append(Component(
                    key=f"pypi:cloud-ingest:{name}", name=name,
                    version=ver or "UNPINNED",
                    license=fact["license"] if fact else "UNKNOWN",
                    ecosystem="pypi", usage="bundled-runtime",
                    unit="cloud-ingest image (optional profile)",
                    source="license-data.json" if fact else "unresolved",
                    note="installed unpinned by the Dockerfile"))
    return out


# ── source 4: container images ───────────────────────────────────────────────
def collect_images(data: dict) -> list[Component]:
    facts = data.get("images", {})
    compose_dir = os.path.join(ROOT, "deployment", "docker")
    if not os.path.isdir(compose_dir):
        raise AuditError("deployment/docker not found")
    refs: dict[str, str] = {}   # image ref (no digest) -> where seen

    for fn in sorted(os.listdir(compose_dir)):
        if not fn.endswith((".yml", ".yaml")):
            continue
        path = os.path.join(compose_dir, fn)
        for line in read_text(path).splitlines():
            m = re.match(r"^\s+image:\s*([^\s#]+)", line)
            if m:
                refs.setdefault(m.group(1).split("@")[0], fn)

    for base, _dirs, files in os.walk(ROOT):
        if any(skip in base for skip in ("node_modules", os.sep + "data", os.sep + "dist",
                                         os.sep + ".git", "vendor")):
            continue
        for fn in files:
            if not fn.startswith("Dockerfile"):
                continue
            path = os.path.join(base, fn)
            for line in read_text(path).splitlines():
                m = re.match(r"^\s*FROM\s+([^\s]+)", line, re.IGNORECASE)
                if m and m.group(1).lower() != "scratch":
                    refs.setdefault(m.group(1).split("@")[0],
                                    os.path.relpath(path, ROOT))

    out: list[Component] = []
    for ref, where in sorted(refs.items()):
        if ref.startswith("netops-"):
            continue  # our own images; their contents are inventoried above
        name, _, tag = ref.rpartition(":")
        if not name:
            name, tag = ref, "latest"
        fact = facts.get(name)
        if not fact:
            out.append(Component(
                key=f"image:{ref}", name=name, version=tag, license="UNKNOWN",
                ecosystem="image", usage="separate-container",
                unit=f"referenced by {where}", source="unresolved"))
            continue
        out.append(Component(
            key=f"image:{ref}", name=name, version=tag, license=fact["license"],
            ecosystem="image", usage=fact.get("usage", "separate-container"),
            unit=fact.get("unit", f"referenced by {where}"),
            source="license-data.json", note=fact.get("note", "")))
    return out


# ── source 5: in-tree vendored third-party content ───────────────────────────
def collect_vendored(data: dict) -> list[Component]:
    """Third-party content that arrived by copy, not by a package manager:
    MIB modules, inlined icon path data, embedded vendor marks, datasets.

    These have no manifest to derive from, so they are DECLARED in
    license-data.json — but every declared path is existence-checked, so a
    file that moves or disappears fails the audit rather than quietly taking
    its attribution with it.
    """
    out: list[Component] = []
    for name, fact in sorted(data.get("vendored", {}).items()):
        paths = fact.get("paths", [])
        if not paths:
            raise AuditError(f"vendored entry '{name}' declares no paths")
        missing = [p for p in paths if not os.path.exists(os.path.join(ROOT, p))]
        if missing:
            raise AuditError(
                f"vendored entry '{name}' points at {len(missing)} path(s) that no "
                f"longer exist ({', '.join(missing[:3])}). Update license-data.json "
                f"— attribution must track the content it covers.")
        out.append(Component(
            key=f"vendored:{name}", name=name, version=fact.get("version", "in-tree"),
            license=fact["license"], ecosystem="vendored",
            usage=fact.get("usage", "bundled-runtime"),
            unit=fact.get("unit", "source tarball"),
            source="license-data.json", note=fact.get("note", "")))
    return out


# ── inventory + gate ─────────────────────────────────────────────────────────
def build_inventory(data: dict) -> list[Component]:
    comps = (collect_go(data) + collect_npm(data) + collect_python(data)
             + collect_images(data) + collect_vendored(data))
    seen: dict[str, Component] = {}
    for c in comps:
        seen.setdefault(c.key, c)
    return sorted(seen.values(), key=lambda c: (c.ecosystem, c.name.lower(), c.version))


def open_findings(comps: Iterable[Component], data: dict) -> list[str]:
    """Exceptions that are ACKNOWLEDGED but still awaiting an owner decision.

    These do not fail the build — they are pre-existing, reviewed and recorded,
    and failing on them would only teach people to disable the gate. But they
    are printed loudly on every run so they cannot rot in silence (§16.1: a
    known-degraded state must stay visible, not be swallowed).
    """
    exceptions = data.get("exceptions", {})
    present = {c.name for c in comps} | {c.key for c in comps}
    out: list[str] = []
    for name, exc in sorted(exceptions.items()):
        if name not in present:
            continue
        if str(exc.get("status", "")).upper().startswith("OPEN"):
            out.append(f"{name} [{exc.get('license', '?')}] "
                       f"{exc.get('owner_decision', 'decision required')}")
    return out


def gate(comps: Iterable[Component], data: dict) -> list[str]:
    """Return the list of violations. Empty list = pass."""
    exceptions = data.get("exceptions", {})
    violations: list[str] = []
    for c in comps:
        k = c.klass
        exc = exceptions.get(c.name) or exceptions.get(c.key)
        if k == "PERMISSIVE":
            continue
        if k == "NOTICE_REQUIRED":
            if c.usage in ("bundled-runtime", "linked") and not exc:
                violations.append(
                    f"{c.ecosystem}:{c.name}@{c.version} is {c.license} "
                    f"({k}) and is SHIPPED ({c.usage}) — it needs an exception "
                    f"entry recording that its notice ships in THIRD_PARTY_LICENSES.md")
            continue
        if k == "REVIEW_REQUIRED":
            if not exc:
                violations.append(
                    f"{c.ecosystem}:{c.name}@{c.version} is {c.license} "
                    f"(weak/file-level copyleft) with no reviewed exception. "
                    f"Add one to license-data.json `exceptions` with the posture, "
                    f"or remove the dependency.")
            continue
        if k == "SEPARATE_PROCESS":
            if c.usage in ("linked", "bundled-runtime"):
                violations.append(
                    f"{c.ecosystem}:{c.name}@{c.version} is {c.license} (strong "
                    f"copyleft) and is {c.usage} INTO OUR OWN ARTIFACT — this "
                    f"would place our code under {c.license}. Never allowed.")
            elif not exc:
                violations.append(
                    f"{c.ecosystem}:{c.name}@{c.version} is {c.license} (strong "
                    f"copyleft, separate container) with no reviewed exception. "
                    f"Owner sign-off required before it may ship.")
            continue
        # FORBIDDEN — unless a reviewed exception already records the posture,
        # in which case open_findings() surfaces it instead of blocking merges.
        if exc:
            continue
        if c.license in ("UNKNOWN", "UNDECLARED", ""):
            violations.append(
                f"{c.ecosystem}:{c.name}@{c.version} has NO resolvable licence "
                f"(source: {c.source}). An unreviewed dependency cannot ship — "
                f"resolve it and record it in license-data.json.")
        else:
            violations.append(
                f"{c.ecosystem}:{c.name}@{c.version} is {c.license} — "
                f"source-available / non-OSS. Forbidden anywhere in Correlix "
                f"(CLAUDE.md §6). Remove it.")
    return violations


# ── outputs ──────────────────────────────────────────────────────────────────
def render_report(comps: list[Component]) -> str:
    lines = ["| Component | Version | Licence (SPDX) | Class | Usage | Distribution unit |",
             "|---|---|---|---|---|---|"]
    for c in comps:
        lines.append(f"| `{c.name}` | {c.version} | {c.license} | {c.klass} "
                     f"| {c.usage} | {c.unit} |")
    return "\n".join(lines)


def render_notices(comps: list[Component], data: dict) -> str:
    units: dict[str, list[Component]] = {}
    for c in comps:
        if c.usage == "build-only":
            continue  # not distributed → no notice obligation
        if c.unit.startswith(("NOT SHIPPED", "NOT REFERENCED")):
            continue  # in the repo, but excluded from every bundle
        units.setdefault(c.unit, []).append(c)
    texts = data.get("license_texts", {})
    out = [
        "# Correlix — Third-party licences",
        "",
        "> GENERATED by `scripts/license-audit.py --notices`. Do not hand-edit;",
        "> edit `scripts/license-data.json` and regenerate.",
        "",
        "Correlix distributes the third-party components below. Build-time-only",
        "tooling (compilers, bundlers, test runners) is excluded: it is not",
        "distributed and carries no notice obligation.",
        "",
    ]
    for unit in sorted(units):
        out.append(f"## {unit}")
        out.append("")
        out.append("| Component | Version | Licence | Notes |")
        out.append("|---|---|---|---|")
        for c in sorted(units[unit], key=lambda x: x.name.lower()):
            out.append(f"| `{c.name}` | {c.version} | {c.license} | {c.note or ''} |")
        out.append("")
    if texts:
        out.append("## Licence texts and source availability")
        out.append("")
        for name in sorted(texts):
            out.append(f"### {name}")
            out.append("")
            out.append(texts[name].rstrip())
            out.append("")
    return "\n".join(out) + "\n"


def refresh_data(comps: list[Component], data: dict) -> dict:
    """Fold anything we resolved from live metadata back into the facts file,
    so a later offline --check can still resolve it."""
    for c in comps:
        if c.license in ("UNKNOWN", "UNDECLARED"):
            continue
        if c.source == "license-data.json":
            continue
        if c.ecosystem == "npm":
            data.setdefault("npm", {})[c.name] = {"license": c.license}
        elif c.ecosystem == "go":
            data.setdefault("go", {})[c.name] = {"license": c.license}
    return data


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="gate the tree (default)")
    ap.add_argument("--write", action="store_true", help="refresh scripts/license-data.json")
    ap.add_argument("--report", action="store_true", help="print the full inventory table")
    ap.add_argument("--notices", action="store_true", help="regenerate docs/THIRD_PARTY_LICENSES.md")
    ap.add_argument("--json", action="store_true", help="print the inventory as JSON")
    args = ap.parse_args(argv)

    try:
        data = load_data()
        comps = build_inventory(data)
    except AuditError as exc:
        print(f"license-audit: CANNOT RUN: {exc}", file=sys.stderr)
        return 2

    if args.write:
        data = refresh_data(comps, data)
        try:
            with open(DATA_FILE, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, sort_keys=True)
                fh.write("\n")
        except OSError as exc:
            print(f"license-audit: cannot write {DATA_FILE}: {exc}", file=sys.stderr)
            return 2
        print(f"license-audit: refreshed {os.path.relpath(DATA_FILE, ROOT)}")

    if args.notices:
        try:
            os.makedirs(os.path.dirname(NOTICES_FILE), exist_ok=True)
            with open(NOTICES_FILE, "w", encoding="utf-8") as fh:
                fh.write(render_notices(comps, data))
        except OSError as exc:
            print(f"license-audit: cannot write {NOTICES_FILE}: {exc}", file=sys.stderr)
            return 2
        print(f"license-audit: wrote {os.path.relpath(NOTICES_FILE, ROOT)}")

    if args.json:
        print(json.dumps([c.as_dict() for c in comps], indent=2))
    elif args.report:
        print(render_report(comps))

    # --check is the default when no other mode was asked for.
    if args.check or not (args.write or args.report or args.notices or args.json):
        counts: dict[str, int] = {}
        for c in comps:
            counts[c.klass] = counts.get(c.klass, 0) + 1
        summary = "  ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        print(f"license-audit: {len(comps)} components  [{summary}]")
        pending = open_findings(comps, data)
        if pending:
            print(f"\nlicense-audit: {len(pending)} ACKNOWLEDGED finding(s) still "
                  f"awaiting an owner decision (not a build failure):")
            for p in pending:
                print(f"  ! {p}")
            print("  see docs/security/LICENSE_AUDIT_2026-09-03.md")
            print()
        violations = gate(comps, data)
        if violations:
            print(f"\nlicense-audit: {len(violations)} VIOLATION(S)", file=sys.stderr)
            for v in violations:
                print(f"  - {v}", file=sys.stderr)
            return 1
        print("license-audit: OK — every component is permissive, or a "
              "reviewed exception covers it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
