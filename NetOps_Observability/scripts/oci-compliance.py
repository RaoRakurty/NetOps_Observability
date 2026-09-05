#!/usr/bin/env python3
"""oci-compliance.py — the FINAL OCI IMAGE is the compliance boundary.

WHY THIS EXISTS
---------------
`scripts/license-audit.py` derives its inventory from what Correlix *declares*:
vendored Go modules, npm lockfiles, pinned requirements, `image:` references in
compose and `FROM` lines in Dockerfiles. That model cannot see software that
arrives inside a base image's LAYERS without ever being named by us.

BusyBox is the confirmed example. `deployment/docker/Dockerfile.frontend` says
`FROM nginx:1.27-alpine@sha256:6564…` and copies a built SPA on top. Nothing in
the tree mentions BusyBox — yet every `netops-frontend` and `netops-nginx` image
we distribute contains `busybox 1.37.0-r12`, GPL-2.0-**only**, with a real
corresponding-source obligation. The audit's `busybox` exception sat OPEN for
months and matched no inventoried component, because the thing it described was
never in the inventory to begin with (tracker 238).

The defect is the MODEL, not the entry. A shipped container is

    upstream base image (BusyBox, libc, OpenSSL, distro packages)
  + everything a package manager pulled in
  + Correlix's own layers

so the compliance boundary has to be the final resolved image, addressed by its
immutable digest — not the Dockerfile that produced it.

WHAT THIS DOES
--------------
It consumes a CycloneDX SBOM taken from a FINAL OCI IMAGE (Syft — the scanner
`.github/workflows/publish-images.yml` already runs against every pushed digest)
and runs the chain the compliance posture actually needs:

  final image → immutable digest → SBOM of the whole image → normalized
  component inventory → licence determination → source obligation → locate a
  Correlix-retained source artifact → verify its checksum → compliance
  manifest → PASS / FAIL

What is EVALUATED is the packages the SBOM inventories. A CycloneDX FILE entry
("/etc/securetty", "/lib/ld-musl-x86_64.so.1") is one file inside such a package,
not an independently licensed work, so it is excluded from the obligation
evaluation — counted in the verdict line and listed in the manifest's
`skipped_file_entries`, never silently dropped. See `is_file_entry`.

Nothing here is BusyBox-specific. The obligation comes from the normalized
LICENCE (the GPL/LGPL/AGPL family), and artifacts are located by normalized
SOURCE-PACKAGE IDENTITY, so the same code covers the next copyleft component
that rides in on a base-image bump — which is the regression this file exists to
prevent.

POLICY AND ARTIFACTS LIVE IN THE EXISTING MECHANISM
---------------------------------------------------
`scripts/source-mirror.json` is already the reviewed pin table that
`scripts/make-installer.sh write_source_offer()` mirrors into every release
bundle's `source-offer/` (owner decision 2026-09-04, licence audit D2). This
tool reads THAT file. Adding a component is one entry there; there is no second
source-archive architecture and no second SBOM system.

Two sections are read:

  components[]  retained corresponding-source artifacts, each with the upstream
                URL, a pinned sha256 and a `provides` list saying which
                normalized component identities it satisfies.
  deferred[]    components with a real source obligation for which Correlix has
                NOT yet produced a retained artifact. Explicitly recorded,
                version-pinned and dated. They are printed loudly on every run
                and they FAIL `--release`. A component that is in neither list
                fails every mode — silence is never a pass.

FAIL CLOSED (scripts/CLAUDE.md §16.1). A missing SBOM, an unparsable SBOM, an
SBOM with no components, a scanner that wrote nothing, a checksum that does not
match, an obligation with no recorded posture — every one of them is an error
with a reason, never a quietly shorter inventory. A scanner failure must never
become "zero affected packages".

USAGE
    # evaluate one image's SBOM
    oci-compliance.py --sbom fe.cdx.json --image netops-frontend \
        --digest sha256:… [--base-layers base.txt] [--source-dir source-offer/] \
        [--manifest out.json] [--release]

    # merge many manifests into the committed inventory license-audit.py reads
    oci-compliance.py --emit-inventory docs/compliance/oci-inventory.json \
        --manifest-in a.json --manifest-in b.json

    # propose register entries for obligations with no artifact yet (review by hand)
    oci-compliance.py --sbom fe.cdx.json --image … --digest … --record-deferred

    oci-compliance.py --selftest      # offline parser/policy self-tests

EXIT CODES
    0  PASS
    1  FAIL (a compliance violation)
    2  CANNOT RUN (missing/unparsable input, scanner output that proves nothing)

Pure standard library (CLAUDE.md §6). No network, no docker, no running stack.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import sys
from typing import Any

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
PIN_TABLE = os.path.join(ROOT, "scripts", "source-mirror.json")
LICENSE_FACTS = os.path.join(ROOT, "scripts", "license-data.json")
GO_MOD = os.path.join(ROOT, "src", "backend", "go.mod")
INVENTORY = os.path.join(ROOT, "docs", "compliance", "oci-inventory.json")

SCHEMA_VERSION = 1


class ComplianceError(Exception):
    """The evaluation could not be performed. Exit 2 — never a silent pass."""


# ── licence policy ───────────────────────────────────────────────────────────
# Corresponding-source obligations, by normalized SPDX id. This is the whole
# policy: an obligation is a property of the LICENCE, never of a package name.
# `if package == "busybox"` is exactly the shape this file must not have.
SOURCE_REQUIRED = {
    "GPL-2.0-only", "GPL-2.0-or-later",
    "GPL-3.0-only", "GPL-3.0-or-later",
    "LGPL-2.1-only", "LGPL-2.1-or-later",
    "LGPL-3.0-only", "LGPL-3.0-or-later",
    "AGPL-3.0-only", "AGPL-3.0-or-later",
    # Older/variant spellings that carry the same obligation.
    "GPL-1.0-only", "GPL-1.0-or-later",
    "LGPL-2.0-only", "LGPL-2.0-or-later",
}

# Permissive ids we can state positively. Anything outside BOTH sets is UNKNOWN
# to this policy and must be resolved by a human — never assumed obligation-free.
NO_SOURCE_OBLIGATION = {
    "0BSD", "Apache-2.0", "Artistic-2.0", "BSD-2-Clause", "BSD-3-Clause",
    "BSD-4-Clause", "BSD-4-Clause-UC", "BSL-1.0", "CC0-1.0", "CC-BY-3.0",
    "CC-BY-4.0", "FTL", "GD", "ISC", "Libpng", "MIT", "MIT-0", "MPL-1.1",
    "MPL-2.0", "OFL-1.1", "PSF-2.0", "Public-Domain", "Python-2.0",
    "PostgreSQL", "Sleepycat", "Unicode-DFS-2016", "Unlicense", "X11",
    "Zlib", "bzip2-1.0.6", "curl", "libtiff", "public-domain",
}

# Free-text → SPDX for the spellings distro metadata actually emits. Never
# normalises INTO a permissive id from something ambiguous.
LICENSE_ALIASES = {
    "gpl": "GPL-UNSPECIFIED",
    "lgpl": "LGPL-UNSPECIFIED",
    "agpl": "AGPL-UNSPECIFIED",
    "gpl-2.0": "GPL-2.0-or-later",
    "gpl-3.0": "GPL-3.0-or-later",
    "gplv2": "GPL-2.0-or-later",
    "gplv3": "GPL-3.0-or-later",
    "lgpl-2.1": "LGPL-2.1-or-later",
    "public domain": "public-domain",
    "expat": "MIT",
    "mit license": "MIT",
    "the mit license": "MIT",
    "apache-2": "Apache-2.0",
    "apache 2": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "bsd license": "BSD-3-Clause",
    "python software foundation license": "PSF-2.0",
}

# An unspecified GPL/LGPL/AGPL family id names a copyleft obligation whose exact
# version is not stated. It is an obligation (never permissive) AND it is not
# precise enough to match an artifact — so it lands in manual-review.
FAMILY_UNSPECIFIED = {"GPL-UNSPECIFIED", "LGPL-UNSPECIFIED", "AGPL-UNSPECIFIED"}

# Source-status vocabulary. `verified` is the only production pass for an
# obligation; upstream availability alone never reaches it.
STATUS_NOT_REQUIRED = "not-required"
STATUS_VERIFIED = "verified"
STATUS_MISSING = "missing"
STATUS_INVALID = "invalid"
STATUS_MANUAL_REVIEW = "manual-review"
STATUS_UNKNOWN = "unknown"
STATUS_PINNED = "pinned-not-materialized"

# Origins a component can have inside a final image.
ORIGIN_FIRST_PARTY = "first-party"
ORIGIN_INHERITED = "inherited-base-layer"
ORIGIN_CORRELIX_LAYER = "correlix-layer"
ORIGIN_UNKNOWN = "unknown"


# ── io helpers ───────────────────────────────────────────────────────────────
def read_json(path: str, *, what: str) -> Any:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise ComplianceError(f"cannot read {what} ({path}): {exc}") from exc


def load_pin_table(path: str | None = None) -> dict:
    """The reviewed pin table. Missing or malformed is CANNOT RUN, not 'no pins'."""
    p = path or PIN_TABLE
    data = read_json(p, what="source pin table")
    if not isinstance(data, dict):
        raise ComplianceError(f"{p}: pin table is not a JSON object")
    comps = data.get("components")
    if not isinstance(comps, list) or not comps:
        raise ComplianceError(f"{p}: pin table declares no `components`")
    for c in comps:
        for field in ("name", "version", "file", "url", "sha256", "license"):
            if not c.get(field):
                raise ComplianceError(
                    f"{p}: component {c.get('name', '?')!r} is missing `{field}`")
        if "/" in c["file"] or c["file"].startswith("."):
            raise ComplianceError(
                f"{p}: component {c['name']!r} has an unsafe file name {c['file']!r}")
        if not c["url"].startswith("https://"):
            raise ComplianceError(
                f"{p}: component {c['name']!r} must be fetched over TLS, got {c['url']!r}")
        if not re.fullmatch(r"[0-9a-f]{64}", str(c["sha256"])):
            raise ComplianceError(
                f"{p}: component {c['name']!r} has a malformed sha256")
    deferred = data.get("deferred", [])
    if not isinstance(deferred, list):
        raise ComplianceError(f"{p}: `deferred` must be a list")
    for d in deferred:
        for field in ("component", "version", "license", "package_type"):
            if not d.get(field):
                raise ComplianceError(
                    f"{p}: deferred entry {d.get('component', '?')!r} is missing `{field}`")
    return data


# ── licence normalization ────────────────────────────────────────────────────
def normalize_license_id(raw: str) -> str:
    """One free-text licence token → an SPDX id we can reason about.

    Never guesses into a permissive id: an unrecognised token comes back as
    itself and is treated as UNKNOWN by the policy.
    """
    tok = (raw or "").strip().strip("()").strip()
    if not tok:
        return ""
    if tok in SOURCE_REQUIRED or tok in NO_SOURCE_OBLIGATION or tok in FAMILY_UNSPECIFIED:
        return tok
    alias = LICENSE_ALIASES.get(tok.lower())
    if alias:
        return alias
    return tok


def _split_expression(expr: str) -> tuple[list[list[str]], str]:
    """Split an SPDX expression into OR-branches of AND-terms.

    Returns (branches, shape) where shape is "or", "and" or "single". Anything
    with a WITH clause or nested parentheses we cannot resolve is reported as
    shape "opaque" so it lands in manual review rather than being guessed at.
    """
    text = " ".join(str(expr or "").split())
    if not text:
        return [], "empty"
    if "(" in text or ")" in text or re.search(r"\bWITH\b", text):
        return [[text]], "opaque"
    or_parts = re.split(r"\s+OR\s+", text)
    branches = [[t.strip() for t in re.split(r"\s+AND\s+", p) if t.strip()]
                for p in or_parts]
    if len(or_parts) > 1:
        return branches, "or"
    if len(branches[0]) > 1:
        return branches, "and"
    return branches, "single"


def evaluate_licenses(raw_ids: list[str], expressions: list[str]) -> dict:
    """Decide the source obligation for one component's licence evidence.

    Three distinguishable shapes, because conflating them is how a real
    obligation disappears:

      expression  a parseable SPDX expression (or a single id). Resolvable:
                  an OR is taken on its most permissive branch, an AND requires
                  source if ANY term does.
      list        several ids with no stated relationship — exactly what dpkg
                  copyright extraction produces. We cannot tell "MIT AND GPL"
                  from "MIT OR GPL", so if any member carries an obligation the
                  answer is MANUAL REVIEW, never a silent pass and never a
                  blanket fail.
      unknown     no licence evidence at all, or ids this policy does not know.

    Returns {license, source_required, confidence, reason}.
    """
    tokens = [str(i).strip() for i in raw_ids if str(i).strip()]
    exprs = [e for e in expressions if str(e).strip()]

    # Syft sometimes splits an SPDX expression it could not resolve into one
    # `name` entry per word, connectors included ("BSD-2-Clause", "AND",
    # "custom"). Treating those as three independent licences loses the stated
    # relationship, so put the expression back together and evaluate it as one.
    if not exprs and any(t.upper() in ("AND", "OR") for t in tokens):
        exprs = [" ".join(t.upper() if t.upper() in ("AND", "OR") else t
                          for t in tokens)]
        tokens = []

    ids = [normalize_license_id(i) for i in tokens]

    # A single stated expression is the strongest evidence available.
    if len(exprs) == 1 and not ids:
        branches, shape = _split_expression(exprs[0])
        if shape == "opaque":
            return {"license": exprs[0], "source_required": True,
                    "confidence": "opaque-expression",
                    "reason": "SPDX expression could not be resolved "
                              "(WITH clause or nested grouping) — human review"}
        if shape == "or":
            # A dual-licensed component may be taken under whichever branch we
            # choose, and we always choose the branch with no source obligation.
            for branch in branches:
                norm = [normalize_license_id(t) for t in branch]
                if all(n in NO_SOURCE_OBLIGATION for n in norm):
                    return {"license": exprs[0], "source_required": False,
                            "confidence": "expression",
                            "reason": f"taken under the permissive branch "
                                      f"{' AND '.join(norm)}"}
            flat = sorted({normalize_license_id(t) for b in branches for t in b})
            if any(n in SOURCE_REQUIRED or n in FAMILY_UNSPECIFIED for n in flat):
                return {"license": exprs[0], "source_required": True,
                        "confidence": "expression",
                        "reason": "every branch of the disjunction carries a "
                                  "corresponding-source obligation"}
            return {"license": exprs[0], "source_required": True,
                    "confidence": "unknown-license",
                    "reason": f"no branch resolves to a known permissive licence "
                              f"({', '.join(flat)}) — human review"}
        # "single" or "and": fall through to the id-set logic below with the
        # terms already normalised, except that a stated AND is a RESOLVED
        # relationship — a copyleft term in it is a definite obligation, not the
        # unresolvable license-list case.
        norm = [normalize_license_id(t) for t in branches[0]]
        if shape == "and" and any(n in SOURCE_REQUIRED or n in FAMILY_UNSPECIFIED
                                  for n in norm):
            return {"license": exprs[0], "source_required": True,
                    "confidence": "expression",
                    "reason": "the stated conjunction includes a copyleft term"}
        ids = norm
        exprs = []

    combined = sorted(set(ids) | {normalize_license_id(e) for e in exprs})
    combined = [c for c in combined if c]
    if not combined:
        return {"license": "", "source_required": True, "confidence": "no-license",
                "reason": "the SBOM records no licence for this component — an "
                          "undetermined licence is never assumed obligation-free"}

    obligated = [c for c in combined if c in SOURCE_REQUIRED]
    family = [c for c in combined if c in FAMILY_UNSPECIFIED]
    unknown = [c for c in combined
               if c not in SOURCE_REQUIRED and c not in NO_SOURCE_OBLIGATION
               and c not in FAMILY_UNSPECIFIED]
    lic = " ; ".join(combined)

    if len(combined) == 1:
        only = combined[0]
        if only in SOURCE_REQUIRED:
            return {"license": lic, "source_required": True,
                    "confidence": "expression",
                    "reason": f"{only} requires corresponding source"}
        if only in NO_SOURCE_OBLIGATION:
            return {"license": lic, "source_required": False,
                    "confidence": "expression",
                    "reason": f"{only} carries no corresponding-source obligation"}
        if only in FAMILY_UNSPECIFIED:
            return {"license": lic, "source_required": True,
                    "confidence": "family-unspecified",
                    "reason": f"{only}: a copyleft family with no stated version — "
                              f"the obligation is real, the exact terms are not "
                              f"determined; human review"}
        return {"license": lic, "source_required": True, "confidence": "unknown-license",
                "reason": f"{only} is not in this policy's licence tables — human review"}

    # Several ids with no stated relationship.
    if obligated or family:
        return {"license": lic, "source_required": True, "confidence": "license-list",
                "reason": "the SBOM lists several licences with no stated "
                          "relationship and at least one is copyleft "
                          f"({', '.join(obligated + family)}) — the obligation "
                          "cannot be resolved mechanically; human review"}
    if unknown:
        return {"license": lic, "source_required": True, "confidence": "unknown-license",
                "reason": f"unrecognised licence id(s) {', '.join(unknown)} — human review"}
    return {"license": lic, "source_required": False, "confidence": "license-list",
            "reason": "every listed licence is permissive"}


# ── component normalization ──────────────────────────────────────────────────
_APK_REV = re.compile(r"^(?P<up>.+?)-r\d+$")
_DEB_VER = re.compile(r"^(?:\d+:)?(?P<up>[^-]+(?:-[^-]+)*?)(?:-[^-]+)?$")


def upstream_version(version: str, package_type: str) -> str:
    """The UPSTREAM version behind a distro package version.

    apk `1.37.0-r12` → `1.37.0`; deb `1:2.41-5` → `2.41`. This is what an
    upstream source tarball is named after, so it is the key an artifact is
    located by. Anything we cannot decompose is returned unchanged rather than
    mangled — a wrong key must not silently match the wrong tarball.
    """
    v = (version or "").strip()
    if not v:
        return ""
    if package_type == "apk":
        m = _APK_REV.match(v)
        return m.group("up") if m else v
    if package_type in ("deb", "dpkg"):
        v = v.split(":", 1)[-1]          # strip the epoch
        v = re.sub(r"\+dfsg.*$", "", v)  # Debian repack marker
        if "-" in v:
            v = v.rsplit("-", 1)[0]      # strip the Debian revision
        return v
    return v


def parse_purl(purl: str) -> dict[str, str]:
    """name / version / type / namespace / qualifiers from a Package URL."""
    out = {"type": "", "namespace": "", "name": "", "version": "", "qualifiers": {}}
    if not purl or not purl.startswith("pkg:"):
        return out
    body = purl[4:]
    body, _, _sub = body.partition("#")
    body, _, qs = body.partition("?")
    path, _, ver = body.partition("@")
    parts = [p for p in path.split("/") if p]
    if parts:
        out["type"] = parts[0]
    if len(parts) > 2:
        out["namespace"] = "/".join(parts[1:-1])
    if len(parts) > 1:
        out["name"] = parts[-1]
    out["version"] = ver
    quals: dict[str, str] = {}
    for kv in qs.split("&"):
        if "=" in kv:
            k, _, v = kv.partition("=")
            quals[k] = v
    out["qualifiers"] = quals
    return out


def _properties(comp: dict) -> dict[str, list[str]]:
    props: dict[str, list[str]] = {}
    for p in comp.get("properties") or []:
        name, value = p.get("name"), p.get("value")
        if name is None or value is None:
            continue
        props.setdefault(str(name), []).append(str(value))
    return props


def normalize_component(comp: dict, *, image: str, image_digest: str,
                        base_layers: set[str] | None) -> dict:
    """One CycloneDX component → the normalized representation the policy uses."""
    props = _properties(comp)
    purl = parse_purl(comp.get("purl", ""))
    ptype = purl["type"] or (props.get("syft:package:type", [""])[0])
    name = comp.get("name") or purl["name"] or ""
    version = str(comp.get("version") or purl["version"] or "")

    raw_ids: list[str] = []
    exprs: list[str] = []
    for entry in comp.get("licenses") or []:
        if entry.get("expression"):
            exprs.append(str(entry["expression"]))
            continue
        lic = entry.get("license") or {}
        val = lic.get("id") or lic.get("name")
        if val:
            # Syft emits a bare `name` for anything not a known SPDX id; a name
            # that IS an expression is handled as one.
            # A bare "AND"/"OR" is a CONNECTOR Syft split out of an expression it
            # could not resolve, not a licence — it must stay in the token list so
            # the expression can be put back together, never be mistaken for an
            # expression in its own right.
            if not lic.get("id") and re.search(r"\S\s+(?:AND|OR)\s+\S", str(val)):
                exprs.append(str(val))
            else:
                raw_ids.append(str(val))

    layer_ids = sorted(set(props.get("syft:location:0:layerID", [])
                           + [v for k, vs in props.items()
                              if k.startswith("syft:location:") and k.endswith(":layerID")
                              for v in vs]))
    if base_layers is None:
        origin = ORIGIN_UNKNOWN
        origin_reason = ("the base image's layer set was not supplied, so whether "
                         "this component was inherited or added by Correlix is "
                         "not determined")
    elif not layer_ids:
        origin = ORIGIN_UNKNOWN
        origin_reason = "the SBOM records no layer for this component"
    elif all(lid in base_layers for lid in layer_ids):
        origin = ORIGIN_INHERITED
        origin_reason = "every layer holding it belongs to the pinned base image"
    else:
        origin = ORIGIN_CORRELIX_LAYER
        origin_reason = "it appears in a layer Correlix's Dockerfile added"

    source_package = (props.get("syft:metadata:originPackage", [""])[0]
                      or purl["qualifiers"].get("upstream", "").split("@")[0]
                      or name)
    distro = purl["qualifiers"].get("distro", "") or purl["namespace"]

    return {
        "name": name,
        "version": version,
        "component_kind": str(comp.get("type") or "library"),
        "package_type": ptype or "unknown",
        "purl": comp.get("purl", ""),
        "supplier": (comp.get("publisher")
                     or (comp.get("supplier") or {}).get("name", "")),
        "source_package": source_package,
        "upstream_version": upstream_version(version, ptype),
        "distro": distro,
        "image": image,
        "image_digest": image_digest,
        "origin": origin,
        "origin_reason": origin_reason,
        "layer_ids": layer_ids,
        # Document ORDER is preserved: Syft sometimes emits an SPDX expression as
        # separate `name` entries ("BSD-2-Clause", "AND", "custom"), and the
        # connectors are only meaningful in place.
        "licenses_raw": raw_ids,
        "license_expressions": exprs,
        # Alpine records the aports commit that BUILT the package. That is the
        # exact-source pointer for a distro build, so it is preserved verbatim.
        "distro_build_ref": props.get("syft:metadata:gitCommitOfApkPort", [""])[0],
    }


# ── reusing what the repository already knows ────────────────────────────────
# An image scan reads licences out of package databases. That works for distro
# packages and says nothing at all about Go modules, whose licence lives in a
# LICENSE file the compiled binary does not carry. scripts/license-audit.py
# already resolves those from src/backend/vendor/<mod>/LICENSE and records the
# answer in scripts/license-data.json. Re-deriving it here would be a second
# licence system; reading the existing one is the whole point.
_FACT_ECOSYSTEM = {"golang": "go", "npm": "npm", "pypi": "python", "python": "python"}


def load_license_facts(path: str | None) -> dict[str, dict[str, str]]:
    """Reviewed licence facts, keyed ecosystem → component name → SPDX id."""
    p = path or LICENSE_FACTS
    if not os.path.isfile(p):
        if path:
            raise ComplianceError(f"licence facts file not found: {p}")
        return {}
    data = read_json(p, what="licence facts")
    out: dict[str, dict[str, str]] = {}
    for eco in ("go", "npm", "python"):
        section = data.get(eco) or {}
        if not isinstance(section, dict):
            raise ComplianceError(f"{p}: `{eco}` is not an object")
        out[eco] = {name: fact.get("license", "")
                    for name, fact in section.items()
                    if isinstance(fact, dict) and fact.get("license")}
    return out


def first_party_prefixes(explicit: list[str], go_mod: str | None = None) -> list[str]:
    """Module paths that are Correlix's own code.

    Derived from `src/backend/go.mod`'s own `module` line rather than hard-coded,
    so renaming the module cannot leave a stale prefix silently classifying our
    binary as somebody else's.
    """
    if explicit:
        return list(explicit)
    path = go_mod or GO_MOD
    if not os.path.isfile(path):
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                m = re.match(r"^module\s+(\S+)", line)
                if m:
                    return [m.group(1)]
    except OSError as exc:
        raise ComplianceError(f"cannot read {path}: {exc}") from exc
    return []


def is_first_party(component: dict, prefixes: list[str]) -> bool:
    name = component.get("name", "")
    return any(name == p or name.startswith(p + "/") for p in prefixes)


# ── SBOM ingestion ───────────────────────────────────────────────────────────
def parse_sbom(path: str) -> tuple[list[dict], dict, list[dict]]:
    """Read a CycloneDX document produced from a final OCI image.

    Returns its components, its metadata and its `dependencies` edges — the
    edges are what name the package that OWNS a file entry (see
    `file_entry_owners`), so they are read here rather than re-opening the
    document later.

    Fail-closed on every shape that would understate the inventory: a missing
    file, a non-CycloneDX document, or zero components. A scanner that produced
    nothing must never read as "nothing to declare".
    """
    doc = read_json(path, what="image SBOM")
    if not isinstance(doc, dict):
        raise ComplianceError(f"{path}: SBOM is not a JSON object")
    fmt = doc.get("bomFormat")
    if fmt != "CycloneDX":
        raise ComplianceError(
            f"{path}: not a CycloneDX document (bomFormat={fmt!r}). "
            f"The image scan did not produce the inventory this gate evaluates.")
    comps = doc.get("components")
    if not isinstance(comps, list) or not comps:
        raise ComplianceError(
            f"{path}: the SBOM lists no components. An image scan that found "
            f"nothing is a scanner failure, not an empty image — refusing to "
            f"report zero affected packages.")
    meta = doc.get("metadata") or {}
    deps = doc.get("dependencies")
    return comps, meta, deps if isinstance(deps, list) else []


# ── file entries are not independently licensed components ───────────────────
# A CycloneDX document taken from an image carries two very different kinds of
# entry:
#
#   PACKAGE entry  "busybox 1.37.0-r12", pkg:apk/alpine/busybox@…  — a
#                  distributed work with its own licence and its own
#                  corresponding-source obligation.
#   FILE entry     "/etc/securetty", "/lib/ld-musl-x86_64.so.1" — ONE FILE
#                  INSIDE such a package. Syft's file catalogers list it with a
#                  name and a digest and nothing else: no purl, no version and
#                  no licence, because a file does not carry a licence of its
#                  own. Its licence is its owning package's, and that package is
#                  already inventoried in the same document.
#
# Which of them a scan contains is a property of the SCANNER, not of the image.
# Syft v1.18.1 (the checked-in fixtures) reported 16 package entries and no file
# entries for the regression image; v1.42.3 (what CI runs) reports the same 16
# packages plus 82 file entries for the byte-identical image. Evaluating those
# 82 as components produced 82 "no licence recorded" violations without a single
# extra byte being shipped — a scanner-shape difference reported as a compliance
# finding, which is exactly the kind of false verdict that teaches people to
# switch a gate off.
#
# So file entries are EXCLUDED from the obligation evaluation — and never
# silently dropped (§10): they are counted in the verdict line and listed in the
# manifest under `skipped_file_entries`, with the owning package whenever the
# document's own relationships name one. Nothing about how a PACKAGE with an
# unknown or absent licence is treated changes: those still land in
# manual-review and fail closed.
_ABSOLUTE_PATH = re.compile(r"/\S*")


def is_file_entry(comp: dict) -> bool:
    """True when this CycloneDX component describes a FILE, not a package.

    Deliberately narrow, because every entry this excludes is an entry the
    licence policy stops looking at:

      * `type: "file"` — the emitter said so itself; or
      * no `purl` AND no `version` AND an absolute-path name — the shape a file
        listing has when the emitter does not set the type.

    An entry that carries a purl or a version is a PACKAGE claim even when its
    name looks like a path, and is evaluated as one (fail closed).
    """
    if str(comp.get("type") or "") == "file":
        return True
    if comp.get("purl") or str(comp.get("version") or ""):
        return False
    return bool(_ABSOLUTE_PATH.fullmatch(str(comp.get("name") or "")))


def file_entry_owners(components: list[dict],
                      dependencies: list[dict] | None) -> dict[str, str]:
    """bom-ref of a file entry → the package entry that CONTAINS it.

    Syft records containment as a relationship, and its CycloneDX encoder writes
    the edges it maps into `dependencies[].dependsOn`; an owner is therefore read
    as "a package entry that depends on this file entry". Not every Syft version
    emits those edges — v1.42.3 emits none for file entries — so the owner is
    reported when the document STATES one and left empty when it does not. It is
    never guessed from the path: a plausible owner would be an invented fact.
    """
    files = {str(c.get("bom-ref")) for c in components
             if c.get("bom-ref") and is_file_entry(c)}
    if not files:
        return {}
    packages: dict[str, str] = {}
    for c in components:
        ref = c.get("bom-ref")
        if not ref or is_file_entry(c):
            continue
        packages[str(ref)] = " ".join(
            x for x in (str(c.get("name") or ""), str(c.get("version") or "")) if x)
    owners: dict[str, str] = {}
    for dep in dependencies or []:
        if not isinstance(dep, dict):
            continue
        owner = packages.get(str(dep.get("ref")))
        if not owner:
            continue
        for child in dep.get("dependsOn") or []:
            owners.setdefault(str(child), owner)
    return {ref: owner for ref, owner in owners.items() if ref in files}


def split_file_entries(components: list[dict],
                       dependencies: list[dict] | None = None
                       ) -> tuple[list[dict], list[dict]]:
    """Components → (package entries to evaluate, file entries recorded as skipped).

    Fail-closed: a document that contains file entries and NO package entry is a
    scan with no package inventory at all, which cannot be evaluated and must
    never read as "nothing to declare".
    """
    owners = file_entry_owners(components, dependencies)
    packages: list[dict] = []
    skipped: list[dict] = []
    for c in components:
        if not is_file_entry(c):
            packages.append(c)
            continue
        declared: list[str] = []
        for entry in c.get("licenses") or []:
            if not isinstance(entry, dict):
                continue
            if entry.get("expression"):
                declared.append(str(entry["expression"]))
                continue
            lic = entry.get("license") or {}
            val = lic.get("id") or lic.get("name")
            if val:
                declared.append(str(val))
        ref = str(c.get("bom-ref") or "")
        skipped.append({
            "name": str(c.get("name") or ""),
            "bom_ref": ref,
            "component_kind": str(c.get("type") or ""),
            "owner_package": owners.get(ref, ""),
            "declared_licenses": declared,
            "reason": ("a file inside an inventoried package, not an "
                       "independently licensed component"),
        })
    if skipped and not packages:
        raise ComplianceError(
            "the SBOM lists file entries and no package entries. A scan with no "
            "package inventory cannot be evaluated for source obligations — "
            "refusing to report zero affected packages.")
    skipped.sort(key=lambda e: e["name"])
    return packages, skipped


def load_base_layers(path: str | None) -> set[str] | None:
    """Diff-ids of the pinned base image, one per line.

    Produced by `docker image inspect <base> --format '{{range .RootFS.Layers}}…'`.
    Absent → origin is reported as `unknown`; provenance is never invented.
    """
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            layers = {ln.strip() for ln in fh if ln.strip()}
    except OSError as exc:
        raise ComplianceError(f"cannot read base-layer list {path}: {exc}") from exc
    if not layers:
        raise ComplianceError(
            f"{path}: base-layer list is empty. An empty list would mark every "
            f"component as Correlix-added, which is the opposite of the truth.")
    bad = [ln for ln in layers if not re.fullmatch(r"sha256:[0-9a-f]{64}", ln)]
    if bad:
        raise ComplianceError(f"{path}: not a layer digest: {bad[0]!r}")
    return layers


# ── artifact location + verification ─────────────────────────────────────────
def _provides_match(component: dict, prov: dict) -> bool:
    if not (prov.get("source_package") or prov.get("name")):
        return False  # a `provides` that constrains nothing matches nothing
    if prov.get("package_type") and prov["package_type"] != component["package_type"]:
        return False
    if prov.get("source_package") and prov["source_package"] != component["source_package"]:
        return False
    if prov.get("name") and prov["name"] != component["name"]:
        return False
    want = prov.get("upstream_version")
    return not (want and want != component["upstream_version"])


def artifacts_for(component: dict, pins: dict) -> list[dict]:
    """Every retained source artifact that serves this component.

    Matching is on the normalized SOURCE-PACKAGE identity, never on a package
    name we special-cased: a pin entry declares what it `provides`, and every
    component whose (package_type, source package, upstream version) matches is
    served by it. Three Alpine packages built from the same `busybox` origin
    share one tarball — dedup, with each image digest still recorded; a
    DIFFERENT busybox version matches nothing and must be mirrored separately.

    A component may be served by more than one artifact, because for a component
    that came from a DISTRIBUTION package the upstream release tarball alone is
    not the source that distribution built: the packaging recipe, its patch set
    and its build configuration are part of the corresponding source. Those are
    separate entries with `role: distro-packaging`.
    """
    out = [entry for entry in pins.get("components", [])
           if any(_provides_match(component, prov)
                  for prov in entry.get("provides", []))]
    out.sort(key=lambda e: 0 if e.get("role", "corresponding-source")
             == "corresponding-source" else 1)
    return out


def artifact_for(component: dict, pins: dict) -> dict | None:
    """The primary corresponding-source artifact, or None."""
    found = artifacts_for(component, pins)
    return found[0] if found else None


def correspondence_for(component: dict, entries: list[dict]) -> tuple[str, str]:
    """(correspondence, detail) — how exactly the retained source matches the binary.

    Never claim more than the evidence supports. `distro-exact` is only returned
    when a retained packaging artifact is pinned to the SAME distribution build
    reference the image's own package database records — for Alpine that is the
    aports commit in the apk database, which the SBOM carries verbatim. Anything
    less is `upstream-release`: the right program at the right version, but not
    proof that this is the tree the distribution built.
    """
    claims = [e for e in entries if e.get("role") == "distro-packaging"]
    if not claims:
        return ("upstream-release",
                ("the upstream release for this version is retained; no artifact "
                 "pins the distribution's own packaging, so exact correspondence "
                 "with the distribution build is NOT asserted"))
    want = component.get("distro_build_ref", "")
    for e in claims:
        have = (e.get("distro_package") or {}).get("build_ref", "")
        if want and have and want == have:
            return ("distro-exact",
                    (f"the retained packaging artifact is pinned to the same "
                     f"distribution build reference the image records ({have})"))
    if not want:
        return ("distro-packaging-unverified",
                ("packaging is retained, but the image records no distribution "
                 "build reference to check it against"))
    return ("distro-packaging-mismatch",
            (f"the image was built from distribution reference {want}, which no "
             f"retained packaging artifact matches"))


def deferred_for(component: dict, pins: dict) -> dict | None:
    """A recorded, version-pinned posture for an obligation with no artifact yet.

    Pinned to the exact package version on purpose: a base-image bump changes the
    version, the record stops matching, and the gate fails until a human looks
    again. A blanket rule would have hidden exactly the class of defect that
    produced tracker 238.
    """
    for entry in pins.get("deferred", []):
        if entry["component"] != component["name"]:
            continue
        if entry["version"] != component["version"]:
            continue
        if entry.get("package_type") and entry["package_type"] != component["package_type"]:
            continue
        if "posture" not in entry and pins.get("deferred_posture"):
            entry = dict(entry, posture=pins["deferred_posture"])
        return entry
    return None


def verify_artifact(entry: dict, source_dir: str | None) -> tuple[str, str, str]:
    """(status, path, measured_sha256) for a retained artifact.

    A pin is a promise; a file whose bytes hash to the pinned digest is the
    proof. Upstream availability is neither, and never reaches `verified`.
    """
    if not source_dir:
        return (STATUS_PINNED, "",
                ("no retained-source directory was supplied, so the pinned "
                 "artifact was not materialised and could not be verified"))
    # `file` is validated on load (no separator, no leading dot), so this cannot
    # traverse out of the retained-source directory.
    path = os.path.join(source_dir, entry["file"])
    if not os.path.isfile(path):
        return (STATUS_MISSING, path,
                f"{entry['file']} is not present in {source_dir}")
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError as exc:
        # An artifact that EXISTS but cannot be read is not a component-level
        # verdict — it means this evaluation cannot determine compliance at all.
        # Returning `invalid` would report a specific finding we did not
        # actually establish; aborting by name is the honest, fail-closed answer
        # (scripts/CLAUDE.md §16.1).
        raise ComplianceError(
            f"cannot read the retained source artifact {path}: {exc}") from exc
    got = h.hexdigest()
    if got != entry["sha256"]:
        return (STATUS_INVALID, path,
                f"sha256 mismatch: pinned {entry['sha256']}, measured {got}")
    return (STATUS_VERIFIED, path, got)


# ── evaluation ───────────────────────────────────────────────────────────────
def evaluate(components: list[dict], pins: dict, *, source_dir: str | None,
             facts: dict[str, dict[str, str]] | None = None,
             first_party: list[str] | None = None) -> list[dict]:
    """Normalized components → compliance records."""
    facts = facts or {}
    first_party = first_party or []
    records: list[dict] = []
    for c in components:
        licenses_raw = list(c["licenses_raw"])
        license_source = "image scan"

        if is_first_party(c, first_party):
            # Correlix's own code. Its corresponding source IS this repository;
            # it is not third-party software with an obligation to discharge.
            c = dict(c, origin=ORIGIN_FIRST_PARTY,
                     origin_reason="Correlix's own module, built from this repository")
            rec = dict(c)
            rec["license"] = "Apache-2.0"
            rec["license_confidence"] = "first-party"
            rec["license_source"] = "licensing-policy.json (Correlix core)"
            rec["source_required"] = False
            rec["policy_reason"] = ("first-party Correlix code; the corresponding "
                                    "source is this repository")
            rec["source_status"] = STATUS_NOT_REQUIRED
            rec["source_artifact"] = ""
            rec["source_sha256"] = ""
            rec["correspondence"] = ""
            rec.pop("licenses_raw", None)
            rec.pop("license_expressions", None)
            records.append(rec)
            continue

        if c.get("component_kind") == "operating-system":
            # The SBOM's distribution marker ("alpine 3.21.3", "debian 12"), not a
            # shipped software package: every package the distribution actually
            # put in the image is inventoried individually above. Stated as an
            # explicit rule rather than dropped, so the row stays visible and the
            # reason is auditable.
            rec = dict(c)
            rec["license"] = ""
            rec["license_confidence"] = "operating-system-marker"
            rec["license_source"] = license_source
            rec["source_required"] = False
            rec["policy_reason"] = ("distribution marker, not a distributed "
                                    "package; its packages are inventoried "
                                    "individually")
            rec["source_status"] = STATUS_NOT_REQUIRED
            rec["source_artifact"] = ""
            rec["source_sha256"] = ""
            rec["correspondence"] = ""
            rec.pop("licenses_raw", None)
            rec.pop("license_expressions", None)
            records.append(rec)
            continue

        expressions = list(c["license_expressions"])
        verdict = evaluate_licenses(licenses_raw, expressions)

        # A REVIEWED fact beats an unresolvable scan. Package metadata routinely
        # carries a licence field holding free text, a marketing name, or the
        # entire licence body pasted in — none of which an image scanner can
        # resolve. scripts/license-data.json holds the answer a human already
        # reached for exactly these components; preferring it here is reusing the
        # existing licence system rather than guessing beside it. It is applied
        # ONLY where the scan could not resolve the licence, never to overrule a
        # clean determination.
        if verdict["confidence"] in ("no-license", "unknown-license",
                                     "opaque-expression"):
            eco = _FACT_ECOSYSTEM.get(c["package_type"], "")
            fact = (facts.get(eco) or {}).get(c["name"]) if eco else None
            if fact:
                licenses_raw, expressions = [fact], []
                verdict = evaluate_licenses(licenses_raw, expressions)
                license_source = "scripts/license-data.json (reviewed)"

        rec = dict(c)
        rec["license_source"] = license_source
        rec["license"] = verdict["license"]
        rec["license_confidence"] = verdict["confidence"]
        rec["source_required"] = verdict["source_required"]
        rec["policy_reason"] = verdict["reason"]
        rec.pop("licenses_raw", None)
        rec.pop("license_expressions", None)

        if not verdict["source_required"]:
            rec["source_status"] = STATUS_NOT_REQUIRED
            rec["source_artifact"] = ""
            rec["source_sha256"] = ""
            rec["correspondence"] = ""
            records.append(rec)
            continue

        entries = artifacts_for(c, pins)
        if entries:
            # EVERY matching artifact is verified, not just the primary one: a
            # packaging archive whose bytes do not match its pin is bad bytes we
            # would ship, exactly like a bad tarball.
            results = [verify_artifact(e, source_dir) for e in entries]
            order = [STATUS_VERIFIED, STATUS_PINNED, STATUS_MISSING, STATUS_INVALID]
            status = max((r[0] for r in results), key=order.index)
            corr, corr_detail = correspondence_for(c, entries)
            rec["source_status"] = status
            rec["source_artifact"] = f"source-offer/{entries[0]['file']}"
            rec["source_sha256"] = entries[0]["sha256"]
            rec["source_url"] = entries[0]["url"]
            rec["source_artifacts"] = [
                {"file": f"source-offer/{e['file']}", "sha256": e["sha256"],
                 "url": e["url"], "role": e.get("role", "corresponding-source"),
                 "status": res[0], "detail": res[2]}
                for e, res in zip(entries, results)
            ]
            rec["correspondence"] = corr
            rec["correspondence_detail"] = corr_detail
            rec["source_detail"] = "; ".join(r[2] for r in results)
            records.append(rec)
            continue

        rec["source_artifact"] = ""
        rec["source_sha256"] = ""
        rec["correspondence"] = ""
        rec["source_status"] = (
            STATUS_MANUAL_REVIEW if verdict["confidence"] in
            ("license-list", "unknown-license", "family-unspecified",
             "opaque-expression", "no-license")
            else STATUS_UNKNOWN)
        record = deferred_for(c, pins)
        if record:
            rec["deferred"] = True
            rec["deferred_posture"] = record.get("posture", "")
            rec["deferred_tracker"] = record.get("tracker", "")
            if rec["source_status"] == STATUS_UNKNOWN:
                rec["source_status"] = STATUS_MISSING
        else:
            rec["deferred"] = False
            rec["source_status"] = (
                STATUS_MISSING if verdict["confidence"] == "expression"
                else rec["source_status"])
        records.append(rec)
    return records


def violations(records: list[dict], *, release: bool) -> list[dict]:
    """Violations, each as {kind, component, status, text}. Empty list = PASS.

    `missing` and `invalid` fail everywhere. A RECORDED posture (`deferred`) is
    reported on every run and fails only a production release, which is the
    existing project convention for an acknowledged, owner-owned finding: failing
    daily builds on it teaches people to switch the gate off.

    The `kind` is a short, stable classification so the verdict LINE can name
    what went wrong. A red job whose one-line summary says only "82 VIOLATION(S)"
    forces a reader into the full log to learn whether the finding is a bad
    checksum or a scanner artefact.
    """
    out: list[dict] = []

    def add(r: dict, kind: str, reason: str) -> None:
        out.append({
            "kind": kind,
            "component": f"{r['name']} {r['version']}".strip(),
            "status": r["source_status"],
            "text": _failure_text(r, reason),
        })

    for r in records:
        if not r.get("source_required"):
            continue
        status = r["source_status"]
        if status in (STATUS_VERIFIED, STATUS_NOT_REQUIRED):
            continue
        recorded = r.get("deferred")
        if status == STATUS_PINNED:
            if release:
                add(r, "pinned-not-materialised",
                    "A corresponding-source artifact is pinned for this "
                    "component but was not materialised for this evaluation, "
                    "so its checksum could not be verified. A production "
                    "release must verify the bytes it ships.")
            continue
        if recorded and not release:
            continue
        if recorded:
            add(r, "recorded-posture-unretained",
                "Corresponding source is required. Correlix has RECORDED a "
                "posture for this component (scripts/source-mirror.json "
                f"`deferred`, tracker {r.get('deferred_tracker', '238')}) but "
                "has NOT produced a retained source artifact. A recorded "
                "posture is not a verified artifact and does not satisfy a "
                "production release.")
            continue
        add(r, f"no-artifact:{status}",
            "Corresponding source is required but no verified Correlix source "
            "artifact exists, and no reviewed posture is recorded for it. "
            "Upstream availability alone does not satisfy Correlix release "
            "policy. Add a `components` entry (with `provides`) to "
            "scripts/source-mirror.json, or record the posture in `deferred`.")
    return out


def failures(records: list[dict], *, release: bool) -> list[str]:
    """The violation TEXTS. Empty list = PASS. See `violations`."""
    return [v["text"] for v in violations(records, release=release)]


def _failure_text(r: dict, reason: str) -> str:
    return (
        "OCI compliance failure\n"
        f"  Image     : {r['image']}@{r['image_digest']}\n"
        f"  Component : {r['name']} {r['version']}"
        f"{' (source package ' + r['source_package'] + ')' if r['source_package'] != r['name'] else ''}\n"
        f"  License   : {r['license'] or '<none recorded>'} "
        f"[{r['license_confidence']}]\n"
        f"  Origin    : {r['origin']}\n"
        f"  Status    : {r['source_status']}\n"
        f"  Reason    : {reason}")


# ── manifest ─────────────────────────────────────────────────────────────────
def build_manifest(image: str, digest: str, records: list[dict], *,
                   sbom_path: str, sbom_meta: dict, base_layers: set[str] | None,
                   source_dir: str | None,
                   file_entries: list[dict] | None = None) -> dict:
    tools = []
    for t in ((sbom_meta.get("tools") or {}).get("components")
              if isinstance(sbom_meta.get("tools"), dict) else sbom_meta.get("tools")) or []:
        if isinstance(t, dict) and t.get("name"):
            tools.append(f"{t['name']} {t.get('version', '')}".strip())
    counts: dict[str, int] = {}
    for r in records:
        counts[r["source_status"]] = counts.get(r["source_status"], 0) + 1
    return {
        "schema_version": SCHEMA_VERSION,
        "generated": os.environ.get("SOURCE_DATE_EPOCH")
        and _dt.datetime.fromtimestamp(
            int(os.environ["SOURCE_DATE_EPOCH"]), _dt.timezone.utc).isoformat()
        or _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat(),
        "image": image,
        "image_digest": digest,
        "sbom": os.path.basename(sbom_path),
        "sbom_tools": sorted(set(tools)),
        "base_layers_known": base_layers is not None,
        "retained_source_dir": source_dir or "",
        "component_count": len(records),
        "status_counts": dict(sorted(counts.items())),
        # File entries are excluded from the evaluation (see `is_file_entry`) and
        # listed here rather than dropped: an exclusion nobody can see is
        # indistinguishable from a scanner that lost them.
        "file_entry_count": len(file_entries or []),
        "skipped_file_entries": sorted(file_entries or [],
                                       key=lambda e: e.get("name", "")),
        "components": sorted(
            records, key=lambda r: (r["name"].lower(), r["version"])),
    }


def write_manifest(manifest: dict, path: str) -> None:
    """Write the compliance manifest. A manifest we could not write is a release
    we cannot evidence, so this aborts by name rather than warning and carrying
    on with an exit code that says PASS (scripts/CLAUDE.md §16.1)."""
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2, sort_keys=False)
            fh.write("\n")
    except OSError as exc:
        raise ComplianceError(f"cannot write the compliance manifest {path}: {exc}") from exc


def merge_inventory(manifests: list[dict]) -> dict:
    """Many per-image manifests → the committed inventory license-audit.py reads.

    Keyed by (name, version, license) so the SAME component in several images is
    one inventory row that names every image and digest it was found in — dedup
    with digest traceability — while two different versions stay two rows.
    """
    rows: dict[tuple[str, str, str], dict] = {}
    for m in manifests:
        for c in m["components"]:
            key = (c["name"], c["version"], c["license"])
            row = rows.get(key)
            if row is None:
                row = {
                    "name": c["name"],
                    "version": c["version"],
                    "license": c["license"],
                    "license_confidence": c["license_confidence"],
                    "package_type": c["package_type"],
                    "source_package": c["source_package"],
                    "purl": c["purl"],
                    "supplier": c.get("supplier", ""),
                    "origin": c["origin"],
                    "source_required": c["source_required"],
                    "source_status": c["source_status"],
                    "recorded_posture": bool(c.get("deferred")),
                    "source_artifact": c.get("source_artifact", ""),
                    "source_sha256": c.get("source_sha256", ""),
                    "correspondence": c.get("correspondence", ""),
                    "images": [],
                }
                rows[key] = row
            row["images"].append({"image": m["image"], "digest": m["image_digest"]})
            row["recorded_posture"] = row["recorded_posture"] or bool(c.get("deferred"))
            # Worst status wins, so a component verified in one image and missing
            # in another cannot be reported as clean.
            order = [STATUS_NOT_REQUIRED, STATUS_VERIFIED, STATUS_PINNED,
                     STATUS_MANUAL_REVIEW, STATUS_UNKNOWN, STATUS_MISSING,
                     STATUS_INVALID]
            if order.index(c["source_status"]) > order.index(row["source_status"]):
                row["source_status"] = c["source_status"]
            if c["origin"] != row["origin"]:
                row["origin"] = (ORIGIN_INHERITED
                                 if ORIGIN_INHERITED in (c["origin"], row["origin"])
                                 else ORIGIN_UNKNOWN)
    for row in rows.values():
        row["images"] = sorted(
            {(i["image"], i["digest"]) for i in row["images"]})
        row["images"] = [{"image": a, "digest": b} for a, b in row["images"]]
    return {
        "schema_version": SCHEMA_VERSION,
        "generated": _dt.datetime.now(_dt.timezone.utc).replace(
            microsecond=0).isoformat() if not os.environ.get("SOURCE_DATE_EPOCH")
        else _dt.datetime.fromtimestamp(
            int(os.environ["SOURCE_DATE_EPOCH"]), _dt.timezone.utc).isoformat(),
        "_comment": [
            "GENERATED by scripts/oci-compliance.py --emit-inventory. Do not hand-edit.",
            "",
            "The authoritative container-compliance inventory: what is actually IN",
            "the Correlix images we distribute, read from a CycloneDX SBOM of each",
            "FINAL image rather than from the Dockerfiles that produced it. This is",
            "the file that lets scripts/license-audit.py see software that arrived",
            "inside an inherited base-image layer and was never named by us.",
            "",
            "THE DIGESTS BELOW IDENTIFY THE IMAGES THIS SNAPSHOT WAS TAKEN FROM —",
            "images built from this tree's Dockerfiles on the machine that ran the",
            "scan. They are NOT release digests. The authoritative evaluation for a",
            "release runs in .github/workflows/publish-images.yml against the digest",
            "actually pushed to the registry; this file is the offline copy that lets",
            "scripts/license-audit.py and the generated notices see inherited-layer",
            "software without a Docker daemon.",
            "",
            "Regenerate with scripts/oci-compliance.py; see",
            "docs/compliance/OCI_SOURCE_COMPLIANCE.md for the whole chain.",
        ],
        "images": sorted({(m["image"], m["image_digest"]) for m in manifests}) and
        [{"image": a, "digest": b}
         for a, b in sorted({(m["image"], m["image_digest"]) for m in manifests})],
        "components": sorted(rows.values(),
                             key=lambda r: (r["name"].lower(), r["version"])),
    }


def propose_deferred(records: list[dict], today: str) -> list[dict]:
    """Register entries a human should review, for obligations with no artifact."""
    out = []
    for r in sorted(records, key=lambda x: (x["name"].lower(), x["version"])):
        if not r.get("source_required") or r.get("deferred"):
            continue
        if r["source_status"] in (STATUS_VERIFIED, STATUS_PINNED, STATUS_NOT_REQUIRED):
            continue
        out.append({
            "component": r["name"],
            "version": r["version"],
            "package_type": r["package_type"],
            "license": r["license"] or "UNDETERMINED",
            "license_confidence": r["license_confidence"],
            "origin": r["origin"],
            "images": [r["image"]],
            "recorded": today,
        })
    return out


# ── selftest ─────────────────────────────────────────────────────────────────
def selftest() -> int:
    fails: list[str] = []
    ran = 0

    def check(label: str, got: Any, want: Any) -> None:
        nonlocal ran
        ran += 1
        if got != want:
            fails.append(f"{label}: got {got!r}, want {want!r}")

    check("apk upstream", upstream_version("1.37.0-r12", "apk"), "1.37.0")
    check("apk no rev", upstream_version("1.37.0", "apk"), "1.37.0")
    check("deb epoch+rev", upstream_version("1:2.41-5", "deb"), "2.41")
    check("deb dfsg", upstream_version("2:6.3.0+dfsg-3", "deb"), "6.3.0")
    check("unknown type", upstream_version("v1.2.3", "golang"), "v1.2.3")

    check("purl type", parse_purl("pkg:apk/alpine/busybox@1.37.0-r12?arch=x86_64")["type"], "apk")
    check("purl name", parse_purl("pkg:apk/alpine/busybox@1.37.0-r12")["name"], "busybox")
    check("purl ver", parse_purl("pkg:apk/alpine/busybox@1.37.0-r12")["version"], "1.37.0-r12")
    check("purl qual", parse_purl("pkg:apk/alpine/x@1?upstream=busybox")["qualifiers"]["upstream"], "busybox")

    check("gpl requires source", evaluate_licenses(["GPL-2.0-only"], [])["source_required"], True)
    check("mit does not", evaluate_licenses(["MIT"], [])["source_required"], False)
    check("or permissive branch",
          evaluate_licenses([], ["BSD-3-Clause OR GPL-2.0-or-later"])["source_required"], False)
    check("or both copyleft",
          evaluate_licenses([], ["GPL-2.0-or-later OR LGPL-3.0-or-later"])["source_required"], True)
    check("and with copyleft",
          evaluate_licenses([], ["MIT AND GPL-2.0-or-later"])["source_required"], True)
    check("license list is manual review",
          evaluate_licenses(["MIT", "GPL-2.0-only"], [])["confidence"], "license-list")
    check("license list still obligated",
          evaluate_licenses(["MIT", "GPL-2.0-only"], [])["source_required"], True)
    check("no licence is not a pass",
          evaluate_licenses([], [])["source_required"], True)
    check("unknown id is not a pass",
          evaluate_licenses(["WeirdLicense-9"], [])["source_required"], True)
    check("bare GPL is family-unspecified",
          evaluate_licenses(["GPL"], [])["confidence"], "family-unspecified")

    pins = {"components": [{
        "name": "busybox", "version": "1.37.0", "file": "busybox-1.37.0.tar.bz2",
        "url": "https://example.invalid/x", "sha256": "0" * 64,
        "license": "GPL-2.0-only", "correspondence": "distro-exact",
        "provides": [{"package_type": "apk", "source_package": "busybox",
                      "upstream_version": "1.37.0"}],
    }]}
    bb = {"name": "busybox-binsh", "package_type": "apk",
          "source_package": "busybox", "upstream_version": "1.37.0"}
    check("subpackage matches origin artifact", artifact_for(bb, pins) is not None, True)
    pins2 = {"components": pins["components"] + [{
        "name": "busybox", "version": "1.37.0-r12",
        "file": "busybox-1.37.0-r12-alpine-aports.tar.gz",
        "url": "https://example.invalid/y", "sha256": "1" * 64,
        "license": "GPL-2.0-only", "role": "distro-packaging",
        "distro_package": {"build_ref": "cafe"},
        "provides": [{"package_type": "apk", "source_package": "busybox",
                      "upstream_version": "1.37.0"}],
    }]}
    check("two artifacts serve one component", len(artifacts_for(bb, pins2)), 2)
    check("primary is the source tarball",
          artifacts_for(bb, pins2)[0]["role" if "role" in artifacts_for(bb, pins2)[0] else "name"],
          "busybox")
    check("distro-exact needs a matching build ref",
          correspondence_for(dict(bb, distro_build_ref="cafe"),
                             artifacts_for(bb, pins2))[0], "distro-exact")
    check("wrong build ref is not exact",
          correspondence_for(dict(bb, distro_build_ref="beef"),
                             artifacts_for(bb, pins2))[0], "distro-packaging-mismatch")
    check("no packaging artifact is upstream-release only",
          correspondence_for(dict(bb, distro_build_ref="cafe"),
                             artifacts_for(bb, pins))[0], "upstream-release")
    other = dict(bb, upstream_version="1.36.1")
    check("other version does not match", artifact_for(other, pins), None)
    wrong_type = dict(bb, package_type="deb")
    check("other ecosystem does not match", artifact_for(wrong_type, pins), None)

    check("first party by exact module",
          is_first_party({"name": "netops/backend"}, ["netops/backend"]), True)
    check("first party by prefix",
          is_first_party({"name": "netops/backend/internal/rca"}, ["netops/backend"]), True)
    check("prefix is not a substring match",
          is_first_party({"name": "netops/backendish"}, ["netops/backend"]), False)
    check("no prefixes claims nothing",
          is_first_party({"name": "netops/backend"}, []), False)

    # File entries: a scanner-shape difference must not read as a compliance
    # finding, and must not hide a package either.
    file_comp = {"bom-ref": "f1", "type": "file", "name": "/etc/securetty"}
    untyped_file = {"bom-ref": "f2", "name": "/lib/ld-musl-x86_64.so.1"}
    pkg = {"bom-ref": "p1", "type": "library", "name": "busybox",
           "version": "1.37.0-r12",
           "purl": "pkg:apk/alpine/busybox@1.37.0-r12"}
    versionless_pkg = {"bom-ref": "p2", "type": "library", "name": "openssl"}
    check("typed file entry is a file", is_file_entry(file_comp), True)
    check("untyped absolute path is a file", is_file_entry(untyped_file), True)
    check("a package is not a file", is_file_entry(pkg), False)
    check("a versionless PACKAGE is still a package",
          is_file_entry(versionless_pkg), False)
    check("a path-named entry WITH a version is a package claim",
          is_file_entry({"name": "/opt/vendor/thing", "version": "1.0"}), False)
    pkgs, skipped = split_file_entries(
        [pkg, file_comp, untyped_file, versionless_pkg],
        [{"ref": "p1", "dependsOn": ["f1"]}])
    check("packages survive the split", [c["name"] for c in pkgs],
          ["busybox", "openssl"])
    check("file entries are counted, not dropped", len(skipped), 2)
    check("the SBOM's own relationship names the owner",
          [e["owner_package"] for e in skipped if e["name"] == "/etc/securetty"],
          ["busybox 1.37.0-r12"])
    check("an unstated owner is left empty, never guessed",
          [e["owner_package"] for e in skipped
           if e["name"] == "/lib/ld-musl-x86_64.so.1"], [""])
    try:
        split_file_entries([file_comp], [])
    except ComplianceError:
        check("files with no package inventory cannot be evaluated", True, True)
    else:
        check("files with no package inventory cannot be evaluated", False, True)

    # A package with NO licence still fails closed — the file-entry skip must not
    # become a way for an unlicensed package to slip through.
    unlicensed = normalize_component(
        {"type": "library", "name": "mystery", "version": "1.0",
         "purl": "pkg:apk/alpine/mystery@1.0"},
        image="i", image_digest="sha256:" + "0" * 64, base_layers=None)
    rec = evaluate([unlicensed], {"components": [], "deferred": []},
                   source_dir=None)[0]
    check("a package with no licence still requires source",
          rec["source_required"], True)
    check("a package with no licence is a violation",
          [v["kind"] for v in violations([rec], release=False)],
          ["no-artifact:manual-review"])

    if fails:
        for f in fails:
            print(f"selftest FAIL: {f}", file=sys.stderr)
        return 1
    print(f"oci-compliance: selftest OK ({ran} checks)")
    return 0


# ── cli ──────────────────────────────────────────────────────────────────────
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sbom", help="CycloneDX SBOM of a FINAL OCI image")
    ap.add_argument("--image", help="image name the SBOM describes")
    ap.add_argument("--digest", help="the image's immutable digest (sha256:…)")
    ap.add_argument("--base-layers", help="file of the pinned base image's diff-ids")
    ap.add_argument("--source-dir", help="directory of retained source artifacts "
                                         "(the bundle's source-offer/)")
    ap.add_argument("--pins", help="pin table (default scripts/source-mirror.json)")
    ap.add_argument("--license-facts",
                    help="reviewed licence facts for components an image scan "
                         "cannot resolve (default scripts/license-data.json)")
    ap.add_argument("--first-party", action="append", default=[],
                    help="module path prefix that is Correlix's own code "
                         "(default: the `module` line of src/backend/go.mod)")
    ap.add_argument("--manifest", help="write the compliance manifest here")
    ap.add_argument("--release", action="store_true",
                    help="production-release mode: a recorded-but-unretained "
                         "obligation FAILS")
    ap.add_argument("--record-deferred", action="store_true",
                    help="print register entries for obligations with no artifact")
    ap.add_argument("--emit-inventory", help="merge --manifest-in files into the "
                                             "committed OCI inventory")
    ap.add_argument("--manifest-in", action="append", default=[],
                    help="a manifest to merge (repeatable)")
    ap.add_argument("--quiet", action="store_true", help="only print the verdict")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    try:
        if args.emit_inventory:
            if not args.manifest_in:
                raise ComplianceError("--emit-inventory needs at least one --manifest-in")
            manifests = [read_json(p, what="compliance manifest") for p in args.manifest_in]
            inv = merge_inventory(manifests)
            write_manifest(inv, args.emit_inventory)
            print(f"oci-compliance: wrote {args.emit_inventory} "
                  f"({len(inv['components'])} components, {len(inv['images'])} image(s))")
            return 0

        missing = [f for f, v in (("--sbom", args.sbom), ("--image", args.image),
                                  ("--digest", args.digest)) if not v]
        if missing:
            raise ComplianceError(f"missing required argument(s): {', '.join(missing)}")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.digest):
            raise ComplianceError(
                f"--digest {args.digest!r} is not an immutable image digest. "
                f"Compliance is tied to image@sha256:<digest>; a mutable tag is "
                f"metadata, never identity.")

        pins = load_pin_table(args.pins)
        raw, meta, deps = parse_sbom(args.sbom)
        # Which entries a scan contains is a property of the scanner: a file
        # entry is a file inside a package this same document already
        # inventories, not an independently licensed work. Split them out here
        # (they are reported, never dropped) so the policy evaluates packages.
        raw, file_entries = split_file_entries(raw, deps)
        base_layers = load_base_layers(args.base_layers)
        norm = [normalize_component(c, image=args.image, image_digest=args.digest,
                                    base_layers=base_layers) for c in raw]
        records = evaluate(norm, pins, source_dir=args.source_dir,
                           facts=load_license_facts(args.license_facts),
                           first_party=first_party_prefixes(args.first_party))
    except ComplianceError as exc:
        print(f"oci-compliance: CANNOT RUN: {exc}", file=sys.stderr)
        return 2

    try:
        manifest = build_manifest(args.image, args.digest, records,
                                  sbom_path=args.sbom, sbom_meta=meta,
                                  base_layers=base_layers,
                                  source_dir=args.source_dir,
                                  file_entries=file_entries)
        if args.manifest:
            write_manifest(manifest, args.manifest)
    except ComplianceError as exc:
        print(f"oci-compliance: CANNOT RUN: {exc}", file=sys.stderr)
        return 2

    if args.record_deferred:
        today = _dt.datetime.now(_dt.timezone.utc).date().isoformat()
        print(json.dumps(propose_deferred(records, today), indent=2))

    problems = violations(records, release=args.release)

    if not args.quiet:
        counts = manifest["status_counts"]
        print(f"oci-compliance: {args.image}@{args.digest}")
        # One line a red job is diagnosable from: the counts, how many entries
        # were file entries rather than packages, and WHAT the first violation
        # is — not just how many there are.
        summary = (f"  {manifest['component_count']} components  "
                   + "  ".join(f"{k}={v}" for k, v in counts.items())
                   + f"  files={manifest['file_entry_count']}")
        if problems:
            summary += (f"  first-violation={problems[0]['kind']}"
                        f" ({problems[0]['component']})")
        print(summary)
        if file_entries:
            print(f"  {len(file_entries)} file entr"
                  f"{'y' if len(file_entries) == 1 else 'ies'} skipped: a file "
                  f"inside an inventoried package is not an independently "
                  f"licensed component (listed in the manifest under "
                  f"`skipped_file_entries`)")
            for e in file_entries[:10]:
                owner = e["owner_package"] or "owning package not stated by the SBOM"
                print(f"    - {e['name']}  [{owner}]")
            if len(file_entries) > 10:
                print(f"    … and {len(file_entries) - 10} more")
        if base_layers is None:
            print("  ! base-image layer set not supplied — component origin is "
                  "reported as `unknown` rather than guessed")
        inherited = [r for r in records if r["origin"] == ORIGIN_INHERITED
                     and r.get("source_required")]
        if inherited:
            print(f"  {len(inherited)} inherited-base-layer component(s) carry a "
                  f"corresponding-source obligation:")
            for r in sorted(inherited, key=lambda x: x["name"]):
                print(f"    - {r['name']} {r['version']} [{r['license']}] "
                      f"→ {r['source_status']}")

    recorded = [r for r in records if r.get("deferred")]
    if recorded and not args.release:
        print(f"\noci-compliance: {len(recorded)} RECORDED source obligation(s) "
              f"with no retained artifact (not a build failure here; these FAIL "
              f"`--release`):")
        for r in sorted(recorded, key=lambda x: x["name"])[:200]:
            print(f"  ! {r['name']} {r['version']} [{r['license']}] "
                  f"tracker {r.get('deferred_tracker', '238')}")
        print("  see docs/compliance/OCI_SOURCE_COMPLIANCE.md\n")

    if problems:
        # BOTH streams. The GitHub log interleaves them, but a caller that
        # captures only stdout (a wrapper, a report, a pipe) used to see the
        # verdict with none of the findings — a violation nobody can read is a
        # silent failure with extra steps (scripts/CLAUDE.md §16.1).
        headline = (f"\noci-compliance: {len(problems)} VIOLATION(S) "
                    f"(first: {problems[0]['kind']} — {problems[0]['component']})")
        for stream in (sys.stdout, sys.stderr):
            print(headline, file=stream)
            for p in problems:
                print(p["text"], file=stream)
                print(file=stream)
        return 1
    print("oci-compliance: PASS — every corresponding-source obligation in this "
          "image is satisfied by a retained artifact or a recorded posture")
    return 0


if __name__ == "__main__":
    sys.exit(main())
