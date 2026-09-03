#!/usr/bin/env python3
"""Generate the CycloneDX software bill of materials for Correlix.

SC-006 asks for an SBOM. `supply-chain.yml` already produces one with Trivy, but
only as an EPHEMERAL CI artifact that expires with the workflow run — you cannot
diff it, cite it in a release, or hand it to a customer who asks what is in the
appliance. This script writes a COMMITTED SBOM under `docs/sbom/`, so "what
shipped in v0.9.0" is answerable from the tag alone, and so a component appearing
or changing version shows up as a reviewable line in a pull request.

It is not a replacement for the Trivy scan (which resolves CVEs); it is the
inventory the scan is run against.

FIVE DEPENDENCY CLASSES, read from the files that actually pin them:

  go-backend         src/backend/vendor/modules.txt + go.mod  (9 vendored modules
                     + the toolchain; `direct` is taken from go.mod's require
                     blocks, so the CLAUDE.md §6 allowlist is legible in the SBOM)
  npm-frontend       src/frontend/package-lock.json
  npm-docs-portal    docs-portal/package-lock.json
  pip-correlation    src/correlation/requirements.txt  (hash-locked; the
                     --generate-hashes digests become CycloneDX hashes)
  container-images   every `image:` in deployment/docker/*compose*.yml and every
                     `FROM` in every Dockerfile, digest-pinned or not

plus `correlix.cdx.json`, the merged document.

DETERMINISM IS A FEATURE. A committed SBOM that churns on every run is noise
nobody reads, and noise nobody reads is how a real change slips through. So:

  * components are sorted by bom-ref;
  * the timestamp and version come from the last commit that touched a
    DEPENDENCY INPUT (see INPUT_PATHS), never from HEAD and never from "now" —
    an SBOM keyed to HEAD would churn on every unrelated commit;
  * image origins name `file(service)`, not `file:line`, because a line number
    moves when an unrelated service is edited above it;
  * the serial number is derived from a hash of the component set.

`--check` compares the COMPONENT SET, not the metadata. That is the distinction
that matters: it must fail when the inventory no longer describes the tree, and
it must NOT fail merely because the document was last regenerated at a different
commit. SOURCE_DATE_EPOCH overrides the timestamp for a reproducible build.

Pure standard library — no `cyclonedx-bom`, no `pip install` (CLAUDE.md §6).

USAGE
    python3 scripts/sbom.py                      # write docs/sbom/
    python3 scripts/sbom.py --out /tmp/sbom      # write elsewhere
    python3 scripts/sbom.py --check              # fail if docs/sbom/ is stale
    python3 scripts/sbom.py --selftest           # parser self-tests, no writes
    python3 scripts/sbom.py --print go-backend   # one document to stdout

EXIT CODES
    0  success (or --check found no drift)
    1  drift (--check), or a selftest failure
    2  usage / a required input file is missing
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime as _dt
import hashlib
import json
import os
import re
import subprocess  # nosec B404 - fixed argv, no shell; see _git()
import sys
import uuid
from collections.abc import Iterable
from pathlib import Path
from typing import Any

# scripts/sbom.py -> NetOps_Observability/
ROOT = Path(__file__).resolve().parents[1]

SPEC_VERSION = "1.6"
TOOL_NAME = "correlix-sbom"
TOOL_VERSION = "1.0.0"

# The five documents, in the order they are written and merged.
CLASSES = (
    "go-backend",
    "npm-frontend",
    "npm-docs-portal",
    "pip-correlation",
    "container-images",
)
AGGREGATE = "correlix"

# Compose files are matched the way Renovate's docker-compose manager does, so
# the SBOM and the patch train never disagree about which files hold image pins.
_COMPOSE_RE = re.compile(r"^(?:docker-)?compose[^/]*\.ya?ml$")
_IMAGE_RE = re.compile(r"^\s{2,}image:\s*(?P<ref>\S+)\s*$")
_FROM_RE = re.compile(r"^FROM\s+(?P<ref>\S+)", re.IGNORECASE)
_SERVICE_RE = re.compile(r"^  (?P<name>[A-Za-z0-9_.-]+):\s*$")

_MODULE_RE = re.compile(r"^# (?P<mod>\S+) (?P<ver>\S+)$")
_REQUIRE_LINE_RE = re.compile(r"^\s*(?P<mod>[^\s/]+\S*)\s+(?P<ver>v\S+)")
_GO_DIRECTIVE_RE = re.compile(r"^go\s+(?P<ver>\S+)$")
_TOOLCHAIN_RE = re.compile(r"^toolchain\s+go(?P<ver>\S+)$")

_PIP_PIN_RE = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)==(?P<ver>[^\s\\]+)")
_PIP_HASH_RE = re.compile(r"^\s+--hash=sha256:(?P<hex>[0-9a-f]{64})")


class SbomError(Exception):
    """A required input is missing or unparseable. Never swallowed (§16.1)."""


# --------------------------------------------------------------------------- #
# purl / helpers
# --------------------------------------------------------------------------- #

_PURL_SAFE = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_~"


def purl_quote(text: str) -> str:
    """Percent-encode a purl segment, leaving '/' as the namespace separator."""
    out = []
    for ch in text:
        if ch in _PURL_SAFE or ch == "/":
            out.append(ch)
        else:
            out.extend(f"%{b:02X}" for b in ch.encode("utf-8"))
    return "".join(out)


def _git(*args: str) -> str | None:
    """Run a git command with a fixed argv. Returns None if git cannot answer.

    No shell, no user-supplied arguments (CLAUDE.md §8). A missing git or a
    non-repo directory is an expected condition, not an error — the caller
    falls back — but any OTHER failure is surfaced by returning None and letting
    the caller decide loudly.
    """
    try:
        res = subprocess.run(  # nosec B603 - fixed argv, shell=False
            ["git", "-C", str(ROOT), *args],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        # Not swallowed (§16.1): the reason is named on stderr before the
        # probe answers "no". A missing git or a non-repo directory is an
        # EXPECTED condition the callers already handle by falling back — but a
        # timeout, an exec failure or a resource limit is not, and the operator
        # must be able to tell which of the two produced an unreproducible
        # timestamp or a "0.0.0-unknown" version.
        print(f"sbom: git {' '.join(args)} unavailable: {exc!r}", file=sys.stderr)
        return None
    if res.returncode != 0:
        return None
    return res.stdout.strip() or None


# The files whose CONTENT this SBOM describes. Provenance is derived from the
# last commit that touched one of these, NOT from HEAD: an SBOM keyed to HEAD
# would churn on every unrelated commit, and a committed artifact that changes
# when nothing it describes has changed is noise nobody reads.
INPUT_PATHS = (
    "src/backend/go.mod",
    "src/backend/go.sum",
    "src/backend/vendor/modules.txt",
    "src/frontend/package-lock.json",
    "docs-portal/package-lock.json",
    "src/correlation/requirements.txt",
    "deployment/docker",
)


# Directory NAMES pruned from the Dockerfile walk in collect_images(): every
# one is a gitignored runtime or build-output tree (or a dependency tree with
# its own upstream Dockerfiles that Correlix neither builds nor ships).
SKIP_TREES = frozenset({
    ".git", ".venv", "__pycache__", "backups", "build", "coverage", "data",
    "dist", "node_modules", "test-results", "vendor",
})


def inputs_revision() -> tuple[str, str] | None:
    """(sha, ISO-8601 date) of the last commit touching a dependency input."""
    out = _git(
        "log", "-1", "--format=%H %cI", "--", *[str(ROOT / p) for p in INPUT_PATHS]
    )
    if not out or " " not in out:
        return None
    sha, _, date = out.partition(" ")
    return sha, date


def build_timestamp() -> str:
    """Deterministic ISO-8601 timestamp: SOURCE_DATE_EPOCH, else the inputs rev."""
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch and epoch.isdigit():
        return (
            _dt.datetime.fromtimestamp(int(epoch), tz=_dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
    rev = inputs_revision()
    if rev:
        return rev[1]
    # No git and no SOURCE_DATE_EPOCH: fall back to now, but say so rather than
    # silently emitting a document that will never reproduce (§16.1).
    print(
        "sbom: WARNING no git and no SOURCE_DATE_EPOCH \u2014 timestamp is NOT reproducible",
        file=sys.stderr,
    )
    return _dt.datetime.now(tz=_dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def product_version() -> str:
    """The version this inventory describes.

    A `v*` tag on HEAD wins — that is a release, and the SBOM should say so.
    Otherwise the version names the dependency snapshot (`<date>-g<sha>` of the
    inputs revision), following make-installer.sh's fallback shape so the two
    remain recognisably the same scheme.
    """
    exact = _git("describe", "--tags", "--match", "v[0-9]*", "--exact-match")
    if exact:
        return exact
    rev = inputs_revision()
    if rev:
        return f"{rev[1][:10].replace('-', '.')}-g{rev[0][:8]}"
    return "0.0.0-unknown"


def _read(path: Path) -> str:
    if not path.is_file():
        raise SbomError(f"required input missing: {path}")
    return path.read_text(encoding="utf-8")


def _sha512_hex_from_integrity(integrity: str) -> tuple[str, str] | None:
    """npm 'sha512-<base64>' / 'sha1-<base64>' -> (CycloneDX alg, hex digest)."""
    if "-" not in integrity:
        return None
    alg, _, b64 = integrity.partition("-")
    algs = {"sha512": "SHA-512", "sha256": "SHA-256", "sha1": "SHA-1"}
    if alg not in algs:
        return None
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    return algs[alg], raw.hex()


# --------------------------------------------------------------------------- #
# class: go-backend
# --------------------------------------------------------------------------- #


def _go_direct_modules(gomod_text: str) -> set[str]:
    """Modules required WITHOUT `// indirect` — i.e. the §6 allowlist surface."""
    direct: set[str] = set()
    in_block = False
    for line in gomod_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        if stripped.startswith("//") or not stripped:
            continue
        target = stripped
        if not in_block:
            if not stripped.startswith("require "):
                continue
            target = stripped[len("require ") :].strip()
        if "// indirect" in target:
            continue
        match = _REQUIRE_LINE_RE.match(target)
        if match:
            direct.add(match.group("mod"))
    return direct


def collect_go(root: Path = ROOT) -> list[dict[str, Any]]:
    """Vendored Go modules + the toolchain, from modules.txt and go.mod."""
    backend = root / "src" / "backend"
    gomod_text = _read(backend / "go.mod")
    modules_text = _read(backend / "vendor" / "modules.txt")
    direct = _go_direct_modules(gomod_text)

    components: list[dict[str, Any]] = []

    go_ver = toolchain = None
    for line in gomod_text.splitlines():
        stripped = line.strip()
        if (m := _GO_DIRECTIVE_RE.match(stripped)) and go_ver is None:
            go_ver = m.group("ver")
        elif (m := _TOOLCHAIN_RE.match(stripped)) and toolchain is None:
            toolchain = m.group("ver")
    if toolchain or go_ver:
        version = toolchain or go_ver
        components.append(
            {
                "type": "platform",
                "bom-ref": f"pkg:golang/go@{version}",
                "name": "go",
                "version": str(version),
                "purl": f"pkg:golang/go@{version}",
                "description": "Go toolchain the backend is built with",
                "properties": [
                    _prop("correlix:class", "go-backend"),
                    _prop("correlix:go.mod:go", str(go_ver)),
                    _prop("correlix:go.mod:toolchain", str(toolchain)),
                ],
            }
        )

    for line in modules_text.splitlines():
        match = _MODULE_RE.match(line)
        if not match:
            continue
        mod, ver = match.group("mod"), match.group("ver")
        ref = f"pkg:golang/{purl_quote(mod)}@{ver}"
        components.append(
            {
                "type": "library",
                "bom-ref": ref,
                "name": mod,
                "version": ver,
                "purl": ref,
                "scope": "required",
                "properties": [
                    _prop("correlix:class", "go-backend"),
                    _prop("correlix:vendored", "true"),
                    _prop("correlix:direct", "true" if mod in direct else "false"),
                ],
            }
        )
    if not components:
        raise SbomError("vendor/modules.txt produced no components")
    return components


# --------------------------------------------------------------------------- #
# class: npm
# --------------------------------------------------------------------------- #


def collect_npm(lock_path: Path, class_name: str) -> list[dict[str, Any]]:
    """Every resolved package in an npm lockfile (v2/v3 `packages` map)."""
    data = json.loads(_read(lock_path))
    packages = data.get("packages")
    if not isinstance(packages, dict):
        raise SbomError(f"{lock_path}: no 'packages' map (lockfileVersion >= 2 required)")

    components: list[dict[str, Any]] = []
    for key, meta in packages.items():
        if not key or not isinstance(meta, dict):
            continue  # "" is the root project itself
        name = meta.get("name") or key.rsplit("node_modules/", 1)[-1]
        version = meta.get("version")
        if not version:
            continue  # link:/workspace entries carry no version
        ref = f"pkg:npm/{purl_quote(name)}@{version}"
        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": ref,
            "name": name,
            "version": version,
            "purl": ref,
            "scope": "optional" if meta.get("dev") or meta.get("optional") else "required",
            "properties": [
                _prop("correlix:class", class_name),
                _prop("correlix:dev", "true" if meta.get("dev") else "false"),
            ],
        }
        if isinstance(meta.get("license"), str):
            component["licenses"] = [{"license": {"id": meta["license"]}}]
        integrity = meta.get("integrity")
        if isinstance(integrity, str):
            parsed = _sha512_hex_from_integrity(integrity)
            if parsed:
                component["hashes"] = [{"alg": parsed[0], "content": parsed[1]}]
        components.append(component)
    if not components:
        raise SbomError(f"{lock_path}: produced no components")
    return components


# --------------------------------------------------------------------------- #
# class: pip
# --------------------------------------------------------------------------- #


def collect_pip(req_path: Path, class_name: str) -> list[dict[str, Any]]:
    """Pins from a pip-compile lock, carrying its --generate-hashes digests."""
    text = _read(req_path)
    components: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in text.splitlines():
        if match := _PIP_PIN_RE.match(line):
            name, version = match.group("name"), match.group("ver")
            ref = f"pkg:pypi/{purl_quote(name.lower())}@{version}"
            current = {
                "type": "library",
                "bom-ref": ref,
                "name": name,
                "version": version,
                "purl": ref,
                "scope": "required",
                "properties": [_prop("correlix:class", class_name)],
                "hashes": [],
            }
            components.append(current)
            continue
        if current is not None and (match := _PIP_HASH_RE.match(line)):
            current["hashes"].append({"alg": "SHA-256", "content": match.group("hex")})
    for component in components:
        if not component["hashes"]:
            # A pin without a hash in a --require-hashes lock would fail install;
            # drop the empty key rather than emit a misleading empty array.
            del component["hashes"]
    if not components:
        raise SbomError(f"{req_path}: produced no components")
    return components


# --------------------------------------------------------------------------- #
# class: container images
# --------------------------------------------------------------------------- #


def parse_image_ref(ref: str) -> dict[str, str]:
    """Split `registry/repo:tag@sha256:...` into its parts."""
    digest = ""
    remainder = ref
    if "@" in remainder:
        remainder, _, digest = remainder.partition("@")
    tag = ""
    # A ':' in the final path segment is a tag; a ':' before a '/' is a port.
    head, sep, tail = remainder.rpartition(":")
    if sep and "/" not in tail:
        remainder, tag = head, tail
    return {"repository": remainder, "tag": tag, "digest": digest}


def _image_component(ref: str, class_name: str, origin: str) -> dict[str, Any]:
    parts = parse_image_ref(ref)
    repo, tag, digest = parts["repository"], parts["tag"], parts["digest"]
    version = digest or tag or "latest"

    qualifiers = []
    if "/" in repo:
        qualifiers.append(f"repository_url={purl_quote(repo)}")
    if tag:
        qualifiers.append(f"tag={purl_quote(tag)}")
    name = repo.rsplit("/", 1)[-1]
    query = ("?" + "&".join(qualifiers)) if qualifiers else ""
    ref_purl = f"pkg:oci/{purl_quote(name)}@{purl_quote(version)}{query}"

    component: dict[str, Any] = {
        "type": "container",
        "bom-ref": f"container:{ref}",
        "name": repo,
        "version": version,
        "purl": ref_purl,
        "properties": [
            _prop("correlix:class", class_name),
            _prop("correlix:image:ref", ref),
            _prop("correlix:image:tag", tag or "(none)"),
            _prop("correlix:image:digest-pinned", "true" if digest else "false"),
            _prop("correlix:origin", origin),
        ],
    }
    if digest.startswith("sha256:"):
        component["hashes"] = [{"alg": "SHA-256", "content": digest[len("sha256:") :]}]
    return component


def collect_images(root: Path = ROOT) -> list[dict[str, Any]]:
    """Every image reference in the compose files and every Dockerfile FROM.

    Locally-built images (`netops-*`, no registry) are included and flagged:
    they are not third-party supply chain, but omitting them would make the SBOM
    a partial picture of what actually runs.
    """
    docker_dir = root / "deployment" / "docker"
    if not docker_dir.is_dir():
        raise SbomError(f"required input missing: {docker_dir}")

    seen: dict[str, dict[str, Any]] = {}

    def add(ref: str, origin: str) -> None:
        if ref.startswith("$") or "${" in ref:
            return  # a variable, not a pin
        component = _image_component(ref, "container-images", origin)
        existing = seen.get(component["bom-ref"])
        if existing is None:
            seen[component["bom-ref"]] = component
            return
        # Same image referenced from several files: record every origin so a
        # reviewer can see all the places one pin has to be changed.
        for prop in existing["properties"]:
            if prop["name"] == "correlix:origin" and origin not in prop["value"]:
                prop["value"] = f"{prop['value']},{origin}"

    for path in sorted(docker_dir.glob("*.yml")):
        if not _COMPOSE_RE.match(path.name):
            continue
        service = "?"
        for line in path.read_text(encoding="utf-8").splitlines():
            if match := _SERVICE_RE.match(line):
                service = match.group("name")
            if match := _IMAGE_RE.match(line):
                add(match.group("ref"), f"{path.name}({service})")

    # Bounded walk, NOT `rglob`: the repo carries large gitignored runtime and
    # output trees — data/ (live storage volumes; VictoriaMetrics rewrites files
    # underneath a scan, which once failed a test with FileNotFoundError on a
    # path that existed when it was listed), dist/, backups/, node_modules/,
    # build outputs. None of them holds a Dockerfile this document describes, so
    # they are pruned at the DIRECTORY level: that removes the race and the cost
    # together, instead of catching (and thereby hiding) the resulting error.
    # Paths are sorted globally afterwards, so the document stays byte-stable.
    dockerfiles: list[Path] = []
    for base, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_TREES]
        dockerfiles.extend(
            Path(base) / name for name in filenames if name.startswith("Dockerfile")
        )
    for path in sorted(dockerfiles):
        if not path.is_file():
            continue  # a dangling symlink; the sorted list above is the truth
        rel = path.relative_to(root)
        for line in path.read_text(encoding="utf-8").splitlines():
            if match := _FROM_RE.match(line):
                ref = match.group("ref")
                if ref.lower() == "scratch":
                    continue
                add(ref, str(rel))

    if not seen:
        raise SbomError("no image references found")
    return list(seen.values())


# --------------------------------------------------------------------------- #
# document assembly
# --------------------------------------------------------------------------- #


def _prop(name: str, value: str) -> dict[str, str]:
    return {"name": name, "value": value}


def _sorted(components: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(components, key=lambda c: (c["bom-ref"], c.get("version", "")))


def build_document(
    class_name: str, components: list[dict[str, Any]], timestamp: str, version: str
) -> dict[str, Any]:
    """Wrap components in a CycloneDX 1.6 document with a content-derived serial."""
    ordered = _sorted(components)
    digest = hashlib.sha256(
        json.dumps(ordered, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).digest()
    serial = uuid.UUID(bytes=digest[:16], version=5)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {"type": "application", "name": TOOL_NAME, "version": TOOL_VERSION}
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": f"correlix@{version}#{class_name}",
                "name": "correlix",
                "version": version,
                "description": f"Correlix — {class_name} dependency inventory",
            },
            "properties": [_prop("correlix:class", class_name)],
        },
        "components": ordered,
    }


def collect_all(root: Path = ROOT) -> dict[str, list[dict[str, Any]]]:
    """Every class, keyed by class name. Raises SbomError on a missing input."""
    return {
        "go-backend": collect_go(root),
        "npm-frontend": collect_npm(
            root / "src" / "frontend" / "package-lock.json", "npm-frontend"
        ),
        "npm-docs-portal": collect_npm(
            root / "docs-portal" / "package-lock.json", "npm-docs-portal"
        ),
        "pip-correlation": collect_pip(
            root / "src" / "correlation" / "requirements.txt", "pip-correlation"
        ),
        "container-images": collect_images(root),
    }


def render(root: Path = ROOT) -> dict[str, str]:
    """Build every document. Returns {filename: json text}, newline-terminated."""
    timestamp = build_timestamp()
    version = product_version()
    by_class = collect_all(root)

    out: dict[str, str] = {}
    merged: dict[str, dict[str, Any]] = {}
    for class_name in CLASSES:
        components = by_class[class_name]
        out[f"{class_name}.cdx.json"] = (
            json.dumps(
                build_document(class_name, components, timestamp, version),
                indent=2,
                sort_keys=False,
            )
            + "\n"
        )
        for component in components:
            merged.setdefault(component["bom-ref"], component)

    out[f"{AGGREGATE}.cdx.json"] = (
        json.dumps(
            build_document(AGGREGATE, list(merged.values()), timestamp, version),
            indent=2,
            sort_keys=False,
        )
        + "\n"
    )
    return out


# --------------------------------------------------------------------------- #
# selftest
# --------------------------------------------------------------------------- #


def selftest() -> int:
    """Parser assertions against literal fixtures. No filesystem, no network."""
    failures: list[str] = []

    def check(label: str, got: Any, want: Any) -> None:
        if got != want:
            failures.append(f"{label}: got {got!r}, want {want!r}")

    check(
        "image: digest+tag",
        parse_image_ref("postgres:16-alpine@sha256:" + "a" * 64),
        {"repository": "postgres", "tag": "16-alpine", "digest": "sha256:" + "a" * 64},
    )
    check(
        "image: registry with port",
        parse_image_ref("registry.local:5000/team/app:v1"),
        {"repository": "registry.local:5000/team/app", "tag": "v1", "digest": ""},
    )
    check(
        "image: tag only",
        parse_image_ref("netops-cloud-ingest"),
        {"repository": "netops-cloud-ingest", "tag": "", "digest": ""},
    )
    check("purl quote: scoped npm", purl_quote("@types/react"), "%40types/react")

    gomod = (
        "module netops/backend\n\ngo 1.26.0\n\ntoolchain go1.26.8\n\n"
        "require (\n\tgithub.com/jackc/pgx/v5 v5.9.2\n\tgolang.org/x/net v0.57.0\n)\n\n"
        "require (\n\tgolang.org/x/sys v0.47.0 // indirect\n)\n"
    )
    check(
        "go.mod direct requires",
        _go_direct_modules(gomod),
        {"github.com/jackc/pgx/v5", "golang.org/x/net"},
    )

    check(
        "npm integrity -> hex",
        _sha512_hex_from_integrity("sha512-" + base64.b64encode(b"\x01\x02").decode()),
        ("SHA-512", "0102"),
    )
    check("npm integrity: unknown alg", _sha512_hex_from_integrity("md5-abcd"), None)

    doc_a = build_document("t", [{"bom-ref": "b"}, {"bom-ref": "a"}], "T", "v0")
    doc_b = build_document("t", [{"bom-ref": "a"}, {"bom-ref": "b"}], "T", "v0")
    check("document is order-independent", doc_a, doc_b)
    check("components are sorted", [c["bom-ref"] for c in doc_a["components"]], ["a", "b"])

    for problem in failures:
        print(f"selftest FAIL  {problem}", file=sys.stderr)
    if failures:
        print(f"sbom selftest: {len(failures)} failure(s)", file=sys.stderr)
        return 1
    print("sbom selftest: all parser checks passed")
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate the Correlix CycloneDX SBOM (stdlib only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--out",
        default=str(ROOT / "docs" / "sbom"),
        help="output directory (default: docs/sbom)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="do not write; exit 1 if the committed SBOM differs from the tree",
    )
    parser.add_argument(
        "--print",
        dest="print_class",
        choices=(*CLASSES, AGGREGATE),
        help="print one document to stdout instead of writing files",
    )
    parser.add_argument(
        "--selftest", action="store_true", help="run parser self-tests and exit"
    )
    args = parser.parse_args(argv)

    if args.selftest:
        return selftest()

    try:
        documents = render()
    except SbomError as exc:
        print(f"sbom: {exc}", file=sys.stderr)
        return 2

    if args.print_class:
        sys.stdout.write(documents[f"{args.print_class}.cdx.json"])
        return 0

    out_dir = Path(args.out)

    if args.check:
        stale: list[str] = []
        for name, text in documents.items():
            path = out_dir / name
            if not path.is_file():
                stale.append(f"{name}: MISSING")
                continue
            try:
                committed = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                stale.append(f"{name}: UNREADABLE ({exc})")
                continue
            expected = json.loads(text)["components"]
            actual = committed.get("components")
            if actual != expected:
                added = {c["bom-ref"] for c in expected} - {
                    c["bom-ref"] for c in actual or []
                }
                removed = {c["bom-ref"] for c in actual or []} - {
                    c["bom-ref"] for c in expected
                }
                detail = []
                if added:
                    detail.append(f"+{len(added)}")
                if removed:
                    detail.append(f"-{len(removed)}")
                if not detail:
                    detail.append("component metadata changed")
                stale.append(f"{name}: STALE ({', '.join(detail)})")
        if stale:
            print("sbom --check: the committed SBOM does not match the tree:", file=sys.stderr)
            for item in stale:
                print(f"  - {item}", file=sys.stderr)
            print("  regenerate with: python3 scripts/sbom.py", file=sys.stderr)
            return 1
        print(f"sbom --check: {len(documents)} document(s) current")
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    for name, text in documents.items():
        (out_dir / name).write_text(text, encoding="utf-8")
    total = len(json.loads(documents[f"{AGGREGATE}.cdx.json"])["components"])
    print(f"sbom: wrote {len(documents)} document(s) to {out_dir} ({total} unique components)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
