#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""NO WINDOWS PE BINARIES IN A LINUX IMAGE (tracker 238(b)).

WHY THIS EXISTS. `netops-correlation` shipped six Windows PE launcher stubs for
months — `pip/_vendor/distlib/{t32,t64,t64-arm,w32,w64,w64-arm}.exe`, vendored
inside pip by the `python:3.12-alpine` base. Nothing on musl Linux can execute
them and nothing links them, but Correlix DISTRIBUTES them, the image carries no
licence text beside them, and Syft therefore catalogued them as a component with
an undischarged source obligation: `Simple Launcher 1.1.0.14`, six times, under
TWO different shapes depending on which PE cataloger claimed the file first —

    syft v1.42.3  type `binary`  pe-binary-package-cataloger          (no purl)
    syft v1.18.1  type `dotnet`  dotnet-portable-executable-cataloger
                                 purl pkg:nuget/Simple%20Launcher@1.1.0.14

Owner decision 2026-09-13: DELETE THE BYTES. A component we do not ship needs no
licence, and a licence we cannot read out of the artifact is not a licence to
assert (docs/compliance/OCI_SOURCE_COMPLIANCE.md §12). `Dockerfile.correlation`
now strips them in its runtime stage and ASSERTS in the same stage that no `*.exe`
and no `MZ`-magic file survives, so the build fails if a base-image bump brings
them back.

THIS SCRIPT IS THE REPO-SIDE HALF of that guard, for the two things an in-build
assertion cannot see:

  --tree  (default)  the source tree Correlix COPYs into its images carries no
                     PE binary, and every owned Dockerfile whose runtime base is
                     a pip-bearing Python image still declares the strip AND the
                     assertion. A guard silently deleted is a guard that never
                     fails.
  --sbom PATH        a Syft SBOM of a FINAL IMAGE (Syft JSON or CycloneDX-JSON)
                     contains no Windows PE component — matched on the cataloger,
                     the package type, the purl namespace AND the file suffix, so
                     the rule does not depend on which representation the scanner
                     happened to choose. That independence is the whole point:
                     the 2026-09-05 inventory recorded these as `nuget` and the
                     2026-09-06 one as `binary`, and a shape difference must
                     never drop an obligation.

Pure stdlib. No Docker daemon, no network, no scanner — it reads files.
Exit 0 = clean, 1 = violation(s).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Repo layout: this file is NetOps_Observability/scripts/check-no-pe-binaries.py
ROOT = Path(__file__).resolve().parents[1]
DOCKER = ROOT / "deployment" / "docker"

# Every Dockerfile Correlix builds, including the build-variant ones the CIS gate
# exempts: a lab-only image is still an image somebody runs.
OWNED_DOCKERFILES = [
    DOCKER / "Dockerfile.backend",
    DOCKER / "Dockerfile.correlation",
    DOCKER / "Dockerfile.frontend",
    DOCKER / "Dockerfile.frontend.full",
    DOCKER / "Dockerfile.nginx",
]

# Runtime bases known to vendor Windows PE launcher stubs (pip → distlib). A base
# matching this pattern in the FINAL stage must carry the strip + the assertion.
PIP_BEARING_BASE = re.compile(r"^FROM\s+(?:docker\.io/)?(?:library/)?python:", re.IGNORECASE)

# What the strip and the assertion have to look like for the guard to count as
# present. Deliberately shape-based rather than an exact string match: the intent
# is "this Dockerfile deletes PE files and then proves it", not a diff lock.
STRIP_PATTERN = re.compile(r"-name\s+'?\*\.exe'?\s+-delete")
ASSERT_PATTERNS = (
    re.compile(r'b"MZ"|b\'MZ\''),          # reads the PE magic
    re.compile(r"sys\.exit\("),            # …and fails the build on a hit
)

# Source-tree scan. Windows PE containers by extension, plus an MZ-magic sniff so
# a renamed stub cannot walk past the suffix list.
PE_SUFFIXES = {".exe", ".dll", ".sys", ".ocx", ".scr", ".cpl", ".msi"}
# Directories that are never COPYd into an image and are not ours to police.
TREE_SKIP_DIRS = {".git", "node_modules", "dist", "data", "backups", "__pycache__"}
# No exemption exists today, and adding one needs a reason in this dict, not a
# silent `if`. Paths are relative to NetOps_Observability/.
TREE_ALLOWLIST: dict[str, str] = {}

# SBOM matching. Any ONE of these makes a component a Windows PE artifact.
PE_CATALOGERS = ("pe-binary", "dotnet-portable-executable")
PE_PKG_TYPES = ("dotnet", "nuget")
PE_PURL_PREFIX = "pkg:nuget/"


# --------------------------------------------------------------------------- #
# --tree
# --------------------------------------------------------------------------- #
def _is_pe_file(path: Path) -> str | None:
    """Return a reason string if `path` is a Windows PE binary, else None."""
    if path.suffix.lower() in PE_SUFFIXES:
        return f"{path.suffix.lower()} suffix"
    try:
        with path.open("rb") as fh:
            if fh.read(2) == b"MZ":
                return "PE MZ magic"
    except OSError as exc:  # unreadable is reported, never skipped (§16.1)
        return f"unreadable ({exc.strerror})"
    return None


def check_tree(root: Path = ROOT) -> list[str]:
    """No PE binary is checked into the tree Correlix builds its images from."""
    problems: list[str] = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if TREE_SKIP_DIRS & set(rel.parts):
            continue
        if not path.is_file() or path.is_symlink():
            continue
        reason = _is_pe_file(path)
        if reason is None:
            continue
        if str(rel) in TREE_ALLOWLIST:
            continue
        problems.append(f"{rel}: Windows PE binary in the source tree ({reason})")
    return problems


def check_dockerfiles(dockerfiles: list[Path] | None = None) -> list[str]:
    """A pip-bearing runtime base must strip the PE stubs AND assert they are gone."""
    problems: list[str] = []
    for df in dockerfiles if dockerfiles is not None else OWNED_DOCKERFILES:
        if not df.exists():
            problems.append(f"{df.name}: MISSING (expected an owned Dockerfile)")
            continue
        text = df.read_text(encoding="utf-8")
        froms = [ln for ln in text.splitlines() if ln.strip().upper().startswith("FROM ")]
        if not froms:
            problems.append(f"{df.name}: no FROM instruction")
            continue
        if not PIP_BEARING_BASE.match(froms[-1].strip()):
            continue  # runtime base carries no pip → nothing to strip
        if not STRIP_PATTERN.search(text):
            problems.append(
                f"{df.name}: runtime base is a pip-bearing Python image but the "
                f"Dockerfile no longer strips Windows PE stubs "
                f"(expected a `find … -name '*.exe' -delete`) — tracker 238(b)"
            )
        if not all(p.search(text) for p in ASSERT_PATTERNS):
            problems.append(
                f"{df.name}: the in-build PE assertion is gone — the build must "
                f"FAIL on a surviving MZ-magic file, not merely delete the ones "
                f"we happen to know about (tracker 238(b))"
            )
    return problems


# --------------------------------------------------------------------------- #
# --sbom
# --------------------------------------------------------------------------- #
def _syft_components(doc: dict) -> list[dict]:
    """Normalise a Syft-JSON or CycloneDX-JSON document to
    {name, version, type, foundBy, purl, paths} records."""
    out: list[dict] = []
    if isinstance(doc.get("artifacts"), list):  # syft native json
        for a in doc["artifacts"]:
            out.append(
                {
                    "name": a.get("name", ""),
                    "version": a.get("version", ""),
                    "type": (a.get("type") or "").lower(),
                    "foundBy": (a.get("foundBy") or "").lower(),
                    "purl": a.get("purl") or "",
                    "paths": [
                        loc.get("path", "") for loc in a.get("locations") or [] if isinstance(loc, dict)
                    ],
                }
            )
        return out
    if isinstance(doc.get("components"), list):  # cyclonedx-json
        for c in doc["components"]:
            props = {
                p.get("name", ""): p.get("value", "")
                for p in c.get("properties") or []
                if isinstance(p, dict)
            }
            out.append(
                {
                    "name": c.get("name", ""),
                    "version": c.get("version", ""),
                    "type": (props.get("syft:package:type") or "").lower(),
                    "foundBy": (props.get("syft:package:foundBy") or "").lower(),
                    "purl": c.get("purl") or "",
                    "paths": [v for k, v in props.items() if k.endswith(":path")],
                }
            )
        return out
    raise ValueError(
        "not a recognised SBOM: expected a Syft `artifacts` array or a "
        "CycloneDX `components` array"
    )


def _pe_reason(comp: dict) -> str | None:
    if any(cat in comp["foundBy"] for cat in PE_CATALOGERS):
        return f"cataloged by {comp['foundBy']}"
    if comp["type"] in PE_PKG_TYPES:
        return f"package type {comp['type']!r}"
    if comp["purl"].startswith(PE_PURL_PREFIX):
        return f"purl {comp['purl']}"
    # Syft's file entries (`"type": "file"`) carry the path as the component NAME
    # and no location property, so the name is a path candidate too — the
    # file-level evidence must not be quieter than the package-level evidence.
    candidates = list(comp["paths"])
    if comp["name"].startswith("/"):
        candidates.append(comp["name"])
    hits = [p for p in candidates if Path(p).suffix.lower() in PE_SUFFIXES]
    if hits:
        return f"located at {', '.join(sorted(hits))}"
    return None


def check_sbom(path: Path) -> list[str]:
    """Fail on any Windows PE component in an SBOM of a final image.

    FAIL CLOSED (§16.1): an unparsable SBOM, or one with zero components, is an
    error — never "zero affected packages". A gate that passes because the
    scanner produced nothing is not a gate.
    """
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [f"{path}: unreadable/unparsable SBOM ({exc})"]
    try:
        comps = _syft_components(doc)
    except ValueError as exc:
        return [f"{path}: {exc}"]
    if not comps:
        return [f"{path}: SBOM lists ZERO components — treated as a scanner failure"]

    problems: list[str] = []
    for comp in comps:
        reason = _pe_reason(comp)
        if reason:
            problems.append(
                f"{path.name}: Windows PE component "
                f"{comp['name']!r} {comp['version']} — {reason}"
            )
    if not problems:
        print(f"  ✓ {path.name}: {len(comps)} components, no Windows PE artifact")
    return problems


# --------------------------------------------------------------------------- #
# --selftest
# --------------------------------------------------------------------------- #
GOOD_DOCKERFILE = (
    "FROM python:3.12-alpine@sha256:" + "a" * 64 + " AS build\n"
    "FROM python:3.12-alpine@sha256:" + "a" * 64 + "\n"
    "RUN rm -f /x/t32.exe \\\n"
    "    && find /usr/local -type f -name '*.exe' -delete \\\n"
    "    && python3 -c 'import sys; sys.exit(\"bad\") if open(\"/x\",\"rb\").read(2) "
    "== b\"MZ\" else print(\"ok\")'\n"
)
NON_PYTHON_DOCKERFILE = "FROM nginx:1.27-alpine@sha256:" + "b" * 64 + "\nUSER nginx\n"


def _selftest() -> int:
    """Proves the gate BITES. A gate that cannot fail is worthless (cis_docker.py
    §_selftest, same reasoning). No pytest, no deps — runs in CI before the real
    check; tests/test_no_pe_binaries.py covers the same ground under pytest."""
    import tempfile

    cases: list[tuple[str, bool]] = []
    with tempfile.TemporaryDirectory() as d:
        td = Path(d)

        # --- Dockerfile rule ---
        good = td / "Dockerfile.good"
        good.write_text(GOOD_DOCKERFILE, encoding="utf-8")
        cases.append(("compliant Dockerfile passes", check_dockerfiles([good]) == []))

        nostrip = td / "Dockerfile.nostrip"
        nostrip.write_text(GOOD_DOCKERFILE.replace(
            "    && find /usr/local -type f -name '*.exe' -delete \\\n", ""), encoding="utf-8")
        cases.append(("removed strip flagged",
                      any("no longer strips" in p for p in check_dockerfiles([nostrip]))))

        noassert = td / "Dockerfile.noassert"
        noassert.write_text("\n".join(GOOD_DOCKERFILE.splitlines()[:4]) + "\n", encoding="utf-8")
        cases.append(("removed assertion flagged",
                      any("assertion is gone" in p for p in check_dockerfiles([noassert]))))

        nginxish = td / "Dockerfile.nginx"
        nginxish.write_text(NON_PYTHON_DOCKERFILE, encoding="utf-8")
        cases.append(("non-python base is out of scope",
                      check_dockerfiles([nginxish]) == []))

        cases.append(("missing Dockerfile flagged",
                      any("MISSING" in p for p in check_dockerfiles([td / "Dockerfile.absent"]))))

        # --- tree rule ---
        clean = td / "tree-clean"
        (clean / "sub").mkdir(parents=True)
        (clean / "sub" / "app.py").write_text("print(1)\n", encoding="utf-8")
        cases.append(("clean tree passes", check_tree(clean) == []))

        dirty = td / "tree-dirty"
        (dirty / "sub").mkdir(parents=True)
        (dirty / "sub" / "t64.exe").write_bytes(b"MZ\x90\x00")
        cases.append(("checked-in .exe flagged",
                      any("t64.exe" in p for p in check_tree(dirty))))
        (dirty / "sub" / "t64.exe").unlink()
        (dirty / "sub" / "renamed.bin").write_bytes(b"MZ\x90\x00")
        cases.append(("renamed PE flagged by MZ magic",
                      any("PE MZ magic" in p for p in check_tree(dirty))))
        skipped = dirty / "node_modules"
        skipped.mkdir()
        (skipped / "x.exe").write_bytes(b"MZ")
        cases.append(("skip-dir honoured",
                      not any("node_modules" in p for p in check_tree(dirty))))

        # --- SBOM rule: BOTH representations of the same six files ---
        binary_rep = {"artifacts": [{
            "name": "Simple Launcher", "version": "1.1.0.14", "type": "binary",
            "foundBy": "pe-binary-package-cataloger", "purl": "",
            "locations": [{"path": "/usr/local/lib/python3.12/site-packages/pip/"
                                   "_vendor/distlib/t32.exe"}]}]}
        nuget_rep = {"artifacts": [{
            "name": "Simple Launcher", "version": "1.1.0.14", "type": "dotnet",
            "foundBy": "dotnet-portable-executable-cataloger",
            "purl": "pkg:nuget/Simple%20Launcher@1.1.0.14",
            "locations": [{"path": "/usr/local/lib/python3.12/site-packages/pip/"
                                   "_vendor/distlib/t32.exe"}]}]}
        cdx_rep = {"components": [{
            "name": "Simple Launcher", "version": "1.1.0.14", "type": "application",
            "properties": [
                {"name": "syft:package:foundBy", "value": "pe-binary-package-cataloger"},
                {"name": "syft:package:type", "value": "binary"},
                {"name": "syft:location:0:path",
                 "value": "/usr/local/lib/python3.12/site-packages/pip/_vendor/distlib/t32.exe"},
            ]}]}
        clean_sbom = {"artifacts": [{
            "name": "busybox", "version": "1.37.0-r31", "type": "apk",
            "foundBy": "apk-db-cataloger", "purl": "pkg:apk/alpine/busybox@1.37.0-r31",
            "locations": [{"path": "/lib/apk/db/installed"}]}]}

        for label, doc in (("syft `binary` representation", binary_rep),
                           ("syft `nuget` representation", nuget_rep),
                           ("cyclonedx representation", cdx_rep)):
            f = td / f"sbom-{abs(hash(label))}.json"
            f.write_text(json.dumps(doc), encoding="utf-8")
            cases.append((f"{label} flagged", any("Simple Launcher" in p for p in check_sbom(f))))

        f = td / "sbom-clean.json"
        f.write_text(json.dumps(clean_sbom), encoding="utf-8")
        cases.append(("PE-free SBOM passes", check_sbom(f) == []))

        f = td / "sbom-empty.json"
        f.write_text(json.dumps({"artifacts": []}), encoding="utf-8")
        cases.append(("empty SBOM is a failure, not a pass",
                      any("ZERO components" in p for p in check_sbom(f))))

        f = td / "sbom-garbage.json"
        f.write_text("not json", encoding="utf-8")
        cases.append(("unparsable SBOM is a failure",
                      any("unparsable" in p for p in check_sbom(f))))

        f = td / "sbom-alien.json"
        f.write_text(json.dumps({"spdxVersion": "SPDX-2.3"}), encoding="utf-8")
        cases.append(("unrecognised SBOM shape is a failure",
                      any("not a recognised SBOM" in p for p in check_sbom(f))))

    failed = [label for label, ok in cases if not ok]
    for label, ok in cases:
        print(f"  {'✓' if ok else '✗'} selftest: {label}")
    if failed:
        print(f"\nselftest FAILED: {failed}")
        return 1
    print(f"selftest PASS ({len(cases)} checks) — the gate bites\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="No Windows PE binaries in a Linux image (tracker 238(b))")
    ap.add_argument("--tree", action="store_true",
                    help="scan the source tree + owned Dockerfiles (default)")
    ap.add_argument("--sbom", action="append", default=[], metavar="PATH",
                    help="Syft JSON or CycloneDX-JSON SBOM of a final image")
    ap.add_argument("--selftest", action="store_true",
                    help="prove the gate catches every representation, then continue")
    args = ap.parse_args(argv)

    if args.selftest:
        rc = _selftest()
        if rc:
            return rc

    problems: list[str] = []
    ran: list[str] = []
    for sbom in args.sbom:
        ran.append(f"SBOM {sbom}")
        problems += check_sbom(Path(sbom))
    if args.tree or not args.sbom:
        ran.append("source tree + owned Dockerfiles")
        problems += check_tree()
        problems += check_dockerfiles()

    if problems:
        print("no-PE-binaries gate: FAIL")
        for p in problems:
            print(f"  ✗ {p}")
        print(f"\n{len(problems)} violation(s). Tracker 238(b): Correlix ships Linux "
              "images; a Windows PE file in one is a component we distribute, cannot "
              "execute and hold no readable licence for. Delete the bytes.")
        return 1
    print("no-PE-binaries gate: PASS")
    for r in ran:
        print(f"  ✓ {r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
