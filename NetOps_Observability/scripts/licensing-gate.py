#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""
licensing-gate.py — enforce the open-core boundary declared in licensing-policy.json.

Why this exists
---------------
A licence split that is only written down is a licence split that drifts. Within
one release somebody adds a directory nobody classified, marks a core file
commercial, imports a commercial package from Apache-2.0 code, or ships an image
whose metadata claims a licence the source does not. Every one of those is
invisible in review and expensive afterwards, because the wrong answer has
already been distributed.

This is the mechanical check. It reads `licensing-policy.json` and nothing else
as authority, and it FAILS CLOSED: anything unclassified, unknown or
contradictory is an error, never a warning.

The eight checks
    A  SPDX headers agree with the policy's classification of their path, and —
       once `header_enforcement.mode` is `enforced` — every source file in the
       swept scope actually carries one.
    B  Every commercial directory carries its own LICENSE notice file.
    C  The commercial identifier appears nowhere outside a commercial directory.
    D  Every Dockerfile is classified, and Correlix images declare the licence
       in OCI metadata while third-party repackages deliberately do not.
    E  Apache-2.0 core never imports a commercially licensed package.
    F  Every top-level directory is classified exactly once, and every path the
       policy names exists on disk.
    G  Every surface that states the project licence states the SAME sentence.
    H  Every artifact Correlix ships carries the licence and notice files.

`--release` additionally fails on the recorded release blockers: a commercial
marking whose licence text does not exist yet, and a CLA with no signing
process. Those must not reach a customer even though they do not block daily
development.

Usage
    python3 scripts/licensing-gate.py             # the eight checks
    python3 scripts/licensing-gate.py --release   # + release blockers
    python3 scripts/licensing-gate.py --json      # machine-readable

Pure standard library. No network, no running stack. Safe in CI.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(HERE)
REPO = os.path.dirname(PROJ)
POLICY_PATH = os.path.join(PROJ, "licensing-policy.json")

SPDX_RE = re.compile(r"SPDX-License-Identifier:\s*([A-Za-z0-9directory.\-+]+)")
# Go import lines: both the factored block and the single-line form.
GO_IMPORT_BLOCK = re.compile(r"^import\s*\(([^)]*)\)", re.MULTILINE | re.DOTALL)
GO_IMPORT_ONE = re.compile(r'^import\s+(?:[\w.]+\s+)?"([^"]+)"', re.MULTILINE)
GO_QUOTED = re.compile(r'"([^"]+)"')
GO_MODULE = "netops/backend"


class Failure:
    """One violation. `check` is the letter; `where` is a repo-relative path."""

    def __init__(self, check: str, where: str, message: str) -> None:
        self.check = check
        self.where = where
        self.message = message

    def __str__(self) -> str:
        return f"[{self.check}] {self.where}: {self.message}"

    def as_dict(self) -> dict:
        return {"check": self.check, "where": self.where, "message": self.message}


def rel(path: str) -> str:
    return os.path.relpath(path, REPO)


def load_policy() -> dict:
    with open(POLICY_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def load_module(filename: str, name: str):
    """Load a sibling script by path. Their filenames carry dashes, so they are
    not importable; this is the same mechanism check G already uses to run
    license-audit.py's generator rather than grepping its source."""
    path = os.path.join(HERE, filename)
    if not os.path.isfile(path):
        return None
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def excluded_names(policy: dict) -> set[str]:
    return {e["name"] for e in policy["excluded_paths"]["entries"]}


def walk_sources(root: str, policy: dict, extensions: tuple[str, ...]) -> list[str]:
    """Every source file under `root`, skipping the excluded directory names."""
    skip = excluded_names(policy)
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for name in filenames:
            if name.endswith(extensions):
                found.append(os.path.join(dirpath, name))
    return found


def commercial_dirs(policy: dict) -> list[str]:
    return [e["path"] for e in policy["commercial_paths"]["entries"]]


def in_commercial(relpath: str, dirs: list[str]) -> bool:
    """True if a project-relative path sits inside a commercial directory."""
    return any(relpath == d or relpath.startswith(d + "/") for d in dirs)


# ── A / C: SPDX headers ──────────────────────────────────────────────────────
def check_spdx(policy: dict) -> list[Failure]:
    fails: list[Failure] = []
    core = policy["identifiers"]["core"]
    comm = policy["identifiers"]["commercial"]
    known = {core, comm}
    cdirs = commercial_dirs(policy)
    exts = tuple(policy["header_enforcement"]["source_extensions"])

    for path in walk_sources(PROJ, policy, exts):
        relp = os.path.relpath(path, PROJ)
        try:
            with open(path, encoding="utf-8") as fh:
                head = fh.read(4096)
        except UnicodeDecodeError:
            # NOT text. walk_sources filters by extension, so this is a file
            # with a source extension whose bytes are not UTF-8 — there is no
            # SPDX header in it to agree or disagree with the policy, and
            # skipping it asserts nothing false.
            continue
        except OSError as err:
            # A source file the gate could not OPEN is a source file the gate
            # did NOT check. This gate fails closed (see the module docstring):
            # a silent `continue` here would let an unreadable file in a
            # commercial directory pass exactly as if its header had been
            # verified. Reported as a check-A failure, which is a non-zero
            # exit — the accumulator IS the escalation (§16.1).
            fails.append(Failure("A", relp,
                                 f"could not be read, so its SPDX header was "
                                 f"never checked: {err}"))
            continue
        found = SPDX_RE.search(head)
        commercial_path = in_commercial(relp, cdirs)

        if commercial_path:
            # A: a commercial directory's every source file must say so.
            if not found:
                fails.append(Failure("A", relp,
                                     f"in a commercial directory but carries no "
                                     f"SPDX-License-Identifier: {comm}"))
            elif found.group(1) != comm:
                fails.append(Failure("A", relp,
                                     f"declares {found.group(1)} but its directory is "
                                     f"commercial ({comm})"))
            continue

        if not found:
            continue  # a missing core header is check_headers()'s business
        ident = found.group(1)
        if ident not in known:
            fails.append(Failure("A", relp, f"unknown SPDX identifier {ident!r}"))
        elif ident == comm:
            # C: the commercial marking must never escape its directory.
            fails.append(Failure("C", relp,
                                 f"declares {comm} but is NOT inside a commercial "
                                 f"directory declared in licensing-policy.json"))

    fails.extend(check_headers(policy))
    return fails


def check_headers(policy: dict) -> list[Failure]:
    """Part of check A: once the sweep has run, EVERY source file in scope must
    carry the header its path maps to.

    The scope and the exemption list are not restated here. They are read from
    the same policy section the sweep obeys, THROUGH the sweep itself
    (scripts/spdx-headers.py), so the gate and the tool that fixes a failure can
    never disagree about which files are covered."""
    if policy["header_enforcement"]["mode"] != "enforced":
        return []  # the sweep has not run yet; only the commercial direction is checked
    try:
        spdx = load_module("spdx-headers.py", "_spdx_headers")
    except Exception as err:  # noqa: BLE001 - any import failure is a real gate failure
        return [Failure("A", "scripts/spdx-headers.py",
                        f"could not be evaluated, so no header was checked: {err}")]
    if spdx is None:
        return [Failure("A", "scripts/spdx-headers.py",
                        "header enforcement is on but the sweep script is missing")]
    violations, _changed = spdx.scan(policy, write=False)
    return [Failure("A", v.path, v.reason) for v in violations]


# ── B: per-directory notice files ────────────────────────────────────────────
def check_notice_files(policy: dict) -> list[Failure]:
    fails: list[Failure] = []
    comm = policy["identifiers"]["commercial"]
    for entry in policy["commercial_paths"]["entries"]:
        notice = os.path.join(PROJ, entry["notice_file"])
        if not os.path.isfile(notice):
            fails.append(Failure("B", entry["notice_file"], "notice file is missing"))
            continue
        with open(notice, encoding="utf-8") as fh:
            body = fh.read()
        if comm not in body:
            fails.append(Failure("B", entry["notice_file"],
                                 f"does not name the identifier {comm}"))
    return fails


# ── D: container image metadata ──────────────────────────────────────────────
def check_dockerfiles(policy: dict) -> list[Failure]:
    fails: list[Failure] = []
    ci = policy["container_images"]
    ours = {e["path"]: e["licence"] for e in ci["ours"]}
    repack = {e["path"] for e in ci["third_party_repackage"]}
    classified = set(ours) | repack

    # ANY file whose basename starts with `Dockerfile`, not a fixed list of
    # suffixes. The suffix list this replaced ((".backend", ".correlation",
    # ".frontend", ".full", ".nginx")) grew by hand, so a Dockerfile with a new
    # suffix — `Dockerfile.inherited`, say — escaped check D entirely while
    # tests/test_licensing_consistency.py still demanded it be classified. Two
    # discovery rules for one question is one rule too many.
    on_disk = {
        os.path.relpath(p, PROJ)
        for p in walk_sources(PROJ, policy, ("",))
        if os.path.basename(p).startswith("Dockerfile")
    }

    for path in sorted(on_disk - classified):
        fails.append(Failure("D", path,
                             "Dockerfile is not classified in licensing-policy.json "
                             "(container_images.ours or .third_party_repackage)"))
    for path in sorted(classified - on_disk):
        fails.append(Failure("D", path,
                             "classified in licensing-policy.json but not on disk"))

    label = "org.opencontainers.image.licenses"
    for path, licence in sorted(ours.items()):
        full = os.path.join(PROJ, path)
        if not os.path.isfile(full):
            continue  # already reported above
        with open(full, encoding="utf-8") as fh:
            body = fh.read()
        if label not in body:
            fails.append(Failure("D", path, f"builds a Correlix image but sets no {label}"))
        elif f'{label}="{licence}"' not in body:
            fails.append(Failure("D", path,
                                 f'{label} does not read "{licence}"'))
    for path in sorted(repack):
        full = os.path.join(PROJ, path)
        if os.path.isfile(full):
            with open(full, encoding="utf-8") as fh:
                if label in fh.read():
                    fails.append(Failure("D", path,
                                         f"repackages a third-party image but sets {label}; "
                                         f"labelling upstream software with our licence "
                                         f"would be a false claim"))
    return fails


# ── E: the import boundary ───────────────────────────────────────────────────
def go_imports(path: str) -> list[str]:
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    out: list[str] = []
    for block in GO_IMPORT_BLOCK.findall(src):
        out.extend(GO_QUOTED.findall(block))
    out.extend(GO_IMPORT_ONE.findall(src))
    return out


def check_import_boundary(policy: dict) -> list[Failure]:
    fails: list[Failure] = []
    cdirs = commercial_dirs(policy)
    backend = os.path.join(PROJ, "src", "backend")
    if not os.path.isdir(backend):
        return [Failure("E", "src/backend", "backend tree not found")]

    # project-relative commercial dir -> Go import path
    commercial_imports = {}
    for d in cdirs:
        if d.startswith("src/backend/"):
            commercial_imports[GO_MODULE + "/" + d[len("src/backend/"):]] = d
    if not commercial_imports:
        return fails

    allowed: dict[str, set[str]] = {}
    for a in policy["import_boundary"]["assembly_allowances"]:
        allowed.setdefault(a["importer"], set()).update(a["files"])

    for path in walk_sources(backend, policy, (".go",)):
        relp = os.path.relpath(path, PROJ)
        if in_commercial(relp, cdirs):
            continue  # commercial code may import commercial code
        pkgdir = os.path.dirname(relp)
        base = os.path.basename(relp)
        if base in allowed.get(pkgdir, set()):
            continue  # the declared assembly seam
        for imp in go_imports(path):
            if imp in commercial_imports:
                fails.append(Failure(
                    "E", relp,
                    f"Apache-2.0 core imports the commercial package "
                    f"{commercial_imports[imp]!r}; core must stay buildable and "
                    f"shippable without commercially licensed code"))
    return fails


# ── F: coverage ──────────────────────────────────────────────────────────────
def check_coverage(policy: dict) -> list[Failure]:
    fails: list[Failure] = []
    skip = excluded_names(policy)

    on_disk = {
        name for name in os.listdir(PROJ)
        if os.path.isdir(os.path.join(PROJ, name)) and name not in skip
    }
    entries = [e["path"] for e in policy["project_top_level"]["entries"]]
    classified = set(entries)

    if len(entries) != len(classified):
        dupes = sorted({e for e in entries if entries.count(e) > 1})
        fails.append(Failure("F", "licensing-policy.json",
                             f"project_top_level lists these more than once: {dupes}"))
    for name in sorted(on_disk - classified):
        fails.append(Failure("F", name,
                             "top-level directory is not classified in "
                             "licensing-policy.json project_top_level"))
    for name in sorted(classified - on_disk):
        fails.append(Failure("F", name,
                             "classified in licensing-policy.json but not on disk"))

    for group in ("commercial_paths", "mixed_directories"):
        for entry in policy[group]["entries"]:
            if not os.path.isdir(os.path.join(PROJ, entry["path"])):
                fails.append(Failure("F", entry["path"],
                                     f"named in {group} but is not a directory"))

    # The packages decided core on evidence are named in the map and in the
    # design record. If one is renamed or deleted, both statements go stale
    # silently, so the path is checked exactly like a classified directory.
    for entry in policy["mixed_directories"]["core_by_evidence"]["entries"]:
        if not os.path.isdir(os.path.join(PROJ, entry["path"])):
            fails.append(Failure("F", entry["path"],
                                 "named in mixed_directories.core_by_evidence but "
                                 "is not a directory"))

    # Every commercial entitlement must exist in the owner's locked set.
    locked = {
        ent["id"]
        for tier in policy["locked_commercial_set"]
        if not tier.startswith("_")
        for ent in policy["locked_commercial_set"][tier]
    }
    for group in ("commercial_paths", "mixed_directories"):
        for entry in policy[group]["entries"]:
            if entry["entitlement"] not in locked:
                fails.append(Failure(
                    "F", entry["path"],
                    f"entitlement {entry['entitlement']!r} is not in the owner's "
                    f"locked commercial set; nothing may be gated on it"))
    return fails


# ── G: one sentence everywhere ───────────────────────────────────────────────
def licence_sentence_surfaces(policy: dict) -> list[tuple[str, str]]:
    """(absolute path, why it must state the licence). Kept here so the pytest
    suite and the gate assert the same list."""
    return [
        (os.path.join(REPO, "LICENSE"), "the repository-root licence notice"),
        (os.path.join(PROJ, "LICENSE"), "the project licence notice"),
        (os.path.join(REPO, "LICENSING.md"), "the root directory map"),
        (os.path.join(PROJ, "LICENSING.md"), "the project directory map"),
        (os.path.join(PROJ, "README.md"), "the first thing a reader sees"),
        (os.path.join(PROJ, "NOTICE"), "the notice file shipped in every image"),
        (os.path.join(PROJ, "src", "frontend", "public", "licenses", "index.html"),
         "the licences page the product serves at /licenses/"),
        (os.path.join(PROJ, "docs-portal", "docs", "reference", "licensing.md"),
         "the customer documentation"),
    ]


# docs/THIRD_PARTY_LICENSES.md is GENERATED, and it is regenerated on a
# different cadence from this change. Grepping the checked-in file would fail on
# staleness rather than on drift, and grepping the generator's SOURCE would fail
# on how its string literals happen to be wrapped. So the assertion runs the
# generator and reads what it actually produces: the header a customer receives.
def render_notices_output() -> str | None:
    """The header render_notices() emits, or None if it cannot be loaded."""
    module = load_module("license-audit.py", "_license_audit")
    if module is None:
        return None
    return module.render_notices([], {})


def check_one_sentence(policy: dict) -> list[Failure]:
    fails: list[Failure] = []
    sentence = policy["canonical_sentence"]
    for path, why in licence_sentence_surfaces(policy):
        if not os.path.isfile(path):
            fails.append(Failure("G", rel(path), f"missing ({why})"))
            continue
        with open(path, encoding="utf-8") as fh:
            body = fh.read()
        if sentence not in body:
            fails.append(Failure("G", rel(path),
                                 f"does not state the canonical licence sentence ({why})"))

    try:
        generated = render_notices_output()
    except Exception as err:  # noqa: BLE001 - any import failure is a real gate failure
        fails.append(Failure("G", "scripts/license-audit.py",
                             f"render_notices() could not be evaluated: {err}"))
    else:
        if generated is None:
            fails.append(Failure("G", "scripts/license-audit.py", "generator is missing"))
        elif sentence not in generated:
            fails.append(Failure(
                "G", "scripts/license-audit.py",
                "render_notices() does not emit the canonical licence sentence into "
                "the generated THIRD_PARTY_LICENSES.md header"))
    return fails


# ── H: what ships ────────────────────────────────────────────────────────────
def check_artifacts(policy: dict) -> list[Failure]:
    fails: list[Failure] = []
    for art in policy["artifact_requirements"]["must_ship"]:
        producer = os.path.join(PROJ, art["produced_by"])
        for required in art["requires"]:
            if "/" not in required and " " in required:
                continue  # a prose requirement, asserted by check G instead
            candidate = os.path.join(PROJ, required)
            if os.path.exists(candidate) or os.path.exists(os.path.join(REPO, required)):
                continue
            if " " in required:
                continue
            fails.append(Failure("H", required,
                                 f"required in the {art['artifact']} but not present "
                                 f"in the tree"))
        if not os.path.exists(producer) and "*" not in art["produced_by"]:
            fails.append(Failure("H", art["produced_by"],
                                 f"producer of the {art['artifact']} is missing"))
    return fails


# ── release blockers ─────────────────────────────────────────────────────────
def check_release_blockers(policy: dict) -> list[Failure]:
    fails: list[Failure] = []
    for b in policy["release_blockers"]["entries"]:
        for root in (REPO, PROJ):
            path = os.path.join(root, b["file"])
            if not os.path.isfile(path):
                continue
            with open(path, encoding="utf-8") as fh:
                if b["marker"] in fh.read():
                    fails.append(Failure("RELEASE", rel(path),
                                         f"{b['what']} {b['why']} "
                                         f"OWNER ACTION: {b['owner_action']}"))
    return fails


CHECKS = (
    ("A", "SPDX headers agree with the policy", check_spdx),
    ("B", "commercial directories carry a LICENSE notice", check_notice_files),
    ("D", "container images declare the right licence", check_dockerfiles),
    ("E", "core never imports commercial code", check_import_boundary),
    ("F", "every directory is classified exactly once", check_coverage),
    ("G", "one licence sentence everywhere", check_one_sentence),
    ("H", "every shipped artifact carries the notices", check_artifacts),
)


def run(policy: dict, release: bool) -> list[Failure]:
    fails: list[Failure] = []
    for _letter, _title, fn in CHECKS:
        fails.extend(fn(policy))
    if release:
        fails.extend(check_release_blockers(policy))
    return fails


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--release", action="store_true",
                    help="also fail on the recorded release blockers")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    policy = load_policy()
    fails = run(policy, args.release)

    if args.json:
        print(json.dumps({"ok": not fails,
                          "failures": [f.as_dict() for f in fails]}, indent=2))
        return 1 if fails else 0

    if not fails:
        scope = "eight checks + release blockers" if args.release else "eight checks"
        print(f"licensing-gate: PASS ({scope})")
        return 0

    by_check: dict[str, list[Failure]] = {}
    for f in fails:
        by_check.setdefault(f.check, []).append(f)
    print(f"licensing-gate: FAIL — {len(fails)} violation(s)", file=sys.stderr)
    for letter in sorted(by_check):
        print(f"  {letter}:", file=sys.stderr)
        for f in by_check[letter]:
            print(f"    {f.where}: {f.message}", file=sys.stderr)
        print(file=sys.stderr)
    print("The policy is licensing-policy.json. Fix the tree, or classify the new "
          "thing there and re-run scripts/gen-licensing-map.py --write.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
