# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Guard: `.github/CODEOWNERS` names every release-critical surface, and names
nobody who does not exist.

WHY THIS EXISTS. RC1 governance directive Decision 6
(`docs/release/RC1_GOVERNANCE_DIRECTIVE_2026-09-13.md`) requires review
ownership over the licence declarations, the CI workflows, the release and
installer scripts, the licence verification/signing code, the authn/authz
policy and the core/commercial boundary. Two failure modes make a CODEOWNERS
file worse than none:

  1. **It goes stale.** A rule whose path no longer exists matches nothing.
     GitHub reports no error for it, so the file keeps *looking* like a control
     while the renamed directory is owned by nobody. Every pattern below is
     therefore resolved against the real tree at test time.
  2. **It gets narrower than the thing it protects.** Somebody adds
     `internal/entitlement/`, or the commercial boundary grows a directory, and
     the file silently stops covering the class it was written for. So the
     classes are asserted by REPRESENTATIVE REAL PATHS — and the
     core/commercial class is derived from `licensing-policy.json`
     `commercial_paths`, the gate's own definition, rather than restated here.

Also asserted: every owner is the explicit `@OWNER-PLACEHOLDER`. The directive's
Non-goals forbid inventing personnel, and a plausible-looking invented handle
would be the worst outcome of all — it reads as a named reviewer and resolves to
nothing. The file is inert until a human substitutes a real handle, and this
suite holds it to saying so.
"""

from __future__ import annotations

import fnmatch
import json
from pathlib import Path

import pytest

PROJ = Path(__file__).resolve().parents[1]
REPO = PROJ.parent
CODEOWNERS = REPO / ".github" / "CODEOWNERS"

PLACEHOLDER = "@OWNER-PLACEHOLDER"

# GitHub reads the FIRST CODEOWNERS it finds, in this order. A second copy would
# make the effective file a matter of trivia, so only the first location may hold
# one.
LOOKUP_ORDER = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")


# ── parsing ──────────────────────────────────────────────────────────────────
def rules() -> list[tuple[int, str, list[str]]]:
    """(line number, pattern, owners) for every rule line."""
    out: list[tuple[int, str, list[str]]] = []
    for n, raw in enumerate(CODEOWNERS.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        out.append((n, fields[0], fields[1:]))
    return out


def matches(pattern: str, relpath: str) -> bool:
    """Does a CODEOWNERS pattern cover this repo-relative path?

    Only the subset of the syntax this file uses: rooted patterns, directory
    patterns ending in `/`, and shell wildcards. Deliberately NOT a full
    gitignore implementation — if a pattern here ever needs one, that is a
    signal the file has become too clever to review.
    """
    pat = pattern.lstrip("/")
    if pat.endswith("/"):
        return relpath == pat.rstrip("/") or relpath.startswith(pat)
    return fnmatch.fnmatch(relpath, pat) or relpath.startswith(pat + "/")


def covered(relpath: str) -> list[str]:
    return [pat for _n, pat, _o in rules() if matches(pat, relpath)]


# ── the sensitive classes, as representative real paths ──────────────────────
def commercial_boundary_paths() -> list[str]:
    """From the licensing gate's own authority, never restated here."""
    policy = json.loads((PROJ / "licensing-policy.json").read_text(encoding="utf-8"))
    return [f"NetOps_Observability/{e['path']}"
            for e in policy["commercial_paths"]["entries"]]


CLASSES: dict[str, list[str]] = {
    "licence declarations (both roots)": [
        "LICENSE",
        "LICENSES/Apache-2.0.txt",
        "LICENSES/Correlix-Enterprise.txt",
        "LICENSING.md",
        "CONTRIBUTING.md",
        "CLA.md",
        "NetOps_Observability/LICENSE",
        "NetOps_Observability/LICENSES/Correlix-Enterprise.txt",
        "NetOps_Observability/LICENSING.md",
        "NetOps_Observability/NOTICE",
    ],
    "the licensing policy and its gate": [
        "NetOps_Observability/licensing-policy.json",
        "NetOps_Observability/scripts/licensing-gate.py",
        "NetOps_Observability/scripts/gen-licensing-map.py",
        "NetOps_Observability/scripts/spdx-headers.py",
        "NetOps_Observability/scripts/license-audit.py",
    ],
    "CI workflows": [
        ".github/workflows/release-gate.yml",
        ".github/workflows/release-bundle.yml",
        ".github/workflows/publish-images.yml",
        ".github/workflows/supply-chain.yml",
        ".github/CODEOWNERS",
    ],
    "release and installer scripts": [
        "NetOps_Observability/scripts/make-installer.sh",
        "NetOps_Observability/scripts/install-correlix.sh",
        "NetOps_Observability/scripts/install.py",
        "NetOps_Observability/scripts/release-qualify.py",
        "NetOps_Observability/scripts/deploy-qualify.sh",
        "NetOps_Observability/scripts/source-archive.py",
    ],
    "licence verification and signing code": [
        "NetOps_Observability/src/backend/internal/licence/keys.go",
        "NetOps_Observability/src/backend/internal/licence/document.go",
        "NetOps_Observability/src/backend/internal/licence/signer/signer.go",
        "NetOps_Observability/src/backend/cmd/correlix-licence/main.go",
    ],
    "authn / authz policy": [
        "NetOps_Observability/src/backend/auth.go",
        "NetOps_Observability/src/backend/auth_config.go",
        "NetOps_Observability/src/backend/authz.go",
        "NetOps_Observability/src/backend/oidc.go",
        "NetOps_Observability/src/backend/oidc_config.go",
        "NetOps_Observability/src/backend/tenancy.go",
        "NetOps_Observability/src/backend/internal/rbac/access.go",
        "NetOps_Observability/src/backend/internal/token/jwt.go",
        "NetOps_Observability/src/backend/internal/elevation/elevation.go",
        "NetOps_Observability/src/backend/internal/users",
    ],
}


# ── the tests ────────────────────────────────────────────────────────────────
def test_codeowners_exists_at_the_location_github_reads_first():
    assert CODEOWNERS.is_file(), (
        f"{LOOKUP_ORDER[0]} is missing. RC1 directive Decision 6 requires it."
    )
    for later in LOOKUP_ORDER[1:]:
        assert not (REPO / later).exists(), (
            f"a second CODEOWNERS exists at {later}. GitHub reads "
            f"{LOOKUP_ORDER[0]} first, so this one enforces nothing while "
            f"appearing to; delete it or merge it into the first."
        )


def test_there_is_at_least_one_rule():
    assert rules(), "CODEOWNERS has no rule lines, so it owns nothing"


@pytest.mark.parametrize("case", rules(), ids=lambda c: f"L{c[0]}:{c[1]}")
def test_every_rule_resolves_to_something_on_disk(case):
    """A pattern matching nothing is a rule that silently stopped protecting its
    path. GitHub does not report it, so this does."""
    _n, pattern, _owners = case
    pat = pattern.lstrip("/")
    if pat.endswith("/"):
        assert (REPO / pat.rstrip("/")).is_dir(), (
            f"CODEOWNERS pattern {pattern!r} names a directory that does not "
            f"exist. If it moved, move the rule; if it is gone, delete the rule."
        )
        assert any((REPO / pat.rstrip("/")).rglob("*")), (
            f"CODEOWNERS pattern {pattern!r} names an EMPTY directory"
        )
    else:
        hits = list(REPO.glob(pat))
        assert hits, (
            f"CODEOWNERS pattern {pattern!r} matches no file in the tree"
        )


@pytest.mark.parametrize("case", rules(), ids=lambda c: f"L{c[0]}")
def test_every_rule_names_the_explicit_placeholder_and_no_invented_handle(case):
    """Directive Non-goals: never invent personnel. One placeholder, spelled the
    same way everywhere, so a human substitution is a single mechanical edit."""
    n, pattern, owners = case
    assert owners, f"line {n}: {pattern!r} has no owner at all"
    for owner in owners:
        assert owner == PLACEHOLDER, (
            f"line {n}: owner {owner!r} on {pattern!r} is not the agreed "
            f"placeholder {PLACEHOLDER!r}. If this is a real handle it must be "
            f"added by a human who can confirm the account exists; if it is a "
            f"guess, it resolves to nobody and reads as a named reviewer."
        )


@pytest.mark.parametrize("name,paths", sorted(CLASSES.items()))
def test_every_sensitive_path_class_is_covered(name, paths):
    for relpath in paths:
        assert (REPO / relpath).exists(), (
            f"the representative path {relpath!r} for {name!r} no longer "
            f"exists; update this test AND the CODEOWNERS rule together"
        )
        assert covered(relpath), (
            f"{relpath!r} ({name}) is matched by NO CODEOWNERS rule — the "
            f"directive requires this class to have an owner"
        )


def test_the_core_commercial_boundary_is_covered_per_the_licensing_policy():
    """Derived, not restated: if `commercial_paths` grows a directory and
    CODEOWNERS does not, the relicensing surface loses its reviewer."""
    paths = commercial_boundary_paths()
    assert paths, "licensing-policy.json declares no commercial paths"
    for relpath in paths:
        assert (REPO / relpath).is_dir(), f"{relpath} is not a directory"
        assert covered(relpath), (
            f"{relpath} is declared commercial in licensing-policy.json but is "
            f"matched by no CODEOWNERS rule. A change there relicenses code."
        )


def test_the_file_documents_that_it_is_inert_until_a_human_edits_it():
    body = CODEOWNERS.read_text(encoding="utf-8")
    assert "HUMAN ACTION REQUIRED" in body, (
        "the file must carry the explicit HUMAN ACTION REQUIRED note the "
        "directive asks for"
    )
    flat = " ".join(body.lower().split())
    assert "inert" in flat, (
        "the file must say plainly that it enforces nothing while the owner is "
        "a placeholder — GitHub ignores an unresolvable owner without erroring"
    )
    assert "require_code_owner_reviews" in body, (
        "the file must record that code-owner review is NOT required on main, "
        "and why (single maintainer, approvals kept at 0 on 2026-09-13)"
    )


def test_the_signing_paths_carry_the_two_approval_consideration():
    """Directive Decision 6: "Consider two approvals on the most sensitive
    signing paths." Recorded as a marked target state rather than applied,
    because two approvals needs three humans to stay unblocked."""
    body = CODEOWNERS.read_text(encoding="utf-8")
    assert "SIGNING PATH" in body, (
        "no rule is marked as a signing path, so the two-approval "
        "consideration is not recorded anywhere"
    )
    marked_blocks = [b for b in body.split("# ──") if "SIGNING PATH" in b]
    assert len(marked_blocks) >= 2, (
        "the signing marker appears in fewer than two sections; the directive "
        "names three trust domains (tag, artifact, licence) and at least the "
        "artifact and licence ones live in this repository"
    )
    for needle in ("internal/licence/", "cmd/correlix-licence/",
                   "make-installer.sh"):
        assert needle in body, f"{needle} is not owned, but it is a signing path"
