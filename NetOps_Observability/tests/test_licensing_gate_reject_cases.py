# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""The licence-gate REJECT cases the RC1 directive names, each proven.

WHY THIS FILE EXISTS, separately from tests/test_licensing_consistency.py. That
suite asserts the TREE is in a good state today — the placeholder is still a
placeholder, no core file carries the commercial identifier, every commercial
file is marked. Those are necessary, but they all pass on a gate that checks
nothing: they read the same files the gate reads and reach the same conclusion by
themselves. What was never proven is that the GATE REJECTS the bad state, and a
gate nobody has seen fail is a gate nobody knows works.

RC1 governance directive Decision 1
(`docs/release/RC1_GOVERNANCE_DIRECTIVE_2026-09-13.md`) enumerates five states
the gate must reject:

  1. the enterprise licence text file is MISSING
  2. it still contains the placeholder marker
  3. it is EMPTY
  4. a file in a commercial directory does not carry the commercial SPDX id
  5. a core/Apache file wrongly carries the commercial SPDX id

A sixth group was added when the owner's Decision 3 (2026-09-13) fixed the
canonical path at EXACTLY `LICENSES/LicenseRef-Correlix-Enterprise.txt`, one-to-
one with the SPDX id. Decision 1's five cases all assume the gate knows WHICH
file to look at; case 6 proves that binding, because during the rename the tree
briefly had one filename and every reference had the other, and a stale checkout
in that state must fail rather than pass on a path nothing resolves.

(2), (4) and (5) were already rejected; (1) and (3) were not, and were fixed in
the same change as this file. The specific holes, recorded because they are the
kind that comes back:

  * (1) `check_artifacts` (check H) demanded the text be present at EITHER root,
    because that is where the installer bundle sources it from. So deleting the
    PROJECT copy — the one that ships in the bundle and in every image — left the
    gate green. And `check_release_blockers` looked for its marker only in files
    that existed, so deleting the file made the release blocker DISAPPEAR: the
    gate reported the placeholder resolved because the placeholder was gone.
  * (3) an empty file has no marker in it either, so blanking it did the same
    thing as deleting it, and check H was satisfied because the path existed.

HOW THE BAD STATES ARE PRODUCED. Cases (1) and (3) are about the enterprise
licence text, which nothing in a test may modify — it is the file counsel's text
lands in, and a crashed test leaving it truncated is not an acceptable failure
mode. So those run against a FIXTURE TREE in `tmp_path` with the gate's own
`REPO`/`PROJ` module globals pointed at it, calling the gate's own functions.
Cases (4) and (5) plant a throwaway `.go` file in the real tree and run the real
script, the way `test_the_import_checker_actually_catches_a_core_to_enterprise_import`
already does for check E — a Go file is cheap to create and delete, and the probe
is removed in a `finally`.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

PROJ = Path(__file__).resolve().parents[1]
REPO = PROJ.parent
GATE = PROJ / "scripts" / "licensing-gate.py"

# The exact sentence the directive requires the release report to contain.
# Pinned here as a literal: if licensing-policy.json's `report` string is
# reworded, the report the owner promised changes, and that must fail a test
# rather than pass quietly.
BLOCKED_SENTENCE = (
    "BLOCKED: final Correlix Enterprise licence text required from counsel."
)


# ── loading the gate as a module ─────────────────────────────────────────────
@pytest.fixture(scope="module")
def gate():
    """The gate itself. Its filename has a dash, so it is not importable by
    name; this is the same mechanism the gate uses on its own siblings."""
    spec = importlib.util.spec_from_file_location("_licensing_gate", GATE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def policy() -> dict:
    return json.loads((PROJ / "licensing-policy.json").read_text(encoding="utf-8"))


@pytest.fixture
def fixture_tree(tmp_path, policy, monkeypatch, gate):
    """A minimal two-root tree that the gate considers HEALTHY, with the gate
    pointed at it.

    Returns (repo, proj). Both roots carry both licence texts, and every
    commercial directory the policy declares carries its notice file — the same
    shape the real tree has, and no more. `assert_healthy` below proves the
    fixture starts clean, so a later failure is caused by the mutation under test
    and not by the fixture being wrong.
    """
    repo = tmp_path / "repo"
    proj = repo / "NetOps_Observability"
    comm = policy["identifiers"]["commercial"]

    bodies = {
        policy["identifiers"]["core"]: (
            "Apache License\nVersion 2.0, January 2004\n"
            "http://www.apache.org/licenses/\n" + ("filler text. " * 20)
        ),
        comm: (
            f"Correlix Enterprise License\nSPDX identifier: {comm}\n\n"
            "CORRELIX-ENTERPRISE-TEXT-PLACEHOLDER\n\n"
            "THIS FILE DOES NOT YET CONTAIN A LICENCE.\n"
        ),
    }
    for root in (repo, proj):
        (root / "LICENSES").mkdir(parents=True, exist_ok=True)
        for ident, relpath in policy["licence_texts"].items():
            (root / relpath).write_text(bodies[ident], encoding="utf-8")
    for entry in policy["commercial_paths"]["entries"]:
        notice = proj / entry["notice_file"]
        notice.parent.mkdir(parents=True, exist_ok=True)
        notice.write_text(
            f"Correlix Enterprise License\nSPDX identifier: {comm}\n",
            encoding="utf-8",
        )

    monkeypatch.setattr(gate, "REPO", str(repo))
    monkeypatch.setattr(gate, "PROJ", str(proj))
    return repo, proj


def enterprise_text_paths(policy: dict, repo: Path, proj: Path) -> list[Path]:
    relpath = policy["licence_texts"][policy["identifiers"]["commercial"]]
    return [repo / relpath, proj / relpath]


def assert_healthy(gate, policy):
    assert gate.check_notice_files(policy) == [], (
        "the fixture tree is not clean to begin with, so nothing this file "
        "asserts about the gate's rejections can be trusted"
    )


def messages(fails) -> str:
    return "\n".join(f"{f.check} {f.where}: {f.message}" for f in fails)


# ─────────────────────────────────────────────────────────────────────────────
# case 1 — the enterprise licence text is MISSING
# ─────────────────────────────────────────────────────────────────────────────

def test_the_fixture_tree_is_clean_before_anything_is_broken(gate, policy, fixture_tree):
    assert_healthy(gate, policy)


@pytest.mark.parametrize("which", ["both roots", "project root only",
                                   "repository root only"])
def test_case1_a_missing_enterprise_licence_text_is_rejected(
        gate, policy, fixture_tree, which):
    """Rejected in the DEFAULT mode, and at EITHER root independently.

    Both copies are real shipped surfaces: the repository root is what a reader
    lands on, the project root is what `make-installer.sh` puts in the bundle and
    what the images COPY. Losing one is not half a problem.
    """
    repo, proj = fixture_tree
    assert_healthy(gate, policy)
    repo_text, proj_text = enterprise_text_paths(policy, repo, proj)
    targets = {"both roots": [repo_text, proj_text],
               "project root only": [proj_text],
               "repository root only": [repo_text]}[which]
    for path in targets:
        path.unlink()

    fails = gate.check_notice_files(policy)
    assert fails, (
        f"the gate ACCEPTED a tree with the enterprise licence text missing at "
        f"{which}. Every file marked with the identifier is then licensed to "
        f"nobody, and the gate is the only thing that would notice."
    )
    text = messages(fails)
    assert all(f.check == "B" for f in fails), text
    assert "missing" in text
    for path in targets:
        assert path.name in text, text


def test_case1_a_missing_blocker_file_does_not_make_the_blocker_vanish(
        gate, policy, fixture_tree):
    """The fail-open this replaced: `--release` used to report the placeholder
    blocker resolved when the placeholder file had simply been deleted."""
    repo, proj = fixture_tree
    narrowed = {"release_blockers": {"entries": [
        b for b in policy["release_blockers"]["entries"]
        if b["id"] == "enterprise-text-placeholder"
    ]}}
    assert narrowed["release_blockers"]["entries"], "the blocker has been removed"

    before = gate.check_release_blockers(narrowed)
    assert before, "the fixture's placeholder text does not trip the blocker"

    for path in enterprise_text_paths(policy, repo, proj):
        path.unlink()
    after = gate.check_release_blockers(narrowed)
    assert after, (
        "deleting the licence text made its release blocker DISAPPEAR. A blocker "
        "that cannot be evaluated must never read as a blocker that was cleared."
    )
    text = messages(after)
    assert BLOCKED_SENTENCE in text, text
    assert "NEITHER" in text or "could not be evaluated" in text, text


# ─────────────────────────────────────────────────────────────────────────────
# case 2 — the placeholder marker is still present
# ─────────────────────────────────────────────────────────────────────────────
# Already proven, and deliberately not re-proven here:
#   * tests/test_licensing_consistency.py::test_enterprise_licence_text_is_still_an_undrafted_placeholder
#     — the marker is present in both copies and the text says it grants nothing.
#   * tests/test_licensing_consistency.py::test_release_blockers_are_recorded_and_still_open
#     — `--release` fails, only on RELEASE failures, for exactly the two recorded ids.
# What was NOT proven is the report STRING, which the directive specifies
# verbatim, so that is what these two add.

def test_case2_the_release_gate_reports_the_directives_exact_blocked_sentence():
    """Run against the real tree, read-only. `--release` must keep failing today,
    and its report must contain the sentence the directive requires — the owner's
    release report and the gate's output are then the same words by construction.
    """
    result = subprocess.run(
        [sys.executable, str(GATE), "--release", "--json"],
        capture_output=True, text=True, cwd=PROJ, check=False,
    )
    report = json.loads(result.stdout)
    assert result.returncode != 0 and not report["ok"], (
        "`licensing-gate.py --release` PASSES. If counsel's Correlix Enterprise "
        "licence text has landed, that is correct — remove the blocker from "
        "licensing-policy.json and update this test and "
        "tests/test_licensing_consistency.py together."
    )
    blob = "\n".join(f["message"] for f in report["failures"])
    assert BLOCKED_SENTENCE in blob, (
        f"the release report does not contain the directive's required sentence "
        f"{BLOCKED_SENTENCE!r}. What it said instead:\n{blob}"
    )


def test_case2_the_blocked_sentence_lives_in_the_policy_not_in_the_gate():
    """One authority. The gate prints what licensing-policy.json records, so the
    sentence cannot be changed in the code without changing the policy."""
    policy_raw = (PROJ / "licensing-policy.json").read_text(encoding="utf-8")
    gate_raw = GATE.read_text(encoding="utf-8")
    assert BLOCKED_SENTENCE in policy_raw, (
        "the required sentence is not recorded in licensing-policy.json"
    )
    assert BLOCKED_SENTENCE not in gate_raw, (
        "the gate hard-codes the blocker's report sentence. It must read it from "
        "the policy, or the two will drift."
    )


# ─────────────────────────────────────────────────────────────────────────────
# case 3 — the enterprise licence text is EMPTY
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("body,why", [
    ("", "completely empty"),
    ("\n\n   \n\t\n", "whitespace only"),
    ("TBD\n", "a stub"),
])
def test_case3_an_empty_or_stubbed_enterprise_licence_text_is_rejected(
        gate, policy, fixture_tree, body, why):
    repo, proj = fixture_tree
    assert_healthy(gate, policy)
    for path in enterprise_text_paths(policy, repo, proj):
        path.write_text(body, encoding="utf-8")

    fails = gate.check_notice_files(policy)
    assert fails, (
        f"the gate ACCEPTED a licence text that is {why}. A blank licence file "
        f"grants exactly as much as a missing one: nothing."
    )
    text = messages(fails)
    assert all(f.check == "B" for f in fails), text
    assert "EMPTY" in text or "truncated" in text or "stubbed" in text, text


def test_case3_an_empty_blocker_file_still_reports_blocked(gate, policy, fixture_tree):
    """Blanking the file removes the marker too. The marker's absence must not be
    read as the placeholder having been replaced by counsel's text."""
    repo, proj = fixture_tree
    narrowed = {"release_blockers": {"entries": [
        b for b in policy["release_blockers"]["entries"]
        if b["id"] == "enterprise-text-placeholder"
    ]}}
    for path in enterprise_text_paths(policy, repo, proj):
        path.write_text("", encoding="utf-8")

    fails = gate.check_release_blockers(narrowed)
    assert fails, "an empty licence text silently cleared its release blocker"
    text = messages(fails)
    assert BLOCKED_SENTENCE in text, text


def test_case3_a_real_licence_text_is_accepted(gate, policy, fixture_tree):
    """The other direction, so the checks above are not passing for the trivial
    reason that the gate rejects everything. A substantive text that names its
    identifier passes check B — only `--release` still objects, and only to the
    placeholder marker."""
    repo, proj = fixture_tree
    comm = policy["identifiers"]["commercial"]
    for path in enterprise_text_paths(policy, repo, proj):
        path.write_text(
            f"Correlix Enterprise License\nSPDX identifier: {comm}\n\n"
            "1. Definitions. " + ("Terms and conditions. " * 30),
            encoding="utf-8",
        )
    assert gate.check_notice_files(policy) == [], (
        "check B rejects a substantive licence text that names its identifier"
    )


def test_case3_a_licenceref_text_that_does_not_name_its_identifier_is_rejected(
        gate, policy, fixture_tree):
    """A LicenseRef is resolved by nothing except its own file, so the file must
    say which identifier it is the text for."""
    repo, proj = fixture_tree
    for path in enterprise_text_paths(policy, repo, proj):
        path.write_text(
            "Some Other Company Source-Available License\n\n"
            "1. Definitions. " + ("Terms and conditions. " * 30),
            encoding="utf-8",
        )
    fails = gate.check_notice_files(policy)
    assert fails, (
        "a licence text that names a DIFFERENT licence was accepted as the text "
        "for LicenseRef-Correlix-Enterprise"
    )
    assert "does not name the identifier" in messages(fails)


# ─────────────────────────────────────────────────────────────────────────────
# case 6 — the identifier and its file are bound one-to-one (owner Decision 3)
# ─────────────────────────────────────────────────────────────────────────────
# Owner Decision 3 (2026-09-13) fixes the canonical artifact path at EXACTLY
# `LICENSES/LicenseRef-Correlix-Enterprise.txt`, one-to-one with the SPDX id
# commercial sources declare. The rename is the interesting part: for one commit
# the tree had one name and every reference had the other, and the states below
# are the ones a half-applied checkout, a bad merge, or a "make both paths work"
# copy actually produces. None of them may pass.
STALE_ENTERPRISE_NAME = "Correlix-Enterprise.txt"  # the pre-Decision-3 filename


def test_case6_the_canonical_name_is_what_the_policy_declares(policy):
    """The binding itself, asserted against the real policy and the real tree.

    Pinned as a literal rather than derived from the id, so renaming the FILE and
    the id together — which would silently satisfy a derived assertion — still
    fails here and forces the owner decision to be re-read.
    """
    comm = policy["identifiers"]["commercial"]
    assert comm == "LicenseRef-Correlix-Enterprise", (
        "the SPDX identifier changed. Decision 3 keeps it fixed; a rename is an "
        "owner decision, not a refactor"
    )
    assert policy["licence_texts"][comm] == (
        "LICENSES/LicenseRef-Correlix-Enterprise.txt"
    ), "the canonical enterprise licence path is not the one Decision 3 names"
    for root in (REPO, PROJ):
        canonical = root / "LICENSES" / "LicenseRef-Correlix-Enterprise.txt"
        assert canonical.is_file(), f"{canonical} is missing"
        stale = root / "LICENSES" / STALE_ENTERPRISE_NAME
        assert not stale.exists(), (
            f"{stale} still exists. The terms must live in exactly one file; the "
            f"rename is a `git mv`, never a copy"
        )


def test_case6_a_stale_checkout_with_only_the_old_filename_is_rejected(
        gate, policy, fixture_tree):
    """The stale-checkout state: the placeholder is present, but under the name
    the tree used BEFORE Decision 3 — so every reference, every SPDX header and
    the installer's bundle list point at a path that does not exist.

    This must fail in the DEFAULT mode. A gate that passed here would certify a
    tree in which the commercial identifier resolves to nothing, which is the
    exact defect the identifier-to-file binding exists to prevent.
    """
    repo, proj = fixture_tree
    assert_healthy(gate, policy)
    for path in enterprise_text_paths(policy, repo, proj):
        path.rename(path.with_name(STALE_ENTERPRISE_NAME))

    fails = gate.check_notice_files(policy)
    assert fails, (
        "the gate ACCEPTED a tree carrying the enterprise licence text ONLY under "
        "its pre-Decision-3 filename. Nothing in the repository resolves that "
        "path, so every commercially marked file is licensed to nobody."
    )
    text = messages(fails)
    assert all(f.check == "B" for f in fails), text
    assert "LicenseRef-Correlix-Enterprise.txt" in text, text
    assert "missing" in text, text


def test_case6_the_stale_filename_does_not_clear_the_release_blocker(
        gate, policy, fixture_tree):
    """And `--release` must still say BLOCKED. The marker is still in the tree,
    just under a name the blocker is not evaluated against — which is precisely
    the fail-open shape (a blocker that became unevaluable reading as cleared)
    that case 1 closed for deletion. Renaming must not reopen it."""
    repo, proj = fixture_tree
    narrowed = {"release_blockers": {"entries": [
        b for b in policy["release_blockers"]["entries"]
        if b["id"] == "enterprise-text-placeholder"
    ]}}
    assert narrowed["release_blockers"]["entries"], "the blocker has been removed"
    for path in enterprise_text_paths(policy, repo, proj):
        path.rename(path.with_name(STALE_ENTERPRISE_NAME))

    fails = gate.check_release_blockers(narrowed)
    assert fails, (
        "renaming the licence text to its old filename cleared its release "
        "blocker. A blocker that cannot be evaluated is not a blocker that was "
        "cleared."
    )
    text = messages(fails)
    assert BLOCKED_SENTENCE in text, text
    assert "NEITHER" in text or "could not be evaluated" in text, text


@pytest.mark.parametrize("which", ["both roots", "project root only",
                                   "repository root only"])
def test_case6_a_second_file_carrying_the_same_terms_is_rejected(
        gate, policy, fixture_tree, which):
    """A copy left beside the canonical file — "so both paths keep working".

    Two files resolving one LicenseRef can disagree about what was granted, and
    the one a scanner picks is then a matter of which reference it followed. The
    bytes are identical the day the copy is made and nothing keeps them that way,
    so this fails even though the copy is currently correct.
    """
    repo, proj = fixture_tree
    assert_healthy(gate, policy)
    repo_text, proj_text = enterprise_text_paths(policy, repo, proj)
    targets = {"both roots": [repo_text, proj_text],
               "project root only": [proj_text],
               "repository root only": [repo_text]}[which]
    for path in targets:
        path.with_name(STALE_ENTERPRISE_NAME).write_text(
            path.read_text(encoding="utf-8"), encoding="utf-8")

    fails = gate.check_notice_files(policy)
    assert fails, (
        f"the gate ACCEPTED a duplicate copy of the enterprise licence terms at "
        f"{which}. Exactly one file may carry them."
    )
    text = messages(fails)
    assert all(f.check == "B" for f in fails), text
    assert "SECOND file" in text, text
    assert STALE_ENTERPRISE_NAME in text, text
    assert len(fails) == len(targets), text


def test_case6_the_apache_text_is_not_treated_as_a_duplicate(
        gate, policy, fixture_tree):
    """The other direction, so the duplicate scan is not just rejecting company.

    The enterprise placeholder names `Apache-2.0` in prose — it has to, because it
    says what is NOT commercial — and `LICENSES/Apache-2.0.txt` sits in the same
    directory. Neither is a second copy of the other's terms, and a scan that
    flagged either would be un-silenceable noise on a healthy tree.
    """
    assert_healthy(gate, policy)
    comm = policy["identifiers"]["commercial"]
    assert gate._check_no_duplicate_terms(
        policy["identifiers"]["core"],
        policy["licence_texts"][policy["identifiers"]["core"]]) == [], (
        "the stock Apache-2.0 text was reported as having a duplicate"
    )
    assert gate._check_no_duplicate_terms(comm, policy["licence_texts"][comm]) == []


def test_case6_a_licenceref_declared_at_a_non_matching_path_is_rejected(
        gate, policy, fixture_tree):
    """The policy itself pointed somewhere else.

    `licensing-policy.json` is the gate's only authority, so a rename applied
    there and nowhere else would move the canonical path by editing one line. The
    basename must be the identifier, which makes the canonical path a rule rather
    than a value somebody can re-point.
    """
    repo, proj = fixture_tree
    comm = policy["identifiers"]["commercial"]
    moved = dict(policy)
    moved["licence_texts"] = dict(policy["licence_texts"])
    moved["licence_texts"][comm] = "LICENSES/Commercial.txt"
    for root in (repo, proj):
        (root / "LICENSES" / "Commercial.txt").write_text(
            (root / policy["licence_texts"][comm]).read_text(encoding="utf-8"),
            encoding="utf-8")
        (root / policy["licence_texts"][comm]).unlink()

    fails = gate.check_notice_files(moved)
    assert fails, (
        "the policy was allowed to declare the enterprise licence text at a path "
        "not named for its identifier, so the canonical path is re-pointable"
    )
    text = messages(fails)
    assert "one-to-one" in text and "LicenseRef-Correlix-Enterprise.txt" in text, text


def test_case6_an_identifier_with_no_licence_text_at_all_is_rejected(
        gate, policy, fixture_tree):
    """The simplest way to make every arm above vacuous: drop the mapping. Then
    the commercial identifier every enterprise file declares resolves to no file,
    and a loop over `licence_texts` checks nothing."""
    comm = policy["identifiers"]["commercial"]
    orphaned = dict(policy)
    orphaned["licence_texts"] = {
        k: v for k, v in policy["licence_texts"].items() if k != comm
    }
    fails = gate.check_notice_files(orphaned)
    assert fails, (
        "an identifier the policy declares with NO licence_texts entry passed. "
        "Every file marked with it then resolves to no terms and the gate looked "
        "at nothing."
    )
    text = messages(fails)
    assert "no entry in licence_texts" in text, text


# ─────────────────────────────────────────────────────────────────────────────
# cases 4 and 5 — the SPDX marking, planted in the real tree
# ─────────────────────────────────────────────────────────────────────────────
PROBE_NAME = "zz_reject_case_probe.go"


def run_real_gate() -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(GATE)],
        capture_output=True, text=True, cwd=PROJ, check=False,
    )


def plant_and_run(path: Path, body: str) -> subprocess.CompletedProcess:
    assert not path.exists(), f"a previous run left {path} behind"
    path.write_text(body, encoding="utf-8")
    try:
        return run_real_gate()
    finally:
        path.unlink()


def test_case4_a_commercial_file_without_the_commercial_spdx_id_is_rejected(policy):
    """Check A's commercial direction: an unmarked file in a commercial directory.

    Its real consequence is the quiet opposite of a leak — the file defaults to
    Apache-2.0 in every scanner that reads headers, so commercial code ships
    labelled as core.
    """
    entry = policy["commercial_paths"]["entries"][0]
    directory = PROJ / entry["path"]
    assert directory.is_dir(), f"{entry['path']} has moved; update this test"
    package = next(
        line.split()[1]
        for src in sorted(directory.glob("*.go"))
        for line in src.read_text(encoding="utf-8").splitlines()
        if line.startswith("package ")
    )
    probe = directory / PROBE_NAME
    result = plant_and_run(
        probe,
        f"package {package}\n\n"
        f"// Deliberate licensing violation planted by {Path(__file__).name}.\n"
        f"// If you are reading this in a working tree, delete it.\n",
    )
    assert result.returncode != 0, (
        f"the gate PASSED with an UNMARKED file in the commercial directory "
        f"{entry['path']} — check A is not enforcing the commercial direction\n"
        f"{result.stdout}\n{result.stderr}"
    )
    output = result.stdout + result.stderr
    assert "A:" in output and PROBE_NAME in output, output
    assert policy["identifiers"]["commercial"] in output, output

    after = run_real_gate()
    assert after.returncode == 0, (
        f"the gate does not pass again after removing the probe:\n"
        f"{after.stdout}\n{after.stderr}"
    )


def test_case5_a_core_file_carrying_the_commercial_spdx_id_is_rejected(policy):
    """The dangerous direction: a stray commercial header on an Apache-2.0 file
    restricts code the project promised was open, and the promise is the thing
    people rely on."""
    comm = policy["identifiers"]["commercial"]
    core_pkg = PROJ / "src" / "backend" / "internal" / "hardening"
    assert core_pkg.is_dir(), "the core package this test plants into has moved"
    probe = core_pkg / PROBE_NAME
    result = plant_and_run(
        probe,
        f"// SPDX-License-Identifier: {comm}\n"
        f"// {policy['header_enforcement']['copyright_line']}\n"
        f"//\n"
        f"// Deliberate licensing violation planted by {Path(__file__).name}.\n"
        f"// If you are reading this in a working tree, delete it.\n"
        f"\npackage hardening\n",
    )
    assert result.returncode != 0, (
        f"the gate PASSED with an Apache-2.0 core file declaring {comm} — "
        f"check C is not enforcing the boundary\n{result.stdout}\n{result.stderr}"
    )
    output = result.stdout + result.stderr
    assert "C:" in output and PROBE_NAME in output, output
    assert "NOT inside a commercial directory" in output, output

    after = run_real_gate()
    assert after.returncode == 0, (
        f"the gate does not pass again after removing the probe:\n"
        f"{after.stdout}\n{after.stderr}"
    )


def test_no_probe_was_left_behind():
    """Runs last by file order. A leaked probe would make the next full gate run
    fail for a reason nobody can find."""
    leaked = sorted(str(p.relative_to(PROJ)) for p in PROJ.rglob(PROBE_NAME))
    assert not leaked, f"probe files left in the tree: {leaked}"
