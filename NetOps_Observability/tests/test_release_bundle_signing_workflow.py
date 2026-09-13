# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Guard: `release-bundle.yml` cannot publish an unsigned bundle.

WHY THIS EXISTS (RC1 governance directive 2026-09-13, Decision 3B / 9 / 10 —
Blocker D). `make-installer.sh` has been able to sign since #97, but the workflow
never set the key, so every bundle ever produced was unsigned and nothing in CI
noticed. `tests/test_release_signing.py` proves the SCRIPT fails closed; this file
proves the WORKFLOW that invokes it does too, because the script is only as
fail-closed as the job that runs it.

The shape asserted here, each line of it a way this has already gone wrong or
could silently go wrong again:

  * a tag build sets `CORRELIX_RELEASE_BUILD` — without it the script reverts to
    the historical "NOTE: checksum-only" behaviour and the release is unsigned;
  * the signing key is imported from `secrets.CORRELIX_DIST_SIGNING_KEY` and a
    MISSING secret FAILS the job. A `if: secrets.X != ''` style guard would skip
    the step and publish unsigned — the exact fail-open the directive removes;
  * the throwaway keyring is wiped in an `always()` step;
  * signature verification is its own step and it PRECEDES every upload;
  * no `run:` block enables `set -x`, and the secret is referenced exactly once
    (in an `env:` mapping) and never echoed (Decision 10);
  * every third-party action is pinned to a 40-hex commit sha (Decision 10);
  * the build is FROM THE TAG's commit — explicit `ref:` plus a `git describe
    --exact-match` refusal (Decision 9);
  * `permissions:` stay declared per job, top-level read-only.

Style follows `tests/test_required_checks_consistency.py`: parse the workflow as
YAML, assert on structure, and keep the `on:`-is-parsed-as-True trap handled.

Run:  python3 -m pytest tests/test_release_bundle_signing_workflow.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
RELEASE_BUNDLE = WORKFLOWS / "release-bundle.yml"

SECRET_NAME = "CORRELIX_DIST_SIGNING_KEY"
# The release-critical workflows: a floating action tag or a `set -x` in any of
# them is a supply-chain / secret-leak hazard on the publishing path.
RELEASE_CRITICAL = ("release-bundle.yml", "publish-images.yml", "release-gate.yml")


@pytest.fixture(scope="module")
def doc() -> dict:
    return yaml.safe_load(RELEASE_BUNDLE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def bundle_job(doc) -> dict:
    jobs = doc.get("jobs") or {}
    assert "bundle" in jobs, "release-bundle.yml no longer has a `bundle` job"
    return jobs["bundle"]


@pytest.fixture(scope="module")
def steps(bundle_job) -> list[dict]:
    st = bundle_job.get("steps") or []
    assert st, "the bundle job declares no steps"
    return st


def step_index(steps: list[dict], needle: str) -> int:
    """Index of the first step whose name OR run body contains `needle`."""
    for i, s in enumerate(steps):
        if needle in (s.get("name") or "") or needle in (s.get("run") or ""):
            return i
        if needle in (s.get("uses") or ""):
            return i
    raise AssertionError(f"no step matching {needle!r} in release-bundle.yml")


def code_lines(run: str) -> list[str]:
    """Non-comment, non-empty lines of a run block."""
    return [ln for ln in run.splitlines()
            if ln.strip() and not ln.strip().startswith("#")]


# ── release mode ────────────────────────────────────────────────────────────

def test_tag_build_sets_release_mode(bundle_job):
    env = bundle_job.get("env") or {}
    assert "CORRELIX_RELEASE_BUILD" in env, (
        "the bundle job must set CORRELIX_RELEASE_BUILD — without it make-installer.sh "
        "builds in developer mode and a tag ships an UNSIGNED bundle")
    value = str(env["CORRELIX_RELEASE_BUILD"])
    assert "refs/tags/" in value and "'1'" in value, (
        "release mode must be switched on for TAG refs specifically; got "
        f"{value!r}")


# ── the signing key: imported, fail-closed, never leaked, always wiped ──────

def test_the_signing_key_is_imported_from_the_named_secret(steps):
    i = step_index(steps, "Import the distribution signing key")
    step = steps[i]
    env = step.get("env") or {}
    refs = [v for v in env.values() if SECRET_NAME in str(v)]
    assert refs, f"the import step must read secrets.{SECRET_NAME} through env:"
    assert all("secrets." in str(v) for v in refs)
    run = step.get("run") or ""
    assert SECRET_NAME in run, (
        "the BLOCKED message must name the secret an operator has to create")
    assert "BLOCKED: distribution signing key not configured" in run
    assert "exit 1" in run, "a missing secret must FAIL, not warn"
    # gpg import must be batch+quiet and must never mint a key in CI.
    assert "--batch" in run and "--quiet" in run
    for forbidden in ("--gen-key", "--generate-key", "--quick-generate-key",
                      "--full-generate-key"):
        assert forbidden not in run, f"CI must never generate a signing key ({forbidden})"
    # A temporary, 700 keyring — not the runner's default GNUPGHOME.
    assert "mktemp -d" in run and "chmod 700" in run
    assert "GNUPGHOME=" in run and "GITHUB_ENV" in run
    assert "CORRELIX_SIGNING_KEY=" in run, (
        "the imported fingerprint must be exported as CORRELIX_SIGNING_KEY")


def test_the_import_step_is_never_skipped(steps):
    """Fail-closed means FAIL. A step conditioned on the secret being present
    would skip on a missing secret and publish an unsigned bundle."""
    step = steps[step_index(steps, "Import the distribution signing key")]
    cond = str(step.get("if", ""))
    assert SECRET_NAME not in cond, (
        "the import step must not be conditioned on the secret's presence — a "
        "skipped signing step is an unsigned release")
    assert "refs/tags/" in cond, "signing is required on tag builds"


def test_the_secret_is_referenced_once_and_never_echoed():
    text = RELEASE_BUNDLE.read_text(encoding="utf-8")
    # Comments are excluded: the header explains the mechanism by name, which is
    # documentation, not a second place the value can flow through.
    code = [ln for ln in text.splitlines() if not ln.strip().startswith("#")]
    occurrences = [ln for ln in code if f"secrets.{SECRET_NAME}" in ln]
    assert len(occurrences) == 1, (
        f"secrets.{SECRET_NAME} must be referenced exactly once (one env: "
        f"mapping); found {len(occurrences)}: {occurrences}")
    assert occurrences[0].strip().startswith("DIST_KEY:"), (
        "the secret must reach the job only through an env: mapping")
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if re.match(r"(echo|printf|cat)\b", stripped) and "DIST_KEY" in stripped:
            # printf '%s' "$DIST_KEY" | gpg --import is the ONE legitimate use:
            # it feeds the key to gpg on a pipe, not to the log.
            assert "| gpg" in stripped, f"the key must never be printed: {stripped}"


def test_the_keyring_is_wiped_whatever_happens(steps):
    i = step_index(steps, "Wipe the signing keyring")
    step = steps[i]
    assert "always()" in str(step.get("if", "")), (
        "the keyring wipe must run on failure and cancellation too")
    run = step.get("run") or ""
    assert 'rm -rf "$GNUPGHOME"' in run
    assert i == len(steps) - 1, "the wipe must be the last step of the job"


# ── verification precedes publication ───────────────────────────────────────

def test_verification_precedes_every_upload(steps):
    verify = step_index(steps, "Verify the bundle signature")
    attach = step_index(steps, "Attach to release")
    artifact = step_index(steps, "upload-artifact")
    assert verify < attach, "the signature must be verified BEFORE assets are attached"
    assert verify < artifact, "the signature must be verified BEFORE any upload"
    run = steps[verify].get("run") or ""
    assert "SHA256SUMS.asc" in run and "gpg" in run and "--verify" in run
    assert "exit 1" in run, "a missing signature must fail the job"
    assert "signing-key" in run, (
        "the verify step must also assert MANIFEST records the signer fingerprint")


def test_the_split_step_does_not_invalidate_the_signature(steps):
    """Splitting a >1900 MiB member used to append to README.md and rewrite the
    README's SHA256SUMS line — which would leave a signed bundle whose signature
    no longer matches its own checksum file."""
    run = steps[step_index(steps, "Prepare assets")].get("run") or ""
    assert "SHA256SUMS.asc" in run, (
        "the split step must know whether the bundle is signed before it edits "
        "README.md or SHA256SUMS")


# ── Decision 9: built from the tag's commit ─────────────────────────────────

def test_the_build_is_from_the_tags_commit(steps):
    checkout = steps[step_index(steps, "actions/checkout")]
    with_ = checkout.get("with") or {}
    assert "github.sha" in str(with_.get("ref", "")), (
        "the checkout must pin github.sha — never a branch head (Decision 9)")
    run = steps[step_index(steps, "Confirm the build commit is the tag")].get("run") or ""
    assert "git describe --exact-match --tags" in run
    assert "BLOCKED" in run and "exit 1" in run


# ── Decision 10: no leakage, least privilege, pinned actions ────────────────

def test_no_run_block_enables_shell_tracing():
    for name in RELEASE_CRITICAL:
        doc = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
        for job_id, job in (doc.get("jobs") or {}).items():
            for step in job.get("steps") or []:
                run = step.get("run") or ""
                for line in code_lines(run):
                    assert not re.search(r"set\s+-[a-z]*x", line), (
                        f"{name}:{job_id}: `set -x` would print secrets: {line.strip()}")


def test_every_third_party_action_is_pinned_to_a_sha():
    for name in RELEASE_CRITICAL:
        text = (WORKFLOWS / name).read_text(encoding="utf-8")
        for m in re.finditer(r"^\s*(?:-\s+)?uses:\s*(\S+)", text, re.MULTILINE):
            ref = m.group(1)
            if ref.startswith("./"):
                continue  # a reusable workflow in this repository, not a pin
            assert re.search(r"@[0-9a-f]{40}$", ref), (
                f"{name}: `uses: {ref}` is not pinned to a full commit sha")


def test_permissions_stay_minimal(doc, bundle_job):
    assert (doc.get("permissions") or {}).get("contents") == "read", (
        "the workflow's default token must stay read-only")
    perms = bundle_job.get("permissions") or {}
    assert perms.get("contents") == "write", (
        "the bundle job needs contents: write to attach assets — and nothing more")
    assert set(perms) == {"contents"}, f"bundle job asks for more than it needs: {perms}"
