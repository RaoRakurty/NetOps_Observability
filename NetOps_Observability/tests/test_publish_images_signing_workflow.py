# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Guard: `publish-images.yml` cannot release an image it has not verified.

WHY THIS EXISTS (owner Decision 4, 2026-09-13; tracker 313). Two separate holes
were filed in that row, and both were real:

  1. **No image signature at all.** Zero cosign/Notation references repo-wide. The
     SLSA build-provenance attestation is adjacent to a signature, not a
     substitute for one: provenance says how a digest was built, a signature says
     who stands behind it.
  2. **The registry was written before anything was checked.**
     `docker/build-push-action` ran with `push: true` and the *release tags*
     applied, and the attestation followed unconditionally — so a failed
     attestation failed the JOB while leaving a fully tagged, unattested,
     unsigned digest in GHCR. The job was fail-closed; the artifact was not.

The owner's decision splits the signing model: GPG stays for conventional bundles
(`release-bundle.yml`, `CORRELIX_DIST_SIGNING_KEY`, directive Decision 3B) and
**Cosign keyless** — GitHub Actions OIDC, short-lived Fulcio certificate, no
permanent private key in GitHub Secrets — signs OCI images **by immutable
digest**. This file is the contract for the image half. Its sibling,
`tests/test_release_bundle_signing_workflow.py`, is the contract for the bundle
half and this file deliberately mirrors its style.

The shape asserted here, each line of it a way this has already gone wrong or
could silently go wrong again:

  * `sigstore/cosign-installer` is pinned to a 40-hex SHA with a version comment,
    and the cosign version it installs is pinned explicitly too (Decision 10 —
    a floating tool inside a pinned action is still a floating tool);
  * the sign step targets `…@sha256:<digest>`, never a tag. A tag can be
    re-pointed at another manifest, which would leave a valid signature attached
    to an image nobody reviewed;
  * `cosign verify` exists, is its own step, and **precedes** the provenance
    attestation and every step that applies a release tag;
  * the verification identity is EXACT: the literal
    `https://token.actions.githubusercontent.com` issuer, and an identity naming
    this repository and this workflow file. No `--certificate-identity-regexp`,
    which with a permissive pattern accepts a signature minted by any workflow in
    any repository;
  * the build pushes BY DIGEST ONLY, so no release tag exists before verification;
  * `id-token: write` is scoped to the one job that needs it, top-level stays
    read-only, and no `run:` block enables `set -x` (Decision 10);
  * `actions/attest-build-provenance` runs on the DIGEST and after verification;
  * the SBOM step is still present and is still a separate, unchanged control —
    the directive's Decision 7 says do not add overlapping provenance tooling, and
    folding the SBOM into the signature step would do exactly that.

WHAT THIS FILE CANNOT PROVE. Keyless signing needs an Actions OIDC token, which
does not exist outside a GitHub-hosted run, so nothing here executes cosign. What
is provable locally — and is what this file proves — is the workflow's SHAPE: step
order, action pins, permission scopes, and the literal verification policy
strings. The signature itself is first exercised on the first `v*` tag build.

Run:  python3 -m pytest tests/test_publish_images_signing_workflow.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
PUBLISH_IMAGES = WORKFLOWS / "publish-images.yml"

WORKFLOW_PATH = ".github/workflows/publish-images.yml"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
SHA40_RE = re.compile(r"@[0-9a-f]{40}$")


@pytest.fixture(scope="module")
def text() -> str:
    return PUBLISH_IMAGES.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def doc() -> dict:
    return yaml.safe_load(PUBLISH_IMAGES.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def publish_job(doc) -> dict:
    jobs = doc.get("jobs") or {}
    assert "publish" in jobs, "publish-images.yml no longer has a `publish` job"
    return jobs["publish"]


@pytest.fixture(scope="module")
def steps(publish_job) -> list[dict]:
    st = publish_job.get("steps") or []
    assert st, "the publish job declares no steps"
    return st


def step_index(steps: list[dict], needle: str) -> int:
    """Index of the first step whose name, `uses:` or run body contains `needle`."""
    for i, s in enumerate(steps):
        for field in ("name", "uses", "run"):
            if needle in (s.get(field) or ""):
                return i
    raise AssertionError(f"no step matching {needle!r} in publish-images.yml")


def code_lines(run: str) -> list[str]:
    """Non-comment, non-empty lines of a run block."""
    return [ln for ln in run.splitlines()
            if ln.strip() and not ln.strip().startswith("#")]


def flat(step: dict) -> str:
    """Every string a step carries, for substring assertions."""
    parts = [str(step.get(k) or "") for k in ("name", "uses", "run", "if")]
    for mapping in ("env", "with"):
        for key, value in (step.get(mapping) or {}).items():
            parts.append(f"{key}: {value}")
    return "\n".join(parts)


# ── the cosign toolchain: pinned action, pinned tool ────────────────────────

def test_cosign_installer_is_pinned_to_a_sha_with_a_version_comment(text):
    """A tag is not a pin: the publisher can move it, and the action then runs
    with this job's OIDC token. `tests/test_workflow_action_pins.py` sweeps every
    workflow; this names the one that signs, because it is the one whose
    compromise forges a Correlix release."""
    lines = [ln for ln in text.splitlines() if "sigstore/cosign-installer@" in ln]
    assert len(lines) == 1, (
        f"expected exactly one sigstore/cosign-installer pin, found {len(lines)}: {lines}")
    spec_match = re.search(r"uses:\s*(\S+)", lines[0])
    assert spec_match, f"unparsable uses line: {lines[0]!r}"
    assert SHA40_RE.search(spec_match.group(1)), (
        f"cosign-installer must be pinned to a full 40-hex commit SHA: {lines[0].strip()}")
    assert re.search(r"#\s*v\d+(?:\.\d+)*", lines[0]), (
        "the pin must carry a `# vX.Y.Z` comment — a bare SHA is unreviewable "
        f"and nobody can tell whether it is current: {lines[0].strip()}")


def test_the_cosign_pin_records_how_and_when_it_was_verified(text):
    """The same standard cla-check.yml documents for its pin: record the tag, the
    SHA, the API that was queried, and the date it was checked."""
    assert "api.github.com/repos/sigstore/cosign-installer/tags" in text, (
        "the comment above the pin must name the API queried to resolve tag -> SHA")
    assert re.search(r"verified 20\d\d-\d\d-\d\d", text), (
        "the comment must record the date the pin was verified")


def test_the_installed_cosign_version_is_pinned_too(steps):
    """A pinned action installing a floating tool is still a floating tool."""
    step = steps[step_index(steps, "sigstore/cosign-installer@")]
    with_ = step.get("with") or {}
    release = str(with_.get("cosign-release") or "")
    assert re.fullmatch(r"v\d+\.\d+\.\d+", release), (
        "cosign-installer must be given an explicit `cosign-release: vX.Y.Z` so a "
        f"cosign upgrade is a reviewed change; got {release!r}")


# ── the digest, never a tag ─────────────────────────────────────────────────

def test_the_build_pushes_by_digest_only(steps):
    """Tracker 313's second hole: the build used to apply the release tags at push
    time, so a digest was reachable by `:{{version}}` before anything checked it."""
    build = steps[step_index(steps, "docker/build-push-action@")]
    with_ = build.get("with") or {}
    outputs = str(with_.get("outputs") or "")
    assert "push-by-digest=true" in outputs, (
        "the build must push BY DIGEST ONLY so no release tag exists before "
        f"verification; `outputs:` is {outputs!r}")
    assert "tags" not in with_, (
        "the build step must not apply tags — they are applied after verification "
        f"by the retag step; got tags: {with_.get('tags')!r}")
    assert build.get("id") == "build", (
        "the build step must keep `id: build`; the digest every later step signs, "
        "verifies and attests is `steps.build.outputs.digest`")


def test_the_sign_step_targets_a_digest_and_refuses_a_tag(steps):
    step = steps[step_index(steps, "Sign the image digest")]
    blob = flat(step)
    assert "@${{ steps.build.outputs.digest }}" in blob, (
        "the signed reference must be `<image>@<digest>` built from the build "
        "step's digest output, not a tag")
    run = step.get("run") or ""
    assert "cosign sign" in run and "--yes" in run, (
        "the sign step must run `cosign sign --yes` non-interactively")
    assert "@sha256:" in run, (
        "the sign step must assert its target is a digest reference — an empty "
        "digest output would otherwise degrade to signing `:latest`")
    assert "exit 1" in run and "BLOCKED" in run, (
        "a non-digest reference must FAIL the job, loudly")
    for forbidden in ("--key", "--sk", "COSIGN_PRIVATE_KEY", "COSIGN_PASSWORD"):
        assert forbidden not in blob, (
            f"image signing is KEYLESS (owner Decision 4): {forbidden} reintroduces "
            "stored key material into the image trust domain")


def test_no_step_signs_a_mutable_reference(text):
    """Belt and braces over the whole file: every `cosign sign` target must be a
    digest expression, whatever step it lives in."""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or "cosign sign" not in stripped:
            continue
        assert '"$IMAGE"' in stripped or "@sha256:" in stripped or "digest" in stripped, (
            f"`cosign sign` must target a digest, not a tag: {stripped}")


# ── verification, and what it is pinned to ──────────────────────────────────

def test_the_verify_step_exists_and_pins_the_exact_identity(steps):
    step = steps[step_index(steps, "Verify the image signature")]
    blob = flat(step)
    run = step.get("run") or ""

    assert any(ln.strip().startswith("cosign verify") for ln in code_lines(run)), (
        "the verify step must actually INVOKE `cosign verify` — a commented-out or "
        "`true`-prefixed invocation still contains the string")
    assert "--certificate-oidc-issuer" in run, (
        "verification must pin the OIDC issuer — without it any issuer's "
        "certificate is accepted")
    assert OIDC_ISSUER in blob, (
        f"the issuer must be the literal GitHub Actions issuer {OIDC_ISSUER}")
    assert "--certificate-identity" in run, (
        "verification must pin the certificate identity — `cosign verify` without "
        "it is not identity verification at all")

    # The identity is built from the workflow's own ref, which is exactly the
    # certificate subject Fulcio issues for this job.
    assert "github.workflow_ref" in blob, (
        "the identity must be constructed from github.workflow_ref (the exact "
        "certificate subject), not hand-written and not guessed")
    assert "github.server_url" in blob, (
        "the identity is a URL: prefix github.workflow_ref with github.server_url")

    # And it is checked against this repository and this file before use.
    assert WORKFLOW_PATH in blob, (
        f"the verify step must name this workflow's path ({WORKFLOW_PATH}) so an "
        "identity that stops pointing at this file fails instead of passing")
    assert "GITHUB_REPOSITORY" in blob or "github.repository" in blob, (
        "the identity check must bind to THIS repository")
    assert "BLOCKED" in run and "exit 1" in run, (
        "a wrong or empty identity must fail the job before cosign is called")


def test_verification_never_uses_a_permissive_identity_regexp(text):
    """`--certificate-identity-regexp '.*'` verifies that *someone* signed the
    image, which is not a control. If a regexp is ever unavoidable it must be
    anchored to this repository and this workflow path."""
    for n, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#") or "--certificate-identity-regexp" not in stripped:
            continue
        assert WORKFLOW_PATH in stripped and "^" in stripped, (
            f"line {n}: an identity regexp must be anchored to this repository and "
            f"{WORKFLOW_PATH}; prefer the exact --certificate-identity: {stripped}")


def test_verification_precedes_the_attestation_and_every_release_tag(steps):
    """The ordering IS the control (owner's flow: push digest -> sign -> verify ->
    provenance -> release)."""
    sign = step_index(steps, "Sign the image digest")
    verify = step_index(steps, "Verify the image signature")
    attest = step_index(steps, "actions/attest-build-provenance@")
    retag = step_index(steps, "Publish the release tags")
    build = step_index(steps, "docker/build-push-action@")

    assert build < sign < verify, "sign the built digest, then verify it"
    assert verify < attest, (
        "the provenance attestation must run AFTER the signature is verified — it "
        "writes to the registry (`push-to-registry: true`), so attesting first "
        "publishes a claim about an unverified image")
    assert verify < retag, (
        "no release tag may be applied before verification — a tag is the only "
        "thing a customer can actually pull by name")


def test_the_release_tags_are_applied_last_and_pinned_to_the_signed_digest(steps):
    retag = step_index(steps, "Publish the release tags")
    step = steps[retag]
    run = step.get("run") or ""
    blob = flat(step)

    assert "imagetools create" in run, (
        "the tags must be applied by a registry-side retag of the signed digest, "
        "not by a second build")
    assert "--prefer-index=false" in run, (
        "without it buildx wraps a single-platform manifest in a NEW index, giving "
        "the tag a different digest from the one that was signed (docker/buildx#2481)")
    assert "steps.meta.outputs.tags" in blob, (
        "the tag set must still come from docker/metadata-action — the tags are "
        "unchanged, only when they are applied")
    assert "EXPECTED_DIGEST" in run or "outputs.digest" in blob, (
        "the retag must know which digest it is supposed to publish")
    assert "BLOCKED" in run and "exit 1" in run, (
        "a tag that does not resolve to the signed digest must fail the job")

    # Nothing may publish or announce after it except the always() artifact upload.
    for later in steps[retag + 1:]:
        assert "always()" in str(later.get("if", "")), (
            f"step {later.get('name') or later.get('uses')!r} runs after the release "
            "tags are applied without being an always() cleanup step — re-check "
            "whether it belongs before verification")


# ── provenance: on the digest, after verification, and checked ──────────────

def test_the_attestation_runs_against_the_digest(steps):
    step = steps[step_index(steps, "actions/attest-build-provenance@")]
    with_ = step.get("with") or {}
    assert "steps.build.outputs.digest" in str(with_.get("subject-digest") or ""), (
        "the attestation must name the digest actually pushed")
    assert str(with_.get("push-to-registry")) in ("True", "true"), (
        "the attestation is published to the registry alongside the image")
    assert step.get("id"), (
        "the attest step needs an `id:` so its outputs can be checked rather than "
        "assumed (owner Decision 4)")


def test_the_attestation_outputs_are_checked(steps):
    """A step that reports success while producing no bundle would leave the
    release claiming a provenance it does not have."""
    attest = steps[step_index(steps, "actions/attest-build-provenance@")]
    confirm_i = step_index(steps, "Confirm the provenance attestation")
    confirm = steps[confirm_i]
    blob = flat(confirm)
    run = confirm.get("run") or ""

    assert confirm_i > step_index(steps, "actions/attest-build-provenance@")
    assert f"steps.{attest['id']}.outputs.bundle-path" in blob, (
        "the check must read the attest step's bundle-path output")
    assert "BLOCKED" in run and "exit 1" in run, (
        "a missing or empty attestation bundle must fail the job")
    # The five things the provenance has to identify (owner Decision 4).
    for needle, label in (
        ("EXPECTED_DIGEST", "the image digest"),
        ("GITHUB_REPOSITORY", "the repository"),
        ("GITHUB_SHA", "the commit sha"),
        ("GITHUB_EVENT_NAME", "the build event"),
        (WORKFLOW_PATH, "the workflow"),
    ):
        assert needle in blob, (
            f"the provenance check must assert the statement identifies {label} "
            f"({needle})")
    assert "slsa.dev/provenance/" in run, (
        "the check must assert the statement really is SLSA provenance")


# ── the SBOM stays a separate, unchanged control ────────────────────────────

def test_the_sbom_step_is_still_present_and_separate(steps):
    """Directive Decision 7: do not add overlapping provenance tooling. The SBOM
    is its own control over the same digest; it must not be folded into signing."""
    step = steps[step_index(steps, "anchore/sbom-action@")]
    with_ = step.get("with") or {}
    assert "steps.build.outputs.digest" in str(with_.get("image") or ""), (
        "the SBOM must still be generated against the pushed digest")
    assert str(with_.get("format")) == "cyclonedx-json", (
        "the SBOM format is unchanged (CycloneDX JSON)")
    assert "cosign" not in flat(step).lower(), (
        "the SBOM step must stay independent of the signing steps")


def test_the_oci_compliance_gate_still_runs_in_release_mode(steps):
    """The pre-existing release gate must not have been reordered out of the way,
    and it must stay after verification."""
    verify = step_index(steps, "Verify the image signature")
    compliance = step_index(steps, "OCI source-compliance gate")
    assert verify < compliance
    run = steps[compliance].get("run") or ""
    assert "--release" in run, "the compliance gate must stay in release mode"


# ── Decision 10: least privilege, no leakage, everything pinned ─────────────

def test_id_token_write_is_scoped_to_the_publish_job(doc, publish_job):
    assert (doc.get("permissions") or {}).get("contents") == "read", (
        "the workflow's default token must stay read-only")
    perms = publish_job.get("permissions") or {}
    assert perms.get("id-token") == "write", (
        "keyless signing needs the OIDC token — `id-token: write` on this job")
    assert perms.get("packages") == "write", "pushing to GHCR needs packages: write"
    assert perms.get("attestations") == "write", "the provenance attestation needs it"
    assert perms.get("contents") == "read", "this job never writes repository contents"
    assert set(perms) == {"contents", "packages", "id-token", "attestations"}, (
        f"the publish job asks for more than it needs: {perms}")

    for job_id, job in (doc.get("jobs") or {}).items():
        if job_id == "publish":
            continue
        assert "write" not in str((job.get("permissions") or {}).values()), (
            f"job `{job_id}` must not hold a write scope: {job.get('permissions')}")


def test_no_run_block_enables_shell_tracing(steps):
    """`set -x` in a job holding an OIDC token prints the whole environment."""
    for step in steps:
        for line in code_lines(step.get("run") or ""):
            assert not re.search(r"set\s+-[a-z]*x", line), (
                f"`set -x` in {step.get('name')!r} would print the job's "
                f"environment: {line.strip()}")


def test_no_step_dumps_the_environment(steps):
    for step in steps:
        for line in code_lines(step.get("run") or ""):
            stripped = line.strip()
            assert not re.fullmatch(r"(env|printenv|export\s+-p)\b.*", stripped), (
                f"an environment dump in {step.get('name')!r} leaks the OIDC "
                f"token request headers: {stripped}")


def test_no_secrets_are_referenced_beyond_the_registry_login(text):
    """Keyless means keyless: the only secret this workflow may touch is the
    built-in GITHUB_TOKEN used to log in to GHCR."""
    for n, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#") or "secrets." not in stripped:
            continue
        assert "secrets.GITHUB_TOKEN" in stripped, (
            f"line {n}: image signing is keyless — this workflow must not read any "
            f"other secret: {stripped}")


def test_every_action_is_pinned_to_a_forty_hex_sha(text):
    for n, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^\s*(?:-\s+)?uses:\s*(\S+)", line)
        if not m:
            continue
        spec = m.group(1)
        if spec.startswith("./"):
            continue  # a reusable workflow in this repository
        assert SHA40_RE.search(spec), (
            f"line {n}: `uses: {spec}` is not pinned to a full commit SHA")


def test_the_gate_still_precedes_the_publish_job(doc, publish_job):
    """Belt and braces over `tests/test_required_checks_consistency.py`: the
    signing order is worthless if untested code can reach the registry."""
    needs = publish_job.get("needs")
    needs = [needs] if isinstance(needs, str) else list(needs or [])
    assert "gate" in needs, "the publish job must stay `needs: gate`"
    gate = (doc.get("jobs") or {}).get("gate") or {}
    assert str(gate.get("uses", "")).endswith("/release-gate.yml")


def test_the_build_is_from_the_tags_commit(steps):
    """Decision 9 — the flow starts at a protected source SHA, not a branch head."""
    checkout = steps[step_index(steps, "actions/checkout@")]
    assert "github.sha" in str((checkout.get("with") or {}).get("ref", "")), (
        "the checkout must pin github.sha, as release-bundle.yml does")
