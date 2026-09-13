# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Guard: the release workflows build the docs portal BEFORE the frontend image.

WHY THIS EXISTS. `release-bundle.yml`'s `bundle` job was RED on main — run
34721086054, 2026-09-12 — and the failure was not in the bundle logic at all:

    => ERROR [frontend 5/7] COPY docs-portal/build /usr/share/nginx/html/docs
    failed to compute cache key: "/docs-portal/build": not found

`deployment/docker/Dockerfile.frontend` COPYs TWO gitignored build artifacts.
`src/frontend/dist` is rebuilt by `make-installer.sh` itself (its step 1), so it
is always there. `docs-portal/build` — the Docusaurus site served at `/docs/` —
is the CALLER's to build, and nothing in the job built it. It never surfaced
locally because the deploy chain builds the portal first, exactly as
`install.py`'s `PREBUILT_WEB_ASSETS` recipe tells an operator to.

`publish-images.yml` builds the same image from the same Dockerfile and looked
green — because **it has never run**: it triggers on `v*.*.*` tags and
`workflow_dispatch` only, and no tag has been pushed. Its green status was the
absence of evidence, not evidence of correctness; the first RC1 tag would have
failed in its `frontend` matrix leg for the identical reason. So the fix is one
canonical recipe in BOTH workflows, and this file exists to keep the copies from
drifting — because two copies of a command that must agree, with nothing
asserting they do, is how this defect gets reintroduced one workflow at a time.

Asserted here:

  * release-bundle.yml's `bundle` job builds the portal, and that step PRECEDES
    the step that builds images (`make-installer.sh`, whose step 2 is
    `docker compose build`);
  * publish-images.yml's `publish` job builds the portal for the `frontend`
    matrix leg, and that step PRECEDES `docker/build-push-action`;
  * every workflow that builds the portal uses the SAME command, and that command
    is the one `scripts/install.py` records as the operator recipe;
  * the build cannot fail silently (`set -euo pipefail`, `&&`-chained, no
    `|| true` — §16.1);
  * `uses:` pins in the two touched workflows are still 40-hex shas.

And, executed rather than grepped, the §16.1 half of the fix in
`scripts/make-installer.sh`: a missing / empty / entry-point-less
`docs-portal/build` is FATAL in the script's own preflight, in seconds, naming
the command that fixes it — instead of being reported minutes later by BuildKit,
about a path that does not exist in the repository. The dry-run modes
(`--licenses-only`, `--source-offer-only`, `--sign-only`) build no image and must
NOT be gated on the portal.

`tests/test_install_prebuilt_assets.py` is the same contract for `install.py`,
which learned this lesson on 2026-09-03. `make-installer.sh` — the other script
that drives `docker compose build` — never did, which is this defect's root.

Run:  python3 -m pytest tests/test_release_bundle_docs_portal.py -v
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PROJECT_ROOT.parent
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
RELEASE_BUNDLE = WORKFLOWS / "release-bundle.yml"
PUBLISH_IMAGES = WORKFLOWS / "publish-images.yml"
MAKE_INSTALLER = PROJECT_ROOT / "scripts" / "make-installer.sh"

# The ONE canonical recipe. `npm ci` (not `install`) so the lockfile is
# authoritative; `--no-audit --no-fund` because a registry audit round-trip is
# not part of building a static site; `&&` so a failed install never runs a build
# against a half-populated node_modules.
PORTAL_CMD = ("(cd NetOps_Observability/docs-portal && "
              "npm ci --no-audit --no-fund && npm run build)")
# What install.py tells an operator to run, minus the workflow's repo-relative
# subshell. The two must stay the same command.
INSTALL_PY_RECIPE = "cd docs-portal && npm ci --no-audit --no-fund && npm run build"


def load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def steps_of(path: Path, job: str) -> list[dict]:
    jobs = load(path).get("jobs") or {}
    assert job in jobs, f"{path.name} no longer has a `{job}` job"
    st = jobs[job].get("steps") or []
    assert st, f"{path.name}:{job} declares no steps"
    return st


def step_index(steps: list[dict], needle: str) -> int:
    """Index of the first step whose name, run body or `uses:` contains `needle`."""
    for i, step in enumerate(steps):
        for field in ("name", "run", "uses"):
            if needle in (step.get(field) or ""):
                return i
    raise AssertionError(f"no step matching {needle!r}")


def portal_lines(text: str) -> list[str]:
    """Every non-comment line of a workflow that builds docs-portal."""
    out = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or "docs-portal" not in stripped:
            continue
        if "npm run build" in stripped:
            out.append(stripped)
    return out


# ── ordering: the portal is built before anything builds an image ────────────

def test_the_bundle_job_builds_the_docs_portal_before_the_image_build():
    steps = steps_of(RELEASE_BUNDLE, "bundle")
    portal = step_index(steps, "docs-portal/build)")
    # The bundle build is what builds images: make-installer.sh's step 2 is
    # `docker compose build`, which is where run 34721086054 died. (Matched by
    # step NAME — an earlier step's comment names the script too.)
    image = step_index(steps, "Build bundle")
    assert "make-installer.sh" in (steps[image].get("run") or ""), (
        "the `Build bundle` step no longer invokes make-installer.sh — this "
        "test's notion of 'the image build' needs updating")
    assert portal < image, (
        "the docs-portal build must PRECEDE the bundle build; the frontend image "
        "COPYs docs-portal/build and cannot be built without it")
    run = steps[portal].get("run") or ""
    assert PORTAL_CMD in run, (
        f"the bundle job must build the portal with the canonical recipe:\n  {PORTAL_CMD}")


def test_publish_images_builds_the_docs_portal_before_the_image_build():
    steps = steps_of(PUBLISH_IMAGES, "publish")
    portal = step_index(steps, "docs-portal/build)")
    build = step_index(steps, "docker/build-push-action@")
    assert portal < build, (
        "publish-images.yml builds the frontend image from the same Dockerfile — "
        "the portal must be built before docker/build-push-action runs")
    step = steps[portal]
    assert PORTAL_CMD in (step.get("run") or ""), (
        f"publish-images.yml must use the canonical recipe:\n  {PORTAL_CMD}")
    # Only the frontend image needs it; the api/correlation/nginx legs must not
    # pay for a Docusaurus build.
    assert "matrix.name == 'frontend'" in str(step.get("if", "")), (
        "the portal build belongs to the frontend matrix leg only")


# ── one recipe, everywhere, and it is the documented one ────────────────────

def test_every_workflow_builds_the_docs_portal_the_same_way():
    """release-bundle.yml and publish-images.yml cannot drift apart — and neither
    can the two workflows that already had this step (fresh-install-integrity,
    scale-miniladder-nightly)."""
    found: dict[str, list[str]] = {}
    for wf in sorted(WORKFLOWS.glob("*.yml")):
        lines = portal_lines(wf.read_text(encoding="utf-8"))
        if lines:
            found[wf.name] = lines
    assert "release-bundle.yml" in found, (
        "release-bundle.yml no longer builds the docs portal — the bundle job's "
        "frontend image build cannot succeed without it (run 34721086054)")
    assert "publish-images.yml" in found, (
        "publish-images.yml no longer builds the docs portal — its frontend "
        "matrix leg builds the same Dockerfile")
    distinct = {line for lines in found.values() for line in lines}
    assert distinct == {PORTAL_CMD}, (
        "every workflow must build the docs portal with ONE canonical command; "
        f"found {len(distinct)} variants: {sorted(distinct)}")


def test_the_recipe_is_the_one_install_py_tells_operators_to_run():
    """CI and the installer's own advice must not disagree about how to build
    the portal: PREBUILT_WEB_ASSETS is what an operator reads when the check
    fires on their host."""
    install_py = (PROJECT_ROOT / "scripts" / "install.py").read_text(encoding="utf-8")
    assert INSTALL_PY_RECIPE in install_py, (
        "scripts/install.py no longer records this recipe in PREBUILT_WEB_ASSETS; "
        "CI and the operator instructions have drifted")
    # The workflow line is that same command, run from the repo root.
    from_repo_root = INSTALL_PY_RECIPE.replace(
        "cd docs-portal", "cd NetOps_Observability/docs-portal", 1)
    assert PORTAL_CMD == f"({from_repo_root})"


# ── the build cannot fail quietly (§16.1) ───────────────────────────────────

def test_the_docs_portal_build_fails_the_job_on_error():
    for path, job in ((RELEASE_BUNDLE, "bundle"), (PUBLISH_IMAGES, "publish")):
        steps = steps_of(path, job)
        run = steps[step_index(steps, "docs-portal/build)")].get("run") or ""
        code = [ln.strip() for ln in run.splitlines()
                if ln.strip() and not ln.strip().startswith("#")]
        assert "set -euo pipefail" in code, (
            f"{path.name}: the portal build must not run under a lenient shell")
        for line in code:
            assert "|| true" not in line, (
                f"{path.name}: a swallowed Docusaurus failure ships an image with "
                f"no documentation (§16.1): {line}")


def test_the_touched_workflows_keep_their_sha_pins():
    """Belt and braces with tests/test_workflow_action_pins.py: these two files
    are the release-publishing path, where a floating tag is RCE with secrets."""
    for path in (RELEASE_BUNDLE, PUBLISH_IMAGES):
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"^\s*(?:-\s+)?uses:\s*(\S+)", text, re.MULTILINE):
            ref = match.group(1)
            if ref.startswith("./"):
                continue  # this repository's own reusable workflow
            assert re.search(r"@[0-9a-f]{40}$", ref), (
                f"{path.name}: `uses: {ref}` is not pinned to a 40-hex commit sha")


# ── make-installer.sh refuses to start without the portal (executed) ────────

def fake_root(tmp_path: Path) -> Path:
    """A tree holding NOTHING but the script under test.

    The preflight under test must fire before the script touches anything else,
    so a root with no repository in it is the honest fixture: if the guard were
    to move back below `docker compose build`, these tests would fail on a
    missing src/frontend instead, which is the signal we want.
    """
    root = tmp_path / "tree"
    (root / "scripts").mkdir(parents=True)
    target = root / "scripts" / "make-installer.sh"
    target.write_bytes(MAKE_INSTALLER.read_bytes())
    target.chmod(0o755)
    return root


def run_make_installer(root: Path, *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.pop("CORRELIX_RELEASE_BUILD", None)
    env.pop("CORRELIX_SIGNING_KEY", None)
    env.pop("REBUILD_FRONTEND", None)
    return subprocess.run(
        ["bash", str(root / "scripts" / "make-installer.sh"), *args],
        capture_output=True, text=True, env=env, cwd=str(root), timeout=120,
        check=False,
    )


def test_a_missing_docs_portal_build_is_fatal(tmp_path):
    root = fake_root(tmp_path)
    result = run_make_installer(root)
    assert result.returncode != 0, (
        "make-installer.sh started a build with no documentation portal; the "
        "frontend image COPYs it and BuildKit is the wrong messenger")
    assert "FATAL" in result.stderr
    assert "docs-portal/build is missing" in result.stderr
    # The message must carry the fix, not just the symptom.
    assert "npm ci --no-audit --no-fund && npm run build" in result.stderr
    # ...and it must happen BEFORE any expensive or state-changing work.
    assert "docker compose build" not in result.stdout
    assert "building frontend dist" not in result.stdout
    assert not (root / "dist").exists(), (
        "the refusal must leave no half-built bundle directory behind (§16.3)")


def test_an_empty_docs_portal_build_is_fatal(tmp_path):
    """`rm -rf build/*` or an interrupted Docusaurus run leaves the directory
    behind; the docker COPY fails on it exactly as if it were absent."""
    root = fake_root(tmp_path)
    (root / "docs-portal" / "build").mkdir(parents=True)
    result = run_make_installer(root)
    assert result.returncode != 0
    assert "EMPTY" in result.stderr
    assert "npm run build" in result.stderr


def test_a_portal_without_an_entry_point_is_fatal(tmp_path):
    root = fake_root(tmp_path)
    build = root / "docs-portal" / "build"
    build.mkdir(parents=True)
    (build / "assets.js").write_text("// not an entry point\n", encoding="utf-8")
    result = run_make_installer(root)
    assert result.returncode != 0
    assert "no index.html" in result.stderr


def test_an_unreadable_portal_is_not_reported_as_missing(tmp_path):
    """§16.1: a permission error must not be dressed up as a missing build — the
    npm recipe cannot fix it, and the docker COPY would fail again."""
    root = fake_root(tmp_path)
    build = root / "docs-portal" / "build"
    build.mkdir(parents=True)
    (build / "index.html").write_text("<html></html>\n", encoding="utf-8")
    build.chmod(0o000)
    try:
        result = run_make_installer(root)
    finally:
        build.chmod(0o755)
    if result.returncode == 0:
        pytest.skip("this host can read a 0000 directory (running as root?)")
    assert "cannot read" in result.stderr
    assert "permissions" in result.stderr
    assert "is missing" not in result.stderr


def test_the_dry_run_modes_are_not_gated_on_the_portal(tmp_path):
    """`--licenses-only` / `--source-offer-only` / `--sign-only` build no image
    and copy no portal. CI runs them (supply-chain.yml, publish-images.yml,
    tests/test_release_signing.py) on trees where the portal was never built, so
    requiring it there would fail them for nothing."""
    root = fake_root(tmp_path)
    for args in (["--sign-only", str(root)], ["--licenses-only"],
                 ["--source-offer-only"]):
        result = run_make_installer(root, *args)
        assert "docs-portal" not in result.stderr, (
            f"`{' '.join(args)}` must not require the documentation portal: "
            f"{result.stderr.strip()[:300]}")
