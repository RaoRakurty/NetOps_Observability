# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""`install.py` refuses to build without the pre-built web assets, ACTIONABLY.

WHY (2026-09-03). `deployment/docker/Dockerfile.frontend` COPYs two directories
that are gitignored BUILD ARTIFACTS:

    src/frontend/dist      the compiled React SPA
    docs-portal/build      the in-app documentation portal served at /docs/

They are deliberately not in git — the Dockerfile explains that npm install
inside the docker build repeatedly hung on container DNS/registry timeouts — so
a CLEAN CLONE has neither. `validate_scaffold()` checked ~30 source files and
not these, so `install.py` sailed through its own scaffold gate and then died
minutes later inside BuildKit with:

    failed to compute cache key: "/src/frontend/dist": not found

which names no remedy and reads like a broken repo. `.github/workflows/
fresh-install-integrity.yml` carries the same lesson in a comment ("First run
of this leg failed exactly here"), which is exactly the kind of knowledge that
belongs in the installer instead of in a workflow comment.

WHAT IS PINNED HERE

  * the check runs on the path that BUILDS, and is skipped on the paths that do
    not: `--offline`/`--bundle` pass `--no-build` to compose, and `--no-start`
    returns before compose runs. release-bundle.yml provisions with
    `install.py --no-start` on a runner that has no npm — requiring the assets
    there would break CI, so "when does it NOT fire" is as load-bearing as
    "when does it fire";
  * an EMPTY directory fails too — it fails the docker build identically;
  * the failure message names the missing directory AND the command that builds
    it. A refusal an evaluator cannot act on is barely better than the BuildKit
    error it replaced.

No docker, no npm, no network: temp dirs and a captured SystemExit.

Run:  python3 -m pytest tests/test_install_prebuilt_assets.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import install  # noqa: E402


@pytest.fixture()
def scaffold(tmp_path: Path) -> Path:
    """A project root satisfying REQUIRED_PATHS but with no web assets."""
    root = tmp_path / "repo"
    for rel in install.REQUIRED_PATHS:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("// fixture\n")
    return root


def _build_assets(root: Path) -> None:
    for rel, _, _ in install.PREBUILT_WEB_ASSETS:
        d = root / rel
        d.mkdir(parents=True, exist_ok=True)
        (d / "index.html").write_text("<!doctype html>\n")


def test_the_asset_list_matches_what_the_frontend_image_copies() -> None:
    """The list is only correct if it tracks the Dockerfile it exists for."""
    dockerfile = (ROOT / "deployment" / "docker" / "Dockerfile.frontend").read_text()
    for rel, _, _ in install.PREBUILT_WEB_ASSETS:
        assert f"COPY {rel} " in dockerfile, (
            f"install.py requires {rel} but Dockerfile.frontend no longer COPYs "
            "it — one of the two has moved"
        )


def test_missing_assets_refuse_the_build(scaffold: Path, capsys) -> None:
    with pytest.raises(SystemExit) as e:
        install.validate_scaffold(scaffold, will_build=True)
    assert e.value.code == 1
    err = capsys.readouterr().err
    for rel, _, how in install.PREBUILT_WEB_ASSETS:
        assert rel in err, f"the refusal must name {rel}"
        assert how in err, (
            f"the refusal must state HOW to build {rel} — it replaces a "
            "BuildKit error that named no remedy"
        )


def test_the_refusal_points_at_the_no_node_alternatives(scaffold: Path, capsys) -> None:
    with pytest.raises(SystemExit):
        install.validate_scaffold(scaffold, will_build=True)
    err = capsys.readouterr().err
    assert "--bundle" in err, "a host without Node can still install from a bundle"
    assert "--no-start" in err


def test_present_assets_pass(scaffold: Path) -> None:
    _build_assets(scaffold)
    install.validate_scaffold(scaffold, will_build=True)  # must not raise


def test_an_empty_asset_directory_is_not_good_enough(scaffold: Path, capsys) -> None:
    """`rm -rf dist/*` and a half-finished build both leave the dir behind."""
    _build_assets(scaffold)
    empty = scaffold / install.PREBUILT_WEB_ASSETS[0][0]
    for child in empty.iterdir():
        child.unlink()
    with pytest.raises(SystemExit):
        install.validate_scaffold(scaffold, will_build=True)
    assert install.PREBUILT_WEB_ASSETS[0][0] in capsys.readouterr().err


@pytest.mark.skipif(hasattr(__import__("os"), "geteuid") and __import__("os").geteuid() == 0,
                    reason="root ignores directory permissions")
def test_an_unreadable_asset_directory_refuses_with_the_real_error(
        scaffold: Path, capsys) -> None:
    """§16.1: unreadable is NOT missing.

    Reporting a permission problem as "missing" would print an `npm run build`
    recipe that cannot fix it, and the docker build would then fail on the same
    directory a second time.
    """
    import os

    _build_assets(scaffold)
    blocked = scaffold / install.PREBUILT_WEB_ASSETS[0][0]
    mode = blocked.stat().st_mode
    os.chmod(blocked, 0o000)
    try:
        with pytest.raises(SystemExit) as e:
            install.validate_scaffold(scaffold, will_build=True)
    finally:
        os.chmod(blocked, mode)
    assert e.value.code == 1
    err = capsys.readouterr().err
    assert "cannot read" in err, f"the refusal must name the real error: {err}"
    assert str(blocked) in err
    assert "npm run build" not in err, (
        "a permission problem must not be reported as a missing build artifact"
    )


def test_a_non_building_install_does_not_require_the_assets(scaffold: Path) -> None:
    """--offline/--bundle/--no-start must stay installable with no npm at all."""
    install.validate_scaffold(scaffold, will_build=False)  # must not raise


def test_scaffold_failures_still_come_first(tmp_path: Path, capsys) -> None:
    """A genuinely broken tree must report THAT, not a missing dist/."""
    root = tmp_path / "empty"
    root.mkdir()
    with pytest.raises(SystemExit):
        install.validate_scaffold(root, will_build=True)
    err = capsys.readouterr().err
    assert "scaffold is incomplete" in err
    assert "npm run build" not in err


def test_installer_only_demands_assets_on_the_building_path() -> None:
    """The call site's gate is the contract; assert it in the source.

    A future refactor that drops `will_build` would silently reintroduce the
    CI break (release-bundle.yml provisions with --no-start on a Node-less
    runner) or the clean-clone break, and no other test would notice.
    """
    src = (SCRIPTS / "install.py").read_text()
    assert "validate_scaffold(root, will_build=not (args.no_start or args.offline))" in src, (
        "install.py's validate_scaffold call no longer gates the web-asset "
        "check on whether this run builds images"
    )
    # --bundle implies --offline (install.py sets it), so the gate covers it.
    assert "args.offline = True" in src
