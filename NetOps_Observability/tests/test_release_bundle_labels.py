# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""The release bundle must not lie about which profile it is.

WHY (2026-09-03). `scripts/make-installer.sh` takes `[--core]`:

    --core   base appliance archive ONLY (PROFILE=core)
    (none)   base + the optional add-on packs (PROFILE=full, the default)

`25a6045a` (the #97 add-on-pack change) deliberately dropped `--core` from
`.github/workflows/release-bundle.yml` so releases carry the packs. Nothing
that NAMES the profile moved with it:

  * make-installer.sh wrote `profile:  core` into MANIFEST unconditionally —
    directly above the add-on packs it had just listed in the same file;
  * the workflow uploaded the artifact as `correlix-bundle-core`;
  * the release notes said "(core profile)";
  * docs/design/packaging-strategy.md §6 still described `--core` in CI.

None of that breaks a build, which is why it survived: a wrong label is only
discovered by a customer holding the wrong bundle. These are static guards over
the committed files — no docker, no bundle build.

THE CONTRACT: whatever flags the workflow passes to make-installer.sh, the
MANIFEST profile line, the artifact name and the release notes all agree.

Run:  python3 -m pytest tests/test_release_bundle_labels.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MAKE_INSTALLER = ROOT / "scripts" / "make-installer.sh"
WORKFLOW = ROOT.parent / ".github" / "workflows" / "release-bundle.yml"

pytestmark = pytest.mark.skipif(
    not WORKFLOW.is_file(), reason=f"{WORKFLOW} not present in this checkout"
)

# make-installer.sh's default when no --core is passed.
DEFAULT_PROFILE = "full"


def _make_installer() -> str:
    return MAKE_INSTALLER.read_text()


def _workflow() -> str:
    return WORKFLOW.read_text()


def test_make_installer_still_has_exactly_these_two_profiles() -> None:
    """If a third profile appears, every guard below needs re-reading."""
    src = _make_installer()
    assert re.search(r'^PROFILE="full"$', src, re.M), (
        "make-installer.sh's default PROFILE is no longer 'full'"
    )
    assert re.search(r'^\s*--core\)\s*PROFILE="core";', src, re.M), (
        "make-installer.sh no longer maps --core to PROFILE=core"
    )


def test_manifest_reports_the_profile_actually_built() -> None:
    """A hard-coded profile line is a label that cannot be wrong-and-noticed."""
    src = _make_installer()
    assert 'echo "profile:  $PROFILE"' in src, (
        "make-installer.sh must write the LIVE $PROFILE into MANIFEST; it "
        'hard-coded "core" until 2026-09-03 even when packs shipped'
    )
    assert 'echo "profile:  core"' not in src


def _workflow_profile() -> str:
    """The profile the release workflow actually builds."""
    m = re.search(r"^\s*bash NetOps_Observability/scripts/make-installer\.sh(.*)$",
                  _workflow(), re.M)
    assert m, "release-bundle.yml no longer invokes make-installer.sh"
    return "core" if "--core" in m.group(1) else DEFAULT_PROFILE


def test_workflow_smoke_asserts_the_manifest_profile_it_built() -> None:
    """The build flag and the MANIFEST are checked against each other in CI."""
    profile = _workflow_profile()
    assert f"grep -q '^profile:  {profile}$' MANIFEST" in _workflow(), (
        f"release-bundle.yml builds the {profile!r} profile but its smoke step "
        "does not assert the MANIFEST says so"
    )


def test_uploaded_artifact_is_named_for_the_profile_built() -> None:
    text = _workflow()
    m = re.search(r"^\s*name:\s*(correlix-bundle-\S+)\s*$", text, re.M)
    assert m, "release-bundle.yml no longer names a correlix-bundle-* artifact"
    assert m.group(1) == f"correlix-bundle-{_workflow_profile()}", (
        f"artifact {m.group(1)!r} does not name the profile actually built "
        f"({_workflow_profile()!r})"
    )


def test_release_notes_name_the_profile_built() -> None:
    m = re.search(r"--notes \"([^\"]*)\"", _workflow())
    assert m, "release-bundle.yml no longer sets release notes"
    notes = m.group(1)
    profile = _workflow_profile()
    assert f"{profile} profile" in notes, (
        f"release notes must say '{profile} profile'; they read: {notes[:120]!r}"
    )
    other = "core" if profile == "full" else "full"
    assert f"{other} profile" not in notes


def test_a_full_build_smoke_tests_that_the_addon_packs_exist() -> None:
    """`full` means the packs shipped — assert the contents, not just the label."""
    if _workflow_profile() != "full":
        pytest.skip("workflow builds --core; there are no add-on packs to assert")
    text = _workflow()
    src = _make_installer()
    # The pack names come from make-installer.sh's ADDONS list ("name:profile").
    m = re.search(r'^ADDONS="([^"]*)"', src, re.M)
    assert m, "make-installer.sh no longer declares an ADDONS list"
    names = [entry.split(":", 1)[0] for entry in m.group(1).split() if entry]
    assert names, "ADDONS is empty — did the pack model change?"
    for name in names:
        assert f"correlix-addon-{name}-*.tar.zst" in text, (
            f"the smoke step does not check that add-on pack {name!r} shipped"
        )
