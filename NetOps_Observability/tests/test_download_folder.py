# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""The customer download folder — what a first-time customer actually receives.

Tracker 265. `scripts/make-installer.sh` builds `dist/correlix-<version>/`, and
that directory is the ENTIRE product hand-over: a customer with no internet, no
prior contact and no Correlix knowledge must be able to install, verify,
operate, get help and satisfy the licence obligations from it alone.

Two halves, on purpose:

* The CONTRACT half parses `scripts/make-installer.sh` and runs on every commit,
  with or without a bundle on disk. It is what stops the layout from being
  quietly reduced — a file dropped from the build script is a file no customer
  ever gets, and the failure is invisible until a release.
* The ARTIFACT half runs against a real `dist/correlix-*/` when one exists and
  is SKIPPED when it does not (cutting a bundle needs Docker, ~2.5 GB of disk
  and twenty minutes — see tracker 125). It proves the built folder matches the
  contract, that its checksums verify, and that its entry-point documentation
  is genuinely short.

Run:  python3 -m pytest tests/test_download_folder.py -v
"""
import hashlib
import os
import re
import subprocess

import pytest

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
INSTALLER = os.path.join(ROOT, "scripts", "make-installer.sh")
DIST = os.path.join(ROOT, "dist")

# Every file a customer must find in the folder, and why it is there. Keep the
# reason in the table: a future reader deciding whether to drop one needs it.
REQUIRED_FILES = {
    "README.txt": "the plain-text START HERE for a server console",
    "README.md": "the formatted quickstart",
    "OPERATIONS.md": "sizing, upgrade, rollback, backup, uninstall",
    "ADVANCED.md": "external Kafka, ports, licence file, diagnostics",
    "TROUBLESHOOTING.md": "the usual first-day failures",
    "SUPPORT.txt": "how to get help and exactly what to send",
    "RELEASE-NOTES.md": "what changed, generated from the log",
    "LICENSES.md": "third-party distribution notices",
    "LICENSE": "Correlix's own mixed-licence notice",
    "LICENSING.md": "which directory is core and which is commercial",
    "NOTICE": "third-party attributions and source offers",
    "MANIFEST": "version, git sha, profile and the exact image list",
    "SHA256SUMS": "the integrity manifest",
    "CHECKSUMS.sha256": "the integrity manifest under the name customers look for",
    "install-correlix.sh": "THE entry point",
    "prepare-host.sh": "one-time host preparation",
    "correlix-setup": "the graphical installer",
    "correlix-debug": "the pipeline debugger",
    "correlix-licence": "the offline licence verifier",
}

REQUIRED_DIRS = {
    "LICENSES": "the two SPDX licence texts the notice points at",
    "docs": "the full documentation portal, built static and readable offline",
    "source-offer": "corresponding source for the GPL/LGPL components",
}


def read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


@pytest.fixture(scope="module")
def script() -> str:
    return read(INSTALLER)


# ── contract: the build script produces the whole folder ────────────────────

# The three project-licence files are copied by a loop, not by name, so the
# contract check looks for the loop instead of a per-file expression.
LICENCE_LOOP = "for f in LICENSE LICENSING.md NOTICE; do"


@pytest.mark.parametrize("name", sorted(REQUIRED_FILES))
def test_build_script_produces_every_required_file(script, name):
    # Either the build writes it (heredoc / cp / ln / go build), copies it in
    # the licence loop, or it is the checksum manifest the build ends with.
    if name in ("LICENSE", "LICENSING.md", "NOTICE"):
        assert LICENCE_LOOP in script, (
            f"the licence copy loop is gone — {name} would not ship")
        return
    produced = any(pat in script for pat in (
        f'"$BUNDLE_DIR/{name}"',
        f"$BUNDLE_DIR/{name}",
        f"> {name}",
    ))
    assert produced, (
        f"make-installer.sh no longer produces {name} — {REQUIRED_FILES[name]}")


@pytest.mark.parametrize("name", sorted(REQUIRED_DIRS))
def test_build_script_produces_every_required_directory(script, name):
    assert f"$BUNDLE_DIR/{name}" in script, (
        f"make-installer.sh no longer produces {name}/ — {REQUIRED_DIRS[name]}")


def test_checksum_manifest_covers_everything_executable_or_installable(script):
    """A file outside SHA256SUMS is a file the customer cannot verify."""
    m = re.search(r'^\(cd "\$BUNDLE_DIR" && sha256sum (.+) > SHA256SUMS\)$',
                  script, re.MULTILINE)
    assert m, "the SHA256SUMS command is gone from make-installer.sh"
    cmd = m.group(1)
    for needed in ("./*.tar.*", "./*.md", "./*.txt", "LICENSE", "NOTICE",
                   "MANIFEST", "install-correlix.sh", "prepare-host.sh",
                   "correlix-setup", "correlix-debug", "correlix-licence",
                   "./source-offer/*"):
        assert needed in cmd, f"SHA256SUMS no longer covers {needed}"
    assert "find ./docs -type f" in script, (
        "the documentation portal is no longer covered by SHA256SUMS — a "
        "documentation set the customer cannot verify is one an attacker can edit")


def test_checksums_alias_is_a_symlink_not_a_second_file(script):
    """Two checksum files are two files that can disagree."""
    assert 'ln -sfn SHA256SUMS "$BUNDLE_DIR/CHECKSUMS.sha256"' in script, (
        "CHECKSUMS.sha256 must stay a symlink to SHA256SUMS")


def test_release_notes_are_generated_never_written(script):
    """Hand-written release notes claim changes a build does not contain."""
    assert "RELEASE-NOTES.md" in script
    assert re.search(r"git -C \"\$ROOT\" log[^\n]*RELEASE|notes=\"\$\(git -C \"\$ROOT\" log",
                     script), "RELEASE-NOTES.md is no longer generated from the log"
    assert 'grep -qE "$LAB_MARKERS" "$BUNDLE_DIR/RELEASE-NOTES.md"' in script, (
        "the generated release notes are no longer lab-leak guarded")


def test_docs_portal_absence_is_a_hard_failure_not_a_skip(script):
    """A bundle that silently ships no documentation is the §16.1 defect."""
    assert 'FATAL: docs-portal/build is missing' in script
    assert 'FATAL: docs-portal/build has no index.html' in script


# ── artifact: the folder that was actually built ────────────────────────────

def newest_bundle() -> str | None:
    if not os.path.isdir(DIST):
        return None
    cands = [os.path.join(DIST, d) for d in os.listdir(DIST)
             if d.startswith("correlix-") and
             os.path.isfile(os.path.join(DIST, d, "MANIFEST"))]
    if not cands:
        return None
    return max(cands, key=os.path.getmtime)


@pytest.fixture(scope="module")
def bundle() -> str:
    b = newest_bundle()
    if not b:
        pytest.skip("no built bundle in dist/ — run: bash scripts/make-installer.sh")
    return b


@pytest.fixture(scope="module")
def manifest(bundle) -> dict:
    text = read(os.path.join(bundle, "MANIFEST"))
    out = {"images": [], "fields": {}}
    for line in text.splitlines():
        if line.startswith("  - "):
            out["images"].append(line[4:].strip())
        elif ":" in line and not line.startswith(" "):
            k, _, v = line.partition(":")
            out["fields"][k.strip()] = v.strip()
    return out


def test_manifest_states_what_this_build_is(manifest):
    for field in ("product", "version", "git_sha", "profile", "built"):
        assert manifest["fields"].get(field), f"MANIFEST has no {field}"
    assert manifest["fields"]["profile"] in ("core", "full")
    assert re.fullmatch(r"[0-9a-f]{7,40}", manifest["fields"]["git_sha"]), (
        "MANIFEST git_sha is not a commit id — bundle-staleness.sh cannot use it")
    assert manifest["images"], "MANIFEST lists no images"


@pytest.mark.parametrize("name", sorted(REQUIRED_FILES))
def test_built_folder_has_every_required_file(bundle, name):
    path = os.path.join(bundle, name)
    assert os.path.exists(path), f"{name} missing — {REQUIRED_FILES[name]}"
    assert os.path.getsize(os.path.realpath(path)) > 0, f"{name} is empty"


@pytest.mark.parametrize("name", sorted(REQUIRED_DIRS))
def test_built_folder_has_every_required_directory(bundle, name):
    path = os.path.join(bundle, name)
    assert os.path.isdir(path), f"{name}/ missing — {REQUIRED_DIRS[name]}"
    assert os.listdir(path), f"{name}/ is empty"


def test_built_folder_carries_the_image_archives_the_manifest_promises(bundle, manifest):
    archives = [f for f in os.listdir(bundle) if f.endswith(".tar.zst")]
    assert archives, "no image archive in the bundle"
    assert any(a.startswith("correlix-images-core-") for a in archives), (
        "the base appliance archive is missing — install-correlix.sh globs for it")
    if manifest["fields"].get("profile") == "full":
        assert any(a.startswith("correlix-addon-") for a in archives), (
            "MANIFEST says profile: full but no add-on pack was built")
    src = [f for f in os.listdir(bundle) if f.startswith("correlix-source-")]
    assert src, "the source tarball is missing — the customer cannot install without it"


def test_checksums_alias_resolves_to_the_manifest(bundle):
    alias = os.path.join(bundle, "CHECKSUMS.sha256")
    assert os.path.islink(alias), "CHECKSUMS.sha256 should be a symlink"
    assert os.readlink(alias) == "SHA256SUMS"
    assert read(alias) == read(os.path.join(bundle, "SHA256SUMS"))


def test_checksums_verify(bundle):
    """Spot-check the manifest against the bytes on disk.

    `sha256sum -c` over a 2 GB archive is too slow for a unit test, so this
    verifies every entry EXCEPT the image archives (whose integrity the
    installer itself checks on the customer host) and asserts the archives are
    at least listed.
    """
    lines = read(os.path.join(bundle, "SHA256SUMS")).splitlines()
    assert lines, "SHA256SUMS is empty"
    listed = {ln.split(None, 1)[1].strip() for ln in lines if ln.strip()}
    assert any(n.endswith(".tar.zst") for n in listed), "no image archive listed"
    checked = 0
    for ln in lines:
        digest, _, name = ln.partition("  ")
        name = name.strip()
        if not name or name.endswith((".tar.zst", ".tar.gz")):
            continue
        path = os.path.join(bundle, name)
        assert os.path.exists(path), f"SHA256SUMS lists {name}, which is not there"
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        assert h.hexdigest() == digest, f"{name} does not match its checksum"
        checked += 1
    assert checked > 20, f"only {checked} files verified — SHA256SUMS looks truncated"


def test_readme_txt_is_one_page_and_plain(bundle):
    text = read(os.path.join(bundle, "README.txt"))
    lines = text.splitlines()
    assert len(lines) <= 70, (
        f"README.txt is {len(lines)} lines — it is the file that has to be read, "
        f"so it stays inside one screen")
    assert max((len(ln) for ln in lines), default=0) <= 80, (
        "README.txt has a line over 80 columns — it is read on a server console")
    for md in ("```", "|---", "<!--"):
        assert md not in text, f"README.txt contains markdown syntax ({md!r})"
    assert "install-correlix.sh" in text, "README.txt does not name the entry point"
    assert "CHECKSUMS.sha256" in text, "README.txt does not tell the customer to verify"


def test_support_txt_names_only_tools_that_ship(bundle):
    text = read(os.path.join(bundle, "SUPPORT.txt"))
    for tool in ("./install-correlix.sh support-bundle", "./correlix-debug",
                 "./correlix-licence"):
        assert tool in text, f"SUPPORT.txt does not mention {tool}"
    for binary in ("correlix-debug", "correlix-licence"):
        assert os.access(os.path.join(bundle, binary), os.X_OK), (
            f"SUPPORT.txt tells the customer to run {binary}, which is not executable here")


def test_documentation_portal_opens_without_a_network(bundle):
    index = os.path.join(bundle, "docs", "index.html")
    assert os.path.isfile(index), "docs/index.html is missing"
    html = read(index)
    # A portal that pulls its own CSS/JS from a CDN is a blank page on an
    # air-gapped appliance, which is exactly where it is needed.
    for host in ("cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
                 "fonts.googleapis.com"):
        assert host not in html, (
            f"the offline documentation portal loads assets from {host}")


def test_entry_point_offers_both_install_paths(bundle):
    """Owner requirement (tracker 266): the first question is GUI or CLI."""
    text = read(os.path.join(bundle, "install-correlix.sh"))
    assert "cmd_choose" in text, "install-correlix.sh no longer asks GUI or terminal"
    assert "-list-ips" in text, (
        "install-correlix.sh no longer offers the host's management addresses")


def test_no_lab_identifier_reached_the_customer_documentation(bundle):
    """The same guard make-installer.sh applies, asserted on the built folder."""
    markers = re.compile(r"10\.70\.245\.120|rao123|correlix-faultlab|hc-ping|8d0f8a4e-c36e")
    for name in ("README.txt", "README.md", "SUPPORT.txt", "OPERATIONS.md",
                 "ADVANCED.md", "TROUBLESHOOTING.md", "RELEASE-NOTES.md"):
        path = os.path.join(bundle, name)
        if os.path.exists(path):
            assert not markers.search(read(path)), f"{name} carries a lab identifier"


def test_bundle_is_not_stale_against_head(bundle):
    """The folder must describe the code it was cut from (scripts/bundle-staleness.sh)."""
    r = subprocess.run(["bash", os.path.join(ROOT, "scripts", "bundle-staleness.sh")],
                       capture_output=True, text=True, timeout=120, check=False)
    assert r.returncode == 0, (
        f"the newest bundle lags HEAD — rebuild it:\n{r.stdout}\n{r.stderr}")
