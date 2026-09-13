# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Release-mode artifact signing — EXECUTED, not grepped.

WHY THIS EXISTS (RC1 governance directive 2026-09-13, Decision 3B, Blocker D).
`make-installer.sh` signed `SHA256SUMS` only when `CORRELIX_SIGNING_KEY` happened
to be set, and `release-bundle.yml` never set it — so *every bundle ever produced
was unsigned*, and nothing failed. The directive's governing principle is that a
release must FAIL CLOSED on a missing signing requirement, which means the
interesting behaviour is no longer "is the code conditional" (that is
`tests/test_perf_signing_ship.py`'s grep contract) but "does a release build
actually refuse".

So these tests RUN the script:

  * `--sign-only DIR` is the dry run for the signing path — the same shape as
    `--licenses-only` / `--source-offer-only`, and it calls the very same
    `finalize_bundle()` the full build calls. No docker, no npm, no Go, no
    20-minute image save.
  * the signing key is a THROWAWAY key generated inside the test, in a temporary
    `GNUPGHOME` that dies with the test. Nothing is committed, and
    `make-installer.sh` itself is still forbidden from ever generating a key
    (asserted in test_perf_signing_ship.py).

Covered (the directive's Decision 4 list, signing half):

  1. release mode + no key              → non-zero, BLOCKED message names the var
  2. release mode + unparsable flag     → non-zero (no silent fallback to unsigned)
  3. release mode + real key            → SHA256SUMS.asc exists and VERIFIES
  4. tampered SHA256SUMS after signing  → verification fails
  5. developer mode + no key            → exit 0, loud checksum-only NOTE, no .asc
  6. partially covered bundle           → release build REFUSES, developer warns
  7. MANIFEST carries the provenance fields (Decision 7)

Run:  python3 -m pytest tests/test_release_signing.py -v
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
MAKE_INSTALLER = ROOT / "scripts" / "make-installer.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("gpg") is None,
    reason="gpg is not installed on this host; the signing path cannot be executed",
)

# Every file the bundle's sha256sum line names explicitly, plus one member for
# each glob it uses. A stub bundle that is missing any of them would fail for the
# wrong reason, so the list is spelled out rather than guessed.
STUB_TEXT_FILES = (
    "README.md",
    "ADVANCED.md",
    "TROUBLESHOOTING.md",
    "LICENSES.md",
    "LICENSING.md",
    "OPERATIONS.md",
    "RELEASE-NOTES.md",
    "README.txt",
    "SUPPORT.txt",
    "LICENSE",
    "NOTICE",
)
STUB_EXECUTABLES = (
    "install-correlix.sh",
    "prepare-host.sh",
    "correlix-setup",
    "correlix-debug",
    "correlix-licence",
)
BASE_MANIFEST = (
    "product:  Correlix (NetOps Observability)\n"
    "version:  0.0.0-test\n"
    "git_sha:  0000000\n"
    "profile:  full\n"
    "built:    2026-01-01T00:00:00+00:00\n"
    "images:\n"
    "  - apache/kafka:4.1.0\n"
)


def stub_bundle(tmp_path: Path) -> Path:
    """A bundle directory with one member for every entry finalize_bundle names.

    Contents are placeholders; what is under test is the integrity manifest, its
    coverage and its signature, none of which care what the bytes are.
    """
    bundle = tmp_path / "correlix-0.0.0-test"
    (bundle / "LICENSES").mkdir(parents=True)
    (bundle / "source-offer").mkdir()
    (bundle / "docs" / "assets").mkdir(parents=True)
    (bundle / "correlix-images-core-0.0.0-test.tar.zst").write_bytes(b"not-really-zstd")
    (bundle / "correlix-source-0.0.0-test.tar.gz").write_bytes(b"not-really-gzip")
    for name in STUB_TEXT_FILES:
        (bundle / name).write_text(f"{name} placeholder\n", encoding="utf-8")
    (bundle / "LICENSES" / "Apache-2.0.txt").write_text("apache text\n", encoding="utf-8")
    (bundle / "MANIFEST").write_text(BASE_MANIFEST, encoding="utf-8")
    for name in STUB_EXECUTABLES:
        p = bundle / name
        p.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        p.chmod(0o755)
    (bundle / "source-offer" / "README").write_text("corresponding source\n", encoding="utf-8")
    (bundle / "docs" / "index.html").write_text("<html></html>\n", encoding="utf-8")
    (bundle / "docs" / "assets" / "app.css").write_text("body{}\n", encoding="utf-8")
    return bundle


def run_installer(bundle: Path, *, release: str | None, gnupghome: Path | None = None,
                  key: str | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.pop("CORRELIX_RELEASE_BUILD", None)
    env.pop("CORRELIX_SIGNING_KEY", None)
    if release is not None:
        env["CORRELIX_RELEASE_BUILD"] = release
    if gnupghome is not None:
        env["GNUPGHOME"] = str(gnupghome)
    if key is not None:
        env["CORRELIX_SIGNING_KEY"] = key
    return subprocess.run(
        ["bash", str(MAKE_INSTALLER), "--sign-only", str(bundle)],
        capture_output=True, text=True, env=env, timeout=300, check=False,
    )


@pytest.fixture
def throwaway_key(tmp_path_factory) -> tuple[Path, str]:
    """A signing key that exists ONLY for this test session.

    Generated here, in a temporary GNUPGHOME — never committed, never reused, and
    deliberately not the shape of a production key (the point is to exercise the
    code path, not to stand in for the owner's custody decision).
    """
    home = tmp_path_factory.mktemp("gnupg")
    home.chmod(0o700)
    env = dict(os.environ, GNUPGHOME=str(home))
    gen = subprocess.run(
        ["gpg", "--batch", "--quiet", "--pinentry-mode", "loopback", "--passphrase", "",
         "--quick-generate-key", "Correlix Test Signing <test@example.invalid>",
         "default", "default", "0"],
        capture_output=True, text=True, env=env, timeout=300, check=False,
    )
    if gen.returncode != 0:
        pytest.skip(f"this host cannot generate a throwaway gpg key: {gen.stderr.strip()}")
    listed = subprocess.run(
        ["gpg", "--batch", "--with-colons", "--list-secret-keys"],
        capture_output=True, text=True, env=env, check=True, timeout=60,
    ).stdout
    fpr = next(line.split(":")[9] for line in listed.splitlines()
               if line.startswith("fpr:"))
    assert len(fpr) == 40, f"unexpected fingerprint {fpr!r}"
    return home, fpr


def gpg_verify(bundle: Path, gnupghome: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["gpg", "--batch", "--verify", str(bundle / "SHA256SUMS.asc"),
         str(bundle / "SHA256SUMS")],
        capture_output=True, text=True, env=dict(os.environ, GNUPGHOME=str(gnupghome)),
        timeout=60, check=False,
    )


# ── 1. release mode with no key: the whole point of Blocker D ────────────────

def test_release_mode_without_a_key_fails_closed(tmp_path):
    bundle = stub_bundle(tmp_path)
    r = run_installer(bundle, release="1")
    assert r.returncode != 0, f"release build produced a bundle with no signing key\n{r.stdout}"
    assert "BLOCKED" in r.stderr
    assert "CORRELIX_SIGNING_KEY" in r.stderr, "the failure must name the variable to set"
    assert "Decision 3B" in r.stderr, "the failure must name the decision it enforces"
    assert not (bundle / "SHA256SUMS.asc").exists()
    # It must fail BEFORE doing any work — an unsigned SHA256SUMS is not written.
    assert not (bundle / "SHA256SUMS").exists(), (
        "the release-mode refusal must happen before the integrity manifest is "
        "written, so no half-built artifact is left behind")


def test_release_flag_is_read_strictly(tmp_path):
    """`CORRELIX_RELEASE_BUILD=true` must not degrade to a developer build.

    A typo that silently produces an unsigned release is exactly the fail-open
    this mode removes.
    """
    bundle = stub_bundle(tmp_path)
    r = run_installer(bundle, release="true")
    assert r.returncode != 0
    assert "CORRELIX_RELEASE_BUILD" in r.stderr
    assert not (bundle / "SHA256SUMS").exists()


# ── 2. release mode with a key: signed, self-verified, recorded ──────────────

def test_release_mode_signs_and_the_signature_verifies(tmp_path, throwaway_key):
    home, fpr = throwaway_key
    bundle = stub_bundle(tmp_path)
    r = run_installer(bundle, release="1", gnupghome=home, key=fpr)
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    assert "signing is MANDATORY" in r.stdout
    asc = bundle / "SHA256SUMS.asc"
    assert asc.is_file(), "release build produced no detached signature"
    assert asc.read_text(encoding="utf-8").startswith("-----BEGIN PGP SIGNATURE-----")
    v = gpg_verify(bundle, home)
    assert v.returncode == 0, f"fresh signature does not verify:\n{v.stderr}"
    assert "Good signature" in v.stderr
    # The fingerprint claim must be INSIDE the signed manifest.
    manifest = (bundle / "MANIFEST").read_text(encoding="utf-8")
    assert f"signing-key {fpr}" in manifest
    sums = (bundle / "SHA256SUMS").read_text(encoding="utf-8")
    assert "MANIFEST" in sums, "MANIFEST must be a SHA256SUMS member"
    # ...and the checksums must actually be correct.
    check = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=bundle,
                           capture_output=True, text=True, timeout=120, check=False)
    assert check.returncode == 0, check.stdout + check.stderr


def test_tampering_after_signing_breaks_verification(tmp_path, throwaway_key):
    """The signature is worth something only if a changed SHA256SUMS fails it."""
    home, fpr = throwaway_key
    bundle = stub_bundle(tmp_path)
    assert run_installer(bundle, release="1", gnupghome=home, key=fpr).returncode == 0
    assert gpg_verify(bundle, home).returncode == 0
    sums = bundle / "SHA256SUMS"
    sums.write_text(sums.read_text(encoding="utf-8").replace(
        "MANIFEST", "MANIFEST-tampered", 1), encoding="utf-8")
    v = gpg_verify(bundle, home)
    assert v.returncode != 0, "a tampered SHA256SUMS still verified"
    assert "BAD signature" in v.stderr


def test_a_key_missing_from_the_keyring_is_fatal(tmp_path, throwaway_key):
    home, _ = throwaway_key
    bundle = stub_bundle(tmp_path)
    r = run_installer(bundle, release="1", gnupghome=home,
                      key="DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF")
    assert r.returncode != 0
    assert "no secret key in the GPG keyring" in r.stderr
    assert not (bundle / "SHA256SUMS.asc").exists()


# ── 3. developer mode is untouched ──────────────────────────────────────────

def test_developer_mode_is_unchanged_and_loud(tmp_path):
    bundle = stub_bundle(tmp_path)
    r = run_installer(bundle, release=None)
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    assert "NOTE: CORRELIX_SIGNING_KEY unset" in r.stdout
    assert "CHECKSUM-ONLY" in r.stdout
    assert not (bundle / "SHA256SUMS.asc").exists()
    assert (bundle / "SHA256SUMS").is_file()
    assert "signing-key" not in (bundle / "MANIFEST").read_text(encoding="utf-8")
    check = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=bundle,
                           capture_output=True, text=True, timeout=120, check=False)
    assert check.returncode == 0, check.stdout + check.stderr


def test_developer_mode_removes_a_stale_signature(tmp_path, throwaway_key):
    """A signed output directory rebuilt without a key must not keep the old .asc:
    the customer's verifier would call it a BAD signature, which it is."""
    home, fpr = throwaway_key
    bundle = stub_bundle(tmp_path)
    assert run_installer(bundle, release="1", gnupghome=home, key=fpr).returncode == 0
    assert (bundle / "SHA256SUMS.asc").is_file()
    r = run_installer(bundle, release=None)
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    assert not (bundle / "SHA256SUMS.asc").exists()
    assert "STALE SHA256SUMS.asc" in r.stdout


# ── 4. no partially signed bundle ───────────────────────────────────────────

def test_a_file_outside_sha256sums_is_refused_in_release_mode(tmp_path, throwaway_key):
    home, fpr = throwaway_key
    bundle = stub_bundle(tmp_path)
    (bundle / "surprise-artifact.bin").write_bytes(b"unmeasured\n")
    r = run_installer(bundle, release="1", gnupghome=home, key=fpr)
    assert r.returncode != 0, "a partially covered bundle was signed"
    assert "NOT covered by SHA256SUMS" in r.stderr
    assert "surprise-artifact.bin" in r.stderr
    assert not (bundle / "SHA256SUMS.asc").exists(), (
        "the coverage check must run BEFORE signing, so no signature is produced")


def test_a_file_outside_sha256sums_only_warns_in_developer_mode(tmp_path):
    bundle = stub_bundle(tmp_path)
    (bundle / "scratch.tmp").write_bytes(b"local\n")
    r = run_installer(bundle, release=None)
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    assert "WARN" in r.stderr and "scratch.tmp" in r.stderr


# ── 5. provenance (Decision 7) ──────────────────────────────────────────────

def test_manifest_carries_the_provenance_fields(tmp_path):
    bundle = stub_bundle(tmp_path)
    assert run_installer(bundle, release=None).returncode == 0
    manifest = (bundle / "MANIFEST").read_text(encoding="utf-8")
    fields = {}
    for line in manifest.splitlines():
        if line.startswith("  ") or ":" not in line:
            continue  # image list members and the signing-key line
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    for required in ("version", "tag", "source_sha", "built", "built_utc",
                     "build_env", "build_tools", "release_mode"):
        assert required in fields, f"MANIFEST is missing the `{required}` provenance field"
    assert len(fields["source_sha"]) == 40 or fields["source_sha"] == "unknown", (
        "source_sha must be the FULL commit sha (Decision 7: one immutable commit)")
    assert fields["built_utc"].endswith("Z"), "built_utc must be UTC"
    assert fields["release_mode"] == "no", "a developer build must say so"
    assert fields["build_env"], "build_env must identify where the bundle was built"
    assert "kernel=" in fields["build_env"]
    # §16.5: a MANIFEST ships to customers — no internal host or user identity.
    hostname = socket.gethostname()
    if hostname and len(hostname) > 3:
        assert hostname not in manifest, (
            "the build host's name must never reach a shipped MANIFEST (§16.5)")


def test_release_mode_manifest_says_release_mode(tmp_path, throwaway_key):
    home, fpr = throwaway_key
    bundle = stub_bundle(tmp_path)
    assert run_installer(bundle, release="1", gnupghome=home, key=fpr).returncode == 0
    manifest = (bundle / "MANIFEST").read_text(encoding="utf-8")
    assert "release_mode: yes" in manifest


def test_finalize_is_idempotent(tmp_path, throwaway_key):
    """A second run must not stack duplicate provenance or fingerprint lines
    (§9: safe to run twice)."""
    home, fpr = throwaway_key
    bundle = stub_bundle(tmp_path)
    assert run_installer(bundle, release="1", gnupghome=home, key=fpr).returncode == 0
    assert run_installer(bundle, release="1", gnupghome=home, key=fpr).returncode == 0
    manifest = (bundle / "MANIFEST").read_text(encoding="utf-8").splitlines()
    for field in ("source_sha:", "built_utc:", "signing-key "):
        assert sum(1 for line in manifest if line.startswith(field)) == 1, (
            f"`{field}` was written twice")
    assert gpg_verify(bundle, home).returncode == 0


# ── 6. the mode itself refuses to be pointed at a non-bundle ────────────────

def test_sign_only_refuses_a_directory_that_is_not_a_bundle(tmp_path):
    (tmp_path / "not-a-bundle").mkdir()
    r = run_installer(tmp_path / "not-a-bundle", release=None)
    assert r.returncode != 0
    assert "has no MANIFEST" in r.stderr
