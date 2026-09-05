"""GPL/LGPL corresponding-source mirror — the bundle must carry the source it owes.

Licence audit D2 (docs/security/LICENSE_AUDIT_2026-09-03.md §4 D2), owner
decision 2026-09-04: Correlix redistributes syslog-ng as an unmodified upstream
container image. syslog-ng OSE is LGPL-2.1-or-later for its core and
GPL-2.0-or-later for modules/ and scl/, with no OpenSSL linking exception. The
owner chose GPL-2.0 §3(a) — SHIP the corresponding source with the binary —
over §3(b)'s three-year written offer, because a promise outlives repositories
and companies but a tarball in the customer's hands does not.

`scripts/make-installer.sh --source-offer-only` is the dry run for that path.
These tests exercise it WITHOUT NETWORK by pointing it at a fixture pin table
and a fixture mirror directory (the same two knobs an air-gapped build host
uses), so the bundle layout, the README's stated terms, the checksum gate and
the SHA256SUMS coverage are all proven on every commit rather than only when
someone cuts a release.

They also assert the checked-in pin table has not drifted from the version the
compose file actually pins — the one failure mode a mocked test could otherwise
hide, and the one most likely to happen (someone bumps the image, nobody
re-mirrors the source, and the bundle ships a source offer for the wrong
version).

Run:  python3 -m pytest tests/test_source_offer.py -v
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile

import pytest

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
INSTALLER = os.path.join(ROOT, "scripts", "make-installer.sh")
PINS = os.path.join(ROOT, "scripts", "source-mirror.json")
COMPOSE = os.path.join(ROOT, "deployment", "docker", "docker-compose.yml")
NOTICES = os.path.join(ROOT, "docs", "THIRD_PARTY_LICENSES.md")


def read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


@pytest.fixture(scope="module")
def pins() -> dict:
    return json.loads(read(PINS))


# ── the checked-in pin table must describe what we actually ship ─────────────

def test_pin_table_is_wellformed(pins):
    comps = pins.get("components")
    assert comps, "scripts/source-mirror.json declares no components"
    for c in comps:
        for field in ("name", "version", "file", "url", "sha256", "size_bytes",
                      "license", "verified_against"):
            assert c.get(field), f"{c.get('name', '?')} is missing `{field}`"
        assert re.fullmatch(r"[0-9a-f]{64}", c["sha256"]), (
            f"{c['name']} sha256 is not a lowercase hex digest")
        assert c["url"].startswith("https://"), (
            f"{c['name']} must be fetched over TLS")
        assert c["version"] in c["file"], (
            f"{c['name']}'s filename must name the version it mirrors")


def test_pin_table_records_that_upstream_publishes_no_checksum(pins):
    """The honest half of the pin. syslog-ng publishes no checksum, signature or
    release-asset digest, so our sha256 is a self-measurement recorded once —
    trust-on-first-use, then enforced forever. That distinction must stay
    written down, or a later reader will mistake it for a vendor attestation."""
    sng = next(c for c in pins["components"] if c["name"] == "syslog-ng")
    assert "self-measured" in sng["verified_against"], (
        "the syslog-ng pin must state that the digest is our own measurement, "
        "not an upstream-published sum")


def test_pin_matches_the_version_compose_actually_pins(pins):
    """The drift guard. Bumping the syslog-ng image without re-mirroring its
    source would ship a source offer for a version we do not distribute — which
    is a compliance failure that looks exactly like compliance."""
    compose = read(COMPOSE)
    m = re.search(r"image:\s*balabit/syslog-ng:([0-9][^\s@]*)", compose)
    assert m, "no pinned balabit/syslog-ng image found in docker-compose.yml"
    pinned = m.group(1)
    sng = next((c for c in pins["components"] if c["name"] == "syslog-ng"), None)
    assert sng, "syslog-ng has no entry in scripts/source-mirror.json"
    assert sng["version"] == pinned, (
        f"docker-compose.yml ships syslog-ng {pinned} but "
        f"scripts/source-mirror.json mirrors {sng['version']} — re-measure the "
        f"upstream tarball for {pinned} and update the pin")


def test_pin_states_the_real_split_licence(pins):
    """syslog-ng is NOT GPL-3.0 (the error the old hand-written bundle notice
    made) and has NO OpenSSL linking exception."""
    sng = next(c for c in pins["components"] if c["name"] == "syslog-ng")
    assert "LGPL-2.1-or-later" in sng["license"] and "GPL-2.0-or-later" in sng["license"]
    assert "GPL-3.0" not in sng["license"]
    assert "OpenSSL" in sng.get("notes", ""), (
        "the pin must record that there is no OpenSSL linking exception")


# ── the installer's source-offer dry run (no network) ────────────────────────

def _fixture_mirror(tmp_path):
    """A stand-in 'upstream tarball' plus a pin table that points at it.

    Both knobs (CORRELIX_SOURCE_PINS, CORRELIX_SOURCE_MIRROR_DIR) are the real
    ones an air-gapped build host uses — the test is not reaching through a
    test-only backdoor, and the checksum gate applies to the fixture exactly as
    it applies to a download.
    """
    mirror = tmp_path / "mirror"
    mirror.mkdir()
    payload = mirror / "fauxcomponent-1.2.3.tar.gz"
    inner = tmp_path / "COPYING"
    inner.write_text("GNU GENERAL PUBLIC LICENSE Version 2\n", encoding="utf-8")
    with tarfile.open(payload, "w:gz") as tf:
        tf.add(inner, arcname="fauxcomponent-1.2.3/COPYING")
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()

    pinfile = tmp_path / "pins.json"
    pinfile.write_text(json.dumps({"components": [{
        "name": "fauxcomponent",
        "version": "1.2.3",
        "file": payload.name,
        "url": "https://example.invalid/fauxcomponent-1.2.3.tar.gz",
        "sha256": digest,
        "size_bytes": payload.stat().st_size,
        "license": "GPL-2.0-or-later AND LGPL-2.1-or-later",
        "verified_against": "test fixture",
        "notes": "fixture component; no OpenSSL linking exception",
    }]}), encoding="utf-8")
    return mirror, pinfile, payload, digest


def _run_offer(tmp_path, mirror, pinfile, out):
    env = dict(os.environ)
    env["CORRELIX_SOURCE_PINS"] = str(pinfile)
    env["CORRELIX_SOURCE_MIRROR_DIR"] = str(mirror)
    return subprocess.run(
        ["bash", INSTALLER, "--source-offer-only", "--out", str(out)],
        cwd=ROOT, capture_output=True, text=True, timeout=180, check=False, env=env,
    )


def _bundle_dir(out):
    dirs = [d for d in out.iterdir() if d.is_dir() and d.name.startswith("correlix-")]
    assert len(dirs) == 1, f"expected one bundle dir, got {dirs}"
    return dirs[0]


def test_source_offer_dry_run_produces_the_expected_bundle_layout(tmp_path):
    mirror, pinfile, payload, digest = _fixture_mirror(tmp_path)
    out = tmp_path / "dist"
    proc = _run_offer(tmp_path, mirror, pinfile, out)
    assert proc.returncode == 0, f"--source-offer-only failed:\n{proc.stdout}\n{proc.stderr}"

    offer = _bundle_dir(out) / "source-offer"
    assert offer.is_dir(), "the bundle has no source-offer/ directory"

    shipped = offer / payload.name
    assert shipped.is_file(), f"source-offer/{payload.name} was not mirrored"
    assert hashlib.sha256(shipped.read_bytes()).hexdigest() == digest, (
        "the mirrored tarball is not byte-identical to the pinned upstream file")
    # It must be the real archive, not a placeholder.
    with tarfile.open(shipped) as tf:
        assert tf.getnames(), "the mirrored source archive is empty"


def test_source_offer_readme_states_the_terms(tmp_path):
    """A directory of tarballs with no explanation discharges nothing. The
    README must say what the terms are and that this IS the corresponding
    source — and must not claim Correlix's own code is covered."""
    mirror, pinfile, payload, digest = _fixture_mirror(tmp_path)
    out = tmp_path / "dist"
    proc = _run_offer(tmp_path, mirror, pinfile, out)
    assert proc.returncode == 0, proc.stderr

    readme = (_bundle_dir(out) / "source-offer" / "README").read_text(encoding="utf-8")
    assert "General Public License" in readme
    assert "Lesser General Public License" in readme
    assert "THIS DIRECTORY IS THAT SOURCE" in readme, (
        "the README must state plainly that the archives ARE the corresponding source")
    assert "unmodified" in readme.lower()
    for token in ("fauxcomponent", "1.2.3", digest, payload.name,
                  "GPL-2.0-or-later AND LGPL-2.1-or-later"):
        assert token in readme, f"source-offer/README omits {token!r}"
    assert "Correlix's own source code is NOT placed under these licences" in readme, (
        "the README must be explicit that no Correlix code is relicensed")


def test_source_offer_fails_closed_on_a_checksum_mismatch(tmp_path):
    """The gate must bite. Corrupt the mirrored bytes and the build must stop —
    an unverified tarball is never shipped (scripts/CLAUDE.md §16.1)."""
    mirror, pinfile, payload, _digest = _fixture_mirror(tmp_path)
    payload.write_bytes(payload.read_bytes() + b"tampered")
    out = tmp_path / "dist"
    proc = _run_offer(tmp_path, mirror, pinfile, out)
    assert proc.returncode != 0, (
        "a corrupted source tarball was accepted:\n" + proc.stdout)
    assert "checksum mismatch" in (proc.stdout + proc.stderr).lower()
    bundle = _bundle_dir(out)
    assert not (bundle / "source-offer" / payload.name).exists(), (
        "the bad bytes were left in the bundle for a later step to pick up")


def test_source_offer_fails_closed_when_the_pin_table_is_missing(tmp_path):
    mirror, _pinfile, _payload, _d = _fixture_mirror(tmp_path)
    out = tmp_path / "dist"
    proc = _run_offer(tmp_path, mirror, tmp_path / "does-not-exist.json", out)
    assert proc.returncode != 0, "a missing pin table did not fail the build"
    assert "pin table not found" in (proc.stdout + proc.stderr)


def test_source_offer_fails_closed_when_it_can_neither_fetch_nor_find(tmp_path):
    """No local mirror + an unresolvable URL = hard failure, not an empty
    directory. 'The network was down' must never yield a bundle whose source
    offer is a lie."""
    _mirror, pinfile, _payload, _d = _fixture_mirror(tmp_path)
    out = tmp_path / "dist"
    env = dict(os.environ)
    env["CORRELIX_SOURCE_PINS"] = str(pinfile)
    env.pop("CORRELIX_SOURCE_MIRROR_DIR", None)
    proc = subprocess.run(
        ["bash", INSTALLER, "--source-offer-only", "--out", str(out)],
        cwd=ROOT, capture_output=True, text=True, timeout=180, check=False, env=env,
    )
    assert proc.returncode != 0, "an unfetchable source tarball did not fail the build"
    assert "corresponding source" in (proc.stdout + proc.stderr)


# ── the installer wiring itself ──────────────────────────────────────────────

def test_installer_covers_the_source_offer_in_sha256sums():
    """A compliance artifact outside SHA256SUMS is one the customer cannot
    verify — and cannot prove we did not swap."""
    body = read(INSTALLER)
    m = re.search(r"^\(cd \"\$BUNDLE_DIR\" && sha256sum .*> SHA256SUMS\)$",
                  body, re.MULTILINE)
    assert m, "could not find the SHA256SUMS line in make-installer.sh"
    line = m.group(0)
    assert "source-offer" in line, (
        "SHA256SUMS does not cover ./source-offer/* — the mirrored GPL source "
        "would ship unverifiable")
    # The glob must be the WHOLE directory. A narrowed one (`./source-offer/*.tar.gz`)
    # would still contain the string "source-offer" and still pass a substring
    # check, while quietly dropping the README — and the README is the half that
    # states the licence terms and that these archives ARE the corresponding
    # source. A directory whose explanation is unverifiable is not a discharge.
    assert "./source-offer/*" in line and "./source-offer/*." not in line, (
        f"SHA256SUMS covers a NARROWED source-offer glob, so the README is "
        f"unverifiable: {line}")


def test_the_source_offer_readme_and_archive_are_both_covered_by_the_glob(tmp_path):
    """The assertion above reads the installer's glob; this proves the glob
    actually matches both files, by running the real dry run and expanding it
    over the directory it produced."""
    import glob as _glob

    mirror, pinfile, payload, _digest = _fixture_mirror(tmp_path)
    out = tmp_path / "dist"
    proc = _run_offer(tmp_path, mirror, pinfile, out)
    assert proc.returncode == 0, f"{proc.stdout}\n{proc.stderr}"

    bundle = _bundle_dir(out)
    covered = {os.path.basename(p)
               for p in _glob.glob(os.path.join(str(bundle), "source-offer", "*"))}
    assert payload.name in covered, "the mirrored archive is not matched by ./source-offer/*"
    assert "README" in covered, (
        "the source-offer README is not matched by ./source-offer/*, so the "
        "statement of terms would ship outside SHA256SUMS")


def test_installer_mirrors_the_source_in_the_real_build_path():
    """--source-offer-only proves the mechanism; this proves a real bundle
    actually calls it."""
    body = read(INSTALLER)
    assert re.search(r"^write_source_offer$", body, re.MULTILINE), (
        "make-installer.sh never calls write_source_offer in the main build path")
    assert body.index("write_licenses\n") < body.rindex("write_source_offer"), (
        "the source offer must be mirrored after the notices that point at it")


def test_written_offer_points_at_the_in_bundle_copy():
    """The notices' written offer used to send customers upstream. Now that we
    ship the source itself, the offer must say so and name where it is."""
    text = read(NOTICES)
    assert "source-offer/" in text, (
        "the written offer in THIRD_PARTY_LICENSES.md does not point at the "
        "in-bundle source-offer/ directory")
    assert "syslog-ng" in text
