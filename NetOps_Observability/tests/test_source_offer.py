# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

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
    m = re.search(# `^\s*`: indented since the line moved into finalize_bundle()
                  # (RC1 directive Decision 3B, release mode).
                  r"^\s*\(cd \"\$BUNDLE_DIR\" && sha256sum .*> SHA256SUMS\)$",
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


# ── retention is consulted UNASKED (the gitlab-418 class, 2026-09-14) ────────
#
# CI run 34789741432 (job `bundle`, on main) failed with
#   curl: (22) The requested URL returned error: 418
# fetching `busybox 1.37.0-r12`'s Alpine packaging archive from
# gitlab.alpinelinux.org — while a byte-identical, sha256-matching copy of that
# exact archive sat in compliance/corresponding-sources/ in the same checkout.
# The retained copy was only consulted when a caller had exported
# CORRELIX_SOURCE_MIRROR_DIR, which release-bundle.yml does not. Retention a
# build reaches for only when asked is tracker 238's "a recorded obligation
# decays" with an extra step, so these tests hold the acquisition ORDER, not
# just the checksum gate.

RETENTION_DIR = os.path.join(ROOT, "compliance", "corresponding-sources")

# A `curl` that cannot reach anything and records every URL it was handed, so a
# test can prove the build took the retained copy INSTEAD of the network rather
# than merely ending up with the right bytes. STUB_CURL_SERVE_PREFIX lets one
# recorded source "work", which makes the mirror-fallback ORDER observable.
#
# It is exported as a bash FUNCTION, not dropped on $PATH: make-installer.sh
# hardens its own PATH to /usr/local/bin:/usr/bin:/bin (§16.2, cron), so a stub
# directory would be ignored — and that hardening is worth more than the
# convenience of a simpler stub. A function still satisfies `command -v curl`.
_STUB_CURL = r'''() {
  local dest="" last=""
  while [ $# -gt 0 ]; do
    if [ "$1" = "-o" ]; then dest="$2"; fi
    last="$1"; shift
  done
  printf '%s\n' "$last" >> "$STUB_CURL_LOG"
  if [ -n "${STUB_CURL_SERVE_PREFIX:-}" ] && [ -n "${STUB_CURL_PAYLOAD:-}" ] \
     && [ "${last#"$STUB_CURL_SERVE_PREFIX"}" != "$last" ] && [ -n "$dest" ]; then
    cp "$STUB_CURL_PAYLOAD" "$dest"
    return 0
  fi
  echo "curl: (22) The requested URL returned error: 418" >&2
  return 22
}'''


def _no_network(tmp_path):
    """(env, log) — an environment whose only curl is the recording stub."""
    log = tmp_path / "curl.log"
    env = dict(os.environ)
    env["BASH_FUNC_curl%%"] = _STUB_CURL
    env["STUB_CURL_LOG"] = str(log)
    # One attempt per URL: the retry schedule is proven by its own test below,
    # and the other tests must not pay for its sleeps.
    env["CORRELIX_SOURCE_FETCH_ATTEMPTS"] = "1"
    env.pop("CORRELIX_SOURCE_MIRROR_DIR", None)
    return env, log


def _real_retained_entry(file_name: str = "busybox-1.37.0-r12-alpine-aports.tar.gz") -> dict:
    """The REAL pin for an artifact this repository actually retains.

    Deliberately not a synthetic fixture: the property under test is that the
    checked-in pin table and the checked-in retention directory resolve each
    other with no help from the environment.
    """
    pins = json.loads(read(PINS))
    entry = next(c for c in pins["components"] if c["file"] == file_name)
    assert os.path.isfile(os.path.join(RETENTION_DIR, file_name)), (
        f"{file_name} is pinned as retained but is not in compliance/corresponding-sources/")
    return entry


def _pin_file(tmp_path, entry: dict, name: str = "pins.json"):
    p = tmp_path / name
    p.write_text(json.dumps({"components": [entry]}), encoding="utf-8")
    return p


def _run(env, pinfile, out, extra=()):
    return subprocess.run(
        ["bash", INSTALLER, "--source-offer-only", "--out", str(out), *extra],
        cwd=ROOT, capture_output=True, text=True, timeout=300, check=False, env={
            **env, "CORRELIX_SOURCE_PINS": str(pinfile)},
    )


def test_a_retained_copy_is_taken_without_any_env_knob(tmp_path):
    """The regression test for run 34789741432. No CORRELIX_SOURCE_MIRROR_DIR,
    no reachable network: the build must still ship the source, from the copy
    Correlix retains in this repository."""
    entry = dict(_real_retained_entry())
    unreachable = "https://gitlab.invalid/alpine/aports/-/archive/deadbeef/x.tar.gz?path=main/busybox"
    entry["url"] = unreachable
    entry.pop("mirrors", None)
    env, log = _no_network(tmp_path)
    out = tmp_path / "dist"
    proc = _run(env, _pin_file(tmp_path, entry), out)

    assert proc.returncode == 0, f"retained source was not used:\n{proc.stdout}\n{proc.stderr}"
    assert "(retained copy)" in proc.stdout, proc.stdout
    assert not log.exists(), (
        f"the build went to the network for an artifact it already retains: "
        f"{log.read_text(encoding='utf-8') if log.exists() else ''}")
    shipped = _bundle_dir(out) / "source-offer" / entry["file"]
    assert hashlib.sha256(shipped.read_bytes()).hexdigest() == entry["sha256"]


def test_the_retention_directory_resolves_by_convention_not_only_by_the_field(tmp_path):
    """`retained_in_git` is bookkeeping; the directory is the retention. A pin
    that names no path must still find the file that is sitting there, or a
    forgotten field silently turns a retained artifact back into a download."""
    entry = dict(_real_retained_entry())
    entry["url"] = "https://gitlab.invalid/aports.tar.gz?path=main/busybox"
    entry["retained_in_git"] = ""
    entry.pop("mirrors", None)
    env, log = _no_network(tmp_path)
    out = tmp_path / "dist"
    proc = _run(env, _pin_file(tmp_path, entry), out)
    assert proc.returncode == 0, f"{proc.stdout}\n{proc.stderr}"
    assert "compliance/corresponding-sources/" in proc.stdout
    assert not log.exists(), "the retention directory was skipped and the network used"


def test_a_retained_copy_that_disagrees_with_the_pin_is_fatal_and_never_fetched(tmp_path):
    """Drift between Correlix's own artifact and Correlix's own pin is a human
    decision (re-measure, or restore the file) — never a reason to fall back to
    the network and ship bytes nobody reviewed."""
    entry = dict(_real_retained_entry())
    entry["sha256"] = "0" * 64
    env, log = _no_network(tmp_path)
    out = tmp_path / "dist"
    proc = _run(env, _pin_file(tmp_path, entry), out)
    both = proc.stdout + proc.stderr
    assert proc.returncode != 0, "a retained copy that fails its pin was accepted"
    assert "checksum mismatch" in both.lower()
    assert "retained copy at compliance/corresponding-sources/" in both, both
    assert not log.exists(), "a pin/retention mismatch fell back to the network"
    assert not (_bundle_dir(out) / "source-offer" / entry["file"]).exists()


def test_a_stale_prepared_mirror_is_reported_even_when_another_copy_is_good(tmp_path):
    """§16.1: the good copy wins, but the stale one is named. A prepared mirror
    that has quietly gone wrong must not be silently stepped over."""
    entry = dict(_real_retained_entry())
    entry.pop("mirrors", None)
    entry["url"] = "https://gitlab.invalid/aports.tar.gz?path=main/busybox"
    stale = tmp_path / "prepared"
    stale.mkdir()
    (stale / entry["file"]).write_bytes(b"not the retained bytes")
    env, log = _no_network(tmp_path)
    env["CORRELIX_SOURCE_MIRROR_DIR"] = str(stale)
    out = tmp_path / "dist"
    proc = _run(env, _pin_file(tmp_path, entry), out)
    assert proc.returncode == 0, f"{proc.stdout}\n{proc.stderr}"
    assert "WARNING" in proc.stderr and entry["file"] in proc.stderr, proc.stderr
    assert "(retained copy)" in proc.stdout
    assert not log.exists()
    shipped = _bundle_dir(out) / "source-offer" / entry["file"]
    assert hashlib.sha256(shipped.read_bytes()).hexdigest() == entry["sha256"]


def test_the_fetch_path_tries_the_recorded_mirror_after_the_pinned_url(tmp_path):
    """§16.2: when an artifact is NOT retained, one host must not be the whole
    plan. The pinned URL is tried first, then each alternate the pin records."""
    _mirror_dir, pinfile, payload, digest = _fixture_mirror(tmp_path)
    entry = json.loads(pinfile.read_text(encoding="utf-8"))["components"][0]
    entry["url"] = "https://primary.invalid/fauxcomponent-1.2.3.tar.gz"
    entry["mirrors"] = [{"url": "https://second.invalid/fauxcomponent-1.2.3.tar.gz",
                         "why": "fixture alternate"}]
    env, log = _no_network(tmp_path)
    env["STUB_CURL_SERVE_PREFIX"] = "https://second.invalid/"
    env["STUB_CURL_PAYLOAD"] = str(payload)
    out = tmp_path / "dist"
    proc = _run(env, _pin_file(tmp_path, entry, "pins-mirror.json"), out)

    assert proc.returncode == 0, f"{proc.stdout}\n{proc.stderr}"
    tried = log.read_text(encoding="utf-8").split()
    assert tried == [entry["url"], entry["mirrors"][0]["url"]], (
        f"wrong acquisition order: {tried}")
    shipped = _bundle_dir(out) / "source-offer" / payload.name
    assert hashlib.sha256(shipped.read_bytes()).hexdigest() == digest


def test_the_fetch_path_retries_each_source_and_then_fails_closed(tmp_path):
    """Bounded retries (CLAUDE.md §9 / §16.2) and a loud end: every recorded
    source is attempted the configured number of times, and an artifact that is
    neither retained nor fetchable FAILS the build."""
    _mirror_dir, pinfile, payload, _digest = _fixture_mirror(tmp_path)
    entry = json.loads(pinfile.read_text(encoding="utf-8"))["components"][0]
    entry["url"] = "https://primary.invalid/fauxcomponent-1.2.3.tar.gz"
    entry["mirrors"] = [{"url": "https://second.invalid/fauxcomponent-1.2.3.tar.gz"}]
    env, log = _no_network(tmp_path)
    env["CORRELIX_SOURCE_FETCH_ATTEMPTS"] = "2"
    out = tmp_path / "dist"
    proc = _run(env, _pin_file(tmp_path, entry, "pins-retry.json"), out)

    assert proc.returncode != 0, "an unfetchable, unretained artifact did not fail the build"
    tried = log.read_text(encoding="utf-8").split()
    assert tried == [entry["url"], entry["url"],
                     entry["mirrors"][0]["url"], entry["mirrors"][0]["url"]], tried
    assert "retrying in" in proc.stderr, "the retry schedule is not reported"
    assert "corresponding source" in (proc.stdout + proc.stderr)
    assert not (_bundle_dir(out) / "source-offer" / payload.name).exists(), (
        "a partial download was left in the bundle")


# ── the class-level guard: no obligation may rest on a gitlab archive URL ────

def _gitlab_generated_archive(url: str) -> bool:
    """GitLab's *generated* archive endpoint — a tarball GitLab builds on demand
    from a git ref, path-filtered (`?path=main/<pkg>`) or whole-repo. The
    path-filtered form is the one that answered CI with HTTP 418, and the
    whole-repo form is the same endpoint on the same bot-filtered host, so the
    guard covers both rather than waiting to learn the difference in a release."""
    return "gitlab.alpinelinux.org" in url and "/-/archive/" in url


def test_no_obligation_depends_on_a_gitlab_generated_archive(pins):
    """The repo-level guard, so this failure class cannot come back.

    Every Alpine aports packaging archive (and the apk-tools release archive) is
    fetched from GitLab's generated archive endpoint, which (a) 418s bot-filtered
    clients — GitHub-hosted runners included — and (b) publishes no digest of its
    own, so our pin is a self-measurement that a future archive-format change
    would break anyway.
    Such a URL is therefore allowed as PROVENANCE only: the artifact itself must
    be retained here, byte-verified against the pin.

    SCOPE: `components[]` — what a build actually fetches. The eleven gitlab URLs
    under `deferred_source_coordinates` are coordinates for obligations tracker
    238 records as UNDISCHARGED; nothing fetches them, and they must not be
    retro-fitted into this guard (that would read as compliance). They come under
    it the moment one of them becomes a component.
    """
    affected = [c for c in pins["components"]
                if _gitlab_generated_archive(c["url"])
                or any(_gitlab_generated_archive(m["url"]) for m in c.get("mirrors") or [])]
    assert len(affected) >= 12, (
        f"expected the eleven Alpine aports packaging archives plus the apk-tools "
        f"release archive, found {len(affected)} — if the class really shrank, keep "
        f"the guard and lower the count deliberately")
    for c in affected:
        retained = c.get("retained_in_git") or ""
        assert retained, (
            f"{c['name']} {c['version']} is acquired from a gitlab generated "
            f"archive ({c['url']}) and retains nothing: one 418 from CI and the "
            f"release cannot prove it ships the source it owes")
        path = os.path.join(ROOT, retained)
        assert os.path.isfile(path), f"{retained} is recorded as retained but is not in the tree"
        with open(path, "rb") as fh:
            got = hashlib.sha256(fh.read()).hexdigest()
        assert got == c["sha256"], (
            f"the retained {retained} does not match its pin ({got} != {c['sha256']})")


def test_the_installer_consults_the_retention_directory_unconditionally():
    """Read from the script: the retention directory is in the candidate list
    with no `if [ -n "$CORRELIX_SOURCE_MIRROR_DIR" ]` in front of it. The bug
    this replaces was exactly that guard."""
    body = read(INSTALLER)
    assert re.search(r'^RETAINED_SOURCE_DIR="compliance/corresponding-sources"$',
                     body, re.MULTILINE), (
        "make-installer.sh no longer names the retention directory")
    m = re.search(r'^\s*retained_dirs\+=\("\$ROOT/\$RETAINED_SOURCE_DIR"\)$',
                  body, re.MULTILINE)
    assert m, "the retention directory is not an unconditional candidate directory"
    # The line before it may test CORRELIX_SOURCE_MIRROR_DIR (that directory IS
    # conditional); the retention line itself must carry no test at all.
    assert "CORRELIX_SOURCE_MIRROR_DIR" not in m.group(0)


def test_the_release_bundle_job_relies_on_the_script_for_retained_source():
    """The job that failed (run 34789741432). Unlike supply-chain.yml it has no
    acquisition step in front of the installer, so the retained copies have to be
    the SCRIPT's own default — which is what the test above holds. If an
    acquisition step is ever added here, this test is the place that says the
    script's default is no longer the only thing standing between a release and a
    third-party outage."""
    wf = os.path.join(ROOT, "..", ".github", "workflows", "release-bundle.yml")
    text = read(wf)
    assert "scripts/make-installer.sh" in text, (
        "release-bundle.yml no longer builds the bundle with make-installer.sh")
    assert "source-archive.py materialise" not in text, (
        "an acquisition step appeared in release-bundle.yml — re-read the "
        "docstring and decide deliberately which layer owns retention here")
