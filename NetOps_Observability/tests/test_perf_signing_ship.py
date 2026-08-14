"""Pipeline-ladder ship contracts (owner-approved rungs, 2026-08-14).

Two rungs pinned here:

1. PERF RUNG — `.github/workflows/perf-nightly.yml`:
   * parses as YAML and is non-blocking on PRs BY CONSTRUCTION (schedule +
     workflow_dispatch only — adding a push/pull_request trigger fails this
     suite, not just review);
   * every pytest file the workflow invokes actually exists in
     src/correlation (a renamed suite must break CI here, at PR time, not
     silently skip in the nightly);
   * the wall-clock canary is opt-in (PERF_CANARY=1 + `perf_canary` marker)
     so the blocking correlation-ci gate never depends on runner speed.

2. SIGNING SCAFFOLD (#97, owner-gated key custody):
   * make-installer.sh signs ONLY when CORRELIX_SIGNING_KEY is set — the
     grep-level contract that the block is conditional, never generates a
     key, records the fingerprint in MANIFEST BEFORE checksumming (so the
     signed SHA256SUMS covers the claim), and announces the checksum-only
     default loudly;
   * install-correlix.sh verify_bundle, EXECUTED (fake gpg on PATH, same
     technique as test_watchdog_ship.py): good signature → ok, BAD signature
     → die, missing public key → warn-and-continue with the import
     instruction, absent .asc → today's checksum-only behavior (gpg never
     invoked).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
MAKE_INSTALLER = SCRIPTS / "make-installer.sh"
INSTALL = SCRIPTS / "install-correlix.sh"
CORRELATION = ROOT / "src" / "correlation"
PERF_WORKFLOW = ROOT.parent / ".github" / "workflows" / "perf-nightly.yml"

REQUIRED_PERF_SUITES = {
    "test_engine_complexity.py",
    "test_rolling_stats.py",
    "test_ch_batching.py",
    "test_series_budget.py",
    "test_perf_canary.py",
}


# ---------------------------------------------------------------------------
# 1. perf-nightly workflow contract
# ---------------------------------------------------------------------------

def _perf_workflow():
    import yaml
    text = PERF_WORKFLOW.read_text()
    wf = yaml.safe_load(text)
    return text, wf


def test_perf_workflow_parses_and_is_nonblocking_on_prs():
    _, wf = _perf_workflow()
    # YAML 1.1 loads a bare `on:` key as boolean True.
    triggers = wf.get("on", wf.get(True))
    assert triggers is not None, "perf-nightly.yml has no trigger block"
    assert set(triggers) == {"schedule", "workflow_dispatch"}, (
        "perf rung must stay non-blocking: schedule + manual dispatch ONLY "
        f"(found triggers: {sorted(triggers)})"
    )
    assert wf.get("permissions") == {"contents": "read"}, (
        "workflow must hold the repo convention: permissions contents: read"
    )
    assert "concurrency" in wf and "group" in wf["concurrency"], (
        "workflow must declare a concurrency group (repo convention)"
    )


def test_perf_workflow_references_only_existing_test_files():
    text, _ = _perf_workflow()
    referenced = set(re.findall(r"\btest_\w+\.py\b", text))
    assert referenced, "perf-nightly.yml invokes no test files at all"
    missing = sorted(f for f in referenced if not (CORRELATION / f).is_file())
    assert not missing, (
        f"perf-nightly.yml references test files that do not exist in "
        f"src/correlation: {missing} — a rename must be mirrored here"
    )
    absent = sorted(REQUIRED_PERF_SUITES - referenced)
    assert not absent, (
        f"perf rung dropped required suites: {absent}"
    )


def test_perf_canary_is_optin_and_marked():
    text, _ = _perf_workflow()
    assert re.search(r"PERF_CANARY:\s*'1'", text), (
        "the canary step must opt in via PERF_CANARY=1 — without it the "
        "nightly would 'pass' on a skipped canary"
    )
    assert "-m perf_canary" in text, "canary step must select the perf_canary marker"
    canary = (CORRELATION / "test_perf_canary.py").read_text()
    assert "@pytest.mark.perf_canary" in canary
    assert re.search(r"CANARY_CEILING_S\s*=\s*30", canary), (
        "the 30s catastrophic ceiling is the owner-approved contract"
    )
    conftest = (CORRELATION / "conftest.py").read_text()
    assert "perf_canary" in conftest and "PERF_CANARY" in conftest, (
        "conftest must register the marker AND gate it on PERF_CANARY — "
        "otherwise the wall-clock test runs inside the blocking PR gate"
    )


# ---------------------------------------------------------------------------
# 2a. make-installer.sh signing block: conditional-only (grep contract)
# ---------------------------------------------------------------------------

def _code_lines(text: str):
    """(line_no, line) for non-comment, non-empty lines."""
    for i, line in enumerate(text.splitlines()):
        s = line.strip()
        if s and not s.startswith("#"):
            yield i, line


def test_make_installer_signs_only_when_owner_key_is_set():
    text = MAKE_INSTALLER.read_text()
    lines = text.splitlines()
    guard = next(
        (i for i, l in enumerate(lines)
         if re.search(r'if \[ -n "\$\{CORRELIX_SIGNING_KEY:-\}" \]', l)),
        None,
    )
    assert guard is not None, "CORRELIX_SIGNING_KEY guard missing from make-installer.sh"
    # Every real gpg invocation lives after (inside) the owner-key gates.
    gpg_calls = [i for i, l in _code_lines(text) if re.search(r"\bgpg\b", l)]
    assert gpg_calls, "signing block lost its gpg invocations"
    early = [i for i in gpg_calls if i < guard]
    assert not early, (
        f"gpg invoked OUTSIDE the CORRELIX_SIGNING_KEY guard (lines {early}) — "
        "signing must be conditional-only"
    )
    sign = next((i for i, l in enumerate(lines) if "--detach-sign" in l), None)
    fpr_guard = next(
        (i for i, l in enumerate(lines) if 'if [ -n "$SIGNING_FPR" ]' in l), None)
    assert sign is not None and fpr_guard is not None and sign > fpr_guard, (
        "--detach-sign must sit inside the `[ -n \"$SIGNING_FPR\" ]` branch"
    )


def test_make_installer_never_generates_a_key():
    """Key custody is an owner decision: the build tooling may USE a key,
    never mint one (the TODO's original 'NEVER generate or embed' clause)."""
    text = MAKE_INSTALLER.read_text()
    for forbidden in ("--gen-key", "--generate-key", "--full-generate-key",
                      "--quick-generate-key", "--quick-gen-key"):
        assert forbidden not in text, (
            f"make-installer.sh must never generate a signing key ({forbidden})"
        )


def test_make_installer_fingerprint_lands_in_manifest_before_checksumming():
    """MANIFEST is a SHA256SUMS member: the signing-key line must be appended
    BEFORE sha256sum runs, or the signed checksums would not cover the
    fingerprint claim."""
    text = MAKE_INSTALLER.read_text()
    fpr = text.find("printf 'signing-key %s\\n'")
    sums = text.find("sha256sum ./*.tar.*")
    assert fpr != -1, "signing-key fingerprint is no longer recorded in MANIFEST"
    assert sums != -1, "SHA256SUMS generation line not found"
    assert fpr < sums, (
        "signing-key must be appended to MANIFEST BEFORE SHA256SUMS is "
        "computed — otherwise the signature does not cover the fingerprint"
    )


def test_make_installer_checksum_only_default_is_loud():
    text = MAKE_INSTALLER.read_text()
    assert re.search(r'^\s*echo "NOTE: CORRELIX_SIGNING_KEY unset.*CHECKSUM-ONLY',
                     text, re.M), (
        "the unsigned default must announce itself with a loud NOTE line — "
        "a checksum-only release is a visible choice, never an accident"
    )


# ---------------------------------------------------------------------------
# 2b. install-correlix.sh verify path, EXECUTED with a fake gpg on PATH
# ---------------------------------------------------------------------------

FAKE_GPG = """#!/bin/sh
# Fake gpg for tests: emits --status-fd 1 verdict lines per GPG_FAKE_MODE.
case "${GPG_FAKE_MODE:-}" in
  good)
    printf '[GNUPG:] GOODSIG 0123456789ABCDEF Correlix Release Signing Key\\n'
    exit 0 ;;
  badsig)
    printf '[GNUPG:] BADSIG 0123456789ABCDEF Correlix Release Signing Key\\n'
    exit 1 ;;
  nopubkey)
    printf '[GNUPG:] ERRSIG 0123456789ABCDEF 1 8 00 1755000000 9 -\\n'
    printf '[GNUPG:] NO_PUBKEY 0123456789ABCDEF\\n'
    exit 2 ;;
  *)
    echo "fake gpg invoked with GPG_FAKE_MODE unset" >&2
    exit 99 ;;
esac
"""


def _extract_verify_functions() -> str:
    out = subprocess.run(
        ["sed", "-n",
         "-e", "/^verify_release_signature() {/,/^}/p",
         "-e", "/^verify_bundle() {/,/^}/p",
         str(INSTALL)],
        check=True, capture_output=True, text=True,
    ).stdout
    assert "verify_release_signature()" in out and "verify_bundle()" in out
    return out


def _run_verify_bundle(tmp_path, mode, with_asc=True):
    """Build a minimal bundle dir (real sha256sum over MANIFEST) and run the
    REAL verify_bundle with stubbed output helpers and a fake gpg on PATH."""
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "MANIFEST").write_text(
        "version test-0.0.0\nsigning-key 0123456789ABCDEF0123456789ABCDEF01234567\n")
    subprocess.run(
        ["bash", "-c", "sha256sum MANIFEST > SHA256SUMS"],
        cwd=bundle, check=True,
    )
    if with_asc:
        (bundle / "SHA256SUMS.asc").write_text(
            "-----BEGIN PGP SIGNATURE-----\nfake\n-----END PGP SIGNATURE-----\n")
    root = tmp_path / "extracted-root"
    root.mkdir()  # present ⇒ verify_bundle skips the tar-extraction branch
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "gpg"
    fake.write_text(FAKE_GPG)
    fake.chmod(0o755)
    env = os.environ.copy()
    env["PATH"] = f"{bindir}:{env['PATH']}"
    if mode is not None:
        env["GPG_FAKE_MODE"] = mode
    script = "\n".join([
        "set -euo pipefail",
        'say()  { printf "SAY: %s\\n" "$*"; }',
        'ok()   { printf "OK: %s\\n" "$*"; }',
        'warn() { printf "WARN: %s\\n" "$*" >&2; }',
        'die()  { printf "DIE: %s\\n" "$1" >&2; exit 9; }',
        f'BUNDLE_DIR="{bundle}"',
        f'ROOT="{root}"',
        _extract_verify_functions(),
        "verify_bundle",
    ])
    return subprocess.run(["bash", "-c", script], env=env,
                          capture_output=True, text=True)


def test_verify_bundle_accepts_good_signature(tmp_path):
    r = _run_verify_bundle(tmp_path, "good")
    assert r.returncode == 0, f"rc={r.returncode}\n{r.stdout}\n{r.stderr}"
    assert "OK: bundle integrity verified" in r.stdout
    assert "release signature verified" in r.stdout


def test_verify_bundle_dies_on_bad_signature(tmp_path):
    r = _run_verify_bundle(tmp_path, "badsig")
    assert r.returncode == 9, (
        f"BAD signature must die, got rc={r.returncode}\n{r.stdout}\n{r.stderr}"
    )
    assert "DIE:" in r.stderr and "FAILED" in r.stderr


def test_verify_bundle_warns_and_continues_without_pubkey(tmp_path):
    r = _run_verify_bundle(tmp_path, "nopubkey")
    assert r.returncode == 0, (
        f"missing PUBLIC key is warn-and-continue, got rc={r.returncode}\n"
        f"{r.stdout}\n{r.stderr}"
    )
    assert "WARN:" in r.stderr and "NOT verified" in r.stderr
    assert "gpg --import" in r.stderr, "the import instruction must be given"
    assert "MANIFEST" in r.stderr, "point at the fingerprint recorded in MANIFEST"


def test_verify_bundle_without_asc_is_todays_behavior(tmp_path):
    """No .asc ⇒ checksum-only path, gpg never invoked (the fake gpg exits 99
    on any un-moded call, so an accidental invocation fails this test)."""
    r = _run_verify_bundle(tmp_path, None, with_asc=False)
    assert r.returncode == 0, f"rc={r.returncode}\n{r.stdout}\n{r.stderr}"
    assert "OK: bundle integrity verified" in r.stdout
    assert "signature" not in (r.stdout + r.stderr).lower()


# ---------------------------------------------------------------------------
# Hygiene floor for the touched scripts
# ---------------------------------------------------------------------------

def test_touched_scripts_parse():
    for script in (MAKE_INSTALLER, INSTALL):
        r = subprocess.run(["bash", "-n", str(script)],
                           capture_output=True, text=True)
        assert r.returncode == 0, f"bash -n {script.name}: {r.stderr}"


@pytest.mark.skipif(shutil.which("shellcheck") is None,
                    reason="shellcheck not installed")
def test_touched_scripts_shellcheck_clean():
    # -S warning: the file carries two pre-existing SC2015 *info* notes in the
    # untouched menu region; warnings and above are the merge bar here.
    for script in (MAKE_INSTALLER, INSTALL):
        r = subprocess.run(["shellcheck", "-S", "warning", str(script)],
                           capture_output=True, text=True)
        assert r.returncode == 0, f"shellcheck {script.name}:\n{r.stdout}{r.stderr}"
