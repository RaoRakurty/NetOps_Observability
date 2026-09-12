# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Pipeline-debugger ship contract (W2 (f), design PIPELINE_DEBUGGER_2026-09-04 §1).

`correlix-debug` is a HOST-SIDE operator CLI, and W1 shipped it only into the
source tree: the customer bundle carried no binary, and the `CORR_DEBUG_TOKEN`
the bus peek and the correlation log-level switch need was minted by nothing —
so on a customer install the debugger was blind at exactly the hop the
2026-09-02 outage turned on (the bus) and there was no binary to run anyway.

Asserted here — static contract guards over the committed files plus a few
executed paths, no docker, no running stack, no bundle build:

  * make-installer.sh BUILDS the binary from src/backend/cmd/correlix-debug,
    with the same convention as the bundle's other Go binary (correlix-setup:
    CGO_ENABLED=0, -trimpath, no GOOS/GOARCH override), self-tests it on the
    build host, covers it in SHA256SUMS, and treats a missing Go toolchain as a
    LOUD failure rather than a silently binary-less bundle (§16.1);
  * the binary is a customer artifact on purpose: not excluded by LAB_PATHS,
    its source is not export-ignored, it carries no LAB_MARKERS, and the
    bundle's ADVANCED.md tells the customer it exists;
  * install.py MINTS CORR_DEBUG_TOKEN on a fresh install (generated → therefore
    covered by --reset-env), classifies it in secret_rotation.POLICY, and seeds
    it into an existing .env without ever overwriting an operator value;
  * update.sh reconciles the same key on an upgrade — EXECUTED, not grepped:
    the script's own reconcile block is run against a temp .env, twice, and the
    minted value must be URL-safe, must not be echoed to the terminal, and must
    survive the second run untouched;
  * docker-compose passes the one variable to BOTH services that must agree on
    it (api + correlation), so a minted value actually reaches them;
  * the two scripts stay `bash -n` and shellcheck clean.

Run:  python3 -m pytest tests/test_pipeline_debug_ship.py -v
"""

from __future__ import annotations

import re
import shutil
import string
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
MAKE_INSTALLER = SCRIPTS / "make-installer.sh"
UPDATE_SH = SCRIPTS / "update.sh"
COMPOSE = ROOT / "deployment" / "docker" / "docker-compose.yml"
CMD_DIR = ROOT / "src" / "backend" / "cmd" / "correlix-debug"

TOKEN_VAR = "CORR_DEBUG_TOKEN"
#: secrets.token_urlsafe / update.sh's randtoken alphabet. A bearer credential
#: has no business containing @ # % ^ & + =.
URLSAFE = set(string.ascii_letters + string.digits + "-_")

sys.path.insert(0, str(SCRIPTS))

import install                        # noqa: E402
import secret_rotation as sr          # noqa: E402


def _make_installer_src() -> str:
    return MAKE_INSTALLER.read_text()


def _guard_var(name: str) -> str:
    """Extract a guard regex exactly as make-installer.sh defines it."""
    m = re.search(rf"^{name}='([^']+)'", _make_installer_src(), re.M)
    assert m, f"{name} definition not found in make-installer.sh"
    return m.group(1)


# ---------------------------------------------------------------------------
# make-installer.sh — the binary is built and shipped
# ---------------------------------------------------------------------------

def test_entrypoint_the_bundle_builds_still_exists():
    assert (CMD_DIR / "main.go").is_file(), (
        "src/backend/cmd/correlix-debug/main.go is gone but make-installer.sh "
        "still builds it — the bundle build would fail at release time.")


def test_make_installer_builds_correlix_debug():
    src = _make_installer_src()
    assert re.search(
        r'go build .*-o "\$BUNDLE_DIR/correlix-debug" \./cmd/correlix-debug', src), (
        "make-installer.sh must build correlix-debug into the bundle "
        "(design §1: shipped in the bundle next to the installer).")
    assert 'cd "$ROOT/src/backend"' in src, (
        "the build must run in the backend module root — ./cmd/correlix-debug "
        "is a package path inside src/backend's go.mod.")


def test_build_follows_the_bundles_existing_go_binary_convention():
    """One convention for both shipped binaries. correlix-setup builds with
    CGO_ENABLED=0 -trimpath -ldflags='-s -w' and NO GOOS/GOARCH override (the
    build host is the release host); correlix-debug must not invent a second."""
    src = _make_installer_src()
    for binary in ("correlix-setup", "correlix-debug"):
        m = re.search(rf'(CGO_ENABLED=0 go build [^\n]*"\$BUNDLE_DIR/{binary}")', src)
        assert m, f"{binary} is not built with CGO_ENABLED=0 (static, no glibc dependency)"
        assert "-trimpath" in m.group(1), f"{binary} build lost -trimpath"
    assert not re.search(r"\bGOOS=|\bGOARCH=", src), (
        "make-installer.sh has grown a GOOS/GOARCH override: the bundle's two "
        "binaries must agree on what a bundle runs on. Change both, or neither.")


def test_missing_go_toolchain_is_a_loud_failure_not_a_silent_omission():
    src = _make_installer_src()
    m = re.search(r"command -v go >/dev/null[^\n]*\n[^\n]*", src)
    assert m, "make-installer.sh must check for the go toolchain by name (§16.2)"
    assert "FATAL" in m.group(0), (
        "a missing go toolchain must be a FATAL, named failure — a bundle that "
        "silently ships without correlix-setup/correlix-debug is §16.1's "
        "cardinal defect.")
    # And the build itself must never be softened into an optional step.
    assert not re.search(r'correlix-debug[^\n]*\|\| true', src), (
        "the correlix-debug build must never be `|| true`'d — that is exactly "
        "how a bundle ends up quietly missing an artifact it claims to ship.")


def test_freshly_built_binary_is_smoke_tested_on_the_build_host():
    src = _make_installer_src()
    assert re.search(r'"\$BUNDLE_DIR/correlix-debug" --help >/dev/null', src), (
        "make-installer.sh must prove the binary RUNS before shipping it — a "
        "0-byte or unexecutable artifact must fail the build here, not on the "
        "customer's host.")
    assert re.search(
        r'"\$BUNDLE_DIR/correlix-debug" --help >/dev/null\s*\\?\s*\n?\s*\|\| \{[^}]*FATAL', src), (
        "the --help smoke test must hard-fail the build (§16.1).")


def test_sha256sums_covers_the_correlix_debug_binary():
    src = _make_installer_src()
    m = re.search(r'^\(cd "\$BUNDLE_DIR" && sha256sum (.+) > SHA256SUMS\)$',
                  src, re.MULTILINE)
    assert m, "make-installer.sh lost its SHA256SUMS line"
    assert "correlix-debug" in m.group(1), (
        "correlix-debug must be covered by SHA256SUMS — a binary outside the "
        "integrity manifest is an unverifiable execution path on the customer "
        "host (the correlix-setup H6 rule, same reasoning).")


def test_correlix_debug_is_a_customer_artifact_not_operator_only():
    """LAB_PATHS is the operator-only exclude list. The design puts this binary
    in the customer bundle deliberately (it grants no authority: every route it
    drives is requirePlatformAdmin + audited), so it must NOT be excluded."""
    lab_paths = _guard_var("LAB_PATHS")
    for token in ("correlix-debug", "pipedebug"):
        assert token not in lab_paths, (
            f"{token} is excluded by LAB_PATHS but the design ships it to "
            f"customers (docs/design/PIPELINE_DEBUGGER_2026-09-04.md §1)")


def test_debugger_source_ships_in_the_source_archive():
    """git archive is the bundle's source of truth: an export-ignored command
    would leave customers a binary they cannot rebuild or audit."""
    paths = ["src/backend/cmd/correlix-debug/main.go",
             "src/backend/internal/pipedebug/cli/cli.go"]
    out = subprocess.run(
        ["git", "check-attr", "export-ignore", "--", *paths],
        cwd=ROOT, check=True, capture_output=True, text=True,
    ).stdout
    for line in out.strip().splitlines():
        path, _, value = line.rpartition(": export-ignore: ")
        assert value == "unspecified", f"{path} is export-ignored — it would not ship"


def test_shipped_debugger_sources_carry_no_lab_markers():
    """De-lab guarantee, using the very regex the bundle build greps with."""
    markers = _guard_var("LAB_MARKERS")
    for f in sorted(CMD_DIR.glob("*.go")):
        hit = re.search(markers, f.read_text())
        assert hit is None, f"lab marker {hit.group(0)!r} in shipped file {f}"


def test_bundle_docs_tell_the_customer_the_binary_exists():
    """A binary at the bundle root that no bundle document mentions is a
    mystery file, not a tool."""
    src = _make_installer_src()
    advanced = src.split('cat > "$BUNDLE_DIR/ADVANCED.md" <<EOF', 1)
    assert len(advanced) == 2, "ADVANCED.md heredoc not found in make-installer.sh"
    body = advanced[1].split("\nEOF\n", 1)[0]
    assert "correlix-debug" in body, (
        "the bundle's ADVANCED.md must document correlix-debug")
    assert "data/debug" in body, (
        "ADVANCED.md must say where the per-module session files land")


# ---------------------------------------------------------------------------
# install.py — the token is minted on a FRESH install
# ---------------------------------------------------------------------------

def test_generate_secrets_mints_the_debug_token():
    minted = install.generate_secrets()
    assert TOKEN_VAR in minted, (
        f"{TOKEN_VAR} must be minted by generate_secrets() — that is the one "
        f"table --reset-env rotates and the rotation gate classifies.")
    value = minted[TOKEN_VAR]
    assert len(value) >= 32, f"{TOKEN_VAR} is too short to be a shared secret"
    assert set(value) <= URLSAFE, (
        f"{TOKEN_VAR} must be URL-safe: it travels as an Authorization: Bearer "
        f"credential ({value!r} has characters outside the safe alphabet)")


def test_debug_token_is_classified_for_rotation():
    pol = sr.POLICY.get(TOKEN_VAR)
    assert pol is not None, (
        f"{TOKEN_VAR} is generated but unclassified — tests/test_secret_rotation "
        f"fails the build on this, and an unclassified secret is how "
        f"--reset-env came to hand out credentials no store was told about.")
    assert pol.cls == sr.FREE, (
        "both ends read the token from their environment at process start, so "
        "it is FREE: rewrite .env, recreate api + correlation, done.")


def _parse_env_file(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip()
    return out


def test_fresh_env_template_contains_the_token(tmp_path, capsys):
    env_path = tmp_path / ".env"
    install.write_env(env_path, 8000, force=True)
    capsys.readouterr()
    env = _parse_env_file(env_path)
    assert TOKEN_VAR in env, (
        f"a freshly written .env must carry {TOKEN_VAR}; without it the bus "
        f"peek and the correlation log-level switch stay 503 forever.")
    assert len(env[TOKEN_VAR]) >= 32 and set(env[TOKEN_VAR]) <= URLSAFE


def test_existing_env_is_seeded_once_and_never_overwritten(tmp_path, capsys):
    """The upgrade path: an install that predates the debugger gets the key,
    and a second run (or an operator-set value) is left alone."""
    env_path = tmp_path / ".env"
    env_path.write_text("BASE_PORT=8000\nADMIN_USERNAME=admin\n")

    install.write_env(env_path, 8000, force=False)
    capsys.readouterr()
    first = _parse_env_file(env_path)
    assert TOKEN_VAR in first, (
        f"write_env() must seed {TOKEN_VAR} into a pre-debugger .env — "
        f"otherwise an upgraded install can never observe the bus stage.")
    assert set(first[TOKEN_VAR]) <= URLSAFE

    install.write_env(env_path, 8000, force=False)
    capsys.readouterr()
    assert _parse_env_file(env_path)[TOKEN_VAR] == first[TOKEN_VAR], (
        "the seed must be idempotent: rewriting the token would desynchronise "
        "the api from the correlation sidecar, which must hold the SAME value.")


# ---------------------------------------------------------------------------
# update.sh — the key is reconciled on an upgrade (executed, not grepped)
# ---------------------------------------------------------------------------

def test_update_reconciliation_enumerates_the_debug_token():
    src = UPDATE_SH.read_text()
    assert f'"{TOKEN_VAR}":' in src, (
        f"{TOKEN_VAR} is missing from update.sh's EXPECTED list — an upgraded "
        f"install would never learn the knob exists.")
    m = re.search(rf'"{TOKEN_VAR}":\s*"([^"]*)"', src)
    assert m and m.group(1) == "__URLSAFE__", (
        f"{TOKEN_VAR} must be reconciled as a GENERATED url-safe secret, not "
        f"as the empty compose default: empty is fail-closed, so an upgraded "
        f"install would keep answering 503 at the bus stage. Got {m and m.group(1)!r}.")


def _reconcile_block() -> str:
    """The .env reconciliation program update.sh actually runs."""
    blocks = re.findall(r"python3 - <<'PY'\n(.*?)\nPY\n", UPDATE_SH.read_text(), re.S)
    for b in blocks:
        if "EXPECTED = {" in b:
            return b
    raise AssertionError("update.sh's .env reconcile block not found")


def test_update_actually_adds_the_token_and_never_touches_it_again(tmp_path):
    """Run update.sh's own reconcile program against a temp .env. Twice."""
    block = _reconcile_block()
    env_path = tmp_path / "deployment" / "docker" / ".env"
    env_path.parent.mkdir(parents=True)
    env_path.write_text("BASE_PORT=8000\nADMIN_USERNAME=admin\n")

    first = subprocess.run([sys.executable, "-c", block], cwd=tmp_path,
                           capture_output=True, text=True, timeout=60)
    assert first.returncode == 0, f"reconcile failed:\n{first.stdout}{first.stderr}"
    env = _parse_env_file(env_path)
    assert TOKEN_VAR in env, (
        f"update.sh did not add {TOKEN_VAR} to an existing .env")
    token = env[TOKEN_VAR]
    assert len(token) == 43 and set(token) <= URLSAFE, (
        f"{TOKEN_VAR} must be a 43-char url-safe token (randtoken), got {len(token)} chars")
    # §8/§16.5: a minted secret must never be echoed to the terminal or a log.
    assert token not in first.stdout and token not in first.stderr, (
        f"update.sh printed the {TOKEN_VAR} value — secrets stay out of output")
    assert f"{TOKEN_VAR}=<43 chars>" in first.stdout, (
        f"update.sh should report {TOKEN_VAR} as redacted so the operator can "
        f"see it was added")

    second = subprocess.run([sys.executable, "-c", block], cwd=tmp_path,
                            capture_output=True, text=True, timeout=60)
    assert second.returncode == 0, f"second reconcile failed:\n{second.stderr}"
    assert _parse_env_file(env_path)[TOKEN_VAR] == token, (
        "reconciliation must never overwrite an existing value (§16.3 "
        "idempotence) — a rewritten token desynchronises api and correlation.")


# ---------------------------------------------------------------------------
# The minted value has to reach both halves of the pair
# ---------------------------------------------------------------------------

def test_compose_passes_the_token_to_both_services_that_must_agree():
    services = yaml.safe_load(COMPOSE.read_text())["services"]
    for svc in ("api", "correlation"):
        env = services[svc].get("environment") or {}
        assert env.get(TOKEN_VAR) == "${" + TOKEN_VAR + ":-}", (
            f"{svc} must receive {TOKEN_VAR} as a defaulted pass-through "
            f"(default-closed); got {env.get(TOKEN_VAR)!r}. Minting the secret "
            f"is pointless if it does not reach both ends of the sidecar call.")


# ---------------------------------------------------------------------------
# Script hygiene (§16.3)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("script", [MAKE_INSTALLER, UPDATE_SH], ids=lambda p: p.name)
def test_scripts_parse(script):
    r = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
    assert r.returncode == 0, f"bash -n {script.name}:\n{r.stderr}"


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck not installed")
@pytest.mark.parametrize("script", [MAKE_INSTALLER, UPDATE_SH], ids=lambda p: p.name)
def test_scripts_are_shellcheck_clean(script):
    r = subprocess.run(["shellcheck", str(script)], capture_output=True, text=True)
    assert r.returncode == 0, f"shellcheck {script.name}:\n{r.stdout}{r.stderr}"
