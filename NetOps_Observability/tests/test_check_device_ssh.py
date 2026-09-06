# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Guards for scripts/check-device-ssh.sh (tracker 247).

The script exists to answer one question honestly — "is the device SSH identity
configured, and does it still authenticate?" — WITHOUT ever exposing the
credential. Both halves of that are testable without a network:

  1. the exit-code contract (0 ok / 1 failed / 2 usage / 3 not configured /
     4 sealed) — an operator and any future watchdog branch on these;
  2. the secret never appears in stdout or stderr on ANY of those paths, and
     the account name only appears when --show-user is passed;
  3. the identity precedence matches protocolDiagCredential() in
     src/backend/protocol_diag_gateway.go — dedicated first, config-backup
     fallback only when none of the three dedicated variables is set, and a
     PARTIAL dedicated identity is a refusal rather than a silent fallback;
  4. §16 shell hygiene: `set -Eeuo pipefail`, an explicit PATH, no `set -x`
     (which would echo the secret into the terminal and any cron mail).

Every case here uses a throwaway env file and an address that is never dialed
(the not-configured/sealed/usage paths all exit before the probe), so the suite
needs neither a device nor the stack.

Run:  python3 -m pytest tests/test_check_device_ssh.py -q
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check-device-ssh.sh"

# A distinctive value that must never be echoed back on any path.
SECRET = "n3v3r-pr1nt-th1s-s3cr3t"
ACCOUNT = "correlix-ro-probe"

# Documentation-range address (RFC 5737). Only the paths that exit BEFORE the
# probe use it, so nothing is ever dialed.
UNUSED_ADDR = "192.0.2.10"


def run(env_file: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(SCRIPT), "--env-file", str(env_file), *args],
        capture_output=True, text=True, timeout=60,
    )


def write_env(tmp_path: Path, body: str, name: str = "probe.env") -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    path.chmod(0o600)
    return path


def test_script_is_executable_and_shellcheck_clean():
    assert SCRIPT.exists(), f"{SCRIPT} is missing"
    assert SCRIPT.stat().st_mode & 0o111, "check-device-ssh.sh must be executable"
    shellcheck = shutil.which("shellcheck")
    if shellcheck is None:
        pytest.skip("shellcheck not installed")
    proc = subprocess.run([shellcheck, str(SCRIPT)], capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, f"shellcheck findings:\n{proc.stdout}{proc.stderr}"


def test_shell_hygiene_16_3():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "set -Eeuo pipefail" in text, "§16.3 requires set -Eeuo pipefail"
    assert "\nPATH=" in text, "§16.2 requires an explicit PATH"
    # `set -x` would trace the sshpass invocation and the secret with it.
    assert "set -x" not in text, "set -x would echo the credential"
    assert "trap " in text, "§16.1 requires a loud failure trap"


def test_not_configured_is_exit_3_and_says_so(tmp_path: Path):
    env = write_env(tmp_path, "")
    proc = run(env, "--address", UNUSED_ADDR)
    assert proc.returncode == 3, proc.stdout + proc.stderr
    assert "configured: no" in proc.stdout
    assert "CONFIG_BACKUP_SSH_USER" in proc.stderr


def test_partial_dedicated_identity_refuses_rather_than_falling_back(tmp_path: Path):
    """protocolDiagCredential() treats this as a hard error; so must the tool.

    A user with no secret must NOT silently fall back to the config-backup
    account — that would authenticate as a different account than the operator
    named, and the tool would then report a credential that is not the one in
    use.
    """
    env = write_env(
        tmp_path,
        f"PROTOCOL_DIAG_SSH_USER={ACCOUNT}\n"
        f"CONFIG_BACKUP_SSH_USER=fallback-account\n"
        f"CONFIG_BACKUP_SSH_PASSWORD={SECRET}\n",
    )
    proc = run(env, "--address", UNUSED_ADDR)
    assert proc.returncode == 3, proc.stdout + proc.stderr
    assert "PROTOCOL_DIAG_SSH_USER" in proc.stderr
    assert SECRET not in proc.stdout + proc.stderr
    assert "fallback-account" not in proc.stdout + proc.stderr


def test_dedicated_identity_wins_over_config_backup(tmp_path: Path):
    env = write_env(
        tmp_path,
        f"PROTOCOL_DIAG_SSH_USER={ACCOUNT}\n"
        f"PROTOCOL_DIAG_SSH_PASSWORD=v1:sealed\n"
        f"CONFIG_BACKUP_SSH_USER=fallback-account\n"
        f"CONFIG_BACKUP_SSH_PASSWORD={SECRET}\n",
    )
    proc = run(env, "--address", UNUSED_ADDR)
    # Sealed short-circuit proves WHICH identity was selected without dialing.
    assert proc.returncode == 4, proc.stdout + proc.stderr
    assert "PROTOCOL_DIAG_SSH_*" in proc.stdout
    assert "CONFIG_BACKUP_SSH_*" not in proc.stdout


def test_config_backup_is_the_documented_fallback(tmp_path: Path):
    env = write_env(
        tmp_path,
        f"CONFIG_BACKUP_SSH_USER={ACCOUNT}\nCONFIG_BACKUP_SSH_PASSWORD=v1:sealed\n",
    )
    proc = run(env, "--address", UNUSED_ADDR)
    assert proc.returncode == 4, proc.stdout + proc.stderr
    assert "CONFIG_BACKUP_SSH_*" in proc.stdout
    assert "the documented fallback" in proc.stdout


def test_sealed_secret_is_reported_not_guessed(tmp_path: Path):
    env = write_env(
        tmp_path,
        f"CONFIG_BACKUP_SSH_USER={ACCOUNT}\nCONFIG_BACKUP_SSH_PASSWORD=v1:{SECRET}\n",
    )
    proc = run(env, "--address", UNUSED_ADDR)
    assert proc.returncode == 4, proc.stdout + proc.stderr
    assert "configured: yes" in proc.stdout
    assert "sealed-secret" in proc.stdout
    assert SECRET not in proc.stdout + proc.stderr


def test_secret_and_account_are_never_printed_by_default(tmp_path: Path):
    env = write_env(
        tmp_path,
        f"CONFIG_BACKUP_SSH_USER={ACCOUNT}\nCONFIG_BACKUP_SSH_PASSWORD=v1:{SECRET}\n",
    )
    proc = run(env, "--address", UNUSED_ADDR)
    combined = proc.stdout + proc.stderr
    assert SECRET not in combined, "the secret leaked into the output"
    assert ACCOUNT not in combined, "the account name leaked without --show-user"
    # The SHAPE is reported instead.
    assert "CONFIG_BACKUP_SSH_PASSWORD=set" in proc.stdout


def test_show_user_is_opt_in(tmp_path: Path):
    env = write_env(
        tmp_path,
        f"CONFIG_BACKUP_SSH_USER={ACCOUNT}\nCONFIG_BACKUP_SSH_PASSWORD=v1:{SECRET}\n",
    )
    proc = run(env, "--address", UNUSED_ADDR, "--show-user")
    assert ACCOUNT in proc.stdout
    assert SECRET not in proc.stdout + proc.stderr


@pytest.mark.parametrize(
    "args",
    [
        ("--identity", "bogus", "--address", UNUSED_ADDR),
        ("--timeout", "zero", "--address", UNUSED_ADDR),
        ("--timeout", "0", "--address", UNUSED_ADDR),
        ("--port", "http", "--address", UNUSED_ADDR),
        ("--nonsense",),
        (),  # neither --device nor --address
    ],
)
def test_usage_errors_are_exit_2(tmp_path: Path, args):
    env = write_env(tmp_path, f"CONFIG_BACKUP_SSH_USER={ACCOUNT}\nCONFIG_BACKUP_SSH_PASSWORD=v1:x\n")
    proc = run(env, *args)
    assert proc.returncode == 2, f"{args} -> {proc.returncode}\n{proc.stdout}{proc.stderr}"


def test_help_exits_zero_and_documents_the_exit_codes():
    proc = subprocess.run([str(SCRIPT), "--help"], capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0
    for code in ("0", "1", "2", "3", "4"):
        assert f"\n  {code}  " in proc.stdout, f"exit code {code} is undocumented"
    assert "device-ssh-credentials.md" in proc.stdout


def test_runbook_names_both_identities_and_the_tool():
    runbook = ROOT / "docs" / "runbooks" / "device-ssh-credentials.md"
    assert runbook.exists(), "the runbook the script points at must exist"
    text = runbook.read_text(encoding="utf-8")
    for name in (
        "CONFIG_BACKUP_SSH_USER", "CONFIG_BACKUP_SSH_PASSWORD", "CONFIG_BACKUP_SSH_KEY",
        "CONFIG_BACKUP_SSH_PORT", "PROTOCOL_DIAG_SSH_USER", "PROTOCOL_DIAG_SSH_PASSWORD",
        "PROTOCOL_DIAG_SSH_KEY", "PROTOCOL_DIAG_SSH_PORT",
        "scripts/check-device-ssh.sh", "/api/devices/{id}/config/status",
    ):
        assert name in text, f"the runbook does not name {name}"
