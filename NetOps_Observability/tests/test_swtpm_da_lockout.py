# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""The secret-custody sidecar must never let the TPM lock its own KEK away.

2026-10-03: a fresh install crash-looped the api on `swtpm unseal: ERR load`.
The software TPM was in dictionary-attack lockout (`0x921`): every stop of a
sidecar that had served an UNSEAL counted as a DA failure, because the stop
was never orderly. `exec socat` replaced the shell, so the trap that should
have stopped swtpm never ran. swtpm locks at 3 failures, and the installer's
own restarts reached that.

Proven against the real image before the fix (counter 1, 2, 3, then `ERR load`
on the 4th boot) and after it: 5 docker stops left the counter at 0; 4 kill -9
crashes were each logged and cleared at the next boot; a state directory
already locked at 3 healed on the first boot of the fixed image. These pins
keep the three properties that proof rests on.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "deployment" / "docker" / "swtpm-sidecar" / "entrypoint.sh"


def _code() -> str:
    """The entrypoint with comment lines removed, so a pin cannot be satisfied
    by prose that merely mentions the command."""
    return "\n".join(line for line in ENTRY.read_text().splitlines()
                     if not line.lstrip().startswith("#"))


def test_shell_stays_pid1_so_the_stop_trap_runs() -> None:
    code = _code()
    assert not re.search(r"^\s*exec\s+socat\b", code, re.M), (
        "`exec socat` replaces the entrypoint shell, so no TERM trap runs and "
        "every docker stop is a non-orderly TPM shutdown (one DA failure each)")
    assert re.search(r"^\s*socat\b.*&\s*$", code, re.M), "socat must run in the background"
    assert re.search(r'^\s*wait\s+"\$SOCAT_PID"', code, re.M), "the shell must wait on socat"


def test_stop_sends_an_orderly_tpm_shutdown_before_stopping_swtpm() -> None:
    code = _code()
    m = re.search(r"^shutdown_tpm\(\)\s*\{(.*?)^\}", code, re.M | re.S)
    assert m, "shutdown_tpm() is gone"
    body = m.group(1)
    shut = body.find("tpm2_shutdown -c")
    kill = body.find('kill "$SWTPM_PID"')
    assert shut != -1, "the stop path must send TPM2_Shutdown(CLEAR)"
    assert kill != -1 and shut < kill, "TPM2_Shutdown must reach swtpm BEFORE swtpm is stopped"
    for sig in ("TERM", "INT", "EXIT"):
        assert re.search(rf"^trap .*shutdown_tpm.*\b{sig}\s*$", code, re.M), (
            f"no {sig} trap runs shutdown_tpm")


def test_boot_clears_a_da_counter_and_refuses_to_serve_while_locked() -> None:
    code = _code()
    clear = code.find("tpm2_dictionarylockout -c")
    ready = code.find("secrets-seal: ready")
    assert clear != -1, "a crash/power loss still costs a DA failure; boot must clear it"
    assert ready != -1 and clear < ready, "the counter must be cleared before the socket is served"
    assert "TPM2_PT_LOCKOUT_COUNTER" in code and "inLockout" in code, (
        "the counter must be read (and logged) before it is cleared")
    after = code[clear:ready]
    assert re.search(r"inLockout\)\"?\s*\"?\s*!=\s*0", after) and "exit 1" in after, (
        "a TPM still locked after the clear must fail boot, not report ready")
