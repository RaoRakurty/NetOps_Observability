# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""With `sso` active, a missing Keycloak database fails the install (FMEA T2).

On .123 (2026-09-15) Keycloak restarted 106 times on `database "keycloak" does
not exist`. The pre-start creation (ffbb4055) fixed the ordering. The residual:
the post-start confirmation only WARNED, so a run whose database could still
not be created reported success over a crash-looping Keycloak.

Pinned here:
  * bootstrap_keycloak_db reports whether the database exists afterwards;
  * confirm_keycloak_db retries a bounded number of times with backoff, then
    fails naming the database and the manual command;
  * the early pre-start attempt stays non-fatal (it may simply be too early),
    and main() uses the fatal confirmation only after the stack started.

No docker: the bootstrap, runner and sleeps are injected.
Run:  python3 -m pytest tests/test_install_keycloak_confirm.py -v
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import install

ENV = {"DB_USER": "netops", "KEYCLOAK_DB_NAME": "keycloak"}


class Bootstrap:
    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = 0

    def __call__(self, compose_dir, env):
        self.calls += 1
        return self.answers.pop(0)


def test_a_database_that_never_appears_fails_the_install(tmp_path, capsys):
    boot, sleeps = Bootstrap([False, False, False]), []
    with pytest.raises(SystemExit) as exc:
        install.confirm_keycloak_db(tmp_path, ENV, bootstrap=boot, sleep=sleeps.append)
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert boot.calls == 3
    assert "'keycloak' still does not exist after 3 attempts" in err
    assert "createdb -U netops keycloak" in err
    assert "not reported as a success" in err


def test_retries_back_off_and_stay_bounded(tmp_path):
    boot, sleeps = Bootstrap([False, False, False]), []
    with pytest.raises(SystemExit):
        install.confirm_keycloak_db(tmp_path, ENV, bootstrap=boot, sleep=sleeps.append,
                                    base_delay_s=10.0)
    assert len(sleeps) == 2, "no sleep after the last attempt"
    assert 7.5 <= sleeps[0] <= 12.5 and 15.0 <= sleeps[1] <= 25.0


def test_a_database_that_appears_on_retry_is_not_an_error(tmp_path, capsys):
    boot, sleeps = Bootstrap([False, True]), []
    install.confirm_keycloak_db(tmp_path, ENV, bootstrap=boot, sleep=sleeps.append)
    assert boot.calls == 2 and len(sleeps) == 1
    assert "[fail ]" not in capsys.readouterr().err


def test_unsafe_names_are_never_echoed_into_a_command(tmp_path, capsys):
    env = {"DB_USER": "netops; rm -rf /", "KEYCLOAK_DB_NAME": "keycloak"}
    with pytest.raises(SystemExit):
        install.confirm_keycloak_db(tmp_path, env, bootstrap=Bootstrap([False] * 3),
                                    sleep=lambda s: None)
    err = capsys.readouterr().err
    assert "rm -rf" not in err and "KEYCLOAK_DB_NAME" in err


# ── bootstrap_keycloak_db reports the outcome ────────────────────────────────

def _result(rc=0, out=""):
    return types.SimpleNamespace(returncode=rc, stdout=out, stderr="")


def test_bootstrap_reports_an_unreachable_postgres_as_false(tmp_path, monkeypatch):
    monkeypatch.setattr(install, "wait_for_postgres", lambda *a, **k: (False, "refused"))
    assert install.bootstrap_keycloak_db(tmp_path, ENV) is False


def test_bootstrap_reports_an_existing_database_as_true(tmp_path, monkeypatch):
    monkeypatch.setattr(install, "wait_for_postgres", lambda *a, **k: (True, "ready"))
    monkeypatch.setattr(install.ComposeRunner, "exec",
                        lambda self, svc, argv, stdin="", timeout=60: _result(0, "1\n"))
    assert install.bootstrap_keycloak_db(tmp_path, ENV) is True


def test_the_early_pre_start_attempt_stays_non_fatal(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(install.subprocess, "run", lambda *a, **k: _result(1, "no such service"))
    assert install.bootstrap_keycloak_db(tmp_path, ENV, start_postgres=True) is False
    assert "could not start postgres" in capsys.readouterr().err


def test_main_confirms_fatally_only_after_the_stack_started():
    src = (SCRIPTS / "install.py").read_text()
    main_src = src[src.index("def main("):]
    first_up = main_src.index("compose_up(compose_dir")
    early = main_src.index(
        "bootstrap_keycloak_db(compose_dir, _parse_env(env_path), start_postgres=True")
    confirm = main_src.index("confirm_keycloak_db(compose_dir, _parse_env(env_path)")
    assert early < first_up < confirm
    assert "confirm_keycloak_db(" not in main_src[:first_up]
