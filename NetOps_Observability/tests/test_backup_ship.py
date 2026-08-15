"""Backup / DR / secret-custody ship contract (wave-2 fixes, 2026-08-14).

Executed-function tests (fake tpm2-tools / rsync / zstd / docker / crontab on
PATH — never grep-only where execution is possible) pinning:

  * seal-handler.sh: the plaintext root KEK NEVER touches a file — it is piped
    base64→tpm2_create via stdin (-i-, verified live against the pinned image,
    tpm2-tools 5.4); SEAL refuses to overwrite an existing sealed KEK
    ("ERR exists", server-side — the 2026-08-04 incident proved the client-side
    guard alone can fail); RESEAL is the explicit operator-only overwrite verb;
    reply grammar stays within what the Go client (secrets_swtpm.go) parses;
  * entrypoint.sh: a stray plaintext kek.bin at boot (pre-fix crash evidence)
    is reported LOUDLY before purge, per the custody-incident discipline;
  * stack-watchdog.sh apply_backup_intent: the #150 loop closure — the GUI's
    stored backup intent is applied host-side when (and only when) the intent
    file is newer than the last-applied stamp; failures are loud problems and
    keep the stamp untouched (retry), success stamps with the intent's mtime;
  * apply-backup-config.sh: strict mode — a failed .env write or crontab
    install exits non-zero and NEVER claims "applied"/"updated";
  * backup.sh: every exit path writes an honest data/api/backup-report.json
    (abort paths included — the GUI must never keep last run's green pill);
    rsync rc=24 on the live data/ tree is an expected warning, not an abort;
    the zstd archive write carries -f (same-day re-run must not abort);
  * restore-drill.sh: writes its report to the exact path the API reads
    (parity-pinned against system_backup.go's RESTORE_DRILL_REPORT default and
    the compose data/api ↔ /data mount) — LastDrillResult can actually appear;
  * every touched script stays `bash -n`/`sh -n` clean and shellcheck-clean
    (restore-drill.sh: no error-severity findings; the rest: fully clean).
"""

import base64
import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
SIDECAR = ROOT / "deployment" / "docker" / "swtpm-sidecar"
SEAL_HANDLER = SIDECAR / "seal-handler.sh"
ENTRYPOINT = SIDECAR / "entrypoint.sh"
WATCHDOG = SCRIPTS / "stack-watchdog.sh"
APPLY = SCRIPTS / "apply-backup-config.sh"
BACKUP = SCRIPTS / "backup.sh"
DRILL = SCRIPTS / "restore-drill.sh"
SYSTEM_BACKUP_GO = ROOT / "src" / "backend" / "system_backup.go"
SWTPM_GO = ROOT / "src" / "backend" / "internal" / "vault" / "secrets_swtpm.go"
COMPOSE = ROOT / "deployment" / "docker" / "docker-compose.yml"


def _write_exec(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


# ---------------------------------------------------------------------------
# seal-handler.sh — executed with fake tpm2-tools on PATH
# ---------------------------------------------------------------------------

def _fake_tpm_bin(tmp_path: Path) -> Path:
    """Fake tpm2-tools that record argv + stdin so the tests can prove what
    crossed the process boundary (and, critically, what never touched disk)."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    _write_exec(bindir / "tpm2_flushcontext", "#!/bin/sh\nexit 0\n")
    _write_exec(bindir / "tpm2_create", (
        "#!/bin/sh\n"
        'printf \'%s\\n\' "$@" > "$TPM2_CREATE_ARGS"\n'
        'cat > "$TPM2_CREATE_STDIN"\n'
        '[ -n "${FAKE_TPM2_CREATE_RC:-}" ] && exit "$FAKE_TPM2_CREATE_RC"\n'
        'while [ $# -gt 0 ]; do\n'
        '  case "$1" in\n'
        '    -u) echo sealed-pub > "$2"; shift 2;;\n'
        '    -r) echo sealed-priv > "$2"; shift 2;;\n'
        '    *) shift;;\n'
        '  esac\n'
        'done\n'
        "exit 0\n"
    ))
    _write_exec(bindir / "tpm2_load", "#!/bin/sh\nexit 0\n")
    _write_exec(bindir / "tpm2_unseal", "#!/bin/sh\nprintf 'unsealed-bytes'\nexit 0\n")
    return bindir


def _run_handler(tmp_path: Path, request_line: str, extra_env=None):
    bindir = _fake_tpm_bin(tmp_path)
    tpmdir = tmp_path / "tpmstate"
    tpmdir.mkdir(exist_ok=True)
    env = os.environ.copy()
    env["PATH"] = f"{bindir}:{env['PATH']}"
    env["TPMDIR"] = str(tpmdir)
    env["TPM2_CREATE_ARGS"] = str(tmp_path / "create.args")
    env["TPM2_CREATE_STDIN"] = str(tmp_path / "create.stdin")
    env.update(extra_env or {})
    r = subprocess.run(
        ["sh", str(SEAL_HANDLER)], input=request_line + "\n",
        env=env, capture_output=True, text=True, timeout=30,
    )
    args_f = tmp_path / "create.args"
    stdin_f = tmp_path / "create.stdin"
    create_args = args_f.read_text().splitlines() if args_f.exists() else None
    create_stdin = stdin_f.read_bytes() if stdin_f.exists() else None
    return r, tpmdir, create_args, create_stdin


KEK = bytes(range(32))
KEK_B64 = base64.b64encode(KEK).decode()


def test_seal_pipes_kek_via_stdin_never_a_file(tmp_path):
    r, tpmdir, args, stdin = _run_handler(tmp_path, f"SEAL {KEK_B64}")
    assert r.stdout.strip() == "OK", r.stderr
    assert args is not None, "tpm2_create was never invoked"
    # The sealing input is stdin ('-i-'), never a path — the pre-fix kek.bin
    # staging left the plaintext root KEK on the persistent host bind mount.
    assert "-i-" in args or ("-i" in args and args[args.index("-i") + 1] == "-"), \
        f"tpm2_create must read the KEK from stdin, got argv: {args}"
    assert not any(a.endswith("kek.bin") for a in args), \
        f"KEK file path in tpm2_create argv: {args}"
    assert stdin == KEK, "the exact decoded KEK must arrive on tpm2_create's stdin"
    # Nothing with plaintext-KEK shape may exist in the state dir, ever.
    leftovers = {p.name for p in tpmdir.iterdir()}
    assert "kek.bin" not in leftovers, f"plaintext KEK staged on disk: {leftovers}"
    assert (tpmdir / "seal.pub").exists() and (tpmdir / "seal.priv").exists()
    assert not (tpmdir / "seal.pub.new").exists() and not (tpmdir / "seal.priv.new").exists(), \
        "temp blob names must be renamed away on success"


def test_seal_refuses_when_sealed_kek_exists(tmp_path):
    tpmdir = tmp_path / "tpmstate"
    tpmdir.mkdir()
    (tpmdir / "seal.priv").write_text("existing-sealed-kek")
    (tpmdir / "seal.pub").write_text("existing-pub")
    r, tpmdir, args, _ = _run_handler(tmp_path, f"SEAL {KEK_B64}")
    assert r.stdout.strip() == "ERR exists", (
        "SEAL over an existing sealed KEK must be refused SERVER-side "
        f"(2026-08-04: the client-side guard alone failed), got: {r.stdout!r}")
    assert args is None, "tpm2_create must not run for a refused SEAL"
    assert (tpmdir / "seal.priv").read_text() == "existing-sealed-kek", \
        "a refused SEAL must not touch the existing blobs"


def test_reseal_overwrites_deliberately(tmp_path):
    tpmdir = tmp_path / "tpmstate"
    tpmdir.mkdir()
    (tpmdir / "seal.priv").write_text("old-priv")
    (tpmdir / "seal.pub").write_text("old-pub")
    r, tpmdir, args, stdin = _run_handler(tmp_path, f"RESEAL {KEK_B64}")
    assert r.stdout.strip() == "OK", r.stderr
    assert stdin == KEK
    assert (tpmdir / "seal.priv").read_text() == "sealed-priv\n", "RESEAL must replace the blobs"
    assert (tpmdir / "seal.pub").read_text() == "sealed-pub\n"


def test_seal_bad_base64_rejected_before_tpm(tmp_path):
    r, tpmdir, args, _ = _run_handler(tmp_path, "SEAL n0t-b@se64!!")
    assert r.stdout.strip() == "ERR b64"
    assert args is None, "malformed base64 must never reach tpm2_create"
    assert not (tpmdir / "seal.priv").exists()


def test_seal_create_failure_leaves_no_partial_blobs(tmp_path):
    r, tpmdir, args, _ = _run_handler(
        tmp_path, f"SEAL {KEK_B64}", extra_env={"FAKE_TPM2_CREATE_RC": "1"})
    assert r.stdout.strip() == "ERR create"
    for name in ("seal.pub", "seal.priv", "seal.pub.new", "seal.priv.new", "kek.bin"):
        assert not (tpmdir / name).exists(), f"failed SEAL left {name} behind"


def test_unseal_first_run_no_kek(tmp_path):
    r, _, _, _ = _run_handler(tmp_path, "UNSEAL")
    assert r.stdout.strip() == "ERR no-kek", \
        "first-run UNSEAL must reply the ONE string the Go client maps to ErrNoKEK"


def test_unknown_verb(tmp_path):
    r, _, _, _ = _run_handler(tmp_path, "BOGUS x")
    assert r.stdout.strip() == "ERR unknown"


def test_reply_grammar_matches_go_client():
    """Parity pin against src/backend/internal/vault/secrets_swtpm.go: the
    handler's replies must stay within the grammar the client parses — 'OK'
    prefix = success, 'ERR no-kek' = the sole ErrNoKEK mapping, any other ERR
    = hard failure (which is exactly how 'ERR exists' must be treated)."""
    go = SWTPM_GO.read_text()
    assert '"ERR no-kek"' in go, "client no longer maps ERR no-kek — grammar drift"
    assert 'strings.HasPrefix(resp, "OK")' in go, "client success check changed"
    sh = SEAL_HANDLER.read_text()
    # Every reply the handler can emit starts with OK or ERR (one line).
    replies = re.findall(r'echo "((?:OK|ERR)[^"]*)"', sh)
    assert replies, "no replies found in seal-handler.sh"
    for rep in replies:
        assert rep.startswith(("OK", "ERR ")), f"reply outside client grammar: {rep!r}"
    assert any(r == "ERR exists" for r in replies), "SEAL exists-guard reply missing"
    # RESEAL is operator-only: the Go client must NOT send it automatically.
    assert "RESEAL" not in go, (
        "the vault client must never send RESEAL — it is an operator-only "
        "key ceremony (see seal-handler.sh header)")
    assert re.search(r"^RESEAL\)", sh, re.M), "RESEAL verb missing from handler"


# ---------------------------------------------------------------------------
# entrypoint.sh — executed with swtpm/tpm2/socat faked
# ---------------------------------------------------------------------------

def _run_entrypoint(tmp_path: Path, stray_kek: bool):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    # swtpm backgrounds; close inherited pipes so the test never hangs on EOF.
    _write_exec(bindir / "swtpm", "#!/bin/sh\nexec sleep 5 >/dev/null 2>&1\n")
    _write_exec(bindir / "tpm2_startup", "#!/bin/sh\nexit 0\n")
    _write_exec(bindir / "tpm2_flushcontext", "#!/bin/sh\nexit 0\n")
    _write_exec(bindir / "tpm2_createprimary", (
        "#!/bin/sh\n"
        'while [ $# -gt 0 ]; do case "$1" in -c) echo ctx > "$2"; shift 2;; *) shift;; esac; done\n'
        "exit 0\n"
    ))
    _write_exec(bindir / "socat", "#!/bin/sh\necho socat-exec-reached\nexit 0\n")
    tpmdir = tmp_path / "tpmstate"
    tpmdir.mkdir(exist_ok=True)
    if stray_kek:
        (tpmdir / "kek.bin").write_bytes(KEK)
        (tpmdir / "seal.pub.new").write_text("stale")
        (tpmdir / "seal.priv.new").write_text("stale")
    env = os.environ.copy()
    env["PATH"] = f"{bindir}:{env['PATH']}"
    env["TPMDIR"] = str(tpmdir)
    env["SEAL_SOCKET"] = str(tmp_path / "run" / "seal.sock")
    r = subprocess.run(["sh", str(ENTRYPOINT)], env=env,
                       capture_output=True, text=True, timeout=60)
    return r, tpmdir


def test_entrypoint_purges_stray_kek_loudly(tmp_path):
    r, tpmdir = _run_entrypoint(tmp_path, stray_kek=True)
    assert r.returncode == 0, r.stderr
    # Custody-incident discipline: evidence is NAMED before it is destroyed.
    assert "SECURITY WARNING" in r.stderr and "kek.bin" in r.stderr, \
        f"stray plaintext KEK must be reported loudly before purge: {r.stderr}"
    assert not (tpmdir / "kek.bin").exists(), "stray kek.bin must be purged at boot"
    assert not (tpmdir / "seal.pub.new").exists() and not (tpmdir / "seal.priv.new").exists(), \
        "stale interrupted-seal temp blobs must be cleaned at boot"
    assert "socat-exec-reached" in r.stdout, "entrypoint must still reach serving"


def test_entrypoint_quiet_when_no_stray_kek(tmp_path):
    r, _ = _run_entrypoint(tmp_path, stray_kek=False)
    assert r.returncode == 0, r.stderr
    assert "SECURITY WARNING" not in r.stderr, "no evidence, no alarm (alert fatigue)"
    assert "socat-exec-reached" in r.stdout


# ---------------------------------------------------------------------------
# stack-watchdog.sh apply_backup_intent — the #150 loop closure, executed
# ---------------------------------------------------------------------------

def _extract_apply_fn() -> str:
    out = subprocess.run(
        ["sed", "-n", "/^apply_backup_intent() {/,/^}/p", str(WATCHDOG)],
        check=True, capture_output=True, text=True).stdout
    assert "apply_backup_intent()" in out, "apply_backup_intent not found in stack-watchdog.sh"
    return out


def _run_apply(tmp_path: Path, intent: bool = True, applier_rc=0,
               applier_missing=False, stamp_mtime=None):
    funcs = _extract_apply_fn()
    intent_f = tmp_path / "system_backup.json"
    if intent and not intent_f.exists():   # keep a caller-seeded intent's mtime
        intent_f.write_text('{"schedule_enabled": true}')
    applier = tmp_path / "apply-backup-config.sh"
    calls = tmp_path / "applier.calls"
    if not applier_missing:
        _write_exec(applier, (
            "#!/bin/sh\n"
            f'echo run >> "{calls}"\n'
            f'[ "{applier_rc}" = "0" ] && echo "apply-backup-config: done." '
            f'|| echo "apply-backup-config: ERROR: crontab update failed" >&2\n'
            f"exit {applier_rc}\n"
        ))
    stamp = tmp_path / ".backup-config.applied"
    if stamp_mtime is not None:
        stamp.write_text("")
        # NANOSECONDS, not float seconds. The script copies the intent's mtime
        # with `touch -r`, which is nanosecond-exact, and compares with `-nt`,
        # which is also nanosecond-exact. Round-tripping through st_mtime (a
        # float in SECONDS) silently truncated the sub-second part, so whenever
        # the intent's mtime had non-zero nanoseconds the stamp landed a hair
        # EARLIER and the "unchanged" case re-applied — a coin-flip failure
        # (3 of 6 identical runs) that had nothing to do with the code.
        os.utime(stamp, ns=(stamp_mtime, stamp_mtime))
    preamble = (
        "problems=()\n"
        f'BACKUP_INTENT="{intent_f}"\nBACKUP_APPLY="{applier}"\nBACKUP_STAMP="{stamp}"\n'
    )
    tail = '\napply_backup_intent\nprintf "PROBLEM:%s\\n" "${problems[@]}"\n'
    r = subprocess.run(["bash", "-c", preamble + funcs + tail],
                       capture_output=True, text=True, timeout=180)
    problems = [l[len("PROBLEM:"):] for l in r.stdout.splitlines()
                if l.startswith("PROBLEM:") and l != "PROBLEM:"]
    ncalls = len(calls.read_text().splitlines()) if calls.exists() else 0
    return r, problems, ncalls, stamp, intent_f


def test_apply_intent_absent_is_quiet_noop(tmp_path):
    r, problems, ncalls, stamp, _ = _run_apply(tmp_path, intent=False)
    assert r.returncode == 0, r.stderr
    assert ncalls == 0 and problems == [] and not stamp.exists()


def test_apply_intent_new_intent_applies_once_and_stamps(tmp_path):
    r, problems, ncalls, stamp, intent_f = _run_apply(tmp_path)
    assert r.returncode == 0, r.stderr
    assert ncalls == 1, "new intent must invoke the applier exactly once"
    assert problems == [], problems
    assert stamp.exists(), "successful apply must write the stamp"
    assert stamp.stat().st_mtime == intent_f.stat().st_mtime, \
        "stamp must carry the intent's own mtime (the -nt discipline)"
    assert "backup intent applied" in r.stdout, "the apply event must be logged"


def test_apply_intent_unchanged_intent_does_not_reapply(tmp_path):
    # Stamp mtime == intent mtime (what a successful apply leaves behind).
    intent_f = tmp_path / "system_backup.json"
    intent_f.write_text('{"schedule_enabled": true}')
    r, problems, ncalls, _, _ = _run_apply(
        tmp_path, stamp_mtime=intent_f.stat().st_mtime_ns)
    assert r.returncode == 0, r.stderr
    assert ncalls == 0, "unchanged intent must not re-run the applier (stamp discipline)"
    assert problems == []
    assert "backup intent applied" not in r.stdout, "quiet steady state (transition-only logging)"


def test_apply_intent_newer_intent_reapplies(tmp_path):
    intent_f = tmp_path / "system_backup.json"
    intent_f.write_text('{"schedule_enabled": true}')
    r, problems, ncalls, _, _ = _run_apply(
        tmp_path, stamp_mtime=intent_f.stat().st_mtime_ns - 60 * 10**9)
    assert r.returncode == 0, r.stderr
    assert ncalls == 1, "an intent newer than the stamp must re-apply"


def test_apply_intent_failure_is_loud_and_keeps_stamp_for_retry(tmp_path):
    r, problems, ncalls, stamp, _ = _run_apply(tmp_path, applier_rc=1)
    assert r.returncode == 0, r.stderr
    assert ncalls == 1
    assert len(problems) == 1 and "FAILED" in problems[0], problems
    assert "crontab update failed" in problems[0], \
        f"the applier's own ERROR line must surface in the problem: {problems}"
    assert not stamp.exists(), \
        "a FAILED apply must not stamp — the next minute must retry"


def test_apply_intent_missing_applier_is_a_problem(tmp_path):
    r, problems, ncalls, _, _ = _run_apply(tmp_path, applier_missing=True)
    assert r.returncode == 0, r.stderr
    assert ncalls == 0
    assert len(problems) == 1 and "NOT enforced" in problems[0], (
        "stored intent with no applier is exactly the silent-non-enforcement "
        f"defect this hook removes — it must be loud: {problems}")


def test_apply_intent_is_bounded_and_wired_into_main_flow():
    text = WATCHDOG.read_text()
    fn = _extract_apply_fn()
    assert re.search(r"timeout\s+120\s+\"\$BACKUP_APPLY\"", fn), \
        "§16.3: the applier must run under a hard timeout"
    assert re.search(r"command -v timeout", fn), \
        "§16.2: probe for `timeout`, degrade to a named skip — never unbounded"
    assert re.search(r"^apply_backup_intent$", text, re.M), \
        "apply_backup_intent is defined but never called by the watchdog run"
    # Packaged installs must be able to repoint everything via the env file.
    for knob in ("BACKUP_INTENT_FILE", "BACKUP_APPLY_SCRIPT", "BACKUP_APPLY_STAMP"):
        assert knob in text, f"missing env override {knob}"


# ---------------------------------------------------------------------------
# apply-backup-config.sh — executed in a throwaway tree with crontab faked
# ---------------------------------------------------------------------------

def _sandboxed_copy(src: Path, dest: Path, bindir: Path) -> None:
    """Copy a script into the scratch tree with the fake-tool bindir prepended
    to its OWN explicit-PATH export. The scripts rightly pin their PATH ahead
    of the inherited one (§16.2 — and install-watchdog treats inherited PATH
    as untrusted), so an env-only PATH cannot intercept; this one-line patch
    is the sanctioned test seam. Everything else is byte-identical."""
    content = src.read_text()
    assert 'export PATH="' in content, f"{src.name} lost its explicit PATH export"
    dest.write_text(content.replace('export PATH="', f'export PATH="{bindir}:', 1))
    dest.chmod(0o755)


def _apply_tree(tmp_path: Path, config: dict, env_writable=True,
                crontab_rc=0, crontab_store=None):
    """Copy the applier into a scratch tree so ROOT-relative paths (.env,
    data/) resolve inside tmp — the test must never touch the real repo,
    and (via _sandboxed_copy) never the real crontab."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (tmp_path / "scripts").mkdir()
    script = tmp_path / "scripts" / "apply-backup-config.sh"
    _sandboxed_copy(APPLY, script, bindir)
    (tmp_path / "deployment" / "docker").mkdir(parents=True)
    env_file = tmp_path / "deployment" / "docker" / ".env"
    env_file.write_text("EXISTING_KEY=1\n")
    if not env_writable:
        env_file.chmod(0o444)
    (tmp_path / "data" / "api").mkdir(parents=True)
    cfg_file = tmp_path / "data" / "api" / "system_backup.json"
    if isinstance(config, str):
        cfg_file.write_text(config)
    else:
        cfg_file.write_text(json.dumps(config))
    store = crontab_store or (tmp_path / "crontab.store")
    _write_exec(bindir / "crontab", (
        "#!/bin/sh\n"
        f'STORE="{store}"\n'
        f'[ "{crontab_rc}" = "0" ] || {{ [ "$1" = "-l" ] || exit {crontab_rc}; }}\n'
        'case "$1" in\n'
        '  -l) [ -f "$STORE" ] && cat "$STORE" || exit 1;;\n'
        '  *) cat "$1" > "$STORE";;\n'
        "esac\n"
    ))
    env = os.environ.copy()
    env["PATH"] = f"{bindir}:{env['PATH']}"
    r = subprocess.run(["bash", str(script)], env=env,
                       capture_output=True, text=True, timeout=60)
    return r, env_file, store


GOOD_CFG = {"remote_url": "rsync://backup-host/correlix/",
            "push_command": "rsync -a", "schedule_enabled": True,
            "schedule_cron": "30 2 * * *", "retain_count": 5}


def test_apply_config_success_writes_env_and_cron_verified(tmp_path):
    r, env_file, store = _apply_tree(tmp_path, GOOD_CFG)
    assert r.returncode == 0, r.stderr
    env_text = env_file.read_text()
    assert "BACKUP_REMOTE=rsync://backup-host/correlix/" in env_text
    assert "BACKUP_KEEP=5" in env_text
    assert "EXISTING_KEY=1" in env_text, "unrelated .env lines must survive"
    cron = store.read_text()
    assert "30 2 * * *" in cron and "correlix-backup (managed" in cron
    assert "applied BACKUP_REMOTE" in r.stdout and "crontab updated" in r.stdout


def test_apply_config_unwritable_env_fails_loud_never_claims_applied(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root ignores file modes")
    r, _, _ = _apply_tree(tmp_path, GOOD_CFG, env_writable=False)
    assert r.returncode != 0, (
        "a failed .env write MUST exit non-zero — the pre-fix script claimed "
        f"success and cron then ran local-only nightly backups (F-55): {r.stdout}")
    assert "ERROR" in r.stderr, r.stderr
    assert "applied BACKUP_REMOTE" not in r.stdout, \
        "must never claim 'applied' for a write that did not land"


def test_apply_config_crontab_failure_fails_loud(tmp_path):
    r, _, _ = _apply_tree(tmp_path, GOOD_CFG, crontab_rc=1)
    assert r.returncode != 0, "a failed crontab install must exit non-zero"
    assert "ERROR" in r.stderr and "NOT applied" in r.stderr, r.stderr
    assert "crontab updated" not in r.stdout


def test_apply_config_corrupt_json_refused(tmp_path):
    r, env_file, _ = _apply_tree(tmp_path, "{not json!!")
    assert r.returncode != 0, "corrupt intent must be refused, not read as all-empty"
    assert "not valid JSON" in r.stderr, r.stderr
    assert "BACKUP_REMOTE" not in env_file.read_text(), \
        "corrupt config must not blank out the .env keys"


def test_apply_config_schedule_disabled_removes_managed_cron(tmp_path):
    store = tmp_path / "crontab.store"
    store.write_text("0 1 * * * /keep/me\n30 2 * * * old-line # correlix-backup (managed by apply-backup-config.sh)\n")
    cfg = dict(GOOD_CFG, schedule_enabled=False)
    r, _, store = _apply_tree(tmp_path, cfg, crontab_store=store)
    assert r.returncode == 0, r.stderr
    cron = store.read_text()
    assert "correlix-backup (managed" not in cron, "managed line must be removed"
    assert "/keep/me" in cron, "foreign crontab lines must survive"


def test_apply_config_schedule_without_remote_refused_f55(tmp_path):
    cfg = dict(GOOD_CFG, remote_url="")
    r, _, _ = _apply_tree(tmp_path, cfg)
    assert r.returncode != 0
    assert "F-55" in r.stderr


# ---------------------------------------------------------------------------
# backup.sh — abort paths write honest reports (executed in a scratch tree)
# ---------------------------------------------------------------------------

def _backup_tree(tmp_path: Path, rsync_data_rc=0, zstd_rc=0):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (tmp_path / "scripts").mkdir()
    script = tmp_path / "scripts" / "backup.sh"
    _sandboxed_copy(BACKUP, script, bindir)
    (tmp_path / "deployment" / "docker").mkdir(parents=True)
    (tmp_path / "deployment" / "docker" / ".env").write_text("BACKUP_KEEP=3\n")
    (tmp_path / "data" / "api").mkdir(parents=True)
    (tmp_path / "data" / "somestore").mkdir()
    (tmp_path / "data" / "somestore" / "f.txt").write_text("payload")
    (tmp_path / "src" / "config").mkdir(parents=True)
    (tmp_path / "src" / "config" / "rules.yaml").write_text("x: 1\n")
    # docker compose ps → no services running (all store dumps SKIP).
    _write_exec(bindir / "docker", "#!/bin/sh\nexit 0\n")
    _write_exec(bindir / "rsync", (
        "#!/bin/sh\n"
        'while [ $# -gt 2 ]; do shift; done\n'
        'src="$1"; dest="$2"\n'
        'mkdir -p "$dest" 2>/dev/null\n'
        'cp -a "$src"/. "$dest"/ 2>/dev/null\n'
        f'case "$src" in */data/) exit {rsync_data_rc};; esac\n'
        "exit 0\n"
    ))
    _write_exec(bindir / "zstd", (
        "#!/bin/sh\n"
        'printf \'%s\\n\' "$@" >> "$ZSTD_ARGS"\n'
        f'[ "{zstd_rc}" = "0" ] || exit {zstd_rc}\n'
        "out=\n"
        'while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; *) shift;; esac; done\n'
        '[ -n "$out" ] && { cat > /dev/null; echo fake-archive > "$out"; }\n'
        "exit 0\n"
    ))
    out_dir = tmp_path / "data" / "backups"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "correlix-20260814.tar.zst"
    env = os.environ.copy()
    env["PATH"] = f"{bindir}:{env['PATH']}"
    env["ZSTD_ARGS"] = str(tmp_path / "zstd.args")
    r = subprocess.run(["bash", str(script), str(out)], env=env,
                       capture_output=True, text=True, timeout=120)
    report_f = tmp_path / "data" / "api" / "backup-report.json"
    report = json.loads(report_f.read_text()) if report_f.exists() else None
    zargs = (tmp_path / "zstd.args").read_text().split() if (tmp_path / "zstd.args").exists() else []
    return r, report, out, zargs


def test_backup_rsync_vanished_files_rc24_is_expected_not_abort(tmp_path):
    r, report, out, _ = _backup_tree(tmp_path, rsync_data_rc=24)
    assert r.returncode == 0, (
        "rsync rc=24 (files vanished from the LIVE data/ tree mid-copy) is the "
        f"expected condition on a running stack, never an abort: {r.stderr}")
    assert out.exists(), "the archive must still be produced"
    assert report is not None and report["status"] == "success", report


def test_backup_rsync_real_error_rc23_fails_with_honest_report(tmp_path):
    r, report, _, _ = _backup_tree(tmp_path, rsync_data_rc=23)
    assert r.returncode != 0, "rc=23 (partial transfer from real errors) must fail the run"
    assert report is not None, "a failed run must still write its report"
    assert report["status"] == "failed" and report["failures"] >= 1, report


def test_backup_zstd_abort_still_writes_failed_report(tmp_path):
    r, report, _, _ = _backup_tree(tmp_path, zstd_rc=1)
    assert r.returncode != 0
    assert report is not None, (
        "an abort in the tar+zstd pipeline must write a status=failed report — "
        "the pre-fix behavior left the PREVIOUS run's green pill as GUI truth")
    assert report["status"] == "failed", report
    assert "tar+zstd" in report.get("reason", ""), \
        f"the report must name the aborted step: {report}"


def test_backup_zstd_invocation_carries_force_overwrite(tmp_path):
    r, report, _, zargs = _backup_tree(tmp_path)
    assert r.returncode == 0, r.stderr
    assert "-f" in zargs, (
        "zstd must run with -f: the cron reuses correlix-YYYYMMDD.tar.zst, so "
        "a same-day retry aborted on zstd's overwrite refusal before the fix")
    assert report is not None and report["status"] == "success"
    assert report["artifact"] == "correlix-20260814.tar.zst"


# ---------------------------------------------------------------------------
# report-path parity: the scripts must write where the API reads
# ---------------------------------------------------------------------------

def _go_default(env_key: str) -> str:
    m = re.search(rf'envOr\("{env_key}",\s*"([^"]+)"\)', SYSTEM_BACKUP_GO.read_text())
    assert m, f"system_backup.go no longer reads {env_key} — update these pins"
    return m.group(1)


def test_api_data_mount_is_data_api():
    """The api container's /data is host data/api — the mapping every
    host-side report path below depends on."""
    assert re.search(r"^\s*-\s*\.\./\.\./data/api:/data\s*$", COMPOSE.read_text(), re.M), \
        "docker-compose.yml no longer mounts ../../data/api at /data for the api"


def test_drill_report_path_matches_api_reader():
    container_path = _go_default("RESTORE_DRILL_REPORT")
    assert container_path == "/data/restore-drill.report.json"
    sh = DRILL.read_text()
    m = re.search(r'REPORT="\$\{RESTORE_DRILL_REPORT:-([^}]+)\}"', sh)
    assert m, "restore-drill.sh REPORT default not found"
    default = m.group(1)
    assert default == "$ROOT/data/api/restore-drill.report.json", (
        f"restore-drill.sh writes {default!r} but the api reads host "
        f"data/api{os.path.basename(container_path)} via its /data mount — "
        "LastDrillResult would never appear (the pre-fix defect)")
    assert Path(container_path).name == Path(default).name


def test_backup_report_path_matches_api_reader():
    container_path = _go_default("BACKUP_REPORT")
    assert container_path == "/data/backup-report.json"
    sh = BACKUP.read_text()
    assert 'rdir="$DATA_DIR/api"' in sh, "backup.sh report dir moved"
    assert 'backup-report.json' in sh


def test_drill_report_env_override_and_writer_work(tmp_path):
    """Executed: the drill honors RESTORE_DRILL_REPORT and its report writer
    produces valid JSON with the fields system_backup.go decodes (result,
    ended). Store legs are skipped via an unknown store name; docker is faked
    so the cleanup trap cannot touch anything real."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    _write_exec(bindir / "docker", "#!/bin/sh\nexit 0\n")
    report = tmp_path / "drill-report.json"
    env = os.environ.copy()
    env["PATH"] = f"{bindir}:{env['PATH']}"
    env["RESTORE_DRILL_REPORT"] = str(report)
    r = subprocess.run(["bash", str(DRILL), "--quiet", "--stores", "none"],
                       env=env, capture_output=True, text=True, timeout=60)
    assert report.exists(), f"drill must write its report: {r.stderr}"
    rep = json.loads(report.read_text())
    assert {"result", "ended", "drill_id"} <= set(rep), rep
    assert rep["result"] in ("pass", "fail")


# ---------------------------------------------------------------------------
# H4/H5/M26 (2026-08-15): custody exclusion, artifact signature, no backup
# nesting, private permissions — REAL rsync + tar + zstd over a temp tree.
#
# The earlier _backup_tree harness fakes rsync/zstd, which is exactly the
# fake that would have hidden these findings: a fake rsync ignores --exclude
# and a fake zstd writes no real archive to list members of. Only `docker` is
# faked here (services "not running" → store dumps SKIP); the archive is
# produced and inspected with the real tools.
# ---------------------------------------------------------------------------

RESTORE = SCRIPTS / "restore.sh"
SIGN_KEY = "test-sign-key-0123456789"


def _real_backup_tree(tmp_path: Path, sign_key=SIGN_KEY):
    tmp_path.mkdir(parents=True, exist_ok=True)  # callers pass sub-trees too
    bindir = tmp_path / "bin"
    bindir.mkdir()
    _write_exec(bindir / "docker", "#!/bin/sh\nexit 0\n")
    (tmp_path / "scripts").mkdir()
    script = tmp_path / "scripts" / "backup.sh"
    _sandboxed_copy(BACKUP, script, bindir)

    (tmp_path / "deployment" / "docker").mkdir(parents=True)
    env_lines = "DB_PASSWORD=super-secret\nBACKUP_KEEP=3\n"
    if sign_key:
        env_lines += f"BACKUP_SIGN_KEY={sign_key}\n"
    (tmp_path / "deployment" / "docker" / ".env").write_text(env_lines)

    data = tmp_path / "data"
    (data / "swtpm").mkdir(parents=True)
    (data / "swtpm" / "tpm2-00.permall").write_bytes(b"KEK-MATERIAL")
    (data / "secrets-seal").mkdir()
    (data / "secrets-seal" / "seal.priv").write_bytes(b"SEALED-KEK")
    (data / "api").mkdir()
    (data / "api" / "secrets_wrapped_keys.json").write_text('{"dek":"wrapped"}')
    (data / "postgres").mkdir()
    (data / "postgres" / "pg.dat").write_text("rows")
    (data / "backups").mkdir()
    (data / "backups" / "correlix-old.tar.zst").write_bytes(b"YESTERDAYS-ARCHIVE")
    (data / "restore-staging").mkdir()
    (data / "restore-staging" / "postgres.sql").write_text("old dump")
    (tmp_path / "src" / "config").mkdir(parents=True)
    (tmp_path / "src" / "config" / "rules.yaml").write_text("x: 1\n")

    out = data / "backups" / "correlix-20260815.tar.zst"
    env = os.environ.copy()
    env["PATH"] = f"{bindir}:{env['PATH']}"
    r = subprocess.run(["bash", str(script), str(out)], env=env,
                       capture_output=True, text=True, timeout=300)
    return r, out, tmp_path


def _members(out: Path) -> list[str]:
    zs = subprocess.run(["zstd", "-dc", str(out)], capture_output=True, timeout=120)
    assert zs.returncode == 0, zs.stderr
    tr = subprocess.run(["tar", "-tf", "-"], input=zs.stdout,
                        capture_output=True, timeout=120)
    assert tr.returncode == 0, tr.stderr
    return tr.stdout.decode().splitlines()


def _member_bytes(out: Path, name: str) -> bytes:
    zs = subprocess.run(["zstd", "-dc", str(out)], capture_output=True, timeout=120)
    tr = subprocess.run(["tar", "-xO", name], input=zs.stdout,
                        capture_output=True, timeout=120)
    assert tr.returncode == 0, tr.stderr.decode()
    return tr.stdout


def _hmac(path: Path, key: str) -> str:
    import hashlib
    import hmac as hmac_mod
    return hmac_mod.new(key.encode(), path.read_bytes(), hashlib.sha256).hexdigest()


def test_h4_h5_archive_excludes_custody_root_and_nested_backups(tmp_path):
    r, out, _ = _real_backup_tree(tmp_path)
    assert r.returncode == 0, f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    members = _members(out)
    joined = "\n".join(members)
    for forbidden in ("./data/swtpm", "./data/secrets-seal",
                      "./data/backups", "./data/restore-staging"):
        assert not any(m.startswith(forbidden) for m in members), (
            f"{forbidden} must never ship in the archive (H4 custody / H5 "
            f"nesting):\n{joined}")
    # H5 explicitly: yesterday's artifact is NOT inside today's.
    assert "correlix-old.tar.zst" not in joined,         "previous backups nested inside the new archive — exponential growth"
    # Wrapped DEKs are ciphertext without the KEK and MUST still ship, as must
    # the ordinary stores and the manifest.
    assert "./data/api/secrets_wrapped_keys.json" in members, joined
    assert "./data/postgres/pg.dat" in members, joined
    assert "./MANIFEST" in members, joined
    assert "./env.backup" in members, joined


def test_h4_env_backup_never_carries_the_sign_key(tmp_path):
    r, out, _ = _real_backup_tree(tmp_path)
    assert r.returncode == 0, r.stderr
    env_backup = _member_bytes(out, "./env.backup").decode()
    assert "BACKUP_SIGN_KEY" not in env_backup, (
        "the archive must not carry the key that authenticates it")
    assert "DB_PASSWORD=super-secret" in env_backup,         "every other .env line must survive the strip"


def test_h4_artifact_signature_sha256_and_hmac(tmp_path):
    r, out, _ = _real_backup_tree(tmp_path)
    assert r.returncode == 0, r.stderr
    sig = Path(str(out) + ".sig")
    assert sig.exists(), "backup.sh must write the signature sidecar"
    lines = dict(ln.split(" ", 1) for ln in sig.read_text().splitlines())
    import hashlib
    assert lines["sha256"] == hashlib.sha256(out.read_bytes()).hexdigest()
    assert lines["hmac-sha256"] == _hmac(out, SIGN_KEY),         "the HMAC must be keyed with BACKUP_SIGN_KEY over the artifact bytes"
    # --verify accepts its own artifact...
    env = os.environ.copy()
    env["PATH"] = f"{tmp_path / 'bin'}:{env['PATH']}"
    v = subprocess.run(["bash", str(tmp_path / "scripts" / "backup.sh"),
                        "--verify", str(out)], env=env,
                       capture_output=True, text=True, timeout=120)
    assert v.returncode == 0, f"--verify must pass a clean artifact: {v.stdout}{v.stderr}"
    # ...and rejects it once a byte changes.
    with open(out, "ab") as f:
        f.write(b"X")
    v2 = subprocess.run(["bash", str(tmp_path / "scripts" / "backup.sh"),
                         "--verify", str(out)], env=env,
                        capture_output=True, text=True, timeout=120)
    assert v2.returncode != 0 and "sha256 mismatch" in v2.stderr,         f"--verify must reject a modified artifact: {v2.stdout}{v2.stderr}"


def test_h4_unsigned_run_warns_and_writes_sha_only_sidecar(tmp_path):
    r, out, _ = _real_backup_tree(tmp_path, sign_key=None)
    assert r.returncode == 0, r.stderr
    assert "BACKUP_SIGN_KEY unset" in r.stderr,         "an unauthenticated artifact must be a LOUD warning, never a silent default"
    sig = Path(str(out) + ".sig").read_text()
    assert sig.startswith("sha256 ") and "hmac-sha256" not in sig


def test_m26_artifact_sidecar_and_dir_are_private(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root ignores file modes")
    r, out, _ = _real_backup_tree(tmp_path)
    assert r.returncode == 0, r.stderr
    assert stat.S_IMODE(out.stat().st_mode) == 0o600, oct(out.stat().st_mode)
    sig = Path(str(out) + ".sig")
    assert stat.S_IMODE(sig.stat().st_mode) == 0o600, oct(sig.stat().st_mode)
    assert stat.S_IMODE(out.parent.stat().st_mode) == 0o700,         f"backup dir must be 0700, got {oct(out.parent.stat().st_mode)}"


# ---------------------------------------------------------------------------
# restore.sh — the verification gate + custody-preserving restore
# ---------------------------------------------------------------------------

def _restore_tree(tmp_path: Path, archive: Path, sig: Path | None,
                  env_key=SIGN_KEY, force=False):
    """A separate 'target host' tree; only real tools run (restore.sh needs no
    docker). The live tree carries custody material and old backups that a
    correct restore must never touch."""
    host = tmp_path / "host"
    # exist_ok: some tests run two restore attempts against the same host tree
    (host / "scripts").mkdir(parents=True, exist_ok=True)
    script = host / "scripts" / "restore.sh"
    bindir = tmp_path / "host-bin"
    bindir.mkdir(exist_ok=True)
    _sandboxed_copy(RESTORE, script, bindir)
    (host / "deployment" / "docker").mkdir(parents=True, exist_ok=True)
    (host / "src" / "config").mkdir(parents=True, exist_ok=True)
    env_lines = "OLD_HOST_KEY=1\n"
    if env_key:
        env_lines += f"BACKUP_SIGN_KEY={env_key}\n"
    (host / "deployment" / "docker" / ".env").write_text(env_lines)
    data = host / "data"
    (data / "swtpm").mkdir(parents=True, exist_ok=True)
    (data / "swtpm" / "live-kek").write_bytes(b"LIVE-KEK")
    (data / "secrets-seal").mkdir(exist_ok=True)
    (data / "secrets-seal" / "seal.priv").write_bytes(b"LIVE-SEAL")
    (data / "backups").mkdir(exist_ok=True)
    (data / "backups" / "keepme.tar.zst").write_bytes(b"EXISTING")
    inbox = tmp_path / "inbox"
    inbox.mkdir(exist_ok=True)
    arc = inbox / archive.name
    shutil.copy(archive, arc)
    if sig is not None:
        shutil.copy(sig, Path(str(arc) + ".sig"))
    env = os.environ.copy()
    env["PATH"] = f"{bindir}:{env['PATH']}"
    if force:
        env["RESTORE_FORCE"] = "1"
    r = subprocess.run(["bash", str(script), str(arc)], env=env,
                       capture_output=True, text=True, timeout=300)
    return r, host, arc


@pytest.fixture()
def signed_archive(tmp_path):
    r, out, _ = _real_backup_tree(tmp_path / "src-host")
    assert r.returncode == 0, r.stderr
    return out, Path(str(out) + ".sig")


def test_h4_restore_refuses_unsigned_artifact(tmp_path, signed_archive):
    out, _ = signed_archive
    r, host, _ = _restore_tree(tmp_path, out, sig=None)
    assert r.returncode != 0, "an artifact without a sidecar must be refused"
    assert "no signature sidecar" in r.stderr, r.stderr
    assert (host / "data" / "swtpm" / "live-kek").exists(),         "a refused restore must not have touched data/"


def test_h4_restore_refuses_tampered_artifact(tmp_path, signed_archive):
    out, sig = signed_archive
    tampered = tmp_path / "tampered.tar.zst"
    tampered.write_bytes(out.read_bytes() + b"EVIL")
    tsig = Path(str(tampered) + ".sig")
    shutil.copy(sig, tsig)
    r, host, _ = _restore_tree(tmp_path, tampered, sig=tsig)
    assert r.returncode != 0
    assert "sha256 mismatch" in r.stderr, r.stderr
    # sha mismatch has NO force override
    r2, _, _ = _restore_tree(tmp_path, tampered, sig=tsig, force=True)
    assert r2.returncode != 0, "RESTORE_FORCE must never override a hash mismatch"


def test_h4_restore_refuses_wrong_key(tmp_path, signed_archive):
    out, sig = signed_archive
    r, _, _ = _restore_tree(tmp_path, out, sig=sig, env_key="a-different-key-000")
    assert r.returncode != 0
    assert "HMAC mismatch" in r.stderr, r.stderr


def test_h4_restore_refuses_macless_sidecar_when_key_is_held(tmp_path, signed_archive):
    out, sig = signed_archive
    stripped = tmp_path / "stripped.sig"
    stripped.write_text("".join(
        ln for ln in sig.read_text().splitlines(keepends=True)
        if not ln.startswith("hmac-sha256")))
    r, _, _ = _restore_tree(tmp_path, out, sig=stripped)
    assert r.returncode != 0,         "a stripped MAC while we hold the key is a downgrade — refuse (H4)"
    assert "downgrade" in r.stderr, r.stderr


def test_h4_h5_restore_good_archive_preserves_custody_and_backups(tmp_path, signed_archive):
    out, sig = signed_archive
    r, host, _ = _restore_tree(tmp_path, out, sig=sig)
    assert r.returncode == 0, f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    assert "signature OK" in r.stdout
    # the restore delivered the payload...
    assert (host / "data" / "postgres" / "pg.dat").exists()
    # ...but --delete NEVER removed the live custody root or existing backups
    # the archive (correctly) does not contain.
    assert (host / "data" / "swtpm" / "live-kek").exists(),         "restore --delete destroyed the live KEK — the matching-excludes guard failed"
    assert (host / "data" / "secrets-seal" / "seal.priv").exists()
    assert (host / "data" / "backups" / "keepme.tar.zst").exists()
    # the live host's sign key survives the .env swap (env.backup is stripped)
    env_text = (host / "deployment" / "docker" / ".env").read_text()
    assert f"BACKUP_SIGN_KEY={SIGN_KEY}" in env_text,         "the restored .env must carry the live host's sign key forward"
    assert "DB_PASSWORD=super-secret" in env_text


def test_h5_prune_removes_signature_sidecar_with_artifact(tmp_path):
    d = tmp_path / "backups"
    d.mkdir()
    import time
    now = time.time()
    for i in range(4):
        f = d / f"correlix-2026081{i}.tar.zst"
        f.write_bytes(b"x")
        Path(str(f) + ".sig").write_text("sha256 aa\n")
        os.utime(f, (now - (4 - i) * 86400, now - (4 - i) * 86400))
    env = os.environ.copy()
    env["BACKUP_KEEP"] = "2"
    r = subprocess.run(["bash", str(BACKUP), "--prune", str(d)], env=env,
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    left = sorted(x.name for x in d.iterdir())
    assert left == ["correlix-20260812.tar.zst", "correlix-20260812.tar.zst.sig",
                    "correlix-20260813.tar.zst", "correlix-20260813.tar.zst.sig"], (
        f"pruned artifacts must take their sidecars with them: {left}")


# ---------------------------------------------------------------------------
# M26 — install.py private writes + gitignore coverage
# ---------------------------------------------------------------------------

def test_m26_env_backups_are_gitignored():
    """.env.rotate.bak (secret rotation) and .env.plan.bak (replan) carry the
    full pre-rotation secret set; deployment/docker/.env* must cover them."""
    for name in (".env", ".env.rotate.bak", ".env.plan.bak"):
        r = subprocess.run(
            ["git", "check-ignore", "-q", f"deployment/docker/{name}"],
            cwd=ROOT, capture_output=True, text=True)
        assert r.returncode == 0, f"deployment/docker/{name} is NOT gitignored"


def test_m26_install_write_private_no_world_readable_window(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root ignores file modes")
    import sys
    sys.path.insert(0, str(SCRIPTS))
    import install
    old_umask = os.umask(0o022)  # the hostile default the fix exists for
    try:
        target = tmp_path / ".env"
        install._write_private(target, "SECRET=1\n")
        assert stat.S_IMODE(target.stat().st_mode) == 0o600, oct(target.stat().st_mode)
        assert target.read_text() == "SECRET=1\n"
        # overwrite of a pre-existing world-readable file ends 0600 too
        loose = tmp_path / "loose.env"
        loose.write_text("OLD=1\n")
        loose.chmod(0o644)
        install._write_private(loose, "NEW=1\n")
        assert stat.S_IMODE(loose.stat().st_mode) == 0o600
        assert loose.read_text() == "NEW=1\n"
        leftovers = [x.name for x in tmp_path.iterdir() if x.name.endswith(".tmp")]
        assert leftovers == [], f"temp files left behind: {leftovers}"
    finally:
        os.umask(old_umask)


def test_m26_write_env_lands_0600_under_hostile_umask(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root ignores file modes")
    import sys
    sys.path.insert(0, str(SCRIPTS))
    import install
    env_path = tmp_path / ".env"
    old_umask = os.umask(0o022)
    try:
        install.write_env(env_path, 8000, force=True)
    finally:
        os.umask(old_umask)
    assert stat.S_IMODE(env_path.stat().st_mode) == 0o600, oct(env_path.stat().st_mode)
    assert "ADMIN_INITIAL_PASSWORD" in env_path.read_text()


# ---------------------------------------------------------------------------
# hygiene gates: every touched script parses and stays shellcheck-clean
# ---------------------------------------------------------------------------

BASH_SCRIPTS = [WATCHDOG, APPLY, BACKUP, DRILL, RESTORE,
                SCRIPTS / "install-watchdog.sh"]
SH_SCRIPTS = [SEAL_HANDLER, ENTRYPOINT]


def test_touched_scripts_parse():
    for s in BASH_SCRIPTS:
        r = subprocess.run(["bash", "-n", str(s)], capture_output=True, text=True)
        assert r.returncode == 0, f"bash -n {s.name}: {r.stderr}"
    for s in SH_SCRIPTS:
        r = subprocess.run(["sh", "-n", str(s)], capture_output=True, text=True)
        assert r.returncode == 0, f"sh -n {s.name}: {r.stderr}"


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck not installed")
def test_touched_scripts_shellcheck_clean():
    for s in [WATCHDOG, APPLY, BACKUP, RESTORE, SCRIPTS / "install-watchdog.sh",
              SEAL_HANDLER, ENTRYPOINT]:
        r = subprocess.run(["shellcheck", str(s)], capture_output=True, text=True)
        assert r.returncode == 0, f"shellcheck {s.name}:\n{r.stdout}{r.stderr}"
    # restore-drill.sh carries pre-existing info/warning findings (out of this
    # change's bounded context); hold the line at zero ERROR-severity findings.
    r = subprocess.run(["shellcheck", "--severity=error", str(DRILL)],
                       capture_output=True, text=True)
    assert r.returncode == 0, f"shellcheck -Serror restore-drill.sh:\n{r.stdout}{r.stderr}"
