# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix
"""Guard: every service that holds a mesh SVID has a renewal path (tracker 351).

WHY THIS EXISTS. The api re-mints every SVID on disk at ~TTL/2, but a process
that loads its certificate once at start keeps the old copy until something
reloads or restarts it. On 2026-10-14 vmalert's start-loaded client SVID
expired and alert delivery was dead for three days: vmalert was in NO renewal
path — not self-reloading, not in the sweep's hot-reload legs, not in its
restart class. The api's and the prober's own client SVIDs had the same gap
(a reloader nobody watched). The sweep itself only ever ran as a hand-installed
lab cron.

This file makes the gap structural instead of a thing someone has to notice:
  * every compose service that mounts an SVID (anything under data/tls other
    than the CA bundle alone) must be in exactly one renewal class;
  * the classes are tied to the code/script that implements them, so moving a
    service between classes without implementing it fails here;
  * the installer schedules the sweep (idempotently, preserving the user's own
    crontab lines) and removes it on uninstall;
  * the watchdog reads the sweep heartbeat where the installer's sweep writes it.
"""
from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
DOCKER = ROOT / "deployment" / "docker"
SCRIPTS = ROOT / "scripts"
SWEEP = SCRIPTS / "rotate-tls-services.sh"
INSTALLER = SCRIPTS / "install-correlix.sh"
RELOAD_GO = ROOT / "src" / "backend" / "tlsconfig" / "reload.go"

# Renew on their own: our Go binary (CertReloader re-checks on use — the api
# and the prober run it) and VictoriaMetrics (vmauth/victoria re-read cert files;
# proven live: victoria's mTLS scrapes stayed up across re-mints since 2026-10-10).
SELF_RENEWING = {"api", "prober", "vmauth", "victoria"}
# Reloaded in place by the sweep's phase 1 (no restart).
HOT_RELOAD = {"kafka", "postgres", "clickhouse", "nginx", "redis"}
# Run once at boot/bootstrap; they hold nothing afterwards.
ONE_SHOT = {"kafka-init", "opensearch-init", "opensearch-security-init", "gotenberg-tls-init"}
# The sweep's dedicated re-stage + restart leg (optional pdf profile).
SPECIAL = {"gotenberg"}


class _Loader(yaml.SafeLoader):
    pass


def _passthrough(loader: yaml.SafeLoader, _suffix: str, node: yaml.Node):
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return loader.construct_scalar(node)


_Loader.add_multi_constructor("!", _passthrough)


def _svid_holders() -> dict[str, list[str]]:
    """service -> its data/tls mounts, for mounts that carry more than the CA."""
    out: dict[str, list[str]] = {}
    for name in ("docker-compose.yml", "compose.tls.yml", "compose.agg.yml"):
        doc = yaml.load((DOCKER / name).read_text(encoding="utf-8"), Loader=_Loader) or {}
        for svc, spec in (doc.get("services") or {}).items():
            for v in (spec or {}).get("volumes") or []:
                src = v if isinstance(v, str) else (v.get("source") or "")
                src = src.split(":", 1)[0]
                if "data/tls" not in src or src.endswith("ca.pem"):
                    continue
                out.setdefault(svc, []).append(src)
    return out


def _restart_class() -> set[str]:
    m = re.search(r'^RESTART_CLASS="([^"]+)"', SWEEP.read_text(encoding="utf-8"), re.MULTILINE)
    assert m, "RESTART_CLASS= assignment not found in rotate-tls-services.sh — the guard is blind"
    return set(m.group(1).split())


def test_discovery_is_not_vacuous() -> None:
    holders = _svid_holders()
    assert {"api", "vmalert", "kafka", "correlation"} <= set(holders), holders


def test_every_svid_holder_has_a_renewal_path() -> None:
    restart = _restart_class()
    covered = SELF_RENEWING | HOT_RELOAD | ONE_SHOT | SPECIAL | restart
    missing = sorted(set(_svid_holders()) - covered)
    assert not missing, (
        f"{missing} mount a mesh SVID but nothing renews it in the running process — "
        "it will present an expired cert one TTL (7 days) after its last restart. Make it "
        "self-reloading, add a hot-reload leg, or add it to RESTART_CLASS in "
        "scripts/rotate-tls-services.sh (tracker 351)")


def test_classes_do_not_overlap() -> None:
    restart = _restart_class()
    classes = {"SELF_RENEWING": SELF_RENEWING, "HOT_RELOAD": HOT_RELOAD,
               "ONE_SHOT": ONE_SHOT, "SPECIAL": SPECIAL, "RESTART_CLASS": restart}
    seen: dict[str, str] = {}
    for cname, members in classes.items():
        for m in members:
            assert m not in seen, f"{m} is in both {seen[m]} and {cname}"
            seen[m] = cname


def test_vmalert_and_cloud_ingest_are_restart_class() -> None:
    """The two services the 2026-10-24 audit found with no renewal path."""
    assert {"vmalert", "cloud-ingest"} <= _restart_class()


def test_hot_reload_legs_exist_in_the_sweep() -> None:
    body = SWEEP.read_text(encoding="utf-8")
    for svc in HOT_RELOAD:
        assert re.search(rf'log "{re.escape(svc)}[ :(]', body), f"no phase-1 reload leg for {svc} in the sweep"


def test_go_reloader_renews_on_use() -> None:
    """SELF_RENEWING api/prober rests on CertReloader re-checking on every use."""
    src = RELOAD_GO.read_text(encoding="utf-8")
    body = src[src.index("func (r *CertReloader) current()"):]
    body = body[: body.index("\n}\n")]
    assert "r.maybeReload()" in body, "CertReloader.current() no longer re-checks the files on use"


def test_served_cert_probe_does_not_depend_on_correlation() -> None:
    """Tracker 311/352: correlation ships no openssl, so every check read 0."""
    body = SWEEP.read_text(encoding="utf-8")
    fn = body[body.index("served_end() {"):]
    fn = fn[: fn.index("\n}\n")]
    assert "exec -T correlation" not in fn
    assert "probe_svc" in fn


# ---------------------------------------------------------------------------
# Installer-managed crontab entry.
# ---------------------------------------------------------------------------

def _functions(path: Path, names: list[str]) -> str:
    out = subprocess.run(
        ["sed", "-n", ";".join(f"/^{n}()/,/^}}/p" for n in names), str(path)],
        capture_output=True, text=True, timeout=30, check=True).stdout
    for n in names:
        assert f"{n}()" in out, f"{n} not found in {path.name}"
    return out


FAKE_CRONTAB = """#!/bin/sh
# Minimal crontab(1): -l prints the table or "no crontab for", - reads stdin,
# -r removes. State lives in $CRONTAB_STATE.
case "$1" in
  -l) if [ -f "$CRONTAB_STATE" ]; then cat "$CRONTAB_STATE"; else echo "no crontab for tester" >&2; exit 1; fi ;;
  -)  cat > "$CRONTAB_STATE" ;;
  -r) if [ -f "$CRONTAB_STATE" ]; then rm -f "$CRONTAB_STATE"; else echo "no crontab for tester" >&2; exit 1; fi ;;
  *)  echo "fake crontab: unsupported $*" >&2; exit 2 ;;
esac
"""


@pytest.fixture
def cron_env(tmp_path: Path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "crontab"
    fake.write_text(FAKE_CRONTAB)
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    state = tmp_path / "crontab.state"
    script = (
        'TLS_CRON_MARK="# correlix-tls-rotate (managed by install-correlix.sh)"\n'
        'ROOT=/opt/correlix/NetOps_Observability\n'
        'warn() { echo "WARN $*" >&2; }\nok() { echo "OK $*"; }\n'
        'tls_active() { [ "${TEST_TLS:-1}" = 1 ]; }\n'
        + _functions(INSTALLER, ["crontab_without_mark", "install_tls_rotation_cron",
                                 "remove_tls_rotation_cron"]))
    env = {"PATH": f"{bindir}:/usr/bin:/bin", "CRONTAB_STATE": str(state)}

    def run(call: str, **extra: str) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", "-c", "set -euo pipefail\n" + script + call],
                              capture_output=True, text=True, timeout=30,
                              env={**env, **extra})
    return run, state


def _ours(table: str) -> list[str]:
    return [line for line in table.splitlines() if "correlix-tls-rotate" in line]


def test_install_schedules_the_sweep_once_and_keeps_user_lines(cron_env) -> None:
    run, state = cron_env
    state.write_text("0 1 * * * /home/u/own-job.sh\n")
    for _ in range(2):  # idempotent: a re-install/upgrade must not duplicate it
        r = run("install_tls_rotation_cron\n")
        assert r.returncode == 0, r.stderr
    table = state.read_text()
    assert "/home/u/own-job.sh" in table
    ours = _ours(table)
    assert len(ours) == 1, table
    assert "/opt/correlix/NetOps_Observability/scripts/rotate-tls-services.sh" in ours[0]


def test_install_on_empty_crontab(cron_env) -> None:
    run, state = cron_env
    r = run("install_tls_rotation_cron\n")
    assert r.returncode == 0, r.stderr
    assert len(_ours(state.read_text())) == 1


def test_upgrade_repoints_the_entry_at_the_new_tree(cron_env) -> None:
    run, state = cron_env
    assert run("install_tls_rotation_cron\n").returncode == 0
    r = run("ROOT=/opt/correlix-v2/NetOps_Observability; install_tls_rotation_cron\n")
    assert r.returncode == 0, r.stderr
    ours = _ours(state.read_text())
    assert len(ours) == 1 and "/opt/correlix-v2/" in ours[0], ours


def test_plaintext_install_schedules_nothing(cron_env) -> None:
    run, state = cron_env
    r = run("install_tls_rotation_cron\n", TEST_TLS="0")
    assert r.returncode == 0, r.stderr
    assert not state.exists()


def test_uninstall_removes_only_our_line(cron_env) -> None:
    run, state = cron_env
    state.write_text("0 1 * * * /home/u/own-job.sh\n")
    assert run("install_tls_rotation_cron\n").returncode == 0
    r = run("remove_tls_rotation_cron\n")
    assert r.returncode == 0, r.stderr
    table = state.read_text()
    assert "/home/u/own-job.sh" in table and not _ours(table)


def test_uninstall_when_ours_was_the_only_line(cron_env) -> None:
    run, state = cron_env
    assert run("install_tls_rotation_cron\n").returncode == 0
    r = run("remove_tls_rotation_cron\n")
    assert r.returncode == 0, r.stderr
    assert not state.exists() or not _ours(state.read_text())


def test_missing_cron_is_loud_on_a_tls_install(tmp_path: Path) -> None:
    script = (
        'TLS_CRON_MARK="# correlix-tls-rotate (managed by install-correlix.sh)"\nROOT=/x\n'
        'warn() { echo "WARN $*" >&2; }\nok() { echo "OK $*"; }\ntls_active() { return 0; }\n'
        + _functions(INSTALLER, ["crontab_without_mark", "install_tls_rotation_cron"]))
    empty = tmp_path / "empty"
    empty.mkdir()
    r = subprocess.run(["/bin/bash", "-c", script + "install_tls_rotation_cron\n"],
                       capture_output=True, text=True, timeout=30, env={"PATH": str(empty)})
    assert r.returncode != 0
    assert "crontab is not installed" in r.stderr


def test_installer_wires_install_and_uninstall() -> None:
    body = INSTALLER.read_text(encoding="utf-8")
    install = body[body.index("cmd_install() {"):]
    install = install[: install.index("\n}\n")]
    assert "install_tls_rotation_cron" in install
    uninstall = body[body.index("cmd_uninstall() {"):]
    uninstall = uninstall[: uninstall.index("\n}\n")]
    assert "remove_tls_rotation_cron" in uninstall


def test_watchdog_reads_the_heartbeat_the_installed_sweep_writes() -> None:
    wd = (SCRIPTS / "stack-watchdog.sh").read_text(encoding="utf-8")
    assert 'tls_beat="${TLS_ROTATE_HEARTBEAT:-' in wd
    iw = (SCRIPTS / "install-watchdog.sh").read_text(encoding="utf-8")
    assert "TLS_ROTATE_HEARTBEAT='$BUNDLE_SCRIPTS_DIR/rotate-tls.heartbeat'" in iw
    # The sweep's default heartbeat lands beside itself in the bundle's scripts/.
    assert 'HEARTBEAT="${HEARTBEAT:-$DIR/rotate-tls.heartbeat}"' in SWEEP.read_text(encoding="utf-8")


def test_watchdog_checks_client_cert_expiry_independently() -> None:
    wd = (SCRIPTS / "stack-watchdog.sh").read_text(encoding="utf-8")
    assert "netops_tls_client_cert_expiry_seconds" in wd
    assert "CLIENT_CERT_CHECK" in wd



# ---------------------------------------------------------------------------
# The watchdog's client-cert block, lifted and run against a stubbed query.
# ---------------------------------------------------------------------------

def _client_cert_block() -> str:
    src = (SCRIPTS / "stack-watchdog.sh").read_text(encoding="utf-8")
    start = src.index('if [ "${CLIENT_CERT_CHECK:-1}" = "1" ] && [ -n "${eng_cid:-}" ]; then')
    end = src.index("# SNAPSHOT RESTORABILITY", start)
    return src[start:src.rindex("\nfi\n", start, end) + 4]


def _run_block(stub: str, **env: str) -> list[str]:
    script = ("problems=()\neng_cid=victoria\n" + stub + "\n" + _client_cert_block()
              + '\nprintf "%s\\n" "${problems[@]}"\n')
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30,
                       env={"PATH": "/usr/bin:/bin", **env})
    assert r.returncode == 0, r.stderr
    return [line for line in r.stdout.splitlines() if line]


def test_watchdog_pages_on_a_client_cert_inside_12h() -> None:
    probs = _run_block('eng_query() { eng_err=""; eng_val="3600"; return 0; }')
    assert any(p.startswith("CLIENT_CERT_EXPIRING") for p in probs), probs


def test_watchdog_quiet_on_a_healthy_or_absent_series() -> None:
    assert _run_block('eng_query() { eng_err=""; eng_val="302400"; return 0; }') == []
    assert _run_block('eng_query() { eng_err=""; eng_val=""; return 0; }') == []


def test_watchdog_failed_or_garbage_query_is_never_healthy() -> None:
    probs = _run_block('eng_query() { eng_err="victoria query failed (rc=8)"; eng_val=""; return 1; }')
    assert any("SKIPPED" in p for p in probs), probs
    probs = _run_block('eng_query() { eng_err=""; eng_val="NaN"; return 0; }')
    assert any("UNKNOWN" in p for p in probs), probs


def test_watchdog_client_cert_check_can_be_disabled() -> None:
    assert _run_block('eng_query() { eng_err=""; eng_val="1"; return 0; }', CLIENT_CERT_CHECK="0") == []

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
