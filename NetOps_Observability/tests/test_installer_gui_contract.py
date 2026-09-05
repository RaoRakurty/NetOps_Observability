"""GUI-installer P0 engine contract tests (docs/design/gui-installer-2026-08.md §6).

Pins the correlix-setup v1 API + event contract the graphical installer parses:

  (a) install.py --progress-json emits `@CX@ {json}` stage/result markers in
      the contract's exact format, ADDITIONAL to the human output; the stage-id
      set matches the contract; the terminal result NEVER carries a password.
      Each CLOSING stage marker (ok/fail) also carries `elapsed_s` — the
      deployment-friction instrument (G6) — and a real run ends with one
      `timing` marker plus data/install-timing.json
  (b) --bootstrap-docker gives the Docker-bootstrap prompt flag parity
      (the prompt is never reached when the flag is given — like --tls)
  (c) --snmp-discovery validates CIDRs at the boundary and lands in .env via
      idempotent line surgery that preserves operator edits
  (d) install-correlix.sh install --config expands Profile JSON v1 to the
      existing flags, fail-closed on unknown keys/add-ons
  (e) resource_planner.py --detect-json serves the GUI facts endpoint with the
      shared auto-profile thresholds install.py uses

Everything runs against temp dirs / --print-flags / fast-fail argv paths — no
docker, no real .env, no running stack.

Run:  python3 -m pytest tests/test_installer_gui_contract.py -v
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import install                        # noqa: E402
import resource_planner as rp         # noqa: E402

INSTALL_SH = SCRIPTS / "install-correlix.sh"

# The authoritative stage-id list from the contract (scratchpad gui-contract.md
# / design §6): install.py's stages in order, then the wrapper's three.
CONTRACT_STAGES = ("prereq", "scaffold", "env", "sizing", "tls-env",
                   "data-dirs", "bundle", "bootstrap-appstate",
                   "up-a", "mint", "up-b",
                   "kafka-acls", "status",
                   "bootstrap-os", "bootstrap-kc", "bootstrap-grafana")
WRAPPER_STAGES = ("preflight", "verify-health", "verify-login")


def marker_lines(out: str) -> list[dict]:
    """Parse `@CX@ {json}` lines; every marker must be a single valid line."""
    found = []
    for line in out.splitlines():
        if line.startswith("@CX@ "):
            found.append(json.loads(line[len("@CX@ "):]))
    return found


@pytest.fixture
def progress_on():
    """Enable marker emission for the test, restoring module state after."""
    old_on, old_stage = install._PROGRESS["on"], install._PROGRESS["stage"]
    install._PROGRESS["on"] = True
    install._PROGRESS["stage"] = None
    yield
    install._PROGRESS["on"] = old_on
    install._PROGRESS["stage"] = old_stage


# ── (a) progress markers ─────────────────────────────────────────────────────

def test_markers_silent_when_disabled(capsys):
    assert install._PROGRESS["on"] is False  # env var not set in the test run
    install._stage_start("prereq", "checking prerequisites")
    install._stage_close_ok()
    install._result_ok("http://localhost:8000", "admin")
    assert "@CX@" not in capsys.readouterr().out


def test_stage_start_then_next_stage_closes_previous_ok(progress_on, capsys):
    install._stage_start("prereq", "checking prerequisites")
    install._stage_start("scaffold", "validating scaffold")
    ms = marker_lines(capsys.readouterr().out)
    # The CLOSING marker carries the stage's wall clock (G6); start markers do
    # not — a stage that has not run yet has no elapsed time to report.
    elapsed = ms[1].pop("elapsed_s")
    assert isinstance(elapsed, float) and elapsed >= 0.0
    assert ms == [
        {"kind": "stage", "id": "prereq", "title": "checking prerequisites",
         "status": "start"},
        {"kind": "stage", "id": "prereq", "title": "checking prerequisites",
         "status": "ok"},
        {"kind": "stage", "id": "scaffold", "title": "validating scaffold",
         "status": "start"},
    ]
    assert "elapsed_s" not in ms[0] and "elapsed_s" not in ms[2]


def test_step_with_stage_keeps_human_output_and_adds_marker(progress_on, capsys):
    install.step("checking prerequisites", stage="prereq")
    out = capsys.readouterr().out
    assert "=== checking prerequisites ===" in out          # human line unchanged
    ms = marker_lines(out)
    assert ms == [{"kind": "stage", "id": "prereq",
                   "title": "checking prerequisites", "status": "start"}]


def test_fail_emits_stage_fail_with_message_then_result_fail(progress_on, capsys):
    install._stage_start("env", "generating environment")
    capsys.readouterr()
    with pytest.raises(SystemExit) as exc:
        install.fail("boom happened")
    assert exc.value.code == 1
    cap = capsys.readouterr()
    assert "[fail ] boom happened" in cap.err               # human line on stderr
    ms = marker_lines(cap.out)
    elapsed = ms[0].pop("elapsed_s")
    assert isinstance(elapsed, float) and elapsed >= 0.0
    assert ms == [
        {"kind": "stage", "id": "env", "title": "generating environment",
         "status": "fail", "message": "boom happened"},
        {"kind": "result", "status": "fail"},
    ]


def test_result_ok_carries_url_and_admin_user_only_never_a_password(progress_on, capsys):
    install._result_ok("http://localhost:8000", "admin")
    out = capsys.readouterr().out
    ms = marker_lines(out)
    assert ms == [{"kind": "result", "status": "ok",
                   "url": "http://localhost:8000", "admin_user": "admin"}]
    assert set(ms[0]) == {"kind", "status", "url", "admin_user"}
    assert "password" not in out.lower()


def test_stage_ids_match_the_contract():
    assert install.PROGRESS_STAGES == CONTRACT_STAGES
    src = (SCRIPTS / "install.py").read_text()
    used = set(re.findall(r'stage="([a-z-]+)"', src))
    assert used == set(CONTRACT_STAGES), (
        "install.py step(..., stage=) call sites drifted from the contract "
        f"stage-id set: {sorted(used ^ set(CONTRACT_STAGES))}")


def test_result_markers_emitted_at_both_run_ends():
    """Both main() completion points (--no-start return and the full-run end)
    emit the terminal result marker the GUI treats as completion."""
    src = (SCRIPTS / "install.py").read_text()
    assert src.count("_result_ok(dash_url") == 2


# ── (a2) deployment-friction timing instrument (G6) ──────────────────────────

@pytest.fixture
def timing_reset():
    """Isolate the module's timing state (it is per-run, not per-import)."""
    old = dict(install._TIMING)
    install._TIMING.update({"t0": install.time.monotonic(), "open_t": None,
                            "stages": [], "record": False, "report": False,
                            "path": None})
    yield install._TIMING
    install._TIMING.clear()
    install._TIMING.update(old)


def test_timing_writes_nothing_until_a_real_run_arms_it(progress_on, timing_reset,
                                                        capsys, tmp_path):
    """Importing the module or failing at the argv boundary must not produce a
    timing file: the instrument measures INSTALLS, and unit tests are not one."""
    timing_reset["path"] = tmp_path / "data" / "install-timing.json"
    install._stage_start("env", "generating environment")
    with pytest.raises(SystemExit):
        install.fail("boom")
    kinds = [m["kind"] for m in marker_lines(capsys.readouterr().out)]
    assert "timing" not in kinds
    assert not (tmp_path / "data").exists()


def test_timing_marker_and_file_carry_total_and_per_stage_elapsed(
        progress_on, timing_reset, capsys, tmp_path):
    timing_reset["record"] = True
    timing_reset["path"] = tmp_path / "data" / "install-timing.json"
    install._stage_start("prereq", "checking prerequisites")
    install._stage_start("scaffold", "validating scaffold")
    install._result_ok("http://localhost:8000", "admin")
    install._timing_finish("ok")

    ms = marker_lines(capsys.readouterr().out)
    timing = [m for m in ms if m["kind"] == "timing"]
    assert len(timing) == 1, "exactly one terminal timing marker per run"
    t = timing[0]
    assert set(t) == {"kind", "status", "total_s", "stages"}
    assert t["status"] == "ok" and isinstance(t["total_s"], float)
    assert [st["id"] for st in t["stages"]] == ["prereq", "scaffold"]
    for st in t["stages"]:
        assert set(st) == {"id", "status", "elapsed_s"}
        assert st["status"] == "ok" and st["elapsed_s"] >= 0.0
    # ...and the same numbers land in the file the friction report reads.
    doc = json.loads((tmp_path / "data" / "install-timing.json").read_text())
    assert doc["version"] == 1 and doc["status"] == "ok"
    assert doc["total_s"] >= 0.0 and doc["generated_utc"].endswith("Z")
    assert [st["id"] for st in doc["stages"]] == ["prereq", "scaffold"]
    assert all("title" in st and "elapsed_s" in st for st in doc["stages"])
    # No credential ever rides the instrument.
    assert "password" not in (tmp_path / "data" / "install-timing.json").read_text().lower()


def test_timing_file_failure_is_reported_not_fatal(timing_reset, capsys, tmp_path):
    """A run that installed the stack is not a failed run because a timing file
    could not be written — but the failure is NAMED (§16.1)."""
    blocked = tmp_path / "file"
    blocked.write_text("not a directory")
    timing_reset["record"] = True
    timing_reset["path"] = blocked / "data" / "install-timing.json"
    install._timing_finish("ok")                       # must not raise
    assert "could not write the install timing file" in capsys.readouterr().err


def test_time_report_prints_a_per_stage_table(timing_reset, capsys):
    timing_reset["record"] = True
    timing_reset["report"] = True
    install._stage_start("prereq", "checking prerequisites")
    install._stage_close_ok()
    install._timing_finish("ok")
    out = capsys.readouterr().out
    assert "=== install timing ===" in out
    assert "prereq" in out and "TOTAL" in out


def test_failed_run_records_the_stage_that_failed(progress_on, timing_reset,
                                                  capsys, tmp_path):
    timing_reset["record"] = True
    timing_reset["path"] = tmp_path / "install-timing.json"
    install._stage_start("up-a", "starting stack")
    with pytest.raises(SystemExit):
        install.fail("compose up failed")
    doc = json.loads((tmp_path / "install-timing.json").read_text())
    assert doc["status"] == "fail"
    assert doc["stages"][-1]["id"] == "up-a"
    assert doc["stages"][-1]["status"] == "fail"


# ── (b) --bootstrap-docker flag parity ───────────────────────────────────────

def test_bootstrap_docker_no_never_reaches_the_prompt(monkeypatch, capsys):
    monkeypatch.setattr(install, "_is_debian_family", lambda: True)
    monkeypatch.setattr("builtins.input",
                        lambda *_: pytest.fail("prompt reached despite the flag"))
    with pytest.raises(SystemExit) as exc:
        install._maybe_bootstrap_ubuntu("docker is not installed.", "no")
    assert exc.value.code == 1
    assert "aborted" in capsys.readouterr().err


def test_bootstrap_docker_yes_runs_bootstrap_without_prompting(monkeypatch, capsys):
    monkeypatch.setattr(install, "_is_debian_family", lambda: True)
    monkeypatch.setattr("builtins.input",
                        lambda *_: pytest.fail("prompt reached despite the flag"))
    calls = []

    class R:
        returncode = 0

    monkeypatch.setattr(install.subprocess, "run",
                        lambda argv, *a, **k: calls.append(argv) or R())
    with pytest.raises(SystemExit) as exc:
        install._maybe_bootstrap_ubuntu("docker is not installed.", "yes")
    assert exc.value.code == 0                    # bootstrap ran; re-login exit
    assert calls and calls[0][:2] == ["sudo", "bash"]
    assert "bootstrap-ubuntu.sh" in calls[0][2]


def test_bootstrap_docker_without_flag_keeps_todays_non_tty_behavior(monkeypatch, capsys):
    monkeypatch.setattr(install, "_is_debian_family", lambda: True)

    def eof(*_):
        raise EOFError

    monkeypatch.setattr("builtins.input", eof)
    with pytest.raises(SystemExit) as exc:
        install._maybe_bootstrap_ubuntu("docker is not installed.", None)
    assert exc.value.code == 1                    # EOF == "no" == abort, as today
    assert "aborted" in capsys.readouterr().err


def test_bootstrap_docker_argparse_rejects_other_values():
    r = subprocess.run([sys.executable, str(SCRIPTS / "install.py"),
                        "--bootstrap-docker", "maybe"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 2
    assert "--bootstrap-docker" in r.stderr


def test_cli_help_advertises_the_new_flags():
    r = subprocess.run([sys.executable, str(SCRIPTS / "install.py"), "--help"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0
    for flag in ("--progress-json", "--bootstrap-docker", "--snmp-discovery",
                 "--time-report"):
        assert flag in r.stdout


# ── (c) --snmp-discovery ─────────────────────────────────────────────────────

@pytest.mark.parametrize("bad", ["999.1.2.3/8", "10.0.0.0/40", "banana", ","])
def test_snmp_discovery_rejects_invalid_input_before_any_step(bad):
    r = subprocess.run([sys.executable, str(SCRIPTS / "install.py"),
                        "--no-start", "--snmp-discovery", bad],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 1
    assert "--snmp-discovery" in r.stderr
    assert "===" not in r.stdout        # failed at the boundary, no step ran


def test_snmp_discovery_lands_in_a_fresh_env(tmp_path):
    env_path = tmp_path / ".env"
    install.write_env(env_path, 8000, force=True)
    install.enable_snmp_discovery_env(env_path, "10.70.0.0/16,192.168.1.0/24")
    env = install._parse_env(env_path)
    assert env["ENABLE_SNMP_DISCOVERY"] == "true"
    assert env["SNMP_CIDR_RANGES"] == "10.70.0.0/16,192.168.1.0/24"
    # In-place substitution of the template defaults, not append-a-duplicate.
    text = env_path.read_text()
    assert text.count("ENABLE_SNMP_DISCOVERY=") == 1
    assert text.count("SNMP_CIDR_RANGES=") == 1


def test_snmp_discovery_line_surgery_is_idempotent(tmp_path):
    env_path = tmp_path / ".env"
    install.write_env(env_path, 8000, force=True)
    install.enable_snmp_discovery_env(env_path, "10.70.0.0/16")
    first = env_path.read_text()
    install.enable_snmp_discovery_env(env_path, "10.70.0.0/16")
    assert env_path.read_text() == first


def test_snmp_discovery_preserves_operator_edits_and_appends_when_missing(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text("# operator file\nBASE_PORT=9001\nCUSTOM_THING=keep-me\n")
    install.enable_snmp_discovery_env(env_path, "172.16.0.0/12")
    text = env_path.read_text()
    assert "BASE_PORT=9001" in text and "CUSTOM_THING=keep-me" in text
    env = install._parse_env(env_path)
    assert env["ENABLE_SNMP_DISCOVERY"] == "true"
    assert env["SNMP_CIDR_RANGES"] == "172.16.0.0/12"
    # A later re-run with a new scope substitutes in place.
    install.enable_snmp_discovery_env(env_path, "10.0.0.0/8")
    text = env_path.read_text()
    assert install._parse_env(env_path)["SNMP_CIDR_RANGES"] == "10.0.0.0/8"
    assert text.count("SNMP_CIDR_RANGES=") == 1


def test_absent_flag_keeps_the_opt_in_defaults(tmp_path):
    env_path = tmp_path / ".env"
    install.write_env(env_path, 8000, force=True)
    env = install._parse_env(env_path)
    assert env["ENABLE_SNMP_DISCOVERY"] == "false"
    assert env["SNMP_CIDR_RANGES"] == ""


# ── (d) install-correlix.sh --config (Profile JSON v1) ───────────────────────

def expand_config(cfg: dict, tmp_path: Path) -> subprocess.CompletedProcess:
    f = tmp_path / "profile.json"
    f.write_text(json.dumps(cfg))
    return subprocess.run(["bash", str(INSTALL_SH), "install",
                           "--config", str(f), "--print-flags"],
                          capture_output=True, text=True, timeout=60,
                          env={"PATH": "/usr/local/bin:/usr/bin:/bin",
                               "CORRELIX_NO_SIZING": "0"})


def flags_of(stdout: str) -> dict:
    """argv lines → {flag: value-or-None} (bare flags map to None)."""
    toks = stdout.splitlines()
    out: dict = {}
    i = 0
    while i < len(toks):
        assert toks[i].startswith("--"), f"unexpected argv token: {toks[i]!r}"
        if i + 1 < len(toks) and not toks[i + 1].startswith("--"):
            out[toks[i]] = toks[i + 1]
            i += 2
        else:
            out[toks[i]] = None
            i += 1
    return out


FULL_PROFILE = {
    "version": 1,
    "port": 8443,
    "tls": "yes",
    "retention_profile": "demo",
    "addons": ["log-search-ui", "self-monitoring"],
    "external_kafka": {"broker_urls": "b1:9092,b2:9092"},
    "discovery": {"enabled": True, "cidrs": ["10.70.0.0/16", "192.168.1.0/24"]},
    "sizing": {"profile": "small"},
}


def test_config_expands_to_the_existing_flags(tmp_path):
    r = expand_config(FULL_PROFILE, tmp_path)
    assert r.returncode == 0, r.stderr
    got = flags_of(r.stdout)
    assert got == {
        "--port": "8443",
        "--broker-urls": "b1:9092,b2:9092",
        "--profiles": "embedded-bus,prober,osd,self-monitoring",
        "--retention-profile": "demo",
        "--plan-resources": "small",
        "--tls": "yes",
        "--bootstrap-docker": "no",
        "--snmp-discovery": "10.70.0.0/16,192.168.1.0/24",
    }


def test_config_minimal_profile_gets_non_interactive_defaults(tmp_path):
    r = expand_config({"version": 1}, tmp_path)
    assert r.returncode == 0, r.stderr
    got = flags_of(r.stdout)
    assert got["--port"] == "8000"
    assert got["--tls"] == "no"                     # fail-closed baseline
    assert got["--bootstrap-docker"] == "no"        # never blocks non-TTY
    assert got["--profiles"] == "embedded-bus,prober"   # no addons listed
    assert got["--retention-profile"] == "production"
    assert "--plan-resources" in got and got["--plan-resources"] is None  # auto
    assert "--snmp-discovery" not in got
    assert "--broker-urls" not in got


@pytest.mark.parametrize("cfg,needle", [
    ({"version": 1, "portt": 9}, "unknown top-level key"),
    ({"version": 2}, "version"),
    ({"version": 1, "tls": "maybe"}, "tls"),
    ({"version": 1, "retention_profile": "forever"}, "retention_profile"),
    ({"version": 1, "external_kafka": {"broker_urls": "a:1", "x": 2}},
     "external_kafka"),
    ({"version": 1, "discovery": {"enabled": True, "cidrs": ["banana"]}},
     "not a valid CIDR"),
    ({"version": 1, "discovery": {"enabled": True, "cidrs": []}}, "cidrs"),
    ({"version": 1, "sizing": {"profile": "huge"}}, "sizing"),
    ({"version": 1, "port": 99999}, "port"),
])
def test_config_rejects_invalid_profiles_fail_closed(tmp_path, cfg, needle):
    r = expand_config(cfg, tmp_path)
    assert r.returncode != 0
    assert needle in (r.stderr + r.stdout)


def test_config_unknown_addon_is_a_hard_error(tmp_path):
    r = expand_config({"version": 1, "addons": ["nonexistent-pack"]}, tmp_path)
    assert r.returncode != 0
    assert "Unknown add-on" in (r.stdout + r.stderr)


def test_wrapper_stage_markers_match_the_contract_format():
    """Exercise cx_stage/cx_result exactly as shipped (extracted verbatim)."""
    helpers = subprocess.run(
        ["sed", "-n", "/^cx_stage()/,/^}/p;/^cx_result()/,/^}/p",
         str(INSTALL_SH)], capture_output=True, text=True, timeout=30).stdout
    assert "cx_stage()" in helpers and "cx_result()" in helpers
    script = helpers + """
cx_stage preflight "checking this host" start
cx_stage preflight "checking this host" fail "host preflight failed"
cx_stage verify-health "waiting for services to become healthy" start
cx_stage verify-health "waiting for services to become healthy" ok
cx_stage verify-login "verifying the admin credential" ok
cx_result ok "http://10.0.0.5:8000" admin
cx_result fail
"""
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                       timeout=30, env={"PATH": "/usr/bin:/bin",
                                        "CORRELIX_PROGRESS_JSON": "1"})
    assert r.returncode == 0, r.stderr
    ms = marker_lines(r.stdout)
    assert [m.get("id", m["kind"]) for m in ms] == [
        "preflight", "preflight", "verify-health", "verify-health",
        "verify-login", "result", "result"]
    assert set(m["id"] for m in ms if m["kind"] == "stage") <= set(WRAPPER_STAGES)
    assert ms[1]["status"] == "fail" and ms[1]["message"] == "host preflight failed"
    assert ms[5] == {"kind": "result", "status": "ok",
                     "url": "http://10.0.0.5:8000", "admin_user": "admin"}
    assert ms[6] == {"kind": "result", "status": "fail"}
    # And silent when the activation env var is absent.
    r2 = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                        timeout=30, env={"PATH": "/usr/bin:/bin"})
    assert r2.returncode == 0 and "@CX@" not in r2.stdout


# ── (e) resource_planner.py --detect-json ────────────────────────────────────

def test_detect_json_shape_and_no_side_effects(tmp_path):
    r = subprocess.run([sys.executable, str(SCRIPTS / "resource_planner.py"),
                        "--detect-json", "--memory", "16g", "--cpus", "4",
                        "--disk-free", "100g"],
                       capture_output=True, text=True, timeout=60,
                       cwd=str(tmp_path))
    assert r.returncode == 0, r.stderr
    doc = json.loads(r.stdout)
    assert set(doc) == {"mem_bytes", "mem_gib", "cpus", "disk_free_bytes",
                        "suggested_profile"}
    assert doc["mem_bytes"] == 16 * (1 << 30)
    assert doc["mem_gib"] == 16.0
    assert doc["cpus"] == 4.0
    assert doc["disk_free_bytes"] == 100 * (1 << 30)
    assert doc["suggested_profile"] == "demo"
    assert list(tmp_path.iterdir()) == []           # wrote nothing


def test_detect_json_uses_real_host_when_unoverridden():
    r = subprocess.run([sys.executable, str(SCRIPTS / "resource_planner.py"),
                        "--detect-json"], capture_output=True, text=True,
                       timeout=60)
    assert r.returncode == 0, r.stderr
    doc = json.loads(r.stdout)
    assert doc["mem_bytes"] > 0 and doc["cpus"] >= 1
    assert doc["suggested_profile"] in ("demo", "small", "medium", "large")


@pytest.mark.parametrize("gib,profile", [
    (8, "demo"), (23, "demo"), (24, "small"), (47, "small"),
    (48, "medium"), (95, "medium"), (96, "large"), (256, "large"),
])
def test_auto_profile_thresholds_are_the_install_py_ones(gib, profile):
    assert rp.suggest_profile(gib * (1 << 30)) == profile


def test_install_py_shares_the_thresholds_instead_of_duplicating():
    src = (SCRIPTS / "install.py").read_text()
    assert "rp.suggest_profile(" in src
    assert 'gib < 24' not in src        # the old inline ternary is gone


# ── make-installer.sh H6: binary in SHA256SUMS ───────────────────────────────

def test_sha256sums_covers_the_correlix_setup_binary():
    src = (SCRIPTS / "make-installer.sh").read_text()
    m = re.search(r"^\(cd \"\$BUNDLE_DIR\" && sha256sum (.+) > SHA256SUMS\)$",
                  src, re.MULTILINE)
    assert m, "make-installer.sh lost its SHA256SUMS line"
    assert "correlix-setup" in m.group(1), (
        "correlix-setup binary must be covered by SHA256SUMS (design §5 H6)")
