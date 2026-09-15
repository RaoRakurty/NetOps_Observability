#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""`install-correlix.sh doctor` — a read-only, bounded, redacted health report.

docs/design/INSTALLER_SELF_HEALING_FMEA_2026-09-15.md §4.6 (rows 5, 15).

What it reports, in order:
  host-profile      the saved data/.host-profile.json verdict + live IO pressure
  install-lock      who holds deployment/docker/.install.lock, or whether a
                    previous run left its record behind
  wizard-job        the setup wizard's correlix-setup-install.job.json state
  env-completeness  every `${VAR:?}` the compose files require, by KEY NAME only
  docker            whether the daemon answers
  containers        every container of the `netops` compose project: state,
                    RestartCount, OOMKilled, health and the log-signature
                    verdict (scripts/install_signatures.py) on its last 200 lines
  disk-watermarks   the data and Docker filesystems vs OpenSearch 85/90/95 %
  install-journal   data/install-timing.json stage records

Exit 0 healthy · 1 actionable problems · 2 could not assess (Docker did not
answer, or the time budget ran out before every container was examined).

It never changes anything: the only docker verbs it issues are info, ps,
inspect and logs, every call is time-bounded, and no file is written. It
never prints a secret value: log evidence is redacted line by line with the
installer's credential regex, and as a second net every .env value of eight
characters or more is replaced in the finished report before it is shown.

Usage:  python3 scripts/install_doctor.py --root DIR --bundle-dir DIR [--json]
Standard library only (CLAUDE.md §6). Every host touch point is injectable
through DoctorEnv (tests/test_install_doctor.py).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import host_profile as hp  # sibling modules: the path is set just above
import install_signatures as sigs

COMPOSE_PROJECT = "netops"  # pinned by `name: netops` in docker-compose.yml
INSPECT_FORMAT = (
    '{"id":{{json .Id}},"name":{{json .Name}},'
    '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
    '"status":{{json .State.Status}},"restarts":{{.RestartCount}},'
    '"oom":{{.State.OOMKilled}},"exit":{{.State.ExitCode}},'
    '"started":{{json .State.StartedAt}},'
    '"health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}"none"{{end}}}')

LOG_LINES = 200
LOOP_RESTARTS = 3          # same threshold install.py's convergence uses
LOOP_WINDOW_S = 600        # restarts only count as a loop if the last start is this recent
MAX_CONTAINERS = 200
DOCKER_TIMEOUT_S = 15
LIST_TIMEOUT_S = 30
DEFAULT_DEADLINE_S = 120.0
MAX_LOG_BYTES = 1 << 20
MAX_ENV_BYTES = 1 << 20
MAX_COMPOSE_BYTES = 4 << 20
MAX_LOCK_BYTES = 4 << 10
MAX_JOB_BYTES = 256 << 10
MAX_JOURNAL_BYTES = 1 << 20
SCRUB_MIN_CHARS = 8
WATERMARKS = ((95, "problem", "at or above the 95 % flood-stage watermark: OpenSearch makes its indices read-only"),
              (90, "problem", "above the 90 % high watermark: OpenSearch stops placing new data here"),
              (85, "warn", "above the 85 % low watermark: OpenSearch starts limiting where data goes"))

STATUSES = ("ok", "warn", "problem", "unknown")
_REQUIRED_VAR = re.compile(r"\$\{([A-Z_][A-Z0-9_]*):\?")
_ENV_LINE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
_SAFE_TOKEN = re.compile(r"[^A-Za-z0-9 _.:+/@-]")
_STARTED = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?Z$")


# ── model ────────────────────────────────────────────────────────────────────

@dataclass
class Check:
    id: str
    title: str
    status: str
    summary: str
    remedy: str = ""
    details: dict = field(default_factory=dict)
    essential: bool = False   # an `unknown` essential check means "could not assess"


@dataclass
class Report:
    generated_utc: str
    checks: list[Check]

    @property
    def exit_code(self) -> int:
        if any(c.status == "unknown" and c.essential for c in self.checks):
            return 2
        if any(c.status == "problem" for c in self.checks):
            return 1
        return 0

    def result_line(self) -> str:
        code = self.exit_code
        if code == 2:
            return "Result: could not assess this install (exit 2) — see the [ ?? ] lines above."
        problems = sum(c.status == "problem" for c in self.checks)
        warns = sum(c.status == "warn" for c in self.checks)
        if code == 1:
            return f"Result: {problems} problem(s) need attention, {warns} warning(s) (exit 1)."
        return f"Result: no problems found, {warns} warning(s) (exit 0)."

    def to_dict(self) -> dict:
        return {"version": 1, "generated_utc": self.generated_utc, "exit_code": self.exit_code,
                "result": self.result_line(),
                "checks": [{"id": c.id, "title": c.title, "status": c.status, "summary": c.summary,
                            "remedy": c.remedy, "details": c.details} for c in self.checks]}

    def render_text(self) -> str:
        tag = {"ok": "[ OK ]", "warn": "[WARN]", "problem": "[FAIL]", "unknown": "[ ?? ]"}
        out = [f"Correlix doctor (read-only report, {self.generated_utc})", ""]
        for c in self.checks:
            out.append(f"{tag[c.status]} {c.title}: {c.summary}")
            verdict = c.details.get("verdict") if isinstance(c.details, dict) else None
            if isinstance(verdict, dict) and verdict.get("class") not in (None, "unknown"):
                if c.status == "ok":
                    out.append(f"         earlier log lines matched: {verdict['class']} "
                               "(the service is running now)")
                else:
                    out.append(f"         log verdict: {verdict['class']} "
                               f"(suggested action: {verdict['action']})")
                if verdict.get("evidence"):
                    out.append(f"         evidence: {verdict['evidence']}")
            if c.remedy and c.status != "ok":
                out.append(f"         fix: {c.remedy}")
        out += ["", self.result_line()]
        return "\n".join(out)


def scrub(text: str, values: list[str]) -> str:
    for v in sorted(values, key=len, reverse=True):
        if v:
            text = text.replace(v, "[redacted]")
    return text


def _scrub_obj(obj: object, values: list[str]) -> object:
    if isinstance(obj, str):
        return scrub(obj, values)
    if isinstance(obj, list):
        return [_scrub_obj(x, values) for x in obj]
    if isinstance(obj, dict):
        return {k: _scrub_obj(v, values) for k, v in obj.items()}
    return obj


def _token(value: object, limit: int = 60) -> str:
    """A string from an on-disk record, reduced to harmless characters."""
    return _SAFE_TOKEN.sub("?", str(value))[:limit]


# ── host seams ───────────────────────────────────────────────────────────────

Runner = Callable[[list[str], int], tuple[int, str, str]]


@dataclass
class DoctorEnv:
    root: Path
    bundle_dir: Path
    runner: Runner
    readers: hp.HostReaders
    disk_usage: Callable[[Path], tuple[int, int, int]]   # total, used, available bytes
    device_of: Callable[[Path], int]
    pid_alive: Callable[[int], bool]
    proc_cmdline: Callable[[int], str]
    proc_start: Callable[[int], str]
    clock: Callable[[], float]
    wall: Callable[[], float]
    deadline_s: float = DEFAULT_DEADLINE_S


def read_bounded(path: Path, limit: int) -> bytes | None:
    """None when the file does not exist; ProbeError when it cannot be read or
    is larger than `limit`."""
    if not path.is_file():
        return None
    try:
        with open(path, "rb") as f:
            raw = f.read(limit + 1)
    except OSError as e:
        raise hp.ProbeError(f"cannot read {path.name}: {e.strerror or e}") from e
    if len(raw) > limit:
        raise hp.ProbeError(f"{path.name} is larger than {limit} bytes, so it was not read")
    return raw


def _statvfs_usage(path: Path) -> tuple[int, int, int]:
    try:
        st = os.statvfs(path)
    except OSError as e:
        raise hp.ProbeError(f"cannot read the size of {path}: {e.strerror or e}") from e
    total = st.f_blocks * st.f_frsize
    return total, (st.f_blocks - st.f_bfree) * st.f_frsize, st.f_bavail * st.f_frsize


def _device(path: Path) -> int:
    try:
        return os.stat(path).st_dev
    except OSError as e:
        raise hp.ProbeError(f"cannot stat {path}: {e.strerror or e}") from e


def _proc_text(pid: int, name: str) -> str:
    try:
        raw = read_bounded(Path(f"/proc/{pid}/{name}"), 64 << 10)
    except hp.ProbeError:
        return ""
    return (raw or b"").decode("utf-8", errors="replace")


def _proc_cmdline(pid: int) -> str:
    return _proc_text(pid, "cmdline").replace("\0", " ").strip()


def _proc_start(pid: int) -> str:
    stat_line = _proc_text(pid, "stat")
    fields = stat_line.rsplit(")", 1)[-1].split()
    return fields[19] if len(fields) > 19 else ""


def default_env(root: Path, bundle_dir: Path, deadline_s: float) -> DoctorEnv:
    import time
    return DoctorEnv(root=root, bundle_dir=bundle_dir, runner=hp.subprocess_runner,
                     readers=hp.default_readers(), disk_usage=_statvfs_usage, device_of=_device,
                     pid_alive=lambda pid: pid > 0 and Path(f"/proc/{pid}").is_dir(),
                     proc_cmdline=_proc_cmdline, proc_start=_proc_start,
                     clock=time.monotonic, wall=time.time, deadline_s=deadline_s)


def _read_proc_file(readers: hp.HostReaders, path: str) -> str:
    try:
        return readers.read_text(path)
    except OSError as e:
        raise hp.ProbeError(f"{path} is not readable ({e.strerror or e})") from e


# ── checks ───────────────────────────────────────────────────────────────────

def check_host_profile(env: DoctorEnv) -> Check:
    path = env.root / "data" / ".host-profile.json"
    live = None
    try:
        psi = hp.parse_psi(_read_proc_file(env.readers, "/proc/pressure/io"))
        live = psi.get("full", {}).get("avg60")
    except hp.ProbeError as e:
        live_note = f"live IO pressure not readable: {e}"
    else:
        live_note = ""
    details = {"live_io_full_avg60": live, "note": live_note} if live_note else {"live_io_full_avg60": live}
    title = "host speed"
    if not path.is_file():
        return Check("host-profile", title, "warn",
                     "no saved host profile yet: preflight measures and saves it on the next install",
                     "Run the installer (its preflight writes data/.host-profile.json).", details)
    try:
        prof = hp.load_profile(path)
    except hp.ProbeError as e:
        return Check("host-profile", title, "warn", f"the saved host profile is not usable: {e}",
                     "Re-run the installer; preflight measures the host again.", details)
    details.update({"class": prof["class"], "budget_factor": prof["budget_factor"],
                    "measured_utc": _token(prof.get("measured_utc", ""))})
    verdict = str(prof.get("verdict") or prof["class"])[:400]
    status = "ok" if prof["class"] in ("fast", "normal") else "warn"
    remedy = "" if status == "ok" else ("Slow storage lengthens every start-up; for production use "
                                        "SSD storage or a less busy host.")
    return Check("host-profile", title, status, verdict, remedy, details)


def check_lock(env: DoctorEnv) -> Check:
    path = env.root / "deployment" / "docker" / ".install.lock"
    title = "installer lock"
    try:
        raw = read_bounded(path, MAX_LOCK_BYTES)
    except hp.ProbeError as e:
        return Check("install-lock", title, "unknown", str(e))
    fields: dict[str, str] = {}
    for line in (raw or b"").decode("utf-8", errors="replace").splitlines():
        k, sep, v = line.partition("=")
        if sep:
            fields[k.strip()] = v.strip()
    pid_s = fields.get("pid", "")
    if not pid_s:
        return Check("install-lock", title, "ok", "no installer is running (no lock record)")
    cmd = _token(fields.get("command", "?"), 40)
    started = _token(fields.get("started_utc", "?"), 40)
    if not pid_s.isdigit():
        return Check("install-lock", title, "warn", "the lock record is unreadable",
                     "It is replaced by the next installer run.")
    pid = int(pid_s)
    details = {"pid": pid, "command": cmd, "started_utc": started}
    remedy = ("If no installer is running, nothing needs doing: the next run takes the record over. "
              "Read the last correlix-install-*.log to see where it stopped.")
    if env.pid_alive(pid):
        if "install-correlix" in env.proc_cmdline(pid):
            return Check("install-lock", title, "ok",
                         f"held: '{cmd}' is running (pid {pid}, started {started})", details=details)
        return Check("install-lock", title, "warn",
                     f"the lock record names pid {pid} ('{cmd}', started {started}), which is now a "
                     "different program: that run did not finish cleanly", remedy, details)
    return Check("install-lock", title, "warn",
                 f"the previous '{cmd}' (pid {pid}, started {started}) did not finish cleanly",
                 remedy, details)


def check_wizard_job(env: DoctorEnv) -> Check:
    path = env.bundle_dir / "correlix-setup-install.job.json"
    title = "setup wizard"
    try:
        raw = read_bounded(path, MAX_JOB_BYTES)
    except hp.ProbeError as e:
        return Check("wizard-job", title, "warn", f"the wizard's job record could not be read: {e}")
    if raw is None:
        return Check("wizard-job", title, "ok", "no setup-wizard install recorded")
    try:
        job = json.loads(raw)
    except ValueError:
        job = None
    if not isinstance(job, dict):
        return Check("wizard-job", title, "warn", "the wizard's job record is not valid JSON",
                     "It is rewritten by the next wizard install.")
    pid = job.get("pid") if isinstance(job.get("pid"), int) else 0
    started = _token(job.get("started_utc", "?"), 40)
    ended = _token(job.get("ended_utc", "?"), 40)
    outcome = _token(job.get("outcome", ""), 20)
    code = job.get("exit_code") if isinstance(job.get("exit_code"), int) else None
    details = {"pid": pid, "started_utc": started, "ended_utc": ended, "outcome": outcome,
               "exit_code": code, "credential_shown": bool(job.get("credential_shown"))}
    if not outcome:
        want = _token(job.get("proc_start", ""), 30)
        if pid > 0 and env.pid_alive(pid) and (not want or env.proc_start(pid) == want):
            return Check("wizard-job", title, "ok",
                         f"a setup-wizard install is running (pid {pid}, started {started})",
                         details=details)
        return Check("wizard-job", title, "warn",
                     f"the setup-wizard install started {started} stopped without recording a result "
                     "(it was interrupted)",
                     "Open the wizard again: it shows the recorded log. Re-running the install is safe.",
                     details)
    if outcome == "ok":
        return Check("wizard-job", title, "ok",
                     f"the last setup-wizard install succeeded (ended {ended})", details=details)
    if outcome == "fail":
        return Check("wizard-job", title, "warn",
                     f"the last setup-wizard install failed (ended {ended}, exit {code})",
                     "The container checks below show what is still wrong; fix those, then re-run.",
                     details)
    return Check("wizard-job", title, "warn",
                 f"the last setup-wizard install ended as '{outcome}' ({ended})",
                 "Re-running the install is safe.", details)


def required_env_keys_from_text(text: str) -> set[str]:
    return set(_REQUIRED_VAR.findall(text))


def required_env_keys(compose_dir: Path) -> set[str]:
    keys: set[str] = set()
    for name in ("docker-compose.yml", "compose.tls.yml"):
        raw = read_bounded(compose_dir / name, MAX_COMPOSE_BYTES)
        if raw is not None:
            keys |= required_env_keys_from_text(raw.decode("utf-8", errors="replace"))
    return keys


def parse_env_text(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = _ENV_LINE.match(s)
        if m:
            v = m.group(2).strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            out[m.group(1)] = v
    return out


def check_env(env: DoctorEnv) -> tuple[Check, list[str], bool]:
    """Returns the check, the values to scrub from the report, and whether .env exists."""
    compose_dir = env.root / "deployment" / "docker"
    title = ".env settings"
    try:
        raw = read_bounded(compose_dir / ".env", MAX_ENV_BYTES)
    except hp.ProbeError as e:
        return Check("env-completeness", title, "unknown", str(e)), [], True
    if raw is None:
        return Check("env-completeness", title, "ok", "no .env: nothing is installed here yet"), [], False
    values = parse_env_text(raw.decode("utf-8", errors="replace"))
    secret_values = [v for v in values.values() if len(v) >= SCRUB_MIN_CHARS]
    try:
        required = required_env_keys(compose_dir)
    except hp.ProbeError as e:
        return Check("env-completeness", title, "unknown", str(e)), secret_values, True
    missing = sorted(k for k in required if not values.get(k, "").strip())
    details = {"required": len(required), "missing": missing}
    if missing:
        return Check("env-completeness", title, "problem",
                     f"{len(missing)} required setting(s) missing or empty: {', '.join(missing)}",
                     "Re-run the installer: it generates missing values. Do not edit .env by hand.",
                     details), secret_values, True
    return Check("env-completeness", title, "ok",
                 f"all {len(required)} required settings are present", details=details), secret_values, True


def _started_epoch(value: str) -> float | None:
    m = _STARTED.match(value or "")
    if not m or m.group(1).startswith("0001"):
        return None
    return datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()


_OOM_REMEDY = ("Docker reports this container was killed for lack of memory (OOMKilled). Give the host "
               "more RAM, or re-run the installer so it sizes the services to this host.")


def assess_container(c: dict, logs: str | None, now: float) -> tuple[str, str, str, dict]:
    """(status, summary, remedy, details) for one container record."""
    service = _token(c.get("service") or sigs.normalize_service(str(c.get("name", "?"))), 60)
    status = _token(c.get("status", "?"), 20)
    restarts = c.get("restarts") if isinstance(c.get("restarts"), int) else 0
    exit_code = c.get("exit") if isinstance(c.get("exit"), int) else 0
    oom = c.get("oom") is True
    health = _token(c.get("health", "none"), 20)
    started = _started_epoch(str(c.get("started", "")))
    ago = None if started is None else max(0, int(now - started))

    if logs is None:
        verdict = sigs.Verdict(service, "unknown", "", "none", "logs were not readable", "")
    else:
        verdict = sigs.classify(service, logs, LOG_LINES)
    if oom and verdict.klass == "unknown":
        verdict = sigs.Verdict(service, "oom-killed", "state:OOMKilled", "fail", _OOM_REMEDY, "")
    details = {"container": _token(str(c.get("name", "")).lstrip("/"), 80), "status": status,
               "restarts": restarts, "oom_killed": oom, "exit_code": exit_code, "health": health,
               "last_start_seconds_ago": ago, "verdict": verdict.to_dict()}

    problem = ""
    note = ""
    if service.endswith("-init"):
        if status == "exited" and exit_code == 0:
            note = "one-shot setup step completed"
        elif status == "exited":
            problem = f"one-shot setup step exited with code {exit_code} (it must exit 0)"
        elif status == "running":
            note = "one-shot setup step is still running"
        else:
            problem = f"one-shot setup step is {status}" + (" (created but never started)" if status == "created" else "")
    elif status == "created":
        problem = "was created but never started"
    elif status == "restarting":
        problem = f"is restarting ({restarts} restarts)"
    elif status in ("exited", "dead"):
        problem = f"is {status} (exit code {exit_code})" + (", killed for lack of memory" if oom else "")
    elif status == "running":
        if health == "unhealthy":
            problem = "is running but unhealthy"
        elif restarts >= LOOP_RESTARTS and ago is not None and ago < LOOP_WINDOW_S:
            problem = f"is restarting repeatedly ({restarts} restarts, last start {ago}s ago)"
        elif health == "starting":
            return "warn", "is still starting", verdict.remedy if verdict.klass != "unknown" else "", details
        else:
            note = f"running ({'no healthcheck' if health == 'none' else health})"
            if restarts:
                note += f", {restarts} restarts in total"
            if oom:
                return ("warn", note + "; it was killed for lack of memory before its last start",
                        _OOM_REMEDY, details)
    else:
        problem = f"is {status}"

    if problem:
        if verdict.klass != "unknown":
            remedy = verdict.remedy
        elif status == "created":
            remedy = ("It usually waits on a service that failed first: fix the other problems "
                      "listed, then re-run the installer.")
        else:
            remedy = f"Read its log: ./install-correlix.sh logs {service}. Re-running the installer is safe."
        return "problem", problem, remedy, details
    return "ok", note, "", details


def check_docker_and_containers(env: DoctorEnv, env_exists: bool, start: float) -> tuple[list[Check], str]:
    """Returns the docker + container checks and Docker's data root ("" if unknown)."""
    try:
        rc, out, err = env.runner(["docker", "info", "--format", "{{.ServerVersion}}|{{.DockerRootDir}}"],
                                  DOCKER_TIMEOUT_S)
    except hp.ProbeError as e:
        rc, out, err = 127, "", str(e)
    if rc != 0:
        last = sigs.redact_line((err.strip().splitlines() or ["no output"])[-1][:300])
        return [Check("docker", "Docker", "unknown",
                      f"could not assess: the Docker daemon did not answer ({last})",
                      "Start Docker (sudo systemctl start docker), or run doctor as a user allowed to "
                      "use Docker.", essential=True)], ""
    version, _, droot = out.strip().partition("|")
    droot = droot.strip() if droot.strip().startswith("/") else ""
    checks = [Check("docker", "Docker", "ok",
                    f"Docker {_token(version, 40)} answers (data root {_token(droot or '?', 200)})")]

    try:
        rc, out, err = env.runner(["docker", "ps", "-a", "--no-trunc", "--filter",
                                   f"label=com.docker.compose.project={COMPOSE_PROJECT}",
                                   "--format", "{{.ID}}"], LIST_TIMEOUT_S)
    except hp.ProbeError as e:
        rc, out, err = 127, "", str(e)
    if rc != 0:
        checks.append(Check("containers", "containers", "unknown",
                            f"could not list this install's containers: {sigs.redact_line(err.strip()[-300:])}",
                            essential=True))
        return checks, droot
    ids = [i for i in (ln.strip() for ln in out.splitlines()) if re.fullmatch(r"[0-9a-f]{12,64}|[A-Za-z0-9_.-]{1,64}", i)]
    if not ids:
        if env_exists:
            checks.append(Check("containers", "containers", "problem",
                                "Correlix is installed (.env exists) but none of its containers exist",
                                "Start it with ./install-correlix.sh start, or re-run the installer."))
        else:
            checks.append(Check("containers", "containers", "ok",
                                "Correlix is not installed here (no containers, no .env)"))
        return checks, droot
    truncated = len(ids) > MAX_CONTAINERS
    ids = ids[:MAX_CONTAINERS]
    try:
        rc, out, err = env.runner(["docker", "inspect", "--format", INSPECT_FORMAT, *ids], LIST_TIMEOUT_S)
    except hp.ProbeError as e:
        rc, out, err = 127, "", str(e)
    if rc != 0:
        checks.append(Check("containers", "containers", "unknown",
                            f"could not inspect this install's containers: {sigs.redact_line(err.strip()[-300:])}",
                            essential=True))
        return checks, droot
    records: list[dict] = []
    for line in out.splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict):
            records.append(rec)
    running = sum(r.get("status") == "running" for r in records)
    summary = f"{len(records)} containers, {running} running"
    if truncated:
        summary += f" (only the first {MAX_CONTAINERS} were examined)"
    checks.append(Check("containers", "containers", "ok" if len(records) == len(ids) else "unknown",
                        summary if len(records) == len(ids) else summary + "; some could not be read",
                        essential=len(records) != len(ids)))

    now = env.wall()
    seen: dict[str, int] = {}
    for rec in sorted(records, key=lambda r: str(r.get("service", ""))):
        service = _token(rec.get("service") or sigs.normalize_service(str(rec.get("name", "?"))), 60)
        seen[service] = seen.get(service, 0) + 1
        cid = f"container:{service}" + (f"#{seen[service]}" if seen[service] > 1 else "")
        title = f"container {service}"
        if env.clock() - start > env.deadline_s:
            checks.append(Check(cid, title, "unknown",
                                f"not examined: the doctor's {int(env.deadline_s)} s time budget ran out",
                                "Run doctor again, or read its log: ./install-correlix.sh logs " + service,
                                essential=True))
            continue
        logs: str | None
        try:
            rc, lout, lerr = env.runner(["docker", "logs", "--tail", str(LOG_LINES), str(rec.get("id", ""))],
                                        DOCKER_TIMEOUT_S)
            logs = (lout + lerr)[-MAX_LOG_BYTES:] if rc == 0 else None
        except hp.ProbeError:
            logs = None
        status, summ, remedy, details = assess_container(rec, logs, now)
        checks.append(Check(cid, title, status, summ, remedy, details))
    return checks, droot


def check_disk(env: DoctorEnv, docker_root: str) -> Check:
    targets: list[tuple[str, Path]] = [("data", hp.nearest_existing_dir(env.root / "data" / "opensearch"))]
    if docker_root:
        targets.append(("docker-root", Path(docker_root)))
    devices: set[int] = set()
    rows: list[dict] = []
    worst = ("ok", "")
    order = {"ok": 0, "warn": 1, "problem": 2}
    for role, path in targets:
        try:
            dev = env.device_of(path)
        except hp.ProbeError:
            dev = None
        if dev is not None and dev in devices:
            continue
        if dev is not None:
            devices.add(dev)
        try:
            total, _used, avail = env.disk_usage(path)
        except hp.ProbeError as e:
            rows.append({"role": role, "path": str(path), "error": str(e)})
            continue
        pct = 0 if total <= 0 else round(100 * (total - avail) / total)
        rows.append({"role": role, "path": str(path), "used_pct": pct,
                     "available_gib": round(avail / 2**30, 1)})
        for limit, status, words in WATERMARKS:
            if pct >= limit:
                if order[status] > order[worst[0]]:
                    worst = (status, f"the {role} filesystem ({path}) is {pct} % full, {words}")
                break
    title = "disk vs OpenSearch watermarks"
    details = {"filesystems": rows}
    measured = [r for r in rows if "used_pct" in r]
    if not measured:
        return Check("disk-watermarks", title, "unknown", "no filesystem could be measured", details=details)
    if worst[0] != "ok":
        return Check("disk-watermarks", title, worst[0], worst[1],
                     "Free space on that filesystem (see `df -h` and `docker system df`). Never delete "
                     "data/opensearch by hand or shrink Kafka retention to make room.", details)
    use = ", ".join(f"{r['role']} {r['used_pct']} %" for r in measured)
    return Check("disk-watermarks", title, "ok", f"{use} used (OpenSearch watermarks 85/90/95 %)",
                 details=details)


def check_journal(env: DoctorEnv) -> Check:
    path = env.root / "data" / "install-timing.json"
    title = "install journal"
    try:
        raw = read_bounded(path, MAX_JOURNAL_BYTES)
    except hp.ProbeError as e:
        return Check("install-journal", title, "warn", str(e))
    if raw is None:
        return Check("install-journal", title, "ok", "no install run has been recorded here")
    try:
        doc = json.loads(raw)
    except ValueError:
        doc = None
    if not isinstance(doc, dict):
        return Check("install-journal", title, "warn", "data/install-timing.json is not a valid record",
                     "It is rewritten by the next install run.")
    stages = []
    for s in doc.get("stages") or []:
        if isinstance(s, dict):
            elapsed = s.get("elapsed_s")
            stages.append({"id": _token(s.get("id", "?"), 40), "status": _token(s.get("status", "?"), 20),
                           "elapsed_s": elapsed if isinstance(elapsed, (int, float)) else None})
    if not stages:
        return Check("install-journal", title, "ok", "no install stages recorded")
    run_status = _token(doc.get("status", "?"), 20)
    when = _token(doc.get("generated_utc", "?"), 40)
    total = doc.get("total_s") if isinstance(doc.get("total_s"), (int, float)) else None
    details = {"status": run_status, "generated_utc": when, "total_s": total, "stages": stages}
    failed = [s["id"] for s in stages if s["status"] == "fail"]
    if run_status == "ok":
        return Check("install-journal", title, "ok",
                     f"the last install run succeeded ({len(stages)} stages, recorded {when})", details=details)
    where = f" at stage {failed[-1]}" if failed else ""
    return Check("install-journal", title, "warn",
                 f"the last install run ended '{run_status}'{where} (recorded {when})",
                 "Re-running the installer is safe; the container checks show what is still wrong.", details)


# ── orchestration ────────────────────────────────────────────────────────────

def run_doctor(env: DoctorEnv) -> Report:
    start = env.clock()
    generated = datetime.fromtimestamp(env.wall(), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    env_check, secret_values, env_exists = check_env(env)
    checks = [check_host_profile(env), check_lock(env), check_wizard_job(env), env_check]
    runtime, docker_root = check_docker_and_containers(env, env_exists, start)
    has_containers = any(c.id.startswith("container:") for c in runtime)
    if not env_exists and has_containers:
        env_check.status = "problem"
        env_check.summary = ".env is missing, but this install's containers exist"
        env_check.remedy = "Restore .env from your backup or re-run the installer; never start the stack without it."
    checks += runtime
    checks += [check_disk(env, docker_root), check_journal(env)]
    clean = [Check(c.id, scrub(c.title, secret_values), c.status, scrub(c.summary, secret_values),
                   scrub(c.remedy, secret_values), _scrub_obj(c.details, secret_values), c.essential)
             for c in checks]
    return Report(generated_utc=generated, checks=clean)


def main(argv: list[str] | None = None, env: DoctorEnv | None = None) -> int:
    ap = argparse.ArgumentParser(prog="install-correlix.sh doctor",
                                 description="Read-only health report of a Correlix install.")
    ap.add_argument("--root", required=True, type=Path)
    ap.add_argument("--bundle-dir", required=True, type=Path)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--deadline-s", type=float, default=DEFAULT_DEADLINE_S)
    args = ap.parse_args(argv)
    if env is None:
        env = default_env(args.root, args.bundle_dir, max(10.0, min(600.0, args.deadline_s)))
    report = run_doctor(env)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.render_text())
    return report.exit_code


if __name__ == "__main__":
    sys.exit(main())
