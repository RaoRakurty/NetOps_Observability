# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Run an install and SIGKILL a store between TLS phase A and phase B.

Installer self-healing FMEA 2026-09-15 §3.7 T1 (the .123 failure): the phase-A
postgres was stopped uncleanly at the phase A→B recreate, its crash recovery
outlived a fixed health gate, and the install failed. Commit ffbb4055 made the
installer wait through recovery. This wrapper is the CI proof: it streams the
install's output, and at the moment phase A has converged and the mint has
finished — install.py's `@CX@ {"kind":"stage","id":"mint",...,"status":"ok"}`
marker, emitted together with the `up-b` start — it runs
`docker kill -s KILL` on the store's container, before stop_stores_cleanly
can stop it cleanly. The install must still exit 0.

A chaos leg that injected no chaos is a test that lied, so this exits non-zero
when:
  * the trigger never fired (not a TLS install, --progress-json missing, or the
    install died before phase B)            → exit 3
  * the marker arrived before phase A (`up-a`) was seen to close ok → exit 3
  * the kill did not land: no running container, `docker kill` failed, or the
    container did not end `exited` with code 137 (e.g. the clean stop won the
    race)                                     → exit 4
Otherwise it exits with the install's own exit code (124 on --timeout).

Evidence (`--evidence FILE`, JSON): the killed container id and name, its state
after the kill, the stage it was killed after, and UTC timestamps — the later
assertion step uses it to look for crash recovery in the new container's log.

The container id is resolved when phase A closes, so the kill itself is one
`docker kill` call: the window between the marker and stop_stores_cleanly's
first `docker compose ps` is well under a second.

Usage:
  python3 chaos_install.py --log LOG --evidence JSON [--service postgres] \\
      -- sudo -E python3 scripts/install.py --tls=yes --progress-json

Standard library only; tested by tests/test_ci_chaos_install.py.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import IO

sys.path.insert(0, str(Path(__file__).resolve().parent))
from install_markers import parse_marker_line

DOCKER_TIMEOUT_S = 30
SIGKILL_EXIT = 137
EXIT_NOT_TRIGGERED = 3
EXIT_KILL_DID_NOT_LAND = 4
EXIT_TIMEOUT = 124

Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class Trigger:
    """Marker state machine. `feed` returns "resolve" once phase A has closed
    ok, "kill" once the mint has closed ok (or phase B has started), else None.
    Each action is returned at most once."""

    def __init__(self) -> None:
        self.phase_a_ok = False
        self.resolved = False
        self.fired = False
        self.fired_on = ""
        self.error = ""

    def feed(self, marker: dict) -> str | None:
        if marker.get("kind") != "stage" or self.fired:
            return None
        sid, status = marker.get("id"), marker.get("status")
        if sid == "up-a" and status == "ok":
            self.phase_a_ok = True
            if not self.resolved:
                self.resolved = True
                return "resolve"
            return None
        if (sid == "mint" and status == "ok") or (sid == "up-b" and status == "start"):
            self.fired = True
            self.fired_on = f"{sid}:{status}"
            if not self.phase_a_ok:
                self.error = (f"saw {sid} {status} before phase A (up-a) closed ok — "
                              "cannot claim the kill landed between the phases")
                return None
            return "kill"
        return None


@dataclass
class Evidence:
    service: str
    triggered_on: str = ""
    container_id: str = ""
    container_name: str = ""
    resolved_utc: str = ""
    killed_utc: str = ""
    kill_rc: int | None = None
    kill_stderr: str = ""
    state_after: dict = field(default_factory=dict)
    error: str = ""

    def landed(self) -> bool:
        return (not self.error and self.kill_rc == 0
                and self.state_after.get("Status") == "exited"
                and self.state_after.get("ExitCode") == SIGKILL_EXIT)


class Docker:
    def __init__(self, project: str, service: str, run: Runner,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.project, self.service, self.run, self.sleep = project, service, run, sleep

    def _call(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        try:
            return self.run(argv)
        except (OSError, subprocess.SubprocessError) as e:
            return subprocess.CompletedProcess(argv, 126, "", f"{type(e).__name__}: {e}")

    def resolve(self) -> tuple[str, str]:
        """(id, error) of the service's RUNNING container."""
        r = self._call(["docker", "ps", "-q", "--no-trunc",
                        "--filter", f"label=com.docker.compose.project={self.project}",
                        "--filter", f"label=com.docker.compose.service={self.service}",
                        "--filter", "status=running"])
        if r.returncode != 0:
            return "", f"docker ps exited {r.returncode}: {r.stderr.strip()}"
        ids = r.stdout.split()
        if len(ids) != 1:
            return "", (f"expected exactly one running {self.service} container, "
                        f"found {len(ids)}")
        return ids[0], ""

    def kill(self, cid: str) -> subprocess.CompletedProcess[str]:
        return self._call(["docker", "kill", "-s", "KILL", cid])

    def state(self, cid: str, settle_s: float = 10.0) -> dict:
        """State after the kill; polls briefly while the daemon records the exit."""
        deadline = settle_s
        waited = 0.0
        while True:
            r = self._call(["docker", "inspect", "--format",
                            "{{json .State}}|{{.Name}}", cid])
            if r.returncode != 0:
                return {"error": f"docker inspect exited {r.returncode}: "
                                 f"{r.stderr.strip()}"}
            raw, _, name = r.stdout.strip().rpartition("|")
            try:
                st = json.loads(raw)
            except ValueError:
                return {"error": f"unparseable docker inspect output: {r.stdout[:200]}"}
            st = st if isinstance(st, dict) else {}
            st["Name"] = name.lstrip("/")
            if st.get("Status") != "running" or waited >= deadline:
                return st
            self.sleep(0.5)
            waited += 0.5


def watch(lines: Iterable[str], sink: Callable[[str], None], trigger: Trigger,
          docker: Docker, evidence: Evidence) -> None:
    """Stream every line to `sink`; act on the markers."""
    cid = ""
    for line in lines:
        sink(line)
        marker = parse_marker_line(line)
        if marker is None:
            continue
        action = trigger.feed(marker)
        if trigger.error and not evidence.error:
            evidence.error = trigger.error
        if action == "resolve":
            cid, err = docker.resolve()
            evidence.resolved_utc = _utc()
            if err:
                sink(f"[chaos] could not pre-resolve {docker.service} at phase A: "
                     f"{err} (will retry at the trigger)\n")
        elif action == "kill":
            evidence.triggered_on = trigger.fired_on
            if not cid:
                cid, err = docker.resolve()
                if err:
                    evidence.error = f"no container to kill: {err}"
                    sink(f"[chaos] {evidence.error}\n")
                    continue
            r = docker.kill(cid)
            evidence.killed_utc = _utc()
            evidence.container_id = cid
            evidence.kill_rc = r.returncode
            evidence.kill_stderr = r.stderr.strip()
            evidence.state_after = docker.state(cid)
            evidence.container_name = str(evidence.state_after.get("Name", ""))
            sink(f"[chaos] docker kill -s KILL {docker.service} ({cid[:12]}) on "
                 f"{trigger.fired_on}: rc={r.returncode} state="
                 f"{evidence.state_after.get('Status')} exit="
                 f"{evidence.state_after.get('ExitCode')}\n")


def verdict(install_rc: int, trigger: Trigger, evidence: Evidence) -> tuple[int, str]:
    if install_rc == EXIT_TIMEOUT:
        return EXIT_TIMEOUT, "install timed out"
    if not trigger.fired:
        msg = ("chaos was never injected: no mint-ok / up-b-start marker "
               "(not a TLS install, --progress-json missing, or the install ended "
               "before phase B)")
        return (install_rc or EXIT_NOT_TRIGGERED), msg
    if trigger.error:
        return (install_rc or EXIT_NOT_TRIGGERED), trigger.error
    if not evidence.landed():
        msg = (f"the kill did not land: {evidence.error or ''} kill rc="
               f"{evidence.kill_rc} stderr={evidence.kill_stderr!r} state="
               f"{evidence.state_after.get('Status')} exit="
               f"{evidence.state_after.get('ExitCode')} (expected exited/"
               f"{SIGKILL_EXIT})").replace("  ", " ")
        return (install_rc or EXIT_KILL_DID_NOT_LAND), msg
    if install_rc != 0:
        return install_rc, (f"{evidence.service} was SIGKILLed between phase A and B "
                            f"and the install FAILED (exit {install_rc}) — it did "
                            "not heal")
    return 0, (f"{evidence.service} was SIGKILLed between phase A and B and the "
               "install still exited 0")


def main(argv: Sequence[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if "--" not in raw:
        print("usage: chaos_install.py [options] -- <install command...>", file=sys.stderr)
        return 2
    split = raw.index("--")
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--log", required=True)
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--project", default="netops")
    ap.add_argument("--service", default="postgres")
    ap.add_argument("--timeout-s", type=int, default=80 * 60)
    args = ap.parse_args(raw[:split])
    cmd = raw[split + 1:]
    if not cmd:
        print("no install command after --", file=sys.stderr)
        return 2

    def run(a: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(list(a), capture_output=True, text=True,
                              timeout=DOCKER_TIMEOUT_S, check=False)

    Path(args.log).parent.mkdir(parents=True, exist_ok=True)
    Path(args.evidence).parent.mkdir(parents=True, exist_ok=True)
    trigger = Trigger()
    evidence = Evidence(service=args.service)
    docker = Docker(args.project, args.service, run)
    timed_out = threading.Event()

    with open(args.log, "w", encoding="utf-8") as log:
        def sink(line: str, _log: IO[str] = log) -> None:
            sys.stdout.write(line)
            sys.stdout.flush()
            _log.write(line)
            _log.flush()

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True,
                                    errors="replace", bufsize=1)
        except OSError as e:
            print(f"could not start the install: {e}", file=sys.stderr)
            return 2

        def on_timeout() -> None:
            timed_out.set()
            proc.kill()

        killer = threading.Timer(args.timeout_s, on_timeout)
        killer.start()
        try:
            assert proc.stdout is not None
            watch(proc.stdout, sink, trigger, docker, evidence)
            rc = proc.wait()
        finally:
            killer.cancel()
    if timed_out.is_set():
        rc = EXIT_TIMEOUT

    try:
        Path(args.evidence).write_text(json.dumps(
            {**evidence.__dict__, "install_rc": rc, "landed": evidence.landed()},
            indent=2) + "\n", encoding="utf-8")
    except OSError as e:
        print(f"could not write the evidence file {args.evidence}: {e}", file=sys.stderr)
        return 2

    code, msg = verdict(rc, trigger, evidence)
    stream = sys.stdout if code == 0 else sys.stderr
    print(f"[chaos] {'PASS' if code == 0 else 'FAIL'}: {msg}", file=stream)
    return code


if __name__ == "__main__":
    sys.exit(main())
