# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Raw wire frames through the REAL edge, in isolated containers (tracker 387, PR 10).

    sender container --udp/tcp--> syslog-ng (a shipped config dir)
        --relay--> Vector (the shipped syslog_in, syslog_sender, syslog_normalized
                   and syslog_admission_stamp, verbatim from vector.yaml)
        --stdout--> one JSON document per record, what kafka_syslog would publish

Nothing here publishes a host port or touches a running stack: one private docker
network, named per run, removed with its containers. Everything is bounded by a
timeout, and a failure to start says which container failed and why.

This module holds no assertions. tests/test_syslog_edge_framing.py owns them.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import yaml

SYSLOG_NG_IMAGE = "balabit/syslog-ng:4.7.1"
VECTOR_IMAGE = "timberio/vector:0.40.0-alpine"
SYSLOG_PORT = 5514
DOCKER_TIMEOUT_S = 120
START_TIMEOUT_S = 90
RECORD_TIMEOUT_S = 20

#: The aggregator transforms a syslog record passes through, in order. The last one
#: is what `kafka_syslog` serializes onto netops.syslog.
TRANSFORMS = ("syslog_sender", "syslog_normalized", "syslog_admission_stamp")

#: A sender on this private network. The frame is base64 so the shell, docker and
#: python all see the exact bytes, NUL and non-UTF-8 included.
_SENDER = """
import base64, socket, sys, json
print(socket.gethostbyname(socket.gethostname()), flush=True)
for line in sys.stdin:
    job = json.loads(line)
    data = base64.b64decode(job["frame"])
    if job["transport"] == "udp":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.sendto(data, (job["host"], job["port"]))
            print("sent", flush=True)
        except OSError as exc:
            print("refused " + str(exc), flush=True)
        s.close()
    else:
        s = socket.create_connection((job["host"], job["port"]), timeout=10)
        s.sendall(data)
        s.close()
        print("sent", flush=True)
"""


class EdgeError(RuntimeError):
    """The edge could not be brought up or did not answer."""


def _docker(*args: str, timeout: int = DOCKER_TIMEOUT_S,
            check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(["docker", *args], capture_output=True, text=True,
                          errors="replace", timeout=timeout, check=False)
    if check and proc.returncode != 0:
        raise EdgeError(f"docker {' '.join(args[:3])} failed: {proc.stderr.strip()}")
    return proc


def vector_config(vector_yaml: Path) -> dict[str, Any]:
    """A runnable config holding ONLY the shipped syslog stages, unedited."""
    shipped = yaml.safe_load(vector_yaml.read_text(encoding="utf-8"))
    transforms = {name: shipped["transforms"][name] for name in TRANSFORMS}
    source = dict(shipped["sources"]["syslog_in"])
    source.pop("tls", None)   # its values are environment substitutions; see running_edge
    return {
        "enrichment_tables": shipped["enrichment_tables"],
        "sources": {"syslog_in": source},
        "transforms": transforms,
        "sinks": {"out": {
            "type": "console", "inputs": [TRANSFORMS[-1]],
            "encoding": {"codec": "json"}}},
    }


class Edge:
    """One running edge. Use through `running_edge`."""

    def __init__(self, network: str, syslog_ng: str, vector: str, sender_proc: subprocess.Popen[str],
                 sender_ip: str) -> None:
        self.network = network
        self.syslog_ng = syslog_ng
        self.vector = vector
        self._sender = sender_proc
        self.sender_ip = sender_ip
        self._seen = 0

    def _stdout_docs(self) -> list[dict[str, Any]]:
        out = _docker("logs", self.vector, check=True).stdout
        docs: list[dict[str, Any]] = []
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            docs.append(json.loads(line))
        return docs

    def send_raw(self, frame: bytes, transport: str = "udp") -> None:
        job = {"frame": base64.b64encode(frame).decode(), "transport": transport,
               "host": self.syslog_ng, "port": SYSLOG_PORT}
        assert self._sender.stdin is not None and self._sender.stdout is not None
        self._sender.stdin.write(json.dumps(job) + "\n")
        self._sender.stdin.flush()
        ack = self._sender.stdout.readline().strip()
        if not ack.startswith("sent"):
            raise EdgeError(f"the sender did not send: {ack!r}")

    def collect(self, expected: int = 1, timeout_s: float = RECORD_TIMEOUT_S) -> list[dict[str, Any]]:
        """The next `expected` documents. Raises when they do not arrive in time."""
        deadline = time.monotonic() + timeout_s
        docs: list[dict[str, Any]] = []
        while time.monotonic() < deadline:
            docs = self._stdout_docs()
            if len(docs) >= self._seen + expected:
                fresh = docs[self._seen:self._seen + expected]
                self._seen += expected
                return fresh
            time.sleep(0.1)
        raise EdgeError(f"expected {expected} new record(s), have {len(docs) - self._seen}; "
                        f"syslog-ng said:\n{self.syslog_ng_log()[-2000:]}")

    def settle(self, quiet_s: float = 1.0) -> list[dict[str, Any]]:
        """Every record still arriving, for a frame whose record count is the question."""
        last = -1
        docs: list[dict[str, Any]] = []
        while True:
            docs = self._stdout_docs()
            if len(docs) == last:
                fresh = docs[self._seen:]
                self._seen = len(docs)
                return fresh
            last = len(docs)
            time.sleep(quiet_s)

    def send(self, frame: bytes, transport: str = "udp") -> dict[str, Any]:
        self.send_raw(frame, transport)
        return self.collect(1)[0]

    def syslog_ng_log(self) -> str:
        proc = _docker("logs", self.syslog_ng, check=False)
        return proc.stdout + proc.stderr

    def vector_log(self) -> str:
        return _docker("logs", self.vector, check=False).stderr

    def close(self) -> None:
        if self._sender.stdin is not None:
            self._sender.stdin.close()
        try:
            self._sender.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self._sender.kill()
            self._sender.wait(timeout=10)


def _wait_for(pred: Any, what: str, name: str, timeout_s: float = START_TIMEOUT_S) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if pred():
            return
        state = _docker("inspect", "-f", "{{.State.Running}}", name, check=False).stdout.strip()
        if state != "true":
            proc = _docker("logs", name, check=False)
            raise EdgeError(f"{name} exited while waiting for {what}:\n{proc.stdout}{proc.stderr}")
        time.sleep(0.25)
    proc = _docker("logs", name, check=False)
    raise EdgeError(f"{name}: no {what} in {timeout_s}s:\n{proc.stdout}{proc.stderr}")


@contextmanager
def running_edge(config_dir: Path, vector_yaml: Path, variant: str = "syslog-ng.conf",
                 registry: Iterable[tuple[str, str]] = (),
                 tls_dir: Path | None = None) -> Iterator[Edge]:
    """Bring up one edge from `config_dir` (a syslog-ng conf.d) and tear it all down.

    `registry` is the device_tenant table as (identity, tenant_id) rows. `tls_dir`, for
    the TLS variant, holds ca.pem, svid/syslog-ng.{crt,key} and aggregator.{crt,key}.
    """
    run_id = uuid.uuid4().hex[:10]
    network = f"cx-syslog-edge-{run_id}"
    vector_name = f"cx-syslog-edge-vector-{run_id}"
    ng_name = f"cx-syslog-edge-ng-{run_id}"
    sender_name = f"cx-syslog-edge-sender-{run_id}"
    work = Path(tempfile.mkdtemp(prefix="cx-syslog-edge-"))
    sender: subprocess.Popen[str] | None = None
    created: list[str] = []
    try:
        cfg = vector_config(vector_yaml)
        if tls_dir is not None:
            cfg["sources"]["syslog_in"]["tls"] = {
                "enabled": True, "crt_file": "/tls/aggregator.crt", "key_file": "/tls/aggregator.key",
                "ca_file": "/tls/ca.pem", "verify_certificate": True}
        (work / "vector.yaml").write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
        enrich = work / "enrichment"
        enrich.mkdir()
        rows = ["identity,tenant_id"] + [f"{a},{b}" for a, b in registry]
        (enrich / "device_tenant.csv").write_text("\n".join(rows) + "\n", encoding="utf-8")
        for path in (work, enrich):
            os.chmod(path, 0o755)
        os.chmod(enrich / "device_tenant.csv", 0o644)
        os.chmod(work / "vector.yaml", 0o644)
        spool = work / "spool"
        spool.mkdir()
        os.chmod(spool, 0o777)

        _docker("network", "create", "--internal", network)
        vector_args = ["run", "-d", "--name", vector_name, "--network", network,
                       "--network-alias", "vector-aggregator",
                       "-v", f"{work / 'vector.yaml'}:/etc/vector/vector.yaml:ro",
                       "-v", f"{enrich}:/etc/vector/enrichment:ro"]
        if tls_dir is not None:
            vector_args += ["-v", f"{tls_dir}:/tls:ro"]
        _docker(*vector_args, "--entrypoint", "vector", VECTOR_IMAGE,
                "--config", "/etc/vector/vector.yaml")
        created.append(vector_name)
        _wait_for(lambda: "Vector has started" in _docker("logs", vector_name, check=False).stderr,
                  "Vector start", vector_name)

        ng_args = ["run", "-d", "--name", ng_name, "--network", network,
                   "--entrypoint", "/usr/sbin/syslog-ng", "-e", f"SYSLOG_PORT={SYSLOG_PORT}",
                   "-v", f"{config_dir}:/etc/syslog-ng/conf.d:ro",
                   "-v", f"{spool}:/var/lib/syslog-ng"]
        if tls_dir is not None:
            ng_args += ["-v", f"{tls_dir}/ca.pem:/tls/ca.pem:ro",
                        "-v", f"{tls_dir}/svid:/tls/svid:ro"]
        _docker(*ng_args, SYSLOG_NG_IMAGE, "-F", "-e", "-f", f"/etc/syslog-ng/conf.d/{variant}")
        created.append(ng_name)
        def _ng_started() -> bool:
            proc = _docker("logs", ng_name, check=False)
            return "syslog-ng starting up" in proc.stdout + proc.stderr

        _wait_for(_ng_started, "syslog-ng start", ng_name)

        sender = subprocess.Popen(
            ["docker", "run", "--rm", "-i", "--name", sender_name, "--network", network,
             "--entrypoint", "python3", SYSLOG_NG_IMAGE, "-c", _SENDER],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert sender.stdout is not None
        ip = sender.stdout.readline().strip()
        if not ip:
            raise EdgeError(f"the sender did not start: {sender.stderr.read() if sender.stderr else ''}")
        edge = Edge(network, ng_name, vector_name, sender, ip)
        try:
            yield edge
        finally:
            edge.close()
    finally:
        if sender is not None and sender.poll() is None:
            sender.kill()
            sender.wait(timeout=10)
        problems: list[str] = []
        for name in created:
            proc = _docker("rm", "-f", name, check=False)
            if proc.returncode != 0:
                problems.append(f"{name}: {proc.stderr.strip()}")
        proc = _docker("network", "rm", network, check=False)
        if proc.returncode != 0 and "not found" not in proc.stderr:
            problems.append(f"{network}: {proc.stderr.strip()}")
        # Root-owned spool files from the container: removed through a container so a
        # non-root test runner can still delete the tree.
        cleanup = subprocess.run(
            ["docker", "run", "--rm", "-v", f"{work}:/w", "--entrypoint", "rm", SYSLOG_NG_IMAGE,
             "-rf", "/w/spool"],
            capture_output=True, text=True, timeout=DOCKER_TIMEOUT_S, check=False)
        if cleanup.returncode != 0:
            problems.append(f"spool cleanup: {cleanup.stderr.strip()}")
        shutil.rmtree(work, ignore_errors=False)
        if problems:
            raise EdgeError("edge teardown left things behind: " + "; ".join(problems))
