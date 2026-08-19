#!/usr/bin/env python3
"""scale-miniladder.py — G2 self-judging nightly scale-regression harness.

Proves, on EVERY run and on ANY hardware, that the stack still holds the
RELATIVE/invariant properties whose loss produced this release's three scale
defects — without asserting a single absolute-throughput number:

  1. Onboarding stays LINEAR      (would have caught the O(N^2) per-device
                                   persistence collapse — fleet rewrite on
                                   every create; fixed in f65b9ac0).
  2. Correlation lag DRAINS       (would have caught "lag never drains":
                                   after a 10x-nominal burst stops, consumer
                                   lag must return to baseline within a
                                   bounded multiple of the burst duration).
  3. NOTHING is lost silently     (would have caught the 238k silent
                                   DLQ-drop: every injected event is either
                                   persisted, in a DLQ we can count, or in an
                                   explicitly-counted rejection — an
                                   unexplained delta FAILS the run).

Phases (each emits PASS/FAIL + evidence into the run dir):
  preflight   stack up + healthy (watchdog-style container checks, API login,
              ACTIVE bus consumers — a broker that authenticates but denies
              its consumers, as after the 2026-08-16 wiped-ACL incident, fails
              HERE, not 40 minutes in) and baseline capture: per-container
              RSS, Kafka end offsets + consumer-group lag, ClickHouse row
              counts, VictoriaMetrics active series, correlation durability
              counters, Vector loss counters.
  onboard     create N devices via the API (names `mlx-<runid>-NNNNN`,
              addresses in 198.18/15 — RFC 2544 benchmark space, unroutable
              on purpose). Creation rate over the LAST window must be
              >= linearity-floor x the FIRST window's rate.
  burst       gate on registry propagation (created devices must reach the
              correlation engine's identity registry, else every injected
              event is tenant-refused into the DLQ), prove the pipeline with
              one canary event, then inject syslog at --eps for
              --burst-minutes via the broker's console producer (mTLS
              listener on the TLS variant), keyed to the created devices with
              real mnemonics (%LINK-3-UPDOWN).
  drain       consumer lag must return to <= baseline + epsilon within
              --drain-factor x burst duration; the lag curve is recorded.
  accounting  injected == OpenSearch-persisted (exact, hostname-prefix count)
              + run-attributable DLQ lines + explicitly-counted Vector loss.
              Plus: every burst device appears in corr_signals (silent
              per-device eviction check) and quarantine WRITE failures must
              not move (the metric-less 238k-drop signal, healthz-only).
  memflat     leak slope: end-of-run RSS per key container <= its END-OF-BURST
              (warm) RSS x --mem-factor, with a 64 MiB jitter floor — a leak
              keeps climbing after input stops, a warmed cache does not. PLUS
              the OOM path: no key container above --mem-headroom-percent of
              its own plan-sized cap. The cold-baseline->warm step is recorded
              as evidence only (a 2-min burst cannot separate first-touch cache
              materialization from a slow leak — that is the lab run + soak).
  cleanup     ALWAYS runs (also on failure/^C): delete every created device
              and VERIFY zero remain; purge run-tagged telemetry from
              ClickHouse (corr_signals) and OpenSearch (syslog lane) so
              `clean-slate.sh --verify` still passes after a run. The stack
              is left as found.
  report      report.md + report.json in the run dir; exit 0 only if every
              phase passed.

Usage:
  scale-miniladder.py [--devices N] [--burst-minutes M] [--eps R] [flags]
  scale-miniladder.py --dry-run          # print the full plan, touch nothing
  scale-miniladder.py --help

Credentials (never on argv, never logged): admin login is read from
MLX_ADMIN_USER / MLX_ADMIN_PASSWORD when set, else from ADMIN_USERNAME /
ADMIN_INITIAL_PASSWORD in --env-file (deployment/docker/.env) — the same
source clean-slate.sh --verify uses. OpenSearch service passwords
(OS_API_PASSWORD / OS_BOOTSTRAP_PASSWORD) come from the same file and ride a
curl config on stdin inside the container, exactly like
docs/ops/OBSERVABILITY_AUDIT.md prescribes.

Nightly cron (lab host). Cron's environment is hostile (CLAUDE.md 16.2): PATH
is /usr/bin:/bin, no profile — this script sets its own PATH and needs only
docker + python3. Log to the run root; the summary heartbeat
(<run-root>/last-run.json) is refreshed every run so "the job stopped
running" is itself detectable by the watchdog. Sample line (do NOT install
blindly — pick the hour your lab is idle):

  17 3 * * * /usr/bin/python3 /home/rao/Projects/NetOps_Observability/NetOps_Observability/scripts/scale-miniladder.py --devices 1000 --burst-minutes 5 >> /home/rao/Projects/NetOps_Observability/NetOps_Observability/data/miniladder/cron.log 2>&1

CI feasibility (Deliverable-2 verdict, 2026-08-16): the full TLS stack DOES
boot on GH-hosted runners — .github/workflows/fresh-install-integrity.yml's
`tls-install-boot` job runs `install.py --tls=yes` end-to-end on
ubuntu-latest and asserts the mesh serves. A reduced nightly profile
(200 devices, 2-minute burst) therefore reuses that bring-up in
.github/workflows/scale-miniladder-nightly.yml. The FULL G2 gate
(1000 devices, 5-minute burst) stays on the lab host via the cron line above:
GH runners are 4-vCPU/16 GiB shared VMs whose absolute numbers are
meaningless and whose 6-hour cap the L1-scale run can approach — the CI leg
guards the invariants at small scale, the lab leg is the GA evidence.

Exit codes: 0 = all phases PASS; 1 = any phase FAILED (report still written);
2 = aborted before touching the stack (usage / preflight refusal).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import signal
import string
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# docker stats MemUsage units. Module scope (a pure constant table): as a class
# attribute ruff RUF012 flags the mutable default, and scripts/ is under the
# pinned-ruff blocking gate (fresh-install-integrity `scripts-lint`).
_MEM_UNITS: dict[str, int] = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3,
                              "TiB": 1024**4, "kB": 1000, "MB": 1000**2, "GB": 1000**3}


# Cron-proof PATH (CLAUDE.md 16.2): docker lives in /usr/bin or /usr/local/bin
# on supported hosts; never rely on an interactive profile. APPLIED IN main(),
# not at import: as module-scope code it leaked into every process that merely
# IMPORTED this file for its parsers — which hid the developer's ~/.local/bin
# and made the shellcheck-based suites fail with "No such file or directory:
# shellcheck" whenever a harness test was collected in the same pytest run.
CRON_PATH = "/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)

DOCKER_TIMEOUT = 30          # bound EVERY docker call (16.3) — a wedged dockerd
KAFKA_TOOL_TIMEOUT = 90      # JVM tools (console producer, consumer-groups)
HTTP_TIMEOUT = 15
MUTATION_TIMEOUT = 180       # ClickHouse ALTER DELETE settle bound

# Containers whose memory growth is asserted in memflat (compose service names).
MEM_SERVICES = [
    "api", "clickhouse", "correlation", "kafka", "opensearch",
    "vector-aggregator", "vector-router", "victoria",
]

# Services that must be running (and healthy where a healthcheck exists) for
# the run to mean anything. Subset of the watchdog's list: only what the
# harness actually exercises — optional profiles (grafana, osd, exporters)
# are the watchdog's job, not a scale gate.
REQUIRED_SERVICES = [
    "api", "clickhouse", "correlation", "kafka", "nginx", "opensearch",
    "postgres", "vector-aggregator", "vector-router", "victoria",
]


def log(msg: str) -> None:
    print(f"miniladder: {msg}", flush=True)


def warn(msg: str) -> None:
    print(f"miniladder: WARNING: {msg}", file=sys.stderr, flush=True)


def die(msg: str, code: int = 2) -> None:
    print(f"miniladder: ERROR: {msg}", file=sys.stderr, flush=True)
    sys.exit(code)


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run(cmd: list[str], timeout: int, input_text: str | None = None) -> tuple[int, str, str]:
    """Bounded subprocess. Never raises on non-zero exit — callers must look
    at rc and REPORT stderr (16.1: no swallowed errors)."""
    try:
        p = subprocess.run(
            cmd, input=input_text, capture_output=True, text=True,
            timeout=timeout, check=False,
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s: {' '.join(cmd[:4])} ..."
    except FileNotFoundError as exc:
        return 127, "", str(exc)


def env_get(env_file: str, key: str) -> str:
    """First KEY= value from the compose .env. Missing file/key -> '' (callers
    decide whether empty is fatal)."""
    try:
        with open(env_file, encoding="utf-8") as f:
            for line in f:
                if line.startswith(key + "="):
                    return line.rstrip("\n").split("=", 1)[1]
    except OSError:
        pass
    return ""


class Stack:
    """Access layer for the live stack: API, broker, stores, metrics.
    Every call is bounded; every failure carries its stderr."""

    def __init__(self, env_file: str, base_url: str, project: str):
        self.env_file = env_file
        self.project = project
        self.base_url = base_url.rstrip("/")
        compose_files = env_get(env_file, "COMPOSE_FILE")
        self.tls = "compose.tls.yml" in compose_files
        self.token = ""
        self._cids: dict[str, str] = {}

    # -- containers ---------------------------------------------------------
    def cid(self, service: str) -> str:
        if service not in self._cids:
            rc, out, err = run(
                ["docker", "ps", "-q",
                 "--filter", f"label=com.docker.compose.project={self.project}",
                 "--filter", f"label=com.docker.compose.service={service}"],
                DOCKER_TIMEOUT)
            if rc != 0:
                warn(f"docker ps for {service} failed: {err.strip()}")
            self._cids[service] = out.split()[0] if out.split() else ""
        return self._cids[service]

    def service_states(self) -> list[dict]:
        rc, out, err = run(
            ["docker", "ps", "-a",
             "--filter", f"label=com.docker.compose.project={self.project}",
             "--format", "{{.Label \"com.docker.compose.service\"}}\t{{.ID}}"],
            DOCKER_TIMEOUT)
        if rc != 0:
            warn(f"docker ps -a failed: {err.strip()}")
            return []
        rows = []
        for line in out.splitlines():
            if "\t" not in line:
                continue
            svc, cid = line.split("\t", 1)
            rc2, out2, err2 = run(
                ["docker", "inspect", "--format",
                 "{{.State.Status}}\t{{if .State.Health}}{{.State.Health.Status}}{{end}}\t{{.State.ExitCode}}",
                 cid.strip()], DOCKER_TIMEOUT)
            if rc2 != 0:
                warn(f"docker inspect {svc} failed: {err2.strip()}")
                continue
            parts = (out2.strip() + "\t\t").split("\t")
            rows.append({"service": svc, "status": parts[0],
                         "health": parts[1], "exit_code": parts[2]})
        return rows

    @staticmethod
    def _mem_bytes(cell: str) -> int:
        m = re.match(r"([0-9.]+)\s*([A-Za-z]+)", cell.strip())
        if m and m.group(2) in _MEM_UNITS:
            return int(float(m.group(1)) * _MEM_UNITS[m.group(2)])
        return -1

    def mem_stats(self) -> dict[str, dict]:
        """Per-container {"used","limit"} bytes via docker stats.

        The LIMIT matters as much as the usage: it is the only self-relative
        yardstick for "is this container heading for an OOM kill" that holds on
        any hardware — the resource plan sizes it per host (#102), so a fixed
        MiB threshold would be a lie on the next box."""
        rc, out, err = run(
            ["docker", "stats", "--no-stream",
             "--format", "{{.Name}}\t{{.MemUsage}}"], 60)
        if rc != 0:
            warn(f"docker stats failed: {err.strip()}")
            return {}
        stats: dict[str, dict] = {}
        for line in out.splitlines():
            if "\t" not in line:
                continue
            name, mem = line.split("\t", 1)
            used, _, limit = mem.partition("/")
            u = self._mem_bytes(used)
            if u >= 0:
                stats[name] = {"used": u, "limit": self._mem_bytes(limit)}
        return stats

    def mem_sample(self) -> dict[str, int]:
        """Per-container RSS-ish working set in bytes (usage only)."""
        return {n: v["used"] for n, v in self.mem_stats().items()}

    # -- API ----------------------------------------------------------------
    def login(self) -> None:
        user = os.environ.get("MLX_ADMIN_USER") or env_get(self.env_file, "ADMIN_USERNAME")
        pw = os.environ.get("MLX_ADMIN_PASSWORD") or env_get(self.env_file, "ADMIN_INITIAL_PASSWORD")
        if not user or not pw:
            raise RuntimeError(
                "no admin credentials: set MLX_ADMIN_USER/MLX_ADMIN_PASSWORD or "
                f"provide ADMIN_USERNAME/ADMIN_INITIAL_PASSWORD in {self.env_file}")
        body = json.dumps({"username": user, "password": pw}).encode()
        req = urllib.request.Request(
            f"{self.base_url}/api/auth/login", data=body,
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            tok = json.load(r).get("token", "")
        if not tok:
            raise RuntimeError("API login returned no token (password rotated since install?)")
        self.token = tok

    def api(self, method: str, path: str, body: dict | None = None) -> tuple[int, object]:
        """Authenticated API call; re-logins ONCE on 401 (1h token TTL vs
        multi-phase runs). Returns (status, parsed-json-or-text)."""
        for attempt in (0, 1):
            data = json.dumps(body).encode() if body is not None else None
            req = urllib.request.Request(
                self.base_url + path, data=data, method=method,
                headers={"Authorization": f"Bearer {self.token}",
                         "Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
                    raw = r.read()
                    try:
                        return r.status, json.loads(raw) if raw else {}
                    except json.JSONDecodeError:
                        return r.status, raw.decode(errors="replace")
            except urllib.error.HTTPError as e:
                if e.code == 401 and attempt == 0:
                    self.login()
                    continue
                return e.code, e.read().decode(errors="replace")[:300]
        return 0, "unreachable"

    # -- Kafka --------------------------------------------------------------
    def _kafka_conn(self, config_flag: str = "--command-config") -> list[str]:
        """Connection args for the in-container Kafka CLI tools. The admin
        tools take --command-config; the console producer alone spells it
        --producer.config (same SSL client config either way)."""
        if self.tls:
            return ["--bootstrap-server", "kafka:9094",
                    config_flag, "/tmp/kafka-tls/admin.properties"]
        return ["--bootstrap-server", "kafka:9092"]

    def kafka_tool(self, tool: str, args: list[str], input_text: str | None = None,
                   timeout: int = KAFKA_TOOL_TIMEOUT,
                   config_flag: str = "--command-config") -> tuple[int, str, str]:
        kc = self.cid("kafka")
        if not kc:
            return 1, "", f"no running kafka container in project {self.project}"
        cmd = ["docker", "exec"]
        if input_text is not None:
            cmd.append("-i")
        cmd += [kc, f"/opt/kafka/bin/{tool}"] + self._kafka_conn(config_flag) + args
        return run(cmd, timeout, input_text)

    def end_offset(self, topic: str) -> int:
        rc, out, err = self.kafka_tool(
            "kafka-get-offsets.sh", ["--topic-partitions", f"{topic}:0"])
        if rc != 0:
            warn(f"kafka-get-offsets {topic} failed: {err.strip()[:200]}")
            return -1
        for line in out.splitlines():
            parts = line.strip().split(":")
            if len(parts) == 3 and parts[0] == topic:
                return int(parts[2])
        return -1

    def group_lag(self, group: str) -> dict:
        """{topic: {current,end,lag}}, plus `_total` lag, `_members` count,
        `_rows` (describe rows seen) and `_uncommitted` (partitions a member
        holds but has never committed).

        A group with committed offsets but zero MEMBERS is a dead consumer —
        exactly the wiped-ACL failure shape.

        ####################################################################
        # MEMBERSHIP IS PARSED INDEPENDENTLY OF LAG. DO NOT RE-COUPLE THEM.
        #
        # `kafka-consumer-groups.sh --describe` prints `-` in CURRENT-OFFSET
        # AND LAG for a partition a LIVE member has been assigned but has not
        # committed yet, while CONSUMER-ID carries a real id. Captured live
        # (2026-08-17, apache/kafka 4.1.1):
        #   GROUP  TOPIC  PARTITION CURRENT-OFFSET LOG-END-OFFSET LAG CONSUMER-ID …
        #   probe… netops.verification 0  -   0   -   console-consumer-c3be… …
        #
        # The first version of this parser did `int(f[5])` FIRST and
        # `continue`d on ValueError, so every such row was dropped before the
        # member count — the group read as `{_total: 0, _members: 0}`, which
        # is byte-identical to the dead-consumer verdict. On the lab host that
        # never showed: traffic had always committed offsets by run time. In
        # CI it is the NORMAL state of a fresh install (nothing produced yet,
        # correlation commits manually at N=100/T=5s, Vector commits on
        # consume) — it failed run 31991056443's preflight with
        # "netops-correlation has NO active consumer" while every container
        # was Up+healthy and install.py's own gate had just PASSED on the
        # same broker 27s earlier.
        ####################################################################
        """
        rc, out, err = self.kafka_tool(
            "kafka-consumer-groups.sh", ["--describe", "--group", group])
        if rc != 0:
            return {"_error": err.strip()[:300], "_total": -1, "_members": 0,
                    "_rows": 0, "_uncommitted": 0}

        def num(cell: str) -> int | None:
            """Numeric cell, or None for Kafka's `-` (no committed offset)."""
            return int(cell) if cell.isdigit() else None

        topics: dict[str, dict] = {}
        total = members = rows = uncommitted = 0
        for line in out.splitlines():
            f = line.split()
            if len(f) < 7 or f[0] != group:
                continue
            rows += 1
            # MEMBERSHIP FIRST — it does not depend on any offset being set.
            if f[6] != "-":
                members += 1
            cur, end, lag = num(f[3]), num(f[4]), num(f[5])
            if lag is None:
                uncommitted += 1
            # Aggregate across partitions of the same topic (single-partition
            # today, but a repartitioned topic must not silently lose lag).
            t = topics.setdefault(f[1], {"current": -1, "end": -1, "lag": 0})
            if cur is not None:
                t["current"] = cur if t["current"] < 0 else min(t["current"], cur)
            if end is not None:
                t["end"] = max(t["end"], end)
            if lag is not None:
                t["lag"] += max(lag, 0)
                total += max(lag, 0)
        topics["_total"] = total
        topics["_members"] = members
        topics["_rows"] = rows
        topics["_uncommitted"] = uncommitted
        return topics

    def produce(self, topic: str, lines: list[str]) -> tuple[bool, str]:
        payload = "\n".join(lines) + "\n"
        # Producer time scales with payload; bound generously but finitely.
        rc, _, err = self.kafka_tool(
            "kafka-console-producer.sh", ["--topic", topic],
            input_text=payload, timeout=max(KAFKA_TOOL_TIMEOUT, 30 + len(lines) // 500),
            config_flag="--producer.config")
        if rc != 0:
            return False, err.strip()[:400]
        return True, ""

    # -- ClickHouse ---------------------------------------------------------
    def ch(self, query: str, timeout: int = 60) -> tuple[bool, str]:
        cc = self.cid("clickhouse")
        if not cc:
            return False, "no running clickhouse container"
        rc, out, err = run(
            ["docker", "exec", cc, "clickhouse-client", "--query",
             query + " SETTINGS tenant_scope='__all__'"], timeout)
        if rc != 0:
            return False, err.strip()[:400]
        return True, out.strip()

    def ch_mutation(self, query: str) -> tuple[bool, str]:
        """ALTER ... DELETE with synchronous mutation (bounded)."""
        cc = self.cid("clickhouse")
        if not cc:
            return False, "no running clickhouse container"
        rc, out, err = run(
            ["docker", "exec", cc, "clickhouse-client", "--query",
             query + " SETTINGS tenant_scope='__all__', mutations_sync=1"],
            MUTATION_TIMEOUT)
        if rc != 0:
            return False, err.strip()[:400]
        return True, out.strip()

    # -- OpenSearch ---------------------------------------------------------
    def os_req(self, role_env: str, user: str, url_path: str,
               body: dict | None = None, timeout: int = 25) -> tuple[bool, dict | str]:
        """In-container curl with creds via a stdin curl config, never argv
        (OBSERVABILITY_AUDIT.md section 0). TLS variant only differs in
        scheme/CA/creds — both handled here."""
        oc = self.cid("opensearch")
        if not oc:
            return False, "no running opensearch container"
        if self.tls:
            pw = env_get(self.env_file, role_env)
            if not pw:
                return False, f"{role_env} missing from {self.env_file}"
            cfg = (f'url = "https://opensearch:9200{url_path}"\n'
                   f"max-time = {timeout}\nsilent\n"
                   f'cacert = "/usr/share/opensearch/config/tls/ca.pem"\n'
                   f'user = "{user}:{pw}"\n')
        else:
            cfg = f'url = "http://localhost:9200{url_path}"\nmax-time = {timeout}\nsilent\n'
        if body is not None:
            data = json.dumps(body).replace("\\", "\\\\").replace('"', '\\"')
            cfg += f'header = "Content-Type: application/json"\ndata = "{data}"\n'
        rc, out, err = run(["docker", "exec", "-i", oc, "curl", "--config", "-"],
                           timeout + 35, cfg)
        if rc != 0:
            return False, (err or out).strip()[:400]
        try:
            return True, json.loads(out)
        except json.JSONDecodeError:
            return False, out.strip()[:400]

    def os_count(self, index: str, prefix_field: str, prefix: str) -> int:
        ok, res = self.os_req(
            "OS_API_PASSWORD", "svc_api", f"/{index}/_count",
            {"query": {"prefix": {prefix_field: prefix}}})
        if not ok or not isinstance(res, dict):
            warn(f"OpenSearch count on {index} failed: {res}")
            return -1
        return int(res.get("count", -1))

    # -- correlation service ------------------------------------------------
    def corr_get(self, path: str) -> tuple[bool, str]:
        cc = self.cid("correlation")
        if not cc:
            return False, "no running correlation container"
        if self.tls:
            py = ("import urllib.request,ssl;"
                  "ctx=ssl.create_default_context(cafile='/certs/ca.pem');"
                  "ctx.load_cert_chain('/certs/svid/correlation.crt','/certs/svid/correlation.key');"
                  f"print(urllib.request.urlopen('https://correlation:8443{path}',timeout=8,context=ctx).read().decode())")
        else:
            py = ("import urllib.request;"
                  f"print(urllib.request.urlopen('http://correlation:8000{path}',timeout=8).read().decode())")
        rc, out, err = run(["docker", "exec", cc, "python", "-c", py], 30)
        if rc != 0:
            return False, err.strip()[:400]
        return True, out

    def registry_missing(self, identities: list[str]) -> list[str]:
        """Which of `identities` the correlation engine's registry does NOT hold.

        TRACKER 161. Reads the enrichment CSV the engine actually loads, rather
        than trusting a count from /healthz — the count is a fleet-wide total
        and cannot say whether THESE devices are attributable. Returns [] when
        the file cannot be read, and the caller keeps its count check as the
        backstop, so an unreadable file never reads as "all present".
        """
        cc = self.cid("correlation")
        if not cc or not identities:
            return []
        rc, out, err = run(["docker", "exec", cc, "sh", "-c",
                            "cat /data/enrichment/device_tenant.csv 2>/dev/null || true"],
                           DOCKER_TIMEOUT)
        if rc != 0 or not out.strip():
            warn(f"registry read failed ({err.strip()[:120]}) — falling back to the "
                 f"count check, which cannot see per-identity gaps")
            return []
        present = set()
        for line in out.splitlines()[1:]:
            ident = line.split(",", 1)[0].strip()
            if ident:
                present.add(ident)
        return [i for i in identities if i not in present]

    def corr_healthz(self) -> dict:
        ok, out = self.corr_get("/healthz")
        if not ok:
            return {"_error": out}
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return {"_error": out[:300]}

    def corr_metric(self, name_with_labels: str) -> float:
        ok, out = self.corr_get("/metrics")
        if not ok:
            return -1.0
        for line in out.splitlines():
            if line.startswith(name_with_labels + " "):
                try:
                    return float(line.rsplit(" ", 1)[1])
                except ValueError:
                    return -1.0
        return 0.0  # counter not yet minted == 0 observed

    # -- VictoriaMetrics ----------------------------------------------------
    def vm_query(self, expr: str) -> float:
        vc = self.cid("victoria")
        if not vc:
            warn("no running victoria container")
            return -1.0
        url = ("http://127.0.0.1:8428/api/v1/query?query=" +
               urllib.parse.quote(expr, safe=""))
        rc, out, err = run(["docker", "exec", vc, "wget", "-qO-", url], DOCKER_TIMEOUT)
        if rc != 0:
            warn(f"VM query failed ({expr[:60]}): {err.strip()[:200]}")
            return -1.0
        try:
            res = json.loads(out)["data"]["result"]
            return float(res[0]["value"][1]) if res else 0.0
        except (json.JSONDecodeError, KeyError, IndexError, ValueError):
            return -1.0

    def dlq_run_reasons(self, runid: str, identity_shas: dict | None = None) -> dict:
        """Run-attributable DLQ lines BROKEN DOWN BY REASON (tracker 159).

        A bare count cannot distinguish "the pipeline dropped something" from
        "zero-trust attribution refused an event it could not attribute to a
        tenant, counted it, and sealed the payload" — which is §3a working. The
        accounting gate needs the reasons to judge the difference, so it reads
        them rather than a total.

        Returns {} on ANY failure — the caller treats an unreadable DLQ as
        unknown and FAILS, never as clean.

        IDENTITY-AWARE (2026-08-19). Grepping for the runid CANNOT see the most
        important category. A tenant-refusal record deliberately withholds the
        payload and the plaintext hostname (F-11 / INV-F11-10) and keeps only
        `identity_sha` = sha256(identity) — so a run's own refusals contain the
        runid nowhere and matched nothing. Measured on ladder 08191832j027:
        **133,349 refused events from this run's devices, and the gate reported
        95.** Passing `identity_shas` (sha256 of every device name -> index)
        makes that category visible without weakening F-11: the ladder knows its
        own device names, so it can compute the same digest the router does.
        """
        cc = self.cid("correlation")
        if not cc:
            return {}
        rc, out, err = run(
            ["docker", "exec", cc, "sh", "-c",
             "cat /data/deadletter/* 2>/dev/null || true"],
            DOCKER_TIMEOUT)
        if rc != 0:
            warn(f"DLQ reason read failed: {err.strip()[:200]}")
            return {}
        shas = identity_shas or {}
        reasons: dict = {}
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                # Only attribute an unparseable line to this run if the runid is
                # literally in it — otherwise a neighbour's corruption would be
                # charged to us.
                if runid in line:
                    reasons["(unparseable DLQ line)"] = (
                        reasons.get("(unparseable DLQ line)", 0) + 1)
                continue
            if not isinstance(rec, dict):
                if runid in line:
                    reasons["(non-object DLQ line)"] = (
                        reasons.get("(non-object DLQ line)", 0) + 1)
                continue
            # Attributable to THIS run either by the runid appearing in the
            # record, or by the sealed identity digest of one of our devices.
            mine = (runid in line) or (rec.get("identity_sha") in shas)
            if not mine:
                continue
            reason = str(rec.get("reason") or "(no reason field)")
            reasons[reason] = reasons.get(reason, 0) + 1
        return reasons

    def dlq_run_lines(self, runid: str) -> int:
        """Run-attributable correlation DLQ lines (payloads carry the device
        hostname, hence the runid)."""
        cc = self.cid("correlation")
        if not cc:
            return -1
        rc, out, err = run(
            ["docker", "exec", cc, "sh", "-c",
             f"cat /data/deadletter/* 2>/dev/null | grep -c -- '{runid}'"],
            DOCKER_TIMEOUT)
        # grep -c exits 1 on zero matches — that is a real 0, not an error.
        if rc not in (0, 1):
            warn(f"DLQ grep failed: {err.strip()[:200]}")
            return -1
        try:
            return int(out.strip() or "0")
        except ValueError:
            return -1


# TRACKER 159. DLQ reasons that are the system working as designed rather than
# losing data. `identity_unattributable` is the §3a tenant check refusing an
# event whose identity it cannot attribute: the event is counted, its payload is
# sealed in the router quarantine (F-11), and nothing is silently dropped.
# Anything NOT listed here fails the accounting gate at a single occurrence.
# How long cleanup waits for the consumer backlog before deleting devices.
# Deleting them earlier turns every in-flight event into a refusal (see
# cleanup()). Bounded: teardown must always happen, drained or not.
CLEANUP_DRAIN_WAIT_S = float(os.environ.get("MLX_CLEANUP_DRAIN_WAIT_S", "300"))

DLQ_EXPECTED_REASONS = frozenset({"identity_unattributable"})

# ...and even an expected reason fails above this share of injected events.
# Measured basis: the worst observed ladder run refused 786 of 600,001 (0.13%),
# which is the registry-propagation edge at the start of a burst. 1% leaves that
# headroom while still failing a ~10x regression.
DLQ_EXPECTED_MAX_FRACTION = 0.01


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

class Harness:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.runid = (datetime.now(timezone.utc).strftime("%m%d%H%M") +
                      "".join(random.choices(string.ascii_lowercase + string.digits, k=4)))
        self.prefix = f"mlx-{self.runid}-"
        self.stack = Stack(args.env_file, args.base_url, args.project)
        self.run_dir = args.run_dir or os.path.join(
            REPO_ROOT, "data", "miniladder",
            datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + self.runid)
        self.phases: list[dict] = []
        self.baseline: dict = {}
        self.created_ids: list[str] = []
        # requested name -> canonical id, when dedupe absorbed the create
        self.absorbed: dict[str, str] = {}
        self.injected_total = 0
        self.burst_seconds = 0.0
        self.produce_failures: list[str] = []
        # Accounting identity (tracker 152 §8.3): the internal generator
        # accounts under this harness's own mlx- namespace; `--load-generator
        # twin` swaps these to the delegated twin run's twx- namespace so the
        # balance equation counts the events that were ACTUALLY injected.
        self.acct_prefix = self.prefix
        self.acct_runid = self.runid
        self.twin_run: dict = {}   # twin mode: {runid, run_dir, devices}
        # Per-container RSS at the END OF THE BURST — the leak anchor. Empty
        # until burst() completes; memflat says so and falls back to the cold
        # baseline rather than passing silently on a missing sample.
        self.warm_mem: dict[str, int] = {}

    # -- plumbing -----------------------------------------------------------
    def phase(self, name: str, status: str, evidence: dict, notes: str = "") -> bool:
        entry = {"phase": name, "status": status, "notes": notes,
                 "evidence": evidence, "at": utcnow()}
        self.phases.append(entry)
        log(f"[{status}] {name}" + (f" — {notes}" if notes else ""))
        return status == "PASS"

    def evidence_file(self, name: str, content: str) -> str:
        path = os.path.join(self.run_dir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    # -- phase 1: preflight -------------------------------------------------
    def preflight(self) -> bool:
        ev: dict = {}
        problems: list[str] = []

        states = self.stack.service_states()
        ev["services"] = states
        seen = {s["service"] for s in states}
        for req in REQUIRED_SERVICES:
            if req not in seen:
                problems.append(f"required service missing: {req}")
        for s in states:
            if s["status"] == "restarting":
                problems.append(f"{s['service']} is crash-looping")
            elif s["status"] == "exited" and s["exit_code"] != "0":
                problems.append(f"{s['service']} exited {s['exit_code']}")
            elif s["health"] == "unhealthy":
                problems.append(f"{s['service']} is unhealthy")

        # Ingress answers.
        try:
            req = urllib.request.Request(self.stack.base_url + "/")
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
                ev["ingress_status"] = r.status
        except (urllib.error.URLError, OSError) as exc:
            problems.append(f"ingress probe {self.stack.base_url}/ failed: {exc}")

        # API auth works (and stays logged in for later phases).
        try:
            self.stack.login()
            ev["api_login"] = "ok"
        except (RuntimeError, urllib.error.URLError, OSError) as exc:
            problems.append(f"API login failed: {exc}")

        # ACTIVE bus consumers — offsets alone lie (a dead consumer keeps its
        # committed offsets forever). Both the RCA engine and the ingest
        # router must hold group membership RIGHT NOW.
        # `--describe` intermittently races the coordinator and reports zero
        # members for a live group (same flake the audit doc notes for
        # kafka-exporter), and a consumer mid-rebalance is memberless between
        # kicks — poll over a bounded window before believing "no consumer".
        # A DEAD consumer (the wiped-ACL shape) never shows a member at all.
        #
        # The wait is BOUNDED and configurable because bring-up cost is
        # hardware-dependent, not invariant: on a cold shared CI runner
        # kafka-init spends a JVM per topic and the last topic of the 16
        # appeared ~7 min after the broker came up (run 31991056443:
        # netops.wireless_events log created 03:34:23), so the engine's final
        # rebalance lands minutes after `docker compose up` returns. Waiting
        # longer never weakens the assertion — the verdict is still "a member
        # must be there", only the patience is tuned (--consumer-settle-seconds).
        settle = self.args.consumer_settle_seconds

        def settled_group(group: str) -> dict:
            last: dict = {"_members": 0, "_rows": 0}
            deadline = time.monotonic() + settle
            waited = 0.0
            while True:
                last = self.stack.group_lag(group)
                if last.get("_members", 0) >= 1:
                    if waited:
                        log(f"preflight: {group} showed a member after {waited:.0f}s")
                    return last
                if time.monotonic() >= deadline:
                    return last
                time.sleep(10)
                waited += 10

        def consumer_problem(group: str, g: dict, role: str) -> str:
            """Name the SHAPE of the absence — the three causes need different
            first moves, and 'no active consumer' alone hid that."""
            if g.get("_error"):
                return (f"{group} could not be described after {settle}s — the "
                        f"membership check is BLIND, not passing: {g['_error']}")
            if g.get("_rows", 0) == 0:
                return (f"{group} is UNKNOWN to the broker after {settle}s — the "
                        f"{role} never joined (consumer down, topics never created, "
                        f"or authorization-dead: check `docker compose logs "
                        f"correlation vector-router` and `logs kafka | grep -i denied`)")
            return (f"{group} has rows but NO active member after {settle}s — "
                    f"committed offsets with zero members is the dead-{role} "
                    f"signature (2026-08-16 wiped-ACL incident)")

        corr_lag = settled_group("netops-correlation")
        router_lag = settled_group("netops-router-syslog")
        ev["corr_group"] = corr_lag
        ev["router_syslog_group"] = router_lag
        ev["consumer_settle_seconds"] = settle
        if corr_lag.get("_members", 0) < 1:
            problems.append(consumer_problem("netops-correlation", corr_lag, "engine"))
        if router_lag.get("_members", 0) < 1:
            problems.append(consumer_problem("netops-router-syslog", router_lag, "router"))
        # A stack still digesting an earlier backlog cannot produce a valid
        # drain verdict — the baseline must be near-idle.
        if corr_lag.get("_total", -1) > self.args.max_baseline_lag:
            problems.append(
                f"correlation lag already {corr_lag['_total']} at baseline "
                f"(> {self.args.max_baseline_lag}) — stack is not idle; a drain "
                f"verdict on top of an existing backlog would be meaningless")

        # Baselines.
        self.baseline["mem"] = self.stack.mem_sample()
        self.baseline["kafka_syslog_end"] = self.stack.end_offset("netops.syslog")
        self.baseline["corr_lag_total"] = corr_lag.get("_total", -1)
        self.baseline["router_lag_total"] = router_lag.get("_total", -1)
        for table in ("corr_signals", "flows"):
            ok, out = self.stack.ch(f"SELECT count() FROM netops.{table}")
            self.baseline[f"ch_{table}"] = int(out) if ok and out.isdigit() else -1
            if not ok:
                problems.append(f"ClickHouse count on netops.{table} failed: {out}")
        self.baseline["vm_active_series"] = self.stack.vm_query(
            'vm_cache_entries{type="storage/hour_metric_ids"}')
        self.baseline["vector_discards"] = self.stack.vm_query(
            'sum(vector_component_discarded_events_total{intentional="false"})')
        self.baseline["vector_deadletter_sent"] = self.stack.vm_query(
            'sum(vector_component_sent_events_total{component_id=~"opensearch_deadletter|kafka_deadletter"})')
        hz = self.stack.corr_healthz()
        dur = hz.get("durability", {}) if isinstance(hz, dict) else {}
        self.baseline["quarantine_write_failures"] = dur.get("quarantine_write_failures", -1)
        self.baseline["registry_identities"] = (
            hz.get("tenant_verification", {}).get("registry_identities", -1)
            if isinstance(hz, dict) else -1)
        self.baseline["corr_deadletters"] = self.stack.corr_metric("corr_deadletters")
        self.baseline["os_run_docs"] = self.stack.os_count(
            "netops-syslog-*", "hostname.keyword", self.prefix)
        if "_error" in hz:
            problems.append(f"correlation /healthz unreachable: {hz['_error']}")
        if self.baseline["os_run_docs"] != 0:
            problems.append(
                f"OpenSearch already holds {self.baseline['os_run_docs']} docs "
                f"for prefix {self.prefix} — runid collision?")

        # The clean-slate --verify heuristic treats a max consumer offset
        # > 100k as "bus never reset". Warn (not fail) when this run would
        # push past it — the operator loses that verify signal until the next
        # reset. Platform-safe either way.
        planned = self.args.eps * 60 * self.args.burst_minutes
        endoff = self.baseline["kafka_syslog_end"]
        if endoff >= 0 and endoff + planned > 100_000:
            warn(f"planned injection ({planned}) + current netops.syslog end offset "
                 f"({endoff}) exceeds 100k — clean-slate.sh --verify's offset "
                 f"heuristic will flag this stack until its next reset")
        ev["baseline"] = self.baseline

        status = "PASS" if not problems else "FAIL"
        return self.phase("preflight", status, ev,
                          "; ".join(problems) if problems else
                          f"{len(states)} services checked, consumers live, baselines captured")

    def device_identity_shas(self) -> dict:
        """sha256(device name) -> device index, for every device this run created.

        The refusal dead-letter record keeps only this digest (F-11 withholds
        the plaintext hostname), so without it a run cannot see its OWN refused
        events. Computing it here uses only names the ladder already owns — it
        reveals nothing the harness did not already know, and it does not weaken
        the sealed-quarantine invariant for anyone else.
        """
        return {hashlib.sha256(name.encode("utf-8", "replace")).hexdigest(): i
                for i, name in enumerate(self.created_ids)}

    # -- phase 2: onboarding linearity --------------------------------------
    def onboard(self) -> bool:
        n = self.args.devices
        k = 100 if n >= 200 else max(10, n // 2)
        durations: list[float] = []
        failures: list[str] = []
        t0 = time.monotonic()
        for i in range(n):
            name = f"{self.prefix}{i:05d}"
            body = {
                "id": name, "name": name,
                # RFC 2544 benchmark space — never routable, so pollers that
                # pick the device up can only time out quietly.
                "address": f"198.18.{i // 250}.{i % 250 + 1}",
                "type": "router", "source": "miniladder-g2",
                "labels": {"mlx_run": self.runid},
            }
            t = time.monotonic()
            st, resp = self.stack.api("POST", "/api/devices", body)
            durations.append(time.monotonic() - t)
            # TRACKER 161: a 201 is not proof the requested identity exists.
            # Cross-source dedupe can absorb a create into an existing device
            # that shares an identity token (management IP), and the API used to
            # answer 201 while echoing the caller's object back. 73 devices were
            # onboarded that way on 2026-08-19 and every event they emitted was
            # unattributable. Trust the CANONICAL identity the API reports, not
            # the status code.
            canonical = ""
            if isinstance(resp, dict):
                canonical = str(resp.get("id") or "")
            if st == 201 and canonical == name:
                self.created_ids.append(name)
            elif st in (200, 201) and canonical and canonical != name:
                # Absorbed into an existing device — record the mapping and do
                # NOT count it as this run's device; nothing downstream will key
                # on the name we asked for.
                self.absorbed[name] = canonical
            else:
                failures.append(f"{name}: HTTP {st} canonical={canonical or '-'} "
                                f"{str(resp)[:100]}")
                if len(failures) >= 10:
                    break
        total_wall = time.monotonic() - t0

        ev: dict = {"devices_requested": n, "devices_created": len(self.created_ids),
                    "devices_absorbed_by_dedupe": len(self.absorbed),
                    "absorbed_mappings": dict(list(self.absorbed.items())[:20]),
                    "window": k, "total_wall_s": round(total_wall, 2),
                    "failures": failures[:10]}
        if self.absorbed:
            return self.phase(
                "onboard", "FAIL", ev,
                f"{len(self.absorbed)} of {n} requested devices were ABSORBED by "
                f"dedupe into an existing device (stale residue on the same "
                f"address?). Their telemetry would be unattributable, so this "
                f"run cannot prove 1000/1000 — clear the residue and re-run")
        if failures:
            return self.phase("onboard", "FAIL", ev,
                              f"{len(failures)}+ create failures (first: {failures[0]})")

        first_rate = k / max(sum(durations[:k]), 1e-9)
        last_rate = k / max(sum(durations[-k:]), 1e-9)
        ratio = last_rate / first_rate
        ev.update({"first_window_rate_per_s": round(first_rate, 2),
                   "last_window_rate_per_s": round(last_rate, 2),
                   "last_over_first": round(ratio, 3),
                   "floor": self.args.linearity_floor})
        ok = ratio >= self.args.linearity_floor
        return self.phase(
            "onboard", "PASS" if ok else "FAIL", ev,
            f"create rate first {first_rate:.1f}/s -> last {last_rate:.1f}/s "
            f"(ratio {ratio:.2f}, floor {self.args.linearity_floor}) — "
            + ("linear enough" if ok else "SUPER-LINEAR SLOWDOWN (O(N^2) class)"))

    # -- phase 3: burst ------------------------------------------------------
    def _syslog_event(self, device: str, seq: int) -> str:
        state = "down" if seq % 2 == 0 else "up"
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        return json.dumps({
            "hostname": device,
            "appname": "LINK-3-UPDOWN",
            "message": (f"%LINK-3-UPDOWN: Interface GigabitEthernet0/{seq % 48}, "
                        f"changed state to {state} [mlx seq {seq}]"),
            "severity": "err",
            "timestamp": ts,
        })

    def burst(self) -> bool:
        # tracker 152 §8.3 composition: the twin generates realistic load,
        # this harness keeps judging. Default path is the internal generator,
        # untouched.
        if getattr(self.args, "load_generator", "internal") == "twin":
            return self._burst_twin()
        return self._burst_internal()

    def _burst_twin(self) -> bool:
        """Delegate the burst to `twin.py run` (kept standing with --keep so
        accounting can count its telemetry; cleanup() tears the twin run down
        after the verdicts). The twin's per-lane emitted counts in
        twin-report.json become the injected side of the balance equation."""
        ev: dict = {}
        twin_py = os.path.join(REPO_ROOT, "scripts", "lab", "twin", "twin.py")
        cmd = [sys.executable, twin_py,
               "--env-file", self.args.env_file,
               "--project", self.args.project,
               "--base-url", self.args.base_url,
               "run", "--scenario", self.args.twin_scenario,
               "--duration-minutes", str(self.args.twin_duration_minutes),
               "--fidelity", self.args.twin_fidelity,
               "--keep"]
        budget = int(self.args.twin_duration_minutes * 60 + 1800)
        t0 = time.monotonic()
        rc, out, err = run(cmd, budget)
        self.burst_seconds = time.monotonic() - t0
        ev["twin_rc"] = rc
        self.evidence_file("twin-stdout.log", out)
        self.evidence_file("twin-stderr.log", err)
        try:
            with open(os.path.join(REPO_ROOT, "data", "twin",
                                   "last-run.json"), encoding="utf-8") as f:
                last = json.load(f)
            with open(os.path.join(last["run_dir"], "twin-report.json"),
                      encoding="utf-8") as f:
                report = json.load(f)
            with open(os.path.join(last["run_dir"], "state.json"),
                      encoding="utf-8") as f:
                state = json.load(f)
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            return self.phase("burst", "FAIL", ev,
                              f"twin run artifacts unreadable ({exc}) — "
                              f"cannot account honestly (twin rc={rc})")
        self.twin_run = {"runid": last.get("runid", ""),
                         "run_dir": last.get("run_dir", ""),
                         "devices": len(state.get("devices") or [])}
        self.acct_prefix = str(state.get("prefix") or "")
        self.acct_runid = str(last.get("runid") or "")
        by_lane = report.get("emitted_by_lane") or {}
        # +1: the twin's canary syslog event rides the same prefix but is not
        # in the schedule counts (lifecycle.canary).
        self.injected_total = int(by_lane.get("syslog") or 0) + 1
        ev.update({
            "twin_runid": self.acct_runid,
            "twin_emitted_by_lane": by_lane,
            "twin_skipped_by_lane": report.get("skipped_by_lane") or {},
            "twin_produce_failures": report.get("produce_failures") or [],
            "twin_accuracy": report.get("accuracy") or {},
            "twin_spread": report.get("spread") or {},
            "injected_total_syslog_lane": self.injected_total,
            "canary_included": True,
        })
        if rc != 0 or not self.acct_prefix or not self.acct_runid:
            return self.phase("burst", "FAIL", ev,
                              f"twin run rc={rc} (see twin-stderr.log)")
        if report.get("produce_failures"):
            return self.phase("burst", "FAIL", ev,
                              "twin reported produce failures — accounting "
                              "would be dishonest")
        return self.phase(
            "burst", "PASS", ev,
            f"twin {self.acct_runid} injected {self.injected_total} syslog-"
            f"lane events (+{sum(v for k, v in by_lane.items() if k != 'syslog')} "
            f"on other lanes) in {self.burst_seconds:.0f}s")

    def _burst_internal(self) -> bool:
        ev: dict = {}
        # Gate 1: registry propagation. The Go API rewrites device_tenant.csv
        # every ~60s; the engine reloads it on mtime change. Without this gate
        # every injected event is tenant-refused (identity_unattributable)
        # straight into the DLQ — proven live 2026-08-16.
        # TRACKER 161: a COUNT cannot prove the right identities are present.
        # On 2026-08-19 this gate passed at 2000 total identities while 73 of
        # THIS run's devices were absent from the registry, and every event they
        # produced was refused. Verify the identities we actually need.
        want = self.baseline.get("registry_identities", 0) + len(self.created_ids)
        deadline = time.monotonic() + 240
        current = -1
        missing: list[str] = []
        while time.monotonic() < deadline:
            hz = self.stack.corr_healthz()
            current = (hz.get("tenant_verification", {}).get("registry_identities", -1)
                       if isinstance(hz, dict) else -1)
            missing = self.stack.registry_missing(self.created_ids)
            if not missing and current >= want:
                break
            time.sleep(10)
        ev["registry_identities"] = {"want_at_least": want, "observed": current,
                                     "missing_identities": len(missing),
                                     "missing_sample": missing[:20]}
        if missing:
            return self.phase("burst", "FAIL", ev,
                              f"{len(missing)} of this run's {len(self.created_ids)} device "
                              f"identities are ABSENT from the correlation engine's registry "
                              f"after 240s (total identities {current}, which is why a "
                              f"count-only gate passed) — their events would be "
                              f"tenant-refused; aborting the burst")
        if current < want:
            return self.phase("burst", "FAIL", ev,
                              f"device registry never propagated to the correlation engine "
                              f"({current} < {want} after 240s) — injected events would be "
                              f"tenant-refused; aborting the burst")

        # Gate 2: one canary through the whole pipe (topic -> engine -> CH).
        canary = self._syslog_event(self.created_ids[0], 999_999)
        ok, err = self.stack.produce("netops.syslog", [canary])
        if not ok:
            return self.phase("burst", "FAIL", ev, f"canary produce failed: {err}")
        self.injected_total += 1
        deadline = time.monotonic() + 150
        canary_seen = False
        while time.monotonic() < deadline:
            okq, out = self.stack.ch(
                f"SELECT count() FROM netops.corr_signals WHERE entity_id LIKE '%{self.prefix}%'")
            if okq and out.isdigit() and int(out) >= 1:
                canary_seen = True
                break
            time.sleep(10)
        ev["canary_signal_seen"] = canary_seen
        if not canary_seen:
            hz = self.stack.corr_healthz()
            ev["healthz_durability"] = hz.get("durability", hz)
            ev["dlq_run_lines"] = self.stack.dlq_run_lines(self.runid)
            return self.phase("burst", "FAIL", ev,
                              "canary event never produced a corr_signal within 150s — "
                              "pipeline broken between the bus and ClickHouse "
                              "(durability/DLQ evidence attached)")

        # The burst proper: eps x 60 x minutes events, paced in chunks.
        chunk_secs = 10
        target = self.args.eps * 60 * self.args.burst_minutes
        seq = 0
        t0 = time.monotonic()
        chunks = []
        while seq < target:
            chunk_n = min(self.args.eps * chunk_secs, target - seq)
            lines = [self._syslog_event(self.created_ids[(seq + j) % len(self.created_ids)],
                                        seq + j)
                     for j in range(chunk_n)]
            tp = time.monotonic()
            ok, err = self.stack.produce("netops.syslog", lines)
            if not ok:
                self.produce_failures.append(err)
                if len(self.produce_failures) >= 3:
                    break
            else:
                self.injected_total += chunk_n
            chunks.append({"n": chunk_n, "ok": ok, "produce_s": round(time.monotonic() - tp, 2)})
            seq += chunk_n
            # Pace to the wall clock; if production is slower than the target
            # rate we record the slippage rather than pretend.
            ahead = t0 + (seq / self.args.eps) - time.monotonic()
            if ahead > 0:
                time.sleep(ahead)
        self.burst_seconds = time.monotonic() - t0
        actual_eps = self.injected_total / max(self.burst_seconds, 1e-9)
        ev.update({
            "target_events": target, "injected_total": self.injected_total,
            "burst_seconds": round(self.burst_seconds, 1),
            "actual_eps": round(actual_eps, 1),
            "target_eps": self.args.eps,
            "chunks": len(chunks),
            "produce_failures": self.produce_failures,
        })
        self.evidence_file("burst-chunks.json", json.dumps(chunks, indent=1))
        if self.produce_failures:
            return self.phase("burst", "FAIL", ev,
                              f"{len(self.produce_failures)} produce failures — accounting "
                              f"would be dishonest (first: {self.produce_failures[0][:160]})")
        return self.phase("burst", "PASS", ev,
                          f"injected {self.injected_total} events in {self.burst_seconds:.0f}s "
                          f"(~{actual_eps:.0f}/s, target {self.args.eps}/s)")

    # -- phase 4: drain ------------------------------------------------------
    def drain(self) -> bool:
        base = max(self.baseline.get("corr_lag_total", 0), 0)
        eps = self.args.lag_epsilon
        budget = max(self.args.drain_factor * self.burst_seconds, 120.0)
        t0 = time.monotonic()
        curve = []
        drained_at = None
        while time.monotonic() - t0 < budget:
            lag = self.stack.group_lag("netops-correlation")
            total = lag.get("_total", -1)
            curve.append({"t_s": round(time.monotonic() - t0, 1), "lag": total,
                          "members": lag.get("_members", 0)})
            if 0 <= total <= base + eps:
                drained_at = time.monotonic() - t0
                break
            time.sleep(10)
        self.evidence_file("lag-curve.json", json.dumps(curve, indent=1))
        ev = {"baseline_lag": base, "epsilon": eps,
              "budget_s": round(budget, 0),
              "drained_at_s": round(drained_at, 1) if drained_at is not None else None,
              "samples": len(curve),
              "peak_lag": max((c["lag"] for c in curve), default=-1),
              "final_lag": curve[-1]["lag"] if curve else -1,
              "curve_file": "lag-curve.json"}
        if drained_at is None:
            # Automatic first-cut diagnosis: a consumer thrashing on
            # max_poll_interval rebalances (CommitFailed -> UnknownMemberId ->
            # rejoin -> reprocess) is the most likely shape of this failure —
            # count the tell-tale log lines so the report carries the WHY.
            cc = self.stack.cid("correlation")
            if cc:
                since = f"{int(budget) + int(self.burst_seconds) + 120}s"
                rc, out, err2 = run(["docker", "logs", "--since", since, cc], 60)
                blob = out + err2 if rc == 0 else ""
                ev["rebalance_diagnosis"] = {
                    "commit_failed": blob.count("CommitFailedError"),
                    "unknown_member": blob.count("UnknownMemberIdError"),
                    "consumer_restarts": blob.count("consumer failed; restarting"),
                }
            return self.phase("drain", "FAIL", ev,
                              f"consumer lag NEVER returned to <= {base}+{eps} within "
                              f"{budget:.0f}s (final {ev['final_lag']}) — the "
                              f"'lag never drains' defect class "
                              f"(rebalance diagnosis in evidence)")
        return self.phase("drain", "PASS", ev,
                          f"lag drained to baseline+eps in {drained_at:.0f}s "
                          f"(budget {budget:.0f}s, peak {ev['peak_lag']})")

    # -- phase 5: accounting -------------------------------------------------
    def accounting(self) -> bool:
        ev: dict = {}
        # Settle: the router must have consumed everything we injected before
        # OS counts are meaningful; then wait for the OS count to go stable
        # (bulk flush + refresh).
        deadline = time.monotonic() + 240
        router_total = -1
        while time.monotonic() < deadline:
            router = self.stack.group_lag("netops-router-syslog")
            router_total = router.get("_total", -1)
            if 0 <= router_total <= max(self.baseline.get("router_lag_total", 0), 0) + 10:
                break
            time.sleep(10)
        ev["router_lag_at_settle"] = router_total

        prev = -1
        os_docs = -1
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            os_docs = self.stack.os_count("netops-syslog-*", "hostname.keyword", self.acct_prefix)
            if os_docs >= 0 and os_docs == prev:
                break
            prev = os_docs
            time.sleep(15)

        dlq_run = self.stack.dlq_run_lines(self.acct_runid)
        discards = self.stack.vm_query(
            'sum(vector_component_discarded_events_total{intentional="false"})')
        dl_sent = self.stack.vm_query(
            'sum(vector_component_sent_events_total{component_id=~"opensearch_deadletter|kafka_deadletter"})')
        d_discards = (discards - self.baseline.get("vector_discards", 0)
                      if discards >= 0 and self.baseline.get("vector_discards", -1) >= 0 else -1)
        d_dl = (dl_sent - self.baseline.get("vector_deadletter_sent", 0)
                if dl_sent >= 0 and self.baseline.get("vector_deadletter_sent", -1) >= 0 else -1)

        hz = self.stack.corr_healthz()
        dur = hz.get("durability", {}) if isinstance(hz, dict) else {}
        qwf_now = dur.get("quarantine_write_failures", -1)
        qwf_base = self.baseline.get("quarantine_write_failures", -1)
        d_qwf = qwf_now - qwf_base if qwf_now >= 0 and qwf_base >= 0 else -1
        ch_fail = dur.get("ch_insert_failures", {})

        twin_mode = getattr(self.args, "load_generator", "internal") == "twin"
        if twin_mode:
            # twin device names are not numeric — count devices by stripping
            # the entity's :interface suffix under the twin prefix.
            okq, out = self.stack.ch(
                "SELECT uniqExact(extract(entity_id, "
                f"'{self.acct_prefix}[A-Za-z0-9_.-]+')) "
                f"FROM netops.corr_signals WHERE entity_id LIKE "
                f"'%{self.acct_prefix}%'")
        else:
            okq, out = self.stack.ch(
                "SELECT uniqExact(extract(entity_id, 'mlx-[a-z0-9]+-[0-9]+')) "
                f"FROM netops.corr_signals WHERE entity_id LIKE '%{self.prefix}%'")
        entities = int(out) if okq and out.isdigit() else -1
        okq2, out2 = self.stack.ch(
            f"SELECT count() FROM netops.corr_signals WHERE entity_id LIKE '%{self.acct_prefix}%'")
        signal_rows = int(out2) if okq2 and out2.isdigit() else -1

        # The equation. Each term and what it honestly counts:
        #   injected_total   events this run produced to netops.syslog
        #                    (producer exited 0; canary included).
        #   os_docs          EXACT run docs in netops-syslog-* (prefix query
        #                    on hostname.keyword) — the raw lane is 1:1 with
        #                    injected events, no dedup window applies.
        #   dlq_run          EXACT run-attributable correlation DLQ lines
        #                    (payload carries the device hostname).
        #   d_discards/d_dl  Vector's honest loss counters, STACK-WIDE deltas:
        #                    they cannot be attributed to the run, so organic
        #                    traffic can inflate them — they may only ever
        #                    OVER-explain a deficit, never mask a surplus.
        # PASS = no unexplained loss: injected - os_docs <= counted losses,
        # with zero counted losses required to call the pipeline lossless.
        missing = self.injected_total - os_docs if os_docs >= 0 else -1
        explained = max(d_discards, 0) + max(d_dl, 0) + max(dlq_run, 0)
        problems = []
        if os_docs < 0:
            problems.append("OpenSearch run-doc count unavailable")
        elif missing < 0:
            problems.append(
                f"MORE docs ({os_docs}) than injected ({self.injected_total}) — "
                f"duplication or runid collision")
        elif missing > 0 and missing > explained:
            problems.append(
                f"{missing} events UNEXPLAINED (injected {self.injected_total}, "
                f"persisted {os_docs}, counted losses {explained}) — silent drop")
        elif missing > 0:
            problems.append(
                f"{missing} events lost but explicitly counted "
                f"(discards {d_discards:.0f}, deadletter {d_dl:.0f}, DLQ {dlq_run}) — "
                f"loss is visible, but a lossless pipeline is the bar")
        # TRACKER 159. A non-empty DLQ is not automatically a defect: the
        # zero-trust tenant check refuses events it cannot attribute, counts
        # them, and seals the payload (§3a). Failing on the raw count made this
        # gate unpassable — the lab carries a standing ~2/s background of
        # identity_unattributable — and, worse, meant the one channel where a
        # NEW loss would appear was always red. So judge by REASON, and keep an
        # envelope on the expected ones so a real regression still fails. This
        # is not muting the check: an unreadable DLQ fails, an unexpected reason
        # fails at a single line, and expected reasons fail above the envelope.
        dlq_reasons = self.stack.dlq_run_reasons(
            self.acct_runid, self.device_identity_shas())
        ev["dlq_run_reasons"] = dlq_reasons
        if dlq_run > 0 and not dlq_reasons:
            problems.append(
                f"{dlq_run} run events in the correlation DLQ but the reasons "
                f"could not be read — unknown is not clean")
        unexpected = {r: n for r, n in dlq_reasons.items()
                      if r not in DLQ_EXPECTED_REASONS}
        expected_n = sum(n for r, n in dlq_reasons.items()
                         if r in DLQ_EXPECTED_REASONS)
        envelope = int(self.injected_total * DLQ_EXPECTED_MAX_FRACTION)
        if unexpected:
            problems.append(
                f"unexpected correlation DLQ reasons (any count is a defect): "
                f"{unexpected}")
        if expected_n > envelope:
            problems.append(
                f"{expected_n} events refused as {sorted(DLQ_EXPECTED_REASONS)} "
                f"— above the {DLQ_EXPECTED_MAX_FRACTION:.1%} envelope "
                f"({envelope} of {self.injected_total}). Expected-but-excessive: "
                f"attribution is failing at scale, not merely at the edges")
        if d_qwf != 0:
            problems.append(
                f"quarantine WRITE failures moved by {d_qwf} — events lost with no "
                f"DLQ copy (the 238k-drop class; check /data/deadletter ownership)")
        if any(v for v in ch_fail.values()) if isinstance(ch_fail, dict) else False:
            problems.append(f"correlation ClickHouse insert failures: {ch_fail}")
        if twin_mode:
            # Per-device coverage is the TWIN's verdict (its accuracy scorer
            # judges signal presence per story/device); the ladder judges the
            # balance equation. Coverage rides as evidence, not a gate.
            ev["twin_devices"] = self.twin_run.get("devices", -1)
        elif entities != len(self.created_ids):
            problems.append(
                f"corr_signals covers {entities}/{len(self.created_ids)} burst devices — "
                f"silent per-device signal loss (window eviction?)")

        ev.update({
            "injected_total": self.injected_total,
            "os_persisted_run_docs": os_docs,
            "dlq_run_lines": dlq_run,
            "vector_discards_delta_stackwide": d_discards,
            "vector_deadletter_delta_stackwide": d_dl,
            "quarantine_write_failures_delta": d_qwf,
            "ch_insert_failures": ch_fail,
            "corr_signal_rows_run": signal_rows,
            "corr_entities_covered": entities,
            "devices_expected": len(self.created_ids),
            "unexplained_missing": max(missing, 0) - explained if missing > 0 else 0,
            "tolerance_notes": (
                "os count and dlq lines are exact+run-attributable; vector "
                "deltas are stack-wide (organic traffic may inflate them — "
                "they can only over-explain a deficit). corr_signals rows are "
                "NOT expected to equal injected events (episodic dedup by "
                "design); the invariant is per-device coverage."),
        })
        status = "PASS" if not problems else "FAIL"
        return self.phase("accounting", status, ev,
                          "; ".join(problems) if problems else
                          f"balanced exactly: {self.injected_total} injected == "
                          f"{os_docs} persisted + 0 DLQ + 0 counted rejections; "
                          f"{entities}/{len(self.created_ids)} devices covered in corr_signals")

    # -- phase 6: memory flat ------------------------------------------------
    def memflat(self) -> bool:
        """Two independent memory verdicts.

        ####################################################################
        # THE SLOPE IS ANCHORED ON THE **WARM** SAMPLE, NOT THE COLD BASELINE.
        #
        # The cold baseline is taken at preflight — seconds after a fresh
        # install, when every cache is EMPTY. The first burst then materializes
        # working state that is bounded BY DESIGN, and a cold->end ratio cannot
        # tell that apart from a leak. Measured in CI run 32040415877
        # (60,001 events, 200 devices):
        #   clickhouse   474 -> 1349 MiB (x2.84)  = 25% of its 5326 MiB cap
        #   correlation   59 ->  187 MiB (x3.15)  = 24% of its  789 MiB cap
        #                 (CORR_WINDOW_BUFFER=50000 signals — a capped deque)
        # Every other container moved <=x1.15, including OpenSearch, which
        # indexed all 60k docs on an already-warm JVM. Nothing was leaking and
        # nothing was near a cap, yet the phase FAILED — a red gate every night
        # teaches operators to ignore it, which is worse than no gate.
        #
        # So: the LEAK slope is measured warm->end (caches already
        # materialized, input stopped — a leak keeps climbing there, a cache
        # does not), and the OOM path gets its own check against each
        # container's own limit. The cold->warm step stays in the evidence,
        # unjudged, because a 2-minute burst genuinely cannot separate
        # first-touch materialization from a slow leak. The leak gate proper
        # is the lab's 1000-device/5-minute run and the 72 h soak that
        # docs/scale/CORRELIX_SCALE_TEST_REPORT.md §6 still lists as not run.
        ####################################################################
        """
        end_stats = self.stack.mem_stats()
        end = {n: v["used"] for n, v in end_stats.items()}
        cold = self.baseline.get("mem", {})
        warm = self.warm_mem or {}
        anchor = "warm (end of burst)" if warm else "cold baseline (no warm sample — burst did not complete)"
        ref = warm or cold
        rows, problems = [], []
        for svc in MEM_SERVICES:
            name = f"{self.args.project}-{svc}-1"
            c, w, e = cold.get(name, -1), warm.get(name, -1), end.get(name, -1)
            r = ref.get(name, -1)
            limit = end_stats.get(name, {}).get("limit", -1)
            grew = (e / r) if r > 0 and e > 0 else -1
            pct_limit = round(100.0 * e / limit, 1) if limit > 0 and e > 0 else None
            rows.append({"container": name, "cold_bytes": c, "warm_bytes": w,
                         "end_bytes": e, "limit_bytes": limit,
                         "pct_of_limit": pct_limit,
                         "ratio_vs_anchor": round(grew, 3) if grew > 0 else None,
                         "ratio_cold_to_end": round(e / c, 3) if c > 0 and e > 0 else None})
            if r <= 0 or e <= 0:
                problems.append(f"{name}: no memory sample (anchor {r}, end {e})")
                continue
            # 64 MiB absolute floor: small containers jitter past any ratio.
            if grew > self.args.mem_factor and (e - r) > 64 * 1024**2:
                problems.append(
                    f"{name}: LEAK SLOPE {r / 1024**2:.0f} -> {e / 1024**2:.0f} MiB "
                    f"(x{grew:.2f} > x{self.args.mem_factor}) after input stopped")
            # The OOM path, self-relative to the plan-sized cap (#102).
            if pct_limit is not None and pct_limit > self.args.mem_headroom_percent:
                problems.append(
                    f"{name}: {e / 1024**2:.0f} MiB is {pct_limit}% of its "
                    f"{limit / 1024**2:.0f} MiB cap (> {self.args.mem_headroom_percent}%) "
                    f"— one burst from an OOM kill")
        ev = {"factor": self.args.mem_factor, "anchor": anchor,
              "headroom_percent": self.args.mem_headroom_percent,
              "containers": rows}
        status = "PASS" if not problems else "FAIL"
        return self.phase("memflat", status, ev,
                          "; ".join(problems) if problems else
                          f"all {len(rows)} key containers within x{self.args.mem_factor} "
                          f"of the {anchor} sample and under "
                          f"{self.args.mem_headroom_percent}% of their caps")

    # -- phase 7: cleanup ----------------------------------------------------
    def cleanup(self) -> bool:
        ev: dict = {}
        problems: list[str] = []
        if self.args.dry_run:
            return True

        # 7·twin: the delegated twin run was kept standing for accounting —
        # tear it down through ITS verified-teardown path now (tracker 152
        # §8.3; twin.py exits non-zero on any teardown residue).
        if self.twin_run.get("runid"):
            twin_py = os.path.join(REPO_ROOT, "scripts", "lab", "twin",
                                   "twin.py")
            rc, out, err = run([sys.executable, twin_py,
                                "--env-file", self.args.env_file,
                                "--project", self.args.project,
                                "--base-url", self.args.base_url,
                                "teardown", "--runid",
                                self.twin_run["runid"]], 1800)
            ev["twin_teardown_rc"] = rc
            if rc != 0:
                problems.append(
                    f"twin teardown rc={rc}: {(err or out).strip()[:200]}")

        # BACKLOG DRAIN GATE (2026-08-19). Deleting the devices while their
        # events are still in flight makes correlation refuse every one of them
        # as identity_unattributable — the registry no longer knows the
        # hostname. Measured on ladder 08191832j027: cleanup began with ~385k
        # events still unconsumed and manufactured **133,349 refusals in two
        # minutes**, all charged to this run's devices. They were invisible
        # because the refusal record withholds the hostname (F-11), and they
        # inflate the lab's standing identity_unattributable rate that tracker
        # 159 is trying to explain.
        #
        # So: wait for the backlog before deleting, and if it will not drain,
        # SAY SO and record how much residue we are about to convert into
        # refusals. This never blocks teardown — an undrained lab must still be
        # cleaned — but it stops the harness quietly polluting its own evidence.
        lag_at_cleanup = self.stack.group_lag("netops-correlation").get("_total", -1)
        if lag_at_cleanup > 0:
            deadline = time.monotonic() + CLEANUP_DRAIN_WAIT_S
            while time.monotonic() < deadline:
                lag_at_cleanup = self.stack.group_lag(
                    "netops-correlation").get("_total", -1)
                if lag_at_cleanup <= 0:
                    break
                time.sleep(15)
        ev["consumer_lag_at_cleanup"] = lag_at_cleanup
        if lag_at_cleanup > 0:
            ev["cleanup_refusals_expected"] = lag_at_cleanup
            warn(f"cleanup starting with {lag_at_cleanup} events still "
                 f"unconsumed — deleting the devices now will refuse them as "
                 f"identity_unattributable; this is harness-induced DLQ traffic, "
                 f"not a product defect, and it is recorded as evidence")

        # 7a. Delete every created device; 404 = already gone (fine).
        del_fail = []
        for did in self.created_ids:
            st, resp = self.stack.api("DELETE", f"/api/devices/{did}")
            if st not in (204, 404):
                del_fail.append(f"{did}: HTTP {st} {str(resp)[:80]}")
        ev["devices_deleted"] = len(self.created_ids) - len(del_fail)
        if del_fail:
            problems.append(f"{len(del_fail)} device deletes failed (first: {del_fail[0]})")

        # 7b. VERIFY zero remain (paged; deletion durability is a past defect,
        # F-69 — never trust the 204).
        remaining, offset = 0, 0
        while True:
            st, resp = self.stack.api(
                "GET", f"/api/devices?envelope=1&limit=5000&offset={offset}")
            if st != 200 or not isinstance(resp, dict):
                problems.append(f"device list for verify failed: HTTP {st}")
                remaining = -1
                break
            rows = resp.get("devices") or []
            remaining += sum(1 for d in rows if str(d.get("id", "")).startswith(self.prefix))
            if resp.get("complete", True) or not rows:
                break
            offset += len(rows)
        ev["devices_remaining"] = remaining
        if remaining != 0:
            problems.append(f"{remaining} run devices still present after delete")

        # 7c. Wait (bounded) for the consumer to finish draining before purging:
        # a purge issued while lag is still draining races the engine's late
        # inserts, which then land AFTER the delete and survive as residue —
        # proven live 2026-08-16 (run 08162031su88 left exactly its 100
        # coverage rows behind this way). A drain-phase FAIL does not skip
        # this wait: the whole point is to purge after the last insert.
        drain_deadline = time.monotonic() + 600
        lag = -1
        while time.monotonic() < drain_deadline:
            lag = self.stack.group_lag("netops-correlation").get("_total", -1)
            if 0 <= lag <= 100:
                break
            time.sleep(15)
        else:
            problems.append(
                f"consumer lag still {lag} after 600s pre-purge wait — purge may race late inserts")
        ev["pre_purge_lag"] = lag

        # Purge run telemetry so the stack (and clean-slate.sh --verify)
        # is left as found. corr_objects/evidence TTL out on their own and are
        # not part of --verify; noted honestly rather than silently skipped.
        ok, out = self.stack.ch_mutation(
            f"ALTER TABLE netops.corr_signals DELETE WHERE entity_id LIKE '%{self.prefix}%'")
        if not ok:
            problems.append(f"ClickHouse corr_signals purge failed: {out}")
        okc, cnt = self.stack.ch(
            f"SELECT count() FROM netops.corr_signals WHERE entity_id LIKE '%{self.prefix}%'")
        ev["ch_signals_left"] = int(cnt) if okc and cnt.isdigit() else -1
        if ev["ch_signals_left"] != 0:
            problems.append(f"{ev['ch_signals_left']} run rows left in corr_signals")

        okd, res = self.stack.os_req(
            "OS_BOOTSTRAP_PASSWORD", "svc_bootstrap",
            "/netops-syslog-*/_delete_by_query?refresh=true",
            {"query": {"prefix": {"hostname.keyword": self.prefix}}},
            timeout=300)
        if not okd or not isinstance(res, dict):
            problems.append(f"OpenSearch syslog purge failed: {res}")
            ev["os_deleted"] = -1
        else:
            ev["os_deleted"] = res.get("deleted", -1)
            if res.get("failures"):
                problems.append(f"OpenSearch purge reported failures: {str(res['failures'])[:200]}")
        left = self.stack.os_count("netops-syslog-*", "hostname.keyword", self.prefix)
        ev["os_docs_left"] = left
        if left != 0:
            problems.append(f"{left} run docs left in netops-syslog-*")
        ev["residuals_note"] = (
            "corr_objects/evidence and correlation DLQ entries tagged with this "
            "run TTL/rotate out on their own; VictoriaMetrics holds no run "
            "series (devices were never polled successfully)")

        status = "PASS" if not problems else "FAIL"
        return self.phase("cleanup", status, ev,
                          "; ".join(problems) if problems else
                          f"{ev['devices_deleted']} devices deleted+verified, "
                          f"telemetry purged (CH+OS)")

    # -- report --------------------------------------------------------------
    def report(self) -> bool:
        overall = all(p["status"] == "PASS" for p in self.phases) and bool(self.phases)
        doc = {
            "harness": "scale-miniladder",
            "runid": self.runid,
            "generated": utcnow(),
            "overall": "PASS" if overall else "FAIL",
            "parameters": {
                "devices": self.args.devices,
                "burst_minutes": self.args.burst_minutes,
                "eps": self.args.eps,
                "linearity_floor": self.args.linearity_floor,
                "drain_factor": self.args.drain_factor,
                "lag_epsilon": self.args.lag_epsilon,
                "mem_factor": self.args.mem_factor,
                "tls_variant": self.stack.tls,
                "base_url": self.stack.base_url,
            },
            "phases": self.phases,
        }
        with open(os.path.join(self.run_dir, "report.json"), "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1)

        lines = [
            f"# G2 scale mini-ladder — run {self.runid}",
            "",
            f"- **Overall: {'PASS' if overall else 'FAIL'}**",
            f"- Generated: {doc['generated']}",
            (f"- Stack: {self.stack.base_url} (TLS variant: {self.stack.tls}, "
             f"project `{self.args.project}`)"),
            (f"- Parameters: {self.args.devices} devices, "
             f"{self.args.burst_minutes} min burst @ {self.args.eps} eps target, "
             f"linearity floor {self.args.linearity_floor}, "
             f"drain budget {self.args.drain_factor}x burst, "
             f"lag epsilon {self.args.lag_epsilon}, mem factor {self.args.mem_factor}"),
            "",
            "| Phase | Status | Notes |",
            "|---|---|---|",
        ]
        for p in self.phases:
            notes = " ".join(p["notes"].replace("|", "\\|").split())
            lines.append(f"| {p['phase']} | {p['status']} | {notes} |")
        lines += ["", "## Evidence", ""]
        for p in self.phases:
            lines.append(f"### {p['phase']} ({p['status']})")
            lines.append("```json")
            lines.append(json.dumps(p["evidence"], indent=1, default=str)[:6000])
            lines.append("```")
            lines.append("")
        lines.append("Raw evidence files (lag curve, burst chunks) sit next to this "
                      "report in the run directory.")
        with open(os.path.join(self.run_dir, "report.md"), "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

        # Heartbeat for the watchdog (16.2): a cron job that silently stops
        # running must itself be detectable.
        hb = {"ts": doc["generated"], "runid": self.runid,
              "overall": doc["overall"], "run_dir": self.run_dir}
        with open(os.path.join(os.path.dirname(self.run_dir), "last-run.json"),
                  "w", encoding="utf-8") as f:
            json.dump(hb, f, indent=1)
        log(f"report written: {os.path.join(self.run_dir, 'report.md')}")
        return overall

    # -- orchestration -------------------------------------------------------
    def execute(self) -> int:
        os.makedirs(self.run_dir, exist_ok=True)
        log(f"run {self.runid} -> {self.run_dir}")
        aborted_early = False
        try:
            if not self.preflight():
                # A broken stack means nothing was created — report and stop
                # without inventing results for phases that never ran.
                aborted_early = True
            else:
                self.onboard()
                # A linearity FAIL still leaves N devices standing — carry on
                # through burst/drain/accounting whenever creation itself
                # succeeded; the phase verdicts stay independent.
                if self.created_ids and self.burst():
                    # Leak anchor: sampled the instant injection stops, so the
                    # workload's caches/buffers are materialized but nothing
                    # new is arriving (see memflat's header).
                    self.warm_mem = self.stack.mem_sample()
                    self.drain()
                    self.accounting()
                self.memflat()
        except KeyboardInterrupt:
            warn("interrupted — running cleanup before exit")
            self.phase("interrupted", "FAIL", {}, "run interrupted by signal")
        finally:
            try:
                if getattr(self.args, "skip_cleanup", False):
                    self.phase(
                        "cleanup", "SKIPPED",
                        {"reason": "--skip-cleanup (diagnostic run)",
                         "residue_warning": (
                             "devices, corr_signals, corr_objects and OpenSearch "
                             "docs are STILL PRESENT and will be counted by the "
                             "next run's baselines")},
                        "cleanup deliberately skipped for investigation — this "
                        "run is NOT qualification evidence")
                else:
                    self.cleanup()
            except Exception as exc:  # noqa: BLE001 — cleanup must never mask the run error silently
                warn(f"cleanup raised: {exc!r}")
                self.phase("cleanup", "FAIL", {}, f"cleanup crashed: {exc!r}")
        overall = self.report()
        if aborted_early:
            return 2
        return 0 if overall else 1


def parse_args(argv: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="scale-miniladder.py",
        description="G2 self-judging scale-regression harness (see module docstring; "
                    "--help shows flags, the header shows the cron line).")
    ap.add_argument("--devices", type=int, default=1000,
                    help="devices to create for the onboarding probe (default 1000)")
    ap.add_argument("--burst-minutes", type=int, default=5,
                    help="ingest burst duration in minutes (default 5)")
    ap.add_argument("--eps", type=int, default=2000,
                    help="target injected events/second — pick ~10x your nominal "
                         "syslog rate and ABOVE the ~1k/s correlation drain ceiling "
                         "so the drain proof is not vacuous (default 2000)")
    ap.add_argument("--linearity-floor", type=float, default=0.6,
                    help="last-window/first-window creation-rate floor (default 0.6)")
    ap.add_argument("--drain-factor", type=float, default=3.0,
                    help="drain budget as a multiple of burst duration (default 3.0)")
    ap.add_argument("--lag-epsilon", type=int, default=100,
                    help="allowed lag above baseline to count as drained (default 100)")
    ap.add_argument("--max-baseline-lag", type=int, default=5000,
                    help="refuse to run when correlation lag already exceeds this "
                         "at preflight — the drain verdict needs a near-idle "
                         "baseline (default 5000)")
    ap.add_argument("--mem-factor", type=float, default=1.3,
                    help="max end/WARM container memory ratio — the leak slope "
                         "after injection stops (default 1.3). The cold->warm "
                         "step is evidence, not a verdict: a short burst cannot "
                         "separate first-touch cache materialization from a leak")
    ap.add_argument("--mem-headroom-percent", type=float, default=85.0,
                    help="fail when a key container ends above this percentage "
                         "of ITS OWN plan-sized memory cap (#102) — the OOM "
                         "path, self-relative so it holds on any host "
                         "(default 85)")
    ap.add_argument("--consumer-settle-seconds", type=int, default=180,
                    help="bounded wait for the correlation + router consumer "
                         "groups to show a live member at preflight. Bring-up "
                         "cost is hardware-dependent (a cold CI runner spends a "
                         "JVM per topic in kafka-init, so the engine's final "
                         "rebalance can land minutes after compose returns); "
                         "patience is tuned here, the assertion never is "
                         "(default 180)")
    ap.add_argument("--run-dir", default="",
                    help="run directory (default <repo>/data/miniladder/<ts>-<runid>)")
    ap.add_argument("--env-file",
                    default=os.path.join(REPO_ROOT, "deployment", "docker", ".env"),
                    help="compose .env for credentials/topology (default repo's)")
    ap.add_argument("--base-url", default="",
                    help="API base URL (default http://localhost:<BASE_PORT from .env>)")
    ap.add_argument("--project", default="",
                    help="compose project name (default COMPOSE_PROJECT_NAME or netops)")
    ap.add_argument(
        "--skip-cleanup", action="store_true",
        help="DIAGNOSTIC ONLY. Leave devices, ClickHouse rows and OpenSearch "
             "docs in place so the run can be investigated afterwards. The "
             "2026-08-19 927/1000 coverage gap could not be diagnosed because "
             "cleanup purges the run's rows before anything can query them. "
             "Never use for qualification: the next run inherits the residue.")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the full plan and exit; touches nothing")
    # tracker 152 §8.3 — twin composition. Default is the internal generator,
    # byte-identical to the pre-flag behavior.
    ap.add_argument("--load-generator", choices=("internal", "twin"),
                    default="internal", dest="load_generator",
                    help="burst-phase load source: internal (default; the "
                         "built-in syslog loop) or twin (delegate to "
                         "scripts/lab/twin/twin.py run — the ladder keeps "
                         "judging; the twin's twin-report.json counts feed "
                         "accounting)")
    ap.add_argument("--twin-scenario", default="",
                    help="scenario file for --load-generator twin")
    ap.add_argument("--twin-duration-minutes", type=float, default=10.0,
                    help="twin run duration (twin mode only; default 10)")
    ap.add_argument("--twin-fidelity", choices=("hostname", "source_ip"),
                    default="hostname",
                    help="fidelity mode passed through to twin.py (default "
                         "hostname)")
    args = ap.parse_args(argv)
    if args.load_generator == "twin" and not args.twin_scenario:
        ap.error("--load-generator twin requires --twin-scenario FILE")
    if args.devices < 10 or args.devices > 20000:
        ap.error("--devices must be between 10 and 20000")
    if args.burst_minutes < 1 or args.burst_minutes > 60:
        ap.error("--burst-minutes must be between 1 and 60")
    if args.eps < 10 or args.eps > 20000:
        ap.error("--eps must be between 10 and 20000")
    return args


def main(argv: list[str]) -> int:
    os.environ["PATH"] = CRON_PATH          # see CRON_PATH: process-entry only
    args = parse_args(argv)
    if not args.project:
        args.project = env_get(args.env_file, "COMPOSE_PROJECT_NAME") or "netops"
    if not args.base_url:
        port = env_get(args.env_file, "BASE_PORT") or "8000"
        args.base_url = f"http://localhost:{port}"

    if args.dry_run:
        planned = args.eps * 60 * args.burst_minutes
        print("scale-miniladder DRY RUN — nothing will be touched")
        print(f"  stack           : {args.base_url} (project {args.project}, "
              f"env {args.env_file})")
        print(f"  phase 1 preflight: {len(REQUIRED_SERVICES)} required services, "
              f"active bus consumers (bounded wait {args.consumer_settle_seconds}s), "
              f"baselines (RSS/offsets/lag/CH/VM/durability)")
        print(f"  phase 2 onboard  : create {args.devices} devices "
              f"(mlx-<runid>-NNNNN @ 198.18/15); last/first window rate floor "
              f"{args.linearity_floor}")
        print(f"  phase 3 burst    : registry gate + canary, then {planned} syslog "
              f"events @ {args.eps}/s for {args.burst_minutes} min to netops.syslog")
        print(f"  phase 4 drain    : lag back to baseline+{args.lag_epsilon} within "
              f"{args.drain_factor}x burst")
        print("  phase 5 account  : injected == OS-persisted + run DLQ + counted "
              "rejections (exact); per-device corr_signals coverage; zero "
              "quarantine-write-failure movement")
        print(f"  phase 6 memflat  : {', '.join(MEM_SERVICES)} <= x{args.mem_factor} "
              f"of their END-OF-BURST RSS, and under "
              f"{args.mem_headroom_percent}% of their own caps")
        print("  phase 7 cleanup  : delete+verify devices, purge CH/OS run telemetry")
        print("  report           : report.md + report.json + last-run.json heartbeat")
        return 0

    if not os.path.isfile(args.env_file):
        die(f"env file not found: {args.env_file} (use --env-file)")

    # Make ^C hit the KeyboardInterrupt path (cleanup in finally) on SIGTERM too.
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))

    return Harness(args).execute()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
