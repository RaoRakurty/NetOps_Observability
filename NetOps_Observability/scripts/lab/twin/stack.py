"""Live-stack access layer for the twin (tracker 152).

Adapted from the PROVEN mechanics of `scripts/scale-miniladder.py` (§16 bar:
every call bounded, every failure carries its stderr, credentials never on
argv):

  * API login/creds from MLX_ADMIN_* env or ADMIN_USERNAME /
    ADMIN_INITIAL_PASSWORD in the compose .env — the same source
    clean-slate.sh --verify uses;
  * Kafka via in-container CLI tools; the TLS variant rides
    `--producer.config /tmp/kafka-tls/admin.properties` (console producer) /
    `--command-config` (admin tools);
  * ClickHouse via clickhouse-client with `tenant_scope='__all__'`
    (ops-catalog idiom);
  * OpenSearch via in-container curl with a config-on-stdin (creds never on
    argv);
  * correlation healthz per REPLICA (the twin needs each replica's partition
    assignment for the §6 spread proof, so unlike the mini-ladder it
    enumerates every correlation container).

Twin-specific additions: KEYED console production (`parse.key` + tab
separator) so injected records honor the bus's tenant-keyed murmur2
partitioner contract — unkeyed injection would round-robin and void the
partition-spread measurement.
"""
from __future__ import annotations

import json
import subprocess
import sys
import urllib.error
import urllib.request

DOCKER_TIMEOUT = 30
KAFKA_TOOL_TIMEOUT = 90
HTTP_TIMEOUT = 15
MUTATION_TIMEOUT = 180


def log(msg: str) -> None:
    print(f"twin: {msg}", flush=True)


def warn(msg: str) -> None:
    print(f"twin: WARNING: {msg}", file=sys.stderr, flush=True)


def run(cmd: list[str], timeout: int,
        input_text: str | None = None) -> tuple[int, str, str]:
    """Bounded subprocess. Never raises on non-zero exit — callers must look
    at rc and REPORT stderr (§16.1: no swallowed errors)."""
    try:
        p = subprocess.run(cmd, input=input_text, capture_output=True,
                           text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s: {' '.join(cmd[:4])} ..."
    except FileNotFoundError as exc:
        return 127, "", str(exc)


def env_get(env_file: str, key: str) -> str:
    """First KEY= value from the compose .env. Missing file/key -> '' (callers
    decide whether empty is fatal — documented mini-ladder contract)."""
    try:
        with open(env_file, encoding="utf-8") as f:
            for line in f:
                if line.startswith(key + "="):
                    return line.rstrip("\n").split("=", 1)[1]
    except OSError:
        pass
    return ""


class StackError(RuntimeError):
    """A stack interaction failed in a way the run cannot proceed past."""


class Stack:
    """Access layer for the live stack. Every call is bounded; every failure
    carries its stderr."""

    def __init__(self, env_file: str, base_url: str, project: str):
        self.env_file = env_file
        self.project = project
        self.base_url = base_url.rstrip("/")
        compose_files = env_get(env_file, "COMPOSE_FILE")
        self.tls = "compose.tls.yml" in compose_files
        self.token = ""
        self._cids: dict[str, str] = {}
        self._all_cids: dict[str, list[str]] = {}

    # -- containers ---------------------------------------------------------
    def cids(self, service: str) -> list[str]:
        """ALL running container ids of a compose service (correlation runs
        with --scale N; the spread proof needs every replica)."""
        if service not in self._all_cids:
            rc, out, err = run(
                ["docker", "ps", "-q",
                 "--filter", f"label=com.docker.compose.project={self.project}",
                 "--filter", f"label=com.docker.compose.service={service}"],
                DOCKER_TIMEOUT)
            if rc != 0:
                warn(f"docker ps for {service} failed: {err.strip()}")
            self._all_cids[service] = out.split()
        return self._all_cids[service]

    def cid(self, service: str) -> str:
        cs = self.cids(service)
        return cs[0] if cs else ""

    def service_states(self) -> list[dict]:
        rc, out, err = run(
            ["docker", "ps", "-a",
             "--filter", f"label=com.docker.compose.project={self.project}",
             "--format",
             "{{.Label \"com.docker.compose.service\"}}\t{{.ID}}\t{{.State}}"],
            DOCKER_TIMEOUT)
        if rc != 0:
            warn(f"docker ps -a failed: {err.strip()}")
            return []
        rows = []
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) == 3:
                rows.append({"service": parts[0], "id": parts[1],
                             "status": parts[2]})
        return rows

    # -- API ----------------------------------------------------------------
    def login(self) -> None:
        import os
        user = os.environ.get("MLX_ADMIN_USER") or env_get(self.env_file,
                                                           "ADMIN_USERNAME")
        pw = (os.environ.get("MLX_ADMIN_PASSWORD")
              or env_get(self.env_file, "ADMIN_INITIAL_PASSWORD"))
        if not user or not pw:
            raise StackError(
                "no admin credentials: set MLX_ADMIN_USER/MLX_ADMIN_PASSWORD "
                f"or provide ADMIN_USERNAME/ADMIN_INITIAL_PASSWORD in "
                f"{self.env_file}")
        body = json.dumps({"username": user, "password": pw}).encode()
        req = urllib.request.Request(
            f"{self.base_url}/api/auth/login", data=body,
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
                tok = json.load(r).get("token", "")
        except (urllib.error.URLError, OSError) as exc:
            raise StackError(f"API login failed: {exc}") from exc
        if not tok:
            raise StackError("API login returned no token "
                             "(password rotated since install?)")
        self.token = tok

    def api(self, method: str, path: str,
            body: dict | None = None) -> tuple[int, object]:
        """Authenticated API call; re-logins ONCE on 401 (token TTL vs long
        runs). Returns (status, parsed-json-or-text)."""
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
            except (urllib.error.URLError, OSError) as exc:
                return 0, f"unreachable: {exc}"
        return 0, "unreachable"

    # -- Kafka --------------------------------------------------------------
    def _kafka_conn(self, config_flag: str = "--command-config") -> list[str]:
        if self.tls:
            return ["--bootstrap-server", "kafka:9094",
                    config_flag, "/tmp/kafka-tls/admin.properties"]
        return ["--bootstrap-server", "kafka:9092"]

    def kafka_tool(self, tool: str, args: list[str],
                   input_text: str | None = None,
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

    def produce_keyed(self, topic: str,
                      keyed_lines: list[tuple[str, str]]) -> tuple[bool, str]:
        """Produce (key, value) records via the console producer with
        parse.key — the key is the TENANT id, so the broker's Java murmur2
        DefaultPartitioner places each record exactly where the production
        Vector sinks would (the partitioner contract every producer on this
        bus must honor, design §4.7)."""
        for key, value in keyed_lines:
            if "\t" in key or "\n" in key or "\n" in value:
                return False, (f"refusing to produce: key/value contains the "
                               f"key separator or newline (key={key!r})")
        payload = "\n".join(f"{k}\t{v}" for k, v in keyed_lines) + "\n"
        rc, _, err = self.kafka_tool(
            "kafka-console-producer.sh",
            ["--topic", topic,
             "--property", "parse.key=true",
             "--property", "key.separator=\t"],
            input_text=payload,
            timeout=max(KAFKA_TOOL_TIMEOUT, 30 + len(keyed_lines) // 500),
            config_flag="--producer.config")
        if rc != 0:
            return False, err.strip()[:400]
        return True, ""

    def group_partitions(self, group: str) -> dict:
        """Per-partition consumer-group state:
        {topic: {partition: {current,end,lag}}, "_members": n, "_total": lag}.
        kafka-consumer-groups --describe columns: GROUP TOPIC PARTITION
        CURRENT-OFFSET LOG-END-OFFSET LAG CONSUMER-ID HOST CLIENT-ID."""
        rc, out, err = self.kafka_tool(
            "kafka-consumer-groups.sh", ["--describe", "--group", group])
        if rc != 0:
            return {"_error": err.strip()[:300], "_total": -1, "_members": 0}
        topics: dict[str, dict[int, dict]] = {}
        total, members = 0, 0
        for line in out.splitlines():
            f = line.split()
            if len(f) >= 6 and f[0] == group and f[2].isdigit():
                topic, part = f[1], int(f[2])
                cur = int(f[3]) if f[3].lstrip("-").isdigit() else -1
                end = int(f[4]) if f[4].lstrip("-").isdigit() else -1
                try:
                    lag = int(f[5])
                except ValueError:
                    lag = -1
                topics.setdefault(topic, {})[part] = {
                    "current": cur, "end": end, "lag": lag}
                total += max(lag, 0)
                if len(f) >= 7 and f[6] != "-":
                    members += 1
        return {**topics, "_total": total, "_members": members}

    def group_lag_total(self, group: str) -> tuple[int, int]:
        g = self.group_partitions(group)
        return int(g.get("_total", -1)), int(g.get("_members", 0))

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

    def ch_json(self, query: str, timeout: int = 60) -> list[dict]:
        ok, out = self.ch(query + " FORMAT JSONEachRow", timeout)
        if not ok:
            warn(f"clickhouse query failed: {out}")
            return []
        rows = []
        for ln in out.splitlines():
            if ln.strip():
                try:
                    rows.append(json.loads(ln))
                except json.JSONDecodeError:
                    warn(f"clickhouse returned unparseable row: {ln[:120]}")
        return rows

    def ch_mutation(self, query: str) -> tuple[bool, str]:
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
               body: dict | None = None,
               timeout: int = 25) -> tuple[bool, dict | str]:
        """In-container curl with creds via a stdin curl config, never argv
        (docs/ops/OBSERVABILITY_AUDIT.md §0 idiom)."""
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
            cfg = (f'url = "http://localhost:9200{url_path}"\n'
                   f"max-time = {timeout}\nsilent\n")
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

    # -- correlation replicas -----------------------------------------------
    def corr_get(self, cid: str, path: str) -> tuple[bool, str]:
        """healthz/metrics from ONE replica. TLS variant: connect to the
        replica's OWN loopback (`https://localhost:8443`) so Docker-DNS
        round-robin on `correlation:8443` cannot answer from a DIFFERENT
        replica; the chain is still CA-verified + mTLS-client-authenticated —
        only the hostname check is relaxed (the SVID names the service, not
        localhost). Lab-tool read of an operational endpoint, verified live."""
        if self.tls:
            py = ("import urllib.request,ssl;"
                  "ctx=ssl.create_default_context(cafile='/certs/ca.pem');"
                  "ctx.check_hostname=False;"
                  "ctx.load_cert_chain('/certs/svid/correlation.crt',"
                  "'/certs/svid/correlation.key');"
                  f"print(urllib.request.urlopen('https://localhost:8443{path}',"
                  f"timeout=8,context=ctx).read().decode())")
        else:
            py = ("import urllib.request;"
                  f"print(urllib.request.urlopen('http://localhost:8000{path}',"
                  f"timeout=8).read().decode())")
        rc, out, err = run(["docker", "exec", cid, "python", "-c", py], 30)
        if rc != 0:
            return False, err.strip()[:400]
        return True, out

    def corr_healthz_all(self) -> dict[str, dict]:
        """healthz per correlation REPLICA, keyed by short container id."""
        out: dict[str, dict] = {}
        for cid in self.cids("correlation"):
            ok, raw = self.corr_get(cid, "/healthz")
            if not ok:
                out[cid[:12]] = {"_error": raw}
                continue
            try:
                out[cid[:12]] = json.loads(raw)
            except json.JSONDecodeError:
                out[cid[:12]] = {"_error": raw[:300]}
        return out

    def dlq_run_lines(self, runid: str) -> int:
        """Run-attributable correlation DLQ lines across replicas."""
        total = 0
        seen_any = False
        for cid in self.cids("correlation"):
            rc, out, err = run(
                ["docker", "exec", cid, "sh", "-c",
                 f"cat /data/deadletter/* 2>/dev/null | grep -c -- '{runid}'"],
                DOCKER_TIMEOUT)
            # grep -c exits 1 on zero matches — that is a real 0, not an error.
            if rc not in (0, 1):
                warn(f"DLQ grep failed on {cid[:12]}: {err.strip()[:200]}")
                continue
            seen_any = True
            try:
                total += int(out.strip() or "0")
            except ValueError:
                warn(f"DLQ grep returned non-numeric on {cid[:12]}: {out[:80]}")
        return total if seen_any else -1
