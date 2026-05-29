#!/usr/bin/env python3
"""End-to-end smoke test for the NetOps Observability stack.

Probes every tier and the API surface and prints a PASS/WARN/FAIL line for
each, with a summary. Designed to answer one question: "is every module
actually working?"

Tiers checked (internal ones via `docker compose exec`):
  nginx · API · OpenSearch · VictoriaMetrics · Prometheus · Grafana ·
  ClickHouse · Redpanda · correlation
API endpoints checked through nginx (:8000). Endpoints behind auth are
verified live either way: with a token we expect 200; without, a 401 still
proves the route is wired (reported as WARN, not FAIL).

Auth (optional, unlocks the 200-level API checks):
  NETOPS_TOKEN=<jwt>                  use this bearer token, or
  NETOPS_USER + NETOPS_PASSWORD       log in to mint one
Falls back to ADMIN_USERNAME/ADMIN_INITIAL_PASSWORD from .env if present.

Stdlib only. Exit code is non-zero if any check FAILs.

  ./smoke-test.py              # full run
  ./smoke-test.py --host 1.2.3.4
"""
import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

G, Y, R, B, X = "\033[32m", "\033[33m", "\033[31m", "\033[1m", "\033[0m"
if not sys.stdout.isatty():
    G = Y = R = B = X = ""

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"
COLOR = {PASS: G, WARN: Y, FAIL: R}
results = []  # (status, name, detail)


def record(status, name, detail=""):
    results.append((status, name, detail))
    tag = f"{COLOR[status]}{status}{X}"
    print(f"  [{tag}] {name}" + (f" — {detail}" if detail else ""))


def compose_dir():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(os.path.dirname(here), "deployment", "docker")


def dexec(service, *cmd, timeout=20):
    """Run a command inside a compose service. Returns (rc, stdout, stderr)."""
    try:
        p = subprocess.run(
            ["docker", "compose", "exec", "-T", service, *cmd],
            cwd=compose_dir(), capture_output=True, timeout=timeout,
        )
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", "docker not found"


# Internal services bind to the compose network only, and the `api` image is
# distroless (no shell). We probe internal HTTP from the opensearch container,
# which ships curl and can reach every service by name.
PROBE_SVC = "opensearch"


def probe(url, method="GET", timeout=6):
    """HTTP GET/POST an internal URL from inside the network. (code, body)."""
    rc, out, err = dexec(PROBE_SVC, "curl", "-s", "-m", str(timeout),
                         "-w", "\n%{http_code}", "-X", method, url, timeout=timeout + 5)
    if rc != 0:
        return None, (err.strip() or "curl failed")
    body, _, code = out.rpartition("\n")
    return (int(code) if code.strip().isdigit() else None), body


def http(url, method="GET", data=None, headers=None, timeout=10):
    """Returns (status_code, body_text) or (None, error_str)."""
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return None, str(e)


# ---------------------------------------------------------------------------
# Tier checks
# ---------------------------------------------------------------------------
def check_compose_services():
    rc, out, err = dexec_ps()
    if rc != 0:
        record(FAIL, "compose services", err.strip()[:120] or "compose ps failed")
        return
    running = [l for l in out.splitlines() if l.strip()]
    not_up = [l for l in running if " running" not in l.lower() and " up" not in l.lower()
              and "healthy" not in l.lower()]
    if not_up:
        record(WARN, "compose services", f"{len(not_up)} not running: " + ", ".join(s.split()[0] for s in not_up[:5]))
    else:
        record(PASS, "compose services", f"{len(running)} services up")


def dexec_ps():
    try:
        p = subprocess.run(
            ["docker", "compose", "ps", "--format", "{{.Service}} {{.State}}"],
            cwd=compose_dir(), capture_output=True, timeout=20,
        )
        return p.returncode, p.stdout.decode(), p.stderr.decode()
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)


def check_nginx(base):
    code, _ = http(base + "/")
    if code in (200, 301, 302):
        record(PASS, "nginx (:8000)", f"HTTP {code}")
    else:
        record(FAIL, "nginx (:8000)", f"HTTP {code}")


def check_api_health(base):
    code, body = http(base + "/admin/health")
    if code == 200:
        try:
            j = json.loads(body)
            st = j.get("status", "?")
            record(PASS if st == "healthy" else WARN, "API /admin/health", f"status={st}")
        except json.JSONDecodeError:
            record(WARN, "API /admin/health", "200 but unparseable body")
    else:
        record(FAIL, "API /admin/health", f"HTTP {code}")


def check_opensearch():
    code, out = probe("http://opensearch:9200/_cluster/health")
    if code == 200 and out:
        try:
            st = json.loads(out).get("status")
            ok = st in ("green", "yellow")
            _, idx = probe("http://opensearch:9200/_cat/indices/netops-*?h=index,docs.count")
            docs = sum(int(l.split()[1]) for l in idx.splitlines() if len(l.split()) > 1 and l.split()[1].isdigit())
            record(PASS if ok else FAIL, "OpenSearch", f"cluster={st}, netops docs={docs}")
        except (json.JSONDecodeError, ValueError):
            record(WARN, "OpenSearch", "health unparseable")
    else:
        record(FAIL, "OpenSearch", f"HTTP {code}")


def check_victoria():
    code, _ = probe("http://victoria:8428/health")
    if code == 200:
        # Count distinct metric series seen in the last hour (range-aware so
        # one-shot pushes outside the 5-min instant-staleness window still
        # count — matching how the Metrics Explorer range-queries).
        _, q = probe("http://victoria:8428/api/v1/query?query="
                     "count(count_over_time(%7B__name__!%3D%22%22%7D%5B1h%5D))")
        n = "?"
        try:
            res = json.loads(q).get("data", {}).get("result", [])
            n = res[0]["value"][1] if res else "0"
        except (json.JSONDecodeError, IndexError, KeyError):
            pass
        record(PASS, "VictoriaMetrics", f"health ok, series(1h)≈{n}")
    else:
        record(FAIL, "VictoriaMetrics", f"health HTTP {code}")


def check_prometheus():
    code, out = probe("http://prometheus:9090/api/v1/targets?state=active")
    if code != 200:
        record(FAIL, "Prometheus", f"targets HTTP {code}")
        return
    try:
        tg = json.loads(out)["data"]["activeTargets"]
        up = sum(1 for t in tg if t.get("health") == "up")
        down = [t["labels"].get("job") for t in tg if t.get("health") != "up"]
        if down:
            record(WARN, "Prometheus", f"{up}/{len(tg)} targets up; down: {', '.join(down)}")
        else:
            record(PASS, "Prometheus", f"{up}/{len(tg)} targets up")
    except (json.JSONDecodeError, KeyError):
        record(WARN, "Prometheus", "targets unparseable")


def check_grafana():
    code, out = probe("http://grafana:3000/api/health")
    if code == 200 and out:
        try:
            db = json.loads(out).get("database")
            record(PASS if db == "ok" else WARN, "Grafana", f"database={db}")
        except json.JSONDecodeError:
            record(WARN, "Grafana", "health unparseable")
    else:
        record(FAIL, "Grafana", f"health HTTP {code}")


def check_clickhouse():
    rc, out, err = dexec("clickhouse", "clickhouse-client", "-q",
                         "SELECT (SELECT count() FROM netops.flows), (SELECT count() FROM netops.findings)")
    if rc == 0 and out.strip():
        parts = out.split()
        flows = parts[0] if parts else "?"
        findings = parts[1] if len(parts) > 1 else "?"
        record(PASS, "ClickHouse", f"flows={flows}, findings={findings}")
    else:
        record(FAIL, "ClickHouse", (err.strip()[:100] or "query failed"))


def check_redpanda():
    rc, out, _ = dexec("redpanda", "rpk", "topic", "list")
    if rc == 0:
        topics = [l.split()[0] for l in out.splitlines()[1:] if l.strip()]
        want = {"netops.applogs", "netops.flows", "netops.metrics", "netops.syslog"}
        missing = want - set(topics)
        if missing:
            record(WARN, "Redpanda", f"topics present={len(topics)}, missing: {', '.join(missing)}")
        else:
            record(PASS, "Redpanda", f"all 4 netops topics present")
    else:
        record(FAIL, "Redpanda", "topic list failed")


def check_correlation():
    for path in ("/healthz", "/findings"):
        code, _ = probe(f"http://correlation:8000{path}")
        if code == 200:
            record(PASS, "correlation", f"reachable ({path})")
            return
    record(WARN, "correlation", "no /healthz|/findings 200 (may be idle)")


# ---------------------------------------------------------------------------
# API surface
# ---------------------------------------------------------------------------
def get_token(base):
    if os.environ.get("NETOPS_TOKEN"):
        return os.environ["NETOPS_TOKEN"]
    user = os.environ.get("NETOPS_USER")
    pw = os.environ.get("NETOPS_PASSWORD")
    if not (user and pw):
        user, pw = _admin_from_env()
    if not (user and pw):
        return None
    code, body = http(base + "/api/auth/login", method="POST",
                      data=json.dumps({"username": user, "password": pw}).encode(),
                      headers={"Content-Type": "application/json"})
    if code == 200:
        try:
            return json.loads(body).get("token")
        except json.JSONDecodeError:
            return None
    return None


def _admin_from_env():
    env = os.path.join(compose_dir(), ".env")
    u = p = None
    try:
        with open(env) as f:
            for line in f:
                if line.startswith("ADMIN_USERNAME="):
                    u = line.split("=", 1)[1].strip()
                elif line.startswith("ADMIN_INITIAL_PASSWORD="):
                    p = line.split("=", 1)[1].strip()
    except OSError:
        pass
    return (u or "admin"), p


def check_api_endpoints(base, token):
    hdr = {"Authorization": f"Bearer {token}"} if token else {}
    # (label, method, path, body)
    eps = [
        ("GET /api/devices", "GET", "/api/devices", None),
        ("GET /api/collectors", "GET", "/api/collectors", None),
        ("GET /api/alerts", "GET", "/api/alerts", None),
        ("GET /api/rules", "GET", "/api/rules", None),
        ("POST /api/logs/search", "POST", "/api/logs/search", {"query": "*", "size": 1}),
        ("GET /api/flows/top", "GET", "/api/flows/top?since=3600s&limit=5", None),
        ("GET /api/metrics/names", "GET", "/api/metrics/names", None),
        ("GET /api/findings", "GET", "/api/findings?limit=5", None),
        ("GET /api/search/global", "GET", "/api/search/global?q=edge", None),
        ("GET /api/reports/runs", "GET", "/api/reports/runs", None),
    ]
    for label, method, path, body in eps:
        data = json.dumps(body).encode() if body is not None else None
        h = dict(hdr)
        if data is not None:
            h["Content-Type"] = "application/json"
        code, _ = http(base + path, method=method, data=data, headers=h)
        if code == 200:
            record(PASS, label, "HTTP 200")
        elif code == 401:
            record(WARN, label, "401 (route live; supply a token to verify 200)")
        else:
            record(FAIL, label, f"HTTP {code}")


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default=os.environ.get("NETOPS_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("BASE_PORT", "8000")))
    args = ap.parse_args()
    base = f"http://{args.host}:{args.port}"

    print(f"{B}NetOps stack smoke test → {base}{X}\n")

    print(f"{B}Infrastructure{X}")
    check_compose_services()
    check_nginx(base)
    check_api_health(base)

    print(f"\n{B}Storage & ingest tiers{X}")
    check_opensearch()
    check_victoria()
    check_prometheus()
    check_grafana()
    check_clickhouse()
    check_redpanda()
    check_correlation()

    print(f"\n{B}API surface{X}")
    token = get_token(base)
    if token:
        print(f"  (authenticated — verifying 200-level responses)")
    else:
        print(f"  (no token — auth'd routes reported as WARN; set NETOPS_TOKEN or NETOPS_USER/NETOPS_PASSWORD)")
    check_api_endpoints(base, token)

    # Summary
    n_pass = sum(1 for s, _, _ in results if s == PASS)
    n_warn = sum(1 for s, _, _ in results if s == WARN)
    n_fail = sum(1 for s, _, _ in results if s == FAIL)
    print(f"\n{B}Summary:{X} {G}{n_pass} PASS{X} · {Y}{n_warn} WARN{X} · {R}{n_fail} FAIL{X}")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
