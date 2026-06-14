#!/usr/bin/env python3
"""SNMP / telemetry fidelity harness — runtime, hop-by-hop, entrance→exit.

This is the RUNTIME counterpart to `audit_metric_contract.py` (which is the
*static*, build-time panel↔emitted guard). This harness inspects what is
ACTUALLY flowing through the live stack and asserts it obeys the research-based
design contract documented in:
    docs/design/telemetry-coverage-reference.md   (single-contract LAW)
    docs/design/telemetry-baseline-research.md    (required SNMP families)
    docs/design/correlation-engine.md             (observer/modality model)
    deployment/docker/gnmic/gnmic.yaml            (gNMI→SNMP ownership gate)

It walks the SNMP path one hop at a time and fails loudly when an invariant is
violated — so a silent gap (un-polled device, missing ifName, +Inf-poisoned
gauge, a family double-emitted by two transports, telemetry that never reaches
the correlation entrance) is caught here, not in a demo.

    Hop A  Ingest liveness      collectors are up
    Hop B  Coverage + freshness every expected device is polled, samples fresh
    Hop C  Contract conformance the single-contract LAW: device_*{device,vendor,ifName,index}
    Hop D  Family coverage      every device emits the research-required IF-MIB families
    Hop E  Ownership gate       exactly one transport per (device,family); the gNMI flip is correct
    Hop F  Value sanity         no +Inf / out-of-range / negative poison
    Hop G  Exit to consumers    SNMP telemetry reaches correlation with correct provenance

Usage:
    python3 scripts/snmp_fidelity_harness.py            # human report, exit 1 on FAIL
    python3 scripts/snmp_fidelity_harness.py --json     # machine-readable (CI)
    python3 scripts/snmp_fidelity_harness.py --strict   # WARN also fails the run

Endpoint discovery (override any with env):
    VM_URL   (default: http://<docker-ip netops-victoria-1>:8428)
    CH_URL   (default: http://<docker-ip netops-clickhouse-1>:8123)
    CH_USER / CH_PASS    (default: read from deployment/docker/.env)
    COMPOSE_PROJECT      (default: netops)

Stdlib-only except PyYAML (a script, not the Go backend; PyYAML is already a
correlation-service dependency). Falls back to a minimal parser if absent.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
DEVICES_YAML = os.path.join(ROOT, "src", "config", "devices.yaml")
ENV_FILE = os.path.join(ROOT, "deployment", "docker", ".env")
PROJECT = os.environ.get("COMPOSE_PROJECT", "netops")

# --- Design constants (grounded; cite source in comment) -------------------

# The single-contract LAW: every canonical interface series MUST carry these
# label keys (telemetry-coverage-reference.md; collectors/snmpmetrics.go:114-119).
REQUIRED_IF_LABELS = ("device", "vendor", "ifName", "index")

# Research-required IF-MIB families every SNMP device MUST emit
# (profiles.go generic profile; telemetry-baseline-research.md). Missing any of
# these on a polled, reachable device is a FAIL — it is a real collection gap.
CORE_IF_FAMILIES = (
    "device_if_in_octets",
    "device_if_out_octets",
    "device_if_oper_status",
    "device_if_admin_status",
    "device_if_speed",
    "device_if_in_errors",
    "device_if_out_errors",
    "device_if_in_discards",
    "device_if_out_discards",
)

# Families the SNMP transport OWNS — they must NEVER also be served by gNMI
# (the ownership gate: one transport per (device,family); gnmic.yaml:343-348).
SNMP_OWNED_FAMILIES = (
    "device_if_in_octets",
    "device_if_out_octets",
    "device_if_oper_status",
    "device_cpu_percent",
    "device_temp_celsius",
)

# Family the gNMI transport owns because the device has NO SNMP source
# (gnmic.yaml:342; audit_metric_contract.py GNMI_OWNED). Nokia SR Linux only.
GNMI_OWNED_FAMILY = "device_mem_percent"
GNMI_OWNED_VENDOR = "nokia"

# Freshness ceiling: telegraf polls every 30s (telegraf.conf:9). 3× interval +
# scrape slack is a generous "this device is currently being polled" bound.
FRESH_MAX_AGE_S = 95.0

# IF-MIB enum domains (RFC 2863).
OPER_STATUS_DOMAIN = set(range(1, 8))   # up(1)..lowerLayerDown(7)
ADMIN_STATUS_DOMAIN = {1, 2, 3}         # up(1) down(2) testing(3)

# Control-plane families expected by role (WARN, not FAIL — vendor/topology
# dependent; surfaced so a regression is visible without false-failing).
ROLE_CONTROL_PLANE = {
    "spine": ["device_bgp_peer_state", "device_isis_adj_state"],
    "leaf": ["device_bgp_peer_state"],
    "wan": ["device_bgp_peer_state"],
}

# ---------------------------------------------------------------------------

GREEN, RED, YEL, BLU, DIM, RST = (
    "\033[32m", "\033[31m", "\033[33m", "\033[36m", "\033[2m", "\033[0m"
)
if not sys.stdout.isatty():
    GREEN = RED = YEL = BLU = DIM = RST = ""

PASS, FAIL, WARN, SKIP, INFO = "PASS", "FAIL", "WARN", "SKIP", "INFO"
_COLOR = {PASS: GREEN, FAIL: RED, WARN: YEL, SKIP: DIM, INFO: BLU}

results: list[dict] = []


def record(hop: str, test: str, status: str, detail: str = "") -> None:
    results.append({"hop": hop, "test": test, "status": status, "detail": detail})
    mark = f"{_COLOR[status]}{status:4}{RST}"
    line = f"  [{mark}] {test}"
    if detail:
        line += f"  {DIM}— {detail}{RST}"
    print(line)


def hop(title: str) -> None:
    print(f"\n{BLU}━━ {title}{RST}")


# --- endpoint + config discovery -------------------------------------------

def docker_ip(container: str) -> str | None:
    try:
        out = subprocess.run(
            ["docker", "inspect", "-f",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
             container],
            capture_output=True, text=True, timeout=15,
        )
        ip = (out.stdout or "").split()
        return ip[0] if ip else None
    except Exception:
        return None


def container_running(container: str) -> bool:
    try:
        out = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", container],
            capture_output=True, text=True, timeout=15,
        )
        return out.stdout.strip() == "true"
    except Exception:
        return False


def read_env(key: str) -> str | None:
    try:
        with open(ENV_FILE) as fh:
            for ln in fh:
                if ln.startswith(key + "="):
                    return ln.split("=", 1)[1].strip()
    except OSError:
        pass
    return None


def resolve_endpoints() -> dict:
    vm = os.environ.get("VM_URL")
    if not vm:
        ip = docker_ip(f"{PROJECT}-victoria-1")
        vm = f"http://{ip}:8428" if ip else None
    ch = os.environ.get("CH_URL")
    if not ch:
        ip = docker_ip(f"{PROJECT}-clickhouse-1")
        ch = f"http://{ip}:8123" if ip else None
    return {
        "vm": vm,
        "ch": ch,
        "ch_user": os.environ.get("CH_USER") or read_env("CLICKHOUSE_USER") or "default",
        "ch_pass": os.environ.get("CH_PASS") or read_env("CLICKHOUSE_PASSWORD") or "",
    }


def load_inventory() -> dict:
    """Expected SNMP devices from src/config/devices.yaml: {name: {vendor, role}}."""
    try:
        import yaml
        with open(DEVICES_YAML) as fh:
            doc = yaml.safe_load(fh) or {}
        devs = doc.get("devices", {})
    except Exception:
        devs = _minimal_devices_parse()
    inv = {}
    for name, d in (devs or {}).items():
        d = d or {}
        if str(d.get("preferred_protocol", "snmp")).lower() != "snmp":
            continue
        inv[name] = {
            "vendor": (d.get("vendor") or "").lower(),
            "role": ((d.get("labels") or {}).get("role") or "").lower(),
        }
    return inv


def _minimal_devices_parse() -> dict:
    """Fallback YAML reader for the flat devices.yaml shape (no PyYAML)."""
    out, cur = {}, None
    indent_dev = None
    try:
        with open(DEVICES_YAML) as fh:
            lines = fh.readlines()
    except OSError:
        return out
    in_devices = False
    for ln in lines:
        if re.match(r"^devices:\s*$", ln):
            in_devices = True
            continue
        if not in_devices or not ln.strip() or ln.lstrip().startswith("#"):
            continue
        m = re.match(r"^(\s+)([A-Za-z0-9_-]+):\s*$", ln)
        if m and (indent_dev is None or len(m.group(1)) == indent_dev):
            indent_dev = len(m.group(1))
            cur = m.group(2)
            out[cur] = {"labels": {}}
            continue
        if cur:
            mv = re.match(r"^\s+vendor:\s*(\S+)", ln)
            mp = re.match(r"^\s+preferred_protocol:\s*(\S+)", ln)
            mr = re.match(r"^\s+role:\s*(\S+)", ln)
            if mv:
                out[cur]["vendor"] = mv.group(1)
            if mp:
                out[cur]["preferred_protocol"] = mp.group(1)
            if mr:
                out[cur].setdefault("labels", {})["role"] = mr.group(1)
    return out


# --- query helpers ----------------------------------------------------------

def http_get(url: str, timeout: float = 12.0) -> str:
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def vm_query(vm: str, promql: str) -> list[dict]:
    """Instant PromQL query → result list ([] on error)."""
    url = vm + "/api/v1/query?query=" + urllib.parse.quote(promql)
    try:
        doc = json.loads(http_get(url))
        if doc.get("status") != "success":
            return []
        return doc["data"]["result"]
    except Exception:
        return []


def ch_query(ep: dict, sql: str) -> str:
    """ClickHouse HTTP query → raw text ('' on error). Adds tenant scope."""
    if "SETTINGS" not in sql.upper():
        sql = sql + " SETTINGS tenant_scope='__all__'"
    req = urllib.request.Request(
        ep["ch"] + "/", data=sql.encode(),
        headers={"X-ClickHouse-User": ep["ch_user"],
                 "X-ClickHouse-Key": ep["ch_pass"]},
    )
    try:
        with urllib.request.urlopen(req, timeout=12) as r:
            return r.read().decode("utf-8", "replace").strip()
    except Exception as e:  # noqa: BLE001
        return f"__ERR__ {e}"


def fnum(s) -> float:
    try:
        return float(s)
    except (TypeError, ValueError):
        return float("nan")


# === HOPS ===================================================================

def hop_a_liveness(ep: dict) -> None:
    hop("Hop A — ingest liveness (collectors up)")
    for svc, name in (("telegraf (SNMP poller)", f"{PROJECT}-telegraf-1"),
                      ("gnmic (gNMI sub)", f"{PROJECT}-gnmic-1"),
                      ("victoria (TSDB)", f"{PROJECT}-victoria-1")):
        record("A", f"{svc} container running",
               PASS if container_running(name) else FAIL,
               name if not container_running(name) else "")
    # VM answers PromQL at all
    up = bool(vm_query(ep["vm"], "vector(1)"))
    record("A", "VictoriaMetrics answers PromQL", PASS if up else FAIL, ep["vm"])


def hop_b_coverage(ep: dict, inv: dict) -> set:
    hop("Hop B — coverage + freshness (every expected device polled, fresh)")
    # observed devices + freshness from the universal canary series.
    ages = vm_query(ep["vm"], "time() - timestamp(device_sysuptime)")
    age_by_dev = {r["metric"].get("device"): fnum(r["value"][1]) for r in ages}
    observed = set(age_by_dev)

    expected = set(inv)
    missing = sorted(expected - observed)
    extra = sorted(observed - expected)

    record("B", f"device coverage {len(observed & expected)}/{len(expected)} expected polled",
           PASS if not missing else FAIL,
           ("not reporting: " + ", ".join(missing)) if missing else "all expected devices report")
    if extra:
        record("B", "inventory drift (reporting but not in devices.yaml)",
               INFO, ", ".join(extra))

    stale = sorted(d for d in observed if age_by_dev[d] > FRESH_MAX_AGE_S)
    record("B", f"freshness < {FRESH_MAX_AGE_S:.0f}s on all reporting devices",
           PASS if not stale else FAIL,
           ("STALE: " + ", ".join(f"{d}={age_by_dev[d]:.0f}s" for d in stale))
           if stale else f"{len(observed)} devices fresh")
    return observed


def hop_c_contract(ep: dict, inv: dict, observed: set) -> None:
    hop("Hop C — contract conformance (single-contract LAW)")
    series = vm_query(ep["vm"], "device_if_in_octets")
    if not series:
        record("C", "interface contract present", FAIL, "no device_if_in_octets series at all")
        return

    # C1: required labels present + non-empty on every interface series.
    offenders = []
    for r in series:
        m = r["metric"]
        miss = [k for k in REQUIRED_IF_LABELS if not m.get(k)]
        if miss:
            offenders.append(f"{m.get('device','?')}/{m.get('ifName', m.get('index','?'))}:{'+'.join(miss)}")
    record("C", "every interface series carries {device,vendor,ifName,index}",
           PASS if not offenders else FAIL,
           ("; ".join(offenders[:8]) + (" …" if len(offenders) > 8 else "")) if offenders else
           f"{len(series)} series conform")

    # C2: vendor label matches the inventory's declared vendor.
    mismatch = []
    seen_vendor = {}
    for r in series:
        m = r["metric"]
        dev, ven = m.get("device"), (m.get("vendor") or "").lower()
        if dev:
            seen_vendor.setdefault(dev, ven)
    for dev, want in inv.items():
        got = seen_vendor.get(dev)
        if got and want["vendor"] and got != want["vendor"]:
            mismatch.append(f"{dev}: inv={want['vendor']} metric={got}")
    record("C", "vendor label matches devices.yaml",
           PASS if not mismatch else FAIL,
           "; ".join(mismatch) if mismatch else "vendors consistent")

    # C3: ifName is a real name, not a bare ifIndex number (#71 ifIndex→ifName).
    numeric = []
    for r in series:
        m = r["metric"]
        nm = m.get("ifName", "")
        if nm and re.fullmatch(r"\d+", nm):
            numeric.append(f"{m.get('device','?')}:{nm}")
    record("C", "ifName is human-readable (not bare ifIndex)",
           PASS if not numeric else FAIL,
           "; ".join(sorted(set(numeric))[:10]) if numeric else "all ifNames resolved")

    # C4: no path-shaped / dotted / uppercase leak in the canonical lane.
    names = []
    try:
        names = json.loads(http_get(ep["vm"] + "/api/v1/label/__name__/values"))["data"]
    except Exception:
        pass
    leaked = [n for n in names if n.startswith("device_") and re.search(r"[/.A-Z]", n)]
    record("C", "canonical lane has no path-shaped/dotted leak",
           PASS if not leaked else FAIL,
           ", ".join(leaked[:8]) if leaked else f"{len([n for n in names if n.startswith('device_')])} clean device_* names")


def hop_d_families(ep: dict, inv: dict, observed: set) -> None:
    hop("Hop D — family coverage (research-required IF-MIB families)")
    polled = sorted(observed & set(inv))
    # one PromQL per family: which devices emit it.
    emit = {}
    for fam in CORE_IF_FAMILIES:
        devs = {r["metric"].get("device") for r in vm_query(ep["vm"], f"count by (device)({fam})")}
        emit[fam] = devs
    gaps = []
    for dev in polled:
        miss = [fam for fam in CORE_IF_FAMILIES if dev not in emit[fam]]
        if miss:
            gaps.append(f"{dev}: " + ",".join(f.replace("device_if_", "") for f in miss))
    record("D", "all polled devices emit the core IF-MIB family set",
           PASS if not gaps else FAIL,
           "; ".join(gaps) if gaps else f"{len(CORE_IF_FAMILIES)} families × {len(polled)} devices complete")

    # control-plane by role (WARN only).
    for role, fams in ROLE_CONTROL_PLANE.items():
        role_devs = [d for d in polled if inv[d]["role"] == role]
        if not role_devs:
            continue
        for fam in fams:
            present = {r["metric"].get("device") for r in vm_query(ep["vm"], f"count by (device)({fam})")}
            miss = [d for d in role_devs if d not in present]
            record("D", f"{role}: {fam}", PASS if not miss else WARN,
                   ("missing on " + ", ".join(miss)) if miss else f"on all {len(role_devs)} {role}(s)")


def hop_e_ownership(ep: dict) -> None:
    hop("Hop E — ownership gate (one transport per (device,family))")
    # E1: gNMI owns device_mem_percent on Nokia SRL (no SNMP source there).
    mem = vm_query(ep["vm"], GNMI_OWNED_FAMILY)
    nokia_gnmi = [r["metric"].get("device") for r in mem
                  if (r["metric"].get("vendor", "").lower() == GNMI_OWNED_VENDOR
                      and r["metric"].get("transport") == "gnmi")]
    record("E", f"{GNMI_OWNED_FAMILY} on Nokia served by transport=gnmi",
           PASS if nokia_gnmi else FAIL,
           ("gnmi-owned: " + ", ".join(sorted(nokia_gnmi))) if nokia_gnmi else
           "no Nokia gNMI-owned mem series (flip broken?)")

    # E2: SNMP-owned families must NOT appear with transport=gnmi (no double-emit).
    violations = []
    for fam in SNMP_OWNED_FAMILIES:
        for r in vm_query(ep["vm"], fam):
            if r["metric"].get("transport") == "gnmi":
                violations.append(f"{fam}@{r['metric'].get('device','?')}")
    record("E", "SNMP-owned families never double-emitted by gNMI",
           PASS if not violations else FAIL,
           "; ".join(sorted(set(violations))[:10]) if violations else
           f"{len(SNMP_OWNED_FAMILIES)} owned families single-transport")

    # E3: raw gnmi_* liveness/parity lane intact.
    try:
        names = json.loads(http_get(ep["vm"] + "/api/v1/label/__name__/values"))["data"]
    except Exception:
        names = []
    raw = [n for n in names if n.startswith("gnmi_")]
    record("E", "raw gnmi_* parity lane present", PASS if raw else WARN,
           f"{len(raw)} raw gnmi_* series" if raw else "no raw gNMI lane (parity source gone)")


def hop_f_sanity(ep: dict) -> None:
    hop("Hop F — value sanity (no +Inf / out-of-range / negative poison)")
    # F1: device_if_speed — no +Inf, no negative (the #71 division-poison guard).
    bad_speed = []
    for r in vm_query(ep["vm"], "device_if_speed"):
        v = r["value"][1]
        x = fnum(v)
        if v in ("+Inf", "-Inf", "NaN") or x != x or x < 0:
            bad_speed.append(f"{r['metric'].get('device','?')}/{r['metric'].get('ifName','?')}={v}")
    record("F", "device_if_speed has no +Inf/NaN/negative",
           PASS if not bad_speed else FAIL,
           "; ".join(bad_speed[:8]) if bad_speed else "all speeds finite ≥ 0")

    # F2: oper/admin status enums in domain.
    for fam, dom, label in (("device_if_oper_status", OPER_STATUS_DOMAIN, "oper"),
                            ("device_if_admin_status", ADMIN_STATUS_DOMAIN, "admin")):
        bad = []
        for r in vm_query(ep["vm"], fam):
            x = fnum(r["value"][1])
            if x == x and int(x) not in dom:
                bad.append(f"{r['metric'].get('device','?')}/{r['metric'].get('ifName','?')}={int(x)}")
        record("F", f"{label}_status within IF-MIB enum domain",
               PASS if not bad else FAIL,
               "; ".join(bad[:8]) if bad else "in domain")

    # F3: percentages in [0,100].
    for fam in ("device_cpu_percent", "device_mem_percent"):
        bad = []
        for r in vm_query(ep["vm"], fam):
            x = fnum(r["value"][1])
            if x == x and not (0 <= x <= 100):
                bad.append(f"{r['metric'].get('device','?')}={x:.1f}")
        rows = vm_query(ep["vm"], fam)
        record("F", f"{fam} in [0,100]",
               (PASS if not bad else FAIL) if rows else SKIP,
               ("; ".join(bad[:8]) if bad else ("in range" if rows else "no series")))


def rpk(args: list[str]) -> str:
    """Run rpk inside the redpanda container → stdout ('' on error)."""
    try:
        out = subprocess.run(
            ["docker", "exec", f"{PROJECT}-redpanda-1", "rpk", *args],
            capture_output=True, text=True, timeout=20,
        )
        return out.stdout
    except Exception:
        return ""


def hop_g_exit(ep: dict) -> None:
    hop("Hop G — exit to consumers (telemetry reaches correlation w/ provenance)")

    # G1: the correlation engine is actually consuming (group Stable, lag bounded).
    # This is liveness — independent of whether any anomaly fired.
    desc = rpk(["group", "describe", "netops-correlation"])
    if not desc:
        record("G", "correlation consumer group reachable", SKIP, "rpk unavailable")
        metrics_fed = None
    else:
        total_lag = None
        m = re.search(r"TOTAL-LAG\s+(\d+)", desc)
        if m:
            total_lag = int(m.group(1))
        record("G", "correlation engine consuming Redpanda (lag bounded)",
               PASS if (total_lag is not None and total_lag < 10000) else FAIL,
               f"TOTAL-LAG={total_lag}" if total_lag is not None else "no lag line")

        # G2: is the SNMP-metric lane FED at all? Telegraf writes straight to VM;
        # correlation's metric-anomaly path consumes the netops.metrics topic. If
        # that topic is near-empty relative to the other planes, the lane is
        # UNWIRED (a real gap) — distinct from "quiet fabric, no anomaly".
        def end_offset(topic: str) -> int:
            for ln in desc.splitlines():
                if ln.lstrip().startswith(topic + " ") or f" {topic} " in ln:
                    cols = ln.split()
                    # TOPIC PARTITION CURRENT LOG-START LOG-END LAG ...
                    try:
                        return int(cols[4])
                    except (IndexError, ValueError):
                        pass
            return -1
        m_end, f_end = end_offset("netops.metrics"), end_offset("netops.flows")
        metrics_fed = m_end >= 1000
        record("G", "SNMP-metric lane is fed (netops.metrics produced, not starved)",
               PASS if metrics_fed else FAIL,
               f"netops.metrics end-offset={m_end} vs netops.flows={f_end} — "
               + ("metric→correlation lane wired"
                  if metrics_fed else
                  "near-empty: SNMP metrics reach VM but NOT correlation; "
                  "device_telemetry CUSUM signals cannot be produced"))

    # G3: device-plane DOES reach correlation (any modality). Proves the device
    # observer class is alive even when the metric lane is starved (syslog path).
    out = ch_query(ep, "SELECT count() FROM netops.corr_signals "
                       "WHERE ts > now() - INTERVAL 1 HOUR AND observer_type='device'")
    if out.startswith("__ERR__"):
        record("G", "device-observer signals reach correlation (last 1h)", SKIP, out)
    else:
        n = int(out) if out.isdigit() else 0
        record("G", "device-observer signals reach correlation (last 1h)",
               PASS if n > 0 else WARN,
               f"{n} device-observer signals (control_plane/device_telemetry)")

    # G3b: device_telemetry (SNMP-metric CUSUM) specifically — anomaly-gated, so
    # absence is only a FAULT when the lane is fed; otherwise it's expected-quiet.
    out_dt = ch_query(ep, "SELECT count() FROM netops.corr_signals "
                          "WHERE ts > now() - INTERVAL 30 MINUTE "
                          "AND modality_class='device_telemetry'")
    if out_dt.startswith("__ERR__"):
        record("G", "device_telemetry (SNMP-metric) signals", SKIP, out_dt)
    else:
        ndt = int(out_dt) if out_dt.isdigit() else 0
        if ndt > 0:
            record("G", "device_telemetry (SNMP-metric) signals present", PASS, f"{ndt} in 30m")
        elif metrics_fed is False:
            record("G", "device_telemetry (SNMP-metric) signals present", FAIL,
                   "0 — and metric lane is starved (root cause above), not anomaly-gating")
        else:
            record("G", "device_telemetry (SNMP-metric) signals present", INFO,
                   "0 in 30m — anomaly-gated; expected on a quiet fabric (lane is fed)")

    # observer provenance LAW: no signal may carry an empty observer_id.
    out2 = ch_query(ep, "SELECT count() FROM netops.corr_signals "
                        "WHERE ts > now() - INTERVAL 1 HOUR AND observer_id=''")
    if out2.startswith("__ERR__"):
        record("G", "observer_id never empty", SKIP, out2)
    else:
        n2 = int(out2) if out2.isdigit() else -1
        record("G", "observer_id provenance never empty (last 1h)",
               PASS if n2 == 0 else FAIL,
               "all signals stamped" if n2 == 0 else f"{n2} signals missing observer_id")


# === main ===================================================================

def main() -> int:
    ap = argparse.ArgumentParser(description="SNMP/telemetry fidelity harness (runtime, hop-by-hop)")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    ap.add_argument("--strict", action="store_true", help="WARN also fails the run")
    args = ap.parse_args()

    ep = resolve_endpoints()
    inv = load_inventory()

    if not args.json:
        print(f"{BLU}SNMP / telemetry fidelity harness{RST}  "
              f"{DIM}VM={ep['vm']}  CH={ep['ch']}  inventory={len(inv)} SNMP devices{RST}")
    if not ep["vm"]:
        print(f"{RED}FATAL: VictoriaMetrics endpoint not resolvable "
              f"(set VM_URL or run on the stack host).{RST}")
        return 2

    hop_a_liveness(ep)
    observed = hop_b_coverage(ep, inv)
    hop_c_contract(ep, inv, observed)
    hop_d_families(ep, inv, observed)
    hop_e_ownership(ep)
    hop_f_sanity(ep)
    hop_g_exit(ep)

    counts = {k: sum(1 for r in results if r["status"] == k)
              for k in (PASS, FAIL, WARN, SKIP, INFO)}
    failed = counts[FAIL] + (counts[WARN] if args.strict else 0)

    if args.json:
        print(json.dumps({"results": results, "counts": counts,
                          "ok": failed == 0}, indent=2))
    else:
        print(f"\n{BLU}━━ summary{RST}")
        print(f"  {GREEN}PASS {counts[PASS]}{RST}   {RED}FAIL {counts[FAIL]}{RST}   "
              f"{YEL}WARN {counts[WARN]}{RST}   {DIM}SKIP {counts[SKIP]}  INFO {counts[INFO]}{RST}")
        verdict = (f"{GREEN}FIDELITY OK{RST}" if failed == 0
                   else f"{RED}FIDELITY VIOLATIONS: {failed}{RST}")
        print(f"  {verdict}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
