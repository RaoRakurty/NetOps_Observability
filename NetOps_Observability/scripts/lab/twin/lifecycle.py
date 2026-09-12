# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Run lifecycle: preflight → tenancy → devices → gates → seams → teardown
(tracker 152, design §7).

Registration goes through the REAL API exactly like production onboarding:
`POST /api/devices?as_tenant=<tenant-id>` — `withActingTenant`
(src/backend/tenancy.go) narrows the platform owner to that tenant, so
`principalTenant` returns (tenant, cross=false) and the handler stamps
`TenantID` from the effective PRINCIPAL, never the body (§3a). That write
regenerates `device_tenant.csv`, which is what the correlation registry gate
below waits on (the mini-ladder's Gate-1, verbatim — without it every injected
event tenant-refuses into the DLQ, proven live 2026-08-16).

Teardown is the VERIFIED mini-ladder cleanup contract, extended: delete +
paged verify-zero devices, retire seams, wait for consumer DRAIN before the
telemetry purge (the late-insert residue race, fixed in the mini-ladder on
2026-08-16 — a purge issued while lag drains races the engine's late inserts,
which then land after the delete and survive), purge ClickHouse + OpenSearch
by run tag and verify zero, then remove run-created tenants/orgs.
"""
from __future__ import annotations

import json
import os
import time

from murmur import tenant_partition
from stack import Stack, log

REQUIRED_SERVICES = [
    "api", "clickhouse", "correlation", "kafka", "nginx", "opensearch",
    "postgres", "vector-aggregator", "vector-router", "victoria",
]

REGISTRY_GATE_TIMEOUT_S = 300
SEAM_GATE_TIMEOUT_S = 180
CANARY_TIMEOUT_S = 150
DRAIN_WAIT_TIMEOUT_S = 600
TENANT_PLACEMENT_ATTEMPTS = 25


class LifecycleError(RuntimeError):
    """A lifecycle phase failed; the message says what and how to fix it."""


# ── preflight ───────────────────────────────────────────────────────────────

def preflight(stack: Stack, partitions: int) -> dict:
    """Stack healthy + consumers ACTIVE + no stale twx namespace + baselines.
    Raises LifecycleError with every problem listed (§16: loud refusal)."""
    problems: list[str] = []
    ev: dict = {}

    states = stack.service_states()
    seen = {s["service"] for s in states}
    for req in REQUIRED_SERVICES:
        if req not in seen:
            problems.append(f"required service missing: {req}")
    for s in states:
        if s["service"] in REQUIRED_SERVICES and s["status"] not in ("running",):
            problems.append(f"{s['service']} is {s['status']}")
    ev["services"] = len(states)

    stack.login()

    # ACTIVE consumers (offsets alone lie — dead-consumer shape of the
    # 2026-08-16 wiped-ACL incident). --describe can race the coordinator;
    # poll a bounded window before believing "no consumer".
    deadline = time.monotonic() + 60
    members = 0
    while time.monotonic() < deadline:
        _total, members = stack.group_lag_total("netops-correlation")
        if members >= 1:
            break
        time.sleep(10)
    if members < 1:
        problems.append("netops-correlation has NO active consumer "
                        "(dead engine or bus authorization failure)")
    total, _ = stack.group_lag_total("netops-correlation")
    ev["baseline_corr_lag"] = total
    if total > 5000:
        problems.append(f"correlation lag already {total} at baseline — the "
                        f"stack is not idle enough for a truthful run")

    # replica assignment must cover all partitions of the scenario's intent
    hz = stack.corr_healthz_all()
    owned: set[int] = set()
    regs: list[int] = []
    for cid, h in hz.items():
        if "_error" in h:
            problems.append(f"correlation replica {cid} healthz unreachable: "
                            f"{h['_error']}")
            continue
        parts = h.get("consumer", {}).get("assignment", {}).get(
            "netops.syslog", [])
        owned.update(int(p) for p in parts)
        regs.append(int(h.get("tenant_verification", {})
                        .get("registry_identities", -1)))
    ev["replicas"] = len(hz)
    ev["owned_partitions"] = sorted(owned)
    ev["baseline_registry_identities"] = min(regs) if regs else -1
    if owned and owned != set(range(partitions)):
        problems.append(
            f"correlation replicas own partitions {sorted(owned)} but the bus "
            f"has {partitions} — assignment does not cover the spread intent")

    # stale-run guard: refuse when a previous twx- namespace survives
    st, resp = stack.api("GET", "/api/devices?envelope=1&limit=5000&offset=0")
    if st != 200 or not isinstance(resp, dict):
        problems.append(f"device list failed: HTTP {st} {str(resp)[:120]}")
    else:
        stale = [d.get("id") for d in (resp.get("devices") or [])
                 if str(d.get("id", "")).startswith("twx-")]
        if stale:
            problems.append(
                f"{len(stale)} stale twx- devices survive from a previous run "
                f"(first: {stale[0]}) — run `twin.py teardown --runid "
                f"{str(stale[0]).split('-')[1]}` first")

    if problems:
        raise LifecycleError("preflight refused:\n  - " + "\n  - ".join(problems))
    return ev


# ── tenancy (orgs + tenants, partition placement computed not hoped) ────────

def _delete_tenant(stack: Stack, tenant_id: str, name: str) -> tuple[bool, str]:
    from urllib.parse import quote
    st, resp = stack.api(
        "DELETE", f"/api/tenants/{tenant_id}?confirm={quote(name)}&force=true")
    if st not in (204, 404):
        return False, f"HTTP {st} {str(resp)[:120]}"
    return True, ""


def setup_tenancy(stack: Stack, sc: dict, runid: str,
                  partitions: int) -> tuple[dict, list[dict]]:
    """Create run-scoped orgs + tenants; COMPUTE each tenant's partition
    (murmur2 over the opaque id the server mints) and re-mint colliding
    tenants until the set covers min(T, P) distinct partitions (design §6:
    placement is computed, not hoped for — ids are random, so coverage is
    achieved by bounded re-mint, and the run REFUSES if it cannot be).

    Returns ({alias: {tenant_id, name, slug, org_id, partition}}, orgs)."""
    tenants_cfg = sc["tenants"]
    target_coverage = min(len(tenants_cfg), partitions)

    orgs: list[dict] = []
    org_ids: dict[str, str] = {}
    for t in tenants_cfg:
        org = t.get("org")
        if not org or org in org_ids:
            continue
        name = f"twx-{runid}-{org}"
        st, resp = stack.api("POST", "/api/orgs", {"name": name, "slug": name})
        if st != 201 or not isinstance(resp, dict):
            raise LifecycleError(f"org create {name!r} failed: HTTP {st} "
                                 f"{str(resp)[:200]}")
        org_ids[org] = str(resp.get("id") or "")
        orgs.append({"scenario_org": org, "id": org_ids[org], "name": name})

    placed: dict[str, dict] = {}
    used_partitions: dict[int, str] = {}
    attempts = 0
    for t in tenants_cfg:
        alias = t["alias"]
        suffix = 0
        while True:
            attempts += 1
            if attempts > TENANT_PLACEMENT_ATTEMPTS:
                raise LifecycleError(
                    f"could not place {len(tenants_cfg)} tenants across "
                    f"{target_coverage} partitions within "
                    f"{TENANT_PLACEMENT_ATTEMPTS} create attempts — "
                    f"partition coverage is a hard requirement of the spread "
                    f"proof (design §6); re-run, or reduce the coverage need")
            name = f"twx-{runid}-{alias}" + (f"-r{suffix}" if suffix else "")
            body = {"name": name, "slug": name}
            if t.get("org"):
                body["org_id"] = org_ids[t["org"]]
            st, resp = stack.api("POST", "/api/tenants", body)
            if st != 201 or not isinstance(resp, dict):
                raise LifecycleError(f"tenant create {name!r} failed: "
                                     f"HTTP {st} {str(resp)[:200]}")
            tid = str(resp.get("id") or "")
            part = tenant_partition(tid, partitions)
            covered = len(set(used_partitions) | {part})
            remaining = len(tenants_cfg) - len(placed) - 1
            # accept when this placement can still reach target coverage
            if part not in used_partitions or covered + remaining >= target_coverage:
                placed[alias] = {"tenant_id": tid, "name": name, "slug": name,
                                 "org_id": org_ids.get(t.get("org") or "", ""),
                                 "partition": part}
                used_partitions.setdefault(part, alias)
                break
            # colliding mint that would strand coverage — delete and re-mint
            ok, err = _delete_tenant(stack, tid, name)
            if not ok:
                raise LifecycleError(f"re-mint delete of tenant {name!r} "
                                     f"failed: {err}")
            suffix += 1
    coverage = len({v["partition"] for v in placed.values()})
    if coverage < target_coverage:
        raise LifecycleError(
            f"tenant set covers only {coverage}/{target_coverage} partitions "
            f"after placement — refusing (design §6 fail-fast)")
    log(f"tenancy: {len(placed)} tenants over partitions "
        f"{sorted({v['partition'] for v in placed.values()})} "
        f"(coverage {coverage}/{target_coverage}, {attempts} create attempts)")
    return placed, orgs


# ── devices ─────────────────────────────────────────────────────────────────

def device_address(i: int) -> str:
    """Twin address plan (design §3.4): 198.19.0.0/16 — RFC 2544 benchmark
    space (unroutable, mini-ladder precedent) but DISJOINT from the
    mini-ladder's own 198.18.x.y so both can run on one stack."""
    return f"198.19.{i // 250}.{i % 250 + 1}"


def register_devices(stack: Stack, sc: dict, prefix: str, runid: str,
                     tenants: dict) -> list[str]:
    created: list[str] = []
    for i, d in enumerate(sc["devices"]):
        name = prefix + d["name"]
        tid = tenants[d["tenant"]]["tenant_id"]
        body = {
            "id": name, "name": name, "address": device_address(i),
            "type": "router", "source": "twin-t1",
            "labels": {"twx_run": runid, "twin_role": d["role"]},
        }
        st, resp = stack.api("POST", f"/api/devices?as_tenant={tid}", body)
        if st != 201:
            raise LifecycleError(f"device create {name!r} (as_tenant={tid}) "
                                 f"failed: HTTP {st} {str(resp)[:200]}")
        created.append(name)
    log(f"devices: {len(created)} registered via POST /api/devices as_tenant")
    return created


def registry_gate(stack: Stack, baseline_min: int, created: int) -> dict:
    """Wait until EVERY correlation replica's registry_identities reaches
    baseline + created (the mini-ladder Gate-1; healthz is eager since the
    2026-08-16 fix, so an idle replica reports the CSV truth too)."""
    want = max(baseline_min, 0) + created
    deadline = time.monotonic() + REGISTRY_GATE_TIMEOUT_S
    per_replica: dict[str, int] = {}
    while time.monotonic() < deadline:
        hz = stack.corr_healthz_all()
        per_replica = {
            cid: int(h.get("tenant_verification", {})
                     .get("registry_identities", -1))
            for cid, h in hz.items()}
        if per_replica and all(v >= want for v in per_replica.values()):
            log(f"registry gate: all {len(per_replica)} replicas ≥ {want} "
                f"identities {per_replica}")
            return {"want": want, "observed": per_replica}
        time.sleep(10)
    raise LifecycleError(
        f"registry never propagated to every correlation replica "
        f"({per_replica} < {want} after {REGISTRY_GATE_TIMEOUT_S}s) — "
        f"injected events would be tenant-refused into the DLQ; aborting "
        f"before emission")


# ── seams ───────────────────────────────────────────────────────────────────

def _seam_payloads(sc: dict, prefix: str, tenants: dict) -> list[dict]:
    """Scenario seams → unified seam objects (SeamView shape). Endpoints carry
    the STRUCTURAL identities the grounding gate matches (engine.py rank 2):
    member device names, plus any provider-side resource_id a story attaches
    to this seam (so the cloud half grounds onto the same seam instance)."""
    out = []
    for sm in sc.get("seams") or []:
        endpoints: dict[str, str] = {}
        for i, mb in enumerate(sm.get("members") or []):
            endpoints[f"member_{mb.get('role') or i}"] = prefix + mb["member_id"]
        for st in sc.get("stories") or []:
            if (st["affected"].get("seam") == sm["seam_id"]):
                cloud = (st.get("params") or {}).get("cloud") or {}
                rid = cloud.get("resource_id")
                if rid:
                    endpoints["provider_resource"] = prefix + str(rid)
        tenant_alias = sm.get("tenant") or ""
        out.append({
            "seam_id": prefix + sm["seam_id"],
            "tenant_id": tenants[tenant_alias]["tenant_id"] if tenant_alias else "",
            "seam_type": sm["seam_type"],
            "state": "active",
            "display_name": sm.get("description") or sm["seam_id"],
            "endpoints": endpoints,
            "visibility": "partial",
            "control_plane_owner": "enterprise",
        })
    return out


def register_seams(stack: Stack, sc: dict, prefix: str, tenants: dict,
                   enrichment_dir: str) -> dict:
    """Register scenario seams so the engine's grounding gate loads them
    through the production enrichment path (SEAM_ENRICHMENT_FILE).

    Primary path: POST /api/seams (state=active) — the Go API exports
    seams.json every 60 s (startSeamEnrichment). FALLBACK: on the file store
    backend the seam inventory is Postgres-only and the API answers 501; the
    twin then writes seams.json into the SAME host enrichment dir the API
    would (documented lab fallback — the engine's read contract is identical,
    and teardown removes the file)."""
    payloads = _seam_payloads(sc, prefix, tenants)
    if not payloads:
        return {"mode": "none", "count": 0}
    mode = "api"
    for p in payloads:
        st, resp = stack.api("POST", "/api/seams", p)
        if st == 501:
            mode = "file"
            break
        if st != 201:
            raise LifecycleError(f"seam create {p['seam_id']!r} failed: "
                                 f"HTTP {st} {str(resp)[:200]}")
    if mode == "file":
        path = os.path.join(enrichment_dir, "seams.json")
        if os.path.exists(path):
            raise LifecycleError(
                f"{path} already exists — refusing to overwrite a seam "
                f"inventory the twin does not own (postgres-backed stacks "
                f"export it; remove/inspect it first)")
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payloads, f)
        os.replace(tmp, path)
        log(f"seams: API store is file-backed (501) — wrote {len(payloads)} "
            f"seam(s) to {path} (engine enrichment fallback)")

    # gate: every replica's seam_inventory reaches the created count
    deadline = time.monotonic() + SEAM_GATE_TIMEOUT_S
    per_replica: dict[str, int] = {}
    while time.monotonic() < deadline:
        hz = stack.corr_healthz_all()
        per_replica = {cid: int(h.get("engine_v2", {}).get("seam_inventory", -1))
                       for cid, h in hz.items()}
        if per_replica and all(v >= len(payloads)
                               for v in per_replica.values()):
            return {"mode": mode, "count": len(payloads),
                    "replicas": per_replica}
        time.sleep(10)
    raise LifecycleError(
        f"seam inventory never reached the engine ({per_replica} < "
        f"{len(payloads)} after {SEAM_GATE_TIMEOUT_S}s) — seam-grounded "
        f"stories would silently lose attribution; aborting")


# ── canary ──────────────────────────────────────────────────────────────────

def canary(stack: Stack, prefix: str, device: str, tenant_id: str) -> None:
    """One event through the whole pipe before any story fires (mini-ladder
    pattern): produce → engine → corr_signals."""
    from emitters import build_payload
    item = {"lane": "syslog", "device": device, "tenant": "_canary",
            "appname": "LINK-3-UPDOWN",
            "message": "%LINK-3-UPDOWN: Interface Management0, changed state "
                       "to up [twin canary]",
            "severity": "notice"}
    payload = build_payload(item, prefix, {"_canary": tenant_id})
    ok, err = stack.produce_keyed("netops.syslog", [(tenant_id, payload)])
    if not ok:
        raise LifecycleError(f"canary produce failed: {err}")
    deadline = time.monotonic() + CANARY_TIMEOUT_S
    while time.monotonic() < deadline:
        okq, out = stack.ch(
            f"SELECT count() FROM netops.corr_signals "
            f"WHERE entity_id LIKE '%{prefix}%'")
        if okq and out.isdigit() and int(out) >= 1:
            log("canary: signal landed in corr_signals — pipe proven")
            return
        time.sleep(10)
    dlq = stack.dlq_run_lines(prefix)
    raise LifecycleError(
        f"canary event produced no corr_signal within {CANARY_TIMEOUT_S}s — "
        f"pipeline broken between the bus and ClickHouse "
        f"(run-tagged DLQ lines: {dlq}); aborting before emission")


# ── teardown ────────────────────────────────────────────────────────────────

def teardown(stack: Stack, state: dict, enrichment_dir: str) -> list[str]:
    """Verified teardown (design §7.2). Returns the list of problems (empty =
    stack left as found). NEVER raises mid-way — every step runs, every
    failure is reported."""
    problems: list[str] = []
    prefix = state["prefix"]
    runid = state["runid"]

    # 1. devices: delete + paged verify-zero (deletion durability is a past
    # defect, F-69 — never trust the 204).
    del_fail = 0
    for name in state.get("devices") or []:
        st, resp = stack.api("DELETE", f"/api/devices/{name}")
        if st not in (204, 404):
            del_fail += 1
            if del_fail == 1:
                problems.append(f"device delete {name}: HTTP {st} "
                                f"{str(resp)[:100]}")
    if del_fail:
        problems.append(f"{del_fail} device deletes failed in total")
    remaining, offset = 0, 0
    while True:
        st, resp = stack.api(
            "GET", f"/api/devices?envelope=1&limit=5000&offset={offset}")
        if st != 200 or not isinstance(resp, dict):
            problems.append(f"device verify list failed: HTTP {st}")
            remaining = -1
            break
        rows = resp.get("devices") or []
        remaining += sum(1 for d in rows
                         if str(d.get("id", "")).startswith(prefix))
        if resp.get("complete", True) or not rows:
            break
        offset += len(rows)
    if remaining != 0:
        problems.append(f"{remaining} run devices still present after delete")
    else:
        log(f"teardown: devices deleted + verified zero ({prefix}*)")

    # 2. seams
    seam_mode = state.get("seam_mode")
    if seam_mode == "api":
        for sid in state.get("seams") or []:
            st, resp = stack.api("PATCH", f"/api/seams/{sid}",
                                 {"state": "retired"})
            if st != 200:
                problems.append(f"seam retire {sid}: HTTP {st} "
                                f"{str(resp)[:100]}")
    elif seam_mode == "file":
        path = os.path.join(enrichment_dir, "seams.json")
        try:
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write("[]")
            os.replace(tmp, path)
            # let every replica reload the EMPTY inventory before removing the
            # file (a removed file keeps the last cached view — main.py).
            deadline = time.monotonic() + 120
            emptied = False
            while time.monotonic() < deadline:
                hz = stack.corr_healthz_all()
                counts = [int(h.get("engine_v2", {}).get("seam_inventory", -1))
                          for h in hz.values()]
                if counts and all(c == 0 for c in counts):
                    emptied = True
                    break
                time.sleep(10)
            if not emptied:
                problems.append("engine seam_inventory did not return to 0 "
                                "after emptying seams.json")
            os.remove(path)
        except OSError as exc:
            problems.append(f"seam enrichment file cleanup failed: {exc}")

    # 3. DRAIN before purge (the late-insert residue race, mini-ladder
    # 2026-08-16 lesson: purge only after the engine's last insert).
    deadline = time.monotonic() + DRAIN_WAIT_TIMEOUT_S
    lag = -1
    while time.monotonic() < deadline:
        lag, _members = stack.group_lag_total("netops-correlation")
        if 0 <= lag <= 100:
            break
        time.sleep(15)
    else:
        problems.append(f"consumer lag still {lag} after "
                        f"{DRAIN_WAIT_TIMEOUT_S}s pre-purge wait — purge may "
                        f"race late inserts")
    log(f"teardown: pre-purge drain gate lag={lag}")

    # 4. ClickHouse purge + verify. corr_objects/evidence TTL out on their own
    # (mini-ladder parity — they carry no --verify weight); corr_signals is
    # the run-tagged table that must be zero.
    ok, out = stack.ch_mutation(
        f"ALTER TABLE netops.corr_signals DELETE "
        f"WHERE entity_id LIKE '%{prefix}%'")
    if not ok:
        problems.append(f"ClickHouse corr_signals purge failed: {out}")
    okc, cnt = stack.ch(
        f"SELECT count() FROM netops.corr_signals "
        f"WHERE entity_id LIKE '%{prefix}%'")
    left = int(cnt) if okc and cnt.isdigit() else -1
    if left != 0:
        problems.append(f"{left} run rows left in corr_signals after purge")
    else:
        log("teardown: corr_signals purged + verified zero")

    # 4b. Fidelity-wave telemetry (only when the run emitted those lanes —
    # zero teardown-surface change for T1-core runs): netops.flows rows are
    # keyed by the run's tenant ids (sampler addresses are REUSED across
    # runs, tenant ids never are), netops-snmptrap-* docs by device prefix.
    run_tenants = sorted(t["tenant_id"]
                         for t in (state.get("tenants") or {}).values())
    if run_tenants and (state.get("fidelity") == "source_ip"):
        tlist = ", ".join(f"'{t}'" for t in run_tenants)
        ok, out = stack.ch_mutation(
            f"ALTER TABLE netops.flows DELETE WHERE tenant_id IN ({tlist})")
        if not ok:
            problems.append(f"ClickHouse flows purge failed: {out}")
        okc, cnt = stack.ch(
            f"SELECT count() FROM netops.flows WHERE tenant_id IN ({tlist})")
        left = int(cnt) if okc and cnt.isdigit() else -1
        if left != 0:
            problems.append(f"{left} run rows left in netops.flows")
        else:
            log("teardown: netops.flows rows purged + verified zero")
    okd, res = stack.os_req(
        "OS_BOOTSTRAP_PASSWORD", "svc_bootstrap",
        "/netops-snmptrap-*/_delete_by_query?refresh=true",
        {"query": {"prefix": {"device.keyword": prefix}}}, timeout=300)
    # index may not exist when the run never emitted traps — only a REPORTED
    # failure counts (delete_by_query on a missing index 404s → okd False
    # with a 'index_not_found' body; treat that as nothing-to-purge).
    if isinstance(res, dict) and res.get("failures"):
        problems.append(f"OpenSearch snmptrap purge failures: "
                        f"{str(res['failures'])[:200]}")
    elif okd:
        trap_left = stack.os_count("netops-snmptrap-*", "device.keyword",
                                   prefix)
        if trap_left > 0:
            problems.append(f"{trap_left} run docs left in netops-snmptrap-*")
        else:
            log("teardown: OpenSearch snmptrap docs purged + verified zero")

    # 5. OpenSearch syslog lane purge + verify.
    okd, res = stack.os_req(
        "OS_BOOTSTRAP_PASSWORD", "svc_bootstrap",
        "/netops-syslog-*/_delete_by_query?refresh=true",
        {"query": {"prefix": {"hostname.keyword": prefix}}}, timeout=300)
    if not okd or not isinstance(res, dict):
        problems.append(f"OpenSearch syslog purge failed: {res}")
    elif res.get("failures"):
        problems.append(f"OpenSearch purge reported failures: "
                        f"{str(res['failures'])[:200]}")
    os_left = stack.os_count("netops-syslog-*", "hostname.keyword", prefix)
    if os_left != 0:
        problems.append(f"{os_left} run docs left in netops-syslog-*")
    else:
        log("teardown: OpenSearch syslog docs purged + verified zero")

    # 6. tenants + orgs (only what the run created).
    for alias, t in (state.get("tenants") or {}).items():
        ok, err = _delete_tenant(stack, t["tenant_id"], t["name"])
        if not ok:
            problems.append(f"tenant delete {t['name']} ({alias}): {err}")
    for o in state.get("orgs") or []:
        st, resp = stack.api("DELETE", f"/api/orgs/{o['id']}")
        if st not in (204, 404):
            problems.append(f"org delete {o['name']}: HTTP {st} "
                            f"{str(resp)[:100]}")
    if not problems:
        log(f"teardown: run {runid} fully removed — stack left as found "
            f"(corr_objects/evidence for the run TTL out on their own, "
            f"mini-ladder parity)")
    return problems
