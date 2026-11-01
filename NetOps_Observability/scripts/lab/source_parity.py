#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix
"""source_parity.py — does every source give correlation the same evidence?

Compares what Correlix knows about the SAME physical devices through two
sources — e.g. SNMP in one scope and a controller integration (vManage) in
another, or both inside one scope — and checks that the two scopes stay
isolated from each other. Plan of record:
docs/design/NMS_DEVICE_IDENTITY_2026-11-01.md §5a (lab acceptance).

Read-only: it only issues GETs and log-search POSTs against the api.

    source_parity.py --base https://localhost --token-file TOKEN \\
        --scope-a global --scope-b <tenant-id> [--pair-by alias|serial|name]
        [--json out.json]

Pairing (how a device in scope A is matched with its counterpart in B):
  alias   B device's controller-reported identities (system-ip, configured
          source addresses in labels) contain A device's address, or the reverse
  serial  equal chassis serial
  name    equal device name (case-insensitive) — weakest, last resort

Exit status: 0 every check passed, 1 at least one FAIL, 2 the harness could not
run (auth, network, malformed response). A GAP row is a FAIL: parity gaps are
defects, not warnings.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

TIMEOUT_S = 30


class HarnessError(Exception):
    """The harness could not obtain a trustworthy answer (exit 2)."""


@dataclass
class Api:
    base: str
    token: str
    insecure: bool

    def _ctx(self) -> ssl.SSLContext:
        if self.insecure:
            return ssl._create_unverified_context()  # lab self-signed cert, explicit flag
        return ssl.create_default_context()

    def call(self, method: str, path: str, scope: str | None, body: Any = None) -> tuple[int, Any]:
        headers = {"Authorization": "Bearer " + self.token, "Content-Type": "application/json"}
        if scope is not None:
            headers["X-Acting-Tenant"] = scope
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, method=method, data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, context=self._ctx(), timeout=TIMEOUT_S) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise HarnessError(f"{method} {path}: HTTP {e.code} — token expired or lacks permission") from e
            return e.code, None
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            raise HarnessError(f"{method} {path}: {e}") from e


def as_list(payload: Any, key: str) -> list[dict]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get(key), list):
        return payload[key]
    raise HarnessError(f"expected a list or {{{key}: [...]}}, got {type(payload).__name__}")


@dataclass
class Result:
    dimension: str
    subject: str
    status: str  # PASS | FAIL
    detail: str


@dataclass
class Report:
    results: list[Result] = field(default_factory=list)

    def add(self, dimension: str, subject: str, ok: bool, detail: str) -> None:
        self.results.append(Result(dimension, subject, "PASS" if ok else "FAIL", detail))

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if r.status == "FAIL")


# ---- device identity helpers -------------------------------------------------

def is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def serial_of(d: dict) -> str:
    labels = d.get("labels") or {}
    return str(d.get("serial") or d.get("serial_number") or labels.get("controller_board_serial") or "").strip().upper()


def identities_of(d: dict) -> set[str]:
    """Addresses a device is known by: inventory address plus every
    controller-reported address label (system-ip, configured sources)."""
    out = {str(d.get("address") or "").strip()}
    for k, v in (d.get("labels") or {}).items():
        if k.endswith(("_ip", "_address", "_addresses", "system_ip")) and isinstance(v, str):
            out.update(x.strip() for x in v.split(","))
    out.discard("")
    return out


def pair_devices(a: list[dict], b: list[dict], how: str) -> tuple[list[tuple[dict, dict]], list[dict], list[dict]]:
    pairs: list[tuple[dict, dict]] = []
    used_b: set[str] = set()
    for da in a:
        match = None
        for db in b:
            if db["id"] in used_b:
                continue
            if how == "serial" and serial_of(da) and serial_of(da) == serial_of(db) or how == "alias" and identities_of(da) & identities_of(db) or how == "name" and da.get("name", "").lower() == db.get("name", "").lower() and da.get("name"):
                match = db
            if match:
                break
        if match:
            used_b.add(match["id"])
            pairs.append((da, match))
    paired_a = {p[0]["id"] for p in pairs}
    return pairs, [d for d in a if d["id"] not in paired_a], [d for d in b if d["id"] not in used_b]


# ---- dimensions --------------------------------------------------------------

INVENTORY_FIELDS = ("name", "vendor", "model", "os", "os_version", "serial", "site", "type", "reachability")


def field_value(d: dict, f: str) -> str:
    if f == "os_version":
        return str(d.get("os_version") or d.get("software_version") or "").strip()
    if f == "serial":
        return serial_of(d)
    if f == "site":
        labels = d.get("labels") or {}
        return str(d.get("site") or d.get("site_id") or labels.get("controller_site_id") or "").strip()
    return str(d.get(f) or "").strip().lower() if f in ("vendor", "os", "type", "reachability") else str(d.get(f) or "").strip()


def check_inventory(rep: Report, pairs: list[tuple[dict, dict]]) -> None:
    for da, db in pairs:
        subject = f'{da.get("name")} ({da["id"]} ↔ {db["id"]})'
        for f in INVENTORY_FIELDS:
            va, vb = field_value(da, f), field_value(db, f)
            if not va and not vb:
                rep.add("inventory", subject, False, f"{f}: neither source provides it")
            elif not va or not vb:
                rep.add("inventory", subject, False, f"{f}: A={va or '∅'} B={vb or '∅'} (one source is missing it)")
            else:
                rep.add("inventory", subject, va.lower() == vb.lower() or f == "os_version" and (va in vb or vb in va),
                        f"{f}: A={va} B={vb}")


def interfaces_of(api: Api, scope: str, dev: dict) -> tuple[dict[str, str], dict]:
    status, body = api.call("GET", f"/api/devices/{urllib.parse.quote(dev['id'])}/interfaces/by-vrf", scope)
    if status != 200 or not isinstance(body, dict):
        return {}, {"error": f"HTTP {status}"}
    out: dict[str, str] = {}
    for g in body.get("groups") or []:
        for i in g.get("interfaces") or []:
            name = str(i.get("name") or i.get("ifname") or "")
            if name:
                out[name] = str(i.get("oper") or i.get("oper_status") or "")
    for i in body.get("ungrouped") or []:
        name = str(i.get("name") or i.get("ifname") or "")
        if name:
            out[name] = str(i.get("oper") or i.get("oper_status") or "")
    return out, body.get("coverage") or {}


def check_interfaces(rep: Report, api: Api, sa: str, sb: str, pairs: list[tuple[dict, dict]]) -> None:
    for da, db in pairs:
        subject = f'{da.get("name")}'
        ia, ca = interfaces_of(api, sa, da)
        ib, cb = interfaces_of(api, sb, db)
        na, nb = int(ca.get("interfaces") or len(ia)), int(cb.get("interfaces") or len(ib))
        rep.add("interfaces", subject, na == nb and na > 0,
                f"count A={na} ({ca.get('transport') or '?'}) B={nb} ({cb.get('transport') or '?'})"
                + ("" if nb or not cb.get("notes") else f" — B: {cb['notes'][0][:120]}")
                + ("" if na or not ca.get("notes") else f" — A: {ca['notes'][0][:120]}"))
        for k in ("utilisation", "errors"):
            rep.add("interfaces", subject, bool(ca.get(k)) == bool(cb.get(k)), f"{k}: A={bool(ca.get(k))} B={bool(cb.get(k))}")


def device_alerts(alerts: list[dict], dev: dict) -> list[dict]:
    ids = {dev["id"], dev.get("name", "")} | identities_of(dev)
    return [a for a in alerts if a.get("device_id") in ids or a.get("deviceId") in ids or a.get("device") in ids]


def check_alerts(rep: Report, api: Api, sa: str, sb: str, pairs: list[tuple[dict, dict]]) -> None:
    alerts = {}
    for s in (sa, sb):
        status, body = api.call("GET", "/api/alerts", s)
        if status != 200:
            raise HarnessError(f"/api/alerts under {s}: HTTP {status}")
        alerts[s] = as_list(body, "alerts")
    for da, db in pairs:
        aa, ab = device_alerts(alerts[sa], da), device_alerts(alerts[sb], db)
        names_a = sorted({str(a.get("rule") or a.get("name") or a.get("alertname")) for a in aa})
        names_b = sorted({str(a.get("rule") or a.get("name") or a.get("alertname")) for a in ab})
        rep.add("alerts", str(da.get("name")), bool(aa) == bool(ab),
                f"A={len(aa)} {names_a[:4]} B={len(ab)} {names_b[:4]}")


def telemetry_count(api: Api, scope: str, signal: str, dev: dict) -> int | None:
    terms = sorted({dev["id"], dev.get("name", "")} | identities_of(dev) - {""})
    # sampler_address is mapped as an OpenSearch `ip`: a non-address value there
    # makes the whole query match nothing, so addresses go to it and names never do.
    addrs = [t for t in terms if is_ip(t)]
    clauses = [f'host:"{t}" OR hostname:"{t}"' for t in terms]
    if signal == "flows":
        clauses = [f'sampler_address:"{a}"' for a in addrs]
        if not clauses:
            return 0
    q = " OR ".join(clauses)
    status, body = api.call("POST", "/api/logs/search", scope, {"signal": signal, "query": q, "limit": 1, "since": "1h"})
    if status != 200 or not isinstance(body, dict):
        return None
    tot = (body.get("hits") or {}).get("total")
    return int(tot.get("value") if isinstance(tot, dict) else tot or 0)


def check_telemetry(rep: Report, api: Api, sa: str, sb: str, pairs: list[tuple[dict, dict]]) -> None:
    for da, db in pairs:
        for sig in ("syslog", "snmptrap", "flows"):
            ca, cb = telemetry_count(api, sa, sig, da), telemetry_count(api, sb, sig, db)
            if ca is None or cb is None:
                rep.add("telemetry", f'{da.get("name")} {sig}', False, f"query failed (A={ca} B={cb})")
                continue
            # Both zero is not parity: correlation has this evidence in neither view.
            rep.add("telemetry", f'{da.get("name")} {sig}', ca > 0 and cb > 0,
                    f"last 1h A={ca} B={cb}" + (" — neither view has it" if ca == cb == 0 else ""))


def check_isolation(rep: Report, api: Api, sa: str, sb: str, dev_a: list[dict], dev_b: list[dict]) -> None:
    ids_a, ids_b = {d["id"] for d in dev_a}, {d["id"] for d in dev_b}
    rep.add("isolation", "device lists", not (ids_a & ids_b), f"overlapping ids: {sorted(ids_a & ids_b)[:5]}")
    for scope, own, other in ((sa, dev_a, dev_b), (sb, dev_b, dev_a)):
        for d in other[:3]:  # a sample is enough to prove the door is shut
            status, _ = api.call("GET", f"/api/devices/{urllib.parse.quote(d['id'])}", scope)
            rep.add("isolation", f"{scope} → other's {d['id']}", status == 404, f"HTTP {status} (want 404)")
    status, body = api.call("GET", "/api/devices", "all")
    if status == 200:
        everything = as_list(body, "devices")
        labelled = all(("tenant_id" in d) or d.get("source") != "api" for d in everything)
        rep.add("isolation", "all-tenants view", len(everything) >= len(dev_a) + len(dev_b) and labelled,
                f"{len(everything)} rows (A {len(dev_a)} + B {len(dev_b)})")


# ---- main --------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", required=True)
    ap.add_argument("--token-file", required=True)
    ap.add_argument("--scope-a", required=True, help="tenant id/slug of the first view (e.g. global = Provider)")
    ap.add_argument("--scope-b", required=True, help="tenant id/slug of the second view")
    ap.add_argument("--pair-by", choices=("alias", "serial", "name"), default="alias")
    ap.add_argument("--insecure", action="store_true", help="accept a self-signed api certificate")
    ap.add_argument("--json", help="also write the full report as JSON to this path")
    args = ap.parse_args()

    try:
        with open(args.token_file, encoding="utf-8") as fh:
            token = fh.read().strip()
        if not token:
            raise HarnessError(f"{args.token_file} is empty")
        api = Api(args.base.rstrip("/"), token, args.insecure)
        lists = {}
        for s in (args.scope_a, args.scope_b):
            status, body = api.call("GET", "/api/devices", s)
            if status != 200:
                raise HarnessError(f"/api/devices under {s}: HTTP {status}")
            lists[s] = as_list(body, "devices")
        dev_a, dev_b = lists[args.scope_a], lists[args.scope_b]
        pairs, only_a, only_b = pair_devices(dev_a, dev_b, args.pair_by)
        if args.pair_by == "alias" and not pairs:
            pairs, only_a, only_b = pair_devices(dev_a, dev_b, "name")

        rep = Report()
        rep.add("pairing", "devices", not only_a and not only_b and bool(pairs),
                f"{len(pairs)} paired; only in A: {[d.get('name') for d in only_a]}; only in B: {[d.get('name') for d in only_b]}")
        check_inventory(rep, pairs)
        check_interfaces(rep, api, args.scope_a, args.scope_b, pairs)
        check_alerts(rep, api, args.scope_a, args.scope_b, pairs)
        check_telemetry(rep, api, args.scope_a, args.scope_b, pairs)
        check_isolation(rep, api, args.scope_a, args.scope_b, dev_a, dev_b)
    except (HarnessError, OSError) as e:
        print(f"source_parity: cannot run: {e}", file=sys.stderr)
        return 2

    by_dim: dict[str, list[Result]] = {}
    for r in rep.results:
        by_dim.setdefault(r.dimension, []).append(r)
    for dim, rows in by_dim.items():
        bad = [r for r in rows if r.status == "FAIL"]
        print(f"\n== {dim}: {len(rows) - len(bad)}/{len(rows)} pass")
        for r in bad:
            print(f"  FAIL {r.subject}: {r.detail}")
    print(f"\nTOTAL {len(rep.results) - rep.failed}/{len(rep.results)} pass, {rep.failed} fail")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump([r.__dict__ for r in rep.results], fh, indent=1)
    return 1 if rep.failed else 0


if __name__ == "__main__":
    sys.exit(main())
