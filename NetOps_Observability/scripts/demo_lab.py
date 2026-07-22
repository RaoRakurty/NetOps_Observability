#!/usr/bin/env python3
"""demo_lab.py — build (and tear down) a multi-tenant demo estate.

Creates orgs, tenants, sites and devices from a PROFILE, then optionally drives
telemetry so every surface populates. Everything it creates is recorded in a
run MANIFEST, and `teardown` deletes exactly what that manifest lists — nothing
else, ever.

    ./demo_lab.py seed     --profile profiles/retail.yaml
    ./demo_lab.py traffic  --run <run-id> --duration 300
    ./demo_lab.py teardown --run <run-id>
    ./demo_lab.py list

WHY A MANIFEST, AND NOT A NAME PREFIX. Deleting "everything that looks like
demo data" is how a cleanup script eats production. This tool only ever deletes
ids it wrote down at creation time, refuses to touch the Provider/global tenant,
and refuses to delete a device it did not create — so a demo teardown cannot
reach the real inventory even if a real device happens to match the naming
scheme.

DURABILITY NOTE. Devices created through POST /api/devices used to live only in
the API's memory and vanished on the next restart (see device_persist.go). They
now persist, which is what makes a seeded estate worth building. If you are
running against an API older than that fix, expect the inventory to disappear on
restart — re-run `seed` rather than assuming this tool failed.

Stdlib only, except PyYAML for .yaml profiles (JSON profiles need nothing).
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import random
import socket
import struct
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

HOST = os.environ.get("NETOPS_HOST", "127.0.0.1")
BASE_PORT = int(os.environ.get("BASE_PORT", "8000"))
SYSLOG_PORT = int(os.environ.get("SYSLOG_PORT", "5514"))
NETFLOW_PORT = int(os.environ.get("NETFLOW_PORT", "2055"))
API = f"http://{HOST}:{BASE_PORT}"

SCRIPT_DIR = Path(__file__).resolve().parent
RUNS_DIR = SCRIPT_DIR / ".demo-runs"
PROFILE_DIR = SCRIPT_DIR / "demo-profiles"

# The Provider realm. Never created, never deleted, never traffic-stamped by
# this tool — it holds the operator's REAL devices.
PROTECTED_TENANTS = {"global", "provider"}


# ---------------------------------------------------------------------------
# profile loading
# ---------------------------------------------------------------------------

DEFAULT_PROFILE = {
    "name": "retail",
    "org": {"name_template": "{brand} Group", "slug_template": "{slug}-grp"},
    "tenants": {
        "count": 3,
        "brands": ["Walmart", "Target", "Costco", "Kroger", "Homedepot",
                   "Lowes", "Bestbuy", "Safeway", "Nordstrom", "Walgreens"],
        "name_template": "{brand} Retail",
        "slug_template": "{slug}",
        "regions": ["us-east", "us-west", "eu-central", "eu-west"],
        "note_template": "demo tenant for {brand}",
    },
    "sites": {"per_tenant": 3, "name_template": "br{n}"},
    "devices": {
        "name_template": "{tenant_slug}-{site}-{role}{idx:02d}",
        "roles": [
            {"role": "core-sw", "type": "switch", "vendor": "arista", "count": 1},
            {"role": "access-sw", "type": "switch", "vendor": "arista", "count": 2},
            {"role": "branch-fw", "type": "firewall", "vendor": "palo-alto", "count": 1},
            {"role": "sdwan-edge", "type": "router", "vendor": "cisco", "count": 1},
        ],
    },
    "addressing": {"base_second_octet": 100, "site_third_octet_start": 1},
    "traffic": {
        "syslog_per_device": 5,
        "netflow_per_device": 10,
        "metrics": True,
        "findings_per_tenant": 1,
    },
}


def load_profile(path: str | None) -> dict:
    """Load a profile. YAML needs PyYAML; JSON needs nothing. No path = builtin."""
    if not path:
        return json.loads(json.dumps(DEFAULT_PROFILE))  # deep copy
    p = Path(path)
    if not p.is_absolute():
        for cand in (Path.cwd() / p, PROFILE_DIR / p, SCRIPT_DIR / p):
            if cand.exists():
                p = cand
                break
    if not p.exists():
        die(f"profile not found: {path}")
    text = p.read_text()
    if p.suffix in (".yaml", ".yml"):
        try:
            import yaml  # optional
        except ImportError:
            die(f"{p.name} is YAML but PyYAML is not installed — "
                f"convert it to JSON or `pip install pyyaml`")
        loaded = yaml.safe_load(text)
    else:
        loaded = json.loads(text)
    if not isinstance(loaded, dict):
        die(f"{p.name}: profile must be a mapping")
    # Shallow-merge onto the defaults so a partial profile is legal — a demo
    # profile that only overrides tenant count should not have to restate the
    # whole device catalogue.
    merged = json.loads(json.dumps(DEFAULT_PROFILE))
    for k, v in loaded.items():
        if isinstance(v, dict) and isinstance(merged.get(k), dict):
            merged[k].update(v)
        else:
            merged[k] = v
    return merged


# ---------------------------------------------------------------------------
# api plumbing
# ---------------------------------------------------------------------------

def die(msg: str) -> "None":
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(2)


class Api:
    """Thin authenticated JSON client. Every call is bounded and reports its
    own failure — a demo tool that silently half-creates an estate is worse
    than one that stops."""

    def __init__(self, token: str, dry_run: bool = False):
        self.token = token
        self.dry_run = dry_run

    def call(self, method: str, path: str, body: dict | None = None,
             ok: tuple[int, ...] = (200, 201, 204)) -> tuple[int, dict | None]:
        if self.dry_run and method in ("POST", "PUT", "DELETE"):
            print(f"  [dry-run] {method} {path} {json.dumps(body) if body else ''}")
            return 200, {}
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(API + path, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.token}")
        if data:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                parsed = json.loads(raw) if raw else None
                return resp.status, parsed
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:300]
            return e.code, {"error": detail}
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            die(f"{method} {path}: cannot reach {API} ({e})")
        return 0, None


def login() -> str:
    """NETOPS_TOKEN, else NETOPS_USER/NETOPS_PASSWORD."""
    tok = os.environ.get("NETOPS_TOKEN", "").strip()
    if tok:
        return tok
    user = os.environ.get("NETOPS_USER") or os.environ.get("NETOPS_USERNAME")
    pw = os.environ.get("NETOPS_PASSWORD")
    if not user or not pw:
        die("set NETOPS_TOKEN, or NETOPS_USER + NETOPS_PASSWORD")
    body = json.dumps({"username": user, "password": pw}).encode()
    req = urllib.request.Request(API + "/api/auth/login", data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            tok = (json.loads(resp.read()) or {}).get("token", "")
    except urllib.error.HTTPError as e:
        die(f"login failed ({e.code}): {e.read().decode(errors='replace')[:200]}")
    except (urllib.error.URLError, OSError) as e:
        die(f"cannot reach {API}: {e}")
    if not tok:
        die("login returned no token")
    return tok


# ---------------------------------------------------------------------------
# manifest
# ---------------------------------------------------------------------------

def manifest_path(run_id: str) -> Path:
    return RUNS_DIR / f"{run_id}.json"


def save_manifest(m: dict) -> None:
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    p = manifest_path(m["run_id"])
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(m, indent=2))
    tmp.replace(p)  # atomic: a half-written manifest cannot orphan an estate


def load_manifest(run_id: str) -> dict:
    p = manifest_path(run_id)
    if not p.exists():
        die(f"no manifest for run {run_id} (looked in {RUNS_DIR})")
    return json.loads(p.read_text())


# ---------------------------------------------------------------------------
# seed
# ---------------------------------------------------------------------------

def slugify(s: str) -> str:
    return "".join(c.lower() if c.isalnum() else "-" for c in s).strip("-")


def plan_estate(profile: dict, seed: int) -> list[dict]:
    """Expand the profile into a concrete plan. Pure — no API calls — so
    --dry-run shows exactly what a real run would create."""
    rnd = random.Random(seed)
    t = profile["tenants"]
    brands = list(t["brands"])
    count = int(t["count"])
    if count > len(brands):
        die(f"profile asks for {count} tenants but lists only {len(brands)} brands")
    chosen = brands[:count]
    regions = t.get("regions") or ["us-east"]
    sites_cfg = profile["sites"]
    dev_cfg = profile["devices"]
    addr = profile["addressing"]

    estate = []
    for ti, brand in enumerate(chosen):
        slug = slugify(brand)
        tenant = {
            "brand": brand,
            "name": t["name_template"].format(brand=brand, slug=slug),
            "slug": t["slug_template"].format(brand=brand, slug=slug),
            "region": regions[ti % len(regions)],
            "note": t.get("note_template", "").format(brand=brand, slug=slug),
            "org_name": profile["org"]["name_template"].format(brand=brand, slug=slug),
            "org_slug": profile["org"]["slug_template"].format(brand=brand, slug=slug),
            "sites": [],
        }
        second = int(addr["base_second_octet"]) + ti
        for si in range(int(sites_cfg["per_tenant"])):
            site = sites_cfg["name_template"].format(n=si + 1)
            third = int(addr["site_third_octet_start"]) + si
            devices, host = [], 20
            for role in dev_cfg["roles"]:
                for idx in range(1, int(role.get("count", 1)) + 1):
                    host += 1
                    devices.append({
                        "name": dev_cfg["name_template"].format(
                            tenant_slug=tenant["slug"], site=site,
                            role=role["role"], idx=idx),
                        "address": f"10.{second}.{third}.{host}",
                        "type": role.get("type", "generic"),
                        "vendor": role.get("vendor", ""),
                        "role": role["role"],
                        "site": site,
                    })
            tenant["sites"].append({"site": site, "devices": devices})
        estate.append(tenant)
    _ = rnd  # reserved for future jitter; kept deterministic on purpose
    return estate


def cmd_seed(args) -> int:
    profile = load_profile(args.profile)
    if args.tenants:
        profile["tenants"]["count"] = args.tenants
    if args.sites_per_tenant:
        profile["sites"]["per_tenant"] = args.sites_per_tenant

    estate = plan_estate(profile, args.seed)
    n_dev = sum(len(s["devices"]) for t in estate for s in t["sites"])
    run_id = args.run or f"demo-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:6]}"

    print(f"run {run_id}: profile={profile.get('name')} "
          f"tenants={len(estate)} devices={n_dev}")
    if args.dry_run:
        for t in estate:
            print(f"  tenant {t['name']} ({t['slug']}, {t['region']})")
            for s in t["sites"]:
                print(f"    site {s['site']}: " +
                      ", ".join(d["name"] for d in s["devices"]))
        print("[dry-run] nothing created")
        return 0

    api = Api(login(), dry_run=False)
    manifest = {
        "run_id": run_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "api": API,
        "profile_name": profile.get("name"),
        "orgs": [], "tenants": [], "devices": [],
    }

    try:
        for t in estate:
            status, org = api.call("POST", "/api/orgs",
                                   {"name": t["org_name"], "slug": t["org_slug"]})
            org_id = (org or {}).get("id") if status in (200, 201) else None
            if org_id:
                manifest["orgs"].append({"id": org_id, "slug": t["org_slug"]})
            elif status not in (400, 409):
                print(f"  ! org {t['org_slug']}: HTTP {status} {(org or {}).get('error','')[:120]}")

            body = {"name": t["name"], "slug": t["slug"],
                    "note": t["note"], "region": t["region"]}
            if org_id:
                body["org_id"] = org_id
            status, tenant = api.call("POST", "/api/tenants", body)
            if status not in (200, 201) or not tenant:
                print(f"  ! tenant {t['slug']}: HTTP {status} "
                      f"{(tenant or {}).get('error','')[:160]}")
                continue
            tid = tenant["id"]
            manifest["tenants"].append({"id": tid, "slug": t["slug"], "name": t["name"]})
            save_manifest(manifest)  # persist AS WE GO: a crash mid-seed must
            #                          still leave a teardown-able record.

            made = 0
            for s in t["sites"]:
                for d in s["devices"]:
                    dev = {
                        "id": d["name"], "name": d["name"], "address": d["address"],
                        "vendor": d["vendor"], "type": d["type"],
                        "tenant_id": tid,
                        "labels": {"site": d["site"], "role": d["role"],
                                   "demo_run": run_id},
                    }
                    st, resp = api.call("POST", "/api/devices", dev)
                    if st in (200, 201):
                        manifest["devices"].append({"id": d["name"], "tenant_id": tid})
                        made += 1
                    else:
                        print(f"  ! device {d['name']}: HTTP {st} "
                              f"{(resp or {}).get('error','')[:120]}")
            save_manifest(manifest)
            print(f"  tenant {t['slug']}: {made} devices")
    finally:
        save_manifest(manifest)

    print(f"\nmanifest: {manifest_path(run_id)}")
    print(f"created: {len(manifest['orgs'])} orgs, {len(manifest['tenants'])} tenants, "
          f"{len(manifest['devices'])} devices")
    print(f"traffic:  ./demo_lab.py traffic  --run {run_id}")
    print(f"teardown: ./demo_lab.py teardown --run {run_id}")

    if args.with_traffic:
        args.run = run_id
        cmd_traffic(args)
    return 0


# ---------------------------------------------------------------------------
# traffic
# ---------------------------------------------------------------------------

SEVERITIES = [(3, "ERROR"), (4, "WARNING"), (5, "NOTICE"), (6, "INFO")]
LOG_TEMPLATES = [
    "%LINK-3-UPDOWN: Interface {ifc}, changed state to down",
    "%LINK-3-UPDOWN: Interface {ifc}, changed state to up",
    "%BGP-5-ADJCHANGE: neighbor {peer} Up",
    "%BGP-3-NOTIFICATION: sent to neighbor {peer} hold time expired",
    "%SYS-5-CONFIG_I: Configured from console by admin",
    "%OSPF-5-ADJCHG: Process 1, Nbr {peer} on {ifc} from LOADING to FULL",
]


def emit_syslog(devices: list[dict], per_device: int) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0
    try:
        for d in devices:
            for _ in range(per_device):
                sev, _name = random.choice(SEVERITIES)
                pri = 16 * 8 + sev  # local0
                ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
                msg = random.choice(LOG_TEMPLATES).format(
                    ifc=f"Ethernet{random.randint(1,48)}",
                    peer=f"10.{random.randint(1,254)}.{random.randint(1,254)}.1")
                line = f"<{pri}>{ts} {d['id']} {msg}"
                sock.sendto(line.encode(), (HOST, SYSLOG_PORT))
                sent += 1
    finally:
        sock.close()
    return sent


def _nf5(records: list[bytes], seq: int) -> bytes:
    up = int(time.time() * 1000) % (2**32)
    hdr = struct.pack("!HHIIIIBBH", 5, len(records), up, int(time.time()), seq, 0, 0, 0, 0)
    return hdr + b"".join(records)


def _nf5_record(src: str, dst: str) -> bytes:
    def ip(a: str) -> int:
        return struct.unpack("!I", socket.inet_aton(a))[0]
    up = int(time.time() * 1000) % (2**32)
    return struct.pack("!IIIHHIIIIHHBBBBHHBBH",
                       ip(src), ip(dst), 0, 1, 2,
                       random.randint(10, 5000), random.randint(1000, 5_000_000),
                       max(up - 1000, 0), up,
                       random.choice([443, 80, 22, 3389]), random.randint(1024, 65535),
                       0, 0x18, 6, 0, 0, 0, 0, 0, 0)


def emit_netflow(devices: list[dict], per_device: int) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent, seq = 0, 0
    try:
        for d in devices:
            recs = []
            for _ in range(per_device):
                recs.append(_nf5_record(
                    d.get("address") or "10.0.0.1",
                    f"104.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"))
                if len(recs) == 20:
                    sock.sendto(_nf5(recs, seq), (HOST, NETFLOW_PORT))
                    seq += len(recs); sent += len(recs); recs = []
            if recs:
                sock.sendto(_nf5(recs, seq), (HOST, NETFLOW_PORT))
                seq += len(recs); sent += len(recs)
    finally:
        sock.close()
    return sent


def cmd_traffic(args) -> int:
    m = load_manifest(args.run)
    devices = m.get("devices", [])
    if not devices:
        die(f"run {args.run} has no devices recorded")
    # Attach addresses from the plan where available; a device id is enough for
    # syslog, but netflow needs a source address.
    for d in devices:
        d.setdefault("address", "10.0.0.1")

    profile = load_profile(args.profile)
    tcfg = profile["traffic"]
    rounds = max(1, args.rounds)
    print(f"run {args.run}: {len(devices)} devices, {rounds} round(s)")
    for r in range(rounds):
        s = emit_syslog(devices, int(tcfg.get("syslog_per_device", 5)))
        f = emit_netflow(devices, int(tcfg.get("netflow_per_device", 10)))
        print(f"  round {r+1}: syslog={s} netflow={f}")
        if r + 1 < rounds:
            time.sleep(max(0, args.interval))
    print("traffic emitted — allow ~30s for the pipeline to index it")
    return 0


# ---------------------------------------------------------------------------
# teardown
# ---------------------------------------------------------------------------

def cmd_teardown(args) -> int:
    m = load_manifest(args.run)
    devices, tenants, orgs = m.get("devices", []), m.get("tenants", []), m.get("orgs", [])

    # Refuse to delete anything in the Provider realm, whatever the manifest
    # says. A manifest is data; this is the invariant.
    for t in tenants:
        if t.get("slug", "").lower() in PROTECTED_TENANTS or t.get("id") in PROTECTED_TENANTS:
            die(f"manifest names the protected tenant {t.get('slug')} — refusing to proceed")

    print(f"run {args.run} ({m.get('created_at')}) will delete:")
    print(f"  {len(devices)} devices, {len(tenants)} tenants, {len(orgs)} orgs")
    if args.dry_run:
        for d in devices[:10]:
            print(f"    device {d['id']}")
        if len(devices) > 10:
            print(f"    … and {len(devices)-10} more")
        print("[dry-run] nothing deleted")
        return 0
    if not args.yes:
        if input("proceed? [y/N] ").strip().lower() not in ("y", "yes"):
            print("aborted")
            return 1

    api = Api(login())
    failed = []

    # Devices first, then tenants, then orgs — reverse of creation, so a tenant
    # is never deleted out from under a device the teardown still has to reach.
    for d in devices:
        st, resp = api.call("DELETE", f"/api/devices/{d['id']}")
        if st not in (200, 204, 404):
            failed.append(("device", d["id"], st, (resp or {}).get("error", "")[:100]))
    print(f"  devices: {len(devices)-len([f for f in failed if f[0]=='device'])}/{len(devices)} deleted")

    for t in tenants:
        st, resp = api.call("DELETE", f"/api/tenants/{t['id']}")
        if st not in (200, 204, 404):
            failed.append(("tenant", t["id"], st, (resp or {}).get("error", "")[:100]))
    print(f"  tenants: {len(tenants)-len([f for f in failed if f[0]=='tenant'])}/{len(tenants)} deleted")

    for o in orgs:
        st, resp = api.call("DELETE", f"/api/orgs/{o['id']}")
        if st not in (200, 204, 404):
            failed.append(("org", o["id"], st, (resp or {}).get("error", "")[:100]))
    print(f"  orgs:    {len(orgs)-len([f for f in failed if f[0]=='org'])}/{len(orgs)} deleted")

    if failed:
        # Keep the manifest. A partial teardown that forgets what it could not
        # delete leaves orphans nobody can find.
        print(f"\n{len(failed)} object(s) could not be deleted — manifest KEPT so you can retry:")
        for kind, ident, st, err in failed[:15]:
            print(f"  {kind} {ident}: HTTP {st} {err}")
        return 1

    manifest_path(args.run).unlink(missing_ok=True)
    print(f"\nteardown complete; manifest removed ({args.run})")
    return 0


def cmd_list(_args) -> int:
    if not RUNS_DIR.exists() or not any(RUNS_DIR.glob("*.json")):
        print("no demo runs recorded")
        return 0
    print(f"{'RUN':40} {'CREATED':22} {'TENANTS':>8} {'DEVICES':>8}")
    for p in sorted(RUNS_DIR.glob("*.json")):
        try:
            m = json.loads(p.read_text())
        except (json.JSONDecodeError, OSError):
            print(f"{p.stem:40} <unreadable>")
            continue
        print(f"{m.get('run_id',p.stem):40} {m.get('created_at','')[:19]:22} "
              f"{len(m.get('tenants',[])):>8} {len(m.get('devices',[])):>8}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("seed", help="create orgs/tenants/devices from a profile")
    s.add_argument("--profile", help="YAML or JSON profile (default: builtin retail)")
    s.add_argument("--tenants", type=int, help="override tenant count")
    s.add_argument("--sites-per-tenant", type=int, help="override sites per tenant")
    s.add_argument("--run", help="explicit run id (default: generated)")
    s.add_argument("--seed", type=int, default=1, help="planning seed (deterministic)")
    s.add_argument("--with-traffic", action="store_true", help="emit one traffic round after seeding")
    s.add_argument("--rounds", type=int, default=1)
    s.add_argument("--interval", type=int, default=30)
    s.add_argument("--dry-run", action="store_true", help="print the plan, create nothing")
    s.set_defaults(func=cmd_seed)

    t = sub.add_parser("traffic", help="emit telemetry for a seeded run")
    t.add_argument("--run", required=True)
    t.add_argument("--profile")
    t.add_argument("--rounds", type=int, default=1)
    t.add_argument("--interval", type=int, default=30)
    t.set_defaults(func=cmd_traffic)

    d = sub.add_parser("teardown", help="delete exactly what a run created")
    d.add_argument("--run", required=True)
    d.add_argument("--yes", action="store_true", help="skip confirmation")
    d.add_argument("--dry-run", action="store_true")
    d.set_defaults(func=cmd_teardown)

    sub.add_parser("list", help="list recorded runs").set_defaults(func=cmd_list)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
