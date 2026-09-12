#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""T5 counter-verification runner (tracker #120): execute the acceptance-drill
counter matrix against the LIVE stack.

Run one drill's check after (or during) the physical drill:

    python3 cloud_drill_verify.py --provider aws --drill 3 --since-min 30
    python3 cloud_drill_verify.py --list            # print the whole matrix

For every `required` any-of group it counts matching signals in
netops.corr_signals inside the window and FAILS (exit 1) if a group saw zero —
a drill whose counters did not fall is a lane regression, not a pass.
`corroborating`/`quiet` kinds and fired `signatures` (corr_objects_latest) are
reported for the operator, never gating. Exit 2 = could not reach ClickHouse
(infra failure is loud, per CLAUDE.md §16 — never a false green).

Same access pattern as correlation_e2e.py: `docker exec <ch> clickhouse-client`
with tenant_scope='__all__' (E2E_CLICKHOUSE overrides the container name).
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys

from cloud_drill_matrix import (
    MATRIX,
    PROVIDER_BLIND_KINDS,
    PROVIDERS,
    expectations_for,
)

CH_CONTAINER = os.environ.get("E2E_CLICKHOUSE", "netops-clickhouse-1")
GREEN, RED, DIM, BOLD, RST = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"


class CHError(RuntimeError):
    pass


def ch(query: str) -> str:
    p = subprocess.run(
        ["docker", "exec", CH_CONTAINER, "clickhouse-client", "-q",
         query + " SETTINGS tenant_scope='__all__'"],
        capture_output=True, text=True, timeout=30,
        check=False,  # error surfaced as CHError with the server's own text
    )
    if p.returncode != 0:
        raise CHError(p.stderr.strip() or f"clickhouse-client exit {p.returncode}")
    return p.stdout.strip()


def _kind_count(kind: str, provider: str, since_min: int) -> int:
    prov = ("" if kind in PROVIDER_BLIND_KINDS
            else f" AND JSONExtractString(attrs,'provider')='{provider}'")
    q = (f"SELECT count() FROM netops.corr_signals WHERE kind='{kind}'"
         f" AND ts > now() - INTERVAL {since_min} MINUTE{prov}")
    return int(ch(q) or "0")


def _fired_signatures(signatures: tuple[str, ...], since_min: int) -> list[str]:
    if not signatures:
        return []
    sig_list = ",".join(f"'{s}'" for s in signatures)
    q = (f"SELECT DISTINCT top_hypothesis FROM netops.corr_objects_latest"
         f" WHERE top_hypothesis IN ({sig_list})"
         f" AND created_at > now() - INTERVAL {since_min} MINUTE")
    out = ch(q)
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


def list_matrix() -> None:
    for e in MATRIX:
        scope = "" if e.providers == PROVIDERS else f"  [{'/'.join(e.providers)}]"
        print(f"{BOLD}drill {e.drill} — {e.name}{scope}{RST}")
        if e.manual:
            print(f"  MANUAL: {e.manual}")
        for group in e.required:
            print(f"  required (any of): {', '.join(group)}")
        if e.corroborating:
            print(f"  corroborating:     {', '.join(e.corroborating)}")
        if e.quiet:
            print(f"  expected quiet:    {', '.join(e.quiet)}")
        if e.signatures:
            print(f"  signatures:        {', '.join(e.signatures)}")
        if e.notes:
            print(f"  {DIM}{e.notes}{RST}")
        print()


def verify(provider: str, drill: int, since_min: int) -> int:
    matches = [e for e in expectations_for(provider) if e.drill == drill]
    if not matches:
        print(f"{RED}no drill {drill} for provider {provider}{RST}", file=sys.stderr)
        return 2
    exp = matches[0]
    print(f"{BOLD}drill {exp.drill} — {exp.name} · provider={provider} · "
          f"window={since_min}m{RST}")
    if exp.manual:
        print(f"MANUAL drill: {exp.manual}")
        print("nothing machine-checkable; record the click-through in the drill log.")
        return 0

    failed = False
    for group in exp.required:
        counts = {k: _kind_count(k, provider, since_min) for k in group}
        moved = {k: c for k, c in counts.items() if c > 0}
        ok = bool(moved)
        failed |= not ok
        mark = f"{GREEN}MOVED{RST}" if ok else f"{RED}DID NOT MOVE{RST}"
        detail = ", ".join(f"{k}={c}" for k, c in counts.items())
        print(f"  required any-of [{detail}] → {mark}")
    for k in exp.corroborating:
        c = _kind_count(k, provider, since_min)
        print(f"  {DIM}corroborating {k}={c}{RST}")
    for k in exp.quiet:
        c = _kind_count(k, provider, since_min)
        note = "quiet as expected" if c == 0 else f"{c} rows (compare to pre-drill baseline)"
        print(f"  {DIM}quiet-check {k}: {note}{RST}")
    fired = _fired_signatures(exp.signatures, since_min)
    if exp.signatures:
        print(f"  signatures fired: {', '.join(fired) if fired else '(none)'} "
              f"{DIM}of candidates {', '.join(exp.signatures)}{RST}")

    if failed:
        print(f"\n{RED}FAIL — a required counter group did not move; the lane "
              f"did not witness the drill.{RST}")
        return 1
    print(f"\n{GREEN}counters PASS{RST} — now confirm the rendered story "
          f"(Service View + RCA) and capture golden log lines as fixtures.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--list", action="store_true", help="print the full matrix and exit")
    ap.add_argument("--provider", choices=PROVIDERS)
    ap.add_argument("--drill", type=int, choices=sorted({e.drill for e in MATRIX}))
    ap.add_argument("--since-min", type=int, default=30,
                    help="drill window to inspect, minutes back from now (default 30)")
    args = ap.parse_args()
    if args.list:
        list_matrix()
        return 0
    if not args.provider or args.drill is None:
        ap.error("--provider and --drill are required (or use --list)")
    try:
        return verify(args.provider, args.drill, args.since_min)
    except (CHError, subprocess.TimeoutExpired, OSError) as exc:
        print(f"{RED}ClickHouse unreachable: {exc}{RST}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
