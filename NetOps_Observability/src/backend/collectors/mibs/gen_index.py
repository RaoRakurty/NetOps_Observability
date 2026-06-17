#!/usr/bin/env python3
"""Generate/validate the embedded OID index (oididx.json) — BUILD TIME ONLY.

Design: docs/design/research/telemetry-normalization-architecture.md §6.

Two modes, both run offline:
  * Always: load the current index, validate its schema + a fixed set of known-OID
    resolve assertions (so a broken index fails the build, not prod), recompute the
    content-hash `version`, and rewrite it deterministically.
  * If pysmi is installed AND vendored .mib files exist under ietf/iana/vendor/*,
    compile them to JSON and MERGE the discovered objects/notifications into the
    index before validating (this is how enterprise OIDs get decoded — drop the
    MIBs, run `make mib-index`, rebuild Go).

pysmi is build-time tooling only — never imported by the Go runtime (CLAUDE.md §6).
Usage:  python3 gen_index.py   (run from anywhere; paths are resolved relative here)
Exit non-zero if validation fails.
"""
from __future__ import annotations
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
INDEX = os.path.join(HERE, "index", "oididx.json")
MIB_DIRS = [os.path.join(HERE, d) for d in ("ietf", "iana")] + [
    os.path.join(HERE, "vendor", v) for v in (
        sorted(os.listdir(os.path.join(HERE, "vendor"))) if os.path.isdir(os.path.join(HERE, "vendor")) else []
    )
]

# Resolve assertions — the index MUST decode these (regression guard mirroring
# collectors/oidindex_test.go). Add the canonical ones any real fabric emits.
ASSERTIONS = {
    "1.3.6.1.2.1.2.2.1.8": ("ifOperStatus", "column"),
    "1.3.6.1.6.3.1.1.5.3": ("linkDown", "notification"),
    "1.3.6.1.2.1.15.0.2": ("bgpBackwardTransition", "notification"),
    "1.3.6.1.2.1.1.5.0": ("sysName", "scalar"),
}


def load() -> dict:
    with open(INDEX) as f:
        return json.load(f)


def compile_mibs(index: dict) -> int:
    """Compile any vendored MIBs via pysmi and merge into index['nodes']. Returns
    the number of nodes added. No-op (0) when pysmi or MIBs are absent."""
    mibs = [d for d in MIB_DIRS if os.path.isdir(d) and any(p.lower().endswith((".mib", ".txt")) for p in os.listdir(d))]
    if not mibs:
        print("gen_index: no vendored MIBs found — keeping seed index. "
              "Drop .mib files under mibs/{ietf,iana,vendor/<vendor>}/ to expand.")
        return 0
    try:
        from pysmi.reader import FileReader
        from pysmi.parser import SmiStarParser
        from pysmi.codegen import JsonCodeGen
        from pysmi.writer import CallbackWriter
        from pysmi.compiler import MibCompiler
    except ImportError:
        print("gen_index: MIBs present but pysmi not installed "
              "(pip install pysmi) — keeping seed index.", file=sys.stderr)
        return 0

    produced: dict[str, str] = {}
    comp = MibCompiler(SmiStarParser(), JsonCodeGen(),
                       CallbackWriter(lambda name, data, ctx: produced.__setitem__(name, data)))
    for d in mibs:
        comp.add_sources(FileReader(d))
    names = sorted({os.path.splitext(p)[0] for d in mibs for p in os.listdir(d)
                    if p.lower().endswith((".mib", ".txt"))})
    comp.compile(*names)

    added = 0
    for _mib, blob in produced.items():
        try:
            mod = json.loads(blob)
        except Exception:
            continue
        for sym, obj in mod.items():
            oid = obj.get("oid")
            if not oid or not isinstance(oid, str) or "." not in oid:
                continue
            cls = obj.get("class", "")
            kind = ("notification" if cls in ("notificationtype", "trapnotification")
                    else "column" if obj.get("maxaccess") and "index" in str(obj).lower()
                    else "scalar")
            node = {"name": obj.get("name", sym), "mib": obj.get("module", _mib), "kind": kind}
            syntax = obj.get("syntax", {})
            if isinstance(syntax, dict):
                if syntax.get("type"):
                    node["type"] = syntax["type"]
                cons = syntax.get("constraints", {})
                if isinstance(cons, dict) and cons.get("enumeration"):
                    node["enum"] = {str(v): k for k, v in cons["enumeration"].items()}
            index.setdefault("nodes", {}).setdefault(oid, node)
            added += 1
    print(f"gen_index: merged {added} nodes from {len(names)} MIB module(s).")
    return added


def validate(index: dict) -> list[str]:
    errs: list[str] = []
    nodes = index.get("nodes", {})
    if not isinstance(nodes, dict) or not nodes:
        return ["index has no nodes"]
    for oid, (want_name, want_kind) in ASSERTIONS.items():
        n = nodes.get(oid)
        if not n:
            errs.append(f"missing assertion OID {oid} ({want_name})")
        elif n.get("name") != want_name or n.get("kind") != want_kind:
            errs.append(f"{oid}: got {n.get('name')}/{n.get('kind')}, want {want_name}/{want_kind}")
    for oid, n in nodes.items():
        if n.get("kind") not in ("scalar", "column", "notification"):
            errs.append(f"{oid}: bad kind {n.get('kind')!r}")
    return errs


def main() -> int:
    index = load()
    compile_mibs(index)
    errs = validate(index)
    if errs:
        print("gen_index: VALIDATION FAILED:\n  " + "\n  ".join(errs), file=sys.stderr)
        return 1
    # deterministic content hash over the nodes (stable key order)
    body = json.dumps(index["nodes"], sort_keys=True, separators=(",", ":")).encode()
    index["version"] = "sha256:" + hashlib.sha256(body).hexdigest()[:16]
    with open(INDEX, "w") as f:
        json.dump(index, f, indent=2, sort_keys=False)
        f.write("\n")
    print(f"gen_index: OK — {len(index['nodes'])} nodes, version {index['version']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
