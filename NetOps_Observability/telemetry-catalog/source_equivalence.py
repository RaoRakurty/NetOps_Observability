# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Source equivalence — does every source give correlation the same evidence?

    python3 source_equivalence.py                  # regenerate the matrix doc
    python3 source_equivalence.py --check          # CI drift guard (exit 1 if stale)
    python3 source_equivalence.py --write-baseline # raise the profile ratchet

Owner requirement (2026-11-01): some customers send SNMP, others a controller
integration; the correlation engine must receive the same evidence either way.
Plan of record: docs/design/NMS_DEVICE_IDENTITY_2026-11-01.md §7a/§7b (E0).

WHAT A SOURCE SUPPLIES IS COMPUTED, NEVER WRITTEN BY HAND. A hand-written
"supported" cell is a claim that outlives the code behind it, so:

  syslog / trap   the kinds of the non-generic rules in events.yaml (the
                  executable rule table the engine's parser runs)
  snmp_poll       the episode kinds of the collector's RCA metric allowlist
                  (coverage_matrix.METRIC_BUCKET → EPISODE_KIND, both pinned to
                  their Go/engine sources by test_coverage_matrix.py)
  flow            flow_volume_anomaly (the flows lane's CUSUM kind)
  connectors      the kind literals each connector's Go normalizer returns
                  (src/backend/nms/<file>.go), plus the SD-WAN state
                  transitions for vManage

A supplied kind only counts if the ENGINE knows it (coverage.EMITTED_KINDS, or a
kind it classifies as pending): a kind the engine has never heard of is an
ORPHAN — collected, then semantically thrown away — and must be declared in
evidence.yaml until fixed. A supplied kind the engine's own coverage registry
still classifies as *pending* is REGISTRY DRIFT (the engine believes nothing
produces it); it counts as supplied, and is declared and reported until
coverage.py is corrected.

evidence.yaml declares only what cannot be computed: the evidence types (which
engine kinds count as which evidence), why a source does NOT supply an evidence
type (status + detail + ref), the orphan kinds, and the customer profiles. Every
(source, evidence) cell is therefore either computed-native or declared-with-a-
reason; an undeclared gap or a declared gap the code has since closed fails the
build (test_source_equivalence.py), the same staleness rule as the tracker guard.

THE SCORECARD is per customer profile (SNMP+push, each controller alone,
SNMP+controller): which evidence types are natively supplied, and how many
enabled RCA templates can be MATCHED — every mandatory clause satisfiable by a
kind the profile supplies. That is the number E1..E8 must move; it is ratcheted
in source_equivalence_baseline.json and never allowed to drop.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

import yaml

import bake_rules as B
import coverage_matrix as CM

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
EVIDENCE_YAML = os.path.join(HERE, "evidence.yaml")
BASELINE = os.path.join(HERE, "source_equivalence_baseline.json")
TARGET = os.path.join(ROOT, "docs", "design", "source-equivalence-matrix.md")
NMS_DIR = os.path.join(ROOT, "src", "backend", "nms")
ENGINE_DIR = os.path.join(ROOT, "src", "correlation")

GAP_STATUSES = ("normalization_pending", "collection_pending", "dormant", "unavailable", "unverified")
#: The connector file(s) whose normalizer decides each registered vendor's kinds.
CONNECTOR_FILES: dict[str, tuple[str, ...]] = {
    "vmanage": ("vmanage.go", "sdwan_state_events.go", "vmanage_kinds.go"),
    "catalyst_center": ("catalyst.go", "canonical_alarm_kinds.go"),
    "meraki": ("meraki.go", "canonical_alarm_kinds.go"),
    "ndfc": ("ndfc.go", "canonical_alarm_kinds.go"),
    "prime": ("prime.go", "canonical_alarm_kinds.go"),
    "versa_director": ("versa.go", "canonical_alarm_kinds.go"),
    "versa_concerto": ("versa.go", "canonical_alarm_kinds.go"),
    "catalyst_9800": ("catalyst9800.go",),
    "generic": ("generic.go",),
}
_MAP_VALUE_KIND = re.compile(r':\s*"((?:controller|wireless|device)_[a-z_]+)"')
_RETURN_KIND = re.compile(r'return\s+"((?:controller|wireless|device)_[a-z_]+)"')
# A connector's canonical kind TABLE (e.g. nms/vmanage_kinds.go, E2a): entries
# written down("kind", …) / up("kind", …) or Kind: "kind".
_TABLE_KIND = re.compile(r'(?:\b(?:down|up)\(|(?<![A-Za-z])Kind:\s*)"([a-z][a-z_]+)"')
_REGISTRY_RE = re.compile(r'\breg\("([a-z0-9_]+)"')


class EquivalenceError(Exception):
    """evidence.yaml or a computed source is inconsistent."""


# ---- engine vocabulary --------------------------------------------------------
#
# Read in a SUBPROCESS running inside src/correlation: the engine's modules
# (`catalog`, `coverage`, `producers`) share names with this directory's own
# `catalog.py`, and importing both into one interpreter makes them collide in
# the module cache and break the rest of this suite.

_ENGINE_PROBE = """
import json
import coverage as cov
from catalog import BUILTIN_TEMPLATES, load_catalog
templates = [
    [t.id, [sorted(c.kinds()) for c in t.requires if not c.optional]]
    for t in load_catalog(BUILTIN_TEMPLATES).templates if getattr(t, "enabled", True)
]
print(json.dumps({
    "emitted": sorted(cov.EMITTED_KINDS),
    "pending": sorted(set(cov.NORMALIZATION_PENDING) | set(cov.COLLECTION_PENDING)),
    "templates": templates,
}))
"""
_engine_cache: dict = {}


def _engine() -> dict:
    if not _engine_cache:
        # Fixed interpreter and fixed script: no user input reaches the command.
        proc = subprocess.run(
            [sys.executable, "-c", _ENGINE_PROBE], cwd=ENGINE_DIR,
            capture_output=True, text=True, timeout=120, check=False)
        if proc.returncode != 0:
            raise EquivalenceError(f"could not read the engine vocabulary: {proc.stderr.strip()[-500:]}")
        _engine_cache.update(json.loads(proc.stdout))
    return _engine_cache


def engine_vocabulary() -> tuple[frozenset[str], frozenset[str]]:
    """(kinds the engine emits/consumes, kinds it knows as declared gaps)."""
    e = _engine()
    return frozenset(e["emitted"]), frozenset(e["pending"])


def enabled_templates() -> list[tuple[str, list[frozenset[str]]]]:
    """(template id, mandatory clause kind-sets) for every enabled template."""
    return [(tid, [frozenset(c) for c in clauses]) for tid, clauses in _engine()["templates"]]


# ---- computed supply ----------------------------------------------------------

def registered_connectors() -> list[str]:
    with open(os.path.join(NMS_DIR, "registry.go"), encoding="utf-8") as fh:
        return sorted(set(_REGISTRY_RE.findall(fh.read())))


def connector_kinds(vendor: str) -> frozenset[str]:
    """Kind literals the vendor's normalizer can return (its emitted vocabulary)."""
    kinds: set[str] = set()
    for name in CONNECTOR_FILES.get(vendor, ()):
        with open(os.path.join(NMS_DIR, name), encoding="utf-8") as fh:
            src = fh.read()
        # sdwan_state_events.go is a state → kind MAP: its keys are state names
        # ("device_health"), only its values are kinds.
        if name == "sdwan_state_events.go":
            pattern = _MAP_VALUE_KIND
        elif name.endswith("_kinds.go"):
            pattern = _TABLE_KIND
        else:
            pattern = _RETURN_KIND
        kinds.update(pattern.findall(src))
    return frozenset(kinds)


def rule_kinds(source: str) -> frozenset[str]:
    _, rows = B.load()
    # `lane: catalog` rows are grammar-only — kept OUT of the runtime parser
    # table on purpose (events.yaml), so they supply nothing at runtime.
    return frozenset(r["kind"] for r in rows
                     if r.get("source") == source and not r.get("generic") and r.get("lane") != "catalog")


def poll_kinds() -> frozenset[str]:
    return frozenset(CM.EPISODE_KIND[b] for b in set(CM.METRIC_BUCKET.values()) if b in CM.EPISODE_KIND)


def raw_supply(source: dict) -> frozenset[str]:
    how = source["computed_from"]
    if how == "syslog_rules":
        return rule_kinds("syslog")
    if how == "trap_rules":
        return rule_kinds("trap")
    if how == "snmp_metric_allowlist":
        return poll_kinds()
    if how == "flow_lane":
        return frozenset({"flow_volume_anomaly"})
    if how == "connector":
        return connector_kinds(source["id"])
    if how == "none":
        return frozenset()
    raise EquivalenceError(f"source {source['id']}: unknown computed_from {how!r}")


# ---- model -------------------------------------------------------------------

def load_model(path: str = EVIDENCE_YAML) -> dict:
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    for key in ("evidence_types", "sources", "orphan_kinds", "profiles"):
        if key not in data:
            raise EquivalenceError(f"evidence.yaml: missing top-level `{key}`")
    return data


def analyse(model: dict) -> dict:
    """Compute every cell, validate every declaration, score every profile.

    Raises EquivalenceError on the first inconsistency; the message names it."""
    emitted, pending = engine_vocabulary()
    known = emitted | pending
    ev_ids = [e["id"] for e in model["evidence_types"]]
    if len(set(ev_ids)) != len(ev_ids):
        raise EquivalenceError("evidence.yaml: duplicate evidence type id")
    for e in model["evidence_types"]:
        unknown = sorted(set(e.get("engine_kinds") or []) - known)
        if unknown:
            raise EquivalenceError(f"evidence type {e['id']}: engine does not know kind(s) {unknown}")

    connectors = registered_connectors()
    src_ids = [s["id"] for s in model["sources"]]
    missing_conn = sorted(set(connectors) - set(src_ids))
    if missing_conn:
        raise EquivalenceError(f"registered connector(s) with no source entry: {missing_conn}")

    orphans_found: dict[str, set[str]] = {}
    cells: dict[str, dict[str, dict]] = {}
    supply: dict[str, frozenset[str]] = {}
    drift_found: dict[str, set[str]] = {}
    for s in model["sources"]:
        raw = raw_supply(s)
        for k in sorted(raw - known):
            orphans_found.setdefault(k, set()).add(s["id"])
        for k in sorted(raw & (known - emitted)):
            drift_found.setdefault(k, set()).add(s["id"])
        supply[s["id"]] = raw & known
        gaps = s.get("gaps") or {}
        unknown_ev = sorted(set(gaps) - set(ev_ids))
        if unknown_ev:
            raise EquivalenceError(f"source {s['id']}: gaps for unknown evidence type(s) {unknown_ev}")
        row: dict[str, dict] = {}
        for e in model["evidence_types"]:
            native = sorted(set(e.get("engine_kinds") or []) & supply[s["id"]])
            decl = gaps.get(e["id"])
            if e.get("declared_only"):
                if decl is None:
                    raise EquivalenceError(f"{s['id']} × {e['id']}: declared-only evidence needs a declaration")
                row[e["id"]] = {"status": decl["status"], "detail": decl.get("detail", ""), "ref": decl.get("ref", "")}
                continue
            if native and decl is not None:
                raise EquivalenceError(
                    f"{s['id']} × {e['id']}: declared {decl.get('status')!r} but the code now supplies "
                    f"{native} — delete the stale declaration")
            if native:
                row[e["id"]] = {"status": "native", "kinds": native}
                continue
            if decl is None:
                raise EquivalenceError(f"{s['id']} × {e['id']}: not supplied and not declared — say why")
            if decl.get("status") not in GAP_STATUSES + ("native_declared",):
                raise EquivalenceError(f"{s['id']} × {e['id']}: status must be one of {GAP_STATUSES}")
            if not str(decl.get("detail") or "").strip():
                raise EquivalenceError(f"{s['id']} × {e['id']}: a gap needs a `detail`")
            row[e["id"]] = {"status": decl["status"], "detail": decl["detail"], "ref": decl.get("ref", "")}
        cells[s["id"]] = row

    declared_orphans = model["orphan_kinds"] or {}
    undeclared = sorted(set(orphans_found) - set(declared_orphans))
    if undeclared:
        raise EquivalenceError(
            "connector kind(s) the engine does not know, undeclared: "
            + ", ".join(f"{k} (from {sorted(orphans_found[k])})" for k in undeclared))
    healed = sorted(set(declared_orphans) - set(orphans_found))
    if healed:
        raise EquivalenceError(f"declared orphan kind(s) no longer orphaned — delete the entry: {healed}")
    for k, o in declared_orphans.items():
        for f in ("reason", "fix"):
            if not str((o or {}).get(f) or "").strip():
                raise EquivalenceError(f"orphan kind {k}: `{f}` is required")

    declared_drift = model.get("registry_drift") or {}
    und = sorted(set(drift_found) - set(declared_drift))
    if und:
        raise EquivalenceError(
            "kind(s) a source supplies but the engine's coverage registry calls pending, undeclared: "
            + ", ".join(f"{k} (from {sorted(drift_found[k])})" for k in und))
    gone = sorted(set(declared_drift) - set(drift_found))
    if gone:
        raise EquivalenceError(f"declared registry drift no longer present — delete the entry: {gone}")

    templates = enabled_templates()
    profiles = {}
    for name, p in model["profiles"].items():
        bad = sorted(set(p["sources"]) - set(src_ids))
        if bad:
            raise EquivalenceError(f"profile {name}: unknown source(s) {bad}")
        kinds = frozenset().union(*(supply[s] for s in p["sources"]))
        covered = [e["id"] for e in model["evidence_types"] if not e.get("declared_only")
                   and any(cells[s][e["id"]]["status"] == "native" for s in p["sources"])]
        matchable = sorted(tid for tid, clauses in templates if clauses and all(c & kinds for c in clauses))
        profiles[name] = {"title": p.get("title", name), "sources": p["sources"], "evidence": covered,
                          "matchable": matchable}
    return {"cells": cells, "supply": supply, "orphans": {k: sorted(v) for k, v in orphans_found.items()},
            "drift": {k: sorted(v) for k, v in drift_found.items()},
            "profiles": profiles, "templates": len(templates)}


# ---- render ------------------------------------------------------------------

_MARK = {"native": "✅", "native_doc": "✅ᵈ", "normalization_pending": "🟠", "collection_pending": "⬜", "dormant": "💤",
         "unavailable": "—", "unverified": "❓", "native_declared": "✅*"}


def _cell_mark(source: dict, status: str) -> str:
    """A native cell of a doc_claimed source is marked apart: the mapping is
    computed from code, but no recorded payload has proven it yet."""
    if status == "native" and source.get("fidelity") == "doc_claimed":
        return _MARK["native_doc"]
    return _MARK[status]


def render(model: dict, a: dict) -> str:
    srcs = model["sources"]
    evs = model["evidence_types"]
    out = [
        "# Source-equivalence matrix",
        "",
        "> GENERATED by `telemetry-catalog/source_equivalence.py` from `telemetry-catalog/evidence.yaml`,",
        "> the executable rule table, the SNMP metric allowlist and the connectors' Go normalizers.",
        "> Do not edit by hand: `python3 source_equivalence.py` regenerates it, `--check` guards drift.",
        "",
        "Does correlation get the same evidence whichever source a customer uses? A ✅ cell is",
        "COMPUTED from code: the source emits a kind the engine consumes for that evidence. Every",
        "other cell is a declared gap with its reason.",
        "",
        "✅ supplied · 🟠 collected, not normalised to an engine kind · ⬜ collectable, not collected ·",
        "💤 built, dormant · — the source cannot supply it · ❓ unverified · ✅* declared (not computable) ·",
        "✅ᵈ supplied by a doc_claimed mapping (computed from code, not yet proven by a recorded payload)",
        "",
        "## Scorecard per customer profile",
        "",
        (f"Matchable = enabled RCA templates whose every mandatory clause the profile can satisfy "
         f"(of {a['templates']} enabled)."),
        "",
        "| Profile | Sources | Evidence types supplied | Matchable templates | Fidelity |",
        "|---|---|---|---|---|",
    ]
    total = len([e for e in evs if not e.get("declared_only")])
    for p in a["profiles"].values():
        fid = sorted({next(x.get("fidelity", "lab_validated") for x in srcs if x["id"] == sid)
                      for sid in p["sources"]})
        out.append(f"| {p['title']} | {', '.join(p['sources'])} | {len(p['evidence'])}/{total} | "
                   f"{len(p['matchable'])} | {' + '.join(fid)} |")
    out += ["", "## Matrix", "", "| Evidence | " + " | ".join(s["id"] for s in srcs) + " |",
            "|---|" + "---|" * len(srcs)]
    for e in evs:
        row = [f"**{e['id']}**"] + [_cell_mark(s, a["cells"][s["id"]][e["id"]]["status"]) for s in srcs]
        out.append("| " + " | ".join(row) + " |")
    out += ["", "## Orphan kinds — collected, then thrown away", "",
            "A connector emits these; the engine has no such kind, so no template can use them.", "",
            "| Kind | Emitted by | Why | Fix |", "|---|---|---|---|"]
    for k, o in sorted((model["orphan_kinds"] or {}).items()):
        out.append(f"| `{k}` | {', '.join(a['orphans'].get(k, []))} | {o['reason']} | {o['fix']} |")
    out += ["", "## Registry drift — supplied, but the engine's coverage registry says pending", "",
            "These kinds ARE produced; `src/correlation/coverage.py` still lists them as a gap, so the",
            "engine's own coverage report under-states what it receives.", "",
            "| Kind | Supplied by | Fix |", "|---|---|---|"]
    for k, d in sorted((model.get("registry_drift") or {}).items()):
        out.append(f"| `{k}` | {', '.join(a['drift'].get(k, []))} | {d['fix']} |")
    out += ["", "## Gaps by source", ""]
    for s in srcs:
        gaps = [(e["id"], a["cells"][s["id"]][e["id"]]) for e in evs
                if a["cells"][s["id"]][e["id"]]["status"] != "native"]
        native = [f"{e['id']} ({', '.join(a['cells'][s['id']][e['id']]['kinds'])})" for e in evs
                  if a["cells"][s["id"]][e["id"]]["status"] == "native"]
        out += [f"### {s['id']} — {s.get('title', '')}", "",
                f"Supplies: {'; '.join(native) if native else 'nothing the engine consumes yet'}.", ""]
        for eid, c in gaps:
            ref = f" ({c['ref']})" if c.get("ref") else ""
            out.append(f"- **{eid}** {_MARK[c['status']]} {c['status']}: {c['detail']}{ref}")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def baseline_of(a: dict) -> dict:
    return {name: len(p["matchable"]) for name, p in a["profiles"].items()}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="exit 1 if the matrix doc is stale")
    ap.add_argument("--write-baseline", action="store_true", help="raise the profile ratchet to today")
    args = ap.parse_args(argv)
    try:
        model = load_model()
        a = analyse(model)
    except EquivalenceError as e:
        print(f"source_equivalence: {e}", file=sys.stderr)
        return 1
    doc = render(model, a)
    if args.check:
        with open(TARGET, encoding="utf-8") as fh:
            if fh.read() != doc:
                print(f"source_equivalence: {TARGET} is stale — run python3 source_equivalence.py", file=sys.stderr)
                return 1
        return 0
    with open(TARGET, "w", encoding="utf-8") as fh:
        fh.write(doc)
    if args.write_baseline:
        with open(BASELINE, "w", encoding="utf-8") as fh:
            json.dump(baseline_of(a), fh, indent=2, sort_keys=True)
            fh.write("\n")
    for name, p in a["profiles"].items():
        print(f"{name:28} evidence {len(p['evidence']):2}  matchable templates {len(p['matchable'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
