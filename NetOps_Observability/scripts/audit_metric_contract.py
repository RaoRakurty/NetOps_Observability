#!/usr/bin/env python3
"""Panel↔metric contract audit (foundation guard, Tier 1).

The failure class this catches: a dashboard panel queries a metric that NO
collector produces, so the panel is silently empty — indistinguishable from a
healthy-but-quiet panel. Discovered late (in a demo) instead of at build time.

This extracts every metric name referenced in the frontend's PromQL queries and
diffs it against the metrics the collectors actually emit (SNMP profiles +
Go-collector exposition strings + the curated extra-emitters list). Anything
referenced-but-not-emitted is an orphan and is reported; a non-empty orphan set
exits non-zero so CI fails.

Run standalone for the audit:  python3 scripts/audit_metric_contract.py
Exit 0 = clean contract; exit 1 = orphans (printed).
"""
from __future__ import annotations

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
FRONTEND = os.path.join(ROOT, "src", "frontend", "src")
BACKEND = os.path.join(ROOT, "src", "backend")

# PromQL functions / keywords that look like identifiers but are never metrics.
PROMQL_KEYWORDS = {
    "rate", "irate", "sum", "avg", "min", "max", "count", "topk", "bottomk",
    "increase", "delta", "deriv", "changes", "abs", "ceil", "floor", "round",
    "clamp_max", "clamp_min", "label_replace", "label_join", "histogram_quantile",
    "by", "without", "on", "ignoring", "group_left", "group_right", "or", "and",
    "unless", "offset", "bool", "time", "vector", "scalar", "absent", "quantile",
    "stddev", "stdvar", "last_over_time", "avg_over_time", "max_over_time",
    "min_over_time", "sum_over_time", "count_over_time", "predict_linear",
}

# Metrics referenced via string-built helpers or bare (no {/[ } anchor), or that
# legitimately come from a source this audit doesn't parse (Telegraf, node-exporter,
# Vector internal). Each entry MUST carry a reason — this is the waiver ledger.
WAIVERS: dict[str, str] = {
    "up": "Prometheus target-up synthetic, always present",
    "node_": "node-exporter prefix (host metrics) — separate exporter, not our collectors",
    "vector_": "Vector internal metrics (prometheus_exporter) — operator scope",
    "scrape_": "Prometheus scrape meta",
    "device_id": "TS field / label selector, not a metric (false positive)",
    "device_if_": "template-literal fragment `device_if_${dir}_octets` — real metrics emitted",
    # OR-fallback branches: the memory panels read
    #   device_mem_percent OR used/(used+free) OR (total-available)/total
    # so these alternates need not all exist as long as the primary
    # (device_mem_percent, emitted) is. Kept waived WITH this reason rather than
    # silently — the audit's job is no UNDOCUMENTED orphan.
    "device_mem_free_bytes": "OR-fallback branch; device_mem_percent is the emitted primary",
    "device_mem_total_kb": "OR-fallback branch; device_mem_percent is the emitted primary",
    "device_mem_available_kb": "OR-fallback branch; device_mem_percent is the emitted primary",
}


def emitted_metrics() -> set[str]:
    """Every metric name the Go collectors produce: profiles.go `Name:` fields +
    exposition strings in Sprintf (`metric_name{...}` / `metric_name %d`)."""
    names: set[str] = set()
    name_re = re.compile(r'Name:\s*"([a-z][a-z0-9_]+)"')
    expo_re = re.compile(r'`([a-z][a-z0-9_]+)\{')          # `probe_rtt_ms{dst=...
    expo2_re = re.compile(r'"([a-z][a-z0-9_]+)\{')          # "collector_up{...
    fmtpct_re = re.compile(r'fmt\.Sprintf\(\s*`?"?([a-z][a-z0-9_]+)\{')
    for dirpath, _dirs, files in os.walk(BACKEND):
        if "/vendor/" in dirpath:
            continue
        for f in files:
            if not f.endswith(".go") or f.endswith("_test.go"):
                continue
            txt = open(os.path.join(dirpath, f)).read()
            for rx in (name_re, expo_re, expo2_re, fmtpct_re):
                names.update(rx.findall(txt))
    return names


def referenced_metrics() -> dict[str, set[str]]:
    """metric_name -> set of files referencing it, extracted from PromQL query
    strings in the frontend. A metric is an identifier immediately followed by
    `{` (selector) or `[` (range) — the syntactic positions only a metric can
    occupy — which excludes TS field names like device_id / device_name."""
    # A metric name = a known telemetry prefix + at least one more segment
    # (snake_case). This shape excludes JS/TS tokens (acc, any, catch) and TS
    # field access (device_id has the prefix but is matched only inside PromQL
    # strings below, and is filtered by requiring a metric-position anchor).
    metric_tok = re.compile(
        r'\b((?:device|probe|synthetic|collector|node|netops|if)_[a-z0-9_]+)\b')
    # A PromQL string carries a range (`[5m]`) or a PromQL function call.
    promql_str = re.compile(
        r'[`"\']([^`"\']*(?:\[\d+[smhd]\]|\b(?:rate|sum|topk|avg|increase|changes|'
        r'label_replace|irate|max|min|count|histogram_quantile)\s*\()[^`"\']*)[`"\']')
    refs: dict[str, set[str]] = {}
    for dirpath, _dirs, files in os.walk(FRONTEND):
        for f in files:
            if not (f.endswith(".tsx") or f.endswith(".ts")):
                continue
            path = os.path.join(dirpath, f)
            txt = open(path).read()
            for m in promql_str.finditer(txt):
                for tok in metric_tok.findall(m.group(1)):
                    if tok in PROMQL_KEYWORDS:
                        continue
                    refs.setdefault(tok, set()).add(os.path.relpath(path, FRONTEND))
    return refs


# KNOWN, ACKNOWLEDGED gaps with an open work item. Distinct from WAIVERS (not a
# real gap): these ARE real — a panel that has no data today — but are tracked,
# not silently hidden. The audit reports them loudly yet does not fail CI on
# them (they're already on the board). A NEW orphan that is neither waived nor
# tracked DOES fail CI — that's the regression guard.
TRACKED_GAPS: dict[str, str] = {
    "device_storage_size": "Storage gauge inactive — needs HOST-RESOURCES hrStorage / vendor-flash OIDs (baseline coverage pass)",
    "device_storage_used": "Storage gauge inactive — needs HOST-RESOURCES hrStorage / vendor-flash OIDs (baseline coverage pass)",
}


def waived(metric: str) -> bool:
    return any(metric == k or (k.endswith("_") and metric.startswith(k)) for k in WAIVERS)


def main() -> int:
    emitted = emitted_metrics()
    refs = referenced_metrics()
    missing = {m: files for m, files in sorted(refs.items())
               if m not in emitted and not waived(m)}
    tracked = {m: f for m, f in missing.items() if m in TRACKED_GAPS}
    untracked = {m: f for m, f in missing.items() if m not in TRACKED_GAPS}

    print("panel↔metric contract audit")
    print(f"  metrics emitted by collectors : {len(emitted)}")
    print(f"  metrics referenced by panels  : {len(refs)}")
    print(f"  tracked gaps (known, on the board): {len(tracked)}")
    print(f"  UNTRACKED orphans (regressions)   : {len(untracked)}")

    if tracked:
        print("\nKNOWN GAPS (panel empty, work item open):")
        for m in tracked:
            print(f"  • {m} — {TRACKED_GAPS[m]}")
    if untracked:
        print("\n✗ UNTRACKED ORPHANS (panel queries it, nothing emits it, no work item):")
        for m, files in untracked.items():
            print(f"  ✗ {m}")
            for fl in sorted(files):
                print(f"       {fl}")
        print("\nFix: add the OID to a collector profile, add a TRACKED_GAPS entry "
              "with a work item, or a justified WAIVERS entry.")
        return 1
    print("\n  ✓ contract clean — no untracked orphans")
    return 0


if __name__ == "__main__":
    sys.exit(main())
