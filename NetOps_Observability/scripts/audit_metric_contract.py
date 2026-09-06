#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

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
GNMIC_YAML = os.path.join(ROOT, "deployment", "docker", "gnmic", "gnmic.yaml")
PROFILES_GO = os.path.join(BACKEND, "collectors", "profiles.go")


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()

# Canonical families gNMI is allowed to emit even though NO SNMP collector emits
# them — i.e. gNMI is the sole owner because the device has no SNMP source. Each
# entry MUST carry a reason (the ownership ledger for the gNMI side, mirroring
# the gnmic.yaml ownership-gate comment).
GNMI_OWNED: dict[str, str] = {
    "device_mem_percent": "Nokia SR Linux has no SNMP memory source; gNMI owns it "
                          "(also emitted by SNMP for Juniper — subset-safe either way)",
    "device_bgp_pfx_in": "per-AFI accepted-prefix count; BGP4-MIB is IPv4-only and "
                         "BGP4V2-MIB is draft (no usable SNMP source) — gNMI owns it "
                         "(gnmic.yaml ownership gate; telemetry-coverage-reference.md).",
    "device_isis_adj_state": "IS-IS adjacency on-change; no IS-IS MIB is collected — "
                             "gNMI is the sole, priority source (gnmic.yaml ownership gate).",
    # --- IGP depth, frontend-wave #11 (telemetry-coverage-reference.md § F) ---
    # The SNMP profile polls NO ISIS-MIB object at all, so the whole IS-IS family
    # is gNMI-owned by the same logic as device_isis_adj_state above. Where
    # ISIS-MIB (RFC 4444) does have a counterpart it is named, so a future
    # agentless-IS-IS device has a starting point rather than a blank.
    "device_isis_lsp_count": "LSP-database size per level (SRL level statistics/total-lsps). "
                             "ISIS-MIB offers no database-SIZE column — only isisLSPTable, one row "
                             "per LSP — and no ISIS-MIB object is polled here; gNMI owns it.",
    "device_isis_spf_runs_total": "SPF runs per level (SRL level statistics/spf-runs). ISIS-MIB has "
                                  "isisSysStatSPFRuns (1.3.6.1.2.1.138.1.5.1.1.12) but no ISIS-MIB "
                                  "object is polled here; gNMI owns it.",
    "device_isis_area": "IS-IS area-address INFO series (SRL instance oper-area-id). ISIS-MIB has "
                        "isisManAreaAddr / isisAreaAddr but no ISIS-MIB object is polled here; "
                        "gNMI owns it.",
    "device_isis_adj_hold_seconds": "per-adjacency REMAINING hold countdown (SRL adjacency "
                                    "remaining-holdtime). ISIS-MIB's isisISAdjHoldTimer "
                                    "(1.3.6.1.2.1.138.1.6.1.1.9) is the nearest counterpart and is "
                                    "not polled here; gNMI owns it.",
}

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
            path = os.path.join(dirpath, f)
            # The security vocabulary DECLARES families with the same
            # `Name: "..."` syntax the SNMP profiles use to emit them; a
            # declaration is not an emission (reserved rows must not read as
            # emitted).
            if path == VOCAB_GO:
                continue
            txt = _read(path)
            for rx in (name_re, expo_re, expo2_re, fmtpct_re):
                names.update(rx.findall(txt))
    return names


def snmp_family_owners() -> tuple[dict[str, dict[str, str]], list[str]]:
    """{family: {profile: owner}} parsed out of builtinProfiles() in profiles.go.

    `SNMPMetric.Owner` is the PER-DEVICE hand-back: a metric marked
    Owner: "gnmi" is withheld by the SNMP poller on any device labelled
    `gnmi: "true"`, so gNMI owns it there and SNMP still serves it everywhere
    else. The absent/empty owner defaults to "snmp" (SNMP emits it always).

    Reads the Go source rather than a transcription of it, and reports a problem
    (never a silent empty map) if the literal's shape changes — a vacuous "no
    owners parsed" would make the double-produce check below pass for free.
    """
    problems: list[str] = []
    if not os.path.exists(PROFILES_GO):
        return {}, [(f"profiles.go not found at {PROFILES_GO} — the SNMP ownership "
                     "half of the single-contract guard cannot be checked")]
    src = _read(PROFILES_GO)
    block = re.search(r"func builtinProfiles\(\) \[\]SNMPProfile \{(.*?)\n\}\n", src, re.DOTALL)
    if not block:
        return {}, [("profiles.go: builtinProfiles() not found — the ownership parse "
                     "went stale and the double-produce guard would pass vacuously")]

    out: dict[str, dict[str, str]] = {}
    profile: str | None = None
    for line in block.group(1).split("\n"):
        m = re.search(r'Name:\s+"([a-z0-9]+)",\s*$', line)
        if m:
            profile = m.group(1)
            continue
        m = re.search(r'\{Name: "(device_[a-z0-9_]+)",\s*OID:(.*)$', line)
        if not m:
            continue
        family, rest = m.group(1), m.group(2)
        if profile is None:
            problems.append(f"profiles.go: metric {family} parsed before any profile "
                            "name — the literal's shape changed")
            continue
        owner = re.search(r'Owner:\s*"([a-z]*)"', rest)
        out.setdefault(family, {})[profile] = (owner.group(1) if owner else "") or "snmp"
    if not out:
        problems.append("profiles.go: no metrics parsed out of builtinProfiles() — the "
                        "literal's shape changed and the double-produce guard would "
                        "pass vacuously")
    return out, problems


def gnmi_canonical_lane(snmp_emitted: set[str]) -> tuple[set[str], list[str]]:
    """Parse the gnmic canonical-lane normalization (deployment/docker/gnmic.yaml).

    The gNMI lane rewrites device paths to canonical `device_*` names (canon-names
    `new:` targets), then the ownership-gate DELETES the families that stay
    SNMP-owned. What survives is the set of canonical names gNMI actually writes
    to VictoriaMetrics. The single-contract invariant: a gNMI-emitted canonical
    name must ALSO be emitted by the SNMP collectors (same contract, two
    transports) — unless it is a documented GNMI_OWNED family (no SNMP source).

    Returns (gnmi_emitted_set, problems). A non-empty problems list fails CI.
    This is the gNMI half of the contract guard — without it the gnmic processor
    chain has zero automated coverage and can silently mis-normalize.
    """
    problems: list[str] = []
    if not os.path.exists(GNMIC_YAML):
        return set(), [f"gnmic.yaml not found at {GNMIC_YAML}"]
    txt = _read(GNMIC_YAML)

    # canon-names is the only processor whose `new:` targets are device_* names
    # (canon-status-enums → "1".."7", canon-tags → "ifName"/"device"). So every
    # `new: "device_..."` in the file is a canonical-lane target.
    targets = set(re.findall(r'new:\s*"(device_[a-z0-9_]+)"', txt))
    if not targets:
        problems.append("canon-names: no `device_*` rewrite targets found — "
                        "chain broken or file moved?")

    # Well-formedness: canonical names carry no '/' or '-' (those are path-shaped
    # and would be dropped by drop-unmapped). Anchored snake_case only.
    name_ok = re.compile(r"^device_[a-z0-9_]+$")
    for t in sorted(targets):
        if not name_ok.match(t):
            problems.append(f"canon-names target malformed (not ^device_[a-z0-9_]+$): {t}")

    # ownership-gate: the value-names delete-list (anchored regexes). Extract the
    # block between `ownership-gate:` and the next 2-space-indented processor key.
    #
    # The gate is EMPTY BY DESIGN since bb76e8e7 (tracker 230): the hand-back to
    # SNMP now happens per DEVICE, via `Owner: "gnmi"` in collectors/profiles.go,
    # because the global gate cost the gNMI-only SR Linux spines their interface,
    # CPU and temperature series entirely. So an empty list is no longer a
    # failure in itself — but the double-produce guarantee it used to carry still
    # has to hold, and it is now proven against profiles.go below.
    #
    # What IS still fatal is the processor going missing: it is the only
    # mechanism for handing a family back, and an empty processor is exactly the
    # kind of thing that gets deleted as dead config.
    gate_block = ""
    m = re.search(r"^  ownership-gate:\n(.*?)(?=^  [a-z])", txt, re.DOTALL | re.MULTILINE)
    if m:
        gate_block = m.group(1)
    else:
        problems.append("ownership-gate: the processor is not in gnmic.yaml — it is the "
                        "ONLY mechanism for handing a canonical family back to SNMP; "
                        "removing it makes a future hand-back silently do nothing.")
    gate_patterns = re.findall(r'-\s*"([^"]+)"', gate_block)
    gate_res = [re.compile(p) for p in gate_patterns]

    def gated(name: str) -> bool:
        return any(rx.search(name) for rx in gate_res)

    # Stale-gate guard: every gate pattern must match at least one canon-names
    # target. A pattern matching nothing is dead config (a renamed family left a
    # ghost entry) and silently weakens the collision guard.
    for p, rx in zip(gate_patterns, gate_res):
        if not any(rx.search(t) for t in targets):
            problems.append(f"ownership-gate pattern matches no canon-names target "
                            f"(stale/dead gate entry): {p}")

    # What gNMI actually emits = mapped targets minus gated ones.
    gnmi_emitted = {t for t in targets if not gated(t)}

    # ── the double-produce guarantee, now carried by profiles.go ─────────────
    #
    # A family that LEAVES the gNMI canonical lane and is ALSO emitted by an SNMP
    # profile is produced twice on a dual-transport device, from two label
    # shapes. The gate used to prevent that globally; `Owner: "gnmi"` now does it
    # per device. So every ungated family with an SNMP counterpart must carry
    # that owner in EVERY profile defining it — that, and only that, is what
    # makes an empty gate a valid state.
    #
    # This mirrors tests/test_gnmi_ownership_contract.py
    # (test_ungated_families_are_gnmi_owned_everywhere), re-implemented here in
    # stdlib regex because this script is dependency-free by contract (the CI job
    # installs nothing) while that test parses YAML with PyYAML. The two read the
    # same two files, so neither can go stale against a transcription.
    owners, owner_problems = snmp_family_owners()
    problems.extend(owner_problems)
    double_produced: list[str] = []
    for fam in sorted(gnmi_emitted):
        for profile, owner in sorted(owners.get(fam, {}).items()):
            if owner != "gnmi":
                double_produced.append(f"{fam} (profile {profile}: Owner {owner!r})")
    for row in double_produced:
        problems.append(
            f"double-produce: {row} leaves the gNMI canonical lane (not in the "
            f"ownership gate) while the SNMP profile still owns it — a device "
            f"carrying both transports emits the same canonical series twice. "
            f"Gate the family in gnmic.yaml or set Owner: \"gnmi\" on it.")
    if not gate_patterns and not owner_problems and double_produced:
        problems.append(
            "the ownership gate is EMPTY and the profiles.go owner mirror above is "
            "inconsistent — with neither mechanism withholding them, those families "
            "double-produce. An empty gate is only valid while every gnmic-mapped "
            "family with an SNMP counterpart carries Owner: \"gnmi\".")

    # Single-contract invariant: gNMI-emitted names ⊆ SNMP-emitted names, modulo
    # documented gNMI-owned families.
    for name in sorted(gnmi_emitted):
        if name not in snmp_emitted and name not in GNMI_OWNED:
            problems.append(
                f"gNMI emits canonical `{name}` that NO SNMP collector emits and "
                f"it is not a documented GNMI_OWNED family — single-contract "
                f"divergence (add an SNMP source, gate it, or add GNMI_OWNED entry).")
    return gnmi_emitted, problems


VOCAB_GO = os.path.join(BACKEND, "internal", "secobs", "vocab.go")


def security_vocabulary(emitted: set[str]) -> list[str]:
    """SEC-020.1 contract: internal/secobs/vocab.go is THE security metric
    vocabulary. Three invariants, cross-checked against the Go source:

      1. every StatusEmitted family is actually emitted somewhere in the
         backend (a vocabulary row claiming "emitted" while nothing emits it is
         the silent-misfire SEC-020 exists to kill);
      2. every emitted `netops_sec_*` family is IN the vocabulary (no name
         squatting outside the registry);
      3. no StatusReserved family is emitted (emission means the row must flip
         to StatusEmitted in the same change — the table stays truthful).

    Returns a list of problems; non-empty fails CI.
    """
    problems: list[str] = []
    if not os.path.exists(VOCAB_GO):
        return [f"security vocabulary not found at {VOCAB_GO}"]
    txt = _read(VOCAB_GO)
    rows = re.findall(
        r'\{Name:\s*"([a-z0-9_]+)",.*?Status:\s*Status(Emitted|Reserved)\}', txt)
    if len(rows) < 8:
        problems.append(
            f"vocab.go: parsed only {len(rows)} vocabulary rows — the "
            "one-row-per-line format this parser relies on has drifted")
        return problems

    # The generic emitted_metrics() only sees `name{` anchors; several
    # security families are label-less (`netops_tls_cert_expiry_seconds %.0f`).
    # Add the bare-exposition shape for this check.
    bare_re = re.compile(r'"([a-z][a-z0-9_]+) %')
    bare: set[str] = set()
    for dirpath, _dirs, files in os.walk(BACKEND):
        if "/vendor/" in dirpath:
            continue
        for f in files:
            if not f.endswith(".go") or f.endswith("_test.go"):
                continue
            path = os.path.join(dirpath, f)
            if path == VOCAB_GO:
                continue
            bare.update(bare_re.findall(_read(path)))
    sec_emitted = emitted | bare

    vocab = {name: status for name, status in rows}
    for name, status in sorted(vocab.items()):
        if status == "Emitted" and name not in sec_emitted:
            problems.append(
                f"vocabulary family `{name}` is StatusEmitted but NO backend "
                "code emits it — emit it or flip the row to StatusReserved")
        if status == "Reserved" and name in sec_emitted:
            problems.append(
                f"vocabulary family `{name}` is StatusReserved but IS emitted — "
                "flip the row to StatusEmitted in the same change")
    for name in sorted(sec_emitted):
        if name.startswith("netops_sec_") and name not in vocab:
            problems.append(
                f"backend emits `{name}` outside the vocabulary — register it "
                "in internal/secobs/vocab.go (SEC-020.1: name the signals once)")
    return problems


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
            if not f.endswith((".tsx", ".ts")):
                continue
            path = os.path.join(dirpath, f)
            txt = _read(path)
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
    vocab_problems = security_vocabulary(emitted)
    gnmi_emitted, gnmi_problems = gnmi_canonical_lane(emitted)
    # The gNMI canonical lane is a producer too: a panel querying a gNMI-owned
    # family (e.g. device_mem_percent) is NOT an orphan.
    emitted = emitted | gnmi_emitted
    refs = referenced_metrics()
    missing = {m: files for m, files in sorted(refs.items())
               if m not in emitted and not waived(m)}
    tracked = {m: f for m, f in missing.items() if m in TRACKED_GAPS}
    untracked = {m: f for m, f in missing.items() if m not in TRACKED_GAPS}

    print("panel↔metric contract audit")
    print(f"  metrics emitted by collectors : {len(emitted)}")
    print(f"  gNMI canonical-lane emits     : {len(gnmi_emitted)} ({', '.join(sorted(gnmi_emitted)) or 'none'})")
    print(f"  metrics referenced by panels  : {len(refs)}")
    print(f"  tracked gaps (known, on the board): {len(tracked)}")
    print(f"  gNMI-lane contract problems       : {len(gnmi_problems)}")
    print(f"  security-vocabulary problems      : {len(vocab_problems)}")
    print(f"  UNTRACKED orphans (regressions)   : {len(untracked)}")

    if vocab_problems:
        print("\n✗ SECURITY VOCABULARY PROBLEMS (SEC-020.1 single-vocabulary guard):")
        for p in vocab_problems:
            print(f"  ✗ {p}")

    if gnmi_problems:
        print("\n✗ gNMI CANONICAL-LANE CONTRACT PROBLEMS (single-contract guard):")
        for p in gnmi_problems:
            print(f"  ✗ {p}")

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
    if gnmi_problems:
        print("\nFix the gNMI canonical-lane contract problems above "
              "(deployment/docker/gnmic/gnmic.yaml).")
        return 1
    if vocab_problems:
        print("\nFix the security-vocabulary problems above "
              "(src/backend/internal/secobs/vocab.go).")
        return 1
    print("\n  ✓ contract clean — no untracked orphans, gNMI lane consistent, "
          "security vocabulary truthful")
    return 0


if __name__ == "__main__":
    sys.exit(main())
