# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Generate `docs/design/telemetry-coverage-matrix.md` — "what does Correlix
recognize?", per symptom, per source, per vendor, with its fidelity.

    python3 coverage_matrix.py            # regenerate
    python3 coverage_matrix.py --check    # CI drift guard: exits 1 if stale

THIS IS THE DESIGN-PARTNER ARTIFACT. A prospect's first question is not "how
does correlation work", it is "do you understand MY estate": does the product
see an OSPF adjacency loss on Juniper, and does it see it when the box speaks
SNMP instead of syslog? The honest answer is a matrix, and the only honest way
to build one is to DERIVE it from the executable rule table rather than write it
by hand — a hand-written coverage claim is a marketing document that rots the
first time a rule changes.

THE THREE SOURCES a symptom can arrive on:

  syslog          a `source: syslog` rule of events.yaml (the syslog + port lanes)
  trap            a `source: trap` rule of events.yaml
  metric episode  the CUSUM/episode detector, which turns a canonical metric
                  family into a `*_anomaly` kind. There is no rule row for it,
                  so the lane is reconstructed from the two places that define
                  it: the collector's RCA metric allowlist
                  (`src/backend/collectors/metric_events.go rcaMetricFamilies`,
                  metric family → signal_family bucket) and the engine's
                  `main.metric_identity` (bucket → episode kind). Both are
                  re-derived and pinned by `test_coverage_matrix.py`, so this
                  file cannot drift from either.

A symptom with TWO OR MORE sources is one the engine can corroborate across
observers; a symptom with one is a single point of blindness, and the summary
counts them because that is the number a design partner should be shown.

GENERIC ROWS ARE NOT COVERAGE. The severity-floor `device_alarm` nets catch
everything by construction, so counting them as a source would make every
symptom look covered. They are reported separately, as the safety net they are.
"""
from __future__ import annotations

import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = os.path.abspath(os.path.join(
    HERE, "..", "docs", "design", "telemetry-coverage-matrix.md"))
METRIC_EVENTS_GO = os.path.abspath(os.path.join(
    HERE, "..", "src", "backend", "collectors", "metric_events.go"))

from bake_rules import load

#: metric-family → signal_family bucket. MIRRORS `rcaMetricFamilies` in
#: `src/backend/collectors/metric_events.go` — the EXPLICIT allowlist of metric
#: names that reach the correlation bus at all. `test_coverage_matrix.py`
#: re-parses the Go map and fails if these two disagree, so the mirror cannot go
#: stale (the alternative, importing Go from Python, does not exist).
METRIC_BUCKET: dict[str, str] = {
    "device_if_oper_status": "interface",
    "device_if_admin_status": "interface",
    "device_if_in_octets": "interface",
    "device_if_out_octets": "interface",
    "device_if_in_errors": "interface",
    "device_if_out_errors": "interface",
    "device_if_in_discards": "interface",
    "device_if_out_discards": "interface",
    "device_if_fcs_errors": "interface",
    "device_if_speed": "interface",
    "device_bgp_peer_state": "bgp",
    "device_bgp_fsm_transitions": "bgp",
    "device_ospf_nbr_state": "igp",
    "device_isis_adj_state": "igp",
    "device_cpu_percent": "device_resource",
    "device_mem_percent": "device_resource",
    "device_temp_celsius": "device_resource",
}

#: signal_family bucket → the episode kind `main.metric_identity` resolves it to.
#: MIRRORS the branches of that function (read-only from here; it lives in the
#: engine). Also pinned by `test_coverage_matrix.py`.
EPISODE_KIND: dict[str, str] = {
    "interface": "if_metric_anomaly",
    "bgp": "bgp_state_anomaly",
    "igp": "igp_state_anomaly",
    "device_resource": "device_resource_anomaly",
    "cloud_resource": "cloud_resource_anomaly",
}

#: The A9 audit's verdicts on symptoms that were NOT promoted. Each is a symptom
#: a real trap exists for; the reason is why a trap rule for it would be worse
#: than the generic alarm it already becomes. Data, so the matrix states them
#: and the drift test keeps them in the artifact.
KEEP_AS_ALARM: tuple[tuple[str, str, str, str], ...] = (
    (
        "lldp_neighbor_change",
        "LLDP-MIB lldpRemTablesChange",
        "no",
        ("The trap carries only INSERT/DELETE/DROP **counters** for the remote "
         "table — no port and no neighbour — so it cannot produce the interface "
         "entity or the up/down state the syslog kind's vocabulary requires. "
         "(LLDP-MIB is also not in the vendored MIB index today, so the OID "
         "would not even resolve to a name.)"),
    ),
    (
        "mac_flap / evpn_mac_move",
        ("CISCO-MAC-NOTIFICATION-MIB cmnMacChangedNotification, "
         "ARISTA-BRIDGE-EXT-MIB aristaBridgeExtMacMove"),
        "no",
        ("The MAC and VLAN live in the FDB varbind's **OID index**, not its "
         "value, and the receiver renders a MAC as `AA:BB:…` while the syslog "
         "lane grounds on the Cisco dotted `aabb.ccdd.eeff`. A MAC is a GLOBAL "
         "grounding token (tracker 168), so emitting one in a second notation "
         "would split one moving MAC into two correlation objects — strictly "
         "worse than the generic alarm, which already carries the decoded "
         "vlan/mac in `fields` + `message_key`."),
    ),
    (
        "bgp_route_churn",
        "CISCO-BGP4-MIB cbgpPeer2PrefixThresholdExceeded",
        "no",
        ("CISCO-BGP4-MIB compiles no notifications into the vendored index, so "
         "there is no OID here that could be checked against a real definition, "
         "and per-prefix churn has no trap form at all (it is BMP/BGP-UPDATE "
         "data). The BGP `.event_type` twin already types any MIB-decoded "
         "vendor BGP transition."),
    ),
    (
        "vtep_state_change",
        "— none",
        "n/a",
        ("VXLAN/EVPN has no IETF notification MIB; NX-OS reports VTEP/NVE "
         "liveness on syslog only. Nothing to promote."),
    ),
    (
        "transceiver / DOM / FEC / PCS (12 port kinds)",
        ("ENTITY-SENSOR-MIB entSensorThresholdNotification, "
         "ARISTA-ENTITY-SENSOR-MIB aristaEntSensorAlarm"),
        "no",
        ("A sensor-threshold trap says *a sensor crossed a threshold*; it does "
         "not say pre-FEC BER, lane bias, deskew or LOS. Mapping one onto a "
         "specific optics kind would be a guess presented as evidence. They "
         "stay generic alarms and the DOM metric lane carries the real signal."),
    ),
    (
        "hardware / environment (fan, PSU, FRU, over-temperature)",
        ("CISCO-ENTITY-FRU-CONTROL-MIB cefc* · CISCO-ENVMON-MIB ciscoEnvMon* · "
         "ENTITY-STATE-MIB entStateOperDisabled · JUNIPER-MIB jnxFanFailure / "
         "jnxPowerSupplyFailure · TIMETRA-CHASSIS-MIB tmnxEq*"),
        "yes — index-verified",
        ("There is no syslog-typed kind for environmental health to pair with, "
         "so promoting these would mean inventing kinds. They belong as generic "
         "`device_alarm`s — and since **A9b they actually ARE ones**: every one "
         "of these notifications carried NO severity hint, defaulted to "
         "`notice` and therefore sat below `ALARM_SEVERITY_FLOOR`, so a failed "
         "power supply or an over-temperature chassis reached the engine as "
         "nothing at all. `gen_index.py SEVERITY_HINT` now seeds the FAULTS at "
         "`warning` and their recovery twins (`jnxFanOK`, `cefcFRUInserted`, "
         "`entStateOperEnabled`) at `info` — the same split `linkDown`/`linkUp` "
         "has always had. Typing them further would still be a guess: a sensor "
         "trap says a threshold moved, not which optic or which lane."),
    ),
    (
        "authenticationFailure",
        "SNMPv2-MIB authenticationFailure (1.3.6.1.6.3.1.1.5.5)",
        "yes — index-verified",
        ("A security-lane symptom with no network-fault counterpart; it is "
         "hinted `warning`, so it already becomes a `device_alarm` and is "
         "searchable. Routing it further is the security programme's call "
         "(network-first scope decision), not the parser's."),
    ),
)

#: A9 verdict that a LATER change overturned. Kept as data — deleting the row
#: would erase the audit's reasoning along with its mistake, and the reason a
#: deferral was wrong is worth more to the next audit than the deferral was.
REOPENED: tuple[tuple[str, str, str], ...] = (
    (
        "link_state_change · ifAdminStatus/ifOperStatus enrichment",
        ("A9 deferred it: reading `ifAdminStatus` would tell an "
         "administratively-shut port from a fault and `ifOperStatus` would "
         "distinguish `lowerLayerDown`, but doing so \"changes the ATTRS and "
         "the state of an already-shipping rule, which re-identifies every "
         "link trap already stored and breaks the frozen parity baseline\"."),
        ("SHIPPED at `parser_rev 2026-09-06-218` (tracker 218). The objection "
         "did not survive being checked against the code. A signal's identity "
         "is a uuid5 over `source`, `native_id` and the event millisecond, so "
         "attrs reach it only through `native_id` — which for this rule is the "
         "device, the literal `trap_link`, the interface, the state and the "
         "timestamp — and the enrichment never touches `state`, which is still "
         "decided by the trap OID alone. The parity objection held only for an "
         "UNCONDITIONAL attr: the two keys are declared `omit_empty`, so they "
         "exist only on the events that actually carry the varbind, and **no "
         "event in the 1,151-entry golden corpus carries either one** — every "
         "recorded output replays byte-for-byte and no baseline skip was "
         "added. `src/correlation/test_link_status_enrichment_218.py` proves "
         "the discrimination, the identical `signal_id` with and without the "
         "varbinds, the absent-vs-empty distinction, and both enum ladders "
         "against the vendored IF-MIB index in both directions."),
    ),
)

def _fmt(items) -> str:
    return ", ".join(f"`{x}`" for x in items) if items else "—"


def build(rows: list[dict], families: dict) -> dict:
    """symptom kind → {source: [rule rows]}, plus the episode lane."""
    by_kind: dict[str, dict[str, list[dict]]] = {}
    for row in rows:
        if row["lane"] == "catalog":
            continue                       # conformance-only, no correlation lane
        slot = by_kind.setdefault(row["kind"], {"syslog": [], "trap": []})
        slot[row["source"]].append(row)

    episode: dict[str, set[str]] = {}
    for row in rows:
        fam = families.get(row.get("family") or "", {})
        metric = fam.get("correlates_with")
        bucket = METRIC_BUCKET.get(str(metric or ""))
        if bucket and EPISODE_KIND.get(bucket):
            episode.setdefault(row["kind"], set()).add(EPISODE_KIND[bucket])
    return {"by_kind": by_kind, "episode": episode}


def _carries(row: dict) -> bool:
    """Does this row actually CARRY the symptom into correlation?

    A `generic` row is the severity-floor safety net, not coverage (§ the
    module docstring). A `shadow` row is evaluated and counted and emits
    NOTHING — advertising it as a source would promise a design partner
    evidence the engine does not produce."""
    return not row.get("generic") and not row.get("shadow")


def _sources(kind: str, slot: dict, episode: dict) -> int:
    """How many INDEPENDENT sources carry this symptom (generic + shadow rows
    excluded — neither produces evidence)."""
    n = 0
    for src in ("syslog", "trap"):
        if any(_carries(r) for r in slot[src]):
            n += 1
    if episode.get(kind):
        n += 1
    return n


def _fidelity(row: dict, families: dict) -> str:
    if row.get("fidelity_status"):
        return row["fidelity_status"]
    fam = families.get(row.get("family") or "", {})
    return str(fam.get("fidelity_status") or "code")


def render(data: dict, rows: list[dict], families: dict, parser_rev: str) -> str:
    by_kind, episode = data["by_kind"], data["episode"]
    typed = {k: v for k, v in by_kind.items()
             if any(_carries(r) for lst in v.values() for r in lst)}
    multi = [k for k, v in typed.items() if _sources(k, v, episode) >= 2]
    trap_typed = [k for k, v in typed.items()
                  if any(_carries(r) for r in v["trap"])]

    out: list[str] = []
    w = out.append
    w("<!-- GENERATED by telemetry-catalog/coverage_matrix.py — DO NOT EDIT. -->")
    w("<!-- Regenerate:  cd telemetry-catalog && python3 coverage_matrix.py   -->")
    w("")
    w("# Telemetry Coverage Matrix — what Correlix recognizes")
    w("")
    w(f"Derived from `telemetry-catalog/events.yaml` at **parser_rev "
      f"`{parser_rev}`**, plus the metric-episode lane reconstructed from")
    w("`src/backend/collectors/metric_events.go` (`rcaMetricFamilies`) and")
    w("`src/correlation/main.py` (`metric_identity`). Nothing here is written by")
    w("hand: `coverage_matrix.py --check` fails CI if this file and the catalog")
    w("disagree, so a coverage claim cannot outlive the rule behind it.")
    w("")
    w("**How to read a row.** The *symptom* is the canonical Signal `kind` — the")
    w("vocabulary the correlation signatures are written in. A trap and a syslog")
    w("line on one row are the SAME symptom seen by two observers, and the")
    w("engine treats them as such. Fidelity is the catalog's ladder")
    w("(`doc_claimed` → `lab_validated` → `live_validated`); **only")
    w("`lab_validated` / `live_validated` may be advertised as supported**, and")
    w("`code` means the grammar exists but the catalog vouches for nothing.")
    w("")
    w("## Summary")
    w("")
    w(f"- **{len(typed)}** typed symptoms (the two severity-floor `device_alarm`")
    w("  nets are the safety net, not coverage, and are excluded).")
    w(f"- **{len(multi)}** of them arrive on **two or more independent sources**")
    w("  and can therefore be corroborated across observers.")
    w(f"- **{len(trap_typed)}** are carried by a typed SNMP-trap rule "
      f"(3 before the A9 trap audit, 7 after it, {len(trap_typed)} since the "
      f"A9b config-change follow-up).")
    w(f"- **{len(typed) - len(multi)}** are single-source today — the list below")
    w("  says which, and the audit section says why.")
    w("")
    w("## Matrix")
    w("")
    w("| Symptom (Signal kind) | syslog | trap | metric episode | vendors | fidelity |")
    w("|---|---|---|---|---|---|")
    for kind in sorted(typed):
        slot = typed[kind]
        cells = {}
        vendors: set[str] = set()
        fids: list[str] = []
        for src in ("syslog", "trap"):
            live = [r for r in slot[src] if _carries(r)]
            cells[src] = _fmt(sorted(r["rule_id"] for r in live))
            for r in live:
                vendors |= set(r.get("vendors") or ())
            rungs = sorted({_fidelity(r, families) for r in live})
            if rungs:
                fids.append(f"{src}: " + "/".join(rungs))
        ep = _fmt(sorted(episode.get(kind, ())))
        n = _sources(kind, slot, episode)
        mark = "**" if n >= 2 else ""
        w(f"| {mark}`{kind}`{mark} | {cells['syslog']} | {cells['trap']} | {ep} "
          f"| {_fmt(sorted(vendors))} | {' · '.join(fids) or '—'} |")
    w("")
    w("Symptoms in **bold** have ≥ 2 independent sources.")
    w("")
    w("### Symptoms with ONLY a metric-episode lane")
    w("")
    w("No syslog line and no trap names these — the episode detector is their")
    w("only witness, so they are single-source by construction.")
    w("")
    w("| Symptom (Signal kind) | source |")
    w("|---|---|")
    paired_eps = {k for v in episode.values() for k in v}
    for ep_kind in sorted(set(EPISODE_KIND.values()) - paired_eps - set(typed)):
        w(f"| `{ep_kind}` | metric episode only |")
    w("")
    w("## Metric-episode lane (no rule row — reconstructed)")
    w("")
    w("| Canonical metric family | signal_family bucket | episode kind |")
    w("|---|---|---|")
    for metric in sorted(METRIC_BUCKET):
        bucket = METRIC_BUCKET[metric]
        w(f"| `{metric}` | `{bucket}` | `{EPISODE_KIND[bucket]}` |")
    w("")
    w("A metric family absent from this table never reaches the correlation bus")
    w("at all (the collector's RCA allowlist is the gate), so an event family")
    w("that `correlates_with` one of those — `device_bgp_pfx_in`, the four")
    w("IS-IS depth series — has **no metric-episode lane**, which is exactly")
    w("why its trap twin matters. The IGP adjacency pair")
    w("(`device_ospf_nbr_state`, `device_isis_adj_state`) was in that position")
    w("until tracker 222 admitted it as the `igp` family: the adjacency-change")
    w("SIGNAL and the polled series are now BOTH lanes for the same fault, and")
    w("the metric lane is the one that answers \"is it still bad?\" without")
    w("waiting for a recovery line.")
    w("")
    w("## The generic safety net (not coverage)")
    w("")
    w("| Rule | Lane | What it catches |")
    w("|---|---|---|")
    for row in rows:
        if not row.get("generic"):
            continue
        w(f"| `{row['rule_id']}` | {row['lane']} | Anything the typed rules "
          f"declined that the DEVICE itself flagged at warning or worse. Below "
          f"that floor it stays a searchable log and is never RCA evidence. |")
    w("")
    shadow_rows = [r for r in rows if r.get("shadow")]
    if shadow_rows:
        w("## Measured but not emitting (`shadow`)")
        w("")
        w("A shadow row is evaluated on real traffic and COUNTED "
          "(`corr_parser_shadow_hits_total{rule_id}`)")
        w("and emits nothing. It is NOT coverage and is excluded from every "
          "count above —")
        w("it is a finished grammar whose promotion is blocked on something "
          "other than itself.")
        w("")
        w("| Rule | Symptom it would emit | Vendors | Blocked on |")
        w("|---|---|---|---|")
        for row in shadow_rows:
            w(f"| `{row['rule_id']}` | `{row['kind']}` | "
              f"{_fmt(sorted(row.get('vendors') or ()))} | "
              "`%SYS-5-CONFIG_I` is 35 of the 100 noise slots of the ratified "
              "V1 workload profile (`scripts/scale-miniladder.py "
              "EVENT_MIX_NOISE`), declared there as a line that never "
              "classifies. Emitting would re-classify a third of the V1 "
              "background — a semantic change to the profile every "
              "CORRELIX_REFERENCE_CAPACITY_V1 number was measured on. "
              "Promotion is `shadow: false` once that profile is versioned. |")
        w("")
    w("## Audited and NOT promoted (A9)")
    w("")
    w("Every symptom below has a real trap. Each is left as a generic")
    w("`device_alarm` on purpose — the reason is the point of the audit.")
    w("")
    w("| Symptom | Trap(s) | MIB in the vendored index? | Why it stays an alarm |")
    w("|---|---|---|---|")
    for symptom, traps, indexed, why in KEEP_AS_ALARM:
        w(f"| {symptom} | {traps} | {indexed} | {why} |")
    w("")
    w("### …and one the audit got wrong")
    w("")
    w("A deferral is a claim about the code, and a claim can be checked. This "
      "one was,")
    w("and it did not hold.")
    w("")
    w("| Symptom | What A9 said | What happened |")
    w("|---|---|---|")
    for symptom, said, happened in REOPENED:
        w(f"| {symptom} | {said} | {happened} |")
    w("")
    w("## A9b — the finding A9 recorded, and closed")
    w("")
    w("A9 left one verdict deliberately open: a **config change** is the "
      "highest-yield")
    w("change-correlation input there is, all four of its OIDs resolve in the "
      "vendored")
    w("index, and it was nevertheless *invisible* — `ciscoConfigManEvent` and")
    w("`entConfigChange` were seeded `notice` in `gen_index.py SEVERITY_HINT`, "
      "BELOW")
    w("`ALARM_SEVERITY_FLOOR`, so they were not even generic `device_alarm`s; "
      "and the")
    w("syslog half (`%SYS-5-CONFIG_I`, severity notice) fell the same way. A9 "
      "would not")
    w("open it because typing a symptom needs a `kind`, and **a kind no "
      "signature")
    w("template names is inert evidence**.")
    w("")
    w("A9b closes it in the order the change had to happen:")
    w("")
    w("1. **The severity seed** — config-change AND hardware/environment "
      "notifications")
    w("   are seeded `warning` (their recovery twins `info`), so they clear the "
      "alarm")
    w("   floor at all. Pinned by `src/correlation/test_config_change_symptom.py` "
      "against")
    w("   the checked-in index *and* end to end through the trap producer.")
    w("2. **The kind** — `device_config_change` (entity `device`, state "
      "`changed`), on")
    w("   BOTH observers: `syslog.config.change` (IOS/NX-OS `CONFIG_I`, EOS "
      "ConfigAgent,")
    w("   Junos `UI_COMMIT`) and `trap.config.change`. The SYSLOG half ships")
    w("   `shadow: true` — counted, emitting nothing — because that line is a "
      "third of")
    w("   the ratified V1 workload profile's declared noise; see the shadow "
      "table")
    w("   above. The trap half emits: V1 injects syslog only, so it "
      "re-classifies")
    w("   nothing. `user` and `source` ride as")
    w("   attributes and NEVER as grounding tokens — a username is not an")
    w("   infrastructure identity, and tokening `admin` would weld every box "
      "that")
    w("   operator ever touched into one correlation object (tracker 168).")
    w("3. **The consumer** — five signature templates name it as an OPTIONAL "
      "clause")
    w("   (BGP / OSPF / IS-IS adjacency, the SD-WAN change-induced family, and "
      "the")
    w("   security hardening-drift story, where it is the only evidence that "
      "can DATE")
    w("   a standing posture failure). Optional and control-plane: it raises "
      "coverage,")
    w("   it can never supply the independent second plane a confirmation "
      "needs.")
    w("")
    w("It is emitted at `info`, below `EngineConfig.severity_open_floor`, so a "
      "fleet")
    w("reconfiguration cannot manufacture RCA objects — a change can only join "
      "an")
    w("object a real fault already opened.")
    w("")
    w("### The anti-fabrication rule this audit followed")
    w("")
    w("A trap rule may match on an **OID only when that OID resolves in the")
    w("vendored MIB index** (`src/backend/collectors/mibs/index/oididx.json`,")
    w("regenerated by `make mib-index` from real MIB sources). An OID recalled")
    w("from memory is an invented wire contract that fails silently on real")
    w("hardware. A symptom whose MIB is not vendored — HSRP and VRRP today — is")
    w("matched on the **MIB-decoded `event_type`** instead, so adding the module")
    w("to `gen_index.py`'s `DEFAULT_MIBS` and re-running `make mib-index` makes")
    w("it classify with no rule edit. `test_trap_rules_a9.py` enforces this.")
    w("")
    return "\n".join(out) + "\n"


def generate() -> str:
    data_yaml, rows = load()
    families = data_yaml.get("families") or {}
    return render(build(rows, families), rows, families,
                  str(data_yaml.get("parser_rev") or ""))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if the checked-in matrix is stale (CI guard)")
    ap.add_argument("--out", default=TARGET)
    args = ap.parse_args(argv)
    text = generate()
    if args.check:
        try:
            with open(args.out, encoding="utf-8") as fh:
                current = fh.read()
        except FileNotFoundError:
            print(f"{args.out} does not exist — run coverage_matrix.py",
                  file=sys.stderr)
            return 1
        if current != text:
            print(f"{args.out} is STALE vs the catalog — run "
                  "`python3 telemetry-catalog/coverage_matrix.py`", file=sys.stderr)
            return 1
        print(f"OK: {args.out} matches the catalog")
        return 0
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"wrote {args.out}")
    return 0


# ── the Go-side mirrors, re-derived (used by test_coverage_matrix.py) ─────────

_GO_MAP_RE = re.compile(
    r'^\s*"(?P<metric>device_[a-z_]+)":\s*\{"(?P<bucket>[a-z_]+)",', re.MULTILINE)


def go_metric_buckets(path: str = METRIC_EVENTS_GO) -> dict[str, str]:
    """Re-parse `rcaMetricFamilies` out of the collector. The mirror above must
    equal this, or the matrix advertises a metric lane the collector never
    forwards (or misses one it does)."""
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    start = src.index("var rcaMetricFamilies = map[string]metricMeta{")
    end = src.index("\n}", start)
    return {m.group("metric"): m.group("bucket")
            for m in _GO_MAP_RE.finditer(src[start:end])}


if __name__ == "__main__":       # pragma: no cover - CLI
    raise SystemExit(main())
