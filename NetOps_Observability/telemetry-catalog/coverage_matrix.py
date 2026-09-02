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
        "config change (a security-lane input)",
        ("CISCO-CONFIG-MAN-MIB ciscoConfigManEvent · ccmCLIRunningConfigChanged "
         "· JUNIPER-CFGMGMT-MIB jnxCmCfgChange · ENTITY-MIB entConfigChange"),
        "yes — index-verified",
        ("**The one gap worth opening.** All four OIDs resolve in the vendored "
         "index, and a config change is the highest-yield change-correlation "
         "input there is. It is NOT promoted here because it needs a `kind` no "
         "signature template names, and a kind nothing consumes is inert "
         "evidence. Worse, it is invisible today: `gen_index.py`'s severity "
         "seed gives `ciscoConfigManEvent` **notice**, which is BELOW "
         "`ALARM_SEVERITY_FLOOR` — so it does not even become a generic alarm. "
         "Two-step fix, in order: (1) seed these notifications at `warning` in "
         "`gen_index.py SEVERITY_HINT` so they surface as `device_alarm`; "
         "(2) add a `device_config_change` kind together with the catalog "
         "clause that consumes it. Neither is in this change's bounded "
         "context."),
    ),
    (
        "hardware / environment (fan, PSU, FRU, over-temperature)",
        ("CISCO-ENTITY-FRU-CONTROL-MIB cefc* · CISCO-ENVMON-MIB ciscoEnvMon* · "
         "ENTITY-STATE-MIB entStateOperDisabled · JUNIPER-MIB jnxFanFailure / "
         "jnxPowerSupplyFailure · TIMETRA-CHASSIS-MIB tmnxEq*"),
        "yes — index-verified",
        ("There is no syslog-typed kind for environmental health to pair with, "
         "so promoting these would mean inventing kinds. They belong as generic "
         "`device_alarm`s — but the same severity-seed gap applies: every one "
         "of these notifications carries NO severity hint and therefore "
         "defaults to `notice`, below the floor. Seeding them at "
         "`warning`/`err` in `gen_index.py` is a one-line, high-value change "
         "outside this scope."),
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
    (
        "link_state_change · ifAdminStatus/ifOperStatus enrichment",
        "IF-MIB linkDown/linkUp varbinds",
        "yes — already classified",
        ("AUDITED AND DEFERRED. Reading `ifAdminStatus` would let the engine "
         "tell an administratively-shut port from a fault, and `ifOperStatus` "
         "would distinguish `lowerLayerDown`. Both change the ATTRS and the "
         "state of an already-shipping rule, which re-identifies every link "
         "trap already stored and breaks the frozen parity baseline — the same "
         "class of change as the declared `bgp_adjacency_change` divergence. "
         "It needs its own corpus re-bake, not a side effect of this audit."),
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


def _sources(kind: str, slot: dict, episode: dict) -> int:
    """How many INDEPENDENT sources carry this symptom (generic nets excluded)."""
    n = 0
    for src in ("syslog", "trap"):
        if any(not r.get("generic") for r in slot[src]):
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
             if any(not r.get("generic") for lst in v.values() for r in lst)}
    multi = [k for k, v in typed.items() if _sources(k, v, episode) >= 2]
    trap_typed = [k for k, v in typed.items()
                  if any(not r.get("generic") for r in v["trap"])]

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
      f"(3 before the A9 audit, {len(trap_typed)} after).")
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
            live = [r for r in slot[src] if not r.get("generic")]
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
    w("that `correlates_with` one of those — `device_ospf_nbr_state`,")
    w("`device_isis_adj_state`, `device_bgp_pfx_in` — has **no metric-episode")
    w("lane**, which is exactly why its trap twin matters.")
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
