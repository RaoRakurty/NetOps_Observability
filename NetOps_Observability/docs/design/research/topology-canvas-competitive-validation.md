# Topology Canvas — Competitive Validation & Plan

**Date:** 2026-06-22
**Inputs:** (1) internal code audit of `src/features/topology/` + `src/backend/topology/`; (2) cited deep-research benchmark of ThousandEyes, Dynatrace, Datadog, NetBrain (2025–2026 capabilities).
**Question:** Are Explore / Investigate / Path Trace / Capacity at world-class standard — logic, visuals, flexibility — and where can we *lead*, not just match?

---

## 1. Verdict (one paragraph)

Our **architecture and logic are already at or near parity** with the field, and on one axis — **honest, evidence-backed RCA** — we are *ahead*. The renderer-agnostic `TopologyView` contract, the zero-trust evidence rule (no edge without evidence), per-source confidence scoring, deterministic Dijkstra, and the grounded "confirmed vs suspected vs missing-evidence" verdict layer are genuinely strong and, in the RCA case, more rigorous than the vendors' opaque AI. Where we **lag** is: (a) **visual density management** (semantic zoom is built but unwired), (b) **path-trace depth** (vendors expose per-hop loss/latency/jitter and BGP AS-path; we resolve a path but don't yet richly instrument each hop), (c) **dependency mapping** (ours is mock-only), and (d) **capacity** — which is *white-space across all four vendors* but is currently **broken in our stack** (utilization doesn't bind to edges). The strategic opportunity is to **make RCA the hero**, **finish capacity into a lead**, and **adopt two specific vendor differentiators** (tag-dimension regrouping; executable remediation).

---

## 2. Per-mode scorecard (us vs the field)

Legend: ● lead · ◑ parity · ○ lag

### EXPLORE — browse the live map
| | Logic / coding | Visual / flexibility |
|---|---|---|
| **Us** | ◑ Evidence-first graph from LLDP+CDP+BGP-LS, deduped, confidence-scored, tenant-scoped, pure projection (`topology/project.go`). Calm-by-default emphasis, hover≠click spotlight. | ○ Floating edges, role icons, health rings, confidence chips — clean. BUT density control is a near-noop (`semanticZoom.ts` unwired), Sigma WebGL overview not mounted, search is O(n·m). |
| **NetBrain** | ● Digital-twin "dynamic maps" auto-discovered from CLI/SNMP/API; the benchmark leader for explore+map. | ◑ Interactive diagrams; less "premium" visually than APM vendors. |
| **Dynatrace** | ● Smartscape: auto-built full-stack graph, *no manual tagging or upkeep*, auto-updates. | ◑ Multi-layer maps; bounded to OneAgent coverage. |
| **Datadog** | ◑ eBPF L4 tag-defined topology. | ● **Regroup by any tag dimension** (not a fixed device hierarchy) — a differentiator we lack. |

### INVESTIGATE — incident / RCA on the graph  ← **our strongest lane**
| | Logic / coding | Visual / flexibility |
|---|---|---|
| **Us** | ● **Evidence-backed, anti-black-box RCA**: grounded verdicts, independent-witness + fate-independence + cross-modality confirmation, "missing evidence" honesty, per-object "why". Auto-pins the most-actionable incident. The probe-corroboration work (2026-06-22) is exactly this. | ◑ RCA overlay (observed/degraded/suspected/confirmed/missing), verdict banner with recommended action. Room to surface blast-radius + the *why* more vividly on-canvas. |
| **Dynatrace (Davis)** | ● Dependency-traversing causal inference. | ◑ Strong, but **agent-coverage-bounded**. |
| **Datadog (Watchdog)** | ◑ Auto-correlation. | — Independent commentary: **"correlation dressed as causation"** — opaque. |
| **NetBrain** | ● Agentic-AI RCA that runs live diagnostics inside the diagram. | ● Executable runbook *in* the map. |

**Read:** Davis/Watchdog are powerful but opaque; NetBrain is actionable but enterprise-CLI-centric. **Our honesty (confirmed-only-with-independent-evidence, shown not asserted) is a defensible moat** the others structurally can't match without re-architecting around evidence.

### PATH TRACE — hop-by-hop  ← **biggest depth gap**
| | Logic / coding | Visual / flexibility |
|---|---|---|
| **Us** | ◑ Real A→B over discovered LLDP/IGP via deterministic Dijkstra (or measured trace); honest "no path found". STAMP/traceroute collectors exist. | ○ Path highlight only; no per-hop loss/latency/jitter bands, no ECMP fan, no golden-path delta yet. |
| **ThousandEyes** | ● TTL traceroute, **unique random source-port per trace + 3 traces/round** to uncover ECMP; **BGP Route Visualization** (AS-path graph, edge thickness = route count). | ● Per-hop green→red bands, complexity slider, round-by-round timeline replay. |
| **Datadog Network Path** | ● NPM hop-by-hop. | ◑ Solid. |

### CAPACITY — utilization / headroom  ← **white-space, but ours is broken**
| | Logic / coding | Visual / flexibility |
|---|---|---|
| **Us** | ◑ Real analytics exist (`topologyCapacity.ts`: hot-link ranking, ECMP imbalance, honest "unmeasured"). **BUT** utilization never binds to edges live — backend queries `by (device, interface)` while metrics are labeled `ifName` (see §4). So Capacity shows nothing on real data. | ○ Capacity panel + saturation spotlight — good design, no data. |
| **All four vendors** | ○ **No claim survived on hot-link / utilization / capacity-planning overlays** — weakest-evidenced workflow across the benchmark. | ○ |

**Read:** nobody owns capacity. Fix our binding, add forecasting/headroom/what-if, and this becomes a **lead**.

### DEPENDENCY — service map  ← **mock-only**
Currently reuses physical LLDP links relabeled (`DependencyWorkflow` → `cloudTopology` mock; not in `REAL_MODES`). Should be a flow-derived service/app graph (ClickHouse flows → who-talks-to-whom, upstream/downstream blast radius). This is the Tier-2 we deferred. Dynatrace/Datadog lead here on auto-built dependency graphs.

---

## 3. Where we can LEAD (exceed, not match)

1. **Evidence-backed RCA as the anti-black-box product.** Vendors' AI asserts; we *show the independent witnesses and refuse to overclaim*. Make this the headline of Investigate: render the confirming pair, the fate-independence, the missing evidence, and the verdict lineage on-canvas. This is our moat — lean in.
2. **Capacity that forecasts.** The field is empty here. Beyond hot-links: trend/headroom-to-saturation, ECMP rebalance suggestions, and "what-if I drain this link" — none of the four do this well.
3. **Time-travel / replay.** We already version `corr_objects` and carry `change_state` (added/removed/stale). Turn that into topology replay across a window (ThousandEyes only replays discrete path rounds; a full-graph evidence replay would exceed that).
4. **Executable remediation (borrow from NetBrain).** We have the `FEATURE_DEVICE_SSH` gateway + ITSM control plane. Guided/one-click runbooks launched from a confirmed verdict would match NetBrain's standout without its CLI-heaviness.
5. **Tag-dimension regrouping (borrow from Datadog).** Let operators regroup the canvas by site/role/tenant/owner/service — not just the device hierarchy.

---

## 4. Known correctness gaps to clear first (grounded in code)

- **Capacity util-binding (blocks the whole mode):** `gatherTopoMetrics` (`backend/topology_view.go`) groups interface metrics `by (device, interface)`, but collectors label them **`ifName`** (+`ifAlias`/`index`). Utilization collapses to empty → 0 edges carry it. Fix: group by `ifName` and reconcile LLDP port descriptions (e.g. `to-spine1`) against `ifName` via `canonIface`.
- **Density knobs are cosmetic:** Exec/Operator/Engineer/Incident only toggle labels; `utils/semanticZoom.ts` is built but never wired into the renderer. Either wire all four strata or collapse to a working Overview/Detail toggle.
- **Dependency is mock-only** (no backend projection).
- **Search is O(n·m)**, no index — won't scale past ~1k nodes.
- **Search-to-expand**: a hit inside a collapsed group doesn't reveal it.
- **No time-series replay** despite `change_state` being tracked.

---

## 5. Plan (phased)

**P0 — Hygiene (make what exists honest & working).** Capacity util-binding fix; decide density-knob fate (wire semantic zoom or cut to 2-state); search-to-expand. *Small, high-credibility.*

**P1 — Play to the moat (the two leads).**
- *Investigate = hero RCA*: render the independent-witness pair, blast radius, evidence lineage and "missing evidence" on-canvas; make the anti-black-box story visible. (Directly leverages the correlation engine + the probe-corroboration work.)
- *Path Trace depth*: per-hop loss/latency/jitter bands from STAMP/traceroute, ECMP fan, golden-path delta. Closes the ThousandEyes/Datadog gap with data we already collect.

**P2 — Close the functional gap.** Dependency mode for real: flow-derived service graph (ClickHouse flows → directional service edges, upstream/downstream). Short research/design pass first (per standing rule).

**P3 — The exceed bets.** Capacity forecasting/headroom/what-if; topology time-travel replay (from versioned `corr_objects` + `change_state`); executable remediation from a confirmed verdict (device-SSH + ITSM); tag-dimension regrouping.

**Cross-cutting:** scale (mount Sigma for >1k nodes), search index, and a visual-polish pass to reach the "trading-floor NOC" bar.

---

## 6. Bottom line

We are **not behind on engineering** — the contract, evidence model, and RCA rigor are strong, and RCA honesty is a real differentiator the incumbents can't easily copy. We are behind on **visual density management, path-trace instrumentation, dependency data, and a (broken) capacity mode**. The fastest path to "world-class and then some" is: clear the correctness gaps (P0), **make evidence-backed RCA the hero** and deepen path-trace with data we already have (P1), build the dependency graph (P2), and take the **capacity-forecasting / replay / remediation** bets where the whole field is weak (P3).
