# Correlix Enhancement — Before / After (program tracker)

**Started:** 2026-06-22. Order follows the convergence-first plan. Each row is updated
from **BEFORE** (honest baseline from the granular audit) to **AFTER** as increments land.
Status: ⬜ not started · 🟡 in progress · ✅ done (deployed + tested).

> North star: Correlix is a **NOC decision system** — what broke, why, who owns it,
> what's affected, what evidence confirms it, what's missing, what's safe next.
> The topology/path/capacity/dependency modes **serve the RCA verdict**.

---

## Increment 1 — RCA contract convergence  (the multiplier)

| Item | BEFORE | AFTER (target) | Status |
|---|---|---|---|
| Verdict tiers | 3: confirmed / suspected / undetermined | 5: + **contradicted** (evidence disagrees) + **recovered** (cleared) | 🟡 |
| Evidence model | grouped by **plane** (device/control/flow/probe); variants main/confirm/missing/conflict | grouped by **ROLE**: supporting / discriminating / contradicting / ignored / missing | 🟡 |
| "Why not confirmed" | shown in workspace impact lines + (new) topology banner | first-class, friendly, on **both** surfaces from one contract | 🟡 |
| Two RCA presentations | canonical `RcaWorkspace`(rcaCase) **+** a forked topology `RcaVerdictBanner` | both consume the **same** canonical evidence model — no divergence | 🟡 |

## Increment 2 — Command Center as primary workflow

| Item | BEFORE | AFTER | Status |
|---|---|---|---|
| Default landing | Dashboards/Home (`#/dashboards/home`) | **Command Center** (incident-first) | ⬜ |
| Filters | severity / state / tier only | + owner / evidence-quality / site / service / needs-action / missing-evidence-class | ⬜ |
| Row actions | "Assign owner"/"Create ticket" partly unwired | wired (owner assign, ticket draft from evidence bundle) | ⬜ |
| Decision line | per-incident next-action present | kept + explicit escalate-to-owner options | ⬜ |

## Increment 3 — Evidence ledger depth (role-grouped, itemized)

| Item | BEFORE | AFTER | Status |
|---|---|---|---|
| Evidence ledger | per-plane summary cards | role-grouped + **per-signal item rows** (class/title/entity/time/why-it-matters/independence) | ⬜ |
| Contradicting/ignored | not surfaced | shown as their own roles | ⬜ |

## Increment 4 — Demo scenarios (make the thesis demonstrable)

| Item | BEFORE | AFTER | Status |
|---|---|---|---|
| Demo data | thin live lab (bgp-flap, dia-latency) | 20 curated enterprise scenarios (ISP DIA, Direct Connect, ExpressRoute, SD-WAN brownout, DNS dep, SPOF, probe-only suspected, contradictory, undetermined, recovered, …) | ⬜ |

## Increment 5 — Topology depth (serve-the-verdict)

| Mode | BEFORE | AFTER | Status |
|---|---|---|---|
| Explore | browse map | + blast-radius/affected overlay, ownership-boundary zones, richer node/edge taxonomy (cloud/isp/service/db; dia/dx/vpn/overlay) | ⬜ |
| Investigate | forked banner | renders canonical evidence on the map (role-grouped, contradicted/recovered) | ⬜ |
| Path Trace | 🔸 proxy (device health + link util) | true per-hop loss/latency/jitter + ECMP + golden-path delta + **hop→evidence link** ("part of confirmed root cause") | ⬜ |
| Capacity | drain what-if + headroom + SPOF | + failure / site-isolation / traffic-growth sims, recommendations, evidence-bundle link | ⬜ |
| Dependency | 🔸 baseline (flow + port name) | service identity (SoT/DNS/SNI) + per-edge health | ⬜ |
| Replay | 🔸 change-diff slice | RCA event timeline (verdict transitions, evidence added, recovery) | ⬜ |

## Increment 6 — Safe remediation ladder

| Item | BEFORE | AFTER | Status |
|---|---|---|---|
| Remediation | read-only runbook + PDF evidence bundle + ticket-eligibility | maturity ladder: bundle → ticket draft → diagnostic preview → dry-run → approval-gated → audit trail | ⬜ |

## Already solid (no regression allowed)
- Evidence-first engine; ≥2 independent-stream confirm rule; STAMP probe corroboration (validated).
- Tenant isolation (opaque IDs, RLS, tenant-scoped queries, decision-#76 internal hiding).
- Friendly-language layer (`labels.ts`) + customer-language pass.
- PDF evidence bundle (`rcaExport.ts`).

## Testing
- Continuous: 144 correlation + Go + frontend unit/regression tests run each increment.
- Operator's own unit/regression cases: to be added to the repo; run + reported when each increment signals "ready".
