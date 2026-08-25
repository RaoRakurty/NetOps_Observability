# Rebuilding the Troubleshooting page — research + design (2026-08-25)

Commissioned by the owner (wave item 7). Researched against primary product
docs + SRE/Cisco methodology + a codebase inventory. This is the design
authority for the rebuild.

## Verdict on the current page

`src/frontend/src/pages/Troubleshooting.tsx` (123 lines) is not operator
troubleshooting — it is collection-pipeline self-health (collector
reachability, ingest counts). Useful, but it belongs on a Pipeline Health
surface; keep its "no data = collector vs device" insight as a step-zero
banner on the new page and reclaim the slot.

## Codebase assets already in place (this grounds v1)

Synthetics collector (ICMP/TCP/HTTP), traceroute collector (ICMP+TCP-SYN,
remote vantages), path graph + path health + baselines, **Active
Verification engine** (`internal/verify/` — CLOSED read-only vendor-keyed
SSH allowlist: `ssh_interfaces`, `ssh_iface_deep`, `ssh_bgp_edge`,
`ssh_config_change` for cisco/nxos/juniper/nokia, re-validated at exec;
today only correlation-triggered), device SSH gateway (ticketed, audited),
RCA objects + action items, incidents/events, topology path trace, IRIS
bounded read-only agent loop (~20 tools, policy-filtered, tenant-scoped,
citations + grounding verifier). **Correlix is already most of a
NetBrain-style guided-diagnosis engine; what's missing is the operator
surface and on-demand (vs correlation-triggered) invocation.**

## (a) Nine canonical NOC workflows (methodology: Google SRE bisection /
Cisco follow-the-path & spot-the-differences / product convergence)

1. "Site/user says X is slow" — entity resolution, uplink util+errors, path
   vs baseline, top talkers, recent changes, scope determination.
2. Device unreachable — ping/SNMP/SSH tri-check, upstream neighbor status
   (originating-vs-dependent), recent changes; check parent's interface.
3. BGP/adjacency down — session state + flaps, underlying interface, config
   change both ends (verify engine has exactly these checks).
4. Packet loss/latency on a path — hop-by-hop with per-hop history ("time
   machine"), per-hop counters on managed hops, re-run traceroute now.
5. Interface errors climbing — trend vs baseline, DDM light levels, LINK
   PARTNER's counters, speed/duplex, flap count.
6. "App team blames the network" — exonerate-or-own: synthetic + TCP-SYN
   traceroute on the app port, per-hop deltas, seam attribution, shareable
   evidence snapshot ("network clean" or "hop 4, our WAN edge, 3% loss").
7. DNS/DHCP/auth failure — the #1 ticket class at Catalyst/Mist; DNS probe
   is a small collector add.
8. Config change broke it — change timeline OVERLAID on symptom metric;
   config diff last-good vs current ("systems have inertia").
9. Congestion/top-talker hunt — interface util + flows scoped to interface
   and window, compare-vs-yesterday.

Cross-cutting: entity resolution, baseline comparison, change awareness,
scope determination, EVIDENCE CAPTURE, verify-after-fix.

## (b) Product affordances (condensed; full table in session transcript)

- SolarWinds: PerfStack shared-time-axis lanes (metrics+events+config
  changes); NetPath history. No guidance, no AI.
- LogicMonitor: originating-vs-dependent alert stamps; collector debug
  console; Edwin AI investigation cards.
- Auvik: in-browser terminal (audited), config diff, Northstar path view.
- Datadog: Device Health issue cards + config-changes-on-metrics; Bits AI
  hypothesis-driven investigations w/ validated/invalidated verdicts; Ask-
  mode remediation approvals (preview).
- Kentik: Data Explorer pivots, Cause Analysis (% contribution), AI Advisor
  agentic investigations with visible reasoning.
- ThousandEyes: **Instant Tests** (run-now, streaming results into the same
  views, shareable Snapshots), path viz with lossy nodes red-circled.
- NetBrain: THE reference — Executable Runbooks (chained action nodes,
  timestamped multi-run results, ad-hoc actions auto-recorded, runbook IS
  the evidence bundle), Network Intents (commands+parsers+if/else anchored
  to config lines), PDAS ticket-triggered automation.
- Cisco Catalyst Center: Issues + Suggested Actions **with a Run button**
  executing CLI from the issue pane (verified in 2.2.2 UG); Machine
  Reasoning Engine stepwise visualization; path trace w/ ACL verdicts.
- Juniper Mist/Marvis: SLE classifiers → per-classifier RCA; dynamic pcap
  AT failure time; **Marvis Actions approve-then-verify loop ("AI
  Validated")** — the industry's most mature; bounce port from dashboard.

Key findings: flow/synthetic vendors ship ZERO device-CLI affordances;
device vendors all put run-command one click from evidence. **Correlix
uniquely has both planes.** Auto-collected evidence at failure time is rare
and differentiating — our verify engine already does it per-correlation.
Shipping-vs-vapor line: hypothesis-driven auto-investigation with tri-state
verdicts, named parallel checks, propose-then-approve actions = GA
somewhere; one-click infra remediation by AI = preview everywhere.

## (c) Information architecture (the rebuild)

Positioning: RCA = what Correlix concluded; **Troubleshooting = where the
operator drives, with the platform doing the legwork.**

Three entry points:
1. **Active-problem rail** (Catalyst Issues / Marvis Actions pattern) —
   open incidents, hot correlations, failing synthetics/paths; one-click
   "Investigate" opens a pre-populated session.
2. **Entity search** → Diagnostic Workbench scoped to device/interface/
   site/path/IP (backed by existing unified search).
3. **Symptom picker** — tiles for the §(a) workflows; each launches a
   curated guided playbook (no runbook editor in v1).

**The core structural decision — the Diagnostic Session workbench:**
- LEFT: **evidence timeline** — every action (probe, show-command, metric
  snapshot, IRIS finding) appends an immutable timestamped card; session is
  persistable, linkable to incident/RCA, shareable by URL. This is what
  turns "a page with buttons" into a product (and what NetBrain charges
  for).
- CENTER: context panels — health strip, metric charts with baseline bands,
  recent-changes lane (config-change verdicts + maintenance windows + alert
  onsets on ONE time axis), path graph when path-scoped, related RCA.
- RIGHT: action palette + docked IRIS.

v1 actions (all reuse existing engines; need HTTP surface + UI):
ping/TCP/HTTP probe now (streaming results, TE-style, Run-again);
traceroute now (both methods, rendered in the existing path graph,
compare-to-baseline); **run device checks** — the verify battery as
operator buttons, per-check verdict + exact command + truncated raw output;
open SSH console (existing gateway, session noted in evidence); pin
anything to the session.

v2: DNS probe, MTU sweep; config snapshot store + side-by-side diff (IRIS
change summary); route-table lookup (new allowlisted commands); operator-
authored playbooks; **gated remediation** (bounce port, rollback) with
explicit approval + post-fix re-verification; Verify-resolution button
(re-runs every red check).

## (d) Guided playbook engine

scope → parallel evidence checks (typed, verdict-bearing — verify-engine +
Grafana-Sift model) → rule-ranked hypotheses with tri-state verdicts
(validated/invalidated/inconclusive) + supporting/refuting cards → suggested
next actions (human-clicked) → verify → persist.

v1 curated set: BGP neighbor down · app-team exoneration · interface errors
· device unreachable · path loss. (Worked end-to-end examples for the first
three are in the session transcript — auto-collected checks ①–⑦, ranked
hypotheses, IRIS next steps, close-out with verify.)

## (e) IRIS tie-in

Three placements: docked session panel (sees entity, evidence, playbook
state); inline narration on evidence bundles (1-2 grounded sentences with
citations); free-form chat that PROPOSES playbooks with scope pre-filled
(chat initiates structured workflows, never replaces them).

New tools: read-only `get_path`, `get_synthetic_results`,
`get_config_change_status`, `get_topology_neighbors`, `get_session`; and
**propose-only action tools** — `propose_probe`, `propose_device_check`,
`propose_playbook` — each renders a card with a Run button; the OPERATOR
clicks; execution runs under the operator's principal; the result lands in
the evidence timeline where IRIS reads it. The model holds suggestion
authority, never execution authority (CLAUDE.md §15 / LLM08; Datadog
Ask-mode made structural).

Boundaries: reads autonomous within existing loop budgets; active probes
operator-clicked per run (v1); SSH checks always operator-approved and
re-validated by the verify engine regardless of who composed them;
state-changing actions (v2) named-approver + exact-command dialog +
post-action verification; every suggestion/action = a session-log entry
(the session doubles as the AI audit trail).

**The wedge no competitor has in one product: probes + closed-allowlist
device checks + seam-attributed RCA + a grounded citation-bearing
assistant** — making "prove it's not the network" a differentiated,
shippable deliverable.
