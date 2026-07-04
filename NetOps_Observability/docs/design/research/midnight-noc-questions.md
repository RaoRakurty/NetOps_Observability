# Midnight NOC Questions — the operator bar for Iris AI

> **Provenance:** written by the product owner (2026-07-02) as the canonical set of
> questions a NOC engineer actually asks during a midnight outage, with intent,
> data sources, evidence thresholds and pitfalls — grounded in Google SRE
> incident guidance and AWS/Azure/GCP/Cisco troubleshooting runbooks. This is
> the **requirements bar** for Iris AI answers and for the platform's
> capability roadmap: §2 maps each question to what Correlix can answer TODAY
> and what is missing. The golden eval set carries fixtures for the answerable
> ones (`docs/ai/golden-examples/golden-qa.json`, `agent-midnight-*`).

**Design principle (owner, standing):** the AI never re-derives what the
correlation engine already concluded — the engine reasons, the AI narrates the
engine's verdicts with citations. Midnight answers are **evidence-backed
narrowing**, not verbose RCA essays: blast radius, what changed, fault-domain
evidence, safe next action.

## 1. The ten questions (priority order)

The realistic midnight flow is progressive elimination, not RCA-first:
**detection → real impact? → blast radius → what changed → transport →
routing/control-plane → policy → front door → brownout vs hard-down →
ours vs provider → safest mitigation.** Each question closes on an explicit
evidence threshold; the operator moves on when it closes.

| # | Question | Intent | Evidence threshold to close |
|---|----------|--------|------------------------------|
| 1 | Real customer-impacting outage or alert noise? | Enter incident mode or keep observing | ≥2 independent symptom signals agree, or 1 strong user-facing symptom + verified impact (symptom-based, never internal-cause-based) |
| 2 | What is the blast radius right now? | Isolate locally vs escalate broadly | Affected users/sites/regions/tenants enumerable in operational terms ("two branch sites", "all tenants behind one VIP") |
| 3 | What changed in the last few minutes? | Change-induced? (the most common trigger) | A time-aligned change identified AND rollback/suppression arrests it, or no relevant change + evidence points elsewhere |
| 4 | Did a link/tunnel/uplink/interconnect actually go down? | Transport break vs higher-layer | Interface/tunnel/interconnect state + path tests converge on the failed segment, or transport clearly healthy |
| 5 | Routing/control-plane healthy, right routes present? | Black-hole / withdrawal / misroute | Session state + route presence + prefix counts all align with expected forwarding, or the mismatch identified ("session up" ≠ "forwarding good") |
| 6 | Firewall/ACL/SG/NSG/route-policy blocking? | Policy denial vs failure | A specific blocking rule/route identified for the failed path, or policy + flow evidence rule it out |
| 7 | DNS, VIPs, LBs, backend health checks normal? | Front-door failure mimicking "network down" | DNS resolves to intended endpoint + backends healthy, or a specific DNS/probe/backend failure proven |
| 8 | Brownout (latency/loss/congestion) vs hard-down? | Path/capacity action vs reachability loss | SUSTAINED loss/latency correlates across multiple measurements on the affected path (isolated spikes are normal) |
| 9 | Ours, or upstream cloud/ISP/provider? | Keep debugging vs fail over vs provider case | Provider/account-scoped health events line up with the incident, or provider clean + local evidence points inward |
| 10 | Safest immediate mitigation right now? | Convert diagnosis to lowest-risk action | One mitigation with materially stronger evidence, known blast radius, explicit worked/failed/revert criteria; rollback is NORMAL when a fresh change is suspected |

Recurring pitfalls the owner flags (encode in wording + evals): a single internal
metric is not an outage; a clean public status page is not proof of health
(account-scoped views matter, dashboards lag); temporal proximity of a change is
not proof but dismissing a fresh high-blast-radius change is worse; "control-plane
up" does not mean "data plane forwarding"; correct DNS does not imply healthy
backends nor probe reachability; one probe's view is not a carrier issue; act on
the strongest evidence, not the loudest alarm.

## 2. Capability map — what Correlix answers today vs what is missing (2026-07-02)

| # | Today | Gap |
|---|-------|-----|
| 1 | **Strong.** Corr verdict/confidence + the ≥2-independent-streams confirm rule IS this threshold; STAMP probes = user-path symptom; ticket linkage exists. | SLO/error-rate + helpdesk-inflow signals not ingested as corroborating streams. |
| 2 | **Partial.** Corr object carries affected entities; topology graph + seam model exist. | No `get_blast_radius` tool exposed to the loop (registry names it, unimplemented); no tenant/service→entity rollup in the answer. |
| 3 | **WEAKEST — build first.** Nothing ingests config/deploy/change history; no change timeline exists anywhere in the platform. | Change/config-drift as `corr_signals` (logged as roadmap since the Cisco study; this doc makes it the top capability gap — the owner's #1 trigger class). NetBox/SoT + device-config diffs + maintenance windows → a queryable "what changed in window W" tool. |
| 4 | **Strong.** Interface oper-down in device health; link/tunnel fault signatures (C5); tunnels table; STAMP path state. | `get_interface_health` (planned, unimplemented) for fresh-counter detail. |
| 5 | **Partial.** BGP peer state (IPv4), OSPF/IS-IS/BFD-adjacent signatures, traps in control_plane lane. | BGP all-AFI (#73 build order ①), prefix counts, "session up but forwarding broken" probes; cloud effective-routes out of scope until cloud ingest. |
| 6 | **Partial.** FortiGate policy/drop logs ingested (`fgt.*`); firewall-drop signature deferred in C5. | No policy-path analysis; cloud reachability tools (AWS/Azure/GCP) not integrated. |
| 7 | **Missing.** No DNS/VIP/LB/health-probe telemetry — the front-door domain is absent. | New ingestion domain (DNS logs, LB target health); design needed before tooling. |
| 8 | **Strong.** STAMP rtt/jitter/loss + Path Behavior Health with sustained-vs-spike logic; brownout vs hard-down is exactly what PBH encodes. | Expose `get_probe_health` / path-health to the agent loop (planned, unimplemented). |
| 9 | **Strong — the differentiator.** Seam model + `dia-egress-corroborated` signature (control-plane fault corroborated by customer-path probe) answers "ours vs provider" with evidence. | Cloud provider health APIs (AWS/Azure/GCP account-scoped) not ingested; ISP notice feeds absent. |
| 10 | **Partial.** Recommended-action + runbook KB + wording library exist in the grounded brain. | Evidence-ranked mitigation requires #3 (change history) for "rollback the 22:40 policy push" answers; failover-state awareness thin. |

**Build order from this map** (value × feasibility): ① change-timeline ingestion +
`get_recent_changes` tool (closes Q3, unlocks Q10) → ② expose existing strengths
to the loop: `get_blast_radius`, `get_probe_health`, `get_interface_health`
(Q2/Q8/Q4 — data already exists, tools don't) → ③ BGP all-AFI + prefix counters
(Q5) → ④ provider-health ingestion (Q9 polish) → ⑤ front-door domain (Q7 — needs
its own design pass).

## 3. Model wording rules (owner input #7 — the voice contract)

**Golden rule:** *say what is broken, who is affected, what the current best
fault-domain hypothesis is, why you think that, what you still do not know, and
what happens next.*

| Do | Don't |
|----|-------|
| Lead with impact and scope ("Users in three branches see intermittent internet access") | Lead with a deep mechanism ("MED changed on one peer") |
| Separate symptom from hypothesis | Collapse them into one sentence unless proven |
| State confidence with a lexical label (suspected / likely / confirmed) | Show a bare percentage without context |
| Quote time-bounded evidence | Timeless claims ("the network is unstable") |
| Name contradictions and gaps explicitly | Hide uncertainty by omission |
| Operators: include the next diagnostic/mitigation step | Stop at description |
| Managers: translate jargon into service impact | Say "DIA egress"/"AFI/SAFI mismatch" unexplained |
| Blameless ("a route policy change coincided with incident start") | Name/shame a person or team |
| Reserve "confirmed root cause" for strong corroboration | "Confirmed RCA" in the first minutes |
| State when the next update comes | Leave stakeholders guessing |

**Approved live-incident verbs:** investigating, identified, likely, suspected,
monitoring, mitigated, resolved, confirmed upstream event, unknown fault domain.
**Forbidden as live defaults:** certainly, definitely, root cause found, proven,
fixed forever.

### Confidence taxonomy (owner-approved)

| Label | Meaning | Safe usage rule |
|-------|---------|-----------------|
| **Confirmed** | Multiple independent evidence classes agree, no material contradiction remains | Use sparingly during a live incident |
| **Likely** | Strong directional evidence from a primary source + support from another, no major counterevidence | Good default when the operator can act |
| **Suspected** | Some evidence points one way but incomplete/circumstantial/contradicted by gaps | Pair with what would confirm or refute it |
| **Unknown** | Evidence missing or conflicting enough that a fault-domain claim would be speculative | State symptom + impact only; never imply RCA |

Never show a raw percentage alone — pair it with the label: *"Likely, 85% model
confidence."* A bare number reads as certainty.

### Sentence templates

- **Operator:** `[Confidence label] [fault domain] affecting [scope]. Evidence:
  [signal A], [signal B], [time window]. Next: [specific check or mitigation].`
  Example (engine says `suspected, 85%, DIA egress`): *"Suspected DIA egress
  degradation on Branch-17, likely via ISP-A. Model confidence: 85%. Evidence:
  probe RTT 18→220 ms + 14% loss since 00:14; flows toward the ISP path
  dropped; BGP session remains Established. Next: check secondary egress health
  before shifting traffic."* Rejected: *"ISP-A is the root cause."*
- **Manager:** `We are investigating / have identified / have mitigated [issue
  type] affecting [service or user scope]. Current impact: [plain English].
  Current understanding: [fault domain or unknown]. Next update: [time].`
  Rejected: any jargon-led sentence ("DIA egress is bad at 85%", "MED changed").
- **Unknown case (both voices):** state confirmed impact + the contradiction
  explicitly ("probes show loss but BGP and device health do not correlate");
  never "no issue found", never a guessed RCA.

**Decision flow before wording:** collect time-bounded evidence → do
independent signals agree? NO → symptom+impact only (unknown/suspected);
PARTIALLY → likely/suspected + name the gaps; YES strongly → likely/confirmed,
scope bounded → then branch on audience (operator = evidence lines + next
check; manager = impact + mitigation status + next update time).

**Operator vs manager voice:** an `audience` parameter on AI answers is
ROADMAP — today the default voice is the operator voice.

## 4. Where this lands in the product

- **Doctrine:** the narrowing order is encoded in the agent loop's system
  doctrine (`agentDoctrine`, copilot_agent.go) — the model triages in this
  sequence and answers with where the evidence points.
- **Evals:** `agent-midnight-*` fixtures in the golden set pin tool selection
  for the answerable questions; the "what changed" question rides as a
  `known_gap` fixture until ① ships (it must FLAG, not silently pass).
- **Wording:** answers must read like the owner's thresholds — "closed because
  two independent streams agree", "session up but forwarding unverified" — the
  RCA wording library is the style source.
