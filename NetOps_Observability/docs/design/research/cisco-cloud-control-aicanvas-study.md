# Cisco Cloud Control / AI Canvas — Competitive Study

Status: **RESEARCH (adversarially verified)** · Date: 2026-06-15 · Scope: informs
`correlation-engine.md` (#67), `front-page.md` (#69), `cloud-ingestion.md` (#68).

> Method note: PRIMARY sources (Cisco newsroom/blogs, ThousandEyes docs, Cisco
> security docs) preferred; trade press (Network World, WWT, Forrester) used as
> corroboration. Every load-bearing claim is tagged VERIFIED (with source) or
> UNVERIFIED, and **ANNOUNCED/marketing** is separated from **SHIPPING**. This
> space moves fast — note the dates: the core AI Canvas announcement is
> **Cisco Live 2025 (June 2025)**; by **June 2026** AI Canvas had moved to
> "Controlled Availability" (early commercial release), so status has shifted
> since first announcement and is tracked per-claim below.

---

## 1. Cisco Networking Cloud / Cisco Cloud Control

**What it is.** Cisco's cloud-native networking platform that unifies management
across previously-siloed domains under one pane: **Meraki Dashboard** (cloud),
**Catalyst Center** (on-prem campus), **ThousandEyes** (assurance/visibility),
and reaching into **Nexus Dashboard** (data center) and **ISE** (identity). It is
positioned as "powered by AgenticOps" — continuous, agent-assisted operations
across owned and unowned networks. (VERIFIED — Cisco product page + AgenticOps
blog.)

**Data/assurance model.** Cisco's pitch leans on scale: intelligence drawn from
"more than 32 million devices and over 1 billion clients" feeding the AI layer,
with **multilayered assurance** "from device to app, hop-by-hop, even across
unowned networks" (embedded ThousandEyes). This is fundamentally an
**ingest-broadly / cloud-aggregate** model: telemetry from the whole installed
base lands in Cisco's cloud and AI surfaces patterns. (VERIFIED — AgenticOps
"from-agenticops-to-assurance" blog.)

**Shipping reality (mid-2025 → 2026).** What actually shipped first is the
**unification plumbing**, not the AI brain:
- Meraki + Catalyst Center **global overview** (single dashboard, SSO, aggregated
  alerts) — SHIPPING.
- **Client360** (below) — SHIPPING in the Meraki dashboard.
- ThousandEyes **embedded** in Meraki dashboard — SHIPPING.
- Cloud management extensions for IOS-XE Catalyst switches (9200/9300/9500,
  new C9350/C9610), Wi-Fi 7 APs — SHIPPING with staggered 2025 dates.
- Cloud-Managed Fabric (L2/L3 campus unification), AI Canvas, deeper agentic
  workflows — ANNOUNCED, rolling out.

**Client360** is the most concrete correlation feature that actually ships: a
real-time + historical client-health view with **"AI-powered correlation across
Meraki, Catalyst, and ThousandEyes."** It surfaces **Onboarding & Correlated
Events** to "quickly surface root causes like DHCP or DNS failures," a
**Connectivity Timeline**, and a **Client Topology** path (extending into
ThousandEyes app monitoring when licensed). This is real, shipping, client-scoped
correlation — narrower than full incident RCA but concrete. (VERIFIED — Meraki
Client360 docs + community demo + AgenticOps blog.)

---

## 2. Cisco AI Canvas (the headline)

**What it actually is.** A **"Generative UI for cross-domain IT"** — a shared,
"multiplayer" workspace inside Cisco Cloud Control where an operator asks a
question in **natural language** and the system **runs a structured multi-agent
investigation**: it "reads the question, identifies the domains involved, builds a
plan, and dispatches specialized agents to gather evidence in parallel," then
**synthesizes findings into one sourced answer with the reasoning trail visible
so operators can defend the conclusion."** Output is rendered as
**"interactive generated widgets"** — topology maps, charts, summaries, reports —
generated on the fly from live data rather than pre-built dashboards. (VERIFIED —
Cisco AI Canvas "controlled availability" blog.)

**Two interaction modes** (VERIFIED — same blog):
- **Default mode** — quick answers, routine health checks, asset views.
- **Deep Reasoning mode** — multi-domain investigation where **the operator
  reviews / revises / approves the plan before any agent runs** (human-in-the-loop
  gate). Supports **multimodal context** (screenshots, dashboards, RF heatmaps,
  topology diagrams, error images) mixed with live telemetry.

**The engine behind it — Deep Network Model.** A purpose-trained networking LLM,
marketed as "the most advanced networking LLM on the market": trained on "40+
years of Cisco expertise," ~40M tokens, 3000+ expert-vetted reasoning traces,
CCIE-level problem solving, and continuously RL-tuned on live telemetry + Cisco
TAC/CX data. Claim: **"up to 20% more accurate reasoning"** for troubleshooting/
config/automation vs general-purpose LLMs. (VERIFIED as a *claim* — "Meet the
Deep Network Model" blog + Network World; the 20%/accuracy numbers are
**Cisco-self-reported, UNVERIFIED** independently.)

**AgenticOps** is the umbrella: Cisco's framing of a shift from AI-*assisted* to
AI-*driven* ops, where LLMs + agents proactively identify/diagnose/resolve. Three
pillars: (1) Deep Network Model, (2) AI Canvas, (3) unified telemetry across the
stack (Meraki, ThousandEyes, Splunk — Cisco stops short of calling it a "data
lake" but that is the architecture). (VERIFIED — AgenticOps blog + WWT.)

**Shipping vs announced.** This is the crux and where adversarial reading matters:
- **June 2025 (Cisco Live):** AI Canvas **ANNOUNCED**, demoed on stage (troubleshot
  a network issue "in seconds"); stated **Alpha**, design partners + ~4 customers
  in **Fall 2025**, possible **GA Q1 2026**. (VERIFIED — Network World CL2025.)
- **June 2026:** AI Canvas blog now reads **"Controlled Availability"** — moving
  from beta (it had been available inside Meraki + Splunk) into **early commercial
  release for U.S. commercial customers**, no full-GA date. (VERIFIED — AI Canvas
  CA blog, June 2026 dateline.)
- **Net read:** the *generative-UI + multi-agent investigation* product is real
  and now in limited customers' hands, but **broad GA and the full cross-domain
  vision remain in flight**; WWT/analyst framing is "most features in development,
  controlled release." Treat the polished keynote RCA demo as **aspirational**,
  the Client360/embedded-assurance pieces as **shipping**.

---

## 3. Cisco Security Cloud Control / CDO (Defense Orchestrator)

**What it is.** Formerly Cisco Defense Orchestrator (CDO), rebranded **Security
Cloud Control** — a cloud-delivered multi-device security manager that creates and
maintains **consistent policy** across firewalls (FTD, cloud-delivered + on-prem
FMC 7.2+) and other security devices. Marketed as **"AI-native … AI baked in from
the start, beyond AI assistants."** (VERIFIED — Cisco SCC series page + data
sheet.)

**Correlation + policy story (relevant to our security-plane RCA):**
- **Policy Analyzer and Optimizer** (SHIPPING) — analyzes security policy, detects
  **anomalies** (duplicate, redundant, shadowed, expired, overlapping, mergeable
  rules) and returns **curated remediation recommendations**; the **AI Assistant**
  collaborates to scrutinize and notify. This is **policy-hygiene correlation**
  (rule-set consistency), not live cross-signal incident RCA. (VERIFIED — Cisco
  Policy Analyzer & Optimizer docs.)
- **Correlation policies / correlation events** (legacy FMC capability surfaced in
  SCC) — rules that fire correlation events when the system generates discovery
  events or detects user activity. This is **rule-defined event correlation** (you
  author the rule), closer to a SIEM correlation rule than to grounded causal
  graph building. (VERIFIED — Cisco FMC/CDO discovery docs; trade-search
  corroborated.)

**Adversarial note:** SCC's "correlation" is two distinct things — *static policy
anomaly analysis* and *operator-authored event-correlation rules*. Neither is a
persistent causal-incident object; both are valuable comparators for **our
security-plane RCA** because they show the market expects (a) policy-drift /
config-hygiene findings and (b) rule-authored correlation — capabilities we can
frame our grounded-causal model as a superset of.

---

## 4. ThousandEyes — correlation + path visualization (Cisco's assurance crown jewel)

This is the closest competitor to our **seam / path / ownership-boundary** model,
so it gets the most adversarial attention.

**Measurement model (VERIFIED — ThousandEyes Path Visualization + Device Layer
docs).** Active **agents act as vantage points**; each test round collects
**path-trace data**, rendered hop-by-hop as **every node and link** between agent
and target. Crucially, this is an **active-probe vantage-point** model — the same
fundamental approach as our STAMP/ICMP/HTTP prober + cloud vantage agent.

**Where the fault is — responsibility assignment (their strongest, most
directly-comparable feature):**
- Distinguishes **Forwarding Loss** (dropped mid-path, in transit) from
  **Terminal Loss** (dropped at the destination). (VERIFIED.)
- **Red node rings** localize the problem: **mid-path red** = network
  responsibility (local net / **upstream ISP** / peering / transit);
  **destination red** = target responsibility (app / firewall / LB / host). Their
  docs call this **"the single most important call you make"** — *who owns the
  fix*. (VERIFIED — Path Visualization docs.)
- **This is exactly our seam `control_plane_owner` → verdict-owner mapping**, done
  visually on a hop graph rather than as a structured causal object. They get to
  "ISP vs you vs target"; we aim to get to "DX vs VPN vs DIA vs CLOUD_BACKBONE
  seam, owner = carrier/cloud/netops/app."

**Cross-layer correlation:** ThousandEyes correlates across **network / DNS /
service** layers; the **Device Layer** enriches path visualization by correlating
**device context** (the actual routing device) with the IP forwarding path,
routing, and app-layer metrics — closing the "app down → which device" gap.
(VERIFIED — TE platform + Device Layer blog; Device Layer page itself 403'd to the
fetcher but corroborated via TE search snippet and product platform description —
mark the Device-Layer *mechanism specifics* UNVERIFIED beyond the summary.)

**AI layer:** "Views Explanations" + AI Assistant — TE's dataset feeds the AI
Assistant's reasoning model to "analyze, correlate, and explain relationships
across tests, agents, network paths, and applications," and an **MCP server**
exposes TE assurance to AI agents. The AI is a **summarizer/explainer over
detected anomalies**, not a published deterministic causal-graph contract.
(VERIFIED as marketing description — TE blogs; the *internal correlation
algorithm* is opaque/UNVERIFIED.)

---

## 5. Shipping vs Announced — verification table

| # | Claim | Status | VERIFIED / UNVERIFIED | Source |
|---|---|---|---|---|
| 1 | Cisco Cloud Control unifies Meraki + Catalyst Center + ThousandEyes (+ Nexus, ISE) | SHIPPING (unification + global overview live) | VERIFIED | Cisco networking-cloud product page; "major-leap-forward" blog |
| 2 | Client360: AI-powered correlation across Meraki/Catalyst/ThousandEyes; surfaces DHCP/DNS root causes | SHIPPING (Meraki dashboard) | VERIFIED | Meraki Client360 docs; AgenticOps blog |
| 3 | "32M devices / 1B clients" feed the AI/assurance layer | SHIPPING (install base claim) | VERIFIED as Cisco claim; scale numbers UNVERIFIED independently | from-agenticops-to-assurance blog |
| 4 | MTTR reduction "over 90%" | ANNOUNCED / marketing | UNVERIFIED (appeared in a search summary; NOT found in fetched primary blog) | search summary only — treat as unsubstantiated |
| 5 | AI Canvas = generative UI, multi-agent NL investigation, sourced answer + visible reasoning trail | SHIPPING (Controlled Availability, US commercial, Jun 2026) | VERIFIED | AI Canvas CA blog (blogs.cisco.com/ai/ai-canvas-controlled-availability) |
| 6 | AI Canvas Deep Reasoning mode: operator approves the agent plan before it runs | SHIPPING (in CA) | VERIFIED | AI Canvas CA blog |
| 7 | AI Canvas first announced Cisco Live Jun 2025, Alpha → ~4 design-partner customers Fall 2025 → possible GA Q1 2026 | ANNOUNCED (historical) | VERIFIED | Network World CL2025 coverage |
| 8 | Deep Network Model = networking LLM, 40+ yrs expertise, ~40M tokens, 3000+ reasoning traces | SHIPPING (powers AI Assistant skills, controlled release) | VERIFIED as described; perf claims self-reported | "Meet the Deep Network Model" blog; Network World |
| 9 | Deep Network Model "20% more accurate reasoning" than general LLMs | ANNOUNCED / marketing | UNVERIFIED (Cisco self-reported, no independent benchmark) | Deep Network Model blog |
| 10 | ThousandEyes path viz: hop-by-hop, forwarding vs terminal loss, red-ring ISP-vs-target ownership call | SHIPPING (mature) | VERIFIED | TE Path Visualization docs |
| 11 | TE Device Layer correlates device ↔ forwarding path ↔ routing ↔ app metrics | SHIPPING | VERIFIED (summary); mechanism details UNVERIFIED (page 403) | TE Device Layer blog/snippet; TE platform page |
| 12 | TE AI Assistant + MCP server explain/correlate across tests/agents/paths/apps | SHIPPING | VERIFIED as feature; algorithm opaque | TE Views-Explanations + MCP blogs |
| 13 | Security Cloud Control = rebranded CDO, AI-native multi-device policy manager | SHIPPING | VERIFIED | Cisco SCC series page + data sheet |
| 14 | SCC Policy Analyzer & Optimizer: detects duplicate/shadowed/redundant/expired rules + remediation recs | SHIPPING | VERIFIED | Cisco Policy Analyzer & Optimizer docs |
| 15 | SCC correlation policies generate correlation events on discovery/user-activity (rule-authored) | SHIPPING (legacy FMC capability in SCC) | VERIFIED | Cisco FMC/CDO discovery docs |
| 16 | AgenticOps = AI agents proactively identify/diagnose/resolve before human intervention | ANNOUNCED (vision); partial shipping (AI Assistant skills) | VERIFIED as positioning; full autonomy UNVERIFIED/aspirational | AgenticOps blog; WWT takeaways |

---

## 6. Lessons for our correlation engine + front page

### 6.1 Where Cisco is strong (respect / learn from)

- **Ownership-boundary fault localization is a *proven, market-validated* framing.**
  ThousandEyes' "red ring = whose fault" (ISP vs transit vs target) is the single
  feature they elevate as "the most important call." This is **direct validation of
  our seam `control_plane_owner` → verdict-owner model** (#67 §4.2, #68 §4). We are
  on the right axis; their version is *visual + per-test*, ours is *structured +
  persistent*. Keep leaning in.
- **Generative UI / NL investigation is a real interaction shift.** AI Canvas'
  "ask in natural language → multi-agent plan → sourced answer with a visible
  reasoning trail" is a genuinely strong UX. The **"visible reasoning trail so the
  operator can defend the conclusion"** is *the same instinct as our evidence log*
  — they market it hard; we should too.
- **Human-in-the-loop plan approval (Deep Reasoning mode).** Operator approves the
  agent plan before it runs. Good trust pattern; aligns with our "no silent
  collapse / undetermined is first-class" honesty stance.
- **Scope discipline that ships.** What Cisco actually shipped first is *unification
  + client-scoped correlation (Client360)*, not the moonshot. Their incremental cut
  mirrors our P1 ("triage page on causal objects, zero services needed").

### 6.2 Where Cisco is weak (our differentiators — sharpen these)

- **Ingest-everything vs causal-relevance-first.** Their model is explicitly
  *aggregate the whole 32M-device install base in the cloud, then let AI find
  patterns*. That is exactly the **"ingest everything then make sense later"**
  posture our `cloud-ingestion.md §0` rejects. Our **causal-relevance-first / seam
  grounding gate** is the architectural opposite and the honest one — lead with it.
- **Opaque ML/LLM vs grounded deterministic edges.** Cisco's correlation/RCA runs
  through the **Deep Network Model LLM** + opaque per-product correlation. Outputs
  are an LLM "sourced answer." Ours are **grounded causal edges (no edge without a
  seam/topology grounding), versioned snapshots, bit-perfect replay, calibrated
  heuristic ranks (never probabilities)**. Their "20% more accurate" is
  self-reported and unverifiable; **our replayability + evidence coverage is
  *checkable*.** That is the trust wedge against an LLM black box.
- **No persistent, replayable causal object.** TE path viz is per-test;
  Client360 is per-client; SCC correlation is per-rule-fire. None is a
  **persistent, versioned, replayable incident object with competing hypotheses**.
  Our `corr_objects` lifecycle (open → version++ → merge → close, forever
  re-runnable) is genuinely differentiated.
- **LLM-as-engine risks (LLM03 overreliance).** Cisco bets RCA correctness on a
  proprietary LLM. Per our CLAUDE.md §15, model output is untrusted. Our design
  uses the LLM (Opsis) only to *summarize an already-grounded evidence log* — never
  as the causal engine. Keep that line bright; it is a defensible safety story.
- **Single-vendor / single-cloud (Cisco) gravity.** Their assurance is richest on
  Cisco gear + Cisco cloud. Our **self-hosted, multi-vendor, multi-tenant, cloud-
  seam-agnostic** posture is a different buyer (the operator who can't or won't send
  everything to Cisco's cloud).

### 6.3 Concrete, actionable UI/UX takeaways

1. **Make the "who owns the fix" verdict the hero of every incident** — copy
   ThousandEyes' instinct, not their visuals. Our Recommended Actions panel
   (front-page §6, panel 3) already renders `verdict.owner` (netops / carrier /
   cloud / app) + first steps. **Elevate the owner badge to the most prominent
   element** of the Top Active Issues row — it is the field operators triage on,
   and TE proves it is the highest-value call. (Cheap, high-impact, P1.)

2. **Brand the evidence log as the anti-black-box feature.** Cisco markets a
   "visible reasoning trail." We already store a human-readable `note` per edge and
   per hypothesis clause (#67 §2.3). **Surface it as "Why this verdict" inline on
   the incident, not buried in a Debug tab** — and explicitly contrast: *grounded,
   replayable, no probability theater* vs an LLM's after-the-fact rationalization.
   This is our LLM01/LLM02-safe differentiator made visible.

3. **Add a "responsibility split" path/seam visual to panel 7/9.** TE's
   forwarding-vs-terminal-loss + red-ring boundary call is the clearest UX in the
   space. For our **Hot paths / seams** + **Topology impact map**, render the seam
   crossing as the boundary node and **color the seam by `control_plane_owner`**,
   with `visibility` (full/partial/blind) shown honestly — turning our seam model
   into the same instant "which side" read, but with our ownership semantics.

4. **Adopt NL-question entry into the triage page — but route it to grounded
   objects, not free-form LLM generation.** AI Canvas' NL entry point is sticky.
   A constrained **"ask about this incident / scope"** box that the assistant
   answers *only from the rendered evidence log + correlation objects* (no new
   inference) gets the UX benefit without the black-box risk. Frame as "explains,
   never invents."

5. **Keep "undetermined + evidence_missing" as a marketed honesty feature.** Cisco
   demos always resolve "in seconds." Operators distrust a tool that is never
   unsure. Our **first-class `undetermined` with mechanically-derived
   `evidence_missing`** ("impact confirmed; cause not — missing: cloud-side probe,
   DX BGP state") is a *trust* differentiator. Show it proudly on the front page,
   don't hide it.

6. **Position policy/config-drift findings as part of RCA, not a separate tool.**
   SCC splits policy-anomaly analysis from event correlation. We already ingest
   `sot_drift` / config-change as first-class signals into the same `corr_signals`
   spine (#67 §2.1). **Show config/policy drift *inside* the causal object** ("BGP
   path change 09:41 ← config push 09:39") — a unification Cisco's own portfolio
   doesn't deliver because the security and network correlation live in different
   products.

---

## 7. Source list (primary first)

- Cisco — *Announcing Cisco AI Canvas: Revolutionizing IT with AgenticOps* (newsroom, Jun 10 2025): https://newsroom.cisco.com/c/r/newsroom/en/us/a/y2025/m06/announcing-cisco-ai-canvas-revolutionizing-it-with-agenticops.html
- Cisco Blogs — *AI Canvas is here: the workspace for agentic operations* (Controlled Availability, Jun 2 2026): https://blogs.cisco.com/ai/ai-canvas-controlled-availability
- Cisco Blogs — *From AgenticOps to Assurance: Redefining Network Operations*: https://blogs.cisco.com/networking/from-agenticops-to-assurance-redefining-network-operations
- Cisco Blogs — *A Major Leap Forward for AgenticOps and Operational Simplicity*: https://blogs.cisco.com/networking/a-major-leap-forward-for-agenticops-and-operational-simplicity
- Cisco Blogs — *AgenticOps: How Cisco is Rewiring Network Operations for the AI Age*: https://blogs.cisco.com/innovation/network-operations-for-the-ai-age
- Cisco Blogs — *Meet the Cisco Deep Network Model*: https://blogs.cisco.com/networking/meet-the-cisco-deep-network-model-trained-by-the-experts-purpose-built-for-the-network
- Cisco — Networking Cloud / Platform product page: https://www.cisco.com/site/us/en/products/networking/networking-cloud/index.html
- Meraki Documentation — Client360 (Cloud): https://documentation.meraki.com/Platform_Management/Dashboard_Administration/Operate_and_Maintain/Monitoring_and_Reporting/Client360_-_Cloud
- ThousandEyes Documentation — Path Visualization: https://docs.thousandeyes.com/product-documentation/internet-and-wan-monitoring/path-visualization
- ThousandEyes — Platform / Assurance: https://www.thousandeyes.com/product/platform
- ThousandEyes Blog — *Device Layer: Diagnose Root Cause from App to Network Device*: https://www.thousandeyes.com/blog/introducing-device-layer-network-device-monitoring
- Cisco — Security Cloud Control series / data sheet: https://www.cisco.com/c/en/us/support/security/security-cloud-control/series.html · https://www.cisco.com/c/en/us/products/collateral/security/security-cloud-control/datasheet-c78-736847.html
- Cisco — Policy Analyzer and Optimizer docs: https://docs.manage.security.cisco.com/c-about-policy-analyzer-and-optimizer.html
- Network World — *At Cisco Live, it's all about AI for networking and security*: https://www.networkworld.com/article/4005266/at-cisco-live-its-all-about-ai-for-networking-and-security.html
- Network World — *Cisco underscores AI commitment with networking LLM, agentic AI interface*: https://www.networkworld.com/article/4005519/
- WWT — *Cisco Live 2025: Observability & AIOps Takeaways*: https://www.wwt.com/blog/cisco-live-2025-observability-and-aiops-takeaways
- Forrester — *Key takeaways from Cisco Live 2025*: https://www.forrester.com/blogs/key-takeaways-from-cisco-live-2025-ciscos-big-bets-for-unified-security-and-ai

> Sources that 403'd the fetcher (claims drawn from search snippets / corroborating
> pages, flagged UNVERIFIED-beyond-summary above): ThousandEyes platform page,
> TE Device Layer blog, SCC "what's new 2025" Cisco doc, SCC community thread.
