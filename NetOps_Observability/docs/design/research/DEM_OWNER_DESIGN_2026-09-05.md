# Correlix Digital Experience Monitoring Dashboard: Market Research, Customer Requirements, Five-Year Product Design, and Claude Code Implementation Prompt

## Executive conclusion

The Digital Experience Monitoring market has moved well beyond “a dashboard of page-load times.” Gartner’s current definition of DEM centers on measuring application availability, performance, and experience from the user’s point of view—including employees, customers, partners, and even **digital agents connecting through APIs**—while also observing behavior and journeys. Gartner’s mandatory DEM features now explicitly require an end-to-end representation of a request or journey through system components, the ability to interrogate how system health affects experience or behavior, and outside-in measurement from a UI or API. citeturn11search0turn11search11

That is unusually favorable to **Correlix’s existing direction**. The connected Correlix fault-lab materials already describe a model much closer to “experience causality” than to traditional monitoring: **user → LAN → WAN/SD-WAN → cloud → application**, cloud topology learned from AWS/Azure route tables instead of guessed, correlation objects that combine configuration changes with symptoms, explicit blast radius, seams and ownership, independent vantage points, and a service-path contract built around `Endpoint`, `PathDefinition`, immutable `PathObservation`, ordered `PathHop`, provenance, observed-versus-inferred distinctions, and explicit edge types. fileciteturn6file0L2-L2 The fault campaign goes further by testing whether Correlix identifies the correct failure path, owner and seam across cloud, WAN/BGP/IPsec and LAN faults, and by refusing to call a result “confirmed” without sufficient independent evidence. fileciteturn8file0L2-L2

**My principal recommendation is therefore not to copy a Datadog, Dynatrace, New Relic, or ThousandEyes dashboard.** Correlix should build a **Digital Experience Causality Platform** whose dashboard happens to be the user interface.

The winning product promise should be:

> **“For every degraded digital experience, Correlix shows who is affected, what journey is failing, exactly where the path breaks, what changed, who owns the failing domain, how confident we are, what evidence supports the conclusion, what action is safe to take, and whether the action actually restored the experience.”**

That position is differentiated because the strongest current vendors tend to be deepest in one or two of five domains: real-user/session behavior, application observability, synthetics, Internet/network assurance, or employee/device experience. Gartner’s five 2025 DEM critical capabilities—RUM and Session Replay, Customer Journey Mapping, Synthetic Transaction and API Monitoring, Mobile App Monitoring, and Internet Performance Monitoring—make clear that the eventual winner has to connect all five. citeturn11search1

The market evidence also shows what **not** to build. Verified user reviews repeatedly complain about unintuitive navigation, difficult query languages, synthetic-test flakiness, alert noise, expensive or hard-to-scale customization, confusing experience scores, costly licensing, long implementation cycles, and platforms that identify interesting problems but still leave customers to build the operational workflow themselves. citeturn14search3turn14search0turn14search1turn19search5turn19search13

So the five-year design principle should be:

**Do not make customers navigate telemetry. Make Correlix navigate evidence on their behalf.**

The target architecture should have five major experience layers:

| Layer | Customer question Correlix must answer |
|---|---|
| Experience | **Are users actually succeeding?** |
| Journey | **Which interaction or business workflow is failing?** |
| Path | **Where between user/device and service is it degrading?** |
| Causality | **Why, what changed, what evidence proves it, and who owns it?** |
| Action | **What should we do, what is safe to automate, and did it work?** |

That design directly addresses what Gartner expects from DEM today while borrowing the most valuable emerging requirements from adjacent Digital Employee Experience tooling—organizational context, sentiment, remediation, workflow automation and ITSM integration—without confusing DEM and DEX as the same product category. Gartner’s June 2026 DEX definition and critical capabilities explicitly emphasize actionable insights, anomaly detection, self-healing, automation, employee feedback, organizational context, and ITSM integration. citeturn19search0turn19search3

The strongest long-term Correlix differentiation would therefore be:

**Outside-in experience + real-user behavior + deterministic path evidence + live topology + change causality + multi-source RCA + business impact + safe automation + evidence-grounded AI.**

That is a considerably stronger product thesis than another “single pane of glass.”

## Market state and what customers are actually buying

Gartner’s DEM market has become broader in a very revealing way. In its 2024 Critical Capabilities report, Gartner separately listed nine capabilities: Real User Monitoring, Session Replay, Customer Journey Mapping, Synthetic Transaction Monitoring, API Monitoring, Thick Client Synthetics, Mobile App Monitoring, Network Path Analysis and Internet Performance Monitoring. The October 2025 report groups the category into five major capabilities: RUM and Session Replay, Customer Journey Mapping, STM and API Monitoring, Mobile App Monitoring, and Internet Performance Monitoring. citeturn11search2turn11search1

I interpret that change not as the disappearance of features, but as **market convergence**: customers increasingly expect the formerly separate functions to operate as coherent workflows. “RUM” without replay is incomplete; synthetics without APIs are incomplete; user experience without Internet-path context is incomplete. Gartner’s mandatory requirements reinforce that interpretation because they ask the product to visually represent a journey intersecting system components, investigate the effect of system health on user behavior, and measure outside-in health from a front-end interface. citeturn11search0

The 2025 Gartner Magic Quadrant evaluated 14 suppliers—including Blue Triangle, Catchpoint, Checkly, Conviva, Datadog, Dynatrace, IBM, ip-label, ITRS, ManageEngine, New Relic, Riverbed, SolarWinds and Splunk—showing that DEM is simultaneously contested by observability platforms, Internet-performance specialists and experience-centric vendors. citeturn11search11

The **practical buying job** behind those analyst categories can be reduced to several questions:

| Buying need | What the buyer really wants |
|---|---|
| RUM | Tell me what actual users experienced, not what the server thinks happened. |
| Session replay | Let me reproduce the frustrating interaction without asking the customer to recreate it. |
| Journey analytics | Show whether users completed search, login, checkout, booking, claims, report generation, etc. |
| Synthetics | Tell me the journey is broken before enough real customers fail to create an obvious trend. |
| API monitoring | Validate machine-to-machine and increasingly AI-agent interactions. |
| Mobile | Capture the user perspective even when backend telemetry looks healthy. |
| Internet/path monitoring | Tell me whether Wi-Fi, LAN, VPN/SASE, ISP, DNS, CDN, BGP, cloud edge or application is responsible. |
| Full-stack correlation | Connect experience symptoms to application, dependency and infrastructure evidence. |
| Business context | Tell executives how many transactions, customers or dollars are at risk. |
| Remediation | Stop at “interesting chart” only when human judgment is genuinely required. |

The business case is measurable. T-Mobile reported that combining real-user Web Vitals with business analytics helped reveal the relationship between performance, bounce and conversion; its subsequent work produced a 42% reduction in LCP, 20% fewer website complaints and a 60% improvement in prospect visit-to-order conversion over the measured period. Importantly for dashboard design, T-Mobile also made the data broadly accessible through shared dashboards and tied monitoring to release-performance requirements rather than leaving performance information inside an SRE team. citeturn18search1

Nuvemshop reported in June 2026 that its LCP health rose from 57% to 96%, Core Web Vitals pass rate from 48% to 72%, and the comparable cohort saw an 8.9% increase in mobile organic-search conversion and 8.4% increase in cart engagement. citeturn18search2 Earlier, redBus used field RUM data to discover interaction problems that its expectations had missed; after optimizing INP, it reported a 72% INP improvement and a 7% overall increase in sales. citeturn18search0

Those examples explain one of the biggest reasons customers love good DEM dashboards: **they translate performance from an infrastructure argument into a customer and business argument**.

They also explain why averages should be demoted in the Correlix interface. A healthy average can conceal a severe problem affecting a particular browser, region, ISP, device type, version, customer tier or journey. The dashboard should make percentiles, affected-population ratios, failure cohorts and journey outcomes primary objects.

SRE practice reinforces the same direction. PayPal described converting end-to-end transaction-flow tests into recurring synthetic monitoring across availability zones, using them as a change-reliability mechanism and for proactive incident detection. citeturn15search2 Atlassian’s SREcon presentation provides the cautionary side: browser synthetics can give unusually intuitive human-like confidence when they work, but flaky, misconfigured or costly tests can destroy trust when poorly implemented. citeturn15search7 eBay has described moving away from absolute error counts and average latency toward SLO-oriented monitoring aimed at customer experience and actionable alerting. citeturn15search4

That suggests a crucial Correlix product decision:

**DEM health should be an SLO/outcome model, not a collection of red/green infrastructure widgets.**

For example, instead of:

> CPU 43% | RAM 61% | Tunnel Up | HTTP latency 1.2 s

Correlix should say:

> **Checkout Experience degraded — 18.4% of US-West mobile sessions affected**  
> Started 10:42:16  
> Purchase completion −11.8% versus baseline  
> Evidence points to ISP-A → AWS route degradation at hop 7  
> App/API health normal  
> Release 2026.09.05.3 not implicated  
> Confidence 94%  
> Network Operations owns the implicated seam  
> Last corroborated by RUM + synthetic probes + path observations 14 seconds ago

The second presentation is what customers are actually trying to obtain when they purchase DEM.

## Why customers love current dashboards, and what they still want fixed

The most useful source for the gap analysis is not vendor marketing but customer review material. Individual Gartner Peer Insights comments are anecdotal rather than statistically representative, but recurring patterns across vendors are highly useful product signals.

Datadog DEM reviewers praise easy visual browser-test recording, detailed metrics, broad integrations, shareable/custom dashboards, and the convenience of seeing infrastructure, logs and performance in one system. Yet reviewers also complain that it can be hard to find a specific trace, navigate to the right dashboard, filter a large number of variables, and manage large synthetic suites. One January 2026 reviewer described a synthetic suite with frequent flaky failures and a list-oriented model that became difficult to manage when journeys branched. citeturn14search3

Dynatrace customers similarly value broad context, cross-correlation through DQL, relatively quick initial RUM value and the ability to reveal problems with potential revenue impact. But reviews highlight sparse or difficult documentation, best-practice guidance gaps, DQL complexity, support escalation issues, difficult permission validation and integration edge cases. citeturn14search0

ThousandEyes customers praise end-to-end visibility, automated end-user testing and Cisco integration. The recurring complaints concern learning curve, advanced-feature training, customization, false alarms, licensing and the operational cost of some probe-based models. citeturn14search1turn14search5

Splunk’s DEM reviews praise query power and real-time monitoring while calling for easier search, particularly as data volume grows. citeturn14search7

The adjacent DEX category exposes another set of gaps that I believe will migrate into DEM purchasing requirements. Nexthink customers praise dashboards that provide an immediate global overview, a meaningful experience score, endpoint-level visibility and a shift from reactive troubleshooting toward proactive optimization. But reviewers also describe a steep learning curve, the need to create many custom use cases, difficulty demonstrating ROI natively, a gap between identifying an insight and operationalizing it at enterprise scale, additional licensing, and a desire for better offline behavior during connectivity outages. citeturn19search4turn19search5

Riverbed reviewers specifically ask for more application-issue information and more API integration into DevOps/codebase workflows, while some users find its experience score concept difficult to understand without training. citeturn19search13 A ServiceNow DEX reviewer noted that dashboard integration and tuning took more effort than expected. citeturn19search10

The combined research yields a very clear customer-needs hierarchy:

| What customers love | What customers increasingly want |
|---|---|
| A single operational view | A **single answer**, not merely a single screen |
| Real-user evidence | Business/journey impact attached to the evidence |
| Session replay | Automatically find the relevant replay segment |
| Synthetics | Self-maintaining tests derived from actual journeys |
| Topology maps | Time-aware, evidence-backed topology and path history |
| Root-cause suggestions | Confidence, evidence and competing hypotheses |
| Experience score | An explainable score showing exactly what moved it |
| Flexible query languages | Natural-language investigation plus structured query access |
| Custom dashboards | Useful zero-configuration role views before customization |
| Alerts | Impact-aware incidents with aggressive deduplication |
| Automation | Safe closed-loop remediation with approvals and rollback |
| AI summaries | AI that cites exact telemetry rather than hallucinating explanations |
| Network visibility | Independent evidence across LAN/WAN/SASE/ISP/DNS/CDN/cloud/application |
| Huge telemetry volume | Cost controls and visible value-per-signal |
| Vendor platform | Open APIs, OpenTelemetry and data portability |

Several vendors are already moving directly toward these demands.

Datadog now connects RUM to synthetics so a real Session Replay can be converted into a browser test by cloning user clicks and page loads. It also has a test-coverage view that identifies heavily used real-user actions that are not protected by browser tests. citeturn12search17turn12search23 Datadog has also connected feature flags to RUM/APM and supports telemetry-driven rollout controls, a significant indication that **release operations and DEM are converging**. citeturn20search5turn20search19

New Relic now applies AI to Session Replay summaries, provides sequence filtering and clips, and its April 2026 mobile replay release synchronizes replays with breadcrumbs and logs while supporting configurable masking and error-based sampling. citeturn20search18turn12search14

Dynatrace’s current RUM model exposes interactions, navigation flows and business-defined session/event properties; its evolving Session Replay experience aligns replay events with requests, errors, navigation and user interactions. citeturn12search1turn12search11turn12search6

Netskope introduced a conversational DEM Data Intelligence Agent in March 2026, enterprise DEM APIs, and more tunable experience-score alerts based on score, impacted users and duration. In June it added aggregated traceroute showing how network paths and hop latency evolved over time instead of presenting only a point-in-time trace. citeturn20search0turn20search11

Cisco is moving even further toward agentic assurance: its current direction includes AI-assisted investigations presenting incidents, evidence, confidence/risk and suggested next steps, while ThousandEyes has introduced an MCP-server model for exposing assurance data to AI workflows. citeturn20search9turn20search16

The significance for Correlix is that **natural-language AI alone will not be a differentiator by the time the product matures**. It is rapidly becoming table stakes.

The differentiator has to be the quality of the underlying causal and evidence model.

## Competitive landscape and the whitespace Correlix should capture

The competitive market can be understood as a set of different starting points rather than one homogeneous category.

| Vendor / archetype | Strongest current value | Structural opening for Correlix |
|---|---|---|
| **Datadog** | Excellent combination of RUM, replay, synthetics, observability and increasingly feature delivery; RUM can generate synthetics. citeturn12search17turn20search19 | Make complex journeys/tests easier to manage; better deterministic network-path causality; fewer navigation/query burdens; transparent evidence. Customer reviews expose test-flakiness and scale-management pain. citeturn14search3 |
| **Dynatrace** | Powerful full-stack correlation, customizable RUM context, behavioral analytics and increasingly rich replay. citeturn12search1turn12search11 | Deliver simpler out-of-box investigation and explainability without requiring expertise in a powerful query language; make path/seam ownership first-class. Reviews show documentation and complexity friction. citeturn14search0 |
| **New Relic** | Browser/mobile RUM, replay, synthetics and increasingly AI-assisted replay interpretation in a broad observability platform. citeturn20search1turn20search18 | Deeper independent Internet/WAN/LAN causality and infrastructure ownership boundaries rather than mainly connecting user activity to application telemetry. |
| **Cisco ThousandEyes** | Outstanding outside-in network/Internet/SaaS visibility and hop-level accountability. citeturn11search0turn20search20 | Combine that path depth with richer application journey, business behavior, replay and change causality; simplify training/customization and reduce false positives highlighted in reviews. citeturn14search1 |
| **Catchpoint** | Very strong Internet Performance Monitoring across DNS, CDN, BGP, SaaS and third-party dependencies, plus synthetic/RUM vantage points and tracing. citeturn13search1turn13search12turn13search13 | Correlix can make causal ownership across enterprise LAN/WAN/cloud configuration/app changes the center rather than primarily Internet health. |
| **Netskope** | User/device + SASE/network/application context, increasingly conversational analysis and historical path visualization. citeturn20search0turn20search11 | Avoid being constrained to the security/SASE control plane; extend across heterogeneous LAN, SD-WAN, carrier, cloud and application environments. |
| **Riverbed Aternity** | Device, application, network and workflow experience; sentiment; proactive remediation/self-service. citeturn13search17turn13search24 | Go deeper into code/app dependency/change causality and DevOps APIs; reviewers explicitly request more application detail and codebase/API integration. citeturn19search13 |
| **Splunk / AppDynamics** | Broad observability, business transactions and real-time application insight. citeturn14search11 | Make customer-path investigation the primary workflow rather than requiring search across large telemetry datasets. |
| **DEX specialists such as Nexthink** | Experience score, device/user context, proactive optimization, sentiment and automation. citeturn19search4turn19search5 | Apply similar action-oriented experience management to external customer journeys and network/cloud/app causality, with less custom-use-case burden. |

The largest remaining whitespace is not another data collector. It is an **evidence-backed causal graph spanning domains that are normally owned by different teams**.

Today, an enterprise incident often generates separate truths:

`Customer Support`
→ “customers cannot complete checkout”

`Frontend team`
→ “INP and JS errors increased”

`Backend team`
→ “service latency looks mostly fine”

`Network team`
→ “tunnel is up”

`Cloud team`
→ “instances are healthy”

`ISP/carrier`
→ “our network is operational”

`Security team`
→ “SASE policies are unchanged”

`Platform team`
→ “a deployment happened 7 minutes earlier”

The product opportunity is to turn those into one causal statement:

```text
CUSTOMER EXPERIENCE INCIDENT

Journey:
Search → Product → Cart → Checkout

Impact:
18.4% checkout failures
3,842 sessions affected
$214K estimated transaction value at risk

Onset:
10:42:16

Observed failure path:
Mobile user
  → Wi-Fi/LAN                 healthy
  → SD-WAN                    healthy
  → ISP-A                     degraded
  → BGP transit hop 7         severe loss
  → AWS NVA                   healthy
  → frontend                  healthy
  → checkout-api              healthy
  → PostgreSQL                healthy

Change correlation:
application releases: no relevant change
cloud route changes: none
network policy changes: none

Evidence:
RUM degradation       YES
synthetic degradation YES
second vantage        YES
path loss             YES
backend latency       NO
application error     NO

Likely cause:
ISP-A transit path degradation

Confidence:
94% — CONFIRMED

Blast radius:
US-West / ISP-A / mobile and broadband users

Owner:
External network provider / Network Operations

Recommended action:
Shift affected traffic to ISP-B

Validation after action:
Run checkout synthetic + compare RUM cohort + path observation
```

**That should be the heart of Correlix DEM.**

Correlix already has several building blocks for this model. Its fault-lab describes correlation of an AWS security-group change and subsequent application failures into one object; validates isolation when an Azure tunnel fails but AWS remains healthy; discovers AWS route tables and Azure UDRs to derive actual edges; and tracks source readiness from what has really landed rather than merely showing configured sources as operational. fileciteturn6file0L2-L2

Its fault-campaign design is particularly differentiated. It distinguishes RST-versus-timeout, health-OK/probe-failing states, destination rejection versus path death, blast-radius shape, change-to-effect adjacency, recurrence, per-flow hashing and faults that persist after the initiating cause. It also calls out additional telemetry requirements such as host-resource metrics, extra vantages, Azure flow/change data, payload-size/directional probes and richer application topology. fileciteturn8file0L2-L2

I would preserve this philosophy rather than diluting it into a generic observability UI.

The opportunity is to put **actual digital-experience data at the left side of that existing causal engine**.

Today Correlix is particularly strong on:

`path + topology + seams + fault signatures + cloud/network RCA`

The major product gap is:

`real user + journey + replay + mobile + synthetics + business outcome`

Connect those two and the architecture becomes substantially more interesting than a conventional DEM dashboard.

## Finalized Correlix DEM product design

The recommended product name internally could be **Correlix Experience Graph** or **Correlix Digital Experience Assurance**. “Dashboard” should describe a presentation layer, not the architecture.

The dashboard should be designed around **progressive disclosure**: an executive sees impact; an operations lead sees ownership and incident state; an SRE sees the causal path; a developer drills into traces/replay; a network engineer gets path hops; a product manager gets journey conversion. They should all be viewing the *same incident object*, not separate dashboards.

**Primary navigation**

```text
Correlix

Experience
Journeys
Incidents
Service Paths
Users & Sessions
Synthetics
Releases & Changes
Internet & Network
Services
AI Investigator
Data Health
Automation
```

The landing page should be **Experience**, not Infrastructure.

A suggested layout is:

```text
┌────────────────────────────────────────────────────────────────────────────┐
│ CORRELIX EXPERIENCE                                                       │
│ Last 30 min ▾  Production ▾  All Apps ▾  All Regions ▾  Compare baseline │
├────────────────────────────────────────────────────────────────────────────┤
│ Experience SLO │ Journey Success │ Impacted Users │ Business Impact       │
│     98.73%     │     96.42%      │      4,218     │    $214K at risk      │
│  ▼ 0.62%       │    ▼ 2.11%      │     ▲ 3,661    │     ▲ $176K           │
├────────────────────────────────────────────────────────────────────────────┤
│ WHAT CHANGED?                         │ WHERE IS EXPERIENCE DEGRADING?      │
│ 10:42 ISP-A route degradation         │ US West        ██████              │
│ 10:40 checkout release 24.9.5         │ ISP-A          ████████            │
│ 10:31 feature flag checkout_v3 25%    │ iOS            ███                 │
├───────────────────────────────────────┴────────────────────────────────────┤
│ ACTIVE EXPERIENCE INCIDENTS                                               │
│                                                                          │
│ 🔴 Checkout degraded     3,842 users   $214K risk   ISP path   94% conf  │
│ 🟠 Login slow              621 users               DNS        81% conf    │
│ 🟡 Reports p95 high         84 users               DB pool    74% conf    │
├────────────────────────────────────────────────────────────────────────────┤
│ JOURNEY HEALTH                                                            │
│ Search 99.9 → Product 99.4 → Cart 98.8 → Checkout 91.6 → Confirmation 91.1│
├────────────────────────────────────────────────────────────────────────────┤
│ TELEMETRY CONFIDENCE                                                      │
│ RUM ✓ Replay ✓ Synthetic ✓ Traces ✓ Network ✓ Change ✓ DNS ⚠ BGP ✓       │
└────────────────────────────────────────────────────────────────────────────┘
```

This layout intentionally puts **impact, journey, cause and evidence** ahead of raw graphs.

The Experience score should not be an opaque 0–100 number. Nexthink reviews show both the appeal of a standardized experience score and the frustration when users cannot easily understand or defend what it means. citeturn19search5turn19search13

Correlix should make the score decomposable:

```text
Experience Health 86 / 100

Journey success        33 / 40
Responsiveness         18 / 20
Availability           18 / 20
Error-free interaction  8 / 10
Network quality         6 /  7
User friction           3 /  3

Why score fell:
- Checkout success: -5.8
- p95 checkout latency: -3.1
- ISP-A path loss: -2.4
- JavaScript error increase: -1.3
```

Every component should be clickable into its evidence.

**The most important screen should be the Experience Incident.**

Its information architecture should be:

```text
Impact
↓
Timeline
↓
Experience path
↓
Likely cause
↓
Evidence
↓
Changes
↓
Ownership
↓
Recommended action
↓
Recovery validation
```

Not:

```text
Alert
↓
50 charts
↓
Good luck
```

The centerpiece should be the **Experience Path Graph**:

```text
REAL USER / DIGITAL AGENT
        │
        ▼
Browser / Mobile / API agent
        │  INP 470 ms • error 8.2%
        ▼
Wi-Fi / LAN
        │  8 ms • healthy
        ▼
SD-WAN / SASE / VPN
        │  21 ms • healthy
        ▼
ISP / BGP / Internet
        │  8.4% loss • DEGRADED
        ▼
DNS / CDN / Edge
        │  healthy
        ▼
Cloud NVA / LB / Gateway
        │  healthy
        ▼
Frontend
        │
        ▼
checkout-api
        │
        ├──────── payment provider
        │
        └──────── PostgreSQL
```

Every node and edge needs four attributes that remain visible in all drill-downs:

```text
STATE
PROVENANCE
CONFIDENCE
FRESHNESS
```

For example:

```text
ISP-A → transit-7

State:       degraded
Evidence:    8.4% packet loss
Observed by: vantage-sfo-4, vantage-user-2881
Provenance:  active path observation
Confidence:  0.97
Last seen:   8 sec ago
```

This directly extends the provenance and observed-versus-inferred principles already recorded in Correlix’s service-path work. fileciteturn6file0L2-L2

The graph must support **time travel**. Netskope’s 2026 aggregated-traceroute design is an important market signal: customers need to understand how a route evolved over a time window, not simply what traceroute looks like now. citeturn20search11 Correlix should apply that idea to the entire path:

```text
10:35   user → ISP-A → transit-3 → AWS
10:42   user → ISP-A → transit-7 → AWS  ← degradation begins
10:55   user → ISP-B → transit-2 → AWS  ← remediation
```

Correlix’s journey system should similarly avoid a simplistic Sankey chart. It needs a **journey graph** capable of branches, loops and abandonment:

```text
Search
 ├─> Product
 │    ├─> Add to Cart
 │    │     ├─> Login
 │    │     │    └─> Checkout
 │    │     └─> Checkout
 │    └─> Back to Search
 └─> Exit
```

For each edge:

`users | success | p50/p75/p95 latency | errors | conversion | business value | release cohort`

The dashboard should automatically compare:

```text
Current vs baseline
Current release vs previous release
Feature flag on vs off
Region A vs Region B
ISP A vs ISP B
Web vs mobile
Browser/version cohorts
Device cohorts
New vs returning user
Paid vs free / customer tier
Synthetic vs real user
```

Release correlation is especially important because Datadog’s 2026 feature-flag integration shows DEM moving toward closed-loop release safety. citeturn20search5 Correlix should add a **Change Lens** to every incident:

```text
Changes in causal window

10:31  feature_flag checkout_v3   5% → 25%
10:34  deployment checkout-api    v412 → v413
10:39  AWS SG update              unrelated resource
10:41  BGP route change           ISP-A
10:42  experience degradation begins
```

A change should never be declared causal merely because it was nearby in time. Correlix should label:

`candidate → correlated → supported → contradicted → confirmed`

That is consistent with its current campaign logic, which specifically tests change-to-effect adjacency and distinguishes configuration faults from other causes. fileciteturn8file0L2-L2

**Synthetics should be designed as a learning system rather than a test inventory.** Datadog’s ability to turn replayed real-user interactions into synthetic tests, combined with Atlassian’s warning about synthetic flakiness, gives Correlix a strong design target. citeturn12search17turn15search7

The UI should continuously show:

```text
Journey Protection

Critical journey actions       47
Protected by synthetics        39
Untested high-volume actions    6
Recently changed actions        4
Broken tests                    2
Suspected flaky tests           3
Coverage                       83%

Suggested tests:
+ Checkout via Apple Pay
+ Password reset from mobile
+ Report export >10 MB
```

Tests should receive their own reliability score:

```text
Test health
- pass/fail consistency
- selector stability
- environmental sensitivity
- execution duration
- false-positive history
- last real-user match
```

A test suspected to be flaky should not create a P1 customer incident by itself.

**Session Replay should be an evidence pane, not a separate product island.** Current New Relic and Dynatrace directions show the value of synchronizing replay with telemetry and AI-generated summaries. citeturn12search14turn20search18turn12search6

Correlix should automatically find:

```text
Representative session
First failing session
Highest-business-value failure
Most common failure sequence
Healthy control session
```

and align the replay timeline with:

```text
user click
↓
browser interaction
↓
network request
↓
trace
↓
service span
↓
dependency
↓
network/path observation
↓
error/change
```

Privacy needs to be architectural rather than an afterthought. Current mobile Session Replay products expose server-side sampling, masking and PII protections specifically because replay data can be sensitive. citeturn12search14turn20search8

The Correlix canonical data contract therefore needs a `data_class` field on every evidence object—something its current service-path contract already appears to anticipate. fileciteturn6file0L2-L2 Recommended classes are:

```text
public
internal
customer_metadata
pseudonymous_user
pii
credential
secret
regulated
```

Access and retention should be policy-driven by classification.

**The canonical model should be built for change.** OpenTelemetry is the right interoperability foundation, but Correlix should not copy OTel schemas directly into permanent storage. OpenTelemetry’s current browser Web Vital semantic conventions remain in Development status, and OTel itself is explicitly expanding into browser/mobile and agentic workloads. citeturn11search3turn17search10

A versioned Correlix schema should normalize external semantics through adapters:

```text
External telemetry
       │
       ▼
Schema adapter
       │
       ▼
Correlix canonical model
       │
       ├─ original payload/version retained
       └─ normalized semantic version
```

OpenTelemetry’s own T-shaped signal guidance is a good architectural principle here: provide broad common signals for most cases and then allow richer domain-specific depth where required. citeturn11search15

I recommend these canonical first-class objects:

| Object | Purpose |
|---|---|
| `ExperienceEvent` | A user/browser/mobile/API interaction |
| `ExperienceSession` | Ordered interaction context |
| `JourneyDefinition` | Business journey model |
| `JourneyObservation` | One actual journey execution |
| `Endpoint` | User, device, browser, agent or service endpoint |
| `PathDefinition` | Intended logical route |
| `PathObservation` | Immutable observed route at a point in time |
| `PathHop` | Ordered hop with metrics/provenance |
| `Service` | Logical application/service identity |
| `Dependency` | DB, API, queue, SaaS, third party |
| `SyntheticDefinition` | Desired synthetic journey |
| `SyntheticRun` | Immutable execution |
| `ChangeEvent` | Deployment/config/flag/network change |
| `BusinessEvent` | Order, login, booking, payment, report |
| `EvidenceItem` | Atomic evidence supporting/contradicting a hypothesis |
| `CausalHypothesis` | Candidate root-cause explanation |
| `ExperienceIncident` | Impact + hypotheses + owner + lifecycle |
| `RemediationAction` | Proposed/executed corrective action |
| `DataSourceHealth` | Freshness/completeness of every ingest lane |
| `ExperienceSLO` | Customer/business outcome objective |

A canonical event envelope should look roughly like:

```json
{
  "event_id": "evt_...",
  "tenant_id": "tenant_...",
  "timestamp": "2026-09-05T15:42:16.231Z",
  "observed_at": "2026-09-05T15:42:16.419Z",

  "source": {
    "type": "rum",
    "name": "correlix-web-sdk",
    "version": "1.0.0"
  },

  "schema": {
    "name": "correlix.experience.event",
    "version": "1.0.0",
    "external_schema": "otel",
    "external_version": "1.44.0"
  },

  "identity": {
    "app_id": "checkout",
    "service_id": "checkout-web",
    "environment": "prod",
    "session_id": "sess_...",
    "journey_id": "purchase",
    "trace_id": "trace_...",
    "user_id": "pseudonymized_..."
  },

  "experience": {
    "event_type": "interaction",
    "action": "submit-payment",
    "success": false,
    "duration_ms": 4280,
    "error_type": "timeout"
  },

  "business": {
    "transaction_type": "purchase",
    "value": 189.25,
    "currency": "USD"
  },

  "privacy": {
    "data_class": "pseudonymous_user",
    "retention_policy": "rum_standard"
  }
}
```

The correlation graph then uses explicit typed relationships rather than token matching:

```text
USER
  used
ENDPOINT
  executed
JOURNEY
  traversed
PATH
  reached
SERVICE
  called
DEPENDENCY

CHANGE
  modified
RESOURCE

INCIDENT
  impacted
JOURNEY

EVIDENCE
  supports / contradicts
HYPOTHESIS
```

Correlix’s existing insistence that the backend own an ordered path spine rather than asking the renderer to infer one should be retained. fileciteturn6file0L2-L2

The entity-resolution order should likewise be explicit:

```text
exact canonical ID
    >
trace/session correlation
    >
cloud/resource identity
    >
service identity
    >
time-bounded endpoint identity
    >
topological containment
    >
observed path adjacency
    >
heuristic inference
```

Each weaker resolution should lower confidence.

**RCA should remain deterministic-first, AI-second.**

Recent research supports graph-based multimodal RCA. CHASE models traces, logs and metrics in a heterogeneous causal graph; newer 2026 preprints such as TORAI investigate RCA where trace graphs contain blind spots, while MetaRCA proposes reusable meta-causal knowledge instantiated against current topology. citeturn17academia14turn17academia12turn17academia13 GALA+ combines dependency-graph-bounded exploration with multi-modal evidence and generates diagnoses and action recommendations; importantly, its premise is that unconstrained LLM exploration can hallucinate or wander. citeturn16academia3 These are emerging/preprint research results rather than settled production standards, but the architectural lesson is strong.

For Correlix:

```text
Deterministic signatures
        +
topology/path evidence
        +
statistical anomalies
        +
temporal/change correlation
        +
blast-radius reasoning
        ↓
candidate hypotheses
        ↓
graph-bounded AI investigator
        ↓
human-readable explanation
```

The LLM should **never invent the root cause and then search for supporting telemetry**.

Instead:

```text
Evidence → hypotheses → ranking → explanation
```

The AI response contract should require:

```json
{
  "answer": "...",
  "confidence": 0.92,
  "hypotheses": [
    {
      "cause": "ISP transit degradation",
      "probability": 0.92,
      "supporting_evidence_ids": ["ev1", "ev2", "ev8"],
      "contradicting_evidence_ids": ["ev9"],
      "missing_evidence": ["bgp_update_feed"]
    }
  ],
  "recommended_actions": [],
  "assumptions": []
}
```

This turns AI into an interface to Correlix evidence rather than an oracle.

That approach is also future-proof for **AI-native applications and agent journeys**. Gartner’s current DEM definition explicitly includes digital agents connecting to APIs, and OpenTelemetry is already standardizing GenAI telemetry such as model identity, token use, tool invocation and agent workflows. citeturn11search0turn17search0

Thus an AI-agent journey should be monitorable like:

```text
User prompt
   ↓
AI agent
   ↓
model call
   ↓
tool call
   ↓
internal API
   ↓
database
   ↓
tool result
   ↓
model response

Experience:
success
latency
cost
tool retries
token usage
accuracy/evaluation
user abandonment
```

That is likely a critical five-year hedge.

The roadmap should therefore be:

| Horizon | Correlix capability |
|---|---|
| **Foundation** | Canonical experience model, Journey/SLO objects, RUM web SDK, experience overview, existing path graph integration, data-health/confidence model |
| **Next product layer** | Browser journey analytics, business events, Core Web Vitals, releases/changes, API synthetics, multi-vantage path tests |
| **Experience depth** | Session Replay, browser synthetics, RUM→synthetic generation, test coverage/flakiness analytics |
| **Multi-channel** | iOS/Android RUM and replay, device/network context, mobile journeys |
| **Internet assurance** | DNS/CDN/BGP/ISP/SASE path intelligence, historical path comparison and third-party SLA evidence |
| **Closed loop** | Feature flags, canary comparison, safe remediation, ITSM/workflow integration, post-action validation |
| **Agentic DEM** | AI/API-agent journey monitoring, model/tool telemetry, AI Investigator with evidence graph, governed agentic actions |
| **Optimization layer** | Experience-to-revenue models, capacity/cost impact, causal experiment analysis, autonomous prevention under policy |

The underlying architecture should remain modular enough that those are **new evidence producers**, not dashboard rewrites.

```text
                        CORRELIX EXPERIENCE GRAPH

 Web RUM ─────────┐
 Mobile RUM ──────┤
 Session Replay ──┤
 Synthetics ──────┤
 API checks ──────┤
 Endpoint data ───┤
 OTLP/APM ─────────┤
 Logs/Metrics ─────┤
 DNS/CDN/BGP ──────┤
 LAN/WAN/SD-WAN ───┤
 Cloud APIs ────────┤
 Flow telemetry ────┤
 Deployments ───────┤
 Feature flags ─────┤
 Business events ───┤
 ITSM/sentiment ─────┤
 AI-agent traces ─────┘
          │
          ▼
┌───────────────────────────────────────────────┐
│ Ingestion + adapters + schema governance      │
│ OpenTelemetry-first / vendor-neutral inputs   │
└──────────────────────┬────────────────────────┘
                       ▼
┌───────────────────────────────────────────────┐
│ Canonical Correlix Experience Model           │
│ identity • provenance • privacy • freshness   │
└───────────────┬───────────────────────────────┘
                ▼
┌───────────────────────────────────────────────┐
│ Temporal Experience Graph                     │
│ user → journey → path → service → dependency  │
│              ↑                                │
│          changes                              │
└───────────────┬───────────────────────────────┘
                ▼
┌───────────────────────────────────────────────┐
│ Correlation / Causality Engine                │
│ signatures + anomaly + topology + timeline    │
│ multi-vantage + blast radius + confidence     │
└───────────────┬───────────────────────────────┘
                ▼
┌───────────────────────────────────────────────┐
│ Experience Incident                           │
│ impact → cause → evidence → owner → action    │
└───────────────┬───────────────────────────────┘
                ▼
┌───────────────────────────────────────────────┐
│ AI Investigator                               │
│ bounded by evidence graph                     │
│ hypotheses • confidence • missing evidence    │
└───────────────┬───────────────────────────────┘
                ▼
┌───────────────────────────────────────────────┐
│ Actions / ITSM / Automation / Release Control │
│ approval → execute → observe → verify         │
└───────────────────────────────────────────────┘
```

The key product KPI should ultimately not be “number of metrics ingested.”

It should be things such as:

`% critical journeys covered`, `experience SLO attainment`, `incidents detected before complaint`, `time to owner attribution`, `time to high-confidence cause`, `false incident rate`, `synthetic false-positive rate`, `percentage incidents with change correlation`, `percentage incidents with automated verification`, `customer-impact minutes`, and `business value protected`.

That is what makes the product economically defensible.

## Claude Code implementation prompt for Correlix

The following prompt is designed to be pasted into Claude Code **inside the actual Correlix product repository**. It intentionally tells Claude to inspect and preserve the existing architecture rather than assuming that references appearing in the fault-lab build log necessarily have identical paths in the current product checkout. The Correlix materials do reference components such as `readiness.ts`, `topoGraph.ts`, `src/backend/cloud_ingestion.go` and `docs/design/service-path-graph-contract.md`, so the prompt treats these as landmarks to search for rather than blindly creating duplicates. fileciteturn6file0L2-L2

```text
You are the principal engineer responsible for implementing the first production
version of Correlix Digital Experience Monitoring / Digital Experience Assurance.

DO NOT approach this as "build another dashboard."

The strategic product goal is:

For every degraded digital experience, Correlix must answer:
1. Who is affected?
2. Which user/business journey is failing?
3. Where along the user → LAN/WAN/Internet/cloud/app path is degradation occurring?
4. What changed?
5. What is the most likely cause?
6. What evidence supports or contradicts that conclusion?
7. How confident are we?
8. Who owns the failing domain/seam?
9. What action should be taken?
10. After action, did the user experience actually recover?

Correlix already has important work in the areas of:
- service/path topology
- cloud topology discovery
- correlation objects
- fault signatures
- seams and ownership
- blast radius
- source-ingestion health
- multi-vantage evidence
- observed vs inferred path information
- provenance
- ordered path/spine rendering

PRESERVE AND EXTEND THOSE CONCEPTS.

Do not replace working service-path/RCA architecture with a separate DEM silo.

============================================================
PHASE A — REPOSITORY RECONNAISSANCE
============================================================

Before changing code:

1. Inspect the entire repository structure.
2. Locate:
   - backend language/framework and entrypoints
   - frontend framework
   - database/storage interfaces and migrations
   - API conventions
   - topology / graph models
   - correlation / RCA models
   - signature engine
   - incident models
   - cloud ingestion
   - service/path rendering
   - data-source readiness
   - auth/RBAC/tenant model
   - test conventions
   - frontend component library
   - feature-flag mechanism
3. Search specifically for these names or equivalents:
   - docs/design/service-path-graph-contract.md
   - Endpoint
   - PathDefinition
   - PathObservation
   - PathHop
   - topoGraph.ts
   - readiness.ts
   - cloud_ingestion.go
   - correlation object
   - evidence
   - confidence
   - seam
   - owner
   - blast radius
4. Read existing design docs before implementation.
5. Identify which existing abstractions can be extended instead of duplicated.
6. Do NOT create parallel topology, incident, confidence, or provenance models if
   an existing one can be evolved safely.
7. Document findings in:
   docs/design/dem-repository-assessment.md

The assessment must contain:
- current architecture
- reusable components
- gaps
- proposed files to modify
- proposed files to add
- migration implications
- compatibility risks

Do not implement major changes until this assessment exists.

============================================================
PHASE B — ARCHITECTURAL NON-NEGOTIABLES
============================================================

Use these design principles.

A. EXPERIENCE FIRST

The dashboard must lead with:
- experience SLO
- journey success
- impacted users/sessions
- business impact
- active experience incidents

Do not lead with CPU/memory/interface charts.

B. ONE EXPERIENCE INCIDENT

Do not create separate incidents for:
- RUM
- synthetics
- network
- cloud
- backend
- changes

These signals should become evidence attached to ONE ExperienceIncident whenever
correlation supports the relationship.

C. EVIDENCE BEFORE AI

AI must never fabricate root cause.

Pipeline:

telemetry
  -> normalized evidence
  -> topology/change/time correlation
  -> candidate hypotheses
  -> confidence
  -> AI explanation

Never:

LLM guess
  -> search for supporting evidence

D. PROVENANCE EVERYWHERE

Every important node/edge/fact must carry:
- source
- source object ID
- observed_at
- event timestamp
- data class
- observed vs inferred
- confidence
- freshness
- schema version

E. IMMUTABLE OBSERVATIONS

Path observations, synthetic runs, experience events, evidence and changes must be
append-only/immutable facts.

Derived current-state objects may be updated.

F. VERSIONED SCHEMA

External schemas such as OpenTelemetry WILL evolve.

Never make an unstable external semantic convention the permanent internal contract.

Store:
- canonical schema name/version
- external schema name/version
- original source reference/payload as allowed by policy

G. EXPLAINABLE SCORES

Never expose an Experience Score that cannot explain:
- components
- weights
- current values
- contribution to score change
- affected population

H. MISSING TELEMETRY IS DATA

If DNS or traces are unavailable, do not silently infer certainty.

Example:

confidence = 0.71
missing_evidence = ["dns", "server_trace"]

A source-health problem must visibly reduce diagnostic confidence where applicable.

============================================================
PHASE C — CANONICAL DOMAIN MODEL
============================================================

Add or extend models for these concepts.

Use existing project naming/style where appropriate.

1. ExperienceEvent

Required concepts:
- id
- tenant/account
- timestamp
- observed_at
- app/service/environment
- session identity
- pseudonymous user identity
- event type
- action
- page/screen/route
- success/failure
- duration
- error
- Web Vitals where relevant
- release/version
- feature flags
- network/device/browser context
- trace correlation
- business context
- source/provenance
- privacy classification
- schema version

2. ExperienceSession

Represents one web/mobile/API-agent session.

Must support:
- start/end
- actor type:
  HUMAN
  SYNTHETIC
  API_CLIENT
  AI_AGENT
- device/browser/mobile metadata
- geo
- network/ISP
- app/version
- journey observations
- experience events
- replay reference
- aggregate health

3. JourneyDefinition

Example:
purchase:
  search
  product
  cart
  authentication
  checkout
  payment
  confirmation

Support:
- branching
- optional steps
- loops
- terminal success
- terminal failure
- business importance
- SLO targets

Do NOT limit journeys to linear Sankey graphs.

4. JourneyObservation

One actual traversal.

Must compute:
- success
- abandonment
- duration
- failed step
- errors
- business value
- correlated trace IDs
- correlated path observation
- version/cohort

5. Endpoint / PathDefinition / PathObservation / PathHop

REUSE the existing service-path contract if it exists.

Do not copy IP addresses into arbitrary token arrays as a shortcut.

PathObservation must be immutable and time-aware.

Every PathHop:
- ordinal
- identity
- hop type
- address/name
- latency
- loss
- source
- confidence
- observed/inferred
- ownership domain
- seam
- health

6. ChangeEvent

Types:
- APPLICATION_DEPLOY
- CONFIG_CHANGE
- FEATURE_FLAG_CHANGE
- CLOUD_CHANGE
- NETWORK_CHANGE
- SECURITY_POLICY_CHANGE
- DNS_CHANGE
- ROUTE_CHANGE
- INFRASTRUCTURE_CHANGE

Fields:
- actor
- object
- before
- after
- timestamp
- deployment/release ID
- source
- rollback reference where available

7. BusinessEvent

Examples:
- login
- purchase
- booking
- payment
- report
- claim
- API transaction

Do not hard-code ecommerce semantics.

Make business_event_type extensible.

8. SyntheticDefinition

Types:
- HTTP
- API
- DNS
- TLS
- BROWSER
- JOURNEY
- NETWORK
- LARGE_PAYLOAD
- DIRECTIONAL_PATH

Support multiple vantages.

9. SyntheticRun

Immutable execution containing:
- definition ID/version
- vantage
- timestamps
- outcome
- step results
- screenshots/reference if supported
- path observation
- response metrics
- generated RUM/session correlation if appropriate

10. EvidenceItem

This is a CRITICAL model.

Fields conceptually:

id
incident_id
kind
source
entity
timestamp
summary
value
baseline
deviation
supports_hypothesis_ids
contradicts_hypothesis_ids
reliability
freshness
independence_group
provenance
data_class

Examples:
- RUM checkout error increased 8x
- synthetic checkout failed from 3 vantages
- backend API p95 unchanged
- ISP hop loss increased to 8%
- deployment occurred 2 minutes earlier
- deployment cohort does NOT correlate with failures

Negative evidence is first-class evidence.

11. CausalHypothesis

Fields:
- id
- incident
- cause entity
- cause class
- human-readable explanation
- supporting evidence
- contradicting evidence
- missing evidence
- confidence
- state:
  CANDIDATE
  SUSPECTED
  SUPPORTED
  CONFIRMED
  REJECTED
- owner
- seam
- blast radius
- alternative hypotheses

12. ExperienceIncident

Fields:
- title
- state
- severity
- detection timestamp
- first impact timestamp
- recovery timestamp
- affected apps
- affected journeys
- impacted user/session counts
- affected cohorts
- business impact
- experience SLO impact
- causal hypotheses
- leading hypothesis
- path observation
- relevant changes
- evidence
- owner/seam
- recommended actions
- executed actions
- verification results

13. RemediationAction

Fields:
- type
- target
- proposed_by
- evidence
- expected outcome
- risk
- reversibility
- approval state
- execution state
- rollback
- verification plan

14. DataSourceHealth

Extend the existing ingestion/readiness model.

For every source:
- configured
- last seen
- expected interval
- event volume
- lag
- health
- error
- coverage
- influence on current incident confidence

============================================================
PHASE D — API CONTRACT
============================================================

Use the repository's current API style.

Implement or adapt endpoints equivalent to:

GET /api/dem/overview
GET /api/dem/incidents
GET /api/dem/incidents/{id}
GET /api/dem/incidents/{id}/evidence
GET /api/dem/incidents/{id}/timeline
GET /api/dem/incidents/{id}/path
GET /api/dem/journeys
GET /api/dem/journeys/{id}
GET /api/dem/journeys/{id}/observations
GET /api/dem/sessions
GET /api/dem/sessions/{id}
GET /api/dem/synthetics
GET /api/dem/synthetics/coverage
GET /api/dem/changes
GET /api/dem/data-health

POST /api/dem/events
POST /api/dem/business-events
POST /api/dem/synthetic-runs

Only add:
POST /api/dem/ai/investigate

after the evidence contract exists.

All list endpoints need:
- time range
- environment
- app/service
- journey
- geography
- browser/device
- ISP/network
- release/version
- feature flag
- tenant/account as appropriate
- pagination

Do not implement high-cardinality filters by blindly loading all rows into memory.

============================================================
PHASE E — EXPERIENCE OVERVIEW UI
============================================================

Implement a new primary screen called:

Experience

Top cards:

1. Experience SLO
2. Journey Success
3. Impacted Users
4. Business Impact
5. Active Experience Incidents

Each card must:
- show current value
- compare baseline
- show direction/change
- support click-through
- expose tooltip explaining calculation

Then render:

A. Active Experience Incidents

Columns:
Severity
Incident
Journey/App
Impact
Business impact
Likely layer
Leading cause
Confidence
Owner
Duration

B. Journey Health

Render key journeys and steps.

C. "What Changed?"

Show recent deployments/config/flag/network/cloud changes.

D. Experience Hotspots

Break down by:
- geography
- ISP
- device
- browser
- application version
- network type

E. Telemetry Confidence

Display actual source health.

Example:

RUM        FLOWING
Replay     FLOWING
Synthetic  FLOWING
Traces     DEGRADED
DNS        OFF
Network    FLOWING
Cloud      FLOWING
Changes    FLOWING

Never hard-code these states.
Use actual DataSourceHealth.

============================================================
PHASE F — EXPERIENCE INCIDENT UI
============================================================

This is the highest-priority screen.

Layout:

HEADER

"Checkout Experience Degraded"

Severity
Status
Started
Impacted users
Business impact
Leading hypothesis
Confidence
Owner

SECTION: IMPACT

- users
- sessions
- transactions
- error %
- latency
- journey success
- business value
- affected cohorts

SECTION: EXPERIENCE PATH

Reuse the service path graph.

Render:

user/device
  -> LAN
  -> WAN/SD-WAN/SASE/VPN
  -> ISP/Internet
  -> DNS/CDN where applicable
  -> cloud edge/NVA/LB
  -> frontend
  -> service
  -> dependency

Each edge:
- state
- latency/loss
- provenance
- confidence
- freshness
- owner/seam

Use visual distinction for:
- observed
- inferred
- unknown
- degraded
- healthy
- no-data

Do not present inferred edges as observed.

SECTION: TIMELINE

Combine:
- experience changes
- synthetic failures
- network/path events
- application anomalies
- cloud/network configuration changes
- deployments
- feature flags
- incident actions

SECTION: HYPOTHESES

Example:

94%  ISP-A transit degradation
42%  checkout-api regression
11%  AWS route issue

For each:
Supporting evidence
Contradicting evidence
Missing evidence

SECTION: CHANGES

Rank nearby changes using actual correlation, not only temporal distance.

SECTION: EVIDENCE

Provide evidence table with filter:
ALL
SUPPORTING
CONTRADICTING
MISSING

SECTION: ACTION

Show:
Recommended action
Expected outcome
Risk
Rollback
Approval requirement

SECTION: VERIFY

After remediation:
- run appropriate synthetic
- compare RUM cohort
- inspect path
- inspect service telemetry
- mark recovery only when evidence supports it

============================================================
PHASE G — JOURNEY ANALYTICS
============================================================

Implement a Journey Explorer.

Requirements:

- support branching journeys
- do not force fixed Sankey columns
- show step conversion
- show latency p50/p75/p95/p99
- show abandonment
- show error rate
- show business impact
- show affected versions/cohorts
- compare time windows
- compare releases
- compare feature flag on/off
- compare synthetic vs RUM

Clicking a failing step should open:
- representative sessions
- relevant incidents
- traces
- path observations
- releases
- replay if available

============================================================
PHASE H — SYNTHETIC COVERAGE
============================================================

Do not build only a list of tests.

Build a coverage model.

For every important real-user action determine:
- interaction volume
- business importance
- number of synthetics protecting it
- last successful synthetic
- synthetic reliability
- coverage state

Expose:

Critical actions
Protected actions
Untested actions
Recently changed actions
Broken tests
Suspected flaky tests
Coverage %

Implement a synthetic reliability score based on:
- inconsistent results
- selector instability where available
- vantage-specific failures
- historical false positives
- environment-specific failures
- runtime variance

A single flaky synthetic must not automatically create a high-severity
ExperienceIncident.

Design the data model so a future feature can generate a synthetic definition
from a RUM/session journey.

Do not fake browser execution if the repository does not have a browser runner yet.
Build the contract and interfaces first.

============================================================
PHASE I — EXPERIENCE SCORE
============================================================

Implement an explainable score service.

Do not bury weights in frontend code.

Initial configurable dimensions:

Journey success
Availability
Responsiveness
Error-free interaction
Network quality
User friction

Return:

{
  "score": 86,
  "previous_score": 97,
  "dimensions": [
    {
      "name": "journey_success",
      "score": 33,
      "max": 40,
      "delta_contribution": -5.8,
      "reason": "Checkout success fell to 91.6%"
    }
  ]
}

All weight sets must be versioned.

Store the scoring-policy version alongside generated score observations.

============================================================
PHASE J — CAUSAL CORRELATION
============================================================

Integrate DEM evidence with the existing Correlix correlation/signature engine.

Do not create a replacement RCA engine.

Extend existing signatures/evidence where necessary.

Correlation inputs should include:

- RUM anomalies
- session/journey failures
- synthetic failures
- path observations
- network telemetry
- cloud health
- app health
- dependency health
- traces
- change events
- business events

Use these concepts when available:

RST vs timeout
HTTP/API success rate
partial vs total failure
blast-radius shape
multi-vantage agreement
directionality
payload-size sensitivity
periodicity
change-before-effect
failure-outlives-cause
per-flow determinism
works-by-IP/fails-by-name
backend healthy while experience fails

Do not collapse all cloud/application failures into generic
"private connectivity down."

Confidence should incorporate:

- evidence reliability
- independent source count
- temporal alignment
- topology consistency
- causal specificity
- contradictory evidence
- telemetry gaps

Document confidence math.

============================================================
PHASE K — AI INVESTIGATOR
============================================================

Only build this after EvidenceItem and CausalHypothesis are functional.

The AI investigator is NOT allowed to query raw unrestricted telemetry and invent
an answer.

Provide the model with a structured incident evidence packet:

incident
impact
topology
path
hypotheses
supporting evidence
contradicting evidence
changes
source health
missing evidence
allowed actions

The model output MUST validate against a JSON schema.

Required output:

answer
confidence
hypotheses[]
supporting_evidence_ids[]
contradicting_evidence_ids[]
missing_evidence[]
recommended_next_queries[]
recommended_actions[]
assumptions[]

Reject AI responses that reference evidence IDs not supplied to the model.

UI must display evidence links.

Every AI-generated conclusion must visibly say:
"AI-assisted analysis based on Correlix evidence"

Do not label an AI-generated hypothesis "confirmed" unless the deterministic
confidence/evidence engine has confirmed it.

Add an AI feature flag.

Do not send PII, credentials, secrets, replay DOM contents or regulated data
to a model unless an explicit data policy allows it.

============================================================
PHASE L — PRIVACY AND SECURITY
============================================================

Add/extend data classification:

PUBLIC
INTERNAL
CUSTOMER_METADATA
PSEUDONYMOUS_USER
PII
REGULATED
CREDENTIAL
SECRET

Requirements:

- pseudonymize user IDs by default
- replay references separated from regular event payloads
- configurable masking
- role-controlled replay access
- configurable retention
- audit replay access
- never log credentials/tokens
- backend authorization on every tenant-scoped API
- do not rely on frontend hiding for access control

============================================================
PHASE M — OPEN TELEMETRY COMPATIBILITY
============================================================

Design adapters for OpenTelemetry rather than binding the storage schema directly
to current OTel browser conventions.

Normalize:
- service/resource identity
- HTTP
- traces
- logs
- browser events/Web Vitals
- mobile where supported
- feature flags where available
- GenAI/agent telemetry in a future-safe form

Persist:
external schema name
external version
canonical schema version

Make adapters independently testable.

============================================================
PHASE N — AI-AGENT/DIGITAL-AGENT FUTURE PROOFING
============================================================

Do not implement a huge AI observability product in this first change.

But the data model must permit:

actor_type = AI_AGENT

Future agent journey:

user request
 -> agent
 -> model
 -> tool
 -> API
 -> service
 -> dependency
 -> tool response
 -> model
 -> final response

Reserve/support fields for:
- agent identity/version
- model/provider
- conversation/run
- tool call
- tool duration
- retry count
- token usage
- cost
- outcome

Avoid provider-specific assumptions in canonical types.

============================================================
PHASE O — TESTING
============================================================

Add strong tests.

Backend/domain tests:

1. Experience incident can correlate multiple source types.
2. Negative evidence lowers hypothesis confidence.
3. Missing telemetry prevents inappropriate CONFIRMED state.
4. Independent vantages increase confidence.
5. One source duplicated several times does NOT count as independent evidence.
6. Change-before-effect can support a hypothesis.
7. Temporal proximity alone cannot confirm causality.
8. Observed path edges remain distinguishable from inferred edges.
9. Historical PathObservation is immutable.
10. Branching journey is represented correctly.
11. Synthetic flakiness does not create false P1 incident.
12. Cross-tenant access is rejected.
13. PII classification is enforced.
14. Experience-score calculation is explainable and versioned.
15. Existing cloud/WAN/LAN RCA tests continue passing.

Frontend tests:

1. Overview loads partial data safely.
2. Data-source degradation is visible.
3. Incident renders evidence/provenance.
4. Confidence is visible and accessible.
5. Inferred vs observed edges look different.
6. Filters update URL/state consistently.
7. No-data is not presented as healthy.
8. Loading/error states exist.
9. Business impact can be absent without crashing.
10. AI panel is unavailable when feature flag is disabled.

Add integration fixtures for at least:

A. Browser slowdown caused by frontend release.
B. Network degradation while backend remains healthy.
C. DB dependency failure with healthy path.
D. DNS failure: works by IP, fails by hostname.
E. Cloud security change immediately preceding experience failure.
F. Flaky synthetic while RUM is healthy.
G. Mobile/client failure not visible in backend telemetry.
H. Missing trace data but enough multi-source evidence for a suspected diagnosis.

============================================================
PHASE P — PERFORMANCE AND COST
============================================================

Do not assume all RUM data can be stored/queryable forever at full cardinality.

Introduce clear interfaces for:
- event sampling
- replay sampling
- retention
- aggregation
- cardinality control
- hot vs historical query paths

Prefer the repository's existing storage technology unless measurements prove it
cannot meet requirements.

Do NOT introduce Kafka, ClickHouse, a graph database, Redis, Elasticsearch, or a
new cloud service merely because it is fashionable.

Add infrastructure only when:
1. there is an explicit requirement,
2. existing storage has been measured,
3. the tradeoff is documented.

Every new dependency requires a design note.

============================================================
PHASE Q — OBSERVABILITY OF DEM ITSELF
============================================================

Correlix must monitor its own DEM pipeline.

Metrics:

ingest events/sec
ingest errors
ingest lag
source freshness
schema rejections
correlation latency
incident-generation latency
AI invocation latency/failure
query latency
synthetic result lag
dropped event count
sampling rate
storage usage

Expose relevant health through the existing source readiness/data-health mechanism.

============================================================
PHASE R — UX RULES
============================================================

Avoid "wall of widgets."

Use progressive disclosure.

Primary hierarchy:

Impact
 -> Cause
 -> Evidence
 -> Path
 -> Timeline
 -> Deep telemetry

Global filters must be consistent.

Use p75/p95/p99 where appropriate rather than only averages.

Always distinguish:
HEALTHY
DEGRADED
FAILED
UNKNOWN
NO DATA
DISABLED

UNKNOWN and NO DATA are NOT HEALTHY.

All chart legends, scores and confidence values require accessible explanations.

Do not require a query language for standard troubleshooting workflows.

Advanced users may have a query/explorer interface separately.

============================================================
PHASE S — DELIVERY SLICES
============================================================

Implement this incrementally.

SLICE 1
Domain contracts
ExperienceEvent
JourneyDefinition
JourneyObservation
EvidenceItem
CausalHypothesis
ExperienceIncident
DataSourceHealth extensions
migrations
tests

SLICE 2
DEM backend aggregation APIs
overview
incident
journey
data-health
tests

SLICE 3
Experience overview UI
filters
experience score
active incidents
journey health
telemetry confidence

SLICE 4
Experience Incident page
reuse existing service-path graph
impact
timeline
evidence
hypotheses
changes
ownership

SLICE 5
Synthetic coverage contracts/UI
test health
coverage gaps

SLICE 6
AI Investigator interface
structured evidence packet
JSON output validation
feature flag
audit trail

Do not attempt Session Replay recording or native mobile SDKs merely to declare
the feature complete unless the necessary platform infrastructure already exists.

Instead create stable interfaces/contracts that allow them to be added later.

============================================================
PHASE T — ACCEPTANCE SCENARIO
============================================================

The first release is not accepted until this scenario works end-to-end:

Scenario:

A user attempts checkout from an affected network.

Real-user telemetry shows:
- checkout latency increase
- failures increase

Multiple synthetics show:
- checkout affected from the same network region

Network/path evidence shows:
- path degradation between ISP and cloud

Backend shows:
- checkout service healthy
- DB healthy

A nearby application deployment exists but:
- healthy users on other ISPs use the same release
- therefore deployment evidence is contradictory

Expected Correlix output:

Incident:
"Checkout Experience Degraded"

Impact:
affected users and journey success shown

Leading hypothesis:
ISP/transit degradation

Confidence:
high/confirmed only if independence requirements are met

Evidence:
RUM + synthetic + network path

Contradictory evidence:
backend healthy
same app release healthy on unaffected cohort

Path:
affected hop highlighted

Owner:
network/provider domain

Recommended action:
traffic shift / provider escalation

Recovery:
after route shift, synthetic succeeds and RUM begins returning to baseline

The UI must make this understandable without requiring the operator to manually
correlate separate dashboards.

============================================================
PHASE U — DOCUMENTATION
============================================================

Create:

docs/design/dem-architecture.md
docs/design/dem-domain-model.md
docs/design/dem-evidence-confidence.md
docs/design/dem-privacy.md
docs/design/dem-api.md
docs/design/dem-ui.md
docs/design/dem-roadmap.md

Update existing service-path documentation rather than contradicting it.

Include Mermaid diagrams where the repository documentation conventions permit.

Document:
- what is observed
- what is inferred
- confidence semantics
- source independence
- score computation
- data retention
- privacy
- future mobile/replay/agent extension points

============================================================
PHASE V — OUTPUT EXPECTATIONS FOR THIS CLAUDE CODE SESSION
============================================================

Work directly in the repository.

First produce the repository assessment.

Then implement the highest-value coherent vertical slice rather than producing
dozens of empty interfaces.

Prefer a working end-to-end Experience Incident path over superficial breadth.

For every code change:
- follow existing code style
- run formatter
- run lint
- run type checker
- run unit tests
- run integration tests that are available
- preserve existing APIs unless an intentional migration is documented

At completion, report:

1. Existing components reused
2. New architecture introduced
3. Files added
4. Files modified
5. Database migrations
6. APIs
7. UI components
8. Tests added
9. Tests executed/results
10. Known gaps
11. Next recommended vertical slice

CRITICAL PRODUCT PRINCIPLE:

Correlix is not trying to win by showing more telemetry.

Correlix wins when an operator can go from:

"Users say it is slow"

to:

"These users and transactions are affected,
this journey step is failing,
this exact part of the path is implicated,
this change is or is not causal,
these independent observations support the conclusion,
this team/provider owns the failure,
this is the safest action,
and the experience recovered after we took it."

Build toward that outcome.
```