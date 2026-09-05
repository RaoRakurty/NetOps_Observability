# Digital Experience Monitoring (DEM) — market and technical research

**Date:** 2026-09-05 · **Status:** RESEARCH INPUT (not a design). The design is written by the
coordinator from this document.

**Owner brief (2026-09-05):** *"Do good research: consider user endpoints, SD-WAN networks, data
centre, enterprise LAN, all types of enterprise endpoints. Do market research and verify all the
vendors' implementations, and compose a futuristic and robust design with minimal interference or
changes to make DEM work, and a glossy, eye-popping DEM dashboard."*

## How to read this document

- Every factual claim carries a source URL. Anything that could not be verified against a primary
  source is marked **UNVERIFIED** and must not be built on.
- **Research constraint, disclosed honestly.** This session's WebSearch budget was exhausted
  (200/200) early. All vendor research was therefore done by **fetching vendor documentation
  directly** — sitemap enumeration then page fetch; for Zscaler's SPA docs, via the
  `help.zscaler.com/zapi/fetch-data` content API that backs it. Consequence: the **technical
  depth is primary-sourced and strong**, while the **analyst and list-price dimension is
  essentially unverified**, because Gartner, Forrester, G2, TrustRadius and every vendor pricing
  page return 403 to unauthenticated fetches. Licensing **shape** (units, tiers, metrics) is
  documented throughout; licensing **price** is not, for any vendor.
- Two vendors are documented gaps rather than omissions: **`juniper.net` and `cisco.com` refused
  programmatic fetches throughout**, so **Juniper Mist's SLE mechanics** and **Cisco Catalyst
  Center Assurance's health-score weights** are UNVERIFIED. **Kentik** could not be reached at
  all. These are named again in §4 as the research to close first.
- Structure: **§1** vendor capability matrix · **§2** measurement techniques and standards ·
  **§3** the six distillations the brief asked for · **§4** a one-page design-inputs summary.

---

# §1 Vendor capability matrix

## 1.0 Cross-vendor summary table

Read this first; the per-vendor sections carry the evidence.

| Vendor | Primary vantage point | Agent? | Score published? | Signature capability | Third-party data egress |
|---|---|---|---|---|---|
| **Cisco ThousandEyes** | Cloud agents in 200+ cities · Enterprise agents (VM/Docker/IOS-XE/Catalyst 9k/Nexus/Meraki MX) · Endpoint agents | Both | **No** (endpoint score = single input, unpublished curve) | Path Visualization + Internet Insights (cross-customer outage corroboration) | API v7 (240 req/min org-wide) + OTel **subset — no path hops, no HAR** |
| **Catchpoint (now LogicMonitor)** | Global node network · endpoint (Workforce Experience) | Both | Reportedly the only published end-user formula (**partially verified**) | Internet Sonar / Internet health | UNVERIFIED |
| **Broadcom AppNeta** | Monitoring Points (HW/virtual/container/host) | Agentless-leaning | UNVERIFIED | Continuous TruPath at 20–50 packets/min | UNVERIFIED |
| **Kentik** | Flow + synthetic agents | Both | UNVERIFIED | Flow ⨯ synthetics ⨯ BGP in one platform | UNVERIFIED |
| **Zscaler ZDX** | Client Connector endpoint · browser ext (RUM) · 19 named cloud DCs (Managed Monitoring) · Service Edges | Agent-first | **Yes, fully** (66/34 bands, min-reduction) | Cloud Path hop view + ISP blackout/brownout incident typing | ZDX APIs + 6 webhook targets, **tier-gated**; **14-day max retention** |
| **Netskope P-DEM** | Client (active) · browser ext (passive) · Enterprise Stations | Both | **Yes** (71/31 bands; refuses <2 of 4 contributions) | Published hop/link-delay arithmetic incl. failure modes | UNVERIFIED |
| **Palo Alto Prisma SD-WAN + ADEM** | GlobalProtect-based agent · agentless on ION devices | Both | **Yes** (70/30 bands) | 30-second network sampling; cross-tenant baseline fallback | UNVERIFIED |
| **HPE Aruba UXI** | Dedicated hardware sensor (Wi-Fi 7 / 6E) + Win/macOS agent | Hardware-first | **No score at all** — threshold + triage | Vendor-neutral sensor; triage PCAP attached to the failure | **Push-only**: S3/BigQuery/Elasticsearch/HTTP/Splunk/BigPanda. API is config+status only |
| **Aruba Central AIOps** | Infrastructure telemetry | Agentless | Bands only, **no formula** | Peer-comparison across classified sites | Classic: **"No external APIs currently available"**. New Central: ~400 endpoints + HMAC-signed webhooks |
| **Aruba EdgeConnect** | SD-WAN appliance | Agentless | No | Pre/post-FEC loss, pre/post packet-order-correction, MOS per tunnel | Orchestrator REST (rate limits undocumented) |
| **Riverbed Aternity / Alluvio** | Endpoint agent (UI-thread instrumentation) | Agent | (see §1.9) | Global industry benchmark comparison | (see §1.9) |
| **Nexthink** | Collector agent + browser ext | Agent | DEX score (see §1.9) | Sentiment (Engage) + remote actions (Act) | (see §1.9) |
| **Datadog / Dynatrace / Splunk-AppD** | Cloud synthetics + RUM + eBPF NPM | Both | Apdex / UX score | Full-stack correlation | (see §1.9) |
| **Juniper Mist** | AP/switch/SSR infrastructure telemetry | Agentless (+ SDK) | **UNVERIFIED — see §1.6** | SLE framework (the market benchmark) | API **5,000 calls/hour per token**; **Premium Analytics has NO API** and is 12–36 h stale |
| **Cisco Catalyst Center** | Network device telemetry + AP sensors | Agentless | **UNVERIFIED — see §1.7** | Client 360 / Intelligent Capture | UNVERIFIED |
| **Cisco Catalyst SD-WAN (vManage)** | BFD on overlay tunnels + on-box ART | Agentless | Bands only (QoE ≥8/5–8/<5); **formula unpublished** | DSCP-aware probing (probe rides the class's QoS queue) | **IPFIX v10, 4 collectors/device, 1:1 unsampled, carries BFD latency/loss/jitter** — the cleanest egress found |
| **Cisco Meraki + Insight** | **MX-resident passive DPI** (in-path) | Agentless | Thresholds published; **19-rule numeric RCA book** | LAN/WAN/server split from TCP SYN/SYN-ACK + HTTP timing | API **10 req/s per ORG shared across all tools**; webhooks; MR MQTT 1 s client RSSI |
| **Versa** | SASE client + VOS | Both | **No** — and **rank is inverted (1 = best)** | Four independently toggleable monitoring categories | **DEM logs exportable only to Versa Analytics — hard wall** |
| **Fortinet** | Endpoint agent · public probes · OnSight collector · **FortiGate itself** | Both | Inputs only, **formula unpublished** | **Passive/prefer-passive mode — path metrics with zero probe traffic**; TWAMP; MOS as a link-selection cost | Rate-limited API + broad ITSM |

---

## 1.1 Cisco ThousandEyes

**Vantage points.** Cloud Agents in *"over 200 cities"*
(https://docs.thousandeyes.com/product-documentation/global-vantage-points/cloud-agents.md);
Enterprise Agents as Docker/VM/appliance (TEVA needs VMXNET3 + bridged networking; TEPA is
validated on specific ASUS/Intel NUC models, **wired only**); embedded on **Catalyst 8000
routers, Catalyst 9300/9400 switches, Nexus 9300–9800 (NX-OS 10.3(3)F+, no BrowserBot)** and
**Meraki MX**; Endpoint Agents on Windows/macOS.

**Footprint — the one hard number in the market.** IOx reservation on Catalyst routers and
switches, from `show app-hosting detail`: **memory 500 MB · disk 1 MB · CPU 1850 units (9%)
· 1 vCPU**
(https://docs.thousandeyes.com/product-documentation/global-vantage-points/enterprise-agents/installing/cisco-devices/installation-methods/installing-enterprise-agents-on-cisco-routers-with-application-hosting.md).
Docker install requires **`--cap-add=NET_ADMIN --cap-add=SYS_ADMIN`** plus a shipped seccomp
profile and AppArmor
(https://docs.thousandeyes.com/product-documentation/global-vantage-points/enterprise-agents/installing/docker-based-agent-installation.md).
BrowserBot runs **only on Ubuntu in Docker**; there is **no native Windows/macOS Enterprise
Agent**.

**Capacity model — worth copying.** Capacity is expressed **behaviourally, not as a hardware
table**: a `utilization` figure per queue (**Browser, General, Bandwidth, Voice**) exposed on
`GET /v7/agents/{id}`, with the explicit statement that adding CPU/RAM *"is generally not
effective in reducing utilization"* — the remedies are more agents, longer intervals, shorter
timeouts, or disabling bandwidth sub-measurements
(https://docs.thousandeyes.com/product-documentation/global-vantage-points/enterprise-agents/managing/enterprise-agent-utilization.md).

**Synthetic load, published per round** (rare, and the number to design against):
agent-to-server TCP **245 packets / 27,346 B**; the same test **with bandwidth measurement
806 packets / 485,368 B** (~18× the bytes); ICMP 194 / 28,280; DNS-server across 4 servers
16 / 1,632; DNS trace 10 / 1,637
(https://docs.thousandeyes.com/product-documentation/tests/network-utilization-from-enterprise-agent-test-traffic.md).

**Endpoint agent — what it actually collects and installs.** Four components (`te-agent`
service, `te-browserhelper`, browser plugin, updater); **installs the Npcap driver on
Windows**; macOS supports the three most recent major versions; **Firefox and Safari
unsupported**. Collects BSSID, channel, signal dBm, **retransmission rate**, roaming and
channel-swap events, battery charge and health, free disk, **device serial number**, and on
mobile RSRP/RSRQ/SINR. Local probes fire as a **once-per-minute burst**. Browser capture is
metadata only and **`Cookie`, `Set-Cookie`, `Authorization` are dropped at collection**
(https://docs.thousandeyes.com/product-documentation/global-vantage-points/endpoint-agents/how-endpoint-agents-work/data-collected-by-endpoint-agent.md).

**The session ⟷ path join (the identity answer).** When a user hits a monitored domain,
`te-browserhelper` creates a **sample** = network profile + active tests (ICMP ping, **ICMP
Paris traceroute** to destination-or-proxy, VPN ping/trace, gateway ping); HAR streams in
near-real-time; **a new sample is linked to the session every 10 minutes**; a session is one
visit to a domain **per protocol** (http and https are distinct). So the model is
*session ⟷ sample ⟷ (network profile + path) at ~10-minute resolution, keyed to a machine ID.*

**Scoring — a black box, and doubly named.** The endpoint **Experience Score is built on a
single input (DOM load time) mapped through an unpublished curve**, and the platform ships
**two unrelated features both called "Experience Score"** (endpoint, and WAN Insights quality).
Segment sub-scores (network / connection / agent) have no published formula. Contrast with
Provider Intelligence, whose min-max/harmonic-mean method **is** published. **Net: ThousandEyes
publishes its provider-comparison math but not its user-experience math.**

**Alerting — the strongest in the market.** *Adaptive sensitivities* with illustrative trigger
thresholds high ≈60%, medium ≈80% (clear 20%), low ≈90%, default medium, plus a **"Why Did This
Alert Trigger?"** tab showing observed-vs-expected and the issue-probability curve crossing the
threshold
(https://docs.thousandeyes.com/product-documentation/alerts/creating-and-editing-alert-rules/adaptive-alerting.md).
*Dynamic baselines*: quantile (recomputed every 15 min) or classic stddev/percent/absolute
(every 5 min), 24-h lookback, ≥24 points, defaults **2σ** or **20%**
(https://docs.thousandeyes.com/product-documentation/alerts/creating-and-editing-alert-rules/dynamic-baselines.md).
Default rules include **Voice MOS ≤ 3**, **SSL cert expiring within 30 days**, and — the pattern
worth stealing — **endpoint network loss ≥25% on 3 agents AND 30% of agents** (absolute count
AND fleet percentage)
(https://docs.thousandeyes.com/product-documentation/alerts/default-alert-rules.md).
A separate **Event Detection** layer tags results by component and computes endpoint impact as
**min(Agent Impact, Failure Volume, Detection Confidence)** — low confidence caps severity
(https://docs.thousandeyes.com/product-documentation/event-detection.md).
**Gotcha: suppression windows are UTC-only and ignore DST**, so they drift an hour twice a year
(https://docs.thousandeyes.com/product-documentation/alerts/alert-clearing/alert-suppression-windows.md).

**Retention is per-artifact, and asymmetric.** UI **31 days** but API **90 days** for standard
synthetics; **per-hop path visualization only 30 days via API**; HAR/screenshots/console
**45 days**; endpoint dashboards 90 / API 30; Activity Log 13 months; **test snapshots
indefinite — the only permanent artifact**
(https://docs.thousandeyes.com/product-documentation/user-management/user-activity/how-long-is-data-accessible.md).

**Licensing.** Five metrics in the Cisco Offer Description (EDCS-23923776 v3.3, 2026-03-18):
**Units** (per unit/month), **Endpoint Agent Licenses per Active User** (Embedded/Essentials/
Advantage, 30-day reassignment lock), **Connected Devices**, **Cloud Insights**,
**Site-Based Offerings**. Bundles: Campus & Branch Assurance (10,000 Units + 100 Essentials
endpoints + 1 Internet Insights package), Data Center Assurance (5,000 Units + Cloud Insights
Essentials), Collaboration Assurance (5,000 Units + 500 Essentials endpoints)
(https://www.cisco.com/c/dam/en_us/about/doing_business/legal/OfferDescriptions/ThousandEyes-Cloud-Service-Product-Description.pdf).
Consumption: rate depends on **agent type × test type × interval × timeout**; **nested layers
are free and disabling them saves nothing**; unused units **do not roll over**; overage cap
defaults to **115%**
(https://docs.thousandeyes.com/product-documentation/user-management/usage-and-billing/test-layers-units.md).
**DNA Advantage Catalyst 9k units may only be spent on Enterprise/Cloud Agent tests**; Catalyst
9000 grants *"22 units per eligible DNA license"*; **Nexus licences are NOT bundled with
Switching Advantage**; Meraki SD-WAN+ grants *"up to 50 free tests"*.

**Reviewer criticism.** PeerSpot 4.2/5 (n=26). Dominant themes: **cost and unit-model opacity**
(*"Licensing complexity arises from the credits system"*), a UI still not unified with Cisco
five years post-acquisition, endpoint licensing singled out, and *"two to three years to fully
realize its value."* Praise: path visualization, historical timeline, stability
(https://www.peerspot.com/products/thousandeyes-reviews). **List prices: UNVERIFIED** —
thousandeyes.com/pricing returns 403.

**Limitations to note.** The Recorder IDE reached **functional EOL 2026-07-26** (replacement is
Chrome DevTools Recorder import); **NTLM proxy auth end-of-support January 2027**; network-layer
data is obtainable only *to* a proxy, never through it; **Core Web Vitals are absent** (a grep
of 634 doc pages found no substantive LCP/CLS/INP/FCP hits — browser metrics are
`DOMContentLoaded`, `load` and HAR); **no Cisco XDR integration** in the 884-URL index.

## 1.2 Catchpoint (now part of LogicMonitor) — PARTIAL

**Corporate change, verified:** `catchpoint.com/internet-sonar` now **301-redirects to
`logicmonitor.com/catchpoint/internet-health`**, whose page title reads *"Internet Health
Monitoring by Catchpoint (Formerly Internet Sonar)"* — Catchpoint operates under LogicMonitor.
**The acquisition date is UNVERIFIED** (not stated on the page).
Positioning: *"use global vantage points to independently validate internet outages"* and
*"independently audit external BGP, ISP, and SaaS provider connectivity boundaries."*
— https://www.logicmonitor.com/catchpoint/internet-health

**UNVERIFIED for Catchpoint:** the node-network composition (backbone/last-mile/wireless/
endpoint), Internet Stack Map, WebPageTest and RUM specifics, Workforce Experience endpoint
agent footprint, licensing, and the concrete visual grammar of the Sonar map. The one
cross-vendor claim carried forward from group-A analysis — that **Catchpoint is the only vendor
publishing an end-user experience formula, and the only one exposing end-user Core Web Vitals**
— should be **re-verified before the design leans on it.**

## 1.3 Broadcom AppNeta — PARTIAL

Verified only indirectly, via cross-vendor comparison in group-A analysis: AppNeta's continuous
path measurement (TruPath) runs at **20–50 packets/minute**, which is the low-water mark for
synthetic load in this market (compare ThousandEyes' 245 packets/round). Monitoring Points come
as hardware, virtual, container and host software, and the product splits into **Delivery**
(continuous path/capacity/loss/jitter/latency, hop-by-hop), **Experience** (synthetic web and
scripted transactions) and **Usage** (flow-based application visibility).
**UNVERIFIED:** all of the above at primary-source level, plus scoring, alerting, identity model
and licensing. AppNeta documentation was not reachable in this session.

## 1.4 Kentik — UNVERIFIED

Not reachable in this session. The intended profile — flow (NetFlow/sFlow/IPFIX/VPC logs)
joined to Kentik Synthetics (mesh/network-mesh/hostname/page-load tests), Kentik NMS, BGP/State
of the Internet, Kentik Kube — is **entirely UNVERIFIED** and must be researched before use.
Its architectural relevance to Correlix is high (it is the closest analogue to "flow + synthetics
+ BGP in one platform"), so this is the **highest-value remaining research gap** after Mist SLE.
## 1.5 Zscaler Digital Experience (ZDX) — the most completely published score

**ZDX Score, exactly as documented**
(https://help.zscaler.com/zdx/understanding-zdx-score):
- Scale 0–100, rounded to whole numbers. **Good 66–100 (green) · Okay 34–65 (amber) ·
  Poor 0–33 (red).**
- *"Zscaler sends a probe from Zscaler Client Connector to an application every 5 minutes…
  **The lowest value within an hour becomes the value for that hour.**"* — worst-case wins, and
  this minimum-taking repeats at every level of the hierarchy.
- Three score types: **Synthetic Probe Score** (Cloud Path or Web probe), **RUM Score**,
  **Combined Score**.
- Inputs — Web probe: **Page Fetch Time, Server Response Time, DNS Time, Availability**.
  Cloud Path probe: **end-to-end latency, packet loss, hops, packet count** (+ jitter on IPv6).
  RUM: page views, route changes, page load time, **Core Web Vitals**.
- **Roll-ups:** *Application score* = for every user who accessed the app, take that user's
  lowest value, sum, divide by user count (worked example 42/76/62 → **60**). *User score* =
  **the app with the lowest value** ("since it represents the user's poorest digital
  experience"). *Organization score* = per interval, the **worst application** represents the
  org, then average the intervals. *Department/Location/City* = lowest among users in the group
  per interval, averaged.
- **Baselines:** the application score is *"based primarily on the Page Fetch Time… compared to
  the **weighted average of the Page Fetch of others in the same region**"* — per-region,
  minimum one active device, **recomputed daily on a rolling 7-day window**.
- **A documented arithmetic quirk:** for a 24-hour range, hourly scores are summed and
  *"divided by 25 (24 hours + 1 for the starting score)"*.
- **Smoothing:** the user trend defaults to a **"Smooth ZDX Score"**; raw is an opt-in checkbox
  (https://help.zscaler.com/zdx/evaluating-user-details).

**Device Health Score** is separate, same 0–100/66/34 banding, driven by CPU, memory and disk
(weights **UNVERIFIED**). Contributing factors collected: CPU, memory, disk usage, **average
disk queue length**, battery, Wi-Fi signal quality, **system crashes** (unexpected
shutdowns/reboots) and **software crashes/hangs**. Devices are classified on a 3×3 grid of
**Hardware Profile (Low/Standard/High)** × **Usage Profile (Light/Normal/Power, 14-day
lookback)** into **Over Provisioned (amber) / Right Sized (green) / Under Provisioned (red)**,
recomputed weekly (https://help.zscaler.com/zdx/monitoring-devices-overview). *This is IT-asset
economics inside a DEM product — nobody else does it.*

**Cloud Path** (https://help.zscaler.com/zdx/evaluating-cloud-path) renders both a **Hop View**
(left-to-right icon chain: client → egress → Public Service Edge → destination, with
**differential latency per leg and the worst leg coloured orange**) and a **Command Line View**
(MTR-style table with hop-direction arrows, region/geolocation, loss % and packets failed).
Notable: GRE tunnels display **underlay hops**; the latency on the Service Edge is specifically
the hop to the **first router in the Zscaler DC** (a congestion indicator); interface type
(cellular/Bluetooth/USB/unknown) is drawn as an overlay icon above the client. Protocols: ICMP,
TCP (Conventional / Resilient / Strict), UDP, and **Adaptive** — which is **not supported for
internal applications through Private Access**.

**Incidents = their RCA** (https://help.zscaler.com/zdx/monitoring-incidents-dashboard). Seven
area types — **Device · Wi-Fi · Last Mile ISP · Intermediate ISP · ZIA Public Service Edge ·
ZPA · Application** — with genuinely granular sub-typing: Last Mile ISP splits into
**Blackout** (connectivity loss) vs **Brownout** (degradation); Intermediate ISP distinguishes
**Internal** (hops inside one ASN), **ISP-to-ISP** (at the peering point) and **peering-ISP to
Zscaler DC**. Each incident is plotted with an **epicenter** on a map.
**Network Intelligence** (Advanced Plus only) adds the cleanest published leg decomposition
anywhere: *Client → Zero Trust Exchange* split into **Forward Path (ISP → ZTE DC)** and
**Reverse Path (ZTE → last-mile ISP)*, plus *ZTE → Application*, *Client → Application (Direct)*
and *Client → Application*, with P50 and other percentiles, and ML baseline comparison
(https://help.zscaler.com/zdx/monitoring-network-intelligence-dashboard). Anomaly "rippling"
markers render on the map **only for geolocations with more than 50 users**.

**Agent.** Windows / macOS / Android / Android-on-ChromeOS / iOS. Four processes: `ZSAUpm`
(service), `ZSAUpmInstaller`, **`ZSAScript` (runs remote scripts on the device)**,
`ZUpmApplication` (RUM). EDR/AV allowlisting is mandatory; GPO estates must allowlist **both**
32- and 64-bit paths because binaries live under `%ProgramFiles(x86)%` even on 64-bit
(https://help.zscaler.com/zdx/zdx-module-processes-allowlist). **Footprint: UNVERIFIED** —
only *"negligible additional CPU consumption"*
(https://help.zscaler.com/zdx/understanding-zdx-cloud-architecture).

**Deployment burden.** RUM needs a **browser extension** (Chrome/Edge, Windows+macOS only).
Probe traffic is real traffic — the docs advise scoping probes to relevant user groups to
*"avoid unnecessary traffic"* (https://help.zscaler.com/zdx/configuring-probe). Diagnostics
requires an active probe that has run **≥30 minutes**. **Location-based probe criteria fail
closed** — if device location cannot be determined, the probe is **skipped**.

**Alerting** (https://help.zscaler.com/zdx/about-alerts,
https://help.zscaler.com/zdx/understanding-alert-triggers). Types Application/Network/Device
(+ Incident and Call Quality); severity High/Medium/Low. **Throttling is first-class and worth
copying**: *Alert Only if Repeated* N times in a row · *Number of Active Devices* ·
*Minimum Devices Impacted* (count **or** %) · *In Group* (departments/cities/regions/locations).
**Documented alert display delay: 30 minutes.** Alert history retention **two weeks**.

**Tiers (published in full — the most useful competitive artifact found).** Standard ·
Microsoft 365 · Advanced · Advanced Plus (https://help.zscaler.com/unified/ranges-limitations).
Selected cut lines: **probing interval 15 min on Standard, 5 min elsewhere**;
**query retention 2 days on Standard, 14 days on every other tier**; **Dynamic Alerting,
Root Cause Analysis, Wi-Fi, inventory: Advanced+**; **RUM, Incidents, Network Intelligence,
Device Health Dashboard, Process Inventory, Self Service, ZDX Copilot: Advanced Plus only**;
alert rules 3 / 10 / 25 / 100; Data Explorer views 0 / 0 / 30 / 100; webhooks 0 / 10 / 10 / 50;
Managed Monitoring quantified as **1 probe per 1,000 users per managed location**.
Licensing is therefore **per-seat**; **prices UNVERIFIED**.

**Visual grammar** — one colour language across the whole product (green 66–100 / amber 34–65 /
red 0–33, reused for ZDX Score, Device Health, Wi-Fi and provisioning status). Distinctive
idioms: **treemaps** for access points (`tile colour = score band, tile size = user volume`) and
for software inventory by vendor
(https://help.zscaler.com/downloads/zdx/analytics/monitoring-wi-fi-dashboard/ZDX-Wi-Fi-Dashboard-1.png);
a world map with **animated "rippling" anomaly markers** and **Top-5 high-latency ASNs as
baseline-relative bars** (tall red = above baseline, thin = near baseline)
(https://help.zscaler.com/downloads/zdx/analytics/monitoring-network-intelligence-dashboard/zdx-network-intelligence-overview-1.png);
the **user detail page** with a horizontal strip of per-app score cards (worst app
auto-selected) above a banded score timeline whose **drag-to-zoom (5-minute floor)
simultaneously re-scopes web-probe metrics, device health and Cloud Path**
(https://help.zscaler.com/downloads/zdx/analytics/users/evaluating-user-details/zdx-user-details-apps.png);
and the Cloud Path chart whose **click-on-timeline snaps the path below it to that instant**
(https://help.zscaler.com/downloads/zdx/analytics/users/evaluating-cloud-path/zdx-cloud-path-latency2.png).

## 1.6 Netskope Proactive DEM (P-DEM)

**The most epistemically honest documentation of any vendor read.** It states what each
measurement model cannot see, warns that long time ranges dilute incidents, and tells you to
treat the score as triage rather than an SLA.

**Score** (https://docs.netskope.com/en/how-dem-user-experience-scores-are-calculated/):
0–100, **per user, in five-minute windows**, each scored independently; longer ranges average
the windows — *"A sharp fifteen-minute incident inside an eight-hour view is diluted to near
invisibility."* Bands: **Good ≥71 · Fair 31–70 · Poor ≤30**. Interpretation guidance: *"A score
moving from 78 to 74 is noise. A score moving from 74 to 62 has crossed from Good into Fair."*

**Four contributions:** **Device** (is the endpoint in the way?) · **On-Ramp** (device → POP) ·
**SaaS/Custom App** (POP → app, and app responsiveness) · **Private App** (through Netskope to
the Publisher). **The composite requires data from at least 2 of the 4 or it renders nothing** —
the doc ships an explicit truth table showing every single-category case → "Score Unavailable"
(https://docs.netskope.com/en/understanding-digital-experience-management-dem-scores/).
*Failing loud rather than emitting a misleading number is the single best design idea in this
whole survey.*

**Active vs passive, stated plainly:** the **Client** is *active* (generates its own
measurements on a schedule; sees the whole device and all steered traffic; but *"measures the
path rather than the user's perception — it cannot see how long a page took to render"*); the
**browser extension** is *passive* (real browsing timings; *"goes quiet when the user is idle,
and can see far less of the device"* — blind to disk, Wi-Fi signal, thermal state and paging).

**Metrics.** Client device (scored): processor headroom, available memory, available disk,
wireless signal strength; collected-not-scored: disk/network throughput, battery. Extension
(scored): processor utilization vs logical-processor count, free memory. On-Ramp: client probes
device→POP RTT (*"networks that drop or deprioritise ICMP and UDP can prevent this data being
produced"*); extension gives TCP connect and TLS handshake time from real traffic.
SaaS: client measures POP→app RTT plus scheduled HTTPS app probes broken into **DNS, connection
setup, TLS handshake, TTFB, content transfer**; extension scores **traditional pages on LCP**
and **single-page apps on the duration of their own fetch/XHR/beacon requests** — the latter
*"calculated by **ranking a session against other sessions in your tenant over a rolling
three-day window**"*. **A tenant-relative percentile score is unique in this survey.**

**Documented blind spots (all from
https://docs.netskope.com/en/understanding-digital-experience-management-dem-scores/):** client
must be online with an active Internet Security Tunnel; endpoints need **>10 MB free disk**;
**hidden Wi-Fi networks may not be detected by standard Windows APIs, causing the Wi-Fi
sub-score to report 0**; **Windows performance counters are English-only**, so localised OS
builds break throughput collection; scores can be **recalculated for up to 1 hour** after first
generation.

**Synthetic probes** (https://docs.netskope.com/en/synthetic-probes/). *Network Probes*:
traceroute principle over ICMP or UDP, **UDP source ports 33435–33535**, **minimum 6 probing
segments per hop escalating to 12**, interval **5 minutes–1 hour in 5-minute steps**; a router
that drops silently is *"still identified in the path visualization graph but no performance
metrics can be computed."* *App Probes*: run against **the top three domains determined by
analysing real tenant traffic** — traffic-informed auto-configuration.

**The steering gymnastics are the real deployment cost.** **Network Probes must NOT be steered**
through Netskope (to see the underlay) and require a PBR rule on the corporate firewall to
bypass the tunnel; **App Probes MUST be steered** (to mimic users) and require the opposite PBR
rule and no SSL DND policy. And: *"If your corporate site has multiple secured tunnels… you have
to deploy **one dedicated Enterprise Station for each tunnel**."* Enterprise Stations auto-probe
**the top two POPs**, chosen once — *"There is no automatic update."*

**Published path arithmetic** (https://docs.netskope.com/en/performance-metrics/) — rare and
directly reusable: RTT = mean of test RTTs across all paths; **E2E packet loss** = no-response
count / test count, and *"if the target is not reached, the packet loss takes the furthest
discovered router into account"*; node-level loss with an explicit **correction algorithm** when
the target is reached; **Link Delay = MIN_RTT(n+1) − MIN_RTT(n)** using minima, with the honest
failure mode that *"node 7 may respond quicker than node 6, leading to a negative network delay…
the Netskope interface will not report any value"*. Aggregation default average; **P50/P75/P90/
P99 selectable**.

**AI.** The **DEM Data Intelligence Agent** is a natural-language interface over DEM telemetry
("Which applications are slow?") covering application performance, user experience, device
health, network/site analysis and **root-cause correlation**; **DEM Enterprise Starter and
Enterprise tiers only**; answers *"typically arrive in well under a minute"*
(https://docs.netskope.com/en/dem-data-intelligence-agent/).

**Tiers:** DEM Standard · Professional · Enterprise Starter · Enterprise (the last adds
Enterprise Stations and App Probes under an "Advanced Diagnostics" menu). **Licensing unit,
full feature matrix, retention, alert-rule surface and notification channels: UNVERIFIED.**
**Borderless SD-WAN documentation is behind a login wall** — SD-WAN edge telemetry, SLA path
selection and SD-WAN licensing terms are consequently **UNVERIFIED**
(https://docs.netskope.com/en/borderless-sd-wan/).

## 1.7 Palo Alto Prisma SD-WAN + ADEM

**Score:** 0–100, **Good ≥70 · Fair 30–69 · Poor <30**. Synthetic score is built from
**TTFB (= DNS + TCP + SSL + server response time) plus availability**; the RUM score is
**min(LCP score, INP score)**; **RUM overrides synthetic entirely when present**; availability
of 0 forces the score to 0. Remote sites score as the **average of active paths**.
**Cadence: ICMP every 30 seconds**, HTTP/S every 5 minutes — the fastest sampling in this survey.

**Baselining — the most sophisticated found.** Percentile-based dynamic baselines over
**30 days of history, refreshed every 24 hours**, clustered by **(City + ASN + PA Gateway)**,
**(City + LAN Gateway IP)** and **(PA Gateway)**, requiring **≥20 agents per cluster**, with a
**cross-tenant fallback** when a tenant's own cluster is too small. *That fallback is the
mechanism behind "compare me to peers" and it is the hardest thing for a single-tenant product
to replicate.*

**Agent transparency — best in class.** Palo Alto publishes **14 named agent processes,
including `mtr`, `curl` and `tcping`**, each with its **privilege level** (Local System /
Network Service / Local Service / logged-in user)
(docs.paloaltonetworks.com/autonomous-dem/administration/agent-processes-windows). Agentless
ADEM runs on **ION** devices. Tests run **regardless of VPN state**, and remote sites measure
**all WAN paths including backup**.

**Licensing:** per **mobile user** plus per **remote site**, and the counts **must match the
Prisma Access base licence exactly — no partial tenant**. Current packaging is **Strata Cloud
Manager Pro**; legacy SKUs were *ADEM Observability* and *AI-Powered ADEM*. **Prices
UNVERIFIED.**

**UNVERIFIED:** the mobile-user org-level roll-up arithmetic, the alert-rule configuration
surface, and ITSM/webhook integrations.

## 1.8 Versa — capable, but a closed data wall

Four **independently toggleable monitoring categories** — Device, Internet, Local Network,
Application — so DEM can run with **zero synthetic probe traffic**. Four **fault-class map
lenses** (Local / WiFi / Internet / Application) are the primary triage idiom. Per-SSID
**transmit and receive bandwidth** (not just signal strength), **time to last byte** as well as
first byte, **ISP name and ISP location enrichment on every responding traceroute hop**, and an
explicit **inactivity bar** drawn on the x-axis when no data exists (Releases 22.1.4+) rather
than a misleading gap.

**Three hard problems.** (1) **The DEM rank is inverted — 1 is best** on a 1–100 scale, and is
internally inconsistent with Versa's own 0–100 Wi-Fi scale; **the formula, weights and bands are
unpublished**. (2) **DEM logs are a proprietary format exportable only to Versa Analytics nodes
— no third-party export.** (3) **No documented DEM alerting, baselining, anomaly detection or
AI/ML.** Default probe interval **300 seconds** (the coarsest here); **3 applications per tenant
unless DEM is explicitly enabled** (then 50). Agent OS support, footprint, privileges and
licensing: **UNVERIFIED**.
Sources: docs.versa-networks.com — *Configure Digital Experience Monitoring* (Director and
Concerto), *View Digital Experience Monitoring Dashboards*, *Active Application Performance
Monitoring Logs*.

## 1.9 Fortinet — three products, no unified score

**FortiMonitor UX Score** is 0–100 (higher better) and — uniquely — is scored **per
(location, target) pair**, so one application carries **multiple simultaneous scores, one per
observer**; hovering a score expands to the per-vantage-point breakdown
(https://docs.fortinet.com/document/fortimonitor/26.2.0/user-guide/337449/ux-score).
Inputs: **Network** (HTTP response time, DNS lookup, latency, jitter, packet loss) measured from
an OnSight or public probe; **Application** (CPU, memory, Wi-Fi signal strength, download and
upload speed) collected by the DEM agent. **The weighting and the roll-up to an "overall UX
Score" are not published — UNVERIFIED**, as are the band thresholds.

**Four vantage-point classes — the broadest mix here:** endpoint agent (Windows/macOS), public
probes, **OnSight / OnSight vCollector** on-prem, and **FortiGate SD-WAN devices themselves**.
The endpoint agent runs jitter, latency, **MOS** and packet-loss checks, HTTP/HTTPS synthetics,
**traceroutes**, download-speed tests, and collects Wi-Fi Rx/Tx rate and signal strength; it can
also trigger **CounterMeasures** (automated remediation)
(https://docs.fortinet.com/document/fortimonitor/26.2.0/user-guide/190924/endpoint-agent).
Fortinet positions endpoint DEM partly as a **site/retail monitor**, not only a
knowledge-worker tool.

**FortiGate SD-WAN Performance SLA is the technique library.** Probe modes: **Active**
(constant measurement, *"does add some overhead"*), **Passive** (*"session information captured
by firewall policies is used to determine latency, jitter, and packet loss… not generating
additional traffic, and does not require the performance SLA to define a specific server"*), and
**Prefer-passive** (traffic when there is traffic, probes when there is none). Protocols:
`ping`, `tcp-echo`, `udp-echo`, `http`, **`twamp`**, `dns` (HTTPS added in 7.4.1). Six
predefined SLA profiles ship by default (AWS, DNS, FortiGuard, Gmail, Google Search, Office 365).
**Probes can be QoS-classified** with `class-id`
(https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/867342/performance-sla-overview,
https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/941705/classifying-sla-probes-for-traffic-prioritization-new).

**MOS as a routing input.** `mos-codec` ∈ {g711 (default), g729, g722}; `link-cost-factor` may
include **mos**; `mos-threshold` **1.0–5.0, default 3.6**. The box will re-path traffic to defend
a voice-quality target
(https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/998548/mean-opinion-score-calculation-and-logging-in-performance-sla-health-checks).

**FortiAIOps is the deepest wireless DEM found.** *"deployment-specific and adaptive learning
AI/ML model, that automatically adjusts whenever there are changes in the RF environment"*, with
a **weekly (Saturday) re-analysis** over the past week's data and model updates logged locally.
SLA thresholds are derived **dynamically by clustering clients on connection quality**, with
static overrides available. Wireless SLAs: Throughput, Coverage, Roaming, **Time to Connect
(thresholds per AP-client environment and per phase — association, authentication/4-way
handshake, DHCP)**, **Connection Failure (staged by cause: association/low RSSI, auth/RADIUS
unreachable, DHCP, DNS)**, AP Health and Uptime, WIDS
(https://docs.fortinet.com/document/fortiaiops/3.0.0/user-guide/133572/overview).
**But it is a separate product with its own console — nothing joins FortiAIOps and FortiMonitor
into one user-experience number.**

Alerting inherits Panopta's maturity: alert timelines/escalation, **flapping detection**,
multi-server outage correlation, SMS and voice, **outage simulation**, CounterMeasures
remediation. Integrations: FortiSOAR, Jira/JSD, Salesforce, Security Fabric, Azure AD SSO, AWS/
Azure/GCP/Kubernetes, a **rate-limited API**. **True multi-tenancy** (subtenants, multi-tenant
dashboards) — MSP-ready, unlike the SASE-native tools. **Data model is infrastructure-shaped**
(instances, templates, location/target pairs), **not identity-shaped** — there is no documented
join to an IdP for per-user experience. **Licensing and agent footprint: UNVERIFIED** (zero of
689 enumerated FortiMonitor doc URLs matched licensing/pricing).
## 1.10 Juniper Mist — the benchmark, and the biggest verification gap

**Honest statement:** the Mist **SLE framework itself could not be verified from a primary
source in this session.** `juniper.net` documentation pages returned 404 or reset the connection
on every attempt (both by the research agent and directly), and `mist.com` reset. **Do not anchor
the design on remembered Mist SLE mechanics.** The following are explicitly **UNVERIFIED**: the
Wireless SLE list and their official names; the Wired and WAN SLE lists; **the SLE computation
(user-minutes denominator, success/failure attribution, the percentage formula)**; the classifier
/ sub-classifier hierarchy and default thresholds; Marvis Actions; the Marvis conversational
assistant; **Marvis Minis**; the Mist client SDK; WAN Assurance with SSR/SRX; per-AP/per-switch
SKUs; webhook topics and HMAC signing; WebSocket channels; and the SLE dashboard visual grammar.

**What *is* verified, and it matters for integration:**
- **Rate limit: 5,000 API calls per hour, per API token**, signalled by HTTP 429, with **no
  rate-limit response headers documented**. 401 = bad token; 403 = insufficient privilege
  (https://www.juniper.net/documentation/us/en/software/mist/automation-integration/topics/concept/rest-api-http-response-codes.html).
- **12 regional API endpoints**: `api.mist.com`, `api.gc1/gc2/gc4.mist.com`, `api.ac2.mist.com`
  (Global); `api.eu.mist.com`, `api.gc3/gc6.mist.com`, `api.ac6.mist.com` (EMEA);
  `api.ac5/gc5/gc7.mist.com` (APAC)
  (https://www.juniper.net/documentation/us/en/software/mist/automation-integration/topics/topic-map/api-endpoint-url-global-regions.html).
- **Premium Analytics — three quotable constraints**: *"Premium Analytics stores data for up to
  13 months"*; **"No, Premium Analytics does not support API. Premium Analytics is a data
  visualization tool."**; *"The data is refreshed once a day"* — collection stops at 00:00 UTC,
  ~12 h processing, available ~12:00 UTC, i.e. **effective staleness 12–36 hours**. Base SKU
  `SUB-PMA`. **"End users cannot create custom dashboards"** — Juniper engineering builds them
  case by case
  (https://www.juniper.net/documentation/us/en/software/mist/mist-analytics/topics/concept/frequently-asked-questions-for-analytics.html).

**Corporate context, verified:** HPE **closed its acquisition of Juniper Networks on 2 July
2025** (~$14 B)
(https://www.hpe.com/us/en/newsroom/press-release/2025/07/hewlett-packard-enterprise-closes-acquisition-of-juniper-networks-to-offer-industry-leading-comprehensive-cloud-native-ai-driven-portfolio.html,
https://www.datacenterdynamics.com/en/news/hpe-closes-14bn-acquisition-of-juniper-networks/).
The Aruba Developer Hub now lists **Central, Classic Central, Mist, ClearPass, EdgeConnect,
Apstra, Junos and UXI side by side** (https://devhub.arubanetworks.com/get-started/home) — merged
at the developer-portal layer, not the product layer. **Any Mist-vs-Central/UXI roadmap is
UNVERIFIED.**

## 1.11 Cisco Catalyst Center (DNA Center) Assurance — UNVERIFIED

**One line, honestly:** no Catalyst Center Assurance claim could be verified from a primary
source in this session; repeated fetches of the 2.3.7 Assurance user-guide chapters and the
DevNet rate-limit pages returned 404 or socket hang-ups. **Everything in the brief for this
vendor is UNVERIFIED** — Client Health Score component KPIs and thresholds, Network Device Health
Score weights, Application Health / NBAR+AVC scoring, Intelligent Capture, the Aironet Active
Sensor test catalogue, Path Trace, AI Network Analytics baselining, Intent API and
`/dna/data/api/v1/...` Assurance Data endpoints, AssuranceEvents, rate limits, the event/webhook
framework, DNA Essentials/Advantage gating, and Client 360's visual grammar.

**Two adjacent facts that were verified:**
- **ThousandEyes WAN Insights is bundled with Cisco DNA Advantage** for SD-WAN and Routing at no
  extra charge, but capped — *"you are entitled to use PPR/WANI for up to a total of **six
  applications or application lists per SDWAN fabric**, regardless the number of DNA Advantage
  licenses"*; **DNA Essentials includes nothing**
  (https://www.cisco.com/c/en/us/products/collateral/software/one-wan-subscription/nb-06-dna-sw-rout-sub-faq-ctp-en.html).
- **Catalyst 9000 switches with DNA Advantage/Premier carry a claimable ThousandEyes unit
  entitlement** deposited into the customer's Smart Account
  (https://www.cisco.com/c/dam/global/en_au/solutions/enterprise-networks/pdf/cisco-thousandeyes-ordering-guide.pdf).

## 1.12 Cisco Catalyst SD-WAN / SD-WAN Manager (vManage)

**Thesis:** it measures *overlay tunnel health* (BFD-derived), *SaaS path quality* (HTTP probes
from candidate egresses) and *on-box flow/ART telemetry*. **It does not measure end-user digital
experience** — Cisco's answer for that is ThousandEyes, sold separately and hosted on the router.

**Application-Aware Routing.** SLA class = a threshold triple; configurable ranges **loss
1–100 %, latency 1–1000 ms, jitter 1–1000 ms**. Predefined classes (re-tuned in 17.15.1a):
Voice-And-Video 2 % / 300 ms / 60 ms · Transactional Data 1 % / 200 / 200 · Bulk Data and
Default 5 % / 500 / 500; **the default class is no longer configurable from SD-WAN Manager
20.12.x**
(https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/policies/ios-xe-17/policies-book-xe/application-aware-routing.html).

**The probe substrate is BFD** at **1 packet/second**: loss from failed BFD echo requests,
latency from request→reply RTT, jitter from arrival-timing variation. Defaults: **BFD hello
1 s · app-route poll interval 600,000 ms (10 min) · multiplier 6 (range 1–6) · BFD control DSCP
48**. Six sliding buckets, 0 newest → 5 oldest, ~600 hellos per bucket:
> *"For the default poll interval of 10 minutes and the default multiplier of 6, the loss,
> latency, and jitter information collected over the last hour is considered when classifying
> the SLA of each tunnel."*

**Net detection latency at defaults: up to ~60 minutes of averaging before a tunnel is
reclassified.** **Enhanced AAR** (17.12.1a / 20.12.1) fixes this — Cisco's own problem statement
is *"devices require several minutes to switch traffic"* — with PfR poll intervals of
**10 s (Aggressive) / 60 s (Moderate) / 300 s (Conservative)**, taking best-case detection to
~60 s, but only when explicitly enabled
(https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/policies/ios-xe-17/policies-book-xe/m-enhanced-application-aware-routing.html).

**A structural blind spot, in Cisco's words:** *"if the data policy rules contain actions such as
redirect DNS, NextHop, secure internet gateway, NAT VPN, or service, the traffic which matches
those rules will skip AAR policy… Data policy actions override AAR rules."* — **the most common
DIA/SIG constructions are precisely the ones AAR does not govern.**

**DSCP-aware probing — the best single technique in this survey.** *"The forwarding class
determines the QoS queue in which the BFD echo request is queued at the egress tunnel port"*, so
each app-probe-class probe experiences the same queueing as the traffic it represents; probes
rotate round-robin; **maximum 6 app-probe-classes**.

**Cloud OnRamp for SaaS and vQoE.** Probes are HTTP/HTTPS (port 80 for IP endpoints, 80 or 443
for URLs). The probe algorithm appears in **no configuration guide** — only in Cisco Live
BRKENT-3412 (EMEA 2023) slide 10: *"Decision on picking interface is based on 12 minutes
measurements · Moving average of 6 buckets of 2 mins each · 1 HTTP/HTTPS Ping per second ·
Send 10 pings & sleep for 20 seconds · Collect 4 sub-buckets of 30 seconds"* → a **12-minute
decision window at ≈20 probes/minute per application-group × path**
(https://www.ciscolive.com/c/dam/r/ciscolive/emea/docs/2023/pdf/BRKENT-3412.pdf).
vQoE: *"calculated based on average loss and average latency. For Office 365 traffic, other
connection metrics are also factored in"*; bands **8–10 green / 5–8 yellow / 1–5 red**, with
**0.0 = no data yet**; and crucially **decorative** — *"monitoring indicators and are **not
failover thresholds**"*, and it *"does not directly influence the… determination of best path"*
(https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/cloudonramp/ios-xe-17/cloud-onramp-book-xe/cloud-onramp-saas.html).
**The loss→score and latency→score transfer functions are unpublished — UNVERIFIED.**
Microsoft 365 telemetry returned to the router is a **tri-state (OK / NOT-OK / INIT)**, not a
continuous metric. Webex metrics *"supplement probing data but do not influence path selection"*
but do carry genuine application-reported experience: packet loss, jitter, latency, resolution
height, frame rate, media bitrate.

**Scoring surfaces.** QoE bands **Good ≥8 · Fair 5–8 · Poor <5**; tunnel Good = QoE ≥8 **AND**
status UP. The QoE computation is **unpublished — UNVERIFIED**, but the per-application SLA
threshold table it scores against is published: Office 365 / Salesforce / Google Workspace
0.03 loss, 300 ms, 300 ms jitter; **Voice and Webex 0.03 / 300 / 50**; GoTo Meeting 0.01 / 300 /
100 (units unlabelled — reading 0.03 as 3 % is inference, **UNVERIFIED**)
(https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/vAnalytics/vAnalytics-book/vAnalytics.html).
WAN Edge health: Good = CPU <80 % and memory <88 %; Poor = CPU ≥90 % or memory ≥93 %.

**On-box ART.** Application Performance Monitor (17.5.1a, profile `sdwan-performance`) yields
*"server network delay, client network delay, and application delay"* plus retransmissions and
transaction duration; media monitors add RTP jitter and loss. **Sampling is 1-in-N, not full**
(examples use 1-in-10 and 1-in-100); **IPv4 only**; **31–47 applications are explicitly
excluded**, including FTP, Citrix, WebEx media/control and VNC
(https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/policies/ios-xe-17/policies-book-xe/m-application-performance-monitoring.html).

**The clean agentless egress: Cflowd/IPFIX.** **IPFIX v10 over UDP, up to four collectors per
device**, exporting the 5-tuple, application id/category, byte/packet counters including drops,
and **BFD average latency, loss and jitter**. `flow-active-timeout` **60 s**, inactive 10 s, BFD
export interval **600 s**, and **1:1 sampling — *"flows are not sampled"***. (SD-WAN Manager's
own UI shows only 4001 cflowd records at a time — another reason to take the IPFIX feed
directly.)
(https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/policies/ios-xe-17/policies-book-xe/traffic-flow-monitor.html)

**The platform's own admission that always-on detail is unaffordable:** *"By default, Cisco
SD-WAN Manager captures aggregated information about flows… To conserve system resources… only
when you request it… stores the information for a limited time (**3 hours by default**)"*, with
**max 10 devices** having active on-demand entries at once
(https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/Monitor-And-Maintain/monitor-maintain-book/m-troubleshooting.html).
**NWPI** per-flow tracing: **10 concurrent traces per tenant, max 2 per device**, TCP/UDP only,
not on VPN 0, and *"Not all packet traces are captured per flow. The system takes samples."*
Speed Test caveat: *"the speed test sends and receives traffic through the control plane"*.

**Retention is the constraint that shapes everything.** Statistics collection interval default
**30 minutes**; 5 GB per feature by default; allocations refresh nightly; from 20.16.1 the system
*"deletes statistics files older than 14 days"* under backpressure. Single-tenant with SAIE on:
<250 devices → 20 days · 250–1000 → 30 days · **1000–2500 and 2500–12500 → 14 days**
(https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-26-1-combined.html).
**At enterprise scale, detailed application telemetry lives 14 days. Long-horizon experience
baselining is not possible on-box.**

**ThousandEyes on IOS-XE — three gaps that matter.** Runs as an embedded Docker app under IOx;
needs **IOS XE 17.6.1a + vManage 20.6.1, 8 GB DRAM (16 recommended), 8 GB storage**. But:
(1) **browser tests are unsupported** — no page-load or transaction tests, removing the two most
user-representative test types; (2) **probes originating from Virtual Port-Group interfaces
bypass AppRoute data policies entirely** — the agent does *not* measure the path AAR actually
chose for user traffic; (3) results live on the ThousandEyes portal — the SD-WAN guide documents
**no in-vManage ThousandEyes dashlet**; the only native surface is *Analytics > Internet Outages*
(https://www.cisco.com/c/en/us/td/docs/routers/sdwan/17-x/systems-interfaces/systems-interfaces-guide-17-x/monitoring-with-thousandeyes.html).

**API.** `POST /j_security_check` → `JSESSIONID`; `GET /dataservice/client/token` → XSRF token
(writes need `X-XSRF-TOKEN`); session **24 h max, 30-minute inactivity timeout**. **Bulk API
48 requests/minute per node**, other APIs 100 req/s, statistics bulk **2 concurrent**; bulk
`scrollId` **expires after 10 minutes**; stats DB paginates by `scrollId`+`count` while config DB
uses `offset`+`limit`. Concurrency is documented inconsistently — the auth page says **100
concurrent sessions**, the rate-limits page says **250** (**UNVERIFIED which is right**).
Useful endpoints: `POST /dataservice/statistics/approute/fec/aggregation` (loss %, latency,
jitter, **`vqoe_score`**, FEC recovery), `/statistics/approute/aggregation`, `/statistics/dpi`,
`/device/tloc`, `/device/interface`, `/alarms`, and
`GET /dataservice/data/device/statistics/{type}` for bulk (`approutestasstatistics`,
`cloudxstatistics`, `dpistatistics`, `cflowdstatistics`, `interfacestatistics`, `deviceevent`,
`alarm`)
(https://developer.cisco.com/docs/sdwan/authentication/,
https://developer.cisco.com/docs/sdwan/20-10/bulk-api/,
https://www.cisco.com/c/en/us/td/docs/routers/sdwan/26x-later/cc-device-mgmt/ctrl-comp-device-mgmt/basic-sys-settings/rate-limit-for-bulk-api-requests.html).
Northbound: email (1–30/min, default 5), Slack/Webex/custom webhooks (custom from 20.16.1),
syslog, SNMP traps; **no documented Kafka/gRPC streaming — UNVERIFIED**; devices *"store a
maximum of 256 events"* before dropping oldest. **gNMI/model-driven telemetry from Catalyst
8000v in *controller* mode: no Cisco documentation found — UNVERIFIED; verify in a lab before
designing against it.**

## 1.13 Cisco Meraki + Meraki Insight

**The architectural fact that governs everything:** Meraki Insight is an **MX-resident, in-path,
passive DPI collector** — *"Currently, MX has a built-in collector to provide Insight data."*
Two consequences are stated explicitly: *"only traffic that passes through an MX can be
tracked"* (inter-VLAN routing on a downstream MS switch is invisible) and *"MXs that are acting
as Auto VPN Hubs will not be able to analyze traffic arriving over the VPN from Spoke sites"* —
**which breaks exactly the hub-and-spoke topology most SD-WAN customers run**
(https://documentation.meraki.com/SASE_and_SD-WAN/MX/Integrations/MI_-_Meraki_Insight/Product_Information_and_Configuration/Meraki_Insight_Introduction).

**Web App Health — the page-load decomposition, without any client instrumentation:**
- **Network latency** — *"calculated based on the **TCP SYN, SYN/ACK response time**"*
- **Application Response Time** — *"based on the HTTP response time… excluding any Network
  Latency"*, precisely *"the historical average time between the **last HTTP Request packet and
  the first HTTP Response packet**"*
- **Goodput** — *"predicted maximum amount of data that could be transmitted per flow, based on
  network latency and loss"*, computed separately per side
(https://documentation.meraki.com/SASE_and_SD-WAN/MX/Integrations/MI_-_Meraki_Insight/User_Guides/MI_Web_App_Health_Overview).
The API confirms the split: `healthByTime` returns **`lanLatencyMs`, `lanLossPercent`,
`lanGoodput`, `wanLatencyMs`, `wanLossPercent`, `wanGoodput`, `responseDuration`, `numClients`**
(https://developer.cisco.com/meraki/api-v1/get-network-insight-application-health-by-time/).
So the model is **client↔MX (LAN) | MX↔server handshake (WAN) | server think-time**, with the MX
as the fulcrum. Thresholds: goodput minimum configurable 10 Kbps–10 Mbps (**default 160 Kbps**);
Application Response Time maximum 100 ms–100 s (**default 3 s**); plus an **"Ignore"** setting
for long-polling/WebSocket apps. Cap: *"we recommend tracking around **10 applications**…
you can track **up to 50**"*; **HTTP/HTTPS only**.

**WAN Health and VoIP are ICMP-derived.** WAN Health pings **`8.8.8.8` every second**
(destination configurable) — *"this measures MX→Google, not MX→your app."* Offline = **100 %
packet loss for 5 minutes**; High Usage = **≥80 %** of the configured ISP limit; **"Poor
Performance" has no published numeric threshold — UNVERIFIED**. VoIP MOS is inferred from
**ICMP probes every second** to a configured media server, banded **>4 Good · 3.5–4 Moderate ·
<3.5 Bad**; **the MOS formula is not published — UNVERIFIED**. And an honesty gap worth naming:
`bestEffortMonitoringEnabled` means *"if the media server doesn't respond to ICMP pings, the
nearest hop will be used in its stead"* — when the SIP server filters ICMP, Meraki silently
measures a different target and still reports it as your VoIP path quality
(https://developer.cisco.com/meraki/api-v1/get-organization-insight-monitored-media-servers/).

**The published root-cause rulebook — Meraki's best asset.** 19 root-cause classes with concrete
numeric triggers, e.g. **ISP Issue** = goodput below threshold AND uplink usage <80 % AND ICMP
ping goodput <2.5 KB; **Uplink Saturation** = goodput below threshold AND usage >80 %;
**MAC Address Flap Anomaly** = MAC learned 3+ times on 2+ ports within 10 s, with ML over 35 days
of hourly counts; **Low VoIP MOS** = below 3.5; **WAN Status Changed** = 5 minutes of 100 % loss
(https://documentation.meraki.com/Platform_Management/Dashboard_Administration/Operate_and_Maintain/Monitoring_and_Reporting/Network_Alerts_and_Notifications/Dashboard_Alerts_-_Insight).
**But RCA scope is narrower than the UI implies:** *"RCA for Web App health will be available
only for causes that are triggered due to **WAN issues ONLY**"* and *"WAN and VoIP health does
not have RCA."*

**Wireless health — published thresholds.** Connection Health (failed attempts): Excellent <5 % ·
Good 5–10 % · Fair 10–25 % · Poor >25 %. Performance Health (average SNR): Excellent ≥35 dB ·
Good 27–35 · Fair 20–27 · Poor <20. **The five-step conditional onboarding funnel** —
**Association → Authentication → DHCP → DNS → Success Rate** — where each step is a percentage
*of the previous step*. "Impacted" thresholds: time-to-connect >5 s · latency >60 ms · loss >3 %
· SNR <27 dB · roam time >3 s, where roam time = *"the delta between dissociation from the first
access point to the first data packet on the new access point"*
(https://documentation.meraki.com/Platform_Management/Dashboard_Administration/Operate_and_Maintain/Monitoring_and_Reporting/Meraki_Health_Overview).
Roaming classes: **Good** <250 ms and RSSI no worse than 5 dBm · **Suboptimal** 250 ms–3 s or
6–10 dBm worse · **Bad** ≥3000 ms or >10 dBm worse
(https://documentation.meraki.com/Wireless/Operate_and_Maintain/User_Guides/Monitoring_and_Reporting/Client_Roaming_Analytics).
Assurance Overview bands **95–100 % Good · 90–94 % Fair · 0–89 % Poor**, with the RF rule
*"Individual AP scores equal the lowest sub-component value"* (**min, not average**).
**Coherence weakness worth citing: four different SNR bandings appear across four Meraki pages
(35/27/20 · 25/15 · 16 · ≥20), and three different "good" bars (95 % vs 95–100 % vs 80 %).**

**Agentless client-side telemetry — architecturally notable.** **Apple Analytics** (firmware
28.1+) surfaces disassociation reason codes directly from Apple clients (DHCP failure, EAP
timeout, 802.1X failure, captive-portal failure, excessive beacon loss); **Intel Analytics**
(Wi-Fi 6+ APs, 28.3+, 802.11w) pulls roaming insights from Intel adapters. **These are real
endpoint-side signals obtained through 802.11 vendor extensions with no agent** — the single
best "minimal interference" idea found in the whole survey
(https://documentation.meraki.com/Platform_Management/Dashboard_Administration/Operate_and_Maintain/Monitoring_and_Reporting/Meraki_Health_Overview/Meraki_Health_-_Client_Details).

**Licensing and retention.** Standalone Insight licensing was **deprecated 2024-07-26**; WAN +
Web App + VoIP Health are **Secure SD-WAN Plus only** (co-term) / **Advantage** (subscription);
**vMX cannot run SD-WAN Plus, therefore no Web App Health**. Retention: event log 12 mo ·
connected clients 3 mo · **client latency real-time 3 hours** · latency stats 2 wk (5-min) /
4 mo (4-h) / 6 mo (1-day). **Insight/Wireless-Health/uplink retention is not published —
UNVERIFIED**; API windows are the proxy: **Insight 7 days**, wireless histories 31 days, packet
loss and channel utilization 90 days, **uplink loss/latency effectively no history**.
**ThousandEyes on MX** needs MX67+ on 18.104+, NAT mode, no vMX; capped at **50 free tests per
org**; **excludes browser/page-load/transaction tests**; **cannot be deployed by API or config
template**.

**API — and the gap list that matters most.** Auth via `X-Cisco-Meraki-API-Key` or OAuth 2.0
(60-min tokens). **Rate limit: 10 req/s +10 burst = 30 in 2 s, PER ORGANIZATION, shared across
every API application the customer runs**; 100 req/s per source IP; 429 carries `Retry-After`
(https://developer.cisco.com/meraki/api-v1/rate-limit/). Rich per-client streams exist —
`connectionStats` (assoc/auth/dhcp/dns failure counts + success), `failedConnections` with
`failureStep ∈ {assoc, auth, dhcp, dns}`, and **`connectivityEvents`** (types assoc/disassoc/
auth/deauth/dns/dhcp/roam/connection/sticky; severities good/info/warn/bad; carries
**`durationMs`**, channel, rssi, captureId; 31-day lookback). Latency is bucketed by **WMM
traffic class** on a power-of-two ladder 0.5→2048 (the unit is documented inconsistently —
**UNVERIFIED**; the bucket edges are solid).

But **the reasoned artifacts are dashboard-only**: no API for WAN Health **jitter**, historical
uplink loss/latency (hard 300 s window, no backfill), VoIP MOS time series, SD-WAN per-tunnel
loss/latency/jitter/MOS, the **conditional onboarding funnel percentages** (API gives raw
counts), time-to-connect distribution, the **Assurance Network Health Score**, Network Service
Health, **roaming classification aggregates**, **RCA attributions and confidence**, ThousandEyes
results, or Apple/Intel Analytics reason codes. **You can rebuild the scoring because the
thresholds are published — but you are re-deriving Meraki's product at 10 requests per second.**
Scale arithmetic: most experience endpoints are **per-network**, so 1,000 networks × 10 monitored
apps = 10,000 calls per cycle ≈ **17 minutes of continuous polling consuming 100 % of the
customer's org-wide API budget.** Prefer org-scoped endpoints, webhooks, and MQTT.

**Other egresses.** **Webhooks**: HTTPS receiver with a **CA-signed cert (self-signed
unsupported)**; source IPs `209.206.48.0/20`, `216.157.128.0/20`, `158.115.128.0/19`; **average
delivery 90 seconds**; **auto-disabled after >100 failed attempts in 24 hours**; **the shared
secret is a bearer value in the body, not an HMAC over the payload** — weaker than
Stripe/GitHub-style signing. **Scanning API v3**: one JSON POST per network per minute per type,
~100 KB per 100 clients, organised by client with `rssiRecords[]` and `latestRecord{time,
nearestApMac, nearestApRssi}`; **triangulation needs 3+ APs**; **MACs are NOT hashed** (unlike
Location Analytics, which SHA1-hashes, salts and truncates to 4 bytes) — a direct privacy
consideration. **MR MQTT**: `Meraki/v1/mr/<NetworkID>/<AP MAC>/<ble|wifi>/<Client MAC>/`,
**minimum publish interval 1 second**, requires MR 28.X+ and an **MR Advanced licence**.
MT sensor MQTT is **QoS 0 — "No guarantee of data delivery"**.

## 1.14 HPE Aruba — UXI, Central AIOps, EdgeConnect

Three products that barely share a data model. UXI appears in Central as a **single "top alert"
field** on a site card.

**UXI sensors.** Current models **UX-7 / UX-7C (Wi-Fi 7, 802.11be, dual tri-band, MLO)** and
**G6E / G6EC (Wi-Fi 6E)**; 1 GbE used for both backhaul and wired testing; BLE 5.x;
**802.3af PoE, 12 W**; UX-7 is 85 × 52 × 300 mm, 627 g; backhaul preference Ethernet → Wi-Fi →
mobile data; **super-capacitors give up to 45 s of reporting during a power cut**
(https://psnow.ext.hpe.com/downloadDoc/HPE%20Aruba%20Networking%20User%20Experience%20Insight%20(UXI)-a00048302enw.pdf?id=a00048302enw,
https://help.capenetworks.com/en/articles/3295755-faq-s).
**Vendor honesty about its own RF:** the sensor has *"limited receive sensitivity"* and
*"throughput measurements from the sensor will be lower than what you can usually measure from a
client"*. **Vendor-neutral is the differentiator** — *"Deliver insights quickly for any network
environment"*, corroborated by a Meraki-AP predefined test and Cisco-specific workaround pages.
**This is the hardest thing for infrastructure-coupled competitors (Mist SLE, Catalyst Center) to
match.**

**Test catalogue.** Core cycle, in order, on every network:
**AP Scan → SSID Check → AP Association → Allocate IP (DHCP) → Gateway → Primary DNS →
Secondary DNS → External Connectivity**, then per-network internal/external service tests,
*"one test at a time… continuous and runs in a round-robin fashion"*, **max 4 networks per
sensor** (https://help.capenetworks.com/en/articles/3529400-user-experience-insight-sensor-test-cycle).
Custom templates: Generic (20 packets on up to 4 TCP ports + 20 ICMP), Webserver (HTTP GET +
status code + **SSL certificate validation**), **VoIP Server (100 packets → latency/loss/jitter →
MOS 1–5)**, Telnet, iPerf2/3, Librespeed, **Web Application Test (replays a Selenium IDE
recording with per-step timing)**, Voice Analysis (real SIP-call MOS)
(https://help.capenetworks.com/en/articles/2744766-custom-test-templates).
Teams MOS method is precise and citable: **100 TCP pings, DSCP 48 on Wi-Fi / 46 on Ethernet, MOS
computed "in accordance with ITU-T Recommendation G.107"**, bands **4.4 optimal · 4.3–4.0
varying · 3.6–3.1 decreasing · <3.1 poor**
(https://help.capenetworks.com/en/articles/5986373-microsoft-teams-voip-mos-test).
Volume: *"approximately **30,000 tests per day, per sensor**"*.

**Path Analysis** is L3 hop-by-hop but better than stock traceroute: **1 packet per hop**,
**matches the parent test's L4 protocol**, all hop probes **in parallel**, with **AS name/number,
DSCP class, geo and cloud-provider** metadata. **Critical gap: it runs only after a *successful*
parent test — a failed transaction produces no path data**
(https://help.capenetworks.com/en/articles/9528214-path-analysis-feature).

**Triage packet capture — the best operational idea found.** Sensors keep a **rolling capture
buffer**; capture is triggered **automatically on test failure** ("triage" mode) as well as on
demand; PCAPs are retained **30 days** and attached to the failure that produced them
(https://help.capenetworks.com/en/articles/1955490-how-does-packet-capture-work).

**There is no score.** UXI's model is **threshold + triage**: a threshold violation on a
*successful* test, or a test failure that triggers *"automated triage mode… a set of predefined
troubleshooting tests to get the root cause"*, comparing wired vs wireless and capturing packets
(https://help.capenetworks.com/en/articles/5137797-types-of-dashboard-issues). Severity is flat
(`ERROR | INFO | WARNING`; status `CONFIRMED | RESOLVED`), with ~200+ issue codes. **AIOps
Incident Detection** is anomaly detection over its own synthetic issue stream: an incident needs
**≥11 co-occurring issues**, **requires ≥20 active sensors**, and **recalculates weekly**
(https://help.capenetworks.com/en/articles/5132163-aiops-incident-detection).
**Identity model:** `customer → hierarchy_node (≤10 levels) → sensor/agent → network → service`.
**There is no user identity, no session, no real-client entity** — `context.mac_address` is the
*sensor's* MAC.

**UXI is no longer sensor-only:** Windows/macOS agents run every **2–5 minutes**, **~1–3 % CPU,
<100 MB RAM** (a rare published footprint), but *"supported application tests are limited to ping
and http get"*, and on macOS the agent collects **location data** — a real PII consideration
(https://help.capenetworks.com/en/articles/11321976-data-collected-by-uxi-agent).
Deployment density: *"usually deployed **1 per 5-8 access points**, or one per retail location,
or one per small building floor"*, mounted **4–5 feet** above the floor.

**Data egress: push-only.** **There is no public REST endpoint for historical test-result time
series.** The API (OpenAPI 3.1, all paths `x-stability-level: alpha`, **5 req/s per customer**)
covers configuration and status only. Bulk telemetry goes out via **Data Push Destinations —
S3, BigQuery, Elasticsearch 7/8, generic HTTP, Splunk (beta), BigPanda (beta)** — four documented
schemas, **"at least once" delivery (duplicates possible), no SLA on pipeline delay**, ~1 KB per
test result (https://help.capenetworks.com/en/articles/5503866-data-push-destinations).
Webhook payloads carry `details, notification_reference, description, severity, status
("ALARM"), start_timestamp`; with Incident Detection on you are notified **only on incident open
and close**; **retry behaviour undocumented — UNVERIFIED**.

**Central AI Insights — and its documented dead end.** Three categories only — **Connectivity,
Wireless Quality, Availability** — with **42 published insights**. Method: an ML model
*"looks for the characteristics of a particular site and classifies each site"*, then establishes
normal behaviour per classification, enabling **peer-to-peer comparison across similar
deployments** (https://arubanetworking.hpe.com/techdocs/central/latest/content/faqs/ai-insights.htm).
**On that same page Aruba publishes three limitations verbatim: "No external APIs currently
available" · "No alert notifications implemented" · "Unavailable in MSP multi-tenant
environments."** In Classic Central, AI Insights is **UI-only — a hard stop for any third party.**
Health scoring publishes **bands but not formulas**, and the bands are internally inconsistent:
wireless client Health Score **0-30 Poor / 31-70 Fair / >71 Good** on one page vs
**Poor 0-25 / Fair 26-50 / Good 51-100** on another, for the same-named column.
**New Central is materially better:** ~400 endpoints including a **Client Onboarding Score API
broken out by stage — `assoc`, `auth`, `dhcp`, `dns`** with `overallScore` and
`BY_CLIENT`/`BY_ATTEMPTS` aggregation
(https://developer.arubanetworks.com/new-central/reference/getclientonboardingscorev1.md),
**CloudEvents + protobuf streaming**, **HMAC-signed webhooks** (`Signature`/`Signature-Input`
over `@method, @target-uri, @authority, @scheme, @path, date`, with key rotation), and an
**MCP server** for LLM agents. **API surface instability is a real risk** — release 2.5.8
*removed* AP-bandwidth, network-monitoring, VPN-usage and UC endpoints. Classic Central limits:
**5,000/day + 7/s, one access token per 30 minutes per client ID**; **Streaming API capped at
5 connections per topic, 1 topic per connection, requiring Advanced licences on every device**;
**webhooks max 10 × 3 URLs, public-CA HTTPS only**.

**EdgeConnect.** Per-tunnel **pre-FEC and post-FEC loss**, RTT (local + remote, max/avg/stddev),
jitter, **out-of-order packets pre and post packet-order-correction**, **MOS**, and brownout
state. **Live View** renders a dual-layer chart — overlay above, underlays below — with tunnel
states **Up / Browned Out / Down**
(https://arubanetworking.hpe.com/techdocs/sdwan/docs/orch/monitoring/tunnel-health/live-view/).
**Application Performance Summary** uses stacked horizontal bars per application:
**orange = Client Network Delay, blue = Server Network Delay**, up to 50 apps
(https://arubanetworking.hpe.com/techdocs/sdwan/docs/orch/monitoring/performance/application-summary/).
**No per-application 0–100 QoE score.** Orchestrator API uses an `X-Auth API Key` header with
read-only/read-write scopes, expiry and an IP allow-list; **rate limits undocumented —
UNVERIFIED**; HPE's own guidance is to *"utilize APIs at the Appliance Level"* to avoid straining
the Orchestrator. Note **"Boost" is now called "WAN Optimization"**, and **Central "Data Explorer"
does not exist** (techdocs search returns "0 result(s)") — treat any such claim as UNVERIFIED.

**UXI licensing:** hardware + **per-sensor cloud subscription** (+ separate LTE subscription for
cellular models); agent licensing is a **pool** — *"Number of cloud subscriptions = Number of
user devices added to the dashboard."* Verified SKUs: `S0U51A`/`S0U52A` (G6E/G6EC),
`S4W52A`/`S4W53A` (Wi-Fi 7); subscriptions `R4W97AAE`–`R4W99AAE` (E-STU) or `S3M51AAS`–`S3M53AAS`
(SaaS); LTE `R4X00AAE`–`R4X02AAE`; agents `S2D97AAE`–`S2D99AAE`. **No published list pricing —
UNVERIFIED.**
## 1.15 Endpoint DEX and APM-side DEM (Aternity · Nexthink · Datadog · Dynatrace · Splunk/AppD)

### Scoring, side by side (all verified)

| Product | Score | Range | Method |
|---|---|---|---|
| **Aternity UXI** | per application | **0–5** | Five inputs — crashes/hour, % hang, % wait, % page errors, average page load — each **flattened to 0 or max outside a narrow meaningful range** (*"anything above, say, 5% [hang] would be unacceptable"*). **Absolute, not baseline-relative.** |
| **Aternity DXI** | per tenant | **0–100** | Weighted average of 5 categories ← components. **Per component: at goal or better = 100; at 3× worse than goal = 0**, linear between. Goals settable to Maintain / Improve 20% / 50th / 75th / 90th percentile **vs industry**. Weekly. |
| **Nexthink DEX** | per user or device, then averaged | **0–100** | Technology (Endpoint + Applications + Collaboration) + Sentiment. Bands **Frustrating 0–30 (red) · Average 31–70 (yellow) · Good 71–100 (green)**. Daily. **Conversion formula is Community-gated — UNVERIFIED.** |
| **Dynatrace Apdex** | per action | 0–1 | Standard Apdex with app-specific auto/manual thresholds. **A JavaScript error forces Frustrated regardless of speed.** Bands Excellent ≥0.94 · Good ≥0.85 · Fair ≥0.7 · Poor ≥0.5 · Unacceptable <0.5. |
| **Dynatrace User Experience Score** | per session | Satisfying / Tolerable / Frustrating | **Weighted-element model — user action = 3, error = 1, rage click = 2, crash = 5000.** Normalise F/T/S by total, compare to thresholds (typically 30 % / 50 %). **"Never Satisfying if there is even one Frustrating element."** |
| **Splunk Synthetics** | per browser run | 0–100 | **Lighthouse v10 algorithm** — an off-the-shelf score, not a proprietary model. |
| **Microsoft Endpoint Analytics** | tenant / device / model | **0–100** | Startup = weighted average of boot and sign-in scores; App reliability primarily **mean time to failure** (crashes ÷ engagement time, 14-day rolling) weighted by usage duration; Work-from-anywhere = weighted average of 4 adoption metrics. Baseline = **"All organizations (median)"**, with a documented opt-out. |
| **Microsoft CQD stream classifiers** | per media stream | Good / Poor / Unclassified | Threshold classifier (**RTT > 500 ms, loss > 0.1, jitter > 30 ms**) **plus** an ML classifier using **percentile thresholding — the lowest-performing 2 % within a platform × region × media-type cohort**. |

**Four lessons the coordinator should carry into the design:**
1. **Dynatrace's crash weight of 5000** is the cleanest encoding of "some events are categorically
   disqualifying", and the **"never Satisfying with one Frustrating element"** override stops a
   good average hiding a bad experience. Both are directly copyable.
2. **Aternity's goal → 3×goal → 0 linear map** is a transparent, arguable rule. Nexthink's
   equivalent is behind a login — that opacity is a weakness to exploit.
3. **Microsoft's percentile cohort thresholding** (worst 2 % within platform × region × media
   type) avoids the "everything on 4G in India is red" failure that absolute thresholds cause.
   It is the most statistically defensible classifier found.
4. **Aternity's end-flattening** is an honest admission that scores should **saturate** — a metric
   that keeps getting worse past the point of unusability adds no information.

### Agent footprint — the one published number

**Nexthink Collector: CPU < 0.15 %, ~60 MB memory, 100–150 bps network**
(docs.nexthink.com — collector overview / technical requirements). **Aternity publishes no agent
footprint at all, by explicit editorial decision.** **HPE UXI agent: ~1–3 % CPU, < 100 MB RAM**
(https://help.capenetworks.com/en/articles/9176908-uxi-agent-for-windows-macos). Everyone else
publishes nothing. **Publishing a measured footprint is a cheap, credible differentiator.**

### Privacy posture, ranked (this is the design-relevant part)

- **Strongest — Nexthink.** Suppression **at source, on the device**: hash usernames, disable
  focus-time tracking, disable user-activity-time reporting, **prevent Wi-Fi SSID/BSSID
  collection**, prevent domain reporting; plus platform-level anonymisation, URL sanitisation, a
  UPN-collection toggle, four permission levels with view domains, a 30-day GDPR data-retrieval
  SLA, 90-day backup destruction, and campaign responses anonymous in dashboards *and* CSV
  exports. The flat commitment: *"Nexthink does not gather information about the content within
  files, emails, websites, or any other piece of content."*
- **Strong — Datadog**, for one specific reason: **Session Replay masking is client-side and
  irreversible** — *"Masked data is not collected in its original form by Datadog's SDKs and thus
  is not sent to the backend"* — explicitly contrasted with Sensitive Data Scanner, where a
  privileged user can unmask. The mobile model is three orthogonal axes (text / input × image ×
  touch) with per-element overrides.
- **Strong — Dynatrace**, for a different reason: **allow-list masking with decentralised
  unmasking** (`data-dtrum-allow` per element) plus **centralised verification through
  release-process quality gates** makes exposure a reviewable code change rather than a console
  setting. That is the best *organisational* privacy design in the survey.
- **Good, with a retroactivity hole — Aternity.** The URL whitelist is excellent (*"Aternity does
  NOT expose all visited websites"*; non-whitelisted sites bucket to `Web browsing`), and the
  no-content / no-keystroke / no-screen commitments are unambiguous. But **PII encryption is not
  retroactive** — *"historical data will not be affected"* — so a works-council-driven enablement
  leaves the prior corpus readable for its full retention window. And **DEM-Q benchmark
  contribution has no documented opt-out**, the most attackable privacy fact found.
- **Structurally exposed — Microsoft.** Per-user call quality is individually attributable **by
  design**; mitigations are role-based (Tier 1 cannot see Advanced/Debug; phone numbers
  permanently obfuscated; federated participant EUII obfuscated) rather than anonymisation-based.
  Microsoft does apply a **five-employees-per-city floor** on remote-worker network insights and
  anonymises/aggregates the Endpoint Analytics baseline with a documented stop-gathering path.
- **Pattern worth adopting — ThousandEyes' deterministic PII anonymisation** rather than
  redaction: the operator can follow one pseudonymous identity across every view without ever
  seeing who it is.

### Licensing shapes

| Vendor | Unit | Published? | Notable mechanic |
|---|---|---|---|
| **Aternity** | License units: **1 per physical device · 1 per VDI user · ¼ per virtual app session · 5 per virtual app server · 1 per mobile** | **No prices** | A licence is **held for 14 days after last report, non-configurable**; 8-hour retry backoff when none is free |
| **Nexthink** | per employee / device by convention | **No** | — |
| **Datadog** | per 10k API runs · per 1k browser runs · **per 1k RUM sessions, split ingest $0.15 / retain $3.00** · per host (CNM $5) · per device (NDM $7) · **per 1k Network Path tests $5** | **Yes, fully** | Browser test = **1 run per 25 steps**; multistep API = **1 run per step**; **EU1 = US price, UK1/AP2 = 1.2×, AP1/US-FED = 1.25×** |
| **Dynatrace** | **DEM units** — RUM session **0.25**, with Session Replay **1.0**, synthetic action **1.0**, HTTP request **0.1**, session/action property **0.01** | **Yes, fully** | $2.25/1k RUM sessions · $4.50/1k with replay · $4.50/1k synthetic actions · $1.00/1k HTTP requests |
| **Splunk / Cisco** | **Eleven meters** across three products | Partial | AppD **synthetic retests after 5xx are charged**; exhausting the allotment **pauses all synthetic jobs until next month**; ThousandEyes tier reassignable **once per 30 days**, units **do not roll over** |

**The commercially significant asymmetry:** the two endpoint-DEX vendors (Aternity, Nexthink)
publish **no prices at all**, while the two application-DEM vendors (Datadog, Dynatrace) publish
**complete per-unit price lists**. *DEX is sold; APM is bought.*

### Retention gaps worth exploiting
**Datadog CNM: 14 days** — the shortest window in the entire Datadog platform, shorter than RUM
sessions and every security product. **Splunk RUM: 8-day default** — the shortest in this set by
a wide margin. **Network evidence retention is a clean differentiator.**

### Datadog's stated root-cause gap
Datadog's root-cause taxonomy has exactly **four causes** — version change, traffic increase, AWS
instance failure, disk full — and explicitly refuses to call degradation a cause.
**Network path change and configuration change are absent entirely.** That is a documented,
stated gap in the market leader.

## 1.16 Microsoft and MDM as agentless data sources

**Microsoft Graph `callRecords` is the most under-exploited data source found in this entire
research.** It supplies, **per call, per stream, with no agent, on every platform Teams runs on**:
`wifiSignalStrength`, `wifiBand`, `wifiChannel`, `wifiRadioType`, **BSSID**, link speed, Wi-Fi
driver, subnet and reflexive IP — plus round-trip time, jitter, packet loss and the user's own
satisfaction rating. **No product in this survey is documented as consuming it as a primary DEX
signal.** Resources: `callrecords-callrecord`, `callrecords-mediastream`,
`callrecords-networkinfo`, `callrecords-participantendpoint`
(https://learn.microsoft.com/en-us/graph/api/resources/callrecords-api-overview and the
per-resource pages). Graph throttling limits apply
(https://learn.microsoft.com/en-us/graph/throttling-limits).
**CQD itself has no documented REST/OData API — UNVERIFIED**; `callRecords` is the programmatic
path. CQD adds the **building/subnet mapping upload** that converts subnets into named sites
(https://learn.microsoft.com/en-us/microsoftteams/cqd-upload-tenant-building-data) — a ready-made
identity join a third party can mirror.

**Intune Endpoint Analytics** exposes startup performance, app reliability and work-from-anywhere
scores through Graph (`intune-devices-userexperienceanalyticsoverview`,
`…deviceperformance`, `…apphealthapplicationperformance`), with the tenant compared to an
**"All organizations (median)"** baseline that can be opted out of
(https://learn.microsoft.com/en-us/intune/endpoint-analytics/scores).

### What is actually obtainable per platform — the honest ceiling

| Signal | Windows | macOS | iOS/iPadOS | Android (corporate) | Android (BYOD work profile) |
|---|---|---|---|---|---|
| **Wi-Fi RSSI (dBm)** | Yes — `wlanSignalQuality` 0–100, linear to −100…−50 dBm | **Yes — `CWInterface.rssiValue()`, true dBm** | **No.** `NEHotspotNetwork.signalStrength` is a **0.0–1.0 float**, needs the `wifi-info` entitlement **plus** one of: precise location, own `NEHotspotConfiguration`, active VPN, or active DNS settings | **Yes — `WifiInfo.getRssi()`, dBm, no location permission required** | Same at app level; **AMAPI reports none** |
| **Noise / SNR** | Not in the association struct | **Yes — `noiseMeasurement()`** | No | Not directly | No |
| **SSID / BSSID** | Yes | Yes | Entitlement + one of four conditions | `ACCESS_FINE_LOCATION`, else `<unknown ssid>` / `02:00:00:00:00:00` | Same |
| **Wi-Fi scan (neighbours)** | Yes | Yes | No | **Throttled: 4 scans / 2 min foreground, 1 / 30 min background** (Android 9+) | Same |
| **App crashes / hangs** | Yes — Event Log 1000/1001/1002/1026 | Yes — system log | **MetricKit, aggregated, once per 24 h** | **Not via AMAPI** — needs an in-app SDK or Play vitals | Not via AMAPI |
| **Boot / logon time** | **Yes — Event ID 100, Kernel-PnP, Shell-Core** | Partial | No | `BOOT_COMPLETED` event only | Not reported |
| **CPU / memory / thermal** | Yes | Yes | MetricKit, daily | **Yes — AMAPI `HardwareStatus` incl. throttle and shutdown thresholds** | **No — "Report data is not available for personally owned devices with work profiles"** |
| **Battery** | Yes | Yes | MetricKit + MDM `BatteryLevel` | AMAPI `PowerManagementEvent` | **No** |
| **ICMP ping / traceroute** | Yes | Yes (privileged daemon) | **No raw sockets; no ICMP transport in the Network framework** | **`isReachable(netif, ttl, timeout)` — boolean only, no hop identity** | Same |
| **System-wide flow visibility** | Yes (driver) | Yes (privileged) | No (content filter needs supervision + entitlement) | Only via `VpnService` with user consent | No |
| **Continuous background probing** | Yes (service) | Yes (launch daemon) | **No — `BGAppRefreshTask`/`BGProcessingTask` are system-scheduled** | Foreground service, **`dataSync` type, visible notification, Play review** | Same |
| **Link-quality abstraction** | — | — | **`NWPath.LinkQuality` — 4 buckets, iOS 26+, and Apple says "do not use to gate connection attempts"** | `NetworkCapabilities.getSignalStrength()` (API 29+), bearer-specific | Same |
| **Bandwidth estimate** | — | — | — | `getLinkDownstream/UpstreamBandwidthKbps()` — **"always only refers to the estimated first hop transport bandwidth"** | Same |

Sources: Apple `NEHotspotNetwork`/`signalStrength`, `NWPath.LinkQuality`, MetricKit
`MXMetricPayload`, `BGAppRefreshTaskRequest`, `CWInterface.rssiValue()`, DDM `status-items`
catalogue and `deviceInformationresponse` (developer.apple.com); Android `WifiInfo`,
`NetworkCapabilities`, `InetAddress`, wifi-scan throttling, Doze/App Standby, Android 14 FGS
types, managed profiles (developer.android.com); Android Management API device schema
(developers.google.com/android/management + the discovery document);
`wlan_association_attributes` and ETW (learn.microsoft.com).

**Three findings that constrain any endpoint strategy:**
1. **Windows and macOS support a real endpoint DEM agent** — true dBm RSSI (SNR on macOS), boot
   and logon phase timing from OS-native events, crash/hang detection from the system log,
   per-process CPU attribution, continuous background execution, and ICMP with TTL control for
   genuine path discovery. Everything ThousandEyes documents doing is achievable **here and
   nowhere else.**
2. **iOS supports almost none of it.** No numeric RSSI without an entitlement and a qualifying
   condition; no raw sockets or traceroute; no continuous background probing; performance data
   only through MetricKit's **once-daily aggregate**; and the **DDM status catalogue contains no
   network, performance, storage or crash item.** An honest iOS offering is: MDM inventory and
   compliance, DDM push-on-change status, MetricKit daily aggregates from your own app,
   `NWPath` interface type and expensive/constrained flags, and on iOS 26+ a four-bucket
   link-quality hint Apple tells you not to act on. **Any vendor claiming real-time iOS network
   experience monitoring is shipping a VPN, holding a special entitlement, or overstating.**
3. **Android forks sharply on ownership.** Corporate-owned gives dBm RSSI without a location
   prompt plus AMAPI thermals/CPU/memory/battery/display. **Personally-owned work-profile devices
   lose hardware status, power events and display info entirely**, and **AMAPI reports no network
   *quality* metric and no app crashes in either configuration.** Continuous probing needs a
   foreground service with a visible notification, declared `dataSync`, reviewed by Google Play
   (*"Google Play policies prohibit apps from requesting direct exemption from… Doze and App
   Standby… unless the core function of the app is adversely affected"*).

---

# §2 Measurement techniques and standards

This section is the physics of DEM: what can actually be measured, by what mechanism, and
what has to exist in the network for it to work. It is deliberately separated from the
vendor section — every vendor above is a packaging of these primitives.

## 2.1 Active path measurement: STAMP, TWAMP, OWAMP

**STAMP — RFC 8762 (Simple Two-way Active Measurement Protocol)** is the current IETF
standard and the one to build on.
- Roles: **Session-Sender** and **Session-Reflector**; a session is the bidirectional packet
  flow between one sender and one reflector (§3).
- Default destination port **UDP 862** (the TWAMP-Test receiver port), with registered or
  ephemeral ports allowed (§4.1).
- Base packet is **44 octets unauthenticated** (Sequence Number 4 · Timestamp 8 · Error
  Estimate 2 · MBZ 30) and **112 octets authenticated** (adds HMAC-SHA-256 truncated to
  128 bits) (§4.2.1, §4.2.2).
- Timestamps: the **Z bit** in the Error Estimate selects **NTP 64-bit** (0) or **PTPv2
  truncated** (1) format. The reflector returns its receive timestamp and its own transmit
  timestamp — giving the classic T1..T4 from which one-way delay, round-trip delay, delay
  variation and loss are derived (§4).
- **Stateful reflectors** allow *directional* loss to be determined; **stateless** reflectors
  only permit round-trip loss (§4).
- **TWAMP-Light interoperability** exists only in **unauthenticated** mode — the authentication
  algorithms differ (HMAC-SHA-256 vs HMAC-SHA-1) (§4.6).
  — https://datatracker.ietf.org/doc/html/rfc8762

**TWAMP — RFC 5357.** Two protocols: **TWAMP-Control over TCP 862** and **TWAMP-Test over
UDP**. Four logical roles: Control-Client, Server, Session-Sender, Session-Reflector.
Unauthenticated reflected packets are ≥41 octets; authenticated/encrypted ≥104 octets.
**TWAMP Light (Appendix I)** removes the control protocol entirely — the reflector is
stateless and simply copies sequence numbers and timestamps back, configured out-of-band.
This is the mode that matters operationally: a "light test point" is cheap enough that
vendors ship it on production routers.
— https://datatracker.ietf.org/doc/html/rfc5357

**Why this matters for minimal interference:** a STAMP/TWAMP-Light *sender* is pure UDP —
implementable with no raw sockets, no elevated privileges, no kernel modules. Only the
**reflector** needs to exist at the far end, and on capable routers it already does
(Fortinet exposes `set protocol twamp` as an SD-WAN health-check protocol —
https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/867342/performance-sla-overview).
Correlix already ships a STAMP sender (`src/backend/collectors/stamp.go`) emitting
`probe_rtt_ms` / `probe_owd_ms` / `probe_pdv_ms` / `probe_loss_pct`.

## 2.2 What "correct" delay / loss / jitter reporting means (IPPM)

- **RFC 7679 — one-way delay.** Singleton `Type-P-One-way-Delay` is a real number in seconds,
  or **undefined/infinite** if the packet does not arrive within a loss threshold `Tmax`.
  Sampling is defined over a Poisson stream to limit bias and avoid self-synchronisation.
  Total measurement uncertainty is `Esynch(t) + Rsource + Rdest + Hsource + Hdest`
  (clock sync error + clock resolutions + wire-time-vs-host-time), and implementations are
  told to publish a calibration error `e` such that the true value is the reported value ±e
  at 95% confidence. **Undefined delays are treated as infinitely large**, so high percentiles
  go infinite when loss is material — a real reporting trap.
  — https://www.rfc-editor.org/rfc/rfc7679.html
- **RFC 7680 — one-way loss.** Singleton is 0 (received) or 1 (lost). The whole difficulty is
  the *methodology* for separating "lost" from "very large but finite delay"; the RFC declines
  to fix a universal `Tmax` and tells implementers to choose one with engineering judgment.
  — https://www.rfc-editor.org/rfc/rfc7680.html
- **RFC 5481 — PDV vs IPDV.** `IPDV(i) = D(i) − D(i−1)` is two-sided and centred on zero;
  `PDV(i) = D(i) − D(min)` is one-sided and anchored at the minimum delay in the interval.
  The RFC's guidance is unambiguous: **use PDV** for de-jitter buffer sizing and for SLA
  reporting (its pseudo-range maps directly onto required buffer capacity and composes across
  path segments); IPDV tolerates clock skew better but "has no universal summary statistic
  that relates to a physical quantity."
  — https://datatracker.ietf.org/doc/html/rfc5481

**Design consequence:** report **PDV**, not "jitter", and say so; carry `Tmax` explicitly;
never let an undefined delay silently become a large finite number.

## 2.3 Y.1731 / IP SLA / RPM — device-native SLA probes

**UNVERIFIED (fetch-blocked):** `itu.int` returns only metadata for G.107 and Y.1731, and
`cisco.com` documentation pages consistently reset the connection to unauthenticated fetches
during this session. The following is therefore carried as *context to verify before use*,
not as sourced fact:
- **ITU-T Y.1731** Ethernet OAM defines ETH-DM (frame delay, DMM/DMR and 1DM one-way),
  ETH-LM (loss measurement) and ETH-SLM (synthetic loss measurement) between MEPs in a MEG —
  the carrier-Ethernet analogue of STAMP, used for E-Line/E-LAN SLA attestation.
- **Cisco IP SLA** operation types (`icmp-echo`, `udp-jitter`, `udp-echo`, `tcp-connect`,
  `http`, `dns`, `path-jitter`) and **Juniper RPM** provide device-native probes; results are
  readable by a third party over SNMP via **CISCO-RTTMON-MIB**, or by streaming telemetry.
- The one device-native SLA probe protocol **verified** in this session is Fortinet's, which
  supports `ping`, `tcp-echo`, `udp-echo`, `http`, **`twamp`** and `dns`, plus **passive** and
  **prefer-passive** modes that derive latency/jitter/loss from the firewall session table with
  **no probe traffic at all**
  (https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/867342/performance-sla-overview).

Fortinet also publishes the rare ability to **QoS-classify its own probes** (`class-id`), which
addresses the failure mode every other vendor documents but does not solve: probes being
deprioritised and therefore lying
(https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/941705/classifying-sla-probes-for-traffic-prioritization-new).

## 2.4 Flow-derived application response time (the agentless workhorse)

The single highest-leverage agentless technique: a flow exporter that watches the TCP
handshake and the request/response exchange can split **network delay** from **server
response time** without touching an endpoint.

Verified information elements (nProbe/IPFIX, which is the concrete, citable instance of the
technique):

| Element | NFv9 / IPFIX id | Meaning |
|---|---|---|
| `CLIENT_NW_LATENCY_MS` | 57595 / 35632.124 | Network RTT/2, client ↔ probe |
| `SERVER_NW_LATENCY_MS` | 57596 / 35632.124 | Network RTT/2, probe ↔ server |
| `APPL_LATENCY_MS` | 57597 / 35632.125 | Application latency, a.k.a. **server response time** |
| `RETRANSMITTED_IN_PKTS` | 57581 / 35632.109 | Retransmitted packets src→dst |
| `RETRANSMITTED_OUT_PKTS` | 57582 / 35632.110 | Retransmitted packets dst→src |
| `OOORDER_IN_PKTS` | 57583 / 35632.111 | Out-of-order TCP packets |
| `OOORDER_OUT_PKTS` | 57584 / 35632.112 | Out-of-order TCP packets |

— https://www.ntop.org/guides/nprobe/flow_information_elements.html

The **base IANA IPFIX registry** carries the TCP primitives (`tcpControlBits` id 6,
`tcpSequenceNumber` 184, `tcpAcknowledgementNumber` 185, `tcpWindowSize` 186,
`tcpWindowScale` 238, SYN/FIN/RST/PSH/ACK/URG counters 218–223) but **no standard
round-trip-time, retransmission or MOS element** — every vendor's ART metrics are
enterprise-specific extensions
(https://www.iana.org/assignments/ipfix/ipfix.xhtml). **Design consequence: ART is a
per-exporter normalisation problem, not a standards problem.** Cisco AVC/NBAR2 publishes an
equivalent ART set (client network delay / server network delay / server response time /
total transaction time / retransmissions) — **UNVERIFIED in this session**, cisco.com fetches
failed; verify against the AVC Performance Monitor guide before relying on exact names.

Correlix already carries an NBAR/IPFIX app-identification adapter
(`src/backend/appid/adapter/nbar_ipfix.go`) and a flows tier, so this is an extension of
existing plumbing rather than a new ingestion path.

## 2.5 Wi-Fi client experience

The connect-phase decomposition is the part that matters, and it is the part vendors compete
on. Two vendors publish an explicit phase model:

- **Fortinet FortiAIOps** computes **Time to Connect thresholds per AP-client environment and
  per connectivity phase — association, authentication (4-way handshake), and DHCP** — and
  stages Connection Failure by cause: association failure (low RSSI), auth failure
  (unreachable RADIUS), DHCP failure, **DNS failure**
  (https://docs.fortinet.com/document/fortiaiops/3.0.0/user-guide/133572/overview).
- **Zscaler ZDX** collects SSID, BSSID, AP prefix, band distribution, per-AP latency and
  jitter, and can key its Wi-Fi dashboard on **signal strength and retransmission rate**
  rather than the composite score
  (https://help.zscaler.com/zdx/monitoring-wi-fi-dashboard).

RF and roaming primitives:
- **802.11k** radio resource measurement supplies neighbour/site reports so a client can be
  told which APs to consider; it is paired with **802.11r** fast BSS transition for the actual
  roam and **802.11v** BSS transition management for steering
  (https://en.wikipedia.org/wiki/IEEE_802.11k-2008 — note this page is thin and flagged for
  citations; **treat the detailed beacon/neighbour-report field list as UNVERIFIED**).
- Per-link RF that actually predicts experience: **RSSI, SNR, MCS, NSS, channel width, retry
  percentage, Tx/Rx rate**. Correlix already stores exactly this set at event boundaries
  (`netops.wireless_client_rf`) plus **MLO per-link rows** for Wi-Fi 7
  (`netops.wireless_mlo_links`) — see `src/backend/internal/chschema/wireless_schema.go`.

**Endpoint-side Wi-Fi is where OS privacy rules bite.** Zscaler documents that on recent
macOS and Windows 11, **SSID and BSSID are simply not captured** unless the OS-level
"Collection Location Info for ZDX" privacy setting is enabled
(https://help.zscaler.com/zdx/monitoring-wi-fi-dashboard). Netskope documents that **hidden
Wi-Fi networks may not be detected by standard Windows APIs, causing the Wi-Fi sub-score to
report 0**, and that **Windows performance counters are English-only**, breaking throughput
collection on localised OS builds
(https://docs.netskope.com/en/understanding-digital-experience-management-dem-scores/).
These are the strongest available arguments for **controller-side Wi-Fi telemetry over
endpoint-side**.

## 2.6 Voice and video quality

- **RFC 3611 RTCP-XR** is the standard carrier of per-call quality. Block type 7, the **VoIP
  Metrics Report Block**, carries: loss rate and discard rate (8-bit fixed point); **burst and
  gap density and duration** (the concentration of loss, which matters more than the average);
  **round-trip delay and end-system delay** (16-bit ms); signal level, noise level and RERL
  (8-bit signed dB); Gmin threshold; receiver configuration (PLC/JBA/JB rate); **R factor**
  (0–100, 94 = toll quality) and extended R factor; **MOS-LQ** and **MOS-CQ**, both encoded as
  **MOS × 10 in the range 10–50, with 127 meaning unavailable**; and jitter-buffer nominal /
  maximum / absolute-maximum. Other blocks: Loss RLE (1), Duplicate RLE (2), Packet Receipt
  Times (3), Receiver Reference Time (4), DLRR (5), Statistics Summary (6).
  — https://www.rfc-editor.org/rfc/rfc3611.html
- **MOS scale.** ACR 1–5 (5 Excellent … 1 Bad). Subjective MOS is the mean of human ratings;
  objective/estimated MOS is an algorithmic prediction trained on those ratings. The critical
  caveat, stated by the reference: **"it is not meaningful to directly compare MOS values
  produced from separate experiments unless those experiments were explicitly designed to be
  compared."** — https://en.wikipedia.org/wiki/Mean_opinion_score
- **ITU-T G.107 E-model** (`R = Ro − Is − Id − Ie-eff + A`, and the R→MOS mapping) is the
  standard way to estimate MOS from loss/jitter/delay. **UNVERIFIED:** the ITU page served
  only front matter; the equation and the R-band-to-satisfaction mapping could not be
  retrieved from a primary source in this session and must be verified before implementation.
- **Estimating MOS without RTP visibility** is what SD-WAN vendors do. Fortinet's is the
  clearest published instance: MOS is computed from **latency, jitter, packet loss and the
  codec** (`g711` default, `g729`, `g722`), on a 1–5 scale, and — uniquely — is usable as a
  **link-selection cost factor** with a configurable `mos-threshold` (range 1.0–5.0,
  **default 3.6**)
  (https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/998548/mean-opinion-score-calculation-and-logging-in-performance-sla-health-checks).
  Zscaler computes its Call Quality ZDX Score "either from MOS (rated 1–5) or from metric
  thresholds", using latency, jitter and packet loss
  (https://help.zscaler.com/zdx/understanding-alert-triggers).

**Error bars:** every codec-model MOS is an estimate with an unstated confidence interval, and
the MOS caveat above means cross-vendor MOS comparison is not defensible. A DEM product should
present estimated MOS **with its inputs visible** and never as a measured ground truth.

## 2.7 Browser RUM

- **Navigation / Resource Timing.** `PerformanceNavigationTiming` extends
  `PerformanceResourceTiming`, so one entry yields the whole waterfall:
  DNS = `domainLookupEnd − domainLookupStart`; TCP connect = `connectEnd − connectStart`;
  TLS = `connectEnd − secureConnectionStart` (when `secureConnectionStart > 0`);
  **TTFB = `responseStart − fetchStart`**; content download = `responseEnd − responseStart`;
  DOM interactive = `domInteractive − fetchStart`; full load = `loadEventEnd − fetchStart`.
  Consumed via `PerformanceObserver` with `{type:"navigation", buffered:true}`.
  — https://developer.mozilla.org/en-US/docs/Web/API/Performance_API/Navigation_timing
- **Core Web Vitals — current thresholds, measured at the 75th percentile of page loads,
  segmented mobile vs desktop:**
  **LCP ≤ 2.5 s · INP ≤ 200 ms · CLS ≤ 0.1**. INP became a stable Core Web Vital in 2024,
  superseding FID. — https://web.dev/articles/vitals
- **CrUX as a global/peer baseline.** The Chrome UX Report API returns aggregated real-user
  data at **origin and URL granularity**, as **histograms (3 bins), p75 percentiles, and
  fractions**, for LCP / FCP / CLS / INP / TTFB / round-trip-time, filterable by form factor
  (PHONE / TABLET / DESKTOP). It is a **28-day rolling average**, lags **~2 days**, updates
  daily around 04:00 UTC, needs a Google Cloud API key, and is limited to **150 queries per
  minute per project, free, with no paid tier**.
  — https://developer.chrome.com/docs/crux/api
  **This is the cheapest credible source of a "compare me to the world" baseline for any
  public web app, and it requires no agent anywhere.**

## 2.8 Synthetic transaction scripting

- **What the market actually runs.** ThousandEyes transaction tests are **Chromium driven by
  Selenium WebDriver, JavaScript, in an isolated Node.js context**, importing from a
  `thousandeyes` module (`driver`, `markers`, `credentials`, `downloads`, `transaction`,
  `authentication`, `test`), with a **5–180 s** timeout. Its own recorder IDE reached
  **functional EOL on 2026-07-26**; the replacement path is **recording in Chrome DevTools
  Recorder and importing**
  (https://docs.thousandeyes.com/product-documentation/browser-synthetics/transaction-tests/transaction-scripting-reference.md,
  https://docs.thousandeyes.com/whats-new/changelog.md).
- **Playwright** is the natural modern engine: official Docker image on Ubuntu 24.04
  (`:v1.63.0-noble`), browsers and system dependencies pre-installed, **`--ipc=host`
  required or Chromium runs out of memory and crashes**, `--init` recommended, an unprivileged
  `pwuser` plus a seccomp profile for untrusted targets, and **Alpine is unsupported** (musl vs
  glibc browser builds). — https://playwright.dev/docs/docker
- **The cost of a browser test is the design constraint.** ThousandEyes publishes per-round
  traffic — agent-to-server TCP **245 packets / 27,346 bytes**; the *same test with bandwidth
  measurement enabled* **806 packets / 485,368 bytes** (~18× the bytes); ICMP 194 pkt /
  28,280 B; DNS-server test across 4 servers only 16 pkt / 1,632 B
  (https://docs.thousandeyes.com/product-documentation/tests/network-utilization-from-enterprise-agent-test-traffic.md).
  It also models agent capacity **behaviourally, not by hardware**: a `utilization` figure per
  queue (**Browser, General, Bandwidth, Voice**) exposed on the agent API, with the explicit
  statement that adding CPU/RAM *"is generally not effective in reducing utilization"* — the
  remedies are more agents, longer intervals, shorter timeouts
  (https://docs.thousandeyes.com/product-documentation/global-vantage-points/enterprise-agents/managing/enterprise-agent-utilization.md).
- **Credentials.** Handle via a secure-credential store bound to the script, never inline; MFA
  targets are the practical wall for scripted synthetics
  (https://docs.thousandeyes.com/product-documentation/browser-synthetics/transaction-tests/getting-started/working-with-secure-credentials.md).

## 2.9 Internet path measurement

- **Classic traceroute is wrong under ECMP.** It varies header fields on every probe; per-flow
  load balancers hash the five-tuple, so successive probes take different paths and the tool
  reports links that do not exist. **Paris traceroute** holds the flow identifier constant and
  varies only fields the balancer ignores: **the UDP checksum**, **the TCP sequence number**,
  or **the ICMP identifier/sequence with a compensating constant header checksum**.
  — https://paris-traceroute.net/about
  (MDA — the multipath detection algorithm that enumerates *all* parallel paths rather than
  pinning one — is **UNVERIFIED**; not described on the page fetched.)
- **How the market implements it.** ThousandEyes runs **3 traces per round with a unique random
  source port per trace on TCP** to deliberately *expose* ECMP alternates, and is explicit that
  **path traces and end-to-end metrics use separate probes**, so the view "cannot identify the
  exact path taken by packets that produced an end-to-end metric" — an honesty worth copying
  (https://docs.thousandeyes.com/product-documentation/internet-and-wan-monitoring/path-visualization/path-trace.md).
  Netskope publishes its probing volume: **minimum 6 segments per hop, auto-escalating to 12**,
  **UDP source ports 33435–33535** (a different port per segment so at least one is closed at
  the target), and states that a router which silently drops without generating ICMP errors is
  **still drawn in the path graph but carries no metrics**
  (https://docs.netskope.com/en/synthetic-probes/).
- **MPLS is a structural blind spot.** ThousandEyes classifies four tunnel cases by
  RFC 4950 × TTL-propagation: **Explicit** (labels visible), **Implicit** ("Hop X in an MPLS
  Tunnel"), **Opaque** (collapsed to one "N-hop MPLS tunnel" node), and **Invisible —
  undetectable, where an erroneous link may be inferred**
  (https://docs.thousandeyes.com/product-documentation/internet-and-wan-monitoring/path-visualization/mpls-tunnel-inference-using-deep-path-analysis.md).
- **BGP-aware attribution, free and agentless.** RIPEstat's Data API exposes routing-status,
  bgp-updates, BGP update activity, BGP state, announced-prefixes, network-info, whois,
  looking-glass, AS overview and routing-consistency endpoints. **No request-count limit**,
  registration requested above ~1,000/day, and a hard **8 concurrent connections per source
  IP**. — https://stat.ripe.net/docs/02.data-api/
- **Outage detection methodology (the reference implementation).** ThousandEyes defines a
  **Network Outage** as *"events with 100% packet loss in the same AS and the same metropolitan
  location during the same period"*, keyed by **ASN**; and an **Application Outage** as enough
  servers of one application failing, where a *server* is the tuple **(hostname, IP)**, keyed
  by **domain**. Crucially it will not report an outage *"based on an application that is used
  by only one customer"* — cross-customer corroboration is the false-positive control
  (https://docs.thousandeyes.com/product-documentation/internet-insights/int-terminology.md,
  https://docs.thousandeyes.com/product-documentation/internet-insights.md).
  **This is the one capability a single-tenant on-prem product structurally cannot copy** — and
  the honest answer is to substitute public BGP/RIS data plus per-tenant corroboration rather
  than pretend to a global panel.

## 2.10 DNS / HTTP / TLS / TCP synthetics

The standard breakdown, which every vendor reproduces almost identically:
**DNS resolution → TCP connect → TLS handshake → time to first byte (server response) →
content transfer → (optionally) time to last byte.**
- Fortinet's SD-WAN synthetic transaction breakdown is exactly *DNS Lookup, TCP Handshake,
  SSL Handshake, Time to First Byte, **Time to Last Byte***
  (https://docs.fortinet.com/document/fortimonitor/26.2.0/user-guide/94189/sd-wan-application-monitoring).
- Netskope's App Probe breaks a request into *DNS resolution, connection setup, TLS handshake,
  time to first byte, content transfer*
  (https://docs.netskope.com/en/how-dem-user-experience-scores-are-calculated/).
- Zscaler's Web Probe reduces to *Page Fetch Time, Server Response Time, DNS Time,
  Availability* (https://help.zscaler.com/zdx/understanding-zdx-score).
- Palo Alto ADEM's synthetic Experience Score is built from **TTFB (= DNS + TCP + SSL +
  server response time) plus availability** (group-B research, ADEM experience-score doc).
- **Certificate expiry** is a standard default rule: ThousandEyes ships "SSL certificate
  expiring within 30 days" as a built-in alert
  (https://docs.thousandeyes.com/product-documentation/alerts/default-alert-rules.md).
- **HTTP/3 (QUIC)** collapses TCP+TLS into a single encrypted handshake, so the classic
  connect/TLS split is not observable the same way, and on-path flow exporters lose the
  handshake-derived RTT. **UNVERIFIED in this session** — no vendor doc fetched addressed
  HTTP/3 measurement explicitly. Flag it as a real and growing measurement gap.

## 2.11 Experience-score methodologies compared

**Apdex** is the only fully public formula:
`Apdex_t = (Satisfied + 0.5 × Tolerating + 0 × Frustrated) / Total`, where Satisfied is
response ≤ T, Tolerating is T < response ≤ 4T, Frustrated is > 4T, and the score runs 0–1.
The tolerable threshold is *defined* as 4T. — https://en.wikipedia.org/wiki/Apdex

The commercial scores diverge on three axes: **inputs**, **reduction operator**, and
**whether the formula is published at all**.

| Score | Scale | Bands (exact) | Inputs | Reduction | Published? |
|---|---|---|---|---|---|
| **Apdex** | 0–1 | — | Response time vs T | Weighted count | **Fully** |
| **Zscaler ZDX** | 0–100 ↑ | Good 66–100 · Okay 34–65 · Poor 0–33 | Page Fetch Time (primary), Server Response, DNS, Availability; Cloud Path latency/loss/hops; RUM CWV | **Minimum at every level** — worst 5-min sample in the hour; worst app for a user; worst app for the org | **Yes, unusually fully** |
| **Palo Alto ADEM** | 0–100 ↑ | Good ≥70 · Fair 30–69 · Poor <30 | Synthetic: TTFB + availability. RUM: min(LCP score, INP score) | RUM **overrides** synthetic when present; remote sites = average of active paths | Yes |
| **Netskope P-DEM** | 0–100 ↑ | Good ≥71 · Fair 31–70 · Poor ≤30 | 4 contributions: Device, On-Ramp, SaaS/Custom App, Private App | 5-min windows averaged; **refuses to render below 2 of 4 contributions**; SPA scores **percentile-ranked within the tenant over a rolling 3 days** | Yes |
| **Versa** | 1–100 **↓ (lower is better)** | Not published | Device, Wi-Fi, local network, internet, application timings | Not published | **No** |
| **Fortinet UX Score** | 0–100 ↑ | Not published | Network (HTTP RT, DNS, latency, jitter, loss) + Application (CPU, mem, Wi-Fi signal, up/down speed) | Per **(location, target)** pair; roll-up unpublished | Inputs only |
| **ThousandEyes Experience Score** | 0–100 | — | **Single input — DOM load time — through an unpublished curve**; two unrelated features share the name | — | **No** |

Sources: https://help.zscaler.com/zdx/understanding-zdx-score ·
https://docs.netskope.com/en/how-dem-user-experience-scores-are-calculated/ ·
https://docs.netskope.com/en/understanding-digital-experience-management-dem-scores/ ·
https://docs.fortinet.com/document/fortimonitor/26.2.0/user-guide/337449/ux-score ·
https://docs.thousandeyes.com/product-documentation/end-user-monitoring/viewing-data/agent-views.md ·
Palo Alto ADEM experience-score doc (docs.paloaltonetworks.com/autonomous-dem).

Three findings from this table matter more than the table:
1. **Everyone converged on 0–100 with three bands, and every boundary is different**
   (66/34 vs 70/30 vs 71/31), **and Versa is inverted**. Any cross-source normalisation must be
   explicit per vendor.
2. **Two opposed reduction philosophies.** Zscaler takes **minima** everywhere ("worst
   experience wins" — maximally sensitive, structurally noisy). Netskope and Palo Alto
   **average/percentile** — stable, and Netskope explicitly warns that a sharp 15-minute
   incident is "diluted to near invisibility" in an 8-hour view.
3. **Availability is universally a gate, not a weighted term.** ADEM: availability 0 → score 0.
   Netskope: fewer than 2 contributions → no score at all. This is the consensus design and
   should be copied.

## 2.12 Endpoint agent footprint and privacy posture

**No vendor researched publishes a numeric CPU / RAM / disk footprint for its DEM endpoint
agent.** Zscaler says only *"negligible additional CPU consumption"*
(https://help.zscaler.com/zdx/understanding-zdx-cloud-architecture). This is a **market gap
and a differentiation opportunity**: publishing a measured footprint would be a first.

What *is* published is the **process and privilege surface**, and it is substantial:
- **Zscaler:** four processes — `ZSAUpm` (service), `ZSAUpmInstaller`, **`ZSAScript` (runs
  remote scripts on the device)**, `ZUpmApplication` (RUM). EDR/AV allowlisting is mandatory,
  and GPO-managed estates must allowlist **both** 32- and 64-bit paths because the binaries
  live under `%ProgramFiles(x86)%` even on 64-bit
  (https://help.zscaler.com/zdx/zdx-module-processes-allowlist).
- **Palo Alto ADEM:** publishes **14 named processes including `mtr`, `curl`, `tcping`** with a
  **per-process privilege level** (Local System / Network Service / Local Service / logged-in
  user) — the most transparent privilege disclosure found
  (docs.paloaltonetworks.com/autonomous-dem/administration/agent-processes-windows).
- **ThousandEyes:** four components (`te-agent` service, `te-browserhelper`, browser plugin,
  updater); **installs the Npcap packet-capture driver on Windows**; macOS supports only the
  three most recent major versions; **Firefox and Safari are unsupported**. It collects
  **BSSID, channel, signal dBm, retransmission rate, roaming and channel-swap events, battery
  charge and health, free disk, device serial number**, and on mobile **RSRP/RSRQ/SINR**. Local
  probes fire **as a once-per-minute burst**, not spread. Browser capture is metadata only and
  **`Cookie`, `Set-Cookie` and `Authorization` headers are dropped at collection**
  (https://docs.thousandeyes.com/product-documentation/global-vantage-points/endpoint-agents/how-endpoint-agents-work/data-collected-by-endpoint-agent.md).
- **Zscaler Advanced Plus** additionally offers **Process Inventory** — per-process visibility
  across the fleet (https://help.zscaler.com/unified/ranges-limitations); Netskope offers an
  opt-in **per-process CPU / memory / disk-I/O** collection toggle
  (https://docs.netskope.com/en/synthetic-probes/).

**Privacy reading of that list:** device serial numbers, per-process inventories, browser
session metadata, battery health, location-derived Wi-Fi identifiers and remote script
execution are, collectively, employee-monitoring capabilities — which is why the EU
works-council question is not a formality. The mitigations that appear in the market are
**drop-at-collection for credential headers**, **metadata-only browser capture**, and
**opt-in toggles per data class**. **UNVERIFIED:** specific GDPR/works-council guidance
published by Nexthink/Aternity could not be retrieved in this session (see §1 group-D notes).

---

# §3 The six distillations

## 3.1 What a modern, futuristic DEM is expected to do in 2026

Gartner's own market definition could not be fetched (403 on both the glossary and the Peer
Insights market page) — **the analyst framing is UNVERIFIED**. What follows is induced from what
the leaders actually ship, which is a stronger basis anyway.

**(a) Score every user, every app, every five minutes — and say how.** The convergent shape is
**0–100, three bands, per user, per app, on a 5-minute window**. Zscaler, Netskope and Palo Alto
all do exactly this; the bands differ (66/34 · 71/31 · 70/30) and Versa is inverted. **The
2026 expectation is not that you have a score — it is that the score is explainable.** Only
Zscaler, Netskope and Palo Alto publish their arithmetic; ThousandEyes' endpoint Experience Score
is a **single input (DOM load time) through an unpublished curve** and it collides by name with a
second, unrelated score. Publishing an auditable formula is a straightforward differentiator.

**(b) Attribute the fault to a segment, not just report a number.** Scoring is table stakes;
**attribution is the product.** The published segment models:
- Zscaler: Device · Wi-Fi · Last Mile ISP (**Blackout vs Brownout**) · Intermediate ISP
  (**Internal / ISP-to-ISP / peering-to-DC**) · ZIA Service Edge · ZPA · Application — plus
  **forward-path vs reverse-path separation**.
- Netskope: Device · On-Ramp · SaaS/Custom App · Private App.
- Palo Alto: Device · Wi-Fi · LAN · ISP · Gateway.
- Versa: Local · WiFi · Internet · Application.
- Fortinet: **none** — only (location, target) pairs.
Attribution quality tracks directly with whether the vendor **baselines per segment** (Palo Alto)
or **per fault class** (Zscaler). ThousandEyes reduces the whole question to one call —
**red ring mid-path = forwarding loss (the path owner's problem); red ring on the target =
terminal loss (the application owner's problem)** — described in its own docs as *"the single
most important call you make… because it tells you who owns the fix."*

**(c) Baseline against peers, not just against yourself.** Three published mechanisms:
- **Palo Alto ADEM** — percentile baselines over **30 days**, refreshed every 24 h, clustered by
  **(City + ASN + Gateway)**, requiring **≥20 agents per cluster**, with **cross-tenant
  fallback** when a tenant's cluster is too small.
- **Zscaler** — per-region Page Fetch baselines on a **rolling 7-day window, recomputed daily**.
- **Aruba Central** — an ML model **classifies each site** and compares it to similar
  deployments.
- **Aternity DXI** — goals expressed as **50th / 75th / 90th percentile vs industry**.
- **Microsoft CQD** — the most defensible: **worst 2 % within a platform × region × media-type
  cohort**, which avoids the "everything on 4G is red" failure of absolute thresholds.
**And the free public equivalent: the CrUX API** (p75 LCP/INP/CLS/TTFB per origin, 150
queries/minute, free) is a credible global baseline for any public web app, requiring no agent
anywhere.

**(d) AI that localises, not AI that chats.** The genuinely differentiated AI in this market is
**incident localisation with a named fault class**: Zscaler's seven area types with
blackout/brownout and internal/ISP-to-ISP sub-typing, and its ML baseline comparison in Network
Intelligence; Fortinet's FortiAIOps **weekly-retrained, deployment-specific RF model** with
SLA thresholds derived by **clustering clients on connection quality**; Aruba's incident
detection requiring **≥11 co-occurring issues**. Conversational assistants (Netskope's DEM Data
Intelligence Agent, Marvis) are a delivery surface on top of that, not a substitute for it.

**(e) Closed-loop remediation as a first-class object.** Zscaler ships **`ZSAScript` — a process
whose job is running remote scripts on the endpoint** (Advanced Plus, 1,000 configured / 100
enabled scripts, 180-day retention). Fortinet ships **CounterMeasures**, triggerable from the
endpoint agent. Nexthink ships **Remote Actions** with **Engage** sentiment campaigns to confirm
the fix landed. Aternity ships **Remediate**. **The bar in 2026 is a recommendation with a
one-click action and a verification loop** — and the honest version of this for a network product
is *remediation hints with evidence*, not autonomous change.

**(f) Detection latency measured in minutes, not hours.** This is where the incumbents are
weakest and it is quantifiable: **Cisco AAR averages over ~60 minutes at defaults** (10-min poll
× 6 buckets) and only reaches ~60 s with Enhanced AAR explicitly enabled on 17.12.1a+;
**Cloud OnRamp decides on a 12-minute window**; **Zscaler alerts carry a documented 30-minute
display delay**; **Meraki webhooks average 90 seconds**; **Mist Premium Analytics is 12–36 hours
stale and has no API**. Anything that detects and attributes inside a minute is genuinely ahead.

**(g) Honesty about what is not measured.** The best documentation in the market is the most
candid: ThousandEyes states that path traces and end-to-end metrics use **separate probes**, so
the view *"cannot identify the exact path taken by packets that produced an end-to-end metric"*,
and that **Invisible MPLS tunnels are undetectable and an erroneous link may be inferred**;
Netskope warns that a long time range **dilutes a 15-minute incident to near invisibility** and
refuses to emit a composite score on fewer than 2 of 4 contributions; Aruba draws **gaps in
charts where no test ran, never interpolated**. **This is a product philosophy, not a
documentation style, and it is directly aligned with Correlix's existing truthfulness posture.**

## 3.2 What can be obtained with MINIMAL interference — the agentless-first ladder

The brief's central constraint. Ordered by interference, lowest first. **Tiers 0–2 require
nothing installed on any user device and no change to any production path.**

### Tier 0 — what the network already emits (zero new components)
| Source | What it yields | Evidence |
|---|---|---|
| **IPFIX / NetFlow / sFlow with ART extensions** | **The network-vs-server split without touching an endpoint**: `CLIENT_NW_LATENCY_MS`, `SERVER_NW_LATENCY_MS`, `APPL_LATENCY_MS` (= server response time), `RETRANSMITTED_IN/OUT_PKTS`, `OOORDER_IN/OUT_PKTS` | ntop IE table (§2.4); Cisco APM emits *"server network delay, client network delay, and application delay"* on-box |
| **Cisco SD-WAN Cflowd/IPFIX** | **IPFIX v10, 4 collectors per device, 1:1 unsampled, carrying app id/category AND BFD average latency/loss/jitter**, 60 s active timeout | The cleanest agentless egress found anywhere |
| **Wireless controller APIs** | Per-client association sessions, **the conditional onboarding funnel (assoc → auth → DHCP → DNS)**, failure step and reason, roam events with duration, per-link RF (RSSI/SNR/MCS/NSS/retry) | Meraki `connectionStats` / `failedConnections` / `connectivityEvents`; Aruba New Central **Client Onboarding Score API broken out by `assoc`/`auth`/`dhcp`/`dns`** |
| **802.11 vendor extensions via the AP** | **Apple Analytics** disassociation reason codes (DHCP failure, EAP timeout, 802.1X failure, captive-portal failure, excessive beacon loss) and **Intel Analytics** roaming insights — **real endpoint-side signal, no agent** | Meraki firmware 28.1+/28.3+ |
| **DHCP / DNS / RADIUS logs** | The same onboarding funnel derived independently of any controller, and the cross-check that proves which step failed | Implied by every vendor's funnel; **UNVERIFIED as a named vendor feature** |
| **Microsoft Graph `callRecords`** | **Per call: Wi-Fi signal strength, band, channel, radio type, BSSID, link speed, subnet, reflexive IP, RTT, jitter, loss, and the user's own rating — every platform Teams runs on, no agent** | learn.microsoft.com; **no vendor in this survey uses it as a primary DEX signal** |
| **Public BGP (RIPEstat)** | Routing-status, bgp-updates, announced-prefixes, AS overview — BGP-aware path attribution, **no request-count limit**, 8 concurrent connections per IP | stat.ripe.net |
| **CrUX API** | p75 LCP/INP/CLS/TTFB per origin and URL, by form factor — **a free global peer baseline** | developer.chrome.com/docs/crux/api |

**Trade-off:** Tier 0 sees *what the network and the SaaS control planes already know*. It cannot
see render time, and it cannot see a user who never sent traffic through the instrumented path.
Its coverage is also gated by API economics — **Meraki's 10 req/s is per organisation and shared
with every other tool the customer runs**; **Mist is 5,000 calls/hour per token**; **Classic
Aruba Central is 5,000/day + 7/s with one token per 30 minutes**. Prefer org-scoped endpoints,
webhooks, streaming and push destinations over polling.

### Tier 1 — Correlix's own probers, already built
Correlix already ships **STAMP** (`collectors/stamp.go`), **traceroute** (`collectors/
traceroute.go`, `golang.org/x/net` ipv4+icmp, allowlisted), **HTTP/ICMP/TCP synthetics**
(`collectors/synthetics.go`), **wan-echo** (`collectors/echo.go`), a **flows tier** with an
**NBAR/IPFIX app-id adapter** (`appid/adapter/nbar_ipfix.go`), and a **wireless per-client event
tier** in ClickHouse — `wireless_sessions`, **`wireless_onboarding_episodes` with per-phase
applicability and outcome**, `wireless_roams`, `wireless_mlo_links`, `wireless_client_rf` with
RSSI/SNR/MCS/NSS/retry sampled **at event boundaries only**
(`src/backend/internal/chschema/wireless_schema.go`). **The onboarding-episode table is already a
Mist-SLE-shaped structure.** The measurement-source tier ladder is already designed and shipped
(`docs/design/wan-measurement-source-ranking.md`, SHIPPED 2026-07-01), ranking app/user
experience (T1) above agent probes (T2) above device-native probes (T3) above passive telemetry
(T4) above flow-derived inference (T5).

**Interference:** a STAMP sender is plain UDP — no raw sockets, no privileges. Traceroute needs
`CAP_NET_RAW`. Probe volume is the thing to bound, and the market gives the numbers to bound it
against: **AppNeta 20–50 packets/minute**; **ThousandEyes 245 packets / 27 KB per round for TCP
agent-to-server, rising to 806 packets / 485 KB with bandwidth measurement enabled**;
**Netskope 6–12 segments per hop**; **Aruba UXI ~30,000 tests/day/sensor**; **Cisco Cloud OnRamp
~20 probes/minute per app-group × path**.

### Tier 2 — device-native probes already present in the network
Point a sender at reflectors that already exist. **Fortinet exposes `twamp` as a first-class
SD-WAN health-check protocol**; STAMP interoperates with TWAMP-Light in unauthenticated mode
(RFC 8762 §4.6). **Cisco IP SLA / Juniper RPM results are readable over SNMP
(CISCO-RTTMON-MIB)** — **UNVERIFIED in this session**, verify before relying on it. Y.1731 DM/LM
gives the same for carrier Ethernet — also **UNVERIFIED**.
**Interference:** configuration on the device, but **no new software and no new box.**

**And the single best technique in the survey, which belongs here:** Cisco's **DSCP-aware
probing** — *"the forwarding class determines the QoS queue in which the BFD echo request is
queued"* — so a probe experiences the same queueing as the traffic class it represents.
Fortinet achieves the same with `class-id` on SLA probes. **Every out-of-band prober that ignores
this is measuring a queue no user's traffic ever enters.** Correlix's probes should carry the
DSCP of the class they claim to represent.

### Tier 3 — opt-in lightweight probes at branches
A small site prober (container, VM, or an existing Correlix collector host) running the same
STAMP/traceroute/HTTP synthetics from the branch LAN. This is what AppNeta Monitoring Points,
ThousandEyes Enterprise Agents, Netskope Enterprise Stations, Fortinet OnSight and Aruba UXI
sensors all are.
**Interference:** one appliance per site — and note the scaling traps the market has already hit:
**Netskope requires one Enterprise Station per tunnel**, and its Network Probes must **bypass**
the tunnel while its App Probes must be **steered** through it, i.e. two opposing PBR rules.
**Aruba UXI density is 1 sensor per 5–8 APs / one per retail location / one per small floor.**
**Design rule: one prober per site, dual-homed logically (one test set through the WAN overlay,
one through DIA), never one per tunnel.**

### Tier 4 — the browser
A RUM snippet gives what nothing else can: **LCP, INP, CLS and the full Navigation Timing
waterfall** (DNS / TCP / TLS / TTFB / transfer), at p75, comparable to CrUX. It requires a change
to the application, so it is only available for apps the customer controls — and note that
**ThousandEyes does not expose Core Web Vitals at all**, and Zscaler's RUM requires a **browser
extension** and is Advanced-Plus-only, Windows/macOS-only.

### Tier 5 — the endpoint agent, last
Everything above fails to see: render time, per-process CPU attribution, boot and logon time,
crashes and hangs, and the off-network user. Only an agent gets those, and **only on Windows and
macOS** (§1.16). The costs are real and documented: EDR/AV allowlisting (Zscaler needs both 32-
and 64-bit GPO paths), an **Npcap driver on Windows** (ThousandEyes), **14 named processes
including `mtr`/`curl`/`tcping`** (Palo Alto), device serial numbers and per-process inventories,
and OS privacy settings that **silently zero the Wi-Fi data** when disabled (Zscaler's
SSID/BSSID; Netskope's hidden-SSID → Wi-Fi sub-score 0; Netskope's **English-only Windows
performance counters**).

**The recommended posture, in one line:** *agentless by default and complete enough to be useful
alone; branch prober where the customer opts in; browser RUM where the app is theirs; endpoint
agent only where the question genuinely cannot be answered otherwise — and say so in the UI.*

## 3.3 The dashboard patterns — the "glossy" bar, described concretely

Correlix already has a design system to hang this on: dark graphite/midnight-navy glassmorphism,
`--accent-teal #2DD4BF` for live telemetry and verified evidence, `--accent-ai #A78BFA` for AI
reasoning only, `--crit #F43F5E` for **confirmed** impact only, `--suspected #F97316` for
suspected RCA and carrier/ISP fault domain, `--unknown #64748B`
(`docs/design/glassmorphism-noc-ui.md`). The patterns below map onto it directly.

**1. The path graph, with a two-channel node encoding (ThousandEyes).** Left-to-right node-link
graph, agents left, target right. **Fill colour = ownership zone** (dark blue = the agent's local
network, blue = identifiable hop, white = unidentifiable, green shading = inside the destination
AS, black ring = the target); **ring = fault** (red ring = loss). **Link colour = delay**.
**Line thickness = number of traces on that route**, which is how ECMP becomes legible.
**Dashes = uncertainty** — dotted line + hop count for a collapsed path, dotted link with `?` for
unknown hops, `X` for a failed trace, a red loop for a routing loop. Controls: Show / Group (by
agent, network, location) / **Highlight sliders** (forwarding loss, link delay in 5 ms steps) /
Select — with **double-click selecting every path through a hop**, and a **complexity slider** that
collapses routes. **Selection and highlights persist in the URL and in snapshots** — that is the
handoff mechanism. Hover exposes MPLS label stacks.
— https://docs.thousandeyes.com/product-documentation/internet-and-wan-monitoring/path-visualization.md
*The design lesson: sliders exist so the picture degrades to "one red thing" rather than a red
wall.*

**2. The time-scrubbed chain (Zscaler Cloud Path).** A latency/loss timeline on top; **clicking a
point on the timeline snaps the hop chain below it to that instant**. The chain itself is a
horizontal run of node icons — client → egress → Service Edge → destination — with
**differential latency per leg and the single worst leg coloured orange**. Interface type
(cellular / Bluetooth / USB / unknown) is an **overlay icon above the client**. Errors are inline
clickable icons. A **Command Line View** mirrors it as an MTR-style table with hop-direction
arrows.
— https://help.zscaler.com/downloads/zdx/analytics/users/evaluating-cloud-path/zdx_MaxLatencyonZEN.png

**3. The score card strip + coupled zoom (Zscaler user detail).** A horizontal strip of
per-application score cards with the **worst app auto-selected**, above a banded score timeline
whose **drag-to-zoom (5-minute floor) simultaneously re-scopes web-probe metrics, device health
and Cloud Path**. One gesture, three panels.
— https://help.zscaler.com/downloads/zdx/analytics/users/evaluating-user-details/zdx-user-details-apps.png

**4. Treemaps for population, not pie charts (Zscaler).** Access points rendered as a treemap
where **tile colour = score band and tile size = number of users**, sorted largest-first;
the same idiom reused for software inventory by vendor. This answers "where is the pain, weighted
by how many people feel it" in one glance.
— https://help.zscaler.com/downloads/zdx/analytics/monitoring-wi-fi-dashboard/ZDX-Wi-Fi-Dashboard-1.png

**5. The baseline-relative bar (Zscaler Network Intelligence).** Top-5 high-latency ASNs where
**a tall red bar means "above its own baseline" and a thin mark means "near baseline"** — the
encoding is *deviation*, not absolute value. Paired with a world map carrying **animated
"rippling" anomaly markers**, suppressed below a 50-user threshold per geolocation.
— https://help.zscaler.com/downloads/zdx/analytics/monitoring-network-intelligence-dashboard/zdx-network-intelligence-overview-1.png

**6. Semantic gaps and event lanes (Aruba UXI, Meraki).** UXI: *"Connecting lines are drawn only
between adjacent buckets that both contain data"* — **a gap means "no test ran", never
interpolated**; buckets scale from 4 hours at 30-day zoom down to 1 minute. Meraki: a second,
orthogonal hue channel — **purple exclusively for events on the time axis** (RF configuration
changes, DFS events) and **blue for connectivity presence** (bars with gaps = disconnections),
kept separate from the green/yellow/red *state* channel. **Separating "state" hue from "event"
hue is one of the best ideas in the survey.** Versa does the same with an explicit
**inactivity bar** drawn on the x-axis.

**7. The per-hop ownership call (Meraki Client Connection Diagram).** client →(RF)→ AP →(port)→
switch →(…)→ MX with public IP, where *"each device/link displays metrics categorized as 'Good,'
'Fair,' or 'Degraded.'"* Alongside it: **ranked failure contributors summing to 100 %** with the
top one in red, floor-plan heatmaps where **darker lines = higher volumes of problematic roams
between AP pairs**, and a **config-change timeline beside the health timeline**.

**8. Baseline-coloured edges (AppDynamics).** Colour lives on the **edge** and means "slow versus
its own learned normal", so a degraded flow map reads as **a red thread through a green graph**.
And **the baseline is a dropdown** — redrawing the same topology against daily-trend vs a
release-pinned window literally changes the meaning of the picture.

**9. Grey for context (Dynatrace Visual Resolution Path).** Affected entities coloured,
*"gray nodes showing related but unimpacted entities."* Greying the unaffected majority makes one
causal chain legible far better than colouring everything.

**10. Path-vs-path comparison (Datadog Network Path).** Two paths stacked with **common hops
aligned and unique hops wrapped in a distinct colour**, overlaid RTT/loss/jitter/hop-count
timeseries, and a **health bar you scrub without moving the page's global time range**. The best
"what changed between then and now" pattern found.

**11. Discrete trend blocks (Aternity).** Trend as **eight discrete coloured blocks** for eight
weeks, not a sparkline — trend read as a colour sequence — with **grey meaning "No Data"
explicitly, never a fake zero**, and a rigid separation of a neutral hue for magnitude from a warm
ramp for severity.

**12. The single-glance aggregate (Aruba UXI "Circles View").** A large smiley as the top-level
KPI, with a **brick grid of every sensor sorted by ongoing issues**, and four traffic-light
sections (Experience / Services / Internal / External). *(Correlix should keep the idea — one
unmistakable aggregate glyph plus a sorted grid — and drop the smiley, which is off-brand for a
NOC-grade product.)*

**Anti-patterns to avoid, all observed:** four different SNR bandings across four pages of the
same vendor's documentation (Meraki) and two different client-health scales on two Aruba pages —
**one score, one banding, everywhere**; a score published only as colour bands with no formula
(Aruba, Cisco QoE/vQoE); a monitoring indicator that looks authoritative but is explicitly
*"not a failover threshold"* (Cisco vQoE); and mixing clip-art-era assets into a modern UI
(Aternity's UXI definition diagram) — **visual inconsistency reads as neglect.**

## 3.4 Identity and data model — unifying endpoints, sites, apps, paths and users

**What the market does, and where each model breaks:**
- **ThousandEyes** — `session ⟷ sample ⟷ (network profile + path)`, re-linked **every 10
  minutes**, keyed to a machine ID; a session is one visit to a domain **per protocol** (http and
  https are distinct entities). Tenancy is Organization → Account Groups, with **enrollment by a
  bearer Account Group Token** the docs say to *"keep secure, like a password."*
- **Zscaler** — joins on **user, device, application, location, location group, department, user
  group, geolocation, OS, ASN/ISP, Service Edge**, with probe targeting on each dimension
  (**capped at 100 selections per field**).
- **Netskope** — four *contributions* (Device, On-Ramp, SaaS/Custom App, Private App) per user per
  5-minute window; **the composite is undefined below 2 of 4**.
- **Fortinet** — the scoring unit is a **(location, target) pair**, so one app carries many
  simultaneous scores, one per observer. **Infrastructure-shaped, not identity-shaped** — no
  documented IdP join.
- **Aruba UXI** — `customer → hierarchy_node (≤10 levels) → sensor/agent → network → service`.
  **There is no user, no session and no real-client entity at all** — `context.mac_address` is the
  *sensor's* MAC. This is the clearest example of an identity model that cannot answer "which
  user is affected".
- **Microsoft CQD** — converts subnets into named buildings/sites via an **uploaded tenant
  building data file**; a ready-made site-identity join a third party can mirror.

**The synthesis the coordinator should build on — five entities and the joins between them:**

| Entity | Key | Joined by |
|---|---|---|
| **User / principal** | tenant + IdP subject | RADIUS username, 802.1X identity, Teams `callRecords` participant, agent enrolment |
| **Endpoint / device** | tenant + stable device id | MAC (with a **confidence flag** for randomised MACs), serial, agent id, Intune/AMAPI device id |
| **Session** | deterministic hash | Correlix already does this: `sha256(tenant\|bssid\|client_mac\|assoc_start_ms)` for wireless sessions, with `identity_confidence` ∈ {unknown, …} and `identity_method` recorded |
| **Site / location** | tenant + site | Subnet→building map (CQD-style), controller site id, SD-WAN site id, geolocation |
| **Application** | tenant + app | NBAR/app-id from flow, SNI/hostname from synthetics, `(hostname, IP)` server tuple from outage detection, domain for RUM |
| **Path / seam** | tenant + (src, dst, method) | Correlix's existing `PathSource` + `MeasurementTier` (1–5) provenance model |

**Three rules that fall straight out of the research:**
1. **Carry identity confidence as data, not as an assumption.** Correlix already does exactly this
   in `wireless_sessions` (`identity_confidence`, `identity_method`; a randomised-MAC client is
   honestly `unknown` and *"cross-session history honestly does not exist"*). Extend that pattern
   to every DEM join. Note the market's own inconsistency here: **Meraki's Scanning API does not
   hash MACs while Location Analytics SHA1-hashes, salts and truncates to 4 bytes.**
2. **Every metric carries its observer and its tier.** Fortinet's insight — one app, many
   simultaneous scores, one per observer — is right, and Correlix already has the machinery
   (`observer_id`, `collection_path`, `data_class` columns; `PathSource.Tier()`/`TierLabel()`).
   A DEM score should be presented **as a tuple of (score, observer, tier)**, never as a bare
   number.
3. **A composite refuses to render when its inputs are too thin.** Netskope's 2-of-4 rule.
   Combine it with Correlix's existing "no-data is not zero" discipline and Aruba's semantic chart
   gaps.

## 3.5 Licensing and packaging norms

**The five shapes actually in use:**
1. **Consumption units** — ThousandEyes: rate = agent type × test type × interval × timeout;
   nested layers are free; **units do not roll over**; overage cap defaults to **115 %**; bundles
   priced as blocks (Campus & Branch Assurance = 10,000 units + 100 endpoints + 1 Internet
   Insights package). Cisco's Offer Description also defines **Endpoint Agent Licenses per Active
   User** with a **30-day reassignment lock**, **Connected Devices**, **Cloud Insights**, and
   **Site-Based Offerings**.
2. **Per seat, tier-gated** — Zscaler: four tiers whose cut lines are the product
   (probe interval 15 min vs 5 min; retention **2 days vs 14 days**; RUM, Incidents, Network
   Intelligence, Device Health and Copilot all **Advanced Plus only**; alert rules 3/10/25/100).
   Palo Alto ADEM: **per mobile user + per remote site, and the counts must match the Prisma
   Access base exactly — no partial tenant.**
3. **Per device / per session, published to the cent** — Datadog (per 1k RUM sessions split
   **ingest $0.15 / retain $3.00**; browser test = 1 run per **25 steps**; **regional multipliers
   1.0 / 1.2 / 1.25**) and Dynatrace (**DEM units**: RUM session 0.25, with replay 1.0, synthetic
   action 1.0, HTTP request 0.1, property 0.01; $2.25–$4.50 per 1k).
4. **Hardware + per-sensor subscription** — Aruba UXI, with agent licences drawn from the **same
   pool** ("number of cloud subscriptions = number of user devices added").
5. **Bundled into the network licence** — Meraki (Insight standalone **deprecated 2024-07-26**;
   WAN/Web-App/VoIP Health are **Secure SD-WAN Plus / Advantage only**, and **vMX cannot run
   it**); Cisco DNA Advantage bundling ThousandEyes WAN Insights but capping it at **six
   applications per SD-WAN fabric**.

**Two market signals worth acting on.** (a) **The endpoint-DEX vendors publish no prices at all;
the application-DEM vendors publish complete price lists.** DEX is sold, APM is bought. (b) The
loudest reviewer complaint about the category leader is **unit-model opacity** — *"Licensing
complexity arises from the credits system"* (PeerSpot, ThousandEyes 4.2/5, n=26).
**For Correlix** — whose model of record is Apache-2.0 open core with `enterprise/`-bounded
commercial add-ons and **semantic entitlements** rather than tier checks
(`docs/design/LICENSING_MODEL_2026-09-04.md`) — the natural shape is a **`FeatureDEM`-style
entitlement plus a transparent, countable unit** (monitored endpoints, or probe-targets, or
sites), **published**, with **no expiring credits**. That is a differentiator precisely because
the incumbent's unit model is its most-criticised attribute. **All competitor list prices in this
research are UNVERIFIED** — pricing pages returned 403 throughout.

## 3.6 Risks

**(a) Privacy and employee monitoring — the sharpest risk.** The endpoint data classes the market
normalises are, collectively, employee surveillance: **device serial numbers, per-process
inventories, browser session metadata, battery health, location-derived Wi-Fi identifiers, and
remote script execution on the endpoint**. Mitigations that already exist in the market and
should be adopted wholesale:
- **Suppression at source, on the device** (Nexthink): hash usernames, disable focus-time and
  user-activity-time reporting, **prevent SSID/BSSID collection**, prevent domain reporting.
- **Drop credentials at collection**: ThousandEyes drops `Cookie`, `Set-Cookie` and
  `Authorization` headers **at collection**, not at storage.
- **Irreversible client-side masking** (Datadog): *"Masked data is not collected in its original
  form… and thus is not sent to the backend"* — as opposed to server-side scanners a privileged
  user can unmask.
- **Allow-list masking with reviewable exposure** (Dynatrace `data-dtrum-allow` + release quality
  gates): exposing a field becomes a code change someone reviews.
- **Deterministic pseudonymisation** (ThousandEyes): the operator follows one identity across
  every view without ever seeing who it is.
- **Population floors before rendering**: Microsoft's **5-employees-per-city** floor; Zscaler's
  **50-users-per-geolocation** floor on anomaly markers; Palo Alto's **≥20 agents per baseline
  cluster**; Aruba's **≥20 sensors** before incident detection.
**The two failures to avoid, both observed:** **Aternity's PII encryption is not retroactive**
(*"historical data will not be affected"*), so a works-council-driven enablement leaves the prior
corpus readable for its full retention; and **Aternity's DEM-Q industry benchmark has no
documented opt-out**, while Microsoft's equivalent baseline explicitly does. **Consent-first
benchmarking is a defensible position and a cheap differentiator.**
**UNVERIFIED:** specific EU works-council / DPIA material published by Nexthink or Aternity could
not be retrieved.

**(b) Endpoint footprint and blast radius.** An agent that installs a **packet-capture driver**
(Npcap), runs **14 processes including `mtr`, `curl` and `tcping`**, or ships a process
(`ZSAScript`) **whose purpose is executing remote scripts** is a security-review event and an
EDR-conflict risk. And the whole apparatus can be **silently defeated by an OS privacy setting**
(Zscaler's Wi-Fi identifiers), a **hidden SSID** (Netskope → sub-score 0), or a **non-English
Windows build** (Netskope's performance counters). Publish a measured footprint; nobody else does.

**(c) Synthetic load on SaaS targets.** Probe traffic is real traffic against someone else's
service, and the volumes are non-trivial: **ThousandEyes 245 packets / 27 KB per round, or 806
packets / 485 KB with bandwidth measurement (~18×)**; **Aruba UXI ~30,000 tests/day/sensor**;
**Cisco Cloud OnRamp ~20 probes/min per app-group × path**; **Netskope 6–12 segments per hop**.
Zscaler's own documentation tells operators to scope probes to relevant user groups to *"avoid
unnecessary traffic."* Risks: rate-limiting or blocking by the SaaS provider, distortion of the
customer's own usage analytics, and cost on metered links. **Bound it: a published per-round
byte/packet budget, a global probe-rate ceiling per tenant, and HEAD-style checks where a GET is
not needed (Fortinet offers HEAD checks explicitly to avoid consuming server bandwidth).**

**(d) Measuring the wrong thing and not saying so.** Three concrete traps documented by vendors
themselves: **Meraki's `bestEffortMonitoringEnabled`** silently measures *the nearest hop* when
the media server filters ICMP and still reports it as your VoIP path quality; **ThousandEyes'
Invisible MPLS tunnels** are undetectable and *"an erroneous link may be inferred"*; and
**ThousandEyes on IOS-XE probes from Virtual Port-Group interfaces that bypass AppRoute data
policies entirely** — the agent does not measure the path the router actually chose for user
traffic. Correlix's existing truthfulness posture (fidelity ladder, `data_class`, provenance
tiers) is the right defence, and these three should be written into the design as named
anti-requirements.

**(e) Probe honesty.** Every vendor except Fortinet documents that deprioritised or dropped
ICMP/UDP corrupts path measurement, and only Fortinet can **QoS-classify its own probes**
(`class-id`) or fall back to a **passive mode that needs no probes at all**. A probe in the
default queue is not measuring the queue the user's traffic uses.

**(f) API-budget exhaustion at the customer's expense.** Polling a controller consumes a shared,
customer-wide resource: **Meraki 10 req/s per organisation shared across every tool**; 1,000
networks × 10 apps ≈ **17 minutes of continuous polling at 100 % of the customer's budget**.
Webhooks, streaming and push destinations are not merely more efficient — they are the difference
between a good citizen and an outage.

**(g) Retention asymmetry.** ThousandEyes: UI 31 days / API 90 / **per-hop path 30** / HAR 45 /
snapshots forever. Zscaler: **14 days at every tier, 2 days on Standard**, query span capped at
48 hours. Cisco SD-WAN: **14 days at 1,000+ devices**, with silent deletion under backpressure.
Meraki: **Insight 7-day lookback; uplink loss/latency has effectively no history**. Mist Premium
Analytics: 13 months, **no API**, 12–36 hours stale. **Decide retention per artifact class and
make the permanent artifact first-class** — and note that continuous warehousing is itself a
competitive advantage over every one of them.

---

# §4 Design inputs — one page for the coordinator

**The market's shape in five sentences.** Every serious DEM converges on a **0–100 score, three
bands, per user, per application, on a 5-minute window** — and the boundaries all differ
(66/34 · 70/30 · 71/31, Versa inverted), so cross-source normalisation must be explicit.
**Scoring is table stakes; segment attribution is the product**, and attribution quality tracks
whether the vendor baselines *per segment* or *per fault class*. **Nobody produces a
seam-attributed causal claim spanning device → radio → LAN → WAN → SaaS → application tier**:
ThousandEyes gets from the radio to the SaaS front door and stops, Dynatrace and Datadog start at
the front door, Aternity and Nexthink own the device and stop at the NIC — **the join is
unowned**. Detection latency at the incumbents is measured in **tens of minutes**, not seconds.
And the most-criticised attribute of the category leader is **not its technology but its unit
licensing model**.

**Ten decisions the design has to make, each with the evidence already in hand.**

1. **Score shape.** Adopt **0–100, three bands**. Choose Netskope's boundaries (Good ≥71 · Fair
   31–70 · Poor ≤30) or Palo Alto's (70/30) and **never invert**. **Publish the formula** — three
   of five SASE vendors do, ThousandEyes does not, and that is the visible gap.
2. **Reduction operator.** The market splits: Zscaler takes **minima everywhere** (worst-wins:
   sensitive, noisy); Netskope and Palo Alto **average/percentile** (stable, but Netskope warns a
   15-minute incident is *"diluted to near invisibility"* in an 8-hour view). **Expose both** — a
   worst-case score for triage and a percentile score for reporting — and label which is on
   screen.
3. **Availability is a gate, not a term.** ADEM: availability 0 → score 0. Netskope: fewer than
   **2 of 4 contributions** → **no score at all**. Adopt the refusal-to-render rule; it pairs
   exactly with Correlix's existing "no-data is not zero" discipline.
4. **Segments.** Use Correlix's existing **seam vocabulary** rather than inventing a parallel one.
   The market's segment sets map cleanly onto it: Device · Wi-Fi/radio · LAN · site egress/on-ramp
   · WAN overlay/underlay · ISP (with **blackout vs brownout** and **internal / ISP-to-ISP /
   peering** sub-types, from Zscaler) · SaaS/DC · Application. Carry **forward vs reverse path**
   separately where the data supports it.
5. **The one call the UI must make.** ThousandEyes' framing is the right north star:
   **red mid-path = forwarding loss (path owner) · red at the target = terminal loss (application
   owner)** — *"it tells you who owns the fix."* That is the same seam-ownership philosophy
   Correlix's RCA already holds.
6. **Baselining.** Three tiers, all achievable: **self** (per path/user, Correlix already has
   per-path p50/p99), **cohort** (Palo Alto's City × ASN × Gateway clustering with a **≥20-member
   floor**; Microsoft's **worst-2 %-within-cohort** classifier is the most defensible), and
   **global** (**the CrUX API — free, p75, no agent, 150 queries/minute**). A single-tenant
   on-prem product **cannot** replicate ThousandEyes' cross-customer outage corroboration; the
   honest substitute is **public BGP (RIPEstat) + per-tenant corroboration**, said plainly.
7. **Collection ladder (the "minimal interference" answer).** Tier 0 — **flow ART IEs, SD-WAN
   IPFIX carrying BFD latency/loss/jitter, controller onboarding funnels, 802.11 vendor
   extensions (Apple/Intel analytics via the AP), DHCP/DNS/RADIUS logs, Microsoft Graph
   `callRecords`, RIPEstat, CrUX** → nothing installed anywhere. Tier 1 — **Correlix's existing
   STAMP / traceroute / HTTP-ICMP-TCP synthetics / wan-echo**. Tier 2 — **point at reflectors that
   already exist** (TWAMP-Light on FortiGate, IP SLA/RPM over SNMP — the latter **UNVERIFIED**).
   Tier 3 — **one opt-in prober per site**, never one per tunnel (Netskope's per-tunnel Enterprise
   Station is the mistake to avoid). Tier 4 — **browser RUM** for apps the customer owns
   (LCP/INP/CLS — which **ThousandEyes does not expose at all**). Tier 5 — **endpoint agent last,
   Windows/macOS only**, because iOS structurally cannot do it.
8. **Probe discipline.** **Carry the DSCP of the class the probe claims to represent** (Cisco's
   app-probe-class, Fortinet's `class-id`) — an out-of-band probe measures a queue no user's
   traffic enters. **Use Paris-consistent traceroute** (hold the flow tuple; vary the UDP
   checksum / TCP sequence number) and, like ThousandEyes, run **multiple traces per round with
   varying source ports to *expose* ECMP** rather than hide it. **Publish a per-round packet/byte
   budget** and a per-tenant probe-rate ceiling; the benchmarks are AppNeta **20–50 packets/min**
   and ThousandEyes **245 pkt / 27 KB per round (806 / 485 KB with bandwidth)**.
9. **Identity.** Five entities — **user · endpoint · session · site · application · path/seam** —
   with **identity confidence carried as data** (Correlix already does this for randomised MACs in
   `wireless_sessions`), a **subnet→site map** in the CQD style, and **every metric presented as
   (value, observer, tier)** using the existing `PathSource`/`MeasurementTier` provenance model.
   Fortinet's insight is right: one application legitimately has many simultaneous scores, one per
   observer.
10. **Licensing.** A **semantic entitlement** (`FeatureDEM`-shaped, consistent with
    `LICENSING_MODEL_2026-09-04.md`) plus **one transparent, countable, published unit** and
    **no expiring credits** — deliberately positioned against the incumbent's most-criticised
    attribute.

**What Correlix already has that shortens this materially.** STAMP sender, traceroute (Paris-
capable via `x/net` ipv4+icmp), HTTP/ICMP/TCP synthetics, wan-echo, a flows tier with an
NBAR/IPFIX app-id adapter, a **wireless per-client event tier whose `wireless_onboarding_episodes`
table is already an SLE-shaped structure** (per-phase applicability and outcome, so a skipped step
is never a failure), MLO-aware per-link RF, a shipped **5-tier measurement-source ranking** with
per-field provenance, tenant isolation with FORCE-RLS and ClickHouse row policies, a correlation
engine with seam-level RCA, and a NOC-grade dark glassmorphism design system with a disciplined
status palette. **DEM is largely a new set of scores, joins and surfaces over telemetry Correlix
already collects — not a new collection stack.**

**The five things to build that nobody in the market does well.**
1. **The unowned join** — one causal chain from radio to application tier, seam-attributed.
2. **A published, auditable experience score** with its inputs visible, in a market where the
   leader's score is a single undisclosed curve.
3. **A published agent footprint.** Only Nexthink (<0.15 % CPU, ~60 MB) and Aruba UXI (1–3 % CPU,
   <100 MB) publish anything; Aternity refuses on principle.
4. **Microsoft Graph `callRecords` as a first-class agentless DEX source** — per-call Wi-Fi
   signal, band, channel, radio type, BSSID, link speed, subnet, RTT, jitter, loss and the user's
   own rating, on every platform, with no agent. **No vendor in this survey is documented as using
   it this way.**
5. **Sub-minute detection and attribution**, against incumbents averaging over 10–60 minutes.

**The three highest-value research gaps still open** (close before anchoring the design on them):
**Juniper Mist SLE mechanics** (juniper.net unreachable — do not build on remembered SLE math),
**Cisco Catalyst Center Assurance health-score weights** (cisco.com unreachable), and **Kentik**
(entirely unverified, and the closest architectural analogue to Correlix's flow + synthetics + BGP
combination). **Catchpoint and AppNeta are partially verified**; note that Catchpoint now operates
under **LogicMonitor**, and that the claim "Catchpoint is the only vendor publishing an end-user
experience formula" needs re-verification. All **list prices, for every vendor, are UNVERIFIED**.

---

# Sources

Inline citations throughout are authoritative; this is the grouped index. Pages marked **403** or
**unreachable** were attempted and refused — recorded so the gap is auditable.

**Standards and specifications**
- RFC 8762 STAMP — https://datatracker.ietf.org/doc/html/rfc8762
- RFC 5357 TWAMP — https://datatracker.ietf.org/doc/html/rfc5357
- RFC 7679 one-way delay — https://www.rfc-editor.org/rfc/rfc7679.html
- RFC 7680 one-way loss — https://www.rfc-editor.org/rfc/rfc7680.html
- RFC 5481 PDV vs IPDV — https://datatracker.ietf.org/doc/html/rfc5481
- RFC 3611 RTCP-XR — https://www.rfc-editor.org/rfc/rfc3611.html
- Mean opinion score — https://en.wikipedia.org/wiki/Mean_opinion_score
- Apdex — https://en.wikipedia.org/wiki/Apdex
- Core Web Vitals — https://web.dev/articles/vitals
- Navigation Timing — https://developer.mozilla.org/en-US/docs/Web/API/Performance_API/Navigation_timing
- CrUX API — https://developer.chrome.com/docs/crux/api
- Paris traceroute — https://paris-traceroute.net/about
- IANA IPFIX registry — https://www.iana.org/assignments/ipfix/ipfix.xhtml
- nProbe flow information elements — https://www.ntop.org/guides/nprobe/flow_information_elements.html
- RIPEstat Data API — https://stat.ripe.net/docs/02.data-api/
- Playwright Docker — https://playwright.dev/docs/docker
- 802.11k (thin source, flagged) — https://en.wikipedia.org/wiki/IEEE_802.11k-2008
- **Unreachable:** ITU-T G.107 (front matter only) · ITU-T Y.1731 · all cisco.com IP SLA and AVC/ART pages

**Cisco ThousandEyes** — docs.thousandeyes.com: cloud-agents · enterprise-agents (installing:
docker-based, TEVA, TEPA, cisco-devices/catalyst-routers, catalyst-switches, nexus-switches,
application-hosting) · enterprise-agent-utilization · endpoint-agents (how-does-the-endpoint-
agent-work, data-collected-by-endpoint-agent, endpoint-agent-licensing) · end-user-monitoring/
viewing-data/agent-views · tests/network-utilization-from-enterprise-agent-test-traffic ·
browser-synthetics/transaction-tests (scripting-reference, getting-started, secure-credentials) ·
internet-and-wan-monitoring/path-visualization (+ path-trace, mpls-tunnel-inference) ·
internet-insights (+ int-terminology) · wan-insights · alerts (default-alert-rules,
alert-notifications, adaptive-alerting, dynamic-baselines, suppression-windows) ·
event-detection · integration-guides (catalyst-center, webex-controlhub, opentelemetry/
support-and-limitations, mcp-server) · user-management (account-groups, how-long-is-data-
accessible, multi-region, usage-and-billing/test-layers-units) · getting-started-with-the-api ·
whats-new/changelog. Plus the **Cisco ThousandEyes Offer Description** —
https://www.cisco.com/c/dam/en_us/about/doing_business/legal/OfferDescriptions/ThousandEyes-Cloud-Service-Product-Description.pdf
and https://www.peerspot.com/products/thousandeyes-reviews.
**403:** thousandeyes.com/pricing · Gartner Peer Insights · G2 · TrustRadius.

**Catchpoint / LogicMonitor** — https://www.logicmonitor.com/catchpoint/internet-health
(reached via a 301 from https://www.catchpoint.com/internet-sonar).

**Zscaler ZDX** — help.zscaler.com/zdx: understanding-zdx-score · understanding-zdx-cloud-
architecture · evaluating-cloud-path · evaluating-user-details · configuring-probe ·
understanding-probing-criteria-logic · understanding-tunnel-information-cloud-path ·
monitoring-devices-overview · monitoring-wi-fi-dashboard · monitoring-network-intelligence-
dashboard · monitoring-incidents-dashboard · monitoring-data-explorer-views ·
understanding-real-user-monitoring · understanding-managed-monitoring · about-alerts ·
understanding-alert-triggers · about-diagnostics · about-integrations · zdx-module-processes-
allowlist · understanding-remediation · supported-versions-feature-compatibility ·
viewing-software-inventory; plus help.zscaler.com/unified/ranges-limitations (the tier matrix)
and the screenshot URLs cited inline under §1.5.

**Netskope** — docs.netskope.com: how-dem-user-experience-scores-are-calculated ·
understanding-digital-experience-management-dem-scores · synthetic-probes · performance-metrics ·
proactive-digital-experience-management-enterprise · dem-data-intelligence-agent · dem-insights ·
borderless-sd-wan (**login wall**) · netskope-one-sd-wan-licensing-terms (**login wall**).

**Palo Alto Networks** — docs.paloaltonetworks.com/autonomous-dem: get-started/experience-score ·
adem-monitoring-and-tests-for-mobile-users · …-for-remote-networks · adem-licensing ·
frequency-of-test-runs · adem-data-collection-and-agent-processes · agent-processes-windows ·
monitor-lan-health · netsec-health.

**Versa** — docs.versa-networks.com: Configure Digital Experience Monitoring (Director and
Concerto) · View Digital Experience Monitoring Dashboards · Active Application Performance
Monitoring Logs.

**Fortinet** — docs.fortinet.com: fortimonitor 26.2.0 user-guide (ux-score, endpoint-agent,
sd-wan-application-monitoring, synthetic-monitoring, alerting and CounterMeasures pages,
multi-tenancy, api-rate-limits) · fortigate 7.4.0 administration-guide (performance-sla-overview,
mean-opinion-score-calculation…, classifying-sla-probes-for-traffic-prioritization) ·
fortiaiops 3.0.0 user-guide (overview, sd-wan).

**Juniper Mist** — juniper.net: rest-api-http-response-codes · api-endpoint-url-global-regions ·
frequently-asked-questions-for-analytics. **Unreachable:** every SLE, Marvis and WAN Assurance
page (404 / ECONNRESET), and mist.com.

**Cisco Catalyst SD-WAN / vManage** — cisco.com sdwan docs: application-aware-routing ·
m-enhanced-application-aware-routing · m-application-performance-monitoring · traffic-flow-monitor
· cloud-onramp-saas (+ vEdge cor-saas, application-lists) · monitor-maintain-book
(vmanage-monitor-overview, m-applications-performance-and-site-monitor, m-network,
m-alarms-events-logs, m-troubleshooting, m-database, Analytics) · network-wide-path-insight ·
vAnalytics · system-overview · ch-server-recs-26-1-combined · TAC 220477 ·
rate-limit-for-bulk-api-requests · monitoring-with-thousandeyes · DNA subscription FAQ ·
ThousandEyes ordering guide (PDF) · developer.cisco.com/docs/sdwan (authentication, rate limits,
bulk-api) · Cisco Live **BRKENT-3412** PDF (the only published Cloud OnRamp probe algorithm).

**Cisco Meraki** — documentation.meraki.com: Meraki Insight Introduction · MI Web App / WAN /
VoIP Health Overviews · Smart Threshold in Meraki Insight · Root Cause Analysis for Web App
Health · Dashboard Alerts – Insight · Meraki Health Overview (+ Client Details, AP Details) ·
Meraki Health Alerts – Smart Thresholds · Meraki Assurance Overview Page · Network Service Health
· Client Roaming Analytics · Location Analytics · Scanning API FAQ · MR MQTT Data Streaming ·
MT MQTT Setup Guide · Subscription – MX Licensing · Dashboard Data Availability · Webhooks ·
Meraki MX ThousandEyes Configuration Guide. Plus developer.cisco.com/meraki: rate-limit ·
authorization · the Insight, wireless connection-stats/failed-connections/latency/connectivity-
events and organization-scoped endpoints cited inline · scanning-api/overview · guides/webhooks.

**HPE Aruba** — UXI: the PSNow datasheet (a00048302enw) · api.capenetworks.com/docs/openapi.yaml ·
help.capenetworks.com (sensor test cycle, custom test templates, predefined tests, Teams VoIP MOS
test, service rate limiting, path analysis, packet capture, types of dashboard issues, AIOps
incident detection, time navigation and test result charts, Wi-Fi environment visualization, data
push destinations + the four schemas, webhooks, best-practice design, FAQs, throughput testing,
UXI agent for Windows & macOS, data collected by UXI agent, subscription management, SaaS vs
E-STU, Terraform provider). Central / EdgeConnect: arubanetworking.hpe.com/techdocs (insights
overview, faqs/ai-insights, client-details-wireless-overview, clients-list-view, healthbar-ap,
network_health_uxi, api-streaming-public-cloud, subscrib_streaming_api, api_webhook,
lic-ftr-det-ai, central258, the Data-Explorer null search, amon, sdwan live-view and
application-summary, orchestrator api-key) and developer.arubanetworks.com (aruba-central
api-getting-started; new-central getting-started-with-rest-apis, webhook-authentication,
central-mcp-server, getclientonboardingscorev1, getclientdetails) · devhub.arubanetworks.com.

**Riverbed Aternity · Nexthink · Datadog · Dynatrace · Splunk/AppDynamics** — help.aternity.com
(system requirements, agent install and modules, PII collection/decrypt, privacy web addon,
retention, RBAC, DXI view and administration, UXI glossary, DEM benchmark, Remediate, licensing,
VDI, Wi-Fi analysis) and riverbed.com product pages · docs.nexthink.com (technical-requirements,
collector-overview, collector-management, dex-score + dex-score-computation, remote-actions,
campaigns, workflows, alerts-and-diagnostics, nql-data-model, data-we-collect-and-store,
data-resolution-and-retention, privacy-policy-and-settings) · datadoghq.com/pricing and
docs.datadoghq.com (synthetics incl. api/browser/mobile/private-locations, RUM incl. session
replay and privacy options, network_monitoring/performance, cloud_network_monitoring,
network_path, network_monitoring/devices, watchdog incl. rca, billing, data_retention_periods) ·
dynatrace.com/pricing and docs.dynatrace.com (digital-experience, rum-classic incl. user-
experience-score and apdex-ratings, visually-complete, GDPR configuration, synthetic-monitoring
and private locations, session-replay configuration and restrictions, DEM units,
root-cause-analysis/concepts, automated-multidimensional-baselining, smartscape-concepts,
data-privacy-and-security, the notification integrations) · help.splunk.com (observability cloud
overview, detectors and alerts, system limits and retention, synthetic monitoring incl. browser
test metrics, RUM incl. session replay and sensitive-data controls, the ThousandEyes integration;
AppDynamics EUM incl. browser/mobile RUM metrics, synthetic monitoring, experience journey map,
EUM licensing; APM business transactions and dynamic baselines; flow maps; health rules and
anomaly detection; licensing models) · developer.cisco.com/docs/cisco-observability-platform.

**Microsoft, Apple, Android** — learn.microsoft.com: cqd-what-is-call-quality-dashboard ·
stream-classification-in-call-quality-dashboard · cqd-intelligent-media-quality-classifiers ·
cqd-upload-tenant-building-data · use-call-analytics-to-troubleshoot-poor-call-quality ·
graph/api/resources/callrecords-* (api-overview, callrecord, mediastream, networkinfo,
participantendpoint, endpoint) · graph/throttling-limits · office-365-network-mac-perf-overview ·
intune/endpoint-analytics (scores, startup-performance, app-reliability, work-from-anywhere,
ref-data-collection) · the intune-devices-userexperienceanalytics* Graph resources ·
wlan_association_attributes · about-event-tracing. developer.apple.com: deviceinformationresponse
· statusreport · status-items · statusdevicebatteryhealth · nehotspotnetwork (+ signalstrength,
fetchcurrent) · nwpath (+ linkquality) · nwconnection · mxmetricpayload · bgapprefreshtaskrequest
· bgprocessingtaskrequest · cwinterface/rssivalue; plus support.apple.com managed-device-
attestation. developers.google.com/android/management (enterprises.devices + the v1 discovery
document) and developer.android.com (wifi-scan, WifiInfo, NetworkCapabilities, InetAddress,
doze-standby, Android 14 fgs-types-required, managed-profiles).

**Corporate** — HPE closes the Juniper acquisition (2 July 2025):
https://www.hpe.com/us/en/newsroom/press-release/2025/07/hewlett-packard-enterprise-closes-acquisition-of-juniper-networks-to-offer-industry-leading-comprehensive-cloud-native-ai-driven-portfolio.html
· https://www.datacenterdynamics.com/en/news/hpe-closes-14bn-acquisition-of-juniper-networks/

**Correlix internal references** (for the coordinator, not external sources):
`docs/design/wan-measurement-source-ranking.md` · `docs/design/active-measurement.md` ·
`docs/design/path-trace-hop-metrics-stamp.md` · `docs/design/glassmorphism-noc-ui.md` ·
`docs/design/LICENSING_MODEL_2026-09-04.md` ·
`src/backend/internal/chschema/wireless_schema.go` · `src/backend/collectors/{stamp,traceroute,synthetics,echo}.go` ·
`src/backend/appid/adapter/nbar_ipfix.go` · `src/backend/path_metric_resolver.go`
