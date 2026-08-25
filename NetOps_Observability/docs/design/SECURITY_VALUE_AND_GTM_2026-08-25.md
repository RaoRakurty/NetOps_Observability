# Security — data reuse, CTEM alignment, and why customers buy (2026-08-25)

How Correlix turns the telemetry it already collects for MONITORING into
SECURITY value, why that aligns with Gartner CTEM, how it is sold, and why a
customer wants it. Strategy input for the security expansion (network-first,
security-as-a-4th-evidence-class, per the ratified HLD).

## 1. The thesis: collect once, secure twice

Correlix's structural advantage is that **the telemetry it already collects for
observability IS the security signal** — no new sensors, no new agents, no new
data pipeline. The same byte does double duty:

| Data already collected (for ops) | Same data, as a security signal |
|---|---|
| **Syslog** (interface/auth/config events) | Logging disabled, config change off-window, new local user, tunnel created — the Salt Typhoon / ArcaneDoor tells |
| **SNMP / gNMI** (device health, versions) | Unexpected reboot, software-image drift/downgrade — T1601 image tampering |
| **NetFlow / sFlow** (traffic, capacity) | Beaconing, scanning, exfiltration by volume, DDoS |
| **Config capture** (backup / drift) | Hardening audit, golden-config compliance, insecure-service exposure |
| **Device inventory** (vendor/model/version) | CVE matching via vendor PSIRT, EoL/EoS exposure |
| **Topology / seam model** (the heart of RCA) | Seam-aware exposure ("reachable from the internet?"), attack-path context |
| **Paths / synthetics / DEM** | Experience-as-evidence — path hijack, degradation coincident with a security signal |
| **The correlation engine** (already built) | Folds all of the above into one seam-attributed exposure story |

The economic consequence is the whole business case: the customer **already
pays** to collect this telemetry for operations. Security is **incremental
value on the same data** — high margin for us, near-zero friction for them
(nothing new to deploy, and network gear can't run agents anyway). Every
competitor either needs new sensors (packet NDRs), has no network telemetry
(digital twins, SIEMs), or forgot the network entirely (Datadog/Dynatrace).

## 2. Why this IS CTEM (and why we're structurally advantaged)

Gartner's Continuous Threat Exposure Management is five stages: **Scope →
Discover → Prioritize → Validate → Mobilize** (and the dated stat: orgs running
a CTEM program are ~3x less likely to be breached by 2026). Map Correlix onto
it:

- **Scope** — tenants + seams. Correlix already models the estate and its
  ownership boundaries.
- **Discover** — device inventory + topology. Already owned; it's the core
  product.
- **Prioritize** — the exposure score: CVSS + EPSS + KEV + EoL + **seam
  position + management-plane reachability from real flow** (context the
  digital twins and Dynatrace can't source for a network).
- **VALIDATE** — *this is the stage nobody else can do.* Pure exposure/EAP
  vendors and digital twins can say "this CVE exists"; they cannot confirm it
  with observed behavior. Correlix validates a hypothesis with LIVE telemetry —
  "this CVE matters because we can SEE the anomalous flow and the config
  change." That is the differentiator, and it exists only because we own the
  monitoring data.
- **Mobilize** — the exposure story's next-action + remediation, the action
  queue, maintenance windows, IRIS approve-cards, and emit-to-SIEM.

So the pitch is precise: **"CTEM, but validated with live network telemetry —
for the asset class exposure-management tools can't see."**

## 3. How we sell it

- **The wedge, stated plainly:** "the security product for the network estate
  the big platforms forgot." Datadog has 15 security SKUs and none touch
  network devices; SIEMs ship near-zero network-device content; digital twins
  have posture but no telemetry. Routers and switches are the most-attacked
  (Salt Typhoon, Volt Typhoon, ArcaneDoor — real 2024-25 campaigns) and least-
  defended class.
- **Packaging:** a security ADD-ON module to the observability platform, priced
  per managed device (the currency customers can forecast), with audit
  frequency / retention / packet-capture volume as resource-metered upsells.
  Not a separate product to integrate — it lights up on data already flowing.
- **"Collect once" economics** as the closing argument: no new sensors, no new
  pipeline, no agents on gear that can't run them. Incremental cost, multiplied
  value.
- **Land-and-expand:** land as NOC observability (today's product), expand into
  security on the SAME install — the NOC/SOC-convergence sale. Migration story
  for Zabbix / SolarWinds estates: "you already collect this; now get security
  and compliance from it, and drop two tools."
- **Partner, don't replace (the scope decision as a sales asset):** we EMIT
  OCSF findings TO the customer's SIEM (Splunk/Sentinel/Elastic) — "the network
  security piece your SIEM was always missing." No rip-and-replace, no
  competitive threat to the incumbent tool = a far easier sale.
- **A second budget holder:** compliance/audit. The regulatory clock (EU CRA
  Sept 2026, DORA live, NIS2) makes "audit-ready control evidence" a budget
  line beyond the NOC — the hardening/compliance module sells to a different
  buyer on the same install.

## 4. Why the customer buys / wants it

1. **It ends the "is it the network or an attack?" fight.** NOC and SOC blame
   each other; Correlix answers both from one causality graph with seam
   ownership. The exposure story names the owner — "your LAN edge," not a
   generic "someone."
2. **The asset class nobody else defends is the one under active attack.**
   Salt Typhoon (nine US telcos), Volt Typhoon, ArcaneDoor — current, headline,
   board-level fear — all hit routers/switches/firewalls, the class existing
   tools cover worst. A real threat, not a hypothetical.
3. **Regulatory obligation.** CRA / DORA / NIS2 give network operators legal
   duties; "audit-ready evidence mapped to controls" is a compliance line item
   with real budget and a deadline.
4. **Tool consolidation.** Enterprises run ~45 security tools; "get network
   security from the observability platform you already operate" removes a
   tool, a pipeline, and a vendor.
5. **The exposure story saves the operator's night.** The visceral one: four
   alerts every other tool makes a human correlate become one narrative with a
   next action and the evidence to trust it. Time-to-understand collapses.
6. **Predictable cost.** Per-device pricing they can forecast; no per-event
   SIEM bill surprise; security is incremental on data already sent.

## The one-sentence answer

**"You already send us the telemetry that proves your network is under attack or
out of policy — we just correlate it into seam-owned exposure stories and
audit-ready evidence, so you get CTEM-grade security and compliance from the
monitoring data you already pay for, without a single new sensor, and we hand
the findings to the SIEM you already run."**

---

## Competitive positioning — honest, no-FUD (owner 2026-08-25)

**The one rule for all of it:** claim what Correlix HAS; let the empty column
speak for what a competitor doesn't. NEVER assert a competitor is "insecure" or
"bad" — attack the GAP, not their strengths (attacking a real strength invites a
credible rebuttal and makes us look ignorant). Every "—" in a table must be TRUE
and verifiable. Comparison tables convert technical buyers; adjectives don't.

### THE headline differentiator — the cross-seam correlation engine (owner 2026-08-25)

Lead with this above every feature comparison, because none of the three have
it: **Correlix has a correlation engine that correlates issues across ALL
OWNERSHIP SEAMS — LAN, ISP, cloud provider, SaaS, app team — into ONE
seam-attributed causality graph that names the root cause AND its owner.**
- Datadog and Dynatrace correlate WITHIN their own telemetry (cloud/app/APM);
  Zabbix doesn't correlate across ownership boundaries at all. None produce a
  seam-attributed root cause ("the loss is in ISP-X's segment, not yours").
- And now SECURITY folds into that SAME engine: a security incident becomes a
  seam-owned exposure story on the same causality graph — CVE + config change +
  anomalous flow + degraded experience, correlated across seams, with the owner
  named. That is the exposure story, and it is architecturally impossible for a
  tool that has no cross-seam causality graph to produce.
- One line: **"They monitor. We correlate across every seam — and now that
  engine secures the network too."** The empty column below shows the features;
  THIS is why they can't just add them.

Add a **"Cross-seam correlation → root cause + owner"** row to every comparison
table below — it is a "—" for all three.

### vs Zabbix

- **Do NOT attack their lack of RLS as "insecure."** Not using RLS on a
  high-throughput monitoring backend is a legitimate engineering choice; a
  technical evaluator rebuts the attack in one paragraph. It's a trap.
- **Honest angle 1 (positive framing):** Correlix enforces tenant isolation at
  the DATABASE layer (FORCE row-level security) as defense-in-depth — an app
  bug still can't leak one customer's data to another. Real differentiator for
  MSP/multi-tenant. A claim about US, not a negative about them.
- **Honest angle 2 (the real gap):** Zabbix has NO security product — no vuln
  mgmt, no threat detection, no compliance/hardening, no config drift (its own
  roadmap puts even NetFlow at 2027). Correlix adds a network security layer.
- Copy: **"Zabbix tells you a device is *up*. Correlix tells you it's
  *exposed*."**

### vs Datadog

- **Do NOT attack their cloud-native breadth / integration ecosystem** — genuinely
  best-in-class; attacking it is futile.
- **The real gap (verifiable):** Datadog ships ~15 security SKUs and NONE touch
  network devices. NDM is young — ~$7/device of metrics + capture-only config,
  ZERO CVE/security features. Cloud SIEM's "network" content is firewalls/
  security appliances, not routers/switches. **"The security product for the
  asset class Datadog forgot."**
- **Supporting angles:** per-DEVICE predictable pricing vs their per-EVENT
  bills (the #1 stated SIEM-pricing resentment); on-prem/air-gap vs SaaS-only;
  network-FIRST vs cloud-first.
- **Coexist, don't rip-replace:** for a Datadog shop, Correlix is the
  network-device security layer they lack — and can emit OCSF findings to their
  stack.
- Copy: **"Datadog secures your cloud. Correlix secures the network under it."**

### vs Dynatrace

- **Do NOT attack Davis AI / APM causal analysis** — genuinely strong.
- **The real gap (verifiable):** Dynatrace barely monitors network devices at
  all — SNMP via ActiveGate extensions only, no NDM product, no flow, no
  config. Its Runtime Vulnerability Analytics is OneAgent PROCESS-level
  (Java/.NET/Node/…) — it needs an agent ON the workload, and **network gear
  cannot run an agent**. So its whole security model structurally can't reach
  routers/switches/firewalls.
- **Honest angle:** agentless network-device security — we score exposure from
  the seam position and management-plane reachability Dynatrace has no way to
  see (no network inventory to score). Steal their best mechanism
  (context-adjusted severity) and apply it where they structurally can't.
- Copy: **"Dynatrace watches your applications. Correlix watches — and secures —
  the network they run on."**

### The shared truth (the wedge)

Datadog and Dynatrace are OBSERVABILITY-first and both left the network estate
out of their security story; Zabbix has no security story at all. Correlix is
NETWORK-first with security fused into the correlation engine. We do NOT
out-cloud Datadog or out-APM Dynatrace — we own the asset class all three
under-serve, we CORRELATE it across every seam (the engine none of them have),
and we integrate/export to whatever they run. The empty column shows the
features; the correlation engine is why they can't simply bolt them on.
