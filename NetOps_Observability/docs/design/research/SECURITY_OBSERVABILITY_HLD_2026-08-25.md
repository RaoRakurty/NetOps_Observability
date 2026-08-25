# Correlix Security Observability — consolidated High-Level Design (2026-08-25)

This is the finalized HLD, reconciling two independent research streams:
- **Owner's `Security-Deep.md`** (strategy/architecture vision — telemetry
  pillars, dual-graph model, exposure scoring, 36-month roadmap, GTM).
- **Agent research** `SECURITY_SECTION_RESEARCH_2026-08-25.md` +
  the deep-security stream (granular market verification, Gartner-dated
  trajectory, a codebase audit that found the Security section ALREADY
  PARTIALLY BUILT, and the network-first differentiation argument).

Product-strategic decisions here are the OWNER's to ratify; this document
proposes and marks open questions. No implementation follows it (per owner:
"Don't implement Security section — leave as is").

---

## RATIFIED DECISIONS (owner)

**2026-08-25 — SCOPE: network-first, security-in-correlation, NOT a SIEM.**
The biggest open question (§9.3) is ANSWERED. Correlix's security scope is the
NETWORK ESTATE — routers, switches, firewalls, and the seams between them.
Server / container / cloud / host / app security detection is EXPLICITLY OUT
OF SCOPE and routed to the customer's existing SIEM (emit OCSF/normalized
findings TO Splunk/Sentinel/Elastic — a partner integration, a selling point,
never a competitor stance). Correlix does NOT try to out-SIEM Splunk on their
turf. Security is added as a FOURTH EVIDENCE CLASS to the EXISTING correlation
engine — security incidents become seam-attributed RCA/exposure objects, not a
parallel security product. This closes §9.3 and constrains every design choice
below: if a proposed capability pulls toward general-purpose log SIEM, it is
out; if it deepens network-security-in-the-causality-graph, it is in.

## 0. The single most important finding (both streams, decisive)

**The Security section is not greenfield — it partially exists in code.** The
agent's codebase audit found:
- `src/backend/internal/vuln`: offline CSV advisory feed (built by
  `scripts/vuln-feed-prepare.py` from NVD + CISA KEV), vendor/product/version
  matching mirroring NVD cpeMatch, tenant-scoped `/api/vulns` with an
  "unassessed devices" honesty list.
- `src/backend/internal/compliance`: 9 checks (SoT drift ×5, SNMP policy ×2,
  OS fleet-baseline consensus, KEV presence), each framework-tagged.
- `ThreatDetection.tsx`: flow-derived heuristics (scan fan-out, risky ports),
  honestly framed in-code as "heuristic, not a verdict."
- Nav already has Security → Vulnerabilities / Threat Detection / Compliance.

**This reframes the entire plan from "build a security product" to "evolve
four existing lanes into the correlation engine."** The owner's 36-month
"Year 1 = ingest flows/build correlation" roadmap is therefore already DONE —
Correlix's Year-3-in-the-owner-plan foundations (Kafka, ClickHouse, RCA
engine, seam grounding, tenant isolation) all ship today. The real roadmap
starts at the owner's "Year 2."

---

## 1. Where the two streams AGREE (the ratified core)

1. **Security is a fourth evidence class for the correlation engine, not a
   bolt-on SIEM.** Both streams independently reach this. The owner's
   dual-graph (Operational + Exposure) and the agent's "security incident as
   an RCA object with an evidence chain" are the same idea. This is THE
   differentiator: Datadog bolts a SIEM alongside; Correlix folds security
   into the seam-attributed causality graph it already owns.
2. **CVSS + EPSS + KEV exposure scoring** — both propose it; both warn against
   naively multiplying EPSS by CVSS (the agent cites the FIRST guidance
   explicitly). Reconciled formula in §4.
3. **The four pillars**: vulnerabilities/exposure, threat detection (NDR-lite),
   compliance, DEM. Both agree, same order.
4. **Network-first GTM** vs Datadog (cloud-first), Elastic/Splunk
   (log-centric), Zabbix (no security). "See across every seam" is the owner's
   line; the agent adds the pricing anchors ($7/device Datadog NDM) and the
   sharpest one-liner: *"the security product for the asset class Datadog
   forgot."*
5. **Build-vs-integrate**: build the correlation/detection IP, integrate
   feeds/pipelines. Both agree.

## 2. Where the streams DIFFER — and the reconciliation

| Topic | Owner's Security-Deep | Agent research | Reconciled decision |
|---|---|---|---|
| **Starting point** | 36-month greenfield from telemetry ingestion up | Section already partially built; start at evolution | **Evolution.** The owner's Year-1 is shipped. Re-baseline the roadmap to start at his Year-2. |
| **CVE data source** | NVD JSON + MITRE feeds | NVD CPE matching is BROKEN for network OSes (60-80% of 2024 CVEs uncped; IOS train naming defeats CPE ranges). **Vendor PSIRT version-query APIs are the gold standard** (Cisco openVuln OS-version endpoints, PAN, Arista CSAF) | **Both, tiered.** Keep the offline NVD CSV as the air-gap base (also the sovereignty story); add PSIRT connectors as plugins where a vendor offers a version API. Never rely on NVD CPE alone for network gear. |
| **NDR depth** | Full packet capture (Zeek/Corelight/ExtraHop-style sensors) as a goal | Packet NDR needs taps Correlix doesn't have; flow-behavioral + device-log detection from ALREADY-INGESTED telemetry is the credible v1 | **Flow + syslog first (zero new sensors).** Packet NDR is a Tier-3 "validate demand first" item, not a v1 pillar. The agent's economics win: detect on telemetry already held. |
| **Detection content** | ML anomaly detection (LSTM/GNN) prominent early | ~25 curated device-log rules FIRST (Splunk ESCU + Sigma cisco/aaa as syllabus); ML gated behind baseline warm-up; FP burden is the product-killer | **Curated rules first, ML later.** A NOC will permanently disable a noisy ML lane. The maintenance-window join (Correlix knows the windows) is the FP killer competitors lack. |
| **Exposure scoring context** | Internet-facing / asset-criticality multipliers | Dynatrace's mechanism: mutate severity from OBSERVED topology (seam position, mgmt-plane reachability from flow evidence) | **Merge.** Use the owner's factor list, but source "internet-facing" from the SEAM MODEL (not a manual tag) and "mgmt exposure" from flow evidence — the observability advantage Dynatrace has and the digital twins don't. |
| **Graph model** | Two graphs (Operational + Exposure/Attack) | Security incident as an RCA object on the existing causality graph | **One engine, security as evidence class.** The "Exposure Graph" is not a second graph to build — it's the existing causality graph with security-lane evidence folded in. Avoids a whole parallel subsystem. |
| **10-yr framing** | CTEM matures, agentic AI, telemetry explosion (directional) | Same, but with VERIFIED Gartner dates (CTEM 3x/2026, preemptive 50%/2030, 1M CVEs/2030, NDR MQ 2025, CRA Sept 2026, PQC 2030/2035) and explicit flags on unverifiable numbers | **Use the agent's dated version.** Several widely-quoted Gartner figures are unverifiable; the roadmap leans only on the dated-and-sourced ones. |

## 3. The flagship object — the Exposure Story (both streams converge here)

A new correlation output class beside RCA reports: an episode whose evidence
set includes security-lane objects, grounded on the same entities and seams.
Canonical narrative (fully supported by the researched Salt Typhoon /
ArcaneDoor TTPs):

> Edge router R1 (ISP seam, tenant Acme-East): KEV-listed CVE on IOS-XE
> 17.9.x (exposure elevated: internet-facing seam + EoL approaching) →
> config change outside any maintenance window: new local user + GRE tunnel +
> syslog target removed (device-log signals, MITRE-tagged, Salt Typhoon TTP
> cluster) → new persistent low-jitter flow to an unseen ASN (beaconing) →
> branch experience degrades on paths transiting R1. The engine grounds all
> four on R1 and its seam, folds them into ONE story: "Branch degradation and
> anomalous egress possibly because of compromise of R1 via CVE-XXXX —
> evidence: [config diff] [flow series] [advisory] [path change]. Ownership:
> LAN edge (yours). Mobilize: isolate R1 / interim ACL / golden-image
> upgrade."

This IS Gartner's CTEM loop rendered as product — Scope → Discovery →
Prioritize → **Validate (with observed telemetry — pure EAP vendors can't)** →
Mobilize (action queue + maintenance windows, all existing surfaces). Nobody
ships it: flow vendors detect but don't explain; packet NDRs explain but need
new sensors; digital twins (Forward, IP Fabric) have posture but NO live
telemetry or incident pipeline.

## 4. Reconciled exposure score

Owner's factor list, agent's data-quality corrections, seam-sourced context:

```
factors (each clickable to its evidence):
  cvss_base        normalized 0..1
  epss_band        FIRST daily; BAND not raw-multiply (0.5 threshold guidance)
  kev              CISA KEV membership → urgency boost
  eol_state        VulnCheck: 42.5% of exploited edge CVEs are on EoL gear —
                   "still receives fixes?" beats any score; first-class field
  seam_exposure    FROM THE SEAM MODEL (internet/DIA seam ⇒ up) — not a tag
  mgmt_exposure    FROM FLOW EVIDENCE (is SSH/SNMP/web-UI reachable, from where)
  asset_criticality  business tier (owner metadata)
Output: an Exposure Score + the evidence list, every factor auditable.
```
The two differentiators over Dynatrace's Davis score: seam-sourced exposure
(they have no network inventory to score) and mgmt-plane reachability from
real flow data.

## 5. Section / nav structure (evolve the existing Security section)

```
Security
├── Security Overview     posture command-center (exposure trend, open stories,
│                         drift, compliance % by framework, signal volume)
├── Exposure              (evolved Vulnerabilities): Findings · Advisories &
│                         Feeds (PSIRT connector health) · Lifecycle (EoL board)
├── Threat Detection      (evolved): Signals (MITRE facets) · Detections
│                         (rules-as-code, tuning) · Network Behavior (flow)
├── Compliance            (evolved): Posture (benchmark scores by framework) ·
│                         Config & Drift (capture history, planned-vs-unplanned)
│                         · Evidence & Reports (auditor packs)
└── Exposure Stories      security-flavored RCA objects (also under Investigate)

DEM lives NOC-first (Operations/its own top-level) with a security-overlay
seam lens as a facet — it is not primarily a security surface.
```
Every surface §3a tenant-scoped (per-tenant feeds state, RLS on new PG tables,
`chTenantScope` on new ClickHouse queries, isolation test shipped per feature).

## 5b. Hardening / configuration audit (owner request 2026-08-25)

Owner wants **auditing tools** — proving servers, routers, switches are
hardened to industry standards (CIS benchmarks, e.g. "as simple as CIS for
Linux"). This is the COMPLIANCE pillar deepened, and it does NOT violate the
network-first / not-a-SIEM decision: **auditing reads config/state and checks
a benchmark; it is posture, not log-based threat detection.** A hardening
finding is one more evidence object ("SSHv1 enabled on core-01",
"root login permitted on app-server-3") that can feed exposure stories.

### The scope nuance to confirm

- **Network devices (routers/switches/firewalls)** — squarely IN. CIS
  benchmarks exist for IOS/IOS-XE 17.x, JunOS v2.1.0, Arista EOS v1.0.0,
  PAN/Fortinet/etc.; DISA STIGs split into NDM/RTR/L2S guides. This is the
  natural extension of the 9 existing checks and is already the Tier-2
  "benchmark engine" item. No new decision needed — build it.
- **Servers / Linux (CIS for Linux)** — a DEFENSIBLE ADJACENCY, not a scope
  break, precisely because it is compliance/posture and NOT SIEM. But it
  crosses from "network estate" to "servers," and it needs a NEW collection
  surface (an agent or SSH + a scanner). **Recommended line to hold:** we
  AUDIT server posture (read config, check a benchmark), we do NOT ingest
  server logs for threat detection — that stays the customer's SIEM's job.
  With that line, Linux/server hardening audit is a legitimate Phase-2
  capability. **Owner to confirm** whether server-scope audit is in.

### Architecture principle: integrate the benchmark engine, author the correlation

The benchmark CONTENT is a maintenance treadmill (CIS versions, quarterly
STIG revisions) — do NOT author it from scratch. Integrate the standard
engines and turn their output into Correlix evidence objects:

- **Network devices:** capture running config over SSH (the Tier-2 config-
  capture feature — feeds compliance + threat + RCA at once), parse with a
  ciscoconfparse2-style hierarchy parser, evaluate a curated CIS/STIG NDM
  rule subset. Own the rules here (small, high-value, network-specific).
- **Linux/servers (if in scope):** do NOT reimplement CIS-for-Linux. INGEST
  the output of the established scanners the customer likely already runs —
  **OpenSCAP/SCAP (OVAL/XCCDF, the open standard), CIS-CAT, or Lynis** — via
  an agent or a results-upload API, and normalize their findings into the
  same ComplianceState/finding model. Build-vs-integrate: integrate the
  scanner, own the normalization + correlation + evidence-story.
  (Deep research on OpenSCAP vs CIS-CAT vs Lynis — licensing, output formats,
  agent footprint — recommended before committing; that is Fable's lane.)

### What it produces (the useful part)

- Per-device / per-host **hardening score** with per-rule pass/fail EVIDENCE
  (the exact config line / OVAL result), framework-tagged (CIS/STIG/PCI/
  DORA/NIS2 — the `Framework` field already models this).
- **Drift-in-minutes** on network devices (syslog-triggered re-audit — the
  differentiator competitors lack) and scheduled re-audit on servers.
- **Planned-vs-unplanned** classification (join against maintenance windows +
  audit log) — a hardening regression outside a change window is itself a
  signal, and can promote into an exposure story.
- **Auditor evidence packs** (the regulatory clock — CRA Sept 2026, DORA,
  NIS2 — makes exportable evidence a sales feature).

### Risk (unchanged, restated for this scope)

Content maintenance is the largest recurring cost. Mitigation: own only the
small network-device rule set; INTEGRATE server benchmark engines rather than
maintain SCAP content; ship "audit-ready evidence," not "certified
compliance," until the certification budget exists. And close Correlix's own
scaffold-grade defaults before selling a hardening product — a hardening tool
that isn't hardened is an embarrassing demo.

## 6. Build order (agent's telemetry-grounded version, owner's phasing intent)

**Tier 0 — harden what's shipped:** EPSS + EoL columns in the feed-prepare
script; KEV facet UI; **emit existing vuln/compliance findings as bus events
so the engine can ground them** (small producer + catalog hypotheses — this
alone lights up the first exposure stories).

**Tier 1 — cheap, existing telemetry, no new engines:**
1. Device-log detection pack (~25 rules over syslog already in OpenSearch;
   maintenance-window join = the FP killer).
2. SecuritySignal event class + engine grounding.
3. Security Overview posture dashboard (assembly).
4. DEM assembly (experience score from existing path/flow/wireless data;
   seam-blame rendering, which already exceeds ThousandEyes' fwd/terminal-loss
   attribution).

**Tier 2 — moderate, new collectors, existing deps:**
5. **Config capture + diff** (SSH via already-allowlisted `x/crypto/ssh`,
   syslog-triggered) — highest leverage single feature: feeds compliance,
   threat, AND RCA at once.
6. Text-tier benchmark engine (CIS/STIG NDM subset; framework tags exist).
7. PSIRT connectors as plugins (offline CSV stays the air-gap path).
8. Flow-behavioral detections in ClickHouse (beaconing/tunneling/exfil).
9. BGP/route-anomaly detection — synergy with the shipped BGP Ops page (§item
   10) and its planned RIS Live consumer.

**Tier 3 — new engines (validate demand first):** packet NDR; model-based
validation (Batfish-class — Java/Python, needs an isolated RPC plugin per §4);
AEV-lite exposure validation (opt-in, heavily gated); auditor report packs;
agentic triage on exposure stories (under §15 LLM rules).

## 7. Risks (the agent's list — all real, owner should weigh)

1. **FP burden is the product-killer** for threat detection. Mitigation: small
   curated pack, maintenance-window suppression, per-rule tuning + backtest,
   ML gated behind baselines. Keep the honest "heuristic not verdict" framing.
2. **Compliance content is a treadmill** (CIS versions, quarterly STIG
   revisions). Largest recurring cost. Ship a small pinned NDM subset; never
   claim full-benchmark certification without the content budget.
3. **Certification expectations**: ship "audit-ready evidence," not "certified
   compliance." AND close Correlix's own scaffold-grade defaults (OpenSearch
   security plugin off, SNMP defaults) before marketing a security SKU — or
   the story is embarrassing.
4. **Vendor-API fragility** (openVuln quotas, Juniper has no API): offline CSV
   stays canonical; connectors degrade to "feed stale" banners.
5. **Version-matching correctness**: prefer vendor version APIs over NVD
   ranges; keep the "unassessed devices" honesty list front and center.
6. **Scope creep into SIEM** — the gravitational pull to "ingest everything."
   The moat is network-first, seam-attributed. Route server/cloud log
   detection to partner SIEMs (pipeline-first "emit OCSF" = a feature).
7. **Active-validation liability** (AEV can break prod gear): default-off,
   per-tenant opt-in, vendor-safe methods only.
8. **Prediction risk**: lean only on verified Gartner dates.

## 8. 10-year trajectory (agent's verified version supersedes the owner's
directional one; same conclusions, dated)

- CTEM mainstream (3x fewer breaches/2026); VM category REPLACED by Exposure
  Assessment Platforms (inaugural MQ Nov 2025) — a list UX won't survive 1M+
  CVEs by 2030 (Gartner).
- Preemptive security = 50% of security spend by 2030 (Gartner, Sept 2025).
- NDR a durable pillar (inaugural MQ 2025) — the network detection Correlix
  targets is structurally first-class, not a fad.
- Agentic SOC with guardian oversight (70% multi-agent by 2028); regulation
  clock CRA Sept 2026 / Dec 2027, DORA live, NIS2 transposed — evidence export
  becomes a sales feature; PQC crypto-agility ("where is RSA-2048 on my
  devices") becomes a compliance query by 2030/2035.

## 9. Open questions for the owner

1. **Ratify the evolution framing** (start at your Year-2; Year-1 is shipped)?
2. **Packet NDR** — Tier-3 "validate demand" (agent) or an earlier pillar
   (your Security-Deep)? Recommendation: Tier-3; the flow+syslog v1 is where
   the differentiated wedge is.
3. **Scope discipline** — ✅ **RATIFIED 2026-08-25: network-first, hold the
   boundary.** Server/cloud/host detection routes to partner SIEMs (emit
   OCSF); Correlix does not pursue general SIEM. Security is a fourth
   evidence class in the correlation engine. (See RATIFIED DECISIONS above.)
4. **Compliance content budget** — is there appetite for the recurring
   benchmark-maintenance cost, or ship "drift + golden-config" only and defer
   framework certification?
5. **Timeline** — the agent's Tier-0/1 is weeks-scale on existing telemetry;
   your 36-month plan front-loaded telemetry that's already built. Re-baseline?

Sources: both research streams (this doc's siblings in docs/design/research/
and /var/tmp/Security-Deep.md); every price/prediction/rule-count/campaign
detail carries its source in the underlying stream, unverifiable claims
flagged inline there.
