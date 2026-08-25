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

## ARCHITECTURE CONSTRAINT — security is a REMOVABLE module (owner, 2026-08-25)

**"Keep the security module modular — remove it from correlation if needed."**
This is a HARD design constraint, not a preference. Security must be a clean,
detachable component; the correlation engine must NOT hard-depend on it.

Mechanism (this is what makes it satisfiable):
- Security lanes are **PRODUCERS** onto the event bus — they emit generic
  evidence objects (SecuritySignal / ExposureFinding / ComplianceState) that
  carry `entity + seam + timestamp + evidence-refs`, the SAME shape every other
  evidence source uses. Security is added as a fourth evidence class by
  EMITTING, not by editing the engine.
- The correlation engine consumes ANY evidence object through its EXISTING
  generic grounding path. It has **zero security-specific code**. It does not
  import the security packages. It grounds "an evidence object with entity+seam"
  — it neither knows nor cares that a given one came from the security lane.
- Therefore **removing security = removing its producers** (feature flag off /
  packages absent). The engine keeps working, just with one fewer evidence
  source. No surgery, no engine dependency to unwind. This is exactly §4
  plug-and-play: isolated, no cross-domain imports, replaceable without system
  change.
- Packaging: security lives in its own packages (`internal/vuln`,
  `internal/compliance`, a new `internal/threat` / `internal/audit`), gated by
  a `FEATURE_SECURITY`-class flag, dormant by default (like every other opt-in
  feature — traceroute, device-ssh, copilot). Its nav section, its bus topics,
  and its stores are all droppable as a unit.

Design test: if a proposed integration would put security-specific logic INSIDE
the correlation engine, it is wrong — re-shape it as an evidence object the
generic engine grounds. The engine's contract is "I ground evidence"; security
is one supplier of evidence, never a dependency.

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
  capability. **✅ OWNER CONFIRMED 2026-08-25: in scope.**

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

  **✅ OWNER CONFIRMED 2026-08-25: server/Linux hardening audit IS in scope**
  (posture, not SIEM — the line holds: audit config, don't ingest logs).
  Tooling research DONE (HARDENING_AUDIT_TOOLING_RESEARCH_2026-08-25.md).
  Headline decisions:
  - **Linux: integrate OpenSCAP/SSG FIRST** (LGPL+BSD-3, ARF/XCCDF, remediation
    codegen, commercially clean). Lynis second (GPLv3). **CIS-CAT is BLOCKED**
    for a commercial product without a negotiated CIS OEM license — the
    licensing, not the tooling, is the gate. Never claim "CIS-certified";
    OpenSCAP output is "CIS-aligned".
  - **Network devices: own-rules-over-captured-config is primary** — there is
    NO machine-readable CIS content for network gear (all PDF prose); only DISA
    SCAP/OVAL for Cisco IOS/IOS-XE is automated (ingest that via OpenSCAP).
    Batfish (Apache-2.0) as an opt-in deep semantic tier. ciscoconfparse2 is
    GPLv3 → RPC-sidecar only, never linked in.
  - **Normalize to OCSF compliance_finding (class 2003, Apache-2.0)** — posture-
    purpose-built, superset of the existing internal/compliance Finding, and it
    IS the "emit OCSF to partner SIEMs" scope decision realized. evidence_class
    "posture" makes it the 4th correlation lane.
  - **Integration: results-upload API first** (customer runs scanner, uploads
    ARF/JSON — least invasive, sidesteps CIS-CAT licensing); SSH-and-run
    secondary via the existing gateway; no phone-home agent.

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

## 5c. Rule evaluation architecture — local-store + local-eval, NOT per-check API (owner decision 2026-08-25)

Owner question: "how are we going to match against the company's rules — will
that be imported into a local DB, or run API calls and ensure? Think optimized
and efficient." **Recommendation: import rules into a LOCAL, VERSION-PINNED
store and evaluate LOCALLY against captured device/host state. The network is
touched ONLY by a background content-sync, never by a per-check API call.**

Separate two things the question conflates:
- **Rule CONTENT** (the benchmark/company-policy DEFINITIONS): local store,
  version-pinned, synced in the background.
- **EVALUATION** (matching a device's captured state against the rules): a
  pure local function (captured_state, ruleset_version) → findings. No network.

### Why local-store + local-eval (five reasons, all decisive)

1. **Determinism & audit.** A compliance verdict must be reproducible: "was
   device X compliant at time T, under which rule version?" If rules come from
   a live API, a past verdict can't be reproduced — auditors (PCI/DORA/NIS2)
   require exactly this. Version-pinned local rules make every verdict
   replayable.
2. **Air-gap / offline.** Compliance in banks/utilities/gov often runs
   air-gapped. Per-check external API calls are a non-starter there. Correlix's
   ethos is already offline-first (the vuln feed is an offline CSV) — stay
   consistent.
3. **Scale.** 1,000 devices × hundreds of rules per cycle cannot make an
   external call per rule — that is latency and rate-limit death. Local
   evaluation is the only path that scales (and the 1K soak proves the local
   compute budget exists).
4. **Availability.** External API down = compliance blind. Local rules =
   compliance always works. A monitoring product must not have a monitoring
   blind spot when a third party has an outage.
5. **Cost.** API-per-check has no viable economics at fleet scale.

### The ONE thing that is a network call: background content sync

New benchmark versions (CIS releases, DISA STIG quarterly revisions,
ComplianceAsCode/CIS-CAT content updates) sync in the BACKGROUND into the
local store, version-pinned, on a slow cadence (weekly). Evaluation NEVER
blocks on a sync. This mirrors `scripts/vuln-feed-prepare.py` exactly — the
vuln lane already does offline-prepared, hot-reloaded, version-pinned content.
Same pattern, one more feed. Air-gapped installs get an operator-provisioned
bundle instead of a live sync (the vuln feed's air-gap path, reused).

### Company/custom rules are ALWAYS local + per-tenant

A customer's own hardening standard / golden config / policy overlay is their
IP — stored per-tenant under FORCE-RLS, never external. This reuses the EXISTING
managed-rules pattern (migration 0033 pipeline-processors): rule DEFINITIONS
live version-pinned (in code / synced store), per-tenant ENABLEMENT + cloned
customizations live in the tenant DB. Do not invent a new mechanism.

### Audit is PERIODIC, not continuous (owner refinement 2026-08-25)

Owner: "audit is not required every day — it can be done once in a while."
Correct, and it SIMPLIFIES the build. The primary mode is a batch audit, not a
continuous engine:

- **PRIMARY — scheduled + on-demand batch audit.** Operator clicks "Run audit"
  (before a real audit / a change) or it runs on a schedule (monthly /
  quarterly, configurable). A full fleet scan of 1K devices is a trivial batch
  job — the soak proves the compute budget — so the heavy incremental
  machinery (rule→input indexing, per-change recompute) is UNNECESSARY for the
  core audit function. Don't build it for v1. A batch that walks every device ×
  its benchmark, produces per-device scores + evidence + the exportable
  auditor pack, and stamps the pinned ruleset version. Simple and complete.
- **Periodic audit REINFORCES the local-store decision.** If you audit
  quarterly, you MUST be able to say "this was CIS v8.1 as of the audit date" —
  the rules cannot silently shift between audits. Version-pinning matters MORE
  when audits are infrequent, not less. This kills any per-check-API idea
  outright.
- **OPTIONAL later layer — continuous drift.** Event-driven re-check on a
  syslog-signalled config change is a VALUE-ADD (a hardening regression that
  feeds an exposure story: "SSHv1 got re-enabled on core-01 the night before
  the incident"), NOT part of the core audit product. Defer it; it only earns
  its keep once the correlation tie-in is being built, and it can reuse the
  166/167 incremental lessons THEN.

### The only efficiency rules that still apply to the batch

1. **Compile the ruleset once per version, reuse across all devices** (the
   snapshot-epoch lesson — build the expensive structure once, not per device).
2. **Cache a device's verdict by (config_hash, ruleset_version)** so a
   scheduled re-audit skips devices that didn't change since the last run —
   and the key doubles as the audit trail.
3. **Background content sync stays weekly + version-pinned** — evaluation
   always runs against a pinned version, never a moving target.

Net: a simple, complete, on-demand/scheduled batch audit that is reproducible,
auditable, and air-gap-capable — with continuous drift as an optional
correlation-feeding layer added only when its exposure-story value is wanted.

### Frequency is a BILLING dimension (owner, 2026-08-25)

"If it needs to run more frequently, that cost goes to the customer depending
on resources used — storage / RAM / CPU." Audit frequency is a resource-
consumption lever, so it is METERED, consistent with the capacity/pricing
model (price per device, retention as an upsell, burst as SLO):
- **Baseline tier:** periodic audit (monthly/quarterly) + on-demand runs.
  Included with the security module — light, cheap.
- **Upsell tier:** high-frequency / continuous drift. It consumes more —
  more config snapshots (STORAGE), more evaluations (CPU), larger working set
  (RAM) — so it is a priced tier, charged on the resources it burns. The
  cache-by-(config_hash, ruleset_version) design means an idle fleet costs
  little even at high frequency; the cost tracks actual change volume, which
  is the fair thing to bill on.
This makes "how often do you want to be audited" a customer knob with a
resource-honest price, not a fixed platform cost the vendor eats.

## 5d. Framework strategy — one check, many frameworks (research 2026-08-25)

Owner: build compliance rules for NIST, OWASP, PCI-DSS, HIPAA, GDPR. Full
analysis: COMPLIANCE_FRAMEWORKS_RESEARCH_2026-08-25.md. The decisive framing:

**Do NOT author a rule set per framework.** Author/import the technical check
ONCE, tag it with the NIST 800-53 controls it evidences, and derive every
framework view by transitive crosswalk through 800-53 as the HUB. This is the
proven ComplianceAsCode/OSCAL pattern — 800-53 is the rosetta stone every
other framework maps TO, so one control tag inherits PCI/HIPAA/CIS/ISO/CSF
mappings for free (no N² maps).

**The frameworks live at two levels — critical for honest scope:**
- **Technical catalogs (map to device checks):** CIS, DISA STIG, NIST
  800-53/171, CSF 2.0, ISO 27001 Annex A.
- **Legal/regulatory (mostly DON'T map):** PCI-DSS (only Req 1/2/4/8/10
  technical sub-reqs), HIPAA (only §164.312 Technical Safeguards), **GDPR
  (near-zero — do NOT ship "GDPR rules for a device"; only Art. 32
  encryption-in-transit as a CONTRIBUTING control, "supports not
  demonstrates")**, **OWASP (app-security — Correlix's OWN platform, per §15,
  not a device-audit framework)**.

**Defensible claim (enforce in UI + marketing):** "audit-ready control
EVIDENCE mapped to framework controls" — NEVER "certified PCI/HIPAA/GDPR
compliance." Show a coverage % per framework so the tool visibly admits it
covers only the technical slice (e.g. HIPAA §164.312, not §164.308/.310).
Standard caption attaches to every regulatory view.

**Schema (OSCAL-aligned, not full OSCAL in v1):** Check → Control (800-53 hub)
→ Mapping (check→controls, OUR IP, per-rule) → Crosswalk (control→framework
req, IMPORTED from official sources — NIST 800-53↔CSF/ISO, PCI SSC, 800-66r2
for HIPAA, CIS Controls Navigator, never hand-maintained). Version-pin
everything; §3a tenant-scope findings, crosswalk data is global read-only
reference. Export OSCAL (Component-Definition + Assessment-Results) later.

## 5e. Network-device hardening — check catalog + remediation + the seam-aware exposure check (owner 2026-08-25)

Owner requirement: check vendor config for insecure exposures — reachable from
public networks, Telnet open, FTP open, and "all kinds of insecure options" —
and for each, **tell the operator what to configure to harden.** This defines
the network rule engine (§5b's "own-rules-over-captured-config") concretely.

### Every rule carries a REMEDIATION (the "what to configure")

A finding is not "Telnet is on" — it is "Telnet is on → to harden, apply THIS."
Each rule holds a per-vendor detection pattern AND a per-vendor remediation
snippet, both dialect-aware via the netconcepts abstraction (item 4 — a rule
reasons about the CONCEPT, renders in the device's dialect). The
ComplianceFinding already has a `Remediation` field (§5b OCSF schema). Example
finding body: *"core-01 (Cisco IOS-XE): Telnet enabled on VTY, reachable from
the ISP seam with no access-class. Harden: `line vty 0 4 / transport input ssh
/ access-class MGMT-IN in`."*

### The differentiator — SEAM-AWARE exposure, not a flag check

The highest-value check is "reachable from a public network," and it is where
Correlix beats every config scanner. CIS-CAT/OpenSCAP can only say a service
is ON. Correlix knows the **seam model** — which interfaces face the ISP /
internet / untrusted seam — so it evaluates the REAL exposure:

  service enabled  AND  bound to / reachable via an interface on an untrusted
  seam  AND  no ACL restricting it  →  EXPOSED (critical)

vs the same service on a mgmt-only interface behind an ACL → informational.
This turns a generic hardening flag into a contextual exposure verdict, and it
feeds the exposure story ("mgmt plane of R1 reachable from the internet" is a
first-class security signal). Batfish (§5b opt-in tier) sharpens this from
"interface-level" to "does a packet from the internet actually reach the
service" (ACL reachability proof) for the deep tier.

### Starter check catalog (v1 — high-value, low-FP, hand-authored)

Insecure MANAGEMENT services (should be off/secured):
- **Telnet** enabled → `transport input ssh` only.
- **FTP / TFTP** server enabled → disable; use SCP/SFTP.
- **HTTP** (non-TLS) server enabled → `no ip http server` / `ip http secure-server`.
- **SSHv1** (not v2) → `ip ssh version 2`.
- **SNMP v1/v2c** communities → SNMPv3 authPriv (already partly in the 9 checks).
- Legacy small services (finger, BOOTP, PAD, tcp/udp-small-servers, CDP on edge)
  → `no service ...`.

PUBLIC-EXPOSURE / access-control (the seam-aware set):
- VTY / mgmt lines with **no access-class ACL** → apply mgmt-subnet ACL.
- Any mgmt service (SSH/SNMP/HTTP/NETCONF) **reachable from an untrusted seam
  with no ACL** → the seam-aware critical above.
- SNMP/HTTP without source restriction.

CREDENTIAL / crypto hygiene:
- No `service password-encryption` → enable it.
- Type-7/plaintext `enable password` instead of `enable secret` → `enable secret`.
- Default SNMP communities (public/private) → remove.
- No AAA / local-only auth on a device that should use TACACS+/RADIUS → configure AAA.

PLANE hardening:
- No central logging target → configure syslog forwarding.
- No NTP auth; no CoPP / control-plane protection on capable platforms.

Each catalog entry = {concept, per-vendor detect pattern, per-vendor
remediation, severity, 800-53/CIS/PCI control tags (§5d), seam-aware? flag}.
Hand-authored (no machine-readable CIS content exists for network gear, §5b),
independently worded (CIS PDF text is non-commercial-licensed, §5b landmine),
version-pinned in the local store (§5c).

### Why this is buildable now

It reuses: config capture over the existing SSH gateway (§5b), the netconcepts
vendor-dialect abstraction (item 4), the seam model (already the core of RCA),
the ComplianceFinding/OCSF schema with its Remediation field (§5b), and the
correlation engine as the consumer (modular producer, per the removable-module
constraint). The starter catalog is ~20-30 rules — small, high-value, and the
seam-aware exposure check is the wedge no incumbent can copy without a topology/
seam model.

## 5f. Image-size & soak impact (owner asked before building, 2026-08-25)

**Image size: single-digit MB on the base — the designs protect it.**
Current: api 41.8 MB, frontend 107 MB (served dist 7 MB), correlation 300 MB.
- Backend Go code compiles into the existing static binary (+~few MB); NO new
  heavy base deps because we INGEST scanner results (not bundle OpenSCAP/
  CIS-CAT) and make Batfish/ciscoconfparse2 OPT-IN SIDECARS. api ~42 → ~45 MB.
- Frontend pages are lazy chunks (+0.5–2 MB total dist, first-load flat). An
  in-browser PCAP analyzer, if ever added, is a large OPTIONAL lazy chunk.
- Opt-in sidecars (Batfish ~1–2 GB Java, ciscoconfparse2 ~100–200 MB) are
  separate feature-flagged containers, never in the base stack.
- Backups + PCAPs are DATA VOLUMES (quota/retention-governed), not image.

**Soak: NO full redo — a direct payoff of the removable-module constraint.**
1. The current 72h soak validates the CORE correlation engine at 1K on the
   GA-candidate; the new modules are DORMANT by default and the engine has
   ZERO security-specific code (producer, not embedded), so the shipping
   default is behaviorally identical to what is soaking. The 72h investment is
   not wasted and does not restart.
2. Compiling the security code in with flags OFF owes a ~45-min T-nominal
   SMOKE gate (confirm the larger binary regressed nothing), NOT a 72h soak.
3. A full incremental soak is needed ONLY for a configuration where a heavy
   feature is ENABLED — security evidence lane active (more signals into the
   engine = heavier workload to re-characterize) or continuous packet capture
   (disk-heavy; disk is the binding resource per the soak). Even then it is an
   INCREMENTAL soak of THAT configuration, characterizing the delta on the
   known baseline, never starting core validation over.

Sequencing: let the current soak close the core-product GA gate; security/
backup/capture is a SEPARATE increment that earns its own incremental
qualification when built + enabled. The modular design is what buys this
separation.

## 5g. CVE awareness — how Correlix stays current per vendor (design)

Question: CVEs drop every day — how does Correlix know which affect which
vendor's devices? The answer inverts the naive model.

### Work from vendor ADVISORIES by version, NOT the raw CVE firehose by CPE

The naive approach — match every NVD CVE against every device by CPE — is both
INACCURATE and high-volume for network gear: NVD CPE matching is broken for
network OSes (60-80% of 2024 CVEs uncped; Cisco IOS train / IOS-XE rebuild
naming defeats CPE version ranges — §2). Instead:

- Match by **vendor + platform + EXACT build** against the VENDOR's own
  advisories (which name affected versions precisely). This inverts the server
  model (there you match a package list against NVD; here you ask the vendor
  "what affects THIS version").
- This is also **far less volume**: a vendor publishes tens-to-hundreds of
  advisories/year per platform (a tractable, curated, version-precise set) vs
  the ~40k/yr raw CVE firehose (Gartner: 1M cumulative by 2030). You never try
  to reason about a CVE that doesn't name a version you run.

The existing `internal/vuln` already does version-constraint matching
(CVE × vendor/product × version-range); the evolution is the SOURCE of those
rows and their refresh.

### Per-vendor sources (PSIRT connectors — the authoritative tier)

The only reliable way to know "what affects Cisco IOS-XE 17.9.4a" is the
VENDOR's PSIRT feed. Add per-vendor connectors (plugins, §4), each normalizing
its feed into the local advisory store keyed by (vendor, platform,
version-range):
- **Cisco openVuln API** — OS-version endpoints (`OSType/iosxe?version=17.9.4a`
  → all advisories for that build); CSAF format. The exemplar.
- **Palo Alto** per-version API; **Arista** CSAF feed; **Fortinet** RSS;
  **Juniper** portal import. ~4-5 bespoke connectors, not one loop.
- **NVD** stays as a broad SUPPLEMENT/cross-check (the current CSV base), never
  the primary for network OS.
- **Cisco EoX API** (+ operator EoL table for others) — "does this version even
  get fixes" (VulnCheck: 42.5% of exploited edge CVEs are on EoL gear — EoL is
  a first-class exposure field).

### Staying current with daily CVEs — background sync, local re-match

The refresh architecture is the §5c pattern (local store + local eval, only the
sync touches the network):
1. A **background sync** pulls new advisories (PSIRT, on-publish/scheduled) +
   **EPSS daily** + **CISA KEV daily** into the LOCAL, version-pinned advisory
   store — NOT a per-device API call.
2. On sync update (or on device-inventory change), **re-match** every device's
   version against the updated store LOCALLY — fast, no rate-limit, reproducible
   ("was this device exposed to CVE-X as of date D, under advisory feed version
   V"). New matches surface as new ExposureFindings; a device's exposure score
   updates.
3. **Air-gapped installs** get an operator-provisioned bundle (the existing
   offline CSV path — `vuln-feed-prepare.py`), refreshed on the operator's
   cadence. The sovereignty/offline story is preserved.

So "a CVE every day" is handled by a daily sync + local re-match, never by
hammering an API at check time.

### Triage the flood (prioritization overlay)

The daily flood is triaged, not listed: KEV membership (actively exploited),
EPSS band (exploitation probability), EoL state, and the seam-sourced exposure
(is the vulnerable device internet-facing, is its mgmt plane reachable — §5e).
An operator sees "3 KEV-listed, internet-facing, EoL" first, not 400 CVEs.

### Honesty (already built, keep it)

The `unassessed devices` list stays front and center: a device whose vendor has
no connector, or whose feed is stale, shows "unassessed" — NEVER a false
"no CVEs / all clear." Plus a feed-staleness banner. Correlix prefers the
vendor's word over NVD's broken CPE, and says so when it can't assess.

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

## 9. Open questions — ALL ANSWERED 2026-08-25 (build started)

1. **Evolution framing** — ✅ Start from Year-2 / evolve the existing
   foundation (don't scratch the aligned vuln+compliance seeds).
2. **Packet NDR** — ✅ Tier-3, validate demand first. Always-on packet
   inspection as a detection engine is deferred; flow+syslog v1 is the wedge.
   (The per-interface on-demand Wireshark capture module stays IN.)
3. **Scope** — ✅ Network-first; integrate/export to SIEM (emit OCSF), never
   pursue general SIEM. Security = 4th evidence class in correlation.
4. **Compliance content** — ✅ **DO NOT fund broad benchmark maintenance yet.**
   This tightens the compliance v1 scope decisively:
   - **IN (cheap, high-value, no content treadmill for us):** config
     backup + drift/golden-config, the ~20-30 hand-authored NETWORK-device
     hardening rules (the differentiator, small + slow-moving), and INGEST
     OpenSCAP/SSG for Linux (the COMMUNITY maintains that content — not us).
     Claim "hardening findings" + control evidence on the small set.
   - **DEFERRED until demand/budget:** the broad framework-crosswalk
     realization (§5d — importing/maintaining the full 800-53↔PCI/HIPAA/CSF/
     ISO mapping data), broad CIS/STIG benchmark coverage, any "framework
     compliance" claim beyond the small tagged set. §5d stays the TARGET
     architecture; its full data-maintenance is not funded now.
5. **Timeline** — ✅ Re-baseline the roadmap from the current shipped state
   (Year-1 already shipped; build the foundation now).

**Also decided this session**Also decided this session (beyond the original 5):** server/Linux hardening
IN scope (§5b); OpenSCAP-first tooling (§5b); local-store + local-eval,
periodic audit (§5c); 800-53-hub framework crosswalk (§5d); network hardening
checks + seam-aware exposure + remediation (§5e); CVE-by-vendor-advisory +
PSIRT connectors + background sync (§5g); security is a REMOVABLE module +
audit frequency = billing (ARCHITECTURE CONSTRAINT + §5c); config backup +
drift/sync + packet capture modules designed; vendor extensibility via one
declarative Vendor Profile.

**Net: 2 questions still need the owner — Q2 (packet-NDR timing, rec Tier-3)
and Q4 (compliance-content budget, rec scoped-(a)).**

Sources: both research streams (this doc's siblings in docs/design/research/
and /var/tmp/Security-Deep.md); every price/prediction/rule-count/campaign
detail carries its source in the underlying stream, unverifiable claims
flagged inline there.
