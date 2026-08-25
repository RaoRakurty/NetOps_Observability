# Hardening / config-audit tooling — research + recommendations (2026-08-25)

Commissioned by the owner: how to build CIS-style hardening audit for routers,
switches, and servers/Linux. Design principle (already set): integrate the
benchmark engines, don't author benchmark content. Researched by a
web-research agent against primary sources. **Decisive axis turned out to be
commercial-ingestion LICENSING, not engineering.**

## (a) Linux/server scanners — comparison + recommendation

| Axis | OpenSCAP + SSG (ComplianceAsCode) | CIS-CAT (Lite/Pro v4) | Lynis |
|---|---|---|---|
| Standards | XCCDF, OVAL, ARF, SCAP 1.2 (NIST-validated) | emits ARF/XCCDF/OVAL; CIS-specific | none (own framework) |
| Content source | ComplianceAsCode/content (SSG), ~quarterly | official CIS-authored | CISOfy's own tests.db |
| CIS coverage | **approximation** — BSD-3 re-impl, "CIS-aligned" NOT certified | **true certified CIS** | none (own "hardening index") |
| Network devices | none (Linux/Unix/container) | partial automated (IOS-XE/XR/NX-OS, PAN); rest PDF | none |
| Output | ARF/XCCDF XML, HTML | JSON/CSV/ARF/XCCDF (no published schema) | report.dat (no JSON in OSS) |
| License | oscap **LGPL-2.1** + content **BSD-3** | proprietary; **CIS SecureSuite membership**; free PDFs **CC BY-NC-SA (non-commercial)** | **GPLv3** |
| Commercial ingestion | **CLEAN** | **BLOCKED** — internal-use-only; embedding output needs a negotiated CIS OEM license | **clean** (read output at arm's length) |

**Recommendation (Linux):**
1. **OpenSCAP/SSG FIRST** — the only option that is CIS-shaped, machine-parseable
   (ARF/XCCDF), remediation-generating, AND commercially clean. Ingest ARF;
   label honestly as "SCAP Security Guide (CIS-aligned)," never "CIS-certified."
2. **Lynis second** — GPLv3, parse report.dat, a cheap complementary hardening
   lane; never relabel its IDs as CIS.
3. **Do NOT ingest CIS-CAT output** into the sold product until a CIS
   commercial/OEM license is negotiated. Near-term-safe CIS-CAT path only:
   the CUSTOMER runs it under their OWN SecureSuite membership and uploads the
   report (even displaying embedded benchmark text is legally grey). **Contracts
   question before any engineering.**

## (b) Network devices — recommendation

Key finding: **there is almost no machine-readable CIS content for network
gear.** In the NIST National Checklist Program every CIS network-device
benchmark is registered "Prose" (manual PDF); the automated logic lives only
inside proprietary CIS-CAT Pro. DISA STIGs are manual XCCDF for all, with
automated SCAP/OVAL for **essentially only the Cisco IOS/IOS-XE family**.

Parse-library landscape: no mature Go-native network-config parser exists
(only hobby repos); re-deriving ciscoconfparse2/Batfish in Go is multi-year.
Realistic path = an isolated sidecar/plugin (fits §4 RPC-plugin rule):
- ciscoconfparse2 (Python) is **GPLv3** → keep behind a process/RPC boundary,
  never linked into the shipped binary.
- Prefer **Apache-2.0** components in the artifact: **Batfish** (Java svc +
  pybatfish — semantic ACL/reachability model), NAPALM/Netmiko/pyATS-Genie for
  capture.
- A **small Go stdlib parser** for trivial regex/indent rules (is
  `snmp-server community` present, is `service password-encryption` set) is a
  fine complement — not a replacement for the sidecar.

**Recommendation (network):** own-rules-over-captured-config is the right
PRIMARY strategy — there's no drop-in CIS content to integrate anyway, and it
plays to the config-capture Correlix already does.
1. Home-grown rule engine over captured running-config (golden-config diff +
   hand-authored hardening rules + drift) — the network-first differentiator,
   no external content license needed.
2. Ingest DISA SCAP/OVAL for Cisco IOS/IOS-XE via OpenSCAP (free, clean) — the
   one automated network family, so it's not hand-authored.
3. Batfish as an opt-in deep tier (Apache-2.0) — semantic ACL/reachability
   proofs pure text rules can't make; strong RCA-story upgrade.
4. CIS-CAT network coverage only via customer-uploads-own-report, same license
   gate as (a).

Emulate Titania's credential-less, offline-config, deterministic virtual-model
shape: capture/export config → parse → (benchmark rules) AND (golden diff) →
drift alerts → framework-mapped report with remediation. Natural fit — Correlix
already captures configs.

## (c) Normalization: OCSF compliance_finding (class 2003)

Normalize everything to **OCSF `compliance_finding`** (Apache-2.0, Linux
Foundation) — posture-purpose-built (unlike SARIF's code-location shape),
compact and queryable (unlike raw ARF XML), and it interoperates with the
SIEM/XDR stacks customers run (fits the "emit OCSF to partner SIEMs" scope
decision exactly). `compliance.status_id` normalizes Pass/Warning/Fail and
absorbs OpenSCAP XCCDF results, CIS-CAT, Lynis, and the network rule engine.
Keep raw ARF/JSON as an attached evidence blob for audit fidelity; drive
storage/RCA/API off the OCSF record. Design it as a SUPERSET of the existing
`internal/compliance` Finding so in-Go checks and external scanners share one
shape and a finding becomes the fourth correlation evidence class
(`evidence_class: "posture"`, with `severity` + `resource.device_id`). Full Go
struct sketch in the session transcript.

## (d) Integration pattern

**Lead with a results-upload API** (customer runs the scanner, uploads
ARF/JSON; we parse → OCSF). Least invasive, most enterprise-acceptable — no
inbound privileged creds, no agent — and it sidesteps the CIS-CAT license
problem (customer generates the report under their own membership).
**Secondary: SSH-and-run** (oscap-ssh style), opt-in + credentialed, reusing
the existing audited SSH gateway (`device_ssh.go`, `FEATURE_DEVICE_SSH`).
**Avoid a phone-home agent** as primary — most invasive, worst fit for network
gear, duplicates customers' existing scanners. (Agents are a non-starter on
switches/routers anyway.)

## (e) Licensing landmines (the decisive section)

1. **CIS SecureSuite terms are internal-use-only** — no resale/redistribution/
   derivative. Embedding CIS-CAT output (carries CIS benchmark text + control
   IDs) in a sold product needs a **negotiated CIS commercial/OEM license**.
   Biggest landmine; a contract gate before any CIS-CAT engineering.
2. **Free CIS benchmark PDFs are CC BY-NC-SA (non-commercial)** — cannot lift
   benchmark prose/rule text into a commercial UI. Hand-authored network rules
   must be independently worded, never copied from the PDF.
3. **"CIS Certified"/logo needs prior CIS written approval** — never imply
   certification; OpenSCAP SSG results are "CIS-aligned," not "CIS-certified."
4. **ciscoconfparse2 is GPLv3** — behind an RPC/process boundary only, never
   linked into the shipped binary; prefer Apache Batfish/NAPALM/Genie.
5. **OpenSCAP (LGPL) + SSG (BSD-3) + Lynis (GPLv3) are all safe to
   run-and-ingest** — obligations attach only to redistributing the binaries,
   not to reading their output.

## (f) Build order (cheapest-first)

1. **ComplianceFinding schema + upload API + storage** (ClickHouse/OpenSearch,
   FORCE-RLS per tenant) + the OCSF normalizer skeleton. Pure plumbing we own;
   ships the "posture" evidence class into correlation.
2. **OpenSCAP ARF ingestion** — cheapest real scanner; commercially clean;
   immediately useful for Linux/server. (Optional opt-in oscap-ssh via the
   existing SSH gateway.)
3. **Lynis report.dat ingestion** — trivial parser, complementary lane.
4. **Home-grown network rule engine over captured config** — golden diff +
   drift + starter hardening rules (SNMP v1/v2c, weak SSH/telnet, AAA,
   logging). The differentiator; no content license needed.
5. **DISA SCAP/OVAL for Cisco IOS/IOS-XE via OpenSCAP** — the one automated
   network family.
6. **Batfish sidecar (opt-in, Apache-2.0)** — semantic proofs; RCA-story upgrade.
7. **CIS-CAT** — only after a CIS OEM license; until then customer-upload only.

Content-treadmill reality: DISA STIGs revise ~quarterly, ComplianceAsCode
~2–4×/yr, CIS benchmark versions are event-driven on OS/product releases.
Integrating engines makes Linux upkeep a bounded chore; authoring your own
Linux rules would mean re-chasing every OS bump forever — so integrate there.
Network-device rules must be hand-authored (no machine-readable CIS exists) but
the surface is small and slow-moving, so the treadmill is tolerable and it's
the differentiator.

**Unverified (don't ship as fact):** exact CIS-CAT JSON schema + Pro REST API;
CIS OEM license terms (get from CIS directly); OpenSCAP SCAP-1.3 NIST
validation; CIS-CAT's precise network coverage matrix; DISA NX-OS STIG
existence; SolarWinds NCM specifics (pages 403'd). Sources: OCSF schema repo,
open-scap.org, ComplianceAsCode, cisecurity.org SecureSuite terms, CISOfy,
ncp.nist.gov, cyber.mil/stigs, Batfish/ciscoconfparse2 repos, titania.com.
