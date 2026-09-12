# Compliance frameworks → rules — research + strategy (2026-08-25)

Commissioned by the owner: how to build compliance rules against NIST, OWASP,
PCI-DSS, HIPAA, GDPR. Researched against primary sources (NIST OSCAL,
ComplianceAsCode, GDPR Art. 32, regulation text). This is the framework
strategy for the compliance/hardening module.

## The core framing (the mistake to avoid)

The five frameworks do NOT live at one level; treating them as five parallel
rule sets is the mistake. Two tiers:

1. **Technical control catalogs** (CIS Benchmarks, DISA STIG, NIST 800-53 /
   800-171, NIST CSF 2.0, ISO 27001 Annex A) — decompose into per-device/host
   config checks. The ONLY tier a config scanner directly evaluates.
2. **Regulatory/legal obligations** (PCI-DSS, HIPAA, GDPR) + **app-security
   guidance** (OWASP) — outcomes and duties, MOST of which no router or Linux
   config check can prove. Only a subset intersects device config.

The industry does NOT author a rule set per framework. It authors the
**technical check ONCE and tags it with every control it provides evidence
for** (one check → many controls → many frameworks), using **NIST SP 800-53 as
the crosswalk hub** and **NIST OSCAL** as the machine-readable model. This is
exactly what OpenSCAP/ComplianceAsCode does today. Correlix adopts this.

**Defensible claim: "audit-ready control EVIDENCE mapped to framework
controls" — NEVER "certified PCI/HIPAA/GDPR compliance."**

## (a) Framework classification

| Framework | Type | Maps to device/host config? | Honest claim |
|---|---|---|---|
| CIS Benchmarks | technical catalog | **Yes (direct)** — native unit of a config audit | "Evaluated against CIS Benchmark vX.Y; N/M pass" |
| DISA STIG | technical catalog | **Yes (direct)** — per-device | "STIG findings CAT I/II/III" |
| NIST 800-53 r5 | control catalog | **Partial → THE HUB.** Many map via CM-6 etc. | "Evidence toward AC-17/SC-8/CM-6/AU-2"; never "800-53 compliant" |
| NIST 800-171 r3 | control catalog (CUI) | Partial (subset) | "Evidence toward 800-171 reqs a config audit can show" |
| NIST CSF 2.0 | outcome framework | Partial/indirect (via 800-53) | "Findings organized by CSF function/category" |
| ISO 27001:2022 | control catalog | Partial (A.8.x technical) | "Evidence toward Annex A controls"; can't certify the ISMS |
| **PCI-DSS v4.0.1** | regulatory | **Partial** (Req 1/2/4/8/10 technical) | "Evidence toward PCI Req 1/2/4/8/10 technical sub-reqs"; NEVER "PCI compliant" (needs QSA/AoC) |
| **HIPAA** | US law | **Partial** (Technical Safeguards §164.312 only) | "Evidence toward §164.312"; not Admin/Physical |
| **GDPR** | privacy law | **Near-zero for a router** (only Art. 32 tangentially) | Do NOT ship "GDPR rules for a device"; at most "Art. 32 encryption-in-transit evidence, supports not demonstrates" |
| **OWASP** | app-security guidance | **Near-zero for network devices** | Use for Correlix's OWN app security (§15), not device audit |

**Over-claim flags (enforce internally):** "GDPR compliance rules for network
gear" is the single most over-claimed item — GDPR imposes no CLI settings.
"PCI-DSS compliant from a scan" — a scan is evidence, compliance is a QSA/AoC
attestation. "HIPAA certified" — there is no HIPAA certification. OWASP as a
"network compliance framework" — category error.

## (b) The crosswalk architecture (the key answer)

**Author/import the technical check ONCE; tag it with the 800-53 controls it
provides evidence for; derive framework coverage by transitive mapping through
800-53 as the hub.**

Why 800-53 is the hub: NIST publishes an official **OSCAL catalog** of 800-53
r5; every other framework publishes crosswalks TO 800-53 (PCI SSC; HIPAA via
NIST **SP 800-66r2**; CIS Controls → 800-53; NIST publishes 800-53↔ISO 27001;
CSF 2.0 informative references land on 800-53). So tagging a check with an
800-53 control inherits the other frameworks' mappings FOR FREE — no N²
framework-to-framework maps.

Confirmed as the real industry pattern: ComplianceAsCode ships one OVAL/CEL
check + remediation per rule, and `content/controls/` files map that rule to
many frameworks (800-53, PCI, CIS, STIG, ANSSI, ISO); profiles select rules
per framework. XCCDF separates check logic (OVAL) from control tags
(CCE + references), so one check answers many frameworks. NIST OSCAL provides
the formal substrate (Catalog / Profile / Component-Definition "satisfies" /
Assessment-Results / POA&M / the newer Control-Mapping model with
`equivalent-to` / `subset-of` / `supports` relationships).

One line: `TechnicalCheck (1) → satisfies → Control[] (800-53 hub) → crosswalk
→ Framework requirement[]`.

## (c) Per-regulation CAN / CANNOT (never overclaim)

**PCI-DSS v4.0.1 — CAN evidence:** Req 1 (network security controls, ACLs,
segmentation, deny-by-default 1.2-1.4), Req 2 (no vendor defaults, disable
unnecessary services 2.2), Req 4 (TLS versions/ciphers, no cleartext 4.2.1),
Req 8 (auth/MFA/timeout config 8.2-8.6), Req 10 (logging enabled, NTP, log
forwarding 10.2-10.6), parts of 5/6.2/7. **CANNOT:** Req 3 (stored-data/key
lifecycle), 9 (physical), 11 (pentest/ASV program), 12 (policy/process), and
whether the device is even in CDE scope (human decision).

**HIPAA §164.312 Technical Safeguards — CAN evidence:** (a) access control
(unique user id, auto-logoff, encryption), (b) audit controls (logging),
(c) integrity, (d) person/entity auth (MFA), (e) transmission security
(TLS/IPsec). **CANNOT:** §164.308 Administrative (risk analysis, training,
BAAs), §164.310 Physical. Drive tags via NIST SP 800-66r2 (HIPAA→800-53).

**GDPR — state plainly:** a data-protection LAW, not a device-hardening
framework. Do NOT ship "GDPR rules" for devices. Only honest intersection:
Art. 32(1) "security of processing" (encryption in transit, integrity/
availability hardening, regular testing) — surface as a CONTRIBUTING control
captioned "supports, does not demonstrate, GDPR compliance." Everything else
(lawful basis, data-subject rights, DPIA, RoPA, breach notice, processor
contracts, transfers) is legal/organizational, unscannable.

**OWASP:** ASVS/Top 10 are APPLICATION security — near-zero relevance to device
config. Correct home = Correlix's OWN app security (CLAUDE.md §15 already binds
the copilot to OWASP LLM Top 10). Not a device-audit framework.

## (d) Defensible claim language (enforce in UI + marketing)

- **DO say:** "audit-ready control evidence / hardening findings mapped to
  framework controls (CIS, STIG, NIST 800-53/171, and — via published
  crosswalks — the technical subset of PCI-DSS/HIPAA)"; "evidence toward
  AC-17 / SC-8 / CM-6"; "N of M CIS L1 checks passing".
- **DO NOT say:** "PCI/HIPAA/GDPR compliant," "certified," "makes you
  compliant."
- **Standard caption on any regulatory view:** "These findings provide
  evidence toward the technical controls indicated. They do not constitute a
  compliance certification; regulatory compliance requires assessment of
  administrative, physical, and organizational controls outside the scope of a
  configuration audit."
- **Coverage honesty:** show coverage % = (controls a config audit can
  evidence) / (all controls), so the tool visibly admits it covers e.g. the
  technical slice of HIPAA (§164.312), not §164.308/.310.

## (e) Internal schema — OSCAL-aligned, not full OSCAL in v1

Adopt OSCAL's concepts and identifiers (Component-Definition "satisfied",
800-53 control IDs, `supports`/`subset-of`/`equivalent-to` relationships) as
the data model; keep the ability to EXPORT OSCAL later (Component-Definition +
Assessment-Results pay off first with auditors). Don't force full OSCAL
document exchange in v1 — heavier than needed, ecosystem still mostly federal.

Four objects: **Check** (what you evaluate, imported from CIS/STIG/CAC,
version-pinned to its source rule) → **Control** (800-53 r5 IDs as the hub key
space) → **Mapping** (check → controls[], `relationship`, YOUR IP, per-rule) →
**Crosswalk** (control → framework requirement[], IMPORTED from official
sources, not hand-maintained). Store the check→control edge yourself; import
the control→framework crosswalk (NIST 800-53↔CSF/ISO, PCI SSC, 800-66r2 for
HIPAA, CIS Controls Navigator). Version-pin everything (a control ID's meaning
shifts 800-53 r4→r5, PCI v3.2.1→v4.0.1). §3a: tenant-scope the findings store;
framework/crosswalk reference data is global read-only reference (not tenant
data).

## Open verification step before hard-coding mappings

The agent confirmed OSCAL, ComplianceAsCode's pattern, and GDPR Art. 32 live,
but did NOT re-fetch the PCI SSC and eCFR crosswalks this session (budget /
anti-bot redirect). Before hard-coding the crosswalk data, pull the
authoritative machine-readable sources: NIST 800-53 r5 OSCAL catalog + its
ISO/CSF mappings (pages.nist.gov), NIST SP 800-66r2 Appendix (HIPAA→800-53),
the PCI SSC v4.x doc library, and the CIS Controls Navigator. Sources:
pages.nist.gov/OSCAL, complianceascode.readthedocs.io, gdpr-info.eu/art-32,
eCFR Title 45 Part 164.
