// SPDX-License-Identifier: LicenseRef-Correlix-Enterprise
//
// COMMERCIAL ADD-ON MODULE. This package implements the `security_dialects`
// entitlement (Enterprise tier) and is NOT Apache-2.0 core. See the LICENSE
// notice file in this directory, ../../../../LICENSING.md, and
// LICENSES/Correlix-Enterprise.txt.

// Package frameworks carries the compliance-framework CROSSWALKS beyond the
// shipped default two.
//
// A framework in Correlix is two separable things. Its IDENTITY — a stable,
// versioned id, the descriptor a picker renders, the default set, and the
// closed vocabulary an API write is validated against — is Apache-2.0 core
// (internal/compliancemodel), because a deployment must be able to name,
// validate and keep serving a selection it has already persisted. Its
// CROSSWALK — the control → framework-requirement edges a scorecard is computed
// from — is the content. For NIST CSF 2.0, the HIPAA §164.312 technical
// safeguards and PCI DSS v4.0.1 that content is the owner's LOCKED
// `security_dialects` entitlement, whose scope is "device-hardening dialects
// beyond the default set, AND compliance frameworks beyond the default two"
// (Enterprise tier). The 800-53 base catalogue and CIS Controls v8.1 stay core
// and are unaffected by this package.
//
// HOW IT PLUGS IN. Each pack is DATA: a framework id plus a constructor for its
// crosswalk provider (compliancemodel.FrameworkPack). Nothing here can add a
// framework to the vocabulary, rename or re-version one, change which
// frameworks are on by default, or override a crosswalk core already ships —
// core wins on every id it provides. The assembly layer (package main) is the
// only place that names this package, inside its ENTERPRISE-ASSEMBLY markers,
// and it hands the packs to secapi behind an entitlement check.
//
// WITH THIS DIRECTORY DELETED the product still runs: the three frameworks stay
// in the catalogue and stay selectable, and an enabled one reports
// compliancemodel.NotLicensedCoverage — a NULL score and a sentence saying the
// crosswalk is not included — never an empty card that would read as "nothing
// here fails".
package frameworks

import "netops/backend/internal/compliancemodel"

// Packs returns the crosswalk packs this module contributes, one per framework.
// Fresh slice per call (§5 no global mutable state).
func Packs() []compliancemodel.FrameworkPack {
	return []compliancemodel.FrameworkPack{
		{ID: compliancemodel.IDNISTCSF, New: NewNISTCSFProvider},
		{ID: compliancemodel.IDHIPAA, New: NewHIPAAProvider},
		{ID: compliancemodel.IDPCIDSS, New: NewPCIProvider},
	}
}

// NewNISTCSFProvider seeds the NIST CSF 2.0 crosswalk.
//
// CSF 2.0 (February 2024) RENUMBERED the subcategories CSF 1.1 used: PR.AC-*
// became PR.AA-* (Identity Management, Authentication and Access Control),
// PR.IP-* was replaced by PR.PS-* (Platform Security), and network protection
// moved to PR.IR-* (Technology Infrastructure Resilience). The ids below are the
// 2.0 ones — the previous seed carried 1.1 ids under a "2.0" label, which is the
// kind of quiet version drift a scorecard must never have.
func NewNISTCSFProvider() *compliancemodel.StaticFrameworkProvider {
	f := compliancemodel.FrameworkNISTCSF
	return compliancemodel.NewStaticFrameworkProvider(f, "2.0", map[string][]compliancemodel.FrameworkRequirement{
		compliancemodel.ControlCM8:  {compliancemodel.Requirement(f, "ID.AM-01", "Inventories of hardware managed by the organization are maintained")},
		compliancemodel.ControlSI2:  {compliancemodel.Requirement(f, "ID.RA-01", "Vulnerabilities in assets are identified, validated and recorded")},
		compliancemodel.ControlAC2:  {compliancemodel.Requirement(f, "PR.AA-01", "Identities and credentials for authorized users and devices are managed")},
		compliancemodel.ControlIA5:  {compliancemodel.Requirement(f, "PR.AA-01", "Identities and credentials for authorized users and devices are managed")},
		compliancemodel.ControlIA2:  {compliancemodel.Requirement(f, "PR.AA-03", "Users, services and hardware are authenticated")},
		compliancemodel.ControlIA3:  {compliancemodel.Requirement(f, "PR.AA-03", "Users, services and hardware are authenticated")},
		compliancemodel.ControlAC3:  {compliancemodel.Requirement(f, "PR.AA-05", "Access permissions and authorizations are defined and enforced")},
		compliancemodel.ControlAC17: {compliancemodel.Requirement(f, "PR.AA-05", "Access permissions and authorizations are defined and enforced")},
		compliancemodel.ControlSC8:  {compliancemodel.Requirement(f, "PR.DS-02", "The confidentiality, integrity and availability of data in transit are protected")},
		compliancemodel.ControlSI7:  {compliancemodel.Requirement(f, "PR.DS-01", "The confidentiality, integrity and availability of data at rest are protected")},
		compliancemodel.ControlCM2:  {compliancemodel.Requirement(f, "PR.PS-01", "Configuration management practices are established and applied")},
		compliancemodel.ControlCM7:  {compliancemodel.Requirement(f, "PR.PS-01", "Configuration management practices are established and applied")},
		compliancemodel.ControlAU2:  {compliancemodel.Requirement(f, "PR.PS-04", "Log records are generated and made available for continuous monitoring")},
		compliancemodel.ControlAU8:  {compliancemodel.Requirement(f, "PR.PS-04", "Log records are generated and made available for continuous monitoring")},
		compliancemodel.ControlAC4:  {compliancemodel.Requirement(f, "PR.IR-01", "Networks and environments are protected from unauthorized logical access")},
		compliancemodel.ControlSC7:  {compliancemodel.Requirement(f, "PR.IR-01", "Networks and environments are protected from unauthorized logical access")},
		compliancemodel.ControlSC5:  {compliancemodel.Requirement(f, "PR.IR-04", "Adequate resource capacity to ensure availability is maintained")},
		compliancemodel.ControlAU6:  {compliancemodel.Requirement(f, "DE.CM-01", "Networks and network services are monitored to find potentially adverse events")},
	})
}

// NewHIPAAProvider seeds the HIPAA Security Rule crosswalk (45 CFR Part 164
// Subpart C as it stands in 2026 — the January 2025 NPRM was moved to HHS'
// long-term agenda with anticipated final action in 2027 and is NOT law, so
// nothing here codes against its proposed requirements). HIPAA is a
// LEGAL/regulatory framework: only the §164.312 Technical Safeguards map to a
// device config audit at all (§5d), so its scope is DELIBERATELY narrow and
// INCLUDES technical-safeguard controls Correlix has no check for yet — that is
// what makes the coverage % honest, and what makes a HIPAA-only tenant's view
// genuinely different from a PCI tenant's.
//
// CM-2/CM-8 (baseline configuration, asset inventory) are deliberately ABSENT:
// they are §164.308 administrative safeguards, not §164.312 technical ones, and
// a config audit cannot evidence them.
//
// NOTE: this is control EVIDENCE for the technical slice, NEVER "certified HIPAA
// compliance" (§5d defensible-claim rule); the broad §164.308/.310 realization
// is out of a config audit's reach.
func NewHIPAAProvider() *compliancemodel.StaticFrameworkProvider {
	f := compliancemodel.FrameworkHIPAA
	return compliancemodel.NewStaticFrameworkProvider(f, "45 CFR 164.312", map[string][]compliancemodel.FrameworkRequirement{
		compliancemodel.ControlAC3:  {compliancemodel.Requirement(f, "164.312(a)(1)", "Access Control")},
		compliancemodel.ControlAC17: {compliancemodel.Requirement(f, "164.312(a)(1)", "Access Control")},
		compliancemodel.ControlAC2:  {compliancemodel.Requirement(f, "164.312(a)(2)(i)", "Unique User Identification")},
		compliancemodel.ControlAU2:  {compliancemodel.Requirement(f, "164.312(b)", "Audit Controls")},
		compliancemodel.ControlAU6:  {compliancemodel.Requirement(f, "164.312(b)", "Audit Controls")},
		compliancemodel.ControlAU8:  {compliancemodel.Requirement(f, "164.312(b)", "Audit Controls")},
		compliancemodel.ControlSI7:  {compliancemodel.Requirement(f, "164.312(c)(1)", "Integrity")},
		compliancemodel.ControlIA2:  {compliancemodel.Requirement(f, "164.312(d)", "Person or Entity Authentication")},
		compliancemodel.ControlIA5:  {compliancemodel.Requirement(f, "164.312(d)", "Person or Entity Authentication")},
		compliancemodel.ControlSC8:  {compliancemodel.Requirement(f, "164.312(e)(1)", "Transmission Security")},
	})
}

// NewPCIProvider seeds the PCI DSS v4.0.1 crosswalk. PCI is also regulatory but its
// TECHNICAL requirements (1/2/4/6/7/8/10/11) cover more of the owned controls
// than HIPAA's technical safeguards do, so a PCI tenant's scope is broader —
// proving the two frameworks are scored on DIFFERENT, INDEPENDENT scopes from
// the same shared findings.
func NewPCIProvider() *compliancemodel.StaticFrameworkProvider {
	f := compliancemodel.FrameworkPCIDSS
	return compliancemodel.NewStaticFrameworkProvider(f, "4.0.1", map[string][]compliancemodel.FrameworkRequirement{
		compliancemodel.ControlAC4:  {compliancemodel.Requirement(f, "Req 1", "Install and maintain network security controls")},
		compliancemodel.ControlSC7:  {compliancemodel.Requirement(f, "Req 1", "Install and maintain network security controls")},
		compliancemodel.ControlSC5:  {compliancemodel.Requirement(f, "Req 1", "Install and maintain network security controls")},
		compliancemodel.ControlCM2:  {compliancemodel.Requirement(f, "Req 2", "Apply secure configurations to all system components")},
		compliancemodel.ControlCM7:  {compliancemodel.Requirement(f, "Req 2", "Apply secure configurations to all system components")},
		compliancemodel.ControlAC17: {compliancemodel.Requirement(f, "Req 2", "Apply secure configurations to all system components")},
		compliancemodel.ControlSC8:  {compliancemodel.Requirement(f, "Req 4", "Protect cardholder data with strong cryptography during transmission")},
		compliancemodel.ControlSI2:  {compliancemodel.Requirement(f, "Req 6", "Develop and maintain secure systems and software")},
		compliancemodel.ControlAC3:  {compliancemodel.Requirement(f, "Req 7", "Restrict access to system components by business need to know")},
		compliancemodel.ControlAC2:  {compliancemodel.Requirement(f, "Req 8", "Identify users and authenticate access to system components")},
		compliancemodel.ControlIA2:  {compliancemodel.Requirement(f, "Req 8", "Identify users and authenticate access to system components")},
		compliancemodel.ControlIA5:  {compliancemodel.Requirement(f, "Req 8", "Identify users and authenticate access to system components")},
		compliancemodel.ControlIA3:  {compliancemodel.Requirement(f, "Req 8", "Identify users and authenticate access to system components")},
		compliancemodel.ControlAU2:  {compliancemodel.Requirement(f, "Req 10", "Log and monitor all access to system components and cardholder data")},
		compliancemodel.ControlAU6:  {compliancemodel.Requirement(f, "Req 10", "Log and monitor all access to system components and cardholder data")},
		compliancemodel.ControlAU8:  {compliancemodel.Requirement(f, "Req 10", "Log and monitor all access to system components and cardholder data")},
		compliancemodel.ControlSI7:  {compliancemodel.Requirement(f, "Req 11", "Test security of systems and networks regularly")},
		compliancemodel.ControlCM8:  {compliancemodel.Requirement(f, "Req 12.5.1", "An inventory of system components in scope for PCI DSS is maintained")},
	})
}
