// Package entitlement is the CENTRAL entitlement service: the one place the
// product asks "is capability X entitled?" and "what is the limit on Y?".
//
// Owner spec of 2026-09-04 (binding, recorded in
// docs/design/LICENSING_MODEL_2026-09-04.md §1 and §2a):
//
//   - Business code asks `Entitled(FeatureSAML)`. It NEVER asks
//     `tier == "enterprise"`. Tier is a commercial label that will move; a
//     semantic capability is what the code actually depends on. A tier
//     comparison anywhere outside this package is a defect.
//   - Source licence (Apache-2.0 / Correlix Enterprise) and runtime entitlement
//     (Community / Team / Enterprise) are SEPARATE axes (§2a). Apache-licensed
//     code carries Community product limits; an Enterprise-licensed file may
//     implement a Team feature. This package is the runtime-entitlement axis
//     only and says nothing about any file's source licence.
//   - This package is CORE (Apache-2.0) and stdlib-only, so the future
//     `enterprise/**` packages may depend on it and the CI import checker's
//     "core never imports enterprise" rule holds in the one direction that
//     matters. Nothing here may ever import `enterprise/**`, and nothing here
//     imports the licence-file parser either: the abstraction outlives its
//     current implementation (internal/licence).
//
// # The safety invariant (non-negotiable)
//
// A licence problem — expired, invalid, tampered, absent, removed — is
// TECHNICALLY INCAPABLE of weakening:
//
//   - tenant isolation and RLS / data separation,
//   - authorization (requirePerm / requirePlatformAdmin / requireCrossTenant),
//   - integrity controls (sealing, audit, signature verification),
//   - core authentication, INCLUDING OIDC, which is core and always available.
//
// That is enforced structurally, not by convention: the isolation and auth
// paths do not consult this package at all, and a test asserts they do not
// import it (see safety_invariant_test.go). Failing closed here can only ever
// remove a COMMERCIAL capability, never a safety property — the worst case of a
// bug in this package is a customer who paid for SAML not getting SAML, which
// is a support ticket, not a breach.
//
// # Expiry, grace and overage (owner decision, 2026-09-05)
//
// Phase is the post-expiry state machine — valid → in_grace → post_grace — and
// SoftCeiling is the paid-tier overage policy. Both live here rather than in
// internal/licence because they are POLICY the product asks about, not file
// format. Two rules govern them and neither is negotiable:
//
//   - post_grace removes CREATION and CONFIGURATION only. Require refuses;
//     RequireRead still admits, so existing data stays viewable and exportable.
//     Nothing is disabled and nothing is deleted.
//   - no phase and no ceiling can reach a safety property. The isolation, RLS,
//     authorization, integrity and authentication paths do not consult this
//     package at all, so there is no state of this machine in which they differ
//     (safety_invariant_test.go).
//
// # Failing closed
//
// The zero value of Service is nil, and every helper here is nil-safe and
// answers with Community. A build that forgets to wire the licence subsystem
// therefore runs at Community rather than unlimited: absence of an entitlement
// answer is "not entitled", never "sure, go ahead".
package entitlement

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// ─────────────────────────────────────────────────────────────────────────────
// The interface business code depends on
// ─────────────────────────────────────────────────────────────────────────────

// Service answers entitlement questions. One implementation ships today
// (internal/licence, backed by the signed licence file); the interface exists so
// callers — including future `enterprise/**` packages — depend on the question,
// not on how it is answered.
//
// Implementations MUST be safe for concurrent use: these are called on
// admission paths while an operator installs a new licence on the admin page.
type Service interface {
	// Entitled reports whether feature f is granted right now.
	// A feature outside the closed vocabulary is never entitled.
	Entitled(f Feature) bool
	// Ceiling returns the limit for a named ceiling and the lowest tier that
	// raises it. limit is Unlimited (-1) for no limit; liftedBy is "" when no
	// higher tier lifts it.
	Ceiling(name string) (limit int, liftedBy Tier)
	// Tier is the tier in force, for display and for the refusal body. It is
	// NOT a gate: nothing outside this package may branch on it.
	Tier() Tier
}

// ─────────────────────────────────────────────────────────────────────────────
// Expiry phases — the post-expiry state machine (owner decision, 2026-09-05)
// ─────────────────────────────────────────────────────────────────────────────

// Phase is where a licence stands against its own expiry. It is the vocabulary
// of the state machine the owner adopted on 2026-09-05
// (docs/design/TIERING_PLAN_2026-09-03.md §9, row "Paid expiry / grace"):
//
//	valid       → the licence has not expired. Everything it grants is in force.
//	in_grace    → expired, inside the issuer's grace window. NOTHING changes for
//	              the user: the licensed ceilings and features are still in
//	              force. The page and a warning alert say how long is left.
//	post_grace  → expired and past grace. The commercial ceilings and features
//	              fall back to Community for CREATION and CONFIGURATION only.
//	              Existing data stays viewable and exportable, over-ceiling state
//	              is LISTED, and nothing is disabled or deleted.
//
// It is a DISPLAY and REFUSAL token, not a gate: no business code branches on
// it. What business code asks is Require (may I create/configure this?) and
// RequireRead (may I still see what is already here?).
//
// The phase can never reach a safety property. Isolation, RLS, authorization,
// integrity and core authentication do not consult this package at all
// (safety_invariant_test.go), so there is no phase in which they change.
type Phase string

const (
	// PhaseValid — not expired. Also the answer for Community, which has no
	// expiry to be past, and for any Service that does not track one.
	PhaseValid Phase = "valid"
	// PhaseInGrace — expired, still inside the issuer's grace window.
	PhaseInGrace Phase = "in_grace"
	// PhasePostGrace — expired and past grace.
	PhasePostGrace Phase = "post_grace"
)

// phaseOrder is the closed phase vocabulary, in the order the machine walks it.
var phaseOrder = []Phase{PhaseValid, PhaseInGrace, PhasePostGrace}

// Phases returns the closed phase vocabulary in transition order.
func Phases() []Phase { return append([]Phase(nil), phaseOrder...) }

// ValidPhase reports whether p is in the closed vocabulary.
func ValidPhase(p Phase) bool {
	for _, k := range phaseOrder {
		if k == p {
			return true
		}
	}
	return false
}

// Label is the phase's display name.
func (p Phase) Label() string {
	switch p {
	case PhaseValid:
		return "Valid"
	case PhaseInGrace:
		return "In grace"
	case PhasePostGrace:
		return "Past grace"
	}
	return string(p)
}

// Lifecycle is the OPTIONAL extension a Service implements when it is backed by
// a document that can expire. It is deliberately an EXTENSION and not part of
// Service: the base question ("is X entitled?") is what business code depends
// on, and a Service that has no expiry — a fixture, a future source of truth —
// must not have to invent an answer about grace periods.
//
// A Service that does not implement it reads as PhaseValid with no retained
// reads, which is the fail-closed direction: nothing extra is granted, and
// nothing is claimed about a lifecycle that is not being tracked.
type Lifecycle interface {
	Service
	// Phase is the expiry phase in force.
	Phase() Phase
	// EntitledForRead reports whether f's EXISTING data stays readable and
	// exportable. It differs from Entitled only in PhasePostGrace, where the
	// owner's policy is that the customer keeps SEEING what they already have
	// and loses only the ability to create and configure more.
	//
	// It must never grant a read the licence never granted at all: a feature
	// the document did not include is not readable because a licence lapsed.
	EntitledForRead(f Feature) bool
}

// PhaseOf reports the expiry phase svc is in. Nil-safe, and PhaseValid for a
// Service that does not track a lifecycle.
func PhaseOf(svc Service) Phase {
	if lc, ok := svc.(Lifecycle); ok && lc != nil {
		if p := lc.Phase(); ValidPhase(p) {
			return p
		}
	}
	return PhaseValid
}

// ─────────────────────────────────────────────────────────────────────────────
// Tiers
// ─────────────────────────────────────────────────────────────────────────────

// Tier is a commercial packaging label. It exists for display, for the "which
// tier lifts this" half of a refusal, and for the licence file's own field —
// never as a gate.
type Tier string

const (
	// TierCommunity is the no-licence default. Needs no key and no file.
	TierCommunity Tier = "community"
	TierTeam      Tier = "team"
	// TierEnterprise ceilings are "unlimited per licence": the FILE carries the
	// numbers, so an Enterprise licence is still a bounded, auditable document.
	TierEnterprise Tier = "enterprise"
)

// tierOrder is the upgrade ladder, lowest first.
var tierOrder = []Tier{TierCommunity, TierTeam, TierEnterprise}

// Tiers returns the upgrade ladder, lowest first.
func Tiers() []Tier { return append([]Tier(nil), tierOrder...) }

// ValidTier reports whether t is in the closed tier vocabulary. An unknown tier
// in a licence file is a verification error, not an unknown-but-permissive one.
func ValidTier(t Tier) bool {
	for _, k := range tierOrder {
		if k == t {
			return true
		}
	}
	return false
}

// Label is the tier's display name.
func (t Tier) Label() string {
	switch t {
	case TierCommunity:
		return "Community"
	case TierTeam:
		return "Team"
	case TierEnterprise:
		return "Enterprise"
	}
	return string(t)
}

// rank is the tier's position on the ladder, -1 if unknown.
func rank(t Tier) int {
	for i, k := range tierOrder {
		if k == t {
			return i
		}
	}
	return -1
}

// ─────────────────────────────────────────────────────────────────────────────
// Features — the LOCKED semantic vocabulary
// ─────────────────────────────────────────────────────────────────────────────

// Feature is a semantic capability. The vocabulary below is CLOSED and LOCKED
// by the owner spec of 2026-09-04: it is exactly the commercial set that has
// been DECIDED, and nothing else.
//
// Everything else in docs/design/TIERING_PLAN_2026-09-03.md — retention beyond
// Community's, compliance-framework counts, reports/PDF, Iris skill counts,
// hosted provider quota, BMP and BGP beyond the Community prefix cap — is a
// PROPOSAL, not a decision, and is therefore NOT gated. Adding a value here
// gates a capability for every customer, so it takes an owner decision, not a
// diff.
type Feature string

const (
	// FeatureSecurityFindings — the security findings lane (CTEM evidence
	// class). TIER: Team and above.
	FeatureSecurityFindings Feature = "security_findings"

	// FeatureSecurityDialects — hardening/config-audit dialects beyond the core
	// set. TIER: Enterprise.
	FeatureSecurityDialects Feature = "security_dialects"
	// FeatureSIEMExport — export of findings/evidence to an external SIEM.
	// TIER: Enterprise.
	FeatureSIEMExport Feature = "siem_export"
	// FeatureMSPManagement — MSP / fleet management of MANY tenants. Note the
	// scope carefully: normal SINGLE-tenant operation and tenant ISOLATION are
	// core and never gated (§1 LOCKED row); what is commercial is managing a
	// fleet of tenants from one place.
	// TIER: Enterprise.
	FeatureMSPManagement Feature = "msp_management"
	// FeatureSAML — SAML single sign-on. OIDC is CORE and always available; SAML
	// is the commercial addition.
	// TIER: Enterprise.
	FeatureSAML Feature = "saml"
	// FeatureSCIM — SCIM user/group provisioning. TIER: Enterprise.
	FeatureSCIM Feature = "scim"
	// FeatureLDAP — LDAP directory authentication. Core authentication (local
	// accounts, OIDC) is never gated; LDAP is the commercial addition.
	// TIER: Enterprise.
	FeatureLDAP Feature = "ldap"
)

// featureOrder is the closed vocabulary in display order (Team first, then
// Enterprise), which is also the order the admin page lists them in.
var featureOrder = []Feature{
	FeatureSecurityFindings,
	FeatureSecurityDialects,
	FeatureSIEMExport,
	FeatureMSPManagement,
	FeatureSAML,
	FeatureSCIM,
	FeatureLDAP,
}

// featureTier is the LOWEST tier that grants each feature. It answers the
// "lifted by" half of a refusal so a 402 always tells the operator what to buy.
// This table is the ONLY tier↔feature mapping in the codebase.
var featureTier = map[Feature]Tier{
	FeatureSecurityFindings: TierTeam,
	FeatureSecurityDialects: TierEnterprise,
	FeatureSIEMExport:       TierEnterprise,
	FeatureMSPManagement:    TierEnterprise,
	FeatureSAML:             TierEnterprise,
	FeatureSCIM:             TierEnterprise,
	FeatureLDAP:             TierEnterprise,
}

// Features returns the closed feature vocabulary in display order.
func Features() []Feature { return append([]Feature(nil), featureOrder...) }

// ValidFeature reports whether f is in the closed vocabulary. A licence naming
// anything else fails verification rather than being ignored: a typo in an
// issued licence must be a loud refusal at issue time, not a capability the
// customer paid for and silently did not receive.
func ValidFeature(f Feature) bool {
	_, ok := featureTier[f]
	return ok
}

// FeatureTier is the lowest tier that grants f ("" for an unknown feature).
func FeatureTier(f Feature) Tier { return featureTier[f] }

// FeatureLabel is the operator-facing name of a feature.
func FeatureLabel(f Feature) string {
	switch f {
	case FeatureSecurityFindings:
		return "security findings"
	case FeatureSecurityDialects:
		return "security dialects"
	case FeatureSIEMExport:
		return "findings export to SIEM"
	case FeatureMSPManagement:
		return "multi-tenant fleet management"
	case FeatureSAML:
		return "SAML single sign-on"
	case FeatureSCIM:
		return "SCIM provisioning"
	case FeatureLDAP:
		return "LDAP authentication"
	}
	return string(f)
}

// ─────────────────────────────────────────────────────────────────────────────
// Ceilings
// ─────────────────────────────────────────────────────────────────────────────

// Ceiling names. Closed vocabulary, shared by the licence file, the refusal
// body, the metrics and the admin page's usage bars — one spelling everywhere.
//
// ENFORCED today (owner-decided product limits, §1 LOCKED row):
//
//	CeilingDevices          — 25 on Community
//	CeilingWatchedPrefixes  —  5 on Community
//
// CARRIED BUT NOT ENFORCED: the remaining names below are part of the licence
// file's documented shape (design §3) so an issued file is forward-compatible,
// and the admin page displays them, but NO code gates on them — they are the
// tiering plan's proposals, and gating an undecided limit would be inventing
// commercial policy. `Enforced(name)` is the machine-readable statement of
// which is which, and a test asserts the un-enforced ones have no call sites.
const (
	// CeilingDevices counts MONITORED devices — see CeilingUnit and the C4
	// decision recorded there. The NAME stays "devices" because it is a signed
	// field of every issued licence document (internal/licence/signer's
	// canonical order); the UNIT it counts is monitored_devices.
	CeilingDevices              = "devices"
	CeilingWatchedPrefixes      = "watched_prefixes"
	CeilingTenants              = "tenants"
	CeilingOrgs                 = "orgs"
	CeilingRetentionDays        = "retention_days"
	CeilingSkills               = "skills"
	CeilingProviderTokensPerDay = "provider_tokens_per_day"
)

// Ceiling UNITS — what each ceiling actually counts, as a machine token.
//
// The unit is separate from the ceiling NAME on purpose. A name is a field of a
// signed licence document and can never change without invalidating every
// licence ever issued; the unit is the product statement of what that number
// measures, and the owner's C4 decision (2026-09-05) changed exactly that for
// devices: the licence counts devices Correlix is CONFIGURED TO MONITOR, not
// rows in the inventory. Discovery is free — finding a device costs nothing and
// consumes no allowance; collecting from one is the priced act.
//
// It rides in the refusal body so a client renders "25 of 25 monitored devices"
// instead of the ambiguous "25 devices", without re-deriving product policy.
const (
	UnitMonitoredDevices    = "monitored_devices"
	UnitWatchedPrefixes     = "watched_prefixes"
	UnitTenants             = "tenants"
	UnitOrgs                = "orgs"
	UnitRetentionDays       = "retention_days"
	UnitSkills              = "skills"
	UnitProviderTokensDaily = "provider_tokens_per_day"
)

// ceilingUnits maps each ceiling to the unit it counts. Only the devices row
// differs from its own name, and that difference is the whole C4 decision.
var ceilingUnits = map[string]string{
	CeilingDevices:              UnitMonitoredDevices,
	CeilingWatchedPrefixes:      UnitWatchedPrefixes,
	CeilingTenants:              UnitTenants,
	CeilingOrgs:                 UnitOrgs,
	CeilingRetentionDays:        UnitRetentionDays,
	CeilingSkills:               UnitSkills,
	CeilingProviderTokensPerDay: UnitProviderTokensDaily,
}

// CeilingUnit is the machine token for what a ceiling counts ("" for a name
// outside the closed vocabulary).
func CeilingUnit(name string) string { return ceilingUnits[name] }

// Unlimited is the ceiling value meaning "no limit". It is -1 and not 0 so a
// genuine zero stays expressible: a missing or zero field must never read as
// "unlimited" by accident.
const Unlimited = -1

// ceilingNames is the closed vocabulary in display order, enforced ones first.
var ceilingNames = []string{
	CeilingDevices,
	CeilingWatchedPrefixes,
	CeilingTenants,
	CeilingOrgs,
	CeilingRetentionDays,
	CeilingSkills,
	CeilingProviderTokensPerDay,
}

// enforcedCeilings is the decided set. See the const block's doc comment.
var enforcedCeilings = map[string]bool{
	CeilingDevices:         true,
	CeilingWatchedPrefixes: true,
}

// CeilingNames returns the closed ceiling vocabulary in display order.
func CeilingNames() []string { return append([]string(nil), ceilingNames...) }

// ValidCeiling reports whether name is in the closed ceiling vocabulary.
func ValidCeiling(name string) bool {
	for _, n := range ceilingNames {
		if n == name {
			return true
		}
	}
	return false
}

// Enforced reports whether a ceiling is actually gated in the product today.
// The admin page uses it to label the rest honestly ("carried, not enforced")
// rather than showing a bar that nothing enforces as if it bit.
func Enforced(name string) bool { return enforcedCeilings[name] }

// ─────────────────────────────────────────────────────────────────────────────
// Soft ceilings — the paid-tier overage policy (owner decision, 2026-09-05)
// ─────────────────────────────────────────────────────────────────────────────

// SoftCeiling reports whether exceeding `name` at tier `at` is ALLOWED and
// recorded, rather than refused.
//
// The owner's decision (docs/design/TIERING_PLAN_2026-09-03.md §9, Team and
// Enterprise rows): "Soft overage + alerts (80/90/100 %), never a kill switch
// during an incident." A paid customer who activates their 251st monitored
// device in the middle of an outage gets the device, not a 402 — the overage is
// recorded, surfaced on the Licence page and the Devices page, alerted on, and
// settled on the order form as a true-up. NO CONTRACTUAL WINDOW IS ENCODED
// HERE: the product records `overage_since` and states the size; how long an
// overage may run and what it costs are commercial terms and live on the order
// form, never in code.
//
// Community is the exception and stays HARD: 25 monitored devices is a
// PUBLISHED free ceiling, and the 26th activation is refused (§9, Community
// row: "Hard block at the 26th activation"). A free tier whose limit did not
// bite would not be a limit.
//
// The watched-prefix ceiling stays hard at every tier: it is a small,
// operator-chosen list with no incident-time urgency behind it, and the owner's
// soft-overage decision names monitored devices only. Adding a ceiling here is
// a commercial decision, not a diff.
//
// Post-grace consequence, and it is deliberate: at PhasePostGrace the tier in
// force IS Community (the fallback), so this returns false and the hard block
// applies to NEW activations. Nothing already monitored is touched — the gate
// only ever sees a transition.
func SoftCeiling(name string, at Tier) bool {
	return name == CeilingDevices && rank(at) >= rank(TierTeam)
}

// CeilingLabel is the operator-facing name of a ceiling.
func CeilingLabel(name string) string {
	switch name {
	case CeilingDevices:
		// "monitored devices", not "devices": the number counts what Correlix
		// is configured to collect from, and an inventory of five hundred
		// discovered candidates against a limit of 25 must never read as if
		// those rows were the thing being limited (owner C4, 2026-09-05).
		return "monitored devices"
	case CeilingWatchedPrefixes:
		return "watched prefixes"
	case CeilingTenants:
		return "tenants"
	case CeilingOrgs:
		return "organisations"
	case CeilingRetentionDays:
		return "retention days"
	case CeilingSkills:
		return "Iris skills"
	case CeilingProviderTokensPerDay:
		return "provider tokens per day"
	}
	return name
}

// Ceilings are the numeric limits. Field order is the licence signature's
// canonical order — see internal/licence/signer.
type Ceilings struct {
	Devices              int `json:"devices"`
	Tenants              int `json:"tenants"`
	Orgs                 int `json:"orgs"`
	RetentionDays        int `json:"retention_days"`
	WatchedPrefixes      int `json:"watched_prefixes"`
	Skills               int `json:"skills"`
	ProviderTokensPerDay int `json:"provider_tokens_per_day"`
}

// Get returns the ceiling by its vocabulary name. ok is false for a name
// outside the closed vocabulary — callers must treat that as a bug, never as
// "unlimited".
func (c Ceilings) Get(name string) (limit int, ok bool) {
	switch name {
	case CeilingDevices:
		return c.Devices, true
	case CeilingTenants:
		return c.Tenants, true
	case CeilingOrgs:
		return c.Orgs, true
	case CeilingRetentionDays:
		return c.RetentionDays, true
	case CeilingWatchedPrefixes:
		return c.WatchedPrefixes, true
	case CeilingSkills:
		return c.Skills, true
	case CeilingProviderTokensPerDay:
		return c.ProviderTokensPerDay, true
	}
	return 0, false
}

// Map renders the ceilings as the wire map the admin page and metrics consume.
func (c Ceilings) Map() map[string]int {
	out := make(map[string]int, len(ceilingNames))
	for _, n := range ceilingNames {
		v, _ := c.Get(n)
		out[n] = v
	}
	return out
}

// Exceeds reports whether current is over limit, honouring Unlimited.
func Exceeds(current, limit int) bool { return limit != Unlimited && current > limit }

// ─────────────────────────────────────────────────────────────────────────────
// Tier reference ceilings — used ONLY to answer "which tier lifts this"
// ─────────────────────────────────────────────────────────────────────────────

// tierCeilings is the reference table from docs/design/TIERING_PLAN_2026-09-03.md
// §2. It is NOT a gate and never grants anything: the ceilings in force always
// come from the licence file (or CommunityCeilings when there is none). Its only
// job is to compute the "lifted by" tier named in a refusal, so a 402 can say
// "Team lifts this" instead of "no".
var tierCeilings = map[Tier]Ceilings{
	TierCommunity: CommunityCeilings(),
	TierTeam: {
		Devices: 250, Tenants: 5, Orgs: 1, RetentionDays: 30,
		WatchedPrefixes: 100, Skills: 10, ProviderTokensPerDay: 0,
	},
	TierEnterprise: {
		Devices: Unlimited, Tenants: Unlimited, Orgs: Unlimited, RetentionDays: 90,
		WatchedPrefixes: Unlimited, Skills: Unlimited, ProviderTokensPerDay: Unlimited,
	},
}

// CommunityCeilings are the free-tier product limits. The two ENFORCED numbers
// (25 devices, 5 watched prefixes) are owner-decided and live in Apache-licensed
// code by design (§1 LOCKED row: "Community ceilings … product limits inside
// Apache code"). The rest are the tiering plan's figures, carried so the shape
// is complete and displayed honestly as un-enforced.
func CommunityCeilings() Ceilings {
	return Ceilings{
		Devices:              25,
		Tenants:              1,
		Orgs:                 1,
		RetentionDays:        7,
		WatchedPrefixes:      5,
		Skills:               0,
		ProviderTokensPerDay: 0,
	}
}

// TierCeilings returns the reference ceilings for a tier, for display and for
// LiftedBy. ok is false for an unknown tier.
func TierCeilings(t Tier) (Ceilings, bool) {
	c, ok := tierCeilings[t]
	return c, ok
}

// LiftedBy returns the lowest tier strictly above `at` whose reference ceiling
// for `name` is higher than `limit` (Unlimited counting as higher than any
// finite value). "" when nothing lifts it — in which case the refusal says
// "contact us" rather than naming a tier that would not help.
func LiftedBy(name string, limit int, at Tier) Tier {
	start := rank(at)
	if start < 0 {
		start = 0
	}
	for i := start + 1; i < len(tierOrder); i++ {
		c, ok := tierCeilings[tierOrder[i]]
		if !ok {
			continue
		}
		v, ok := c.Get(name)
		if !ok {
			continue
		}
		if v == Unlimited || (limit != Unlimited && v > limit) {
			return tierOrder[i]
		}
	}
	return ""
}

// ─────────────────────────────────────────────────────────────────────────────
// Refusals — the structured 402
// ─────────────────────────────────────────────────────────────────────────────

// ErrLicence is the structured refusal every gate returns. It carries enough for
// the SPA to render an upgrade card without parsing prose: WHICH limit, WHERE
// the caller is against it, and WHICH tier lifts it.
//
// Exactly one of Ceiling and Feature is set.
type ErrLicence struct {
	// Ceiling is the ceiling vocabulary name, or "" for a feature refusal.
	Ceiling string `json:"ceiling,omitempty"`
	// Unit is what the ceiling COUNTS, as a machine token (CeilingUnit) — e.g.
	// "monitored_devices" for the devices ceiling. A client renders the unit,
	// never the ceiling name, so a limit on monitored devices can never be
	// mistaken for a limit on inventory rows.
	Unit string `json:"unit,omitempty"`
	// Feature is the feature vocabulary name, or "" for a ceiling refusal.
	Feature Feature `json:"feature,omitempty"`
	// Current is the caller's present value (a count, or a requested number).
	// Meaningful only for a ceiling refusal.
	Current int `json:"current,omitempty"`
	// Limit is the ceiling in force. Unlimited (-1) never appears here: an
	// unlimited ceiling cannot refuse.
	Limit int `json:"limit,omitempty"`
	// Tier is the tier in force — for display in the card, never a gate.
	Tier Tier `json:"tier"`
	// LiftedBy is the lowest tier that removes this refusal, "" when none does.
	LiftedBy Tier `json:"lifted_by,omitempty"`
	// LicenceState is the expiry phase in force (PhaseValid / PhaseInGrace /
	// PhasePostGrace). It is what lets a client tell "you never bought this"
	// from "the licence that covered this has lapsed", which are the same 402
	// with two entirely different remedies. Always set.
	LicenceState Phase `json:"licence_state,omitempty"`
	// Message is the honest operator-facing sentence.
	Message string `json:"message"`
}

// Error implements error.
func (e *ErrLicence) Error() string {
	if e == nil {
		return "licence: refused"
	}
	return e.Message
}

// Is makes errors.Is(err, ErrNotEntitled) true for every licence refusal, so a
// caller that only needs "was this a licence refusal?" does not have to type
// assert.
func (e *ErrLicence) Is(target error) bool { return target == ErrNotEntitled }

// ErrNotEntitled is the sentinel every ErrLicence matches under errors.Is.
var ErrNotEntitled = errors.New("licence: not entitled")

// As is the convenience wrapper for pulling the structured refusal out of a
// wrapped error.
func As(err error) (*ErrLicence, bool) {
	var e *ErrLicence
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// ─────────────────────────────────────────────────────────────────────────────
// The gates business code calls
// ─────────────────────────────────────────────────────────────────────────────

// Entitled reports whether svc grants f. Nil-safe: a nil Service is Community,
// which grants nothing. Fails closed by construction.
func Entitled(svc Service, f Feature) bool {
	if svc == nil || !ValidFeature(f) {
		return false
	}
	return svc.Entitled(f)
}

// Require is the feature gate. It returns nil when entitled and an *ErrLicence
// when not. Callers render the error with WriteRefusal.
//
//	if err := entitlement.Require(s.entitlements, entitlement.FeatureSAML); err != nil {
//	        entitlement.WriteRefusal(w, err)
//	        return
//	}
func Require(svc Service, f Feature) error {
	if Entitled(svc, f) {
		return nil
	}
	at := TierCommunity
	if svc != nil {
		at = svc.Tier()
	}
	phase := PhaseOf(svc)
	lifted := featureTier[f]
	if rank(lifted) <= rank(at) {
		// Either an unknown feature, or the tier in force already ought to grant
		// it — which happens when a licence is expired/degraded. Naming a tier
		// the customer already has would be a lie, so we name none and the
		// message carries the real reason.
		lifted = ""
	}
	var msg string
	if phase == PhasePostGrace && EntitledForRead(svc, f) {
		// The customer DID buy this and the licence lapsed. Naming a tier to
		// upgrade to would be the wrong instruction entirely: the fix is a
		// renewal, and the reassurance they need first is that the data they
		// already have is still there.
		lifted = ""
		msg = fmt.Sprintf("%s cannot be configured: the licence that included it has expired and its grace period has ended. "+
			"What is already here stays visible and exportable, and nothing has been disabled or deleted — "+
			"install a renewed licence to configure it again", FeatureLabel(f))
	} else {
		msg = fmt.Sprintf("%s is not included in your %s licence", FeatureLabel(f), at.Label())
		if lifted != "" {
			msg += fmt.Sprintf(" — the %s tier includes it", lifted.Label())
		} else {
			msg += " — contact Correlix to enable it"
		}
	}
	return &ErrLicence{Feature: f, Tier: at, LiftedBy: lifted, LicenceState: phase, Message: msg}
}

// EntitledForRead reports whether f's EXISTING data may still be read and
// exported.
//
// It is Entitled, widened by exactly one case: a licence that GRANTED f and has
// since lapsed past its grace period. The owner's 2026-09-05 decision draws the
// line at creation and configuration —
//
//	"after grace, paid-only creation/configuration actions become unavailable,
//	 existing data stays viewable/exportable, over-ceiling state is listed;
//	 never delete data or weaken a security property"
//
// — so a customer whose Team licence lapsed can still open, search and export
// the findings they have. They cannot make new ones.
//
// Nil-safe and fail-closed: with no Service, or a Service that tracks no
// lifecycle, this is exactly Entitled. It NEVER grants a read for a feature the
// licence did not include in the first place.
func EntitledForRead(svc Service, f Feature) bool {
	if Entitled(svc, f) {
		return true
	}
	if !ValidFeature(f) {
		return false
	}
	lc, ok := svc.(Lifecycle)
	if !ok || lc == nil {
		return false
	}
	return lc.EntitledForRead(f)
}

// RequireRead is the READ half of the feature gate: it admits a caller who may
// still SEE what f produced, and refuses one who never had f at all.
//
// Pair it with Require, which stays the CREATE/CONFIGURE gate:
//
//	GET  /api/security/findings   → RequireRead(svc, FeatureSecurityFindings)
//	POST /api/security/exports    → Require(svc, FeatureSIEMExport)
//
// The two are different questions and must not share an answer. Using Require
// on a read would delete a lapsed customer's access to their own history from
// their point of view — the screen would be empty — which is precisely the
// "never delete data" line the owner drew.
func RequireRead(svc Service, f Feature) error {
	if EntitledForRead(svc, f) {
		return nil
	}
	return Require(svc, f)
}

// CheckCeiling is the ceiling gate for ADMITTING ONE MORE of something.
// `current` is how many exist now; it returns an *ErrLicence when admitting one
// more would exceed the limit.
//
//	if err := entitlement.CheckCeiling(s.entitlements, entitlement.CeilingDevices, len(devices)); err != nil {
//	        entitlement.WriteRefusal(w, err)
//	        return
//	}
//
// Note the boundary: with a HARD limit of 25 and 25 devices already admitted,
// the 26th is refused. Where the ceiling is SOFT (SoftCeiling — monitored
// devices on a paid tier) the 26th is ADMITTED and the overage recorded; the
// owner's decision is that a paid customer is never blocked mid-incident.
// Nothing existing is ever removed or hidden by this call either way —
// over-ceiling items already present stay visible and are LISTED as
// over-ceiling (see internal/licence State.Overages), which is the honest
// degradation the design requires.
func CheckCeiling(svc Service, name string, current int) error {
	return CheckCeilingValue(svc, name, current+1, current)
}

// CheckCeilingValue is the ceiling gate for SETTING a value (a configured
// retention, a requested count) rather than admitting one more. `want` is the
// value being requested; `current` is reported in the refusal so the card can
// show where the caller stands.
func CheckCeilingValue(svc Service, name string, want, current int) error {
	if !ValidCeiling(name) {
		// A name outside the closed vocabulary is a programming error. Refuse:
		// silently permitting an unknown ceiling is how a gate quietly stops
		// gating.
		return &ErrLicence{
			Ceiling: name, Current: current, Tier: TierCommunity, LicenceState: PhaseOf(svc),
			Message: fmt.Sprintf("unknown licence ceiling %q", name),
		}
	}
	at := TierCommunity
	limit := CommunityCeilings()
	if svc != nil {
		at = svc.Tier()
	}
	lim, _ := limit.Get(name)
	if svc != nil {
		lim, _ = svc.Ceiling(name)
	}
	if !Exceeds(want, lim) {
		return nil
	}
	if SoftCeiling(name, at) {
		// SOFT: allowed and recorded, never refused. The overage is measured
		// from usage (internal/licence.OverageTracker), shown on the Licence and
		// Devices pages, and alerted on at 80/90/100 %. Returning nil here is
		// the whole "never a kill switch during an incident" decision — the
		// admission succeeds and the commercial conversation happens out of
		// band.
		return nil
	}
	phase := PhaseOf(svc)
	lifted := LiftedBy(name, lim, at)
	msg := fmt.Sprintf("your %s licence covers %d %s and %d %s in use",
		at.Label(), lim, CeilingLabel(name), current, plural(current))
	if phase == PhasePostGrace {
		// The Community ceilings in force are a FALLBACK, not what the customer
		// bought. Say so, and say what is not happening: nothing already
		// admitted has been touched.
		msg = fmt.Sprintf("the licence that covered this expired and its grace period has ended, so the Community ceiling of %d %s is the one in force and %d %s in use",
			lim, CeilingLabel(name), current, plural(current))
		msg += " — nothing has been disabled or deleted and everything over the ceiling is listed; install a renewed licence to lift it again"
	} else if lifted != "" {
		lc, _ := tierCeilings[lifted].Get(name)
		if lc == Unlimited {
			msg += fmt.Sprintf(" — the %s tier removes this limit", lifted.Label())
		} else {
			msg += fmt.Sprintf(" — the %s tier raises it to %d", lifted.Label(), lc)
		}
	} else {
		msg += " — contact Correlix to raise it"
	}
	if phase == PhasePostGrace {
		// A renewal is the remedy, not an upgrade: naming a tier to buy would
		// send the operator to the wrong purchase.
		lifted = ""
	}
	return &ErrLicence{
		Ceiling: name, Unit: CeilingUnit(name), Current: current, Limit: lim,
		Tier: at, LiftedBy: lifted, LicenceState: phase, Message: msg,
	}
}

func plural(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP rendering
// ─────────────────────────────────────────────────────────────────────────────

// StatusLicence is the HTTP status a licence refusal carries: 402 Payment
// Required. It is deliberately NOT 403 — the caller's authorization is fine,
// the licence is what is short, and the SPA keys the upgrade card off this
// exact status so an authorization failure can never be mis-rendered as an
// upsell (or vice versa).
const StatusLicence = http.StatusPaymentRequired

// RefusalBody is the 402 wire body. `error` is a stable machine token; the SPA
// switches on it, then renders `message` and the card from the rest.
type RefusalBody struct {
	Error string `json:"error"`
	*ErrLicence
}

// Refusal kinds — the stable machine tokens in RefusalBody.Error.
const (
	KindCeiling = "licence_ceiling"
	KindFeature = "licence_feature"
)

// WriteRefusal renders err as the structured 402 when it is a licence refusal
// and reports whether it did. A non-licence error is left entirely alone (the
// caller's own error handling runs), so this is safe to put in front of any
// error path:
//
//	if entitlement.WriteRefusal(w, err) {
//	        return
//	}
func WriteRefusal(w http.ResponseWriter, err error) bool {
	e, ok := As(err)
	if !ok || w == nil {
		return false
	}
	kind := KindCeiling
	if e.Feature != "" {
		kind = KindFeature
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(StatusLicence)
	// The body is a fixed, closed struct of our own values, so it cannot fail to
	// marshal, and the 402 status line is already on the wire — there is nothing
	// left to report an encode failure with.
	_ = json.NewEncoder(w).Encode(RefusalBody{Error: kind, ErrLicence: e}) // best-effort: nothing can act on a write failure after the status line
	return true
}
