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
	CeilingDevices              = "devices"
	CeilingWatchedPrefixes      = "watched_prefixes"
	CeilingTenants              = "tenants"
	CeilingOrgs                 = "orgs"
	CeilingRetentionDays        = "retention_days"
	CeilingSkills               = "skills"
	CeilingProviderTokensPerDay = "provider_tokens_per_day"
)

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

// CeilingLabel is the operator-facing name of a ceiling.
func CeilingLabel(name string) string {
	switch name {
	case CeilingDevices:
		return "devices"
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
	lifted := featureTier[f]
	if rank(lifted) <= rank(at) {
		// Either an unknown feature, or the tier in force already ought to grant
		// it — which happens when a licence is expired/degraded. Naming a tier
		// the customer already has would be a lie, so we name none and the
		// message carries the real reason.
		lifted = ""
	}
	msg := fmt.Sprintf("%s is not included in your %s licence", FeatureLabel(f), at.Label())
	if lifted != "" {
		msg += fmt.Sprintf(" — the %s tier includes it", lifted.Label())
	} else {
		msg += " — contact Correlix to enable it"
	}
	return &ErrLicence{Feature: f, Tier: at, LiftedBy: lifted, Message: msg}
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
// Note the boundary: with a limit of 25 and 25 devices already admitted, the
// 26th is refused. Nothing existing is ever removed or hidden by this call —
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
			Ceiling: name, Current: current, Tier: TierCommunity,
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
	lifted := LiftedBy(name, lim, at)
	msg := fmt.Sprintf("your %s licence covers %d %s and %d %s in use",
		at.Label(), lim, CeilingLabel(name), current, plural(current))
	if lifted != "" {
		lc, _ := tierCeilings[lifted].Get(name)
		if lc == Unlimited {
			msg += fmt.Sprintf(" — the %s tier removes this limit", lifted.Label())
		} else {
			msg += fmt.Sprintf(" — the %s tier raises it to %d", lifted.Label(), lc)
		}
	} else {
		msg += " — contact Correlix to raise it"
	}
	return &ErrLicence{
		Ceiling: name, Current: current, Limit: lim,
		Tier: at, LiftedBy: lifted, Message: msg,
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
