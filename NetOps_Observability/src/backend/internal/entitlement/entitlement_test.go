package entitlement_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/internal/entitlement"
)

// entitlement_test.go — the owner's acceptance list for the central entitlement
// service, asserted against the abstraction rather than any one implementation.
//
// The stub below is deliberately dumb: a set of features and a ceilings struct.
// Testing the SEMANTIC layer against a stub, and the licence FILE separately
// (internal/licence), is what makes "business code asks Entitled(FeatureX),
// never tier == enterprise" checkable — if a gate secretly depended on a real
// licence document, it could not be exercised here at all.

// stub is a Service with hand-set answers.
type stub struct {
	tier     entitlement.Tier
	features map[entitlement.Feature]bool
	ceilings entitlement.Ceilings
}

func (s stub) Entitled(f entitlement.Feature) bool { return s.features[f] }
func (s stub) Tier() entitlement.Tier              { return s.tier }
func (s stub) Ceiling(name string) (int, entitlement.Tier) {
	v, ok := s.ceilings.Get(name)
	if !ok {
		return 0, ""
	}
	return v, entitlement.LiftedBy(name, v, s.tier)
}

func community() stub {
	return stub{tier: entitlement.TierCommunity, features: map[entitlement.Feature]bool{}, ceilings: entitlement.CommunityCeilings()}
}

func team() stub {
	c, _ := entitlement.TierCeilings(entitlement.TierTeam)
	return stub{
		tier:     entitlement.TierTeam,
		features: map[entitlement.Feature]bool{entitlement.FeatureSecurityFindings: true},
		ceilings: c,
	}
}

func enterprise() stub {
	c, _ := entitlement.TierCeilings(entitlement.TierEnterprise)
	f := map[entitlement.Feature]bool{}
	for _, k := range entitlement.Features() {
		f[k] = true
	}
	return stub{tier: entitlement.TierEnterprise, features: f, ceilings: c}
}

// featuresUnderTest is shared with safety_invariant_test.go.
func featuresUnderTest() []entitlement.Feature { return entitlement.Features() }

// ─────────────────────────────────────────────────────────────────────────────
// Owner's list, item 1: Community / no entitlement
// ─────────────────────────────────────────────────────────────────────────────

// TestCommunityEnforcesTheTwoDecidedCeilings: 25 devices and 5 watched prefixes
// are the owner-decided Community product limits, and they are the ONLY numeric
// limits the product gates on.
func TestCommunityEnforcesTheTwoDecidedCeilings(t *testing.T) {
	svc := community()

	t.Run("the 25th device is admitted and the 26th is refused", func(t *testing.T) {
		if err := entitlement.CheckCeiling(svc, entitlement.CeilingDevices, 24); err != nil {
			t.Fatalf("the 25th device is within the Community ceiling: %v", err)
		}
		err := entitlement.CheckCeiling(svc, entitlement.CeilingDevices, 25)
		if err == nil {
			t.Fatal("the 26th device must be refused under Community")
		}
		e, ok := entitlement.As(err)
		if !ok {
			t.Fatalf("a ceiling refusal must be a structured *ErrLicence, got %T", err)
		}
		if e.Ceiling != entitlement.CeilingDevices || e.Limit != 25 || e.Current != 25 {
			t.Fatalf("the refusal must name the ceiling, the limit and where the caller stands: %+v", e)
		}
		if e.Tier != entitlement.TierCommunity {
			t.Fatalf("tier in force = %q", e.Tier)
		}
		if e.LiftedBy != entitlement.TierTeam {
			t.Fatalf("Team (250 devices) lifts this — the refusal must say so, got %q", e.LiftedBy)
		}
		// The card must be renderable without parsing prose.
		if !strings.Contains(e.Message, "25") || !strings.Contains(e.Message, "Team") {
			t.Fatalf("the message must be honest and actionable: %q", e.Message)
		}
	})

	t.Run("the 5th watched prefix is admitted and the 6th is refused", func(t *testing.T) {
		if err := entitlement.CheckCeiling(svc, entitlement.CeilingWatchedPrefixes, 4); err != nil {
			t.Fatalf("the 5th prefix is within the Community ceiling: %v", err)
		}
		err := entitlement.CheckCeiling(svc, entitlement.CeilingWatchedPrefixes, 5)
		if err == nil {
			t.Fatal("the 6th watched prefix must be refused under Community")
		}
		e, _ := entitlement.As(err)
		if e.Ceiling != entitlement.CeilingWatchedPrefixes || e.Limit != 5 {
			t.Fatalf("%+v", e)
		}
		if e.LiftedBy != entitlement.TierTeam {
			t.Fatalf("Team (100 prefixes) lifts this, got %q", e.LiftedBy)
		}
	})
}

// TestCommunityGrantsNoCommercialFeature is the owner's "without Enterprise →
// unavailable" list, plus the Team feature, checked from the free tier.
func TestCommunityGrantsNoCommercialFeature(t *testing.T) {
	svc := community()
	for _, f := range entitlement.Features() {
		if entitlement.Entitled(svc, f) {
			t.Fatalf("Community must not grant %q", f)
		}
		err := entitlement.Require(svc, f)
		if err == nil {
			t.Fatalf("Require(%q) must refuse under Community", f)
		}
		e, ok := entitlement.As(err)
		if !ok {
			t.Fatalf("a feature refusal must be a structured *ErrLicence, got %T", err)
		}
		if e.Feature != f {
			t.Fatalf("the refusal must name the feature, got %q", e.Feature)
		}
		if e.LiftedBy != entitlement.FeatureTier(f) {
			t.Fatalf("%q is included in %q — the refusal must say so, got %q", f, entitlement.FeatureTier(f), e.LiftedBy)
		}
		if e.Ceiling != "" {
			t.Fatalf("a feature refusal carries no ceiling: %+v", e)
		}
	}
}

// TestNoEntitlementServiceIsCommunity: the fail-closed direction. A nil Service
// — a build that never wired the licence subsystem — grants nothing and enforces
// the Community ceilings, rather than granting everything.
func TestNoEntitlementServiceIsCommunity(t *testing.T) {
	var svc entitlement.Service // nil

	for _, f := range entitlement.Features() {
		if entitlement.Entitled(svc, f) {
			t.Fatalf("an unwired entitlement service must grant nothing, granted %q", f)
		}
		if entitlement.Require(svc, f) == nil {
			t.Fatalf("an unwired service must refuse %q", f)
		}
	}
	if err := entitlement.CheckCeiling(svc, entitlement.CeilingDevices, 25); err == nil {
		t.Fatal("an unwired service must still enforce the Community device ceiling — failing OPEN would make forgetting the wiring an unlimited licence")
	}
	if err := entitlement.CheckCeiling(svc, entitlement.CeilingDevices, 10); err != nil {
		t.Fatalf("and must not refuse below it: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Owner's list, item 2: Team
// ─────────────────────────────────────────────────────────────────────────────

// TestTeamGrantsSecurityFindingsAndNothingElse pins the LOCKED set's Team row.
func TestTeamGrantsSecurityFindingsAndNothingElse(t *testing.T) {
	svc := team()

	if !entitlement.Entitled(svc, entitlement.FeatureSecurityFindings) {
		t.Fatal("Team includes security findings")
	}
	if err := entitlement.Require(svc, entitlement.FeatureSecurityFindings); err != nil {
		t.Fatalf("Require must pass for an entitled feature: %v", err)
	}
	for _, f := range entitlement.Features() {
		if f == entitlement.FeatureSecurityFindings {
			continue
		}
		if entitlement.Entitled(svc, f) {
			t.Fatalf("Team must NOT grant %q — it is Enterprise", f)
		}
	}
	// And Team's ceilings lift Community's.
	if err := entitlement.CheckCeiling(svc, entitlement.CeilingDevices, 25); err != nil {
		t.Fatalf("the 26th device is admitted under Team: %v", err)
	}
	if err := entitlement.CheckCeiling(svc, entitlement.CeilingDevices, 250); err == nil {
		t.Fatal("the 251st device is refused under Team")
	}
	if err := entitlement.CheckCeiling(svc, entitlement.CeilingWatchedPrefixes, 5); err != nil {
		t.Fatalf("the 6th prefix is admitted under Team: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Owner's list, item 3: Enterprise
// ─────────────────────────────────────────────────────────────────────────────

// TestEnterpriseGrantsTheLockedSet: with a valid Enterprise entitlement, every
// commercial capability the owner locked is available.
func TestEnterpriseGrantsTheLockedSet(t *testing.T) {
	svc := enterprise()
	for _, f := range entitlement.Features() {
		if !entitlement.Entitled(svc, f) {
			t.Fatalf("Enterprise must grant %q", f)
		}
		if err := entitlement.Require(svc, f); err != nil {
			t.Fatalf("Require(%q) under Enterprise: %v", f, err)
		}
	}
	// Unlimited ceilings never refuse.
	if err := entitlement.CheckCeiling(svc, entitlement.CeilingDevices, 1_000_000); err != nil {
		t.Fatalf("Enterprise devices are unlimited per licence: %v", err)
	}
	if err := entitlement.CheckCeiling(svc, entitlement.CeilingWatchedPrefixes, 999_999); err != nil {
		t.Fatalf("Enterprise prefixes are unlimited per licence: %v", err)
	}
}

// TestEnterpriseOnlyFeaturesAreUnavailableBelowIt is the owner's "without
// Enterprise → SAML/SCIM/LDAP/SIEM export/dialects/MSP management unavailable",
// stated explicitly rather than inferred from the loop above.
func TestEnterpriseOnlyFeaturesAreUnavailableBelowIt(t *testing.T) {
	enterpriseOnly := []entitlement.Feature{
		entitlement.FeatureSAML,
		entitlement.FeatureSCIM,
		entitlement.FeatureLDAP,
		entitlement.FeatureSIEMExport,
		entitlement.FeatureSecurityDialects,
		entitlement.FeatureMSPManagement,
	}
	for _, svc := range []stub{community(), team()} {
		for _, f := range enterpriseOnly {
			if entitlement.Entitled(svc, f) {
				t.Fatalf("%s must not grant %q", svc.tier, f)
			}
			e, ok := entitlement.As(entitlement.Require(svc, f))
			if !ok {
				t.Fatalf("%s: %q must produce a structured refusal", svc.tier, f)
			}
			if e.LiftedBy != entitlement.TierEnterprise {
				t.Fatalf("%q is an Enterprise feature; the refusal must name Enterprise, got %q", f, e.LiftedBy)
			}
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// The tier-check ban
// ─────────────────────────────────────────────────────────────────────────────

// TestFeaturesAreSemanticNotTierChecks: every gate answers a SEMANTIC question.
// A caller who somehow held only a tier string could not reproduce these
// answers, which is the point — Entitled(FeatureX) is the contract, and
// `tier == "enterprise"` is a defect.
func TestFeaturesAreSemanticNotTierChecks(t *testing.T) {
	// A hand-issued licence may grant a feature outside its tier's usual bundle
	// (a trial, a contractual exception). Semantic gating handles that with no
	// special case; a tier comparison would silently deny it.
	odd := stub{
		tier:     entitlement.TierTeam,
		features: map[entitlement.Feature]bool{entitlement.FeatureSAML: true},
		ceilings: entitlement.CommunityCeilings(),
	}
	if !entitlement.Entitled(odd, entitlement.FeatureSAML) {
		t.Fatal("a Team licence that explicitly grants SAML must grant SAML — the FILE decides, not the tier label")
	}
	if err := entitlement.Require(odd, entitlement.FeatureSAML); err != nil {
		t.Fatalf("Require must honour the explicit grant: %v", err)
	}
	// And the converse: an Enterprise-tier licence that does NOT list a feature
	// does not get it.
	stingy := stub{tier: entitlement.TierEnterprise, features: map[entitlement.Feature]bool{}}
	if entitlement.Entitled(stingy, entitlement.FeatureSCIM) {
		t.Fatal("the tier label must not grant anything on its own")
	}
}

// TestUnknownVocabularyIsNeverGranted: closed means closed. A feature name that
// is not in the vocabulary is never entitled, however it got into a document.
func TestUnknownVocabularyIsNeverGranted(t *testing.T) {
	svc := stub{
		tier:     entitlement.TierEnterprise,
		features: map[entitlement.Feature]bool{"root_access": true, "reports": true},
	}
	for _, f := range []entitlement.Feature{"root_access", "reports", "", "SAML"} {
		if entitlement.Entitled(svc, f) {
			t.Fatalf("%q is outside the closed vocabulary and must never be entitled", f)
		}
	}
	if !entitlement.ValidFeature(entitlement.FeatureSAML) {
		t.Fatal("the real vocabulary must still validate")
	}
}

// TestUnknownCeilingRefusesRatherThanPermits: a mistyped ceiling name is a
// programming error. Permitting it would be a gate that quietly stopped gating.
func TestUnknownCeilingRefusesRatherThanPermits(t *testing.T) {
	err := entitlement.CheckCeiling(enterprise(), "devicez", 0)
	if err == nil {
		t.Fatal("an unknown ceiling name must refuse, not silently permit")
	}
	if !strings.Contains(err.Error(), "unknown licence ceiling") {
		t.Fatalf("and must say so: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// The 402
// ─────────────────────────────────────────────────────────────────────────────

// TestWriteRefusalRendersThe402 is the wire contract the SPA's upgrade card
// depends on.
func TestWriteRefusalRendersThe402(t *testing.T) {
	t.Run("ceiling", func(t *testing.T) {
		w := httptest.NewRecorder()
		if !entitlement.WriteRefusal(w, entitlement.CheckCeiling(community(), entitlement.CeilingDevices, 25)) {
			t.Fatal("a licence refusal must be rendered")
		}
		if w.Code != http.StatusPaymentRequired {
			t.Fatalf("status = %d, want 402 — the SPA keys the upgrade card off this exact status, and 403 would render as an authorization failure", w.Code)
		}
		if ct := w.Header().Get("Content-Type"); ct != "application/json" {
			t.Fatalf("content-type = %q", ct)
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("the 402 body must be JSON: %v", err)
		}
		if body["error"] != entitlement.KindCeiling {
			t.Fatalf("error = %v, want %q", body["error"], entitlement.KindCeiling)
		}
		for _, k := range []string{"ceiling", "unit", "current", "limit", "tier", "lifted_by", "message"} {
			if _, ok := body[k]; !ok {
				t.Fatalf("the card needs %q in the body: %v", k, body)
			}
		}
		// The UNIT is what stops a client rendering a limit on collection as a
		// limit on inventory rows. The ceiling NAME cannot say it: it is a
		// signed field of every issued licence and can never change.
		if body["unit"] != entitlement.UnitMonitoredDevices {
			t.Fatalf("unit = %v, want %q", body["unit"], entitlement.UnitMonitoredDevices)
		}
	})

	t.Run("feature", func(t *testing.T) {
		w := httptest.NewRecorder()
		if !entitlement.WriteRefusal(w, entitlement.Require(community(), entitlement.FeatureSAML)) {
			t.Fatal("a feature refusal must be rendered")
		}
		if w.Code != http.StatusPaymentRequired {
			t.Fatalf("status = %d, want 402", w.Code)
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body["error"] != entitlement.KindFeature {
			t.Fatalf("error = %v, want %q", body["error"], entitlement.KindFeature)
		}
		if body["feature"] != string(entitlement.FeatureSAML) {
			t.Fatalf("feature = %v", body["feature"])
		}
		if body["lifted_by"] != string(entitlement.TierEnterprise) {
			t.Fatalf("lifted_by = %v", body["lifted_by"])
		}
	})

	t.Run("leaves a non-licence error alone", func(t *testing.T) {
		// This is what makes WriteRefusal safe to put in front of any error path:
		// it must not swallow an unrelated failure and turn a 500 into an upsell.
		w := httptest.NewRecorder()
		if entitlement.WriteRefusal(w, errors.New("database is on fire")) {
			t.Fatal("a non-licence error must not be rendered as a 402")
		}
		if w.Code != http.StatusOK || w.Body.Len() != 0 {
			t.Fatal("and must not be written to at all")
		}
	})

	t.Run("nil error is not a refusal", func(t *testing.T) {
		w := httptest.NewRecorder()
		if entitlement.WriteRefusal(w, nil) {
			t.Fatal("nil is success, not a refusal")
		}
	})
}

// TestCeilingsSayWhatTheyCount pins the C4 decision at the vocabulary level:
// the devices ceiling counts MONITORED devices, its name stays "devices"
// because every issued licence signs that field, and the label an operator
// reads says so out loud.
func TestCeilingsSayWhatTheyCount(t *testing.T) {
	if entitlement.CeilingDevices != "devices" {
		t.Fatalf("the licence-file field must not be renamed: every issued document signs it (%q)", entitlement.CeilingDevices)
	}
	if got := entitlement.CeilingUnit(entitlement.CeilingDevices); got != entitlement.UnitMonitoredDevices {
		t.Fatalf("unit = %q, want %q — discovery is free and inventory rows are not the licensed unit", got, entitlement.UnitMonitoredDevices)
	}
	if got := entitlement.CeilingLabel(entitlement.CeilingDevices); got != "monitored devices" {
		t.Fatalf("label = %q — a bar reading \"devices\" beside a 500-device inventory teaches the wrong rule", got)
	}
	// Every ceiling in the closed vocabulary says what it counts; a blank unit
	// is a row a client cannot render honestly.
	for _, n := range entitlement.CeilingNames() {
		if entitlement.CeilingUnit(n) == "" {
			t.Fatalf("ceiling %q has no unit", n)
		}
	}
	if entitlement.CeilingUnit("not-a-ceiling") != "" {
		t.Fatal("a name outside the vocabulary has no unit")
	}
	// And the refusal sentence names it, so the message alone is unambiguous.
	err := entitlement.CheckCeiling(community(), entitlement.CeilingDevices, 25)
	if err == nil || !strings.Contains(err.Error(), "monitored devices") {
		t.Fatalf("the refusal must say what is limited: %v", err)
	}
}

// TestErrorsIsSentinel lets a caller ask "was this a licence refusal?" without
// a type assertion.
func TestErrorsIsSentinel(t *testing.T) {
	err := entitlement.Require(community(), entitlement.FeatureSAML)
	if !errors.Is(err, entitlement.ErrNotEntitled) {
		t.Fatal("every licence refusal must match ErrNotEntitled")
	}
	if errors.Is(errors.New("other"), entitlement.ErrNotEntitled) {
		t.Fatal("and nothing else may")
	}
	// Wrapped, as a store would return it.
	wrapped := errors.Join(errors.New("adding device"), err)
	e, ok := entitlement.As(wrapped)
	if !ok || e.Feature != entitlement.FeatureSAML {
		t.Fatalf("As must find the refusal through a wrap: %+v %v", e, ok)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Lifting tiers
// ─────────────────────────────────────────────────────────────────────────────

func TestLiftedBy(t *testing.T) {
	cases := []struct {
		name  string
		limit int
		at    entitlement.Tier
		want  entitlement.Tier
	}{
		{entitlement.CeilingDevices, 25, entitlement.TierCommunity, entitlement.TierTeam},
		{entitlement.CeilingDevices, 250, entitlement.TierTeam, entitlement.TierEnterprise},
		// Nothing above Enterprise: the refusal says "contact us" rather than
		// naming a tier that would not help.
		{entitlement.CeilingDevices, entitlement.Unlimited, entitlement.TierEnterprise, ""},
		{entitlement.CeilingWatchedPrefixes, 5, entitlement.TierCommunity, entitlement.TierTeam},
		{entitlement.CeilingWatchedPrefixes, 100, entitlement.TierTeam, entitlement.TierEnterprise},
	}
	for _, c := range cases {
		if got := entitlement.LiftedBy(c.name, c.limit, c.at); got != c.want {
			t.Fatalf("LiftedBy(%s, %d, %s) = %q, want %q", c.name, c.limit, c.at, got, c.want)
		}
	}
}

// TestUnlimitedNeverRefuses guards the -1 sentinel end to end. A limit of -1
// read as a literal number would refuse everything.
func TestUnlimitedNeverRefuses(t *testing.T) {
	if entitlement.Exceeds(1_000_000, entitlement.Unlimited) {
		t.Fatal("nothing exceeds an unlimited ceiling")
	}
	if !entitlement.Exceeds(1, 0) {
		t.Fatal("a ceiling of zero is a real zero, not an unlimited one")
	}
	svc := stub{tier: entitlement.TierEnterprise, ceilings: entitlement.Ceilings{Devices: entitlement.Unlimited}}
	if err := entitlement.CheckCeiling(svc, entitlement.CeilingDevices, 10_000_000); err != nil {
		t.Fatalf("unlimited must never refuse: %v", err)
	}
}
