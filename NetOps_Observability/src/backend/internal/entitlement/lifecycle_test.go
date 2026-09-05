package entitlement_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/internal/entitlement"
)

// lifecycle_test.go — the post-expiry state machine and the soft-overage
// policy, asserted against the ABSTRACTION (owner decision, 2026-09-05;
// docs/design/TIERING_PLAN_2026-09-03.md §9).
//
// The lifecycle stub below is what a lapsed licence looks like to business
// code: the tier in force has fallen back to Community and the granted set is
// empty, but the features the expired document DID grant are still readable.
// Proving the rule here rather than only against a real signed file is what
// makes it a property of the gate and not of one document.

// lifecycleStub is a Service that also reports an expiry phase and a retained
// read set — entitlement.Lifecycle.
type lifecycleStub struct {
	stub
	phase  entitlement.Phase
	lapsed map[entitlement.Feature]bool
}

func (s lifecycleStub) Phase() entitlement.Phase { return s.phase }
func (s lifecycleStub) EntitledForRead(f entitlement.Feature) bool {
	return s.features[f] || s.lapsed[f]
}

// lapsedTeam is a Team licence past its grace period: Community ceilings and no
// granted features, with security findings still READABLE.
func lapsedTeam() lifecycleStub {
	return lifecycleStub{
		stub: stub{
			tier:     entitlement.TierCommunity,
			features: map[entitlement.Feature]bool{},
			ceilings: entitlement.CommunityCeilings(),
		},
		phase:  entitlement.PhasePostGrace,
		lapsed: map[entitlement.Feature]bool{entitlement.FeatureSecurityFindings: true},
	}
}

// TestPhaseVocabularyIsClosed: the machine has exactly three states and a
// Service that tracks none reads as `valid`.
func TestPhaseVocabularyIsClosed(t *testing.T) {
	want := []entitlement.Phase{entitlement.PhaseValid, entitlement.PhaseInGrace, entitlement.PhasePostGrace}
	got := entitlement.Phases()
	if len(got) != len(want) {
		t.Fatalf("phases = %v, want exactly %v — a fourth state is a product decision, not a diff", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("phase order = %v, want %v (the order the machine walks)", got, want)
		}
	}
	if entitlement.ValidPhase("degraded") {
		t.Fatal("the phase vocabulary must be closed — an unknown phase is not a permissive one")
	}
	if p := entitlement.PhaseOf(nil); p != entitlement.PhaseValid {
		t.Fatalf("a nil service reads as %q, want valid — absence of a lifecycle is not a lapse", p)
	}
	if p := entitlement.PhaseOf(community()); p != entitlement.PhaseValid {
		t.Fatalf("a Service with no lifecycle reads as %q, want valid — Community has no expiry to be past", p)
	}
}

// TestPostGraceKeepsReadsAndRefusesWrites is the OWNER'S LINE, at the gate:
// "after grace, paid-only creation/configuration actions become unavailable,
// existing data stays viewable/exportable".
func TestPostGraceKeepsReadsAndRefusesWrites(t *testing.T) {
	svc := lapsedTeam()

	if entitlement.Entitled(svc, entitlement.FeatureSecurityFindings) {
		t.Fatal("a lapsed licence grants nothing NEW — Entitled must be false")
	}
	if err := entitlement.Require(svc, entitlement.FeatureSecurityFindings); err == nil {
		t.Fatal("configuring a lapsed capability must be refused")
	}
	if !entitlement.EntitledForRead(svc, entitlement.FeatureSecurityFindings) {
		t.Fatal("existing findings must stay READABLE after a lapse — a screen that goes empty is data loss from the operator's side")
	}
	if err := entitlement.RequireRead(svc, entitlement.FeatureSecurityFindings); err != nil {
		t.Fatalf("RequireRead must admit a lapsed feature's existing data: %v", err)
	}
}

// TestPostGraceNeverGrantsWhatWasNeverBought: a lapse widens reads for the
// features the document GRANTED and for nothing else. Otherwise "let it expire"
// would be a way to acquire Enterprise reads.
func TestPostGraceNeverGrantsWhatWasNeverBought(t *testing.T) {
	svc := lapsedTeam()
	for _, f := range entitlement.Features() {
		if f == entitlement.FeatureSecurityFindings {
			continue
		}
		if entitlement.EntitledForRead(svc, f) {
			t.Fatalf("%q was never in this licence — a lapse must not make it readable", f)
		}
		if err := entitlement.RequireRead(svc, f); err == nil {
			t.Fatalf("RequireRead must refuse %q: the licence never included it", f)
		}
	}
}

// TestRefusalCarriesLicenceState: every refusal names the phase, so a client can
// tell "you never bought this" (upgrade) from "your licence lapsed" (renew).
// They are the same 402 with two entirely different remedies.
func TestRefusalCarriesLicenceState(t *testing.T) {
	t.Run("feature refusal after grace", func(t *testing.T) {
		err := entitlement.Require(lapsedTeam(), entitlement.FeatureSecurityFindings)
		e, ok := entitlement.As(err)
		if !ok {
			t.Fatalf("want a structured refusal, got %T", err)
		}
		if e.LicenceState != entitlement.PhasePostGrace {
			t.Fatalf("licence_state = %q, want post_grace", e.LicenceState)
		}
		if e.LiftedBy != "" {
			t.Fatalf("lifted_by = %q — naming a tier to BUY sends a lapsed customer to the wrong purchase; the remedy is a renewal", e.LiftedBy)
		}
		if !strings.Contains(e.Message, "expired") || !strings.Contains(e.Message, "exportable") {
			t.Fatalf("the message must say the licence expired AND that the data is still there: %q", e.Message)
		}
	})

	t.Run("ceiling refusal after grace", func(t *testing.T) {
		err := entitlement.CheckCeiling(lapsedTeam(), entitlement.CeilingDevices, 25)
		e, ok := entitlement.As(err)
		if !ok {
			t.Fatalf("want a structured refusal, got %T", err)
		}
		if e.LicenceState != entitlement.PhasePostGrace {
			t.Fatalf("licence_state = %q, want post_grace", e.LicenceState)
		}
		if e.Unit != entitlement.UnitMonitoredDevices {
			t.Fatalf("unit = %q, want monitored_devices — the C4 wording is what stops a client rendering it as inventory rows", e.Unit)
		}
		if !strings.Contains(e.Message, "nothing has been disabled or deleted") {
			t.Fatalf("the refusal must say what did NOT happen: %q", e.Message)
		}
	})

	t.Run("a normal refusal is still valid-phase", func(t *testing.T) {
		err := entitlement.Require(community(), entitlement.FeatureSAML)
		e, _ := entitlement.As(err)
		if e == nil || e.LicenceState != entitlement.PhaseValid {
			t.Fatalf("a Community refusal is not a lapse: %+v", e)
		}
		if e.LiftedBy != entitlement.TierEnterprise {
			t.Fatalf("lifted_by = %q, want enterprise — this caller SHOULD be sent to an upgrade", e.LiftedBy)
		}
	})
}

// TestRefusalBodyCarriesLicenceStateOnTheWire: the field the SPA reads is
// actually in the 402 JSON, not merely on the struct.
func TestRefusalBodyCarriesLicenceStateOnTheWire(t *testing.T) {
	w := httptest.NewRecorder()
	if !entitlement.WriteRefusal(w, entitlement.Require(lapsedTeam(), entitlement.FeatureSecurityFindings)) {
		t.Fatal("WriteRefusal must render a licence refusal")
	}
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("the 402 body must be JSON: %v (%s)", err, w.Body.String())
	}
	if body["licence_state"] != string(entitlement.PhasePostGrace) {
		t.Fatalf("licence_state = %v, want %q", body["licence_state"], entitlement.PhasePostGrace)
	}
	if body["error"] != entitlement.KindFeature {
		t.Fatalf("error = %v, want %q — the machine token the SPA switches on", body["error"], entitlement.KindFeature)
	}
}

// TestSoftCeilingIsMonitoredDevicesOnPaidTiersOnly pins the owner's decision
// exactly: Team and Enterprise monitored devices are soft; everything else,
// including every Community ceiling, is hard.
func TestSoftCeilingIsMonitoredDevicesOnPaidTiersOnly(t *testing.T) {
	for _, tier := range entitlement.Tiers() {
		for _, name := range entitlement.CeilingNames() {
			want := name == entitlement.CeilingDevices &&
				(tier == entitlement.TierTeam || tier == entitlement.TierEnterprise)
			if got := entitlement.SoftCeiling(name, tier); got != want {
				t.Fatalf("SoftCeiling(%q, %q) = %v, want %v — softness is a commercial decision and this table IS the decision",
					name, tier, got, want)
			}
		}
	}
}

// TestCommunityDeviceCeilingStaysHard: the published free ceiling must bite at
// the 26th activation (§9 Community row), including after a lapse — where the
// tier in force IS Community.
func TestCommunityDeviceCeilingStaysHard(t *testing.T) {
	for name, svc := range map[string]entitlement.Service{
		"free tier":   community(),
		"after grace": lapsedTeam(),
	} {
		t.Run(name, func(t *testing.T) {
			if err := entitlement.CheckCeiling(svc, entitlement.CeilingDevices, 25); err == nil {
				t.Fatal("the 26th monitored device must be refused: 25 is a published free ceiling and a limit that does not bite is not a limit")
			}
		})
	}
}

// TestSoftOverageAdmitsBeyondTheCeiling is the "never a kill switch during an
// incident" half: at Team, activation past 250 succeeds and is recorded
// elsewhere (internal/licence.OverageTracker), not refused here.
func TestSoftOverageAdmitsBeyondTheCeiling(t *testing.T) {
	svc := team()
	for _, current := range []int{250, 300, 4_000} {
		if err := entitlement.CheckCeiling(svc, entitlement.CeilingDevices, current); err != nil {
			t.Fatalf("at %d monitored devices the next activation must be ADMITTED under Team: %v", current, err)
		}
	}
	// …and Enterprise, whose reference ceiling is unlimited anyway, must not
	// regress into a refusal either.
	if err := entitlement.CheckCeiling(enterprise(), entitlement.CeilingDevices, 100_000); err != nil {
		t.Fatalf("Enterprise must admit: %v", err)
	}
}
