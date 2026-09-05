package licence_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/entitlement"
	"netops/backend/internal/licence"
	"netops/backend/internal/licence/signer"
)

// expiry_test.go — the post-expiry state machine, trial issuance and the
// soft-overage register (owner decision, 2026-09-05; TIERING_PLAN §9).
//
// These run against REAL signed documents, because the thing being asserted is
// what the product does with a file a customer actually holds. The semantic
// half — that the gates honour the phase — is proved separately against the
// abstraction in internal/entitlement/lifecycle_test.go.

// expKey is a throwaway signing identity and the verifier that trusts it.
type expKey struct {
	kp signer.KeyPair
	v  licence.Verifier
}

func newExpKey(t *testing.T) expKey {
	t.Helper()
	kp, err := signer.GenerateKey()
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	return expKey{kp: kp, v: licence.NewVerifier(licence.NewPublicKey(kp.Public, licence.RoleCurrent, "expiry test key"))}
}

// sign issues a document and returns its bytes.
func (k expKey) sign(t *testing.T, doc licence.Document) []byte {
	t.Helper()
	signed, err := signer.Sign(doc, k.kp.Private)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// expiryTeamDoc is a Team licence expiring at `expires` with `grace` days of grace.
func expiryTeamDoc(expires time.Time, grace int, trial bool) licence.Document {
	c, _ := entitlement.TierCeilings(entitlement.TierTeam)
	return licence.Document{
		LicenceID: "expiry-test",
		Customer:  "Expiry Test Ltd",
		Tier:      entitlement.TierTeam,
		IssuedAt:  expires.AddDate(-1, 0, 0),
		ExpiresAt: expires,
		Ceilings:  c,
		Features:  []entitlement.Feature{entitlement.FeatureSecurityFindings},
		GraceDays: grace,
		Trial:     trial,
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// The state machine
// ─────────────────────────────────────────────────────────────────────────────

// TestExpiryStateMachine walks valid → in_grace → post_grace across the exact
// boundaries, because a state machine is only as good as its edges.
func TestExpiryStateMachine(t *testing.T) {
	k := newExpKey(t)
	expires := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	raw := k.sign(t, expiryTeamDoc(expires, licence.PaidGraceDays, false))

	cases := []struct {
		name  string
		at    time.Time
		phase entitlement.Phase
	}{
		{"a year before expiry", expires.AddDate(-1, 0, 0).Add(time.Hour), entitlement.PhaseValid},
		{"the last second before expiry", expires.Add(-time.Second), entitlement.PhaseValid},
		{"exactly at expiry", expires, entitlement.PhaseValid},
		{"one second after expiry", expires.Add(time.Second), entitlement.PhaseInGrace},
		{"the last day of grace", expires.AddDate(0, 0, 29), entitlement.PhaseInGrace},
		{"exactly at the end of grace", expires.AddDate(0, 0, 30), entitlement.PhaseInGrace},
		{"one second past grace", expires.AddDate(0, 0, 30).Add(time.Second), entitlement.PhasePostGrace},
		{"long past grace", expires.AddDate(1, 0, 0), entitlement.PhasePostGrace},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st, err := k.v.Verify(raw, c.at)
			if err != nil {
				t.Fatalf("an EXPIRED licence is still authentic and must verify: %v", err)
			}
			if st.Phase != c.phase {
				t.Fatalf("phase = %q, want %q", st.Phase, c.phase)
			}
			// The boolean shape the metrics and the installed SPA read must
			// never disagree with the phase.
			if st.InGrace != (c.phase == entitlement.PhaseInGrace) {
				t.Fatalf("in_grace = %v but phase = %q", st.InGrace, st.Phase)
			}
			if st.Degraded != (c.phase == entitlement.PhasePostGrace) {
				t.Fatalf("degraded = %v but phase = %q", st.Degraded, st.Phase)
			}
			if !st.GraceEndsAt.Equal(expires.AddDate(0, 0, 30)) {
				t.Fatalf("grace_ends_at = %s, want %s — the window must be stated before it is needed",
					st.GraceEndsAt, expires.AddDate(0, 0, 30))
			}
		})
	}
}

// TestInGraceChangesNothing: during grace the customer keeps EVERYTHING. That
// is the whole promise of a grace period, and a page or a gate that quietly
// tightened here would make it worthless.
func TestInGraceChangesNothing(t *testing.T) {
	k := newExpKey(t)
	expires := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	raw := k.sign(t, expiryTeamDoc(expires, licence.PaidGraceDays, false))

	live, err := k.v.Verify(raw, expires.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	grace, err := k.v.Verify(raw, expires.AddDate(0, 0, 10))
	if err != nil {
		t.Fatal(err)
	}
	if grace.Tier != live.Tier {
		t.Fatalf("tier in grace = %q, want the licensed %q", grace.Tier, live.Tier)
	}
	if grace.Ceilings != live.Ceilings {
		t.Fatalf("ceilings in grace = %+v, want the licensed %+v", grace.Ceilings, live.Ceilings)
	}
	if !grace.Has(entitlement.FeatureSecurityFindings) {
		t.Fatal("a licensed feature must stay granted during grace")
	}
	if len(grace.LapsedFeatures) != 0 {
		t.Fatalf("nothing has lapsed during grace: %v", grace.LapsedFeatures)
	}
	svc := licence.NewService(licence.NewStaticStore(grace))
	if err := entitlement.Require(svc, entitlement.FeatureSecurityFindings); err != nil {
		t.Fatalf("configuring a licensed feature must still work in grace: %v", err)
	}
	if err := entitlement.CheckCeiling(svc, entitlement.CeilingDevices, 100); err != nil {
		t.Fatalf("the Team device ceiling must still be in force in grace: %v", err)
	}

	// And the runway the chip and the alert rule show.
	left, ok := grace.GraceDaysLeft(expires.AddDate(0, 0, 10))
	if !ok || left != 20 {
		t.Fatalf("grace days left = %d (ok=%v), want 20", left, ok)
	}
	if _, ok := live.GraceDaysLeft(expires.Add(-time.Hour)); ok {
		t.Fatal("a licence that has not expired is not IN grace — reporting a countdown would invent a state")
	}
	if _, ok := licence.Community().GraceDaysLeft(time.Now()); ok {
		t.Fatal("Community has no grace window; there is nothing to count down")
	}
}

// TestPostGraceFallsBackButKeepsReads is the owner's line at the state level:
// Community ceilings and no NEW capability, with the granted set retained as
// LapsedFeatures so existing data stays readable and exportable.
func TestPostGraceFallsBackButKeepsReads(t *testing.T) {
	k := newExpKey(t)
	expires := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	raw := k.sign(t, expiryTeamDoc(expires, licence.PaidGraceDays, false))

	st, err := k.v.Verify(raw, expires.AddDate(0, 2, 0))
	if err != nil {
		t.Fatal(err)
	}
	if st.Tier != entitlement.TierCommunity {
		t.Fatalf("tier in force = %q, want community (the fallback)", st.Tier)
	}
	if st.LicensedTier != entitlement.TierTeam {
		t.Fatalf("licensed tier = %q, want team — the page must be able to say WHICH licence expired", st.LicensedTier)
	}
	if st.Ceilings != entitlement.CommunityCeilings() {
		t.Fatalf("ceilings = %+v, want the Community ones", st.Ceilings)
	}
	if len(st.Features) != 0 {
		t.Fatalf("nothing new is granted past grace: %v", st.Features)
	}
	if !st.HasLapsed(entitlement.FeatureSecurityFindings) {
		t.Fatal("the lapsed licence's features must be REMEMBERED — that is what keeps existing data readable")
	}

	svc := licence.NewService(licence.NewStaticStore(st))
	if svc.Phase() != entitlement.PhasePostGrace {
		t.Fatalf("service phase = %q, want post_grace", svc.Phase())
	}
	if entitlement.Entitled(svc, entitlement.FeatureSecurityFindings) {
		t.Fatal("Entitled (create/configure) must be false past grace")
	}
	if !entitlement.EntitledForRead(svc, entitlement.FeatureSecurityFindings) {
		t.Fatal("EntitledForRead (view/export existing) must stay true past grace")
	}
	for _, f := range []entitlement.Feature{entitlement.FeatureSAML, entitlement.FeatureSIEMExport, entitlement.FeatureLDAP} {
		if entitlement.EntitledForRead(svc, f) {
			t.Fatalf("%q was never in this licence — a lapse must not make it readable", f)
		}
	}
	// The reason is what an operator reads at 2am: it must say what did NOT
	// happen, not only what did.
	for _, want := range []string{"expired", "visible and exportable", "nothing has been disabled or deleted"} {
		if !strings.Contains(st.Reason, want) {
			t.Fatalf("the reason must contain %q: %q", want, st.Reason)
		}
	}
}

// TestZeroGraceIsStillZero: the owner's 30-day policy is applied by the ISSUER.
// A licence already in a customer's hands that carries grace_days: 0 keeps
// meaning zero — a policy change must never silently re-term an issued file.
func TestZeroGraceIsStillZero(t *testing.T) {
	k := newExpKey(t)
	expires := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	raw := k.sign(t, expiryTeamDoc(expires, 0, false))

	st, err := k.v.Verify(raw, expires.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if st.Phase != entitlement.PhasePostGrace {
		t.Fatalf("phase = %q one second after a zero-grace expiry, want post_grace — the file's own terms decide, not the current policy", st.Phase)
	}
	if !strings.Contains(st.Reason, "no grace period") {
		t.Fatalf("the reason must say the licence carries no grace: %q", st.Reason)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Trials
// ─────────────────────────────────────────────────────────────────────────────

// TestTrialIsCarriedAndDisplayed: the flag survives signing, verification and
// evaluation, and changes the WORDS without changing the enforcement.
func TestTrialIsCarriedAndDisplayed(t *testing.T) {
	k := newExpKey(t)
	expires := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	raw := k.sign(t, expiryTeamDoc(expires, licence.TrialGraceDays, true))

	st, err := k.v.Verify(raw, expires.AddDate(0, 0, -1))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Trial {
		t.Fatal("the trial flag must survive to the evaluated state")
	}
	if st.Tier != entitlement.TierTeam || !st.Has(entitlement.FeatureSecurityFindings) {
		t.Fatal("a trial grants exactly what its tier and features say — the flag is display, not enforcement")
	}
	expired, err := k.v.Verify(raw, expires.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(expired.Reason, "evaluation licence") {
		t.Fatalf("an expired trial must say so in words: %q", expired.Reason)
	}
}

// TestTrialFlagIsSignatureCovered: the flag can be neither added to nor
// stripped from an issued file.
func TestTrialFlagIsSignatureCovered(t *testing.T) {
	k := newExpKey(t)
	expires := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	raw := k.sign(t, expiryTeamDoc(expires, licence.TrialGraceDays, true))

	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	obj["trial"] = false
	tampered, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.v.Verify(tampered, expires.AddDate(0, 0, -1)); err == nil {
		t.Fatal("turning a trial into a full licence must break the signature")
	}
}

// TestNonTrialCanonicalisesExactlyAsBefore is the BACKWARD-COMPATIBILITY proof.
//
// `trial` is `omitempty` in the canonical payload, so a document that is not a
// trial signs over byte-for-byte the same payload it did before the field
// existed. Without that, adding the field would have invalidated every licence
// ever issued — which is the kind of change that is obvious in hindsight and
// invisible in a diff.
func TestNonTrialCanonicalisesExactlyAsBefore(t *testing.T) {
	expires := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	doc := expiryTeamDoc(expires, licence.PaidGraceDays, false)

	payload, err := licence.CanonicalPayload(doc)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte("trial")) {
		t.Fatalf("a NON-trial document must canonicalise without the field, or every previously issued licence stops verifying: %s", payload)
	}
	doc.Trial = true
	trialPayload, err := licence.CanonicalPayload(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(trialPayload, []byte(`"trial":true`)) {
		t.Fatalf("a trial document must canonicalise WITH the field, or the flag would not be signed: %s", trialPayload)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Issuance policy
// ─────────────────────────────────────────────────────────────────────────────

// TestDefaultGraceDays pins the owner's issuance defaults, including the two
// cases that are easy to get wrong: an explicit zero must be honoured, and
// Community gets none.
func TestDefaultGraceDays(t *testing.T) {
	cases := []struct {
		tier     entitlement.Tier
		trial    bool
		explicit int
		want     int
	}{
		{entitlement.TierTeam, false, licence.GraceDaysUnset, 30},
		{entitlement.TierEnterprise, false, licence.GraceDaysUnset, 30},
		{entitlement.TierTeam, true, licence.GraceDaysUnset, 7},
		{entitlement.TierEnterprise, true, licence.GraceDaysUnset, 7},
		{entitlement.TierCommunity, false, licence.GraceDaysUnset, 0},
		// An explicit value always wins — including an explicit zero, which is
		// a legitimate choice and must not be read as "unset".
		{entitlement.TierTeam, false, 0, 0},
		{entitlement.TierTeam, true, 90, 90},
	}
	for _, c := range cases {
		if got := licence.DefaultGraceDays(c.tier, c.trial, c.explicit); got != c.want {
			t.Fatalf("DefaultGraceDays(%q, trial=%v, explicit=%d) = %d, want %d",
				c.tier, c.trial, c.explicit, got, c.want)
		}
	}
}
