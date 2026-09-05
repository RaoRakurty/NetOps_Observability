package backend

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/entitlement"
	"netops/backend/internal/licence"
	"netops/backend/internal/licence/signer"
	"netops/backend/internal/rbac"
)

// licence_expiry_routes_test.go — the post-expiry state machine and the
// soft-overage policy, AT THE CHOKEPOINTS (owner decision, 2026-09-05;
// docs/design/TIERING_PLAN_2026-09-03.md §9).
//
// internal/licence proves the state machine and internal/entitlement proves the
// gates. Neither can prove the two things that only exist in the wiring:
//
//  1. that a lapsed licence keeps every READ path open and closes every WRITE
//     path — route by route, driven through the real middleware;
//  2. that a lapsed licence changes NO authorization decision, which is the
//     safety invariant expressed behaviourally rather than structurally.

// licIssueExpired signs a licence at `tier` that expired `expiredDays` ago with
// `grace` days of grace, so the state machine lands wherever the caller wants.
func (k licTestKey) issueExpired(t *testing.T, tier entitlement.Tier, features []entitlement.Feature, expiredDays, grace int, trial bool) []byte {
	t.Helper()
	c, ok := entitlement.TierCeilings(tier)
	if !ok {
		t.Fatalf("no reference ceilings for tier %q", tier)
	}
	now := time.Now().UTC()
	doc := licence.Document{
		LicenceID: "expired-" + string(tier),
		Customer:  "Lapsed Customer",
		Tier:      tier,
		IssuedAt:  now.AddDate(-1, 0, 0),
		ExpiresAt: now.AddDate(0, 0, -expiredDays),
		Ceilings:  c,
		Features:  features,
		GraceDays: grace,
		Trial:     trial,
	}
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

// ─────────────────────────────────────────────────────────────────────────────
// Post-grace: reads stay open, writes refuse
// ─────────────────────────────────────────────────────────────────────────────

// TestLicencePostGraceReadsStayOpenWritesRefuse is the ENUMERATION the owner
// asked for: every route the feature middleware wraps, driven with a read verb
// and a write verb, under a licence that has lapsed past its grace period.
//
// The rule under test, verbatim from the decision: "existing data stays
// viewable and exportable (GET/list/export paths of licensed features keep
// working); enabling licensed features' write paths refuse with the existing
// 402 shape + a licence_state: post_grace field".
func TestLicencePostGraceReadsStayOpenWritesRefuse(t *testing.T) {
	k := newLicTestKey(t)
	reached := func(hit *bool) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) { *hit = true; w.WriteHeader(http.StatusOK) }
	}

	// The full inventory of feature-gated surfaces, with the verbs each one
	// actually serves. Adding a licenceFeature route without adding it here is
	// caught by TestLicenceGatedRoutesAreRegistered, which reads main.go.
	routes := []struct {
		path    string
		feature entitlement.Feature
		grant   entitlement.Tier
		reads   []string
		writes  []string
	}{
		{
			path: "/api/security/findings", feature: entitlement.FeatureSecurityFindings,
			grant: entitlement.TierTeam, reads: []string{http.MethodGet, http.MethodHead},
			writes: []string{http.MethodPost, http.MethodPut, http.MethodDelete},
		},
		{
			path: "/api/security/findings/facets", feature: entitlement.FeatureSecurityFindings,
			grant: entitlement.TierTeam, reads: []string{http.MethodGet}, writes: []string{http.MethodPost},
		},
		{
			path: "/api/security/findings/trend", feature: entitlement.FeatureSecurityFindings,
			grant: entitlement.TierTeam, reads: []string{http.MethodGet}, writes: []string{http.MethodPost},
		},
		{
			path: "/api/security/findings/{id}", feature: entitlement.FeatureSecurityFindings,
			grant: entitlement.TierTeam, reads: []string{http.MethodGet}, writes: []string{http.MethodPut, http.MethodDelete},
		},
		{
			path: "/api/auth/ldap/config", feature: entitlement.FeatureLDAP,
			grant: entitlement.TierEnterprise, reads: []string{http.MethodGet}, writes: []string{http.MethodPut, http.MethodPost},
		},
		{
			// The LDAP connectivity test EXERCISES the commercial capability, so
			// it is a configuration action and stops with the rest of them. It
			// reads nothing that already exists.
			path: "/api/auth/ldap/test", feature: entitlement.FeatureLDAP,
			grant: entitlement.TierEnterprise, reads: nil, writes: []string{http.MethodPost},
		},
	}

	for _, rt := range routes {
		// A licence that GRANTED the feature and lapsed 40 days ago with the
		// standard 30-day grace: 10 days past grace.
		raw := k.issueExpired(t, rt.grant, []entitlement.Feature{rt.feature}, 40, licence.PaidGraceDays, false)
		s := &server{entitlements: k.service(t, raw)}
		if got := s.entitlements.Phase(); got != entitlement.PhasePostGrace {
			t.Fatalf("%s: fixture phase = %q, want post_grace", rt.path, got)
		}

		for _, verb := range rt.reads {
			t.Run(rt.path+" "+verb+" keeps working after grace", func(t *testing.T) {
				hit := false
				w := httptest.NewRecorder()
				s.licenceFeature(rt.feature, reached(&hit))(w, httptest.NewRequest(verb, rt.path, nil))
				if !hit || w.Code != http.StatusOK {
					t.Fatalf("a lapsed licence must keep EXISTING data viewable and exportable — "+
						"a screen that goes empty is data loss from the operator's side: hit=%v code=%d body=%s",
						hit, w.Code, w.Body.String())
				}
			})
		}
		for _, verb := range rt.writes {
			t.Run(rt.path+" "+verb+" refuses after grace", func(t *testing.T) {
				hit := false
				w := httptest.NewRecorder()
				s.licenceFeature(rt.feature, reached(&hit))(w, httptest.NewRequest(verb, rt.path, strings.NewReader("{}")))
				if hit {
					t.Fatal("configuring paid capability past grace must not reach the handler")
				}
				assertPostGraceRefusal(t, w, entitlement.KindFeature, string(rt.feature))
			})
		}
	}
}

// TestLicenceInGraceChangesNothingAtTheChokepoints: during grace, every verb on
// every gated route behaves exactly as it did the day before expiry. A grace
// period that quietly tightened would be worthless.
func TestLicenceInGraceChangesNothingAtTheChokepoints(t *testing.T) {
	k := newLicTestKey(t)
	raw := k.issueExpired(t, entitlement.TierTeam, []entitlement.Feature{entitlement.FeatureSecurityFindings}, 5, licence.PaidGraceDays, false)
	s := &server{entitlements: k.service(t, raw)}
	if got := s.entitlements.Phase(); got != entitlement.PhaseInGrace {
		t.Fatalf("fixture phase = %q, want in_grace", got)
	}
	for _, verb := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete} {
		hit := false
		w := httptest.NewRecorder()
		s.licenceFeature(entitlement.FeatureSecurityFindings, func(w http.ResponseWriter, _ *http.Request) {
			hit = true
			w.WriteHeader(http.StatusOK)
		})(w, httptest.NewRequest(verb, "/api/security/findings", nil))
		if !hit || w.Code != http.StatusOK {
			t.Fatalf("%s must still be served in grace: code=%d body=%s", verb, w.Code, w.Body.String())
		}
	}
	// And the ceilings are still the LICENSED ones, not Community's.
	if err := entitlement.CheckCeiling(s.entitlements, entitlement.CeilingWatchedPrefixes, 40); err != nil {
		t.Fatalf("the Team prefix ceiling must still be in force in grace: %v", err)
	}
}

// TestLicencePostGraceTenantAndOrgCreateRefuse: the two MSP chokepoints are
// "creation" in the plainest sense, and both must refuse past grace while the
// tenants and orgs that already exist keep working (isolation between them is a
// safety property and is asserted separately).
func TestLicencePostGraceTenantAndOrgCreateRefuse(t *testing.T) {
	k := newLicTestKey(t)
	raw := k.issueExpired(t, entitlement.TierEnterprise, []entitlement.Feature{entitlement.FeatureMSPManagement}, 40, licence.PaidGraceDays, false)
	s := licIdentityServer(t, k.service(t, raw))

	t.Run("a second tenant is refused", func(t *testing.T) {
		// The FIRST tenant is core single-tenant operation and is never gated
		// (TestLicenceMSPManagement pins that). What a lapse stops is the
		// SECOND — the fleet — so the fixture has to get past the first.
		w := httptest.NewRecorder()
		s.handleTenants(w, licReq(http.MethodPost, "/api/tenants", `{"name":"First","slug":"first"}`, licClaims()))
		if w.Code >= 400 {
			t.Fatalf("the first tenant is core operation and must succeed in every licence state: %d %s", w.Code, w.Body.String())
		}
		w = httptest.NewRecorder()
		s.handleTenants(w, licReq(http.MethodPost, "/api/tenants", `{"name":"Acme","slug":"acme"}`, licClaims()))
		assertPostGraceRefusal(t, w, entitlement.KindFeature, string(entitlement.FeatureMSPManagement))
	})
	t.Run("a second org is refused", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleOrgs(w, licReq(http.MethodPost, "/api/orgs", `{"name":"Partner","slug":"partner"}`, licClaims()))
		assertPostGraceRefusal(t, w, entitlement.KindFeature, string(entitlement.FeatureMSPManagement))
	})
	t.Run("listing what already exists still works", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleTenants(w, licReq(http.MethodGet, "/api/tenants", "", licClaims()))
		if w.Code != http.StatusOK {
			t.Fatalf("existing tenants must stay listable past grace: %d %s", w.Code, w.Body.String())
		}
		w = httptest.NewRecorder()
		s.handleOrgs(w, licReq(http.MethodGet, "/api/orgs", "", licClaims()))
		if w.Code != http.StatusOK {
			t.Fatalf("existing orgs must stay listable past grace: %d %s", w.Code, w.Body.String())
		}
	})
}

// assertPostGraceRefusal asserts the EXISTING 402 shape plus the new
// licence_state field, and that the message tells a lapsed customer the two
// things they need: renew, and your data is still there.
func assertPostGraceRefusal(t *testing.T, w *httptest.ResponseRecorder, wantKind, wantName string) {
	t.Helper()
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402; body = %s", w.Code, w.Body.String())
	}
	var body struct {
		Error        string `json:"error"`
		Ceiling      string `json:"ceiling"`
		Feature      string `json:"feature"`
		LicenceState string `json:"licence_state"`
		LiftedBy     string `json:"lifted_by"`
		Message      string `json:"message"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("the 402 body must be the JSON the upgrade card renders: %v (%s)", err, w.Body.String())
	}
	if body.Error != wantKind {
		t.Fatalf("error = %q, want %q", body.Error, wantKind)
	}
	got := body.Ceiling
	if wantKind == entitlement.KindFeature {
		got = body.Feature
	}
	if got != wantName {
		t.Fatalf("refusal names %q, want %q", got, wantName)
	}
	if body.LicenceState != string(entitlement.PhasePostGrace) {
		t.Fatalf("licence_state = %q, want post_grace — without it a client cannot tell "+
			"\"you never bought this\" (upgrade) from \"your licence lapsed\" (renew)", body.LicenceState)
	}
	if body.LiftedBy != "" {
		t.Fatalf("lifted_by = %q: naming a tier to BUY sends a lapsed customer to the wrong purchase", body.LiftedBy)
	}
	if !strings.Contains(body.Message, "expired") {
		t.Fatalf("the message must say the licence expired: %q", body.Message)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// The safety invariant, behaviourally
// ─────────────────────────────────────────────────────────────────────────────

// TestLicencePostGraceChangesNoAuthorizationDecision is the owner's
// non-negotiable, asserted as behaviour rather than as an import graph.
//
// safety_invariant_test.go proves the STRUCTURE — the authorization paths
// cannot ask the entitlement service, so there is no answer that could weaken
// them. This proves the CONSEQUENCE, over the licence states the new state
// machine introduced: for every (principal, module, level) triple, the decision
// is identical with no licence, with a live licence, in grace, and past grace.
//
// If a licence state ever moved one of these answers, this test fails and the
// invariant is gone — no amount of correct commercial gating would restore it.
func TestLicencePostGraceChangesNoAuthorizationDecision(t *testing.T) {
	k := newLicTestKey(t)
	feats := []entitlement.Feature{entitlement.FeatureSecurityFindings}

	states := map[string]*licence.Service{
		"no licence (Community)": k.service(t, nil),
		"live licence":           k.service(t, k.issue(t, entitlement.TierTeam, feats, nil)),
		"in grace":               k.service(t, k.issueExpired(t, entitlement.TierTeam, feats, 5, licence.PaidGraceDays, false)),
		"past grace":             k.service(t, k.issueExpired(t, entitlement.TierTeam, feats, 40, licence.PaidGraceDays, false)),
		"expired trial":          k.service(t, k.issueExpired(t, entitlement.TierTeam, feats, 40, licence.TrialGraceDays, true)),
	}

	principals := map[string]jwtClaims{
		"platform owner": licClaims(),
		"tenant admin":   licTenantAdminClaims(),
		"operator":       {Sub: "op@acme.test", Role: rbac.RoleOperator, Tenant: "acme"},
		"viewer":         {Sub: "view@acme.test", Role: rbac.RoleReadOnly, Tenant: "acme"},
	}

	type decision struct {
		perm, admin, platform bool
		permCode              int
	}
	// The baseline is the no-licence deployment: whatever it decides is what
	// every other licence state must decide too.
	var baseline map[string]decision

	for _, name := range []string{"no licence (Community)", "live licence", "in grace", "past grace", "expired trial"} {
		ent := states[name]
		roles, err := newRoleStore(filepath.Join(t.TempDir(), "roles.json"))
		if err != nil {
			t.Fatal(err)
		}
		s := &server{roles: roles, entitlements: ent}
		got := map[string]decision{}
		for pname, claims := range principals {
			for _, module := range []string{"infrastructure", "administration", "security", "monitoring"} {
				for _, level := range []int{LevelRead, LevelWrite, LevelAdmin} {
					key := pname + "/" + module + "/" + rbac.LevelName(level)
					w := httptest.NewRecorder()
					_, okPerm := s.requirePerm(w, licReq(http.MethodGet, "/x", "", claims), module, level)
					d := decision{perm: okPerm, permCode: w.Code}

					w2 := httptest.NewRecorder()
					_, d.admin = s.requireAdmin(w2, licReq(http.MethodGet, "/x", "", claims))
					w3 := httptest.NewRecorder()
					_, d.platform = s.requirePlatformAdmin(w3, licReq(http.MethodGet, "/x", "", claims))
					got[key] = d
				}
			}
		}
		if baseline == nil {
			baseline = got
			continue
		}
		for key, want := range baseline {
			if got[key] != want {
				t.Fatalf("AUTHORIZATION MOVED with the licence state %q at %s: %+v, want %+v\n\n"+
					"A licence problem — expired, in grace, past grace, absent — must be TECHNICALLY INCAPABLE of\n"+
					"weakening isolation, RLS, authorization, integrity or core authentication (owner spec, 2026-09-04).\n"+
					"The commercial gate belongs at its own call site, never inside an authorization decision.",
					name, key, got[key], want)
			}
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Soft overage at the device chokepoint
// ─────────────────────────────────────────────────────────────────────────────

// TestLicenceSoftOverageOnPaidTiers is the "never a kill switch during an
// incident" decision at the real chokepoint: at 250 of 250 monitored devices,
// a Team deployment admits the 251st. The same request under Community at 25
// is refused, because 25 is a published free ceiling.
func TestLicenceSoftOverageOnPaidTiers(t *testing.T) {
	k := newLicTestKey(t)

	t.Run("Team admits the 251st monitored device", func(t *testing.T) {
		raw := k.issue(t, entitlement.TierTeam, nil, nil)
		s := licDeviceServer(t, k.service(t, raw), 250)
		w := httptest.NewRecorder()
		s.handleDevices(w, licReq(http.MethodPost, "/api/devices",
			`{"id":"over-1","name":"over-1","address":"10.99.0.1"}`, licClaims()))
		if w.Code == http.StatusPaymentRequired {
			t.Fatalf("a paid tier must NOT be blocked at its device allowance — the overage is recorded, not refused: %s", w.Body.String())
		}
		if s.discovery.MonitoredCount() != 251 {
			t.Fatalf("the device must actually be monitored: count = %d, want 251", s.discovery.MonitoredCount())
		}
		// And the overage is LISTED, with the soft wording.
		over := s.entitlements.Overages(licence.Usage{entitlement.CeilingDevices: s.discovery.MonitoredCount()})
		if len(over) != 1 || !over[0].Soft || over[0].Over != 1 {
			t.Fatalf("the overage must be listed as soft and sized: %+v", over)
		}
		if !strings.Contains(over[0].Message, "true-up") {
			t.Fatalf("a soft overage is a billing fact, not a fault: %q", over[0].Message)
		}
		// The over-ceiling device list names ONE device — the size of the
		// overage — and says it is still being collected from. WHICH device it
		// names is presentational (the API states that verbatim); what is
		// asserted here is that the list exists, is sized, and is honest.
		rows := s.licenceOverCeilingDevices(t.Context())
		if len(rows) != 1 {
			t.Fatalf("1 device over the allowance must produce a 1-row listing: %+v", rows)
		}
		if !strings.Contains(rows[0].Reason, "still being collected from") {
			t.Fatalf("the listing must say the device is NOT disabled: %q", rows[0].Reason)
		}
		if s.discovery.MonitoringWithheldCount() != 0 {
			t.Fatal("a soft overage withholds nothing")
		}
	})

	t.Run("Community still blocks the 26th", func(t *testing.T) {
		s := licDeviceServer(t, k.service(t, nil), 25)
		w := httptest.NewRecorder()
		s.handleDevices(w, licReq(http.MethodPost, "/api/devices",
			`{"id":"over-1","name":"over-1","address":"10.99.0.1"}`, licClaims()))
		licAssertRefusal(t, w, entitlement.KindCeiling, entitlement.CeilingDevices, entitlement.TierTeam)
		if s.discovery.MonitoredCount() != 25 {
			t.Fatalf("the refused device must not be monitored: count = %d", s.discovery.MonitoredCount())
		}
	})

	t.Run("past grace the hard Community ceiling is back for NEW activations", func(t *testing.T) {
		raw := k.issueExpired(t, entitlement.TierTeam, nil, 40, licence.PaidGraceDays, false)
		s := licDeviceServer(t, k.service(t, raw), 30)
		// Nothing was disabled: the 30 devices admitted under the live licence
		// are all still monitored.
		if s.discovery.MonitoredCount() != 30 {
			t.Fatalf("a lapse must not disable anything: count = %d, want 30", s.discovery.MonitoredCount())
		}
		w := httptest.NewRecorder()
		s.handleDevices(w, licReq(http.MethodPost, "/api/devices",
			`{"id":"over-2","name":"over-2","address":"10.99.0.2"}`, licClaims()))
		assertPostGraceRefusal(t, w, entitlement.KindCeiling, entitlement.CeilingDevices)
		if s.discovery.MonitoredCount() != 30 {
			t.Fatalf("and the refusal must not have changed the existing fleet: count = %d", s.discovery.MonitoredCount())
		}
	})
}
