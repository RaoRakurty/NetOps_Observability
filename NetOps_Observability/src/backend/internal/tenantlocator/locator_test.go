// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tenantlocator

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// dir is a counting Directory: it records how many times each list was asked
// for, which is how TestResolveCostIsFlat proves an unknown ref and a
// known-but-hidden ref cost the same.
type dir struct {
	tenants  []TenantRef
	orgs     []OrgRef
	tCalls   int
	oCalls   int
	tScanned int
	oScanned int
}

func (d *dir) Tenants() []TenantRef {
	d.tCalls++
	d.tScanned += len(d.tenants)
	return d.tenants
}

func (d *dir) Orgs() []OrgRef {
	d.oCalls++
	d.oScanned += len(d.orgs)
	return d.orgs
}

func fixture() *dir {
	return &dir{
		tenants: []TenantRef{
			{ID: "t_aaa", Slug: "acme", Name: "Acme Corporation", OrgID: "org_1", Status: "active"},
			{ID: "t_bbb", Slug: "globex", Name: "Globex", OrgID: "org_2"}, // blank status = active
			{ID: "t_ccc", Slug: "initech", Name: "Initech", OrgID: "org_1", Status: "suspended"},
			{ID: "t_ddd", Slug: "legacy", Name: "Legacy Co"}, // no org = root org
		},
		orgs: []OrgRef{
			{ID: "org_1", Slug: "acme-group", Name: "Acme Group"},
			{ID: "org_2", Slug: "globex-inc", Name: "Globex Inc"},
			{ID: "org_3", Slug: "empty", Name: "Empty Holdings"}, // owns no tenant
			{ID: "global", Slug: "global", Name: "Provider"},
		},
	}
}

// ---- parsing ---------------------------------------------------------------

func TestParsePath(t *testing.T) {
	cases := []struct {
		in        string
		kind, ref string
		ok        bool
	}{
		{"/t/acme", KindTenant, "acme", true},
		{"/t/acme/", KindTenant, "acme", true},
		{"/t/ACME", KindTenant, "acme", true},
		{"/t/acme/sso/okta/callback", KindTenant, "acme", true},
		{"/org/org_1", KindOrg, "org_1", true},
		{"/org/org_1/sso/okta/callback", KindOrg, "org_1", true},
		{"/t/", "", "", false},
		{"/t", "", "", false},
		{"/org/", "", "", false},
		{"/", "", "", false},
		{"/api/auth/sso/callback", "", "", false},
		{"/t/..", "", "", false},
		{"/t/a%2fb", "", "", false}, // encoded separator: not a plain identifier
		{"/t/a b", "", "", false},   // whitespace inside
		{"/t/a.b", "", "", false},   // dot: not a slug character
		{"/t/" + strings.Repeat("a", refMax+1), "", "", false},
	}
	for _, c := range cases {
		kind, ref, ok := ParsePath(c.in)
		if ok != c.ok || kind != c.kind || ref != c.ref {
			t.Errorf("ParsePath(%q) = (%q,%q,%v), want (%q,%q,%v)", c.in, kind, ref, ok, c.kind, c.ref, c.ok)
		}
	}
}

func TestParseCallbackPath(t *testing.T) {
	cases := []struct {
		in                     string
		kind, ref, alias, leaf string
		ok                     bool
	}{
		{"/t/acme/sso/okta/callback", KindTenant, "acme", "okta", "callback", true},
		{"/t/acme/sso/okta/login", KindTenant, "acme", "okta", "login", true},
		{"/org/org_1/sso/entra/callback", KindOrg, "org_1", "entra", "callback", true},
		{"/t/acme/sso/okta/callback/extra", "", "", "", "", false},
		{"/t/acme/sso/okta", "", "", "", "", false},
		{"/t/acme/sso//callback", "", "", "", "", false},
		{"/t/acme/oidc/okta/callback", "", "", "", "", false},
		{"/t/acme", "", "", "", "", false},
		{"/api/auth/sso/callback", "", "", "", "", false},
	}
	for _, c := range cases {
		kind, ref, alias, leaf, ok := ParseCallbackPath(c.in)
		if ok != c.ok || kind != c.kind || ref != c.ref || alias != c.alias || leaf != c.leaf {
			t.Errorf("ParseCallbackPath(%q) = (%q,%q,%q,%q,%v), want (%q,%q,%q,%q,%v)",
				c.in, kind, ref, alias, leaf, ok, c.kind, c.ref, c.alias, c.leaf, c.ok)
		}
	}
}

// ---- resolution ------------------------------------------------------------

func TestResolveTenantSlug(t *testing.T) {
	c, ok := Resolve(fixture(), KindTenant, "acme")
	if !ok {
		t.Fatal("acme must resolve")
	}
	if c.Kind != KindTenant || c.TenantID != "t_aaa" || c.OrgID != "org_1" || c.DisplayName != "Acme Corporation" {
		t.Fatalf("wrong candidate: %+v", c)
	}
	if c.Path() != "/t/acme" {
		t.Fatalf("path = %q", c.Path())
	}
	if c.CallbackPath("okta") != "/t/acme/sso/okta/callback" {
		t.Fatalf("callback = %q", c.CallbackPath("okta"))
	}
	if c.LoginPath("okta") != "/t/acme/sso/okta/login" {
		t.Fatalf("login = %q", c.LoginPath("okta"))
	}
}

// The slug is an ALIAS: it resolves to the immutable id and the id is what the
// candidate carries. Resolving by id through /t/ must NOT work — that path
// takes slugs, and accepting an id there would create a second, undocumented
// name for the same realm.
func TestResolveTenantByIDIsNotASlug(t *testing.T) {
	if _, ok := Resolve(fixture(), KindTenant, "t_aaa"); ok {
		t.Fatal("/t/{tenant-id} must not resolve — the shared path takes a slug")
	}
}

func TestResolveTenantWithoutOrgFallsToRootOrg(t *testing.T) {
	c, ok := Resolve(fixture(), KindTenant, "legacy")
	if !ok {
		t.Fatal("legacy must resolve")
	}
	if c.OrgID != DefaultOrgID {
		t.Fatalf("pre-org tenant org = %q, want %q", c.OrgID, DefaultOrgID)
	}
}

func TestResolveFailsClosed(t *testing.T) {
	cases := []struct{ kind, ref, why string }{
		{KindTenant, "nope", "unknown slug"},
		{KindTenant, "initech", "suspended tenant"},
		{KindTenant, "", "empty ref"},
		{KindOrg, "org_9", "unknown org"},
		{KindOrg, "org_3", "org owning no live tenant"},
		{"managed_subdomain", "acme", "deferred locator kind"},
		{"", "acme", "no kind"},
	}
	for _, c := range cases {
		if got, ok := Resolve(fixture(), c.kind, c.ref); ok {
			t.Errorf("%s must not resolve (%s), got %+v", c.ref, c.why, got)
		}
	}
	if _, ok := Resolve(nil, KindTenant, "acme"); ok {
		t.Error("nil directory must not resolve")
	}
}

func TestResolveOrg(t *testing.T) {
	c, ok := Resolve(fixture(), KindOrg, "ORG_1")
	if !ok {
		t.Fatal("org_1 must resolve")
	}
	if c.Kind != KindOrg || c.OrgID != "org_1" || c.TenantID != "" || c.DisplayName != "Acme Group" {
		t.Fatalf("wrong candidate: %+v", c)
	}
	if c.Path() != "/org/org_1" {
		t.Fatalf("path = %q", c.Path())
	}
}

// The invariant behind "no information leak": an unknown ref and a
// known-but-hidden ref must be indistinguishable in ANSWER and in COST. The
// answer is checked above; this checks the cost, deterministically (a wall-clock
// assertion would be flaky) by counting the directory work each takes.
func TestResolveCostIsFlat(t *testing.T) {
	probe := func(kind, ref string) (int, int, int, int) {
		d := fixture()
		Resolve(d, kind, ref)
		return d.tCalls, d.oCalls, d.tScanned, d.oScanned
	}
	unknownT := [4]int{}
	hiddenT := [4]int{}
	knownT := [4]int{}
	unknownT[0], unknownT[1], unknownT[2], unknownT[3] = probe(KindTenant, "nosuchtenant")
	hiddenT[0], hiddenT[1], hiddenT[2], hiddenT[3] = probe(KindTenant, "initech")
	knownT[0], knownT[1], knownT[2], knownT[3] = probe(KindTenant, "acme")
	if unknownT != hiddenT {
		t.Errorf("tenant: unknown %v vs suspended %v — an enumeration probe can time the difference", unknownT, hiddenT)
	}
	if unknownT != knownT {
		t.Errorf("tenant: unknown %v vs known %v — same scan expected", unknownT, knownT)
	}

	unknownO := [4]int{}
	hiddenO := [4]int{}
	unknownO[0], unknownO[1], unknownO[2], unknownO[3] = probe(KindOrg, "org_nope")
	hiddenO[0], hiddenO[1], hiddenO[2], hiddenO[3] = probe(KindOrg, "org_3")
	if unknownO != hiddenO {
		t.Errorf("org: unknown %v vs empty %v", unknownO, hiddenO)
	}
}

func TestResolveID(t *testing.T) {
	c, ok := ResolveID(fixture(), KindTenant, "T_AAA")
	if !ok || c.TenantSlug != "acme" || c.TenantID != "t_aaa" {
		t.Fatalf("ResolveID tenant = %+v ok=%v", c, ok)
	}
	if _, ok := ResolveID(fixture(), KindTenant, "t_ccc"); ok {
		t.Error("a suspended tenant's id must stop resolving — a live cookie must not outlive the suspension")
	}
	if _, ok := ResolveID(fixture(), KindTenant, "t_zzz"); ok {
		t.Error("unknown id must not resolve")
	}
	if c, ok := ResolveID(fixture(), KindOrg, "org_2"); !ok || c.OrgID != "org_2" {
		t.Errorf("ResolveID org = %+v ok=%v", c, ok)
	}
	if _, ok := ResolveID(fixture(), "custom_domain", "acme"); ok {
		t.Error("a deferred locator kind must not resolve")
	}
}

// ---- provider reach --------------------------------------------------------

func TestReaches(t *testing.T) {
	acme, _ := Resolve(fixture(), KindTenant, "acme")
	globex, _ := Resolve(fixture(), KindTenant, "globex")
	org1, _ := Resolve(fixture(), KindOrg, "org_1")

	// Unbound (platform-realm) registrations stay visible everywhere.
	for _, c := range []Candidate{acme, globex, org1} {
		if !c.Reaches("", "") {
			t.Errorf("%s: an unbound registration must stay visible", c.DisplayName)
		}
	}
	if !acme.Reaches("t_aaa", "org_1") {
		t.Error("acme must see its own registration")
	}
	if acme.Reaches("t_bbb", "org_2") {
		t.Error("CROSS-TENANT LEAK: acme must not see globex's registration")
	}
	if globex.Reaches("t_aaa", "org_1") {
		t.Error("CROSS-TENANT LEAK: globex must not see acme's registration")
	}
	if !org1.Reaches("t_aaa", "org_1") {
		t.Error("an org locator must see its own tenants' registrations")
	}
	if org1.Reaches("t_bbb", "org_2") {
		t.Error("CROSS-ORG LEAK: org_1 must not see org_2's registration")
	}
	// A registration bound to a tenant with no org of its own belongs to the
	// root org, and only the root org's locator reaches it.
	if org1.Reaches("t_ddd", "") {
		t.Error("CROSS-ORG LEAK: org_1 must not reach a root-org registration")
	}
	if (Candidate{}).Reaches("t_aaa", "org_1") {
		t.Error("a zero candidate must reach nothing bound")
	}
}

// ---- signed candidate token ------------------------------------------------

func TestTokenRoundTrip(t *testing.T) {
	s := NewSigner("platform-secret")
	now := time.Now()
	c, _ := Resolve(fixture(), KindTenant, "acme")
	tok, err := s.Mint(c, now)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	got, err := s.Verify(tok, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Kind != KindTenant || got.ID != "t_aaa" {
		t.Fatalf("claim = %+v", got)
	}
	// The token carries the immutable id and NOTHING else that could contradict
	// the directory — no slug, no display name, no role, no tenant assertion.
	if strings.Contains(tok, "acme") || strings.Contains(tok, "Acme") {
		t.Error("the candidate token must not carry the mutable slug or display name")
	}
}

func TestTokenRejections(t *testing.T) {
	s := NewSigner("platform-secret")
	other := NewSigner("a-different-secret")
	now := time.Now()
	c, _ := Resolve(fixture(), KindOrg, "org_1")
	tok, err := s.Mint(c, now)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := other.Verify(tok, now); err == nil {
		t.Error("a token signed with another key must be refused")
	}
	if _, err := s.Verify(tok, now.Add(TTL+time.Second)); err == nil {
		t.Error("an expired token must be refused")
	}
	payload, sig, _ := strings.Cut(tok, ".")
	for _, bad := range []string{
		"", ".", payload, payload + ".", "." + sig, payload + "." + sig + "x",
		payload + "x." + sig, "not-base64!." + sig, strings.Repeat("a", 600),
	} {
		if _, err := s.Verify(bad, now); err == nil {
			t.Errorf("malformed token %q must be refused", bad)
		}
	}
	// Every rejection is the SAME error: the caller must not be able to tell an
	// attacker whether the signature, the shape or the clock said no.
	_, e1 := other.Verify(tok, now)
	_, e2 := s.Verify("garbage", now)
	_, e3 := s.Verify(tok, now.Add(2*TTL))
	if !errors.Is(e1, ErrBadToken) || !errors.Is(e2, ErrBadToken) || !errors.Is(e3, ErrBadToken) {
		t.Errorf("rejections must be indistinguishable: %v / %v / %v", e1, e2, e3)
	}
}

func TestMintRefusesIncompleteCandidate(t *testing.T) {
	s := NewSigner("platform-secret")
	now := time.Now()
	for _, c := range []Candidate{
		{},
		{Kind: KindTenant},                  // no id
		{Kind: KindOrg, TenantID: "t_aaa"},  // org kind with no org id
		{Kind: "custom_domain", OrgID: "x"}, // deferred kind
	} {
		if tok, err := s.Mint(c, now); err == nil {
			// A deferred kind may mint, but must never verify back into a live
			// locator; assert the round trip fails somewhere.
			if _, verr := s.Verify(tok, now); verr == nil {
				t.Errorf("candidate %+v must not produce a usable token", c)
			}
		}
	}
	var nilSigner *Signer
	if _, err := nilSigner.Mint(Candidate{Kind: KindTenant, TenantID: "t_aaa"}, now); err == nil {
		t.Error("a nil signer must refuse to mint")
	}
	if _, err := nilSigner.Verify("x.y", now); err == nil {
		t.Error("a nil signer must refuse to verify")
	}
}
