// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Route templates covered (the coverage guard matches this literal text):
//   "/api/auth/sso/tenant-idp"  "/api/auth/sso/tenant-idp/"
//
// tenant_idp_elevation_test.go — the ACCESS MODEL of a connection is
// platform-governed, and a tenant-admin save must never move it.
//
// THE DEFECT. tenantIdPBody carried no `kind` and no `elevation`, the record
// built from it copied an explicit field list that omitted both, and
// ssoidp.Store.Set is a FULL REPLACE that carries forward only the client
// secret. Normalize then reads a blank kind as "standing". A platform admin can
// legitimately create a connection that is BOTH tenant-bound AND
// kind: elevation (the platform PUT decodes the whole record), and
// tenantOwnsIdP makes exactly that connection editable by the tenant admin. So
// ONE ordinary tenant-admin save — a display-name edit — turned a just-in-time
// elevation door into a standing one: the stored kind went to "standing", the
// login-page provider string lost its ":elevation" segment on the way through
// applySSOIdP, and every later sign-in through it handed out a PERMANENT role
// and rewrote the account, instead of minting one expiring binding. That breaks
// the owner's 2026-09-07 rule that elevation never changes a standing role.
//
// What is proved here:
//   - an ordinary tenant-admin save keeps kind AND the elevation block;
//   - a save that ASKS to change either is refused by name, not ignored;
//   - a tenant admin cannot create an elevation connection, and the refusal is
//     word-for-word the "you cannot convert one" refusal, so it is no oracle;
//   - a tenant admin cannot delete one either (delete + re-create is the same
//     conversion in two calls) but can still switch it off;
//   - a real sign-in after the save still produces a TIME-BOUND binding and
//     leaves the account untouched;
//   - every field a tenant admin DOES own still round-trips;
//   - none of the new refusals leaks across an org boundary (§3a rule 5).

package backend

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/ssoidp"
)

// elevationIdPBody is what a platform administrator sends to create a
// TENANT-BOUND elevation door: the platform surface is the only one that can
// express `kind`, and it takes the owning tenant from the body because a
// platform admin may write into any realm.
func elevationIdPBody(name, tenantID string) map[string]any {
	body := oidcIdPBody(name)
	body["kind"] = ssoidp.KindElevation
	body["tenant_id"] = tenantID
	body["elevation"] = map[string]any{
		"ttl_claim":    "access_expires_at",
		"max_minutes":  30,
		"reason_claim": "change_ticket",
	}
	return body
}

// seedTenantElevationIdP creates one through the REAL platform route, which is
// what makes the defect reachable in the first place.
func seedTenantElevationIdP(t *testing.T, f *tenantIdPFixture, alias, name, tenantID string) {
	t.Helper()
	if st, b := do(t, f.srv, "PUT", "/api/auth/sso/idp/"+alias, f.admin, elevationIdPBody(name, tenantID)); st != 200 {
		t.Fatalf("platform admin could not create a tenant-bound elevation connection: %d %s", st, b)
	}
	reg, ok := f.s.ssoIdPCfg.Get(alias)
	if !ok || !reg.IsElevation() || reg.Realm() != strings.ToLower(tenantID) {
		t.Fatalf("seed is not a tenant-bound elevation connection: %+v ok=%v", reg, ok)
	}
}

// storedIdP reads one record straight out of the store — the effective state,
// not the view.
func storedIdP(t *testing.T, f *tenantIdPFixture, alias string) ssoidp.Config {
	t.Helper()
	reg, ok := f.s.ssoIdPCfg.Get(alias)
	if !ok {
		t.Fatalf("connection %q is not stored", alias)
	}
	return reg
}

// ---- 1. the defect ---------------------------------------------------------

// One ordinary tenant-admin save — the display name — must leave the access
// model exactly as the platform administrator set it.
func TestTenantIdPSaveKeepsTheElevationAccessModel(t *testing.T) {
	f := newTenantIdPFixture(t)
	seedTenantElevationIdP(t, f, "acme-breakglass", "Acme Break Glass", f.tenantA)
	before := storedIdP(t, f, "acme-breakglass")

	st, b := do(t, f.srv, "PUT", "/api/auth/sso/tenant-idp/acme-breakglass", f.tokenA, oidcIdPBody("Acme Break Glass (renamed)"))
	if st != 200 {
		t.Fatalf("a legitimate tenant-admin edit was refused: %d %s", st, b)
	}
	after := storedIdP(t, f, "acme-breakglass")
	if !after.IsElevation() {
		t.Fatalf("ELEVATION DOWNGRADED TO STANDING by a tenant-admin save: kind = %q", after.KindOrStanding())
	}
	if after.Elevation != before.Elevation {
		t.Fatalf("the elevation block was dropped: %+v, want %+v", after.Elevation, before.Elevation)
	}
	if after.DisplayName != "Acme Break Glass (renamed)" {
		t.Errorf("the edit the tenant admin DOES own did not land: %q", after.DisplayName)
	}
	// The login-page button list is the other half of the damage: losing the
	// ":elevation" segment makes the door a standing one even if the record is
	// right.
	if got := f.s.oidcCfg.effective().Providers; !strings.Contains(got, "acme-breakglass:Acme Break Glass (renamed):oidc:elevation") {
		t.Errorf("the provider button lost its elevation segment: %q", got)
	}
	// And the answer SAYS so, rather than letting the operator believe the body
	// they sent is the record they now have.
	body := string(b)
	if !strings.Contains(body, `"kind":"elevation"`) {
		t.Errorf("the response does not carry the access model: %s", body)
	}
	if !strings.Contains(body, "just-in-time elevation connection") {
		t.Errorf("the response does not tell the operator the access model is not theirs: %s", body)
	}
}

// Asking for the change is refused BY NAME. Ignoring a submitted field silently
// is how the record and the operator end up disagreeing.
func TestTenantIdPSaveRefusesAnAccessModelChange(t *testing.T) {
	f := newTenantIdPFixture(t)
	seedTenantElevationIdP(t, f, "acme-breakglass", "Acme Break Glass", f.tenantA)
	before := storedIdP(t, f, "acme-breakglass")

	cases := []struct {
		name string
		body map[string]any
	}{
		{"kind to standing", func() map[string]any {
			b := oidcIdPBody("Acme Break Glass")
			b["kind"] = ssoidp.KindStanding
			return b
		}()},
		{"kind blanked", func() map[string]any {
			b := oidcIdPBody("Acme Break Glass")
			b["kind"] = ""
			return b
		}()},
		{"ceiling widened", func() map[string]any {
			b := oidcIdPBody("Acme Break Glass")
			b["elevation"] = map[string]any{"ttl_claim": "access_expires_at", "max_minutes": 480, "reason_claim": "change_ticket"}
			return b
		}()},
		{"ttl claim repointed", func() map[string]any {
			b := oidcIdPBody("Acme Break Glass")
			b["elevation"] = map[string]any{"ttl_claim": "never_expires", "max_minutes": 30, "reason_claim": "change_ticket"}
			return b
		}()},
	}
	for _, c := range cases {
		st, b := do(t, f.srv, "PUT", "/api/auth/sso/tenant-idp/acme-breakglass", f.tokenA, c.body)
		if st != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403 (%s)", c.name, st, b)
		}
		if !strings.Contains(string(b), "platform administrator") {
			t.Errorf("%s: the refusal does not name who owns the field: %s", c.name, b)
		}
		if after := storedIdP(t, f, "acme-breakglass"); after.KindOrStanding() != before.KindOrStanding() || after.Elevation != before.Elevation {
			t.Fatalf("%s: A REFUSED SAVE STILL CHANGED THE RECORD: %+v, want %+v", c.name, after, before)
		}
	}
	// The refusal is evidence (§10): it is audited as a denial, with the reason.
	events, err := f.s.audit.List("", true, auditQuery{Limit: 200})
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	found := false
	for _, e := range events {
		if e.Decision == "deny" && e.Detail["action"] == "sso.tenant_idp.access_model_refused" {
			found = true
			if got, _ := e.Detail["idp"].(string); got != "acme-breakglass" {
				t.Errorf("the audited refusal names idp %q", got)
			}
		}
	}
	if !found {
		t.Errorf("no refusal was audited across %d entries", len(events))
	}

	// Submitting the values it ALREADY has is not a change, so a client that
	// round-trips the whole record still saves.
	echo := oidcIdPBody("Acme Break Glass")
	echo["kind"] = ssoidp.KindElevation
	echo["elevation"] = map[string]any{"ttl_claim": "access_expires_at", "max_minutes": 30, "reason_claim": "change_ticket"}
	if st, b := do(t, f.srv, "PUT", "/api/auth/sso/tenant-idp/acme-breakglass", f.tokenA, echo); st != 200 {
		t.Fatalf("a round-tripped record was refused: %d %s", st, b)
	}
}

// Creating an elevation door is a platform administrator's privilege. The
// refusal must be word-for-word the one a conversion attempt gets, or the pair
// tells the caller whether the alias already exists.
func TestTenantIdPCannotCreateAnElevationConnection(t *testing.T) {
	f := newTenantIdPFixture(t)

	body := oidcIdPBody("Acme Break Glass")
	body["kind"] = ssoidp.KindElevation
	body["elevation"] = map[string]any{"max_minutes": 480}
	st, newAlias := do(t, f.srv, "PUT", "/api/auth/sso/tenant-idp/acme-breakglass", f.tokenA, body)
	if st != http.StatusForbidden {
		t.Fatalf("a tenant admin created an elevation connection: %d %s", st, newAlias)
	}
	if _, ok := f.s.ssoIdPCfg.Get("acme-breakglass"); ok {
		t.Fatal("the refused connection was stored anyway")
	}

	// The same request against an alias that EXISTS as a standing connection of
	// the caller's own.
	if st, b := do(t, f.srv, "PUT", "/api/auth/sso/tenant-idp/acme-okta", f.tokenA, oidcIdPBody("Acme Okta")); st != 200 {
		t.Fatalf("create standing: %d %s", st, b)
	}
	st, existing := do(t, f.srv, "PUT", "/api/auth/sso/tenant-idp/acme-okta", f.tokenA, body)
	if st != http.StatusForbidden {
		t.Fatalf("a standing connection was converted to elevation: %d %s", st, existing)
	}
	if string(newAlias) != string(existing) {
		t.Fatalf("EXISTENCE ORACLE: a new alias answers\n  %s\nan existing one answers\n  %s", newAlias, existing)
	}
	if reg := storedIdP(t, f, "acme-okta"); reg.IsElevation() {
		t.Fatal("the standing connection became an elevation door")
	}
}

// Delete + re-create is the same conversion in two calls. It is refused, and
// the tenant admin keeps the fail-closed off-switch instead.
func TestTenantIdPCannotDeleteAnElevationConnectionButCanDisableIt(t *testing.T) {
	f := newTenantIdPFixture(t)
	seedTenantElevationIdP(t, f, "acme-breakglass", "Acme Break Glass", f.tenantA)

	st, b := do(t, f.srv, "DELETE", "/api/auth/sso/tenant-idp/acme-breakglass", f.tokenA, nil)
	if st != http.StatusForbidden {
		t.Fatalf("a tenant admin deleted an elevation connection: %d %s", st, b)
	}
	if !strings.Contains(string(b), "platform administrator") {
		t.Errorf("the refusal does not name who owns the connection: %s", b)
	}
	if reg := storedIdP(t, f, "acme-breakglass"); !reg.IsElevation() {
		t.Fatal("the connection was altered by a refused delete")
	}

	// The off-switch still works, and switching it off does not smuggle the
	// access model away with it.
	off := oidcIdPBody("Acme Break Glass")
	off["enabled"] = false
	if st, b := do(t, f.srv, "PUT", "/api/auth/sso/tenant-idp/acme-breakglass", f.tokenA, off); st != 200 {
		t.Fatalf("a tenant admin could not switch its elevation door off: %d %s", st, b)
	}
	reg := storedIdP(t, f, "acme-breakglass")
	if reg.Enabled {
		t.Error("the connection is still enabled")
	}
	if !reg.IsElevation() {
		t.Fatal("switching the door off downgraded it to standing")
	}
	// A platform administrator still removes it.
	if st, b := do(t, f.srv, "DELETE", "/api/auth/sso/idp/acme-breakglass", f.admin, nil); st != 200 {
		t.Fatalf("platform delete: %d %s", st, b)
	}
	if _, ok := f.s.ssoIdPCfg.Get("acme-breakglass"); ok {
		t.Error("the platform delete did not remove the connection")
	}
}

// ---- 2. everything a tenant admin DOES own ---------------------------------

// The field-by-field walk: every field of ssoidp.Config a tenant admin owns
// must survive its own save. Alias comes from the URL and TenantID from the
// token; Kind and Elevation are the platform's. The rest is theirs, and the
// client secret is preserved when the redacted round-trip omits it.
func TestTenantIdPSaveKeepsEveryFieldATenantAdminOwns(t *testing.T) {
	f := newTenantIdPFixture(t)

	oidcBody := map[string]any{
		"display_name":     "Acme Okta",
		"protocol":         "oidc",
		"enabled":          true,
		"discovery_url":    "https://idp.example.com/.well-known/openid-configuration",
		"client_id":        "cid",
		"client_secret":    "shh",
		"groups_attr":      "correlix_groups",
		"signing_cert_pem": "-----BEGIN CERTIFICATE-----\nnot-a-real-cert\n-----END CERTIFICATE-----",
		"attr_mappings":    []map[string]string{{"idp_attr": "dept", "user_attr": "department"}},
		"role_mappings":    []map[string]string{{"value": "correlix-ops", "role": RoleOperator}},
	}
	if st, b := do(t, f.srv, "PUT", "/api/auth/sso/tenant-idp/acme-okta", f.tokenA, oidcBody); st != 200 {
		t.Fatalf("create: %d %s", st, b)
	}
	reg := storedIdP(t, f, "acme-okta")
	for _, c := range []struct {
		field string
		ok    bool
	}{
		{"display_name", reg.DisplayName == "Acme Okta"},
		{"protocol", reg.Protocol == "oidc"},
		{"enabled", reg.Enabled},
		{"discovery_url", reg.DiscoveryURL == "https://idp.example.com/.well-known/openid-configuration"},
		{"client_id", reg.ClientID == "cid"},
		{"client_secret", reg.ClientSecret == "shh"},
		{"groups_attr", reg.GroupsAttr == "correlix_groups"},
		{"signing_cert_pem", strings.Contains(reg.SigningCertPEM, "not-a-real-cert")},
		{"attr_mappings", len(reg.AttrMappings) == 1 && reg.AttrMappings[0].UserAttr == "department"},
		{"role_mappings", len(reg.RoleMappings) == 1 && reg.RoleMappings[0].Role == RoleOperator},
		{"alias (from the URL)", reg.Alias == "acme-okta"},
		{"tenant_id (from the token)", reg.Realm() == f.tenantA},
		{"kind (standing, since a tenant admin cannot make an elevation door)", reg.KindOrStanding() == ssoidp.KindStanding},
	} {
		if !c.ok {
			t.Errorf("%s did not survive the save: %+v", c.field, reg)
		}
	}

	// An edit that omits the secret keeps the stored one (the redacted
	// round-trip), and changes everything else.
	edit := map[string]any{
		"display_name":  "Acme Okta (prod)",
		"protocol":      "oidc",
		"enabled":       false,
		"discovery_url": "https://idp2.example.com/.well-known/openid-configuration",
		"client_id":     "cid2",
		"groups_attr":   "teams",
		"attr_mappings": []map[string]string{{"idp_attr": "org", "user_attr": "organisation"}},
		"role_mappings": []map[string]string{},
	}
	if st, b := do(t, f.srv, "PUT", "/api/auth/sso/tenant-idp/acme-okta", f.tokenA, edit); st != 200 {
		t.Fatalf("edit: %d %s", st, b)
	}
	reg = storedIdP(t, f, "acme-okta")
	if reg.ClientSecret != "shh" {
		t.Error("the stored client secret was wiped by a save that omitted it")
	}
	if reg.DisplayName != "Acme Okta (prod)" || reg.Enabled || reg.ClientID != "cid2" || reg.GroupsAttr != "teams" {
		t.Errorf("the edit did not land: %+v", reg)
	}
	if len(reg.AttrMappings) != 1 || reg.AttrMappings[0].UserAttr != "organisation" || len(reg.RoleMappings) != 0 {
		t.Errorf("mappings did not land: %+v %+v", reg.AttrMappings, reg.RoleMappings)
	}

	// SAML's own fields, on a connection of the same tenant.
	samlBody := map[string]any{
		"display_name": "Acme SAML",
		"protocol":     "saml",
		"enabled":      true,
		"metadata_xml": `<EntityDescriptor entityID="https://okta.example.com/exk1"><IDPSSODescriptor/></EntityDescriptor>`,
	}
	if st, b := do(t, f.srv, "PUT", "/api/auth/sso/tenant-idp/acme-saml", f.tokenA, samlBody); st != 200 {
		t.Fatalf("create saml: %d %s", st, b)
	}
	if reg := storedIdP(t, f, "acme-saml"); !strings.Contains(reg.MetadataXML, "IDPSSODescriptor") {
		t.Errorf("metadata_xml = %q", reg.MetadataXML)
	}
	delete(samlBody, "metadata_xml")
	samlBody["metadata_url"] = "https://okta.example.com/app/exk1/sso/saml/metadata"
	if st, b := do(t, f.srv, "PUT", "/api/auth/sso/tenant-idp/acme-saml", f.tokenA, samlBody); st != 200 {
		t.Fatalf("edit saml: %d %s", st, b)
	}
	if reg := storedIdP(t, f, "acme-saml"); reg.MetadataURL != "https://okta.example.com/app/exk1/sso/saml/metadata" || reg.MetadataXML != "" {
		t.Errorf("metadata source did not switch: url=%q xml=%q", reg.MetadataURL, reg.MetadataXML)
	}
}

// ---- 3. §3a rule 5: the new refusals stop at the org boundary --------------

// The ownership check runs FIRST, so another org's elevation connection answers
// 404 on every verb — never the 403 that would confirm it exists, and never a
// mutation.
func TestTenantIdPElevationRefusalsKeepCrossOrgIsolation(t *testing.T) {
	f := newTenantIdPFixture(t)
	seedTenantElevationIdP(t, f, "globex-breakglass", "Globex Break Glass", f.tenantB)
	before := storedIdP(t, f, "globex-breakglass")

	// Own-only list: acme cannot even see it.
	if got := aliasesFor(t, f.srv, f.tokenA, ""); len(got) != 0 {
		t.Fatalf("CROSS-TENANT LEAK: acme sees %v", got)
	}
	if got := aliasesFor(t, f.srv, f.tokenB, ""); len(got) != 1 || got[0] != "globex-breakglass" {
		t.Fatalf("globex cannot see its own connection: %v", got)
	}
	// as_tenant into the other org cannot widen the view.
	if got := aliasesFor(t, f.srv, f.tokenA, "?as_tenant="+f.tenantB); len(got) != 0 {
		t.Fatalf("CROSS-TENANT LEAK: as_tenant widened acme's view to %v", got)
	}
	for _, c := range []struct {
		method string
		body   any
	}{
		{"GET", nil},
		{"PUT", oidcIdPBody("Hijack")},
		{"DELETE", nil},
	} {
		if st, b := do(t, f.srv, c.method, "/api/auth/sso/tenant-idp/globex-breakglass", f.tokenA, c.body); st != http.StatusNotFound {
			t.Errorf("%s another org's elevation connection: status %d, want 404 (%s)", c.method, st, b)
		}
	}
	after := storedIdP(t, f, "globex-breakglass")
	if after.DisplayName != before.DisplayName || after.KindOrStanding() != before.KindOrStanding() ||
		after.Elevation != before.Elevation || after.Realm() != before.Realm() || after.Enabled != before.Enabled {
		t.Fatalf("another org's connection was mutated: %+v, want %+v", after, before)
	}
	// A platform-realm elevation connection is nobody's here either.
	if _, err := f.s.ssoIdPCfg.Set(ssoidp.Config{
		Alias: "shared-breakglass", DisplayName: "Corporate Break Glass", Protocol: "oidc", Enabled: true,
		DiscoveryURL: "https://idp.example.com/.well-known/openid-configuration", ClientID: "cid",
		Kind: ssoidp.KindElevation, Elevation: ssoidp.Elevation{MaxMinutes: 30},
	}); err != nil {
		t.Fatalf("seed platform-realm elevation connection: %v", err)
	}
	for _, method := range []string{"GET", "DELETE"} {
		if st, _ := do(t, f.srv, method, "/api/auth/sso/tenant-idp/shared-breakglass", f.tokenA, nil); st != http.StatusNotFound {
			t.Errorf("%s a platform-realm elevation connection: %d, want 404", method, st)
		}
	}
	if reg := storedIdP(t, f, "shared-breakglass"); !reg.IsElevation() || reg.Realm() != "" {
		t.Fatalf("the platform-realm connection was altered: %+v", reg)
	}
}

// ---- 4. the property the owner actually cares about ------------------------

// The record and the button list are means to an end. The END is that a
// sign-in through an elevation door produces a grant that EXPIRES and leaves
// the account alone. Prove it through the real code flow, after the save that
// used to break it.
func TestElevationStaysTimeBoundAfterATenantAdminSave(t *testing.T) {
	h := newRealmHarness(t)
	// globex-elev is tenant B's elevation door (seeded by the harness). Give
	// tenant B an administrator of its own, and an account to elevate.
	if st, b := do(t, h.f.srv, "POST", "/api/users", h.f.admin, map[string]any{
		"username": "globex-admin", "password": "Passw0rd!2345", "role": RoleSuperAdmin, "tenant_id": h.f.tenantB,
	}); st != 201 && st != 200 {
		t.Fatalf("create tenant admin: %d %s", st, b)
	}
	token := login(t, h.f.srv, "globex-admin", "Passw0rd!2345").Token
	before := h.seedFederated(t, "globexuser", h.f.tenantB, RoleReadOnly, "ldap")

	// The save that used to convert the door.
	body := oidcIdPBody("Globex Break Glass (renamed)")
	if st, b := do(t, h.f.srv, "PUT", "/api/auth/sso/tenant-idp/globex-elev", token, body); st != 200 {
		t.Fatalf("tenant-admin save: %d %s", st, b)
	}
	h.seedDiscovery(t) // any save rebuilds the live provider

	grant := map[string]any{
		"access_expires_at": time.Now().Add(10 * time.Minute).Unix(),
		"change_ticket":     "CHG-77",
	}
	frag := h.roundTrip(t, "/t/"+h.f.slugB+"/sso/globex-elev/login", "/t/"+h.f.slugB+"/sso/globex-elev/callback", "globexuser", grant)
	if frag.Get("token") == "" {
		t.Fatalf("the elevation sign-in was refused after the save: %q", frag.Get("sso_error"))
	}

	b, ok := h.f.s.activeElevation(httptest.NewRequest(http.MethodGet, "http://x/api/x", nil), "globexuser", h.f.tenantB)
	if !ok {
		t.Fatal("NO ELEVATION BINDING: the tenant-admin save turned the elevation door into a standing one, and the sign-in handed out a permanent role")
	}
	if b.ExpiresAt == nil {
		t.Fatal("the binding never expires — that is a standing role wearing an elevation label")
	}
	if !b.ExpiresAt.After(time.Now()) || b.ExpiresAt.After(time.Now().Add(31*time.Minute)) {
		t.Errorf("expiry = %v, want inside the provider's 30-minute ceiling", b.ExpiresAt)
	}
	if !b.IsElevation() {
		t.Errorf("the binding is not marked as an elevation: %+v", b.Condition)
	}
	// ELEVATION NEVER CHANGES A STANDING ROLE (owner, 2026-09-07): the account
	// is read on this path, never written.
	after, ok := h.f.s.users.Get("globexuser")
	if !ok {
		t.Fatal("the account vanished")
	}
	if after.Role != before.Role || after.AuthSource != before.AuthSource || after.TenantID != before.TenantID {
		t.Fatalf("THE ELEVATION LOGIN REWROTE THE ACCOUNT: %+v, want %+v", after, before)
	}
}

// The tenant-admin view of an elevation connection tells the truth about it, so
// nobody has to guess what they are editing.
func TestTenantIdPViewShowsTheAccessModel(t *testing.T) {
	f := newTenantIdPFixture(t)
	seedTenantElevationIdP(t, f, "acme-breakglass", "Acme Break Glass", f.tenantA)

	st, b := do(t, f.srv, "GET", "/api/auth/sso/tenant-idp/acme-breakglass", f.tokenA, nil)
	if st != 200 {
		t.Fatalf("get: %d %s", st, b)
	}
	var got struct {
		IdP struct {
			Kind      string `json:"kind"`
			Elevation struct {
				TTLClaim   string `json:"ttl_claim"`
				MaxMinutes int    `json:"max_minutes"`
			} `json:"elevation"`
		} `json:"idp"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("decode: %v (%s)", err, b)
	}
	if got.IdP.Kind != ssoidp.KindElevation || got.IdP.Elevation.MaxMinutes != 30 || got.IdP.Elevation.TTLClaim != "access_expires_at" {
		t.Fatalf("the tenant view hides the access model: %+v", got.IdP)
	}
}
