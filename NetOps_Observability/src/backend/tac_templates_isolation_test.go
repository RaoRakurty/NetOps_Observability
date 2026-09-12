// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Route templates covered (the coverage guard matches this literal text):
//   "/api/tac/templates"           "/api/tac/templates/"
//   "/api/tac/templates/defaults"  "/api/tac/templates/validate"
//   "/api/tac/connectors"

package backend

// tac_templates_isolation_test.go — §3a cross-org isolation guard for the TAC
// COMMAND TEMPLATES (tracker 250), exercised through the REAL router + auth
// middleware (org_isolation_test.go template).
//
// The obligations §3a rule 5 demands, and one more this feature adds:
//
//	· own-only        — a tenant lists only its own saved sets
//	· foreign → 404   — another org's template id is indistinguishable from an
//	                    id that does not exist; never 403, which would confirm it
//	· as_tenant       — an X-Acting-Tenant override into another org is ignored
//	· owner stamped   — the tenant comes from the TOKEN; a tenant_id in the body
//	                    is a 400, because the wire type cannot express one
//	· defaults        — Correlix's own sets are readable by every tenant, are
//	                    byte-identical for each of them, and are IMMUTABLE
//
// And the property the whole feature rests on, proven here through the HTTP
// path rather than only in the package: a client cannot widen what runs. A
// forbidden command is refused on the way into a template, and a TAMPERED
// collect list is refused AS A WHOLE, naming the line.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/incident"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/tac"
	"netops/backend/internal/ticketing"
	"netops/backend/models"
)

// tplBody is the create/update payload. It deliberately mirrors the module's
// wire type: a field it does not carry (a tenant) cannot be sent by accident.
func tplBody(dialect, name string, commands ...string) map[string]any {
	steps := make([]map[string]any, 0, len(commands))
	for _, c := range commands {
		steps = append(steps, map[string]any{"command": c})
	}
	return map[string]any{"dialect": dialect, "name": name, "steps": steps}
}

func tplID(t *testing.T, body []byte) string {
	t.Helper()
	var out struct {
		Template struct {
			ID string `json:"id"`
		} `json:"template"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode template: %v (%s)", err, body)
	}
	if out.Template.ID == "" {
		t.Fatalf("no template id in %s", body)
	}
	return out.Template.ID
}

func TestTACTemplatesCrossOrgIsolation(t *testing.T) {
	srv, _ := newTACTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	fix := map[string]*orgFixture{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "TPL Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "TPL Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "tpl-user-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &orgFixture{orgID: orgID, tenantID: tenantID, user: user,
			token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b := fix["A"], fix["B"]

	// ── own-only: each org saves its own set ────────────────────────────────
	stA, bodyA := do(t, srv, "POST", "/api/tac/templates", a.token,
		tplBody("arista-eos", "ACME EOS baseline", "show version", "show ip nhrp brief detail summary"))
	if stA != 201 {
		t.Fatalf("A saves its own template: %d %s", stA, bodyA)
	}
	idA := tplID(t, bodyA)
	stB, bodyB := do(t, srv, "POST", "/api/tac/templates", b.token,
		tplBody("arista-eos", "OTHER EOS baseline", "show version"))
	if stB != 201 {
		t.Fatalf("B saves its own template: %d %s", stB, bodyB)
	}
	idB := tplID(t, bodyB)

	st, list := do(t, srv, "GET", "/api/tac/templates", a.token, nil)
	if st != 200 {
		t.Fatalf("A lists: %d %s", st, list)
	}
	if !strings.Contains(string(list), "ACME EOS baseline") {
		t.Fatal("A cannot see its own template")
	}
	if strings.Contains(string(list), "OTHER EOS baseline") || strings.Contains(string(list), idB) {
		t.Fatal("CROSS-TENANT LEAK: A sees B's command template")
	}

	// ── foreign id → 404 on every item verb, never 403 ─────────────────────
	for _, route := range []struct {
		method string
		body   map[string]any
	}{
		{"GET", nil},
		{"PUT", tplBody("arista-eos", "hijacked", "show version")},
		{"DELETE", nil},
	} {
		st, body := do(t, srv, route.method, "/api/tac/templates/"+idB, a.token, route.body)
		if st != http.StatusNotFound {
			t.Errorf("%s another org's template: %d %s, want 404", route.method, st, body)
		}
	}
	// An id that does not exist at all answers IDENTICALLY — the subtree is not
	// an existence oracle.
	if st, _ := do(t, srv, "GET", "/api/tac/templates/tpl-000000000000000000000000", a.token, nil); st != http.StatusNotFound {
		t.Fatalf("unknown template id: %d, want the same 404 a foreign id gets", st)
	}
	// B's template is untouched by A's attempts.
	if st, body := do(t, srv, "GET", "/api/tac/templates/"+idB, b.token, nil); st != 200 ||
		!strings.Contains(string(body), "OTHER EOS baseline") {
		t.Fatalf("A's cross-tenant writes damaged B's template: %d %s", st, body)
	}

	// ── as_tenant / X-Acting-Tenant into another org is ignored ─────────────
	{
		payload, _ := json.Marshal(tplBody("arista-eos", "smuggled", "show version"))
		req, err := http.NewRequest("POST", srv.URL+"/api/tac/templates", bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+a.token)
		req.Header.Set("X-Acting-Tenant", b.tenantID)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == 201 {
			// It may only have landed in A's own scope; assert that B cannot see it.
			_, blist := do(t, srv, "GET", "/api/tac/templates", b.token, nil)
			if strings.Contains(string(blist), "smuggled") {
				t.Fatal("acting-tenant override wrote into another org's templates")
			}
		}
	}

	// ── the owner is stamped from the token; a tenant in the body is a 400 ──
	if st, body := do(t, srv, "POST", "/api/tac/templates", a.token, map[string]any{
		"dialect": "arista-eos", "name": "forged", "tenant_id": b.tenantID,
		"steps": []map[string]any{{"command": "show version"}},
	}); st != http.StatusBadRequest {
		t.Fatalf("a tenant smuggled into the body was not rejected: %d %s", st, body)
	}

	// ── Correlix defaults: readable by both, identical, immutable ───────────
	stA1, defA := do(t, srv, "GET", "/api/tac/templates/defaults?dialect=arista-eos", a.token, nil)
	stB1, defB := do(t, srv, "GET", "/api/tac/templates/defaults?dialect=arista-eos", b.token, nil)
	if stA1 != 200 || stB1 != 200 {
		t.Fatalf("defaults: %d / %d", stA1, stB1)
	}
	if string(defA) != string(defB) {
		t.Fatal("the Correlix defaults are tenant-variant; they are reference data and must not be")
	}
	if !strings.Contains(string(defA), "correlix:arista-eos:") {
		t.Fatalf("the defaults do not carry Correlix's own template ids: %s", defA)
	}
	for _, m := range []string{"PUT", "DELETE"} {
		var payload map[string]any
		if m == "PUT" {
			payload = tplBody("arista-eos", "rewritten", "show version")
		}
		if st, body := do(t, srv, m, "/api/tac/templates/correlix:arista-eos:baseline", a.token, payload); st != http.StatusForbidden {
			t.Errorf("%s a Correlix default: %d %s, want 403", m, st, body)
		}
	}

	// ── a forbidden command never reaches a saved template ──────────────────
	st, body := do(t, srv, "POST", "/api/tac/templates", a.token,
		tplBody("arista-eos", "bad", "show version", "configure terminal"))
	if st != http.StatusBadRequest {
		t.Fatalf("a template carrying a config command was saved: %d %s", st, body)
	}
	if !strings.Contains(string(body), "configure terminal") || !strings.Contains(string(body), "config") {
		t.Fatalf("the refusal does not name the line and its family: %s", body)
	}

	// ── the operator's own template updates, and the version increments ─────
	st, body = do(t, srv, "PUT", "/api/tac/templates/"+idA, a.token,
		tplBody("arista-eos", "ACME EOS baseline", "show version", "show interfaces status"))
	if st != 200 {
		t.Fatalf("A updates its own template: %d %s", st, body)
	}
	if !strings.Contains(string(body), `"version":2`) && !strings.Contains(string(body), `"version": 2`) {
		t.Fatalf("the update did not increment the version: %s", body)
	}
	if st, _ := do(t, srv, "DELETE", "/api/tac/templates/"+idA, a.token, nil); st != 200 {
		t.Fatalf("A deletes its own template: %d", st)
	}
}

// TestTACTemplateValidateNamesTheFamilyAndTheRule — the review step's live
// check, through the router. An operator who is told "invalid" learns nothing;
// the response must name the family and the rule that refused the line.
func TestTACTemplateValidateNamesTheFamilyAndTheRule(t *testing.T) {
	srv, _ := newTACTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	st, body := do(t, srv, "POST", "/api/tac/templates/validate", admin, map[string]any{
		"dialect":  "cisco-iosxe",
		"commands": []string{"show version", "reload", "clear ip bgp *", "show ip nhrp brief detail summary"},
	})
	if st != 200 {
		t.Fatalf("validate: %d %s", st, body)
	}
	s := string(body)
	for _, want := range []string{`"family":"restart"`, `"family":"config"`, `"origin":"catalog"`, `"origin":"custom"`} {
		if !strings.Contains(s, want) {
			t.Errorf("the validation response is missing %s: %s", want, s)
		}
	}
	if !strings.Contains(s, `"refused":2`) {
		t.Errorf("expected two refused lines: %s", s)
	}
}

// TestTACCollectRefusesATamperedReviewedList is the tampering guard on the path
// that actually touches a device. The client sends a reviewed list with a config
// command in it; the server refuses the WHOLE collection and names the line.
// Nothing is silently dropped and nothing runs.
func TestTACCollectRefusesATamperedReviewedList(t *testing.T) {
	srv, s := newTACTestServer(t)
	inc := newMemIncidents()
	s.incidents = inc
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	now := time.Now().UTC()
	inc.put(incident.Incident{ID: "tacinc-tpl", TenantID: "", Title: "OSPF adjacency down",
		Severity: "critical", Status: "open", FirstSeenAt: now.Add(-time.Hour), LastSeenAt: now})
	s.discovery.Upsert(models.Device{ID: "tac-dev-tpl", Name: "tac-dev-tpl", Vendor: "Cisco", OS: "IOS-XE"})

	if st, _ := do(t, srv, "POST", "/api/incidents/tacinc-tpl/tac/classify", admin, map[string]any{}); st != 200 {
		t.Fatalf("classify: %d", st)
	}
	if st, body := do(t, srv, "POST", "/api/incidents/tacinc-tpl/tac/plan", admin,
		map[string]any{"device_id": "tac-dev-tpl", "class_id": "ospf-adjacency"}); st != 200 {
		t.Fatalf("plan: %d %s", st, body)
	}
	st, body := do(t, srv, "POST", "/api/incidents/tacinc-tpl/tac/collect", admin, map[string]any{
		"steps": []map[string]any{
			{"command": "show version"},
			{"command": "configure terminal"},
		},
	})
	if st != http.StatusBadRequest {
		t.Fatalf("a tampered reviewed list was accepted: %d %s", st, body)
	}
	if !strings.Contains(string(body), "configure terminal") {
		t.Fatalf("the refusal does not name the offending line: %s", body)
	}
	if !strings.Contains(string(body), "nothing ran") {
		t.Fatalf("the refusal must say the whole collection was refused: %s", body)
	}
	// An unknown template id is refused too — provenance is server-resolved, so
	// a MANIFEST can never name a template nobody can find.
	if st, body := do(t, srv, "POST", "/api/incidents/tacinc-tpl/tac/collect", admin, map[string]any{
		"template_id": "tpl-deadbeefdeadbeefdeadbeef",
		"steps":       []map[string]any{{"command": "show version"}},
	}); st != http.StatusBadRequest || !strings.Contains(string(body), "unknown command template") {
		t.Fatalf("an unknown template id was accepted: %d %s", st, body)
	}
}

// TestTACTemplateStoreRLSIsolationPG proves the Postgres backend's tenant_iso
// FORCE-RLS policy (migration 0045) enforces the same rule the file store's
// tenant-keyed map does — with the store connected as a NON-superuser role,
// because a superuser ignores RLS entirely even under FORCE.
//
// It needs a real PostgreSQL: set DATABASE_URL_TEST (a THROWAWAY database) to
// run it; skipped otherwise so the default suite stays offline.
func TestTACTemplateStoreRLSIsolationPG(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the TAC template RLS isolation test")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()
	st := tac.NewPGTemplateStore(ps.DB())

	mk := func(tenant, name string) tac.Template {
		return tac.Template{TenantID: tenant, Dialect: "arista-eos", Name: name,
			Steps: []tac.TemplateStep{{Command: "show version"}}, CreatedBy: "u@" + tenant}
	}
	acme, err := st.Create(ctx, mk("acme", "acme baseline"))
	if err != nil {
		t.Fatalf("acme create: %v", err)
	}
	globex, err := st.Create(ctx, mk("globex", "globex baseline"))
	if err != nil {
		t.Fatalf("globex create: %v", err)
	}
	t.Cleanup(func() {
		_ = st.Delete(ctx, "acme", acme.ID)
		_ = st.Delete(ctx, "globex", globex.ID)
	})

	rows, err := st.List(ctx, "acme")
	if err != nil {
		t.Fatalf("acme list: %v", err)
	}
	for _, r := range rows {
		if r.ID == globex.ID || r.Name == "globex baseline" {
			t.Fatal("CROSS-TENANT LEAK: acme sees globex's command template")
		}
	}
	if _, gerr := st.Get(ctx, "acme", globex.ID); gerr == nil {
		t.Fatal("acme read globex's template by id")
	}
	if _, uerr := st.Update(ctx, "acme", globex.ID, mk("acme", "hijack")); uerr == nil {
		t.Fatal("acme updated globex's template")
	}
	if derr := st.Delete(ctx, "acme", globex.ID); derr == nil {
		t.Fatal("acme deleted globex's template")
	}
	// globex's row survived every one of those.
	if got, gerr := st.Get(ctx, "globex", globex.ID); gerr != nil || got.Name != "globex baseline" {
		t.Fatalf("acme's cross-tenant writes reached globex's row: %+v %v", got, gerr)
	}
}

// ── /api/tac/connectors (§3a rule 5) ────────────────────────────────────────
//
// The catalogue is platform reference data, so a leak here cannot be a row of
// someone else's; what CAN leak is the per-tenant `configured` flag and its
// status note, which together say whether another customer has brought
// credentials for a vendor. This proves the read is keyed on the TOKEN's tenant
// and that an X-Acting-Tenant header cannot move it.
func TestTACConnectorsAreScopedToTheCallersOwnTenant(t *testing.T) {
	srv, s := newTACTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	fix := map[string]*orgFixture{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "CONN Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "CONN Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "conn-user-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &orgFixture{orgID: orgID, tenantID: tenantID, user: user,
			token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b := fix["A"], fix["B"]

	// Only A opts a connector in. The stamp is the store's own scoping call —
	// the same one the resolver makes — so this is A's row and nobody else's.
	if err := s.tacConnectors.Set(a.tenantID, false, a.tenantID, ticketing.TACConnectorConfig{
		Jira: ticketing.JiraAttachConfig{Enabled: true, Deployment: "cloud"},
	}); err != nil {
		t.Fatalf("store A's connector config: %v", err)
	}

	read := func(token, acting string) []map[string]any {
		t.Helper()
		req, err := http.NewRequest("GET", srv.URL+"/api/tac/connectors", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if acting != "" {
			req.Header.Set("X-Acting-Tenant", acting)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("GET /api/tac/connectors: %d", resp.StatusCode)
		}
		var out struct {
			Connectors []map[string]any `json:"connectors"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(out.Connectors) == 0 {
			t.Fatal("no connectors at all")
		}
		return out.Connectors
	}
	statusOf := func(rows []map[string]any, id string) string {
		for _, r := range rows {
			if r["id"] == id {
				note, _ := r["status_note"].(string)
				return note
			}
		}
		t.Fatalf("connector %q missing from the list", id)
		return ""
	}

	// A's own row is read: Jira is opted in but has no ITSM connection, so the
	// note is the connector's own reason and not the not-configured state.
	if got := statusOf(read(a.token, ""), "jira"); !strings.Contains(got, "no Jira connection") {
		t.Fatalf("A must read its OWN connector row, got %q", got)
	}
	// B stored nothing. It must see the not-configured STATE — never A's row,
	// and never an unreadable-store error.
	bNote := statusOf(read(b.token, ""), "jira")
	if bNote != ticketing.NotConfiguredStatusNote {
		t.Fatalf("CROSS-TENANT LEAK or false error: B's jira status = %q", bNote)
	}
	for _, row := range read(b.token, "") {
		if unavailable, _ := row["unavailable"].(bool); unavailable {
			t.Fatalf("a tenant with no stored row must not read as unavailable: %v", row["id"])
		}
	}
	// An X-Acting-Tenant override into another org is ignored: B still reads B.
	if got := statusOf(read(b.token, a.tenantID), "jira"); got != ticketing.NotConfiguredStatusNote {
		t.Fatalf("as_tenant into another org moved the read: %q", got)
	}
}
