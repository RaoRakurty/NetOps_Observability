// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Route templates covered (the coverage guard matches this literal text):
//   "/api/tac/connectors/{id}"
//   "/api/tac/connectors/{id}/test"

package backend

// tac_connector_config_isolation_test.go — §3a cross-org isolation guard for the
// CASE-CONNECTOR SETTINGS: the routes a customer brings its own Jira /
// ServiceNow / Cisco / Juniper / SMTP credentials through.
//
// This subtree is the highest-value row in the product: it IS the customer's
// vendor credentials. So the obligations §3a rule 5 demands are proven through
// the REAL router and auth middleware (org_isolation_test.go template), plus the
// three this feature adds:
//
//	· own-only        — a tenant reads and writes only its own settings; another
//	                    tenant's saved host never appears in its answer
//	· owner stamped   — the tenant comes from the TOKEN. A tenant_id in the body
//	                    is a 400 rather than a silently ignored field, because
//	                    the form rejects unknown fields outright
//	· as_tenant       — an X-Acting-Tenant override into another org is ignored
//	· foreign/unknown — an id nobody carries answers 404, so the catalogue is not
//	                    an existence oracle
//	· secret hygiene  — a stored secret is NEVER in a response; only its presence
//	· keep-on-save    — a save that omits the secret keeps the stored one, and
//	                    the connector stays ready afterwards
//
// The connector id itself is platform reference data (every tenant sees the same
// twelve), so the leak this guards is not a foreign id — it is a foreign VALUE:
// tenant A's relay host, its reply-to address, whether it has a credential at
// all. Each assertion below is aimed at one of those.

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// tacConnRequest issues one request as a token, optionally ACTING AS another
// tenant — the override this test proves is ignored. It is spelled out rather
// than reusing do() because that helper cannot set a header.
func tacConnRequest(t *testing.T, url, method, path, token, acting string, body []byte) (int, []byte) {
	t.Helper()
	var rdr *strings.Reader
	if body != nil {
		rdr = strings.NewReader(string(body))
	}
	var req *http.Request
	var err error
	if rdr != nil {
		req, err = http.NewRequest(method, url+path, rdr)
	} else {
		req, err = http.NewRequest(method, url+path, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	if acting != "" {
		req.Header.Set("X-Acting-Tenant", acting)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf, rerr := io.ReadAll(resp.Body)
	if rerr != nil {
		t.Fatalf("read %s %s: %v", method, path, rerr)
	}
	return resp.StatusCode, buf
}

func TestTACConnectorSettingsAreScopedToTheCallersOwnTenant(t *testing.T) {
	srv, _ := newTACTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	fix := map[string]*orgFixture{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "CFG Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "CFG Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "cfg-user-" + name
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

	type emailView struct {
		ID       string          `json:"id"`
		Section  string          `json:"section"`
		Editable bool            `json:"editable"`
		Secrets  map[string]bool `json:"secrets"`
		Email    *struct {
			Enabled  bool   `json:"enabled"`
			Host     string `json:"host"`
			From     string `json:"from"`
			User     string `json:"user"`
			Password string `json:"password"`
			ReplyTo  string `json:"reply_to"`
		} `json:"email"`
		Configured bool   `json:"configured"`
		StatusNote string `json:"status_note"`
	}
	decode := func(body []byte) emailView {
		t.Helper()
		var v emailView
		if err := json.Unmarshal(body, &v); err != nil {
			t.Fatalf("decode %s: %v", body, err)
		}
		return v
	}

	const path = "/api/tac/connectors/email-arista"
	const secret = "s3cr3t-relay-password"

	// ── A brings credentials ────────────────────────────────────────────────
	saved := []byte(`{"enabled":true,"host":"smtp.acme.example:587","from":"noc@acme.example",` +
		`"user":"acme-relay","password":"` + secret + `","reply_to":"jane.doe@acme.example"}`)
	st, body := tacConnRequest(t, srv.URL, "PUT", path, a.token, "", saved)
	if st != 200 {
		t.Fatalf("A saves its relay: %d %s", st, body)
	}
	got := decode(body)
	if got.Email == nil || got.Email.Host != "smtp.acme.example:587" {
		t.Fatalf("A's save did not come back: %s", body)
	}
	if got.Email.Password != "" || strings.Contains(string(body), secret) {
		t.Fatalf("SECRET LEAKED in the save response: %s", body)
	}
	if !got.Secrets["password"] {
		t.Fatalf("the stored secret must be reported as present: %s", body)
	}
	if !got.Configured {
		t.Fatalf("a complete relay must read as configured: %+v", got)
	}

	// ── B reads the same connector: its OWN empty settings ──────────────────
	st, body = tacConnRequest(t, srv.URL, "GET", path, b.token, "", nil)
	if st != 200 {
		t.Fatalf("B reads its own settings: %d %s", st, body)
	}
	other := decode(body)
	if strings.Contains(string(body), "acme.example") || strings.Contains(string(body), secret) {
		t.Fatalf("CROSS-TENANT LEAK: B can read A's relay settings: %s", body)
	}
	if other.Secrets["password"] {
		t.Fatalf("CROSS-TENANT LEAK: B is told a credential is stored: %s", body)
	}
	if other.Configured {
		t.Fatalf("B has brought nothing and must not read as configured: %+v", other)
	}

	// ── as_tenant into another org is ignored ───────────────────────────────
	st, body = tacConnRequest(t, srv.URL, "GET", path, b.token, a.tenantID, nil)
	if st != 200 || strings.Contains(string(body), "acme.example") {
		t.Fatalf("as_tenant into another org moved the read: %d %s", st, body)
	}
	// And it cannot move a WRITE either: B's save under A's acting tenant lands
	// on B, and A's row survives untouched.
	st, body = tacConnRequest(t, srv.URL, "PUT", path, b.token, a.tenantID,
		[]byte(`{"enabled":true,"host":"smtp.globex.example:587","from":"noc@globex.example"}`))
	if st != 200 {
		t.Fatalf("B saves its own relay: %d %s", st, body)
	}
	st, body = tacConnRequest(t, srv.URL, "GET", path, a.token, "", nil)
	if st != 200 {
		t.Fatalf("A re-reads: %d %s", st, body)
	}
	if v := decode(body); v.Email == nil || v.Email.Host != "smtp.acme.example:587" {
		t.Fatalf("CROSS-TENANT WRITE: B's save reached A's row: %s", body)
	}

	// ── the owner is stamped, so a tenant in the body is a 400 ──────────────
	for _, payload := range []string{
		`{"tenant_id":"` + a.tenantID + `","enabled":true,"host":"smtp.evil.example:587","from":"x@evil.example"}`,
		`{"tenant":"` + a.tenantID + `","enabled":false}`,
	} {
		if st, body := tacConnRequest(t, srv.URL, "PUT", path, b.token, "", []byte(payload)); st != http.StatusBadRequest {
			t.Fatalf("a tenant in the body must be refused, got %d %s", st, body)
		}
	}

	// ── a save that omits the secret KEEPS it ───────────────────────────────
	st, body = tacConnRequest(t, srv.URL, "PUT", path, a.token, "",
		[]byte(`{"enabled":true,"host":"smtp.acme.example:465","from":"noc@acme.example","user":"acme-relay","tls_on_connect":true}`))
	if st != 200 {
		t.Fatalf("A edits without resending the secret: %d %s", st, body)
	}
	kept := decode(body)
	if !kept.Secrets["password"] {
		t.Fatal("a save that omitted the password DROPPED the stored one")
	}
	if !kept.Configured {
		t.Fatalf("the connector must stay ready after an edit: %+v", kept)
	}

	// ── an explicit empty string CLEARS it ──────────────────────────────────
	st, body = tacConnRequest(t, srv.URL, "PUT", path, a.token, "",
		[]byte(`{"enabled":true,"host":"smtp.acme.example:465","from":"noc@acme.example","user":"acme-relay","password":"","tls_on_connect":true}`))
	if st != 200 {
		t.Fatalf("A clears the secret: %d %s", st, body)
	}
	if decode(body).Secrets["password"] {
		t.Fatal("an explicit empty secret must remove the stored one")
	}

	// ── a refusal names the field, and changes nothing ──────────────────────
	if st, body := tacConnRequest(t, srv.URL, "PUT", path, a.token, "",
		[]byte(`{"enabled":true,"host":"smtp.acme.example","from":"noc@acme.example"}`)); st != http.StatusBadRequest ||
		!strings.Contains(string(body), "host:port") {
		t.Fatalf("an incomplete relay must be refused BY FIELD, got %d %s", st, body)
	}

	// ── an unknown connector id is a 404 on every verb ──────────────────────
	for _, m := range []string{"GET", "PUT", "DELETE"} {
		if st, _ := tacConnRequest(t, srv.URL, m, "/api/tac/connectors/not-a-connector", a.token, "", []byte(`{}`)); st != http.StatusNotFound {
			t.Fatalf("%s on an unknown connector must be 404, got %d", m, st)
		}
	}
	if st, _ := tacConnRequest(t, srv.URL, "POST", "/api/tac/connectors/not-a-connector/test", a.token, "", nil); st != http.StatusNotFound {
		t.Fatal("a probe of an unknown connector must be 404")
	}

	// ── a portal-only path has nothing to configure, and says so ────────────
	if st, body := tacConnRequest(t, srv.URL, "GET", "/api/tac/connectors/portal-nokia", a.token, "", nil); st != 200 ||
		!strings.Contains(string(body), `"editable":false`) {
		t.Fatalf("a portal-only connector must read as not editable: %d %s", st, body)
	}
	if st, _ := tacConnRequest(t, srv.URL, "PUT", "/api/tac/connectors/portal-nokia", a.token, "", []byte(`{"enabled":true}`)); st != http.StatusConflict {
		t.Fatal("saving settings on a portal-only connector must be refused")
	}

	// ── the probe never touches a vendor when nothing is configured ─────────
	st, body = tacConnRequest(t, srv.URL, "POST", "/api/tac/connectors/juniper/test", b.token, "", nil)
	if st != 200 {
		t.Fatalf("probe: %d %s", st, body)
	}
	var probe struct {
		ConnectorID string `json:"connector_id"`
		Outcome     string `json:"outcome"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		t.Fatalf("decode probe: %v", err)
	}
	if probe.Outcome != "not_configured" || probe.ConnectorID != "juniper" {
		t.Fatalf("an unconfigured connector must probe as not_configured: %s", body)
	}

	// ── DELETE removes only this connector's block ──────────────────────────
	if st, body := tacConnRequest(t, srv.URL, "PUT", "/api/tac/connectors/jira", a.token, "",
		[]byte(`{"enabled":true,"deployment":"cloud"}`)); st != 200 {
		t.Fatalf("A enables the Jira attach path: %d %s", st, body)
	}
	if st, body := tacConnRequest(t, srv.URL, "DELETE", path, a.token, "", nil); st != 200 {
		t.Fatalf("A removes its relay: %d %s", st, body)
	}
	st, body = tacConnRequest(t, srv.URL, "GET", "/api/tac/connectors/jira", a.token, "", nil)
	if st != 200 || !strings.Contains(string(body), `"enabled":true`) {
		t.Fatalf("removing the relay took the Jira settings with it: %d %s", st, body)
	}
	st, body = tacConnRequest(t, srv.URL, "GET", path, a.token, "", nil)
	if st != 200 || strings.Contains(string(body), "acme.example") {
		t.Fatalf("the relay settings survived their removal: %d %s", st, body)
	}
}
