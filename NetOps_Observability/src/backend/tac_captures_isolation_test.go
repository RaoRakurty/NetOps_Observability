// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Route templates covered (the coverage guard matches this literal text):
//   "/api/tac/captures"  "/api/tac/captures/"

package backend

// tac_captures_isolation_test.go — §3a cross-org isolation guard for the TAC
// CAPTURES surface (docs/design/TAC_CAPTURES_2026-09-06.md), exercised through
// the REAL router + auth middleware (org_isolation_test.go template).
//
// A capture is a named list of commands, and a SAVED one is a template row — the
// same store, the same tenant-keyed bucket / FORCE-RLS policy. That is exactly
// why this file exists rather than trusting the template test: the routes are
// new, and a route is where isolation is lost, not a store.
//
// The obligations proven here:
//
//	· own-only        — a tenant lists only its own captures
//	· foreign → 404   — another org's capture id is indistinguishable from an id
//	                    that does not exist; never 403, which would confirm it
//	· body tenant     — a tenant_id in the body is a 400: the wire type cannot
//	                    express one, and ownership is stamped from the token
//	· as_tenant       — an X-Acting-Tenant override into another org is ignored
//
// And the property the upload path rests on: EVERY line is held to the
// output-only policy, ONE refused line refuses the WHOLE file, and the refusal
// names the LINE NUMBER IN THE UPLOADED FILE — not the validator's index, which
// is a different number the moment the file carries a comment or a blank line.

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// capBody is the save payload. It mirrors the module's wire type: a field it
// does not carry (a tenant) cannot be sent by accident.
func capBody(dialect, name string, commands ...string) map[string]any {
	rows := make([]map[string]any, 0, len(commands))
	for _, c := range commands {
		rows = append(rows, map[string]any{"command": c})
	}
	return map[string]any{"dialect": dialect, "name": name, "commands": rows}
}

func capID(t *testing.T, body []byte) string {
	t.Helper()
	var out struct {
		Capture struct {
			ID string `json:"id"`
		} `json:"capture"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode capture: %v (%s)", err, body)
	}
	if out.Capture.ID == "" {
		t.Fatalf("no capture id in %s", body)
	}
	return out.Capture.ID
}

// upload POSTs a file's BYTES as the request body, which is what the browser
// does: the filename rides on the query string, is used only to pick a parser,
// and never touches a path.
func upload(t *testing.T, srv *httptest.Server, token, filename, dialect string, data []byte, actingTenant string) (int, []byte) {
	t.Helper()
	url := srv.URL + "/api/tac/captures/upload?filename=" + filename
	if dialect != "" {
		url += "&dialect=" + dialect
	}
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", "Bearer "+token)
	if actingTenant != "" {
		req.Header.Set("X-Acting-Tenant", actingTenant)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func newCaptureOrgs(t *testing.T, srv *httptest.Server, prefix string) (*orgFixture, *orgFixture) {
	t.Helper()
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	fix := map[string]*orgFixture{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": prefix + " Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": prefix + " Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := strings.ToLower(prefix) + "-user-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &orgFixture{orgID: orgID, tenantID: tenantID, user: user,
			token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	return fix["A"], fix["B"]
}

func TestTACCapturesCrossOrgIsolation(t *testing.T) {
	srv, _ := newTACTestServer(t)
	a, b := newCaptureOrgs(t, srv, "CAP")

	// ── own-only ────────────────────────────────────────────────────────────
	stA, bodyA := do(t, srv, "POST", "/api/tac/captures", a.token,
		capBody("arista-eos", "ACME captures", "show version", "show interfaces status"))
	if stA != 201 {
		t.Fatalf("A saves its own capture: %d %s", stA, bodyA)
	}
	idA := capID(t, bodyA)
	stB, bodyB := do(t, srv, "POST", "/api/tac/captures", b.token,
		capBody("arista-eos", "OTHER captures", "show version"))
	if stB != 201 {
		t.Fatalf("B saves its own capture: %d %s", stB, bodyB)
	}
	idB := capID(t, bodyB)

	st, list := do(t, srv, "GET", "/api/tac/captures", a.token, nil)
	if st != 200 {
		t.Fatalf("A lists: %d %s", st, list)
	}
	if !strings.Contains(string(list), "ACME captures") {
		t.Fatal("A cannot see its own capture")
	}
	if strings.Contains(string(list), "OTHER captures") || strings.Contains(string(list), idB) {
		t.Fatal("CROSS-TENANT LEAK: A sees B's capture")
	}
	// The saved capture round-trips as a CAPTURE, not as a template shape.
	if !strings.Contains(string(list), `"source":"template"`) ||
		!strings.Contains(string(list), `"command":"show interfaces status"`) {
		t.Fatalf("the listing is not in capture shape: %s", list)
	}

	// ── another org's id → 404, identical to an id that does not exist ───────
	if st, body := do(t, srv, "GET", "/api/tac/captures/"+idB, a.token, nil); st != http.StatusNotFound {
		t.Errorf("GET another org's capture: %d %s, want 404", st, body)
	}
	if st, _ := do(t, srv, "GET", "/api/tac/captures/tpl-000000000000000000000000", a.token, nil); st != http.StatusNotFound {
		t.Fatalf("unknown capture id: %d, want the same 404 a foreign id gets", st)
	}
	// A's own id still reads, so the 404 above was about ownership.
	if st, body := do(t, srv, "GET", "/api/tac/captures/"+idA, a.token, nil); st != 200 ||
		!strings.Contains(string(body), "ACME captures") {
		t.Fatalf("A cannot read its own capture: %d %s", st, body)
	}
	// B's row is untouched by A's attempts.
	if st, body := do(t, srv, "GET", "/api/tac/captures/"+idB, b.token, nil); st != 200 ||
		!strings.Contains(string(body), "OTHER captures") {
		t.Fatalf("A's cross-tenant reads damaged B's capture: %d %s", st, body)
	}

	// ── a tenant in the body is a 400 (the wire type cannot express one) ─────
	if st, body := do(t, srv, "POST", "/api/tac/captures", a.token, map[string]any{
		"dialect": "arista-eos", "name": "forged", "tenant_id": b.tenantID,
		"commands": []map[string]any{{"command": "show version"}},
	}); st != http.StatusBadRequest {
		t.Fatalf("a tenant smuggled into the body was not rejected: %d %s", st, body)
	}

	// ── X-Acting-Tenant into another org is ignored ─────────────────────────
	{
		payload, _ := json.Marshal(capBody("arista-eos", "smuggled", "show version"))
		req, err := http.NewRequest("POST", srv.URL+"/api/tac/captures", bytes.NewReader(payload))
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
		_, blist := do(t, srv, "GET", "/api/tac/captures", b.token, nil)
		if strings.Contains(string(blist), "smuggled") {
			t.Fatal("acting-tenant override wrote into another org's captures")
		}
	}

	// An upload is not stored, so it cannot leak either — but it is scoped the
	// same way, and a cross-tenant header must not move it.
	if st, _ := upload(t, srv, a.token, "acme.txt", "arista-eos",
		[]byte("show version\n"), b.tenantID); st != 200 {
		t.Fatalf("upload with an acting-tenant header: %d", st)
	}
	_, blist := do(t, srv, "GET", "/api/tac/captures", b.token, nil)
	if strings.Contains(string(blist), "acme") {
		t.Fatal("an upload became a row in another org")
	}
}

// TestTACCaptureUploadParsesEveryFormat proves each documented format
// round-trips through the REAL route, including a genuine minimal .docx.
func TestTACCaptureUploadParsesEveryFormat(t *testing.T) {
	srv, _ := newTACTestServer(t)
	a, _ := newCaptureOrgs(t, srv, "CAPFMT")

	docx := buildTestDocx(t, []string{"show version", "show interfaces status"})
	for _, tc := range []struct {
		name string
		file string
		data []byte
		want []string
	}{
		{"txt", "runbook.txt", []byte("# ACME\n\nshow version\nshow interfaces status\n"),
			[]string{"show version", "show interfaces status"}},
		{"csv", "runbook.csv", []byte("command,note\nshow version,the baseline\nshow interfaces status,\n"),
			[]string{"show version", "show interfaces status"}},
		{"json", "runbook.json", []byte(`{"name":"ACME","commands":["show version","show interfaces status"]}`),
			[]string{"show version", "show interfaces status"}},
		{"yaml", "runbook.yaml", []byte("name: ACME\ncommands:\n  - show version\n  - show interfaces status\n"),
			[]string{"show version", "show interfaces status"}},
		{"docx", "runbook.docx", docx, []string{"show version", "show interfaces status"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, body := upload(t, srv, a.token, tc.file, "arista-eos", tc.data, "")
			if st != 200 {
				t.Fatalf("upload %s: %d %s", tc.name, st, body)
			}
			s := string(body)
			if !strings.Contains(s, `"source":"uploaded"`) {
				t.Errorf("an upload must come back as source=uploaded: %s", s)
			}
			for _, want := range tc.want {
				if !strings.Contains(s, `"command":"`+want+`"`) {
					t.Errorf("%s upload is missing %q: %s", tc.name, want, s)
				}
			}
		})
	}

	// A format nobody documented is refused BY NAME, with what to bring instead.
	st, body := upload(t, srv, a.token, "runbook.xlsx", "arista-eos", []byte("x"), "")
	if st != http.StatusBadRequest || !strings.Contains(string(body), "txt, csv, json, yaml, docx") {
		t.Fatalf("an unsupported format: %d %s", st, body)
	}
	// A body over the ceiling is refused rather than truncated into a shorter
	// command set than the operator wrote.
	big := []byte(strings.Repeat("show version\n", 200000))
	if st, _ := upload(t, srv, a.token, "big.txt", "arista-eos", big, ""); st != http.StatusRequestEntityTooLarge &&
		st != http.StatusBadRequest {
		t.Fatalf("an oversized upload: %d, want a refusal", st)
	}
}

// TestTACCaptureUploadRefusesByLineAndRule is the whole promise of the upload
// path: one forbidden line refuses the FILE, and the refusal points at the line
// number in the operator's own file — not at the validator's index, which is a
// different number as soon as the file carries a comment.
func TestTACCaptureUploadRefusesByLineAndRule(t *testing.T) {
	srv, _ := newTACTestServer(t)
	a, _ := newCaptureOrgs(t, srv, "CAPPOL")

	// `configure terminal` is on line 5 of the file and index 1 of the command
	// list — the two numbers deliberately differ.
	file := "# ACME runbook\n\n# the baseline\nshow version\nconfigure terminal\nshow logging\n"
	st, body := upload(t, srv, a.token, "bad.txt", "cisco-iosxe", []byte(file), "")
	if st != http.StatusBadRequest {
		t.Fatalf("a file carrying a config command was accepted: %d %s", st, body)
	}
	var out struct {
		Error    string `json:"error"`
		Refusals []struct {
			Line    int    `json:"line"`
			Command string `json:"command"`
			Family  string `json:"family"`
			Rule    string `json:"rule"`
			Reason  string `json:"reason"`
		} `json:"refusals"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode refusal: %v (%s)", err, body)
	}
	if len(out.Refusals) != 1 {
		t.Fatalf("want exactly one refused line, got %+v", out.Refusals)
	}
	r := out.Refusals[0]
	if r.Line != 5 {
		t.Errorf("refusal line = %d, want 5 (the line in the uploaded file)", r.Line)
	}
	if r.Command != "configure terminal" {
		t.Errorf("refusal command = %q", r.Command)
	}
	if r.Family != "config" {
		t.Errorf("refusal family = %q, want the policy family by name", r.Family)
	}
	if r.Rule == "" || r.Reason == "" {
		t.Errorf("a refusal must name the rule and give a reason: %+v", r)
	}
	if !strings.Contains(out.Error, "nothing in it will run") {
		t.Errorf("the headline must say the whole file was refused: %q", out.Error)
	}
	// And nothing was stored: the refusal is fail-closed, not fail-partial.
	_, list := do(t, srv, "GET", "/api/tac/captures", a.token, nil)
	if strings.Contains(string(list), "show version") {
		t.Fatalf("a refused upload left a row behind: %s", list)
	}

	// The same rule on the SAVE path: a forbidden command never reaches a row.
	if st, body := do(t, srv, "POST", "/api/tac/captures", a.token,
		capBody("cisco-iosxe", "bad", "show version", "reload")); st != http.StatusBadRequest {
		t.Fatalf("a capture carrying a restart command was saved: %d %s", st, body)
	}
}

// buildTestDocx writes the minimal OPC package Word writes: a zip whose
// word/document.xml holds one paragraph per command. Built here rather than
// checked in so the fixture can never drift out of regenerability.
func buildTestDocx(t *testing.T, commands []string) []byte {
	t.Helper()
	var body strings.Builder
	for _, c := range commands {
		body.WriteString(`<w:p><w:r><w:t>` + c + `</w:t></w:r></w:p>`)
	}
	const ns = `xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"`
	doc := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<w:document ` + ns + `><w:body>` + body.String() + `</w:body></w:document>`
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("word/document.xml")
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	if _, err := w.Write([]byte(doc)); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}
