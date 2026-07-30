package backend

// graphql_test.go — regression guards for audit F-72.
//
// The finding had two halves and both are tested here:
//
//	SECURITY  /api/graphql ran with `claims, _ := userFrom(ctx)` and NO
//	          requirePerm, while its REST twin required infrastructure:read.
//	          A principal with zero infrastructure permission could read the
//	          entire device inventory through GraphQL.
//	CORRECTNESS  substring dispatch: arguments ignored (`limit:1` returned all
//	          512 devices), selection set ignored (every field of every row),
//	          variables never read, and `{bogus}` answered 200 + `{"data":{}}`
//	          — which every spec-compliant client reads as "success, no results".

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
)

type gqlResp struct {
	Data   map[string]json.RawMessage `json:"data"`
	Errors []struct {
		Message string   `json:"message"`
		Path    []string `json:"path"`
	} `json:"errors"`
}

// doRaw is `do` against a bare base URL (the GraphQL tests need the raw body
// before it is typed).
func doRaw(t *testing.T, baseURL, method, path, token string, body any) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, baseURL+path, r)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func gql(t *testing.T, srvURL, token, query string, vars map[string]any) (int, gqlResp, []byte) {
	t.Helper()
	body := map[string]any{"query": query}
	if vars != nil {
		body["variables"] = vars
	}
	st, raw := doRaw(t, srvURL, "POST", "/api/graphql", token, body)
	var out gqlResp
	_ = json.Unmarshal(raw, &out)
	return st, out, raw
}

// ── SECURITY: the RBAC hole ───────────────────────────────────────────────────

// TestGraphQLEnforcesTheSameRBACGateAsREST is the F-72 security regression.
// It builds a principal with infrastructure:none and asserts BOTH doors are
// shut. Before the fix the REST door was shut and the GraphQL door returned the
// whole fleet.
func TestGraphQLEnforcesTheSameRBACGateAsREST(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	seedDevices(s, "", 4, "secret")

	// A custom role that can read reports but NOT infrastructure.
	mustDo(t, srv, "POST", "/api/roles", admin, map[string]any{
		"id": "reports-only", "name": "Reports Only",
		"permissions": map[string]int{"infrastructure": LevelNone, "reports": LevelRead},
	}, 201)
	mustDo(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "noinfra", "password": "Passw0rd!2345", "role": "reports-only",
	}, 201)
	weak := login(t, srv, "noinfra", "Passw0rd!2345").Token

	stREST, bREST := do(t, srv, "GET", "/api/devices", weak, nil)
	if stREST != http.StatusForbidden {
		t.Fatalf("REST /api/devices for an infrastructure:none principal = %d, want 403: %s", stREST, truncBody(bREST))
	}
	stGQL, _, rawGQL := gql(t, srv.URL, weak, "{devices{id}}", nil)
	if stGQL != http.StatusForbidden {
		t.Fatalf("GraphQL devices for the SAME principal = %d, want 403 — /api/graphql must not be a "+
			"second door into infrastructure data (F-72): %s", stGQL, truncBody(rawGQL))
	}
	if bytesContain(rawGQL, "secret-0000") {
		t.Fatal("GraphQL leaked device data to a principal with no infrastructure permission")
	}
}

func TestGraphQLRequiresAuthentication(t *testing.T) {
	srv, _ := newTestServerState(t)
	st, _, _ := gql(t, srv.URL, "", "{devices{id}}", nil)
	if st != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GraphQL = %d, want 401", st)
	}
}

// TestGraphQLRulesRefusedForScopedTenant: rules are platform-global. The old
// code handed a scoped caller an EMPTY list, which reads as "there are no
// rules" — a lie shaped like data. An honest refusal is an error.
func TestGraphQLRulesRefusedForScopedTenant(t *testing.T) {
	srv, _ := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	org := idOf(t, mustDo(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org Rules"}, 201))
	tenant := idOf(t, mustDo(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant Rules", "org_id": org}, 201))
	mustDo(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "scoped", "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenant}, 201)
	tok := login(t, srv, "scoped", "Passw0rd!2345").Token

	st, resp, raw := gql(t, srv.URL, tok, "{rules{id}}", nil)
	if st != http.StatusBadRequest || len(resp.Errors) == 0 {
		t.Fatalf("scoped `rules` = %d with %d errors, want 400 + an errors array: %s",
			st, len(resp.Errors), truncBody(raw))
	}
}

// ── CORRECTNESS: unknown fields, arguments, selection sets, variables ─────────

// TestGraphQLUnknownFieldIsAnError is the exact probe from the audit report:
// `{bogus}` used to be 200 + `{"data":{}}`.
func TestGraphQLUnknownFieldIsAnError(t *testing.T) {
	srv, _ := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	st, resp, raw := gql(t, srv.URL, admin, "{bogus}", nil)
	if st == http.StatusOK {
		t.Fatalf("`{bogus}` returned 200 — a spec-compliant client reads that as "+
			"\"success, no results\" (F-72): %s", truncBody(raw))
	}
	if len(resp.Errors) == 0 {
		t.Fatalf("`{bogus}` returned no `errors` array: %s", truncBody(raw))
	}
	if _, hasData := resp.Data["bogus"]; hasData {
		t.Fatal("`{bogus}` must not produce a data key")
	}
	if !bytesContain(raw, "bogus") {
		t.Errorf("the error does not name the unknown field: %s", truncBody(raw))
	}
}

// TestGraphQLArgumentsAreApplied is the other audit probe: the two queries below
// returned byte-identical 218 KB bodies before the fix.
func TestGraphQLArgumentsAreApplied(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	seedDevices(s, "", 50, "dev")

	st, resp, raw := gql(t, srv.URL, admin, "{devices(limit:1){id}}", nil)
	if st != 200 {
		t.Fatalf("status %d: %s", st, truncBody(raw))
	}
	var one []map[string]any
	if err := json.Unmarshal(resp.Data["devices"], &one); err != nil {
		t.Fatal(err)
	}
	if len(one) != 1 {
		t.Fatalf("devices(limit:1) returned %d rows — the argument is being ignored (F-72)", len(one))
	}

	// offset must actually move the window, and the walk must cover everything.
	seen := map[string]int{}
	for off := 0; off < 60; off += 10 {
		_, r, _ := gql(t, srv.URL, admin, fmt.Sprintf("{devices(limit:10, offset:%d){id}}", off), nil)
		var rows []map[string]any
		if err := json.Unmarshal(r.Data["devices"], &rows); err != nil {
			t.Fatal(err)
		}
		if off >= 50 && len(rows) != 0 {
			t.Fatalf("offset %d past 50 devices returned %d rows, want an empty page", off, len(rows))
		}
		for _, d := range rows {
			seen[fmt.Sprint(d["id"])]++
		}
	}
	if len(seen) != 50 {
		t.Fatalf("the offset walk reached %d distinct devices, want 50", len(seen))
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("device %s appeared %d times in the walk", id, n)
		}
	}
}

func TestGraphQLRejectsUnknownAndOutOfRangeArguments(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	seedDevices(s, "", 5, "dev")

	for _, tc := range []struct{ name, query, wantIn string }{
		{"relay arg the audit probed with", "{devices(first:1){id}}", "first"},
		{"unknown arg", "{devices(page_size:1){id}}", "page_size"},
		{"arg on a field that takes none", "{health(limit:1){status}}", "limit"},
		{"limit out of range", "{devices(limit:0){id}}", "limit"},
		{"limit above the ceiling", "{devices(limit:9999999){id}}", "limit"},
		{"limit of the wrong type", `{devices(limit:"ten"){id}}`, "limit"},
		{"negative offset", "{devices(offset:-1){id}}", "offset"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, resp, raw := gql(t, srv.URL, admin, tc.query, nil)
			if st != http.StatusBadRequest || len(resp.Errors) == 0 {
				t.Fatalf("%s = %d with %d errors, want 400 + errors: %s",
					tc.query, st, len(resp.Errors), truncBody(raw))
			}
			if !bytesContain(raw, tc.wantIn) {
				t.Errorf("error does not name %q: %s", tc.wantIn, truncBody(raw))
			}
		})
	}
}

// TestGraphQLHonoursTheSelectionSet: `{devices{id}}` used to serialize every
// field of every device.
func TestGraphQLHonoursTheSelectionSet(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	seedDevices(s, "", 3, "dev")

	st, resp, raw := gql(t, srv.URL, admin, "{devices(limit:1){id name}}", nil)
	if st != 200 {
		t.Fatalf("status %d: %s", st, truncBody(raw))
	}
	var rows []map[string]any
	if err := json.Unmarshal(resp.Data["devices"], &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	if len(rows[0]) != 2 {
		t.Fatalf("selection set {id name} produced %d fields (%v) — the whole struct is still being serialized",
			len(rows[0]), rows[0])
	}
	for _, k := range []string{"id", "name"} {
		if _, ok := rows[0][k]; !ok {
			t.Errorf("missing selected field %q", k)
		}
	}
	if _, leaked := rows[0]["address"]; leaked {
		t.Error("unselected field `address` was returned")
	}

	// Aliases resolve to the response key.
	_, aliased, _ := gql(t, srv.URL, admin, "{kit: devices(limit:1){deviceId: id}}", nil)
	var akeys []map[string]any
	if err := json.Unmarshal(aliased.Data["kit"], &akeys); err != nil {
		t.Fatalf("alias `kit` was not honoured: %v", err)
	}
	if _, ok := akeys[0]["deviceId"]; !ok {
		t.Errorf("field alias not honoured: %v", akeys[0])
	}
}

func TestGraphQLUnknownSubfieldIsAnError(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	seedDevices(s, "", 2, "dev")
	st, resp, raw := gql(t, srv.URL, admin, "{devices(limit:1){nayme}}", nil)
	if st != http.StatusBadRequest || len(resp.Errors) == 0 {
		t.Fatalf("a misspelled subfield = %d with %d errors, want 400 + errors: %s",
			st, len(resp.Errors), truncBody(raw))
	}
	if !bytesContain(raw, "nayme") {
		t.Errorf("error does not name the misspelled field: %s", truncBody(raw))
	}
}

// TestGraphQLVariablesAreReadAndValidated: `Variables` had ZERO read sites.
func TestGraphQLVariablesAreReadAndValidated(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	seedDevices(s, "", 30, "dev")

	st, resp, raw := gql(t, srv.URL, admin,
		"query Fleet($n: Int!) { devices(limit: $n) { id } }", map[string]any{"n": 3})
	if st != 200 {
		t.Fatalf("status %d: %s", st, truncBody(raw))
	}
	var rows []map[string]any
	if err := json.Unmarshal(resp.Data["devices"], &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("$n=3 produced %d rows — the variable was not read (F-72)", len(rows))
	}

	// A variable the document declares but the request omits is an error, not
	// a silently-defaulted limit.
	st, _, raw = gql(t, srv.URL, admin, "query Fleet($n: Int!) { devices(limit: $n) { id } }", map[string]any{})
	if st != http.StatusBadRequest {
		t.Fatalf("a missing variable = %d, want 400: %s", st, truncBody(raw))
	}
	// A variable the request supplies but the document never declares is an
	// error too — otherwise the caller believes an input was applied.
	st, _, raw = gql(t, srv.URL, admin, "{devices(limit:2){id}}", map[string]any{"n": 3})
	if st != http.StatusBadRequest {
		t.Fatalf("an undeclared variable = %d, want 400: %s", st, truncBody(raw))
	}
}

func TestGraphQLRefusesUnsupportedOperations(t *testing.T) {
	srv, _ := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	for _, tc := range []struct{ name, query string }{
		{"mutation", "mutation { deleteEverything }"},
		{"subscription", "subscription { devices { id } }"},
		{"fragment", "{devices{...F}} fragment F on Device { id }"},
		{"two operations", "query A { devices { id } } query B { alerts { id } }"},
		{"empty", ""},
		{"unbalanced braces", "{devices{id}"},
		{"garbage", "not a graphql document at all"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, resp, raw := gql(t, srv.URL, admin, tc.query, nil)
			if st != http.StatusBadRequest || len(resp.Errors) == 0 {
				t.Fatalf("%q = %d with %d errors, want 400 + errors: %s",
					tc.query, st, len(resp.Errors), truncBody(raw))
			}
		})
	}
}

// TestGraphQLTenantIsolation (§3a.5): the GraphQL door must scope exactly like
// the REST door, including when the caller pages through it.
func TestGraphQLTenantIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	orgA := idOf(t, mustDo(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org Alpha"}, 201))
	orgB := idOf(t, mustDo(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org Bravo"}, 201))
	tenantA := idOf(t, mustDo(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant Alpha", "org_id": orgA}, 201))
	tenantB := idOf(t, mustDo(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant Bravo", "org_id": orgB}, 201))
	mustDo(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "gql-a", "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantA}, 201)
	tokA := login(t, srv, "gql-a", "Passw0rd!2345").Token

	seedDevices(s, tenantA, 6, "a")
	seedDevices(s, tenantB, 9, "b")

	check := func(path string) {
		t.Helper()
		st, raw := doRaw(t, srv.URL, "POST", path, tokA, map[string]any{
			"query": "{devices(limit:500){id tenant_id}}"})
		if st != 200 {
			t.Fatalf("%s: status %d: %s", path, st, truncBody(raw))
		}
		var resp gqlResp
		if err := json.Unmarshal(raw, &resp); err != nil {
			t.Fatal(err)
		}
		var rows []map[string]any
		if err := json.Unmarshal(resp.Data["devices"], &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 6 {
			t.Fatalf("%s: tenant A sees %d devices, want its own 6", path, len(rows))
		}
		for _, d := range rows {
			if fmt.Sprint(d["tenant_id"]) != tenantA {
				t.Fatalf("%s: CROSS-TENANT LEAK — row owned by %v", path, d["tenant_id"])
			}
		}
	}
	check("/api/graphql")
	// as_tenant into another org must be ignored, never honoured.
	check("/api/graphql?as_tenant=" + tenantB)
}

// ── parser unit tests ────────────────────────────────────────────────────────
