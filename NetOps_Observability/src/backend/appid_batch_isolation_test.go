// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"netops/backend/appid"
	"testing"

	"netops/backend/cloud"
)

// CLAUDE.md §3a mandatory (template: org_isolation_test.go): the batch resolver
// (#81 P3G) is tenant-scoped default-closed — tenant A's cloud identity
// mappings must NEVER resolve for a non-cross tenant B; the platform owner
// (cross) may resolve across buckets. The batch endpoint rides principalTenant
// exactly like the single resolve.

func batchTestServer(t *testing.T) *server {
	t.Helper()
	roles, err := newRoleStore(t.TempDir() + "/roles.json")
	if err != nil {
		t.Fatalf("roleStore: %v", err)
	}
	r := appid.NewCloudResolver(nil)
	r.SeedForTest([]cloud.CloudIdentityMapping{
		{TenantID: "acme", MatchKeyType: cloud.MatchPrivateIP, MatchKey: "10.0.1.10", AppName: "billing", Source: cloud.SrcCloudTag, Confidence: cloud.Confirmed},
		{TenantID: "globex", MatchKeyType: cloud.MatchPrivateIP, MatchKey: "10.9.9.9", AppName: "payroll", Source: cloud.SrcCloudTag, Confidence: cloud.Confirmed},
	})
	return &server{roles: roles, cloudApp: r}
}

func postBatch(t *testing.T, s *server, claims jwtClaims, body string) (int, map[string]appIDBatchVerdict) {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleAppIDResolveBatch(w, req(http.MethodPost, "/api/appid/resolve/batch", body, claims))
	out := map[string]appIDBatchVerdict{}
	if w.Code == http.StatusOK {
		if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	return w.Code, out
}

func TestAppIDResolveBatchTenantIsolation(t *testing.T) {
	s := batchTestServer(t)
	keys := `{"keys":["10.0.1.10","10.9.9.9","8.8.8.8"]}`

	// 1) scoped acme resolves ONLY its own mapping; globex's key and the
	// uncatalogued IP are simply absent (no "unknown" rows, no leak).
	st, out := postBatch(t, s, acme(), keys)
	if st != http.StatusOK {
		t.Fatalf("acme batch status = %d", st)
	}
	if v, ok := out["10.0.1.10"]; !ok || v.App != "billing" || v.Source != "cloud_tag" {
		t.Fatalf("acme own key: %+v (ok=%v)", v, ok)
	}
	if _, leak := out["10.9.9.9"]; leak {
		t.Fatal("TENANT LEAK: acme resolved globex's cloud identity mapping")
	}
	if _, spam := out["8.8.8.8"]; spam {
		t.Fatal("unresolved key must be omitted, never guessed")
	}

	// 2) scoped globex: the mirror view.
	_, out = postBatch(t, s, globex(), keys)
	if v, ok := out["10.9.9.9"]; !ok || v.App != "payroll" {
		t.Fatalf("globex own key: %+v (ok=%v)", v, ok)
	}
	if _, leak := out["10.0.1.10"]; leak {
		t.Fatal("TENANT LEAK: globex resolved acme's cloud identity mapping")
	}

	// 3) platform owner (cross) sees both tenants' mappings.
	_, out = postBatch(t, s, superA(), keys)
	if len(out) != 2 {
		t.Fatalf("cross batch = %d entries, want 2: %+v", len(out), out)
	}
}

func TestAppIDResolveBatchValidation(t *testing.T) {
	s := batchTestServer(t)

	// method gate
	w := httptest.NewRecorder()
	s.handleAppIDResolveBatch(w, req(http.MethodGet, "/api/appid/resolve/batch", "", acme()))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d, want 405", w.Code)
	}

	// empty / missing keys
	if st, _ := postBatch(t, s, acme(), `{"keys":[]}`); st != http.StatusBadRequest {
		t.Fatalf("empty keys status = %d, want 400", st)
	}
	// malformed JSON
	if st, _ := postBatch(t, s, acme(), `{"keys": nope`); st != http.StatusBadRequest {
		t.Fatalf("bad json status = %d, want 400", st)
	}
	// charset violation (shape-validated, injection-safe)
	if st, _ := postBatch(t, s, acme(), `{"keys":["1.2.3.4; DROP TABLE x"]}`); st != http.StatusBadRequest {
		t.Fatalf("charset-invalid key status = %d, want 400", st)
	}
	// charset-valid but not an IP
	if st, _ := postBatch(t, s, acme(), `{"keys":["1.2.3"]}`); st != http.StatusBadRequest {
		t.Fatalf("non-IP key status = %d, want 400", st)
	}
	// cap: 201 keys → 400
	over := `{"keys":[`
	for i := 0; i <= appIDBatchMaxKeys; i++ {
		if i > 0 {
			over += ","
		}
		over += `"10.0.0.1"`
	}
	over += `]}`
	if st, _ := postBatch(t, s, acme(), over); st != http.StatusBadRequest {
		t.Fatalf("over-cap status = %d, want 400", st)
	}
	// duplicate keys dedupe into one entry, no error
	st, out := postBatch(t, s, acme(), `{"keys":["10.0.1.10","10.0.1.10"]}`)
	if st != http.StatusOK || len(out) != 1 {
		t.Fatalf("dedupe: status=%d entries=%d", st, len(out))
	}
}
