package backend

// vulns_pagination_test.go — regression guards for audit F-79.
//
// Measured live: `/api/vulns` default returned `findings: 500` while
// `summary.findings` said 7,560, and `?limit=2000` (the hard ceiling) returned
// 2,000. **5,560 findings were unreachable at ANY limit** — there was no offset
// and no cursor. Teams triaged 6.6% of fleet exposure believing it was all of
// it. `unassessed` had no bound at all.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"netops/backend/internal/vuln"
	"netops/backend/models"
)

type vulnsBody struct {
	Enabled bool `json:"vuln_enabled"`
	Summary struct {
		Devices  int `json:"devices"`
		Findings int `json:"findings"`
	} `json:"summary"`
	Findings []struct {
		DeviceID string `json:"device_id"`
		CVE      string `json:"cve"`
	} `json:"findings"`
	Unassessed []struct {
		DeviceID string `json:"device_id"`
	} `json:"unassessed"`
	Page struct {
		Limit             int  `json:"limit"`
		Offset            int  `json:"offset"`
		MaxLimit          int  `json:"max_limit"`
		Returned          int  `json:"returned"`
		Total             int  `json:"total"`
		Complete          bool `json:"complete"`
		UnassessedTotal   int  `json:"unassessed_total"`
		UnassessedPartial bool `json:"unassessed_partial"`
	} `json:"page"`
}

// seedVulnFleet wires a feed with one CVE per vendor/product and n devices that
// all match it, so `n` findings exist deterministically.
func seedVulnFleet(t *testing.T, s *server, tenant string, n int, prefix string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "advisories.csv")
	csvData := `vendor,product,cve,severity,cvss,ver_start_incl,ver_start_excl,ver_end_incl,ver_end_excl,ver_exact,kev,published,summary
arista,eos,CVE-2024-0002,high,8.1,4.30.0,,,4.33.2,,0,2024-02-20,Range DoS
`
	if err := os.WriteFile(path, []byte(csvData), 0o600); err != nil {
		t.Fatal(err)
	}
	s.vulns = vuln.NewFeed(path, nil, nil)
	for i := 0; i < n; i++ {
		s.discovery.Upsert(models.Device{
			ID:       fmt.Sprintf("%s-%04d", prefix, i),
			Name:     fmt.Sprintf("%s-%04d", prefix, i),
			Address:  fmt.Sprintf("10.8.%d.%d", i/250, i%250),
			Vendor:   "arista",
			OS:       "Arista Networks EOS version 4.33.1F running on an Arista DCS-7050",
			TenantID: tenant,
			Source:   "test",
		})
	}
}

// TestVulnsOffsetMakesEveryFindingReachable is the F-79 core: with only a limit,
// finding number limit+1 could never be retrieved.
func TestVulnsOffsetMakesEveryFindingReachable(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	const total = 120
	seedVulnFleet(t, s, "", total, "vd")

	// Default page (no params) must state the true total AND that it is partial.
	st, b := do(t, srv, "GET", "/api/vulns?limit=50", admin, nil)
	if st != 200 {
		t.Fatalf("status %d: %s", st, truncBody(b))
	}
	var first vulnsBody
	if err := json.Unmarshal(b, &first); err != nil {
		t.Fatalf("decode: %v (%s)", err, truncBody(b))
	}
	if first.Summary.Findings != total || first.Page.Total != total {
		t.Fatalf("summary.findings=%d page.total=%d, want %d", first.Summary.Findings, first.Page.Total, total)
	}
	if len(first.Findings) != 50 {
		t.Fatalf("limit=50 returned %d findings", len(first.Findings))
	}
	if first.Page.Complete {
		t.Fatal("a 50-of-120 response reported complete=true — the exact lie that hid 5,560 findings")
	}

	// The walk: every finding reachable, exactly once, and an empty page past
	// the end rather than a clamped repeat.
	seen := map[string]int{}
	const limit = 25
	for offset := 0; offset < total+limit; offset += limit {
		st, b := do(t, srv, "GET", fmt.Sprintf("/api/vulns?limit=%d&offset=%d", limit, offset), admin, nil)
		if st != 200 {
			t.Fatalf("offset %d: status %d: %s", offset, st, truncBody(b))
		}
		var page vulnsBody
		if err := json.Unmarshal(b, &page); err != nil {
			t.Fatal(err)
		}
		if page.Page.Total != total {
			t.Fatalf("offset %d reported total=%d, want %d", offset, page.Page.Total, total)
		}
		if offset >= total {
			if len(page.Findings) != 0 {
				t.Fatalf("offset %d past %d findings returned %d, want an empty page",
					offset, total, len(page.Findings))
			}
			continue
		}
		for _, f := range page.Findings {
			seen[f.DeviceID+"|"+f.CVE]++
		}
	}
	if len(seen) != total {
		t.Fatalf("the offset walk reached %d of %d findings — %d are still unreachable (F-79)",
			len(seen), total, total-len(seen))
	}
	for k, n := range seen {
		if n != 1 {
			t.Fatalf("finding %s returned %d times across the walk", k, n)
		}
	}
}

// TestVulnsUnassessedIsBoundedAndReportsItsTotal: `unassessed` had NO limit.
func TestVulnsUnassessedIsBoundedAndReportsItsTotal(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	seedVulnFleet(t, s, "", 2, "vd")
	// 40 devices with no vendor → 40 unassessed rows. Names and addresses must
	// be distinct: dedupeDevices unions records that share ANY stable identity.
	for i := 0; i < 40; i++ {
		s.discovery.Upsert(models.Device{
			ID:      fmt.Sprintf("blind-%03d", i),
			Name:    fmt.Sprintf("blind-%03d", i),
			Address: fmt.Sprintf("10.7.%d.%d", i/250, i%250),
			Source:  "test"})
	}
	st, b := do(t, srv, "GET", "/api/vulns?limit=10", admin, nil)
	if st != 200 {
		t.Fatalf("status %d: %s", st, truncBody(b))
	}
	var body vulnsBody
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatal(err)
	}
	if body.Page.UnassessedTotal != 40 {
		t.Fatalf("unassessed_total = %d, want 40", body.Page.UnassessedTotal)
	}
	if len(body.Unassessed) > 10 {
		t.Fatalf("unassessed returned %d rows for limit=10 — it used to be unbounded", len(body.Unassessed))
	}
	if !body.Page.UnassessedPartial {
		t.Fatal("a 10-of-40 unassessed list did not report itself as partial")
	}
}

func TestVulnsRejectsBadParams(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	seedVulnFleet(t, s, "", 3, "vd")
	for _, tc := range []struct{ name, query, wantIn string }{
		{"unknown param", "?cursor=abc", "cursor"},
		{"limit above the ceiling", "?limit=100000", "limit"},
		{"limit zero", "?limit=0", "limit"},
		{"negative offset", "?offset=-5", "offset"},
		{"offset garbage", "?offset=next", "offset"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, b := do(t, srv, "GET", "/api/vulns"+tc.query, admin, nil)
			if st != http.StatusBadRequest {
				t.Fatalf("GET /api/vulns%s = %d, want 400: %s", tc.query, st, truncBody(b))
			}
			if !bytesContain(b, tc.wantIn) {
				t.Errorf("400 body %s does not name %q", truncBody(b), tc.wantIn)
			}
		})
	}
}

// TestVulnsTenantIsolation (§3a.5): findings, the summary counts AND the paged
// total are all scoped to the caller.
func TestVulnsTenantIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	orgA := idOf(t, mustDo(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org Alpha"}, 201))
	orgB := idOf(t, mustDo(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org Bravo"}, 201))
	tenantA := idOf(t, mustDo(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant Alpha", "org_id": orgA}, 201))
	tenantB := idOf(t, mustDo(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant Bravo", "org_id": orgB}, 201))
	mustDo(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "vuln-a", "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantA}, 201)
	tokA := login(t, srv, "vuln-a", "Passw0rd!2345").Token

	seedVulnFleet(t, s, tenantA, 7, "a")
	// Same feed, org B's devices.
	for i := 0; i < 25; i++ {
		s.discovery.Upsert(models.Device{
			ID: fmt.Sprintf("b-%04d", i), Name: "b", Address: "10.6.0.1", Vendor: "arista",
			OS:       "Arista Networks EOS version 4.33.1F running on an Arista DCS-7050",
			TenantID: tenantB, Source: "test"})
	}

	check := func(path string) {
		t.Helper()
		st, b := do(t, srv, "GET", path, tokA, nil)
		if st != 200 {
			t.Fatalf("%s: status %d: %s", path, st, truncBody(b))
		}
		var body vulnsBody
		if err := json.Unmarshal(b, &body); err != nil {
			t.Fatal(err)
		}
		if body.Page.Total != 7 || body.Summary.Findings != 7 || body.Summary.Devices != 7 {
			t.Fatalf("%s: tenant A sees total=%d summary.findings=%d devices=%d, want 7/7/7 — "+
				"the total must be scoped like the rows", path, body.Page.Total,
				body.Summary.Findings, body.Summary.Devices)
		}
		for _, f := range body.Findings {
			if len(f.DeviceID) > 0 && f.DeviceID[0] == 'b' {
				t.Fatalf("%s: CROSS-TENANT LEAK — finding on org B device %s", path, f.DeviceID)
			}
		}
	}
	check("/api/vulns?limit=500")
	check("/api/vulns?limit=500&as_tenant=" + tenantB) // narrowing must never widen
	// paging must not become a way around the scope
	for offset := 0; offset < 40; offset += 5 {
		check(fmt.Sprintf("/api/vulns?limit=5&offset=%d", offset))
	}
}
