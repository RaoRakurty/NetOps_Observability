// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// tunnels_restriction_test.go — the CLAUDE.md §3a rule-5 isolation test for the
// operator-visibility restriction (Tenant.OperatorRestricted) on the tunnel QoE
// surface, GET /api/tunnels.
//
// A tunnel row is the customer's overlay: the two endpoint device names, both
// endpoint addresses, and the measured latency / jitter / loss / QoE of the link
// between them. A tenant that has switched the restriction on is invisible to the
// platform owner in flows, findings, logs, metrics and the BMP feed, and must be
// invisible here too — in the Global view and under ?as_tenant.
//
// The fake ClickHouse here does not just record the SQL: it APPLIES the handler's
// WHERE clause to seeded rows, the way the server would. So a leak shows up as the
// restricted tenant's own bytes in the response body, named field by field.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/internal/discovery"
	"netops/backend/models"
)

// ── a ClickHouse that enforces the clause, so a leak is visible as bytes ──────

// tunnelRowFixture is one seeded netops.tunnels row.
type tunnelRowFixture struct {
	ID           string  `json:"id"`
	LocalDevice  string  `json:"local_device"`
	LocalAddr    string  `json:"local_addr"`
	RemoteDevice string  `json:"remote_device"`
	RemoteAddr   string  `json:"remote_addr"`
	Status       string  `json:"status"`
	QoE          float64 `json:"qoe"`
	LatencyMs    float64 `json:"latency_ms"`
}

// field reads one column of the row by its SQL name.
func (r tunnelRowFixture) field(col string) string {
	switch col {
	case "local_device":
		return r.LocalDevice
	case "remote_device":
		return r.RemoteDevice
	case "status":
		return r.Status
	default:
		return ""
	}
}

// sqlListValues pulls the quoted members out of an IN (...) list.
func sqlListValues(list string) []string {
	var out []string
	for _, part := range strings.Split(list, ",") {
		out = append(out, strings.Trim(strings.TrimSpace(part), "'"))
	}
	return out
}

// matchesTunnelCond evaluates ONE conjunct of the handler's WHERE clause. The
// handler emits exactly three shapes, so the model covers exactly three:
//
//	status = 'up'
//	(local_device IN (…) OR remote_device IN (…))
//	local_device NOT IN (…)            [and its remote_device twin]
func matchesTunnelCond(row tunnelRowFixture, cond string) bool {
	cond = strings.TrimSpace(cond)
	if strings.HasPrefix(cond, "(") && strings.HasSuffix(cond, ")") && strings.Contains(cond, " OR ") {
		for _, part := range strings.Split(strings.Trim(cond, "()"), " OR ") {
			if matchesTunnelCond(row, part) {
				return true
			}
		}
		return false
	}
	if col, list, ok := strings.Cut(cond, " NOT IN ("); ok {
		for _, v := range sqlListValues(strings.TrimSuffix(strings.TrimSpace(list), ")")) {
			if row.field(strings.TrimSpace(col)) == v {
				return false
			}
		}
		return true
	}
	if col, list, ok := strings.Cut(cond, " IN ("); ok {
		for _, v := range sqlListValues(strings.TrimSuffix(strings.TrimSpace(list), ")")) {
			if row.field(strings.TrimSpace(col)) == v {
				return true
			}
		}
		return false
	}
	if col, want, ok := strings.Cut(cond, " = "); ok {
		return row.field(strings.TrimSpace(col)) == strings.Trim(strings.TrimSpace(want), "'")
	}
	return true
}

// tunnelPolicyCH stands in for ClickHouse on the tunnel read: it applies the
// emitted WHERE clause to the seeded rows and serves the survivors in the
// FORMAT JSON envelope the handler proxies through.
func tunnelPolicyCH(t *testing.T, rows []tunnelRowFixture) (queries *[]string) {
	t.Helper()
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sql := string(b)
		got = append(got, sql)

		var conds []string
		if _, where, ok := strings.Cut(sql, " WHERE "); ok {
			where, _, _ = strings.Cut(where, "\n ORDER BY")
			conds = strings.Split(where, " AND ")
		}
		out := []tunnelRowFixture{}
		for _, row := range rows {
			keep := true
			for _, c := range conds {
				if !matchesTunnelCond(row, c) {
					keep = false
					break
				}
			}
			if keep {
				out = append(out, row)
			}
		}
		body, err := json.Marshal(map[string]any{"meta": []any{}, "data": out, "rows": len(out)})
		if err != nil {
			t.Errorf("marshal fake clickhouse body: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")
	return &got
}

// ── the isolation test ───────────────────────────────────────────────────────

// TestTunnelQoEHonoursTheOperatorVisibilityRestriction is the §3a rule-5 test for
// GET /api/tunnels. Both halves: the platform owner's Global view, and the owner
// scoped into the restricted tenant with ?as_tenant.
func TestTunnelQoEHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	rows := []tunnelRowFixture{
		{ID: "tun-acme-1", LocalDevice: "acme-edge-a", LocalAddr: "10.1.0.1",
			RemoteDevice: "acme-hub", RemoteAddr: "203.0.113.7", Status: "up",
			QoE: 41.5, LatencyMs: 118.7},
		{ID: "tun-globex-1", LocalDevice: "globex-edge-b", LocalAddr: "10.2.0.1",
			RemoteDevice: "globex-hub", RemoteAddr: "198.51.100.9", Status: "up",
			QoE: 92.25, LatencyMs: 12.5},
	}
	queries := tunnelPolicyCH(t, rows)

	ts, err := newTenantStore(filepath.Join(t.TempDir(), "tenants.json"))
	if err != nil {
		t.Fatalf("newTenantStore: %v", err)
	}
	acmeT, err := ts.Create("Acme", "acme", "", "", "")
	if err != nil {
		t.Fatalf("create acme: %v", err)
	}
	globexT, err := ts.Create("Globex", "globex", "", "", "")
	if err != nil {
		t.Fatalf("create globex: %v", err)
	}
	d := discovery.NewDiscoveryAggregator()
	d.Upsert(models.Device{ID: "acme-edge-a", Name: "acme-edge-a", Address: "10.1.0.1", TenantID: acmeT.ID})
	d.Upsert(models.Device{ID: "acme-hub", Name: "acme-hub", Address: "203.0.113.7", TenantID: acmeT.ID})
	d.Upsert(models.Device{ID: "globex-edge-b", Name: "globex-edge-b", Address: "10.2.0.1", TenantID: globexT.ID})
	d.Upsert(models.Device{ID: "globex-hub", Name: "globex-hub", Address: "198.51.100.9", TenantID: globexT.ID})
	s := &server{discovery: d, tenants: ts}

	get := func(claims jwtClaims) string {
		t.Helper()
		w := httptest.NewRecorder()
		s.handleTunnels(w, req(http.MethodGet, "/api/tunnels", "", claims))
		if w.Code != http.StatusOK {
			t.Fatalf("GET /api/tunnels = %d (%s)", w.Code, w.Body.String())
		}
		return w.Body.String()
	}

	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}

	// Baseline: before anything is restricted the owner reads BOTH overlays, so
	// this test cannot pass by serving nothing.
	base := get(owner)
	for _, want := range []string{"tun-acme-1", "acme-hub", "tun-globex-1", "globex-hub"} {
		if !strings.Contains(base, want) {
			t.Fatalf("baseline: owner Global view does not contain %q: %s", want, base)
		}
	}

	if _, err := ts.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}

	// ── half 1: the Global view. Acme's overlay is gone; globex's is intact.
	body := get(owner)
	for _, leak := range []string{
		"tun-acme-1",  // the tunnel id
		"acme-edge-a", // the local endpoint device
		"acme-hub",    // the remote endpoint device
		"203.0.113.7", // the remote endpoint address
		"41.5",        // the measured QoE score
		"118.7",       // the measured latency
	} {
		if strings.Contains(body, leak) {
			t.Errorf("RESTRICTION LEAK: the platform owner's Global tunnel view returned acme's %q: %s", leak, body)
		}
	}
	for _, want := range []string{"tun-globex-1", "globex-hub", "92.25"} {
		if !strings.Contains(body, want) {
			t.Errorf("restricting acme also hid globex's %q: %s", want, body)
		}
	}
	last := (*queries)[len(*queries)-1]
	if !strings.Contains(last, "local_device NOT IN ('acme-edge-a', 'acme-hub')") ||
		!strings.Contains(last, "remote_device NOT IN ('acme-edge-a', 'acme-hub')") {
		t.Errorf("the Global tunnel read does not exclude acme's endpoints at BOTH ends.\nSQL: %s", last)
	}
	if strings.Contains(last, "globex") {
		t.Errorf("the Global tunnel read excluded globex, which is not restricted.\nSQL: %s", last)
	}

	// ── half 2: ?as_tenant into the restricted tenant. Nothing at all, and NO
	// storage is read — the answer is decided before the first row.
	*queries = nil
	body = get(ownerActing(owner, acmeT.ID))
	if !strings.Contains(body, `"rows":0`) {
		t.Errorf("RESTRICTION LEAK: owner→acme tunnel view returned rows: %s", body)
	}
	for _, leak := range []string{"tun-acme-1", "acme-hub", "203.0.113.7", "41.5"} {
		if strings.Contains(body, leak) {
			t.Errorf("RESTRICTION LEAK: owner→acme tunnel view returned acme's %q: %s", leak, body)
		}
	}
	if len(*queries) != 0 {
		t.Errorf("owner→acme still read ClickHouse %d times: %v", len(*queries), *queries)
	}

	// The owner scoped into the UNRESTRICTED tenant still reads it.
	if body = get(ownerActing(owner, globexT.ID)); !strings.Contains(body, "tun-globex-1") {
		t.Errorf("owner→globex lost globex's own tunnel: %s", body)
	}

	// And acme's OWN user is never restricted from acme's own overlay — the
	// switch hides a tenant from the PLATFORM, never from itself.
	acmeUser := jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: acmeT.ID}
	body = get(acmeUser)
	if !strings.Contains(body, "tun-acme-1") || !strings.Contains(body, "41.5") {
		t.Fatalf("acme's own user lost its own tunnel QoE: %s", body)
	}
	if strings.Contains(body, "tun-globex-1") {
		t.Fatalf("acme's own user saw globex's tunnel: %s", body)
	}
}
