// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// tunnels_fold_isolation_test.go — the CLAUDE.md §3a rule-5 isolation test for
// the folded SD-WAN tunnel view on GET /api/tunnels (Paths P4): rows, matrix
// sites, quality and cases.
//
// The two orgs here run IDENTICAL overlays — same system-ips, same colours,
// so the same canonical tunnel id — which is exactly the case a key without
// the tenant would merge. The fake VictoriaMetrics and ClickHouse LIE: they
// return both orgs' series and objects whatever scope they are asked for, so
// the test proves the join itself refuses a foreign row, and separately
// asserts that the caller's own scope went out on the wire.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/collectors"
	"netops/backend/internal/discovery"
	"netops/backend/models"
	"netops/backend/topology"
)

const foldTID = "10.255.255.20/mpls|10.255.255.51/mpls"

type foldFakes struct {
	mu        sync.Mutex
	vmFilters [][]string
	chScopes  []string
	chSQL     []string
	vmDown    bool
	chDown    bool
}

// foldWorld seeds two orgs with identical overlays and lying backends.
func foldWorld(t *testing.T) (*server, *foldFakes, string, string) {
	t.Helper()
	ts, err := newTenantStore(filepath.Join(t.TempDir(), "tenants.json"))
	if err != nil {
		t.Fatalf("newTenantStore: %v", err)
	}
	acmeT, err := ts.Create("Acme", "acme", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	globexT, err := ts.Create("Globex", "globex", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	d := discovery.NewDiscoveryAggregator()
	facts := map[string]collectors.OverlayDeviceFacts{}
	devTenant := map[string]string{}
	res := topology.OverlayResult{SystemIPs: map[string]map[string]string{}, DeviceSites: map[string]string{}}
	for _, org := range []struct{ prefix, tenant, siteLabel string }{
		{"acme", acmeT.ID, "Acme HQ"}, {"globex", globexT.ID, "Globex HQ"},
	} {
		a, b := org.prefix+"-e20", org.prefix+"-e51"
		d.Upsert(models.Device{ID: a, Name: a, TenantID: org.tenant, Labels: map[string]string{"site": org.siteLabel}})
		d.Upsert(models.Device{ID: b, Name: b, TenantID: org.tenant, Labels: map[string]string{"site": org.siteLabel}})
		tn := normTenant(org.tenant)
		devTenant[a], devTenant[b] = tn, tn
		res.SystemIPs[tn] = map[string]string{"10.255.255.20": a, "10.255.255.51": b}
		up := 1
		if org.prefix == "globex" {
			up = 0 // globex's tunnel is DOWN: a mixed fold would show it
		}
		facts[a] = collectors.OverlayDeviceFacts{DeviceID: a, SystemIP: "10.255.255.20", Source: collectors.OverlaySourceController,
			Peers: []collectors.OverlayPeer{{SystemIP: "10.255.255.51", TLOCAddrs: []string{"198.51.100.51"},
				ColorPairs: []collectors.OverlayColorPairs{{LocalColor: "mpls", RemoteColor: "mpls", Sessions: 1, Up: up}}}}}
		facts[b] = collectors.OverlayDeviceFacts{DeviceID: b, SystemIP: "10.255.255.51", Source: collectors.OverlaySourceController,
			Peers: []collectors.OverlayPeer{{SystemIP: "10.255.255.20", TLOCAddrs: []string{"198.51.100.20"},
				ColorPairs: []collectors.OverlayColorPairs{{LocalColor: "mpls", RemoteColor: "mpls", Sessions: 1, Up: up}}}}}
	}
	s := &server{discovery: d, tenants: ts}
	snap, _ := newSDWANOverlaySnapshot(time.Unix(1_800_000_000, 0), res, facts, devTenant)
	s.sdwanOverlay.Store(snap)

	f := &foldFakes{}
	// VictoriaMetrics: both orgs' series, whatever filters arrive. Acme
	// 0.137, globex 63.21 — a foreign join would show 63.21.
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.vmFilters = append(f.vmFilters, r.URL.Query()["extra_filters[]"])
		down := f.vmDown
		f.mu.Unlock()
		if down {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		q := r.URL.Query().Get("query")
		var result []map[string]any
		for _, org := range []struct {
			tenant string
			loss   string
		}{{acmeT.ID, "0.137"}, {globexT.ID, "63.21"}} {
			for _, rep := range [][2]string{{"10.255.255.20", "10.255.255.51"}, {"10.255.255.51", "10.255.255.20"}} {
				labels := map[string]string{"tenant_id": org.tenant, "controller_device": rep[0], "peer": rep[1],
					"local_color": "mpls", "remote_color": "mpls"}
				val := "1799990000"
				if strings.HasPrefix(q, "last_over_time") {
					labels["__name__"] = "controller_metric_tunnel_loss_pct"
					val = org.loss
				}
				result = append(result, map[string]any{"metric": labels, "value": []any{1_800_000_000, val}})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "vector", "result": result}})
	}))
	t.Cleanup(vm.Close)
	t.Setenv("VICTORIA_URL", vm.URL)

	// ClickHouse: the netops.tunnels read is empty; corr_current returns both
	// orgs' open objects naming the same tunnel id.
	ch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sql := string(b)
		f.mu.Lock()
		f.chScopes = append(f.chScopes, r.URL.Query().Get("tenant_scope"))
		f.chSQL = append(f.chSQL, sql)
		down := f.chDown && strings.Contains(sql, "corr_current")
		f.mu.Unlock()
		if down {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		rows := []map[string]any{}
		if strings.Contains(sql, "corr_current") {
			rows = append(rows,
				map[string]any{"id": "11111111-1111-1111-1111-111111111111", "tier": "suspected", "tenant_id": acmeT.ID,
					"created": "1799999000", "paths": []any{foldTID + "@ci-aaaaaaaaaaaaaaaa"}},
				map[string]any{"id": "99999999-9999-9999-9999-999999999999", "tier": "confirmed", "tenant_id": globexT.ID,
					"created": "1799999500", "paths": []any{foldTID}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"meta": []any{}, "data": rows, "rows": len(rows)})
	}))
	t.Cleanup(ch.Close)
	t.Setenv("CLICKHOUSE_URL", ch.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")
	return s, f, acmeT.ID, globexT.ID
}

type foldBody struct {
	Data    []map[string]any `json:"data"`
	Rows    int              `json:"rows"`
	Total   int              `json:"total"`
	Quality struct {
		Status string `json:"status"`
	} `json:"quality"`
	Cases struct {
		Status string `json:"status"`
	} `json:"cases"`
	Matrix *struct {
		Sites []struct {
			Label string `json:"label"`
		} `json:"sites"`
		Cells []map[string]any `json:"cells"`
	} `json:"matrix"`
}

func foldGet(t *testing.T, s *server, path string, claims jwtClaims) (foldBody, string) {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleTunnels(w, req(http.MethodGet, path, "", claims))
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s = %d (%s)", path, w.Code, w.Body.String())
	}
	var b foldBody
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	return b, w.Body.String()
}

func TestFoldedTunnelsAreTheCallersOwnOnly(t *testing.T) {
	s, f, acmeID, globexID := foldWorld(t)
	acmeUser := jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: acmeID}
	b, raw := foldGet(t, s, "/api/tunnels?include=matrix", acmeUser)

	if len(b.Data) != 1 {
		t.Fatalf("acme must see ONE folded tunnel, got %d: %s", len(b.Data), raw)
	}
	row := b.Data[0]
	if row["tunnel_id"] != foldTID || row["state"] != "up" || row["ends_reported"] != float64(2) {
		t.Fatalf("acme's tunnel mixed with globex's (globex is down): %v", row)
	}
	for _, leak := range []string{"globex", globexID, "63.21", "99999999-9999-9999-9999-999999999999", "Globex HQ"} {
		if strings.Contains(raw, leak) {
			t.Errorf("CROSS-TENANT LEAK: acme's tunnel view carries %q: %s", leak, raw)
		}
	}
	q, _ := row["quality"].(map[string]any)
	if q == nil || q["loss_pct"] != 0.137 || row["measured"] != true {
		t.Fatalf("acme's own quality must join: %v", row["quality"])
	}
	c, _ := row["case"].(map[string]any)
	if c == nil || c["id"] != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("acme's own case must attach: %v", row["case"])
	}
	if b.Matrix == nil || len(b.Matrix.Sites) != 1 || b.Matrix.Sites[0].Label != "Acme HQ" || len(b.Matrix.Cells) != 1 {
		t.Fatalf("matrix must hold acme's site only: %+v", b.Matrix)
	}

	// The caller's own scope went out on the wire, to both stores.
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.vmFilters) != 2 {
		t.Fatalf("want 2 VictoriaMetrics reads, got %d", len(f.vmFilters))
	}
	for _, fl := range f.vmFilters {
		if len(fl) == 0 {
			t.Errorf("a VictoriaMetrics read went out with NO tenant filter")
		}
		for _, x := range fl {
			if strings.Contains(x, "globex") {
				t.Errorf("acme's VictoriaMetrics filter names globex: %v", fl)
			}
		}
	}
	for i, sc := range f.chScopes {
		if sc != normTenant(acmeID) && sc != acmeID {
			t.Errorf("ClickHouse read %d ran at scope %q, want acme's (%s)", i, sc, f.chSQL[i])
		}
	}
}

func TestFoldedTunnelsGlobexSideAndAsTenantIgnored(t *testing.T) {
	s, _, acmeID, globexID := foldWorld(t)
	globexUser := jwtClaims{Sub: "g@globex", Role: RoleOperator, Tenant: globexID}
	b, raw := foldGet(t, s, "/api/tunnels?include=matrix&as_tenant="+acmeID, globexUser)
	if len(b.Data) != 1 || b.Data[0]["state"] != "down" {
		t.Fatalf("globex must see its own (down) tunnel only: %s", raw)
	}
	for _, leak := range []string{"acme-e", "Acme HQ", "11111111-1111-1111-1111-111111111111", "0.137"} {
		if strings.Contains(raw, leak) {
			t.Errorf("as_tenant widened globex into acme: %q in %s", leak, raw)
		}
	}
}

func TestFoldedTunnelsHonourTheOperatorRestriction(t *testing.T) {
	s, f, acmeID, globexID := foldWorld(t)
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}
	b, raw := foldGet(t, s, "/api/tunnels?include=matrix", owner)
	if len(b.Data) != 2 {
		t.Fatalf("baseline: the owner sees both orgs' tunnels as two rows: %s", raw)
	}
	if b.Data[0]["id"] == b.Data[1]["id"] {
		t.Fatalf("two orgs' identical tunnels share a row id: %s", raw)
	}
	if _, err := s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatal(err)
	}
	b, raw = foldGet(t, s, "/api/tunnels?include=matrix", owner)
	if len(b.Data) != 1 || strings.Contains(raw, "acme-e") || strings.Contains(raw, "Acme HQ") {
		t.Fatalf("RESTRICTION LEAK: owner Global view still shows acme's overlay: %s", raw)
	}
	f.mu.Lock()
	f.chSQL = nil
	f.mu.Unlock()
	b, raw = foldGet(t, s, "/api/tunnels?include=matrix", ownerActing(owner, acmeID))
	if len(b.Data) != 0 || strings.Contains(raw, "acme-e") {
		t.Fatalf("RESTRICTION LEAK: owner→acme read acme's tunnels: %s", raw)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.chSQL) != 0 {
		t.Errorf("owner→acme still read ClickHouse: %v", f.chSQL)
	}
	_ = globexID
}

func TestFoldedTunnelsDegradeHonestlyWhenAStoreIsDown(t *testing.T) {
	s, f, acmeID, _ := foldWorld(t)
	f.vmDown, f.chDown = true, true
	acmeUser := jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: acmeID}
	b, raw := foldGet(t, s, "/api/tunnels", acmeUser)
	if b.Quality.Status != "unavailable" || b.Cases.Status != "unavailable" {
		t.Fatalf("a failed read must say unavailable: %s", raw)
	}
	if len(b.Data) != 1 || b.Data[0]["measured"] != false || b.Data[0]["quality"] != nil || b.Data[0]["case"] != nil ||
		b.Data[0]["loss_pct"] != float64(0) {
		t.Fatalf("an unread quality is a dash, never a reading: %s", raw)
	}
	if b.Matrix != nil {
		t.Fatalf("no matrix unless asked: %s", raw)
	}
}

func TestFoldedTunnelsStatusFilterAndLimitApplyAfterTheMatrix(t *testing.T) {
	s, _, _, _ := foldWorld(t)
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}
	b, raw := foldGet(t, s, "/api/tunnels?include=matrix&status=down", owner)
	if len(b.Data) != 1 || b.Data[0]["status"] != "down" || b.Total != 1 {
		t.Fatalf("status=down: %s", raw)
	}
	if b.Matrix == nil || len(b.Matrix.Sites) != 2 {
		t.Fatalf("the matrix covers every visible tunnel, not the filtered page: %s", raw)
	}
	b, raw = foldGet(t, s, "/api/tunnels?limit=1", owner)
	if len(b.Data) != 1 || b.Total != 2 || !strings.Contains(raw, `"truncated":true`) {
		t.Fatalf("limit: %s", raw)
	}
}
