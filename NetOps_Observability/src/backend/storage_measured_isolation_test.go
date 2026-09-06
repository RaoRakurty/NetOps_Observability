// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// storage_measured_isolation_test.go — CROSS-ORG isolation for the MEASURED
// storage surface (CLAUDE.md §3a rule 5), exercised through the REAL router,
// the REAL auth middleware and the REAL gate the running system uses.
//
// The route under test, spelled out literally so the coverage guard in
// route_isolation_coverage_test.go can see it:
//
//	/api/system/storage/measured
//
// WHY THIS TEST MATTERS BEYOND THE USUAL. Storage volume is business
// intelligence: how many bytes a tenant's telemetry occupies says how big that
// customer is. It is exactly the class of fact §3a exists to keep in its own
// lane, and it is easy to leak by accident because the two tenant-partitioned
// stores are addressed by NAME (an index name, a partition value) rather than
// by a row the database filters for you.
//
// What is proved here:
//
//   - own-only: a tenant admin's report carries readings for THEIR tenant (plus
//     the shared untagged lane, which is in their own read pattern) and no
//     other tenant's scope, in any store;
//   - the storage layer is narrowed BEFORE the query leaves the process: the
//     OpenSearch `_cat` pattern the handler asked for names only the caller's
//     own indices, and the ClickHouse SQL carries the caller's partition
//     prefix — asserted on what the fake stores were ASKED, not only on what
//     came back;
//   - a HOSTILE store cannot leak: the fakes answer a scoped request with every
//     tenant's rows, and the report still carries only the caller's own;
//   - `as_tenant` into another org is ignored — this route reads no tenant
//     selector at all, so the answer stays the caller's own;
//   - the platform owner sees every tenant;
//   - the four stores that are NOT tenant-partitioned on disk return a scoped
//     caller a nil and a reason, never a pro-rata share and never a zero.

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/oslog"
	"netops/backend/internal/storagemeter"
)

// storageFakeStores records what each store was ASKED and answers with EVERY
// tenant's rows regardless — a deliberately hostile store, so the test proves
// the scoping rather than the fake's politeness.
type storageFakeStores struct {
	// tenantA/tenantB are the ids the fakes speak. Fields, not package vars:
	// two tests use this fake and a shared global would make one depend on the
	// other's ordering (CLAUDE.md §5 — no global state, tests included).
	tenantA, tenantB string

	mu       sync.Mutex
	catPaths []string
	sql      []string
}

func (f *storageFakeStores) openSearch(_ context.Context, path string, out any) error {
	f.mu.Lock()
	f.catPaths = append(f.catPaths, path)
	f.mu.Unlock()
	rows := []map[string]string{
		{"index": "netops-syslog-" + f.tenantA + "-2026.09.06", "store.size": "1000", "docs.count": "10"},
		{"index": "netops-syslog-" + f.tenantB + "-2026.09.06", "store.size": "999999", "docs.count": "99"},
		{"index": "netops-syslog-untagged-2026.09.06", "store.size": "300", "docs.count": "3"},
	}
	blob, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	return json.Unmarshal(blob, out)
}

func (f *storageFakeStores) clickHouse(_ context.Context, sql string) ([]map[string]any, error) {
	f.mu.Lock()
	f.sql = append(f.sql, sql)
	f.mu.Unlock()
	return []map[string]any{
		{"database": "netops", "table": "corr_signals",
			"partition": "('" + f.tenantA + "',20260906)", "bytes": "2000", "rows": "20", "uncompressed": "8000"},
		{"database": "netops", "table": "corr_signals",
			"partition": "('" + f.tenantB + "',20260906)", "bytes": "888888", "rows": "88", "uncompressed": "999999"},
	}, nil
}

type storageReport struct {
	Scope              string `json:"scope"`
	CrossTenant        bool   `json:"cross_tenant"`
	TotalMeasuredBytes int64  `json:"total_measured_bytes"`
	MeasurementNote    string `json:"measurement_note"`
	UnmeasuredStores   []string
	Readings           []struct {
		Store       string `json:"store"`
		Scope       string `json:"scope"`
		BytesOnDisk *int64 `json:"bytes_on_disk"`
		Detail      string `json:"detail"`
		Source      string `json:"source"`
	} `json:"readings"`
}

func decodeStorageReport(t *testing.T, body []byte) storageReport {
	t.Helper()
	var v storageReport
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("decode storage report: %v (body %s)", err, body)
	}
	return v
}

// installStorageFakes replaces the server's meter with one wired to the fakes
// but to the REAL gate and the REAL pattern/segment derivations — the part
// under test.
func installStorageFakes(s *server, f *storageFakeStores) {
	s.storageMeter = storagemeter.New(storagemeter.Deps{
		Now:         func() time.Time { return time.Now().UTC() },
		Gate:        s.storageMeterGate,
		OpenSearch:  f.openSearch,
		CatPattern:  oslog.TenantCatPattern,
		IndexTenant: indexTenantSegment,
		ClickHouse:  f.clickHouse,
		Database:    storageMeterDatabase,
	})
}

func TestStorageMeasuredCrossOrgIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	type org struct{ orgID, tenantID, token string }
	fix := map[string]*org{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Storage Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Storage Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "storage-admin-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "admin", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &org{orgID: orgID, tenantID: tenantID, token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	f := &storageFakeStores{tenantA: fix["A"].tenantID, tenantB: fix["B"].tenantID}
	installStorageFakes(s, f)

	// ── own-only ────────────────────────────────────────────────────────────
	st, b := do(t, srv, "GET", "/api/system/storage/measured", fix["A"].token, nil)
	if st != 200 {
		t.Fatalf("A reads its own storage: %d %s", st, b)
	}
	v := decodeStorageReport(t, b)
	if v.CrossTenant || v.Scope != fix["A"].tenantID {
		t.Fatalf("A got scope=%q cross=%v, want its own tenant", v.Scope, v.CrossTenant)
	}
	sawOwn := false
	for _, r := range v.Readings {
		switch r.Scope {
		case fix["A"].tenantID:
			if r.BytesOnDisk != nil {
				sawOwn = true
			}
		case storagemeter.ScopeUntagged, storagemeter.ScopePlatform:
			// The shared untagged lane is in A's own read pattern; the platform
			// scope only ever carries a NOT-MEASURED reading for a scoped caller.
			if r.Scope == storagemeter.ScopePlatform && r.BytesOnDisk != nil {
				t.Fatalf("a scoped caller was handed a measured PLATFORM number: %+v", r)
			}
		default:
			t.Fatalf("CROSS-TENANT LEAK: A was handed a %q reading (%s)", r.Scope, r.Store)
		}
	}
	if !sawOwn {
		t.Fatal("A sees no measured rows at all — the fixture did not land and this guard would pass vacuously")
	}
	// A's total must be its own bytes plus the shared untagged lane, and can
	// never include B's 999999/888888.
	if v.TotalMeasuredBytes != 1000+300+2000 {
		t.Fatalf("A's total = %d, want %d (own OpenSearch + untagged + own ClickHouse)",
			v.TotalMeasuredBytes, 1000+300+2000)
	}

	// ── the narrowing happened at the STORAGE layer, before the query ────────
	f.mu.Lock()
	cats, sqls := append([]string(nil), f.catPaths...), append([]string(nil), f.sql...)
	f.mu.Unlock()
	if len(cats) == 0 || len(sqls) == 0 {
		t.Fatal("neither store was asked anything")
	}
	for _, p := range cats {
		if strings.Contains(p, fix["B"].tenantID) {
			t.Fatalf("the _cat pattern named another tenant's indices: %s", p)
		}
		if !strings.Contains(p, oslog.IndexTenantSeg(fix["A"].tenantID)) {
			t.Fatalf("the _cat pattern did not name the caller's own tenant segment: %s", p)
		}
	}
	for _, q := range sqls {
		if !strings.Contains(q, "partition = '"+fix["A"].tenantID+"'") {
			t.Fatalf("the ClickHouse read was not scoped to the caller's partition: %s", q)
		}
	}

	// ── as_tenant into another org is ignored ───────────────────────────────
	for _, path := range []string{
		"/api/system/storage/measured?as_tenant=" + fix["B"].tenantID,
		"/api/system/storage/measured?tenant=" + fix["B"].tenantID,
	} {
		st, b = do(t, srv, "GET", path, fix["A"].token, nil)
		if st != 200 {
			t.Fatalf("%s: %d %s", path, st, b)
		}
		got := decodeStorageReport(t, b)
		if got.Scope != fix["A"].tenantID {
			t.Fatalf("%s widened A's scope to %q", path, got.Scope)
		}
		for _, r := range got.Readings {
			if r.Scope == fix["B"].tenantID {
				t.Fatalf("%s leaked a B reading", path)
			}
		}
	}

	// ── the platform owner sees every tenant ────────────────────────────────
	st, b = do(t, srv, "GET", "/api/system/storage/measured", admin, nil)
	if st != 200 {
		t.Fatalf("owner read: %d %s", st, b)
	}
	owner := decodeStorageReport(t, b)
	if !owner.CrossTenant {
		t.Fatal("the platform owner's report must be cross-tenant")
	}
	seen := map[string]bool{}
	for _, r := range owner.Readings {
		seen[r.Scope] = true
	}
	for _, want := range []string{fix["A"].tenantID, fix["B"].tenantID} {
		if !seen[want] {
			t.Errorf("the owner's report is missing tenant %s", want)
		}
	}
}

// The stores that are NOT tenant-partitioned on disk must refuse to invent a
// tenant's share — a nil with a reason, never a zero and never a pro rata.
func TestStorageMeasuredRefusesToDeriveAPerTenantShare(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Storage Org S"})
	if st != 201 {
		t.Fatalf("create org: %d %s", st, b)
	}
	orgID := idOf(t, b)
	st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Storage Tenant S", "org_id": orgID})
	if st != 201 {
		t.Fatalf("create tenant: %d %s", st, b)
	}
	tenantID := idOf(t, b)
	st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "storage-admin-s", "password": "Passw0rd!2345", "role": "admin", "tenant_id": tenantID,
	})
	if st != 201 {
		t.Fatalf("create user: %d %s", st, b)
	}
	token := login(t, srv, "storage-admin-s", "Passw0rd!2345").Token
	installStorageFakes(s, &storageFakeStores{tenantA: tenantID, tenantB: "other-tenant"})

	st, b = do(t, srv, "GET", "/api/system/storage/measured", token, nil)
	if st != 200 {
		t.Fatalf("read: %d %s", st, b)
	}
	v := decodeStorageReport(t, b)
	want := map[string]bool{"victoriametrics": true, "postgres": true, "filestore": true, "kafka": true}
	found := map[string]bool{}
	for _, r := range v.Readings {
		if !want[r.Store] {
			continue
		}
		found[r.Store] = true
		if r.BytesOnDisk != nil {
			t.Errorf("%s handed a scoped caller a number it cannot measure per tenant: %+v", r.Store, r)
		}
		if !strings.HasPrefix(r.Detail, "not measured — ") {
			t.Errorf("%s: an unmeasured reading must say why, got %q", r.Store, r.Detail)
		}
	}
	for s := range want {
		if !found[s] {
			t.Errorf("store %s is missing from the report entirely — silence is not an answer", s)
		}
	}
	if !strings.HasPrefix(v.MeasurementNote, "PARTIAL.") {
		t.Errorf("a report with unmeasured stores must warn that the total is a lower bound: %q", v.MeasurementNote)
	}
}

// indexTenantSegment is the INVERSE of the index naming vector-router writes
// (deployment/docker/vector-router/vector.yaml:
// `netops-{{ log_index_base }}-{{ tenant_seg }}-%Y.%m.%d`). If the two ever
// disagree, bytes attribute to the wrong tenant — a §3a leak, not a cosmetic
// bug — so the mapping is pinned here against the real names, including the
// platform-owned lanes that carry no tenant segment at all.
func TestIndexTenantSegmentMatchesTheNamingIngestWrites(t *testing.T) {
	cases := []struct {
		index string
		want  string
		ok    bool
	}{
		{"netops-syslog-acme-2026.09.06", "acme", true},
		{"netops-snmptrap-t_9f2c-2026.09.06", "t_9f2c", true},
		{"netops-flows-untagged-2026.09.06", "untagged", true},
		{"netops-secfindings-acme-2026.09.06", "acme", true},
		// The date is %Y.%m.%d — dots, never hyphens — so a tenant segment may
		// itself contain hyphens without swallowing part of the date.
		{"netops-syslog-acme-eu-west-2026.09.06", "acme-eu-west", true},
		// Platform-owned lanes: no tenant segment, so no attribution.
		{"netops-quarantine-2026.09.06", "", false},
		{"netops-deadletter-2026.09.06", "", false},
		{"netops-audit-2026.09", "", false},
		// Not ours at all.
		{"security-auditlog-2026.09.06", "", false},
		{".kibana_1", "", false},
		{"netops-", "", false},
	}
	for _, c := range cases {
		got, ok := indexTenantSegment(c.index)
		if got != c.want || ok != c.ok {
			t.Errorf("indexTenantSegment(%q) = (%q,%v), want (%q,%v)",
				c.index, got, ok, c.want, c.ok)
		}
	}
}
