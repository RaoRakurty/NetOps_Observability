package main

// pagination_test.go — failure-path and boundary tests for the bounded-read
// contract (audit F-57 / F-61 / F-72 / F-74 / F-79).
//
// The audit's whole point about this class is that it is INVISIBLE from a
// success response: `?limit=1` returning 512 rows and `?limit=1` returning 1
// row are both HTTP 200 with a JSON array. So these tests never assert "it
// worked" — they seed PAST the limit on purpose and assert the three things a
// silent implementation cannot do:
//
//  1. a walk reaches every row EXACTLY ONCE (no duplicates, no gaps);
//  2. an offset past the end yields an EMPTY page, never a clamped one;
//  3. the response states the TRUE total, so a partial set is distinguishable
//     from a complete one.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"netops/backend/models"
)

// doHead is `do` but also returns the response headers, which is where the
// bounded-read contract is reported on the legacy (bare-array) shapes.
func doHead(t *testing.T, srv *httptest.Server, method, path, token string) (int, []byte, http.Header) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header
}

// seedDevices puts n devices into the aggregator, owned by tenant (may be "").
func seedDevices(s *server, tenant string, n int, prefix string) {
	for i := 0; i < n; i++ {
		s.discovery.Upsert(models.Device{
			ID:       fmt.Sprintf("%s-%04d", prefix, i),
			Name:     fmt.Sprintf("%s node %d", prefix, i),
			Address:  fmt.Sprintf("10.9.%d.%d", i/250, i%250),
			TenantID: tenant,
			Source:   "test",
		})
	}
}

func decodeDevices(t *testing.T, body []byte) []models.Device {
	t.Helper()
	var out []models.Device
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode device array: %v (%s)", err, truncBody(body))
	}
	return out
}

func truncBody(b []byte) string {
	if len(b) > 200 {
		return string(b[:200]) + "…"
	}
	return string(b)
}

func headerInt(t *testing.T, h http.Header, key string) int {
	t.Helper()
	v := h.Get(key)
	if v == "" {
		t.Fatalf("response is missing the %s header — the true total must be reported on every bounded read", key)
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		t.Fatalf("%s = %q is not an integer", key, v)
	}
	return n
}

// ── F-61: GET /api/devices ────────────────────────────────────────────────────

// TestDevicesPaginationWalksEveryRowExactlyOnce seeds PAST the page size and
// walks the whole fleet. The pre-fix endpoint returned all 512 rows for every
// parameter set, so this test would have seen each row 26 times.
func TestDevicesPaginationWalksEveryRowExactlyOnce(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	const total = 137
	seedDevices(s, "", total, "dev")

	seen := map[string]int{}
	const limit = 20
	for offset := 0; offset < total+limit; offset += limit {
		st, b, h := doHead(t, srv, "GET", fmt.Sprintf("/api/devices?limit=%d&offset=%d", limit, offset), admin)
		if st != 200 {
			t.Fatalf("offset %d: status %d: %s", offset, st, b)
		}
		if got := headerInt(t, h, headerTotalCount); got != total {
			t.Fatalf("offset %d: X-Total-Count = %d, want the TRUE total %d", offset, got, total)
		}
		rows := decodeDevices(t, b)
		if offset >= total {
			// Boundary: past the end is EMPTY, never a clamped last page.
			if len(rows) != 0 {
				t.Fatalf("offset %d is past the end of %d rows but returned %d — "+
					"a clamped page re-serves rows the caller already walked and never terminates",
					offset, total, len(rows))
			}
			continue
		}
		if len(rows) > limit {
			t.Fatalf("offset %d: got %d rows for limit=%d", offset, len(rows), limit)
		}
		for _, d := range rows {
			seen[d.ID]++
		}
	}
	if len(seen) != total {
		t.Fatalf("walk reached %d distinct devices, want %d", len(seen), total)
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("device %s was returned %d times — a paging walk must see each row exactly once", id, n)
		}
	}
}

// TestDevicesRejectsUnknownAndOutOfRangeParams is the F-61 core: the endpoint
// used to answer 200 + the whole table for `?page_size=1`. A parameter is
// applied or refused BY NAME; it is never swallowed.
func TestDevicesRejectsUnknownAndOutOfRangeParams(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	seedDevices(s, "", 5, "dev")

	for _, tc := range []struct{ name, query, wantIn string }{
		{"unknown param", "?page_size=1", "page_size"},
		{"unknown param among valid ones", "?limit=2&pageSize=3", "pageSize"},
		{"limit above the ceiling", "?limit=999999", "limit"},
		{"limit zero", "?limit=0", "limit"},
		{"limit not a number", "?limit=1e3", "limit"},
		{"limit with trailing garbage", "?limit=10x", "limit"},
		{"negative offset", "?offset=-1", "offset"},
		{"offset not a number", "?offset=abc", "offset"},
		{"envelope gibberish", "?envelope=maybe", "envelope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, b := do(t, srv, "GET", "/api/devices"+tc.query, admin, nil)
			if st != http.StatusBadRequest {
				t.Fatalf("GET /api/devices%s = %d, want 400 (silent acceptance is the defect): %s",
					tc.query, st, truncBody(b))
			}
			if !bytesContain(b, tc.wantIn) {
				t.Errorf("400 body %s does not name the offending key %q", truncBody(b), tc.wantIn)
			}
		})
	}
}

// TestDevicesEnvelopeReportsTrueTotalAndCompleteness asserts a client can tell
// a page from the whole fleet without reading headers.
func TestDevicesEnvelopeReportsTrueTotalAndCompleteness(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	seedDevices(s, "", 40, "dev")

	type env struct {
		Devices  []models.Device `json:"devices"`
		Total    int             `json:"total"`
		Returned int             `json:"returned"`
		Complete bool            `json:"complete"`
		Limit    int             `json:"limit"`
		Offset   int             `json:"offset"`
	}
	st, b := do(t, srv, "GET", "/api/devices?envelope=1&limit=10", admin, nil)
	if st != 200 {
		t.Fatalf("status %d: %s", st, b)
	}
	var partial env
	if err := json.Unmarshal(b, &partial); err != nil {
		t.Fatal(err)
	}
	if partial.Total != 40 || partial.Returned != 10 {
		t.Fatalf("partial page: total=%d returned=%d, want 40/10", partial.Total, partial.Returned)
	}
	if partial.Complete {
		t.Fatal("a 10-of-40 page reported complete=true — that is exactly the lie this finding is about")
	}

	st, b = do(t, srv, "GET", "/api/devices?envelope=1&limit=100", admin, nil)
	if st != 200 {
		t.Fatalf("status %d: %s", st, b)
	}
	var whole env
	if err := json.Unmarshal(b, &whole); err != nil {
		t.Fatal(err)
	}
	if !whole.Complete || whole.Returned != 40 || whole.Total != 40 {
		t.Fatalf("whole set reported total=%d returned=%d complete=%v, want 40/40/true",
			whole.Total, whole.Returned, whole.Complete)
	}
}

// TestDevicesDefaultShapeUnchanged pins the wire contract the SPA and every
// existing API-key client depend on (docs/design/sot-provider-model.md).
func TestDevicesDefaultShapeUnchanged(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	seedDevices(s, "", 3, "dev")
	st, b, h := doHead(t, srv, "GET", "/api/devices", admin)
	if st != 200 {
		t.Fatalf("status %d: %s", st, b)
	}
	if len(decodeDevices(t, b)) != 3 {
		t.Fatalf("unparameterised GET must still return the bare array: %s", truncBody(b))
	}
	if h.Get(headerPageDone) != "true" {
		t.Errorf("X-Page-Complete = %q, want true for a 3-of-3 response", h.Get(headerPageDone))
	}
	if got := headerInt(t, h, headerTotalCount); got != 3 {
		t.Errorf("X-Total-Count = %d, want 3", got)
	}
}

// ── F-61 tenant isolation (§3a.5) ─────────────────────────────────────────────

// TestDevicesPaginationIsTenantScoped is the isolation test for the paged read:
// paging must NEVER become a way to reach another tenant's rows, and the
// reported total must be the CALLER's total, not the platform's.
func TestDevicesPaginationIsTenantScoped(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	orgA := idOf(t, mustDo(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org Alpha"}, 201))
	orgB := idOf(t, mustDo(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org Bravo"}, 201))
	tenantA := idOf(t, mustDo(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant Alpha", "org_id": orgA}, 201))
	tenantB := idOf(t, mustDo(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant Bravo", "org_id": orgB}, 201))
	mustDo(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "op-a", "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantA}, 201)
	tokenA := login(t, srv, "op-a", "Passw0rd!2345").Token

	seedDevices(s, tenantA, 12, "a")
	seedDevices(s, tenantB, 30, "b")

	// Own-only list, and the TOTAL is the caller's total — not 42.
	st, b, h := doHead(t, srv, "GET", "/api/devices?limit=100", tokenA)
	if st != 200 {
		t.Fatalf("status %d: %s", st, b)
	}
	if got := headerInt(t, h, headerTotalCount); got != 12 {
		t.Fatalf("tenant A sees total=%d, want 12 — the total must be scoped like the rows", got)
	}
	for _, d := range decodeDevices(t, b) {
		if d.TenantID != tenantA {
			t.Fatalf("tenant A received a device owned by %q — CROSS-TENANT LEAK", d.TenantID)
		}
	}

	// Walking offsets must never surface org B's rows.
	for offset := 0; offset < 60; offset += 5 {
		st, b, _ := doHead(t, srv, "GET", fmt.Sprintf("/api/devices?limit=5&offset=%d", offset), tokenA)
		if st != 200 {
			t.Fatalf("offset %d: status %d: %s", offset, st, b)
		}
		for _, d := range decodeDevices(t, b) {
			if d.TenantID != tenantA {
				t.Fatalf("offset %d leaked a device owned by %q", offset, d.TenantID)
			}
		}
	}

	// as_tenant into another org is ignored for a scoped principal.
	st, b, h = doHead(t, srv, "GET", "/api/devices?limit=100&as_tenant="+tenantB, tokenA)
	if st != 200 {
		t.Fatalf("status %d: %s", st, b)
	}
	if got := headerInt(t, h, headerTotalCount); got != 12 {
		t.Fatalf("as_tenant=%s changed tenant A's total to %d — narrowing must never WIDEN", tenantB, got)
	}
	for _, d := range decodeDevices(t, b) {
		if d.TenantID != tenantA {
			t.Fatalf("as_tenant leaked a device owned by %q", d.TenantID)
		}
	}
}

// ── F-57: GET /api/audit ──────────────────────────────────────────────────────

func TestAuditPaginationAndParamValidation(t *testing.T) {
	srv, _ := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// Seed past the page size with real audited mutations (the middleware
	// records every non-GET), so this exercises the trail as it is written.
	const seeded = 25
	for i := 0; i < seeded; i++ {
		do(t, srv, "POST", "/api/devices", admin, map[string]any{
			"id": fmt.Sprintf("aud-%02d", i), "name": "x", "address": "10.0.0.1"})
	}

	st, b, h := doHead(t, srv, "GET", "/api/audit?limit=5", admin)
	if st != 200 {
		t.Fatalf("status %d: %s", st, b)
	}
	total := headerInt(t, h, headerTotalCount)
	if total < seeded {
		t.Fatalf("X-Total-Count = %d but at least %d events were recorded — "+
			"the read path cannot report less than it holds (F-57)", total, seeded)
	}
	var page []AuditEvent
	if err := json.Unmarshal(b, &page); err != nil {
		t.Fatalf("decode audit array: %v (%s)", err, truncBody(b))
	}
	if len(page) != 5 {
		t.Fatalf("limit=5 returned %d events", len(page))
	}
	if h.Get(headerPageDone) != "false" {
		t.Errorf("a 5-of-%d page reported X-Page-Complete=%q", total, h.Get(headerPageDone))
	}

	// The walk: every event exactly once, then an empty page past the end.
	seen := map[string]int{}
	for offset := 0; offset <= total; offset += 5 {
		st, b, _ := doHead(t, srv, "GET", fmt.Sprintf("/api/audit?limit=5&offset=%d", offset), admin)
		if st != 200 {
			t.Fatalf("offset %d: status %d: %s", offset, st, b)
		}
		var rows []AuditEvent
		if err := json.Unmarshal(b, &rows); err != nil {
			t.Fatal(err)
		}
		if offset >= total && len(rows) != 0 {
			t.Fatalf("offset %d past a total of %d returned %d rows, want an empty page",
				offset, total, len(rows))
		}
		for _, e := range rows {
			seen[e.ID]++
		}
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("audit event %s returned %d times across the walk", id, n)
		}
	}

	for _, tc := range []struct{ name, query, wantIn string }{
		{"unknown param", "?window=7d", "window"},
		{"limit above the cap", "?limit=100000", "limit"},
		{"limit garbage", "?limit=200OR1=1", "limit"},
		{"before not RFC3339", "?before=yesterday", "before"},
		{"since not RFC3339", "?since=2026-07-21", "since"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, b := do(t, srv, "GET", "/api/audit"+tc.query, admin, nil)
			if st != http.StatusBadRequest {
				t.Fatalf("GET /api/audit%s = %d, want 400: %s", tc.query, st, truncBody(b))
			}
			if !bytesContain(b, tc.wantIn) {
				t.Errorf("400 body %s does not name %q", truncBody(b), tc.wantIn)
			}
		})
	}
}

// TestAuditStoreOffsetBoundary exercises the store directly at the seam the
// handler cannot reach: offset exactly at, and past, the end.
func TestAuditStoreOffsetBoundary(t *testing.T) {
	dir := t.TempDir()
	repo, err := newAuditStore(dir + "/audit.json")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 7; i++ {
		repo.Record(AuditEvent{Actor: "a", Tenant: "t1", Method: "POST", Path: "/x", Status: 200})
	}
	if n := repo.Count("t1", false, auditQuery{}); n != 7 {
		t.Fatalf("Count = %d, want 7", n)
	}
	if got := len(listOK(t, repo, "t1", false, auditQuery{Limit: 3, Offset: 6})); got != 1 {
		t.Fatalf("offset 6 of 7 returned %d rows, want 1", got)
	}
	if got := len(listOK(t, repo, "t1", false, auditQuery{Limit: 3, Offset: 7})); got != 0 {
		t.Fatalf("offset AT the end returned %d rows, want an empty page", got)
	}
	if got := len(listOK(t, repo, "t1", false, auditQuery{Limit: 3, Offset: 900})); got != 0 {
		t.Fatalf("offset far past the end returned %d rows, want an empty page", got)
	}
	// Isolation: another tenant's scope sees nothing, and its total is 0 —
	// never the platform's 7.
	if n := repo.Count("t2", false, auditQuery{}); n != 0 {
		t.Fatalf("tenant t2 Count = %d over t1's events — CROSS-TENANT LEAK", n)
	}
	if got := len(listOK(t, repo, "t2", false, auditQuery{Limit: 10})); got != 0 {
		t.Fatalf("tenant t2 List returned %d of t1's events — CROSS-TENANT LEAK", got)
	}
}

// ── unit-level contract ───────────────────────────────────────────────────────

func TestPageSliceOfBoundaries(t *testing.T) {
	rows := []int{0, 1, 2, 3, 4}
	for _, tc := range []struct {
		name          string
		limit, offset int
		want          []int
	}{
		{"first page", 2, 0, []int{0, 1}},
		{"middle page", 2, 2, []int{2, 3}},
		{"short last page", 2, 4, []int{4}},
		{"offset exactly at the end", 2, 5, []int{}},
		{"offset past the end", 2, 500, []int{}},
		{"limit larger than the set", 50, 0, []int{0, 1, 2, 3, 4}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := pageSliceOf(rows, pageRequest{Limit: tc.limit, Offset: tc.offset})
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestPageCompleteOnlyWhenWhole(t *testing.T) {
	if !pageComplete(pageRequest{Offset: 0}, 10, 10) {
		t.Error("offset 0 returning all 10 of 10 must be complete")
	}
	if pageComplete(pageRequest{Offset: 0}, 10, 11) {
		t.Error("10 of 11 must NOT be complete — this is the bit that makes truncation visible")
	}
	if pageComplete(pageRequest{Offset: 5}, 5, 10) {
		t.Error("a page at offset 5 is never the whole set, even when it happens to be full")
	}
}

func TestRejectUnknownQueryNamesTheKey(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/x?limit=5&as_tenant=t1&frobnicate=9", nil)
	err := rejectUnknownQuery(r, "status")
	if err == nil {
		t.Fatal("an unrecognised query parameter must be an error — silent acceptance is the defect")
	}
	if !stringContains(err.Error(), "frobnicate") {
		t.Errorf("error %q does not name the offending key", err)
	}
	if err := rejectUnknownQuery(r, "status", "frobnicate"); err != nil {
		t.Errorf("an allowlisted key must pass: %v", err)
	}
	// The always-allowed set must not need declaring at every call site.
	r2 := httptest.NewRequest("GET", "/api/x?limit=5&offset=2&envelope=1&as_tenant=t", nil)
	if err := rejectUnknownQuery(r2); err != nil {
		t.Errorf("paging/tenancy params must always be accepted: %v", err)
	}
}

func TestBoolQueryIsStrict(t *testing.T) {
	for _, v := range []string{"1", "true", "0", "false", ""} {
		r := httptest.NewRequest("GET", "/api/x?envelope="+v, nil)
		if _, err := boolQuery(r, "envelope"); err != nil {
			t.Errorf("envelope=%q should parse: %v", v, err)
		}
	}
	for _, v := range []string{"yes", "y", "TrUe", "2", "on"} {
		r := httptest.NewRequest("GET", "/api/x?envelope="+v, nil)
		if _, err := boolQuery(r, "envelope"); err == nil {
			t.Errorf("envelope=%q must be rejected, not silently read as false", v)
		}
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func bytesContain(b []byte, sub string) bool { return stringContains(string(b), sub) }

func stringContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// mustDo is `do` with an expected status.
func mustDo(t *testing.T, srv *httptest.Server, method, path, token string, body any, want int) []byte {
	t.Helper()
	st, b := do(t, srv, method, path, token, body)
	if st != want {
		t.Fatalf("%s %s = %d, want %d: %s", method, path, st, want, truncBody(b))
	}
	return b
}
