// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package discoveryscope

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/discovery"
	"netops/backend/models"
)

// handlerRig drives Deps.Handler with a caller chosen per request through test
// headers (the real gates are proved in the root isolation test).
type handlerRig struct {
	t        *testing.T
	deps     Deps
	audits   []string
	refresh  int
	devices  []models.Device
	statuses []discovery.ScopeStatus
	platOn   bool
	platHost int
	nextID   int
}

func newHandlerRig(t *testing.T) *handlerRig {
	h := &handlerRig{t: t, platOn: true, platHost: 4}
	reg := NewRegistry(NewFileStore("/data/discovery_scopes.json", newMemKV()))
	caller := func(r *http.Request) Caller {
		return Caller{Subject: r.Header.Get("X-Sub"), Tenant: r.Header.Get("X-Tenant"),
			Cross: r.Header.Get("X-Cross") == "1", PlatformOwner: r.Header.Get("X-Owner") == "1"}
	}
	creds := map[string]string{"p-a": "t_a", "p-a2": "t_a", "p-b": "t_b", "p-plat": ""}
	h.deps = Deps{
		Registry: reg,
		Reader:   func(_ http.ResponseWriter, r *http.Request) (Caller, bool) { return caller(r), true },
		Writer: func(w http.ResponseWriter, r *http.Request) (Caller, bool) {
			c := caller(r)
			if !c.PlatformOwner {
				http.Error(w, "platform administrator required", http.StatusForbidden)
				return c, false
			}
			return c, true
		},
		ResolveTenant: func(ref string) (string, bool) {
			switch strings.ToLower(strings.TrimSpace(ref)) {
			case "t_a", "acme":
				return "t_a", true
			case "t_b":
				return "t_b", true
			case "global":
				return "global", true
			}
			return "", false
		},
		TenantName:      func(id string) string { return "Name of " + id },
		CredentialOwner: func(id string) (string, bool) { t, ok := creds[id]; return t, ok },
		PlatformScan:    func() ([]string, bool, int) { return []string{"10.0.9.0/29"}, h.platOn, h.platHost },
		Status:          func() []discovery.ScopeStatus { return h.statuses },
		Devices:         func() []models.Device { return h.devices },
		Refresh:         func() { h.refresh++ },
		Audit: func(_ *http.Request, c Caller, action string, sc Scope) {
			h.audits = append(h.audits, action+":"+sc.TenantID+":"+c.Subject)
		},
		NewID: func() (string, error) { h.nextID++; return fmt.Sprintf("ds-%016x", h.nextID), nil },
		Now:   func() time.Time { return t0 },
		WriteJSON: func(w http.ResponseWriter, status int, v any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			if err := json.NewEncoder(w).Encode(v); err != nil {
				t.Errorf("encode: %v", err)
			}
		},
		WriteError: func(w http.ResponseWriter, status int, err error) { http.Error(w, err.Error(), status) },
		Log:        func(msg string, err error) { t.Logf("%s: %v", msg, err) },
	}
	return h
}

type who struct {
	tenant       string
	cross, owner bool
}

var (
	ownerAll      = who{tenant: "global", cross: true, owner: true}
	ownerProvider = who{tenant: "global", owner: true}
	ownerAsA      = who{tenant: "t_a", owner: true}
	userA         = who{tenant: "t_a"}
	userB         = who{tenant: "t_b"}
)

func (h *handlerRig) do(c who, method, path string, body any) (int, []byte) {
	h.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			h.t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("X-Sub", "sub-"+c.tenant)
	req.Header.Set("X-Tenant", c.tenant)
	if c.cross {
		req.Header.Set("X-Cross", "1")
	}
	if c.owner {
		req.Header.Set("X-Owner", "1")
	}
	rec := httptest.NewRecorder()
	h.deps.Handler(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func (h *handlerRig) create(c who, body map[string]any) (int, scopeView) {
	h.t.Helper()
	st, b := h.do(c, http.MethodPost, apiPrefix, body)
	var v scopeView
	if st == http.StatusCreated {
		if err := json.Unmarshal(b, &v); err != nil {
			h.t.Fatalf("decode: %v (%s)", err, b)
		}
	}
	return st, v
}

func body(tenant string, ranges ...string) map[string]any {
	return map[string]any{"tenant_id": tenant, "name": "RETAIL edges", "ranges": ranges, "enabled": true}
}

func TestCreateStampsTheOwnerFromTheCallerNeverTheBody(t *testing.T) {
	h := newHandlerRig(t)
	// Cross-tenant owner: names the customer explicitly (resolved, never raw).
	st, v := h.create(ownerAll, body("acme", "10.70.0.80/30"))
	if st != http.StatusCreated || v.TenantID != "t_a" || v.CreatedBy != "sub-global" || v.TenantName != "Name of t_a" {
		t.Fatalf("create: %d %+v", st, v)
	}
	if len(h.audits) != 1 || h.audits[0] != "create:t_a:sub-global" || h.refresh != 1 {
		t.Fatalf("a committed create is audited and triggers a sweep: %v refresh=%d", h.audits, h.refresh)
	}
	if snap := h.deps.Registry.Snapshot(); len(snap) != 1 || snap[0].ID != v.ID {
		t.Fatal("the scanner's view must hold the new scope")
	}
	// Owner narrowed to t_a: the body naming t_b is ignored.
	if st, v := h.create(ownerAsA, body("t_b", "10.70.1.0/30")); st != http.StatusCreated || v.TenantID != "t_a" {
		t.Fatalf("a narrowed caller creates for its own tenant only: %d %+v", st, v)
	}
	// No / unknown customer, or the platform as customer, is refused.
	for _, b := range []map[string]any{body("", "10.70.2.0/30"), body("nope", "10.70.2.0/30"), body("global", "10.70.2.0/30")} {
		if st, _ := h.create(ownerAll, b); st != http.StatusBadRequest {
			t.Fatalf("create %v: %d, want 400", b["tenant_id"], st)
		}
	}
	if st, _ := h.create(ownerProvider, body("t_a", "10.70.2.0/30")); st != http.StatusBadRequest {
		t.Fatalf("the Provider view has no customer to create for: %d", st)
	}
	// A customer (even an admin of it) cannot create: platform owner only (D1).
	if st, _ := h.create(userA, body("t_a", "10.70.2.0/30")); st != http.StatusForbidden {
		t.Fatalf("tenant create: %d, want 403", st)
	}
	// Unknown fields are refused, so a misspelt field is never silently dropped.
	if st, _ := h.do(ownerAll, http.MethodPost, apiPrefix, map[string]any{"tenant_id": "t_a", "name": "x", "ranges": []string{"10.70.3.0/30"}, "community": "public"}); st != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", st)
	}
}

func TestCreateUsesOnlyTheCustomersOwnProfiles(t *testing.T) {
	h := newHandlerRig(t)
	for _, ref := range []string{"p-b", "p-plat", "missing"} {
		b := body("t_a", "10.70.0.80/30")
		b["credential_refs"] = []string{ref}
		st, raw := h.do(ownerAll, http.MethodPost, apiPrefix, b)
		if st != http.StatusBadRequest || !strings.Contains(string(raw), "not one of this customer's own profiles") {
			t.Fatalf("profile %q: %d %s", ref, st, raw)
		}
	}
	b := body("t_a", "10.70.0.80/30")
	b["credential_refs"] = []string{"p-a", "p-a2"}
	if st, v := h.create(ownerAll, b); st != http.StatusCreated || strings.Join(v.CredentialRefs, ",") != "p-a,p-a2" {
		t.Fatalf("own profiles: %d %+v", st, v)
	}
}

func TestCreateHonoursTheSharedSweepBudget(t *testing.T) {
	h := newHandlerRig(t)
	h.platHost = 4096 - 4
	if st, _ := h.create(ownerAll, body("t_a", "10.70.0.0/29")); st != http.StatusBadRequest {
		t.Fatalf("over the shared budget: %d, want 400", st)
	}
	off := body("t_a", "10.70.0.0/29")
	off["enabled"] = false
	if st, _ := h.create(ownerAll, off); st != http.StatusCreated {
		t.Fatalf("a scan that is off charges nothing: %d", st)
	}
	h.platOn = false
	if st, _ := h.create(ownerAll, body("t_a", "10.70.0.0/29")); st != http.StatusCreated {
		t.Fatalf("a platform scan that is off charges nothing: %d", st)
	}
}

func TestReadsAreTenantScopedAndForeignIDsAre404(t *testing.T) {
	h := newHandlerRig(t)
	_, a := h.create(ownerAll, body("t_a", "10.70.0.80/30"))
	_, b := h.create(ownerAll, body("t_b", "10.70.0.80/30"))
	list := func(c who) (ids []string, hasPlatform bool) {
		st, raw := h.do(c, http.MethodGet, apiPrefix, nil)
		if st != http.StatusOK {
			t.Fatalf("list: %d %s", st, raw)
		}
		var out struct {
			Scopes   []scopeView     `json:"scopes"`
			Platform json.RawMessage `json:"platform"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		for _, s := range out.Scopes {
			ids = append(ids, s.TenantID)
		}
		return ids, len(out.Platform) > 0
	}
	if ids, plat := list(userA); strings.Join(ids, ",") != "t_a" || plat {
		t.Fatalf("CROSS-TENANT LEAK: user A lists %v (platform %v)", ids, plat)
	}
	if ids, plat := list(ownerAll); strings.Join(ids, ",") != "t_a,t_b" || !plat {
		t.Fatalf("the platform owner sees all, plus the platform scan: %v %v", ids, plat)
	}
	if ids, plat := list(ownerProvider); len(ids) != 0 || !plat {
		t.Fatalf("the Provider view sees only the platform scan: %v %v", ids, plat)
	}
	if ids, plat := list(ownerAsA); strings.Join(ids, ",") != "t_a" || plat {
		t.Fatalf("the owner viewing as t_a sees t_a only: %v %v", ids, plat)
	}
	if ids, plat := list(who{tenant: "global"}); len(ids) != 0 || plat {
		t.Fatalf("a non-owner in the global tenant sees nothing: %v %v", ids, plat)
	}

	// By id: another tenant's scan is the same 404 as a missing one — for GET,
	// PUT and DELETE alike, so writes cannot probe ids either.
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		if st, _ := h.do(userA, m, apiPrefix+"/"+b.ID, body("t_a", "10.70.0.80/30")); st != http.StatusNotFound {
			t.Fatalf("user A %s of B's scan: %d, want 404", m, st)
		}
		if st, _ := h.do(userA, m, apiPrefix+"/ds-00000000000000ff", body("t_a", "10.70.0.80/30")); st != http.StatusNotFound {
			t.Fatalf("user A %s of a missing scan: %d, want 404", m, st)
		}
	}
	if st, _ := h.do(userA, http.MethodGet, apiPrefix+"/"+a.ID, nil); st != http.StatusOK {
		t.Fatalf("user A reads its own scan: %d", st)
	}
	// Its own scan: readable, but not writable (platform owner only).
	for _, m := range []string{http.MethodPut, http.MethodDelete} {
		if st, _ := h.do(userA, m, apiPrefix+"/"+a.ID, body("t_a", "10.70.0.84/30")); st != http.StatusForbidden {
			t.Fatalf("user A %s of its own scan: %d, want 403", m, st)
		}
	}
	if st, _ := h.do(ownerAsA, http.MethodDelete, apiPrefix+"/"+b.ID, nil); st != http.StatusNotFound {
		t.Fatalf("the owner narrowed to t_a cannot reach t_b's scan: %d", st)
	}
	if snap := h.deps.Registry.Snapshot(); len(snap) != 2 {
		t.Fatalf("no refused write may change anything: %d scopes", len(snap))
	}
	_ = userB
}

func TestUpdateNeverMovesAScanAndKeepsItsStamps(t *testing.T) {
	h := newHandlerRig(t)
	_, a := h.create(ownerAll, body("t_a", "10.70.0.80/30"))
	if st, raw := h.do(ownerAll, http.MethodPut, apiPrefix+"/"+a.ID, body("t_b", "10.70.0.80/30")); st != http.StatusBadRequest || !strings.Contains(string(raw), "cannot be changed") {
		t.Fatalf("re-homing a scan: %d %s", st, raw)
	}
	upd := body("t_a", "10.70.0.84/30")
	upd["name"] = "renamed"
	st, raw := h.do(ownerAll, http.MethodPut, apiPrefix+"/"+a.ID, upd)
	var v scopeView
	if err := json.Unmarshal(raw, &v); st != http.StatusOK || err != nil {
		t.Fatalf("update: %d %s", st, raw)
	}
	if v.TenantID != "t_a" || v.CreatedBy != a.CreatedBy || !v.CreatedAt.Equal(a.CreatedAt) || v.Name != "renamed" || v.Ranges[0] != "10.70.0.84/30" {
		t.Fatalf("update: %+v", v)
	}
	// The owner narrowed to t_a: body tenant ignored, the stored owner kept.
	if st, raw := h.do(ownerAsA, http.MethodPut, apiPrefix+"/"+a.ID, body("t_b", "10.70.0.84/30")); st != http.StatusOK || !strings.Contains(string(raw), `"tenant_id":"t_a"`) {
		t.Fatalf("narrowed update: %d %s", st, raw)
	}
	if st, _ := h.do(ownerAll, http.MethodDelete, apiPrefix+"/"+a.ID, nil); st != http.StatusNoContent {
		t.Fatalf("delete: %d", st)
	}
	if got := strings.Join(h.audits, " "); got != "create:t_a:sub-global update:t_a:sub-global update:t_a:sub-t_a delete:t_a:sub-global" {
		t.Fatalf("audit trail: %s", got)
	}
	if len(h.deps.Registry.Snapshot()) != 0 {
		t.Fatal("the scanner's view must drop a deleted scan")
	}
}

func TestFoundListFlagsDuplicatesWithoutLeakingOtherCustomers(t *testing.T) {
	h := newHandlerRig(t)
	_, a := h.create(ownerAll, body("t_a", "10.70.0.80/30"))
	h.devices = []models.Device{
		{ID: "a-81", Name: "cEDGE-81", Address: "10.70.0.81", Source: "snmp", TenantID: "t_a"},
		{ID: "a-82", Name: "cEDGE-82", Address: "10.70.0.82", Source: "snmp", TenantID: "t_a"},
		{ID: "a-out", Name: "far", Address: "10.99.0.1", Source: "snmp", TenantID: "t_a"},    // outside the ranges
		{ID: "a-man", Name: "man", Address: "10.70.0.83", Source: "manual", TenantID: "t_a"}, // not found by a scan
		{ID: "plat-81", Name: "cEDGE-81", Address: "10.70.0.81", Source: "snmp"},             // the platform's copy
		{ID: "b-82", Name: "x", Address: "10.70.0.82", Source: "snmp", TenantID: "t_b"},      // another customer
	}
	h.statuses = []discovery.ScopeStatus{{ScopeID: a.ID, TenantID: "t_a", LastSweep: t0, Answering: 2}}
	get := func(c who) scopeView {
		st, raw := h.do(c, http.MethodGet, apiPrefix+"/"+a.ID, nil)
		var v scopeView
		if err := json.Unmarshal(raw, &v); st != http.StatusOK || err != nil {
			t.Fatalf("get: %d %s", st, raw)
		}
		return v
	}
	v := get(userA)
	if v.FoundTotal != 2 || v.Found[0].ID != "a-81" || !v.Found[0].AlsoFoundByPlatform || v.Found[1].AlsoFoundByPlatform {
		t.Fatalf("found: %+v", v.Found)
	}
	if v.Found[1].AlsoFoundByOtherCustomers != 0 {
		t.Fatal("CROSS-TENANT LEAK: a customer learned another customer holds the address")
	}
	if v.Status == nil || v.Status.Answering != 2 || v.Status.LastSweep == nil {
		t.Fatalf("status: %+v", v.Status)
	}
	if x := get(ownerAll); x.Found[1].AlsoFoundByOtherCustomers != 1 {
		t.Fatalf("the platform owner sees the other-customer duplicate: %+v", x.Found)
	}
}

func TestHandlerRoutingRefusals(t *testing.T) {
	h := newHandlerRig(t)
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodPatch, apiPrefix, http.StatusMethodNotAllowed},
		{http.MethodPost, apiPrefix + "/ds-0000000000000001", http.StatusMethodNotAllowed},
		{http.MethodGet, apiPrefix + "/a/b", http.StatusNotFound},
		{http.MethodGet, apiPrefix + "/../x", http.StatusNotFound},
		{http.MethodGet, apiPrefix + "/not-an-id", http.StatusNotFound},
	} {
		if st, _ := h.do(ownerAll, tc.method, tc.path, nil); st != tc.want {
			t.Errorf("%s %s: %d, want %d", tc.method, tc.path, st, tc.want)
		}
	}
	h.deps.NewID = func() (string, error) { return "", errors.New("no entropy") }
	if st, _ := h.create(ownerAll, body("t_a", "10.70.0.80/30")); st != http.StatusInternalServerError {
		t.Fatalf("id failure: %d", st)
	}
}

// TestACustomerReadLeavesOutPlatformSideDetail: a non-cross read of a scan
// carries no created_by (the platform's record) and no budget-refusal text
// (it measures other scans' load); it keeps the "also found by the platform
// scan" flag, which the owner wants every customer to see.
func TestACustomerReadLeavesOutPlatformSideDetail(t *testing.T) {
	h := newHandlerRig(t)
	_, a := h.create(ownerAll, body("t_a", "10.70.0.80/30"))
	h.devices = []models.Device{
		{ID: "a-81", Name: "cEDGE-81", Address: "10.70.0.81", Source: "snmp", TenantID: "t_a"},
		{ID: "plat-81", Name: "cEDGE-81", Address: "10.70.0.81", Source: "snmp"},
	}
	raw := "scope " + a.ID + ": discovery ranges refused: the scans together would probe more than 4096 addresses per sweep (one budget for the appliance, the platform scan charged first) — narrow this scan's ranges"
	h.statuses = []discovery.ScopeStatus{{ScopeID: a.ID, TenantID: "t_a", LastError: raw, BudgetRefused: true}}
	for _, c := range []who{userA, ownerAsA} {
		st, b := h.do(c, http.MethodGet, apiPrefix+"/"+a.ID, nil)
		got := string(b)
		if st != http.StatusOK || strings.Contains(got, "created_by") || strings.Contains(got, "sub-global") {
			t.Fatalf("a non-cross read must not carry created_by: %d %s", st, got)
		}
		if strings.Contains(got, "4096") || strings.Contains(got, "platform scan charged") || !strings.Contains(got, budgetRefusedForCustomer) {
			t.Fatalf("a non-cross read must not carry the budget-refusal detail: %s", got)
		}
		if !strings.Contains(got, `"also_found_by_platform":true`) {
			t.Fatalf("the duplicate flag stays: %s", got)
		}
		st, b = h.do(c, http.MethodGet, apiPrefix, nil)
		if st != http.StatusOK || strings.Contains(string(b), "created_by") || strings.Contains(string(b), "4096 addresses per sweep (") {
			t.Fatalf("the list must leave them out too: %s", b)
		}
	}
	_, b := h.do(ownerAll, http.MethodGet, apiPrefix+"/"+a.ID, nil)
	if got := string(b); !strings.Contains(got, `"created_by":"sub-global"`) || !strings.Contains(got, "platform scan charged first") {
		t.Fatalf("the cross-tenant owner keeps the full detail: %s", got)
	}
	// A non-budget refusal is the customer's own problem and is shown as is.
	h.statuses = []discovery.ScopeStatus{{ScopeID: a.ID, TenantID: "t_a", LastError: "discovery sweep refused: no SNMP profiles to try"}}
	if _, b := h.do(userA, http.MethodGet, apiPrefix+"/"+a.ID, nil); !strings.Contains(string(b), "no SNMP profiles to try") {
		t.Fatalf("a customer still sees its own refusal: %s", b)
	}
}
