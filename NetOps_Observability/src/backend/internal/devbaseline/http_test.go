// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package devbaseline

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeServer models the server's hooks: a caller header names the tenant and
// whether it holds write; each tenant sees only its own devices. A request
// field naming another tenant (as_tenant) must change nothing.
type fakeServer struct {
	devices  map[string]Device // id → device (owning tenant inside)
	collects int
	notWired string
	cur      func() Snapshot
}

func (f *fakeServer) api(st Store) *API {
	return &API{Store: st, Now: func() time.Time { return time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC) }, Hooks: Hooks{
		Authorize: func(w http.ResponseWriter, r *http.Request, live bool) (Caller, bool) {
			if r.Header.Get("X-Tenant") == "" {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return Caller{}, false
			}
			if live && r.Header.Get("X-Write") != "1" {
				http.Error(w, "forbidden", http.StatusForbidden)
				return Caller{}, false
			}
			return Caller{Subject: "u-" + r.Header.Get("X-Tenant")}, true
		},
		Device: func(r *http.Request, id string) (Device, bool) {
			d, ok := f.devices[id]
			if !ok || d.TenantID != r.Header.Get("X-Tenant") {
				return Device{}, false
			}
			return d, true
		},
		Collect: func(context.Context, *http.Request, Device) (Snapshot, string, error) {
			f.collects++
			if f.notWired != "" {
				return Snapshot{}, f.notWired, nil
			}
			return f.cur(), "", nil
		},
	}}
}

func do(t *testing.T, a *API, method, path, tenant string, write bool, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if tenant != "" {
		r.Header.Set("X-Tenant", tenant)
	}
	if write {
		r.Header.Set("X-Write", "1")
	}
	w := httptest.NewRecorder()
	if !a.ServeDeviceSubroute(w, r) {
		t.Fatalf("%s %s was not handled", method, path)
	}
	return w
}

func newFake(t *testing.T) (*fakeServer, *API) {
	f := &fakeServer{devices: map[string]Device{
		"dev-a": {ID: "dev-a", Name: "edge-a", TenantID: "t-a"},
		"dev-b": {ID: "dev-b", Name: "edge-b", TenantID: "t-b"},
	}}
	f.cur = func() Snapshot { s := baseFixture(t); s.TenantID = ""; return s }
	return f, f.api(NewFileStore(""))
}

func TestHTTPTakeListGetCompare(t *testing.T) {
	f, a := newFake(t)
	w := do(t, a, http.MethodPost, "/api/devices/dev-a/baselines", "t-a", true, `{"label":"CHG-1042"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("take: %d %s", w.Code, w.Body)
	}
	var taken Snapshot
	if err := json.Unmarshal(w.Body.Bytes(), &taken); err != nil {
		t.Fatal(err)
	}
	if taken.Label != "CHG-1042" || taken.TakenBy != "u-t-a" || taken.DeviceName != "edge-a" || taken.ID == "" {
		t.Fatalf("taken: %+v", taken)
	}
	if strings.Contains(w.Body.String(), "tenant") {
		t.Errorf("a baseline response must not carry the tenant: %s", w.Body)
	}
	w = do(t, a, http.MethodGet, "/api/devices/dev-a/baselines", "t-a", false, "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), taken.ID) {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	w = do(t, a, http.MethodGet, "/api/devices/dev-a/baselines/"+taken.ID, "t-a", false, "")
	if w.Code != http.StatusOK {
		t.Fatalf("get: %d %s", w.Code, w.Body)
	}
	// After the change: an OSPF neighbour is gone and an interface is down.
	f.cur = func() Snapshot {
		s := baseFixture(t)
		s.Neighbors = s.Neighbors[:2]
		s.Interfaces[2].Oper = "down"
		return s
	}
	w = do(t, a, http.MethodPost, "/api/devices/dev-a/baselines/compare", "t-a", true, "")
	if w.Code != http.StatusOK {
		t.Fatalf("compare: %d %s", w.Code, w.Body)
	}
	var dv DiffView
	if err := json.Unmarshal(w.Body.Bytes(), &dv); err != nil {
		t.Fatal(err)
	}
	if len(dv.Changes) != 2 || dv.Baseline.ID != taken.ID || len(dv.Lines) != 2 {
		t.Fatalf("diff: %+v", dv)
	}
	if !strings.Contains(dv.Lines[0], "GigabitEthernet3 was up/up before the change and is up/down now") {
		t.Errorf("worst change first: %v", dv.Lines)
	}
}

// §3a: tenant b never sees, reads, takes or compares tenant a's baselines, by
// device id or baseline id; an as_tenant parameter or body field changes
// nothing; another tenant's device is the same 404 as an unknown one.
func TestHTTPCrossTenantIsolation(t *testing.T) {
	f, a := newFake(t)
	w := do(t, a, http.MethodPost, "/api/devices/dev-a/baselines", "t-a", true, "")
	var taken Snapshot
	if err := json.Unmarshal(w.Body.Bytes(), &taken); err != nil {
		t.Fatal(err)
	}
	collects := f.collects
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/devices/dev-a/baselines", ""},
		{http.MethodGet, "/api/devices/dev-a/baselines?as_tenant=t-a", ""},
		{http.MethodGet, "/api/devices/dev-a/baselines/" + taken.ID, ""},
		{http.MethodPost, "/api/devices/dev-a/baselines", `{"label":"x"}`},
		{http.MethodPost, "/api/devices/dev-a/baselines/compare", ""},
		{http.MethodPost, "/api/devices/dev-a/baselines/compare?as_tenant=t-a", ""},
		{http.MethodGet, "/api/devices/dev-unknown/baselines", ""},
	} {
		if w := do(t, a, tc.method, tc.path, "t-b", true, tc.body); w.Code != http.StatusNotFound {
			t.Errorf("tenant b %s %s: %d, want 404", tc.method, tc.path, w.Code)
		}
	}
	// Tenant a's baseline id under tenant b's own device is not found either.
	if w := do(t, a, http.MethodGet, "/api/devices/dev-b/baselines/"+taken.ID, "t-b", false, ""); w.Code != http.StatusNotFound {
		t.Errorf("a's baseline id under b's device: %d, want 404", w.Code)
	}
	// A tenant smuggled in the body is refused as an unknown field, never used.
	if w := do(t, a, http.MethodPost, "/api/devices/dev-b/baselines", "t-b", true, `{"tenant_id":"t-a"}`); w.Code != http.StatusBadRequest {
		t.Errorf("tenant in body: %d, want 400", w.Code)
	}
	w = do(t, a, http.MethodGet, "/api/devices/dev-b/baselines?as_tenant=t-a", "t-b", false, "")
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), taken.ID) {
		t.Errorf("tenant b's own list with as_tenant=t-a leaked a's baseline: %s", w.Body)
	}
	if f.collects != collects {
		t.Errorf("a refused request still read a device (%d reads)", f.collects-collects)
	}
}

func TestHTTPPermissionsAndNotWired(t *testing.T) {
	f, a := newFake(t)
	if w := do(t, a, http.MethodGet, "/api/devices/dev-a/baselines", "", false, ""); w.Code != http.StatusUnauthorized {
		t.Errorf("anonymous: %d", w.Code)
	}
	// Listing needs read; taking and comparing are live reads and need write.
	if w := do(t, a, http.MethodGet, "/api/devices/dev-a/baselines", "t-a", false, ""); w.Code != http.StatusOK {
		t.Errorf("read list: %d", w.Code)
	}
	for _, p := range []string{"/api/devices/dev-a/baselines", "/api/devices/dev-a/baselines/compare"} {
		if w := do(t, a, http.MethodPost, p, "t-a", false, ""); w.Code != http.StatusForbidden {
			t.Errorf("POST %s without write: %d, want 403", p, w.Code)
		}
	}
	if f.collects != 0 {
		t.Fatalf("a refused request read the device")
	}
	// Compare with no baseline yet says so.
	if w := do(t, a, http.MethodPost, "/api/devices/dev-a/baselines/compare", "t-a", true, ""); w.Code != http.StatusNotFound ||
		!strings.Contains(w.Body.String(), "no baseline has been taken") {
		t.Errorf("compare without a baseline: %d %s", w.Code, w.Body)
	}
	// Nothing could be read: 409 with the reason, nothing stored.
	f.notWired = "live device-state collection is not wired on this deployment — no command was run"
	w := do(t, a, http.MethodPost, "/api/devices/dev-a/baselines", "t-a", true, "")
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "not wired") {
		t.Errorf("not wired: %d %s", w.Code, w.Body)
	}
	if l, _ := a.Store.List(context.Background(), "t-a", "dev-a"); len(l) != 0 {
		t.Errorf("a read that did not run stored a baseline: %v", l)
	}
	// Bounds: an over-long label and an oversized body are refused.
	f.notWired = ""
	if w := do(t, a, http.MethodPost, "/api/devices/dev-a/baselines", "t-a", true, `{"label":"`+strings.Repeat("x", 81)+`"}`); w.Code != http.StatusBadRequest {
		t.Errorf("long label: %d", w.Code)
	}
	if w := do(t, a, http.MethodPost, "/api/devices/dev-a/baselines", "t-a", true, strings.Repeat(" ", maxRequestBody+10)); w.Code != http.StatusBadRequest {
		t.Errorf("oversized body: %d", w.Code)
	}
	if w := do(t, a, http.MethodDelete, "/api/devices/dev-a/baselines", "t-a", true, ""); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE: %d (baselines are never deleted through the API; retention trims them)", w.Code)
	}
}

func TestPath(t *testing.T) {
	cases := []struct {
		in, id, rest string
		ok           bool
	}{
		{"/api/devices/dev-a/baselines", "dev-a", "", true},
		{"/api/devices/dev-a/baselines/", "dev-a", "", true},
		{"/api/devices/dev-a/baselines/compare", "dev-a", "compare", true},
		{"/api/devices/dev-a/baselines/abc", "dev-a", "abc", true},
		{"/api/devices/dev-a/baselines/abc/x", "", "", false},
		{"/api/devices/dev-a/baselinesx", "", "", false},
		{"/api/devices/dev-a", "", "", false},
		{"/api/devices//baselines", "", "", false},
		{"/api/devices/a/b/baselines", "", "", false},
	}
	for _, c := range cases {
		id, rest, ok := Path(c.in)
		if ok != c.ok || id != c.id || rest != c.rest {
			t.Errorf("Path(%q) = %q %q %v", c.in, id, rest, ok)
		}
	}
}
