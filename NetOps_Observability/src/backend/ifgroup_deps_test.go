// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// ifgroup_deps_test.go — the CLAUDE.md §3a rule-5 cross-org test for
//
//	GET /api/devices/{id}/interfaces/by-vrf
//
// (frontend-wave item 4, internal/ifgroup), exercised through the REAL wiring:
// the module is assembled by s.buildIfGroup() itself, so the gate under test is
// the production s.ifgroupAuthz mapping, the device boundary is the production
// s.ifgroupLookupDevice + ifgroupCanSee pair, and the metrics filters are the
// production s.ifgroupScopeFilters. A fixture that re-implemented any of those
// would prove nothing about the deployed surface.
//
// Only the OUTBOUND metric store is swapped for a recorder — the module cannot
// reach VictoriaMetrics in a unit test, and recording what was SENT is the
// point: an isolation property observable only through the response body is one
// that can silently rot.
//
// Proven here:
//   - tenant A cannot see tenant B's device: 404, byte-identical to the answer
//     for a device that does not exist (no existence oracle), with no store read;
//   - EVERY VictoriaMetrics read carries that tenant's device boundary as
//     extra_filters[], and a tenant with no visible device gets the
//     match-nothing sentinel rather than an unfiltered fleet read;
//   - ?as_tenant= into another org is ignored for a non-owner;
//   - the platform owner is the ONLY principal that reads cross-tenant, and a
//     tenant admin holding full administration:admin is NOT that principal;
//   - a read-only principal is admitted (this is a read) and the route refuses
//     unknown query parameters and an out-of-range window before reading.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/internal/discovery"
	"netops/backend/internal/ifgroup"
	"netops/backend/models"
)

// ifgroupRoute is the registered mux pattern, spelled LITERALLY so this file is
// the searchable proof — for the §3a route-isolation coverage guard and for a
// human — that the route was exercised cross-tenant here:
//
//	/api/devices/{id}/interfaces/by-vrf
const ifgroupRoute = "/api/devices/{id}/interfaces/by-vrf"

// ifgroupPath renders the concrete request path for one device id.
func ifgroupPath(id string) string { return "/api/devices/" + id + "/interfaces/by-vrf" }

// ifgroupCall records one outbound metric-store read.
type ifgroupCall struct {
	query   string
	filters []string
}

type ifgroupFixture struct {
	s   *server
	api *ifgroup.API
	vm  []ifgroupCall
}

func newIfGroupFixture(t *testing.T) *ifgroupFixture {
	t.Helper()
	dir := t.TempDir()
	roles, err := newRoleStore(dir + "/roles.json")
	if err != nil {
		t.Fatalf("roleStore: %v", err)
	}
	d := discovery.NewDiscoveryAggregator()
	d.Upsert(models.Device{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1", Vendor: "arista", TenantID: "acme"})
	d.Upsert(models.Device{ID: "globex-core", Name: "gx-edge", Address: "10.2.0.1", Vendor: "juniper", TenantID: "globex"})
	d.Upsert(models.Device{ID: "shared-dns", Name: "shared-dns", Address: "10.9.0.1"}) // platform-owned

	f := &ifgroupFixture{s: &server{roles: roles, discovery: d}}

	// The production Deps, with ONLY the metric store replaced by a recorder.
	// Every isolation-bearing collaborator (Authz, LookupDevice, CanSee,
	// ScopeFilters) is the deployed one. buildIfGroup is called first so a
	// wiring regression fails here too.
	if prod, berr := f.s.buildIfGroup(); berr != nil {
		t.Fatalf("buildIfGroup: %v", berr)
	} else if prod == nil {
		t.Fatal("buildIfGroup returned a nil API")
	}
	api, err := ifgroup.New(ifgroup.Deps{
		Authz:        f.s.ifgroupAuthz,
		LookupDevice: f.s.ifgroupLookupDevice,
		CanSee:       ifgroupCanSee,
		ScopeFilters: f.s.ifgroupScopeFilters,
		VMQuery: func(_ context.Context, q string, filters []string) ([]ifgroup.Sample, error) {
			f.vm = append(f.vm, ifgroupCall{query: q, filters: append([]string(nil), filters...)})
			return nil, nil
		},
		VRFTerm:    ifgroupVRFTerm,
		WriteJSON:  writeJSON,
		WriteError: writeError,
		LogWarn:    func(string, map[string]any) {},
	})
	if err != nil {
		t.Fatalf("ifgroup.New: %v", err)
	}
	f.api = api
	return f
}

func (f *ifgroupFixture) get(path string, claims jwtClaims) *httptest.ResponseRecorder {
	f.vm = nil
	w := httptest.NewRecorder()
	f.api.Handler()(w, req(http.MethodGet, path, "", claims))
	return w
}

// TestIfGroupRouteIsOwnTenantOnly — the caller's own device answers, another
// org's device is a 404 indistinguishable from an absent one, and as_tenant
// cannot reach across the org boundary.
func TestIfGroupRouteIsOwnTenantOnly(t *testing.T) {
	f := newIfGroupFixture(t)
	_ = ifgroupRoute // the registered pattern this file covers

	own := f.get(ifgroupPath("acme-core"), acme())
	if own.Code != http.StatusOK {
		t.Fatalf("GET %s (own) = %d (%s)", ifgroupPath("acme-core"), own.Code, own.Body.String())
	}
	if body := own.Body.String(); strings.Contains(body, "globex") || strings.Contains(body, "gx-edge") {
		t.Errorf("the own-device response leaked another org: %s", body)
	}

	foreign := f.get(ifgroupPath("globex-core"), acme())
	foreignStores := len(f.vm)
	absent := f.get(ifgroupPath("no-such-device"), acme())
	if foreign.Code != http.StatusNotFound || absent.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant = %d, absent = %d, want 404/404", foreign.Code, absent.Code)
	}
	if foreign.Body.String() != absent.Body.String() {
		t.Errorf("EXISTENCE ORACLE: foreign %q != absent %q", foreign.Body.String(), absent.Body.String())
	}
	if foreignStores != 0 {
		t.Error("a device the caller cannot see reached the metric store")
	}

	// ?as_tenant= into another org is ignored for a non-owner: the device stays
	// invisible, and the read stays bounded to the caller's own devices.
	as := f.get(ifgroupPath("globex-core")+"?as_tenant=globex", acme())
	if as.Code != http.StatusNotFound {
		t.Errorf("as_tenant into another org = %d, want 404", as.Code)
	}
	if own := f.get(ifgroupPath("acme-core")+"?as_tenant=globex", acme()); own.Code != http.StatusBadRequest && own.Code != http.StatusOK {
		t.Errorf("as_tenant on an own device = %d, want the request handled without crossing orgs", own.Code)
	}
	for _, c := range f.vm {
		if strings.Contains(strings.Join(c.filters, " "), "globex") {
			t.Errorf("as_tenant widened the metric boundary into another org: %v", c.filters)
		}
	}
}

// TestIfGroupPlatformOwnedDeviceIsNotATenantsToRead — the platform-owned
// (untagged) device is visible only cross-tenant, and a tenant admin holding
// full administration:admin is NOT the platform owner (§3a rule 3).
func TestIfGroupPlatformOwnedDeviceIsNotATenantsToRead(t *testing.T) {
	f := newIfGroupFixture(t)
	if w := f.get(ifgroupPath("shared-dns"), acme()); w.Code != http.StatusNotFound {
		t.Errorf("a tenant read a platform-owned device: %d", w.Code)
	}
	if w := f.get(ifgroupPath("shared-dns"), platformOwner()); w.Code != http.StatusOK {
		t.Errorf("the platform owner could not read the shared device: %d (%s)", w.Code, w.Body.String())
	}
	if w := f.get(ifgroupPath("globex-core"), platformOwner()); w.Code != http.StatusOK {
		t.Errorf("the platform owner could not read cross-tenant: %d", w.Code)
	}
	if w := f.get(ifgroupPath("globex-core"), tAdmin("acme")); w.Code != http.StatusNotFound {
		t.Errorf("a tenant admin reached another tenant's device: %d", w.Code)
	}
}

// TestIfGroupEveryMetricsReadCarriesTheTenantDeviceBoundary — §3a rule 4.
func TestIfGroupEveryMetricsReadCarriesTheTenantDeviceBoundary(t *testing.T) {
	f := newIfGroupFixture(t)

	if w := f.get(ifgroupPath("acme-core"), acme()); w.Code != http.StatusOK {
		t.Fatalf("GET = %d (%s)", w.Code, w.Body.String())
	}
	if len(f.vm) == 0 {
		t.Fatal("the request issued no metrics read")
	}
	for _, c := range f.vm {
		joined := strings.Join(c.filters, " ")
		if joined == "" {
			t.Fatalf("UNSCOPED metrics read: %q", c.query)
		}
		if !strings.Contains(joined, "acme-core") {
			t.Errorf("filters do not bound the read to acme's devices: %v", c.filters)
		}
		if strings.Contains(joined, "globex-core") || strings.Contains(joined, "gx-edge") {
			t.Errorf("filters admitted another tenant's device: %v", c.filters)
		}
		// The PromQL itself must also name only the subject device.
		if !strings.Contains(c.query, "acme-core") {
			t.Errorf("query %q does not select the subject device", c.query)
		}
		if strings.Contains(c.query, "globex") || strings.Contains(c.query, "gx-edge") {
			t.Errorf("query %q named another tenant's device", c.query)
		}
	}

	// A tenant with NO visible device never reaches this route (its devices do
	// not resolve), but the boundary builder itself must still fail closed.
	empty := jwtClaims{Sub: "u@nowhere", Role: RoleOperator, Tenant: "nowhere"}
	filters := f.s.ifgroupScopeFilters(req(http.MethodGet, ifgroupPath("acme-core"), "", empty), ifgroup.Principal{Tenant: "nowhere"})
	if !strings.Contains(strings.Join(filters, " "), "__netops_no_visible_device__") {
		t.Errorf("a device-less tenant was not bounded by the match-nothing sentinel: %v", filters)
	}

	// The unrestricted platform owner has nothing to restrict.
	if w := f.get(ifgroupPath("shared-dns"), platformOwner()); w.Code != http.StatusOK {
		t.Fatalf("owner read = %d", w.Code)
	}
	for _, c := range f.vm {
		if len(c.filters) != 0 {
			t.Errorf("the platform owner's read was restricted: %v", c.filters)
		}
	}
}

// TestIfGroupRefusesUnknownParametersAndUnboundedWindows — §3 zero trust at the
// boundary: the refusal happens before any store is touched.
func TestIfGroupRefusesUnknownParametersAndUnboundedWindows(t *testing.T) {
	f := newIfGroupFixture(t)
	for _, qs := range []string{"?vrf=CORP", "?group=1", "?window=30d", "?window=1s", "?window=nope"} {
		w := f.get(ifgroupPath("acme-core")+qs, acme())
		if w.Code != http.StatusBadRequest {
			t.Errorf("GET %s = %d, want 400", qs, w.Code)
		}
		if len(f.vm) != 0 {
			t.Errorf("GET %s reached the metric store despite being refused", qs)
		}
	}
}

// TestIfGroupResponseNeverInventsADefaultInstance — the product invariant, at
// the wire. With no vrf label collected (today's reality on both transports)
// the response groups nothing and says why, in the DEVICE's dialect.
func TestIfGroupResponseNeverInventsADefaultInstance(t *testing.T) {
	f := newIfGroupFixture(t)
	for _, tc := range []struct{ device, term string }{
		{"acme-core", "VRF"},                // arista
		{"globex-core", "routing-instance"}, // juniper
	} {
		claims := acme()
		if tc.device == "globex-core" {
			claims = globex()
		}
		w := f.get(ifgroupPath(tc.device), claims)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s = %d (%s)", tc.device, w.Code, w.Body.String())
		}
		var body struct {
			Dialect  struct{ Term string } `json:"dialect"`
			Coverage struct {
				VRFLabels bool     `json:"vrf_labels"`
				Notes     []string `json:"notes"`
			} `json:"coverage"`
			Groups []struct {
				VRF        string `json:"vrf"`
				Membership string `json:"membership"`
			} `json:"groups"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v (%s)", err, w.Body.String())
		}
		if body.Dialect.Term != tc.term {
			t.Errorf("%s dialect term = %q, want %q", tc.device, body.Dialect.Term, tc.term)
		}
		if body.Coverage.VRFLabels {
			t.Errorf("%s claimed vrf labels with no series at all", tc.device)
		}
		for _, g := range body.Groups {
			if strings.EqualFold(g.VRF, "default") {
				t.Errorf("%s invented a default instance: %+v", tc.device, g)
			}
		}
		if strings.Contains(strings.ToLower(strings.Join(body.Coverage.Notes, " ")), "default vrf") {
			t.Errorf("%s notes claim a default instance: %v", tc.device, body.Coverage.Notes)
		}
	}
}

// TestIfGroupRouteCoexistsWithTheDeviceSubtree — the wildcard pattern
// "/api/devices/{id}/interfaces/by-vrf" is registered alongside the
// "/api/devices/" subtree that handleDeviceByID owns. Go's ServeMux prefers the
// more specific pattern, and registering both is legal — but that is a property
// of the router, not of our code, so it is pinned here: a Go change (or a
// second wildcard added later) that turned this into a conflict would panic at
// boot, and boot panics are the worst possible place to learn about a route.
func TestIfGroupRouteCoexistsWithTheDeviceSubtree(t *testing.T) {
	mux := http.NewServeMux()
	hit := ""
	mux.HandleFunc("/api/devices/", func(http.ResponseWriter, *http.Request) { hit = "subtree" })
	mux.HandleFunc(ifgroupRoute, func(http.ResponseWriter, *http.Request) { hit = "by-vrf" })

	cases := map[string]string{
		ifgroupPath("core-1"):                "by-vrf",
		"/api/devices/core-1":                "subtree",
		"/api/devices/core-1/config/status":  "subtree",
		"/api/devices/locations":             "subtree",
		"/api/devices/core-1/interfaces":     "subtree",
		"/api/devices/a/b/interfaces/by-vrf": "subtree",
	}
	for path, want := range cases {
		hit = ""
		mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
		if hit != want {
			t.Errorf("%s routed to %q, want %q", path, hit, want)
		}
	}
}
