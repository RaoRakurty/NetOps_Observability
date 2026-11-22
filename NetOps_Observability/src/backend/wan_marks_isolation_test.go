// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/wan"
)

// §3a for operator WAN marks (template: org_isolation_test.go), on the
// restricted-WAN fixture: acme (acme-wan, acme-spine), globex (globex-wan,
// globex-leaf), platform (stack-gw).

type wanMarksResp struct {
	Marks []wan.InterfaceMark `json:"marks"`
}

func (f *restrictedWanFixture) withMarks() {
	f.t.Helper()
	ms, err := newWanMarkStore(filepath.Join(f.t.TempDir(), "wan_marks.json"))
	if err != nil {
		f.t.Fatalf("newWanMarkStore: %v", err)
	}
	f.s.wanMarks = ms
}

func (f *restrictedWanFixture) markReq(method, path, body string, claims jwtClaims) *httptest.ResponseRecorder {
	f.t.Helper()
	w := httptest.NewRecorder()
	f.s.handleWanMarks(w, req(method, path, body, claims))
	return w
}

func TestWanMarksAreTheDeviceTenantsOnly(t *testing.T) {
	f := newRestrictedWanFixture(t)
	f.withMarks()

	// acme marks its own port; a tenant in the body is ignored.
	w := f.markReq(http.MethodPut, "/api/wan/marks",
		`{"device_id":"acme-wan","interface":"Ethernet9","mark":"not_wan","tenant_id":"globex"}`, f.acmeUser())
	if w.Code != http.StatusOK {
		t.Fatalf("acme PUT own mark = %d %s", w.Code, w.Body.String())
	}
	var stored wan.InterfaceMark
	if err := json.Unmarshal(w.Body.Bytes(), &stored); err != nil {
		t.Fatal(err)
	}
	if stored.TenantID != f.acme || stored.UpdatedBy != "a@acme" {
		t.Fatalf("owner must come from the device, author from the token: %+v", stored)
	}
	// globex marks its own.
	if w := f.markReq(http.MethodPut, "/api/wan/marks", `{"device_id":"globex-leaf","interface":"Ethernet7","mark":"wan"}`, f.globexUser()); w.Code != http.StatusOK {
		t.Fatalf("globex PUT own = %d", w.Code)
	}

	// Cross-tenant write / delete by id → 404, never 403 (no id disclosure).
	if w := f.markReq(http.MethodPut, "/api/wan/marks", `{"device_id":"globex-wan","interface":"Ethernet1","mark":"wan"}`, f.acmeUser()); w.Code != http.StatusNotFound {
		t.Fatalf("acme PUT on a globex device = %d, want 404", w.Code)
	}
	if w := f.markReq(http.MethodDelete, "/api/wan/marks?device_id=globex-leaf&interface=Ethernet7", "", f.acmeUser()); w.Code != http.StatusNotFound {
		t.Fatalf("acme DELETE a globex mark = %d, want 404", w.Code)
	}
	if w := f.markReq(http.MethodPut, "/api/wan/marks", `{"device_id":"no-such-device","interface":"Ethernet1","mark":"wan"}`, f.acmeUser()); w.Code != http.StatusNotFound {
		t.Fatalf("PUT on an unknown device = %d, want 404 (the same answer as another tenant's)", w.Code)
	}

	// Own-only list; as_tenant into another org is ignored for a tenant user.
	var own wanMarksResp
	f.get(f.s.handleWanMarks, "/api/wan/marks?as_tenant="+f.globex, f.acmeUser(), &own)
	if len(own.Marks) != 1 || own.Marks[0].DeviceID != "acme-wan" {
		t.Fatalf("acme lists %+v, want only its own mark", own.Marks)
	}
	var all wanMarksResp
	f.get(f.s.handleWanMarks, "/api/wan/marks", f.owner(), &all)
	if len(all.Marks) != 2 {
		t.Fatalf("the platform owner lists %+v, want both tenants' marks", all.Marks)
	}

	// The restriction: the owner scoped into acme sees and writes nothing.
	f.restrictAcme()
	var scoped wanMarksResp
	body := f.asTenant(f.s.handleWanMarks, "/api/wan/marks", f.acme, &scoped)
	if len(scoped.Marks) != 0 || strings.Contains(body, "acme-wan") {
		t.Fatalf("RESTRICTION LEAK: as_tenant=acme served %s", body)
	}
	if w := f.markReq(http.MethodPut, "/api/wan/marks", `{"device_id":"acme-wan","interface":"Ethernet1","mark":"wan"}`, ownerActing(f.owner(), f.acme)); w.Code != http.StatusNotFound {
		t.Fatalf("restricted write = %d, want 404", w.Code)
	}
	// …and acme's own view is unchanged.
	var after wanMarksResp
	f.get(f.s.handleWanMarks, "/api/wan/marks", f.acmeUser(), &after)
	if len(after.Marks) != 1 {
		t.Fatalf("acme's own marks changed when restricted: %+v", after.Marks)
	}
}

func TestWanMarksValidateAndDeleteOwn(t *testing.T) {
	f := newRestrictedWanFixture(t)
	f.withMarks()
	for _, body := range []string{
		`{"device_id":"acme-wan","interface":"Ethernet1","mark":"maybe"}`,
		`{"device_id":"acme-wan","interface":"","mark":"wan"}`,
		`{"device_id":"acme-wan","interface":"Eth\u0000ernet1","mark":"wan"}`,
		`{"device_id":"acme-wan","interface":"` + strings.Repeat("x", 200) + `","mark":"wan"}`,
		`not json`,
	} {
		if w := f.markReq(http.MethodPut, "/api/wan/marks", body, f.acmeUser()); w.Code != http.StatusBadRequest {
			t.Errorf("PUT %q = %d, want 400", body, w.Code)
		}
	}
	if w := f.markReq(http.MethodPut, "/api/wan/marks", `{"device_id":"acme-wan","interface":"Ethernet1","mark":"wan"}`, f.acmeUser()); w.Code != http.StatusOK {
		t.Fatalf("PUT = %d", w.Code)
	}
	if w := f.markReq(http.MethodDelete, "/api/wan/marks?device_id=acme-wan&interface=Ethernet1", "", f.acmeUser()); w.Code != http.StatusOK {
		t.Fatalf("DELETE own = %d", w.Code)
	}
	if w := f.markReq(http.MethodDelete, "/api/wan/marks?device_id=acme-wan&interface=Ethernet1", "", f.acmeUser()); w.Code != http.StatusNotFound {
		t.Fatalf("DELETE twice = %d, want 404", w.Code)
	}
}

// The marks reach the projection: "WAN" confirms an offered port (and it is
// measured), "not WAN" hides a confirmed one (and it stops being measured).
func TestWanMarksDecideTheProjection(t *testing.T) {
	f := newRestrictedWanFixture(t)
	f.withMarks()
	ctx := context.Background()
	acme := f.s.deviceVisibilityFor(f.acmeUser())

	before, _ := f.s.wanProjectAll(ctx, acme)
	keys := func(eps []WanEndpoint) map[string]bool {
		out := map[string]bool{}
		for _, e := range eps {
			out[e.Device+"/"+e.Interface] = true
		}
		return out
	}
	if !keys(before.Candidates)["acme-spine/Ethernet3"] || !keys(before.Endpoints)["acme-wan/Ethernet9"] {
		t.Fatalf("fixture: spine offered, wan Ethernet9 confirmed: %v / %v", keys(before.Endpoints), keys(before.Candidates))
	}
	for _, body := range []string{
		`{"device_id":"acme-spine","interface":"Ethernet3","mark":"wan"}`,
		`{"device_id":"acme-wan","interface":"Ethernet9","mark":"not_wan"}`,
	} {
		if w := f.markReq(http.MethodPut, "/api/wan/marks", body, f.acmeUser()); w.Code != http.StatusOK {
			t.Fatalf("PUT %s = %d", body, w.Code)
		}
	}
	after, _ := f.s.wanProjectAll(ctx, acme)
	if !keys(after.Endpoints)["acme-spine/Ethernet3"] || keys(after.Candidates)["acme-spine/Ethernet3"] {
		t.Fatalf("a port marked WAN must be confirmed: %v", keys(after.Endpoints))
	}
	if keys(after.Endpoints)["acme-wan/Ethernet9"] || keys(after.Candidates)["acme-wan/Ethernet9"] {
		t.Fatal("a port marked not WAN must disappear")
	}
	for _, e := range after.Endpoints {
		if e.Device == "acme-spine" && e.WanBasis != wan.BasisOperator {
			t.Fatalf("basis %q, want operator", e.WanBasis)
		}
	}
	// globex's view is untouched by acme's marks.
	g, _ := f.s.wanProjectAll(ctx, f.s.deviceVisibilityFor(f.globexUser()))
	for _, e := range append(g.Endpoints, g.Candidates...) {
		if strings.HasPrefix(e.Device, "acme-") {
			t.Fatalf("TENANT LEAK: globex saw %s", e.Device)
		}
	}
}
