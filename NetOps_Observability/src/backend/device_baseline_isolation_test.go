// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// device_baseline_isolation_test.go — the CLAUDE.md §3a rule 5 test for the
// before/after change baselines (/api/devices/{id}/baselines…, Iris change
// assistance), through the REAL server dispatch (handleDeviceByID) and the
// real permission store. org_isolation_test.go / rca_resolution_isolation_test.go
// are the template.
//
// Proven here:
//   - own-only list; another tenant's device → 404 for list, get, take and
//     compare, and nothing is read from the device or stored;
//   - a baseline id of another tenant under the caller's own device → 404;
//   - ?as_tenant= is ignored for a non-owner;
//   - a read-only user may list but not take or compare (a live device read);
//   - with no capture transport, take answers 409 with the reason and stores
//     nothing — a baseline is never fabricated;
//   - the Iris seam resolves through the caller's own inventory (another
//     tenant's device is ai.ErrNotFound) and stores nothing on a refusal.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/devbaseline"
	"netops/backend/internal/protocoldiag"
	"netops/backend/internal/showparse"
	"netops/backend/models"
)

func baselineServer(t *testing.T) *server {
	t.Helper()
	s := tenantServer(t)
	// acme's router is a lab-shaped IOS-XE edge, so the platform gate passes
	// and the transport gate is the one that answers.
	s.discovery.Upsert(models.Device{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1", TenantID: "acme",
		Vendor: "Cisco", OS: "IOS-XE", Model: "C8000V"})
	s.deviceBaselines = devbaseline.NewFileStore("")
	return s
}

func baselineSeed(t *testing.T, s *server, tenant, deviceID string) devbaseline.Snapshot {
	t.Helper()
	total := int64(10)
	snap, err := s.deviceBaselines.Put(context.Background(), tenant, devbaseline.Snapshot{
		TenantID: tenant, DeviceID: deviceID, DeviceName: deviceID, TakenBy: "seed@" + tenant,
		TakenAt: time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC), Label: "CHG-" + tenant,
		Interfaces: []devbaseline.Interface{{Name: "GigabitEthernet1", Admin: "up", Oper: "up"}},
		Neighbors:  []devbaseline.Neighbor{}, NotRead: []string{}, RouteTotal: &total,
	})
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func baselineDo(s *server, method, path, body string, claims jwtClaims) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.handleDeviceByID(w, req(method, path, body, claims))
	return w
}

func TestDeviceBaselineCrossTenantIsolation(t *testing.T) {
	s := baselineServer(t)
	acmeSnap := baselineSeed(t, s, "acme", "acme-core")
	globexSnap := baselineSeed(t, s, "globex", "globex-core")

	// Own-only list.
	w := baselineDo(s, http.MethodGet, "/api/devices/acme-core/baselines", "", acme())
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), acmeSnap.ID) || strings.Contains(w.Body.String(), globexSnap.ID) {
		t.Fatalf("acme list: %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "globex") {
		t.Fatalf("TENANT LEAK in acme's list: %s", w.Body)
	}
	// Another tenant's device: 404 everywhere, whatever the acting-tenant hint.
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/devices/globex-core/baselines"},
		{http.MethodGet, "/api/devices/globex-core/baselines?as_tenant=globex"},
		{http.MethodGet, "/api/devices/globex-core/baselines/" + globexSnap.ID},
		{http.MethodPost, "/api/devices/globex-core/baselines"},
		{http.MethodPost, "/api/devices/globex-core/baselines/compare"},
		{http.MethodPost, "/api/devices/globex-core/baselines/compare?as_tenant=globex"},
		{http.MethodGet, "/api/devices/shared-dns/baselines"}, // a platform device is not acme's
	} {
		if w := baselineDo(s, tc.method, tc.path, "", acme()); w.Code != http.StatusNotFound {
			t.Errorf("acme %s %s = %d, want 404 (%s)", tc.method, tc.path, w.Code, w.Body)
		}
	}
	// globex's baseline id under acme's own device is not found.
	if w := baselineDo(s, http.MethodGet, "/api/devices/acme-core/baselines/"+globexSnap.ID, "", acme()); w.Code != http.StatusNotFound {
		t.Errorf("globex's id under acme's device = %d, want 404", w.Code)
	}
	// acme's own baseline by id.
	if w := baselineDo(s, http.MethodGet, "/api/devices/acme-core/baselines/"+acmeSnap.ID, "", acme()); w.Code != http.StatusOK {
		t.Errorf("acme get own = %d", w.Code)
	}
	// Nothing was added to globex by any of acme's attempts.
	if l, _ := s.deviceBaselines.List(context.Background(), "globex", "globex-core"); len(l) != 1 {
		t.Errorf("globex now holds %d baselines, want 1", len(l))
	}
	// The platform owner sees a tenant's baselines (cross-tenant by design).
	if w := baselineDo(s, http.MethodGet, "/api/devices/globex-core/baselines", "", superA()); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), globexSnap.ID) {
		t.Errorf("super-admin list: %d %s", w.Code, w.Body)
	}
}

func TestDeviceBaselinePermissionsAndNoFabrication(t *testing.T) {
	s := baselineServer(t)
	ro := jwtClaims{Sub: "r@acme", Role: RoleReadOnly, Tenant: "acme"}
	if w := baselineDo(s, http.MethodGet, "/api/devices/acme-core/baselines", "", ro); w.Code != http.StatusOK {
		t.Fatalf("read-only list = %d (%s)", w.Code, w.Body)
	}
	for _, p := range []string{"/api/devices/acme-core/baselines", "/api/devices/acme-core/baselines/compare"} {
		if w := baselineDo(s, http.MethodPost, p, "", ro); w.Code != http.StatusForbidden {
			t.Errorf("read-only POST %s = %d, want 403", p, w.Code)
		}
	}
	// No capture transport on this server: take says so and stores nothing.
	w := baselineDo(s, http.MethodPost, "/api/devices/acme-core/baselines", `{"label":"CHG-1"}`, acme())
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "no command was run") {
		t.Fatalf("take without transport = %d (%s), want 409 with the reason", w.Code, w.Body)
	}
	if l, _ := s.deviceBaselines.List(context.Background(), "acme", "acme-core"); len(l) != 0 {
		t.Fatalf("a read that never ran stored a baseline: %+v", l)
	}
	// No store: the routes say so rather than 404-ing as if the device were gone.
	s.deviceBaselines = nil
	if w := baselineDo(s, http.MethodGet, "/api/devices/acme-core/baselines", "", acme()); w.Code != http.StatusServiceUnavailable {
		t.Errorf("no store = %d, want 503", w.Code)
	}
	// The device route itself is untouched.
	if w := baselineDo(s, http.MethodGet, "/api/devices/acme-core", "", acme()); w.Code != http.StatusOK {
		t.Errorf("device GET = %d", w.Code)
	}
}

func TestDeviceBaselineIrisSeamIsolation(t *testing.T) {
	s := baselineServer(t)
	baselineSeed(t, s, "globex", "globex-core")
	r := req(http.MethodPost, "/api/ai/ask", "", acme())
	seam := s.aiDeviceBaseline(r, acme())
	for _, ref := range []string{"globex-core", "shared-dns", "nope"} {
		for _, op := range []string{ai.BaselineTake, ai.BaselineCompare} {
			if _, err := seam(context.Background(), ai.Principal{Tenant: "acme"}, ai.BaselineRequest{DeviceID: ref, Op: op}); !errors.Is(err, ai.ErrNotFound) {
				t.Errorf("acme %s %s: err = %v, want ErrNotFound", op, ref, err)
			}
		}
	}
	// Own device, no transport: an honest NotWired, nothing stored.
	rep, err := seam(context.Background(), ai.Principal{Tenant: "acme"}, ai.BaselineRequest{DeviceID: "acme-core", Op: ai.BaselineTake})
	if err != nil || !strings.Contains(rep.NotWired, "no command was run") {
		t.Fatalf("own take: %+v %v", rep, err)
	}
	rep, err = seam(context.Background(), ai.Principal{Tenant: "acme"}, ai.BaselineRequest{DeviceID: "acme-core", Op: ai.BaselineCompare})
	if err != nil || !strings.Contains(rep.NotWired, "no baseline has been taken of acme-core yet") {
		t.Fatalf("own compare without a baseline: %+v %v", rep, err)
	}
	if l, _ := s.deviceBaselines.List(context.Background(), "acme", "acme-core"); len(l) != 0 {
		t.Fatalf("stored %d baselines without a read", len(l))
	}
	// The deps wire the seam only with a store and an inventory.
	if s.aiTroubleshootDeps(r, acme()).DeviceBaseline == nil {
		t.Error("the Iris seam is not wired although the store exists")
	}
	s.deviceBaselines = nil
	if s.aiTroubleshootDeps(r, acme()).DeviceBaseline != nil {
		t.Error("the Iris seam is wired without a store")
	}
}

// The change review's "was a baseline taken?" seam: the caller's own device
// reports its newest baseline's time; another tenant's device (even one that
// HAS a baseline) is ai.ErrNotFound, never "none" and never its time.
func TestDeviceBaselineAtSeamIsolation(t *testing.T) {
	s := baselineServer(t)
	baselineSeed(t, s, "globex", "globex-core")
	r := req(http.MethodPost, "/api/ai/ask", "", acme())
	at := s.aiTroubleshootDeps(r, acme()).DeviceBaselineAt
	if at == nil {
		t.Fatal("DeviceBaselineAt is not wired although the store exists")
	}
	p := ai.Principal{Tenant: "acme"}
	for _, ref := range []string{"globex-core", "shared-dns", "nope"} {
		if when, ok, err := at(context.Background(), p, ref); !errors.Is(err, ai.ErrNotFound) || ok || !when.IsZero() {
			t.Errorf("acme → %s: (%v, %v, %v), want ErrNotFound", ref, when, ok, err)
		}
	}
	if _, ok, err := at(context.Background(), p, "acme-core"); err != nil || ok {
		t.Fatalf("own device with no baseline: ok=%v err=%v, want ok=false", ok, err)
	}
	older := baselineSeed(t, s, "acme", "acme-core")
	newer, err := s.deviceBaselines.Put(context.Background(), "acme", devbaseline.Snapshot{
		TenantID: "acme", DeviceID: "acme-core", DeviceName: "acme-core", TakenBy: "seed@acme",
		TakenAt: older.TakenAt.Add(2 * time.Hour), Neighbors: []devbaseline.Neighbor{}, NotRead: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	when, ok, err := at(context.Background(), p, "acme-core")
	if err != nil || !ok || !when.Equal(newer.TakenAt) {
		t.Fatalf("own device: (%v, %v, %v), want the newest baseline %v", when, ok, err, newer.TakenAt)
	}
	s.deviceBaselines = nil
	if s.aiTroubleshootDeps(r, acme()).DeviceBaselineAt != nil {
		t.Error("DeviceBaselineAt is wired without a store")
	}
}

// A command that failed inside a partial read is CANNOT COMPARE, never an empty
// table; a failed area carries its reason; a half-read overlay is dropped.
func TestBaselineReadProjection(t *testing.T) {
	st := protocoldiag.DeviceState{Status: protocoldiag.DeviceStatusPartial,
		Commands: []protocoldiag.CollectedCommand{{SpecID: showparse.CmdOSPFNeighbor}, {SpecID: showparse.CmdISISNeighbor, Err: "timeout"}},
		Parsed:   []showparse.Result{{CmdID: showparse.CmdOSPFNeighbor, IGPNeighbors: []showparse.IGPNeighbor{{Proto: "ospf", ID: "10.0.0.2", State: "FULL/DR"}}}}}
	snap := devbaseline.Build([]devbaseline.Read{baselineRead(devbaseline.SectionIGP, st)}, nil)
	if len(snap.Neighbors) != 1 || len(snap.NotRead) != 1 || !strings.HasPrefix(snap.NotRead[0], "isis:") {
		t.Fatalf("partial read: %+v", snap)
	}
	failed := baselineRead(devbaseline.SectionBGP, protocoldiag.DeviceState{Status: protocoldiag.DeviceStatusTimedOut, Note: "the device did not answer within its collection deadline"})
	if failed.NotRead == "" || len(failed.Results) != 0 {
		t.Fatalf("timed out: %+v", failed)
	}
	if ov := baselineOverlay(ai.OverlayState{Read: true, Member: true, ControlRead: true}); ov != nil {
		t.Errorf("a half-read overlay was kept: %+v", ov)
	}
	ov := baselineOverlay(ai.OverlayState{Read: true, Member: true, ControlRead: true, DataRead: true, OMPUp: 2,
		Transports: []ai.OverlayTransportState{{Color: "mpls", Sessions: 6, Up: 6}, {Color: "biz-internet", Sessions: 6, Up: 5}}})
	if ov == nil || ov.ControlUp != 2 || ov.ControlTotal != 2 || ov.BFDUp != 11 || ov.BFDTotal != 12 {
		t.Errorf("overlay: %+v", ov)
	}
}
