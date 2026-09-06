// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pcap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// http_test.go — the §3a rule-5 cross-org test for the pcap subtree, plus the
// gate-choice and audit assertions. A PCAP is customer payload, so "another
// tenant cannot reach it" is the single most important property in this module.

// seed stores one finished capture for a tenant/device and returns its id.
func (f *fixture) seed(t *testing.T, tenant, device, id, iface string) Capture {
	t.Helper()
	sealed, err := f.sealer.Seal(tenant, BlobField(device, id), string(samplePCAP(2)))
	if err != nil {
		t.Fatal(err)
	}
	ref, err := f.blobs.Put(tenant, device, id, sealed)
	if err != nil {
		t.Fatal(err)
	}
	ended := f.now
	c := Capture{
		TenantID: tenant, DeviceID: device, ID: id, Interface: iface,
		DurationSec: 30, MaxPackets: 100, StartedAt: f.now.Add(-time.Minute),
		ExpiresAt: f.now, EndedAt: &ended, Status: StatusStored,
		Packets: 2, Bytes: int64(len(samplePCAP(2))), BlobRef: ref, Actor: "u@" + tenant,
	}
	if err := f.store.Put(context.Background(), tenant, false, c); err != nil {
		t.Fatal(err)
	}
	return c
}

const (
	acmeCap   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"
	globexCap = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2"
)

func seededFixture(t *testing.T) *fixture {
	t.Helper()
	fx := newFixture(t, nil)
	fx.seed(t, "acme", "acme-core", acmeCap, "Ethernet1/1")
	fx.seed(t, "globex", "globex-core", globexCap, "Ethernet1/1")
	return fx
}

func TestPcapListIsOwnTenantOnly(t *testing.T) {
	fx := seededFixture(t)

	w := fx.as("acme", false).do(http.MethodGet, "/api/devices/acme-core/pcap", "")
	if w.Code != http.StatusOK {
		t.Fatalf("own list = %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), acmeCap) {
		t.Fatalf("acme's own capture is missing — the guard would be vacuous: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), globexCap) || strings.Contains(w.Body.String(), "globex") {
		t.Fatalf("TENANT LEAK: acme's list carried globex data: %s", w.Body.String())
	}

	w = fx.as("globex", false).do(http.MethodGet, "/api/devices/globex-core/pcap", "")
	if !strings.Contains(w.Body.String(), globexCap) || strings.Contains(w.Body.String(), acmeCap) {
		t.Fatalf("globex's list is wrong: %s", w.Body.String())
	}
}

func TestPcapForeignDeviceIsAlways404(t *testing.T) {
	fx := seededFixture(t)
	fx.as("acme", false)
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/devices/globex-core/pcap"},
		{http.MethodPost, "/api/devices/globex-core/pcap"},
		{http.MethodGet, "/api/devices/globex-core/pcap/" + globexCap},
		{http.MethodGet, "/api/devices/globex-core/pcap/" + globexCap + "/download"},
		{http.MethodDelete, "/api/devices/globex-core/pcap/" + globexCap},
	} {
		w := fx.do(tc.method, tc.path, `{"interface":"Ethernet1/1"}`)
		if w.Code != http.StatusNotFound {
			t.Errorf("cross-tenant %s %s = %d, want 404 (%s)", tc.method, tc.path, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), globexCap) {
			t.Errorf("TENANT LEAK: the 404 body named the foreign capture: %s", w.Body.String())
		}
	}
	// An id that exists NOWHERE answers identically — absent and foreign must be
	// indistinguishable or the subtree is an existence oracle.
	w := fx.do(http.MethodGet, "/api/devices/no-such-device/pcap", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("absent device = %d, want the same 404 a foreign device gets", w.Code)
	}
}

func TestPcapForeignCaptureIDUnderOwnDeviceIs404(t *testing.T) {
	fx := seededFixture(t)
	fx.as("acme", false)
	// The DEVICE is acme's, so the device gate passes; the store's tenant filter
	// is what must refuse the other tenant's capture id.
	for _, path := range []string{
		"/api/devices/acme-core/pcap/" + globexCap,
		"/api/devices/acme-core/pcap/" + globexCap + "/download",
	} {
		w := fx.do(http.MethodGet, path, "")
		if w.Code != http.StatusNotFound {
			t.Errorf("foreign capture id at %s = %d, want 404 (%s)", path, w.Code, w.Body.String())
		}
	}
	// A malformed id gets the SAME answer: a different refusal would be an
	// oracle for the id format.
	w := fx.do(http.MethodGet, "/api/devices/acme-core/pcap/not-a-capture-id", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("malformed id = %d, want 404", w.Code)
	}
}

func TestPcapCrossTenantWriteIsRefused(t *testing.T) {
	fx := seededFixture(t)
	fx.as("acme", false)
	w := fx.do(http.MethodDelete, "/api/devices/globex-core/pcap/"+globexCap, "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant DELETE = %d, want 404", w.Code)
	}
	// globex's capture is untouched.
	if _, err := fx.store.Get(context.Background(), "globex", false, "globex-core", globexCap); err != nil {
		t.Fatalf("a cross-tenant DELETE removed another tenant's capture: %v", err)
	}
}

func TestPcapPlatformOwnerReadsCrossTenant(t *testing.T) {
	fx := seededFixture(t)
	w := fx.as("", true).do(http.MethodGet, "/api/devices/globex-core/pcap", "")
	if w.Code != http.StatusOK {
		t.Fatalf("platform owner = %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), globexCap) {
		t.Fatalf("the platform owner must read cross-tenant: %s", w.Body.String())
	}
}

func TestPcapStartStampsTheDeviceOwnerNotTheCaller(t *testing.T) {
	// §3a rule 2: the row's tenant comes from the DEVICE, never the principal or
	// the body. A cross-tenant platform owner capturing on globex-core must
	// produce a globex-owned row.
	fx := newFixture(t, nil)
	fx.as("", true)
	rec, err := fx.mgr.Start(context.Background(), fx.principal, fx.devices["globex-core"],
		StartRequest{Interface: "Ethernet1/1", DurationSec: 1}, "root")
	if err != nil {
		t.Fatalf("Start = %v", err)
	}
	if rec.TenantID != "globex" {
		t.Fatalf("row tenant = %q, want the DEVICE's owner (globex)", rec.TenantID)
	}
	// And a scoped globex caller can see it — the row landed in globex's scope.
	if _, err := fx.store.Get(context.Background(), "globex", false, "globex-core", rec.ID); err != nil {
		t.Fatalf("the row was not stamped into the device's tenant: %v", err)
	}
	if _, err := fx.store.Get(context.Background(), "acme", false, "globex-core", rec.ID); err == nil {
		t.Fatal("TENANT LEAK: acme can read a globex-owned capture row")
	}
}

func TestPcapDownloadIsWriteGatedAndAudited(t *testing.T) {
	fx := seededFixture(t)
	fx.as("acme", false)
	fx.gates = nil
	w := fx.do(http.MethodGet, "/api/devices/acme-core/pcap/"+acmeCap+"/download", "")
	if w.Code != http.StatusOK {
		t.Fatalf("download = %d (%s)", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != pcapContentType {
		t.Fatalf("Content-Type = %q, want %q", ct, pcapContentType)
	}
	if !strings.Contains(w.Header().Get("Content-Disposition"), acmeCap) {
		t.Fatalf("Content-Disposition = %q", w.Header().Get("Content-Disposition"))
	}
	if got := w.Body.String(); got != string(samplePCAP(2)) {
		t.Fatal("the streamed bytes are not the unsealed capture")
	}
	// A download REVEALS customer payload, so it takes the WRITE gate.
	if len(fx.gates) != 1 || fx.gates[0] != GateWrite {
		t.Fatalf("download asked for gates %v, want exactly [GateWrite]", fx.gates)
	}
	// …and it is audited with the sensitive tag.
	recs := fx.auditsFor("pcap_capture_downloaded")
	if len(recs) != 1 {
		t.Fatalf("download audits = %d, want 1", len(recs))
	}
	if recs[0].Detail["sensitive"] != true {
		t.Fatalf("the download audit is not tagged sensitive: %+v", recs[0].Detail)
	}
	if recs[0].Tenant != "acme" || recs[0].Detail["capture"] != acmeCap {
		t.Fatalf("the download audit does not identify what was revealed: %+v", recs[0])
	}
	if got := fx.metrics.Snapshot()["downloads_total"]; got != 1 {
		t.Fatalf("downloads_total = %d, want 1", got)
	}
}

func TestPcapStartAndDeleteAreWriteGatedAndAudited(t *testing.T) {
	fx := newFixture(t, nil)
	fx.as("acme", false)
	fx.gates = nil
	w := fx.do(http.MethodPost, "/api/devices/acme-core/pcap",
		`{"interface":"Ethernet1/1","duration_s":1,"filter":"tcp and port 22"}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("start = %d (%s)", w.Code, w.Body.String())
	}
	if len(fx.gates) != 1 || fx.gates[0] != GateWrite {
		t.Fatalf("start asked for gates %v, want [GateWrite]", fx.gates)
	}
	recs := fx.auditsFor("pcap_capture_started")
	if len(recs) != 1 || recs[0].Detail["sensitive"] != true {
		t.Fatalf("start audit = %+v, want exactly one tagged sensitive", recs)
	}
	if recs[0].Detail["filter"] != "tcp and port 22" || recs[0].Detail["interface"] != "Ethernet1/1" {
		t.Fatalf("the start audit does not record WHAT was captured: %+v", recs[0].Detail)
	}

	var accepted struct {
		CaptureID string `json:"capture_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &accepted)
	fx.gates = nil
	w = fx.do(http.MethodDelete, "/api/devices/acme-core/pcap/"+accepted.CaptureID, "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete = %d (%s)", w.Code, w.Body.String())
	}
	if len(fx.gates) != 1 || fx.gates[0] != GateWrite {
		t.Fatalf("delete asked for gates %v, want exactly [GateWrite]", fx.gates)
	}
	if len(fx.auditsFor("pcap_capture_deleted")) != 1 {
		t.Fatal("the delete was not audited")
	}
}

func TestPcapListAndStatusAreReadGated(t *testing.T) {
	fx := seededFixture(t)
	fx.as("acme", false)
	fx.gates = nil
	fx.do(http.MethodGet, "/api/devices/acme-core/pcap", "")
	fx.do(http.MethodGet, "/api/devices/acme-core/pcap/"+acmeCap, "")
	for _, g := range fx.gates {
		if g != GateRead {
			t.Fatalf("a read route asked for %v, want GateRead", fx.gates)
		}
	}
}

func TestPcapResponsesNeverCarryOwnerOrPathFields(t *testing.T) {
	fx := seededFixture(t)
	fx.as("acme", false)
	for _, path := range []string{
		"/api/devices/acme-core/pcap",
		"/api/devices/acme-core/pcap/" + acmeCap,
	} {
		body := fx.do(http.MethodGet, path, "").Body.String()
		for _, leak := range []string{"tenant_id", "blob_ref", "remote_path", "actor"} {
			if strings.Contains(body, leak) {
				t.Errorf("%s leaked %q onto the wire: %s", path, leak, body)
			}
		}
	}
}

func TestPcapFlagOffClaimsNothing(t *testing.T) {
	// A nil API (the flag-off deployment) must DECLINE every path so the device
	// router keeps its existing behaviour and a prober cannot enumerate a
	// dormant, highly-privileged feature.
	var api *API
	for _, path := range []string{
		"/api/devices/acme-core/pcap",
		"/api/devices/acme-core/pcap/" + acmeCap,
		"/api/devices/acme-core/pcap/" + acmeCap + "/download",
	} {
		w := httptest.NewRecorder()
		if api.ServeDeviceSubroute(w, httptest.NewRequest(http.MethodGet, path, nil)) {
			t.Errorf("a nil API claimed %s", path)
		}
	}
	// And an API over a nil manager is equally inert.
	if NewAPI(nil).ServeDeviceSubroute(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/api/devices/acme-core/pcap", nil)) {
		t.Fatal("an API over a nil manager claimed a path")
	}
}

func TestPcapSubtreeDeclinesForeignPaths(t *testing.T) {
	fx := newFixture(t, nil)
	for _, path := range []string{
		"/api/devices/acme-core/config/versions",
		"/api/devices/acme-core",
		"/api/devices",
		"/api/devices/acme-core/pcapfoo",
		"/api/devices/acme-core/pcap/aaaa/bbbb/cccc",
	} {
		w := httptest.NewRecorder()
		if fx.api.ServeDeviceSubroute(w, httptest.NewRequest(http.MethodGet, path, nil)) {
			t.Errorf("the pcap subtree wrongly claimed %s", path)
		}
	}
}

func TestPcapDownloadOfAnUnfinishedCaptureIsNotAnEmptyFile(t *testing.T) {
	fx := newFixture(t, func(d *Deps) { d.Run = func(func()) {} })
	fx.as("acme", false)
	w := fx.do(http.MethodPost, "/api/devices/acme-core/pcap", `{"interface":"Ethernet1/1","duration_s":5}`)
	var accepted struct {
		CaptureID string `json:"capture_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &accepted)
	w = fx.do(http.MethodGet, "/api/devices/acme-core/pcap/"+accepted.CaptureID+"/download", "")
	if w.Code != http.StatusConflict {
		t.Fatalf("download of a running capture = %d, want 409 (an empty pcap would read as a capture that saw nothing)", w.Code)
	}
}
