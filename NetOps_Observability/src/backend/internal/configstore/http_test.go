// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package configstore

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// http_test.go — the wire contract and the §3a isolation obligations of the
// HTTP surface. The response shapes asserted here are the ones the SPA is built
// against; changing a key name breaks the inventory badge, so they are pinned.

func seedVersions(t *testing.T, f *fixture, deviceID, tenant string, n int) []string {
	t.Helper()
	dev := f.devices[deviceID]
	shas := make([]string, 0, n)
	for i := 0; i < n; i++ {
		f.now = f.now.Add(time.Hour)
		f.gw.set(deviceID, sampleConfig("edge-"+string(rune('a'+i))))
		v, err := f.mgr.Capture(context.Background(), dev, tenant, "test")
		if err != nil {
			t.Fatalf("seed capture: %v", err)
		}
		shas = append(shas, v.SHA)
	}
	return shas
}

// TestVersionsListContract pins the shape the frontend consumes.
func TestVersionsListContract(t *testing.T) {
	f := newFixture(t, nil)
	f.addDevice("d1", "acme", "Cisco IOS-XE")
	f.principal = Principal{Tenant: "acme", Subject: "ops@acme"}
	shas := seedVersions(t, f, "d1", "acme", 2)
	if err := f.store.SetGolden(context.Background(), "acme", false, "d1", shas[0]); err != nil {
		t.Fatal(err)
	}

	w := f.do(http.MethodGet, "/api/devices/d1/config/versions", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body)
	}
	body := f.decode(w)
	if body["device_id"] != "d1" {
		t.Errorf("device_id = %v", body["device_id"])
	}
	if body["next_cursor"] != nil {
		t.Errorf("next_cursor = %v, want null", body["next_cursor"])
	}
	if body["golden_sha"] != shas[0] {
		t.Errorf("golden_sha = %v, want %v", body["golden_sha"], shas[0])
	}
	items, ok := body["items"].([]any)
	if !ok || len(items) != 2 {
		t.Fatalf("items = %v", body["items"])
	}
	first := items[0].(map[string]any)
	for _, key := range []string{"sha", "captured_at", "size_bytes", "status", "golden", "drift"} {
		if _, present := first[key]; !present {
			t.Errorf("item is missing %q: %v", key, first)
		}
	}
	// Newest first.
	if first["sha"] != shas[1] {
		t.Errorf("items are not newest-first: %v", first["sha"])
	}
	if first["status"] != StatusOK {
		t.Errorf("status = %v", first["status"])
	}
}

// TestVersionTextIsRedactedAndAuditedSensitive.
func TestVersionTextIsRedactedAndAuditedSensitive(t *testing.T) {
	f := newFixture(t, nil)
	f.addDevice("d1", "acme", "Cisco IOS-XE")
	f.principal = Principal{Tenant: "acme", Subject: "ops@acme"}
	shas := seedVersions(t, f, "d1", "acme", 1)

	w := f.do(http.MethodGet, "/api/devices/d1/config/versions/"+shas[0], "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body)
	}
	body := f.decode(w)
	text, _ := body["text"].(string)
	if text == "" {
		t.Fatal("no text returned")
	}
	for _, canary := range []string{canaryEnableSecret, canaryCommunity} {
		if strings.Contains(text, canary) {
			t.Fatalf("SECRET LEAK in the API body: %q", canary)
		}
	}
	if !strings.Contains(text, "hostname edge-a") {
		t.Fatalf("redaction destroyed the configuration:\n%s", text)
	}
	for _, key := range []string{"device_id", "sha", "captured_at", "size_bytes", "golden"} {
		if _, present := body[key]; !present {
			t.Errorf("response is missing %q", key)
		}
	}
	// The read must be audited with the `sensitive` tag.
	f.mu.Lock()
	defer f.mu.Unlock()
	var found bool
	for _, a := range f.audits {
		if a["action"] == "config_backup_version_read" && a["sensitive"] == true {
			found = true
		}
	}
	if !found {
		t.Fatalf("a configuration read was not audited as sensitive: %v", f.audits)
	}
}

// TestDiffContract pins the diff response shape and its redaction.
func TestDiffContract(t *testing.T) {
	f := newFixture(t, nil)
	f.addDevice("d1", "acme", "Cisco IOS-XE")
	f.principal = Principal{Tenant: "acme", Subject: "ops@acme"}
	shas := seedVersions(t, f, "d1", "acme", 2)

	w := f.do(http.MethodGet, "/api/devices/d1/config/diff?from="+shas[0]+"&to="+shas[1], "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body)
	}
	body := f.decode(w)
	for _, key := range []string{"device_id", "from", "to", "added", "removed", "unified", "truncated"} {
		if _, present := body[key]; !present {
			t.Errorf("diff response is missing %q", key)
		}
	}
	unified, _ := body["unified"].(string)
	if !strings.Contains(unified, "hostname edge-") {
		t.Fatalf("diff rendered nothing:\n%s", unified)
	}
	if strings.Contains(unified, canaryEnableSecret) || strings.Contains(unified, canaryCommunity) {
		t.Fatal("SECRET LEAK in the diff body")
	}
	// A malformed version id is a 400, not a store lookup.
	if w := f.do(http.MethodGet, "/api/devices/d1/config/diff?from=zzz&to="+shas[1], ""); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed from = %d, want 400", w.Code)
	}
}

// TestBackupReturns202AndOverlapReturns429.
func TestBackupReturns202AndOverlapReturns429(t *testing.T) {
	f := newFixture(t, nil)
	f.addDevice("d1", "acme", "Cisco IOS-XE")
	f.principal = Principal{Tenant: "acme", Subject: "ops@acme"}
	f.gw.set("d1", sampleConfig("edge-01"))
	f.gw.delay = 300 * time.Millisecond

	w := f.do(http.MethodPost, "/api/devices/d1/config/backup", "")
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", w.Code, w.Body)
	}
	body := f.decode(w)
	if body["status"] != "queued" {
		t.Errorf("status = %v, want queued", body["status"])
	}
	job, _ := body["job_id"].(string)
	if job == "" {
		t.Error("no job_id returned")
	}

	// The second trigger, while the first is still dialling, is a 429 with the
	// {error} envelope.
	w2 := f.do(http.MethodPost, "/api/devices/d1/config/backup", "")
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("overlapping trigger = %d, want 429: %s", w2.Code, w2.Body)
	}
	if _, present := f.decode(w2)["error"]; !present {
		t.Errorf("429 body must be {error}: %s", w2.Body)
	}

	deadline := time.Now().Add(3 * time.Second)
	for f.mgr.InFlight("d1") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if f.mgr.InFlight("d1") {
		t.Fatal("the manual capture never released its claim")
	}
}

// TestGoldenContractAndBodyTenantRejected.
func TestGoldenContractAndBodyTenantRejected(t *testing.T) {
	f := newFixture(t, nil)
	f.addDevice("d1", "acme", "Cisco IOS-XE")
	f.principal = Principal{Tenant: "acme", Subject: "ops@acme"}
	shas := seedVersions(t, f, "d1", "acme", 1)

	w := f.do(http.MethodPost, "/api/devices/d1/config/golden", `{"sha":"`+shas[0]+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body)
	}
	body := f.decode(w)
	if body["device_id"] != "d1" || body["golden_sha"] != shas[0] {
		t.Fatalf("golden response = %v", body)
	}
	// §3a rule 2: an attempt to name a tenant in the body is REJECTED, never
	// silently ignored.
	w2 := f.do(http.MethodPost, "/api/devices/d1/config/golden",
		`{"sha":"`+shas[0]+`","tenant_id":"globex"}`)
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("a tenant in the body = %d, want 400", w2.Code)
	}
	// An unknown sha is a 404, not a 500.
	w3 := f.do(http.MethodPost, "/api/devices/d1/config/golden",
		`{"sha":"`+SHA256Hex("nope")+`"}`)
	if w3.Code != http.StatusNotFound {
		t.Fatalf("unknown sha = %d, want 404", w3.Code)
	}
}

// TestCrossTenantDeviceIs404 is the §3a rule 1 obligation across EVERY route:
// another tenant's device id must be indistinguishable from a non-existent one.
func TestCrossTenantDeviceIs404(t *testing.T) {
	f := newFixture(t, nil)
	f.addDevice("d1", "acme", "Cisco IOS-XE")
	f.addDevice("d2", "globex", "Cisco IOS-XE")
	f.principal = Principal{Tenant: "acme", Subject: "ops@acme"}
	foreign := seedVersions(t, f, "d2", "globex", 1)

	paths := []struct{ method, path, body string }{
		{http.MethodGet, "/api/devices/d2/config/versions", ""},
		{http.MethodGet, "/api/devices/d2/config/versions/" + foreign[0], ""},
		{http.MethodGet, "/api/devices/d2/config/diff?from=" + foreign[0] + "&to=" + foreign[0], ""},
		{http.MethodGet, "/api/devices/d2/config/status", ""},
		{http.MethodPost, "/api/devices/d2/config/backup", ""},
		{http.MethodPost, "/api/devices/d2/config/golden", `{"sha":"` + foreign[0] + `"}`},
		{http.MethodGet, "/api/devices/nosuchdevice/config/versions", ""},
	}
	for _, p := range paths {
		w := f.do(p.method, p.path, p.body)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404 (body %s)", p.method, p.path, w.Code, w.Body)
		}
	}
	// And the version id of a foreign device is not readable under the caller's
	// OWN device id either.
	w := f.do(http.MethodGet, "/api/devices/d1/config/versions/"+foreign[0], "")
	if w.Code != http.StatusNotFound {
		t.Errorf("foreign sha under own device = %d, want 404", w.Code)
	}
}

// TestQueryTenantIsIgnored: the caller's scope comes from the authenticated
// principal ONLY. A ?tenant= / ?as_tenant= in the URL changes nothing.
func TestQueryTenantIsIgnored(t *testing.T) {
	f := newFixture(t, nil)
	f.addDevice("d1", "acme", "Cisco IOS-XE")
	f.addDevice("d2", "globex", "Cisco IOS-XE")
	f.principal = Principal{Tenant: "acme", Subject: "ops@acme"}
	seedVersions(t, f, "d2", "globex", 1)

	for _, q := range []string{"?tenant=globex", "?as_tenant=globex", "?tenant_id=globex"} {
		w := f.do(http.MethodGet, "/api/devices/d2/config/versions"+q, "")
		if w.Code != http.StatusNotFound {
			t.Errorf("%s widened the caller's scope: %d %s", q, w.Code, w.Body)
		}
	}
}

// TestCrossTenantPrincipalSeesEverything is the other half: a platform-owner
// (cross) principal is deliberately not blocked — isolation is scope-based, not
// a blanket ban.
func TestCrossTenantPrincipalSeesEverything(t *testing.T) {
	f := newFixture(t, nil)
	f.addDevice("d2", "globex", "Cisco IOS-XE")
	f.principal = Principal{Tenant: "", Cross: true, Subject: "platform"}
	seedVersions(t, f, "d2", "globex", 1)

	w := f.do(http.MethodGet, "/api/devices/d2/config/versions", "")
	if w.Code != http.StatusOK {
		t.Fatalf("cross-tenant read = %d: %s", w.Code, w.Body)
	}
	items := f.decode(w)["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("cross-tenant list returned %d items", len(items))
	}
}

// TestStatusContractWithoutDriftConsumer: with no drift consumer wired the badge
// answers the honest `unknown`, never a green default.
func TestStatusContractWithoutDriftConsumer(t *testing.T) {
	f := newFixture(t, nil)
	f.addDevice("d1", "acme", "Cisco IOS-XE")
	f.principal = Principal{Tenant: "acme", Subject: "ops@acme"}

	w := f.do(http.MethodGet, "/api/devices/d1/config/status", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body)
	}
	body := f.decode(w)
	if body["state"] != DriftUnknown {
		t.Errorf("state = %v, want %q", body["state"], DriftUnknown)
	}
	for _, key := range []string{"device_id", "state", "last_capture_at", "last_sha", "golden_sha"} {
		if _, present := body[key]; !present {
			t.Errorf("status response is missing %q", key)
		}
	}
	if body["last_sha"] != nil || body["golden_sha"] != nil || body["last_capture_at"] != nil {
		t.Errorf("absent fields must be null, got %v", body)
	}
}

// TestStatusUsesInjectedSource + next_scheduled_at.
func TestStatusUsesInjectedSource(t *testing.T) {
	f := newFixture(t, nil)
	f.addDevice("d1", "acme", "Cisco IOS-XE")
	f.principal = Principal{Tenant: "acme", Subject: "ops@acme"}
	at := f.now
	sha := SHA256Hex("x")
	f.api = NewAPI(f.mgr, func(_ context.Context, tenant string, cross bool, deviceID string) (DriftStatus, bool, error) {
		if tenant != "acme" || cross || deviceID != "d1" {
			t.Errorf("status source called with (%q,%v,%q)", tenant, cross, deviceID)
		}
		return DriftStatus{State: DriftDrifted, LastSHA: &sha, LastCapture: &at, LastError: ""}, true, nil
	})
	w := f.do(http.MethodGet, "/api/devices/d1/config/status", "")
	body := f.decode(w)
	if body["state"] != DriftDrifted {
		t.Errorf("state = %v", body["state"])
	}
	if body["next_scheduled_at"] == nil {
		t.Error("next_scheduled_at must be derived from the last capture + interval")
	}
}

// TestFlagOffDispatchesNothing: a dormant module claims NO route, so the
// integrator's existing device router behaves exactly as before and a prober
// cannot enumerate the feature.
func TestFlagOffDispatchesNothing(t *testing.T) {
	var dormant *API
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/devices/d1/config/versions", nil)
	if dormant.ServeDeviceSubroute(w, r) {
		t.Fatal("a nil (flag-off) API must claim no route")
	}
	if (&API{}).ServeDeviceSubroute(w, r) {
		t.Fatal("an API with no manager must claim no route")
	}
}

// TestNonConfigDeviceRoutesAreNotClaimed: the dispatcher must not swallow the
// device routes the core already owns.
func TestNonConfigDeviceRoutesAreNotClaimed(t *testing.T) {
	f := newFixture(t, nil)
	for _, path := range []string{
		"/api/devices", "/api/devices/d1", "/api/devices/d1/ssh",
		"/api/devices/d1/location", "/api/devices/locations", "/api/config/drift",
		"/api/devices/d1/configuration",
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, path, nil)
		if f.api.ServeDeviceSubroute(w, r) {
			t.Errorf("dispatcher wrongly claimed %s", path)
		}
	}
}

// TestMethodGuards.
func TestMethodGuards(t *testing.T) {
	f := newFixture(t, nil)
	f.addDevice("d1", "acme", "Cisco IOS-XE")
	f.principal = Principal{Tenant: "acme", Subject: "ops@acme"}
	cases := []struct{ method, path string }{
		{http.MethodPost, "/api/devices/d1/config/versions"},
		{http.MethodGet, "/api/devices/d1/config/backup"},
		{http.MethodDelete, "/api/devices/d1/config/golden"},
		{http.MethodPost, "/api/devices/d1/config/status"},
	}
	for _, c := range cases {
		w := f.do(c.method, c.path, "")
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s = %d, want 405", c.method, c.path, w.Code)
		}
	}
}

// TestAuthzRefusalStopsTheHandler: an unauthorized caller never reaches a store.
func TestAuthzRefusalStopsTheHandler(t *testing.T) {
	f := newFixture(t, nil)
	f.addDevice("d1", "acme", "Cisco IOS-XE")
	f.authzOK = false
	w := f.do(http.MethodGet, "/api/devices/d1/config/versions", "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}
