// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package devmon_test

// api_test.go — the read-only monitoring status surface, in isolation from the
// platform that wires it.
//
// What this file proves is the module's own guarantees, the ones that must hold
// however it is wired: it gates before it reads anything, it refuses to serve
// at all when a seam is missing rather than serving ungated or guessing,
// another tenant's device is indistinguishable from one that does not exist,
// there is no way to SET monitoring, and "monitored" is never reported as
// "collecting" when no collector for the device's methods is running.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/internal/devmon"
	"netops/backend/models"
)

type fakeRegistry struct{ devices map[string]models.Device }

func (f *fakeRegistry) Get(id string) (models.Device, bool) {
	d, ok := f.devices[id]
	return d, ok
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body) // best-effort: test sink
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

type harness struct {
	api   *devmon.API
	reg   *fakeRegistry
	gated int
}

func newHarness(t *testing.T, over func(*devmon.Deps)) *harness {
	t.Helper()
	h := &harness{reg: &fakeRegistry{devices: map[string]models.Device{
		"d1": {ID: "d1", Name: "d1", Address: "10.0.0.1", Source: "manual",
			Monitored: true, MonitorState: devmon.StateMonitored, MonitorReason: devmon.ReasonMonitored},
		"over": {ID: "over", Name: "over", Address: "10.0.0.2", Source: "snmp",
			MonitorState: devmon.StateOverLimit, MonitorReason: devmon.OverLimitReason(25), MonitorLimit: 25},
		"other": {ID: "other", Name: "other", Address: "10.9.0.1", Source: "manual", TenantID: "globex",
			Monitored: true, MonitorState: devmon.StateMonitored, MonitorReason: devmon.ReasonMonitored},
	}}}
	d := devmon.Deps{
		Registry: h.reg,
		ReadGate: func(http.ResponseWriter, *http.Request) (devmon.Principal, bool) {
			h.gated++
			return devmon.Principal{Subject: "op", Tenant: "acme"}, true
		},
		CanSee: func(dev models.Device, tenant string, cross bool) bool {
			return cross || dev.TenantID == "" || dev.TenantID == tenant
		},
		CollectorEnabled: func(m string) bool { return m == devmon.MethodSNMP },
		WriteJSON:        writeJSON,
		WriteError:       writeErr,
	}
	if over != nil {
		over(&d)
	}
	h.api = devmon.New(d)
	return h
}

func (h *harness) get(path string) (*httptest.ResponseRecorder, devmon.View) {
	w := httptest.NewRecorder()
	h.api.Handle(w, httptest.NewRequest(http.MethodGet, path, nil))
	var v devmon.View
	if w.Code == http.StatusOK {
		_ = json.Unmarshal(w.Body.Bytes(), &v)
	}
	return w, v
}

func TestPathMatchesOnlyTheMonitoringRoute(t *testing.T) {
	for _, p := range []string{"/api/devices/d1/monitoring", "/api/devices/a%2Fb/monitoring"} {
		if _, ok := devmon.Path(p); !ok {
			t.Fatalf("%s must match", p)
		}
	}
	for _, p := range []string{
		"/api/devices/monitoring", "/api/devices/d1/config/status", "/api/devices/d1",
		"/api/devices/d1/pcap/monitoring", "/api/monitoring",
	} {
		if _, ok := devmon.Path(p); ok {
			t.Fatalf("%s must NOT match", p)
		}
	}
}

func TestAMonitoredDeviceWithARunningCollectorIsCollecting(t *testing.T) {
	h := newHarness(t, nil)
	w, v := h.get("/api/devices/d1/monitoring")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	if !v.Monitored || !v.Collecting || v.State != devmon.StateMonitored || v.Reason != devmon.ReasonMonitored {
		t.Fatalf("view = %+v", v)
	}
	if len(v.CollectingMethods) != 1 || v.CollectingMethods[0] != devmon.MethodSNMP {
		t.Fatalf("collecting methods = %v", v.CollectingMethods)
	}
}

// TestMonitoredButNoCollectorIsSaidOutLoud is the honesty case: before, the
// status read "monitored" while every collector the device needed was off.
func TestMonitoredButNoCollectorIsSaidOutLoud(t *testing.T) {
	h := newHarness(t, func(d *devmon.Deps) { d.CollectorEnabled = func(string) bool { return false } })
	_, v := h.get("/api/devices/d1/monitoring")
	if !v.Monitored {
		t.Fatal("the device is still monitored — the licence counts it")
	}
	if v.Collecting || len(v.CollectingMethods) != 0 {
		t.Fatalf("nothing is collecting, but the view claims %+v", v)
	}
	if !strings.Contains(v.Reason, "no collector for snmp is enabled") || !strings.Contains(v.Reason, "nothing is being collected") {
		t.Fatalf("the reason must say no collector is running: %q", v.Reason)
	}
}

func TestAnOverLimitDeviceSaysSoAndIsNotCollecting(t *testing.T) {
	h := newHarness(t, nil)
	_, v := h.get("/api/devices/over/monitoring")
	if v.Monitored || v.Collecting || v.State != devmon.StateOverLimit || v.Limit != 25 {
		t.Fatalf("view = %+v", v)
	}
	if !strings.Contains(v.Reason, "licence limit of 25") {
		t.Fatalf("reason = %q", v.Reason)
	}
}

func TestAnUnstampedDeviceIsNotGuessed(t *testing.T) {
	h := newHarness(t, nil)
	h.reg.devices["raw"] = models.Device{ID: "raw", Address: "10.0.0.7"}
	_, v := h.get("/api/devices/raw/monitoring")
	if v.Monitored || v.Collecting || !strings.Contains(v.Reason, "not available") {
		t.Fatalf("an unstamped row must not be reported as monitored: %+v", v)
	}
}

func TestAnotherTenantsDeviceIsIndistinguishableFromAbsent(t *testing.T) {
	h := newHarness(t, nil)
	theirs, _ := h.get("/api/devices/other/monitoring")
	absent, _ := h.get("/api/devices/nope/monitoring")
	if theirs.Code != http.StatusNotFound || absent.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant %d, absent %d — both must be 404", theirs.Code, absent.Code)
	}
	if theirs.Body.String() != absent.Body.String() {
		t.Fatal("the two 404s must be byte-identical")
	}
}

func TestGateRunsBeforeAnythingIsRead(t *testing.T) {
	h := newHarness(t, func(d *devmon.Deps) {
		d.ReadGate = func(w http.ResponseWriter, _ *http.Request) (devmon.Principal, bool) {
			http.Error(w, "nope", http.StatusForbidden)
			return devmon.Principal{}, false
		}
	})
	w, _ := h.get("/api/devices/d1/monitoring")
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "10.0.0.1") {
		t.Fatalf("a refused caller learns nothing: %d %s", w.Code, w.Body.String())
	}
}

func TestAMissingSeamRefusesRatherThanServing(t *testing.T) {
	for name, strip := range map[string]func(*devmon.Deps){
		"registry":  func(d *devmon.Deps) { d.Registry = nil },
		"gate":      func(d *devmon.Deps) { d.ReadGate = nil },
		"canSee":    func(d *devmon.Deps) { d.CanSee = nil },
		"collector": func(d *devmon.Deps) { d.CollectorEnabled = nil },
		"json":      func(d *devmon.Deps) { d.WriteJSON = nil },
	} {
		h := newHarness(t, strip)
		if w, _ := h.get("/api/devices/d1/monitoring"); w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s missing: status %d, want 503", name, w.Code)
		}
	}
}

// TestThereIsNoSwitch: the monitoring state is derived; no verb sets it.
func TestThereIsNoSwitch(t *testing.T) {
	h := newHarness(t, nil)
	for _, m := range []string{http.MethodPut, http.MethodPost, http.MethodPatch, http.MethodDelete} {
		w := httptest.NewRecorder()
		h.api.Handle(w, httptest.NewRequest(m, "/api/devices/d1/monitoring", strings.NewReader(`{"enabled":false}`)))
		if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != http.MethodGet {
			t.Fatalf("%s: status %d allow %q — the route is read-only", m, w.Code, w.Header().Get("Allow"))
		}
	}
	if h.gated != 0 {
		t.Fatal("a refused verb must not reach the gate or the registry")
	}
}
