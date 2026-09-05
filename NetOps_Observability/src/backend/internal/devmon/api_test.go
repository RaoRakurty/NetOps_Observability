package devmon_test

// api_test.go — the monitoring switch's HTTP contract, in isolation from the
// platform that wires it.
//
// What this file proves is the module's own guarantees, the ones that must hold
// however it is wired: it gates every verb before it reads anything, it refuses
// to serve at all when a seam is missing rather than serving ungated, another
// tenant's device is indistinguishable from one that does not exist, and a
// ceiling refusal is rendered by the platform's renderer rather than invented
// here.

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/internal/devmon"
	"netops/backend/models"
)

// fakeRegistry is a device registry with a scripted answer.
type fakeRegistry struct {
	devices  map[string]models.Device
	decision map[string]devmon.Record
	setErr   error
	calls    []string
}

func (f *fakeRegistry) Get(id string) (models.Device, bool) {
	d, ok := f.devices[id]
	return d, ok
}

func (f *fakeRegistry) MonitoringDecision(id string) (devmon.Record, bool) {
	r, ok := f.decision[id]
	return r, ok
}

func (f *fakeRegistry) SetMonitoring(id string, enabled bool, by string) (models.Device, error) {
	f.calls = append(f.calls, id+":"+by)
	if f.setErr != nil {
		return models.Device{}, f.setErr
	}
	d := f.devices[id]
	d.Monitored = enabled
	d.MonitorReason = devmon.ReasonEnabled
	if !enabled {
		d.MonitorReason = devmon.ReasonDisabled
	}
	f.devices[id] = d
	return d, nil
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
	api *devmon.API
	reg *fakeRegistry
}

func newHarness(t *testing.T, over func(*devmon.Deps)) *harness {
	t.Helper()
	reg := &fakeRegistry{
		devices: map[string]models.Device{
			"d1": {ID: "d1", Name: "d1", Address: "10.0.0.1", Source: "manual",
				Monitored: true, MonitorReason: devmon.ReasonDeclared, MonitorMethods: []string{"snmp"}},
			"other": {ID: "other", Name: "other", Address: "10.9.0.1", Source: "manual", TenantID: "globex"},
		},
		decision: map[string]devmon.Record{},
	}
	d := devmon.Deps{
		Registry: reg,
		ReadGate: func(http.ResponseWriter, *http.Request) (devmon.Principal, bool) {
			return devmon.Principal{Subject: "op", Tenant: "acme"}, true
		},
		WriteGate: func(http.ResponseWriter, *http.Request) (devmon.Principal, bool) {
			return devmon.Principal{Subject: "op", Tenant: "acme"}, true
		},
		CanSee: func(dev models.Device, tenant string, cross bool) bool {
			return cross || dev.TenantID == "" || dev.TenantID == tenant
		},
		WriteJSON:  writeJSON,
		WriteError: writeErr,
	}
	if over != nil {
		over(&d)
	}
	return &harness{api: devmon.New(d), reg: reg}
}

func (h *harness) do(method, path, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	w := httptest.NewRecorder()
	h.api.Handle(w, r)
	return w
}

func TestPathMatchesOnlyTheMonitoringRoute(t *testing.T) {
	for _, p := range []string{
		"/api/devices/d1/monitoring",
		"/api/devices/a%2Fb/monitoring",
	} {
		if _, ok := devmon.Path(p); !ok {
			t.Fatalf("%s must match", p)
		}
	}
	for _, p := range []string{
		"/api/devices/monitoring",       // no id
		"/api/devices/d1/config/status", // another subroute
		"/api/devices/d1",
		"/api/devices/d1/pcap/monitoring", // an id may not contain a slash
		"/api/monitoring",
	} {
		if _, ok := devmon.Path(p); ok {
			t.Fatalf("%s must NOT match", p)
		}
	}
}

func TestReadReportsTheStateAndWhy(t *testing.T) {
	h := newHarness(t, nil)
	w := h.do(http.MethodGet, "/api/devices/d1/monitoring", "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET = %d %s", w.Code, w.Body.String())
	}
	var v devmon.View
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if !v.Monitored || v.Reason == "" || v.DeviceID != "d1" {
		t.Fatalf("view = %+v", v)
	}
	if v.Decided {
		t.Fatal("a state that came from the default must not claim somebody decided it")
	}
}

func TestWriteRecordsTheDecidingPrincipal(t *testing.T) {
	h := newHarness(t, nil)
	w := h.do(http.MethodPut, "/api/devices/d1/monitoring", `{"enabled":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT = %d %s", w.Code, w.Body.String())
	}
	if len(h.reg.calls) != 1 || h.reg.calls[0] != "d1:op" {
		t.Fatalf("the registry must be told WHO decided: %v", h.reg.calls)
	}
}

func TestAnotherTenantsDeviceIsIndistinguishableFromAbsent(t *testing.T) {
	h := newHarness(t, nil)
	if w := h.do(http.MethodGet, "/api/devices/other/monitoring", ""); w.Code != http.StatusNotFound {
		t.Fatalf("GET = %d, want 404 — a 403 confirms the id exists", w.Code)
	}
	if w := h.do(http.MethodPut, "/api/devices/other/monitoring", `{"enabled":true}`); w.Code != http.StatusNotFound {
		t.Fatalf("PUT = %d, want 404", w.Code)
	}
	if len(h.reg.calls) != 0 {
		t.Fatalf("a cross-tenant write must never reach the registry: %v", h.reg.calls)
	}
	if w := h.do(http.MethodGet, "/api/devices/nope/monitoring", ""); w.Code != http.StatusNotFound {
		t.Fatalf("an absent device = %d, want the SAME 404", w.Code)
	}
}

func TestGateRunsBeforeAnythingIsRead(t *testing.T) {
	var body string
	h := newHarness(t, func(d *devmon.Deps) {
		d.WriteGate = func(w http.ResponseWriter, r *http.Request) (devmon.Principal, bool) {
			b := make([]byte, 4)
			n, _ := r.Body.Read(b) // best-effort: proving the body is still unread
			body = string(b[:n])
			http.Error(w, "forbidden", http.StatusForbidden)
			return devmon.Principal{}, false
		}
	})
	w := h.do(http.MethodPut, "/api/devices/d1/monitoring", `{"enabled":true}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("PUT = %d, want the gate's 403", w.Code)
	}
	if body != `{"en` {
		t.Fatalf("the gate must run before the handler reads anything, got %q", body)
	}
	if len(h.reg.calls) != 0 {
		t.Fatal("a refused caller must not reach the registry")
	}
}

func TestAMissingSeamRefusesRatherThanServing(t *testing.T) {
	for _, tc := range []struct {
		name string
		over func(*devmon.Deps)
	}{
		{"no registry", func(d *devmon.Deps) { d.Registry = nil }},
		{"no read gate", func(d *devmon.Deps) { d.ReadGate = nil }},
		{"no visibility rule", func(d *devmon.Deps) { d.CanSee = nil }},
		{"no json writer", func(d *devmon.Deps) { d.WriteJSON = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.over)
			w := h.do(http.MethodGet, "/api/devices/d1/monitoring", "")
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("GET = %d, want 503 — a surface that cannot gate must not serve", w.Code)
			}
		})
	}
}

func TestBodyContract(t *testing.T) {
	h := newHarness(t, nil)
	for _, body := range []string{`{}`, `{"enabled":null}`, `not json`, ``} {
		w := h.do(http.MethodPut, "/api/devices/d1/monitoring", body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("PUT %q = %d, want 400 — a missing decision must never be read as 'stop collecting'", body, w.Code)
		}
	}
	if len(h.reg.calls) != 0 {
		t.Fatalf("no bad body may reach the registry: %v", h.reg.calls)
	}
}

func TestARefusalIsRenderedByThePlatform(t *testing.T) {
	rendered := false
	refusal := errors.New("the ceiling is full")
	h := newHarness(t, func(d *devmon.Deps) {
		d.Refusal = func(w http.ResponseWriter, err error) bool {
			if !errors.Is(err, refusal) {
				return false
			}
			rendered = true
			w.WriteHeader(http.StatusPaymentRequired)
			return true
		}
	})
	h.reg.setErr = refusal
	w := h.do(http.MethodPut, "/api/devices/d1/monitoring", `{"enabled":true}`)
	if !rendered || w.Code != http.StatusPaymentRequired {
		t.Fatalf("the platform's renderer must own the 402: rendered=%v code=%d", rendered, w.Code)
	}
}

func TestAnUnknownDeviceFromTheRegistryIs404(t *testing.T) {
	h := newHarness(t, nil)
	h.reg.setErr = devmon.ErrUnknownDevice
	w := h.do(http.MethodPut, "/api/devices/d1/monitoring", `{"enabled":true}`)
	if w.Code != http.StatusNotFound {
		t.Fatalf("PUT = %d, want 404 — never a create", w.Code)
	}
}

func TestBothOutcomesAreAudited(t *testing.T) {
	var events []devmon.AuditRecord
	h := newHarness(t, func(d *devmon.Deps) {
		d.Audit = func(_ *http.Request, ev devmon.AuditRecord) { events = append(events, ev) }
		d.Refusal = func(w http.ResponseWriter, err error) bool { w.WriteHeader(http.StatusPaymentRequired); return true }
	})
	h.do(http.MethodPut, "/api/devices/d1/monitoring", `{"enabled":true}`)
	h.reg.setErr = errors.New("ceiling")
	h.do(http.MethodPut, "/api/devices/d1/monitoring", `{"enabled":true}`)

	if len(events) != 2 {
		t.Fatalf("both the allow and the deny must be recorded, got %d", len(events))
	}
	if events[0].Decision != "allow" || events[1].Decision != "deny" {
		t.Fatalf("decisions = %q, %q", events[0].Decision, events[1].Decision)
	}
	for i, ev := range events {
		if ev.Detail["action"] != "device_monitoring_set" || ev.Detail["device"] != "d1" {
			t.Fatalf("event %d must name the action and the device: %+v", i, ev.Detail)
		}
	}
}

func TestOnlyGetAndPut(t *testing.T) {
	h := newHarness(t, nil)
	for _, m := range []string{http.MethodDelete, http.MethodPost, http.MethodPatch} {
		w := h.do(m, "/api/devices/d1/monitoring", "")
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s = %d, want 405", m, w.Code)
		}
		if got := w.Header().Get("Allow"); got != "GET, PUT" {
			t.Fatalf("Allow = %q", got)
		}
	}
}
