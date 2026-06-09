package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"netops/backend/models"
)

// A fake NetBox: GET /?slug=/?name=/?serial= → empty until something is POSTed,
// POST → assigns an id and remembers it (so re-runs find it = idempotent).
type fakeNetbox struct {
	mu       sync.Mutex
	next     int
	byEP     map[string][]map[string]any // endpoint path → created objects
	postedDC int                         // device POST count
}

func newFakeNetbox() *fakeNetbox { return &fakeNetbox{byEP: map[string][]map[string]any{}, next: 1} }

func (f *fakeNetbox) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ep := strings.TrimPrefix(r.URL.Path, "/api/")
		ep = strings.TrimRight(ep, "/")
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Method == http.MethodGet {
			q := r.URL.Query()
			var match func(map[string]any) bool
			switch {
			case q.Get("slug") != "":
				match = func(o map[string]any) bool { return o["slug"] == q.Get("slug") }
			case q.Get("name") != "":
				match = func(o map[string]any) bool { return o["name"] == q.Get("name") }
			case q.Get("serial") != "":
				match = func(o map[string]any) bool { return o["serial"] == q.Get("serial") }
			default:
				match = func(map[string]any) bool { return false }
			}
			results := []map[string]any{}
			for _, o := range f.byEP[ep] {
				if match(o) {
					results = append(results, o)
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"count": len(results), "results": results})
			return
		}
		// POST: create
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		body["id"] = float64(f.next)
		f.next++
		f.byEP[ep] = append(f.byEP[ep], body)
		if ep == "dcim/devices" {
			f.postedDC++
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(body)
	})
}

func TestNetboxSyncerReconcile(t *testing.T) {
	fake := newFakeNetbox()
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	devs := []models.Device{
		{ID: "snmp-10.0.0.1", Name: "leaf1", Address: "10.0.0.1", Vendor: "Arista", Model: "7050", Source: "snmp"},
		{ID: "snmp-10.0.0.2", Name: "leaf2", Address: "10.0.0.2", Source: "snmp"}, // no vendor/model → Unknown
	}
	cfg := func() netboxConfig { return netboxConfig{Enabled: true, URL: srv.URL, Token: "t"} }
	s := newNetboxSyncer(cfg, func() []models.Device { return devs })

	st, err := s.SyncOnce(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if st.Created != 2 || st.Present != 0 {
		t.Fatalf("first run: created=%d present=%d, want 2/0", st.Created, st.Present)
	}
	// Idempotent: a second run creates nothing (devices already exist by name).
	st, err = s.SyncOnce(context.Background())
	if err != nil {
		t.Fatalf("sync2: %v", err)
	}
	if st.Created != 0 || st.Present != 2 {
		t.Errorf("second run: created=%d present=%d, want 0/2 (idempotent)", st.Created, st.Present)
	}
	if fake.postedDC != 2 {
		t.Errorf("device POSTs = %d, want 2 (no duplicate creates)", fake.postedDC)
	}
	// FK auto-provisioning happened once: Discovered site + role, two manufacturers
	// (Arista, Unknown), two device-types.
	if len(fake.byEP["dcim/sites"]) != 1 || len(fake.byEP["dcim/device-roles"]) != 1 {
		t.Errorf("expected one Discovered site + role")
	}
	if len(fake.byEP["dcim/manufacturers"]) != 2 {
		t.Errorf("manufacturers = %d, want 2 (Arista, Unknown)", len(fake.byEP["dcim/manufacturers"]))
	}
}

// Disabled NetBox → the syncer is a clean no-op.
func TestNetboxSyncerDisabled(t *testing.T) {
	s := newNetboxSyncer(func() netboxConfig { return netboxConfig{Enabled: false} },
		func() []models.Device { return []models.Device{{Name: "x"}} })
	st, err := s.SyncOnce(context.Background())
	if err != nil || st.Created != 0 {
		t.Errorf("disabled should no-op: created=%d err=%v", st.Created, err)
	}
}
