// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package changeapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/dem/experience"
)

var now = time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

const incID = "11111111-2222-4333-8444-555555555555"

func change(tenant, id, object, site string, at time.Time, mut func(*experience.ChangeEvent)) experience.ChangeEvent {
	c := experience.ChangeEvent{
		TenantID: tenant, ID: id, Type: experience.ChangeConfig, Object: object, ObjectKind: "device",
		Site: site, Summary: "change " + id, Actor: "alice", SourceSystem: experience.SourceSystemLedger,
		Provenance: experience.Provenance{Source: experience.SourceConfigDrift, Producer: "test", EventAt: at, ObservedAt: at,
			Observation: experience.ObservationObserved, DataClass: experience.DataClassCustomerMetadata},
	}
	if mut != nil {
		mut(&c)
	}
	return c
}

type fixture struct {
	deps    Deps
	diffArg []string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	st := experience.NewFileStoreWithClock("", func() time.Time { return now })
	for _, c := range []experience.ChangeEvent{
		change("acme", "chg-a1", "edge-1", "dfw", now.Add(-20*time.Minute), nil),
		change("acme", "chg-a2", "edge-9", "aus", now.Add(-15*time.Minute), func(c *experience.ChangeEvent) {
			c.Before, c.After = "password=hunter2", "password=swordfish"
		}),
		change("acme", "chg-a3", "edge-1", "dfw", now.Add(-10*time.Minute), func(c *experience.ChangeEvent) {
			c.SourceSystem, c.Before, c.After = experience.SourceSystemConfigCapture, "sha256:aaaaaaaaaaaa", "sha256:bbbbbbbbbbbb"
		}),
		change("acme", "chg-old", "edge-1", "dfw", now.Add(-3*time.Hour), nil),
		change("globex", "chg-g1", "edge-1", "dfw", now.Add(-12*time.Minute), nil),
	} {
		if _, err := st.RecordChange(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	}
	f := &fixture{}
	f.deps = Deps{
		Store: st,
		Authorize: func(w http.ResponseWriter, r *http.Request) (Caller, bool) {
			switch r.Header.Get("X-Test-Tenant") {
			case "":
				w.WriteHeader(http.StatusUnauthorized)
				return Caller{}, false
			case "*":
				return Caller{Tenant: "global", Cross: true}, true
			default:
				return Caller{Tenant: r.Header.Get("X-Test-Tenant")}, true
			}
		},
		Incident: func(_ context.Context, r *http.Request, id string) (IncidentScope, error) {
			if id != incID || r.Header.Get("X-Test-Tenant") != "acme" {
				return IncidentScope{}, ErrNotFound
			}
			return IncidentScope{ID: id, Start: now.Add(-12 * time.Minute), Devices: []string{"EDGE-1"}, Sites: []string{"dfw"}}, nil
		},
		ConfigDiff: func(_ context.Context, _ *http.Request, dev, from, to string) (Diff, error) {
			f.diffArg = []string{dev, from, to}
			return Diff{DeviceID: dev, FromVersion: from, ToVersion: to, Added: 1, Unified: "+ ntp server 10.0.0.1"}, nil
		},
		Redact: func(s string) string {
			return strings.ReplaceAll(strings.ReplaceAll(s, "hunter2", "[REDACTED]"), "swordfish", "[REDACTED]")
		},
		WriteJSON:  func(w http.ResponseWriter, st int, v any) { w.WriteHeader(st); _ = json.NewEncoder(w).Encode(v) },        // best-effort: test writer
		WriteError: func(w http.ResponseWriter, st int, err error) { w.WriteHeader(st); _, _ = w.Write([]byte(err.Error())) }, // best-effort: test writer
		Now:        func() time.Time { return now },
	}
	return f
}

func (f *fixture) get(t *testing.T, tenant, path string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if tenant != "" {
		r.Header.Set("X-Test-Tenant", tenant)
	}
	w := httptest.NewRecorder()
	f.deps.Handler(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out) // best-effort: error bodies are asserted by status
	return w.Code, out
}

func ids(out map[string]any) []string {
	var got []string
	for _, c := range out["changes"].([]any) {
		got = append(got, c.(map[string]any)["id"].(string))
	}
	return got
}

func TestListIsTheCallersOwnAndBounded(t *testing.T) {
	f := newFixture(t)
	code, out := f.get(t, "acme", "/api/changes?window=1h")
	if code != 200 || strings.Join(ids(out), ",") != "chg-a3,chg-a2,chg-a1" {
		t.Fatalf("acme's last hour: %d %v", code, out)
	}
	if _, out := f.get(t, "globex", "/api/changes?window=1h"); strings.Join(ids(out), ",") != "chg-g1" {
		t.Fatalf("globex sees only its own: %v", out)
	}
	if _, out := f.get(t, "acme", "/api/changes?window=1h&limit=2"); out["truncated"] != true || len(ids(out)) != 2 {
		t.Fatalf("limit must report truncation: %v", out)
	}
	if _, out := f.get(t, "acme", "/api/changes?window=1h&site=aus"); strings.Join(ids(out), ",") != "chg-a2" {
		t.Fatalf("site filter: %v", out)
	}
	for name, path := range map[string]string{
		"window too long": "/api/changes?window=9000h", "bad limit": "/api/changes?limit=0",
		"bad incident": "/api/changes?incident_id=x'--", "bad since": "/api/changes?since=yesterday",
		"too many values": "/api/changes?type=" + strings.Repeat("A,", 25),
	} {
		if code, _ := f.get(t, "acme", path); code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, code)
		}
	}
	if code, _ := f.get(t, "", "/api/changes"); code != http.StatusUnauthorized {
		t.Errorf("unauthenticated: %d", code)
	}
	if _, out := f.get(t, "*", "/api/changes"); len(ids(out)) != 0 || out["note"] == nil {
		t.Fatalf("the Global view has no single ledger and says so: %v", out)
	}
}

func TestIncidentAnchoredChangesAreTemporalNeverCausal(t *testing.T) {
	f := newFixture(t)
	code, out := f.get(t, "acme", "/api/changes?incident_id="+incID)
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	// Window: incident start (now-12m) minus 30m to plus 10m; chg-old (now-3h) is outside it.
	got := map[string]map[string]any{}
	for _, c := range out["changes"].([]any) {
		m := c.(map[string]any)
		got[m["id"].(string)] = m
	}
	if _, ok := got["chg-old"]; ok {
		t.Fatal("a change outside the incident window was listed")
	}
	for id, m := range got {
		if m["relation"] != RelationTemporal || !strings.Contains(m["relation_note"].(string), "not established as its cause") {
			t.Errorf("%s must be labelled temporal, never causal: %v", id, m)
		}
	}
	if got["chg-a1"]["in_incident_scope"] != true || got["chg-a2"]["in_incident_scope"] != false {
		t.Fatalf("scope: a1 touched affected EDGE-1 (any case) / dfw; a2 touched neither: %v %v", got["chg-a1"], got["chg-a2"])
	}
	if code, _ := f.get(t, "globex", "/api/changes?incident_id="+incID); code != http.StatusNotFound {
		t.Fatalf("another tenant's incident must be 404, got %d", code)
	}
}

func TestOneChangeIsTheCallersOwnAndRedacted(t *testing.T) {
	f := newFixture(t)
	code, out := f.get(t, "acme", "/api/changes/chg-a2")
	if code != 200 || out["id"] != "chg-a2" {
		t.Fatalf("%d %v", code, out)
	}
	if strings.Contains(out["before"].(string)+out["after"].(string), "hunter2") {
		t.Fatalf("before/after must be redacted: %v", out)
	}
	for who, path := range map[string]string{"globex": "/api/changes/chg-a1", "acme": "/api/changes/chg-g1", "*": "/api/changes/chg-a1"} {
		if code, _ := f.get(t, who, path); code != http.StatusNotFound {
			t.Errorf("%s reading %s: %d, want 404", who, path, code)
		}
	}
	for _, bad := range []string{"/api/changes/../x", "/api/changes/chg-a1/other", "/api/changes/%27or%201"} {
		if code, _ := f.get(t, "acme", bad); code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", bad, code)
		}
	}
}

func TestDiff(t *testing.T) {
	f := newFixture(t)
	code, out := f.get(t, "acme", "/api/changes/chg-a3/diff")
	if code != 200 || out["kind"] != "config" || strings.Join(f.diffArg, " ") != "edge-1 aaaaaaaaaaaa bbbbbbbbbbbb" {
		t.Fatalf("a configuration change diffs its two captured versions: %d %v %v", code, out, f.diffArg)
	}
	_, out = f.get(t, "acme", "/api/changes/chg-a2/diff")
	if out["kind"] != "values" || strings.Contains(out["before"].(string), "hunter2") {
		t.Fatalf("a value change shows redacted before/after: %v", out)
	}
	f.deps.ConfigDiff = nil
	if _, out := f.get(t, "acme", "/api/changes/chg-a3/diff"); !strings.Contains(nlJSON(out), "not enabled") {
		t.Fatalf("no backup: honest unavailable, got %v", out)
	}
	f.deps.ConfigDiff = func(context.Context, *http.Request, string, string, string) (Diff, error) { return Diff{}, ErrNotFound }
	if code, _ := f.get(t, "acme", "/api/changes/chg-a3/diff"); code != http.StatusNotFound {
		t.Fatalf("a device the caller cannot see: %d", code)
	}
	f.deps.ConfigDiff = func(context.Context, *http.Request, string, string, string) (Diff, error) {
		return Diff{}, errors.New("boom")
	}
	if code, _ := f.get(t, "acme", "/api/changes/chg-a3/diff"); code != http.StatusInternalServerError {
		t.Fatalf("a store failure is a 500, not an empty diff: %d", code)
	}
}

func TestOnlyGET(t *testing.T) {
	f := newFixture(t)
	r := httptest.NewRequest(http.MethodPost, "/api/changes", nil)
	r.Header.Set("X-Test-Tenant", "acme")
	w := httptest.NewRecorder()
	f.deps.Handler(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", w.Code)
	}
}

func nlJSON(v any) string {
	b, _ := json.Marshal(v) // best-effort: test formatting
	return string(b)
}
