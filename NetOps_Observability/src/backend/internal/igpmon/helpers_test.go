// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package igpmon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// helpers_test.go — the in-memory harness. Every external collaborator is
// recorded so a test can assert on WHAT WAS SENT (the tenant scope, the SQL,
// the extra_filters[]) and not merely on what came back: an isolation property
// that is only observed through the response is a property that can rot.

type chCall struct {
	scope string
	sql   string
}

type vmCall struct {
	query   string
	filters []string
}

type harness struct {
	t *testing.T

	// recorded traffic
	ch []chCall
	vm []vmCall

	// programmable behaviour
	principal    Principal
	authzOK      bool
	authzStatus  int // the status the refusing gate writes (401 or 403)
	scope        string
	devices      map[string]Device
	visibleTo    func(d Device, p Principal) bool
	rows         []map[string]any
	chErr        error
	samples      map[string][]Sample // query → samples
	vmErr        error
	scopeFilters []string
	now          time.Time
	// onWarn observes the module's structured warnings (§10: no silent failure).
	onWarn func(msg string, fields map[string]any)

	api *API
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{
		t:            t,
		authzOK:      true,
		authzStatus:  http.StatusForbidden,
		principal:    Principal{Tenant: "acme", Subject: "u1"},
		scope:        "acme",
		devices:      map[string]Device{},
		samples:      map[string][]Sample{},
		scopeFilters: []string{`{device=~"spine1"}`},
		now:          time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC),
	}
	h.visibleTo = func(d Device, p Principal) bool { return p.Cross || d.TenantID == p.Tenant }
	api, err := New(Deps{
		Now: func() time.Time { return h.now },
		Authz: func(w http.ResponseWriter, r *http.Request, g Gate) (Principal, bool) {
			if !h.authzOK {
				status := h.authzStatus
				if status == 0 {
					status = http.StatusForbidden
				}
				writeTestJSON(w, status, map[string]any{"error": http.StatusText(status)})
				return Principal{}, false
			}
			return h.principal, true
		},
		LookupDevice: func(id string) (Device, bool) { d, ok := h.devices[id]; return d, ok },
		CanSee:       func(d Device, p Principal) bool { return h.visibleTo(d, p) },
		Scope:        func(r *http.Request) string { return h.scope },
		CHQuery: func(ctx context.Context, scope, sql string) ([]map[string]any, error) {
			h.ch = append(h.ch, chCall{scope: scope, sql: sql})
			if h.chErr != nil {
				return nil, h.chErr
			}
			return h.rows, nil
		},
		ScopeFilters: func(r *http.Request, p Principal) []string { return h.scopeFilters },
		VMQuery: func(ctx context.Context, q string, f []string) ([]Sample, error) {
			h.vm = append(h.vm, vmCall{query: q, filters: append([]string(nil), f...)})
			if h.vmErr != nil {
				return nil, h.vmErr
			}
			return h.samples[q], nil
		},
		Metrics:   NewMetrics(),
		WriteJSON: func(w http.ResponseWriter, status int, body any) { writeTestJSON(w, status, body) },
		WriteError: func(w http.ResponseWriter, status int, err error) {
			writeTestJSON(w, status, map[string]any{"error": err.Error()})
		},
		LogWarn: func(msg string, f map[string]any) {
			if h.onWarn != nil {
				h.onWarn(msg, f)
			}
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.api = api
	return h
}

func writeTestJSON(w http.ResponseWriter, status int, body any) {
	b, err := json.Marshal(body)
	if err != nil {
		http.Error(w, "encode", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b) // test sink: a short write on a recorder is not actionable
}

// get issues a GET through the real dispatcher and returns the recorder plus
// the decoded body.
func (h *harness) get(path string) (*httptest.ResponseRecorder, map[string]any) {
	h.t.Helper()
	w := httptest.NewRecorder()
	h.api.Handler()(w, httptest.NewRequest(http.MethodGet, path, nil))
	var body map[string]any
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			body = nil
		}
	}
	return w, body
}

// chRow builds one ClickHouse FORMAT JSON row. 64-bit integers arrive QUOTED,
// which is exactly the shape the parser has to survive.
func chRow(tsMS int64, signalID, device, peer, state, severity, source, ifname string) map[string]any {
	return map[string]any{
		"ts_ms":     jsonInt(tsMS),
		"signal_id": signalID,
		"device":    device,
		"peer":      peer,
		"state":     state,
		"severity":  severity,
		"source":    source,
		"ifname":    ifname,
	}
}

func jsonInt(n int64) string {
	b, _ := json.Marshal(n) // #nosec G104 -- marshalling an int64 cannot fail
	return string(b)
}

func coverageOf(t *testing.T, body map[string]any) Coverage {
	t.Helper()
	raw, ok := body["coverage"].(map[string]any)
	if !ok {
		t.Fatalf("response has no coverage block: %v", body)
	}
	return Coverage{
		Events:     raw["events"] == true,
		LiveSeries: raw["live_series"] == true,
		LSDB:       raw["lsdb"] == true,
		Areas:      raw["areas"] == true,
		SPFRuns:    raw["spf_runs"] == true,
		Timers:     raw["timers"] == true,
	}
}

func notesOf(body map[string]any) []string {
	raw, _ := body["notes"].([]any)
	out := make([]string, 0, len(raw))
	for _, n := range raw {
		if s, ok := n.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
