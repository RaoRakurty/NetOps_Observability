// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// escalategate_test.go — which permission level each escalation route runs at.
//
// The rule this file pins is simple and was broken: a route that CHANGES the
// escalation takes the write gate. Classify overwrites the recorded class and
// nulls a plan built for the old one; Plan overwrites the prepared plan; Refresh
// spends the vendor's rate-limit budget and writes the case record back onto the
// incident. None of those is "view everything, change nothing".
//
// The sharpest consequence is not the overwrite. Both mutating routes reach the
// register through stateLocked, and stateLocked evicts at the per-tenant bound —
// which calls Capture.Close, which REMOVES another operator's collected
// evidence from disk. So the last test here holds a full register of collected
// escalations and proves a read-only caller cannot reach that.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// gateRole is the caller's level, decided the way the platform decides it:
// infrastructure:read or infrastructure:write.
type gateRole string

const (
	roleReadOnly gateRole = "read-only"
	roleOperator gateRole = "operator"
)

// gateProbe is a whole escalate surface over an injected gate, recording which
// level each route actually asked for.
type gateProbe struct {
	api     *EscalateAPI
	svc     *Service
	asked   []bool // one entry per Resolve call: true = write level
	refused int
}

// newGateProbe wires the surface with the platform's own gate SHAPE: a write
// request from a read-only principal is a 403, exactly as requirePerm answers.
func newGateProbe(t *testing.T, svc *Service, role gateRole) *gateProbe {
	t.Helper()
	p := &gateProbe{svc: svc}
	tracker := NewCaseTracker(func() time.Time { return time.Unix(1700000000, 0).UTC() })
	poller, err := NewCasePoller(tracker,
		func(context.Context, string, string, CaseHandle) (CaseResult, error) {
			return CaseResult{}, ErrCapabilityUnsupported
		},
		nil, nil)
	if err != nil {
		t.Fatalf("poller: %v", err)
	}
	api, err := NewEscalateAPI(EscalateAPIDeps{
		Service: svc,
		Resolve: func(w http.ResponseWriter, r *http.Request, write bool) (Subject, bool) {
			p.asked = append(p.asked, write)
			if write && role == roleReadOnly {
				p.refused++
				http.Error(w, "forbidden", http.StatusForbidden)
				return Subject{}, false
			}
			return Subject{
				IncidentID: strings.TrimSpace(r.PathValue("id")), Ref: "INC-1", Title: "OSPF down",
				Tenant: "t1", Actor: "op@example.test", Devices: []string{"d1"},
			}, true
		},
		ResolveDevice: func(_ http.ResponseWriter, _ *http.Request, _ Subject, _ string) (Device, bool) {
			return iosxeDevice(), true
		},
		Evidence: func(*http.Request, Subject) (Evidence, []string, []string) {
			return Evidence{Alerts: []string{"OSPFNeighborDown"}}, []string{"alerts"}, nil
		},
		Topology:    func(*http.Request, string) []TopologyNote { return nil },
		BundleInput: func(*http.Request, Subject) BundleInput { return BundleInput{} },
		Settings:    func(*http.Request, Subject, string, string) EscalationSettings { return EscalationSettings{} },
		Tracker:     tracker,
		Poller:      poller,
		PersistCase: func(context.Context, string, string, CaseLink) {},
		Audit:       func(*http.Request, string, string, map[string]any) {},
		WriteJSON: func(w http.ResponseWriter, status int, body any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(body)
		},
		WriteError: func(w http.ResponseWriter, status int, err error) {
			http.Error(w, err.Error(), status)
		},
		Now: func() time.Time { return time.Unix(1700000000, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("escalate api: %v", err)
	}
	p.api = api
	return p
}

// post drives one route with {id} bound, the way the mux does.
func (p *gateProbe) post(h http.HandlerFunc, incident, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/incidents/"+incident+"/tac", strings.NewReader(body))
	r.SetPathValue("id", incident)
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

// TestMutatingEscalationRoutesTakeTheWriteGate — Classify, Plan and Refresh all
// change something, so a read-only principal is refused on every one of them.
func TestMutatingEscalationRoutesTakeTheWriteGate(t *testing.T) {
	routes := []struct {
		name string
		pick func(a *EscalateAPI) http.HandlerFunc
		body string
	}{
		{"classify", func(a *EscalateAPI) http.HandlerFunc { return a.HandleClassify }, ""},
		{"plan", func(a *EscalateAPI) http.HandlerFunc { return a.HandlePlan }, `{"device_id":"d1"}`},
		{"refresh", func(a *EscalateAPI) http.HandlerFunc { return a.HandleRefresh }, ""},
	}
	for _, rt := range routes {
		t.Run(rt.name, func(t *testing.T) {
			svc := testService(t)
			p := newGateProbe(t, svc, roleReadOnly)
			w := p.post(rt.pick(p.api), "inc-1", rt.body)
			if w.Code != http.StatusForbidden {
				t.Fatalf("a read-only principal got %d from %s, not 403", w.Code, rt.name)
			}
			if len(p.asked) != 1 || !p.asked[0] {
				t.Fatalf("%s asked the gate for write=%v; it must ask for write", rt.name, p.asked)
			}
			if st := svc.Get("t1", "inc-1"); st != nil {
				t.Fatalf("%s left state behind for a caller it refused: %+v", rt.name, st)
			}
		})
	}
}

// TestClassifyAndPlanStillWorkForAnOperator — the gate moved, the feature did
// not: a write principal classifies and plans exactly as before.
func TestClassifyAndPlanStillWorkForAnOperator(t *testing.T) {
	svc := testService(t)
	p := newGateProbe(t, svc, roleOperator)

	if w := p.post(p.api.HandleClassify, "inc-1", ""); w.Code != http.StatusOK {
		t.Fatalf("classify: %d %s", w.Code, w.Body.String())
	}
	st := svc.Get("t1", "inc-1")
	if st == nil || st.Classification == nil {
		t.Fatal("classify recorded nothing for an operator")
	}
	if w := p.post(p.api.HandlePlan, "inc-1", `{"device_id":"d1"}`); w.Code != http.StatusOK {
		t.Fatalf("plan: %d %s", w.Code, w.Body.String())
	}
	if st = svc.Get("t1", "inc-1"); st == nil || st.Plan == nil {
		t.Fatal("plan recorded nothing for an operator")
	}
}

// TestAReadOnlyPrincipalCannotEvictAnotherOperatorsEvidence is the destructive
// half of the finding. The register is full of COLLECTED escalations, each
// holding a spill directory on disk. A classify or a plan for a new incident
// would evict the oldest and delete its files; a read-only caller must not be
// able to reach that.
func TestAReadOnlyPrincipalCannotEvictAnotherOperatorsEvidence(t *testing.T) {
	svc := testService(t)
	root := t.TempDir()
	byInc := map[string]*State{}
	dirs := make([]string, 0, maxEscalationsPerTenant)
	for i := 0; i < maxEscalationsPerTenant; i++ {
		capt := captureWithSpill(t, root)
		dirs = append(dirs, capt.SpillDir)
		id := "inc-old-" + itoaTAC(i)
		byInc[id] = &State{TenantID: "t1", IncidentID: id, Capture: capt,
			Bundles: []StoredBundle{}, UpdatedAt: time.Unix(1700000000, 0).UTC()}
	}
	svc.mu.Lock()
	svc.states["t1"] = byInc
	svc.mu.Unlock()

	p := newGateProbe(t, svc, roleReadOnly)
	for _, tc := range []struct {
		name string
		h    http.HandlerFunc
		body string
	}{
		{"classify", p.api.HandleClassify, ""},
		{"plan", p.api.HandlePlan, `{"device_id":"d1"}`},
	} {
		if w := p.post(tc.h, "inc-new", tc.body); w.Code != http.StatusForbidden {
			t.Fatalf("%s: a read-only principal got %d, not 403", tc.name, w.Code)
		}
	}
	for _, d := range dirs {
		if _, err := os.Stat(d); err != nil {
			t.Fatalf("a read-only caller destroyed collected evidence at %s: %v", d, err)
		}
	}
	svc.mu.Lock()
	n := len(svc.states["t1"])
	svc.mu.Unlock()
	if n != maxEscalationsPerTenant {
		t.Fatalf("the register lost %d escalations to a read-only caller", maxEscalationsPerTenant-n)
	}
}
