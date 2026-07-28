package ticketing

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"netops/backend/internal/noclabel"
	"strings"
	"sync"
	"testing"
)

// mockServiceNow is an httptest-backed stand-in for the ServiceNow Table API
// (incident table only): create/patch/lookup-by-correlation_id, with knobs to
// force failures so we exercise the worker's retry/dead-letter paths. Shared by
// the adapter and worker tests (same package).
type mockServiceNow struct {
	srv       *httptest.Server
	mu        sync.Mutex
	incidents map[string]map[string]any // sys_id -> fields
	byCorr    map[string]string         // correlation_id -> sys_id
	seq       int
	failNext  int // return 500 for the next N create/patch calls
	wantUser  string
	wantPass  string
	creates   int
}

func newMockServiceNow() *mockServiceNow {
	m := &mockServiceNow{
		incidents: map[string]map[string]any{},
		byCorr:    map[string]string{},
		wantUser:  "svc",
		wantPass:  "secret",
	}
	m.srv = httptest.NewServer(http.HandlerFunc(m.handle))
	return m
}

func (m *mockServiceNow) Close() { m.srv.Close() }

func (m *mockServiceNow) cfg() SystemConfig {
	return SystemConfig{
		System: "servicenow", InstanceURL: m.srv.URL, AuthType: "basic",
		User: m.wantUser, Password: m.wantPass,
	}
}

func (m *mockServiceNow) adapter() *ServiceNowAdapter {
	return &ServiceNowAdapter{httpClient: m.srv.Client()}
}

func (m *mockServiceNow) handle(w http.ResponseWriter, r *http.Request) {
	if u, p, ok := r.BasicAuth(); !ok || u != m.wantUser || p != m.wantPass {
		http.Error(w, `{"error":{"message":"unauthorized"}}`, http.StatusUnauthorized)
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	switch {
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/now/table/incident/"):
		// Single-record read (inbound state sync): GET .../incident/{sys_id}.
		sysID := strings.TrimPrefix(r.URL.Path, "/api/now/table/incident/")
		inc, ok := m.incidents[sysID]
		if !ok {
			writeMockJSON(w, 404, map[string]any{"error": map[string]any{"message": "no record"}})
			return
		}
		writeMockJSON(w, 200, map[string]any{"result": inc})

	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/now/table/incident"):
		q := r.URL.Query().Get("sysparm_query")
		var res []map[string]any
		if corr, ok := strings.CutPrefix(q, "correlation_id="); ok {
			if sysID, found := m.byCorr[corr]; found {
				inc := m.incidents[sysID]
				res = append(res, map[string]any{"number": inc["number"], "sys_id": sysID})
			}
		}
		writeMockJSON(w, 200, map[string]any{"result": res})

	case r.Method == http.MethodPost && r.URL.Path == "/api/now/table/incident":
		if m.failNext > 0 {
			m.failNext--
			writeMockJSON(w, 500, map[string]any{"error": map[string]any{"message": "simulated failure"}})
			return
		}
		body := readMockBody(r)
		m.seq++
		m.creates++
		sysID := fmt.Sprintf("sys%04d", m.seq)
		number := fmt.Sprintf("INC%07d", m.seq)
		body["number"] = number
		body["sys_id"] = sysID
		m.incidents[sysID] = body
		if corr, _ := body["correlation_id"].(string); corr != "" {
			m.byCorr[corr] = sysID
		}
		writeMockJSON(w, 201, map[string]any{"result": map[string]any{"number": number, "sys_id": sysID}})

	case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/api/now/table/incident/"):
		if m.failNext > 0 {
			m.failNext--
			writeMockJSON(w, 500, map[string]any{"error": map[string]any{"message": "simulated failure"}})
			return
		}
		sysID := strings.TrimPrefix(r.URL.Path, "/api/now/table/incident/")
		inc, ok := m.incidents[sysID]
		if !ok {
			writeMockJSON(w, 404, map[string]any{"error": map[string]any{"message": "no record"}})
			return
		}
		for k, v := range readMockBody(r) {
			inc[k] = v
		}
		m.incidents[sysID] = inc
		writeMockJSON(w, 200, map[string]any{"result": inc})

	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (m *mockServiceNow) incidentByCorr(corr string) (map[string]any, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sysID, ok := m.byCorr[corr]
	if !ok {
		return nil, false
	}
	return m.incidents[sysID], true
}

func writeMockJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func readMockBody(r *http.Request) map[string]any {
	b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	m := map[string]any{}
	_ = json.Unmarshal(b, &m)
	return m
}

// ── adapter tests ────────────────────────────────────────────────────────────

func samplePayload(corrID string) Payload {
	return Payload{
		CorrObjectID:      corrID,
		ExternalSystem:    "servicenow",
		Title:             "Confirmed local link fault on edge1 Gi0/1",
		Verdict:           "confirmed",
		Confidence:        0.91,
		Signature:         "local-link-fault",
		Summary:           "Interface down corroborated by probe loss.",
		RecommendedAction: "Dispatch to site; check edge1 Gi0/1 optics.",
		AffectedScope:     "edge1 Gi0/1",
		EvidenceUsed:      []string{"two independent planes agree"},
		MissingEvidence:   []string{"neighbor-side confirmation"},
		RCAURL:            "https://correlix.example/app/correlations/" + corrID,
		Impact:            1,
		Urgency:           2,
	}
}

// TestSnowFriendlyProblemID: the friendly Correlix Problem ID (P-XXXXXX) is
// stamped into short_description, a custom field, and the body, so NOC and
// ServiceNow share one handle (#10).
func TestSnowFriendlyProblemID(t *testing.T) {
	corrID := "5564d162-c891-5480-800b-9b7fbcdd59b2"
	pid := noclabel.ProblemDisplayID(corrID) // P-5564D1
	f := snowIncidentFields(SystemConfig{}, samplePayload(corrID))
	sd, _ := f["short_description"].(string)
	if !strings.HasPrefix(sd, "["+pid+"] ") {
		t.Fatalf("short_description must lead with the friendly id, got %q", sd)
	}
	if f["u_correlix_problem_id"] != pid {
		t.Fatalf("u_correlix_problem_id = %v, want %s", f["u_correlix_problem_id"], pid)
	}
	if f["correlation_id"] != corrID || f["u_correlix_object_id"] != corrID {
		t.Fatal("the UUID must stay the dedupe anchor")
	}
	if desc, _ := f["description"].(string); !strings.Contains(desc, "Correlix Problem: "+pid) {
		t.Fatalf("description must name the problem id, got %q", desc)
	}
}

func TestServiceNowAdapter_CreateLookupUpdateResolve(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	m := newMockServiceNow()
	defer m.Close()
	a := m.adapter()
	cfg := m.cfg()
	ctx := context.Background()

	ref, err := a.CreateIncident(ctx, cfg, samplePayload("obj-1"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if ref.SysID == "" || ref.Number == "" {
		t.Fatalf("create returned empty ref: %+v", ref)
	}

	// The incident carries the RCA correlation_id + custom fields.
	inc, ok := m.incidentByCorr("obj-1")
	if !ok {
		t.Fatal("incident not stored under correlation_id")
	}
	if inc["u_correlix_verdict"] != "confirmed" || inc["correlation_id"] != "obj-1" {
		t.Fatalf("RCA fields not mapped: %+v", inc)
	}

	// Lookup recovers the same incident by correlation id.
	got, found, err := a.LookupByCorrelationID(ctx, cfg, "obj-1")
	if err != nil || !found || got.SysID != ref.SysID {
		t.Fatalf("lookup mismatch: found=%v err=%v got=%+v", found, err, got)
	}

	if err := a.UpdateIncident(ctx, cfg, ref, samplePayload("obj-1")); err != nil {
		t.Fatalf("update: %v", err)
	}
	if err := a.AddWorkNote(ctx, cfg, ref, "verdict refreshed"); err != nil {
		t.Fatalf("work note: %v", err)
	}
	if err := a.ResolveIncident(ctx, cfg, ref, "incident cleared"); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	inc, _ = m.incidentByCorr("obj-1")
	if inc["state"] != "6" {
		t.Fatalf("resolve did not set state=6: %+v", inc["state"])
	}
}

func TestServiceNowAdapter_ValidateConfig(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	a := NewServiceNowAdapter()
	if err := a.ValidateConfig(SystemConfig{InstanceURL: "https://x.example", AuthType: "basic", User: "u", Password: "p"}); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if err := a.ValidateConfig(SystemConfig{InstanceURL: "https://x.example", AuthType: "basic", User: "u"}); err == nil {
		t.Fatal("missing password should fail")
	}
	if err := a.ValidateConfig(SystemConfig{InstanceURL: "", AuthType: "basic"}); err == nil {
		t.Fatal("missing instance_url should fail")
	}
}

func TestServiceNowAdapter_ErrorNeverLeaksSecret(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	m := newMockServiceNow()
	defer m.Close()
	a := m.adapter()
	cfg := m.cfg()
	cfg.Password = "super-secret-token"
	m.wantPass = "different" // force a 401
	_, err := a.CreateIncident(context.Background(), cfg, samplePayload("obj-x"))
	if err == nil {
		t.Fatal("expected auth error")
	}
	if strings.Contains(err.Error(), "super-secret-token") {
		t.Fatalf("error leaked the secret: %v", err)
	}
}

// TestSnowIncidentCategory pins the incident category: every Correlix RCA ticket
// is a network fault — leaving category unset misrouted incidents to ServiceNow's
// default queue (operator report 2026-07-11).
func TestSnowIncidentCategory(t *testing.T) {
	f := snowIncidentFields(SystemConfig{}, samplePayload("936cc7fe-0000-0000-0000-0000000000aa"))
	if f["category"] != "network" {
		t.Fatalf("category = %v, want network", f["category"])
	}
}
