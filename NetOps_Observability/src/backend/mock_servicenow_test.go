package backend

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"netops/backend/internal/ticketing"
)

// Duplicated test fixture: the package's adapter tests and main's worker/
// inbound tests both need the ServiceNow Table API stand-in, and test files
// cannot be imported across packages.
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

func (m *mockServiceNow) cfg() ticketing.SystemConfig {
	return ticketing.SystemConfig{
		System: "servicenow", InstanceURL: m.srv.URL, AuthType: "basic",
		User: m.wantUser, Password: m.wantPass,
	}
}

func (m *mockServiceNow) adapter() *ticketing.ServiceNowAdapter {
	return ticketing.NewServiceNowAdapterWithClient(m.srv.Client())
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

// samplePayload mirrors the package fixture for main's worker/inbound tests.
func samplePayload(corrID string) ticketing.Payload {
	return ticketing.Payload{
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
