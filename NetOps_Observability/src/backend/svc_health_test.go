package backend

// svc_health_test.go — per-service health score (#69 P2): pure collapse
// detector, seam-token allowlist, handler gates, and the bound-path filter's
// default-closed behavior. The cross-tenant 404 path rides GetService under
// RLS (svc_catalog_isolation_pg_test.go).

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/healthscore"
)

func TestServiceFlowBadness(t *testing.T) {
	if b := serviceFlowBadness(0, 0, 0); b != 0 {
		t.Errorf("no history must yield 0, got %v", b)
	}
	if b := serviceFlowBadness(0, 100, 30); b != 0 {
		t.Errorf("under an hour of norm history must yield 0, got %v", b)
	}
	// Healthy: recent ≈ norm.
	if b := serviceFlowBadness(15e6, 24*60*1e6, 24*60); b != 0 {
		t.Errorf("steady traffic must yield 0, got %v", b)
	}
	// Halved traffic is ordinary variance — below the hinge.
	if b := serviceFlowBadness(7.5e6, 24*60*1e6, 24*60); b != 0 {
		t.Errorf("50%% dip must not register, got %v", b)
	}
	// Total collapse pegs the signal.
	if b := serviceFlowBadness(0, 24*60*1e6, 24*60); b != 1 {
		t.Errorf("total stop must yield 1, got %v", b)
	}
	// Near-collapse ramps between the hinge points.
	if b := serviceFlowBadness(1.5e6, 24*60*1e6, 24*60); b <= 0 || b >= 1 {
		t.Errorf("90%% drop must ramp in (0,1), got %v", b)
	}
}

func TestIsSeamToken(t *testing.T) {
	for _, ok := range []string{"seam:aws-dx.dallas", "core_edge-1"} {
		if !isSeamToken(ok) {
			t.Errorf("%q should be a valid seam token", ok)
		}
	}
	for _, bad := range []string{"", "x' OR 1=1 --", "a b", string(make([]byte, 200))} {
		if isSeamToken(bad) {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

// Scope routing + input gates: unknown scope 400, service scope requires a
// UUID, and without the Postgres catalog the service scope is an honest 501.
func TestHealthScoreServiceScopeGates(t *testing.T) {
	roles, err := newRoleStore(t.TempDir() + "/roles.json")
	if err != nil {
		t.Fatal(err)
	}
	s := &server{roles: roles}

	w := httptest.NewRecorder()
	s.handleHealthScore(w, req("GET", "/api/health/score?scope=fleet", "", superA()))
	if w.Code != 400 {
		t.Errorf("unknown scope = %d, want 400", w.Code)
	}
	w = httptest.NewRecorder()
	s.handleHealthScore(w, req("GET", "/api/health/score?scope=service&service_id=nope", "", superA()))
	if w.Code != 501 && w.Code != 400 {
		t.Errorf("bad service_id = %d, want 400/501", w.Code)
	}
	w = httptest.NewRecorder()
	s.handleHealthScore(w, req("GET", "/api/health/score?scope=service&service_id=11111111-1111-4111-8111-111111111111", "", superA()))
	if w.Code != 501 {
		t.Errorf("service scope without catalog = %d, want 501", w.Code)
	}
}

// A service with NO probe/path bindings must not inherit the whole fleet's
// paths: an empty (non-nil) allow set short-circuits to not-live — before any
// VictoriaMetrics IO (default-closed).
func TestFetchPathHealthClassFilteredEmptyAllow(t *testing.T) {
	t.Setenv("VICTORIA_URL", "http://127.0.0.1:9") // any dial would fail loudly
	s := &server{}
	res := s.fetchPathHealthClassFiltered(t.Context(), map[string]bool{}, nil)
	if res.Live {
		t.Fatal("no bound paths must leave the class not live")
	}
}

// fetchServiceFlowClass: rollup rows present with a recent total stop → live
// class with a collapse contribution; the query is pinned to the service row's
// own tenant.
func TestFetchServiceFlowClassCollapse(t *testing.T) {
	now := time.Now().UTC()
	var gotSQL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotSQL = string(b)
		rows := ""
		for i := 30; i < 90; i++ { // an hour of steady traffic, stopping 30m ago
			if rows != "" {
				rows += ","
			}
			rows += fmt.Sprintf(`{"minute_ts":%d,"bytes":1000000,"flows":10}`, now.Add(-time.Duration(i)*time.Minute).Unix())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[` + rows + `]}`))
	}))
	defer srv.Close()
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")

	s := &server{}
	svc := Service{ServiceID: "11111111-1111-4111-8111-111111111111", TenantID: "acme", Name: "Teams"}
	res := s.fetchServiceFlowClass(req("GET", "/api/health/score", "", acme()), svc)
	if !res.Live {
		t.Fatal("rows present → class must be live")
	}
	if res.Badness <= 0.9 {
		t.Errorf("total recent stop should peg badness, got %v", res.Badness)
	}
	if len(res.Contribs) != 1 || res.Contribs[0].Entity != "Teams" {
		t.Errorf("collapse must contribute with the service name: %+v", res.Contribs)
	}
	for _, want := range []string{"tenant_id = 'acme'", "argMax(b, selector_version)"} {
		if !strings.Contains(gotSQL, want) {
			t.Errorf("rollup read missing %q:\n%s", want, gotSQL)
		}
	}
}

// A dark rollup (no rows / CH down) drops the class rather than scoring it.
func TestFetchServiceFlowClassDarkNotLive(t *testing.T) {
	t.Setenv("CLICKHOUSE_URL", "http://127.0.0.1:9")
	s := &server{}
	res := s.fetchServiceFlowClass(req("GET", "/x", "", acme()), Service{ServiceID: "11111111-1111-4111-8111-111111111111", TenantID: "acme"})
	if res.Live {
		t.Fatal("unreachable ClickHouse must leave flow_health not live")
	}
}

// The service response keeps the shared explainability contract (arrays never
// null, INSUFFICIENT_TELEMETRY with <2 live classes).
func TestServiceScopeInsufficientTelemetryContract(t *testing.T) {
	r := healthscore.Aggregate("service", "svc-1", []healthscore.ClassResult{
		{Class: "flow_health", Live: true, Badness: 0.2},
		{Class: "path_health"}, {Class: "correlation"},
	}, "now")
	if r.CoverageStatus != "INSUFFICIENT_TELEMETRY" || r.Score != nil {
		t.Fatalf("one live class must be insufficient: %+v", r)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), `"contributions":null`) {
		t.Error("list fields must serialize as [], never null")
	}
}
