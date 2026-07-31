package backend

// topology_metrics_isolation_test.go — §3a.4 regression guard.
//
// The topology metric bundle is keyed by device NAME and joined to the caller's
// devices by name. Queried unscoped, two tenants that both run a "core-sw1"
// would read each other's CPU, memory and interface utilisation onto their own
// topology nodes — a cross-tenant leak that renders as perfectly plausible data,
// which is what makes it dangerous: nothing looks wrong.
//
// This pins that every query gatherTopoMetrics issues carries the caller's
// VictoriaMetrics `extra_filters[]` scope.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"netops/backend/models"
)

// captureVM records the query args VictoriaMetrics is asked for.
type captureVM struct {
	mu      sync.Mutex
	queries []map[string][]string
}

func (c *captureVM) start(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		c.queries = append(c.queries, r.URL.Query())
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("VICTORIA_URL", srv.URL)
	return srv
}

func (c *captureVM) all() []map[string][]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]map[string][]string(nil), c.queries...)
}

func TestTopologyMetricsAreTenantScoped(t *testing.T) {
	cap := &captureVM{}
	cap.start(t)
	_, s := newTestServerState(t)

	// A scoped tenant with one visible device.
	s.discovery.Upsert(models.Device{ID: "d1", Name: "core-sw1", TenantID: "tenant-a"})
	claims := jwtClaims{Sub: "alice", Role: "operator", Tenant: "tenant-a"}

	s.gatherTopoMetrics(context.Background(), claims)

	got := cap.all()
	if len(got) == 0 {
		t.Fatal("no VictoriaMetrics queries were issued — the test cannot prove anything")
	}
	for i, q := range got {
		filters := q["extra_filters[]"]
		if len(filters) == 0 {
			t.Fatalf("query %d ran UNSCOPED (%q) — a tenant would read another tenant's device metrics by name",
				i, strings.Join(q["query"], ""))
		}
		// The filter must actually reference this tenant's device identity.
		joined := strings.Join(filters, " ")
		if !strings.Contains(joined, "d1") && !strings.Contains(joined, "core-sw1") &&
			!strings.Contains(joined, "__netops_no_visible_device__") {
			t.Fatalf("query %d carried a filter that names neither the visible device nor the empty-set sentinel: %q", i, joined)
		}
	}
}

// A platform owner legitimately sees everything, so no filter is expected —
// pinned so a future "always filter" change does not silently break the
// cross-tenant view.
func TestTopologyMetricsUnfilteredForPlatformOwner(t *testing.T) {
	cap := &captureVM{}
	cap.start(t)
	_, s := newTestServerState(t)

	s.gatherTopoMetrics(context.Background(), jwtClaims{Sub: "root", Role: "super-admin"})

	for i, q := range cap.all() {
		if len(q["extra_filters[]"]) != 0 {
			t.Fatalf("query %d restricted the platform owner: %v", i, q["extra_filters[]"])
		}
	}
}

// A scoped principal with NO visible devices must match nothing, never
// everything — the fail-closed half of the boundary.
func TestTopologyMetricsEmptyScopeMatchesNothing(t *testing.T) {
	cap := &captureVM{}
	cap.start(t)
	_, s := newTestServerState(t)

	s.gatherTopoMetrics(context.Background(), jwtClaims{Sub: "nobody", Role: "operator", Tenant: "tenant-empty"})

	got := cap.all()
	if len(got) == 0 {
		t.Fatal("no queries issued")
	}
	for i, q := range got {
		joined := strings.Join(q["extra_filters[]"], " ")
		if !strings.Contains(joined, "__netops_no_visible_device__") {
			t.Fatalf("query %d for a principal with no visible devices was not constrained to the empty set: %q", i, joined)
		}
	}
}
