package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Infra-stack monitoring is reserved for the PLATFORM OWNER (the cross-tenant
// global-tenant super-admin). A tenant-scoped principal monitors its OWN
// network; it never sees the platform's own plumbing (the container stack + data
// backends). This is the backend enforcement; the SPA also hides the nav entries.
// See the strict-tenancy model in tenancy.go. NOTE: this gate is deliberately
// standalone for now; it will be re-expressed through the central Authorize()
// layer (Phase 1) once that lands, so the rule lives in one place.

// requireCrossTenant gates an action to the platform owner. Returns 403 for any
// tenant-scoped principal — even a tenant's own super-admin — who may run their
// own network monitoring but never the platform's stack.
func (s *server) requireCrossTenant(w http.ResponseWriter, r *http.Request) (jwtClaims, bool) {
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
		return claims, false
	}
	if _, cross := principalTenant(claims); !cross {
		writeError(w, http.StatusForbidden, errors.New("platform administrator required"))
		return claims, false
	}
	return claims, true
}

// stackProbe describes one stack dependency to liveness-probe.
type stackProbe struct {
	name     string
	category string // search | metrics | olap | analytics | bus | state | visualization
	kind     string // "http" | "tcp"
	target   string // http URL (kind=http) or host:port (kind=tcp)
}

// stackComponentHealth is the per-component result the UI renders.
type stackComponentHealth struct {
	Name      string `json:"name"`
	Category  string `json:"category"`
	Status    string `json:"status"` // up | degraded | down
	LatencyMS int64  `json:"latency_ms"`
	Detail    string `json:"detail,omitempty"`
}

// stackInventory builds the probe list from the SAME env the API already uses to
// reach the stack (with compose-network defaults), so health targets are never
// guesswork — they track whatever the deployment is actually configured to use.
func stackInventory() []stackProbe {
	return []stackProbe{
		{"Search (OpenSearch)", "search", "http", envOr("OPENSEARCH_URL", "http://opensearch:9200") + "/_cluster/health"},
		{"Metrics store (VictoriaMetrics)", "metrics", "http", envOr("VICTORIA_URL", "http://victoria:8428") + "/health"},
		{"Metrics scrape (Prometheus)", "metrics", "http", envOr("PROMETHEUS_URL", "http://prometheus:9090") + "/-/healthy"},
		{"OLAP / flows (ClickHouse)", "olap", "http", envOr("CLICKHOUSE_URL", "http://clickhouse:8123") + "/ping"},
		{"Correlation service", "analytics", "http", envOr("CORRELATION_URL", "http://correlation:8000") + "/findings"},
		{"Visualization (Grafana)", "visualization", "http", envOr("GRAFANA_URL", "http://grafana:3000") + "/api/health"},
		{"Event bus (Redpanda)", "bus", "tcp", net.JoinHostPort(envOr("REDPANDA_HOST", "redpanda"), envOr("REDPANDA_PORT", "9092"))},
		{"App database (PostgreSQL)", "state", "tcp", net.JoinHostPort(envOr("DB_HOST", "postgres"), envOr("DB_PORT", "5432"))},
		{"Cache (Redis)", "state", "tcp", net.JoinHostPort(envOr("REDIS_HOST", "redis"), envOr("REDIS_PORT", "6379"))},
	}
}

// probeOne liveness-checks a single stack dependency. An HTTP response (even a
// 4xx) means the process is alive → "up"; a 5xx is "degraded"; a transport
// error or timeout is "down". A TCP probe is up iff the connection establishes.
// Every probe is bounded by the supplied context plus a per-probe timeout.
func probeOne(ctx context.Context, p stackProbe) stackComponentHealth {
	out := stackComponentHealth{Name: p.name, Category: p.category, Status: "down"}
	start := time.Now()
	switch p.kind {
	case "http":
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.target, nil)
		if err != nil {
			out.Detail = err.Error()
			return out
		}
		client := &http.Client{Timeout: 4 * time.Second}
		resp, err := client.Do(req)
		out.LatencyMS = time.Since(start).Milliseconds()
		if err != nil {
			out.Detail = err.Error()
			return out
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode >= 500 {
			out.Status = "degraded"
		} else {
			out.Status = "up"
		}
		out.Detail = resp.Status
	case "tcp":
		d := net.Dialer{Timeout: 4 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", p.target)
		out.LatencyMS = time.Since(start).Milliseconds()
		if err != nil {
			out.Detail = err.Error()
			return out
		}
		_ = conn.Close()
		out.Status = "up"
	}
	return out
}

// handleStackHealth reports the platform's own stack health (data backends, bus,
// state, visualization) plus the in-process subsystems. PLATFORM-OWNER ONLY.
func (s *server) handleStackHealth(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireCrossTenant(w, r); !ok {
		return
	}
	probes := stackInventory()
	results := make([]stackComponentHealth, len(probes))

	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for i, p := range probes {
		wg.Add(1)
		go func(i int, p stackProbe) {
			defer wg.Done()
			results[i] = probeOne(ctx, p)
		}(i, p)
	}
	wg.Wait()

	up, degraded, down := 0, 0, 0
	for _, c := range results {
		switch c.Status {
		case "up":
			up++
		case "degraded":
			degraded++
		default:
			down++
		}
	}
	overall := "healthy"
	switch {
	case up == 0:
		overall = "down"
	case down > 0 || degraded > 0:
		overall = "degraded"
	}

	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Category != results[j].Category {
			return results[i].Category < results[j].Category
		}
		return results[i].Name < results[j].Name
	})

	// In-process subsystems, included so the platform view is one call. Guarded
	// so the endpoint never panics if a subsystem isn't wired (e.g. in tests).
	subsystems := map[string]any{}
	if s.discovery != nil {
		subsystems["discovery"] = s.discovery.Health()
	}
	if s.collectors != nil {
		subsystems["collectors"] = s.collectors.Health()
	}
	if s.alerts != nil {
		subsystems["alerts"] = s.alerts.Health()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"overall":    overall,
		"up":         up,
		"degraded":   degraded,
		"down":       down,
		"components": results,
		"subsystems": subsystems,
	})
}
