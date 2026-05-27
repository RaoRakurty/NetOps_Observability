package main

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"time"
)

// dashboard.go — endpoints that feed the live Dashboard tab.
//
//   GET /api/metrics      → tile data for the initial render
//   (live updates arrive over WebSocket on /api/events)

// MetricTile matches the shape the glassy Dashboard expects per card.
type MetricTile struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Trend string `json:"trend,omitempty"`
}

func (s *server) handleMetricTiles(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.currentMetricTiles())
}

// currentMetricTiles snapshots the system state into the dashboard
// tile shape. Add tiles by appending — the frontend simply renders
// whatever the array contains.
func (s *server) currentMetricTiles() []MetricTile {
	devices := len(s.discovery.Devices())
	alerts := len(s.alerts.Active())
	rules := len(s.alerts.Rules())

	collectorsOn := 0
	for _, c := range s.collectors.Status() {
		if c.Enabled {
			collectorsOn++
		}
	}

	return []MetricTile{
		{Title: "Devices",        Value: fmt.Sprintf("%d", devices),      Trend: trendForCount(devices)},
		{Title: "Active Alerts",  Value: fmt.Sprintf("%d", alerts),       Trend: trendForAlerts(alerts)},
		{Title: "Collectors",     Value: fmt.Sprintf("%d", collectorsOn), Trend: "live"},
		{Title: "Alert Rules",    Value: fmt.Sprintf("%d", rules),        Trend: ""},
	}
}

func trendForCount(n int) string {
	if n == 0 {
		return ""
	}
	return "+"
}

func trendForAlerts(n int) string {
	switch {
	case n == 0:
		return "all clear"
	case n > 0 && n < 5:
		return "warning"
	default:
		return "critical"
	}
}

// ----------------------------------------------------------------------------
// startBroadcaster runs in its own goroutine and emits the three event
// types the dashboard listens for. Real metric_update / telemetry events
// are derived from the system's own state; alert events fan out from
// the notifier.
// ----------------------------------------------------------------------------

func (s *server) startBroadcaster(stop <-chan struct{}) {
	metricsTicker := time.NewTicker(5 * time.Second)
	defer metricsTicker.Stop()

	telemetryTicker := time.NewTicker(2 * time.Second)
	defer telemetryTicker.Stop()

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for {
		select {
		case <-stop:
			return

		case <-metricsTicker.C:
			// Push the full tile list so the client doesn't have to
			// reconcile partial updates. The receiver upserts by title.
			for _, t := range s.currentMetricTiles() {
				s.hub.Broadcast(map[string]any{
					"type": "metric_update",
					"data": t,
				})
			}

		case <-telemetryTicker.C:
			// Placeholder telemetry value — replace with a real
			// throughput / ingest-rate metric when wired.
			val := 40 + rng.Intn(120)
			s.hub.Broadcast(map[string]any{
				"type": "telemetry",
				"data": map[string]any{"value": val},
			})
		}
	}
}

// watchAlertsForBroadcast polls the active alert set every few seconds
// and broadcasts new alerts to the WebSocket hub. We diff against the
// last seen set so each alert is sent exactly once per firing.
//
// (A push-based hook would be cleaner — alert engine calls hub.Broadcast
// directly when a rule fires — but that creates a circular import
// between the alerts package and the main package's Hub. The polling
// shim avoids the dependency tangle without losing much fidelity since
// the engine itself only ticks every 30s.)
func (s *server) watchAlertsForBroadcast(ctx context.Context) {
	seen := make(map[string]bool)
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, a := range s.alerts.Active() {
				if seen[a.ID] {
					continue
				}
				seen[a.ID] = true
				s.hub.Broadcast(map[string]any{
					"type": "alert",
					"data": a,
				})
			}
		}
	}
}
