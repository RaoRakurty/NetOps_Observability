// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"netops/backend/models"
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

func (s *server) handleMetricTiles(w http.ResponseWriter, r *http.Request) {
	claims, _ := userFrom(r.Context())
	writeJSON(w, http.StatusOK, s.currentMetricTiles(claims))
}

// currentMetricTiles snapshots the system state into the dashboard tile shape,
// SCOPED to the caller's tenant. The headline KPIs are operations-first: fleet
// size, what's DOWN right now, active security/critical threats, and site
// coverage. Add tiles by appending — the frontend renders whatever the array
// contains.
//
// Tenant isolation: a scoped principal's tiles reflect only its own devices and
// alerts — the dashboard must not leak the global fleet's counts (the platform
// owner, cross-tenant, still sees everything).
func (s *server) currentMetricTiles(claims jwtClaims) []MetricTile {
	devs := visibleDevices(s.discovery.Devices(), claims)
	devices := len(devs)
	ids, cross := s.visibleDeviceIDs(claims)

	// Devices down. Platform owner: unreachable targets summed across protocol
	// collectors (collector stats are fleet-wide, not tenant-attributable). A
	// scoped tenant instead proxies reachability with LastSeen staleness over its
	// OWN devices, so the count never reflects another tenant's fleet.
	down := 0
	if cross {
		if s.collectors != nil {
			for _, c := range s.collectors.Status() {
				if c.Kind != "" && c.Kind != "protocol" {
					continue
				}
				if d := c.Targets - c.Reachable; d > 0 {
					down += d
				}
			}
		}
	} else {
		now := time.Now()
		for _, d := range devs {
			if !d.LastSeen.IsZero() && now.Sub(d.LastSeen) > 5*time.Minute {
				down++
			}
		}
	}

	// Critical threats: active critical alerts the principal is allowed to see
	// (same visibility rule as GET /api/alerts; device-less alerts stay visible).
	threats := 0
	if s.alerts != nil {
		for _, a := range s.alerts.Active() {
			if !strings.EqualFold(strings.TrimSpace(a.Severity), "critical") {
				continue
			}
			if !cross && !(a.DeviceID == "" || ids[a.DeviceID]) {
				continue
			}
			threats++
		}
	}

	// Sites: distinct site/location labels across the VISIBLE fleet.
	siteSet := map[string]struct{}{}
	for _, d := range devs {
		site := d.Labels["site"]
		if site == "" {
			site = d.Labels["location"]
		}
		if site != "" {
			siteSet[site] = struct{}{}
		}
	}

	return []MetricTile{
		{Title: "Devices", Value: fmt.Sprintf("%d", devices), Trend: trendForCount(devices)},
		{Title: "Devices Down", Value: fmt.Sprintf("%d", down), Trend: trendForBad(down, "all up")},
		{Title: "Critical Threats", Value: fmt.Sprintf("%d", threats), Trend: trendForBad(threats, "clear")},
		{Title: "Sites", Value: fmt.Sprintf("%d", len(siteSet)), Trend: ""},
	}
}

func trendForCount(n int) string {
	if n == 0 {
		return ""
	}
	return "+"
}

// trendForBad returns an "all good" label at zero, else "critical" so the
// frontend tints the tile red (kpi-trend.t-crit).
func trendForBad(n int, okLabel string) string {
	if n == 0 {
		return okLabel
	}
	return "critical"
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

	rng := rand.New(rand.NewSource(time.Now().UnixNano())) // #nosec G404 -- non-cryptographic: seeds synthetic dashboard telemetry, not security tokens

	for {
		select {
		case <-stop:
			return

		case <-metricsTicker.C:
			// Push the full tile list so the client doesn't have to reconcile
			// partial updates. The receiver upserts by title. Tiles are computed
			// PER CLIENT from its own tenant scope so the dashboard never leaks
			// the global fleet's counts to a tenant-scoped user.
			s.hub.BroadcastFiltered(func(claims jwtClaims) []map[string]any {
				tiles := s.currentMetricTiles(claims)
				msgs := make([]map[string]any, 0, len(tiles))
				for _, t := range tiles {
					msgs = append(msgs, map[string]any{"type": "metric_update", "data": t})
				}
				return msgs
			})

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
			active := s.alerts.Active()
			// F-33: `seen` was keyed by alert fingerprint (rule|device|ifName|…)
			// and NOTHING ever deleted from it. Every distinct series that ever
			// fired stayed for the life of the process — on a fleet with churning
			// interface/device labels that grows without bound, inside the API
			// process, and the alert built to catch that growth was the one F-35
			// had disabled.
			//
			// Pruning to the currently-active set also fixes a behavioural bug
			// this loop's own comment promised and did not deliver ("each alert
			// is sent exactly once per FIRING"): an alert that resolved and later
			// re-fired kept its `seen` entry forever, so the re-fire was never
			// broadcast and the dashboard silently missed it.
			pruneSeenAlerts(seen, active)
			for _, a := range active {
				if seen[a.ID] {
					continue
				}
				seen[a.ID] = true
				alert := a // capture for the per-client closure
				// Fan out only to clients whose tenant may see this alert (same
				// rule as GET /api/alerts) so one tenant's alerts never surface
				// on another's dashboard.
				s.hub.BroadcastFiltered(func(claims jwtClaims) []map[string]any {
					if !s.alertVisibleTo(alert, claims) {
						return nil
					}
					return []map[string]any{{"type": "alert", "data": alert}}
				})
			}
		}
	}
}

// pruneSeenAlerts drops broadcast-dedup entries for alerts that are no longer
// active (F-33). Extracted so the retention rule is directly testable — the
// growth it prevents is invisible in any happy-path assertion.
func pruneSeenAlerts(seen map[string]bool, active []models.Alert) {
	if len(seen) == 0 {
		return
	}
	live := make(map[string]bool, len(active))
	for _, a := range active {
		live[a.ID] = true
	}
	for id := range seen {
		if !live[id] {
			delete(seen, id)
		}
	}
}
