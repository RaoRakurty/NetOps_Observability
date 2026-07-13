package main

// cloud_ingestion.go — GET /api/cloud/ingestion: the REAL per-source ingestion
// status behind App Observability's Sources / Ingestion-Status matrices.
//
// The UI used to hard-code every source except Inventory to "off" (a placeholder
// from when nothing else was ingested). That understates a live deployment and,
// worse, it is not a measurement — it can never become true. This handler answers
// the question honestly from the data itself: for each source we look at what has
// actually landed, and report flowing / stale / off with the volume and last-seen
// that justify the claim. A source with no producer stays "off" — we never invent
// coverage we do not have.
//
// Freshness: seen within FRESH → flowing; within STALE_MAX → stale; else off.

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	ingestFreshWindow = 15 * time.Minute
	ingestStaleWindow = 24 * time.Hour
)

// cloudSourceKinds maps a UI source type to the corr_signals kinds that prove it.
// Kinds come from the correlation contract (cloud_producers.CLOUD_KINDS); a source
// with no kind here has no producer today and is reported "off".
var cloudSourceKinds = map[string][]string{
	"flow_logs":    {"cloud_flow_log"},
	"lb_logs":      {"cloud_lb_log"},
	"metrics":      {"cloud_metric", "database_metric", "cloud_resource_anomaly"},
	"cloud_health": {"cloud_health", "cloud_resource_health"},
	"change_audit": {"cloud_change", "cloud_audit", "security_policy_change"},
}

// cloudSourceOrder is the display order the UI expects (readiness.SOURCE_TYPES).
var cloudSourceOrder = []string{
	"inventory", "flow_logs", "lb_logs", "metrics", "cloud_health",
	"change_audit", "traces", "dns_logs", "firewall_logs", "nat_logs", "seam_data",
}

type cloudSourceStatus struct {
	SourceType  string `json:"source_type"`
	Status      string `json:"status"` // flowing | stale | off
	Volume      int64  `json:"volume"`
	LastSeenISO string `json:"last_seen_iso,omitempty"`
}

// ingestStatusFor turns (volume, lastSeen) into the honest status.
func ingestStatusFor(volume int64, lastSeen time.Time, now time.Time) string {
	if volume == 0 || lastSeen.IsZero() {
		return "off"
	}
	age := now.Sub(lastSeen)
	switch {
	case age <= ingestFreshWindow:
		return "flowing"
	case age <= ingestStaleWindow:
		return "stale"
	default:
		return "off"
	}
}

// handleCloudIngestion serves GET /api/cloud/ingestion.
func (s *server) handleCloudIngestion(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	now := time.Now().UTC()

	// Per-kind volume + last-seen over the stale horizon, tenant-scoped by the
	// caller's scope (the corr_signals row policy enforces it in the DB too).
	byKind := map[string]struct {
		volume   int64
		lastSeen time.Time
	}{}
	sql := fmt.Sprintf(`
SELECT kind, count() AS volume, toString(max(ts)) AS last_seen
  FROM netops.corr_signals
 WHERE source = 'cloud' AND ts > now() - INTERVAL %d HOUR
 GROUP BY kind
 SETTINGS tenant_scope = '%s'
 FORMAT TSV`, int(ingestStaleWindow/time.Hour), chTenantScope(r))
	for _, line := range chQuery(sql) {
		f := strings.Split(line, "\t")
		if len(f) < 3 {
			continue
		}
		vol, err := strconv.ParseInt(strings.TrimSpace(f[1]), 10, 64)
		if err != nil {
			continue
		}
		ts, err := time.Parse("2006-01-02 15:04:05", strings.TrimSpace(f[2]))
		if err != nil {
			continue
		}
		byKind[strings.TrimSpace(f[0])] = struct {
			volume   int64
			lastSeen time.Time
		}{vol, ts.UTC()}
	}

	out := make([]cloudSourceStatus, 0, len(cloudSourceOrder))
	for _, src := range cloudSourceOrder {
		st := cloudSourceStatus{SourceType: src, Status: "off"}

		switch src {
		case "inventory":
			// Inventory is real whenever the store has resources for this caller.
			if res, _, _, err := s.cloudResources(r); err == nil && len(res) > 0 {
				st.Status = "flowing"
				st.Volume = int64(len(res))
			}
		case "seam_data":
			// Network seam data = the ACTIVE seam inventory the engine grounds on
			// (VPN / DX / SDWAN / DIA / CLOUD_BACKBONE). Suggested seams don't count.
			if s.seams != nil {
				claims, _ := userFrom(r.Context())
				tenant, cross := principalTenant(claims)
				if active, err := s.seams.List(r.Context(), tenant, cross, "active", ""); err == nil && len(active) > 0 {
					st.Status = "flowing"
					st.Volume = int64(len(active))
				}
			}
		default:
			// Everything else is proven by signals actually landing on the bus.
			for _, kind := range cloudSourceKinds[src] {
				k, ok := byKind[kind]
				if !ok {
					continue
				}
				st.Volume += k.volume
				if k.lastSeen.After(mustParseZero(st.LastSeenISO)) {
					st.LastSeenISO = k.lastSeen.Format(time.RFC3339)
				}
			}
			st.Status = ingestStatusFor(st.Volume, mustParseZero(st.LastSeenISO), now)
		}
		out = append(out, st)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"sources":      out,
		"generated_at": now.Format(time.RFC3339),
	})
}

// mustParseZero parses an RFC3339 stamp, returning the zero time for "" / garbage.
func mustParseZero(iso string) time.Time {
	if iso == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, iso)
	if err != nil {
		return time.Time{}
	}
	return t
}
