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
	"flow_logs":     {"cloud_flow_log", "cloud_flow_volume"},
	"lb_logs":       {"cloud_lb_log"},
	"metrics":       {"cloud_metric", "database_metric", "cloud_resource_anomaly"},
	"cloud_health":  {"cloud_health", "cloud_resource_health"},
	"change_audit":  {"cloud_change", "cloud_audit", "security_policy_change"},
	"firewall_logs": {"cloud_waf_log"}, // WAF BLOCK rollups (log-fidelity lane)
	"dns_logs":      {"cloud_dns_log"}, // resolver failure rollups
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
	// Capability distinguishes WHY a source can be "off" — the UI must never
	// paint "no producer exists yet" (planned) the same as "a producer exists
	// but nothing is configured/landing" (available). Conflating them made the
	// whole Ingestion matrix read as broken.
	Capability string `json:"capability"` // available | planned
	// Poller-reported error context (Wave 2 #4, additive): when Status is
	// permission_denied/misconfigured, Detail says what failed and SinceISO
	// when it started — "IAM denied flow logs since Tuesday", not "off".
	Detail   string `json:"detail,omitempty"`
	SinceISO string `json:"since_iso,omitempty"`
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

// kindStat is one (provider, kind) bucket's proof-of-life.
type kindStat struct {
	volume   int64
	lastSeen time.Time
}

// handleCloudIngestion serves GET /api/cloud/ingestion.
//
// PROVIDER-FACETED (audit Azure P0-7): the matrix used to group by kind alone,
// so AWS flow logs landing made "metrics" read flowing for a NOC looking at the
// Azure account. Every proof is now bucketed by the signal's own provider attr;
// the global `sources` list (any provider) is kept for the summary strip, and
// `providers` carries the per-provider matrices. A signal whose producer did
// not stamp a provider counts ONLY toward the global list — provider rows are
// never inflated by unattributed data.
func (s *server) handleCloudIngestion(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	now := time.Now().UTC()

	// Per (provider, kind) volume + last-seen over the stale horizon, tenant-
	// scoped by the caller's scope (the corr_signals row policy enforces it in
	// the DB too). Provider '' = the producer didn't stamp one.
	byProvKind := map[string]map[string]kindStat{} // provider → kind → stat
	globalKind := map[string]kindStat{}            // any provider
	sql := fmt.Sprintf(`
SELECT JSONExtractString(attrs,'provider') AS prov, kind,
       count() AS volume, `+chISO("max(ts)")+` AS last_seen
  FROM netops.corr_signals
 WHERE source = 'cloud' AND ts > now() - INTERVAL %d HOUR
 GROUP BY prov, kind
 SETTINGS tenant_scope = '%s'
 FORMAT TSV`, int(ingestStaleWindow/time.Hour), chTenantScope(r))
	for _, line := range chQuery(sql) {
		f := strings.Split(line, "\t")
		if len(f) < 4 {
			continue
		}
		prov := strings.ToLower(strings.TrimSpace(f[0]))
		kind := strings.TrimSpace(f[1])
		vol, err := strconv.ParseInt(strings.TrimSpace(f[2]), 10, 64)
		if err != nil {
			continue
		}
		ts := parseCHTime(strings.TrimSpace(f[3]))
		if ts.IsZero() {
			continue
		}
		g := globalKind[kind]
		g.volume += vol
		if ts.UTC().After(g.lastSeen) {
			g.lastSeen = ts.UTC()
		}
		globalKind[kind] = g
		if prov == "" {
			continue // unattributed: global only, never credited to a provider
		}
		if byProvKind[prov] == nil {
			byProvKind[prov] = map[string]kindStat{}
		}
		byProvKind[prov][kind] = kindStat{vol, ts.UTC()}
	}

	// The metric lane's canonical store is VictoriaMetrics, not ClickHouse
	// (audit D-P1-8): live series prove "metrics flowing" even when no anomaly
	// signal reached the bus. Per-provider last-sample + series count.
	vmLast := vmQueryBy(r.Context(),
		`max by (provider) (timestamp(last_over_time({__name__=~"cloud_.+"}[24h])))`, "provider")
	vmSeries := vmQueryBy(r.Context(),
		`count by (provider) (last_over_time({__name__=~"cloud_.+"}[24h]))`, "provider")

	// Inventory per provider (declared resources).
	invByProv := map[string]int64{}
	var invTotal int64
	if res, _, _, err := s.cloudResources(r); err == nil {
		invTotal = int64(len(res))
		for _, rs := range res {
			invByProv[strings.ToLower(string(rs.Provider))]++
		}
	}

	// Providers worth a matrix: anything the inventory declares or a signal /
	// metric series proves. (GCP appears here automatically once connected.)
	provSet := map[string]bool{}
	for p := range invByProv {
		if p != "" {
			provSet[p] = true
		}
	}
	for p := range byProvKind {
		provSet[p] = true
	}
	for p := range vmLast {
		provSet[strings.ToLower(p)] = true
	}

	buildRows := func(kinds map[string]kindStat, inv int64, provider string) []cloudSourceStatus {
		rows := make([]cloudSourceStatus, 0, len(cloudSourceOrder))
		for _, src := range cloudSourceOrder {
			st := cloudSourceStatus{SourceType: src, Status: "off", Capability: "available"}
			if _, hasProducer := cloudSourceKinds[src]; !hasProducer && src != "inventory" && src != "seam_data" {
				st.Capability = "planned" // no producer ships these kinds today
			}
			switch src {
			case "inventory":
				if inv > 0 {
					st.Status = "flowing"
					st.Volume = inv
				}
			case "seam_data":
				// Network seam data = the ACTIVE seam inventory the engine grounds
				// on (VPN / DX / SDWAN / DIA / CLOUD_BACKBONE) — not provider-
				// attributable; reported on the global row only.
				if provider == "" && s.seams != nil {
					claims, _ := userFrom(r.Context())
					tenant, cross := principalTenant(claims)
					if active, err := s.seams.List(r.Context(), tenant, cross, "active", ""); err == nil && len(active) > 0 {
						st.Status = "flowing"
						st.Volume = int64(len(active))
					}
				}
			default:
				for _, kind := range cloudSourceKinds[src] {
					k, ok := kinds[kind]
					if !ok {
						continue
					}
					st.Volume += k.volume
					if k.lastSeen.After(mustParseZero(st.LastSeenISO)) {
						st.LastSeenISO = k.lastSeen.Format(time.RFC3339)
					}
				}
				// Metrics: merge the metric store's own proof-of-life.
				if src == "metrics" {
					keys := []string{provider}
					if provider == "" { // global row: any provider's series count
						keys = keys[:0]
						for p := range vmLast {
							keys = append(keys, p)
						}
					}
					for _, p := range keys {
						if tsSec, ok := vmLast[p]; ok {
							t := time.Unix(int64(tsSec), 0).UTC()
							if t.After(mustParseZero(st.LastSeenISO)) {
								st.LastSeenISO = t.Format(time.RFC3339)
							}
							st.Volume += int64(vmSeries[p])
						}
					}
				}
				st.Status = ingestStatusFor(st.Volume, mustParseZero(st.LastSeenISO), now)
			}
			rows = append(rows, st)
		}
		return rows
	}

	// Poller-reported error states (Wave 2 #4): permission_denied/misconfigured
	// records, tenant-scoped to the CALLER. An active record also forces its
	// provider into the matrix — an account whose every read is IAM-denied must
	// show a red row, never vanish for lack of landed data.
	var errRecs []cloudSourceStatusRecord
	if s.cloudSourceStatus != nil {
		claims, _ := userFrom(r.Context())
		tenant, cross := principalTenant(claims)
		errRecs = s.cloudSourceStatus.ForTenant(tenant, cross, now)
		for _, rec := range errRecs {
			if rec.Provider != "" {
				provSet[rec.Provider] = true
			}
		}
	}

	providers := map[string][]cloudSourceStatus{}
	for p := range provSet {
		providers[p] = overlaySourceStatus(buildRows(byProvKind[p], invByProv[p], p), errRecs, p)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"sources":      overlaySourceStatus(buildRows(globalKind, invTotal, ""), errRecs, ""),
		"providers":    providers,
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
