package main

// flows_apps.go — GET /api/flows/apps (#81 P1b). Flow traffic attributed per
// IDENTIFIED application (the app-centric flow view). QUERY-TIME, like
// flows_services.go: one ClickHouse scan for the top destinations by volume over
// the window. The flows row policy is HYBRID (untagged rows are shared to every
// tenant scope), so the app-layer addrTenantClauseFor IS the isolation for
// untagged telemetry — same contract as /api/flows and the dependency view.
// Each destination is resolved to an app by the in-memory catalog, then aggregated
// per app. No materialized view over netops.flows (the banned ingestion regressor).
//
// Coverage is the top-N destinations by bytes (reported honestly in the response);
// uncatalogued/internal destinations resolve to "unknown" — a first-class bucket,
// never a guessed label.

import (
	"errors"
	"net/http"
	"net/netip"
	"sort"
	"time"

	"netops/backend/appid"
)

const flowsAppsTopN = 1000

type appFlowRow struct {
	App   string  `json:"app"`
	Tier  string  `json:"tier"`  // strongest verdict tier seen across this app's destinations
	Bytes float64 `json:"bytes"` // sampling-corrected
	Flows float64 `json:"flows"`
	Dests int     `json:"dests"` // distinct destination IPs attributed to this app
}

func tierRank(t appid.Tier) int {
	switch t {
	case appid.Confirmed:
		return 2
	case appid.Suspected:
		return 1
	default:
		return 0
	}
}

// aggregateFlowApps resolves each destination row (cols d=dst_addr, b=bytes,
// f=flows) to an app via the global catalog, layering any extra signals from
// extraFor(dst) (operator overrides + the authoritative NGFW app-id), and
// aggregates by app, strongest-tier-wins, sorted by bytes desc. Pure (no IO;
// extraFor is an injected lookup) so it is unit-tested without ClickHouse.
// extraFor may be nil.
func aggregateFlowApps(rows []map[string]any, cat *appid.Catalog, extraFor func(dst string) []appid.Signal) []appFlowRow {
	type agg struct {
		bytes, flows float64
		dests        int
		tier         appid.Tier
	}
	byApp := map[string]*agg{}
	var order []string
	for _, row := range rows {
		dst, _ := row["d"].(string)
		var extra []appid.Signal
		if extraFor != nil {
			extra = extraFor(dst)
		}
		v := cat.ResolveStr(dst, extra...)
		a := byApp[v.App]
		if a == nil {
			a = &agg{tier: v.Tier}
			byApp[v.App] = a
			order = append(order, v.App)
		}
		a.bytes += asFloat(row["b"])
		a.flows += asFloat(row["f"])
		a.dests++
		if tierRank(v.Tier) > tierRank(a.tier) {
			a.tier = v.Tier
		}
	}
	out := make([]appFlowRow, 0, len(byApp))
	for _, app := range order {
		a := byApp[app]
		out = append(out, appFlowRow{App: app, Tier: string(a.tier), Bytes: a.bytes, Flows: a.flows, Dests: a.dests})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	return out
}

func (s *server) handleFlowsApps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	since := durationQuery(r, "since", time.Hour)
	// Tenant isolation: the flows row policy shares untagged rows to every tenant
	// scope (hybrid model), so a scoped principal is narrowed to flows touching
	// its own device addresses; no devices → nothing (default-closed).
	clause, empty := s.addrTenantClauseFor(claims, "src_addr", "dst_addr")
	var rows []map[string]any
	if !empty {
		sql := "SELECT dst_addr AS d, " +
			"sum(bytes*if(sampling_rate=0,1,sampling_rate)) AS b, count() AS f " +
			"FROM netops.flows WHERE ts >= now() - INTERVAL " + intToString(int(since.Seconds())) + " SECOND" + clause + " " +
			"GROUP BY dst_addr ORDER BY b DESC LIMIT " + intToString(flowsAppsTopN) + " FORMAT JSON"
		var err error
		rows, err = s.chRows(r, sql)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
	}

	cat := s.appCatalog.get()
	tenant, cross := principalTenant(claims)
	ov := s.overridesFor(r.Context(), tenant, cross) // operator-defined internal apps (#81 P1c)
	extraFor := func(dst string) []appid.Signal {
		var extra []appid.Signal
		if ip, err := netip.ParseAddr(dst); err == nil {
			extra = append(extra, ov.prefixes.SignalsFor(ip)...)
		}
		if sig, has := s.ngfw.signalFor(tenant, cross, dst); has {
			extra = append(extra, sig)
		}
		// cloud inventory identity-map: a flow to a tagged cloud private IP now
		// resolves to its app instead of "unknown" (#81 P3F+1).
		if sig, has := s.cloudApp.signalFor(tenant, cross, dst); has {
			extra = append(extra, sig)
		}
		return extra
	}
	out := aggregateFlowApps(rows, cat, extraFor)

	writeJSON(w, http.StatusOK, map[string]any{
		"apps":  out,
		"count": len(out),
		// honest coverage: we resolved the top-N destinations by volume, not every flow.
		"coverage": map[string]any{
			"top_destinations": flowsAppsTopN,
			"window_seconds":   int(since.Seconds()),
			"catalog_prefixes": cat.Size(),
		},
	})
}
