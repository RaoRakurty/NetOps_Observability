package main

// flows_apps.go — GET /api/flows/apps (#81 P1b). Flow traffic attributed per
// IDENTIFIED application (the app-centric flow view). QUERY-TIME, like
// flows_services.go: one ClickHouse scan for the top destinations by volume over
// the window (tenant-scoped via chRows → the CH row policy enforces isolation),
// each destination resolved to an app by the in-memory catalog, then aggregated
// per app. No materialized view over netops.flows (the banned ingestion regressor).
//
// Coverage is the top-N destinations by bytes (reported honestly in the response);
// uncatalogued/internal destinations resolve to "unknown" — a first-class bucket,
// never a guessed label.

import (
	"errors"
	"net/http"
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
// f=flows) to an app via the catalog and aggregates by app, strongest-tier-wins,
// sorted by bytes desc. Pure (no IO) so it is unit-tested without ClickHouse.
func aggregateFlowApps(rows []map[string]any, cat *appid.Catalog) []appFlowRow {
	type agg struct {
		bytes, flows float64
		dests        int
		tier         appid.Tier
	}
	byApp := map[string]*agg{}
	var order []string
	for _, row := range rows {
		dst, _ := row["d"].(string)
		v := cat.ResolveStr(dst)
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
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	since := durationQuery(r, "since", time.Hour)
	sql := "SELECT dst_addr AS d, " +
		"sum(bytes*if(sampling_rate=0,1,sampling_rate)) AS b, count() AS f " +
		"FROM netops.flows WHERE ts >= now() - INTERVAL " + intToString(int(since.Seconds())) + " SECOND " +
		"GROUP BY dst_addr ORDER BY b DESC LIMIT " + intToString(flowsAppsTopN) + " FORMAT JSON"
	rows, err := s.chRows(r, sql)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}

	cat := s.appCatalog.get()
	out := aggregateFlowApps(rows, cat)

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
