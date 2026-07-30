package backend

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
	App string `json:"app"`
	// SrcApp is the SOURCE side's resolved app (#81 P3G): the same resolver run
	// over src_addr, so app→app conversations surface ("payroll → AWS S3").
	// "unknown" is first-class here too; "" only for legacy rows with no src col.
	SrcApp string  `json:"src_app,omitempty"`
	Tier   string  `json:"tier"`  // strongest verdict tier seen across this app's destinations
	Bytes  float64 `json:"bytes"` // sampling-corrected
	Flows  float64 `json:"flows"`
	Dests  int     `json:"dests"` // distinct destination IPs attributed to this app
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

// aggregateFlowApps resolves each row's destination (col d=dst_addr) AND source
// (col s=src_addr, when present) to an app via the global catalog, layering any
// extra signals from extraFor(addr) (operator overrides + the authoritative NGFW
// app-id + the cloud identity-map), and aggregates by the (dst app, src app)
// pair, strongest-dst-tier-wins, sorted by bytes desc. Rows without a src col
// (legacy shape) aggregate exactly as before (pair key with empty src). Pure
// (no IO; extraFor is an injected lookup) so it is unit-tested without
// ClickHouse. extraFor may be nil.
func aggregateFlowApps(rows []map[string]any, cat *appid.Catalog, extraFor func(addr string) []appid.Signal) []appFlowRow {
	type agg struct {
		app, srcApp  string
		bytes, flows float64
		dests        map[string]struct{} // distinct destination IPs (rows are src×dst pairs)
		tier         appid.Tier
	}
	resolve := func(addr string) appid.Verdict {
		var extra []appid.Signal
		if extraFor != nil {
			extra = extraFor(addr)
		}
		return cat.ResolveStr(addr, extra...)
	}
	byPair := map[string]*agg{}
	var order []string
	for _, row := range rows {
		dst, _ := row["d"].(string)
		src, _ := row["s"].(string)
		v := resolve(dst)
		srcApp := ""
		if src != "" {
			srcApp = resolve(src).App // second extraFor pass — the SAME resolver path
		}
		key := v.App + "\x00" + srcApp
		a := byPair[key]
		if a == nil {
			a = &agg{app: v.App, srcApp: srcApp, tier: v.Tier, dests: map[string]struct{}{}}
			byPair[key] = a
			order = append(order, key)
		}
		a.bytes += asFloat(row["b"])
		a.flows += asFloat(row["f"])
		a.dests[dst] = struct{}{}
		if tierRank(v.Tier) > tierRank(a.tier) {
			a.tier = v.Tier
		}
	}
	out := make([]appFlowRow, 0, len(byPair))
	for _, key := range order {
		a := byPair[key]
		out = append(out, appFlowRow{App: a.app, SrcApp: a.srcApp, Tier: string(a.tier), Bytes: a.bytes, Flows: a.flows, Dests: len(a.dests)})
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
		// src_addr rides along (#81 P3G) so the source side resolves too — the
		// top-N is now the top src×dst pairs by bytes (coverage reports honestly).
		sql := "SELECT dst_addr AS d, src_addr AS s, " +
			"sum(bytes*if(sampling_rate=0,1,sampling_rate)) AS b, count() AS f " +
			"FROM netops.flows WHERE ts >= now() - INTERVAL " + intToString(int(since.Seconds())) + " SECOND" + clause + " " +
			"GROUP BY dst_addr, src_addr ORDER BY b DESC LIMIT " + intToString(flowsAppsTopN) + " FORMAT JSON"
		var err error
		rows, err = s.chRows(r, sql)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
	}

	cat := s.appCatalog.Get()
	tenant, cross := principalTenant(claims)
	ov, ovErr := s.overridesFor(r.Context(), tenant, cross) // operator-defined internal apps (#81 P1c)
	if ovErr != nil {
		// Enrichment, not the answer: the top-N still renders, but a store that
		// did not answer is logged instead of passing as "no overrides".
		logWarn("appid", "operator override store did not answer — flow app names fall back to lower-precedence sources",
			map[string]any{"tenant": tenant, "err": ovErr.Error()})
	}
	// extraFor layers the non-catalog signals for EITHER side's address (dst and,
	// since #81 P3G, src): operator prefix overrides, the authoritative NGFW
	// app-id, and the cloud identity-map (a flow to/from a tagged cloud private
	// IP resolves to its app instead of "unknown", #81 P3F+1). The catalog itself
	// is applied inside ResolveStr — not here — so no signal is double-counted.
	extraFor := func(addr string) []appid.Signal {
		var extra []appid.Signal
		if ip, err := netip.ParseAddr(addr); err == nil {
			extra = append(extra, ov.Prefixes.SignalsFor(ip)...)
		}
		if sig, has := s.ngfw.signalFor(tenant, cross, addr); has {
			extra = append(extra, sig)
		}
		if sig, has := s.cloudApp.SignalFor(tenant, cross, addr); has {
			extra = append(extra, sig)
		}
		return extra
	}
	out := aggregateFlowApps(rows, cat, extraFor)

	writeJSON(w, http.StatusOK, map[string]any{
		"apps":  out,
		"count": len(out),
		// honest coverage: we resolved the top-N src×dst pairs by volume, not every flow.
		"coverage": map[string]any{
			"top_pairs":        flowsAppsTopN,
			"window_seconds":   int(since.Seconds()),
			"catalog_prefixes": cat.Size(),
		},
	})
}
