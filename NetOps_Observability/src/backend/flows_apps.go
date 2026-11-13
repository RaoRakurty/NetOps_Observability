// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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
	"context"
	"errors"
	"net/http"
	"net/netip"
	"sort"
	"time"

	"netops/backend/appid"
	"netops/backend/internal/chschema"
	"netops/backend/internal/flowquery"
	"netops/backend/internal/iana"
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
	// What the EXPORTER called this traffic (IPFIX / NetFlow v9 IE 95/96), beside
	// — never fused into — the address verdict above. Empty when the exporter
	// sent nothing. ExporterApp is set only for an application-kind id with a
	// real name; an id-only row carries ExporterAppID and no name.
	ExporterApp     string `json:"exporter_app,omitempty"`
	ExporterAppID   string `json:"exporter_app_id,omitempty"`
	ExporterAppKind string `json:"exporter_app_kind,omitempty"`
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
		xName, xID   string
		xKind        string
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
		xName, xID, xKind := exporterVerdict(row)
		key := v.App + "\x00" + srcApp + "\x00" + xID + "\x00" + xName
		a := byPair[key]
		if a == nil {
			a = &agg{app: v.App, srcApp: srcApp, xName: xName, xID: xID, xKind: xKind, tier: v.Tier, dests: map[string]struct{}{}}
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
		out = append(out, appFlowRow{App: a.app, SrcApp: a.srcApp, Tier: string(a.tier), Bytes: a.bytes, Flows: a.flows, Dests: len(a.dests),
			ExporterApp: a.xName, ExporterAppID: a.xID, ExporterAppKind: a.xKind})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	return out
}

// exporterVerdict reads the exporter's classification off a row (xi = IE 95 as
// stored by vector-router, xn = IE 96). A malformed id is ignored; a name is
// kept only for an application-kind id (a port/protocol id names a service
// class, not an application) or when no id was sent at all.
func exporterVerdict(row map[string]any) (name, id, kind string) {
	rawID, _ := row["xi"].(string)
	rawName, _ := row["xn"].(string)
	name = appid.ExporterAppName(rawName)
	if p, ok := appid.ParseExporterAppID(rawID); ok {
		id, kind = rawID, p.Kind
		if p.Kind != appid.ExporterKindApp {
			name = ""
		}
	} else if name != "" {
		kind = appid.ExporterKindApp
	}
	return name, id, kind
}

func (s *server) handleFlowsApps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requireFlowsRead(w, r)
	if !ok {
		return
	}
	// Tracker 400 (e): an exact window (since, or from+to) parsed fail-closed,
	// and the filter bar's keys — device and interface included — narrow the
	// list, so it can answer for one link. flowFilterClause also applies the
	// platform-traffic exclusion the page's toggle controls.
	now := time.Now()
	win, err := flowquery.ParseWindow(r.URL.Query(), now, flowquery.DefaultLimits)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := flowStrictParams(r); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	filter, err := flowFilterClause(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// Tenant isolation: the flows row policy shares untagged rows to every tenant
	// scope (hybrid model), so a scoped principal is narrowed to flows touching
	// its own device addresses; no devices → nothing (default-closed).
	clause, empty := s.flowTenantClauseFor(claims)
	var rows []map[string]any
	if !empty {
		// src_addr rides along (#81 P3G) so the source side resolves too — the
		// top-N is now the top src×dst pairs by bytes (coverage reports honestly).
		// exporter_app_* ride along so the exporter's own classification (IE
		// 95/96) is reported beside the address verdict; both are '' for an
		// exporter that sends none, which groups exactly as before.
		sql := "SELECT dst_addr AS d, src_addr AS s, exporter_app_id AS xi, exporter_app_name AS xn, " +
			"sum(bytes*if(sampling_rate=0,1,sampling_rate)) AS b, count() AS f " +
			"FROM netops.flows WHERE " + win.Predicate() + clause + flowTypeClause(r) + filter + " " +
			"GROUP BY dst_addr, src_addr, exporter_app_id, exporter_app_name ORDER BY b DESC LIMIT " + intToString(flowsAppsTopN) + " FORMAT JSON"
		rows, err = s.chRows(r, sql)
		if err != nil {
			logError("flows", "applications query failed", map[string]any{"error": err.Error()})
			writeError(w, http.StatusBadGateway, errors.New("query backend unavailable"))
			return
		}
	}

	cat := s.appCatalog.Get()
	out := aggregateFlowApps(rows, cat, s.flowAppSignals(r.Context(), claims))

	writeJSON(w, http.StatusOK, map[string]any{
		"apps":   out,
		"count":  len(out),
		"window": win.Echo(now, chschema.RetentionConfig().Flows),
		// honest coverage: we resolved the top-N src×dst pairs by volume, not every flow.
		"coverage": map[string]any{
			"top_pairs":        flowsAppsTopN,
			"window_seconds":   int(win.Span().Seconds()),
			"catalog_prefixes": cat.Size(),
		},
	})
}

// flowAppSignals layers the non-catalog signals for EITHER side's address (dst
// and, since #81 P3G, src): operator prefix overrides, the authoritative NGFW
// app-id, and the cloud identity-map (a flow to/from a tagged cloud private IP
// resolves to its app instead of "unknown", #81 P3F+1). The catalog itself is
// applied inside ResolveStr — not here — so no signal is double-counted. Every
// source is read at the caller's (tenant, cross) scope.
func (s *server) flowAppSignals(ctx context.Context, claims jwtClaims) func(addr string) []appid.Signal {
	tenant, cross := principalTenant(claims)
	ov, ovErr := s.overridesFor(ctx, tenant, cross) // operator-defined internal apps (#81 P1c)
	if ovErr != nil {
		// Enrichment, not the answer: the top-N still renders, but a store that
		// did not answer is logged instead of passing as "no overrides".
		logWarn("appid", "operator override store did not answer — flow app names fall back to lower-precedence sources",
			map[string]any{"tenant": tenant, "err": ovErr.Error()})
	}
	return func(addr string) []appid.Signal {
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
}

// appMoverBytes resolves a movers app-pair answer (d, s, xi, xn, cur_b, prev_b)
// to per-application bytes in each window, with the same resolver and the same
// aggregation /api/flows/apps uses — run once per window, then joined by the
// destination application's name.
func appMoverBytes(rows []map[string]any, cat *appid.Catalog, extraFor func(string) []appid.Signal) []flowquery.KeyBytes {
	cur := make([]map[string]any, 0, len(rows))
	prev := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		base := map[string]any{"d": r["d"], "s": r["s"], "xi": r["xi"], "xn": r["xn"]}
		c, p := map[string]any{"b": flowquery.Num(r["cur_b"])}, map[string]any{"b": flowquery.Num(r["prev_b"])}
		for k, v := range base {
			c[k], p[k] = v, v
		}
		cur, prev = append(cur, c), append(prev, p)
	}
	sum := map[string]*flowquery.KeyBytes{}
	var order []string
	add := func(rows []appFlowRow, isCur bool) {
		for _, a := range rows {
			kb := sum[a.App]
			if kb == nil {
				kb = &flowquery.KeyBytes{Key: a.App}
				sum[a.App] = kb
				order = append(order, a.App)
			}
			if isCur {
				kb.Cur += a.Bytes
			} else {
				kb.Prev += a.Bytes
			}
		}
	}
	add(aggregateFlowApps(cur, cat, extraFor), true)
	add(aggregateFlowApps(prev, cat, extraFor), false)
	out := make([]flowquery.KeyBytes, 0, len(order))
	for _, k := range order {
		out = append(out, *sum[k])
	}
	return out
}

// GET /api/flows/links/movers (tracker 400 (c)) — "what changed" on one link:
// the talkers, applications or service ports whose traffic moved most against
// the previous window of the same length. Same gate and STRICTER link clause as
// /api/flows/links; parameters parsed fail-closed.
func (s *server) handleFlowsLinkMovers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requireFlowsRead(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	link, err := flowquery.ParseLink(q)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	dir, err := flowquery.ParseDir(q.Get("dir"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	by, err := flowquery.ParseMoversBy(q.Get("by"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	limit, err := intQuery(r, "limit", 10, 1, 50)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	now := time.Now()
	win, err := flowquery.ParseWindow(q, now, flowquery.DefaultLimits)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := flowStrictParams(r); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	echo := win.Echo(now, chschema.RetentionConfig().Flows)
	prevKnown := !echo.PrevBeforeRetention
	body := map[string]any{
		"window": echo, "exporter": link.Exporter, "ifindex": link.IfIndex, "by": by, "dir": dir,
		"totals": map[string]any{"bytes": 0, "prev_bytes": nil}, "movers": []flowquery.Mover{},
		"basis": flowquery.NewResponseBasis(0, 0),
	}
	clause, empty := s.flowLinkTenantClauseFor(claims)
	if empty {
		writeJSON(w, http.StatusOK, body)
		return
	}
	scope := clause + flowLinkTenantNarrow(r, claims) + flowTypeClause(r) + flowTrafficClassClause(r)
	tot, err := s.chRows(r, flowquery.MoverTotalsSQL(link, dir, win, scope))
	if err != nil {
		logError("flows", "link movers totals query failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadGateway, errors.New("query backend unavailable"))
		return
	}
	rows, err := s.chRows(r, flowquery.MoversSQL(link, dir, win, by, scope, limit))
	if err != nil {
		logError("flows", "link movers query failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadGateway, errors.New("query backend unavailable"))
		return
	}
	var kb []flowquery.KeyBytes
	switch by {
	case flowquery.ByApp:
		kb = appMoverBytes(rows, s.appCatalog.Get(), s.flowAppSignals(r.Context(), claims))
		body["coverage"] = map[string]any{"top_pairs": flowquery.MoverAppPairs}
	default:
		kb = flowquery.ParseKeyBytes(rows)
	}
	movers := flowquery.BuildMovers(kb, prevKnown, limit)
	if by == flowquery.ByPort {
		names := iana.Default()
		for i := range movers {
			movers[i].Label, movers[i].LabelBasis = flowKeyLabel(names, flowLabelService, movers[i].Key)
		}
	}
	var curB, prevB, fl, rr float64
	if len(tot) > 0 {
		curB, prevB = flowquery.Num(tot[0]["cur_b"]), flowquery.Num(tot[0]["prev_b"])
		fl, rr = flowquery.Num(tot[0]["fl"]), flowquery.Num(tot[0]["fl_rr"])
	}
	totals := map[string]any{"bytes": curB, "prev_bytes": nil}
	if prevKnown {
		totals["prev_bytes"] = prevB
	}
	body["totals"], body["movers"], body["basis"] = totals, movers, flowquery.NewResponseBasis(fl, rr)
	writeJSON(w, http.StatusOK, body)
}
