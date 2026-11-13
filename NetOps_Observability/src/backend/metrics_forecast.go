// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// Capacity forecast (#69 panel 10) — days-to-90% utilization per interface from a
// linear trend over VM range data. Honest: < 14 days of history ⇒ "building
// baseline" (no forecast), flat/declining ⇒ "stable" (not a fake countdown).
// Computed in Go over /api/v1/query_range; no new storage.
//
//   GET /api/metrics/forecast?class=wan_util&days=28
//
// Pure trend math (linFit / daysToThreshold) is unit-tested; the VM fetch wraps it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"netops/backend/internal/discovery"
	"netops/backend/internal/flownames"
	"netops/backend/internal/flowquery"
	"netops/backend/internal/metricval"
	"netops/backend/internal/nlquery/plan"
)

const forecastThreshold = 0.90 // 90% utilization line
const forecastMinDays = 14.0   // need ≥ this much history to forecast

// ---- tenant isolation (CLAUDE.md §3a) ---------------------------------------
//
// The forecast reads the SAME per-interface series the Metrics Explorer reads, so
// it gets the SAME boundary: VictoriaMetrics `extra_filters[]` injected
// server-side (see the long note in metrics_query.go — we never parse the PromQL),
// built by the one derivation every metrics lane uses, metricsScopeFiltersFor.
// A scoped principal with no visible device gets the match-nothing selector
// (fail closed), never an unfiltered query, and so does an operator who scoped
// into a tenant that switched the operator-visibility restriction on.
//
// Because this handler — unlike proxyMetrics — assembles the response rows itself
// in Go, it ALSO drops any series whose device labels are outside the principal's
// visible set before emitting a row. That second pass is defense in depth: the
// upstream filter is the enforcement point, the row filter guarantees that a
// series which somehow came back anyway (upstream misconfiguration, a relabeled
// series) still cannot reach a caller who may not see that device.
type forecastScope struct {
	filters []string        // VM extra_filters[] to send upstream
	scoped  bool            // scoped principal → allowlist below applies
	ids     map[string]bool // visible device ids   (`device` label)
	names   map[string]bool // visible device names (`hostname` / `source` labels)
	denied  map[string]bool // identifiers to EXCLUDE from a cross-tenant view
	denyAll bool            // operator scoped into a restricted tenant → no data
}

// forecastScopeOf resolves the caller's metric boundary. Mirrors the switch in
// proxyMetrics exactly (restricted-deny → scoped-tenant → operator exclusion).
func (s *server) forecastScopeOf(c jwtClaims) forecastScope {
	ids, names, cross := s.visibleDeviceMetricLabels(c)
	rt := s.restrictedTelemetry(c)
	// The wire filters come from the ONE derivation; what follows only decides
	// which in-Go row filter goes with them.
	sc := forecastScope{filters: s.metricsScopeFiltersFor(c)}
	switch {
	case rt.deny:
		// Operator scoped into an operator-restricted tenant → match nothing.
		sc.denyAll = true
	case !cross:
		// Scoped tenant → only its own devices' series.
		sc.scoped = true
		sc.ids, sc.names = forecastLabelSet(ids), forecastLabelSet(names)
	case len(rt.ids) > 0 || len(rt.names) > 0:
		// Operator Global view → exclude restricted tenants' devices.
		sc.denied = forecastLabelSet(append(append([]string{}, rt.ids...), rt.names...))
	}
	return sc
}

// forecastLabelSet indexes non-empty label values for O(1) membership checks.
func forecastLabelSet(vals []string) map[string]bool {
	set := make(map[string]bool, len(vals))
	for _, v := range vals {
		if v != "" {
			set[v] = true
		}
	}
	return set
}

// permits reports whether a series' labels identify a device the principal may
// see. Default-closed for a scoped principal: a series carrying NONE of the
// device-identifying labels (stack/self-observability series) is not its data.
func (sc forecastScope) permits(lbl map[string]string) bool {
	if sc.denyAll {
		return false
	}
	if sc.scoped {
		// A cloud-lane series (it carries a resource_id) is owned by the cloud
		// inventory, never by a device id or name it happens to share (392).
		if lbl["resource_id"] != "" {
			return false
		}
		return sc.ids[lbl["device"]] || sc.names[lbl["hostname"]] || sc.names[lbl["source"]]
	}
	for _, k := range []string{"device", "hostname", "source"} {
		if v := lbl[k]; v != "" && sc.denied[v] {
			return false
		}
	}
	return true
}

// linFit returns the least-squares slope (per x-unit) over points [(x,y)…] and the
// last y. ok=false when there are < 2 points or x has no spread.
func linFit(pts [][2]float64) (slope, last float64, ok bool) {
	n := float64(len(pts))
	if n < 2 {
		return 0, 0, false
	}
	var sx, sy, sxx, sxy float64
	for _, p := range pts {
		sx += p[0]
		sy += p[1]
		sxx += p[0] * p[0]
		sxy += p[0] * p[1]
	}
	denom := n*sxx - sx*sx
	if denom == 0 {
		return 0, pts[len(pts)-1][1], false
	}
	slope = (n*sxy - sx*sy) / denom
	return slope, pts[len(pts)-1][1], true
}

// daysToThreshold: how long until `current` reaches `threshold` at slopePerDay.
// -1 = not trending up (flat/declining); 0 = already at/over threshold.
func daysToThreshold(threshold, current, slopePerDay float64) float64 {
	if current >= threshold {
		return 0
	}
	if slopePerDay <= 0 {
		return -1
	}
	return (threshold - current) / slopePerDay
}

type forecastRow struct {
	Device      string  `json:"device"`
	Interface   string  `json:"interface"`
	CurrentUtil float64 `json:"current_util_pct"`
	SlopePerDay float64 `json:"slope_per_day_pct"`
	DaysTo90    float64 `json:"days_to_90"` // -1 = stable, 0 = already saturated
	Status      string  `json:"status"`     // saturated | trending | stable | building_baseline
	HistoryDays float64 `json:"history_days"`
}

// vmRange runs an instant range query and returns per-series points + labels,
// keyed by device\x1finterface (the IF-MIB identity). filters are the caller's
// tenant-scope `extra_filters[]` values — VictoriaMetrics AND-injects each into
// every series selector server-side, so the upstream never evaluates an unscoped
// query for a scoped principal.
func (s *server) vmRange(ctx context.Context, query string, start, end, step int64, filters []string) (map[string][][2]float64, map[string]map[string]string, error) {
	base := s.metricsBase()
	q := url.Values{}
	q.Set("query", query)
	q.Set("start", strconv.FormatInt(start, 10))
	q.Set("end", strconv.FormatInt(end, 10))
	q.Set("step", strconv.FormatInt(step, 10))
	for _, f := range filters {
		q.Add("extra_filters[]", f)
	}
	endpoint := strings.TrimRight(base, "/") + "/api/v1/query_range?" + q.Encode()
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := backendHTTPClient(25 * time.Second).Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	var out struct {
		Data struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Values [][2]any          `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&out); err != nil {
		return nil, nil, err
	}
	pts := map[string][][2]float64{}
	labels := map[string]map[string]string{}
	for _, r := range out.Data.Result {
		key := r.Metric["device"] + "\x1f" + r.Metric["index"]
		labels[key] = r.Metric
		for _, v := range r.Values {
			ts, _ := v[0].(float64)
			str, isStr := v[1].(string)
			if !isStr {
				continue
			}
			// F-21: a NaN point is MISSING, not zero. Feeding 0 into the trend
			// fit would drag the forecast toward zero and invent a "capacity
			// improving" signal out of a gap in the data; carrying the NaN
			// through would break the JSON encode for the whole response.
			val, ok := metricval.Parse(str)
			if !ok {
				continue
			}
			pts[key] = append(pts[key], [2]float64{ts, val})
		}
	}
	return pts, labels, nil
}

func (s *server) handleMetricsForecast(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	// Tenant isolation (§3a): resolve the caller's device boundary BEFORE any read.
	scope := s.forecastScopeOf(claims)
	if len(scope.filters) > 0 && !metricsUpstreamIsVictoria(s.metricsBase()) {
		// Fail closed: only VictoriaMetrics honours extra_filters[], so a Prometheus
		// upstream cannot enforce the boundary — refuse rather than serve unscoped.
		writeError(w, http.StatusNotImplemented,
			errors.New("metrics scoping requires a VictoriaMetrics backend"))
		return
	}
	daysN, errDays := intQuery(r, "days", 28, 7, 90)
	if errDays != nil {
		writeError(w, http.StatusBadRequest, errDays)
		return
	}
	days := float64(daysN)
	end := time.Now().Unix()
	start := end - int64(days*86400)
	step := int64(6 * 3600) // 6h
	ctx := r.Context()
	// Utilization fraction per interface, trended on the worse of the two
	// directions. in/out series share identical labels, so a single `or` query
	// would return in-only (set-union, left-precedence) — NOT the max; we fetch
	// both and take a pointwise max in Go.
	inUtil := `rate(device_if_in_octets[1h])*8 / ((device_if_speed > 0)*1000000)`
	outUtil := `rate(device_if_out_octets[1h])*8 / ((device_if_speed > 0)*1000000)`
	inS, inLabels, err := s.vmRange(ctx, inUtil, start, end, step, scope.filters)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	outS, outLabels, _ := s.vmRange(ctx, outUtil, start, end, step, scope.filters) // best-effort second direction

	labels := map[string]map[string]string{}
	byTs := map[string]map[float64]float64{}
	mergeMax := func(src map[string][][2]float64, lbls map[string]map[string]string) {
		for key, pts := range src {
			if labels[key] == nil {
				labels[key] = lbls[key]
			}
			m := byTs[key]
			if m == nil {
				m = map[float64]float64{}
				byTs[key] = m
			}
			for _, p := range pts {
				if v, seen := m[p[0]]; !seen || p[1] > v {
					m[p[0]] = p[1]
				}
			}
		}
	}
	mergeMax(inS, inLabels)
	mergeMax(outS, outLabels)

	series := map[string][][2]float64{}
	for key, m := range byTs {
		pts := make([][2]float64, 0, len(m))
		for ts, v := range m {
			pts = append(pts, [2]float64{ts, v})
		}
		sort.Slice(pts, func(i, j int) bool { return pts[i][0] < pts[j][0] })
		series[key] = pts
	}
	rows := make([]forecastRow, 0, len(series))
	for key, pts := range series {
		if len(pts) < 2 {
			continue
		}
		t0 := pts[0][0]
		xy := make([][2]float64, 0, len(pts))
		for _, p := range pts {
			xy = append(xy, [2]float64{(p[0] - t0) / 86400.0, p[1]}) // x in days
		}
		historyDays := (pts[len(pts)-1][0] - t0) / 86400.0
		slopePerDay, last, ok := linFit(xy)
		// Guard implausible utilization: a fraction far outside 0..1 means the
		// interface's ifSpeed metadata is wrong/zero (we'd otherwise surface a raw
		// bps number like 1073807616%). Drop it rather than show garbage.
		if last < 0 || last > 2.0 {
			continue
		}
		lbl := labels[key]
		// Second isolation pass (§3a): never emit a row for a device the caller
		// cannot see, whatever the upstream returned.
		if !scope.permits(lbl) {
			continue
		}
		iface := lbl["ifName"]
		if iface == "" {
			iface = lbl["index"]
		}
		row := forecastRow{
			Device: lbl["device"], Interface: iface,
			CurrentUtil: round1(last * 100), SlopePerDay: round2(slopePerDay * 100),
			HistoryDays: round1(historyDays),
		}
		switch {
		case historyDays < forecastMinDays || !ok:
			row.Status = "building_baseline"
			row.DaysTo90 = -1
		default:
			d := daysToThreshold(forecastThreshold, last, slopePerDay)
			row.DaysTo90 = round1(d)
			switch {
			case d == 0:
				row.Status = "saturated"
			case d < 0 || d > 365:
				// flat/declining OR a trickle so slow it's beyond a year — not a
				// meaningful countdown ("not expected"), don't show a huge day count.
				row.Status = "stable"
				row.DaysTo90 = -1
			default:
				row.Status = "trending"
			}
		}
		rows = append(rows, row)
	}
	// worst-first: saturated, then soonest-to-90, then stable/building last
	sort.SliceStable(rows, func(i, j int) bool {
		return forecastRank(rows[i]) < forecastRank(rows[j])
	})
	writeJSON(w, http.StatusOK, map[string]any{"class": "wan_util", "interfaces": rows, "count": len(rows), "min_days": forecastMinDays})
}

// forecastRank orders rows worst-first: saturated (0) < trending-soonest < stable < building.
func forecastRank(r forecastRow) float64 {
	switch r.Status {
	case "saturated":
		return -1
	case "trending":
		return r.DaysTo90 // soonest first
	case "stable":
		return 1e6
	default: // building_baseline
		return 1e7
	}
}

// vmRangeSeries is the GENERIC scoped range read for the Iris NL query path
// (tracker 337 N-C4): unlike vmRange it keys series by their FULL label set
// (BGP-peer and circuit series carry no `index`, and vmRange would merge them),
// and unlike vmQueryRangeByIf it keeps series that are not interfaces. The body
// read is bounded, NaN/Inf become 0 (they cannot be JSON-encoded), and at most
// maxSeries series are returned, with truncation reported rather than hidden.
// filters are the caller's tenant-scope extra_filters[] — never nil on a
// principal's path (the structural guard enforces it).
func (s *server) vmRangeSeries(ctx context.Context, query string, start, end time.Time, step time.Duration, filters []string, maxSeries int) ([]plan.Series, bool, error) {
	q := url.Values{}
	q.Set("query", query)
	q.Set("start", strconv.FormatInt(start.Unix(), 10))
	q.Set("end", strconv.FormatInt(end.Unix(), 10))
	q.Set("step", strconv.FormatInt(int64(step/time.Second), 10))
	for _, f := range filters {
		q.Add("extra_filters[]", f)
	}
	endpoint := strings.TrimRight(s.metricsBase(), "/") + "/api/v1/query_range?" + q.Encode()
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := backendHTTPClient(25 * time.Second).Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("victoriametrics status %d", resp.StatusCode)
	}
	var out struct {
		Data struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Values [][2]any          `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&out); err != nil {
		return nil, false, err
	}
	truncated := false
	series := make([]plan.Series, 0, len(out.Data.Result))
	for _, r := range out.Data.Result {
		if len(series) == maxSeries {
			truncated = true
			break
		}
		pts := make([]plan.Point, 0, len(r.Values))
		for _, v := range r.Values {
			ts, _ := v[0].(float64)
			str, _ := v[1].(string)
			pts = append(pts, plan.Point{T: int64(ts), V: metricval.FiniteOrZero(str)})
		}
		series = append(series, plan.Series{Labels: r.Metric, Points: pts})
	}
	return series, truncated, nil
}

// ── GET /api/flows/capacity (tracker 400 (d), Flows page Capacity tab) ───────
//
// Per-link 95th percentile, peak, headroom and days-to-90 % over the chosen
// window, from the INTERFACE COUNTERS (internal/flowquery/capacity.go says why
// not flows). Gate: explore, like every flow read (owner decision 2026-11-13
// (b)). Isolation is the forecast lane's, unchanged: the caller's boundary rides
// on every VictoriaMetrics read as extra_filters[] (forecastScopeOf →
// metricsScopeFiltersFor), and a second pass drops any series whose device the
// caller cannot see before a row is built. A Prometheus upstream cannot honour
// the filters, so a scoped read there is refused (501), as for the forecast.

// capacitySamples runs one instant query at the caller's boundary and indexes
// the permitted series by interface.
func (s *server) capacitySamples(ctx context.Context, query string, scope forecastScope) (map[string]flowquery.IfKey, map[string]float64, error) {
	samples, err := s.vmInstantScoped(ctx, query, scope.filters)
	if err != nil {
		return nil, nil, err
	}
	keys := map[string]flowquery.IfKey{}
	vals := map[string]float64{}
	for _, sm := range samples {
		if !scope.permits(sm.Labels) {
			continue // second isolation pass (§3a)
		}
		k, ok := flowquery.KeyOf(sm.Labels)
		if !ok {
			continue
		}
		keys[k.String()], vals[k.String()] = k, sm.Value
	}
	return keys, vals, nil
}

func (s *server) handleFlowsCapacity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requireFlowsRead(w, r)
	if !ok {
		return
	}
	scope := s.forecastScopeOf(claims)
	if len(scope.filters) > 0 && !metricsUpstreamIsVictoria(s.metricsBase()) {
		writeError(w, http.StatusNotImplemented, errors.New("metrics scoping requires a VictoriaMetrics backend"))
		return
	}
	now := time.Now()
	win, err := flowquery.ParseWindow(r.URL.Query(), now, flowquery.DefaultLimits)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	limit, err := intQuery(r, "limit", 100, 1, 500)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	days, err := intQuery(r, "days", 28, flowquery.ForecastMinDays, 30)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	body := map[string]any{
		"window":     win.Echo(now, 0),
		"interfaces": []flowquery.CapacityRow{},
		"count":      0,
		"total":      0,
		"forecast": map[string]any{
			"days": days, "min_days": flowquery.ForecastMinDays, "min_r2": flowquery.ForecastMinR2, "threshold_pct": flowquery.ThresholdPct,
		},
	}
	if scope.denyAll {
		writeJSON(w, http.StatusOK, body)
		return
	}
	ctx := r.Context()
	span := int64(win.Span() / time.Second)
	var end int64 // 0 = now: a "last N" window is evaluated live
	if win.Explicit {
		end = win.To.Unix()
	}
	figs := map[string]*flowquery.IfFigures{}
	fig := func(k flowquery.IfKey) *flowquery.IfFigures {
		f := figs[k.String()]
		if f == nil {
			f = &flowquery.IfFigures{Key: k}
			figs[k.String()] = f
		}
		return f
	}
	type q struct {
		expr string
		put  func(f *flowquery.IfFigures, v float64)
	}
	queries := []q{
		{flowquery.P95BpsQuery("in", span, end), func(f *flowquery.IfFigures, v float64) { f.P95In = &v }},
		{flowquery.P95BpsQuery("out", span, end), func(f *flowquery.IfFigures, v float64) { f.P95Out = &v }},
		{flowquery.PeakBpsQuery("in", span, end), func(f *flowquery.IfFigures, v float64) { f.PeakIn = &v }},
		{flowquery.PeakBpsQuery("out", span, end), func(f *flowquery.IfFigures, v float64) { f.PeakOut = &v }},
	}
	for _, qq := range queries {
		keys, vals, err := s.capacitySamples(ctx, qq.expr, scope)
		if err != nil {
			logError("flows", "capacity query failed", map[string]any{"error": err.Error()})
			writeError(w, http.StatusBadGateway, errors.New("metrics backend unavailable"))
			return
		}
		for ks, k := range keys {
			qq.put(fig(k), vals[ks])
		}
	}
	// Speed only for interfaces that carried a rate: a speed alone is not a link
	// in this window.
	keys, vals, err := s.capacitySamples(ctx, flowquery.SpeedBpsQuery(end), scope)
	if err != nil {
		logError("flows", "capacity speed query failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadGateway, errors.New("metrics backend unavailable"))
		return
	}
	for ks := range keys {
		if f := figs[ks]; f != nil {
			v := vals[ks]
			f.Speed = &v
		}
	}

	type devInfo struct{ name, site, exporter string }
	tenant, cross := principalTenant(claims)
	assign := s.geoAssignments(tenant, cross)
	devs := map[string]devInfo{}
	for _, d := range s.visibleDevicesFor(claims) {
		di := devInfo{name: d.Name, site: sotSiteFor(d, assign), exporter: flownames.NormAddr(d.Address)}
		if di.name == "" {
			di.name = d.ID
		}
		if di.site == "" && s.deviceLocations != nil {
			if l, ok := s.deviceLocations.Lookup(discovery.DeviceIdentities(d)); ok {
				di.site = l.Site
			}
		}
		devs[d.ID] = di
	}
	rows := make([]flowquery.CapacityRow, 0, len(figs))
	for _, f := range figs {
		row := flowquery.BuildCapacityRow(*f)
		row.DeviceName = row.DeviceID
		if di, ok := devs[row.DeviceID]; ok {
			row.DeviceName, row.Site, row.Exporter = di.name, di.site, di.exporter
		}
		rows = append(rows, row)
	}
	flowquery.SortCapacity(rows)
	total := len(rows)
	if len(rows) > limit {
		rows = rows[:limit]
	}
	body["forecast"].(map[string]any)["unavailable"] = !s.attachCapacityForecasts(ctx, rows, days, now, scope)
	body["interfaces"], body["count"], body["total"] = rows, len(rows), total
	writeJSON(w, http.StatusOK, body)
}

// attachCapacityForecasts fits days-to-90 % for the displayed rows that report a
// plausible speed: each complete UTC day's p95, busier direction, read by one
// range query per direction bounded to those rows' devices (never fleet-wide).
// It reports false when the daily read failed; the rows then keep "not enough
// history" and the answer says the forecast was unavailable.
func (s *server) attachCapacityForecasts(ctx context.Context, rows []flowquery.CapacityRow, days int, now time.Time, scope forecastScope) bool {
	var ids []string
	for _, r := range rows {
		if r.SpeedBasis == flowquery.SpeedReported && r.IfIndex != "" {
			ids = append(ids, r.DeviceID)
		}
	}
	if len(ids) == 0 {
		return true
	}
	// Evaluation points at the END of each complete UTC day.
	lastEnd := now.UTC().Truncate(24 * time.Hour).Unix()
	firstEnd := lastEnd - int64(days-1)*86400
	daily := [2]map[string]map[int64]float64{}
	for i, dir := range [2]string{"in", "out"} {
		pts, labels, err := s.vmRange(ctx, flowquery.DailyP95Query(dir, ids), firstEnd, lastEnd, 86400, scope.filters)
		if err != nil {
			logWarn("flows", "capacity forecast read failed; rows keep no forecast", map[string]any{"error": err.Error(), "direction": dir})
			return false
		}
		daily[i] = map[string]map[int64]float64{}
		for key, series := range pts {
			if !scope.permits(labels[key]) {
				continue // second isolation pass (§3a)
			}
			m := map[int64]float64{}
			for _, p := range series {
				m[int64(p[0])] = p[1]
			}
			daily[i][key] = m
		}
	}
	for i := range rows {
		r := &rows[i]
		if r.SpeedBasis != flowquery.SpeedReported || r.IfIndex == "" || r.SpeedBps == nil {
			continue
		}
		key := r.DeviceID + "\x1f" + r.IfIndex
		r.Forecast = flowquery.FitForecast(flowquery.DailyUtil(daily[0][key], daily[1][key], *r.SpeedBps))
	}
	return true
}
