package main

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
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const forecastThreshold = 0.90 // 90% utilization line
const forecastMinDays = 14.0   // need ≥ this much history to forecast

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
// keyed by device\x1finterface (the IF-MIB identity).
func (s *server) vmRange(ctx context.Context, query string, start, end, step int64) (map[string][][2]float64, map[string]map[string]string, error) {
	base := envOr("VICTORIA_URL", envOr("METRICS_URL", "http://victoria:8428"))
	q := url.Values{}
	q.Set("query", query)
	q.Set("start", strconv.FormatInt(start, 10))
	q.Set("end", strconv.FormatInt(end, 10))
	q.Set("step", strconv.FormatInt(step, 10))
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
			val, ok := parseMetricFloat(str)
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
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
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
	inS, inLabels, err := s.vmRange(ctx, inUtil, start, end, step)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	outS, outLabels, _ := s.vmRange(ctx, outUtil, start, end, step) // best-effort second direction

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
