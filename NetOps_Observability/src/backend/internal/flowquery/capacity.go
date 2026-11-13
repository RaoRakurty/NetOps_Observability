// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package flowquery

import (
	"math"
	"sort"
	"strconv"
	"strings"
)

// Capacity is read from the INTERFACE COUNTERS (VictoriaMetrics device_if_*),
// not from flows: flow records are kept 7 days and a sampling exporter that
// reports no rate reads low, while the counters are exact and kept 30 days.
// device_if_speed is ifHighSpeed in Mbps (hence × 1 000 000), labelled
// device = inventory id, index = ifIndex, ifName.
//
// Every query here is written for the caller's tenant boundary to be added
// on the wire as extra_filters[] by the root handler; nothing here scopes.

const (
	// ThresholdPct is the line "reaches 90 %" counts towards.
	ThresholdPct = 90.0
	// ForecastMinDays is how many complete UTC days of daily p95 a forecast needs.
	ForecastMinDays = 14
	// ForecastMinR2 is the least goodness of fit a forecast is given at; below
	// it the trend is too unsteady to put a date on.
	ForecastMinR2 = 0.5
	// ForecastMaxDays: a crossing further out than this is "not rising".
	ForecastMaxDays = 365.0
	// ImplausibleRatio: a rate above twice the reported speed means the speed
	// itself is wrong (a bad ifHighSpeed), so no percentage is derived from it.
	ImplausibleRatio = 2.0
)

// Capacity forecast statuses.
const (
	ForecastSpeedUnknown = "speed_unknown"
	ForecastNotEnough    = "not_enough_history"
	ForecastAtOrOver     = "at_or_over_90"
	ForecastFlat         = "flat_or_falling"
	ForecastUnsteady     = "unsteady"
	ForecastRising       = "rising"
)

// Speed basis values.
const (
	SpeedReported    = "reported"
	SpeedUnknown     = "unknown"
	SpeedImplausible = "implausible"
)

// rateBps is one direction's throughput in bits per second.
func rateBps(dir, sel string) string {
	return "rate(device_if_" + dir + "_octets" + sel + "[5m]) * 8"
}

// windowToken renders a PromQL range of whole seconds (at least 5 minutes).
func windowToken(seconds int64) string {
	if seconds < 300 {
		seconds = 300
	}
	return strconv.FormatInt(seconds, 10) + "s"
}

// at renders the PromQL `@` modifier that evaluates a subquery at a past
// instant (unix seconds), or "" for "now".
func at(unix int64) string {
	if unix <= 0 {
		return ""
	}
	return " @ " + strconv.FormatInt(unix, 10)
}

// P95BpsQuery is the 95th percentile of the 5-minute rate over the window that
// ends at endUnix (0 = now), per interface and direction ("in" or "out"). It is
// the standard capacity figure: the busiest 5 % of five-minute samples are set
// aside, so one burst does not read as a full link.
func P95BpsQuery(dir string, windowSeconds, endUnix int64) string {
	return "quantile_over_time(0.95, (" + rateBps(dir, "") + ")[" + windowToken(windowSeconds) + ":5m]" + at(endUnix) + ")"
}

// PeakBpsQuery is the highest 5-minute rate over the window ending at endUnix.
func PeakBpsQuery(dir string, windowSeconds, endUnix int64) string {
	return "max_over_time((" + rateBps(dir, "") + ")[" + windowToken(windowSeconds) + ":5m]" + at(endUnix) + ")"
}

// SpeedBpsQuery is the reported speed in bits per second at endUnix (0 = now);
// absent when unknown.
func SpeedBpsQuery(endUnix int64) string {
	if endUnix <= 0 {
		return "(device_if_speed > 0) * 1000000"
	}
	return "(last_over_time(device_if_speed[1h]" + at(endUnix) + ") > 0) * 1000000"
}

// DailyP95Query is each UTC day's p95 for the given devices, evaluated at the
// END of each day by a range query with a one-day step aligned to midnight.
// ids are sanitised to [A-Za-z0-9._:-] and regex-escaped; an empty list yields "".
func DailyP95Query(dir string, ids []string) string {
	sel := DeviceSelector(ids)
	if sel == "" {
		return ""
	}
	return "quantile_over_time(0.95, (" + rateBps(dir, sel) + ")[1d:5m])"
}

// DeviceSelector matches any of the given device ids exactly, or "" for none.
func DeviceSelector(ids []string) string {
	seen := map[string]bool{}
	var alts []string
	for _, id := range ids {
		clean := strings.Map(func(r rune) rune {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == ':', r == '-':
				return r
			}
			return -1
		}, id)
		if clean == "" || seen[clean] {
			continue
		}
		seen[clean] = true
		alts = append(alts, strings.ReplaceAll(clean, ".", `\\.`))
	}
	if len(alts) == 0 {
		return ""
	}
	sort.Strings(alts)
	return `{device=~"` + strings.Join(alts, "|") + `"}`
}

// IfKey identifies one interface series: the device id and the ifIndex, or the
// ifName when the source (vManage) carries no index.
type IfKey struct{ Device, Index, IfName string }

// String is the stable map key.
func (k IfKey) String() string {
	if k.Index != "" {
		return k.Device + "|" + k.Index
	}
	return k.Device + "|name:" + k.IfName
}

// KeyOf builds the key from a series' labels; ok=false without a device or
// any interface identity.
func KeyOf(lbl map[string]string) (IfKey, bool) {
	k := IfKey{Device: lbl["device"], Index: lbl["index"], IfName: strings.TrimSpace(lbl["ifName"])}
	if k.Device == "" || (k.Index == "" && k.IfName == "") {
		return IfKey{}, false
	}
	return k, true
}

// IfFigures are the window figures for one interface.
type IfFigures struct {
	Key                            IfKey
	P95In, P95Out, PeakIn, PeakOut *float64
	Speed                          *float64
}

// Forecast is the days-to-90 % estimate for one interface.
type Forecast struct {
	Status         string   `json:"status"`
	DaysTo90       *float64 `json:"days_to_90"`
	SlopePctPerDay *float64 `json:"slope_pct_per_day"`
	// FittedPct is the trend line's value on the last day: "current" is read
	// off the fit, never off the last raw point, so one noisy day does not move
	// the date.
	FittedPct   *float64 `json:"fitted_pct"`
	R2          *float64 `json:"r2"`
	HistoryDays int      `json:"history_days"`
	MinDays     int      `json:"min_days"`
}

// FitForecast fits a least-squares line to daily p95 utilisation points
// (x = day number, y = percent of speed) and reads the 90 % crossing off it.
func FitForecast(points [][2]float64) Forecast {
	f := Forecast{HistoryDays: len(points), MinDays: ForecastMinDays}
	if len(points) < ForecastMinDays {
		f.Status = ForecastNotEnough
		return f
	}
	slope, intercept, r2 := leastSquares(points)
	last := points[len(points)-1][0]
	fitted := intercept + slope*last
	s, fp, rr := round2(slope), round1(fitted), round2(r2)
	f.SlopePctPerDay, f.FittedPct, f.R2 = &s, &fp, &rr
	switch {
	case fitted >= ThresholdPct:
		f.Status = ForecastAtOrOver
		z := 0.0
		f.DaysTo90 = &z
	case slope <= 0:
		f.Status = ForecastFlat
	case r2 < ForecastMinR2:
		f.Status = ForecastUnsteady
	default:
		d := (ThresholdPct - fitted) / slope
		if d > ForecastMaxDays {
			f.Status = ForecastFlat
			break
		}
		d = round1(d)
		f.Status, f.DaysTo90 = ForecastRising, &d
	}
	return f
}

// leastSquares returns slope, intercept and R². A constant series fits
// perfectly (R² = 1).
func leastSquares(pts [][2]float64) (slope, intercept, r2 float64) {
	n := float64(len(pts))
	var sx, sy, sxx, sxy float64
	for _, p := range pts {
		sx += p[0]
		sy += p[1]
		sxx += p[0] * p[0]
		sxy += p[0] * p[1]
	}
	den := n*sxx - sx*sx
	if den == 0 {
		return 0, sy / n, 1
	}
	slope = (n*sxy - sx*sy) / den
	intercept = (sy - slope*sx) / n
	mean := sy / n
	var ssTot, ssRes float64
	for _, p := range pts {
		ssTot += (p[1] - mean) * (p[1] - mean)
		e := p[1] - (intercept + slope*p[0])
		ssRes += e * e
	}
	if ssTot == 0 {
		return slope, intercept, 1
	}
	return slope, intercept, 1 - ssRes/ssTot
}

// CapacityRow is one interface in a /api/flows/capacity answer. Percentages,
// headroom and the forecast are null unless the interface reports a plausible
// speed; the throughput figures are always given.
type CapacityRow struct {
	DeviceID    string   `json:"device_id"`
	DeviceName  string   `json:"device_name"`
	Site        string   `json:"site,omitempty"`
	IfIndex     string   `json:"ifindex"`
	IfName      string   `json:"if_name"`
	Exporter    string   `json:"exporter,omitempty"`
	SpeedBps    *float64 `json:"speed_bps"`
	SpeedBasis  string   `json:"speed_basis"`
	P95InBps    *float64 `json:"p95_in_bps"`
	P95OutBps   *float64 `json:"p95_out_bps"`
	P95Bps      *float64 `json:"p95_bps"`
	PeakBps     *float64 `json:"peak_bps"`
	P95InPct    *float64 `json:"p95_in_pct"`
	P95OutPct   *float64 `json:"p95_out_pct"`
	P95Pct      *float64 `json:"p95_pct"`
	PeakPct     *float64 `json:"peak_pct"`
	HeadroomBps *float64 `json:"headroom_bps"`
	HeadroomPct *float64 `json:"headroom_pct"`
	Forecast    Forecast `json:"forecast"`
}

func maxPtr(a, b *float64) *float64 {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	case *a >= *b:
		return a
	}
	return b
}

func pctOf(v, speed *float64) *float64 {
	if v == nil || speed == nil || *speed <= 0 {
		return nil
	}
	p := round1(*v * 100 / *speed)
	return &p
}

// BuildCapacityRow derives one row from its window figures (no forecast yet).
func BuildCapacityRow(f IfFigures) CapacityRow {
	r := CapacityRow{
		DeviceID: f.Key.Device, IfIndex: f.Key.Index, IfName: f.Key.IfName,
		P95InBps: roundPtr(f.P95In), P95OutBps: roundPtr(f.P95Out),
		P95Bps: roundPtr(maxPtr(f.P95In, f.P95Out)), PeakBps: roundPtr(maxPtr(f.PeakIn, f.PeakOut)),
		SpeedBasis: SpeedUnknown,
		Forecast:   Forecast{Status: ForecastSpeedUnknown, MinDays: ForecastMinDays},
	}
	if f.Speed == nil || *f.Speed <= 0 {
		return r
	}
	sp := *f.Speed
	r.SpeedBps = &sp
	top := maxPtr(r.P95Bps, r.PeakBps)
	if top != nil && *top > ImplausibleRatio*sp {
		r.SpeedBasis = SpeedImplausible
		return r
	}
	r.SpeedBasis = SpeedReported
	r.P95InPct, r.P95OutPct = pctOf(f.P95In, &sp), pctOf(f.P95Out, &sp)
	r.P95Pct, r.PeakPct = pctOf(r.P95Bps, &sp), pctOf(r.PeakBps, &sp)
	if r.P95Bps != nil {
		h := math.Max(0, sp-*r.P95Bps)
		hp := round1(math.Max(0, 100-*r.P95Pct))
		h = math.Round(h)
		r.HeadroomBps, r.HeadroomPct = &h, &hp
	}
	r.Forecast = Forecast{Status: ForecastNotEnough, MinDays: ForecastMinDays}
	return r
}

func roundPtr(p *float64) *float64 {
	if p == nil {
		return nil
	}
	v := math.Round(*p)
	return &v
}

// DailyUtil turns per-day p95 rates of both directions into the busier
// direction's percent of speed, one point per day (x = day number since the
// first day). days are unix seconds at each day's END; a day either direction
// lacks still counts with the other direction alone.
func DailyUtil(in, out map[int64]float64, speed float64) [][2]float64 {
	if speed <= 0 {
		return nil
	}
	days := map[int64]float64{}
	for t, v := range in {
		days[t] = v
	}
	for t, v := range out {
		if cur, ok := days[t]; !ok || v > cur {
			days[t] = v
		}
	}
	ts := make([]int64, 0, len(days))
	for t := range days {
		ts = append(ts, t)
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
	pts := make([][2]float64, 0, len(ts))
	for _, t := range ts {
		pts = append(pts, [2]float64{float64(t-ts[0]) / 86400, days[t] * 100 / speed})
	}
	return pts
}

// SortCapacity orders rows busiest first: p95 percent, then p95 throughput for
// rows with no speed, then device and interface.
func SortCapacity(rows []CapacityRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		ap, bp := -1.0, -1.0
		if a.P95Pct != nil {
			ap = *a.P95Pct
		}
		if b.P95Pct != nil {
			bp = *b.P95Pct
		}
		if ap != bp {
			return ap > bp
		}
		ab, bb := 0.0, 0.0
		if a.P95Bps != nil {
			ab = *a.P95Bps
		}
		if b.P95Bps != nil {
			bb = *b.P95Bps
		}
		if ab != bb {
			return ab > bb
		}
		if a.DeviceID != b.DeviceID {
			return a.DeviceID < b.DeviceID
		}
		return a.IfIndex+a.IfName < b.IfIndex+b.IfName
	})
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }
