// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package plan

import (
	"fmt"
	"time"

	"netops/backend/internal/nlquery/mql"
)

// tctx is what a template builds from: a selector factory that already carries
// the entity matchers, the rate window, and the whole query window.
type tctx struct {
	sel     func(physical string) (mql.Expr, error)
	rateWin time.Duration
	win     time.Duration
}

// template renders one catalog metric. series is the value at each step;
// windowed, when set, is the metric's own whole-window value (counts such as
// flaps), used instead of aggregating the series.
type template struct {
	series   func(c tctx) (mql.Expr, error)
	windowed func(c tctx) (mql.Expr, error)
	labels   []string // the physical labels a result series is keyed by
}

func raw(phys string) func(c tctx) (mql.Expr, error) {
	return func(c tctx) (mql.Expr, error) { return c.sel(phys) }
}

func rate(phys string, scale float64) func(c tctx) (mql.Expr, error) {
	return func(c tctx) (mql.Expr, error) {
		s, err := c.sel(phys)
		if err != nil {
			return mql.Expr{}, err
		}
		r, err := mql.Range("rate", s, c.rateWin)
		if err != nil || scale == 1 {
			return r, err
		}
		return mql.Bin(r, "*", mql.Scalar(scale))
	}
}

func sum2(a, b func(c tctx) (mql.Expr, error)) func(c tctx) (mql.Expr, error) {
	return func(c tctx) (mql.Expr, error) {
		x, err := a(c)
		if err != nil {
			return mql.Expr{}, err
		}
		y, err := b(c)
		if err != nil {
			return mql.Expr{}, err
		}
		return mql.Bin(x, "+", y)
	}
}

// util renders bits/s ÷ (speed Mbps × 1e6, speed > 0) × 100 — interfaces that
// report speed 0 drop out instead of rendering as 0 %.
func util(octets string) func(c tctx) (mql.Expr, error) {
	return func(c tctx) (mql.Expr, error) {
		bps, err := rate(octets, 8)(c)
		if err != nil {
			return mql.Expr{}, err
		}
		speed, err := c.sel("device_if_speed")
		if err != nil {
			return mql.Expr{}, err
		}
		bpsSpeed, err := mql.Bin(speed, "*", mql.Scalar(1e6))
		if err != nil {
			return mql.Expr{}, err
		}
		positive, err := mql.Cmp(bpsSpeed, ">", mql.Scalar(0))
		if err != nil {
			return mql.Expr{}, err
		}
		ratio, err := mql.Bin(bps, "/", positive)
		if err != nil {
			return mql.Expr{}, err
		}
		return mql.Bin(ratio, "*", mql.Scalar(100))
	}
}

func overWindow(fn, phys string) func(c tctx) (mql.Expr, error) {
	return func(c tctx) (mql.Expr, error) {
		s, err := c.sel(phys)
		if err != nil {
			return mql.Expr{}, err
		}
		return mql.Range(fn, s, c.win)
	}
}

func overStep(fn, phys string) func(c tctx) (mql.Expr, error) {
	return func(c tctx) (mql.Expr, error) {
		s, err := c.sel(phys)
		if err != nil {
			return mql.Expr{}, err
		}
		return mql.Range(fn, s, c.rateWin)
	}
}

var (
	ifLabels      = []string{"device", "ifName"}
	bgpLabels     = []string{"device", "peer"}
	deviceLabels  = []string{"device"}
	circuitLabels = []string{"circuit", "local_device"}
	probeLabels   = []string{"dst"}
)

// templates are keyed by catalog metric name. A test asserts this key set
// equals the catalog's metric set and that each template reads only its own
// declared physical metrics.
var templates = map[string]template{
	"if_in_bps":       {series: rate("device_if_in_octets", 8), labels: ifLabels},
	"if_out_bps":      {series: rate("device_if_out_octets", 8), labels: ifLabels},
	"if_total_bps":    {series: sum2(rate("device_if_in_octets", 8), rate("device_if_out_octets", 8)), labels: ifLabels},
	"if_util_in_pct":  {series: util("device_if_in_octets"), labels: ifLabels},
	"if_util_out_pct": {series: util("device_if_out_octets"), labels: ifLabels},
	"if_util_max_pct": {series: func(c tctx) (mql.Expr, error) {
		in, err := util("device_if_in_octets")(c)
		if err != nil {
			return mql.Expr{}, err
		}
		out, err := util("device_if_out_octets")(c)
		if err != nil {
			return mql.Expr{}, err
		}
		return mql.Greatest(in, out)
	}, labels: ifLabels},
	"if_oper_status":    {series: raw("device_if_oper_status"), labels: ifLabels},
	"if_flaps":          {series: overStep("changes", "device_if_oper_status"), windowed: overWindow("changes", "device_if_oper_status"), labels: ifLabels},
	"if_in_errors":      {series: rate("device_if_in_errors", 1), labels: ifLabels},
	"if_out_errors":     {series: rate("device_if_out_errors", 1), labels: ifLabels},
	"if_errors":         {series: sum2(rate("device_if_in_errors", 1), rate("device_if_out_errors", 1)), labels: ifLabels},
	"if_in_discards":    {series: rate("device_if_in_discards", 1), labels: ifLabels},
	"if_out_discards":   {series: rate("device_if_out_discards", 1), labels: ifLabels},
	"if_discards":       {series: sum2(rate("device_if_in_discards", 1), rate("device_if_out_discards", 1)), labels: ifLabels},
	"bgp_session_state": {series: raw("device_bgp_peer_state"), labels: bgpLabels},
	"bgp_flaps": {series: overStep("increase", "device_bgp_fsm_transitions"),
		windowed: overWindow("increase", "device_bgp_fsm_transitions"), labels: bgpLabels},
	"bgp_prefixes_received": {series: raw("device_bgp_pfx_in"), labels: bgpLabels},
	"cpu_util_pct": {series: func(c tctx) (mql.Expr, error) {
		s, err := c.sel("device_cpu_percent")
		if err != nil {
			return mql.Expr{}, err
		}
		return mql.Agg("avg", s, "device")
	}, labels: deviceLabels},
	"mem_util_pct":       {series: raw("device_mem_percent"), labels: deviceLabels},
	"circuit_loss_pct":   {series: raw("circuit_loss_pct"), labels: circuitLabels},
	"circuit_latency_ms": {series: raw("circuit_latency_ms"), labels: circuitLabels},
	"circuit_jitter_ms":  {series: raw("circuit_jitter_ms"), labels: circuitLabels},
	"circuit_qoe":        {series: raw("circuit_qoe"), labels: circuitLabels},
	"probe_rtt_ms":       {series: raw("probe_rtt_ms"), labels: probeLabels},
	"probe_loss_pct":     {series: raw("probe_loss_pct"), labels: probeLabels},
	"probe_pdv_ms":       {series: raw("probe_pdv_ms"), labels: probeLabels},
	"probe_owd_ms":       {series: raw("probe_owd_ms"), labels: probeLabels},
}

// aggregate turns a per-step series into one value over the whole window.
func aggregate(t template, c tctx, agg string, step time.Duration) (mql.Expr, error) {
	if t.windowed != nil && (agg == "sum" || agg == "count") {
		return t.windowed(c)
	}
	s, err := t.series(c)
	if err != nil {
		return mql.Expr{}, err
	}
	switch agg {
	case "avg":
		return mql.Subquery("avg_over_time", s, c.win, step)
	case "max":
		return mql.Subquery("max_over_time", s, c.win, step)
	case "min":
		return mql.Subquery("min_over_time", s, c.win, step)
	case "sum":
		return mql.Subquery("sum_over_time", s, c.win, step)
	case "last":
		return mql.Subquery("last_over_time", s, c.win, step)
	case "p95":
		return mql.QuantileSubquery(0.95, s, c.win, step)
	}
	return mql.Expr{}, fmt.Errorf("plan: aggregation %q has no template", agg)
}
