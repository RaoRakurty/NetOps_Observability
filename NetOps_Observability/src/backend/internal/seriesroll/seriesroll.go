// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package seriesroll is the hourly roll-up behind Iris's seasonal baselines
// (tracker 337 N-H6 PR 2): once per closed hour it reads, for every eligible
// metric, each series' p10 / p50 / p90 and sample count over that hour from
// VictoriaMetrics and writes one row per series into netops.series_hourly —
// so a seasonal profile can reach further back than VictoriaMetrics keeps raw
// samples, and an estate-wide "abnormal for this time of week" reads one
// table.
//
// Tenant: the worker has no caller, so every row is stamped with the series'
// DEVICE OWNER from the inventory (Owners). A series whose device has no owner
// — or that carries no device label — is skipped and counted; a row with
// an empty tenant_id is never written (the table's row policy is STRICT).
//
// Bounds (§9): one instant query per metric for the quantiles and one for the
// count, each under QueryTimeout; at most MaxSeries rows per hour across all
// metrics, kept in a deterministic order (metric order, then entity key), the
// rest dropped and counted. Re-rolling an hour writes it again under a higher
// version, so a re-run replaces instead of adding. Every skip and failure has
// a counter (Stats), and a failed write is returned, never swallowed.
package seriesroll

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// DefaultMaxSeries bounds one hour's rows across every metric.
const DefaultMaxSeries = 50000

// DefaultQueryTimeout bounds each VictoriaMetrics read.
const DefaultQueryTimeout = 30 * time.Second

// Sample is one instant-query value with its labels.
type Sample struct {
	Labels map[string]string
	Value  float64
}

// VM evaluates an instant query NOW against the platform's metric store; the
// worker reaches an earlier instant with an explicit `offset` in the query.
// It runs with no principal, so this read is fleet-wide by design; every row
// it produces is re-owned by its device's tenant before it is written.
type VM interface {
	Query(ctx context.Context, query string) ([]Sample, error)
}

// Row is one series' hour.
type Row struct {
	Tenant    string    `json:"tenant_id"`
	Metric    string    `json:"metric"`
	EntityKey string    `json:"entity_key"`
	Hour      time.Time `json:"hour"`
	P10       float64   `json:"p10"`
	P50       float64   `json:"p50"`
	P90       float64   `json:"p90"`
	N         uint32    `json:"n"`
	Version   uint64    `json:"version"`
}

// Store writes one hour's rows.
type Store interface {
	Insert(ctx context.Context, rows []Row) error
}

// Owners says which tenant owns a device (by the series' device label).
// ok=false or an empty tenant means "no owner": the series is skipped.
type Owners interface {
	Owner(device string) (tenant string, ok bool)
}

// Metric is one eligible series family: Name is the catalog metric, Expr the
// PromQL/MetricsQL series expression, Labels the labels that key one series
// (the device label first among them).
type Metric struct {
	Name   string
	Expr   string
	Labels []string
}

// Config bounds a Roller.
type Config struct {
	Metrics      []Metric
	MaxSeries    int
	QueryTimeout time.Duration
	// Now is the clock (tests inject one); nil = time.Now.
	Now func() time.Time
}

// Stats are the worker's counters, read by the api's metrics endpoint.
type Stats struct {
	Hours       atomic.Int64 // hours rolled and written
	Rows        atomic.Int64 // rows written
	Unowned     atomic.Int64 // series skipped: no device, or the device has no owner
	CapDropped  atomic.Int64 // series dropped past MaxSeries
	VMErrors    atomic.Int64 // metric reads that failed (that metric is skipped for the hour)
	StoreErrors atomic.Int64 // hour writes that failed
}

// Roller rolls hours.
type Roller struct {
	cfg    Config
	vm     VM
	store  Store
	owners Owners
	Stats  Stats
}

// New builds a Roller; it refuses a missing dependency or an empty metric set.
func New(cfg Config, vm VM, store Store, owners Owners) (*Roller, error) {
	if vm == nil || store == nil || owners == nil {
		return nil, errors.New("seriesroll: vm, store and owners are required")
	}
	if len(cfg.Metrics) == 0 {
		return nil, errors.New("seriesroll: no eligible metric")
	}
	if cfg.MaxSeries <= 0 {
		cfg.MaxSeries = DefaultMaxSeries
	}
	if cfg.QueryTimeout <= 0 {
		cfg.QueryTimeout = DefaultQueryTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Roller{cfg: cfg, vm: vm, store: store, owners: owners}, nil
}

// QuantileQuery is the one quantile read of a metric over the hour ending
// `back` before now (MetricsQL quantiles_over_time over a 1-minute subquery,
// so rate-shaped expressions roll correctly).
func QuantileQuery(expr string, back time.Duration) string {
	return `quantiles_over_time("phi", 0.1, 0.5, 0.9, (` + expr + `)[1h:1m]` + offset(back) + `)`
}

// CountQuery is the matching sample count.
func CountQuery(expr string, back time.Duration) string {
	return `count_over_time((` + expr + `)[1h:1m]` + offset(back) + `)`
}

// offset renders a whole-second subquery offset, or nothing for "now".
func offset(back time.Duration) string {
	secs := int64(back / time.Second)
	if secs <= 0 {
		return ""
	}
	return " offset " + strconv.FormatInt(secs, 10) + "s"
}

// Result says what one hour produced.
type Result struct {
	Hour       time.Time
	Rows       int
	Unowned    int
	CapDropped int
	Failed     []string // metrics whose read failed
}

// LastClosedHour is the most recent hour that has fully passed at now.
func LastClosedHour(now time.Time) time.Time {
	return now.UTC().Truncate(time.Hour).Add(-time.Hour)
}

// RollHour rolls the hour starting at hour (truncated to the hour, UTC) and
// writes it. A metric whose read fails is skipped and counted; the write's
// failure is returned.
func (r *Roller) RollHour(ctx context.Context, hour time.Time) (Result, error) {
	hour = hour.UTC().Truncate(time.Hour)
	now := r.cfg.Now()
	end := hour.Add(time.Hour)
	if end.After(now) {
		return Result{Hour: hour}, fmt.Errorf("seriesroll: hour %s has not closed yet", hour.Format(time.RFC3339))
	}
	back := now.Sub(end)
	res := Result{Hour: hour}
	version := uint64(now.UnixNano())
	var rows []Row
	for _, m := range r.cfg.Metrics {
		got, err := r.readMetric(ctx, m, back)
		if err != nil {
			r.Stats.VMErrors.Add(1)
			res.Failed = append(res.Failed, m.Name)
			continue
		}
		keys := make([]string, 0, len(got))
		for k := range got {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			s := got[k]
			if !s.complete() {
				continue
			}
			tenant, ok := r.owners.Owner(s.device)
			if s.device == "" || !ok || strings.TrimSpace(tenant) == "" {
				res.Unowned++
				continue
			}
			if len(rows) >= r.cfg.MaxSeries {
				res.CapDropped++
				continue
			}
			rows = append(rows, Row{
				Tenant: strings.ToLower(strings.TrimSpace(tenant)), Metric: m.Name, EntityKey: k, Hour: hour,
				P10: s.q[0], P50: s.q[1], P90: s.q[2], N: s.n, Version: version,
			})
		}
	}
	r.Stats.Unowned.Add(int64(res.Unowned))
	r.Stats.CapDropped.Add(int64(res.CapDropped))
	if len(rows) == 0 {
		return res, nil
	}
	if err := r.store.Insert(ctx, rows); err != nil {
		r.Stats.StoreErrors.Add(1)
		return res, fmt.Errorf("seriesroll: write hour %s (%d rows): %w", hour.Format(time.RFC3339), len(rows), err)
	}
	res.Rows = len(rows)
	r.Stats.Hours.Add(1)
	r.Stats.Rows.Add(int64(len(rows)))
	return res, nil
}

// series accumulates one series' three quantiles and count.
type series struct {
	device string
	q      [3]float64
	have   [3]bool
	n      uint32
}

func (s series) complete() bool { return s.have[0] && s.have[1] && s.have[2] }

func (r *Roller) readMetric(ctx context.Context, m Metric, back time.Duration) (map[string]series, error) {
	qctx, cancel := context.WithTimeout(ctx, r.cfg.QueryTimeout)
	defer cancel()
	qs, err := r.vm.Query(qctx, QuantileQuery(m.Expr, back))
	if err != nil {
		return nil, err
	}
	out := map[string]series{}
	for _, s := range qs {
		if math.IsNaN(s.Value) || math.IsInf(s.Value, 0) {
			continue
		}
		idx := phiIndex(s.Labels["phi"])
		if idx < 0 {
			continue
		}
		k := EntityKey(m.Labels, s.Labels)
		cur := out[k]
		cur.device = deviceOf(s.Labels)
		cur.q[idx], cur.have[idx] = s.Value, true
		out[k] = cur
	}
	cctx, ccancel := context.WithTimeout(ctx, r.cfg.QueryTimeout)
	defer ccancel()
	cs, err := r.vm.Query(cctx, CountQuery(m.Expr, back))
	if err != nil {
		return nil, err
	}
	for _, s := range cs {
		k := EntityKey(m.Labels, s.Labels)
		if cur, ok := out[k]; ok && s.Value >= 0 && s.Value <= math.MaxUint32 {
			cur.n = uint32(s.Value)
			out[k] = cur
		}
	}
	return out, nil
}

func phiIndex(phi string) int {
	f, err := strconv.ParseFloat(phi, 64)
	if err != nil {
		return -1
	}
	switch f {
	case 0.1:
		return 0
	case 0.5:
		return 1
	case 0.9:
		return 2
	}
	return -1
}

// EntityKey joins the series' key labels (the same order the metric declares).
func EntityKey(labels []string, raw map[string]string) string {
	parts := make([]string, len(labels))
	for i, l := range labels {
		parts[i] = raw[l]
	}
	return strings.Join(parts, "\x1f")
}

func deviceOf(l map[string]string) string {
	if d := l["device"]; d != "" {
		return d
	}
	return l["local_device"]
}

// Run rolls the last closed hour every interval until ctx ends. Each pass is
// idempotent (a re-roll replaces); a failed pass is reported to onErr and the
// loop goes on.
func (r *Roller) Run(ctx context.Context, interval time.Duration, onErr func(error)) {
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		if _, err := r.RollHour(ctx, LastClosedHour(r.cfg.Now())); err != nil && onErr != nil {
			onErr(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
