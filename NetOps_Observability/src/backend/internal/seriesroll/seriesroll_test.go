// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package seriesroll

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

var clock = time.Date(2026, 11, 23, 9, 17, 0, 0, time.UTC)

type fakeVM struct {
	mu      sync.Mutex
	queries []string
	// devices served for every metric: device → p10/p50/p90/n
	devices map[string][4]float64
	fail    string // a query containing this substring errors
	block   bool   // block until the context ends
}

func (f *fakeVM) Query(ctx context.Context, q string) ([]Sample, error) {
	f.mu.Lock()
	f.queries = append(f.queries, q)
	f.mu.Unlock()
	if f.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if f.fail != "" && strings.Contains(q, f.fail) {
		return nil, errors.New("vm down")
	}
	var out []Sample
	for d, v := range f.devices {
		if strings.HasPrefix(q, "quantiles_over_time") {
			for i, phi := range []string{"0.1", "0.5", "0.9"} {
				out = append(out, Sample{Labels: map[string]string{"device": d, "phi": phi}, Value: v[i]})
			}
		} else {
			out = append(out, Sample{Labels: map[string]string{"device": d}, Value: v[3]})
		}
	}
	return out, nil
}

type fakeStore struct {
	rows [][]Row
	err  error
}

func (s *fakeStore) Insert(_ context.Context, rows []Row) error {
	if s.err != nil {
		return s.err
	}
	s.rows = append(s.rows, rows)
	return nil
}

type owners map[string]string

func (o owners) Owner(d string) (string, bool) { t, ok := o[d]; return t, ok }

var cpu = Metric{Name: "cpu_util_pct", Expr: "device_cpu_percent", Labels: []string{"device"}}

func newRoller(t *testing.T, vm VM, st Store, ow Owners, max int, metrics ...Metric) *Roller {
	t.Helper()
	if len(metrics) == 0 {
		metrics = []Metric{cpu}
	}
	r, err := New(Config{Metrics: metrics, MaxSeries: max, Now: func() time.Time { return clock }, QueryTimeout: time.Second}, vm, st, ow)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRollHourStampsTheDeviceOwnerAndSkipsTheUnowned(t *testing.T) {
	vm := &fakeVM{devices: map[string][4]float64{
		"dev-a":    {10, 20, 30, 60},
		"dev-b":    {1, 2, 3, 60},
		"orphan":   {5, 5, 5, 60}, // no inventory owner
		"blanker":  {5, 5, 5, 60}, // owner recorded as "" — still unowned
		"capsowns": {7, 8, 9, 60},
	}}
	st := &fakeStore{}
	r := newRoller(t, vm, st, owners{"dev-a": "T-A", "dev-b": "t-b", "blanker": " ", "capsowns": "t-a"}, 0)
	res, err := r.RollHour(context.Background(), LastClosedHour(clock))
	if err != nil {
		t.Fatal(err)
	}
	if res.Rows != 3 || res.Unowned != 2 || r.Stats.Unowned.Load() != 2 {
		t.Fatalf("result %+v unowned stat %d", res, r.Stats.Unowned.Load())
	}
	byKey := map[string]Row{}
	for _, row := range st.rows[0] {
		if row.Tenant == "" {
			t.Fatalf("an untagged row was written: %+v", row)
		}
		byKey[row.EntityKey] = row
	}
	a := byKey["dev-a"]
	if a.Tenant != "t-a" || a.P10 != 10 || a.P50 != 20 || a.P90 != 30 || a.N != 60 {
		t.Fatalf("dev-a row = %+v (tenant normalised, quantiles and count kept)", a)
	}
	if !a.Hour.Equal(time.Date(2026, 11, 23, 8, 0, 0, 0, time.UTC)) {
		t.Fatalf("hour = %s, want the last closed hour 08:00", a.Hour)
	}
	// The read ends at the END of the hour (09:00; now is 09:17 → offset
	// 1020 s), one quantile + one count query.
	if len(vm.queries) != 2 ||
		vm.queries[0] != `quantiles_over_time("phi", 0.1, 0.5, 0.9, (device_cpu_percent)[1h:1m] offset 1020s)` ||
		vm.queries[1] != `count_over_time((device_cpu_percent)[1h:1m] offset 1020s)` {
		t.Fatalf("queries = %v", vm.queries)
	}
}

// The same device name in two tenants' inventories cannot exist as one
// series key; what CAN happen is the same metric label value on two devices
// owned by different tenants — each row carries its own device's owner.
func TestSameMetricDifferentOwnersGiveDisjointRows(t *testing.T) {
	vm := &fakeVM{devices: map[string][4]float64{"edge-1": {1, 2, 3, 60}, "edge-2": {4, 5, 6, 60}}}
	st := &fakeStore{}
	r := newRoller(t, vm, st, owners{"edge-1": "t-a", "edge-2": "t-b"}, 0)
	if _, err := r.RollHour(context.Background(), LastClosedHour(clock)); err != nil {
		t.Fatal(err)
	}
	tenants := map[string]string{}
	for _, row := range st.rows[0] {
		tenants[row.EntityKey] = row.Tenant
	}
	if tenants["edge-1"] != "t-a" || tenants["edge-2"] != "t-b" {
		t.Fatalf("tenants = %v", tenants)
	}
}

func TestCapIsDeterministicAndCounted(t *testing.T) {
	vm := &fakeVM{devices: map[string][4]float64{"d1": {1, 1, 1, 1}, "d2": {1, 1, 1, 1}, "d3": {1, 1, 1, 1}}}
	st := &fakeStore{}
	r := newRoller(t, vm, st, owners{"d1": "t", "d2": "t", "d3": "t"}, 2)
	res, err := r.RollHour(context.Background(), LastClosedHour(clock))
	if err != nil {
		t.Fatal(err)
	}
	if res.Rows != 2 || res.CapDropped != 1 || r.Stats.CapDropped.Load() != 1 {
		t.Fatalf("result %+v", res)
	}
	if st.rows[0][0].EntityKey != "d1" || st.rows[0][1].EntityKey != "d2" {
		t.Fatalf("cap must keep a deterministic order: %+v", st.rows[0])
	}
}

func TestAFailingMetricIsSkippedAndCounted(t *testing.T) {
	mem := Metric{Name: "mem_util_pct", Expr: "device_mem_percent", Labels: []string{"device"}}
	vm := &fakeVM{devices: map[string][4]float64{"d1": {1, 2, 3, 4}}, fail: "device_mem_percent"}
	st := &fakeStore{}
	r := newRoller(t, vm, st, owners{"d1": "t"}, 0, cpu, mem)
	res, err := r.RollHour(context.Background(), LastClosedHour(clock))
	if err != nil {
		t.Fatal(err)
	}
	if res.Rows != 1 || len(res.Failed) != 1 || res.Failed[0] != "mem_util_pct" || r.Stats.VMErrors.Load() != 1 {
		t.Fatalf("result %+v vm errors %d", res, r.Stats.VMErrors.Load())
	}
}

func TestStoreFailureIsReturnedAndCounted(t *testing.T) {
	vm := &fakeVM{devices: map[string][4]float64{"d1": {1, 2, 3, 4}}}
	r := newRoller(t, vm, &fakeStore{err: errors.New("clickhouse down")}, owners{"d1": "t"}, 0)
	if _, err := r.RollHour(context.Background(), LastClosedHour(clock)); err == nil || !strings.Contains(err.Error(), "clickhouse down") {
		t.Fatalf("err = %v", err)
	}
	if r.Stats.StoreErrors.Load() != 1 || r.Stats.Hours.Load() != 0 {
		t.Fatalf("store errors %d hours %d", r.Stats.StoreErrors.Load(), r.Stats.Hours.Load())
	}
}

// A re-run of the same hour writes the same keys under a newer version, so
// the ReplacingMergeTree keeps one row per key.
func TestReRollingAnHourReplaces(t *testing.T) {
	vm := &fakeVM{devices: map[string][4]float64{"d1": {1, 2, 3, 4}}}
	st := &fakeStore{}
	now := clock
	r, err := New(Config{Metrics: []Metric{cpu}, Now: func() time.Time { return now }}, vm, st, owners{"d1": "t"})
	if err != nil {
		t.Fatal(err)
	}
	h := LastClosedHour(clock)
	if _, err := r.RollHour(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if _, err := r.RollHour(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	a, b := st.rows[0][0], st.rows[1][0]
	if a.EntityKey != b.EntityKey || !a.Hour.Equal(b.Hour) || a.Metric != b.Metric || b.Version <= a.Version {
		t.Fatalf("re-roll must reuse the key with a higher version: %+v then %+v", a, b)
	}
}

func TestEachReadIsBoundedByTheQueryTimeout(t *testing.T) {
	vm := &fakeVM{block: true}
	r, err := New(Config{Metrics: []Metric{cpu}, QueryTimeout: 20 * time.Millisecond, Now: func() time.Time { return clock }}, vm, &fakeStore{}, owners{})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	res, err := r.RollHour(context.Background(), LastClosedHour(clock))
	if err != nil || len(res.Failed) != 1 {
		t.Fatalf("a timed-out read is a failed metric: %+v %v", res, err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("the read was not bounded: %s", time.Since(start))
	}
}

func TestAnOpenHourIsRefused(t *testing.T) {
	r := newRoller(t, &fakeVM{}, &fakeStore{}, owners{}, 0)
	if _, err := r.RollHour(context.Background(), clock.Truncate(time.Hour)); err == nil {
		t.Fatal("the current, still-open hour must not be rolled")
	}
}

func TestNewRefusesMissingDependencies(t *testing.T) {
	if _, err := New(Config{Metrics: []Metric{cpu}}, nil, &fakeStore{}, owners{}); err == nil {
		t.Fatal("nil VM accepted")
	}
	if _, err := New(Config{}, &fakeVM{}, &fakeStore{}, owners{}); err == nil {
		t.Fatal("empty metric set accepted")
	}
}
