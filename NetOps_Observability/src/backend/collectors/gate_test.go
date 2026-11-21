// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeLoop is a collector whose Run blocks until cancelled (or returns
// exitErr at once when set), counting starts and live runs.
type fakeLoop struct {
	starts  atomic.Int32
	live    atomic.Int32
	exitErr error
}

func (f *fakeLoop) Name() string { return "traceroute" }
func (f *fakeLoop) Status() Status {
	return Status{Name: "traceroute", Kind: "metrics", Healthy: true, Targets: 3}
}
func (f *fakeLoop) Run(ctx context.Context) error {
	f.starts.Add(1)
	if f.exitErr != nil {
		return f.exitErr
	}
	f.live.Add(1)
	defer f.live.Add(-1)
	<-ctx.Done()
	return ctx.Err()
}

type switchable struct {
	mu     sync.Mutex
	on     bool
	reason string
}

func (s *switchable) set(on bool, reason string) {
	s.mu.Lock()
	s.on, s.reason = on, reason
	s.mu.Unlock()
}
func (s *switchable) gate(context.Context) (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.on, s.reason
}

type metricSink struct {
	mu    sync.Mutex
	lines []string
}

func (m *metricSink) emit(_ context.Context, body string) {
	m.mu.Lock()
	m.lines = append(m.lines, body)
	m.mu.Unlock()
}
func (m *metricSink) last() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.lines) == 0 {
		return ""
	}
	return m.lines[len(m.lines)-1]
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// Off at first: the collector never runs and its status says why. Switched
// on, it starts within one check; switched off, it is cancelled within one
// check — no restart either way.
func TestGatedCollectorStartsAndStopsWithItsSwitch(t *testing.T) {
	inner := &fakeLoop{}
	sw := &switchable{reason: "not_published"}
	sink := &metricSink{}
	g := newGated(inner, sw.gate, 10*time.Millisecond, sink.emit)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- g.Run(ctx) }()

	waitFor(t, "an off metric", func() bool { return strings.Contains(sink.last(), `reason="not_published"} 0`) })
	if inner.starts.Load() != 0 {
		t.Fatal("an off switch must never start the collector")
	}
	if st := g.Status(); st.Enabled || !st.Healthy || !strings.Contains(st.LastError, "not_published") {
		t.Fatalf("off status = %+v", st)
	}

	sw.set(true, "published")
	waitFor(t, "the collector to run", func() bool { return inner.live.Load() == 1 })
	waitFor(t, "an on metric", func() bool {
		return strings.Contains(sink.last(), `prober_collector_enabled{collector="traceroute",reason="published"} 1`)
	})
	if st := g.Status(); !st.Enabled || st.Targets != 3 {
		t.Fatalf("on status must be the inner collector's: %+v", st)
	}
	time.Sleep(40 * time.Millisecond)
	if n := inner.starts.Load(); n != 1 {
		t.Fatalf("a steady on switch must not relaunch the collector: %d starts", n)
	}

	sw.set(false, "stale")
	waitFor(t, "the collector to stop", func() bool { return inner.live.Load() == 0 })
	if st := g.Status(); st.Enabled {
		t.Fatalf("status after switching off = %+v", st)
	}

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v", err)
	}
}

// A collector that exits on its own while its switch reads on is relaunched
// at the check cadence, never in a hot loop.
func TestGatedCollectorRelaunchesAtCheckCadence(t *testing.T) {
	inner := &fakeLoop{exitErr: errors.New("bind: address in use")}
	sw := &switchable{on: true, reason: "published"}
	g := newGated(inner, sw.gate, 20*time.Millisecond, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Millisecond)
	defer cancel()
	_ = g.Run(ctx) // returns ctx.Err() at the deadline; the counts are the assertion
	n := inner.starts.Load()
	if n < 2 || n > 7 {
		t.Fatalf("starts = %d over ~5 checks: want a relaunch per check, not a hot loop", n)
	}
}

// Cancelling Run stops a running collector before Run returns.
func TestGatedCollectorStopsOnShutdown(t *testing.T) {
	inner := &fakeLoop{}
	sw := &switchable{on: true, reason: "published"}
	g := newGated(inner, sw.gate, 10*time.Millisecond, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = g.Run(ctx); close(done) }() // the error is ctx.Err(); the stop is the assertion
	waitFor(t, "the collector to run", func() bool { return inner.live.Load() == 1 })
	cancel()
	<-done
	if inner.live.Load() != 0 {
		t.Fatal("Run returned with the collector still running")
	}
}

func TestPoolGateRefusesUnknownAndNil(t *testing.T) {
	p := NewPool(nil)
	if err := p.Gate("no-such-collector", func(context.Context) (bool, string) { return true, "x" }, time.Second); err == nil {
		t.Fatal("an unknown collector must be refused")
	}
	if err := p.Gate("traceroute", nil, time.Second); err == nil {
		t.Fatal("a nil gate must be refused")
	}
	if err := p.Gate("traceroute", func(context.Context) (bool, string) { return false, "not_published" }, time.Second); err != nil {
		t.Fatal(err)
	}
	if !p.enabled["traceroute"] {
		t.Fatal("a gated collector is launched by Start (its gate decides whether it runs)")
	}
	if _, ok := p.collectors["traceroute"].(*gatedCollector); !ok {
		t.Fatal("the collector was not wrapped")
	}
}

func fakeLookup(m map[string][]string) nameLookup {
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		addrs, ok := m[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		var out []netip.Addr
		for _, a := range addrs {
			out = append(out, netip.MustParseAddr(a))
		}
		return out, nil
	}
}

// The install's target list: what is never probed is refused whoever wrote
// it; the operator's own internal space and public targets pass; a name that
// does not resolve is dropped; one bad entry costs that entry only, and the
// error never carries a refused address.
func TestEnvTargetsKeepOnlyAllowedTargets(t *testing.T) {
	env := map[string]string{
		"TRACEROUTE_TARGETS": " 10.20.0.1, 127.0.0.1 ,169.254.169.254, branch-edge, metadata-alias, 8.8.8.8, ghost,, 224.0.0.5",
	}
	e := &envTargets{key: "TRACEROUTE_TARGETS", getenv: func(k string) string { return env[k] },
		lookup: fakeLookup(map[string][]string{
			"branch-edge":    {"192.168.222.105"},
			"metadata-alias": {"203.0.113.9", "169.254.169.254"},
		})}
	got, err := e.Targets(context.Background())
	want := "10.20.0.1,branch-edge,8.8.8.8"
	if strings.Join(got, ",") != want {
		t.Fatalf("targets = %v, want %s", got, want)
	}
	if err == nil {
		t.Fatal("dropped targets must be reported")
	}
	msg := err.Error()
	if !strings.Contains(msg, "5 target(s) dropped") || !strings.Contains(msg, "4 refused") || !strings.Contains(msg, "1 did not resolve") {
		t.Fatalf("error = %q", msg)
	}
	for _, leaked := range []string{"127.0.0.1", "169.254.169.254", "224.0.0.5", "ghost"} {
		if strings.Contains(msg, leaked) {
			t.Fatalf("the error must not carry the address %s: %q", leaked, msg)
		}
	}
}

// STAMP entries are host[:port]: a bare host gets the default port, and the
// host part is what the rule checks.
func TestEnvTargetsWithPorts(t *testing.T) {
	env := map[string]string{"STAMP_TARGETS": "10.1.1.1, 10.1.1.2:8620, 127.0.0.1:862"}
	e := &envTargets{key: "STAMP_TARGETS", defaultPort: 862, getenv: func(k string) string { return env[k] }, lookup: fakeLookup(nil)}
	got, err := e.Targets(context.Background())
	if strings.Join(got, ",") != "10.1.1.1:862,10.1.1.2:8620" {
		t.Fatalf("targets = %v", got)
	}
	if err == nil || !strings.Contains(err.Error(), "1 refused") {
		t.Fatalf("loopback with a port must still be refused: %v", err)
	}
}

func TestEnvTargetsEmpty(t *testing.T) {
	e := &envTargets{key: "TRACEROUTE_TARGETS", getenv: func(string) string { return "  " }, lookup: fakeLookup(nil)}
	if got, err := e.Targets(context.Background()); got != nil || err != nil {
		t.Fatalf("empty list: %v %v", got, err)
	}
}
