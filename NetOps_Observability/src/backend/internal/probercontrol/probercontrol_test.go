// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package probercontrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// fakeKV is the key-value channel in memory.
type fakeKV struct {
	configured bool
	vals       map[string]string
	ttl        map[string]int
	getErr     error
	setErr     error
	gets       int
}

func newKV() *fakeKV {
	return &fakeKV{configured: true, vals: map[string]string{}, ttl: map[string]int{}}
}

func (k *fakeKV) Configured() bool { return k.configured }
func (k *fakeKV) SetEX(_ context.Context, channel, key, val string, ttl int) error {
	if channel != Channel {
		return fmt.Errorf("unexpected channel %q", channel)
	}
	if k.setErr != nil {
		return k.setErr
	}
	k.vals[key], k.ttl[key] = val, ttl
	return nil
}
func (k *fakeKV) Get(_ context.Context, key string) (string, error) {
	k.gets++
	if k.getErr != nil {
		return "", k.getErr
	}
	return k.vals[key], nil
}

func envOf(m map[string]string) LookupEnv {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

var t0 = time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)

func clock(t time.Time) func() time.Time { return func() time.Time { return t } }

// The api publishes exactly the resolved values of every delivered switch,
// with the schema version, its own time and the TTL that expires it.
func TestPublisherWritesTheResolvedSwitches(t *testing.T) {
	kv := newKV()
	resolved := map[string]bool{EnvTraceroute: true, EnvActiveProbe: false}
	p := NewPublisher(kv, func(env string) bool { return resolved[env] }, clock(t0))
	if err := p.PublishOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	var rec Record
	if err := json.Unmarshal([]byte(kv.vals[Key]), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.V != SchemaVersion || !rec.IssuedAt.Equal(t0) || len(rec.Switches) != len(Delivered()) {
		t.Fatalf("record = %+v", rec)
	}
	if !rec.Switches[EnvTraceroute] || rec.Switches[EnvActiveProbe] {
		t.Fatalf("switches = %v, want traceroute on, active probe off", rec.Switches)
	}
	if kv.ttl[Key] != TTLSeconds {
		t.Fatalf("ttl = %d, want %d", kv.ttl[Key], TTLSeconds)
	}
}

// No channel: nothing is published and nothing fails (the prober reads its
// own environment there). A failed write is returned to the caller.
func TestPublisherWithoutChannelAndOnFailure(t *testing.T) {
	kv := newKV()
	kv.configured = false
	p := NewPublisher(kv, func(string) bool { return true }, clock(t0))
	if err := p.PublishOnce(context.Background()); err != nil || len(kv.vals) != 0 {
		t.Fatalf("no channel: err=%v vals=%v", err, kv.vals)
	}
	kv.configured, kv.setErr = true, errors.New("NOAUTH")
	if err := p.PublishOnce(context.Background()); err == nil {
		t.Fatal("a failed publish must be returned")
	}
}

// The gating table: every doubt reads OFF; only a fresh, valid record that
// names the switch turns it on; no channel at all falls back to the env.
func TestReaderFailsClosed(t *testing.T) {
	fresh := func(sw map[string]bool, at time.Time) string {
		b, _ := json.Marshal(Record{V: SchemaVersion, IssuedAt: at, Switches: sw})
		return string(b)
	}
	cases := []struct {
		name       string
		configured bool
		val        string
		getErr     error
		env        map[string]string
		want       Decision
	}{
		{"published on", true, fresh(map[string]bool{EnvTraceroute: true}, t0.Add(-30*time.Second)), nil, nil, Decision{true, ReasonPublished}},
		{"published off beats env on", true, fresh(map[string]bool{EnvTraceroute: false}, t0), nil, map[string]string{EnvTraceroute: "true"}, Decision{false, ReasonPublished}},
		{"unread channel", true, "", errors.New("dial tcp: refused"), map[string]string{EnvTraceroute: "true"}, Decision{false, ReasonUnread}},
		{"nothing published", true, "", nil, map[string]string{EnvTraceroute: "true"}, Decision{false, ReasonNotPublished}},
		{"switch not named", true, fresh(map[string]bool{EnvActiveProbe: true}, t0), nil, nil, Decision{false, ReasonNotPublished}},
		{"garbage", true, "{not json", nil, nil, Decision{false, ReasonInvalid}},
		{"wrong schema", true, `{"v":2,"issued_at":"2026-11-20T10:00:00Z","switches":{"FEATURE_TRACEROUTE":true}}`, nil, nil, Decision{false, ReasonInvalid}},
		{"no timestamp", true, `{"v":1,"switches":{"FEATURE_TRACEROUTE":true}}`, nil, nil, Decision{false, ReasonInvalid}},
		{"stale", true, fresh(map[string]bool{EnvTraceroute: true}, t0.Add(-MaxAge-time.Second)), nil, nil, Decision{false, ReasonStale}},
		{"from the future", true, fresh(map[string]bool{EnvTraceroute: true}, t0.Add(2*time.Minute)), nil, nil, Decision{false, ReasonStale}},
		{"small skew tolerated", true, fresh(map[string]bool{EnvTraceroute: true}, t0.Add(30*time.Second)), nil, nil, Decision{true, ReasonPublished}},
		{"no channel: env on", false, "", nil, map[string]string{EnvTraceroute: "true"}, Decision{true, ReasonNoChannel}},
		{"no channel: env loose value is off", false, "", nil, map[string]string{EnvTraceroute: "yes"}, Decision{false, ReasonNoChannel}},
		{"no channel: env unset", false, "", nil, nil, Decision{false, ReasonNoChannel}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kv := newKV()
			kv.configured, kv.getErr = c.configured, c.getErr
			if c.val != "" {
				kv.vals[Key] = c.val
			}
			r := NewReader(kv, envOf(c.env), clock(t0), nil)
			if got := r.Decide(context.Background(), EnvTraceroute); got != c.want {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

// A switch change on the page reaches the prober on its next check, with no
// restart: publish on, read on; publish off, read off.
func TestRoundTripAppliesWithoutRestart(t *testing.T) {
	kv := newKV()
	on := true
	now := t0
	p := NewPublisher(kv, func(env string) bool { return env == EnvTraceroute && on }, func() time.Time { return now })
	r := NewReader(kv, envOf(nil), func() time.Time { return now }, nil)
	if err := p.PublishOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d := r.Decide(context.Background(), EnvTraceroute); !d.On {
		t.Fatalf("after publishing on: %+v", d)
	}
	if d := r.Decide(context.Background(), EnvActiveProbe); d.On || d.Reason != ReasonPublished {
		t.Fatalf("active probe must read off from the record: %+v", d)
	}
	on, now = false, now.Add(PublishEvery)
	if err := p.PublishOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d := r.Decide(context.Background(), EnvTraceroute); d.On {
		t.Fatalf("after publishing off: %+v", d)
	}
	// The api stops publishing: past MaxAge the collector goes off on its own.
	on = true
	if err := p.PublishOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(MaxAge + time.Second)
	if d := r.Decide(context.Background(), EnvTraceroute); d.On || d.Reason != ReasonStale {
		t.Fatalf("a record the api stopped refreshing must go stale: %+v", d)
	}
}

// Each change of state or reason is logged once as one structured line; a
// steady state is not repeated every check.
func TestReaderLogsTransitionsOnce(t *testing.T) {
	kv := newKV()
	var lines []string
	logf := func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) }
	r := NewReader(kv, envOf(nil), clock(t0), logf)
	for i := 0; i < 3; i++ {
		r.Decide(context.Background(), EnvTraceroute)
	}
	kv.getErr = errors.New("down")
	r.Decide(context.Background(), EnvTraceroute)
	r.Decide(context.Background(), EnvTraceroute)
	if len(lines) != 2 {
		t.Fatalf("want 2 transition lines, got %d: %q", len(lines), lines)
	}
	if !strings.Contains(lines[0], "switch=FEATURE_TRACEROUTE on=false reason=not_published") ||
		!strings.Contains(lines[1], "reason=channel_unread") {
		t.Fatalf("lines = %q", lines)
	}
}

func TestDeliveredIsTheTwoMeasurementSwitches(t *testing.T) {
	got := strings.Join(Delivered(), ",")
	if got != "FEATURE_ACTIVE_PROBE,FEATURE_TRACEROUTE" {
		t.Fatalf("Delivered() = %s", got)
	}
}
