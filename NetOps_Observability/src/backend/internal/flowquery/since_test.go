// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package flowquery

import (
	"net/url"
	"testing"
	"time"
)

// Tracker 405: the older routes' since is fail-closed — the default only when
// absent, an error (never the default) when malformed or out of range.
func TestParseSince(t *testing.T) {
	ok := []struct {
		q    string
		want time.Duration
	}{
		{"", time.Hour},
		{"since=2h", 2 * time.Hour},
		{"since=900s", 15 * time.Minute},
		{"since=900", 15 * time.Minute},
		{"since=5m", 5 * time.Minute},
		{"since=720h", 30 * 24 * time.Hour},
		{"since=%201h%20", time.Hour},
	}
	for _, c := range ok {
		q, _ := url.ParseQuery(c.q)
		got, err := ParseSince(q, DefaultLimits)
		if err != nil || got != c.want {
			t.Errorf("%q: (%v, %v), want %v", c.q, got, err, c.want)
		}
	}
	for _, bad := range []string{
		"since=45d", "since=721h", "since=1m", "since=0", "since=-1h", "since=abc",
		"since=1h%3BDROP", "since=99999999999999999999", "from=1", "to=2",
		"since=1h&from=2026-11-13T05:00:00Z&to=2026-11-13T06:00:00Z",
	} {
		q, _ := url.ParseQuery(bad)
		if got, err := ParseSince(q, DefaultLimits); err == nil {
			t.Errorf("%q: accepted as %v, want an error", bad, got)
		}
	}
}

func TestParseBucketStep(t *testing.T) {
	ok := []struct {
		v    string
		span time.Duration
		want time.Duration
	}{
		{"", time.Hour, time.Minute},
		{"60", time.Hour, time.Minute},
		{"120s", time.Hour, 2 * time.Minute},
		{"5m", 24 * time.Hour, 5 * time.Minute},
		{"1h", time.Hour, time.Hour},
		// Absent over 30 d: the 1m default would be 43,200 points, so the
		// automatic step is used instead of refusing a parameter never sent.
		{"", 30 * 24 * time.Hour, 6 * time.Hour},
	}
	for _, c := range ok {
		got, err := ParseBucketStep(c.v, c.span, time.Minute)
		if err != nil || got != c.want {
			t.Errorf("step %q over %v: (%v, %v), want %v", c.v, c.span, got, err, c.want)
		}
	}
	for _, c := range []struct {
		v    string
		span time.Duration
	}{
		{"0", time.Hour}, {"-1m", time.Hour}, {"500ms", time.Hour}, {"1.5s", time.Hour},
		{"abc", time.Hour}, {"2h", time.Hour}, {"7200", time.Hour},
		{"1s", time.Hour}, // 3600 buckets > MaxPoints
		{"99999999999999999999", time.Hour},
	} {
		if got, err := ParseBucketStep(c.v, c.span, time.Minute); err == nil {
			t.Errorf("step %q over %v: accepted as %v, want an error", c.v, c.span, got)
		}
	}
}
