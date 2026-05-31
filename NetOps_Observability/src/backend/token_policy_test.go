package main

import (
	"testing"
	"time"
)

func TestClampDuration(t *testing.T) {
	cases := []struct {
		name             string
		d, min, max, want time.Duration
		clamped          bool
	}{
		{"in-range", time.Hour, time.Minute, 24 * time.Hour, time.Hour, false},
		{"below-min", time.Second, time.Minute, 24 * time.Hour, time.Minute, true},
		{"above-max", 365 * 24 * time.Hour, time.Minute, 24 * time.Hour, 24 * time.Hour, true},
		{"at-min", time.Minute, time.Minute, 24 * time.Hour, time.Minute, false},
		{"at-max", 24 * time.Hour, time.Minute, 24 * time.Hour, 24 * time.Hour, false},
	}
	for _, c := range cases {
		got, was := clampDuration(c.d, c.min, c.max)
		if got != c.want || was != c.clamped {
			t.Errorf("%s: clampDuration=%v,%v want %v,%v", c.name, got, was, c.want, c.clamped)
		}
	}
}

// Access-token TTL must never exceed the hard 24h ceiling even if an operator
// sets something absurd, and the default stays at the configured 1h.
func TestAccessTokenTTLBounds(t *testing.T) {
	t.Setenv("ACCESS_TOKEN_TTL", "8760h") // a year
	if got := accessTokenTTL(); got != accessTTLMax {
		t.Errorf("a year-long access TTL should clamp to %v, got %v", accessTTLMax, got)
	}
	t.Setenv("ACCESS_TOKEN_TTL", "1s") // too short
	if got := accessTokenTTL(); got != accessTTLMin {
		t.Errorf("a 1s access TTL should clamp to %v, got %v", accessTTLMin, got)
	}
	t.Setenv("ACCESS_TOKEN_TTL", "")
	if got := accessTokenTTL(); got != time.Hour {
		t.Errorf("default access TTL should be 1h, got %v", got)
	}
	t.Setenv("ACCESS_TOKEN_TTL", "15m") // recommended
	if got := accessTokenTTL(); got != 15*time.Minute {
		t.Errorf("15m should pass through, got %v", got)
	}
}

func TestRefreshTokenTTLBounds(t *testing.T) {
	t.Setenv("REFRESH_TOKEN_TTL", "8760h") // a year > 90d max
	if got := refreshTokenTTL(); got != refreshTTLMax {
		t.Errorf("year-long refresh TTL should clamp to %v, got %v", refreshTTLMax, got)
	}
	t.Setenv("REFRESH_TOKEN_TTL", "")
	if got := refreshTokenTTL(); got != 7*24*time.Hour {
		t.Errorf("default refresh TTL should be 7d, got %v", got)
	}
}
