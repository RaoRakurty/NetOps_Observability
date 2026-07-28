package main

import (
	"netops/backend/internal/session"
	"os"
	"testing"
	"time"
)

func TestClampDuration(t *testing.T) {
	cases := []struct {
		name              string
		d, min, max, want time.Duration
		clamped           bool
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
	if got := accessTokenTTL(); got != 15*time.Minute {
		t.Errorf("default access TTL should be 15m (short token + server-side sessions), got %v", got)
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

func TestTokenPolicyStoreClampPersistAndApply(t *testing.T) {
	// Snapshot + restore the process env this store mutates.
	origA, okA := os.LookupEnv("ACCESS_TOKEN_TTL")
	origR, okR := os.LookupEnv("REFRESH_TOKEN_TTL")
	t.Cleanup(func() {
		restore := func(k, v string, had bool) {
			if had {
				_ = os.Setenv(k, v)
			} else {
				_ = os.Unsetenv(k)
			}
		}
		restore("ACCESS_TOKEN_TTL", origA, okA)
		restore("REFRESH_TOKEN_TTL", origR, okR)
	})

	dir := t.TempDir()
	rf, err := session.NewRefreshStore(dir+"/r.json", time.Hour, platformKV{})
	if err != nil {
		t.Fatal(err)
	}
	st := newTokenPolicyStore(dir+"/tp.json", rf)

	if _, err := st.set(tokenPolicyConfig{AccessTTLSeconds: 0, RefreshTTLSeconds: 0}); err == nil {
		t.Fatal("expected error for non-positive TTLs")
	}

	out, err := st.set(tokenPolicyConfig{AccessTTLSeconds: 1, RefreshTTLSeconds: 999 * 86400})
	if err != nil {
		t.Fatal(err)
	}
	if out.AccessTTLSeconds != int(accessTTLMin.Seconds()) {
		t.Fatalf("access not clamped to min: got %d want %d", out.AccessTTLSeconds, int(accessTTLMin.Seconds()))
	}
	if out.RefreshTTLSeconds != int(refreshTTLMax.Seconds()) {
		t.Fatalf("refresh not clamped to max: got %d want %d", out.RefreshTTLSeconds, int(refreshTTLMax.Seconds()))
	}
	if rf.TTL() != refreshTTLMax {
		t.Fatalf("refresh store ttl not updated live: %v", rf.TTL())
	}

	if _, err := st.set(tokenPolicyConfig{AccessTTLSeconds: 1800, RefreshTTLSeconds: 14 * 86400}); err != nil {
		t.Fatal(err)
	}
	st2 := newTokenPolicyStore(dir+"/tp.json", rf)
	if e := st2.effective(); e.AccessTTLSeconds != 1800 || e.RefreshTTLSeconds != 14*86400 {
		t.Fatalf("reload lost policy: %+v", e)
	}
}
