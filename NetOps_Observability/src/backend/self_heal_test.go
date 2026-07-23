package main

// self_heal_test.go — the guard's two pure decision points. The heal rule is
// safety-critical in BOTH directions: failing to heal leaves ingest silently
// dead; healing while the disk is still hot re-arms the flood immediately.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestShouldHeal(t *testing.T) {
	cases := []struct {
		name                       string
		diskPct, clearPct, blocked int
		want                       bool
	}{
		{"heals when blocked and disk safe", 76, 90, 3, true},
		{"never heals with nothing blocked", 76, 90, 0, false},
		{"never heals while disk still hot", 93, 90, 3, false},
		{"never heals AT the watermark", 90, 90, 3, false},
		{"never heals blind (disk unmeasurable)", -1, 90, 3, false},
		{"heals just under the watermark", 89, 90, 1, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := shouldHeal(c.diskPct, c.clearPct, c.blocked); got != c.want {
				t.Fatalf("shouldHeal(%d,%d,%d) = %v, want %v", c.diskPct, c.clearPct, c.blocked, got, c.want)
			}
		})
	}
}

func TestParseBlockedIndices(t *testing.T) {
	body := []byte(`{
	  "netops-flows-2026.07.09": {"settings":{"index":{"blocks":{"read_only_allow_delete":"true"}}}},
	  "netops-syslog-2026.07.10": {"settings":{"index":{"blocks":{"read_only_allow_delete":"true"}}}},
	  "healthy-index": {"settings":{"index":{"blocks":{"read_only_allow_delete":"false"}}}}
	}`)
	got, err := parseBlockedIndices(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("blocked = %v, want the 2 true-blocked indices only", got)
	}

	// no blocks at all → empty, not an error (the common steady-state answer)
	got, err = parseBlockedIndices([]byte(`{}`))
	if err != nil || len(got) != 0 {
		t.Fatalf("empty settings: got %v, %v", got, err)
	}

	// garbage → error, never a phantom index list
	if _, err = parseBlockedIndices([]byte(`not json`)); err == nil {
		t.Fatal("garbage body must error")
	}
}

// The full loop against a fake search store: sees the block, clears it with
// ONE settings call, records the heal in the snapshot. (Live OpenSearch ≥2.x
// usually auto-releases synthetic blocks before our tick — the 2026-07-14
// incident proved that release can lag or fail, which is why this backstop
// exists — so the loop's own behavior is proven here, deterministically.)
func TestSelfHealerHealsBlockedIndices(t *testing.T) {
	var mu sync.Mutex
	blocked := true
	var clearCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet:
			if blocked {
				_, _ = w.Write([]byte(`{"idx-a":{"settings":{"index":{"blocks":{"read_only_allow_delete":"true"}}}}}`))
			} else {
				_, _ = w.Write([]byte(`{}`))
			}
		case r.Method == http.MethodPut && r.URL.Path == "/_all/_settings":
			clearCalls++
			blocked = false
			_, _ = w.Write([]byte(`{"acknowledged":true}`))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	h := &selfHealer{
		osURL:    srv.URL,
		diskPath: "/test",
		clearPct: 90,
		enabled:  true,
		interval: 10 * time.Millisecond,
		// Inject a disk reading below the watermark rather than measuring the real
		// host filesystem. The old test used t.TempDir() and so passed or failed on
		// whatever the host's /tmp happened to be — it failed at 91% real usage,
		// which is a genuine disk problem, not a code fault. The heal DECISION is
		// what this test is about, so the disk input must be deterministic.
		diskPctFn: func(string) int { return 40 },
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.run(ctx)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s := h.snapshot(); s.LastHealResult == "healed" {
			if s.LastHealCount != 1 {
				t.Fatalf("healed count = %d, want 1", s.LastHealCount)
			}
			mu.Lock()
			defer mu.Unlock()
			if clearCalls != 1 {
				t.Fatalf("clear calls = %d, want exactly 1 (heal is an edge, not a loop)", clearCalls)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("healer never healed; snapshot: %+v", h.snapshot())
}

// SELF_HEAL=false keeps watching but never acts.
func TestSelfHealerDisabledOnlyWatches(t *testing.T) {
	var clearCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			clearCalls++
		}
		_, _ = w.Write([]byte(`{"idx-a":{"settings":{"index":{"blocks":{"read_only_allow_delete":"true"}}}}}`))
	}))
	defer srv.Close()

	h := &selfHealer{osURL: srv.URL, diskPath: t.TempDir(), clearPct: 90, enabled: false, interval: 10 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.run(ctx)

	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if s := h.snapshot(); s.BlockedIndices == 1 { // it SAW the block
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if s := h.snapshot(); s.BlockedIndices != 1 {
		t.Fatalf("disabled healer must still WATCH; snapshot: %+v", s)
	}
	if clearCalls != 0 {
		t.Fatalf("disabled healer must never act; clear calls = %d", clearCalls)
	}
}
