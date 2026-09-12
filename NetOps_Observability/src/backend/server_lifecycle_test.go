// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"
)

// server_lifecycle_test.go — the HTTP server's timeout envelope and the
// shutdown drain. Both are about resources the process must not hold forever:
// a dribbled request body / parked connection, and a worker killed mid-write.

func TestAPIServerHasCompleteTimeoutSet(t *testing.T) {
	srv := newAPIServer(":0", http.NewServeMux())
	tests := []struct {
		name string
		got  time.Duration
	}{
		{"ReadHeaderTimeout", srv.ReadHeaderTimeout},
		{"ReadTimeout", srv.ReadTimeout},   // slowloris-on-body
		{"WriteTimeout", srv.WriteTimeout}, // a stuck handler must not pin a conn
		{"IdleTimeout", srv.IdleTimeout},   // keep-alive parking
	}
	for _, tc := range tests {
		if tc.got <= 0 {
			t.Errorf("%s is unset — the Go server is reachable directly in TLS mode, with no nginx in front", tc.name)
		}
	}
	if srv.ReadHeaderTimeout > srv.ReadTimeout {
		t.Errorf("ReadHeaderTimeout (%v) must not exceed ReadTimeout (%v)", srv.ReadHeaderTimeout, srv.ReadTimeout)
	}
	// The copilot proxy waits up to 60s on its upstream; a shorter write budget
	// would cut off a legitimate response.
	if srv.WriteTimeout < 90*time.Second {
		t.Errorf("WriteTimeout %v is below the slowest in-handler upstream wait", srv.WriteTimeout)
	}
	if srv.MaxHeaderBytes != 1<<20 {
		t.Errorf("MaxHeaderBytes = %d, want 1 MiB", srv.MaxHeaderBytes)
	}
}

func TestAPIServerTimeoutsAreEnvTunable(t *testing.T) {
	t.Setenv("HTTP_READ_TIMEOUT", "7s")
	t.Setenv("HTTP_IDLE_TIMEOUT", "11s")
	srv := newAPIServer(":0", http.NewServeMux())
	if srv.ReadTimeout != 7*time.Second || srv.IdleTimeout != 11*time.Second {
		t.Fatalf("read=%v idle=%v, want 7s/11s", srv.ReadTimeout, srv.IdleTimeout)
	}
}

// A deploy must wait for background workers to finish their in-flight write
// rather than cancelling the context and returning immediately.
func TestWorkerGroupDrainsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	g := &workerGroup{}

	var mu sync.Mutex
	finished := 0
	for i := 0; i < 5; i++ {
		g.start("test-worker", func() {
			<-ctx.Done()
			// Stand-in for flushing an in-flight Postgres/ClickHouse write.
			time.Sleep(20 * time.Millisecond)
			mu.Lock()
			finished++
			mu.Unlock()
		})
	}

	cancel()
	if stuck := g.drain(5 * time.Second); len(stuck) > 0 {
		t.Fatalf("drain timed out on workers that do honour cancellation: %v", stuck)
	}
	mu.Lock()
	defer mu.Unlock()
	if finished != 5 {
		t.Fatalf("only %d/5 workers completed — shutdown abandoned work", finished)
	}
}

// A worker that ignores cancellation must cost the drain timeout and be
// reported BY NAME, not hang the shutdown forever.
func TestWorkerGroupDrainReportsTimeout(t *testing.T) {
	g := &workerGroup{}
	release := make(chan struct{})
	g.start("stuck-worker", func() { <-release })

	stuck := g.drain(100 * time.Millisecond)
	if len(stuck) == 0 {
		t.Fatal("drain claimed success while a worker was still running")
	}
	if stuck[0] != "stuck-worker" {
		t.Fatalf("drain reported %v, want the stuck worker named", stuck)
	}
	close(release)
	if again := g.drain(5 * time.Second); len(again) > 0 {
		t.Fatalf("drain never completed after the worker returned: %v", again)
	}
}

// A panicking worker must be recovered (not kill the process) AND must still
// release its slot in the drain group, or shutdown would hang on it.
func TestWorkerGroupSurvivesPanickingWorker(t *testing.T) {
	g := &workerGroup{}
	g.start("panicking-worker", func() { panic(errors.New("worker exploded")) })
	if stuck := g.drain(5 * time.Second); len(stuck) > 0 {
		t.Fatalf("a panicking worker left the drain group blocked: %v", stuck)
	}
}

// writeToNilMap panics the way a real bug does — an uninitialized map write.
func writeToNilMap() {
	var m map[string]int
	set := func(k string, v int) { m[k] = v }
	set("boom", 1)
}

// safeGo is the process-wide guard: a panic on a background goroutine must not
// escape to the runtime.
func TestSafeGoRecovers(t *testing.T) {
	done := make(chan struct{})
	safeGo("test-goroutine", func() {
		defer close(done)
		writeToNilMap()
	})
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("goroutine never ran")
	}
}
