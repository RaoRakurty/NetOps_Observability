package collectors

// mesh_client_test.go — regression guards for the 2026-08-05 finding: when
// SEC-009/SEC-010 turned the store URLs https, every collector still built a
// bare &http.Client{} verifying against the system pool, so tunnel inserts
// and ALL collector telemetry (collector_up included — the CollectorDown
// alert's own input) failed with "certificate signed by unknown authority".
// These tests stand up a TLS backend whose CA the system pool does not know,
// exactly like the mesh CA, and prove the seam is what makes the call succeed.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// tlsBackend returns a TLS server whose certificate no system pool trusts,
// plus a factory producing clients that trust it — the shape of
// backendHTTPClient with the mesh trust bundle loaded.
func tlsBackend(t *testing.T, handler http.HandlerFunc) (*httptest.Server, func(time.Duration) *http.Client) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	factory := func(timeout time.Duration) *http.Client {
		c := srv.Client() // trusts the test server's CA, nothing else
		c.Timeout = timeout
		return c
	}
	return srv, factory
}

func TestInsertTunnelsUsesMeshClientSeam(t *testing.T) {
	var got atomic.Int64
	srv, factory := tlsBackend(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		got.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	rows := []tunnelRow{{ID: "t1", Status: "up", TenantID: "acme"}}

	// Without the seam (the pre-fix world): the bare default client must fail
	// against a mesh-style CA. If this ever starts passing, the test backend
	// is no longer exercising the trust boundary and the suite is lying.
	SetMeshHTTPClient(nil)
	t.Cleanup(func() { SetMeshHTTPClient(nil) })
	if err := insertTunnels(context.Background(), rows); err == nil {
		t.Fatal("bare-client insert against an unknown CA succeeded — the test no longer exercises the trust boundary")
	} else if !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expected a certificate verification failure, got: %v", err)
	}

	// With the seam: the injected hardened client carries the trust bundle and
	// the insert lands. THIS is the call shape SEC-009.1 missed.
	SetMeshHTTPClient(factory)
	if err := insertTunnels(context.Background(), rows); err != nil {
		t.Fatalf("insert through the mesh seam failed: %v", err)
	}
	if got.Load() != 1 {
		t.Fatalf("backend saw %d inserts, want 1", got.Load())
	}
}

func TestEmitMetricsUsesMeshClientSeam(t *testing.T) {
	var bodies atomic.Int64
	srv, factory := tlsBackend(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), "collector_up") {
			bodies.Add(1)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	t.Setenv("VICTORIA_URL", srv.URL)

	SetMeshHTTPClient(factory)
	t.Cleanup(func() { SetMeshHTTPClient(nil) })

	before := metricsPushOK.Load()
	emitMetrics(context.Background(), `collector_up{collector="test"} 1`)
	if bodies.Load() != 1 {
		t.Fatal("collector telemetry did not reach the TLS metric store through the seam — " +
			"this is the exact failure that silenced collector_up (and with it CollectorDown) on 2026-08-05")
	}
	if metricsPushOK.Load() != before+1 {
		t.Fatalf("push success was not counted (ok=%d, want %d)", metricsPushOK.Load(), before+1)
	}
}

func TestMeshClientDefaultIsPlain(t *testing.T) {
	// A plaintext deployment must be bit-for-bit unchanged: no factory → a
	// plain client that talks http exactly as before the seam existed.
	SetMeshHTTPClient(nil)
	var got atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	if err := insertTunnels(context.Background(), []tunnelRow{{ID: "t1"}}); err != nil {
		t.Fatalf("plaintext insert with the default client failed: %v", err)
	}
	if got.Load() != 1 {
		t.Fatalf("backend saw %d inserts, want 1", got.Load())
	}
}
