package collectors

// mesh_client.go — the ONE seam through which collectors reach mesh-internal
// backends (ClickHouse, VictoriaMetrics/vmauth, the Vector ingest tier) over
// HTTP.
//
// THE DEFECT THIS CLOSES (2026-08-05): when SEC-009/SEC-010 moved the stores
// behind TLS, the API's shared hardened client (backendHTTPClient, which
// carries the mesh trust bundle and applies URL-userinfo credentials) was
// wired into the package-main call sites — but every collector built its own
// bare &http.Client{}. Each of those clients verified against the system
// pool, so the moment CLICKHOUSE_URL/VICTORIA_URL turned https, every tunnel
// insert and every collector-telemetry push failed with "certificate signed
// by unknown authority" — 900+ silent-to-the-dashboard failures before the
// posture check caught it, including collector_up itself (so CollectorDown
// could not fire: the watcher died with the watched).
//
// The seam is injectable configuration in the style of ingest_auth.go: the
// process wires its hardened factory once at startup; unset, the default is
// the plain client the collectors always had, so a plaintext deployment is
// bit-for-bit unchanged. Collectors whose targets are EXTERNAL (synthetics
// probes, the UniFi controller, traceroute enrichment) must NOT use this
// seam — public-CA endpoints stay on the system pool (see backend_client.go).

import (
	"net/http"
	"sync/atomic"
	"time"
)

// meshClientFactory holds the injected factory. Atomic because collectors
// read it from their own goroutines while main wires it during startup.
var meshClientFactory atomic.Pointer[func(timeout time.Duration) *http.Client]

// SetMeshHTTPClient injects the process's hardened internal-backend client
// factory. Called once from the API's wiring before the pool starts; passing
// nil restores the plain-client default (tests use this to isolate).
func SetMeshHTTPClient(f func(timeout time.Duration) *http.Client) {
	if f == nil {
		meshClientFactory.Store(nil)
		return
	}
	meshClientFactory.Store(&f)
}

// meshHTTPClient returns the client every mesh-internal call site must use.
// Default (no factory injected) is a plain client with the given timeout —
// identical to the pre-seam behaviour.
func meshHTTPClient(timeout time.Duration) *http.Client {
	if p := meshClientFactory.Load(); p != nil {
		return (*p)(timeout)
	}
	return &http.Client{Timeout: timeout}
}
