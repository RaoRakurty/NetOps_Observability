package sealedfields

// edgekeys.go — the ONE endpoint that serves key material.
//
//	GET /internal/sealing/edge-keys?tenant=<id>
//	→ {"seal_key":"<base64>","mac_key":"<base64>","key_version":N}
//
// It exists because sealing happens at the edge: Vector's VRL cannot call this
// process per event, so the router's `exec` secret backend fetches each tenant's
// DERIVED keys once, at config load, and holds them in memory only — Vector's
// secret backends never write to disk.
//
// Everything about this file is shaped by that being the highest-value target in
// the product:
//
//   - It is NOT on the public API surface. The path is /internal/, it is
//     registered only when sealing is enabled, and it requires the stack-internal
//     credential (the same INGEST_TOKEN pair the collectors use) — a browser
//     session, an API token or an operator's JWT cannot reach it. Reveal is the
//     human path and it is audited; this is the machine path and it is not
//     human-reachable at all.
//   - It serves DERIVED keys, never the tenant DEK. A router compromise exposes
//     the seal keys of tenants that enabled sealing — not a master capable of
//     deriving every tenant's key, and not the DEK protecting stored credentials.
//   - It is per-tenant. There is deliberately no "give me every tenant's keys"
//     form, because that response is the entire platform's secrets in one body.
//   - Responses are marked no-store so no proxy or log layer retains them.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// EdgeKeyPath is the internal route the router's secret backend calls.
const EdgeKeyPath = "/internal/sealing/edge-keys"

type edgeKeyResponse struct {
	SealKey    string `json:"seal_key"` // base64 (padded, std) — VRL decode_base64 requires padding
	MACKey     string `json:"mac_key"`  // base64 (padded, std)
	KeyVersion int    `json:"key_version"`
}

// EdgeKeyHandler serves derived per-tenant key material to the ingest runtime.
//
// authorized reports whether the caller presented the stack-internal
// credential; it is injected rather than read here so this package stays
// testable without the server's auth stack, and so the credential check cannot
// silently become a no-op when the env is unset (see the guard below).
func EdgeKeyHandler(provider CryptoProviderSource, authorized func(*http.Request) bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeEdgeError(w, http.StatusMethodNotAllowed, "GET required")
			return
		}
		p := provider()
		if p == nil {
			writeEdgeError(w, http.StatusNotImplemented, "sealing is not enabled")
			return
		}
		// Fail CLOSED: if no internal credential is configured, this endpoint
		// refuses rather than serving key material to anything that can reach
		// the port. An unauthenticated key server is worse than no sealing.
		if authorized == nil || !authorized(r) {
			writeEdgeError(w, http.StatusUnauthorized, "stack-internal credential required")
			return
		}
		tenant := strings.TrimSpace(r.URL.Query().Get("tenant"))
		if tenant == "" {
			writeEdgeError(w, http.StatusBadRequest, "tenant is required")
			return
		}

		m, err := p.EdgeKey(r.Context(), tenant)
		if err != nil {
			// Deliberately uniform: a caller must not be able to enumerate which
			// tenants have custody configured by reading distinct error text.
			writeEdgeError(w, http.StatusNotFound, "no sealing key for this tenant")
			return
		}

		// Padded standard base64: VRL's decode_base64 rejects unpadded input.
		out := edgeKeyResponse{
			SealKey:    base64.StdEncoding.EncodeToString(m.SealKey),
			MACKey:     base64.StdEncoding.EncodeToString(m.MACKey),
			KeyVersion: m.Version,
		}
		w.Header().Set("Content-Type", "application/json")
		// No intermediary may retain a body containing key material.
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		w.Header().Set("Pragma", "no-cache")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(out)
	}
}

func writeEdgeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ErrNoProvider is returned by a nil provider source.
var ErrNoProvider = errors.New("sealing provider is not configured")
