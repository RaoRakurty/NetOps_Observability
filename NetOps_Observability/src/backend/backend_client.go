package main

import (
	"net/http"
	"os"
	"strings"
	"time"

	"netops/backend/tlsconfig"
)

// backend_client.go — hardened HTTP client for the API's INTERNAL backends
// (OpenSearch / ClickHouse / VictoriaMetrics / correlation / stack probes).
// #18 phase 3.
//
// When an internal trust bundle is configured (TLS_BACKEND_CA_FILE, defaulting to
// the mesh CA in TLS_CLIENT_CA_FILE), https calls to those backends verify against
// THAT explicit CA — never the system pool — and optionally present a client SVID
// for mTLS (TLS_BACKEND_CERT_FILE/KEY). Plain http is unaffected. Dormant (plain
// client, current behavior) when no bundle is set.
//
// External services (Anthropic/OpenAI copilot, the OIDC issuer/JWKS, NetBox) are
// PUBLIC-CA endpoints and deliberately keep the default system-pool client — they
// must NOT route through this internal-CA transport.

// backendTr is the shared hardened transport, set once at startup by
// initBackendTransport. nil = no internal TLS configured → default client.
var backendTr *http.Transport

// initBackendTransport builds the internal-backend transport from env. Fail
// closed: a configured-but-unloadable bundle/cert is a fatal startup error
// (returned to the caller), never a silent downgrade to the system pool.
func initBackendTransport() error {
	caFile := strings.TrimSpace(envOr("TLS_BACKEND_CA_FILE", os.Getenv("TLS_CLIENT_CA_FILE")))
	if caFile == "" {
		return nil // dormant — default client (unchanged behavior)
	}
	// SPIFFE federation (#18 phase 5): fold federated roots into BOTH the combined
	// pool (chain building) and the registry (domain binding) — invariant
	// anchorable ⊇ registered — so an outbound backend in another trust domain
	// can't impersonate a local identity.
	fedEntries, err := parseFederationBundles(os.Getenv("TLS_FEDERATED_BUNDLES"))
	if err != nil {
		return err
	}
	bundle, err := tlsconfig.LoadTrustBundle(append([]string{caFile}, federationPaths(fedEntries)...)...)
	if err != nil {
		return err
	}
	opts := tlsconfig.ClientOptions{RootCAs: bundle}
	if len(fedEntries) > 0 {
		fed, err := tlsconfig.LoadFederationTrust(fedEntries)
		if err != nil {
			return err
		}
		opts.Peer = tlsconfig.PeerPolicy{
			Federation: fed,
			OnReject: func(identity string, rerr error) {
				logError("tls", "backend SPIFFE federation rejected", map[string]any{"peer_identity": identity, "reason": rerr.Error()})
			},
		}
	}
	// Optional mTLS: present the API's client SVID to backends that require it.
	if cf, kf := os.Getenv("TLS_BACKEND_CERT_FILE"), os.Getenv("TLS_BACKEND_KEY_FILE"); cf != "" && kf != "" {
		rl, err := tlsconfig.NewCertReloader(cf, kf)
		if err != nil {
			return err
		}
		opts.Reloader = rl
	}
	tr, err := tlsconfig.HTTPTransport(opts)
	if err != nil {
		return err
	}
	backendTr = tr
	return nil
}

// backendHTTPClient returns an *http.Client for an internal-backend call with the
// given timeout, sharing the one hardened transport (connection pooling) when
// internal TLS is configured, else a plain client.
func backendHTTPClient(timeout time.Duration) *http.Client {
	c := &http.Client{Timeout: timeout}
	if backendTr != nil {
		c.Transport = backendTr
	}
	return c
}
