package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"netops/backend/tlsconfig"
)

// tls_server.go — opt-in HTTPS/mTLS for the API listener (#18 phase 1), built on
// the centralized tlsconfig package. DORMANT by default: with no TLS_CERT_FILE
// the API serves plaintext on its internal port exactly as before (nginx remains
// the ingress TLS terminator). When configured it fails CLOSED — a bad cert or CA
// bundle aborts boot rather than silently downgrading.
//
// Env contract:
//   TLS_CERT_FILE / TLS_KEY_FILE   enable HTTPS (both required)
//   TLS_CLIENT_CA_FILE             enable mTLS — require + verify client certs
//                                  against this explicit CA bundle
//   TLS_CLIENT_ALLOWED_DNS         csv DNS-SAN allowlist (least-privilege mTLS)
//   TLS_CLIENT_ALLOWED_URIS        csv URI/SPIFFE-SAN allowlist
//   TLS_RELOAD_INTERVAL            cert hot-reload poll (default 30s)

type tlsServer struct {
	config   *tls.Config
	reloader *tlsconfig.CertReloader
	mtls     bool
	interval time.Duration
}

// buildTLSServer returns a configured tlsServer, or (nil, nil) when TLS is not
// configured (plaintext mode), or an error the caller must treat as fatal.
func buildTLSServer() (*tlsServer, error) {
	certFile := strings.TrimSpace(os.Getenv("TLS_CERT_FILE"))
	keyFile := strings.TrimSpace(os.Getenv("TLS_KEY_FILE"))
	if certFile == "" && keyFile == "" {
		return nil, nil // plaintext mode (unchanged default)
	}
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("tls: TLS_CERT_FILE and TLS_KEY_FILE must both be set")
	}
	reloader, err := tlsconfig.NewCertReloader(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	opts := tlsconfig.ServerOptions{Reloader: reloader}
	if caFile := strings.TrimSpace(os.Getenv("TLS_CLIENT_CA_FILE")); caFile != "" {
		bundle, err := tlsconfig.LoadTrustBundle(caFile)
		if err != nil {
			return nil, err
		}
		opts.RequireClientCert = true
		opts.ClientCAs = bundle
		opts.Peer = tlsconfig.PeerPolicy{
			AllowedDNS:  splitCSV(os.Getenv("TLS_CLIENT_ALLOWED_DNS")),
			AllowedURIs: splitCSV(os.Getenv("TLS_CLIENT_ALLOWED_URIS")),
		}
	}
	cfg, err := tlsconfig.ServerConfig(opts)
	if err != nil {
		return nil, err
	}
	return &tlsServer{
		config:   cfg,
		reloader: reloader,
		mtls:     opts.RequireClientCert,
		interval: durationOr("TLS_RELOAD_INTERVAL", 30*time.Second),
	}, nil
}

// hsts adds HSTS on TLS responses so a conforming browser refuses to ever talk to
// this origin over plaintext. Only meaningful (and only emitted) when serving TLS.
func hsts(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

// writeTLSMetrics emits cert-expiry observability (#18). Scrape-time gauge so a
// rotation is reflected immediately; alert on it approaching zero.
func (t *tlsServer) writeTLSMetrics(w io.Writer) {
	if t == nil || t.reloader == nil {
		return
	}
	leaf := t.reloader.Leaf()
	if leaf == nil {
		return
	}
	secs := time.Until(leaf.NotAfter).Seconds()
	fmt.Fprintf(w, "# HELP netops_tls_cert_expiry_seconds Seconds until the API server TLS certificate expires.\n")
	fmt.Fprintf(w, "# TYPE netops_tls_cert_expiry_seconds gauge\n")
	fmt.Fprintf(w, "netops_tls_cert_expiry_seconds %.0f\n", secs)
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func durationOr(env string, def time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(env)); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}
