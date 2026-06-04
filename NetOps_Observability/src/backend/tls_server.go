package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
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
	metrics  *tlsMetrics
}

// tlsMetrics are the handshake/trust observability counters (#18 phase 4).
type tlsMetrics struct {
	handshakeErrors atomic.Int64 // TLS handshake failures at the listener
	identityRejects atomic.Int64 // mTLS peers with a trusted chain but disallowed identity
}

// handshakeErrLog is wired to http.Server.ErrorLog when serving TLS. net/http
// logs "http: TLS handshake error from <addr>: <reason>" there; we count those
// (a downgrade attempt / cert problem / scanner) and emit a structured log,
// rather than letting them vanish into the default logger.
type handshakeErrLog struct{ m *tlsMetrics }

func (h handshakeErrLog) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("TLS handshake error")) {
		h.m.handshakeErrors.Add(1)
		logError("tls", "handshake error", map[string]any{"detail": strings.TrimSpace(string(p))})
	}
	return len(p), nil
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
	metrics := &tlsMetrics{}
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
			// Audit + count every trusted-but-unauthorized peer (a confused-deputy
			// or lateral-movement signal) — fail-closed already rejected it.
			OnReject: func(identity string, rerr error) {
				metrics.identityRejects.Add(1)
				logError("tls", "mTLS identity rejected", map[string]any{"peer_identity": identity, "reason": rerr.Error()})
			},
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
		metrics:  metrics,
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
	if t.metrics != nil {
		fmt.Fprintf(w, "# HELP netops_tls_handshake_errors_total TLS handshake failures at the API listener.\n")
		fmt.Fprintf(w, "# TYPE netops_tls_handshake_errors_total counter\n")
		fmt.Fprintf(w, "netops_tls_handshake_errors_total %d\n", t.metrics.handshakeErrors.Load())
		fmt.Fprintf(w, "# HELP netops_tls_identity_rejected_total mTLS peers with a trusted chain but a disallowed identity.\n")
		fmt.Fprintf(w, "# TYPE netops_tls_identity_rejected_total counter\n")
		fmt.Fprintf(w, "netops_tls_identity_rejected_total %d\n", t.metrics.identityRejects.Load())
	}
}

// certValid reports whether the served leaf exists and is within its validity
// window with at least `margin` left — the readiness signal (#18 phase 4).
func (t *tlsServer) certValid(margin time.Duration) (bool, string) {
	if t == nil || t.reloader == nil {
		return true, "tls disabled"
	}
	leaf := t.reloader.Leaf()
	if leaf == nil {
		return false, "no certificate loaded"
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return false, "certificate not yet valid"
	}
	if now.Add(margin).After(leaf.NotAfter) {
		return false, "certificate expired or within renewal margin"
	}
	return true, "ok"
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
