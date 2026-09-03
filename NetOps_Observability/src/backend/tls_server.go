package backend

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
//
// §10 (no silent failures): ErrorLog is ALSO where net/http writes a recovered
// handler panic ("http: panic serving <addr>: ..." plus the stack). Dropping
// everything that is not a handshake error made those invisible — the process
// stayed up, the connection was torn down, the client saw a bare 502 and the
// stack trace went nowhere. Every other line is therefore forwarded as a
// structured error too, so a panic is observable rather than silent.
type handshakeErrLog struct{ m *tlsMetrics }

func (h handshakeErrLog) Write(p []byte) (int, error) {
	detail := strings.TrimSpace(string(p))
	switch {
	case bytes.Contains(p, []byte("TLS handshake error")):
		h.m.handshakeErrors.Add(1)
		logError("tls", "handshake error", map[string]any{"detail": detail})
	case detail != "":
		// Anything else net/http reports here is a server-side fault (most
		// importantly a recovered handler panic). Never swallow it.
		logError("http", "server error", map[string]any{"detail": detail})
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
		// SPIFFE federation (#18 phase 5): each federated root must be in BOTH the
		// combined ClientCAs pool (so the stdlib can build a chain to it) AND the
		// FederationTrust registry (so the domain binding can be checked). Build
		// both from the same entry list to keep the invariant anchorable ⊇ registered.
		fedEntries, err := parseFederationBundles(os.Getenv("TLS_FEDERATED_BUNDLES"))
		if err != nil {
			return nil, err
		}
		bundlePaths := append([]string{caFile}, federationPaths(fedEntries)...)
		bundle, err := tlsconfig.LoadTrustBundle(bundlePaths...)
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
		if len(fedEntries) > 0 {
			// Auto-register the local domain so enabling federation doesn't reject
			// the platform's own same-domain peers (the local root is already in the
			// pool above; this maps it in the registry too).
			regEntries := ensureLocalDomain(fedEntries, caFile)
			fed, err := tlsconfig.LoadFederationTrust(regEntries)
			if err != nil {
				return nil, err
			}
			opts.Peer.Federation = fed
			logInfo("tls", "SPIFFE federation enabled", map[string]any{"trust_domains": federationDomains(regEntries)})
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

// parseFederationBundles parses "domA=/a.pem,domB=/b.pem" (TLS_FEDERATED_BUNDLES)
// into entries. Fail-closed: a missing '=' or an empty side is a fatal config
// error. Empty input → nil (federation disabled).
func parseFederationBundles(s string) ([]tlsconfig.FederationEntry, error) {
	if s = strings.TrimSpace(s); s == "" {
		return nil, nil
	}
	var entries []tlsconfig.FederationEntry
	for _, pair := range strings.Split(s, ",") {
		if pair = strings.TrimSpace(pair); pair == "" {
			continue
		}
		domain, path, ok := strings.Cut(pair, "=")
		domain, path = strings.TrimSpace(domain), strings.TrimSpace(path)
		if !ok || domain == "" || path == "" {
			return nil, fmt.Errorf("tls: invalid TLS_FEDERATED_BUNDLES entry %q (want domain=/path/root.pem)", pair)
		}
		entries = append(entries, tlsconfig.FederationEntry{Domain: domain, Path: path})
	}
	return entries, nil
}

// ensureLocalDomain prepends the local trust domain → local CA mapping so that
// turning federation ON never breaks same-domain (local) mTLS. Without it, the
// local CA root is in the chain-building pool but NOT the FederationTrust registry,
// so every local peer (nginx→api, the API's own SVID) would chain to an
// "unmapped root" and be rejected. Skipped if the operator already listed the
// local domain explicitly (so their path wins, and we don't trip the
// duplicate-domain guard). The local domain matches tls_ca.go's TLS_TRUST_DOMAIN.
func ensureLocalDomain(entries []tlsconfig.FederationEntry, caFile string) []tlsconfig.FederationEntry {
	local := strings.ToLower(strings.TrimSpace(envOr("TLS_TRUST_DOMAIN", "netops")))
	for _, e := range entries {
		if strings.ToLower(strings.TrimSpace(e.Domain)) == local {
			return entries
		}
	}
	return append([]tlsconfig.FederationEntry{{Domain: local, Path: caFile}}, entries...)
}

func federationPaths(entries []tlsconfig.FederationEntry) []string {
	paths := make([]string, 0, len(entries))
	for _, e := range entries {
		paths = append(paths, e.Path)
	}
	return paths
}

func federationDomains(entries []tlsconfig.FederationEntry) []string {
	domains := make([]string, 0, len(entries))
	for _, e := range entries {
		domains = append(domains, e.Domain)
	}
	return domains
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
